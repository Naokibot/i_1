package runtime

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

type keyedTestKEM struct{}

func (keyedTestKEM) Encapsulate(_ context.Context, publicKeyPath, algorithm string) ([]byte, []byte, error) {
	key, err := os.ReadFile(publicKeyPath)
	if err != nil {
		return nil, nil, err
	}
	ciphertext := make([]byte, 32)
	if _, err := rand.Read(ciphertext); err != nil {
		return nil, nil, err
	}
	return ciphertext, testSharedSecret(key, algorithm, ciphertext), nil
}

func (keyedTestKEM) Decapsulate(_ context.Context, privateKeyPath, algorithm string, ciphertext []byte) ([]byte, error) {
	key, err := os.ReadFile(privateKeyPath)
	if err != nil {
		return nil, err
	}
	return testSharedSecret(key, algorithm, ciphertext), nil
}

func testSharedSecret(key []byte, algorithm string, ciphertext []byte) []byte {
	hasher := sha256.New()
	_, _ = hasher.Write([]byte("test-kem-v1\x00"))
	_, _ = hasher.Write(key)
	_, _ = hasher.Write([]byte(algorithm))
	_, _ = hasher.Write(ciphertext)
	return hasher.Sum(nil)
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	t.Parallel()
	fixture := newRecryptFixture(t)
	plaintext := bytes.Repeat([]byte("post-quantum migration\n"), 700)
	writeFile(t, fixture.source, plaintext)

	header, err := fixture.recryptor.EncryptFile(context.Background(), fixture.source, fixture.envelope, fixture.oldPublic, "old-key", "ML-KEM-768")
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if header.Version != 2 || header.Generation != 1 || header.HeaderMAC == "" {
		t.Fatalf("unexpected header: version=%d generation=%d mac=%t", header.Version, header.Generation, header.HeaderMAC != "")
	}
	if _, err := fixture.recryptor.DecryptFile(context.Background(), fixture.envelope, fixture.output, fixture.oldPrivate); err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	assertFileEquals(t, fixture.output, plaintext)
}

func TestRewrapPreservesCiphertextAndAdvancesGeneration(t *testing.T) {
	t.Parallel()
	fixture := newRecryptFixture(t)
	plaintext := bytes.Repeat([]byte{0x00, 0x7f, 0x80, 0xff}, 3000)
	writeFile(t, fixture.source, plaintext)

	original, err := fixture.recryptor.EncryptFile(context.Background(), fixture.source, fixture.envelope, fixture.oldPublic, "old-key", "ML-KEM-768")
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	rewrapped, err := fixture.recryptor.RewrapFile(context.Background(), fixture.envelope, fixture.rewrapped, fixture.oldPrivate, fixture.newPublic, "new-key", "ML-KEM-768")
	if err != nil {
		t.Fatalf("rewrap: %v", err)
	}
	if rewrapped.Generation != original.Generation+1 {
		t.Fatalf("generation=%d, want %d", rewrapped.Generation, original.Generation+1)
	}
	if len(rewrapped.Lineage) != 1 || rewrapped.Lineage[0].Generation != 1 || rewrapped.Lineage[0].EnvelopeSHA256 == "" {
		t.Fatalf("unexpected lineage: %#v", rewrapped.Lineage)
	}
	if !bytes.Equal(envelopePayload(t, fixture.envelope), envelopePayload(t, fixture.rewrapped)) {
		t.Fatal("rewrap changed encrypted payload")
	}
	if _, err := fixture.recryptor.DecryptFileWithPolicy(
		context.Background(), fixture.rewrapped, fixture.output, fixture.newPrivate,
		DecryptPolicy{MinimumGeneration: 2, ExpectedKeyID: "new-key", RejectLegacyV1: true},
	); err != nil {
		t.Fatalf("decrypt rewrapped: %v", err)
	}
	assertFileEquals(t, fixture.output, plaintext)
}

func TestTamperedHeaderIsRejectedWithoutReplacingOutput(t *testing.T) {
	t.Parallel()
	fixture := newRecryptFixture(t)
	writeFile(t, fixture.source, []byte("authenticated metadata"))
	if _, err := fixture.recryptor.EncryptFile(context.Background(), fixture.source, fixture.envelope, fixture.oldPublic, "old-key", "ML-KEM-768"); err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	tampered := filepath.Join(fixture.directory, "tampered-header.pqm")
	mutateHeader(t, fixture.envelope, tampered, func(header *EnvelopeHeader) {
		if header.PlaintextSHA256[0] == '0' {
			header.PlaintextSHA256 = "1" + header.PlaintextSHA256[1:]
		} else {
			header.PlaintextSHA256 = "0" + header.PlaintextSHA256[1:]
		}
	})
	writeFile(t, fixture.output, []byte("keep-me"))
	_, err := fixture.recryptor.DecryptFile(context.Background(), tampered, fixture.output, fixture.oldPrivate)
	if !errors.Is(err, ErrAuthentication) {
		t.Fatalf("decrypt tampered header error=%v, want ErrAuthentication", err)
	}
	assertFileEquals(t, fixture.output, []byte("keep-me"))
	assertNoTransactionResidue(t, fixture.output)
}

func TestTamperedCiphertextIsRejected(t *testing.T) {
	t.Parallel()
	fixture := newRecryptFixture(t)
	writeFile(t, fixture.source, bytes.Repeat([]byte("ciphertext"), 2000))
	if _, err := fixture.recryptor.EncryptFile(context.Background(), fixture.source, fixture.envelope, fixture.oldPublic, "old-key", "ML-KEM-768"); err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	data := readFile(t, fixture.envelope)
	bodyOffset := envelopeBodyOffset(t, data)
	if len(data) < bodyOffset+8 {
		t.Fatal("test envelope body is unexpectedly short")
	}
	data[bodyOffset+6] ^= 0x40
	tampered := filepath.Join(fixture.directory, "tampered-body.pqm")
	writeFile(t, tampered, data)
	_, err := fixture.recryptor.DecryptFile(context.Background(), tampered, fixture.output, fixture.oldPrivate)
	if !errors.Is(err, ErrAuthentication) {
		t.Fatalf("decrypt tampered body error=%v, want ErrAuthentication", err)
	}
	if _, statErr := os.Stat(fixture.output); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("failed decrypt created output: %v", statErr)
	}
}

func TestTruncatedEnvelopeIsRejected(t *testing.T) {
	t.Parallel()
	fixture := newRecryptFixture(t)
	writeFile(t, fixture.source, bytes.Repeat([]byte("truncation"), 3000))
	if _, err := fixture.recryptor.EncryptFile(context.Background(), fixture.source, fixture.envelope, fixture.oldPublic, "old-key", "ML-KEM-768"); err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	complete := readFile(t, fixture.envelope)
	bodyOffset := envelopeBodyOffset(t, complete)
	cuts := []int{1, 9, bodyOffset - 1, bodyOffset + 2, len(complete) - 1}
	for _, cut := range cuts {
		cut := cut
		t.Run(fmt.Sprintf("cut-%d", cut), func(t *testing.T) {
			path := filepath.Join(fixture.directory, fmt.Sprintf("truncated-%d.pqm", cut))
			writeFile(t, path, complete[:cut])
			_, err := fixture.recryptor.DecryptFile(context.Background(), path, fixture.output+fmt.Sprintf("-%d", cut), fixture.oldPrivate)
			if err == nil {
				t.Fatal("truncated envelope was accepted")
			}
		})
	}
}

func TestWrongPrivateKeyIsRejected(t *testing.T) {
	t.Parallel()
	fixture := newRecryptFixture(t)
	writeFile(t, fixture.source, []byte("wrong-key test"))
	if _, err := fixture.recryptor.EncryptFile(context.Background(), fixture.source, fixture.envelope, fixture.oldPublic, "old-key", "ML-KEM-768"); err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	_, err := fixture.recryptor.DecryptFile(context.Background(), fixture.envelope, fixture.output, fixture.newPrivate)
	if !errors.Is(err, ErrAuthentication) {
		t.Fatalf("wrong-key error=%v, want ErrAuthentication", err)
	}
}

func TestRollbackPolicyRejectsOlderGeneration(t *testing.T) {
	t.Parallel()
	fixture := newRecryptFixture(t)
	writeFile(t, fixture.source, []byte("rollback policy"))
	if _, err := fixture.recryptor.EncryptFile(context.Background(), fixture.source, fixture.envelope, fixture.oldPublic, "old-key", "ML-KEM-768"); err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if _, err := fixture.recryptor.RewrapFile(context.Background(), fixture.envelope, fixture.rewrapped, fixture.oldPrivate, fixture.newPublic, "new-key", "ML-KEM-768"); err != nil {
		t.Fatalf("rewrap: %v", err)
	}

	_, err := fixture.recryptor.DecryptFileWithPolicy(
		context.Background(), fixture.envelope, fixture.output, fixture.oldPrivate,
		DecryptPolicy{MinimumGeneration: 2},
	)
	if !errors.Is(err, ErrRollbackDetected) {
		t.Fatalf("old generation error=%v, want ErrRollbackDetected", err)
	}
	if _, err := fixture.recryptor.DecryptFileWithPolicy(
		context.Background(), fixture.rewrapped, fixture.output, fixture.newPrivate,
		DecryptPolicy{MinimumGeneration: 2, ExpectedKeyID: "new-key"},
	); err != nil {
		t.Fatalf("current generation rejected: %v", err)
	}
}

func TestCrashRecoveryRollsBackBeforeCommitPoint(t *testing.T) {
	fixture := newRecryptFixture(t)
	writeFile(t, fixture.source, bytes.Repeat([]byte("new-data"), 1000))
	writeFile(t, fixture.output, []byte("previous-output"))

	runCrashHelper(t, fixture, phaseBackedUp)
	if err := RecoverFile(fixture.output); err != nil {
		t.Fatalf("recover: %v", err)
	}
	assertFileEquals(t, fixture.output, []byte("previous-output"))
	assertNoTransactionResidue(t, fixture.output)
}

func TestCrashRecoveryCompletesAfterCommitPoint(t *testing.T) {
	fixture := newRecryptFixture(t)
	plaintext := bytes.Repeat([]byte("committed-data"), 1000)
	writeFile(t, fixture.source, plaintext)
	writeFile(t, fixture.output, []byte("previous-output"))

	runCrashHelper(t, fixture, phaseReplaced)
	if err := RecoverFile(fixture.output); err != nil {
		t.Fatalf("recover: %v", err)
	}
	if _, err := fixture.recryptor.DecryptFile(context.Background(), fixture.output, fixture.envelope, fixture.oldPrivate); err != nil {
		t.Fatalf("decrypt recovered envelope: %v", err)
	}
	assertFileEquals(t, fixture.envelope, plaintext)
	assertNoTransactionResidue(t, fixture.output)
}

func TestCrashHelperProcess(t *testing.T) {
	if os.Getenv("PQM_CRASH_HELPER") != "1" {
		return
	}
	phase := commitPhase(os.Getenv("PQM_CRASH_PHASE"))
	recryptor := Recryptor{KEM: keyedTestKEM{}, ChunkSize: 4096}
	recryptor.commitHook = func(current commitPhase) error {
		if current == phase {
			os.Exit(86)
		}
		return nil
	}
	_, err := recryptor.EncryptFile(
		context.Background(),
		os.Getenv("PQM_CRASH_SOURCE"),
		os.Getenv("PQM_CRASH_DESTINATION"),
		os.Getenv("PQM_CRASH_PUBLIC_KEY"),
		"old-key",
		"ML-KEM-768",
	)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(87)
	}
	os.Exit(88)
}

func TestRecoveryRejectsJournalPathTraversal(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	destination := filepath.Join(directory, "out.bin")
	absolute, err := filepath.Abs(destination)
	if err != nil {
		t.Fatal(err)
	}
	journal := transactionJournal{
		Version:     transactionJournalVersion,
		Destination: absolute,
		Stage:       "../outside",
		Phase:       phasePrepared,
	}
	encoded, err := json.Marshal(journal)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, journalPathFor(destination), encoded)
	if err := RecoverFile(destination); err == nil || !strings.Contains(err.Error(), "unsafe recovery journal") {
		t.Fatalf("path traversal journal error=%v", err)
	}
}

type recryptFixture struct {
	directory  string
	source     string
	envelope   string
	rewrapped  string
	output     string
	oldPrivate string
	oldPublic  string
	newPrivate string
	newPublic  string
	recryptor  Recryptor
}

func newRecryptFixture(t *testing.T) recryptFixture {
	t.Helper()
	directory := t.TempDir()
	fixture := recryptFixture{
		directory:  directory,
		source:     filepath.Join(directory, "source.bin"),
		envelope:   filepath.Join(directory, "envelope.pqm"),
		rewrapped:  filepath.Join(directory, "rewrapped.pqm"),
		output:     filepath.Join(directory, "output.bin"),
		oldPrivate: filepath.Join(directory, "old-private.key"),
		oldPublic:  filepath.Join(directory, "old-public.key"),
		newPrivate: filepath.Join(directory, "new-private.key"),
		newPublic:  filepath.Join(directory, "new-public.key"),
		recryptor:  Recryptor{KEM: keyedTestKEM{}, ChunkSize: 4096},
	}
	writeFile(t, fixture.oldPrivate, []byte("old-key-material"))
	writeFile(t, fixture.oldPublic, []byte("old-key-material"))
	writeFile(t, fixture.newPrivate, []byte("new-key-material"))
	writeFile(t, fixture.newPublic, []byte("new-key-material"))
	return fixture
}

func runCrashHelper(t *testing.T, fixture recryptFixture, phase commitPhase) {
	t.Helper()
	command := exec.Command(os.Args[0], "-test.run=^TestCrashHelperProcess$")
	command.Env = append(os.Environ(),
		"PQM_CRASH_HELPER=1",
		"PQM_CRASH_PHASE="+string(phase),
		"PQM_CRASH_SOURCE="+fixture.source,
		"PQM_CRASH_DESTINATION="+fixture.output,
		"PQM_CRASH_PUBLIC_KEY="+fixture.oldPublic,
	)
	output, err := command.CombinedOutput()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 86 {
		t.Fatalf("crash helper error=%v exit=%v output=%s", err, exitCode(exitErr), output)
	}
}

func exitCode(err *exec.ExitError) int {
	if err == nil {
		return 0
	}
	return err.ExitCode()
}

func mutateHeader(t *testing.T, source, destination string, mutate func(*EnvelopeHeader)) {
	t.Helper()
	data := readFile(t, source)
	offset := envelopeBodyOffset(t, data)
	headerLength := int(binary.BigEndian.Uint32(data[8:12]))
	var header EnvelopeHeader
	if err := json.Unmarshal(data[12:12+headerLength], &header); err != nil {
		t.Fatal(err)
	}
	mutate(&header)
	encoded, err := json.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}
	var result bytes.Buffer
	result.Write(data[:8])
	if err := binary.Write(&result, binary.BigEndian, uint32(len(encoded))); err != nil {
		t.Fatal(err)
	}
	result.Write(encoded)
	result.Write(data[offset:])
	writeFile(t, destination, result.Bytes())
}

func envelopePayload(t *testing.T, path string) []byte {
	t.Helper()
	data := readFile(t, path)
	return data[envelopeBodyOffset(t, data):]
}

func envelopeBodyOffset(t *testing.T, data []byte) int {
	t.Helper()
	if len(data) < 12 {
		t.Fatal("envelope too short")
	}
	headerLength := int(binary.BigEndian.Uint32(data[8:12]))
	offset := 12 + headerLength
	if offset > len(data) {
		t.Fatal("header extends past envelope")
	}
	return offset
}

func writeFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func assertFileEquals(t *testing.T, path string, expected []byte) {
	t.Helper()
	actual := readFile(t, path)
	if !bytes.Equal(actual, expected) {
		t.Fatalf("file %s differs: got %d bytes, want %d", path, len(actual), len(expected))
	}
}

func assertNoTransactionResidue(t *testing.T, destination string) {
	t.Helper()
	if _, err := os.Stat(journalPathFor(destination)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("journal residue: %v", err)
	}
	pattern := filepath.Join(filepath.Dir(destination), "."+filepath.Base(destination)+".*")
	matches, err := filepath.Glob(pattern)
	if err != nil {
		t.Fatal(err)
	}
	for _, match := range matches {
		if strings.Contains(filepath.Base(match), ".stage-") || strings.Contains(filepath.Base(match), ".backup-") {
			t.Fatalf("transaction residue: %s", match)
		}
	}
}
