package runtime

import (
	"bufio"
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"math"
	"os"
	"path/filepath"
	"time"
)

var (
	envelopeMagicV1 = [8]byte{'P', 'Q', 'M', 'E', 'N', 'C', '0', '1'}
	envelopeMagicV2 = [8]byte{'P', 'Q', 'M', 'E', 'N', 'C', '0', '2'}

	ErrAuthentication   = errors.New("envelope authentication failed")
	ErrTruncated        = errors.New("envelope is truncated")
	ErrRollbackDetected = errors.New("envelope rollback detected")
	ErrPolicyViolation  = errors.New("envelope policy violation")
)

const (
	defaultChunkSize = 1 << 20
	maxChunkSize     = 64 << 20
	maxHeaderSize    = 4 << 20
	maxLineageLength = 1024
)

type RewrapRecord struct {
	Generation     uint64    `json:"generation"`
	KeyID          string    `json:"keyId"`
	KEMAlgorithm   string    `json:"kemAlgorithm"`
	EnvelopeSHA256 string    `json:"envelopeSha256"`
	RewrappedAt    time.Time `json:"rewrappedAt"`
}

type EnvelopeHeader struct {
	Version         int            `json:"version"`
	Generation      uint64         `json:"generation,omitempty"`
	ObjectID        string         `json:"objectId"`
	DataCipher      string         `json:"dataCipher"`
	KEMAlgorithm    string         `json:"kemAlgorithm"`
	KeyID           string         `json:"keyId"`
	KEMCiphertext   string         `json:"kemCiphertext"`
	KeyWrapNonce    string         `json:"keyWrapNonce"`
	WrappedDEK      string         `json:"wrappedDek"`
	DataNoncePrefix string         `json:"dataNoncePrefix"`
	ChunkSize       int            `json:"chunkSize"`
	PlaintextSHA256 string         `json:"plaintextSha256"`
	PlaintextSize   int64          `json:"plaintextSize"`
	CreatedAt       time.Time      `json:"createdAt"`
	RewrappedAt     time.Time      `json:"rewrappedAt,omitempty"`
	PreviousKeyID   string         `json:"previousKeyId,omitempty"`
	PreviousKEM     string         `json:"previousKem,omitempty"`
	Lineage         []RewrapRecord `json:"lineage,omitempty"`
	HeaderMAC       string         `json:"headerMac,omitempty"`
}

type DecryptPolicy struct {
	MinimumGeneration uint64
	ExpectedKeyID     string
	RejectLegacyV1    bool
}

type Recryptor struct {
	KEM       KEMBackend
	ChunkSize int

	// commitHook is intentionally unexported. It is used by process-crash tests
	// to stop at durable transaction boundaries without exposing fault injection
	// in the production CLI.
	commitHook commitHook
}

type openedEnvelope struct {
	file       *os.File
	header     EnvelopeHeader
	format     int
	bodyOffset int64
}

func (r Recryptor) EncryptFile(ctx context.Context, source, destination, publicKeyPath, keyID, kemAlgorithm string) (EnvelopeHeader, error) {
	if err := r.validate(); err != nil {
		return EnvelopeHeader{}, err
	}
	if kemAlgorithm == "" {
		kemAlgorithm = "ML-KEM-768"
	}
	if keyID == "" {
		return EnvelopeHeader{}, errors.New("key ID is required")
	}
	chunkSize, err := normalizedChunkSize(r.ChunkSize)
	if err != nil {
		return EnvelopeHeader{}, err
	}

	input, err := os.Open(source)
	if err != nil {
		return EnvelopeHeader{}, err
	}
	defer input.Close()

	directory := filepath.Dir(destination)
	if err := os.MkdirAll(directory, 0o750); err != nil {
		return EnvelopeHeader{}, err
	}
	workDir, err := os.MkdirTemp(directory, ".pqm-encrypt-")
	if err != nil {
		return EnvelopeHeader{}, err
	}
	defer os.RemoveAll(workDir)

	payloadPath := filepath.Join(workDir, "payload.bin")
	payload, err := os.OpenFile(payloadPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return EnvelopeHeader{}, err
	}

	dek := make([]byte, 32)
	if _, err := rand.Read(dek); err != nil {
		_ = payload.Close()
		return EnvelopeHeader{}, err
	}
	defer wipe(dek)
	dataGCM, err := newAESGCM(dek)
	if err != nil {
		_ = payload.Close()
		return EnvelopeHeader{}, err
	}
	noncePrefix := make([]byte, 8)
	if _, err := rand.Read(noncePrefix); err != nil {
		_ = payload.Close()
		return EnvelopeHeader{}, err
	}
	objectID := newID("object")
	hasher := sha256.New()
	plainSize, encryptErr := encryptChunks(ctx, input, payload, dataGCM, noncePrefix, objectID, hasher, chunkSize)
	if encryptErr == nil {
		encryptErr = payload.Sync()
	}
	closeErr := payload.Close()
	if encryptErr != nil {
		return EnvelopeHeader{}, encryptErr
	}
	if closeErr != nil {
		return EnvelopeHeader{}, closeErr
	}

	header := EnvelopeHeader{
		Version:         2,
		Generation:      1,
		ObjectID:        objectID,
		DataCipher:      "AES-256-GCM-CHUNKED",
		KEMAlgorithm:    kemAlgorithm,
		KeyID:           keyID,
		DataNoncePrefix: base64.StdEncoding.EncodeToString(noncePrefix),
		ChunkSize:       chunkSize,
		PlaintextSHA256: hex.EncodeToString(hasher.Sum(nil)),
		PlaintextSize:   plainSize,
		CreatedAt:       time.Now().UTC(),
	}
	if err := r.wrapDEK(ctx, &header, dek, publicKeyPath); err != nil {
		return EnvelopeHeader{}, err
	}
	if err := setHeaderMAC(&header, dek); err != nil {
		return EnvelopeHeader{}, err
	}
	if err := validateHeader(header, 2); err != nil {
		return EnvelopeHeader{}, fmt.Errorf("generated invalid envelope header: %w", err)
	}

	payload, err = os.Open(payloadPath)
	if err != nil {
		return EnvelopeHeader{}, err
	}
	defer payload.Close()
	if err := durableReplace(destination, 0o600, func(output *os.File) error {
		return writeEnvelope(output, envelopeMagicV2, header, payload)
	}, r.commitHook); err != nil {
		return EnvelopeHeader{}, err
	}
	return header, nil
}

func (r Recryptor) DecryptFile(ctx context.Context, source, destination, privateKeyPath string) (EnvelopeHeader, error) {
	return r.DecryptFileWithPolicy(ctx, source, destination, privateKeyPath, DecryptPolicy{})
}

func (r Recryptor) DecryptFileWithPolicy(ctx context.Context, source, destination, privateKeyPath string, policy DecryptPolicy) (EnvelopeHeader, error) {
	if err := r.validate(); err != nil {
		return EnvelopeHeader{}, err
	}
	envelope, err := openEnvelope(source)
	if err != nil {
		return EnvelopeHeader{}, err
	}
	defer envelope.file.Close()
	dek, err := r.unwrapDEK(ctx, envelope.header, envelope.format, privateKeyPath)
	if err != nil {
		return EnvelopeHeader{}, err
	}
	defer wipe(dek)
	if envelope.format == 2 {
		if err := verifyHeaderMAC(envelope.header, dek); err != nil {
			return EnvelopeHeader{}, err
		}
	}
	// Policies are evaluated only after cryptographic authentication. Header
	// fields such as key ID and generation are attacker-controlled until then.
	if err := enforcePolicy(envelope.header, envelope.format, policy); err != nil {
		return EnvelopeHeader{}, err
	}
	dataGCM, err := newAESGCM(dek)
	if err != nil {
		return EnvelopeHeader{}, err
	}
	noncePrefix, err := decodeFixedBase64("data nonce prefix", envelope.header.DataNoncePrefix, 8)
	if err != nil {
		return EnvelopeHeader{}, err
	}

	err = durableReplace(destination, 0o600, func(output *os.File) error {
		hasher := sha256.New()
		written, err := decryptChunks(ctx, envelope.file, output, dataGCM, noncePrefix, envelope.header.ObjectID, hasher, envelope.header.ChunkSize)
		if err != nil {
			return err
		}
		if written != envelope.header.PlaintextSize || !hmac.Equal(hasher.Sum(nil), mustDecodeHex(envelope.header.PlaintextSHA256)) {
			return fmt.Errorf("%w: plaintext size or digest mismatch", ErrAuthentication)
		}
		return nil
	}, r.commitHook)
	if err != nil {
		return EnvelopeHeader{}, err
	}
	return envelope.header, nil
}

func (r Recryptor) RewrapFile(ctx context.Context, source, destination, oldPrivateKey, newPublicKey, newKeyID, newKEM string) (EnvelopeHeader, error) {
	if err := r.validate(); err != nil {
		return EnvelopeHeader{}, err
	}
	if newKeyID == "" {
		return EnvelopeHeader{}, errors.New("new key ID is required")
	}
	if newKEM == "" {
		newKEM = "ML-KEM-768"
	}
	envelope, err := openEnvelope(source)
	if err != nil {
		return EnvelopeHeader{}, err
	}
	defer envelope.file.Close()
	dek, err := r.unwrapDEK(ctx, envelope.header, envelope.format, oldPrivateKey)
	if err != nil {
		return EnvelopeHeader{}, err
	}
	defer wipe(dek)
	if envelope.format == 2 {
		if err := verifyHeaderMAC(envelope.header, dek); err != nil {
			return EnvelopeHeader{}, err
		}
	}
	sourceDigest, err := hashOpenEnvelope(envelope.file, envelope.bodyOffset)
	if err != nil {
		return EnvelopeHeader{}, err
	}

	header := envelope.header
	if header.Generation == 0 {
		header.Generation = 1
	}
	if len(header.Lineage) >= maxLineageLength {
		return EnvelopeHeader{}, errors.New("envelope lineage limit reached")
	}
	now := time.Now().UTC()
	header.Lineage = append(append([]RewrapRecord(nil), header.Lineage...), RewrapRecord{
		Generation:     header.Generation,
		KeyID:          header.KeyID,
		KEMAlgorithm:   header.KEMAlgorithm,
		EnvelopeSHA256: sourceDigest,
		RewrappedAt:    now,
	})
	header.Version = 2
	header.Generation++
	header.PreviousKeyID = header.KeyID
	header.PreviousKEM = header.KEMAlgorithm
	header.KeyID = newKeyID
	header.KEMAlgorithm = newKEM
	header.RewrappedAt = now
	header.HeaderMAC = ""
	if err := r.wrapDEK(ctx, &header, dek, newPublicKey); err != nil {
		return EnvelopeHeader{}, err
	}
	if err := setHeaderMAC(&header, dek); err != nil {
		return EnvelopeHeader{}, err
	}
	if err := validateHeader(header, 2); err != nil {
		return EnvelopeHeader{}, fmt.Errorf("generated invalid rewrapped header: %w", err)
	}

	if err := durableReplace(destination, 0o600, func(output *os.File) error {
		return writeEnvelope(output, envelopeMagicV2, header, envelope.file)
	}, r.commitHook); err != nil {
		return EnvelopeHeader{}, err
	}
	return header, nil
}

func (r Recryptor) validate() error {
	if r.KEM == nil {
		return errors.New("KEM backend is required")
	}
	return nil
}

func (r Recryptor) wrapDEK(ctx context.Context, header *EnvelopeHeader, dek []byte, publicKeyPath string) error {
	kemCiphertext, sharedSecret, err := r.KEM.Encapsulate(ctx, publicKeyPath, header.KEMAlgorithm)
	if err != nil {
		return err
	}
	defer wipe(sharedSecret)
	if len(kemCiphertext) == 0 || len(sharedSecret) == 0 {
		return errors.New("KEM returned empty output")
	}
	kek := deriveWrapKey(sharedSecret, header.ObjectID, 2)
	defer wipe(kek)
	gcm, err := newAESGCM(kek)
	if err != nil {
		return err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	wrapped := gcm.Seal(nil, nonce, dek, wrapAAD(header.ObjectID, 2))
	header.KEMCiphertext = base64.StdEncoding.EncodeToString(kemCiphertext)
	header.KeyWrapNonce = base64.StdEncoding.EncodeToString(nonce)
	header.WrappedDEK = base64.StdEncoding.EncodeToString(wrapped)
	return nil
}

func (r Recryptor) unwrapDEK(ctx context.Context, header EnvelopeHeader, format int, privateKeyPath string) ([]byte, error) {
	kemCiphertext, err := base64.StdEncoding.DecodeString(header.KEMCiphertext)
	if err != nil || len(kemCiphertext) == 0 {
		return nil, fmt.Errorf("%w: invalid KEM ciphertext", ErrAuthentication)
	}
	secret, err := r.KEM.Decapsulate(ctx, privateKeyPath, header.KEMAlgorithm, kemCiphertext)
	if err != nil || len(secret) == 0 {
		return nil, fmt.Errorf("%w: KEM decapsulation failed", ErrAuthentication)
	}
	defer wipe(secret)
	kek := deriveWrapKey(secret, header.ObjectID, format)
	defer wipe(kek)
	gcm, err := newAESGCM(kek)
	if err != nil {
		return nil, err
	}
	nonce, err := decodeFixedBase64("key wrap nonce", header.KeyWrapNonce, gcm.NonceSize())
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrAuthentication, err)
	}
	wrapped, err := base64.StdEncoding.DecodeString(header.WrappedDEK)
	if err != nil || len(wrapped) != 32+gcm.Overhead() {
		return nil, fmt.Errorf("%w: invalid wrapped DEK", ErrAuthentication)
	}
	dek, err := gcm.Open(nil, nonce, wrapped, wrapAAD(header.ObjectID, format))
	if err != nil {
		return nil, fmt.Errorf("%w: DEK unwrap failed", ErrAuthentication)
	}
	if len(dek) != 32 {
		wipe(dek)
		return nil, fmt.Errorf("%w: invalid DEK size", ErrAuthentication)
	}
	return dek, nil
}

func deriveWrapKey(secret []byte, objectID string, format int) []byte {
	info := []byte("pqm-envelope-key-wrap-v1")
	if format == 2 {
		info = []byte("pqm-envelope-key-wrap-v2")
	}
	return hkdfSHA256(secret, []byte(objectID), info, 32)
}

func wrapAAD(objectID string, format int) []byte {
	if format == 1 {
		return []byte(objectID)
	}
	return append([]byte("pqm-envelope/dek/v2\x00"), []byte(objectID)...)
}

func setHeaderMAC(header *EnvelopeHeader, dek []byte) error {
	header.HeaderMAC = ""
	canonical, err := json.Marshal(header)
	if err != nil {
		return err
	}
	key := hkdfSHA256(dek, []byte(header.ObjectID), []byte("pqm-envelope-header-mac-v2"), 32)
	defer wipe(key)
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(canonical)
	header.HeaderMAC = base64.StdEncoding.EncodeToString(mac.Sum(nil))
	return nil
}

func verifyHeaderMAC(header EnvelopeHeader, dek []byte) error {
	actual, err := decodeFixedBase64("header MAC", header.HeaderMAC, sha256.Size)
	if err != nil {
		return fmt.Errorf("%w: invalid header MAC", ErrAuthentication)
	}
	header.HeaderMAC = ""
	canonical, err := json.Marshal(header)
	if err != nil {
		return err
	}
	key := hkdfSHA256(dek, []byte(header.ObjectID), []byte("pqm-envelope-header-mac-v2"), 32)
	defer wipe(key)
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(canonical)
	if !hmac.Equal(actual, mac.Sum(nil)) {
		return fmt.Errorf("%w: header MAC mismatch", ErrAuthentication)
	}
	return nil
}

func enforcePolicy(header EnvelopeHeader, format int, policy DecryptPolicy) error {
	if format == 1 && policy.RejectLegacyV1 {
		return fmt.Errorf("%w: legacy v1 envelope rejected", ErrPolicyViolation)
	}
	generation := header.Generation
	if generation == 0 {
		generation = 1
	}
	if generation < policy.MinimumGeneration {
		return fmt.Errorf("%w: generation %d is below required generation %d", ErrRollbackDetected, generation, policy.MinimumGeneration)
	}
	if policy.ExpectedKeyID != "" && header.KeyID != policy.ExpectedKeyID {
		return fmt.Errorf("%w: key ID %q does not match expected key ID", ErrPolicyViolation, header.KeyID)
	}
	return nil
}

func openEnvelope(path string) (openedEnvelope, error) {
	file, err := os.Open(path)
	if err != nil {
		return openedEnvelope{}, err
	}
	fail := func(err error) (openedEnvelope, error) {
		_ = file.Close()
		return openedEnvelope{}, err
	}
	var magic [8]byte
	if _, err := io.ReadFull(file, magic[:]); err != nil {
		return fail(truncationError("magic", err))
	}
	format := 0
	switch magic {
	case envelopeMagicV1:
		format = 1
	case envelopeMagicV2:
		format = 2
	default:
		return fail(errors.New("invalid envelope magic"))
	}
	var headerLength uint32
	if err := binary.Read(file, binary.BigEndian, &headerLength); err != nil {
		return fail(truncationError("header length", err))
	}
	if headerLength == 0 || headerLength > maxHeaderSize {
		return fail(errors.New("invalid envelope header length"))
	}
	headerBytes := make([]byte, headerLength)
	if _, err := io.ReadFull(file, headerBytes); err != nil {
		return fail(truncationError("header", err))
	}
	decoder := json.NewDecoder(bytes.NewReader(headerBytes))
	decoder.DisallowUnknownFields()
	var header EnvelopeHeader
	if err := decoder.Decode(&header); err != nil {
		return fail(fmt.Errorf("decode envelope header: %w", err))
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return fail(fmt.Errorf("decode envelope header: %w", err))
	}
	if err := validateHeader(header, format); err != nil {
		return fail(err)
	}
	bodyOffset, err := file.Seek(0, io.SeekCurrent)
	if err != nil {
		return fail(fmt.Errorf("locate envelope body: %w", err))
	}
	return openedEnvelope{file: file, header: header, format: format, bodyOffset: bodyOffset}, nil
}

func validateHeader(header EnvelopeHeader, format int) error {
	if header.Version != format {
		return errors.New("envelope magic and version mismatch")
	}
	if header.ObjectID == "" || len(header.ObjectID) > 256 {
		return errors.New("invalid object ID")
	}
	if header.DataCipher != "AES-256-GCM-CHUNKED" {
		return errors.New("unsupported data cipher")
	}
	if header.KEMAlgorithm == "" || len(header.KEMAlgorithm) > 128 {
		return errors.New("invalid KEM algorithm")
	}
	if header.KeyID == "" || len(header.KeyID) > 512 {
		return errors.New("invalid key ID")
	}
	if _, err := normalizedChunkSize(header.ChunkSize); err != nil {
		return err
	}
	if header.PlaintextSize < 0 {
		return errors.New("invalid plaintext size")
	}
	if len(mustDecodeHex(header.PlaintextSHA256)) != sha256.Size {
		return errors.New("invalid plaintext digest")
	}
	if _, err := decodeNonEmptyBase64("KEM ciphertext", header.KEMCiphertext); err != nil {
		return err
	}
	if _, err := decodeFixedBase64("key wrap nonce", header.KeyWrapNonce, 12); err != nil {
		return err
	}
	if _, err := decodeFixedBase64("wrapped DEK", header.WrappedDEK, 48); err != nil {
		return err
	}
	if _, err := decodeFixedBase64("data nonce prefix", header.DataNoncePrefix, 8); err != nil {
		return err
	}
	if header.CreatedAt.IsZero() {
		return errors.New("missing creation time")
	}
	if format == 2 {
		if header.Generation == 0 {
			return errors.New("missing generation")
		}
		if _, err := decodeFixedBase64("header MAC", header.HeaderMAC, sha256.Size); err != nil {
			return err
		}
		if len(header.Lineage) > maxLineageLength {
			return errors.New("envelope lineage is too long")
		}
		for i, record := range header.Lineage {
			if record.Generation == 0 || record.Generation >= header.Generation {
				return fmt.Errorf("invalid lineage generation at index %d", i)
			}
			if record.KeyID == "" || record.KEMAlgorithm == "" || len(mustDecodeHex(record.EnvelopeSHA256)) != sha256.Size || record.RewrappedAt.IsZero() {
				return fmt.Errorf("invalid lineage record at index %d", i)
			}
			if i > 0 && header.Lineage[i-1].Generation >= record.Generation {
				return errors.New("lineage generations are not strictly increasing")
			}
		}
	}
	return nil
}

func writeEnvelope(output io.Writer, magic [8]byte, header EnvelopeHeader, payload io.Reader) error {
	headerBytes, err := json.Marshal(header)
	if err != nil {
		return err
	}
	if len(headerBytes) > maxHeaderSize {
		return errors.New("envelope header is too large")
	}
	if _, err := output.Write(magic[:]); err != nil {
		return err
	}
	if err := binary.Write(output, binary.BigEndian, uint32(len(headerBytes))); err != nil {
		return err
	}
	if _, err := output.Write(headerBytes); err != nil {
		return err
	}
	_, err = io.Copy(output, payload)
	return err
}

func encryptChunks(ctx context.Context, input io.Reader, output io.Writer, gcm cipher.AEAD, noncePrefix []byte, objectID string, hasher hash.Hash, chunkSize int) (int64, error) {
	buffer := make([]byte, chunkSize)
	var total int64
	for counter := uint64(0); ; counter++ {
		if counter > math.MaxUint32 {
			return total, errors.New("encrypted payload exceeds nonce counter capacity")
		}
		if err := ctx.Err(); err != nil {
			return total, err
		}
		n, readErr := io.ReadFull(input, buffer)
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil && !errors.Is(readErr, io.ErrUnexpectedEOF) {
			return total, readErr
		}
		plain := buffer[:n]
		_, _ = hasher.Write(plain)
		total += int64(n)
		sealed := gcm.Seal(nil, chunkNonce(noncePrefix, uint32(counter)), plain, chunkAAD(objectID, uint32(counter)))
		if err := binary.Write(output, binary.BigEndian, uint32(len(sealed))); err != nil {
			return total, err
		}
		if _, err := output.Write(sealed); err != nil {
			return total, err
		}
		if errors.Is(readErr, io.ErrUnexpectedEOF) {
			break
		}
	}
	if err := binary.Write(output, binary.BigEndian, uint32(0)); err != nil {
		return total, err
	}
	return total, nil
}

func decryptChunks(ctx context.Context, input io.Reader, output io.Writer, gcm cipher.AEAD, noncePrefix []byte, objectID string, hasher hash.Hash, chunkSize int) (int64, error) {
	reader := bufio.NewReader(input)
	var total int64
	for counter := uint64(0); ; counter++ {
		if counter > math.MaxUint32 {
			return total, errors.New("encrypted payload exceeds nonce counter capacity")
		}
		if err := ctx.Err(); err != nil {
			return total, err
		}
		var length uint32
		if err := binary.Read(reader, binary.BigEndian, &length); err != nil {
			return total, truncationError("chunk length", err)
		}
		if length == 0 {
			if _, err := reader.Peek(1); err == nil {
				return total, errors.New("trailing data after encrypted payload")
			} else if !errors.Is(err, io.EOF) {
				return total, err
			}
			break
		}
		maximum := uint32(chunkSize + gcm.Overhead())
		if length < uint32(gcm.Overhead()) || length > maximum {
			return total, errors.New("invalid encrypted chunk length")
		}
		sealed := make([]byte, length)
		if _, err := io.ReadFull(reader, sealed); err != nil {
			return total, truncationError("encrypted chunk", err)
		}
		plain, err := gcm.Open(nil, chunkNonce(noncePrefix, uint32(counter)), sealed, chunkAAD(objectID, uint32(counter)))
		if err != nil {
			return total, fmt.Errorf("%w: chunk %d", ErrAuthentication, counter)
		}
		if _, err := output.Write(plain); err != nil {
			return total, err
		}
		_, _ = hasher.Write(plain)
		total += int64(len(plain))
	}
	return total, nil
}

func chunkNonce(prefix []byte, counter uint32) []byte {
	nonce := make([]byte, 12)
	copy(nonce, prefix)
	binary.BigEndian.PutUint32(nonce[8:], counter)
	return nonce
}

func chunkAAD(objectID string, counter uint32) []byte {
	out := make([]byte, len(objectID)+4)
	copy(out, objectID)
	binary.BigEndian.PutUint32(out[len(objectID):], counter)
	return out
}

func normalizedChunkSize(size int) (int, error) {
	if size == 0 {
		return defaultChunkSize, nil
	}
	if size < 4<<10 || size > maxChunkSize {
		return 0, fmt.Errorf("chunk size must be between 4096 and %d bytes", maxChunkSize)
	}
	return size, nil
}

func newAESGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func decodeFixedBase64(name, encoded string, expected int) ([]byte, error) {
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(decoded) != expected {
		return nil, fmt.Errorf("invalid %s", name)
	}
	return decoded, nil
}

func decodeNonEmptyBase64(name, encoded string) ([]byte, error) {
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(decoded) == 0 {
		return nil, fmt.Errorf("invalid %s", name)
	}
	return decoded, nil
}

func mustDecodeHex(encoded string) []byte {
	decoded, _ := hex.DecodeString(encoded)
	return decoded
}

func truncationError(component string, err error) error {
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return fmt.Errorf("%w: %s", ErrTruncated, component)
	}
	return err
}

func hashOpenEnvelope(file *os.File, bodyOffset int64) (string, error) {
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return "", fmt.Errorf("rewind envelope for hashing: %w", err)
	}
	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return "", fmt.Errorf("hash envelope: %w", err)
	}
	if _, err := file.Seek(bodyOffset, io.SeekStart); err != nil {
		return "", fmt.Errorf("restore envelope body position: %w", err)
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

func hkdfSHA256(secret, salt, info []byte, length int) []byte {
	extract := hmac.New(sha256.New, salt)
	_, _ = extract.Write(secret)
	prk := extract.Sum(nil)
	defer wipe(prk)
	result := make([]byte, 0, length)
	previous := []byte(nil)
	for counter := byte(1); len(result) < length; counter++ {
		expand := hmac.New(sha256.New, prk)
		_, _ = expand.Write(previous)
		_, _ = expand.Write(info)
		_, _ = expand.Write([]byte{counter})
		previous = expand.Sum(nil)
		remaining := length - len(result)
		if remaining > len(previous) {
			remaining = len(previous)
		}
		result = append(result, previous[:remaining]...)
	}
	wipe(previous)
	return result
}

func wipe(value []byte) {
	for i := range value {
		value[i] = 0
	}
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("trailing JSON value")
		}
		return err
	}
	return nil
}
