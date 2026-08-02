package runtime

import (
	"context"
	"crypto/sha256"
	"os"
	"path/filepath"
	"testing"
)

type deterministicKEM struct{}

func (deterministicKEM) Encapsulate(_ context.Context, publicKeyPath, algorithm string) ([]byte, []byte, error) {
	ciphertext := sha256.Sum256([]byte(publicKeyPath + "|" + algorithm))
	secret := sha256.Sum256(append([]byte("secret|"), ciphertext[:]...))
	return ciphertext[:], secret[:], nil
}

func (deterministicKEM) Decapsulate(_ context.Context, privateKeyPath, algorithm string, ciphertext []byte) ([]byte, error) {
	secret := sha256.Sum256(append([]byte("secret|"), ciphertext...))
	return secret[:], nil
}

func TestEncryptDecryptAndRewrap(t *testing.T) {
	dir := t.TempDir()
	plain := filepath.Join(dir, "plain.bin")
	encrypted := filepath.Join(dir, "encrypted.pqm")
	decrypted := filepath.Join(dir, "decrypted.bin")
	rewrapped := filepath.Join(dir, "rewrapped.pqm")
	decryptedAgain := filepath.Join(dir, "decrypted-again.bin")
	content := make([]byte, 3*defaultChunkSize+137)
	for i := range content {
		content[i] = byte(i % 251)
	}
	if err := os.WriteFile(plain, content, 0o600); err != nil {
		t.Fatal(err)
	}
	recryptor := Recryptor{KEM: deterministicKEM{}}
	header, err := recryptor.EncryptFile(context.Background(), plain, encrypted, "public-a", "key-a", "ML-KEM-768")
	if err != nil {
		t.Fatal(err)
	}
	if header.PlaintextSize != int64(len(content)) {
		t.Fatalf("wrong plaintext size: %d", header.PlaintextSize)
	}
	if _, err := recryptor.DecryptFile(context.Background(), encrypted, decrypted, "private-a"); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(decrypted)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(content) {
		t.Fatal("decrypted content differs")
	}
	rewrappedHeader, err := recryptor.RewrapFile(context.Background(), encrypted, rewrapped, "private-a", "public-b", "key-b", "ML-KEM-1024")
	if err != nil {
		t.Fatal(err)
	}
	if rewrappedHeader.KeyID != "key-b" || rewrappedHeader.PreviousKeyID != "key-a" {
		t.Fatalf("rewrap history missing: %#v", rewrappedHeader)
	}
	if _, err := recryptor.DecryptFile(context.Background(), rewrapped, decryptedAgain, "private-b"); err != nil {
		t.Fatal(err)
	}
	got, err = os.ReadFile(decryptedAgain)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(content) {
		t.Fatal("rewrapped content differs")
	}
}
