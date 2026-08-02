package runtime

import (
	"bufio"
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
	"os"
	"path/filepath"
	"time"
)

var envelopeMagic = [8]byte{'P', 'Q', 'M', 'E', 'N', 'C', '0', '1'}

const defaultChunkSize = 1 << 20

type EnvelopeHeader struct {
	Version         int       `json:"version"`
	ObjectID        string    `json:"objectId"`
	DataCipher      string    `json:"dataCipher"`
	KEMAlgorithm    string    `json:"kemAlgorithm"`
	KeyID           string    `json:"keyId"`
	KEMCiphertext   string    `json:"kemCiphertext"`
	KeyWrapNonce    string    `json:"keyWrapNonce"`
	WrappedDEK      string    `json:"wrappedDek"`
	DataNoncePrefix string    `json:"dataNoncePrefix"`
	ChunkSize       int       `json:"chunkSize"`
	PlaintextSHA256 string    `json:"plaintextSha256"`
	PlaintextSize   int64     `json:"plaintextSize"`
	CreatedAt       time.Time `json:"createdAt"`
	RewrappedAt     time.Time `json:"rewrappedAt,omitempty"`
	PreviousKeyID   string    `json:"previousKeyId,omitempty"`
	PreviousKEM     string    `json:"previousKem,omitempty"`
}

type Recryptor struct {
	KEM KEMBackend
}

func (r Recryptor) EncryptFile(ctx context.Context, source, destination, publicKeyPath, keyID, kemAlgorithm string) (EnvelopeHeader, error) {
	if r.KEM == nil {
		return EnvelopeHeader{}, errors.New("KEM backend is required")
	}
	if kemAlgorithm == "" {
		kemAlgorithm = "ML-KEM-768"
	}
	input, err := os.Open(source)
	if err != nil {
		return EnvelopeHeader{}, err
	}
	defer input.Close()
	if err := os.MkdirAll(filepath.Dir(destination), 0o750); err != nil {
		return EnvelopeHeader{}, err
	}
	workDir, err := os.MkdirTemp(filepath.Dir(destination), ".pqm-encrypt-")
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
	block, err := aes.NewCipher(dek)
	if err != nil {
		_ = payload.Close()
		return EnvelopeHeader{}, err
	}
	gcm, err := cipher.NewGCM(block)
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
	plainSize, err := encryptChunks(ctx, input, payload, gcm, noncePrefix, objectID, hasher, defaultChunkSize)
	closeErr := payload.Close()
	if err != nil {
		return EnvelopeHeader{}, err
	}
	if closeErr != nil {
		return EnvelopeHeader{}, closeErr
	}

	kemCiphertext, sharedSecret, err := r.KEM.Encapsulate(ctx, publicKeyPath, kemAlgorithm)
	if err != nil {
		return EnvelopeHeader{}, err
	}
	defer wipe(sharedSecret)
	kek := hkdfSHA256(sharedSecret, []byte(objectID), []byte("pqm-envelope-key-wrap-v1"), 32)
	defer wipe(kek)
	wrapBlock, err := aes.NewCipher(kek)
	if err != nil {
		return EnvelopeHeader{}, err
	}
	wrapGCM, err := cipher.NewGCM(wrapBlock)
	if err != nil {
		return EnvelopeHeader{}, err
	}
	wrapNonce := make([]byte, wrapGCM.NonceSize())
	if _, err := rand.Read(wrapNonce); err != nil {
		return EnvelopeHeader{}, err
	}
	wrappedDEK := wrapGCM.Seal(nil, wrapNonce, dek, []byte(objectID))
	header := EnvelopeHeader{
		Version:         1,
		ObjectID:        objectID,
		DataCipher:      "AES-256-GCM-CHUNKED",
		KEMAlgorithm:    kemAlgorithm,
		KeyID:           keyID,
		KEMCiphertext:   base64.StdEncoding.EncodeToString(kemCiphertext),
		KeyWrapNonce:    base64.StdEncoding.EncodeToString(wrapNonce),
		WrappedDEK:      base64.StdEncoding.EncodeToString(wrappedDEK),
		DataNoncePrefix: base64.StdEncoding.EncodeToString(noncePrefix),
		ChunkSize:       defaultChunkSize,
		PlaintextSHA256: hex.EncodeToString(hasher.Sum(nil)),
		PlaintextSize:   plainSize,
		CreatedAt:       time.Now().UTC(),
	}
	if err := writeEnvelope(destination, header, payloadPath); err != nil {
		return EnvelopeHeader{}, err
	}
	return header, nil
}

func (r Recryptor) DecryptFile(ctx context.Context, source, destination, privateKeyPath string) (EnvelopeHeader, error) {
	if r.KEM == nil {
		return EnvelopeHeader{}, errors.New("KEM backend is required")
	}
	input, header, err := openEnvelope(source)
	if err != nil {
		return EnvelopeHeader{}, err
	}
	defer input.Close()
	dek, err := r.unwrapDEK(ctx, header, privateKeyPath)
	if err != nil {
		return EnvelopeHeader{}, err
	}
	defer wipe(dek)
	block, err := aes.NewCipher(dek)
	if err != nil {
		return EnvelopeHeader{}, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return EnvelopeHeader{}, err
	}
	noncePrefix, err := base64.StdEncoding.DecodeString(header.DataNoncePrefix)
	if err != nil || len(noncePrefix) != 8 {
		return EnvelopeHeader{}, errors.New("invalid data nonce prefix")
	}
	if err := os.MkdirAll(filepath.Dir(destination), 0o750); err != nil {
		return EnvelopeHeader{}, err
	}
	tmp := destination + ".tmp"
	output, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return EnvelopeHeader{}, err
	}
	hasher := sha256.New()
	written, decryptErr := decryptChunks(ctx, input, output, gcm, noncePrefix, header.ObjectID, hasher)
	closeErr := output.Close()
	if decryptErr != nil {
		_ = os.Remove(tmp)
		return EnvelopeHeader{}, decryptErr
	}
	if closeErr != nil {
		_ = os.Remove(tmp)
		return EnvelopeHeader{}, closeErr
	}
	if written != header.PlaintextSize || hex.EncodeToString(hasher.Sum(nil)) != header.PlaintextSHA256 {
		_ = os.Remove(tmp)
		return EnvelopeHeader{}, errors.New("plaintext integrity verification failed")
	}
	if err := os.Rename(tmp, destination); err != nil {
		_ = os.Remove(tmp)
		return EnvelopeHeader{}, err
	}
	return header, nil
}

func (r Recryptor) RewrapFile(ctx context.Context, source, destination, oldPrivateKey, newPublicKey, newKeyID, newKEM string) (EnvelopeHeader, error) {
	if r.KEM == nil {
		return EnvelopeHeader{}, errors.New("KEM backend is required")
	}
	input, header, err := openEnvelope(source)
	if err != nil {
		return EnvelopeHeader{}, err
	}
	defer input.Close()
	dek, err := r.unwrapDEK(ctx, header, oldPrivateKey)
	if err != nil {
		return EnvelopeHeader{}, err
	}
	defer wipe(dek)
	if newKEM == "" {
		newKEM = "ML-KEM-768"
	}
	kemCiphertext, sharedSecret, err := r.KEM.Encapsulate(ctx, newPublicKey, newKEM)
	if err != nil {
		return EnvelopeHeader{}, err
	}
	defer wipe(sharedSecret)
	kek := hkdfSHA256(sharedSecret, []byte(header.ObjectID), []byte("pqm-envelope-key-wrap-v1"), 32)
	defer wipe(kek)
	block, err := aes.NewCipher(kek)
	if err != nil {
		return EnvelopeHeader{}, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return EnvelopeHeader{}, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return EnvelopeHeader{}, err
	}
	wrapped := gcm.Seal(nil, nonce, dek, []byte(header.ObjectID))
	header.PreviousKeyID = header.KeyID
	header.PreviousKEM = header.KEMAlgorithm
	header.KeyID = newKeyID
	header.KEMAlgorithm = newKEM
	header.KEMCiphertext = base64.StdEncoding.EncodeToString(kemCiphertext)
	header.KeyWrapNonce = base64.StdEncoding.EncodeToString(nonce)
	header.WrappedDEK = base64.StdEncoding.EncodeToString(wrapped)
	header.RewrappedAt = time.Now().UTC()
	if err := copyEnvelopePayload(destination, header, input); err != nil {
		return EnvelopeHeader{}, err
	}
	return header, nil
}

func (r Recryptor) unwrapDEK(ctx context.Context, header EnvelopeHeader, privateKeyPath string) ([]byte, error) {
	kemCiphertext, err := base64.StdEncoding.DecodeString(header.KEMCiphertext)
	if err != nil {
		return nil, fmt.Errorf("decode KEM ciphertext: %w", err)
	}
	secret, err := r.KEM.Decapsulate(ctx, privateKeyPath, header.KEMAlgorithm, kemCiphertext)
	if err != nil {
		return nil, err
	}
	defer wipe(secret)
	kek := hkdfSHA256(secret, []byte(header.ObjectID), []byte("pqm-envelope-key-wrap-v1"), 32)
	defer wipe(kek)
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce, err := base64.StdEncoding.DecodeString(header.KeyWrapNonce)
	if err != nil {
		return nil, fmt.Errorf("decode key wrap nonce: %w", err)
	}
	wrapped, err := base64.StdEncoding.DecodeString(header.WrappedDEK)
	if err != nil {
		return nil, fmt.Errorf("decode wrapped DEK: %w", err)
	}
	dek, err := gcm.Open(nil, nonce, wrapped, []byte(header.ObjectID))
	if err != nil {
		return nil, errors.New("DEK unwrap failed")
	}
	if len(dek) != 32 {
		wipe(dek)
		return nil, errors.New("invalid DEK size")
	}
	return dek, nil
}

func encryptChunks(ctx context.Context, input io.Reader, output io.Writer, gcm cipher.AEAD, noncePrefix []byte, objectID string, hasher hash.Hash, chunkSize int) (int64, error) {
	buffer := make([]byte, chunkSize)
	var total int64
	for counter := uint32(0); ; counter++ {
		if err := ctx.Err(); err != nil {
			return total, err
		}
		n, err := io.ReadFull(input, buffer)
		if err == io.EOF {
			break
		}
		if err != nil && err != io.ErrUnexpectedEOF {
			return total, err
		}
		plain := buffer[:n]
		_, _ = hasher.Write(plain)
		total += int64(n)
		nonce := chunkNonce(noncePrefix, counter)
		aad := chunkAAD(objectID, counter)
		sealed := gcm.Seal(nil, nonce, plain, aad)
		if err := binary.Write(output, binary.BigEndian, uint32(len(sealed))); err != nil {
			return total, err
		}
		if _, err := output.Write(sealed); err != nil {
			return total, err
		}
		if err == io.ErrUnexpectedEOF {
			break
		}
	}
	if err := binary.Write(output, binary.BigEndian, uint32(0)); err != nil {
		return total, err
	}
	return total, nil
}

func decryptChunks(ctx context.Context, input io.Reader, output io.Writer, gcm cipher.AEAD, noncePrefix []byte, objectID string, hasher hash.Hash) (int64, error) {
	reader := bufio.NewReader(input)
	var total int64
	for counter := uint32(0); ; counter++ {
		if err := ctx.Err(); err != nil {
			return total, err
		}
		var length uint32
		if err := binary.Read(reader, binary.BigEndian, &length); err != nil {
			return total, err
		}
		if length == 0 {
			break
		}
		if length > 64<<20 {
			return total, errors.New("encrypted chunk is too large")
		}
		sealed := make([]byte, length)
		if _, err := io.ReadFull(reader, sealed); err != nil {
			return total, err
		}
		plain, err := gcm.Open(nil, chunkNonce(noncePrefix, counter), sealed, chunkAAD(objectID, counter))
		if err != nil {
			return total, fmt.Errorf("decrypt chunk %d: authentication failed", counter)
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

func writeEnvelope(destination string, header EnvelopeHeader, payloadPath string) error {
	payload, err := os.Open(payloadPath)
	if err != nil {
		return err
	}
	defer payload.Close()
	return writeEnvelopeFromReader(destination, header, payload)
}

func copyEnvelopePayload(destination string, header EnvelopeHeader, payload io.Reader) error {
	return writeEnvelopeFromReader(destination, header, payload)
}

func writeEnvelopeFromReader(destination string, header EnvelopeHeader, payload io.Reader) error {
	headerBytes, err := json.Marshal(header)
	if err != nil {
		return err
	}
	if len(headerBytes) > 4<<20 {
		return errors.New("envelope header is too large")
	}
	tmp := destination + ".tmp"
	output, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		_ = output.Close()
		if !ok {
			_ = os.Remove(tmp)
		}
	}()
	if _, err := output.Write(envelopeMagic[:]); err != nil {
		return err
	}
	if err := binary.Write(output, binary.BigEndian, uint32(len(headerBytes))); err != nil {
		return err
	}
	if _, err := output.Write(headerBytes); err != nil {
		return err
	}
	if _, err := io.Copy(output, payload); err != nil {
		return err
	}
	if err := output.Sync(); err != nil {
		return err
	}
	if err := output.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, destination); err != nil {
		return err
	}
	ok = true
	return nil
}

func openEnvelope(path string) (*os.File, EnvelopeHeader, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, EnvelopeHeader{}, err
	}
	var magic [8]byte
	if _, err := io.ReadFull(file, magic[:]); err != nil {
		_ = file.Close()
		return nil, EnvelopeHeader{}, err
	}
	if magic != envelopeMagic {
		_ = file.Close()
		return nil, EnvelopeHeader{}, errors.New("not a PQM envelope")
	}
	var headerLength uint32
	if err := binary.Read(file, binary.BigEndian, &headerLength); err != nil {
		_ = file.Close()
		return nil, EnvelopeHeader{}, err
	}
	if headerLength == 0 || headerLength > 4<<20 {
		_ = file.Close()
		return nil, EnvelopeHeader{}, errors.New("invalid envelope header length")
	}
	headerBytes := make([]byte, headerLength)
	if _, err := io.ReadFull(file, headerBytes); err != nil {
		_ = file.Close()
		return nil, EnvelopeHeader{}, err
	}
	var header EnvelopeHeader
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		_ = file.Close()
		return nil, EnvelopeHeader{}, fmt.Errorf("decode envelope header: %w", err)
	}
	if header.Version != 1 || header.DataCipher != "AES-256-GCM-CHUNKED" {
		_ = file.Close()
		return nil, EnvelopeHeader{}, errors.New("unsupported envelope format")
	}
	return file, header, nil
}

func hkdfSHA256(secret, salt, info []byte, length int) []byte {
	extract := hmac.New(sha256.New, salt)
	_, _ = extract.Write(secret)
	prk := extract.Sum(nil)
	defer wipe(prk)
	out := make([]byte, 0, length)
	var previous []byte
	for counter := byte(1); len(out) < length; counter++ {
		expand := hmac.New(sha256.New, prk)
		_, _ = expand.Write(previous)
		_, _ = expand.Write(info)
		_, _ = expand.Write([]byte{counter})
		previous = expand.Sum(nil)
		out = append(out, previous...)
	}
	return out[:length]
}

func wipe(data []byte) {
	for i := range data {
		data[i] = 0
	}
}
