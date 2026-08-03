package runtime

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type CommandRunner interface {
	Run(ctx context.Context, name string, args ...string) ([]byte, error)
}

type ExecRunner struct{}

func (ExecRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return stdout.Bytes(), nil
}

type KEMBackend interface {
	Encapsulate(ctx context.Context, publicKeyPath, algorithm string) (ciphertext, secret []byte, err error)
	Decapsulate(ctx context.Context, privateKeyPath, algorithm string, ciphertext []byte) (secret []byte, err error)
}

type OpenSSLBackend struct {
	Binary       string
	Provider     string
	ProviderPath string
	Runner       CommandRunner
}

func NewOpenSSLBackend() *OpenSSLBackend {
	return &OpenSSLBackend{Binary: "openssl", Provider: "default", Runner: ExecRunner{}}
}

func (b *OpenSSLBackend) providerArgs() []string {
	args := []string{}
	if b.ProviderPath != "" {
		args = append(args, "-provider-path", b.ProviderPath)
	}
	if b.Provider != "" {
		args = append(args, "-provider", b.Provider)
	}
	return args
}

func (b *OpenSSLBackend) GenerateKEMKeyPair(ctx context.Context, algorithm, privateKeyPath, publicKeyPath string) error {
	if algorithm == "" {
		algorithm = "ML-KEM-768"
	}
	if err := os.MkdirAll(filepath.Dir(privateKeyPath), 0o700); err != nil {
		return err
	}
	args := []string{"genpkey", "-algorithm", algorithm, "-out", privateKeyPath}
	args = append(args, b.providerArgs()...)
	if _, err := b.runner().Run(ctx, b.binary(), args...); err != nil {
		return err
	}
	if err := os.Chmod(privateKeyPath, 0o600); err != nil {
		return err
	}
	args = []string{"pkey", "-in", privateKeyPath, "-pubout", "-out", publicKeyPath}
	args = append(args, b.providerArgs()...)
	_, err := b.runner().Run(ctx, b.binary(), args...)
	return err
}

func (b *OpenSSLBackend) Encapsulate(ctx context.Context, publicKeyPath, algorithm string) ([]byte, []byte, error) {
	if publicKeyPath == "" {
		return nil, nil, errors.New("public key path is required")
	}
	dir, err := os.MkdirTemp("", "pqm-encap-")
	if err != nil {
		return nil, nil, err
	}
	defer os.RemoveAll(dir)
	ciphertextPath := filepath.Join(dir, "ciphertext.bin")
	secretPath := filepath.Join(dir, "secret.bin")
	args := []string{"pkeyutl", "-encap", "-inkey", publicKeyPath, "-pubin", "-out", ciphertextPath, "-secret", secretPath}
	args = append(args, b.providerArgs()...)
	if _, err := b.runner().Run(ctx, b.binary(), args...); err != nil {
		return nil, nil, err
	}
	ciphertext, err := os.ReadFile(ciphertextPath)
	if err != nil {
		return nil, nil, err
	}
	secret, err := os.ReadFile(secretPath)
	if err != nil {
		return nil, nil, err
	}
	return ciphertext, secret, nil
}

func (b *OpenSSLBackend) Decapsulate(ctx context.Context, privateKeyPath, algorithm string, ciphertext []byte) ([]byte, error) {
	if privateKeyPath == "" {
		return nil, errors.New("private key path is required")
	}
	dir, err := os.MkdirTemp("", "pqm-decap-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	ciphertextPath := filepath.Join(dir, "ciphertext.bin")
	secretPath := filepath.Join(dir, "secret.bin")
	if err := os.WriteFile(ciphertextPath, ciphertext, 0o600); err != nil {
		return nil, err
	}
	args := []string{"pkeyutl", "-decap", "-inkey", privateKeyPath, "-in", ciphertextPath, "-secret", secretPath}
	args = append(args, b.providerArgs()...)
	if _, err := b.runner().Run(ctx, b.binary(), args...); err != nil {
		return nil, err
	}
	return os.ReadFile(secretPath)
}

func (b *OpenSSLBackend) Sign(ctx context.Context, privateKeyPath string, message []byte) ([]byte, error) {
	dir, err := os.MkdirTemp("", "pqm-sign-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	inputPath := filepath.Join(dir, "message.bin")
	signaturePath := filepath.Join(dir, "signature.bin")
	if err := os.WriteFile(inputPath, message, 0o600); err != nil {
		return nil, err
	}
	args := []string{"pkeyutl", "-sign", "-rawin", "-inkey", privateKeyPath, "-in", inputPath, "-out", signaturePath}
	args = append(args, b.providerArgs()...)
	if _, err := b.runner().Run(ctx, b.binary(), args...); err != nil {
		return nil, err
	}
	return os.ReadFile(signaturePath)
}

func (b *OpenSSLBackend) Verify(ctx context.Context, publicKeyPath string, message, signature []byte) error {
	dir, err := os.MkdirTemp("", "pqm-verify-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	inputPath := filepath.Join(dir, "message.bin")
	signaturePath := filepath.Join(dir, "signature.bin")
	if err := os.WriteFile(inputPath, message, 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(signaturePath, signature, 0o600); err != nil {
		return err
	}
	args := []string{"pkeyutl", "-verify", "-rawin", "-pubin", "-inkey", publicKeyPath, "-in", inputPath, "-sigfile", signaturePath}
	args = append(args, b.providerArgs()...)
	_, err = b.runner().Run(ctx, b.binary(), args...)
	return err
}

func (b *OpenSSLBackend) binary() string {
	if b.Binary == "" {
		return "openssl"
	}
	return b.Binary
}

func (b *OpenSSLBackend) runner() CommandRunner {
	if b.Runner == nil {
		return ExecRunner{}
	}
	return b.Runner
}

type AWSKMSBackend struct {
	Binary string
	Runner CommandRunner
}

func (b AWSKMSBackend) Sign(ctx context.Context, keyID, algorithm string, message []byte) ([]byte, error) {
	if keyID == "" {
		return nil, errors.New("AWS KMS key ID is required")
	}
	if algorithm == "" {
		algorithm = "ML_DSA_SHAKE_256"
	}
	dir, err := os.MkdirTemp("", "pqm-aws-kms-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	messagePath := filepath.Join(dir, "message.bin")
	if err := os.WriteFile(messagePath, message, 0o600); err != nil {
		return nil, err
	}
	binary := b.Binary
	if binary == "" {
		binary = "aws"
	}
	runner := b.Runner
	if runner == nil {
		runner = ExecRunner{}
	}
	out, err := runner.Run(ctx, binary, "kms", "sign", "--key-id", keyID, "--message", "fileb://"+messagePath, "--message-type", "RAW", "--signing-algorithm", algorithm, "--output", "json")
	if err != nil {
		return nil, err
	}
	var response struct {
		Signature string `json:"Signature"`
	}
	if err := json.Unmarshal(out, &response); err != nil {
		return nil, fmt.Errorf("decode AWS KMS response: %w", err)
	}
	return base64.StdEncoding.DecodeString(response.Signature)
}

type GCPKMSBackend struct {
	Binary string
	Runner CommandRunner
}

type GCPKeyReference struct {
	Location string
	Keyring  string
	Key      string
	Version  string
}

func (b GCPKMSBackend) Sign(ctx context.Context, ref GCPKeyReference, digestAlgorithm string, message []byte) ([]byte, error) {
	if ref.Location == "" || ref.Keyring == "" || ref.Key == "" || ref.Version == "" {
		return nil, errors.New("complete GCP KMS key reference is required")
	}
	dir, err := os.MkdirTemp("", "pqm-gcp-kms-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	inputPath := filepath.Join(dir, "message.bin")
	signaturePath := filepath.Join(dir, "signature.b64")
	if err := os.WriteFile(inputPath, message, 0o600); err != nil {
		return nil, err
	}
	binary := b.Binary
	if binary == "" {
		binary = "gcloud"
	}
	runner := b.Runner
	if runner == nil {
		runner = ExecRunner{}
	}
	args := []string{"kms", "asymmetric-sign", "--location", ref.Location, "--keyring", ref.Keyring, "--key", ref.Key, "--version", ref.Version, "--input-file", inputPath, "--signature-file", signaturePath}
	if digestAlgorithm != "" {
		args = append(args, "--digest-algorithm", digestAlgorithm)
	}
	if _, err := runner.Run(ctx, binary, args...); err != nil {
		return nil, err
	}
	encoded, err := os.ReadFile(signaturePath)
	if err != nil {
		return nil, err
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(encoded)))
	if err == nil {
		return decoded, nil
	}
	return encoded, nil
}
