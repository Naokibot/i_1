package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	runtimepkg "github.com/Naokibot/i_1/internal/runtime"
)

func main() {
	var (
		mode         = flag.String("mode", "", "encrypt, decrypt, or rewrap")
		source       = flag.String("source", "", "source file")
		destination  = flag.String("destination", "", "destination file")
		publicKey    = flag.String("public-key", "", "ML-KEM public key for encrypt/rewrap")
		privateKey   = flag.String("private-key", "", "ML-KEM private key for decrypt/rewrap")
		keyID        = flag.String("key-id", "", "logical target key identifier")
		algorithm    = flag.String("algorithm", "ML-KEM-768", "ML-KEM algorithm")
		openssl      = flag.String("openssl", "openssl", "OpenSSL 3.5 binary")
		provider     = flag.String("provider", "default", "OpenSSL provider")
		providerPath = flag.String("provider-path", "", "OpenSSL provider module path")
		timeout      = flag.Duration("timeout", 2*time.Hour, "operation timeout")
	)
	flag.Parse()
	if *source == "" || *destination == "" {
		flag.Usage()
		os.Exit(2)
	}
	backend := runtimepkg.NewOpenSSLBackend()
	backend.Binary = *openssl
	backend.Provider = *provider
	backend.ProviderPath = *providerPath
	recryptor := runtimepkg.Recryptor{KEM: backend}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	var (
		header runtimepkg.EnvelopeHeader
		err    error
	)
	switch *mode {
	case "encrypt":
		header, err = recryptor.EncryptFile(ctx, *source, *destination, *publicKey, *keyID, *algorithm)
	case "decrypt":
		header, err = recryptor.DecryptFile(ctx, *source, *destination, *privateKey)
	case "rewrap":
		header, err = recryptor.RewrapFile(ctx, *source, *destination, *privateKey, *publicKey, *keyID, *algorithm)
	default:
		err = fmt.Errorf("mode must be encrypt, decrypt, or rewrap")
	}
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("object=%s key=%s kem=%s plaintext_sha256=%s bytes=%d\n", header.ObjectID, header.KeyID, header.KEMAlgorithm, header.PlaintextSHA256, header.PlaintextSize)
}
