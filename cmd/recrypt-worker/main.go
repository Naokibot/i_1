package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	runtimepkg "github.com/Naokibot/i_1/internal/runtime"
)

const defaultOperationTimeout = 2 * time.Hour

type backendOptions struct {
	openssl      string
	provider     string
	providerPath string
	timeout      time.Duration
	chunkSize    int
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		printUsage(stderr)
		return 2
	}
	if !strings.HasPrefix(args[0], "-") {
		switch args[0] {
		case "encrypt":
			return runEncrypt(args[1:], stdout, stderr)
		case "decrypt":
			return runDecrypt(args[1:], stdout, stderr)
		case "rewrap":
			return runRewrap(args[1:], stdout, stderr)
		case "recover":
			return runRecover(args[1:], stdout, stderr)
		default:
			fmt.Fprintf(stderr, "unknown command %q\n", args[0])
			printUsage(stderr)
			return 2
		}
	}
	return runLegacy(args, stdout, stderr)
}

func runEncrypt(args []string, stdout, stderr io.Writer) int {
	set := flag.NewFlagSet("encrypt", flag.ContinueOnError)
	set.SetOutput(stderr)
	var common backendOptions
	bindBackendFlags(set, &common)
	input := set.String("input", "", "plaintext input file")
	output := set.String("output", "", "envelope output file")
	publicKey := set.String("public-key", "", "KEM public key")
	keyID := set.String("key-id", "", "logical key identifier")
	algorithm := set.String("kem-algorithm", "ML-KEM-768", "KEM algorithm")
	if err := set.Parse(args); err != nil {
		return 2
	}
	if err := requireFlags(map[string]string{"input": *input, "output": *output, "public-key": *publicKey, "key-id": *keyID}); err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	header, err := withRecryptor(common, func(ctx context.Context, recryptor runtimepkg.Recryptor) (runtimepkg.EnvelopeHeader, error) {
		return recryptor.EncryptFile(ctx, *input, *output, *publicKey, *keyID, *algorithm)
	})
	return finish(header, err, stdout, stderr)
}

func runDecrypt(args []string, stdout, stderr io.Writer) int {
	set := flag.NewFlagSet("decrypt", flag.ContinueOnError)
	set.SetOutput(stderr)
	var common backendOptions
	bindBackendFlags(set, &common)
	input := set.String("input", "", "envelope input file")
	output := set.String("output", "", "plaintext output file")
	privateKey := set.String("private-key", "", "KEM private key")
	minimumGeneration := set.Uint64("minimum-generation", 0, "minimum accepted envelope generation")
	expectedKeyID := set.String("expected-key-id", "", "required logical key identifier")
	rejectLegacy := set.Bool("reject-legacy-v1", false, "reject legacy v1 envelopes")
	if err := set.Parse(args); err != nil {
		return 2
	}
	if err := requireFlags(map[string]string{"input": *input, "output": *output, "private-key": *privateKey}); err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	policy := runtimepkg.DecryptPolicy{
		MinimumGeneration: *minimumGeneration,
		ExpectedKeyID:     *expectedKeyID,
		RejectLegacyV1:    *rejectLegacy,
	}
	header, err := withRecryptor(common, func(ctx context.Context, recryptor runtimepkg.Recryptor) (runtimepkg.EnvelopeHeader, error) {
		return recryptor.DecryptFileWithPolicy(ctx, *input, *output, *privateKey, policy)
	})
	return finish(header, err, stdout, stderr)
}

func runRewrap(args []string, stdout, stderr io.Writer) int {
	set := flag.NewFlagSet("rewrap", flag.ContinueOnError)
	set.SetOutput(stderr)
	var common backendOptions
	bindBackendFlags(set, &common)
	input := set.String("input", "", "source envelope")
	output := set.String("output", "", "rewrapped envelope")
	oldPrivateKey := set.String("old-private-key", "", "current KEM private key")
	newPublicKey := set.String("new-public-key", "", "replacement KEM public key")
	newKeyID := set.String("new-key-id", "", "replacement logical key identifier")
	newAlgorithm := set.String("new-kem-algorithm", "ML-KEM-768", "replacement KEM algorithm")
	if err := set.Parse(args); err != nil {
		return 2
	}
	if err := requireFlags(map[string]string{
		"input": *input, "output": *output, "old-private-key": *oldPrivateKey,
		"new-public-key": *newPublicKey, "new-key-id": *newKeyID,
	}); err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	header, err := withRecryptor(common, func(ctx context.Context, recryptor runtimepkg.Recryptor) (runtimepkg.EnvelopeHeader, error) {
		return recryptor.RewrapFile(ctx, *input, *output, *oldPrivateKey, *newPublicKey, *newKeyID, *newAlgorithm)
	})
	return finish(header, err, stdout, stderr)
}

func runRecover(args []string, stdout, stderr io.Writer) int {
	set := flag.NewFlagSet("recover", flag.ContinueOnError)
	set.SetOutput(stderr)
	output := set.String("output", "", "destination file whose interrupted transaction should be recovered")
	if err := set.Parse(args); err != nil {
		return 2
	}
	if *output == "" {
		fmt.Fprintln(stderr, "missing required flag --output")
		return 2
	}
	if err := runtimepkg.RecoverFile(*output); err != nil {
		fmt.Fprintf(stderr, "recover: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "recovered=%s\n", *output)
	return 0
}

// runLegacy preserves the original -mode interface for existing automation.
// New integrations should use the explicit subcommands above.
func runLegacy(args []string, stdout, stderr io.Writer) int {
	set := flag.NewFlagSet("legacy", flag.ContinueOnError)
	set.SetOutput(stderr)
	var common backendOptions
	bindBackendFlags(set, &common)
	mode := set.String("mode", "", "encrypt, decrypt, rewrap, or recover")
	source := set.String("source", "", "source file")
	destination := set.String("destination", "", "destination file")
	publicKey := set.String("public-key", "", "KEM public key")
	privateKey := set.String("private-key", "", "KEM private key")
	keyID := set.String("key-id", "", "logical target key identifier")
	algorithm := "ML-KEM-768"
	set.StringVar(&algorithm, "kem", algorithm, "KEM algorithm")
	set.StringVar(&algorithm, "algorithm", algorithm, "deprecated alias for -kem")
	minimumGeneration := set.Uint64("minimum-generation", 0, "minimum accepted envelope generation")
	if err := set.Parse(args); err != nil {
		return 2
	}
	if *mode == "recover" {
		if *destination == "" {
			fmt.Fprintln(stderr, "missing required flag -destination")
			return 2
		}
		if err := runtimepkg.RecoverFile(*destination); err != nil {
			fmt.Fprintf(stderr, "recover: %v\n", err)
			return 1
		}
		fmt.Fprintf(stdout, "recovered=%s\n", *destination)
		return 0
	}
	if *source == "" || *destination == "" {
		fmt.Fprintln(stderr, "-source and -destination are required")
		return 2
	}
	header, err := withRecryptor(common, func(ctx context.Context, recryptor runtimepkg.Recryptor) (runtimepkg.EnvelopeHeader, error) {
		switch *mode {
		case "encrypt":
			return recryptor.EncryptFile(ctx, *source, *destination, *publicKey, *keyID, algorithm)
		case "decrypt":
			return recryptor.DecryptFileWithPolicy(ctx, *source, *destination, *privateKey, runtimepkg.DecryptPolicy{MinimumGeneration: *minimumGeneration})
		case "rewrap":
			return recryptor.RewrapFile(ctx, *source, *destination, *privateKey, *publicKey, *keyID, algorithm)
		default:
			return runtimepkg.EnvelopeHeader{}, errors.New("-mode must be encrypt, decrypt, rewrap, or recover")
		}
	})
	return finish(header, err, stdout, stderr)
}

func bindBackendFlags(set *flag.FlagSet, options *backendOptions) {
	set.StringVar(&options.openssl, "openssl", "openssl", "OpenSSL 3.5 binary")
	set.StringVar(&options.provider, "provider", "default", "OpenSSL provider")
	set.StringVar(&options.providerPath, "provider-path", "", "OpenSSL provider module path")
	set.DurationVar(&options.timeout, "timeout", defaultOperationTimeout, "operation timeout")
	set.IntVar(&options.chunkSize, "chunk-size", 0, "plaintext chunk size in bytes (0 uses the secure default)")
}

func withRecryptor(options backendOptions, operation func(context.Context, runtimepkg.Recryptor) (runtimepkg.EnvelopeHeader, error)) (runtimepkg.EnvelopeHeader, error) {
	backend := runtimepkg.NewOpenSSLBackend()
	backend.Binary = options.openssl
	backend.Provider = options.provider
	backend.ProviderPath = options.providerPath
	recryptor := runtimepkg.Recryptor{KEM: backend, ChunkSize: options.chunkSize}
	ctx, cancel := context.WithTimeout(context.Background(), options.timeout)
	defer cancel()
	return operation(ctx, recryptor)
}

func requireFlags(values map[string]string) error {
	missing := make([]string, 0)
	for name, value := range values {
		if strings.TrimSpace(value) == "" {
			missing = append(missing, "--"+name)
		}
	}
	if len(missing) == 0 {
		return nil
	}
	sort.Strings(missing)
	return fmt.Errorf("missing required flags: %s", strings.Join(missing, ", "))
}

func finish(header runtimepkg.EnvelopeHeader, err error, stdout, stderr io.Writer) int {
	if err != nil {
		fmt.Fprintf(stderr, "recrypt: %v\n", err)
		return 1
	}
	fmt.Fprintf(
		stdout,
		"object=%s generation=%d key=%s kem=%s plaintext_sha256=%s bytes=%d\n",
		header.ObjectID, header.Generation, header.KeyID, header.KEMAlgorithm,
		header.PlaintextSHA256, header.PlaintextSize,
	)
	return 0
}

func printUsage(output io.Writer) {
	fmt.Fprintln(output, "usage: recrypt-worker <encrypt|decrypt|rewrap|recover> [options]")
	fmt.Fprintln(output, "       recrypt-worker -mode <encrypt|decrypt|rewrap|recover> [legacy options]")
}
