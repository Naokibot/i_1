package runtime

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type commandRunnerFunc func(context.Context, string, ...string) ([]byte, error)

func (f commandRunnerFunc) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	return f(ctx, name, args...)
}

func TestAWSKMSAdapterUsesMode0600FileAndParsesSignature(t *testing.T) {
	message := []byte("message bytes must not be command arguments")
	runner := commandRunnerFunc(func(_ context.Context, name string, args ...string) ([]byte, error) {
		if name != "aws-test" {
			t.Fatalf("binary = %q", name)
		}
		joined := strings.Join(args, " ")
		if strings.Contains(joined, string(message)) {
			t.Fatal("message was exposed in command arguments")
		}
		messageArg := argumentAfter(t, args, "--message")
		if !strings.HasPrefix(messageArg, "fileb://") {
			t.Fatalf("message argument = %q", messageArg)
		}
		path := strings.TrimPrefix(messageArg, "fileb://")
		assertPrivateFile(t, path, message)
		if got := argumentAfter(t, args, "--message-type"); got != "RAW" {
			t.Fatalf("message type = %q", got)
		}
		if got := argumentAfter(t, args, "--signing-algorithm"); got != "ML_DSA_SHAKE_256" {
			t.Fatalf("algorithm = %q", got)
		}
		payload, err := json.Marshal(map[string]string{
			"Signature": base64.StdEncoding.EncodeToString([]byte("aws-signature")),
		})
		if err != nil {
			t.Fatal(err)
		}
		return payload, nil
	})
	backend := AWSKMSBackend{Binary: "aws-test", Runner: runner}
	signature, err := backend.Sign(context.Background(), "key-id", "", message)
	if err != nil {
		t.Fatal(err)
	}
	if string(signature) != "aws-signature" {
		t.Fatalf("signature = %q", signature)
	}
}

func TestGCPKMSAdapterUsesMode0600FileAndReadsSignature(t *testing.T) {
	message := []byte("gcp-message")
	runner := commandRunnerFunc(func(_ context.Context, name string, args ...string) ([]byte, error) {
		if name != "gcloud-test" {
			t.Fatalf("binary = %q", name)
		}
		input := argumentAfter(t, args, "--input-file")
		output := argumentAfter(t, args, "--signature-file")
		assertPrivateFile(t, input, message)
		if got := argumentAfter(t, args, "--location"); got != "global" {
			t.Fatalf("location = %q", got)
		}
		if got := argumentAfter(t, args, "--digest-algorithm"); got != "sha256" {
			t.Fatalf("digest algorithm = %q", got)
		}
		encoded := base64.StdEncoding.EncodeToString([]byte("gcp-signature"))
		if err := os.WriteFile(output, []byte(encoded), 0o600); err != nil {
			t.Fatal(err)
		}
		return nil, nil
	})
	backend := GCPKMSBackend{Binary: "gcloud-test", Runner: runner}
	signature, err := backend.Sign(context.Background(), GCPKeyReference{
		Location: "global",
		Keyring:  "ring",
		Key:      "key",
		Version:  "1",
	}, "sha256", message)
	if err != nil {
		t.Fatal(err)
	}
	if string(signature) != "gcp-signature" {
		t.Fatalf("signature = %q", signature)
	}
}

func TestKMSAdaptersRejectIncompleteKeyReferences(t *testing.T) {
	if _, err := (AWSKMSBackend{}).Sign(context.Background(), "", "", nil); err == nil {
		t.Fatal("AWS KMS accepted an empty key ID")
	}
	if _, err := (GCPKMSBackend{}).Sign(context.Background(), GCPKeyReference{}, "", nil); err == nil {
		t.Fatal("GCP KMS accepted an incomplete key reference")
	}
}

func argumentAfter(t *testing.T, args []string, option string) string {
	t.Helper()
	for i := 0; i+1 < len(args); i++ {
		if args[i] == option {
			return args[i+1]
		}
	}
	t.Fatalf("missing option %s in %v", option, args)
	return ""
}

func assertPrivateFile(t *testing.T, path string, expected []byte) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("%s mode = %o", filepath.Base(path), info.Mode().Perm())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != string(expected) {
		t.Fatalf("%s content mismatch", filepath.Base(path))
	}
}
