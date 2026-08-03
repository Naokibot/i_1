package scanner

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/Naokibot/i_1/internal/model"
)

func TestSourceScanFindsLegacyCrypto(t *testing.T) {
	root := t.TempDir()
	project := filepath.Join(root, "project")
	if err := os.Mkdir(project, 0o755); err != nil {
		t.Fatal(err)
	}
	code := `class A { void f() throws Exception { java.security.KeyPairGenerator.getInstance("RSA"); javax.crypto.Cipher.getInstance("RSA/ECB/PKCS1Padding"); } }`
	if err := os.WriteFile(filepath.Join(project, "A.java"), []byte(code), 0o600); err != nil {
		t.Fatal(err)
	}
	asset, findings, err := ScanSource(context.Background(), model.ScanRequest{Kind: "source", Target: "project"}, root)
	if err != nil {
		t.Fatal(err)
	}
	if len(asset.Crypto) < 2 || len(findings) < 2 {
		t.Fatalf("expected multiple discoveries, crypto=%d findings=%d", len(asset.Crypto), len(findings))
	}
}
