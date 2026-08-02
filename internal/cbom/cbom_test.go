package cbom

import (
	"regexp"
	"testing"

	"github.com/Naokibot/i_1/internal/model"
)

func TestGenerateCycloneDX17(t *testing.T) {
	bom := Generate([]model.Asset{{ID: "asset-1", Name: "service", Location: "service:443", Crypto: []model.CryptoComponent{{ID: "crypto-1", Category: "protocol", Algorithm: "TLS 1.3", Protocol: "TLS", Version: "TLS 1.3", PQCStatus: "legacy", Source: "test"}, {ID: "crypto-2", Category: "algorithm", Algorithm: "X25519MLKEM768", Primitive: "key-agreement", PQCStatus: "hybrid", Source: "test"}}}})
	if bom.BomFormat != "CycloneDX" || bom.SpecVersion != "1.7" {
		t.Fatalf("unexpected BOM header: %#v", bom)
	}
	if !regexp.MustCompile(`^urn:uuid:[0-9a-f-]{36}$`).MatchString(bom.SerialNumber) {
		t.Fatalf("invalid serial: %s", bom.SerialNumber)
	}
	if len(bom.Components) != 3 {
		t.Fatalf("expected application plus two crypto components, got %d", len(bom.Components))
	}
}
