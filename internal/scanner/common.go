package scanner

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"github.com/Naokibot/i_1/internal/model"
)

func statusFor(name string) string {
	n := strings.ToLower(name)
	if strings.Contains(n, "ml-kem") || strings.Contains(n, "mlkem") || strings.Contains(n, "ml-dsa") || strings.Contains(n, "mldsa") || strings.Contains(n, "slh-dsa") || strings.Contains(n, "slhdsa") {
		if strings.Contains(n, "x25519") || strings.Contains(n, "ecdh") || strings.Contains(n, "rsa") || strings.Contains(n, "ecdsa") {
			return "hybrid"
		}
		return "native"
	}
	if strings.Contains(n, "sntrup") && strings.Contains(n, "x25519") {
		return "hybrid"
	}
	if strings.Contains(n, "rsa") || strings.Contains(n, "ecdsa") || strings.Contains(n, "ecdh") || strings.Contains(n, "curve25519") || strings.Contains(n, "x25519") || strings.Contains(n, "diffie-hellman") || strings.Contains(n, "ssh-ed25519") || strings.Contains(n, "dsa") {
		return "legacy"
	}
	return "not-applicable"
}

func component(category, algorithm, primitive, usage, source string) model.CryptoComponent {
	return model.CryptoComponent{ID: model.NewID("crypto"), Category: category, Algorithm: algorithm, Primitive: primitive, Usage: usage, PQCStatus: statusFor(algorithm), Source: source}
}

func stableCryptoID(parts ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(parts, "|")))
	return "crypto-" + hex.EncodeToString(sum[:10])
}
