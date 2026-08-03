package scanner

import "testing"

func TestStatusFor(t *testing.T) {
	cases := map[string]string{"RSA": "legacy", "X25519MLKEM768": "hybrid", "ML-DSA-65": "native", "AES-256-GCM": "not-applicable"}
	for in, want := range cases {
		if got := statusFor(in); got != want {
			t.Fatalf("%s: got %s want %s", in, got, want)
		}
	}
}
