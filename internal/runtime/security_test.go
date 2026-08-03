package runtime

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEmergencyDirectiveRejectsTamperingExpiryAndDuplicateApproval(t *testing.T) {
	rootPublic, rootPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	alicePublic, alicePrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	base := EmergencyDirective{
		ID:                 "security-directive",
		IssuedAt:           now.Add(-time.Minute),
		ExpiresAt:          now.Add(time.Hour),
		Severity:           "critical",
		AffectedAlgorithms: []string{"X25519MLKEM768"},
		ReplacementGroups:  []string{"SecP384r1MLKEM1024"},
	}
	signed, err := SignEmergencyDirective(rootPrivate, base)
	if err != nil {
		t.Fatal(err)
	}
	signed, err = SignEmergencyApproval(alicePrivate, "alice", signed)
	if err != nil {
		t.Fatal(err)
	}
	// Re-signing by the same approver replaces the prior entry and must not count twice.
	signed, err = SignEmergencyApproval(alicePrivate, "alice", signed)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyEmergencyDirective(rootPublic, map[string]ed25519.PublicKey{"alice": alicePublic}, signed, now); err == nil {
		t.Fatal("duplicate approval identity satisfied two-person control")
	}

	tampered := signed
	tampered.ReplacementGroups = []string{"X25519"}
	if err := VerifyEmergencyDirective(rootPublic, map[string]ed25519.PublicKey{"alice": alicePublic}, tampered, now); err == nil {
		t.Fatal("tampered directive was accepted")
	}

	expired := base
	expired.ExpiresAt = now.Add(-time.Second)
	expired, err = SignEmergencyDirective(rootPrivate, expired)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyEmergencyDirective(rootPublic, nil, expired, now); err == nil {
		t.Fatal("expired directive was accepted")
	}

	farFuture := base
	farFuture.IssuedAt = now.Add(6 * time.Minute)
	farFuture.ExpiresAt = now.Add(time.Hour)
	farFuture, err = SignEmergencyDirective(rootPrivate, farFuture)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyEmergencyDirective(rootPublic, nil, farFuture, now); err == nil {
		t.Fatal("directive issued too far in the future was accepted")
	}
}

func TestEmergencyDirectiveReplayIsRejected(t *testing.T) {
	rootPublic, rootPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	alicePublic, alicePrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	bobPublic, bobPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	store, err := OpenStateStore(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	controller := NewRolloutController(store)
	now := time.Now().UTC()
	controller.now = func() time.Time { return now }
	_, err = controller.CreateDeployment("payments", GatewayConfig{
		Revision: "r1",
		Kind:     "tls",
		Listen:   ":8443",
		Upstream: "payments:443",
		Groups:   []string{"X25519MLKEM768"},
	}, Thresholds{})
	if err != nil {
		t.Fatal(err)
	}
	directive := EmergencyDirective{
		ID:                 "one-time-directive",
		IssuedAt:           now.Add(-time.Minute),
		ExpiresAt:          now.Add(time.Hour),
		Severity:           "critical",
		AffectedAlgorithms: []string{"X25519MLKEM768"},
		ReplacementGroups:  []string{"SecP384r1MLKEM1024"},
	}
	directive, err = SignEmergencyDirective(rootPrivate, directive)
	if err != nil {
		t.Fatal(err)
	}
	directive, err = SignEmergencyApproval(alicePrivate, "alice", directive)
	if err != nil {
		t.Fatal(err)
	}
	directive, err = SignEmergencyApproval(bobPrivate, "bob", directive)
	if err != nil {
		t.Fatal(err)
	}
	approvers := map[string]ed25519.PublicKey{"alice": alicePublic, "bob": bobPublic}
	if _, err := controller.ExecuteEmergency(rootPublic, approvers, directive); err != nil {
		t.Fatalf("first execution failed: %v", err)
	}
	if _, err := controller.ExecuteEmergency(rootPublic, approvers, directive); err == nil {
		t.Fatal("replayed emergency directive was accepted")
	}
}

func TestAuditChainDetectsPersistedTampering(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	store, err := OpenStateStore(path)
	if err != nil {
		t.Fatal(err)
	}
	controller := NewRolloutController(store)
	_, err = controller.CreateDeployment("payments", GatewayConfig{
		Revision: "r1",
		Kind:     "tls",
		Listen:   ":8443",
		Upstream: "payments:443",
		Groups:   []string{"X25519MLKEM768"},
	}, Thresholds{})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.VerifyAudit(); err != nil {
		t.Fatalf("valid audit chain rejected: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	audit := raw["audit"].([]any)
	first := audit[0].(map[string]any)
	first["action"] = "deployment.delete"
	data, err = json.Marshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}

	tamperedStore, err := OpenStateStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := tamperedStore.VerifyAudit(); err == nil {
		t.Fatal("tampered audit chain was accepted")
	}
}

func TestMetricBoundaryFailuresTriggerRollback(t *testing.T) {
	thresholds := Thresholds{
		MinimumSuccessRate:  0.995,
		MaximumFallbackRate: 0.01,
		MaximumP99Ratio:     1.25,
		MinimumSamples:      100,
	}
	cases := []MetricWindow{
		{Handshakes: 99, StableP99Millis: 10, P99LatencyMillis: 10},
		{Handshakes: 1000, Failures: 6, StableP99Millis: 10, P99LatencyMillis: 10},
		{Handshakes: 1000, Fallbacks: 11, StableP99Millis: 10, P99LatencyMillis: 10},
		{Handshakes: 1000, StableP99Millis: 10, P99LatencyMillis: 13},
	}
	for i, metrics := range cases {
		if failure := evaluateMetrics(metrics, thresholds); failure == "" {
			t.Fatalf("case %d unexpectedly passed", i)
		}
	}
}
