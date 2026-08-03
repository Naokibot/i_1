package runtime

import (
	"crypto/ed25519"
	"crypto/rand"
	"path/filepath"
	"testing"
	"time"
)

func TestRolloutAdvancesAndRollsBack(t *testing.T) {
	store, err := OpenStateStore(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	controller := NewRolloutController(store)
	stable := GatewayConfig{Revision: "r1", Kind: "tls", Listen: ":8443", Upstream: "service:443", Groups: []string{"X25519"}}
	deployment, err := controller.CreateDeployment("payments", stable, Thresholds{MinimumSamples: 10})
	if err != nil {
		t.Fatal(err)
	}
	candidate := stable
	candidate.Revision = "r2"
	candidate.Groups = []string{"X25519MLKEM768", "X25519"}
	deployment, err = controller.SetCandidate(deployment.ID, candidate)
	if err != nil {
		t.Fatal(err)
	}
	good := MetricWindow{Handshakes: 1000, Failures: 1, Fallbacks: 1, P99LatencyMillis: 11, StableP99Millis: 10}
	for deployment.State != RolloutFull {
		deployment, err = controller.Advance(deployment.ID, good)
		if err != nil {
			t.Fatal(err)
		}
	}
	if deployment.Stable.Revision != "r2" {
		t.Fatalf("candidate was not promoted: %#v", deployment)
	}

	candidate.Revision = "r3"
	deployment, err = controller.SetCandidate(deployment.ID, candidate)
	if err != nil {
		t.Fatal(err)
	}
	bad := MetricWindow{Handshakes: 1000, Failures: 100, Fallbacks: 100, P99LatencyMillis: 30, StableP99Millis: 10}
	deployment, err = controller.Advance(deployment.ID, bad)
	if err != nil {
		t.Fatal(err)
	}
	if deployment.State != RolloutRolledBack || deployment.Stable.Revision != "r2" {
		t.Fatalf("expected rollback to r2, got %#v", deployment)
	}
}

func TestEmergencyDirectiveSignatureAndExecution(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
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
	deployment, err := controller.CreateDeployment("api", GatewayConfig{Revision: "r1", Kind: "tls", Listen: ":8443", Upstream: "api:443", Groups: []string{"X25519MLKEM768", "X25519"}}, Thresholds{})
	if err != nil {
		t.Fatal(err)
	}
	directive := EmergencyDirective{
		ID:                 "emergency-1",
		IssuedAt:           now.Add(-time.Minute),
		ExpiresAt:          now.Add(time.Hour),
		Severity:           "critical",
		AffectedAlgorithms: []string{"X25519MLKEM768"},
		ReplacementGroups:  []string{"SecP384r1MLKEM1024"},
	}
	alicePublic, alicePrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	bobPublic, bobPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	directive, err = SignEmergencyDirective(privateKey, directive)
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
	directive, err = controller.ExecuteEmergency(publicKey, map[string]ed25519.PublicKey{"alice": alicePublic, "bob": bobPublic}, directive)
	if err != nil {
		t.Fatal(err)
	}
	if len(directive.AffectedDeployments) != 1 || directive.AffectedDeployments[0] != deployment.ID {
		t.Fatalf("unexpected affected deployments: %#v", directive.AffectedDeployments)
	}
	updated, ok := store.GetDeployment(deployment.ID)
	if !ok || updated.Candidate == nil || updated.Candidate.Groups[0] != "SecP384r1MLKEM1024" {
		t.Fatalf("emergency candidate not prepared: %#v", updated)
	}
}

func TestCanaryAssignmentIsStable(t *testing.T) {
	first := InCanary("payments", "client-42", 10)
	for i := 0; i < 100; i++ {
		if InCanary("payments", "client-42", 10) != first {
			t.Fatal("canary assignment changed")
		}
	}
}
