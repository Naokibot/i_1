package store

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/Naokibot/i_1/internal/model"
)

func TestCapabilityRegressionAndAudit(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	first, err := st.UpsertCapability(model.CapabilityRecord{Subject: "service-a", State: "Hybrid Capable", Algorithms: map[string]bool{"RSA": true, "ML-KEM": true}, LastSeen: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	if first.DowngradeSuspect {
		t.Fatal("first report must not be a downgrade")
	}
	second, err := st.UpsertCapability(model.CapabilityRecord{Subject: "service-a", State: "Legacy Only", Algorithms: map[string]bool{"RSA": true}, LastSeen: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	if !second.DowngradeSuspect {
		t.Fatal("expected capability regression to be flagged")
	}
	ok, index, message := st.VerifyAudit()
	if !ok {
		t.Fatalf("audit invalid at %d: %s", index, message)
	}
}
