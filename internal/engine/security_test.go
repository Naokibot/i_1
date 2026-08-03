package engine

import (
	"strings"
	"testing"

	"github.com/Naokibot/i_1/internal/model"
)

func TestValidateRejectsHostileTargets(t *testing.T) {
	tests := []model.ScanRequest{
		{Kind: "tls", Target: "host.example\nforged-log-line"},
		{Kind: "ssh", Target: strings.Repeat("a", maxScanTargetBytes+1)},
		{Kind: "unsupported", Target: "host.example"},
		{Kind: "tls", Target: "host.example", Port: 70000},
	}
	for _, request := range tests {
		if err := validate(request); err == nil {
			t.Fatalf("validate accepted hostile request: %#v", request)
		}
	}
}

func TestStartRejectsWhenCapacityIsExhausted(t *testing.T) {
	slots := make(chan struct{}, 1)
	slots <- struct{}{}
	engine := &Engine{scanSlots: slots}
	_, err := engine.Start(model.ScanRequest{Kind: "tls", Target: "example.com", Port: 443})
	if err == nil || !strings.Contains(err.Error(), "capacity") {
		t.Fatalf("Start error=%v, want capacity error", err)
	}
}
