package main

import (
	"testing"
	"time"
)

func TestMakeWindow(t *testing.T) {
	started := time.Date(2026, 8, 3, 0, 0, 0, 0, time.UTC)
	events := make([]event, 100)
	for i := range events {
		events[i] = event{Time: started.Add(time.Duration(i) * time.Second), Status: "connected", LatencyMillis: float64(i + 1)}
	}
	events[4].Status = "upstream-handshake-failed"
	events[7].Fallback = true
	window := makeWindow(events, 50)
	if window.Handshakes != 100 || window.Failures != 1 || window.Fallbacks != 1 {
		t.Fatalf("unexpected counters: %#v", window)
	}
	if window.P99LatencyMillis != 99 {
		t.Fatalf("unexpected p99: %f", window.P99LatencyMillis)
	}
}
