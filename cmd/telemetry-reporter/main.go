package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"

	runtimepkg "github.com/Naokibot/i_1/internal/runtime"
)

type event struct {
	Time          time.Time `json:"time"`
	Status        string    `json:"status"`
	LatencyMillis float64   `json:"latencyMillis"`
	Fallback      bool      `json:"fallback"`
}

type checkpoint struct {
	Offset int64 `json:"offset"`
}

func main() {
	file := flag.String("file", "gateway-telemetry.jsonl", "gateway JSONL telemetry file")
	checkpointPath := flag.String("checkpoint", "data/telemetry-reporter.json", "reader checkpoint file")
	controller := flag.String("controller", os.Getenv("PQM_CONTROLLER_URL"), "runtime controller base URL")
	deployment := flag.String("deployment", os.Getenv("PQM_DEPLOYMENT_ID"), "deployment ID")
	token := flag.String("token", os.Getenv("PQM_RUNTIME_TOKEN"), "runtime API bearer token")
	stableP99 := flag.Float64("stable-p99", 1, "stable revision p99 latency in milliseconds")
	minimumSamples := flag.Int("minimum-samples", 100, "minimum events per report")
	interval := flag.Duration("interval", time.Minute, "report interval")
	flag.Parse()
	if *controller == "" || *deployment == "" || *stableP99 <= 0 || *minimumSamples < 1 {
		log.Fatal("controller, deployment, positive stable-p99, and minimum-samples are required")
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, *file, *checkpointPath, strings.TrimRight(*controller, "/"), *deployment, *token, *stableP99, *minimumSamples, *interval); err != nil && !errors.Is(err, context.Canceled) {
		log.Fatal(err)
	}
}

func run(ctx context.Context, file, checkpointPath, controller, deployment, token string, stableP99 float64, minimumSamples int, interval time.Duration) error {
	if interval < time.Second {
		return errors.New("interval must be at least one second")
	}
	client := &http.Client{Timeout: 20 * time.Second}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		if err := report(ctx, client, file, checkpointPath, controller, deployment, token, stableP99, minimumSamples); err != nil && !errors.Is(err, os.ErrNotExist) {
			log.Printf("telemetry report failed: %v", err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func report(ctx context.Context, client *http.Client, path, checkpointPath, controller, deployment, token string, stableP99 float64, minimumSamples int) error {
	position := readCheckpoint(checkpointPath)
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if position.Offset < 0 || position.Offset > info.Size() {
		position.Offset = 0
	}
	if _, err := file.Seek(position.Offset, io.SeekStart); err != nil {
		return err
	}

	events := make([]event, 0, minimumSamples)
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64<<10), 2<<20)
	for scanner.Scan() {
		var item event
		if err := json.Unmarshal(scanner.Bytes(), &item); err != nil {
			continue
		}
		if item.Time.IsZero() {
			continue
		}
		events = append(events, item)
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	newOffset, err := file.Seek(0, io.SeekCurrent)
	if err != nil {
		return err
	}
	if len(events) < minimumSamples {
		return nil
	}

	metrics := makeWindow(events, stableP99)
	payload, err := json.Marshal(metrics)
	if err != nil {
		return err
	}
	endpoint := controller + "/api/v1/deployments/" + deployment + "/metrics"
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(response.Body, 64<<10))
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("controller returned %s: %s", response.Status, strings.TrimSpace(string(body)))
	}
	if err := writeCheckpoint(checkpointPath, checkpoint{Offset: newOffset}); err != nil {
		return err
	}
	log.Printf("reported %d handshakes, failures=%d fallbacks=%d p99=%.3fms", metrics.Handshakes, metrics.Failures, metrics.Fallbacks, metrics.P99LatencyMillis)
	return nil
}

func makeWindow(events []event, stableP99 float64) runtimepkg.MetricWindow {
	latencies := make([]float64, 0, len(events))
	window := runtimepkg.MetricWindow{StartedAt: events[0].Time, CompletedAt: events[len(events)-1].Time, Handshakes: int64(len(events)), StableP99Millis: stableP99}
	for _, item := range events {
		if item.Time.Before(window.StartedAt) {
			window.StartedAt = item.Time
		}
		if item.Time.After(window.CompletedAt) {
			window.CompletedAt = item.Time
		}
		if item.Status != "connected" {
			window.Failures++
		}
		if item.Fallback {
			window.Fallbacks++
		}
		latencies = append(latencies, item.LatencyMillis)
	}
	sort.Float64s(latencies)
	index := int(float64(len(latencies)-1) * 0.99)
	window.P99LatencyMillis = latencies[index]
	return window
}

func readCheckpoint(path string) checkpoint {
	data, err := os.ReadFile(path)
	if err != nil {
		return checkpoint{}
	}
	var value checkpoint
	if json.Unmarshal(data, &value) != nil {
		return checkpoint{}
	}
	return value
}

func writeCheckpoint(path string, value checkpoint) error {
	if err := os.MkdirAll(filepathDir(path), 0o750); err != nil {
		return err
	}
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	temporary := path + ".tmp"
	if err := os.WriteFile(temporary, data, 0o600); err != nil {
		return err
	}
	return os.Rename(temporary, path)
}

func filepathDir(path string) string {
	index := strings.LastIndexAny(path, `/\\`)
	if index < 0 {
		return "."
	}
	if index == 0 {
		return path[:1]
	}
	return path[:index]
}
