package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	runtimepkg "github.com/Naokibot/i_1/internal/runtime"
)

type stagedRevision struct {
	ConfigPath string
	PIDPath    string
	LogPath    string
	Directory  string
}

type managedProcess struct {
	command *exec.Cmd
	done    <-chan error
}

type desiredResponse struct {
	DeploymentID string                   `json:"deploymentId"`
	Selected     string                   `json:"selected"`
	State        runtimepkg.RolloutState  `json:"state"`
	Canary       int                      `json:"canaryPercent"`
	Config       runtimepkg.GatewayConfig `json:"config"`
}

type agentOptions struct {
	stateDir      string
	healthTimeout time.Duration
	drainTimeout  time.Duration
}

func main() {
	stateDir := flag.String("state-dir", envOr("PQM_AGENT_STATE", "data/gateway-agent"), "gateway agent state directory")
	healthTimeout := flag.Duration("health-timeout", 20*time.Second, "candidate health-check timeout")
	drainTimeout := flag.Duration("drain-timeout", 10*time.Second, "old process graceful shutdown timeout")
	controller := flag.String("controller", os.Getenv("PQM_CONTROLLER_URL"), "runtime controller base URL")
	deployment := flag.String("deployment", os.Getenv("PQM_DEPLOYMENT_ID"), "deployment ID")
	clientID := flag.String("client-id", envOr("PQM_CLIENT_ID", hostname()), "stable canary client ID")
	token := flag.String("token", os.Getenv("PQM_RUNTIME_TOKEN"), "runtime API bearer token")
	interval := flag.Duration("interval", 10*time.Second, "desired-state polling interval")
	flag.Parse()

	options := agentOptions{stateDir: *stateDir, healthTimeout: *healthTimeout, drainTimeout: *drainTimeout}
	if flag.NArg() == 2 && flag.Arg(0) == "apply" {
		config, err := readConfig(flag.Arg(1))
		if err != nil {
			log.Fatal(err)
		}
		if err := withAgentLock(options.stateDir, func() error { return apply(options, config) }); err != nil {
			log.Fatal(err)
		}
		return
	}
	if flag.NArg() == 1 && flag.Arg(0) == "watch" {
		if *controller == "" || *deployment == "" || *clientID == "" {
			log.Fatal("watch requires -controller, -deployment, and -client-id")
		}
		ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
		defer stop()
		if err := watch(ctx, options, *controller, *deployment, *clientID, *token, *interval); err != nil && !errors.Is(err, context.Canceled) {
			log.Fatal(err)
		}
		return
	}
	fmt.Fprintln(os.Stderr, "usage: gateway-agent [flags] apply CONFIG.json | gateway-agent [flags] watch")
	os.Exit(2)
}

func watch(ctx context.Context, options agentOptions, controller, deployment, clientID, token string, interval time.Duration) error {
	if interval < time.Second {
		return errors.New("poll interval must be at least one second")
	}
	base, err := url.Parse(strings.TrimRight(controller, "/"))
	if err != nil || (base.Scheme != "http" && base.Scheme != "https") || base.Host == "" {
		return errors.New("controller must be an absolute HTTP or HTTPS URL")
	}
	client := &http.Client{Timeout: 15 * time.Second}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		if err := reconcile(ctx, client, options, base, deployment, clientID, token); err != nil && !errors.Is(err, context.Canceled) {
			log.Printf("desired-state reconciliation failed: %v", err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func reconcile(ctx context.Context, client *http.Client, options agentOptions, base *url.URL, deployment, clientID, token string) error {
	endpoint := *base
	endpoint.Path = strings.TrimRight(endpoint.Path, "/") + "/api/v1/deployments/" + url.PathEscape(deployment) + "/desired"
	query := endpoint.Query()
	query.Set("clientId", clientID)
	endpoint.RawQuery = query.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	response, err := client.Do(req)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(response.Body, 8<<10))
		return fmt.Errorf("controller returned %s: %s", response.Status, strings.TrimSpace(string(body)))
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, 2<<20))
	decoder.DisallowUnknownFields()
	var desired desiredResponse
	if err := decoder.Decode(&desired); err != nil {
		return err
	}
	if desired.Config.Revision == "" {
		return errors.New("controller returned an empty revision")
	}
	current, _ := currentConfig(options.stateDir)
	if current.Revision == desired.Config.Revision && processAlive(currentPID(options.stateDir)) {
		return nil
	}
	log.Printf("reconciling deployment=%s selection=%s state=%s revision=%s", desired.DeploymentID, desired.Selected, desired.State, desired.Config.Revision)
	return withAgentLock(options.stateDir, func() error { return apply(options, desired.Config) })
}

func readConfig(path string) (runtimepkg.GatewayConfig, error) {
	file, err := os.Open(path)
	if err != nil {
		return runtimepkg.GatewayConfig{}, err
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, 2<<20))
	decoder.DisallowUnknownFields()
	var config runtimepkg.GatewayConfig
	if err := decoder.Decode(&config); err != nil {
		return runtimepkg.GatewayConfig{}, err
	}
	if config.Revision == "" || len(config.Command) == 0 {
		return runtimepkg.GatewayConfig{}, errors.New("revision and command are required")
	}
	return config, nil
}

func apply(options agentOptions, config runtimepkg.GatewayConfig) error {
	if err := os.MkdirAll(filepath.Join(options.stateDir, "revisions"), 0o750); err != nil {
		return err
	}
	current, _ := currentConfig(options.stateDir)
	oldTarget, _ := os.Readlink(filepath.Join(options.stateDir, "current"))
	oldPID := currentPID(options.stateDir)
	if current.Revision == config.Revision && processAlive(oldPID) {
		return nil
	}

	staged, err := stageRevision(options.stateDir, config)
	if err != nil {
		return err
	}
	if err := validateCandidate(config, staged.ConfigPath); err != nil {
		return fmt.Errorf("candidate validation failed: %w", err)
	}

	if oldPID > 1 {
		terminate(oldPID, options.drainTimeout)
	}
	candidate, err := startProcess(config, staged)
	if err != nil {
		_ = restorePrevious(options, oldTarget)
		return err
	}
	if err := os.WriteFile(staged.PIDPath, []byte(strconv.Itoa(candidate.command.Process.Pid)+"\n"), 0o600); err != nil {
		stopManaged(candidate, options.drainTimeout)
		_ = restorePrevious(options, oldTarget)
		return err
	}
	if err := waitForHealth(config, candidate, options.healthTimeout); err != nil {
		stopManaged(candidate, options.drainTimeout)
		restoreErr := restorePrevious(options, oldTarget)
		if restoreErr != nil {
			return fmt.Errorf("candidate unhealthy (%v) and previous revision restore failed: %w", err, restoreErr)
		}
		return fmt.Errorf("candidate unhealthy; previous revision restored: %w", err)
	}
	if err := switchCurrent(options.stateDir, staged.Directory); err != nil {
		stopManaged(candidate, options.drainTimeout)
		_ = restorePrevious(options, oldTarget)
		return err
	}
	log.Printf("activated revision %s pid=%d config_sha256=%s", config.Revision, candidate.command.Process.Pid, fileHash(staged.ConfigPath))
	return nil
}

func restorePrevious(options agentOptions, oldTarget string) error {
	if oldTarget == "" {
		return nil
	}
	configPath := filepath.Join(options.stateDir, oldTarget, "config.json")
	config, err := readConfig(configPath)
	if err != nil {
		return err
	}
	staged := stagedRevision{
		ConfigPath: configPath,
		PIDPath:    filepath.Join(options.stateDir, oldTarget, "process.pid"),
		LogPath:    filepath.Join(options.stateDir, oldTarget, "gateway.log"),
		Directory:  oldTarget,
	}
	process, err := startProcess(config, staged)
	if err != nil {
		return err
	}
	if err := os.WriteFile(staged.PIDPath, []byte(strconv.Itoa(process.command.Process.Pid)+"\n"), 0o600); err != nil {
		stopManaged(process, options.drainTimeout)
		return err
	}
	if err := waitForHealth(config, process, options.healthTimeout); err != nil {
		stopManaged(process, options.drainTimeout)
		return err
	}
	return nil
}

func stageRevision(stateDir string, config runtimepkg.GatewayConfig) (stagedRevision, error) {
	safeRevision := strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.' {
			return r
		}
		return '-'
	}, config.Revision)
	if safeRevision == "" || safeRevision == "." || safeRevision == ".." {
		return stagedRevision{}, errors.New("revision does not contain a safe file name")
	}
	relativeDir := filepath.Join("revisions", safeRevision)
	directory := filepath.Join(stateDir, relativeDir)
	if err := os.MkdirAll(directory, 0o750); err != nil {
		return stagedRevision{}, err
	}
	configPath := filepath.Join(directory, "config.json")
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return stagedRevision{}, err
	}
	if err := writeAtomic(configPath, data, 0o600); err != nil {
		return stagedRevision{}, err
	}
	return stagedRevision{ConfigPath: configPath, PIDPath: filepath.Join(directory, "process.pid"), LogPath: filepath.Join(directory, "gateway.log"), Directory: relativeDir}, nil
}

func validateCandidate(config runtimepkg.GatewayConfig, configPath string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	args := append([]string(nil), config.Command[1:]...)
	args = append(args, "--check-config", configPath)
	command := exec.CommandContext(ctx, config.Command[0], args...)
	command.Env = commandEnvironment(config.Environment)
	output, err := command.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func startProcess(config runtimepkg.GatewayConfig, staged stagedRevision) (managedProcess, error) {
	logFile, err := os.OpenFile(staged.LogPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return managedProcess{}, err
	}
	args := append([]string(nil), config.Command[1:]...)
	args = append(args, "--config", staged.ConfigPath)
	command := exec.Command(config.Command[0], args...)
	command.Env = commandEnvironment(config.Environment)
	command.Stdout = logFile
	command.Stderr = logFile
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := command.Start(); err != nil {
		_ = logFile.Close()
		return managedProcess{}, err
	}
	done := make(chan error, 1)
	go func() {
		done <- command.Wait()
		_ = logFile.Close()
	}()
	return managedProcess{command: command, done: done}, nil
}

func waitForHealth(config runtimepkg.GatewayConfig, process managedProcess, timeout time.Duration) error {
	address := config.HealthAddress
	if address == "" {
		address = config.Listen
		if strings.HasPrefix(address, ":") {
			address = "127.0.0.1" + address
		}
	}
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case err := <-process.done:
			if err == nil {
				return errors.New("candidate exited before becoming healthy")
			}
			return fmt.Errorf("candidate exited before becoming healthy: %w", err)
		case <-ticker.C:
			connection, err := net.DialTimeout("tcp", address, time.Second)
			if err == nil {
				_ = connection.Close()
				return nil
			}
		case <-deadline.C:
			return fmt.Errorf("health address %s did not accept connections", address)
		}
	}
}

func switchCurrent(stateDir, relativeDir string) error {
	newLink := filepath.Join(stateDir, ".current-new")
	_ = os.Remove(newLink)
	if err := os.Symlink(relativeDir, newLink); err != nil {
		return err
	}
	return os.Rename(newLink, filepath.Join(stateDir, "current"))
}

func currentConfig(stateDir string) (runtimepkg.GatewayConfig, error) {
	target, err := os.Readlink(filepath.Join(stateDir, "current"))
	if err != nil {
		return runtimepkg.GatewayConfig{}, err
	}
	return readConfig(filepath.Join(stateDir, target, "config.json"))
}

func currentPID(stateDir string) int {
	target, err := os.Readlink(filepath.Join(stateDir, "current"))
	if err != nil {
		return 0
	}
	return readPID(filepath.Join(stateDir, target, "process.pid"))
}

func readPID(path string) int {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	pid, _ := strconv.Atoi(strings.TrimSpace(string(data)))
	return pid
}

func processAlive(pid int) bool {
	if pid <= 1 {
		return false
	}
	process, err := os.FindProcess(pid)
	return err == nil && process.Signal(syscall.Signal(0)) == nil
}

func stopManaged(process managedProcess, timeout time.Duration) {
	if process.command == nil || process.command.Process == nil {
		return
	}
	terminate(process.command.Process.Pid, timeout)
}

func terminate(pid int, timeout time.Duration) {
	if pid <= 1 {
		return
	}
	_ = syscall.Kill(-pid, syscall.SIGTERM)
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if syscall.Kill(-pid, 0) != nil {
			return
		}
		time.Sleep(250 * time.Millisecond)
	}
	_ = syscall.Kill(-pid, syscall.SIGKILL)
}

func commandEnvironment(overrides map[string]string) []string {
	environment := append([]string(nil), os.Environ()...)
	for key, value := range overrides {
		if strings.ContainsAny(key, "=\x00") || strings.ContainsRune(value, '\x00') {
			continue
		}
		environment = append(environment, key+"="+value)
	}
	return environment
}

func fileHash(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return "unavailable"
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func writeAtomic(path string, data []byte, mode os.FileMode) error {
	temporary := path + ".tmp"
	if err := os.WriteFile(temporary, data, mode); err != nil {
		return err
	}
	file, err := os.OpenFile(temporary, os.O_RDWR, mode)
	if err != nil {
		_ = os.Remove(temporary)
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		_ = os.Remove(temporary)
		return err
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(temporary)
		return err
	}
	return os.Rename(temporary, path)
}

func withAgentLock(stateDir string, function func() error) error {
	if err := os.MkdirAll(stateDir, 0o750); err != nil {
		return err
	}
	lockFile, err := os.OpenFile(filepath.Join(stateDir, ".lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	defer lockFile.Close()
	if err := syscall.Flock(int(lockFile.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	defer syscall.Flock(int(lockFile.Fd()), syscall.LOCK_UN)
	return function()
}

func hostname() string {
	name, err := os.Hostname()
	if err != nil || strings.TrimSpace(name) == "" {
		return "unknown-host"
	}
	return name
}

func envOr(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
