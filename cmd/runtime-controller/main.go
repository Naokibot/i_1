package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	runtimepkg "github.com/Naokibot/i_1/internal/runtime"
)

type server struct {
	store        *runtimepkg.StateStore
	rollouts     *runtimepkg.RolloutController
	recryptor    runtimepkg.Recryptor
	root         string
	token        string
	emergencyPK  ed25519.PublicKey
	approverKeys map[string]ed25519.PublicKey
}

func main() {
	listen := flag.String("listen", envOr("PQM_RUNTIME_LISTEN", ":8090"), "HTTP listen address")
	dataPath := flag.String("data", envOr("PQM_RUNTIME_DATA", "data/runtime.json"), "runtime state file")
	root := flag.String("root", envOr("PQM_RUNTIME_ROOT", "."), "allowed root for re-encryption files and keys")
	token := flag.String("token", os.Getenv("PQM_RUNTIME_TOKEN"), "API bearer token")
	emergencyPublicKey := flag.String("emergency-public-key", os.Getenv("PQM_EMERGENCY_PUBLIC_KEY"), "base64 Ed25519 emergency root public key")
	emergencyApprovers := flag.String("emergency-approvers", os.Getenv("PQM_EMERGENCY_APPROVERS"), "JSON file mapping approver names to base64 Ed25519 public keys")
	opensslBinary := flag.String("openssl", envOr("PQM_OPENSSL", "openssl"), "OpenSSL 3.5 binary")
	provider := flag.String("provider", envOr("PQM_OPENSSL_PROVIDER", "default"), "OpenSSL provider")
	providerPath := flag.String("provider-path", os.Getenv("PQM_OPENSSL_PROVIDER_PATH"), "OpenSSL provider module directory")
	flag.Parse()

	absoluteRoot, err := filepath.Abs(*root)
	if err != nil {
		log.Fatal(err)
	}
	store, err := runtimepkg.OpenStateStore(*dataPath)
	if err != nil {
		log.Fatal(err)
	}
	backend := runtimepkg.NewOpenSSLBackend()
	backend.Binary = *opensslBinary
	backend.Provider = *provider
	backend.ProviderPath = *providerPath
	s := &server{
		store:        store,
		rollouts:     runtimepkg.NewRolloutController(store),
		recryptor:    runtimepkg.Recryptor{KEM: backend},
		root:         absoluteRoot,
		token:        *token,
		approverKeys: map[string]ed25519.PublicKey{},
	}
	if *emergencyPublicKey != "" {
		decoded, err := base64.StdEncoding.DecodeString(*emergencyPublicKey)
		if err != nil || len(decoded) != ed25519.PublicKeySize {
			log.Fatal("invalid emergency public key")
		}
		s.emergencyPK = ed25519.PublicKey(decoded)
	}
	if *emergencyApprovers != "" {
		keys, err := loadApproverKeys(*emergencyApprovers)
		if err != nil {
			log.Fatalf("load emergency approvers: %v", err)
		}
		s.approverKeys = keys
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/health", s.health)
	mux.HandleFunc("/api/v1/deployments", s.deployments)
	mux.HandleFunc("/api/v1/deployments/", s.deployment)
	mux.HandleFunc("/api/v1/emergencies", s.emergencies)
	mux.HandleFunc("/api/v1/emergencies/execute", s.executeEmergency)
	mux.HandleFunc("/api/v1/recrypt", s.recryptJobs)
	mux.HandleFunc("/api/v1/recrypt/", s.recryptJob)
	mux.HandleFunc("/api/v1/audit/verify", s.auditVerify)
	server := &http.Server{
		Addr:              *listen,
		Handler:           s.middleware(mux),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	log.Printf("runtime controller listening on %s", *listen)
	log.Fatal(server.ListenAndServe())
}

func (s *server) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")
		if r.URL.Path != "/api/v1/health" && s.token != "" && r.Header.Get("Authorization") != "Bearer "+s.token {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *server) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "time": time.Now().UTC()})
}

func (s *server) deployments(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, s.store.ListDeployments())
	case http.MethodPost:
		var request struct {
			Service    string                   `json:"service"`
			Stable     runtimepkg.GatewayConfig `json:"stable"`
			Thresholds runtimepkg.Thresholds    `json:"thresholds"`
		}
		if !decodeJSON(w, r, &request) {
			return
		}
		deployment, err := s.rollouts.CreateDeployment(request.Service, request.Stable, request.Thresholds)
		respond(w, deployment, err, http.StatusCreated)
	default:
		methodNotAllowed(w)
	}
}

func (s *server) deployment(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/deployments/")
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		notFound(w)
		return
	}
	id := parts[0]
	if len(parts) == 1 && r.Method == http.MethodGet {
		deployment, ok := s.store.GetDeployment(id)
		if !ok {
			notFound(w)
			return
		}
		writeJSON(w, http.StatusOK, deployment)
		return
	}
	if len(parts) == 2 && parts[1] == "desired" && r.Method == http.MethodGet {
		deployment, ok := s.store.GetDeployment(id)
		if !ok {
			notFound(w)
			return
		}
		clientID := strings.TrimSpace(r.URL.Query().Get("clientId"))
		if clientID == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "clientId is required"})
			return
		}
		desired := deployment.Stable
		selected := "stable"
		if deployment.State == runtimepkg.RolloutCanary && deployment.Candidate != nil && runtimepkg.InCanary(deployment.Service, clientID, deployment.CanaryPercent) {
			desired = *deployment.Candidate
			selected = "candidate"
		}
		writeJSON(w, http.StatusOK, map[string]any{"deploymentId": deployment.ID, "selected": selected, "state": deployment.State, "canaryPercent": deployment.CanaryPercent, "config": desired})
		return
	}
	if len(parts) != 2 || r.Method != http.MethodPost {
		notFound(w)
		return
	}
	switch parts[1] {
	case "candidate":
		var candidate runtimepkg.GatewayConfig
		if !decodeJSON(w, r, &candidate) {
			return
		}
		deployment, err := s.rollouts.SetCandidate(id, candidate)
		respond(w, deployment, err, http.StatusOK)
	case "advance", "metrics":
		var metrics runtimepkg.MetricWindow
		if !decodeJSON(w, r, &metrics) {
			return
		}
		deployment, err := s.rollouts.Advance(id, metrics)
		respond(w, deployment, err, http.StatusOK)
	case "rollback":
		var request struct {
			Reason string `json:"reason"`
		}
		if !decodeJSON(w, r, &request) {
			return
		}
		deployment, err := s.rollouts.Rollback(id, request.Reason)
		respond(w, deployment, err, http.StatusOK)
	default:
		notFound(w)
	}
}

func (s *server) emergencies(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	writeJSON(w, http.StatusOK, s.store.ListDirectives())
}

func (s *server) executeEmergency(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	if len(s.emergencyPK) != ed25519.PublicKeySize {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "emergency signing public key is not configured"})
		return
	}
	var directive runtimepkg.EmergencyDirective
	if !decodeJSON(w, r, &directive) {
		return
	}
	executed, err := s.rollouts.ExecuteEmergency(s.emergencyPK, s.approverKeys, directive)
	respond(w, executed, err, http.StatusAccepted)
}

func (s *server) recryptJobs(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, s.store.ListRecryptJobs())
	case http.MethodPost:
		var request runtimepkg.RecryptJob
		if !decodeJSON(w, r, &request) {
			return
		}
		job, err := s.prepareJob(request)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		if err := s.store.PutRecryptJob(job, "runtime-api", "recrypt.queue"); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		go s.runJob(job)
		writeJSON(w, http.StatusAccepted, job)
	default:
		methodNotAllowed(w)
	}
}

func (s *server) recryptJob(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	id := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/v1/recrypt/"), "/")
	job, ok := s.store.GetRecryptJob(id)
	if !ok {
		notFound(w)
		return
	}
	writeJSON(w, http.StatusOK, job)
}

func (s *server) prepareJob(request runtimepkg.RecryptJob) (runtimepkg.RecryptJob, error) {
	if request.Mode != "encrypt" && request.Mode != "decrypt" && request.Mode != "rewrap" {
		return runtimepkg.RecryptJob{}, errors.New("mode must be encrypt, decrypt, or rewrap")
	}
	var err error
	request.Source, err = securePath(s.root, request.Source)
	if err != nil {
		return runtimepkg.RecryptJob{}, err
	}
	request.Destination, err = securePath(s.root, request.Destination)
	if err != nil {
		return runtimepkg.RecryptJob{}, err
	}
	if request.SourceKey != "" {
		request.SourceKey, err = securePath(s.root, request.SourceKey)
		if err != nil {
			return runtimepkg.RecryptJob{}, err
		}
	}
	if request.TargetKey != "" {
		request.TargetKey, err = securePath(s.root, request.TargetKey)
		if err != nil {
			return runtimepkg.RecryptJob{}, err
		}
	}
	if request.KEMAlgorithm == "" {
		request.KEMAlgorithm = "ML-KEM-768"
	}
	request.ID = newJobID()
	request.Status = runtimepkg.RecryptQueued
	request.Error = ""
	request.CreatedAt = time.Now().UTC()
	request.UpdatedAt = request.CreatedAt
	return request, nil
}

func (s *server) runJob(job runtimepkg.RecryptJob) {
	job.Status = runtimepkg.RecryptRunning
	job.UpdatedAt = time.Now().UTC()
	_ = s.store.PutRecryptJob(job, "recrypt-worker", "recrypt.start")
	ctx, cancel := context.WithTimeout(context.Background(), 24*time.Hour)
	defer cancel()
	var (
		header runtimepkg.EnvelopeHeader
		err    error
	)
	switch job.Mode {
	case "encrypt":
		header, err = s.recryptor.EncryptFile(ctx, job.Source, job.Destination, job.TargetKey, filepath.Base(job.TargetKey), job.KEMAlgorithm)
	case "decrypt":
		header, err = s.recryptor.DecryptFile(ctx, job.Source, job.Destination, job.SourceKey)
	case "rewrap":
		header, err = s.recryptor.RewrapFile(ctx, job.Source, job.Destination, job.SourceKey, job.TargetKey, filepath.Base(job.TargetKey), job.KEMAlgorithm)
	}
	job.UpdatedAt = time.Now().UTC()
	if err != nil {
		job.Status = runtimepkg.RecryptFailed
		job.Error = err.Error()
		_ = s.store.PutRecryptJob(job, "recrypt-worker", "recrypt.failed")
		return
	}
	job.Status = runtimepkg.RecryptCompleted
	job.PlaintextHash = header.PlaintextSHA256
	job.BytesProcessed = header.PlaintextSize
	_ = s.store.PutRecryptJob(job, "recrypt-worker", "recrypt.completed")
}

func (s *server) auditVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	if err := s.store.VerifyAudit(); err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"valid": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"valid": true, "records": len(s.store.AuditRecords())})
}

func loadApproverKeys(path string) (map[string]ed25519.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var encoded map[string]string
	if err := json.Unmarshal(data, &encoded); err != nil {
		return nil, err
	}
	keys := make(map[string]ed25519.PublicKey, len(encoded))
	for name, value := range encoded {
		name = strings.TrimSpace(name)
		decoded, err := base64.StdEncoding.DecodeString(value)
		if name == "" || err != nil || len(decoded) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("invalid approver key for %q", name)
		}
		keys[name] = ed25519.PublicKey(decoded)
	}
	return keys, nil
}

func securePath(root, path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", errors.New("path is required")
	}
	candidate := path
	if !filepath.IsAbs(candidate) {
		candidate = filepath.Join(root, candidate)
	}
	candidate, err := filepath.Abs(candidate)
	if err != nil {
		return "", err
	}
	relative, err := filepath.Rel(root, candidate)
	if err != nil {
		return "", err
	}
	if relative == ".." || strings.HasPrefix(relative, ".."+string(os.PathSeparator)) {
		return "", errors.New("path is outside the configured root")
	}
	return candidate, nil
}

func decodeJSON(w http.ResponseWriter, r *http.Request, target any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 4<<20)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return false
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "request must contain one JSON object"})
		return false
	}
	return true
}

func respond(w http.ResponseWriter, value any, err error, success int) {
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, success, value)
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func methodNotAllowed(w http.ResponseWriter) {
	writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
}

func notFound(w http.ResponseWriter) {
	writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
}

func newJobID() string {
	return fmt.Sprintf("recrypt-%d", time.Now().UTC().UnixNano())
}

func envOr(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
