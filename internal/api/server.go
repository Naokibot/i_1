package api

import (
	"crypto/subtle"
	"embed"
	"encoding/json"
	"io"
	"io/fs"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/Naokibot/i_1/internal/cbom"
	"github.com/Naokibot/i_1/internal/engine"
	"github.com/Naokibot/i_1/internal/model"
	"github.com/Naokibot/i_1/internal/policy"
	"github.com/Naokibot/i_1/internal/store"
)

const maxRequestBodyBytes int64 = 1 << 20

//go:embed web/*
var webFS embed.FS

type server struct {
	store  *store.Store
	engine *engine.Engine
}

type Options struct {
	BearerToken string
}

func New(st *store.Store, eng *engine.Engine) http.Handler {
	return NewWithOptions(st, eng, Options{})
}

func NewWithOptions(st *store.Store, eng *engine.Engine, options Options) http.Handler {
	s := &server{store: st, engine: eng}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/health", s.health)
	mux.HandleFunc("/api/v1/summary", s.summary)
	mux.HandleFunc("/api/v1/assets", s.assets)
	mux.HandleFunc("/api/v1/assets/", s.asset)
	mux.HandleFunc("/api/v1/findings", s.findings)
	mux.HandleFunc("/api/v1/scans", s.scans)
	mux.HandleFunc("/api/v1/scans/", s.scan)
	mux.HandleFunc("/api/v1/cbom", s.cbom)
	mux.HandleFunc("/api/v1/capabilities", s.capabilities)
	mux.HandleFunc("/api/v1/capabilities/report", s.capabilityReport)
	mux.HandleFunc("/api/v1/policy/compile", s.compilePolicy)
	mux.HandleFunc("/api/v1/audit/verify", s.auditVerify)
	sub, _ := fs.Sub(webFS, "web")
	mux.Handle("/", http.FileServer(http.FS(sub)))

	var handler http.Handler = mux
	if options.BearerToken != "" {
		handler = bearerAuth(options.BearerToken, handler)
	}
	return requestLog(securityHeaders(handler))
}

func (s *server) health(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		method(w)
		return
	}
	write(w, http.StatusOK, map[string]any{"status": "ok", "time": time.Now().UTC()})
}

func (s *server) summary(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		method(w)
		return
	}
	assets := s.store.ListAssets()
	findings := s.store.ListFindings()
	levels := map[string]int{}
	paths := map[string]int{}
	for _, a := range assets {
		levels[a.Risk.Level]++
		paths[a.Migration.PathStatus]++
	}
	sev := map[string]int{}
	for _, f := range findings {
		sev[f.Severity]++
	}
	write(w, http.StatusOK, map[string]any{"assetCount": len(assets), "findingCount": len(findings), "riskLevels": levels, "findingSeverities": sev, "pathStatus": paths, "scanCount": len(s.store.ListScans())})
}

func (s *server) assets(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		method(w)
		return
	}
	write(w, http.StatusOK, s.store.ListAssets())
}

func (s *server) asset(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/assets/")
	parts := strings.Split(path, "/")
	id := parts[0]
	if len(parts) == 1 && r.Method == http.MethodGet {
		a, ok := s.store.GetAsset(id)
		if !ok {
			notFound(w)
			return
		}
		write(w, http.StatusOK, a)
		return
	}
	if len(parts) == 2 && parts[1] == "context" && r.Method == http.MethodPost {
		var c model.RiskContext
		if !decode(w, r, &c) {
			return
		}
		if _, err := s.store.UpdateContext(id, c); err != nil {
			bad(w, err.Error())
			return
		}
		a, err := s.engine.Recalculate(id)
		if err != nil {
			bad(w, err.Error())
			return
		}
		write(w, http.StatusOK, a)
		return
	}
	if len(parts) == 2 && parts[1] == "recalculate" && r.Method == http.MethodPost {
		a, err := s.engine.Recalculate(id)
		if err != nil {
			bad(w, err.Error())
			return
		}
		write(w, http.StatusOK, a)
		return
	}
	notFound(w)
}

func (s *server) findings(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		method(w)
		return
	}
	write(w, http.StatusOK, s.store.ListFindings())
}

func (s *server) scans(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		write(w, http.StatusOK, s.store.ListScans())
	case http.MethodPost:
		var req model.ScanRequest
		if !decode(w, r, &req) {
			return
		}
		j, err := s.engine.Start(req)
		if err != nil {
			bad(w, err.Error())
			return
		}
		write(w, http.StatusAccepted, j)
	default:
		method(w)
	}
}

func (s *server) scan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		method(w)
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/scans/")
	j, ok := s.store.GetScan(id)
	if !ok {
		notFound(w)
		return
	}
	write(w, http.StatusOK, j)
}

func (s *server) cbom(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		method(w)
		return
	}
	w.Header().Set("Content-Type", "application/vnd.cyclonedx+json; version=1.7")
	w.Header().Set("Content-Disposition", "attachment; filename=observatory.cdx.json")
	_ = json.NewEncoder(w).Encode(cbom.Generate(s.store.ListAssets()))
}

func (s *server) capabilities(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		method(w)
		return
	}
	write(w, http.StatusOK, s.store.ListCapabilities())
}

func (s *server) capabilityReport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		method(w)
		return
	}
	var c model.CapabilityRecord
	if !decode(w, r, &c) {
		return
	}
	if c.Subject == "" {
		bad(w, "subject is required")
		return
	}
	c.ID = model.NewID("cap")
	c.LastSeen = time.Now().UTC()
	c.State = classifyCapability(c.Algorithms)
	stored, err := s.store.UpsertCapability(c)
	if err != nil {
		bad(w, err.Error())
		return
	}
	write(w, http.StatusOK, stored)
}

func classifyCapability(a map[string]bool) string {
	hasPQC := a["ML-KEM"] || a["ML-DSA"] || a["SLH-DSA"]
	hasClassical := a["RSA"] || a["ECDSA"] || a["X25519"] || a["ECDH"]
	if hasPQC && hasClassical {
		return "Hybrid Capable"
	}
	if hasPQC {
		return "PQC Native"
	}
	if hasClassical {
		return "Legacy Only"
	}
	return "Unknown"
}

func (s *server) compilePolicy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		method(w)
		return
	}
	var p policy.Policy
	if !decode(w, r, &p) {
		return
	}
	c, err := policy.Compile(p)
	if err != nil {
		bad(w, err.Error())
		return
	}
	write(w, http.StatusOK, c)
}

func (s *server) auditVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		method(w)
		return
	}
	ok, index, msg := s.store.VerifyAudit()
	write(w, http.StatusOK, map[string]any{"valid": ok, "failedIndex": index, "message": msg, "events": len(s.store.AuditEvents())})
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		bad(w, "invalid JSON request")
		return false
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		bad(w, "request body must contain exactly one JSON value")
		return false
	}
	return true
}

func bearerAuth(token string, next http.Handler) http.Handler {
	expected := []byte(token)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/health" {
			next.ServeHTTP(w, r)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/api/") {
			provided := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			if len(provided) != len(token) || subtle.ConstantTimeCompare([]byte(provided), expected) != 1 {
				w.Header().Set("WWW-Authenticate", `Bearer realm="pqm-observatory"`)
				write(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func write(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func bad(w http.ResponseWriter, msg string) { write(w, http.StatusBadRequest, map[string]string{"error": msg}) }
func notFound(w http.ResponseWriter)        { write(w, http.StatusNotFound, map[string]string{"error": "not found"}) }
func method(w http.ResponseWriter)          { write(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"}) }

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self'; script-src 'self'; connect-src 'self'")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		next.ServeHTTP(w, r)
	})
}

func requestLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("%s %s %s", r.Method, r.URL.Path, time.Since(start).Round(time.Millisecond))
	})
}
