package api

import (
	"embed"
	"encoding/json"
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

//go:embed web/*
var webFS embed.FS

type server struct {
	store  *store.Store
	engine *engine.Engine
}

func New(st *store.Store, eng *engine.Engine) http.Handler {
	s := &server{st, eng}
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
	return requestLog(securityHeaders(mux))
}
func (s *server) health(w http.ResponseWriter, r *http.Request) {
	write(w, 200, map[string]any{"status": "ok", "time": time.Now().UTC()})
}
func (s *server) summary(w http.ResponseWriter, r *http.Request) {
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
	write(w, 200, map[string]any{"assetCount": len(assets), "findingCount": len(findings), "riskLevels": levels, "findingSeverities": sev, "pathStatus": paths, "scanCount": len(s.store.ListScans())})
}
func (s *server) assets(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		method(w)
		return
	}
	write(w, 200, s.store.ListAssets())
}
func (s *server) asset(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/assets/")
	parts := strings.Split(path, "/")
	id := parts[0]
	if len(parts) == 1 && r.Method == "GET" {
		a, ok := s.store.GetAsset(id)
		if !ok {
			notFound(w)
			return
		}
		write(w, 200, a)
		return
	}
	if len(parts) == 2 && parts[1] == "context" && r.Method == "POST" {
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
		write(w, 200, a)
		return
	}
	if len(parts) == 2 && parts[1] == "recalculate" && r.Method == "POST" {
		a, err := s.engine.Recalculate(id)
		if err != nil {
			bad(w, err.Error())
			return
		}
		write(w, 200, a)
		return
	}
	notFound(w)
}
func (s *server) findings(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		method(w)
		return
	}
	write(w, 200, s.store.ListFindings())
}
func (s *server) scans(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		write(w, 200, s.store.ListScans())
	case "POST":
		var req model.ScanRequest
		if !decode(w, r, &req) {
			return
		}
		j, err := s.engine.Start(req)
		if err != nil {
			bad(w, err.Error())
			return
		}
		write(w, 202, j)
	default:
		method(w)
	}
}
func (s *server) scan(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		method(w)
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/scans/")
	j, ok := s.store.GetScan(id)
	if !ok {
		notFound(w)
		return
	}
	write(w, 200, j)
}
func (s *server) cbom(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		method(w)
		return
	}
	w.Header().Set("Content-Type", "application/vnd.cyclonedx+json; version=1.7")
	w.Header().Set("Content-Disposition", "attachment; filename=observatory.cdx.json")
	_ = json.NewEncoder(w).Encode(cbom.Generate(s.store.ListAssets()))
}
func (s *server) capabilities(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		method(w)
		return
	}
	write(w, 200, s.store.ListCapabilities())
}
func (s *server) capabilityReport(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
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
	write(w, 200, stored)
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
	if r.Method != "POST" {
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
	write(w, 200, c)
}
func (s *server) auditVerify(w http.ResponseWriter, r *http.Request) {
	ok, index, msg := s.store.VerifyAudit()
	write(w, 200, map[string]any{"valid": ok, "failedIndex": index, "message": msg, "events": len(s.store.AuditEvents())})
}
func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 2<<20)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		bad(w, err.Error())
		return false
	}
	return true
}
func write(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func bad(w http.ResponseWriter, msg string) { write(w, 400, map[string]string{"error": msg}) }
func notFound(w http.ResponseWriter)        { write(w, 404, map[string]string{"error": "not found"}) }
func method(w http.ResponseWriter)          { write(w, 405, map[string]string{"error": "method not allowed"}) }
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self'; script-src 'self'; connect-src 'self'")
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
