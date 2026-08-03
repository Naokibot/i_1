package store

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/Naokibot/i_1/internal/model"
)

type snapshot struct {
	Version      int                               `json:"version"`
	Assets       map[string]model.Asset            `json:"assets"`
	Findings     map[string]model.Finding          `json:"findings"`
	Scans        map[string]model.ScanJob          `json:"scans"`
	Capabilities map[string]model.CapabilityRecord `json:"capabilities"`
	Audit        []model.AuditEvent                `json:"audit"`
}

type Store struct {
	mu   sync.RWMutex
	path string
	data snapshot
}

func Open(path string) (*Store, error) {
	s := &Store{path: path, data: emptySnapshot()}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	if len(b) == 0 {
		return s, nil
	}
	if err := json.Unmarshal(b, &s.data); err != nil {
		return nil, fmt.Errorf("decode state: %w", err)
	}
	s.ensureMaps()
	return s, nil
}

func emptySnapshot() snapshot {
	return snapshot{Version: 1, Assets: map[string]model.Asset{}, Findings: map[string]model.Finding{}, Scans: map[string]model.ScanJob{}, Capabilities: map[string]model.CapabilityRecord{}, Audit: []model.AuditEvent{}}
}

func (s *Store) ensureMaps() {
	if s.data.Assets == nil {
		s.data.Assets = map[string]model.Asset{}
	}
	if s.data.Findings == nil {
		s.data.Findings = map[string]model.Finding{}
	}
	if s.data.Scans == nil {
		s.data.Scans = map[string]model.ScanJob{}
	}
	if s.data.Capabilities == nil {
		s.data.Capabilities = map[string]model.CapabilityRecord{}
	}
}

func (s *Store) persistLocked() error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o750); err != nil {
		return err
	}
	b, err := json.MarshalIndent(s.data, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

func (s *Store) UpsertAsset(a model.Asset, actor string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if old, ok := s.data.Assets[a.ID]; ok {
		a.DiscoveredAt = old.DiscoveredAt
	}
	s.data.Assets[a.ID] = a
	s.appendAuditLocked(actor, "asset.upsert", "asset", a.ID, map[string]any{"kind": a.Kind, "location": a.Location})
	return s.persistLocked()
}

func (s *Store) AddFindings(items []model.Finding, actor string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, f := range items {
		s.data.Findings[f.ID] = f
	}
	s.appendAuditLocked(actor, "finding.add", "finding-set", fmt.Sprint(len(items)), map[string]any{"count": len(items)})
	return s.persistLocked()
}

func (s *Store) CreateScan(j model.ScanJob) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data.Scans[j.ID] = j
	s.appendAuditLocked("api", "scan.create", "scan", j.ID, map[string]any{"kind": j.Request.Kind, "target": j.Request.Target})
	return s.persistLocked()
}

func (s *Store) UpdateScan(j model.ScanJob) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data.Scans[j.ID] = j
	s.appendAuditLocked("scanner", "scan."+j.Status, "scan", j.ID, map[string]any{"assetId": j.AssetID, "error": j.Error})
	return s.persistLocked()
}

func (s *Store) UpsertCapability(c model.CapabilityRecord) (model.CapabilityRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if old, ok := s.data.Capabilities[c.Subject]; ok {
		c.PreviousState = old.State
		if (old.State == "Hybrid Capable" || old.State == "PQC Native") && c.State == "Legacy Only" {
			c.DowngradeSuspect = true
			c.Notes = append(c.Notes, "Previously PQC-capable subject reported legacy-only support")
		}
	}
	s.data.Capabilities[c.Subject] = c
	s.appendAuditLocked("api", "capability.report", "capability", c.Subject, map[string]any{"state": c.State, "downgradeSuspect": c.DowngradeSuspect})
	return c, s.persistLocked()
}

func (s *Store) UpdateContext(id string, c model.RiskContext) (model.Asset, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.data.Assets[id]
	if !ok {
		return model.Asset{}, os.ErrNotExist
	}
	a.Context = c
	s.data.Assets[id] = a
	s.appendAuditLocked("api", "asset.context.update", "asset", id, nil)
	return a, s.persistLocked()
}

func (s *Store) ListAssets() []model.Asset {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]model.Asset, 0, len(s.data.Assets))
	for _, a := range s.data.Assets {
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Risk.Score > out[j].Risk.Score })
	return out
}

func (s *Store) GetAsset(id string) (model.Asset, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	a, ok := s.data.Assets[id]
	return a, ok
}
func (s *Store) GetScan(id string) (model.ScanJob, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	j, ok := s.data.Scans[id]
	return j, ok
}

func (s *Store) ListScans() []model.ScanJob {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]model.ScanJob, 0, len(s.data.Scans))
	for _, j := range s.data.Scans {
		out = append(out, j)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].StartedAt.After(out[j].StartedAt) })
	return out
}
func (s *Store) ListFindings() []model.Finding {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]model.Finding, 0, len(s.data.Findings))
	for _, f := range s.data.Findings {
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool { return severityRank(out[i].Severity) > severityRank(out[j].Severity) })
	return out
}
func (s *Store) ListCapabilities() []model.CapabilityRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]model.CapabilityRecord, 0, len(s.data.Capabilities))
	for _, c := range s.data.Capabilities {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Subject < out[j].Subject })
	return out
}
func (s *Store) AuditEvents() []model.AuditEvent {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]model.AuditEvent(nil), s.data.Audit...)
}

func (s *Store) VerifyAudit() (bool, int, string) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	prev := ""
	for i, e := range s.data.Audit {
		if e.PrevHash != prev {
			return false, i, "previous hash mismatch"
		}
		expected := hashEvent(e)
		if expected != e.Hash {
			return false, i, "event hash mismatch"
		}
		prev = e.Hash
	}
	return true, -1, "ok"
}

func (s *Store) appendAuditLocked(actor, action, objectType, objectID string, details map[string]any) {
	prev := ""
	if n := len(s.data.Audit); n > 0 {
		prev = s.data.Audit[n-1].Hash
	}
	e := model.AuditEvent{Sequence: int64(len(s.data.Audit) + 1), Timestamp: time.Now().UTC(), Actor: actor, Action: action, ObjectType: objectType, ObjectID: objectID, Details: details, PrevHash: prev}
	e.Hash = hashEvent(e)
	s.data.Audit = append(s.data.Audit, e)
}

func hashEvent(e model.AuditEvent) string {
	clone := e
	clone.Hash = ""
	b, _ := json.Marshal(clone)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func severityRank(s string) int {
	switch s {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	default:
		return 1
	}
}
