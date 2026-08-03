package runtime

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
)

type state struct {
	Version     int                           `json:"version"`
	Deployments map[string]Deployment         `json:"deployments"`
	Directives  map[string]EmergencyDirective `json:"directives"`
	RecryptJobs map[string]RecryptJob         `json:"recryptJobs"`
	Audit       []AuditRecord                 `json:"audit"`
}

type StateStore struct {
	mu   sync.RWMutex
	path string
	data state
}

func OpenStateStore(path string) (*StateStore, error) {
	s := &StateStore{path: path, data: emptyState()}
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
		return nil, fmt.Errorf("decode runtime state: %w", err)
	}
	s.ensureMaps()
	return s, nil
}

func emptyState() state {
	return state{
		Version:     1,
		Deployments: map[string]Deployment{},
		Directives:  map[string]EmergencyDirective{},
		RecryptJobs: map[string]RecryptJob{},
		Audit:       []AuditRecord{},
	}
}

func (s *StateStore) ensureMaps() {
	if s.data.Deployments == nil {
		s.data.Deployments = map[string]Deployment{}
	}
	if s.data.Directives == nil {
		s.data.Directives = map[string]EmergencyDirective{}
	}
	if s.data.RecryptJobs == nil {
		s.data.RecryptJobs = map[string]RecryptJob{}
	}
	if s.data.Audit == nil {
		s.data.Audit = []AuditRecord{}
	}
}

func (s *StateStore) persistLocked() error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o750); err != nil {
		return err
	}
	b, err := json.MarshalIndent(s.data, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

func (s *StateStore) PutDeployment(d Deployment, actor, action string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data.Deployments[d.ID] = d
	s.appendAuditLocked(actor, action, d.ID, map[string]any{"state": d.State, "service": d.Service, "canaryPercent": d.CanaryPercent})
	return s.persistLocked()
}

func (s *StateStore) GetDeployment(id string) (Deployment, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	d, ok := s.data.Deployments[id]
	return d, ok
}

func (s *StateStore) ListDeployments() []Deployment {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Deployment, 0, len(s.data.Deployments))
	for _, d := range s.data.Deployments {
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].UpdatedAt.After(out[j].UpdatedAt) })
	return out
}

func (s *StateStore) PutDirective(d EmergencyDirective, actor, action string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data.Directives[d.ID] = d
	s.appendAuditLocked(actor, action, d.ID, map[string]any{"status": d.Status, "severity": d.Severity})
	return s.persistLocked()
}

func (s *StateStore) ReserveDirective(d EmergencyDirective, actor, action string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.data.Directives[d.ID]; exists {
		return errors.New("emergency directive has already been processed")
	}
	s.data.Directives[d.ID] = d
	s.appendAuditLocked(actor, action, d.ID, map[string]any{"status": d.Status, "severity": d.Severity})
	if err := s.persistLocked(); err != nil {
		delete(s.data.Directives, d.ID)
		s.data.Audit = s.data.Audit[:len(s.data.Audit)-1]
		return err
	}
	return nil
}

func (s *StateStore) GetDirective(id string) (EmergencyDirective, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	d, ok := s.data.Directives[id]
	return d, ok
}

func (s *StateStore) ListDirectives() []EmergencyDirective {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]EmergencyDirective, 0, len(s.data.Directives))
	for _, d := range s.data.Directives {
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].IssuedAt.After(out[j].IssuedAt) })
	return out
}

func (s *StateStore) PutRecryptJob(j RecryptJob, actor, action string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data.RecryptJobs[j.ID] = j
	s.appendAuditLocked(actor, action, j.ID, map[string]any{"status": j.Status, "mode": j.Mode, "source": j.Source})
	return s.persistLocked()
}

func (s *StateStore) GetRecryptJob(id string) (RecryptJob, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	j, ok := s.data.RecryptJobs[id]
	return j, ok
}

func (s *StateStore) ListRecryptJobs() []RecryptJob {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]RecryptJob, 0, len(s.data.RecryptJobs))
	for _, j := range s.data.RecryptJobs {
		out = append(out, j)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].UpdatedAt.After(out[j].UpdatedAt) })
	return out
}

func (s *StateStore) AuditRecords() []AuditRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]AuditRecord(nil), s.data.Audit...)
}

func (s *StateStore) VerifyAudit() error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	previous := ""
	for i, record := range s.data.Audit {
		if record.PrevHash != previous {
			return fmt.Errorf("audit record %d previous hash mismatch", i)
		}
		if hashAudit(record) != record.Hash {
			return fmt.Errorf("audit record %d hash mismatch", i)
		}
		previous = record.Hash
	}
	return nil
}

func (s *StateStore) appendAuditLocked(actor, action, objectID string, details map[string]any) {
	previous := ""
	if len(s.data.Audit) > 0 {
		previous = s.data.Audit[len(s.data.Audit)-1].Hash
	}
	r := AuditRecord{
		Sequence: int64(len(s.data.Audit) + 1),
		Time:     time.Now().UTC(),
		Actor:    actor,
		Action:   action,
		ObjectID: objectID,
		Details:  details,
		PrevHash: previous,
	}
	r.Hash = hashAudit(r)
	s.data.Audit = append(s.data.Audit, r)
}

func hashAudit(r AuditRecord) string {
	copy := r
	copy.Hash = ""
	b, _ := json.Marshal(copy)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
