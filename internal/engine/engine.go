package engine

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/Naokibot/i_1/internal/model"
	"github.com/Naokibot/i_1/internal/risk"
	"github.com/Naokibot/i_1/internal/scanner"
	"github.com/Naokibot/i_1/internal/store"
)

type Engine struct {
	store      *store.Store
	sourceRoot string
}

func New(st *store.Store, sourceRoot string) (*Engine, error) {
	abs, err := filepath.Abs(sourceRoot)
	if err != nil {
		return nil, err
	}
	return &Engine{store: st, sourceRoot: abs}, nil
}

func (e *Engine) Start(req model.ScanRequest) (model.ScanJob, error) {
	if err := validate(req); err != nil {
		return model.ScanJob{}, err
	}
	j := model.ScanJob{ID: model.NewID("scan"), Request: req, Status: "queued", StartedAt: time.Now().UTC()}
	if err := e.store.CreateScan(j); err != nil {
		return model.ScanJob{}, err
	}
	go e.run(j)
	return j, nil
}

func (e *Engine) run(j model.ScanJob) {
	j.Status = "running"
	_ = e.store.UpdateScan(j)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	var a model.Asset
	var f []model.Finding
	var err error
	switch strings.ToLower(j.Request.Kind) {
	case "tls":
		a, f, err = scanner.ScanTLS(ctx, j.Request)
	case "ssh":
		a, f, err = scanner.ScanSSH(ctx, j.Request)
	case "source":
		a, f, err = scanner.ScanSource(ctx, j.Request, e.sourceRoot)
	default:
		err = fmt.Errorf("unsupported scan kind")
	}
	now := time.Now().UTC()
	j.FinishedAt = &now
	if err != nil {
		j.Status = "failed"
		j.Error = err.Error()
		_ = e.store.UpdateScan(j)
		return
	}
	a.Risk = risk.Evaluate(a)
	a.Migration = risk.Recommend(a)
	if err := e.store.UpsertAsset(a, "scanner"); err != nil {
		j.Status = "failed"
		j.Error = err.Error()
		_ = e.store.UpdateScan(j)
		return
	}
	if len(f) > 0 {
		_ = e.store.AddFindings(f, "scanner")
	}
	j.Status = "completed"
	j.AssetID = a.ID
	_ = e.store.UpdateScan(j)
}

func (e *Engine) Recalculate(id string) (model.Asset, error) {
	a, ok := e.store.GetAsset(id)
	if !ok {
		return model.Asset{}, fmt.Errorf("asset not found")
	}
	a.Risk = risk.Evaluate(a)
	a.Migration = risk.Recommend(a)
	return a, e.store.UpsertAsset(a, "risk-engine")
}
func validate(r model.ScanRequest) error {
	if r.Target == "" {
		return fmt.Errorf("target is required")
	}
	switch strings.ToLower(r.Kind) {
	case "tls", "ssh", "source":
	default:
		return fmt.Errorf("kind must be tls, ssh, or source")
	}
	if r.BusinessCriticality < 0 || r.BusinessCriticality > 5 {
		return fmt.Errorf("businessCriticality must be 1-5")
	}
	if r.Port < 0 || r.Port > 65535 {
		return fmt.Errorf("invalid port")
	}
	return nil
}
