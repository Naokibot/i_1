package model

import (
	"crypto/rand"
	"encoding/hex"
	"time"
)

type AssetKind string

const (
	AssetTLS    AssetKind = "tls-service"
	AssetSSH    AssetKind = "ssh-service"
	AssetSource AssetKind = "source-project"
	AssetManual AssetKind = "manual"
)

type Asset struct {
	ID            string                  `json:"id"`
	Name          string                  `json:"name"`
	Kind          AssetKind               `json:"kind"`
	Location      string                  `json:"location"`
	Status        string                  `json:"status"`
	DiscoveredAt  time.Time               `json:"discoveredAt"`
	LastObserved  time.Time               `json:"lastObserved"`
	Context       RiskContext             `json:"context"`
	Crypto        []CryptoComponent       `json:"crypto"`
	Relationships []Relationship          `json:"relationships,omitempty"`
	Evidence      map[string]any          `json:"evidence,omitempty"`
	Risk          RiskAssessment          `json:"risk"`
	Migration     MigrationRecommendation `json:"migration"`
}

type RiskContext struct {
	DataClassification  string `json:"dataClassification"`
	RetentionDays       int    `json:"retentionDays"`
	InternetExposed     bool   `json:"internetExposed"`
	BusinessCriticality int    `json:"businessCriticality"`
	Updateability       string `json:"updateability"`
	HasAlternative      bool   `json:"hasAlternative"`
	HarvestNowRisk      string `json:"harvestNowRisk"`
}

type CryptoComponent struct {
	ID          string            `json:"id"`
	Category    string            `json:"category"`
	Algorithm   string            `json:"algorithm"`
	Primitive   string            `json:"primitive,omitempty"`
	Usage       string            `json:"usage,omitempty"`
	KeySize     int               `json:"keySize,omitempty"`
	Protocol    string            `json:"protocol,omitempty"`
	Version     string            `json:"version,omitempty"`
	Mode        string            `json:"mode,omitempty"`
	OID         string            `json:"oid,omitempty"`
	PQCStatus   string            `json:"pqcStatus"`
	Source      string            `json:"source"`
	Fingerprint string            `json:"fingerprint,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

type Relationship struct {
	FromID string `json:"fromId"`
	ToID   string `json:"toId"`
	Type   string `json:"type"`
}

type RiskAssessment struct {
	Score       int            `json:"score"`
	Level       string         `json:"level"`
	Factors     map[string]int `json:"factors"`
	Explanation []string       `json:"explanation"`
	EvaluatedAt time.Time      `json:"evaluatedAt"`
}

type MigrationRecommendation struct {
	Stage       int      `json:"stage"`
	StageName   string   `json:"stageName"`
	PathStatus  string   `json:"pathStatus"`
	Rationale   []string `json:"rationale"`
	Blockers    []string `json:"blockers,omitempty"`
	NextActions []string `json:"nextActions"`
}

type Finding struct {
	ID          string    `json:"id"`
	AssetID     string    `json:"assetId"`
	RuleID      string    `json:"ruleId"`
	Severity    string    `json:"severity"`
	Title       string    `json:"title"`
	Detail      string    `json:"detail"`
	Location    string    `json:"location"`
	Evidence    string    `json:"evidence,omitempty"`
	Remediation string    `json:"remediation"`
	Status      string    `json:"status"`
	CreatedAt   time.Time `json:"createdAt"`
}

type ScanRequest struct {
	Kind                string `json:"kind"`
	Target              string `json:"target"`
	Port                int    `json:"port,omitempty"`
	DataClassification  string `json:"dataClassification,omitempty"`
	RetentionDays       int    `json:"retentionDays,omitempty"`
	InternetExposed     bool   `json:"internetExposed,omitempty"`
	BusinessCriticality int    `json:"businessCriticality,omitempty"`
	Updateability       string `json:"updateability,omitempty"`
	HasAlternative      bool   `json:"hasAlternative,omitempty"`
	HarvestNowRisk      string `json:"harvestNowRisk,omitempty"`
}

type ScanJob struct {
	ID         string      `json:"id"`
	Request    ScanRequest `json:"request"`
	Status     string      `json:"status"`
	Error      string      `json:"error,omitempty"`
	AssetID    string      `json:"assetId,omitempty"`
	StartedAt  time.Time   `json:"startedAt"`
	FinishedAt *time.Time  `json:"finishedAt,omitempty"`
}

type CapabilityRecord struct {
	ID               string          `json:"id"`
	Subject          string          `json:"subject"`
	State            string          `json:"state"`
	Algorithms       map[string]bool `json:"algorithms"`
	LastSeen         time.Time       `json:"lastSeen"`
	PreviousState    string          `json:"previousState,omitempty"`
	DowngradeSuspect bool            `json:"downgradeSuspect"`
	Notes            []string        `json:"notes,omitempty"`
}

type AuditEvent struct {
	Sequence   int64          `json:"sequence"`
	Timestamp  time.Time      `json:"timestamp"`
	Actor      string         `json:"actor"`
	Action     string         `json:"action"`
	ObjectType string         `json:"objectType"`
	ObjectID   string         `json:"objectId"`
	Details    map[string]any `json:"details,omitempty"`
	PrevHash   string         `json:"prevHash"`
	Hash       string         `json:"hash"`
}

func NewUUID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "00000000-0000-4000-8000-" + time.Now().UTC().Format("060102150405")
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return hex.EncodeToString(b[0:4]) + "-" + hex.EncodeToString(b[4:6]) + "-" + hex.EncodeToString(b[6:8]) + "-" + hex.EncodeToString(b[8:10]) + "-" + hex.EncodeToString(b[10:16])
}

func NewID(prefix string) string {
	b := make([]byte, 10)
	if _, err := rand.Read(b); err != nil {
		return prefix + "-" + time.Now().UTC().Format("20060102150405.000000000")
	}
	return prefix + "-" + hex.EncodeToString(b)
}

func ContextFromRequest(r ScanRequest) RiskContext {
	c := RiskContext{
		DataClassification:  r.DataClassification,
		RetentionDays:       r.RetentionDays,
		InternetExposed:     r.InternetExposed,
		BusinessCriticality: r.BusinessCriticality,
		Updateability:       r.Updateability,
		HasAlternative:      r.HasAlternative,
		HarvestNowRisk:      r.HarvestNowRisk,
	}
	if c.DataClassification == "" {
		c.DataClassification = "internal"
	}
	if c.BusinessCriticality == 0 {
		c.BusinessCriticality = 3
	}
	if c.Updateability == "" {
		c.Updateability = "unknown"
	}
	if c.HarvestNowRisk == "" {
		c.HarvestNowRisk = "unknown"
	}
	return c
}
