package runtime

import "time"

type RolloutState string

const (
	RolloutDraft      RolloutState = "draft"
	RolloutValidating RolloutState = "validating"
	RolloutShadow     RolloutState = "shadow"
	RolloutCanary     RolloutState = "canary"
	RolloutFull       RolloutState = "full"
	RolloutRolledBack RolloutState = "rolled-back"
	RolloutFailed     RolloutState = "failed"
)

type GatewayConfig struct {
	Revision       string            `json:"revision"`
	Kind           string            `json:"kind"`
	Listen         string            `json:"listen"`
	Upstream       string            `json:"upstream"`
	ServerName     string            `json:"serverName,omitempty"`
	Certificate    string            `json:"certificate,omitempty"`
	PrivateKey     string            `json:"privateKey,omitempty"`
	CAFile         string            `json:"caFile,omitempty"`
	Groups         []string          `json:"groups,omitempty"`
	Provider       string            `json:"provider,omitempty"`
	ProviderPath   string            `json:"providerPath,omitempty"`
	TelemetryFile  string            `json:"telemetryFile,omitempty"`
	VerifyUpstream bool              `json:"verifyUpstream"`
	Command        []string          `json:"command,omitempty"`
	Environment    map[string]string `json:"environment,omitempty"`
	HealthAddress  string            `json:"healthAddress,omitempty"`
}

type Thresholds struct {
	MinimumSuccessRate  float64 `json:"minimumSuccessRate"`
	MaximumFallbackRate float64 `json:"maximumFallbackRate"`
	MaximumP99Ratio     float64 `json:"maximumP99Ratio"`
	MinimumSamples      int64   `json:"minimumSamples"`
}

type MetricWindow struct {
	StartedAt         time.Time `json:"startedAt"`
	CompletedAt       time.Time `json:"completedAt"`
	Handshakes        int64     `json:"handshakes"`
	Failures          int64     `json:"failures"`
	Fallbacks         int64     `json:"fallbacks"`
	P99LatencyMillis  float64   `json:"p99LatencyMillis"`
	StableP99Millis   float64   `json:"stableP99Millis"`
	ConfigurationHash string    `json:"configurationHash,omitempty"`
}

func (m MetricWindow) SuccessRate() float64 {
	if m.Handshakes == 0 {
		return 0
	}
	return float64(m.Handshakes-m.Failures) / float64(m.Handshakes)
}

func (m MetricWindow) FallbackRate() float64 {
	if m.Handshakes == 0 {
		return 0
	}
	return float64(m.Fallbacks) / float64(m.Handshakes)
}

func (m MetricWindow) P99Ratio() float64 {
	if m.StableP99Millis <= 0 {
		return 1
	}
	return m.P99LatencyMillis / m.StableP99Millis
}

type Deployment struct {
	ID                string         `json:"id"`
	Service           string         `json:"service"`
	State             RolloutState   `json:"state"`
	Stable            GatewayConfig  `json:"stable"`
	Candidate         *GatewayConfig `json:"candidate,omitempty"`
	CanaryPercent     int            `json:"canaryPercent"`
	Thresholds        Thresholds     `json:"thresholds"`
	LastMetrics       *MetricWindow  `json:"lastMetrics,omitempty"`
	LastFailure       string         `json:"lastFailure,omitempty"`
	PreviousRevisions []string       `json:"previousRevisions,omitempty"`
	CreatedAt         time.Time      `json:"createdAt"`
	UpdatedAt         time.Time      `json:"updatedAt"`
}

type EmergencyApproval struct {
	Approver  string `json:"approver"`
	Signature string `json:"signature"`
}

type EmergencyDirective struct {
	ID                   string              `json:"id"`
	IssuedAt             time.Time           `json:"issuedAt"`
	ExpiresAt            time.Time           `json:"expiresAt"`
	Severity             string              `json:"severity"`
	AffectedAlgorithms   []string            `json:"affectedAlgorithms"`
	ReplacementGroups    []string            `json:"replacementGroups"`
	MinimumVersion       string              `json:"minimumVersion,omitempty"`
	FallbackAllowed      bool                `json:"fallbackAllowed"`
	Approvals            []EmergencyApproval `json:"approvals"`
	Signature            string              `json:"signature"`
	Status               string              `json:"status"`
	AffectedDeployments  []string            `json:"affectedDeployments,omitempty"`
	ExecutionDescription string              `json:"executionDescription,omitempty"`
}

type RecryptStatus string

const (
	RecryptQueued    RecryptStatus = "queued"
	RecryptRunning   RecryptStatus = "running"
	RecryptVerifying RecryptStatus = "verifying"
	RecryptCompleted RecryptStatus = "completed"
	RecryptFailed    RecryptStatus = "failed"
)

type RecryptJob struct {
	ID             string        `json:"id"`
	Mode           string        `json:"mode"`
	Source         string        `json:"source"`
	Destination    string        `json:"destination"`
	SourceKey      string        `json:"sourceKey,omitempty"`
	TargetKey      string        `json:"targetKey"`
	KEMAlgorithm   string        `json:"kemAlgorithm"`
	Status         RecryptStatus `json:"status"`
	PlaintextHash  string        `json:"plaintextHash,omitempty"`
	BytesProcessed int64         `json:"bytesProcessed"`
	Error          string        `json:"error,omitempty"`
	CreatedAt      time.Time     `json:"createdAt"`
	UpdatedAt      time.Time     `json:"updatedAt"`
}

type AuditRecord struct {
	Sequence int64          `json:"sequence"`
	Time     time.Time      `json:"time"`
	Actor    string         `json:"actor"`
	Action   string         `json:"action"`
	ObjectID string         `json:"objectId"`
	Details  map[string]any `json:"details,omitempty"`
	PrevHash string         `json:"prevHash"`
	Hash     string         `json:"hash"`
}
