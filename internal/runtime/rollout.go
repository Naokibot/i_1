package runtime

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

type RolloutController struct {
	store *StateStore
	now   func() time.Time
}

func NewRolloutController(store *StateStore) *RolloutController {
	return &RolloutController{store: store, now: func() time.Time { return time.Now().UTC() }}
}

func (c *RolloutController) CreateDeployment(service string, stable GatewayConfig, thresholds Thresholds) (Deployment, error) {
	if strings.TrimSpace(service) == "" {
		return Deployment{}, errors.New("service is required")
	}
	if stable.Revision == "" {
		return Deployment{}, errors.New("stable revision is required")
	}
	thresholds = normalizeThresholds(thresholds)
	now := c.now()
	d := Deployment{
		ID:            newID("deployment"),
		Service:       service,
		State:         RolloutDraft,
		Stable:        stable,
		Thresholds:    thresholds,
		CreatedAt:     now,
		UpdatedAt:     now,
		CanaryPercent: 0,
	}
	return d, c.store.PutDeployment(d, "runtime-controller", "deployment.create")
}

func (c *RolloutController) SetCandidate(id string, candidate GatewayConfig) (Deployment, error) {
	d, ok := c.store.GetDeployment(id)
	if !ok {
		return Deployment{}, errors.New("deployment not found")
	}
	if candidate.Revision == "" || candidate.Revision == d.Stable.Revision {
		return Deployment{}, errors.New("candidate revision must be non-empty and differ from stable")
	}
	if err := validateGatewayConfig(candidate); err != nil {
		return Deployment{}, err
	}
	d.Candidate = &candidate
	d.State = RolloutValidating
	d.CanaryPercent = 0
	d.LastFailure = ""
	d.UpdatedAt = c.now()
	return d, c.store.PutDeployment(d, "runtime-controller", "deployment.candidate.set")
}

func (c *RolloutController) Advance(id string, metrics MetricWindow) (Deployment, error) {
	d, ok := c.store.GetDeployment(id)
	if !ok {
		return Deployment{}, errors.New("deployment not found")
	}
	if d.Candidate == nil {
		return Deployment{}, errors.New("deployment has no candidate")
	}
	d.LastMetrics = &metrics
	if failure := evaluateMetrics(metrics, d.Thresholds); failure != "" {
		return c.rollback(d, failure)
	}
	switch d.State {
	case RolloutValidating:
		d.State = RolloutShadow
	case RolloutShadow:
		d.State = RolloutCanary
		d.CanaryPercent = 1
	case RolloutCanary:
		switch d.CanaryPercent {
		case 0:
			d.CanaryPercent = 1
		case 1:
			d.CanaryPercent = 5
		case 5:
			d.CanaryPercent = 25
		case 25:
			d.CanaryPercent = 50
		case 50:
			d.CanaryPercent = 100
		default:
			d.CanaryPercent = 100
		}
		if d.CanaryPercent == 100 {
			d.PreviousRevisions = append(d.PreviousRevisions, d.Stable.Revision)
			d.Stable = *d.Candidate
			d.Candidate = nil
			d.State = RolloutFull
		}
	case RolloutFull:
		return d, errors.New("deployment is already fully rolled out")
	case RolloutRolledBack, RolloutFailed:
		return d, errors.New("deployment must receive a new candidate after rollback or failure")
	default:
		return d, fmt.Errorf("cannot advance from state %q", d.State)
	}
	d.UpdatedAt = c.now()
	return d, c.store.PutDeployment(d, "runtime-controller", "deployment.advance")
}

func (c *RolloutController) Rollback(id, reason string) (Deployment, error) {
	d, ok := c.store.GetDeployment(id)
	if !ok {
		return Deployment{}, errors.New("deployment not found")
	}
	if strings.TrimSpace(reason) == "" {
		reason = "manual rollback"
	}
	return c.rollback(d, reason)
}

func (c *RolloutController) rollback(d Deployment, reason string) (Deployment, error) {
	d.State = RolloutRolledBack
	d.CanaryPercent = 0
	d.LastFailure = reason
	d.Candidate = nil
	d.UpdatedAt = c.now()
	return d, c.store.PutDeployment(d, "runtime-controller", "deployment.rollback")
}

func normalizeThresholds(t Thresholds) Thresholds {
	if t.MinimumSuccessRate == 0 {
		t.MinimumSuccessRate = 0.995
	}
	if t.MaximumFallbackRate == 0 {
		t.MaximumFallbackRate = 0.01
	}
	if t.MaximumP99Ratio == 0 {
		t.MaximumP99Ratio = 1.25
	}
	if t.MinimumSamples == 0 {
		t.MinimumSamples = 100
	}
	return t
}

func validateGatewayConfig(c GatewayConfig) error {
	if c.Kind != "tls" && c.Kind != "ssh" && c.Kind != "vpn" {
		return errors.New("gateway kind must be tls, ssh, or vpn")
	}
	if c.Listen == "" || c.Upstream == "" {
		return errors.New("listen and upstream are required")
	}
	if c.Kind == "tls" && len(c.Groups) == 0 {
		return errors.New("TLS gateway must declare allowed groups")
	}
	return nil
}

func evaluateMetrics(m MetricWindow, t Thresholds) string {
	if m.Handshakes < t.MinimumSamples {
		return fmt.Sprintf("insufficient samples: got %d, require %d", m.Handshakes, t.MinimumSamples)
	}
	if m.SuccessRate() < t.MinimumSuccessRate {
		return fmt.Sprintf("success rate %.5f below %.5f", m.SuccessRate(), t.MinimumSuccessRate)
	}
	if m.FallbackRate() > t.MaximumFallbackRate {
		return fmt.Sprintf("fallback rate %.5f above %.5f", m.FallbackRate(), t.MaximumFallbackRate)
	}
	if m.P99Ratio() > t.MaximumP99Ratio {
		return fmt.Sprintf("p99 ratio %.3f above %.3f", m.P99Ratio(), t.MaximumP99Ratio)
	}
	return ""
}

func InCanary(serviceID, clientID string, percent int) bool {
	if percent <= 0 {
		return false
	}
	if percent >= 100 {
		return true
	}
	sum := sha256.Sum256([]byte(serviceID + "\x00" + clientID))
	bucket := int(binary.BigEndian.Uint32(sum[:4]) % 100)
	return bucket < percent
}

func VerifyEmergencyDirective(rootPublicKey ed25519.PublicKey, approverKeys map[string]ed25519.PublicKey, directive EmergencyDirective, now time.Time) error {
	if len(rootPublicKey) != ed25519.PublicKeySize {
		return errors.New("invalid emergency root signing public key")
	}
	if directive.ID == "" || directive.IssuedAt.IsZero() || directive.ExpiresAt.IsZero() {
		return errors.New("directive identity and validity window are required")
	}
	if now.Before(directive.IssuedAt.Add(-5*time.Minute)) || !now.Before(directive.ExpiresAt) {
		return errors.New("directive is not currently valid")
	}
	payload, err := canonicalDirective(directive)
	if err != nil {
		return err
	}
	rootSignature, err := base64.StdEncoding.DecodeString(directive.Signature)
	if err != nil {
		return fmt.Errorf("decode directive signature: %w", err)
	}
	if !ed25519.Verify(rootPublicKey, payload, rootSignature) {
		return errors.New("directive root signature verification failed")
	}
	validApprovers := map[string]struct{}{}
	for _, approval := range directive.Approvals {
		name := strings.TrimSpace(approval.Approver)
		key, trusted := approverKeys[name]
		if !trusted || len(key) != ed25519.PublicKeySize {
			continue
		}
		signature, err := base64.StdEncoding.DecodeString(approval.Signature)
		if err != nil || !ed25519.Verify(key, payload, signature) {
			continue
		}
		validApprovers[name] = struct{}{}
	}
	if len(validApprovers) < 2 {
		return errors.New("two distinct trusted approver signatures are required")
	}
	return nil
}

func SignEmergencyDirective(privateKey ed25519.PrivateKey, directive EmergencyDirective) (EmergencyDirective, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return EmergencyDirective{}, errors.New("invalid emergency signing private key")
	}
	payload, err := canonicalDirective(directive)
	if err != nil {
		return EmergencyDirective{}, err
	}
	directive.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, payload))
	return directive, nil
}

func SignEmergencyApproval(privateKey ed25519.PrivateKey, approver string, directive EmergencyDirective) (EmergencyDirective, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return EmergencyDirective{}, errors.New("invalid approver private key")
	}
	approver = strings.TrimSpace(approver)
	if approver == "" {
		return EmergencyDirective{}, errors.New("approver is required")
	}
	payload, err := canonicalDirective(directive)
	if err != nil {
		return EmergencyDirective{}, err
	}
	approval := EmergencyApproval{Approver: approver, Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, payload))}
	filtered := make([]EmergencyApproval, 0, len(directive.Approvals)+1)
	for _, existing := range directive.Approvals {
		if strings.TrimSpace(existing.Approver) != approver {
			filtered = append(filtered, existing)
		}
	}
	directive.Approvals = append(filtered, approval)
	return directive, nil
}

func canonicalDirective(d EmergencyDirective) ([]byte, error) {
	d.Signature = ""
	d.Status = ""
	d.AffectedDeployments = nil
	d.ExecutionDescription = ""
	d.Approvals = nil
	d.AffectedAlgorithms = uniqueStrings(d.AffectedAlgorithms)
	sort.Strings(d.AffectedAlgorithms)
	d.ReplacementGroups = uniqueStrings(d.ReplacementGroups)
	sort.Strings(d.ReplacementGroups)
	return json.Marshal(d)
}

func uniqueStrings(values []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func (c *RolloutController) ExecuteEmergency(rootPublicKey ed25519.PublicKey, approverKeys map[string]ed25519.PublicKey, directive EmergencyDirective) (EmergencyDirective, error) {
	if err := VerifyEmergencyDirective(rootPublicKey, approverKeys, directive, c.now()); err != nil {
		return EmergencyDirective{}, err
	}
	directive.Status = "reserved"
	if err := c.store.ReserveDirective(directive, "runtime-controller", "emergency.reserve"); err != nil {
		return EmergencyDirective{}, err
	}
	affected := []string{}
	for _, deployment := range c.store.ListDeployments() {
		if !configurationUsesAny(deployment.Stable, directive.AffectedAlgorithms) && (deployment.Candidate == nil || !configurationUsesAny(*deployment.Candidate, directive.AffectedAlgorithms)) {
			continue
		}
		candidate := deployment.Stable
		candidate.Revision = directive.ID + "-" + deployment.Stable.Revision
		candidate.Groups = append([]string(nil), directive.ReplacementGroups...)
		if !directive.FallbackAllowed {
			candidate.Environment = cloneMap(candidate.Environment)
			candidate.Environment["PQM_FALLBACK_ALLOWED"] = "false"
		}
		if _, err := c.SetCandidate(deployment.ID, candidate); err != nil {
			return EmergencyDirective{}, fmt.Errorf("prepare %s: %w", deployment.ID, err)
		}
		affected = append(affected, deployment.ID)
	}
	directive.Status = "executing"
	directive.AffectedDeployments = affected
	directive.ExecutionDescription = fmt.Sprintf("prepared %d deployment candidates for canary rollout", len(affected))
	if len(affected) == 0 {
		directive.Status = "completed-no-impact"
	}
	return directive, c.store.PutDirective(directive, "runtime-controller", "emergency.execute")
}

func configurationUsesAny(config GatewayConfig, algorithms []string) bool {
	for _, group := range config.Groups {
		for _, affected := range algorithms {
			if strings.EqualFold(group, affected) || strings.Contains(strings.ToLower(group), strings.ToLower(affected)) {
				return true
			}
		}
	}
	return false
}

func cloneMap(in map[string]string) map[string]string {
	out := make(map[string]string, len(in)+1)
	for k, v := range in {
		out[k] = v
	}
	return out
}
