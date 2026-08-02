package policy

import (
	"fmt"
	"strings"
	"time"
)

type Policy struct {
	DataClassification string       `json:"dataClassification"`
	RetentionPeriod    string       `json:"retentionPeriod"`
	Requirements       Requirements `json:"requirements"`
	Exceptions         Exceptions   `json:"exceptions"`
}
type Requirements struct {
	KeyExchange Minimum `json:"keyExchange"`
	Signature   Minimum `json:"signature"`
	Storage     Storage `json:"storage"`
}
type Minimum struct {
	Minimum string `json:"minimum"`
}
type Storage struct {
	PQCKeyWrapping string `json:"pqcKeyWrapping"`
}
type Exceptions struct {
	LegacyDevices LegacyDevices `json:"legacyDevices"`
}
type LegacyDevices struct {
	TemporaryGateway string `json:"temporaryGateway"`
	Deadline         string `json:"deadline"`
}
type Compiled struct {
	Profile            string     `json:"profile"`
	AllowedKeyExchange []string   `json:"allowedKeyExchange"`
	SignatureModes     []string   `json:"signatureModes"`
	StorageKeyWrapping string     `json:"storageKeyWrapping"`
	GatewayAllowed     bool       `json:"gatewayAllowed"`
	Deadline           *time.Time `json:"deadline,omitempty"`
	Rollout            []string   `json:"rollout"`
	AuditRules         []string   `json:"auditRules"`
	Warnings           []string   `json:"warnings,omitempty"`
}

func Compile(p Policy) (Compiled, error) {
	c := Compiled{Profile: p.DataClassification + "/" + p.RetentionPeriod, StorageKeyWrapping: p.Requirements.Storage.PQCKeyWrapping, Rollout: []string{"Observe", "Simulate", "Shadow", "Hybrid", "PQC Preferred", "PQC Required", "Legacy Removal"}, AuditRules: []string{"Record negotiated algorithms", "Alert on capability regression", "Require approval for legacy fallback", "Verify signed audit hash chain"}}
	switch strings.ToLower(p.Requirements.KeyExchange.Minimum) {
	case "hybrid-pqc":
		c.AllowedKeyExchange = []string{"X25519MLKEM768", "ML-KEM-768", "approved future hybrid groups"}
	case "pqc":
		c.AllowedKeyExchange = []string{"ML-KEM-768", "approved PQC KEMs"}
	case "classical":
		c.AllowedKeyExchange = []string{"X25519", "P-256"}
	default:
		return c, fmt.Errorf("unknown key exchange minimum")
	}
	switch strings.ToLower(p.Requirements.Signature.Minimum) {
	case "dual-signature":
		c.SignatureModes = []string{"parallel-classical-and-ML-DSA", "dual-certificate"}
	case "pqc":
		c.SignatureModes = []string{"ML-DSA", "SLH-DSA"}
	case "classical":
		c.SignatureModes = []string{"RSA", "ECDSA", "EdDSA"}
	default:
		return c, fmt.Errorf("unknown signature minimum")
	}
	c.GatewayAllowed = strings.EqualFold(p.Exceptions.LegacyDevices.TemporaryGateway, "allowed")
	if p.Exceptions.LegacyDevices.Deadline != "" {
		t, err := time.Parse("2006-01-02", p.Exceptions.LegacyDevices.Deadline)
		if err != nil {
			return c, fmt.Errorf("invalid legacy deadline: %w", err)
		}
		c.Deadline = &t
		if t.Before(time.Now()) {
			c.Warnings = append(c.Warnings, "legacy gateway exception deadline has passed")
		}
	}
	if c.GatewayAllowed {
		c.Warnings = append(c.Warnings, "A gateway does not make the legacy endpoint-to-gateway segment quantum resistant")
	}
	return c, nil
}
