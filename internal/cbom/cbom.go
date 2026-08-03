package cbom

import (
	"fmt"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Naokibot/i_1/internal/model"
)

type BOM struct {
	BomFormat    string       `json:"bomFormat"`
	SpecVersion  string       `json:"specVersion"`
	SerialNumber string       `json:"serialNumber"`
	Version      int          `json:"version"`
	Metadata     Metadata     `json:"metadata"`
	Components   []Component  `json:"components"`
	Dependencies []Dependency `json:"dependencies,omitempty"`
}
type Metadata struct {
	Timestamp  time.Time      `json:"timestamp"`
	Component  map[string]any `json:"component"`
	Properties []Property     `json:"properties,omitempty"`
}
type Property struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}
type Component struct {
	Type             string         `json:"type"`
	Name             string         `json:"name"`
	BomRef           string         `json:"bom-ref"`
	CryptoProperties map[string]any `json:"cryptoProperties,omitempty"`
	Properties       []Property     `json:"properties,omitempty"`
}
type Dependency struct {
	Ref       string   `json:"ref"`
	DependsOn []string `json:"dependsOn,omitempty"`
}

func Generate(assets []model.Asset) BOM {
	b := BOM{BomFormat: "CycloneDX", SpecVersion: "1.7", SerialNumber: "urn:uuid:" + model.NewUUID(), Version: 1, Metadata: Metadata{Timestamp: time.Now().UTC(), Component: map[string]any{"type": "application", "name": "PQM Observatory inventory", "version": "0.1.0"}, Properties: []Property{{"pqm.asset.count", strconv.Itoa(len(assets))}}}}
	seen := map[string]string{}
	deps := map[string][]string{}
	for _, a := range assets {
		appRef := "asset/" + a.ID
		b.Components = append(b.Components, Component{Type: "application", Name: a.Name, BomRef: appRef, Properties: []Property{{"pqm.location", a.Location}, {"pqm.risk.score", strconv.Itoa(a.Risk.Score)}, {"pqm.risk.level", a.Risk.Level}, {"pqm.migration.stage", a.Migration.StageName}, {"pqm.path.status", a.Migration.PathStatus}}})
		for _, c := range a.Crypto {
			key := c.Category + "|" + c.Algorithm + "|" + c.Version + "|" + c.Fingerprint
			ref, ok := seen[key]
			if !ok {
				ref = "crypto/" + sanitize(c.Category) + "/" + sanitize(c.Algorithm) + "@" + c.ID
				seen[key] = ref
				b.Components = append(b.Components, toComponent(c, ref))
			}
			deps[appRef] = appendUnique(deps[appRef], ref)
		}
	}
	for ref, d := range deps {
		sort.Strings(d)
		b.Dependencies = append(b.Dependencies, Dependency{Ref: ref, DependsOn: d})
	}
	sort.Slice(b.Components, func(i, j int) bool { return b.Components[i].BomRef < b.Components[j].BomRef })
	sort.Slice(b.Dependencies, func(i, j int) bool { return b.Dependencies[i].Ref < b.Dependencies[j].Ref })
	return b
}

func toComponent(c model.CryptoComponent, ref string) Component {
	cp := map[string]any{}
	switch c.Category {
	case "protocol":
		cp["assetType"] = "protocol"
		pp := map[string]any{"type": strings.ToLower(c.Protocol), "version": strings.TrimPrefix(strings.TrimPrefix(c.Version, "TLS "), "SSH ")}
		cp["protocolProperties"] = pp
	case "certificate":
		cp["assetType"] = "certificate"
		cert := map[string]any{"certificateFormat": "X.509", "certificateFileExtension": "crt"}
		if c.Metadata != nil {
			cert["subjectName"] = c.Metadata["subject"]
			cert["issuerName"] = c.Metadata["issuer"]
			cert["notValidBefore"] = c.Metadata["notBefore"]
			cert["notValidAfter"] = c.Metadata["notAfter"]
		}
		cp["certificateProperties"] = cert
	default:
		cp["assetType"] = "algorithm"
		ap := map[string]any{"executionEnvironment": "software-plain-ram", "implementationPlatform": runtime.GOARCH, "certificationLevel": []string{"none"}, "nistQuantumSecurityLevel": quantumLevel(c)}
		if c.Primitive != "" {
			ap["primitive"] = primitiveFor(c)
		}
		if c.KeySize > 0 {
			ap["parameterSetIdentifier"] = strconv.Itoa(c.KeySize)
			ap["classicalSecurityLevel"] = classicalLevel(c)
		}
		if c.Mode != "" {
			ap["mode"] = strings.ToLower(c.Mode)
		}
		cp["algorithmProperties"] = ap
	}
	if c.OID != "" {
		cp["oid"] = c.OID
	}
	props := []Property{{"pqm.pqc.status", c.PQCStatus}, {"pqm.source", c.Source}}
	if c.Usage != "" {
		props = append(props, Property{"pqm.usage", c.Usage})
	}
	if c.Fingerprint != "" {
		props = append(props, Property{"pqm.fingerprint.sha256", c.Fingerprint})
	}
	return Component{Type: "cryptographic-asset", Name: c.Algorithm, BomRef: ref, CryptoProperties: cp, Properties: props}
}
func primitiveFor(c model.CryptoComponent) string {
	s := strings.ToLower(c.Primitive)
	a := strings.ToLower(c.Algorithm)
	switch {
	case strings.Contains(s, "signature") && !strings.Contains(s, "key-transport"):
		return "signature"
	case strings.Contains(s, "key-agreement"):
		return "key-agree"
	case strings.Contains(s, "hash"):
		return "hash"
	case strings.Contains(s, "mac"):
		return "mac"
	case strings.Contains(a, "ml-kem") || strings.Contains(a, "mlkem"):
		return "kem"
	case strings.Contains(a, "rsa") && strings.Contains(s, "encryption"):
		return "pke"
	case strings.Contains(s, "encryption-mode"):
		return "block-cipher"
	case strings.Contains(s, "authenticated"):
		return "ae"
	case strings.Contains(s, "encryption"):
		return "other"
	}
	return "other"
}
func quantumLevel(c model.CryptoComponent) int {
	switch c.PQCStatus {
	case "native", "hybrid":
		return 1
	default:
		return 0
	}
}
func classicalLevel(c model.CryptoComponent) int {
	if c.KeySize >= 4096 {
		return 152
	}
	if c.KeySize >= 3072 {
		return 128
	}
	if c.KeySize >= 2048 {
		return 112
	}
	if c.KeySize >= 384 {
		return 192
	}
	if c.KeySize >= 256 {
		return 128
	}
	return 0
}
func sanitize(s string) string {
	s = strings.ToLower(s)
	s = strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '.' {
			return r
		}
		return '-'
	}, s)
	return strings.Trim(s, "-")
}
func appendUnique(xs []string, v string) []string {
	for _, x := range xs {
		if x == v {
			return xs
		}
	}
	return append(xs, v)
}

var _ = fmt.Sprintf
