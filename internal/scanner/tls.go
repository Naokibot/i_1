package scanner

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/Naokibot/i_1/internal/model"
)

func ScanTLS(ctx context.Context, req model.ScanRequest) (model.Asset, []model.Finding, error) {
	port := req.Port
	if port == 0 {
		port = 443
	}
	address := net.JoinHostPort(req.Target, strconv.Itoa(port))
	host := req.Target
	d := &net.Dialer{Timeout: 8 * time.Second}
	raw, err := d.DialContext(ctx, "tcp", address)
	if err != nil {
		return model.Asset{}, nil, err
	}
	defer raw.Close()
	serverName := host
	if net.ParseIP(host) != nil {
		serverName = ""
	}
	conn := tls.Client(raw, &tls.Config{ServerName: serverName, InsecureSkipVerify: true, MinVersion: tls.VersionTLS10}) // Discovery intentionally records invalid chains instead of aborting.
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	} else {
		_ = conn.SetDeadline(time.Now().Add(12 * time.Second))
	}
	if err := conn.HandshakeContext(ctx); err != nil {
		return model.Asset{}, nil, err
	}
	st := conn.ConnectionState()
	now := time.Now().UTC()
	asset := model.Asset{ID: stableAssetID("tls", address), Name: "TLS " + address, Kind: model.AssetTLS, Location: address, Status: "observed", DiscoveredAt: now, LastObserved: now, Context: model.ContextFromRequest(req), Evidence: map[string]any{"negotiatedProtocol": tlsVersion(st.Version), "cipherSuite": tls.CipherSuiteName(st.CipherSuite), "alpn": st.NegotiatedProtocol, "serverName": st.ServerName}}
	p := component("protocol", tlsVersion(st.Version), "protocol", "transport security", "active scan")
	p.Protocol = "TLS"
	p.Version = tlsVersion(st.Version)
	asset.Crypto = append(asset.Crypto, p)
	cs := component("algorithm", tls.CipherSuiteName(st.CipherSuite), "authenticated-encryption", "record protection", "active scan")
	asset.Crypto = append(asset.Crypto, cs)
	findings := []model.Finding{}
	if st.Version < tls.VersionTLS12 {
		findings = append(findings, newFinding(asset.ID, "TLS-OLD", "high", "Obsolete TLS version", fmt.Sprintf("Negotiated %s", tlsVersion(st.Version)), address, tlsVersion(st.Version), "Require TLS 1.2 or TLS 1.3 before PQC migration"))
	}
	for i, cert := range st.PeerCertificates {
		pubAlg, size := publicKeyInfo(cert.PublicKey)
		fp := sha256.Sum256(cert.Raw)
		c := component("certificate", pubAlg, "signature", "X.509 certificate", "active scan")
		c.KeySize = size
		c.Fingerprint = hex.EncodeToString(fp[:])
		c.ID = stableCryptoID("certificate", c.Algorithm, c.Fingerprint)
		c.Metadata = map[string]string{"subject": cert.Subject.String(), "issuer": cert.Issuer.String(), "notBefore": cert.NotBefore.UTC().Format(time.RFC3339), "notAfter": cert.NotAfter.UTC().Format(time.RFC3339), "signatureAlgorithm": cert.SignatureAlgorithm.String(), "serialNumber": cert.SerialNumber.String()}
		asset.Crypto = append(asset.Crypto, c)
		sig := component("algorithm", cert.SignatureAlgorithm.String(), "signature", "certificate signature", "active scan")
		asset.Crypto = append(asset.Crypto, sig)
		if i == 0 {
			if cert.NotAfter.Before(now) {
				findings = append(findings, newFinding(asset.ID, "CERT-EXPIRED", "critical", "Expired certificate", "The leaf certificate is expired", address, cert.NotAfter.String(), "Replace the certificate and test both classical and PQC certificate paths"))
			}
			if cert.NotAfter.Before(now.Add(30 * 24 * time.Hour)) {
				findings = append(findings, newFinding(asset.ID, "CERT-SOON", "medium", "Certificate expires soon", "The leaf certificate expires within 30 days", address, cert.NotAfter.String(), "Schedule rotation and include migration capability testing"))
			}
			if strings.Contains(strings.ToLower(cert.SignatureAlgorithm.String()), "sha1") {
				findings = append(findings, newFinding(asset.ID, "CERT-SHA1", "high", "SHA-1 certificate signature", cert.SignatureAlgorithm.String(), address, cert.SignatureAlgorithm.String(), "Issue a certificate with a modern signature algorithm"))
			}
			if strings.HasPrefix(pubAlg, "RSA") && size < 2048 {
				findings = append(findings, newFinding(asset.ID, "RSA-SMALL", "critical", "Undersized RSA key", fmt.Sprintf("RSA key size is %d bits", size), address, pubAlg, "Rotate to at least RSA-2048 as an interim measure, then introduce PQC/hybrid signing"))
			}
			intermediates := x509.NewCertPool()
			for _, peer := range st.PeerCertificates[1:] {
				intermediates.AddCert(peer)
			}
			opts := x509.VerifyOptions{DNSName: host, Intermediates: intermediates}
			if _, err := cert.Verify(opts); err != nil {
				findings = append(findings, newFinding(asset.ID, "CERT-VERIFY", "high", "Certificate validation failed", err.Error(), address, cert.Subject.String(), "Correct trust chain, hostname, and validity before migration"))
			}
		}
	}
	return asset, findings, nil
}

func publicKeyInfo(k any) (string, int) {
	switch v := k.(type) {
	case *rsa.PublicKey:
		return "RSA", v.N.BitLen()
	case *ecdsa.PublicKey:
		return "ECDSA-" + v.Curve.Params().Name, v.Curve.Params().BitSize
	case ed25519.PublicKey:
		return "Ed25519", len(v) * 8
	default:
		return fmt.Sprintf("%T", k), 0
	}
}
func tlsVersion(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("TLS 0x%04x", v)
	}
}
func stableAssetID(kind, location string) string {
	s := sha256.Sum256([]byte(kind + ":" + location))
	return "asset-" + hex.EncodeToString(s[:10])
}
func newFinding(assetID, rule, severity, title, detail, location, evidence, remediation string) model.Finding {
	return model.Finding{ID: model.NewID("finding"), AssetID: assetID, RuleID: rule, Severity: severity, Title: title, Detail: detail, Location: location, Evidence: evidence, Remediation: remediation, Status: "open", CreatedAt: time.Now().UTC()}
}

func stableFindingID(parts ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(parts, "|")))
	return "finding-" + hex.EncodeToString(sum[:10])
}
