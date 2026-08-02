package scanner

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/Naokibot/i_1/internal/model"
)

func ScanSSH(ctx context.Context, req model.ScanRequest) (model.Asset, []model.Finding, error) {
	port := req.Port
	if port == 0 {
		port = 22
	}
	address := net.JoinHostPort(req.Target, strconv.Itoa(port))
	d := &net.Dialer{Timeout: 8 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", address)
	if err != nil {
		return model.Asset{}, nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(12 * time.Second))
	br := bufio.NewReader(conn)
	banner := ""
	for i := 0; i < 50; i++ {
		line, err := br.ReadString('\n')
		if err != nil {
			return model.Asset{}, nil, err
		}
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "SSH-") {
			banner = line
			break
		}
	}
	if banner == "" {
		return model.Asset{}, nil, fmt.Errorf("SSH identification not received")
	}
	if _, err := io.WriteString(conn, "SSH-2.0-PQMObservatory_0.1\r\n"); err != nil {
		return model.Asset{}, nil, err
	}
	payload, err := readSSHPacket(br)
	if err != nil {
		return model.Asset{}, nil, err
	}
	lists, err := parseKEXInit(payload)
	if err != nil {
		return model.Asset{}, nil, err
	}
	now := time.Now().UTC()
	asset := model.Asset{ID: stableAssetID("ssh", address), Name: "SSH " + address, Kind: model.AssetSSH, Location: address, Status: "observed", DiscoveredAt: now, LastObserved: now, Context: model.ContextFromRequest(req), Evidence: map[string]any{"banner": banner, "algorithms": lists}}
	p := component("protocol", "SSH", "protocol", "remote administration", "active scan")
	p.Protocol = "SSH"
	p.Version = strings.Split(banner, "-")[1]
	asset.Crypto = append(asset.Crypto, p)
	findings := []model.Finding{}
	keys := []struct{ name, primitive, usage string }{{"kex", "key-agreement", "SSH key exchange"}, {"hostKey", "signature", "SSH host authentication"}, {"cipherC2S", "encryption", "SSH client-to-server encryption"}, {"cipherS2C", "encryption", "SSH server-to-client encryption"}, {"macC2S", "mac", "SSH client-to-server integrity"}}
	for _, k := range keys {
		for _, alg := range lists[k.name] {
			c := component("algorithm", alg, k.primitive, k.usage, "active scan")
			asset.Crypto = append(asset.Crypto, c)
			if sev, ok := weakSSH(alg); ok {
				findings = append(findings, newFinding(asset.ID, "SSH-WEAK-"+strings.ToUpper(strings.ReplaceAll(alg, "@", "-")), sev, "Weak SSH algorithm", alg, address, alg, "Disable this algorithm and test a modern or hybrid replacement"))
			}
		}
	}
	if contains(lists["hostKey"], "ssh-rsa") {
		findings = append(findings, newFinding(asset.ID, "SSH-RSA-SHA1", "high", "Legacy ssh-rsa host key offered", "ssh-rsa uses RSA with SHA-1 signatures", address, "ssh-rsa", "Prefer rsa-sha2-256/512, Ed25519 as interim options, and a PQC/hybrid path when supported"))
	}
	return asset, findings, nil
}

func readSSHPacket(r *bufio.Reader) ([]byte, error) {
	hdr := make([]byte, 5)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint32(hdr[:4]))
	pad := int(hdr[4])
	if n < 2 || n > 2_000_000 {
		return nil, fmt.Errorf("invalid SSH packet length %d", n)
	}
	rest := make([]byte, n-1)
	if _, err := io.ReadFull(r, rest); err != nil {
		return nil, err
	}
	payloadLen := n - pad - 1
	if payloadLen < 1 || payloadLen > len(rest) {
		return nil, fmt.Errorf("invalid SSH padding")
	}
	return rest[:payloadLen], nil
}
func parseKEXInit(p []byte) (map[string][]string, error) {
	if len(p) < 17 || p[0] != 20 {
		return nil, fmt.Errorf("expected SSH_MSG_KEXINIT")
	}
	p = p[17:]
	names := []string{"kex", "hostKey", "cipherC2S", "cipherS2C", "macC2S", "macS2C", "compressionC2S", "compressionS2C", "languageC2S", "languageS2C"}
	out := map[string][]string{}
	for _, name := range names {
		if len(p) < 4 {
			return nil, io.ErrUnexpectedEOF
		}
		n := int(binary.BigEndian.Uint32(p[:4]))
		p = p[4:]
		if n > len(p) {
			return nil, io.ErrUnexpectedEOF
		}
		raw := string(p[:n])
		p = p[n:]
		if raw != "" {
			out[name] = strings.Split(raw, ",")
		} else {
			out[name] = []string{}
		}
	}
	return out, nil
}
func weakSSH(a string) (string, bool) {
	s := strings.ToLower(a)
	switch {
	case strings.Contains(s, "group1-sha1"), strings.Contains(s, "-md5"), strings.Contains(s, "3des"), strings.Contains(s, "arcfour"):
		return "critical", true
	case strings.Contains(s, "group14-sha1"), strings.Contains(s, "hmac-sha1"), strings.Contains(s, "-cbc"):
		return "high", true
	}
	return "", false
}
func contains(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}
