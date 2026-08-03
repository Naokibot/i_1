package scanner

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/Naokibot/i_1/internal/model"
)

type sourceRule struct {
	id, severity, title, algorithm, primitive, remediation string
	re                                                     *regexp.Regexp
}

var sourceRules = []sourceRule{
	{"SRC-RSA", "medium", "RSA API usage", "RSA", "signature/key-transport", "Inventory the calling contract, then test dual-signature or hybrid key establishment before replacement", regexp.MustCompile(`(?i)(RSA_generate_key|EVP_PKEY_RSA|KeyPairGenerator\s*\.\s*getInstance\s*\(\s*"RSA"|RSACryptoServiceProvider|RSA\.Create\s*\()`)},
	{"SRC-RSA-PKCS1", "high", "RSA PKCS#1 v1.5 encryption", "RSA/ECB/PKCS1Padding", "encryption", "Replace with a reviewed KEM-based design; do not mechanically rename the cipher", regexp.MustCompile(`(?i)RSA/ECB/PKCS1Padding|RSA_PKCS1_PADDING`)},
	{"SRC-ECDSA", "medium", "ECDSA API usage", "ECDSA", "signature", "Plan parallel ML-DSA signatures and preserve compatibility evidence", regexp.MustCompile(`(?i)(ECDSA_sign|Signature\s*\.\s*getInstance\s*\(\s*".*ECDSA|ECDsa\.Create\s*\()`)},
	{"SRC-ECDH", "medium", "ECDH API usage", "ECDH", "key-agreement", "Benchmark a hybrid ML-KEM plus ECDH path", regexp.MustCompile(`(?i)(ECDH|X25519|KeyAgreement\s*\.\s*getInstance\s*\(\s*"ECDH")`)},
	{"SRC-SHA1", "high", "SHA-1 usage", "SHA-1", "hash", "Use SHA-256 or stronger where compatibility allows and separately migrate public-key algorithms", regexp.MustCompile(`(?i)(SHA-?1|MessageDigest\s*\.\s*getInstance\s*\(\s*"SHA-?1")`)},
	{"SRC-MD5", "critical", "MD5 usage", "MD5", "hash", "Remove MD5 from security-sensitive use", regexp.MustCompile(`(?i)(MD5|MessageDigest\s*\.\s*getInstance\s*\(\s*"MD5")`)},
	{"SRC-DES", "critical", "DES or 3DES usage", "DES/3DES", "encryption", "Replace with authenticated encryption and review stored-data migration", regexp.MustCompile(`(?i)(DESede|TripleDES|\b3DES\b|Cipher\s*\.\s*getInstance\s*\(\s*"DES)`)},
	{"SRC-ECB", "high", "ECB mode usage", "ECB", "encryption-mode", "Use an authenticated encryption mode such as GCM; redesign message framing as needed", regexp.MustCompile(`(?i)/(ECB)/|CipherMode\.ECB`)},
	{"SRC-TLS10", "high", "Obsolete TLS version configured", "TLS 1.0/1.1", "protocol", "Raise the minimum to TLS 1.2 or TLS 1.3 before adding PQC negotiation", regexp.MustCompile(`(?i)(TLSv1(\.0)?\b|TLSv1\.1\b|SslProtocols\.Tls\b)`)},
}

func ScanSource(ctx context.Context, req model.ScanRequest, root string) (model.Asset, []model.Finding, error) {
	target, err := securePath(root, req.Target)
	if err != nil {
		return model.Asset{}, nil, err
	}
	info, err := os.Stat(target)
	if err != nil {
		return model.Asset{}, nil, err
	}
	if !info.IsDir() {
		return model.Asset{}, nil, fmt.Errorf("source target must be a directory")
	}
	now := time.Now().UTC()
	asset := model.Asset{ID: stableAssetID("source", target), Name: filepath.Base(target), Kind: model.AssetSource, Location: target, Status: "observed", DiscoveredAt: now, LastObserved: now, Context: model.ContextFromRequest(req), Evidence: map[string]any{}}
	findings := []model.Finding{}
	seen := map[string]bool{}
	files, bytesRead := 0, int64(0)
	err = filepath.WalkDir(target, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		if d.Type()&os.ModeSymlink != 0 {
			return nil
		}
		if d.IsDir() {
			if path != target && skipDir(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if files >= 25000 || bytesRead > 512<<20 {
			return filepath.SkipAll
		}
		if !sourceExt(path) {
			return nil
		}
		fi, err := d.Info()
		if err != nil || !fi.Mode().IsRegular() || fi.Size() > 10<<20 {
			return nil
		}
		rel, err := filepath.Rel(target, path)
		if err != nil {
			return nil
		}
		fileFindings, err := scanSourceFile(ctx, path, rel, asset.ID, &asset, seen)
		if err != nil {
			return nil
		}
		files++
		bytesRead += fi.Size()
		findings = append(findings, fileFindings...)
		return nil
	})
	if err != nil {
		return model.Asset{}, nil, err
	}
	asset.Evidence["filesScanned"] = files
	asset.Evidence["bytesScanned"] = bytesRead
	asset.Evidence["findingCount"] = len(findings)
	return asset, findings, nil
}

func scanSourceFile(ctx context.Context, path, rel, assetID string, asset *model.Asset, seen map[string]bool) ([]model.Finding, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	findings := []model.Finding{}
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	line := 0
	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		line++
		text := scanner.Text()
		for _, rule := range sourceRules {
			if rule.re.MatchString(text) {
				loc := fmt.Sprintf("%s:%d", rel, line)
				findings = append(findings, newFinding(assetID, rule.id, rule.severity, rule.title, "Cryptographic API or configuration matched", loc, trimEvidence(text), rule.remediation))
				key := rule.algorithm + "|" + rule.primitive
				if !seen[key] {
					c := component("algorithm", rule.algorithm, rule.primitive, "source-code dependency", "source scan")
					c.Metadata = map[string]string{"firstSeen": loc}
					asset.Crypto = append(asset.Crypto, c)
					seen[key] = true
				}
			}
		}
		detectPQC(text, locOr(rel, line), asset, seen)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return findings, nil
}

func securePath(root, target string) (string, error) {
	r, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	r, err = filepath.EvalSymlinks(r)
	if err != nil {
		return "", fmt.Errorf("resolve source root: %w", err)
	}
	p := target
	if !filepath.IsAbs(p) {
		p = filepath.Join(r, p)
	}
	p, err = filepath.Abs(p)
	if err != nil {
		return "", err
	}
	p, err = filepath.EvalSymlinks(p)
	if err != nil {
		return "", fmt.Errorf("resolve source target: %w", err)
	}
	rel, err := filepath.Rel(r, p)
	if err != nil {
		return "", err
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return "", fmt.Errorf("target is outside allowed source root")
	}
	return p, nil
}
func skipDir(n string) bool {
	switch n {
	case ".git", "node_modules", "vendor", "dist", "build", "target", ".idea", ".gradle", "bin", "obj":
		return true
	}
	return false
}
func sourceExt(p string) bool {
	switch strings.ToLower(filepath.Ext(p)) {
	case ".java", ".cs", ".go", ".c", ".h", ".cpp", ".cc", ".py", ".js", ".ts", ".rb", ".php", ".xml", ".properties", ".conf", ".yaml", ".yml", ".json", ".gradle", ".csproj", ".sln", ".sh":
		return true
	}
	return false
}
func trimEvidence(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 240 {
		return s[:240] + "..."
	}
	return s
}
func locOr(rel string, line int) string { return fmt.Sprintf("%s:%d", rel, line) }
func detectPQC(text, loc string, a *model.Asset, seen map[string]bool) {
	for _, alg := range []string{"ML-KEM", "ML-DSA", "SLH-DSA", "X25519MLKEM768"} {
		if strings.Contains(strings.ToUpper(strings.ReplaceAll(text, "_", "-")), strings.ToUpper(alg)) {
			if !seen[alg] {
				c := component("algorithm", alg, "post-quantum", "source-code dependency", "source scan")
				c.Metadata = map[string]string{"firstSeen": loc}
				a.Crypto = append(a.Crypto, c)
				seen[alg] = true
			}
		}
	}
}
