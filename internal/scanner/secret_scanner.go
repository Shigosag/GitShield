package scanner

import (
	"bufio"
	"bytes"
	"fmt"
	"path/filepath"
	"strings"
)

type Finding struct {
	ID          string   `json:"id"`
	Category    string   `json:"category"`
	Severity    Severity `json:"severity"`
	File        string   `json:"file"`
	Line        int      `json:"line"`
	Detected    string   `json:"detected"`
	WhyItMatter string   `json:"why_it_matters"`
	Remediation string   `json:"remediation"`
}

type SecretScanner struct {
	rules            []SecretRule
	entropyThreshold float64
}

func NewSecretScanner(threshold float64) *SecretScanner {
	return &SecretScanner{
		rules:            GetSecretRules(),
		entropyThreshold: threshold,
	}
}

// isHashOrLockfile identifies files containing legitimate high-entropy checksums
func isHashOrLockfile(filename string) bool {
	lower := strings.ToLower(filename)
	return lower == "go.sum" ||
		strings.HasSuffix(lower, ".sum") ||
		strings.HasSuffix(lower, ".lock") ||
		strings.HasSuffix(lower, "-lock.json") ||
		strings.HasSuffix(lower, "-lock.yaml") ||
		strings.HasSuffix(lower, ".map")
}

func (s *SecretScanner) ScanContent(filePath string, content []byte) ([]Finding, error) {
	var findings []Finding
	baseName := filepath.Base(filePath)
	skipEntropy := isHashOrLockfile(baseName)

	scanner := bufio.NewScanner(bytes.NewReader(content))
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "#") {
			if !strings.HasPrefix(baseName, ".env") {
				continue
			}
		}

		// 1. Concrete Secret Rules (AWS, GitHub, Stripe, etc.)
		for _, rule := range s.rules {
			if rule.ID == "SEC-ENV-001" && !strings.Contains(baseName, ".env") {
				continue
			}
			matches := rule.Regex.FindAllStringSubmatch(line, -1)
			for _, m := range matches {
				val := m[0]
				if len(m) > 1 {
					val = m[1]
				}
				findings = append(findings, Finding{
					ID:          fmt.Sprintf("%s-%s-%d", rule.ID, baseName, lineNum),
					Category:    "SECRET",
					Severity:    rule.Severity,
					File:        filePath,
					Line:        lineNum,
					Detected:    fmt.Sprintf("%s (%s)", rule.Name, MaskSecret(val)),
					WhyItMatter: rule.WhyItMatter,
					Remediation: rule.Remediation,
				})
			}
		}

		// 2. Generic High-Entropy Heuristic (skipped for checksum/lock files)
		if !skipEntropy {
			words := strings.FieldsFunc(line, func(r rune) bool {
				return r == ' ' || r == '\t' || r == '"' || r == '\'' || r == '=' || r == ':' || r == '`' || r == ';'
			})

			for _, w := range words {
				if len(w) >= 24 && !strings.Contains(w, "/") && !strings.Contains(w, ".") && !strings.Contains(w, "-") {
					entropy := CalculateShannonEntropy(w)
					if entropy >= s.entropyThreshold {
						findings = append(findings, Finding{
							ID:          fmt.Sprintf("SEC-ENTROPY-%s-%d", baseName, lineNum),
							Category:    "SECRET",
							Severity:    SeverityMedium,
							File:        filePath,
							Line:        lineNum,
							Detected:    fmt.Sprintf("High-Entropy Token [Entropy: %.2f bits] (%s)", entropy, MaskSecret(w)),
							WhyItMatter: "High Shannon entropy indicates an auto-generated private key, API secret, or password.",
							Remediation: "Verify if this string is a credential. Move it into an environment variable or secrets vault.",
						})
					}
				}
			}
		}
	}

	return findings, scanner.Err()
}