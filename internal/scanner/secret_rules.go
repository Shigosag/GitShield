package scanner

import (
	"math"
	"regexp"
)

type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
)

type SecretRule struct {
	ID          string
	Name        string
	Severity    Severity
	Regex       *regexp.Regexp
	WhyItMatter string
	Remediation string
}

func GetSecretRules() []SecretRule {
	return []SecretRule{
		{
			ID:          "SEC-AWS-001",
			Name:        "AWS Access Key ID",
			Severity:    SeverityCritical,
			Regex:       regexp.MustCompile(`\b(AKIA[0-9A-Z]{16})\b`),
			WhyItMatter: "Grants programmatic access to AWS cloud resources, compute nodes, and data storage.",
			Remediation: "Deactivate and delete this access key immediately in AWS IAM Console. Rotate credentials into a secrets manager.",
		},
		{
			ID:          "SEC-AWS-002",
			Name:        "AWS Secret Access Key",
			Severity:    SeverityCritical,
			Regex:       regexp.MustCompile(`(?i)(?:aws_secret_access_key|aws_secret_key|secret_key)\s*[:=]\s*["']?([A-Za-z0-9/+=]{40})["']?`),
			WhyItMatter: "Functions as the private password component for AWS IAM programmatic identities.",
			Remediation: "Rotate the matching AWS Access Key pair immediately. Review CloudTrail audit logs for unauthorized actions.",
		},
		{
			ID:          "SEC-GH-001",
			Name:        "GitHub Personal Access Token (Classic)",
			Severity:    SeverityCritical,
			Regex:       regexp.MustCompile(`\b(ghp_[a-zA-Z0-9]{36})\b`),
			WhyItMatter: "Grants complete account repository read/write access under the developer's GitHub identity.",
			Remediation: "Revoke token under GitHub Developer Settings -> Personal access tokens.",
		},
		{
			ID:          "SEC-GH-002",
			Name:        "GitHub Fine-Grained Personal Access Token",
			Severity:    SeverityCritical,
			Regex:       regexp.MustCompile(`\b(github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59})\b`),
			WhyItMatter: "Grants granular API and git push access to specified repositories.",
			Remediation: "Revoke the token from GitHub Account Settings -> Personal Access Tokens.",
		},
		{
			ID:          "SEC-GH-003",
			Name:        "GitHub OAuth / App Token",
			Severity:    SeverityHigh,
			Regex:       regexp.MustCompile(`\b(gh[ousr]_[a-zA-Z0-9]{36})\b`),
			WhyItMatter: "Authorizes third-party application or server actions on behalf of GitHub repositories.",
			Remediation: "Revoke the token or revoke app permissions in GitHub Organization/User Settings.",
		},
		{
			ID:          "SEC-STRIPE-001",
			Name:        "Stripe Live Secret Key",
			Severity:    SeverityCritical,
			Regex:       regexp.MustCompile(`\b(sk_live_[0-9a-zA-Z]{24,99})\b`),
			WhyItMatter: "Allows full control over Stripe accounts, including customer records, transfers, and balance charges.",
			Remediation: "Roll this key in the Stripe Dashboard (Developers -> API Keys) and audit recent financial transactions.",
		},
		{
			ID:          "SEC-STRIPE-002",
			Name:        "Stripe Live Restricted Key",
			Severity:    SeverityHigh,
			Regex:       regexp.MustCompile(`\b(rk_live_[0-9a-zA-Z]{24,99})\b`),
			WhyItMatter: "Allows programmatic access to scoped financial operations in Stripe.",
			Remediation: "Delete the restricted key from Stripe Dashboard and issue a new restricted key stored in your secret vault.",
		},
		{
			ID:          "SEC-OPENAI-001",
			Name:        "OpenAI API Secret Key",
			Severity:    SeverityHigh,
			Regex:       regexp.MustCompile(`\b(sk-[a-zA-Z0-9]{48}|sk-proj-[a-zA-Z0-9_-]{48,128})\b`),
			WhyItMatter: "Allows unmetered API token consumption charged to your OpenAI billing account.",
			Remediation: "Revoke the key immediately in OpenAI Dashboard -> API Keys.",
		},
		{
			ID:          "SEC-ENV-001",
			Name:        "Committed .env Secret",
			Severity:    SeverityHigh,
			Regex:       regexp.MustCompile(`(?i)(?:SECRET|PASSWORD|PASSWD|AUTH_TOKEN|PRIVATE_KEY|DATABASE_URL)\s*=\s*["']?([^#\r\n\s]{8,})["']?`),
			WhyItMatter: "Contains local environment configuration with active database credentials or private keys.",
			Remediation: "Add '.env' to your root .gitignore and rotate the exposed secrets.",
		},
	}
}

// CalculateShannonEntropy measures informational randomness in a string
func CalculateShannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0.0
	}
	freq := make(map[rune]float64)
	for _, r := range s {
		freq[r]++
	}
	length := float64(len(s))
	var entropy float64
	for _, count := range freq {
		p := count / length
		entropy -= p * math.Log2(p)
	}
	return entropy
}

func MaskSecret(secret string) string {
	l := len(secret)
	if l <= 6 {
		return "******"
	}
	return secret[:3] + "..." + secret[l-3:]
}