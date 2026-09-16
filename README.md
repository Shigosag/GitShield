# 🛡️ GitShield V1

[![Go](https://img.shields.io/badge/Go-1.22+-00ADD8?logo=go&logoColor=white)](https://go.dev/)
[![Git](https://img.shields.io/badge/Git-Compatible-F05032?logo=git&logoColor=white)](https://git-scm.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

GitShield is a fast, standalone Go CLI security engine designed to prevent credential leaks and identify vulnerable dependencies before code leaves your workstation.

It scans source code for hardcoded secrets, audits package lockfiles against the [OSV.dev](https://osv.dev) advisory database, and installs automated Git pre-commit and pre-push hooks.

---

## Key Features

- 🔑 **Secret Detection**: Pattern matching for AWS Access Keys, GitHub Personal Access Tokens, Stripe API Keys, OpenAI Keys, and committed `.env` secrets.
- 🎲 **Shannon Entropy Analysis**: Heuristic scanning to flag high-entropy generic credentials while automatically ignoring cryptographic checksums (e.g., `go.sum`, lockfiles).
- 📦 **Dependency Vulnerability Scanning**: Audits dependencies in `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`, `requirements.txt`, and `poetry.lock` via OSV.dev batch API.
- 🪝 **One-Command Git Hooks**: `gitshield init` configures `.git/hooks/pre-commit` and `.git/hooks/pre-push` to halt dangerous commits automatically.
- 🤖 **CI/CD Native**: Seamless integration with GitHub Actions to block builds when vulnerabilities exceed severity thresholds.

---

## Prerequisites

- **[Go](https://go.dev/dl/)** (v1.22 or higher)
- **[Git](https://git-scm.com/)**

---

## Installation

### Windows (PowerShell / Command Prompt)

```powershell
# Clone the repository
git clone https://github.com/Shigosag/GitShield.git
cd gitshield

# Download dependencies & build
go mod tidy
go build -o gitshield.exe ./cmd/gitshield

# (Optional) Install globally to Go bin
go install ./cmd/gitshield
```

### Linux & macOS (Bash / Zsh)

```bash
# Clone the repository
git clone https://github.com/Shigosag/GitShield.git
cd gitshield

# Download dependencies & build
go mod tidy
go build -o gitshield ./cmd/gitshield

# (Optional) Move to system path
sudo mv gitshield /usr/local/bin/
```

---

## Quick Start & Usage

> **Note:** GitShield must be run inside a Git repository. If your directory is not yet a repository, run `git init` first.

### 1. Initialize Git & Install Hooks
```bash
# Initialize repository (if not already a git repo)
git init

# Install automated pre-commit & pre-push protection hooks
gitshield init
```

---

### 2. Verify Installation (Quick Test)
Verify that GitShield catches real secrets before using it on real code:

```bash
# 1. Create a dummy test secret
echo "AWS_KEY=AKIA""IOSFODNN7EXAMPLE" > test_secret.txt

# 2. Run scan (will flag CRITICAL)
gitshield scan

# 3. Clean up the dummy file
del test_secret.txt       # Windows PowerShell / CMD
rm test_secret.txt        # Linux / macOS
```

---

### 3. Run Security Audits

#### Audit entire repository
```bash
gitshield scan
```

#### Audit only staged changes (pre-commit check)
```bash
gitshield scan --staged
```

#### Enforce build failure severity
Set the minimum severity level that causes GitShield to exit with code `1`:
```bash
# Fail on HIGH or CRITICAL issues (Default)
gitshield scan --fail-on HIGH

# Fail strictly on CRITICAL issues only
gitshield scan --fail-on CRITICAL

# Fail on any finding (LOW, MEDIUM, HIGH, CRITICAL)
gitshield scan --fail-on LOW
```

#### Output scan results as JSON
```bash
gitshield scan --json
```

---

## License

MIT License. Free and open source for developers and organizations.