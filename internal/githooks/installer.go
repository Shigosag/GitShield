package githooks

import (
	"fmt"
	"os"
	"path/filepath"
)

const preCommitHook = `#!/usr/bin/env sh
# GitShield: Pre-commit hook
echo "\033[1;36m==> [GitShield] Checking staged files for secrets and lockfile vulnerabilities...\033[0m"

if command -v gitshield >/dev/null 2>&1; then
    CMD="gitshield"
elif [ -f "./gitshield" ]; then
    CMD="./gitshield"
elif [ -f "./gitshield.exe" ]; then
    CMD="./gitshield.exe"
else
    echo "\033[1;33m[GitShield Notice] 'gitshield' binary not found in PATH or repo root. Skipping hook.\033[0m"
    exit 0
fi

$CMD scan --staged --fail-on HIGH
EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ]; then
    echo "\033[1;31m[GitShield Blocked] Commit halted. Remediate flagged findings above.\033[0m"
    exit $EXIT_CODE
fi

exit 0
`

const prePushHook = `#!/usr/bin/env sh
# GitShield: Pre-push hook
echo "\033[1;36m==> [GitShield] Auditing repository prior to remote push...\033[0m"

if command -v gitshield >/dev/null 2>&1; then
    CMD="gitshield"
elif [ -f "./gitshield" ]; then
    CMD="./gitshield"
elif [ -f "./gitshield.exe" ]; then
    CMD="./gitshield.exe"
else
    echo "\033[1;33m[GitShield Notice] 'gitshield' binary not found in PATH or repo root. Skipping hook.\033[0m"
    exit 0
fi

$CMD scan --fail-on CRITICAL
EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ]; then
    echo "\033[1;31m[GitShield Blocked] Push halted due to CRITICAL findings.\033[0m"
    exit $EXIT_CODE
fi

exit 0
`

func InstallHooks(repoRoot string) error {
	gitDir := filepath.Join(repoRoot, ".git")
	if info, err := os.Stat(gitDir); err != nil || !info.IsDir() {
		return fmt.Errorf("%q is not a git repository root", repoRoot)
	}

	hooksDir := filepath.Join(gitDir, "hooks")
	if err := os.MkdirAll(hooksDir, 0755); err != nil {
		return fmt.Errorf("failed creating hooks directory: %w", err)
	}

	preCommitPath := filepath.Join(hooksDir, "pre-commit")
	if err := os.WriteFile(preCommitPath, []byte(preCommitHook), 0755); err != nil {
		return fmt.Errorf("failed writing pre-commit: %w", err)
	}

	prePushPath := filepath.Join(hooksDir, "pre-push")
	if err := os.WriteFile(prePushPath, []byte(prePushHook), 0755); err != nil {
		return fmt.Errorf("failed writing pre-push: %w", err)
	}

	return nil
}