package scanner

import (
	"bytes"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const maxScanFileSize = 10 * 1024 * 1024 // 10MB limit

type ScanSummary struct {
	TotalFilesScanned int       `json:"total_files_scanned"`
	Findings          []Finding `json:"findings"`
	CriticalCount     int       `json:"critical_count"`
	HighCount         int       `json:"high_count"`
	MediumCount       int       `json:"medium_count"`
	LowCount          int       `json:"low_count"`
}

type ScanRunner struct {
	secretScanner *SecretScanner
	depScanner    *DependencyScanner
}

func NewScanRunner(secScanner *SecretScanner, depScanner *DependencyScanner) *ScanRunner {
	return &ScanRunner{
		secretScanner: secScanner,
		depScanner:    depScanner,
	}
}

// isBinaryOrMedia checks file extensions and header bytes for non-text data
func isBinaryOrMedia(path string, header []byte) bool {
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".exe", ".dll", ".so", ".dylib", ".bin",
		".png", ".jpg", ".jpeg", ".gif", ".ico", ".webp", ".bmp", ".tiff",
		".zip", ".tar", ".gz", ".bz2", ".xz", ".7z", ".rar",
		".pdf", ".wasm", ".woff", ".woff2", ".ttf", ".eot",
		".mp4", ".mp3", ".mov", ".avi", ".flv", ".webm":
		return true
	}

	// Null byte check in initial segment
	if bytes.IndexByte(header, 0x00) != -1 {
		return true
	}

	return false
}

func (r *ScanRunner) Scan(targetPath string, stagedOnly bool) (*ScanSummary, error) {
	summary := &ScanSummary{}
	var filesToScan []string

	absTarget, err := filepath.Abs(targetPath)
	if err != nil {
		absTarget = targetPath
	}

	if stagedOnly {
		cmd := exec.Command("git", "diff", "--cached", "--name-only", "--diff-filter=ACM")
		cmd.Dir = absTarget
		out, err := cmd.Output()
		if err != nil {
			return nil, fmt.Errorf("git diff failed in %s: %w", absTarget, err)
		}
		for _, line := range strings.Split(string(out), "\n") {
			t := strings.TrimSpace(line)
			if t != "" {
				filesToScan = append(filesToScan, filepath.Join(absTarget, t))
			}
		}
	} else {
		err := filepath.WalkDir(absTarget, func(path string, d fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return nil
			}
			if d.IsDir() {
				name := d.Name()
				if name == ".git" || name == "node_modules" || name == "vendor" || name == ".venv" || name == "dist" || name == "bin" {
					return filepath.SkipDir
				}
				return nil
			}
			filesToScan = append(filesToScan, path)
			return nil
		})
		if err != nil {
			return nil, err
		}
	}

	var allDeps []DependencyItem

	for _, path := range filesToScan {
		info, err := os.Stat(path)
		if err != nil || info.IsDir() || info.Size() > maxScanFileSize {
			continue
		}

		file, err := os.Open(path)
		if err != nil {
			continue
		}

		header := make([]byte, 512)
		n, _ := file.Read(header)
		if isBinaryOrMedia(path, header[:n]) {
			file.Close()
			continue
		}

		_, _ = file.Seek(0, io.SeekStart)
		data, err := io.ReadAll(file)
		file.Close()
		if err != nil {
			continue
		}

		summary.TotalFilesScanned++

		relPath, relErr := filepath.Rel(absTarget, path)
		if relErr != nil {
			relPath = path
		}

		secFindings, err := r.secretScanner.ScanContent(relPath, data)
		if err == nil && len(secFindings) > 0 {
			summary.Findings = append(summary.Findings, secFindings...)
		}

		deps := r.depScanner.ParseLockfile(relPath, data)
		if len(deps) > 0 {
			allDeps = append(allDeps, deps...)
		}
	}

	if len(allDeps) > 0 {
		depFindings, err := r.depScanner.ScanDependencies(allDeps)
		if err == nil {
			summary.Findings = append(summary.Findings, depFindings...)
		}
	}

	for _, f := range summary.Findings {
		switch f.Severity {
		case SeverityCritical:
			summary.CriticalCount++
		case SeverityHigh:
			summary.HighCount++
		case SeverityMedium:
			summary.MediumCount++
		case SeverityLow:
			summary.LowCount++
		}
	}

	return summary, nil
}