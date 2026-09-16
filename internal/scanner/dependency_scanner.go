package scanner

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

type DependencyItem struct {
	Name      string
	Version   string
	Ecosystem string
	File      string
	Line      int
}

type DependencyScanner struct {
	osvClient *OSVClient
}

func NewDependencyScanner(client *OSVClient) *DependencyScanner {
	return &DependencyScanner{osvClient: client}
}

func (ds *DependencyScanner) ParseLockfile(path string, content []byte) []DependencyItem {
	filename := filepath.Base(path)
	switch filename {
	case "package-lock.json":
		return parsePackageLock(path, content)
	case "yarn.lock":
		return parseYarnLock(path, content)
	case "pnpm-lock.yaml":
		return parsePnpmLock(path, content)
	case "requirements.txt":
		return parseRequirementsTxt(path, content)
	case "poetry.lock":
		return parsePoetryLock(path, content)
	}
	return nil
}

func parsePackageLock(filePath string, data []byte) []DependencyItem {
	var results []DependencyItem
	var manifest struct {
		Packages map[string]struct {
			Version string `json:"version"`
		} `json:"packages"`
		Dependencies map[string]struct {
			Version string `json:"version"`
		} `json:"dependencies"`
	}

	if err := json.Unmarshal(data, &manifest); err != nil {
		return results
	}

	if len(manifest.Packages) > 0 {
		for pkgPath, pkg := range manifest.Packages {
			if pkgPath == "" || pkg.Version == "" {
				continue
			}
			name := strings.TrimPrefix(pkgPath, "node_modules/")
			if idx := strings.LastIndex(name, "node_modules/"); idx != -1 {
				name = name[idx+len("node_modules/"):]
			}
			results = append(results, DependencyItem{
				Name:      name,
				Version:   pkg.Version,
				Ecosystem: "npm",
				File:      filePath,
				Line:      1,
			})
		}
	} else {
		for name, dep := range manifest.Dependencies {
			if dep.Version != "" {
				results = append(results, DependencyItem{
					Name:      name,
					Version:   dep.Version,
					Ecosystem: "npm",
					File:      filePath,
					Line:      1,
				})
			}
		}
	}
	return results
}

func parseYarnLock(filePath string, data []byte) []DependencyItem {
	var results []DependencyItem
	scanner := bufio.NewScanner(bytes.NewReader(data))
	var currentName string
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		if strings.HasPrefix(line, "\"") || (len(line) > 0 && line[0] != ' ' && strings.Contains(line, ":")) {
			header := strings.TrimRight(trimmed, ":")
			parts := strings.Split(header, ",")
			primary := strings.TrimSpace(parts[0])
			primary = strings.Trim(primary, "\"")
			if at := strings.LastIndex(primary, "@"); at > 0 {
				currentName = primary[:at]
			}
		} else if strings.HasPrefix(trimmed, "version ") && currentName != "" {
			ver := strings.Trim(strings.TrimPrefix(trimmed, "version "), "\"")
			results = append(results, DependencyItem{
				Name:      currentName,
				Version:   ver,
				Ecosystem: "npm",
				File:      filePath,
				Line:      lineNum,
			})
			currentName = ""
		}
	}
	return results
}

func parsePnpmLock(filePath string, data []byte) []DependencyItem {
	var results []DependencyItem
	var node struct {
		Packages map[string]interface{} `yaml:"packages"`
	}
	if err := yaml.Unmarshal(data, &node); err != nil {
		return results
	}

	for key := range node.Packages {
		clean := strings.TrimPrefix(key, "/")
		if atIdx := strings.LastIndex(clean, "@"); atIdx > 0 {
			name := clean[:atIdx]
			ver := clean[atIdx+1:]
			if paren := strings.Index(ver, "("); paren != -1 {
				ver = ver[:paren]
			}
			results = append(results, DependencyItem{
				Name:      name,
				Version:   ver,
				Ecosystem: "npm",
				File:      filePath,
				Line:      1,
			})
		}
	}
	return results
}

func parseRequirementsTxt(filePath string, data []byte) []DependencyItem {
	var results []DependencyItem
	scanner := bufio.NewScanner(bytes.NewReader(data))
	lineNum := 0
	reqRegex := regexp.MustCompile(`^([a-zA-Z0-9_\-\.]+)\s*==\s*([a-zA-Z0-9_\-\.]+)`)

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if match := reqRegex.FindStringSubmatch(line); len(match) == 3 {
			results = append(results, DependencyItem{
				Name:      match[1],
				Version:   match[2],
				Ecosystem: "PyPI",
				File:      filePath,
				Line:      lineNum,
			})
		}
	}
	return results
}

func parsePoetryLock(filePath string, data []byte) []DependencyItem {
	var results []DependencyItem
	scanner := bufio.NewScanner(bytes.NewReader(data))
	lineNum := 0
	var curName, curVersion string
	inPackage := false

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "[[package]]" {
			if inPackage && curName != "" && curVersion != "" {
				results = append(results, DependencyItem{
					Name: curName, Version: curVersion, Ecosystem: "PyPI", File: filePath, Line: lineNum,
				})
			}
			inPackage = true
			curName, curVersion = "", ""
			continue
		}
		if inPackage {
			if strings.HasPrefix(line, "name = ") {
				curName = strings.Trim(strings.TrimPrefix(line, "name = "), "\"")
			} else if strings.HasPrefix(line, "version = ") {
				curVersion = strings.Trim(strings.TrimPrefix(line, "version = "), "\"")
			}
		}
	}
	if inPackage && curName != "" && curVersion != "" {
		results = append(results, DependencyItem{
			Name: curName, Version: curVersion, Ecosystem: "PyPI", File: filePath, Line: lineNum,
		})
	}
	return results
}

func (ds *DependencyScanner) ScanDependencies(deps []DependencyItem) ([]Finding, error) {
	var findings []Finding
	const batchLimit = 500

	for i := 0; i < len(deps); i += batchLimit {
		end := i + batchLimit
		if end > len(deps) {
			end = len(deps)
		}

		batchSlice := deps[i:end]
		var queries []OSVBatchQuery
		for _, dep := range batchSlice {
			queries = append(queries, OSVBatchQuery{
				Package: OSVPackage{Name: dep.Name, Ecosystem: dep.Ecosystem},
				Version: dep.Version,
			})
		}

		resp, err := ds.osvClient.BatchQuery(queries)
		if err != nil {
			return nil, fmt.Errorf("OSV lookup failed: %w", err)
		}

		for qIdx, res := range resp.Results {
			dep := batchSlice[qIdx]
			for _, vuln := range res.Vulns {
				sev := SeverityHigh
				for _, s := range vuln.Severities {
					if strings.Contains(s.Score, "CVSS:3") || strings.Contains(s.Score, "CVSS:4") {
						sev = SeverityCritical
						break
					}
				}

				summary := vuln.Summary
				if summary == "" {
					summary = fmt.Sprintf("Vulnerability advisory logged in %s@%s", dep.Name, dep.Version)
				}

				findings = append(findings, Finding{
					ID:          vuln.ID,
					Category:    "DEPENDENCY",
					Severity:    sev,
					File:        dep.File,
					Line:        dep.Line,
					Detected:    fmt.Sprintf("%s in %s@%s", vuln.ID, dep.Name, dep.Version),
					WhyItMatter: summary,
					Remediation: fmt.Sprintf("Upgrade %s to a non-vulnerable version per advisory %s.", dep.Name, vuln.ID),
				})
			}
		}
	}

	return findings, nil
}