package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/gitshield/gitshield/internal/config"
	"github.com/gitshield/gitshield/internal/githooks"
	"github.com/gitshield/gitshield/internal/output"
	"github.com/gitshield/gitshield/internal/scanner"
)

func main() {
	cfg := config.LoadConfig()

	if len(os.Args) < 2 {
		printUsage()
		os.Exit(0)
	}

	switch os.Args[1] {
	case "init":
		runInit()
	case "scan":
		runScan(cfg)
	case "version":
		fmt.Println("GitShield V1 (Go CLI)")
	default:
		fmt.Printf("Unknown command: %q\n\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`GitShield - Developer Security Scanner

Usage:
  gitshield [command] [flags]

Available Commands:
  scan       Run secret and lockfile security audits
  init       Install automated pre-commit and pre-push Git hooks
  version    Display GitShield version info

Flags for 'scan':
  --staged        Scan only git-staged changes
  --fail-on       Minimum severity that exits with code 1 (CRITICAL, HIGH, MEDIUM, LOW)
  --json          Output results as JSON
  --path          Path to scan (defaults to '.')`)
}

func runInit() {
	pwd, err := os.Getwd()
	if err != nil {
		log.Fatalf("Failed obtaining current directory: %v", err)
	}
	if err := githooks.InstallHooks(pwd); err != nil {
		fmt.Printf("%s[GitShield Error]%s %v\n", output.Red, output.Reset, err)
		os.Exit(1)
	}
	fmt.Printf("%s[GitShield]%s Pre-commit and pre-push hooks installed in .git/hooks/\n", output.Cyan, output.Reset)
}

func runScan(cfg *config.Config) {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	staged := fs.Bool("staged", false, "Scan staged git changes")
	jsonOut := fs.Bool("json", false, "Format output as JSON")
	failOn := fs.String("fail-on", cfg.DefaultFailOn, "Exit 1 if severity >= CRITICAL|HIGH|MEDIUM|LOW")
	path := fs.String("path", ".", "Target path")
	_ = fs.Parse(os.Args[2:])

	secScanner := scanner.NewSecretScanner(cfg.EntropyThreshold)
	depScanner := scanner.NewDependencyScanner(scanner.NewOSVClient())
	runner := scanner.NewScanRunner(secScanner, depScanner)

	summary, err := runner.Scan(*path, *staged)
	if err != nil {
		log.Fatalf("Scan execution failed: %v", err)
	}

	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(summary)
	} else {
		output.PrintReport(os.Stdout, summary)
	}

	shouldFail := false
	switch *failOn {
	case "CRITICAL":
		shouldFail = summary.CriticalCount > 0
	case "HIGH":
		shouldFail = summary.CriticalCount > 0 || summary.HighCount > 0
	case "MEDIUM":
		shouldFail = summary.CriticalCount > 0 || summary.HighCount > 0 || summary.MediumCount > 0
	case "LOW":
		shouldFail = len(summary.Findings) > 0
	}

	if shouldFail {
		os.Exit(1)
	}
}