package output

import (
	"fmt"
	"io"
	"os"

	"github.com/gitshield/gitshield/internal/scanner"
)

const (
	Reset   = "\033[0m"
	Bold    = "\033[1m"
	Red     = "\033[1;31m"
	Amber   = "\033[1;33m"
	Cyan    = "\033[1;36m"
	Gray    = "\033[0;90m"
	White   = "\033[1;37m"
	BgRed   = "\033[41;37m"
	BgAmber = "\033[43;30m"
)

func PrintReport(w io.Writer, summary *scanner.ScanSummary) {
	if w == nil {
		w = os.Stdout
	}

	fmt.Fprintf(w, "\n%s================================================================================%s\n", Cyan, Reset)
	fmt.Fprintf(w, "%s   GitShield Security Scanner - V1 Report%s\n", Bold, Reset)
	fmt.Fprintf(w, "%s================================================================================%s\n\n", Cyan, Reset)

	if len(summary.Findings) == 0 {
		fmt.Fprintf(w, "\033[1;32m   Zero secrets or package vulnerabilities detected!%s\n\n", Reset)
		return
	}

	for idx, f := range summary.Findings {
		var badge string
		switch f.Severity {
		case scanner.SeverityCritical:
			badge = fmt.Sprintf("%s CRITICAL %s", BgRed, Reset)
		case scanner.SeverityHigh:
			badge = fmt.Sprintf("%s HIGH %s", BgAmber, Reset)
		case scanner.SeverityMedium:
			badge = fmt.Sprintf("%s%s MEDIUM %s", Amber, Bold, Reset)
		default:
			badge = fmt.Sprintf("%s%s %s %s", Cyan, Bold, f.Severity, Reset)
		}

		fmt.Fprintf(w, "[%d] %s %s%s%s\n", idx+1, badge, Bold, f.Detected, Reset)
		fmt.Fprintf(w, "    %sLocation:%s            %s:%d\n", Gray, Reset, f.File, f.Line)
		fmt.Fprintf(w, "    %sWhat was detected:%s   %s\n", Gray, Reset, f.Detected)
		fmt.Fprintf(w, "    %sWhy it matters:%s      %s\n", Gray, Reset, f.WhyItMatter)
		fmt.Fprintf(w, "    %sRemediation:%s         %s%s%s\n\n", Gray, Reset, White, f.Remediation, Reset)
	}

	fmt.Fprintf(w, "%s--------------------------------------------------------------------------------%s\n", Gray, Reset)
	fmt.Fprintf(w, "  Summary: %d Files Audited | %s%d Critical%s | %s%d High%s | %d Medium | %d Low\n",
		summary.TotalFilesScanned,
		Red, summary.CriticalCount, Reset,
		Amber, summary.HighCount, Reset,
		summary.MediumCount,
		summary.LowCount,
	)
	fmt.Fprintf(w, "%s--------------------------------------------------------------------------------%s\n\n", Gray, Reset)
}