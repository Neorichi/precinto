package doctor

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// Rendering of findings for `precinto doctor` (Render, Worst): a human
// listing and a JSON document. Both sanitize again: a finding may come from
// the agent.

// severityRank orders severities from the worst.
var severityRank = map[Severity]int{Fail: 0, Warn: 1, Info: 2, OK: 3}

// severityLabel is the fixed-width label of the human listing.
var severityLabel = map[Severity]string{Fail: "FAIL", Warn: "warn", Info: "info", OK: "ok"}

// worst returns the most severe severity among fs (OK when empty).
func worst(fs []Finding) Severity {
	w := OK
	for _, f := range fs {
		if r, ok := severityRank[f.Severity]; ok && r < severityRank[w] {
			w = f.Severity
		}
	}
	return w
}

// writeHuman writes one line per finding ("FAIL  code  message") with its
// fix on the next line, then a summary line.
func writeHuman(w io.Writer, fs []Finding) error {
	width := 0
	for _, f := range fs {
		width = max(width, len(f.Code))
	}
	counts := map[Severity]int{}
	var b strings.Builder
	for _, f := range fs {
		counts[f.Severity]++
		label, ok := severityLabel[f.Severity]
		if !ok {
			label = oneLine(string(f.Severity))
		}
		fmt.Fprintf(&b, "%-4s  %-*s  %s\n", label, width, oneLine(f.Code), oneLine(f.Message))
		if fix := oneLine(f.Fix); fix != "" {
			fmt.Fprintf(&b, "%-4s  %-*s  fix: %s\n", "", width, "", fix)
		}
	}
	fmt.Fprintf(&b, "precinto doctor: %d failed, %s, %s, %d ok\n", counts[Fail],
		plural(counts[Warn], "warning", "warnings"), plural(counts[Info], "note", "notes"), counts[OK])
	_, err := io.WriteString(w, b.String())
	return err
}

// jsonReport is the JSON document of `precinto doctor --json` (v1).
type jsonReport struct {
	V        int           `json:"v"`
	Worst    Severity      `json:"worst"`
	Findings []jsonFinding `json:"findings"`
}

type jsonFinding struct {
	Code     string   `json:"code"`
	Severity Severity `json:"severity"`
	Message  string   `json:"message"`
	Fix      string   `json:"fix,omitempty"`
}

// writeJSON writes the findings as one JSON document.
func writeJSON(w io.Writer, fs []Finding) error {
	r := jsonReport{V: 1, Worst: worst(fs), Findings: make([]jsonFinding, 0, len(fs))}
	for _, f := range fs {
		r.Findings = append(r.Findings, jsonFinding{Code: oneLine(f.Code), Severity: Severity(oneLine(string(f.Severity))), Message: oneLine(f.Message), Fix: oneLine(f.Fix)})
	}
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}
