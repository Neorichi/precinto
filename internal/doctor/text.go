package doctor

import (
	"fmt"
	"sort"
	"strings"

	"github.com/precinto/precinto/internal/paths"
	"github.com/precinto/precinto/internal/ui"
)

// Message rules (SPEC §16.3): one line; content-free (paths, counts, names
// of keys and variables, never values, prompts or file content); the
// user-facing words of the catalog ("folder", "locked", never "root",
// "grant", "soft" or "hard"). Texts that exist in the ui catalog are taken
// from it; the others are composed here until the catalog has doctor
// messages (change request).

// oneLine strips control characters (a folder or file name can carry
// terminal escapes, S17) and keeps the text on one line.
func oneLine(s string) string {
	b := ui.SanitizeTerminal([]byte(s))
	return strings.NewReplacer("\n", " ", "\t", " ").Replace(string(b))
}

// catalog renders a catalog message for a finding: without the
// "precinto: " prefix the CLI adds itself, on one line.
func catalog(id ui.MsgID, v ui.Vars) string {
	s := ui.Format(id, v)
	s = strings.TrimPrefix(s, "precinto: ")
	return oneLine(s)
}

// shellArg renders a path as one shell word for a fix command: the
// ~-shortened form when it needs no quoting, else the absolute path in
// single quotes.
func shellArg(home, p string) string {
	short := paths.Tilde(home, p)
	if shellSafe(short) {
		return short
	}
	return "'" + strings.ReplaceAll(oneLine(p), "'", `'\''`) + "'"
}

func shellSafe(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		switch {
		case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', '0' <= c && c <= '9':
		case strings.ContainsRune("/._-+:,@%~", c):
		default:
			return false
		}
	}
	return !strings.HasPrefix(s, "~") || s == "~" || strings.HasPrefix(s, "~/")
}

// plural returns "1 file" / "3 files" style counts.
func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}

// verb picks the form that agrees with n ("is"/"are", "was"/"were").
func verb(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// joinNames renders a sorted, de-duplicated list of names.
func joinNames(names []string) string {
	set := map[string]bool{}
	var out []string
	for _, n := range names {
		n = oneLine(n)
		if n != "" && !set[n] {
			set[n] = true
			out = append(out, n)
		}
	}
	sort.Strings(out)
	return strings.Join(out, ", ")
}

// ok, info, warn and fail build findings.
func ok(code, msg string) Finding { return Finding{Code: code, Severity: OK, Message: msg} }

func info(code, msg, fix string) Finding {
	return Finding{Code: code, Severity: Info, Message: msg, Fix: fix}
}

func warn(code, msg, fix string) Finding {
	return Finding{Code: code, Severity: Warn, Message: msg, Fix: fix}
}

func fail(code, msg, fix string) Finding {
	return Finding{Code: code, Severity: Fail, Message: msg, Fix: fix}
}

// sortedKeys returns the keys of m sorted.
func sortedKeys(m map[string]int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
