package ui

import (
	"strings"
	"testing"
)

// D150 (U6-5): a generated passphrase (words joined by hyphens) is shown
// exactly as it must be typed: no space is added, and a line that would be
// too long breaks only after a hyphen. A recovery key keeps its groups of
// 6 (its spaces are dropped when it is typed, a passphrase's are not).
func TestGeneratedPassphraseIsShownAsTyped(t *testing.T) {
	const pass = "apple-river-stone-candle-orbit-velvet-meadow" // a made-up 7-word example
	layout := func(secret string, width int) string {
		t.Helper()
		body, err := groupedSecret([]byte(secret), width)
		if err != nil {
			t.Fatal(err)
		}
		defer body.Destroy()
		return string(body.Bytes())
	}
	if got := layout(pass, 80); got != "  "+pass+"\n" {
		t.Errorf("80 columns: %q, want the passphrase as typed", got)
	}
	narrow := layout(pass, 24)
	for _, line := range strings.Split(strings.TrimSuffix(narrow, "\n"), "\n") {
		if !strings.HasPrefix(line, "  ") || strings.Contains(line[2:], " ") || len(line) > 23 {
			t.Errorf("24 columns: line %q adds a space or is too wide (%q)", line, narrow)
		}
		if body := line[2:]; body != "" && !strings.HasSuffix(body, "-") && !strings.HasSuffix(pass, body) {
			t.Errorf("24 columns: line %q breaks inside a word (%q)", line, narrow)
		}
	}
	if joined := strings.ReplaceAll(strings.ReplaceAll(narrow, "\n", ""), "  ", ""); joined != pass {
		t.Errorf("24 columns: the lines join to %q, want %q", joined, pass)
	}
	// Not a generated passphrase: the recovery-key layout stays.
	for secret, want := range map[string]string{
		"AGE-SECRET-KEY-1TESTKEYTESTKEY": "  AGE-SE CRET-K EY-1TE STKEYT ESTKEY\n",
		"ABCDEFGH":                       "  ABCDEF GH\n",
		"apple--river":                   "  apple- -river\n",
		"Apple-river":                    "  Apple- river\n",
	} {
		if got := layout(secret, 80); got != want {
			t.Errorf("%q shown as %q, want %q", secret, got, want)
		}
	}
}

// D150 (U6-9): C9.claude names the cause a new user meets first (the
// plugin is not installed) and the command that tells which one applies,
// and keeps its first 40 characters, which E2E-7 matches.
func TestClaudeNoHooksNamesTheNextCommand(t *testing.T) {
	got := Format(MsgClaudeNoHooks, Vars{})
	for _, want := range []string{"plugin not installed", "precinto doctor claude-code"} {
		if !strings.Contains(got, want) {
			t.Errorf("C9.claude %q lacks %q", got, want)
		}
	}
	if !strings.HasPrefix(got, "precinto: Claude's precinto hooks didn't") {
		t.Errorf("C9.claude %q changed the prefix E2E-7 matches", got)
	}
	if strings.Contains(got, "while the folder was locked") {
		t.Errorf("C9.claude %q speaks of a lock the session may never have seen", got)
	}
}
