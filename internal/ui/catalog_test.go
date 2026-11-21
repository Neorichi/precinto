package ui

import (
	"go/ast"
	"go/parser"
	"go/token"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestCatalogMatchesComments keeps the normative comment of every MsgID
// constant identical to the text Format renders (SPEC §16.3).
func TestCatalogMatchesComments(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "ui.go", nil, parser.ParseComments)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[MsgID]bool{}
	ast.Inspect(f, func(n ast.Node) bool {
		vs, ok := n.(*ast.ValueSpec)
		if !ok || vs.Type == nil || len(vs.Values) != 1 {
			return true
		}
		if id, ok := vs.Type.(*ast.Ident); !ok || id.Name != "MsgID" {
			return true
		}
		lit, ok := vs.Values[0].(*ast.BasicLit)
		if !ok {
			return true
		}
		val, err := strconv.Unquote(lit.Value)
		if err != nil {
			t.Fatal(err)
		}
		id := MsgID(val)
		if seen[id] {
			t.Errorf("duplicate MsgID %s", id)
		}
		seen[id] = true
		if vs.Comment == nil {
			t.Errorf("%s has no normative comment", id)
			return true
		}
		comment := strings.TrimSpace(vs.Comment.Text())
		want, ok := catalog[id]
		if !ok {
			t.Errorf("%s missing from the catalog table", id)
			return true
		}
		if comment != strings.ReplaceAll(want, "\n", `\n`) {
			t.Errorf("%s: comment and catalog differ:\n comment: %s\n catalog: %s", id, comment, want)
		}
		return true
	})
	for id := range catalog {
		if !seen[id] {
			t.Errorf("catalog entry %s has no MsgID constant", id)
		}
	}
}

var (
	placeholder = regexp.MustCompile(`\{[a-z]+\}`)
	// User-facing words never used (SPEC §16.3); the --root flag is allowed.
	forbidden = regexp.MustCompile(`\b(root|grant|soft|hard)\b`)
)

// TestCatalogRenders renders every message with every variable set.
func TestCatalogRenders(t *testing.T) {
	v := Vars{
		Folder: "~/work/acme", Other: "~/work/beta", Reason: ReasonIdle, Idle: 15 * time.Minute,
		Harness: "claude", TTY: "ttys003", Factor: "Mac password", N: 2,
		Until: time.Date(2026, 11, 21, 18, 30, 0, 0, time.UTC), Limit: 8 * time.Hour,
		SID: "0123456789abcdef", PID: 4242, Files: 3, Bytes: 12_000_000, Cause: "disk full",
		Resume: "claude --resume 01234567", Days: 30, File: "notes.md", Conflict: "notes.conflict-20261121-1830.md",
		Action: "delete 3 generations", Command: "prune", Unit: "0123456789abcdef0123456789abcdef",
	}
	for id := range catalog {
		got := Format(id, v)
		if m := placeholder.FindString(got); m != "" {
			t.Errorf("%s: unfilled placeholder %s in %q", id, m, got)
		}
		if m := forbidden.FindString(strings.ReplaceAll(got, "--root", "")); m != "" {
			t.Errorf("%s: forbidden user-facing word %q", id, m)
		}
	}
	if got := Format(MsgNoteMarker, Vars{Unit: "k"}); got != "This note is sealed by precinto. Run `precinto unlock` in this folder to open it.\nid: k" {
		t.Errorf("marker text: %q", got)
	}
	if got, want := Format(MsgPromptBlocked, v), "precinto: ~/work/acme is locked (idle 15 min)."; !strings.HasPrefix(got, want) {
		t.Errorf("C3.blocked = %q, want prefix %q", got, want)
	}
}

func TestShimTextIsShellAndJSONSafe(t *testing.T) {
	// The shims embed MsgShimFailed in single-quoted sh and in a JSON
	// string: no quotes, backslashes or control characters (HOOKS-IO §5).
	s := catalog[MsgShimFailed]
	if strings.ContainsAny(s, "'\"\\`$") || strings.ContainsFunc(s, func(r rune) bool { return r < 0x20 }) {
		t.Errorf("MsgShimFailed is not safe to embed: %q", s)
	}
}

func TestHumanUnits(t *testing.T) {
	for d, want := range map[time.Duration]string{
		45 * time.Second: "45 s", 15 * time.Minute: "15 min", 8 * time.Hour: "8 h", 90 * time.Minute: "1 h 30 min",
	} {
		if got := humanDuration(d); got != want {
			t.Errorf("humanDuration(%s) = %q, want %q", d, got, want)
		}
	}
	for n, want := range map[int64]string{512: "512 B", 12_345: "12 kB", 12_000_000: "12 MB", 1_234_000_000: "1.2 GB"} {
		if got := HumanBytes(n); got != want {
			t.Errorf("HumanBytes(%d) = %q, want %q", n, got, want)
		}
	}
}
