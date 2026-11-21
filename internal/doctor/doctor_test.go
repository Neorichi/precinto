package doctor_test

import (
	"context"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/precinto/precinto/internal/config"
	"github.com/precinto/precinto/internal/doctor"
	"github.com/precinto/precinto/internal/harness"
	"github.com/precinto/precinto/internal/ipc"
	"github.com/precinto/precinto/internal/paths"
	"github.com/precinto/precinto/internal/sweep"
	"github.com/precinto/precinto/internal/testkit"
	"github.com/precinto/precinto/internal/ui"
)

// constValues returns the string constants of a Go file whose names start
// with prefix (the contract's Check* and Attn* vocabularies).
func constValues(t *testing.T, file, prefix string, resolve map[string]string) map[string]string {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), file, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	ast.Inspect(f, func(n ast.Node) bool {
		vs, ok := n.(*ast.ValueSpec)
		if !ok {
			return true
		}
		for i, name := range vs.Names {
			if !strings.HasPrefix(name.Name, prefix) || i >= len(vs.Values) {
				continue
			}
			switch v := vs.Values[i].(type) {
			case *ast.BasicLit:
				s, err := strconv.Unquote(v.Value)
				if err == nil {
					out[name.Name] = s
				}
			case *ast.SelectorExpr: // ipc.AttnX
				if s, ok := resolve[v.Sel.Name]; ok {
					out[name.Name] = s
				} else {
					t.Errorf("%s = %s.%s: unknown constant", name.Name, v.X, v.Sel.Name)
				}
			}
		}
		return true
	})
	return out
}

func TestCodesCoverTheVocabulary(t *testing.T) {
	attn := constValues(t, "../ipc/ipc.go", "Attn", nil)
	if len(attn) == 0 {
		t.Fatal("no ipc.Attn* constants found")
	}
	checks := constValues(t, "doctor.go", "Check", attn)
	codes := doctor.Codes()
	seen := map[string]bool{}
	for _, c := range codes {
		if seen[c] {
			t.Errorf("code %q listed twice", c)
		}
		seen[c] = true
	}
	for name, v := range checks {
		if !seen[v] {
			t.Errorf("doctor.%s (%q) is missing from Codes()", name, v)
		}
	}
	if len(codes) != len(checks) {
		t.Errorf("Codes() has %d codes, doctor.go declares %d Check constants", len(codes), len(checks))
	}
	// One vocabulary: every status attention code is a doctor code.
	for name, v := range attn {
		if !seen[v] {
			t.Errorf("ipc.%s (%q) is not a doctor code", name, v)
		}
	}
	// Codes returns a fresh slice.
	codes[0] = "changed"
	if doctor.Codes()[0] == "changed" {
		t.Error("Codes() returns shared state")
	}
}

func TestRunValidatesOptions(t *testing.T) {
	f := newFixture(t)
	for _, h := range []string{"", "claude-code", "claude", "codex", " codex ", "gemini"} {
		f.o.Harness = h
		if _, err := doctor.RunWith(context.Background(), f.o, f.d); err != nil {
			t.Errorf("Harness %q: %v", h, err)
		}
	}
	f.o.Harness = "no-such-harness"
	if _, err := doctor.RunWith(context.Background(), f.o, f.d); !errors.Is(err, harness.ErrUnknownHarness) {
		t.Errorf("unknown harness: err = %v, want ErrUnknownHarness", err)
	}
	f.o.Harness = ""
	o := f.o
	o.Layout.Base = ""
	if _, err := doctor.RunWith(context.Background(), o, f.d); err == nil {
		t.Error("an empty layout was accepted")
	}
}

func TestCleanHomeHasNoProblems(t *testing.T) {
	f := newFixture(t)
	f.installClaudePlugin()
	fs := f.run()
	for _, x := range fs {
		if x.Severity == doctor.Warn || x.Severity == doctor.Fail {
			t.Errorf("clean home: %s %s: %s", x.Severity, x.Code, x.Message)
		}
	}
	want(t, fs, doctor.CheckVaultTampered, doctor.OK)
	want(t, fs, doctor.CheckClaudeSettingsEnv, doctor.OK)
	want(t, fs, doctor.CheckUnsealed, doctor.OK)
}

func TestHarnessFilter(t *testing.T) {
	f := newFixture(t)
	f.o.Harness = "codex"
	for _, x := range f.run() {
		if strings.HasPrefix(x.Code, "claude-") || x.Code == doctor.CheckHistoryPending {
			t.Errorf("doctor codex ran %s", x.Code)
		}
	}
	f.o.Harness = "claude-code"
	for _, x := range f.run() {
		if strings.HasPrefix(x.Code, "codex-") {
			t.Errorf("doctor claude-code ran %s", x.Code)
		}
	}
	// A harness precinto does not manage is not checked either.
	f.o.Harness = ""
	cfg := f.h.Cfg
	cfg.Harness = map[string]config.Harness{}
	for k, v := range f.h.Cfg.Harness {
		cfg.Harness[k] = v
	}
	cc := cfg.Harness["claude-code"]
	cc.Enabled = false
	cfg.Harness["claude-code"] = cc
	f.o.Cfg = cfg
	for _, x := range f.run() {
		if strings.HasPrefix(x.Code, "claude-") {
			t.Errorf("disabled claude-code: ran %s", x.Code)
		}
	}
}

func TestPanickingDependencyIsContained(t *testing.T) {
	f := newFixture(t)
	f.d.Plaintext = func(context.Context) ([]sweep.Plaintext, error) { panic("unimplemented: sweep.PlaintextSummary") }
	fs, err := doctor.RunWith(context.Background(), f.o, f.d)
	if err != nil {
		t.Fatal(err)
	}
	got := want(t, fs, doctor.CheckUnsealed, doctor.Warn, doctor.InternalErrorText)
	if strings.Contains(got.Message, "unimplemented") || strings.Contains(got.Fix, "unimplemented") {
		t.Errorf("the panic value leaked into the finding: %+v", got)
	}
	// The other checks still ran.
	want(t, fs, doctor.CheckVaultTampered, doctor.OK)
	want(t, fs, doctor.CheckConflict, doctor.OK)
}

func TestCancelledContext(t *testing.T) {
	f := newFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := doctor.RunWith(ctx, f.o, f.d); !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled", err)
	}
}

func TestAttentionItemsAreMerged(t *testing.T) {
	f := newFixture(t)
	st := ipc.StatusResp{PID: 4242, Attention: []ipc.Attention{
		{Code: ipc.AttnVaultTampered, Folder: f.h.Root, Fix: "precinto vault repair --root ~/work/acme"},
		{Code: ipc.AttnHoldCapped, Folder: f.h.Root, Count: 2},
		{Code: ipc.AttnUngatedSession, Folder: f.h.Root, PID: 777, Detail: "claude\x1b[31m"},
		{Code: ipc.AttnCodexWrongHome, Folder: f.h.Root, Count: 3},
		{Code: ipc.AttnExposed, Folder: f.h.Root, Count: 1},
		{Code: "future-code", Detail: "new"},
	}}
	f.d.DaemonStatus = func(context.Context) (ipc.StatusResp, error) { return st, nil }
	fs, err := doctor.RunWith(context.Background(), f.o, f.d)
	if err != nil {
		t.Fatal(err)
	}
	var known []doctor.Finding
	for _, x := range fs {
		if slices.Contains(doctor.Codes(), x.Code) {
			known = append(known, x)
		}
	}
	checkInvariants(t, known, nil)
	folder := f.tilde(f.h.Root)
	want(t, fs, doctor.CheckVaultTampered, doctor.Fail, folder+"'s vault file was changed outside precinto")
	want(t, fs, doctor.CheckHoldCapped, doctor.Warn, "2 units")
	ug := want(t, fs, doctor.CheckUngatedSession, doctor.Warn, "pid 777", folder)
	if strings.Contains(ug.Message, "\x1b") {
		t.Errorf("escape sequence from the agent reached the message: %q", ug.Message)
	}
	want(t, fs, doctor.CheckCodexWrongHome, doctor.Warn, "3 Codex conversation(s) from "+folder)
	want(t, fs, doctor.CheckExposed, doctor.Fail, "1 capsule")
	// A code this build does not know is shown, never dropped.
	found := false
	for _, x := range fs {
		if x.Code == "future-code" {
			found = x.Severity == doctor.Warn
		}
	}
	if !found {
		t.Errorf("unknown attention code dropped:\n%s", dump(fs))
	}
}

// TestUngatedAttentionNamesTheHarness: an ungated-session item that names
// its harness (ipc.Attention.Harness, CC-48) is rendered as C9.ungated
// exactly, with the command users type; one without a usable harness keeps
// the generic text.
func TestUngatedAttentionNamesTheHarness(t *testing.T) {
	f := newFixture(t)
	st := ipc.StatusResp{PID: 4242, Attention: []ipc.Attention{
		{Code: ipc.AttnUngatedSession, Folder: "~/work/acme", PID: 778, Harness: "claude-code", Detail: "no hooks"},
		{Code: ipc.AttnUngatedSession, Folder: f.h.Root, PID: 779, Harness: "codex", Fix: "precinto run codex"},
		{Code: ipc.AttnUngatedSession, PID: 780, Harness: "gemini"},
		{Code: ipc.AttnUngatedSession, Folder: f.h.Root, PID: 781, Harness: "$(evil)"},
	}}
	f.d.DaemonStatus = func(context.Context) (ipc.StatusResp, error) { return st, nil }
	fs := f.run()
	folder := f.tilde(f.h.Root)
	exact := map[int]string{
		778: ui.Format(ui.MsgUngatedSession, ui.Vars{Harness: "claude", PID: 778, Folder: "~/work/acme"}),
		779: ui.Format(ui.MsgUngatedSession, ui.Vars{Harness: "codex", PID: 779, Folder: folder}),
	}
	for pid, text := range exact {
		got := want(t, fs, doctor.CheckUngatedSession, doctor.Warn, fmt.Sprintf("(pid %d)", pid))
		if wantMsg := strings.TrimPrefix(text, "precinto: "); got.Message != wantMsg {
			t.Errorf("pid %d: message\n %q\nwant C9.ungated\n %q", pid, got.Message, wantMsg)
		}
	}
	if got := want(t, fs, doctor.CheckUngatedSession, doctor.Warn, "(pid 778)"); got.Fix != "quit it, or start it with: precinto run claude" {
		t.Errorf("fix %q", got.Fix)
	}
	if got := want(t, fs, doctor.CheckUngatedSession, doctor.Warn, "(pid 779)"); got.Fix != "precinto run codex" {
		t.Errorf("the agent's own fix was replaced: %q", got.Fix)
	}
	// No folder: no C9.ungated (it names one), but the harness is named.
	if got := want(t, fs, doctor.CheckUngatedSession, doctor.Warn, "gemini (pid 780) runs without precinto's hooks"); got.Fix != "quit it, or start it with: precinto run gemini" {
		t.Errorf("fix %q", got.Fix)
	}
	// A harness that is not a command word is never put into a command.
	got := want(t, fs, doctor.CheckUngatedSession, doctor.Warn, "a session (pid 781)")
	if strings.Contains(got.Message, "evil") || strings.Contains(got.Fix, "evil") {
		t.Errorf("finding %+v", got)
	}

	// `precinto doctor codex` leaves out the Claude Code session.
	f.o.Harness = "codex"
	fs = f.run()
	want(t, fs, doctor.CheckUngatedSession, doctor.Warn, "(pid 779)")
	for _, x := range of(fs, doctor.CheckUngatedSession) {
		if strings.Contains(x.Message, "(pid 778)") {
			t.Errorf("doctor codex shows a Claude Code session: %q", x.Message)
		}
	}
}

// Only a layout: no config, no environment, no process table. Every check
// copes (nothing panics, nothing is invented).
func TestMinimalOptions(t *testing.T) {
	base := t.TempDir()
	run := testkit.ShortTempDir(t)
	l, err := paths.LayoutAt(base, run)
	if err != nil {
		t.Fatal(err)
	}
	for _, goos := range []string{"darwin", "linux"} {
		d := safeDeps(now)
		d.GOOS = goos
		fs, err := doctor.RunWith(context.Background(), doctor.Options{Layout: l, Leaks: true}, d)
		if err != nil {
			t.Fatal(err)
		}
		checkInvariants(t, fs, nil)
	}
}
