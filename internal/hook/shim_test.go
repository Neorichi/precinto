package hook_test

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/precinto/precinto/internal/paths"
	"github.com/precinto/precinto/internal/ui"
)

// Shim tests (HOOK-4, HOOKS-IO §5): the POSIX shim run by several shells,
// against fake precinto binaries from testdata/, in temporary homes. The
// shells get an explicit environment, no controlling terminal and a
// temporary HOME: nothing of the real user's is read.

// shell is one way of running the shim as `sh <shim> HARNESS EVENT`.
type shell struct {
	name string
	argv []string
}

// shimShells are the shells the shim must work under; missing ones are
// skipped (fish is not a POSIX shell: the shim always runs under sh).
func shimShells(t *testing.T) []shell {
	t.Helper()
	all := []shell{
		{"sh", []string{"/bin/sh"}},
		{"dash", []string{"/bin/dash"}},
		{"bash", []string{"/bin/bash"}},
		{"bash-posix", []string{"/bin/bash", "--posix"}},
		{"zsh-sh", []string{"/bin/zsh", "--emulate", "sh"}},
		{"ksh", []string{"/bin/ksh"}},
		{"bash-homebrew", []string{"/opt/homebrew/bin/bash", "--posix"}},
		{"busybox", []string{"/bin/busybox", "sh"}},
	}
	var out []shell
	for _, s := range all {
		if st, err := os.Stat(s.argv[0]); err == nil && st.Mode().IsRegular() {
			out = append(out, s)
		}
	}
	if len(out) == 0 {
		t.Skip("no POSIX shell found")
	}
	return out
}

// macOS is the shim's own platform test (it decides the base and case
// folding the same way).
func macOS() bool {
	_, err := os.Stat("/System/Library/CoreServices")
	return err == nil
}

// shimHome is a temporary HOME with precinto's base, a protected folder and
// a folder outside it.
type shimHome struct {
	home, base, root, outside, logFile string
	xdg                                string // XDG_DATA_HOME off macOS
}

func newShimHome(t *testing.T) *shimHome {
	t.Helper()
	// The shim falls back to these install locations when <base>/bin and
	// PATH have no precinto: a test of a missing binary would then run a
	// real installed precinto, outside any fake home. Never do that.
	for _, p := range []string{"/opt/homebrew/bin/precinto", "/usr/local/bin/precinto"} {
		if _, err := os.Lstat(p); err == nil {
			t.Skipf("%s is installed: the shim tests would run it", p)
		}
	}
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	h := &shimHome{home: filepath.Join(dir, "home")}
	if macOS() {
		h.base = filepath.Join(h.home, "Library", "Application Support", "precinto")
	} else {
		h.xdg = filepath.Join(h.home, "xdg data")
		h.base = filepath.Join(h.xdg, "precinto")
	}
	h.root = filepath.Join(h.home, "work", "acme corp")
	h.outside = filepath.Join(h.home, "work", "acme corp-other")
	h.logFile = filepath.Join(dir, "fake.log")
	for _, d := range []string{filepath.Join(h.base, "bin"), filepath.Join(h.root, "sub"), h.outside} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(h.base, "roots.list"), []byte("relative/ignored\n\n"+h.root+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return h
}

// install puts the fake binary at <base>/bin/precinto.
func (h *shimHome) install(t *testing.T, src string) {
	t.Helper()
	b, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(h.base, "bin", "precinto"), b, 0o755); err != nil {
		t.Fatal(err)
	}
}

type shimRun struct {
	stdout, stderr string
	exit           int
}

// runShim runs the shim of the Claude plugin under sh with cwd dir and
// exactly env (plus HOME, PATH and PWD).
func (h *shimHome) runShim(t *testing.T, sh shell, dir string, env map[string]string, stdin string, args ...string) shimRun {
	t.Helper()
	shim, err := filepath.Abs(filepath.Join(repo, "plugin", "scripts", "precinto-hook"))
	if err != nil {
		t.Fatal(err)
	}
	full := map[string]string{"HOME": h.home, "PATH": "/usr/bin:/bin", "PWD": dir}
	if h.xdg != "" {
		full["XDG_DATA_HOME"] = h.xdg
	}
	for k, v := range env {
		if v == "\x00unset" {
			delete(full, k)
			continue
		}
		full[k] = v
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, sh.argv[0], append(append(sh.argv[1:], shim), args...)...)
	cmd.Dir = dir
	cmd.Env = nil
	for k, v := range full {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	cmd.Stdin = strings.NewReader(stdin)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true} // never the test's terminal
	cmd.WaitDelay = 5 * time.Second                      // a straggler holding the pipes cannot stall Wait
	err = cmd.Run()
	r := shimRun{stdout: out.String(), stderr: errb.String()}
	if ee, ok := err.(*exec.ExitError); ok {
		r.exit = ee.ExitCode()
	} else if err != nil {
		t.Fatalf("%s: %v", sh.name, err)
	}
	return r
}

var gateEvents = []string{"UserPromptSubmit", "PreToolUse", "PermissionRequest", "PreCompact"}

// staticBlock is the shim's answer for a gate event inside a protected
// folder when the binary is missing or failed (HOOKS-IO §5 step 3).
func staticBlock(harness, event string) shimRun {
	d := ui.Format(ui.MsgShimFailed, ui.Vars{})
	if harness == "codex" {
		if event == "PreCompact" {
			return shimRun{stdout: `{"continue":false,"stopReason":"` + d + `"}`}
		}
		return shimRun{stderr: d + "\n", exit: 2}
	}
	switch event {
	case "UserPromptSubmit":
		return shimRun{stdout: `{"decision":"block","reason":"` + d + `","hookSpecificOutput":{"hookEventName":"UserPromptSubmit","suppressOriginalPrompt":true}}`}
	case "PreToolUse":
		return shimRun{stdout: `{"continue":false,"stopReason":"` + d + `","hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"` + d + `"}}`}
	case "PermissionRequest":
		return shimRun{stdout: `{"hookSpecificOutput":{"hookEventName":"PermissionRequest","decision":{"behavior":"deny","message":"` + d + `"}}}`}
	default:
		return shimRun{stdout: `{"decision":"block","reason":"` + d + `"}`}
	}
}

// expectedShim is the HOOK-4 table: binary behaviour → shim answer.
func expectedShim(mode, harness, event string, inside bool) shimRun {
	switch mode {
	case "json":
		return shimRun{stdout: `{"fake":true}`}
	case "empty":
		return shimRun{}
	case "ten":
		return shimRun{stderr: "fake reason\n", exit: 2}
	}
	// text, tenempty, one, two, kill, gopanic, missing: a failed run.
	gate := false
	for _, g := range gateEvents {
		gate = gate || g == event
	}
	if gate && inside {
		return staticBlock(harness, event)
	}
	return shimRun{}
}

// goPanicBinary builds testdata/gopanic, a binary that dies of a real Go
// runtime panic (exit 2), with the toolchain running the tests, into the
// test's temporary directory.
func goPanicBinary(t *testing.T) string {
	t.Helper()
	goroot := os.Getenv("GOROOT")
	if goroot == "" {
		goroot = runtime.GOROOT()
	}
	out := filepath.Join(t.TempDir(), "precinto")
	var env []string
	for _, kv := range os.Environ() {
		k, _, _ := strings.Cut(kv, "=")
		if k == "PATH" || k == "HOME" || k == "TMPDIR" || k == "XDG_CACHE_HOME" || strings.HasPrefix(k, "GO") {
			env = append(env, kv)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, filepath.Join(goroot, "bin", "go"), "build", "-buildvcs=false", "-o", out, "./testdata/gopanic")
	cmd.Env = append(env, "CGO_ENABLED=0")
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build ./testdata/gopanic: %v\n%s", err, b)
	}
	return out
}

// TestShimExitTable runs the HOOK-4 table under /bin/sh for every harness,
// gate and non-gate event, binary behaviour, and folder.
func TestShimExitTable(t *testing.T) {
	sh := shell{"sh", []string{"/bin/sh"}}
	modes := []string{"json", "empty", "text", "ten", "tenempty", "one", "two", "kill", "missing"}
	if !testing.Short() {
		modes = append(modes, "gopanic")
	}
	events := append(append([]string(nil), gateEvents...), "SessionStart", "PostToolUse", "SessionEnd")
	for _, mode := range modes {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			h := newShimHome(t)
			switch mode {
			case "missing":
			case "gopanic":
				h.install(t, goPanicBinary(t))
			default:
				h.install(t, filepath.Join("testdata", "fakebin", "precinto"))
			}
			where := map[string]struct {
				dir    string
				env    map[string]string
				inside bool
			}{
				"inside":             {filepath.Join(h.root, "sub"), nil, true},
				"root itself":        {h.root, nil, true},
				"outside (prefix)":   {h.outside, nil, false},
				"project dir inside": {h.outside, map[string]string{"CLAUDE_PROJECT_DIR": h.root}, true},
			}
			for _, harness := range []string{"claude-code", "codex"} {
				for _, ev := range events {
					for wname, w := range where {
						env := map[string]string{"FAKE_PRECINTO_MODE": mode}
						for k, v := range w.env {
							env[k] = v
						}
						got := h.runShim(t, sh, w.dir, env, `{"session_id":"s"}`, harness, ev)
						if want := expectedShim(mode, harness, ev, w.inside); got != want {
							t.Errorf("%s %s %s %s:\n got %+v\nwant %+v", mode, harness, ev, wname, got, want)
						}
					}
				}
			}
		})
	}
}

// TestShimShells runs the gate part of the table under every available
// shell (HOOK-4: sh, dash, bash, zsh in sh emulation, ksh).
func TestShimShells(t *testing.T) {
	if testing.Short() {
		t.Skip("runs every shell")
	}
	for _, sh := range shimShells(t) {
		t.Run(sh.name, func(t *testing.T) {
			t.Parallel()
			h := newShimHome(t)
			h.install(t, filepath.Join("testdata", "fakebin", "precinto"))
			for _, mode := range []string{"json", "empty", "text", "ten", "one", "two", "kill"} {
				for _, harness := range []string{"claude-code", "codex"} {
					for _, ev := range gateEvents {
						for _, inside := range []bool{true, false} {
							dir := h.outside
							if inside {
								dir = filepath.Join(h.root, "sub")
							}
							got := h.runShim(t, sh, dir, map[string]string{"FAKE_PRECINTO_MODE": mode}, "{}", harness, ev)
							if want := expectedShim(mode, harness, ev, inside); got != want {
								t.Errorf("%s %s %s inside=%v:\n got %+v\nwant %+v", mode, harness, ev, inside, got, want)
							}
						}
					}
				}
			}
		})
	}
}

// TestShimPassesPayloadAndArgs: stdin reaches the binary unchanged and the
// arguments are `hook HARNESS EVENT`.
func TestShimPassesPayloadAndArgs(t *testing.T) {
	h := newShimHome(t)
	h.install(t, filepath.Join("testdata", "fakebin", "precinto"))
	payload := `{"session_id":"s","prompt":"a b  c"}`
	got := h.runShim(t, shell{"sh", []string{"/bin/sh"}}, h.root, map[string]string{"FAKE_PRECINTO_MODE": "json", "FAKE_PRECINTO_LOG": h.logFile}, payload, "claude-code", "UserPromptSubmit")
	if got.exit != 0 || got.stdout != `{"fake":true}` {
		t.Fatalf("run: %+v", got)
	}
	log, err := os.ReadFile(h.logFile)
	if err != nil {
		t.Fatal(err)
	}
	if want := "args:hook claude-code UserPromptSubmit\nstdin:" + payload + "\n"; string(log) != want {
		t.Errorf("binary saw %q, want %q", log, want)
	}
}

// TestShimIgnoresPrecintoVariables (SEC-12, SEC-31): PRECINTO_BIN,
// PRECINTO_DEV and PRECINTO_HOME in the hook's environment change neither
// the binary nor the folders the shim protects.
func TestShimIgnoresPrecintoVariables(t *testing.T) {
	h := newShimHome(t)
	h.install(t, filepath.Join("testdata", "fakebin", "precinto"))
	other := t.TempDir()
	evil := filepath.Join(other, "evil")
	if err := os.WriteFile(evil, []byte("#!/bin/sh\ncat >/dev/null\necho ran >>\""+h.logFile+"\"\nprintf '{\"evil\":true}'\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	otherBase := filepath.Join(other, "base")
	if err := os.MkdirAll(filepath.Join(otherBase, "bin"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(otherBase, "roots.list"), []byte(h.outside+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(evil, filepath.Join(otherBase, "bin", "precinto")); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{
		"PRECINTO_BIN": evil, "PRECINTO_DEV": "1", "PRECINTO_HOME": otherBase, "PRECINTO_RUNTIME_DIR": other,
		"FAKE_PRECINTO_MODE": "one",
	}
	for _, sh := range shimShells(t) {
		// Inside the real root: the real (failing) binary ran, the static block.
		if got, want := h.runShim(t, sh, h.root, env, "{}", "claude-code", "UserPromptSubmit"), staticBlock("claude-code", "UserPromptSubmit"); got != want {
			t.Errorf("%s inside: %+v", sh.name, got)
		}
		// The folder only PRECINTO_HOME's roots.list names is not protected.
		if got := h.runShim(t, sh, h.outside, env, "{}", "claude-code", "UserPromptSubmit"); got != (shimRun{}) {
			t.Errorf("%s outside: %+v", sh.name, got)
		}
	}
	if b, _ := os.ReadFile(h.logFile); len(b) != 0 {
		t.Errorf("a PRECINTO_* binary ran: %q", b)
	}
}

// TestShimBinaryLookup: <base>/bin/precinto first, then precinto on PATH
// (absolute entries only), and nothing else from the environment.
func TestShimBinaryLookup(t *testing.T) {
	h := newShimHome(t)
	sh := shell{"sh", []string{"/bin/sh"}}
	pathDir := t.TempDir()
	relDir := filepath.Join(h.root, "rel")
	for _, d := range []string{pathDir, relDir} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	fake, err := os.ReadFile(filepath.Join("testdata", "fakebin", "precinto"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pathDir, "precinto"), fake, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(relDir, "precinto"), []byte("#!/bin/sh\nprintf '{\"relative\":true}'\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	// No <base>/bin/precinto: the PATH one runs; the relative entry is skipped.
	got := h.runShim(t, sh, h.root, map[string]string{"PATH": "rel:/usr/bin:/bin:" + pathDir, "FAKE_PRECINTO_MODE": "json"}, "{}", "claude-code", "PreToolUse")
	if got.stdout != `{"fake":true}` || got.exit != 0 {
		t.Errorf("PATH lookup: %+v", got)
	}
	// A non-executable <base>/bin/precinto is skipped too.
	if err := os.WriteFile(filepath.Join(h.base, "bin", "precinto"), fake, 0o644); err != nil {
		t.Fatal(err)
	}
	got = h.runShim(t, sh, h.root, map[string]string{"PATH": "/usr/bin:/bin:" + pathDir, "FAKE_PRECINTO_MODE": "empty"}, "{}", "claude-code", "PreToolUse")
	if got != (shimRun{}) {
		t.Errorf("non-executable base binary: %+v", got)
	}
	// With <base>/bin/precinto executable it wins over PATH.
	base := filepath.Join(h.base, "bin", "precinto")
	if err := os.WriteFile(base, []byte("#!/bin/sh\ncat >/dev/null\nprintf '{\"base\":true}'\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(base, 0o755); err != nil { // WriteFile keeps an existing file's mode
		t.Fatal(err)
	}
	got = h.runShim(t, sh, h.root, map[string]string{"PATH": "/usr/bin:/bin:" + pathDir, "FAKE_PRECINTO_MODE": "json"}, "{}", "claude-code", "PreToolUse")
	if got.stdout != `{"base":true}` {
		t.Errorf("base binary did not win: %+v", got)
	}
}

// TestShimRootsList covers the path-boundary comparison of step 3.
func TestShimRootsList(t *testing.T) {
	h := newShimHome(t) // no binary installed: every run fails
	sh := shell{"sh", []string{"/bin/sh"}}
	block := staticBlock("claude-code", "PreToolUse")
	check := func(name, dir string, env map[string]string, want shimRun) {
		t.Helper()
		if got := h.runShim(t, sh, dir, env, "{}", "claude-code", "PreToolUse"); got != want {
			t.Errorf("%s: %+v, want %+v", name, got, want)
		}
	}
	check("below the root", filepath.Join(h.root, "sub"), nil, block)
	check("a sibling sharing the prefix", h.outside, nil, shimRun{})
	check("PWD with a trailing slash", h.root, map[string]string{"PWD": h.root + "/"}, block)
	check("no PWD, no project dir", h.outside, map[string]string{"PWD": "\x00unset"}, shimRun{})
	if macOS() {
		check("case-folded on macOS", h.root, map[string]string{"PWD": strings.ToUpper(h.root)}, block)
	}
	// A roots.list line with a trailing slash still matches.
	if err := os.WriteFile(filepath.Join(h.base, "roots.list"), []byte(h.root+"/"), 0o600); err != nil {
		t.Fatal(err)
	}
	check("root line with a trailing slash and no newline", filepath.Join(h.root, "sub"), nil, block)
	// No roots.list: nothing is protected.
	if err := os.Remove(filepath.Join(h.base, "roots.list")); err != nil {
		t.Fatal(err)
	}
	check("no roots.list", h.root, nil, shimRun{})
	// No usable HOME: no base, nothing is protected, no error printed.
	check("relative HOME", h.root, map[string]string{"HOME": "relative"}, shimRun{})
}

// TestShimExperimentalHosts: the static blocks of the Cursor and Copilot
// drafts, and an unknown label's universal exit 2.
func TestShimExperimentalHosts(t *testing.T) {
	h := newShimHome(t)
	sh := shell{"sh", []string{"/bin/sh"}}
	d := ui.Format(ui.MsgShimFailed, ui.Vars{})
	for _, c := range []struct {
		harness, event string
		want           shimRun
	}{
		{"cursor", "beforeSubmitPrompt", shimRun{stdout: `{"continue":false,"user_message":"` + d + `"}`}},
		{"cursor", "preToolUse", shimRun{stdout: `{"permission":"deny","user_message":"` + d + `","agent_message":"` + d + `"}`}},
		{"cursor", "beforeReadFile", shimRun{stdout: `{"permission":"deny","user_message":"` + d + `","agent_message":"` + d + `"}`}},
		{"cursor", "afterFileEdit", shimRun{}},
		{"copilot", "preToolUse", shimRun{stdout: `{"permissionDecision":"deny","permissionDecisionReason":"` + d + `"}`}},
		{"foo-agent", "UserPromptSubmit", shimRun{stdout: staticBlock("claude-code", "UserPromptSubmit").stdout}},
		{"foo-agent", "beforeSubmitPrompt", shimRun{stderr: d + "\n", exit: 2}},
	} {
		if got := h.runShim(t, sh, h.root, nil, "{}", c.harness, c.event); got != c.want {
			t.Errorf("%s %s: %+v, want %+v", c.harness, c.event, got, c.want)
		}
	}
}

// TestShimStaticOutputsMatchSchemas: the shim's static JSON decodes with the
// strict mirrors (Claude §2.4 shapes, Codex PreCompact schema).
func TestShimStaticOutputsMatchSchemas(t *testing.T) {
	for _, ev := range gateEvents {
		out := []byte(staticBlock("claude-code", ev).stdout)
		switch ev {
		case "UserPromptSubmit":
			var v claudePromptBlock
			strictDecode(t, out, &v)
		case "PreToolUse":
			var v claudeToolDeny
			strictDecode(t, out, &v)
		case "PermissionRequest":
			var v claudePermissionDeny
			strictDecode(t, out, &v)
		case "PreCompact":
			var v claudeCompactBlock
			strictDecode(t, out, &v)
		}
	}
	var v codexPreCompactOutput
	strictDecode(t, []byte(staticBlock("codex", "PreCompact").stdout), &v)
}

// TestShimSyntax: every shell parses the shim (sh -n), and shellcheck -s sh
// passes when shellcheck is installed (CI installs it).
func TestShimSyntax(t *testing.T) {
	shims := []string{
		filepath.Join(repo, "plugin", "scripts", "precinto-hook"),
		filepath.Join(repo, "plugins", "codex", "scripts", "precinto-hook"),
	}
	for _, shim := range shims {
		for _, sh := range shimShells(t) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			cmd := exec.CommandContext(ctx, sh.argv[0], append(append(sh.argv[1:], "-n"), shim)...)
			cmd.Env = []string{"PATH=/usr/bin:/bin"}
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Errorf("%s -n %s: %v\n%s", sh.name, shim, err, out)
			}
			cancel()
		}
	}
	sc, err := exec.LookPath("shellcheck")
	if err != nil {
		// CI installs shellcheck (.github/scripts/install-shells.sh): there
		// a missing one is a failure, never a skip (TESTPLAN §10).
		if inCI() {
			t.Fatal("shellcheck is required in CI (TESTPLAN §10) and is not installed")
		}
		t.Skip("shellcheck not installed (required in CI)")
	}
	for _, shim := range shims {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		cmd := exec.CommandContext(ctx, sc, "-s", "sh", shim)
		cmd.Env = []string{"PATH=/usr/bin:/bin"}
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Errorf("shellcheck -s sh %s: %v\n%s", shim, err, out)
		}
		cancel()
	}
}

// inCI reports whether the tests run in CI (GitHub Actions sets CI=true),
// where every tool a test needs is installed.
func inCI() bool {
	v := paths.FromOS().Get("CI")
	return v != "" && v != "0" && v != "false"
}
