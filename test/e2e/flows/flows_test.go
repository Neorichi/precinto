// Package flows_test holds G7's opt-in end-to-end flows (docs/TESTPLAN.md
// §9): a real `claude -p --plugin-dir ./plugin` (pinned version ≥ 2.1.295,
// --model haiku) runs inside a protected folder of a throwaway HOME whose
// <base>/bin/precinto links to the testing build, so the plugin's shim runs
// it (hooks never take a binary from the environment, D56). They run only
// with PRECINTO_E2E=1 (`make test-e2e`) and never in CI by default.
//
// The throwaway CLAUDE_CONFIG_DIR sets CLAUDE_SECURESTORAGE_CONFIG_DIR=""
// so the existing login keychain item is reused; no transcript of the user
// is read (TESTPLAN §2). Codex is never run here.
package flows_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/creack/pty"

	"github.com/precinto/precinto/internal/config"
	"github.com/precinto/precinto/internal/paths"
	"github.com/precinto/precinto/internal/testkit"
	"github.com/precinto/precinto/internal/ui"
)

const (
	e2ePassphrase = "end-to-end only passphrase 4 vaults"
	stepTimeout   = 5 * time.Minute
)

// e2e is one throwaway installation driving a real Claude Code.
type e2e struct {
	t      *testing.T
	h      *testkit.Home
	exe    string // testing build of precinto
	claude string // the real claude binary
	plugin string // <repo>/plugin
	env    paths.Env
}

// setup skips unless PRECINTO_E2E=1 and a real claude is installed, then
// builds the throwaway installation: fake HOME, <base>/bin/precinto link,
// init (passphrase factor), agent, protected folder.
func setup(t *testing.T) *e2e {
	t.Helper()
	host := paths.FromOS()
	if host.Get(paths.EnvE2E) != "1" {
		t.Skip("opt-in: set PRECINTO_E2E=1 (make test-e2e)")
	}
	// PRECINTO_E2E_CLAUDE (an absolute path) picks one of several installs
	// (TESTPLAN §2).
	claude := host.Get("PRECINTO_E2E_CLAUDE")
	if claude == "" {
		var err error
		if claude, err = paths.LookPath(host, "claude"); err != nil {
			t.Skip("claude is not installed")
		}
	} else if !filepath.IsAbs(claude) {
		t.Fatalf("PRECINTO_E2E_CLAUDE=%q: give an absolute path", claude)
	}
	t.Logf("claude: %s", claude)
	root := moduleRoot(t)
	plugin := filepath.Join(root, "plugin")
	if _, err := os.Stat(filepath.Join(plugin, "hooks", "hooks.json")); err != nil {
		t.Skip("plugin/ is not built yet")
	}
	h := testkit.NewHome(t)
	exe := testkit.BuildBinary(t)
	if err := os.MkdirAll(filepath.Dir(h.Layout.BinLink), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(exe, h.Layout.BinLink); err != nil {
		t.Fatal(err)
	}
	// The smallest stability window config.Validate accepts (D63).
	h.Cfg.Policy.QuietWindow = config.Duration(10 * time.Second)
	if err := config.Save(h.Layout.ConfigFile, h.Cfg); err != nil {
		t.Fatal(err)
	}
	env := h.Env.
		With("PATH", filepath.Dir(claude)+":"+h.Env.Get("PATH")).
		With("CLAUDE_SECURESTORAGE_CONFIG_DIR", "")
	if v := host.Get("TERM"); v != "" {
		env = env.With("TERM", v)
	}
	x := &e2e{t: t, h: h, exe: exe, claude: claude, plugin: plugin, env: env}
	x.init()
	x.startAgent()
	x.protect()
	return x
}

func moduleRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for d := wd; ; d = filepath.Dir(d) {
		if _, err := os.Stat(filepath.Join(d, "go.mod")); err == nil {
			return d
		}
		if filepath.Dir(d) == d {
			t.Fatal("go.mod not found")
		}
	}
}

// run runs precinto (no controlling terminal) and returns exit code and
// output.
func (x *e2e) run(dir string, args ...string) (int, string, string) {
	x.t.Helper()
	return x.runCmd(dir, x.exe, args...)
}

func (x *e2e) runCmd(dir, exe string, args ...string) (int, string, string) {
	x.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), stepTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe, args...)
	cmd.Env = x.env.Environ()
	cmd.Dir = dir
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	var so, se bytes.Buffer
	cmd.Stdout, cmd.Stderr = &so, &se
	cmd.WaitDelay = 10 * time.Second // a worker holding the pipes cannot stall Wait
	err := cmd.Run()
	code := 0
	if err != nil {
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			x.t.Fatalf("%s %v: %v", exe, args, err)
		}
		code = ee.ExitCode()
	}
	return code, so.String(), se.String()
}

// tty runs precinto on a pseudo-terminal and answers each prompt in turn.
func (x *e2e) tty(dir string, dialog [][2]string, args ...string) {
	x.t.Helper()
	cmd := exec.Command(x.exe, args...)
	cmd.Env = x.env.With("TERM", "xterm-256color").Environ()
	cmd.Dir = dir
	f, err := pty.StartWithSize(cmd, &pty.Winsize{Rows: 40, Cols: 120})
	if err != nil {
		x.t.Fatal(err)
	}
	defer f.Close()
	var mu sync.Mutex
	var out bytes.Buffer
	go func() { _, _ = io.Copy(lockedWriter{&mu, &out}, f) }()
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	seen := 0
	for _, step := range dialog {
		deadline := time.Now().Add(stepTimeout)
		for {
			mu.Lock()
			rest := out.String()[seen:]
			i := strings.Index(rest, step[0])
			if i >= 0 {
				seen += i + len(step[0])
			}
			mu.Unlock()
			if i >= 0 {
				break
			}
			if time.Now().After(deadline) {
				_ = cmd.Process.Kill() // started by this test
				x.t.Fatalf("%v: no %q in %q", args, step[0], out.String())
			}
			time.Sleep(20 * time.Millisecond)
		}
		if _, err := io.WriteString(f, step[1]); err != nil {
			x.t.Fatal(err)
		}
	}
	select {
	case err := <-done:
		if err != nil {
			x.t.Fatalf("%v: %v (%q)", args, err, out.String())
		}
	case <-time.After(stepTimeout):
		_ = cmd.Process.Kill()
		x.t.Fatalf("%v timed out", args)
	}
}

type lockedWriter struct {
	mu *sync.Mutex
	w  io.Writer
}

func (l lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

// The prompts the answerers wait for are the catalog's (CC-38, D70), never
// literal copies.
var (
	promptNewPassphrase   = ui.Format(ui.MsgPassphraseNew, ui.Vars{})
	promptAgainPassphrase = ui.Format(ui.MsgPassphraseAgain, ui.Vars{})
	promptService         = ui.Format(ui.MsgServiceOffer, ui.Vars{})
)

func (x *e2e) init() {
	dialog := [][2]string{
		{promptNewPassphrase, e2ePassphrase + "\r"},
		{promptAgainPassphrase, e2ePassphrase + "\r"},
	}
	if runtime.GOOS == "darwin" {
		dialog = append(dialog, [2]string{promptService, "n\r"})
	}
	x.tty(x.h.HomeDir, dialog, "init", "--factor", "passphrase", "--recovery-out", filepath.Join(x.h.Dir, "recovery.txt"))
}

func (x *e2e) startAgent() {
	cmd := exec.Command(x.exe, "agent", "--foreground")
	cmd.Env = x.env.Environ()
	cmd.Dir = "/"
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		x.t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	x.t.Cleanup(func() {
		_ = cmd.Process.Signal(syscall.SIGTERM) // started by this test
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			_ = cmd.Process.Kill()
			<-done
		}
	})
	for i := 0; i < 300; i++ {
		if _, err := os.Stat(x.h.Layout.Socket); err == nil {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	x.t.Fatal("agent did not start")
}

func (x *e2e) protect() {
	x.tty(x.h.HomeDir, [][2]string{{"passphrase", e2ePassphrase + "\r"}}, "protect", x.h.Root)
}

func (x *e2e) unlock() {
	x.tty(x.h.Root, [][2]string{{"passphrase", e2ePassphrase + "\r"}}, "unlock", "--root", x.h.Root)
}

// claudeJSON runs `precinto run -- claude -p PROMPT` (direct mode: gated,
// sealed after exit) and returns Claude's JSON result.
func (x *e2e) claudeJSON(prompt string, extra ...string) map[string]any {
	x.t.Helper()
	args := append([]string{"run", "--no-pty", "--", x.claude, "-p", prompt, "--model", "haiku",
		"--output-format", "json", "--plugin-dir", x.plugin}, extra...)
	code, out, errOut := x.run(x.h.Root, args...)
	if code != 0 {
		x.t.Fatalf("claude exit %d: %s", code, errOut)
	}
	var res map[string]any
	if err := json.Unmarshal([]byte(lastJSONLine(out)), &res); err != nil {
		x.t.Fatalf("claude output: %v (%q)", err, out)
	}
	return res
}

func lastJSONLine(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if strings.HasPrefix(strings.TrimSpace(lines[i]), "{") {
			return lines[i]
		}
	}
	return s
}

// transcripts lists the session transcripts in the throwaway config dir.
func (x *e2e) transcripts() []string {
	m, _ := filepath.Glob(filepath.Join(x.h.ClaudeConfig, "projects", "*", "*.jsonl"))
	return m
}

func (x *e2e) waitSealed() {
	x.t.Helper()
	for i := 0; i < 600; i++ {
		if len(x.transcripts()) == 0 {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	x.t.Fatalf("transcripts still in plaintext: %v", x.transcripts())
}

// E2E-3 (G6 + G7): a session is sealed after exit and when the folder
// locks; `precinto run claude --resume <sid>` restores it before launch and
// Claude continues with its full context.
func TestE2EResumeRestoresContext(t *testing.T) {
	x := setup(t)
	word := "violet" + strings.ReplaceAll(testkit.Marker(t)[len("precinto-marker-"):], "-", "")[:6]
	res := x.claudeJSON("Remember this code word: " + word + ". Reply only with OK.")
	sid, _ := res["session_id"].(string)
	if sid == "" {
		t.Fatalf("no session_id in %v", res)
	}
	if code, _, e := x.run(x.h.Root, "lock"); code != 0 {
		t.Fatalf("lock: %s", e)
	}
	if code, _, e := x.run(x.h.Root, "sweep", "--wait"); code != 0 {
		t.Fatalf("sweep: %s", e)
	}
	x.waitSealed()
	x.unlock()
	res = x.claudeJSON("What was the code word? Reply with the word only.", "--resume", sid)
	if got, _ := res["result"].(string); !strings.Contains(strings.ToLower(got), word) {
		t.Fatalf("resumed session lost its context: %q", got)
	}
}

// SEC-22 (G7): after a full run with markers in the prompt, the assistant
// output and the files, a final lock + sweep leaves no marker anywhere in
// plaintext: not in <base> (capsules excepted), logs, ledgers or the
// throwaway Claude home.
func TestE2EHygieneAfterFullRun(t *testing.T) {
	x := setup(t)
	marker := testkit.Marker(t)
	note := filepath.Join(x.h.Root, "notes", "e2e.md")
	x.claudeJSON("Create the file notes/e2e.md containing exactly the text " + marker + ", then reply with " + marker + ".")
	if b, err := os.ReadFile(note); err != nil || !strings.Contains(string(b), marker) {
		t.Logf("note not written by the model (%v); the transcript still carries the marker", err)
	}
	if code, _, e := x.run(x.h.Root, "lock"); code != 0 {
		t.Fatalf("lock: %s", e)
	}
	if code, _, e := x.run(x.h.Root, "sweep", "--wait"); code != 0 {
		t.Fatalf("sweep: %s", e)
	}
	x.waitSealed()
	// history.jsonl keeps the prompt line until a rotation, which runs only
	// while no Claude process runs anywhere on the machine (SPEC §7.1.4,
	// §19): a documented residual that status reports as history-pending.
	if hits := testkit.GrepTree(t, x.h.Dir, marker, "capsules", "history.jsonl"); len(hits) > 0 {
		t.Fatalf("marker in plaintext after lock + sweep (I7, S13): %v", hits)
	}
	code, out, _ := x.run(x.h.Root, "status", "--json")
	if code != 0 {
		t.Fatalf("status: exit %d", code)
	}
	if b, err := os.ReadFile(filepath.Join(x.h.ClaudeConfig, "history.jsonl")); err == nil && strings.Contains(string(b), marker) &&
		!strings.Contains(out, `"history-pending"`) {
		t.Fatalf("history line pending without a history-pending attention item:\n%s", out)
	}
}
