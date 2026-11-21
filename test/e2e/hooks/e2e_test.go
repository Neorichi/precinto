//go:build testing

// Package hooks_test holds the opt-in end-to-end tests of precinto's hooks
// and plugins against real harnesses (docs/TESTPLAN.md §9: E2E-1, E2E-2,
// E2E-8, E2E-9, HOOK-5, SEC-13, SEC-17). They run only with
// PRECINTO_E2E=1 (`make test-e2e`), and always in a throwaway HOME: a
// short temporary directory holding precinto's base (whose bin/precinto
// links to the -tags testing build), a throwaway CLAUDE_CONFIG_DIR and a
// synthetic CODEX_HOME. Following TESTPLAN §2, CLAUDE_SECURESTORAGE_CONFIG_DIR
// is set empty so that Claude reuses its login item and reads no
// transcript of the user; the model is haiku. Hooks never take a binary
// from the environment (D56): the shim finds the testing build through the
// throwaway HOME.
package hooks_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/creack/pty"

	"github.com/precinto/precinto/internal/config"
	"github.com/precinto/precinto/internal/paths"
	"github.com/precinto/precinto/internal/platform"
	"github.com/precinto/precinto/internal/testkit"
	"github.com/precinto/precinto/internal/ui"
)

// repoRoot is the repository root seen from test/e2e/hooks.
const repoRoot = "../../.."

// e2ePassphrase is the passphrase factor of throwaway vaults.
const e2ePassphrase = "e2e passphrase for a throwaway vault only"

// requireE2E skips unless the opt-in E2E run was asked for.
func requireE2E(t *testing.T) {
	t.Helper()
	if os.Getenv("PRECINTO_E2E") != "1" {
		t.Skip("opt-in: set PRECINTO_E2E=1 (runs real harnesses in throwaway homes)")
	}
}

// sandbox is a throwaway HOME for one test.
type sandbox struct {
	t       *testing.T
	home    string // HOME (short: the hook-mode socket lives below it)
	base    string // precinto's default base for this HOME
	runDir  string // its run directory (linux: XDG_RUNTIME_DIR/precinto)
	root    string // protected folder
	outside string // a folder outside it
	fakeBin string // the only directory on PATH besides /usr/bin:/bin
	bin     string // the -tags testing build
	env     []string
	agent   *exec.Cmd
	model   *bool // whether claude -p reaches the model from this HOME (modelReachable)
}

// harnessPath finds a harness for the sandbox: PRECINTO_E2E_<NAME> (an
// absolute path, for example PRECINTO_E2E_CLAUDE=$HOME/.local/bin/claude)
// first, else the runner's PATH. A machine can carry several installs of
// one harness (a native one and an old npm one), so newSandbox logs the
// binary and the version every run tests.
func harnessPath(t *testing.T, name string) (string, bool) {
	t.Helper()
	if p := os.Getenv("PRECINTO_E2E_" + strings.ToUpper(name)); p != "" {
		if !filepath.IsAbs(p) {
			t.Fatalf("PRECINTO_E2E_%s=%q: give an absolute path", strings.ToUpper(name), p)
		}
		return p, true
	}
	p, err := exec.LookPath(name) // the runner's PATH, only to find the harness
	return p, err == nil
}

// newSandbox creates the throwaway HOME and links <base>/bin/precinto to the
// testing build. The real harness executables are reached through symlinks
// in fakeBin, so nothing else of the user's PATH is visible.
func newSandbox(t *testing.T, harnesses ...string) *sandbox {
	t.Helper()
	requireE2E(t)
	for _, p := range []string{"/opt/homebrew/bin/precinto", "/usr/local/bin/precinto", "/usr/bin/precinto"} {
		if _, err := os.Lstat(p); err == nil {
			t.Skipf("%s is installed: the shim could reach it", p)
		}
	}
	s := &sandbox{t: t, home: testkit.ShortTempDir(t)}
	// Harnesses report their working directory resolved (/tmp is a symlink
	// on macOS) and precinto records roots realpath'd at protect time, so
	// the sandbox resolves its HOME too, or its folder would never match.
	real, err := filepath.EvalSymlinks(s.home)
	if err != nil {
		t.Fatal(err)
	}
	s.home = real
	if runtime.GOOS == "darwin" {
		s.base = filepath.Join(s.home, "Library", "Application Support", "precinto")
		s.runDir = filepath.Join(s.base, "run")
	} else {
		s.base = filepath.Join(s.home, "xdg", "data", "precinto")
		s.runDir = filepath.Join(s.home, "xr", "precinto")
	}
	s.root = filepath.Join(s.home, "work", "acme")
	s.outside = filepath.Join(s.home, "play")
	s.fakeBin = filepath.Join(s.home, "fakebin")
	for _, d := range []string{filepath.Join(s.base, "bin"), s.root, s.outside, s.fakeBin, filepath.Join(s.home, "claude"), filepath.Join(s.home, "tmp")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	s.bin = testkit.BuildBinary(t, "testing")
	if err := os.Symlink(s.bin, filepath.Join(s.base, "bin", "precinto")); err != nil {
		t.Fatal(err)
	}
	for _, h := range append(harnesses, "node") {
		real, ok := harnessPath(t, h)
		if !ok {
			if h == "node" {
				continue
			}
			t.Skipf("%s is not installed", h)
		}
		if err := os.Symlink(real, filepath.Join(s.fakeBin, h)); err != nil {
			t.Fatal(err)
		}
	}
	s.env = []string{
		"HOME=" + s.home,
		"PATH=" + s.fakeBin + ":/usr/bin:/bin",
		"TMPDIR=" + filepath.Join(s.home, "tmp"),
		"LANG=en_US.UTF-8",
		"TERM=dumb",
		"CLAUDE_CONFIG_DIR=" + filepath.Join(s.home, "claude"),
		"CLAUDE_SECURESTORAGE_CONFIG_DIR=",
		"CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1",
		// D64: the testing build's agent-context walk ends at this test,
		// so the suite can init and unlock when it runs inside an agent
		// session; hook mode and the shim ignore it (SEC-31, SEC-33).
		paths.EnvTestAncestryStop + "=" + platform.Self().String(),
	}
	if runtime.GOOS != "darwin" {
		s.env = append(s.env, "XDG_DATA_HOME="+filepath.Join(s.home, "xdg", "data"), "XDG_RUNTIME_DIR="+filepath.Dir(s.runDir))
	}
	for _, k := range []string{"ANTHROPIC_API_KEY", "OPENAI_API_KEY"} {
		if v, ok := os.LookupEnv(k); ok {
			s.env = append(s.env, k+"="+v)
		}
	}
	s.writeConfig()
	t.Cleanup(s.stopAgent)
	for _, h := range harnesses {
		link := filepath.Join(s.fakeBin, h)
		target, _ := filepath.EvalSymlinks(link)
		out, _ := s.run(s.home, time.Minute, nil, link, "--version")
		version, _, _ := strings.Cut(strings.TrimSpace(out), "\n")
		t.Logf("%s: %s (%s)", h, version, target)
	}
	return s
}

// loginError reports whether a claude -p result is Claude's own refusal to
// start a turn without credentials.
func loginError(result string) bool {
	for _, m := range []string{"Invalid API key", "Please run /login", "Not logged in"} {
		if strings.Contains(result, m) {
			return true
		}
	}
	return false
}

// modelReachable reports whether claude -p reaches the model from the
// sandbox. A throwaway HOME can hide Claude's login (on macOS the keychain
// item is found through the real HOME); every prompt that passes precinto's
// gates then ends with Claude's login error before any model call. The
// gates themselves run before the model, so they are checked either way;
// only the checks that need the model's answer are skipped. Set
// ANTHROPIC_API_KEY to run those too.
func (s *sandbox) modelReachable() bool {
	s.t.Helper()
	if s.model != nil {
		return *s.model
	}
	out, _ := s.claude(s.outside, pluginDir(s.t), "Reply with the single word OK.")
	r := parseClaude(out)
	ok := !(r.IsError && loginError(r.Result))
	s.model = &ok
	if !ok {
		s.t.Logf("claude reaches no model from the throwaway HOME (%q): checks that need its answer are skipped; set ANTHROPIC_API_KEY to run them", r.Result)
	}
	return ok
}

// passedGates reports whether a claude -p run got past every precinto gate:
// a turn started (the model answered, or Claude stopped at its own login
// error when modelReachable is false) and no hook blocked the prompt.
func passedGates(r claudeResult) bool {
	return r.NumTurns > 0 && !strings.Contains(r.Result, "blocked by hook")
}

// awaitIdle waits, at most within, until precinto's seal queue and journal
// are empty (the detached workers finished, SPEC §9), and returns the files
// left below state/ relative to it.
func (s *sandbox) awaitIdle(within time.Duration) []string {
	s.t.Helper()
	state := filepath.Join(s.base, "state")
	deadline := time.Now().Add(within)
	for {
		busy := false
		for _, d := range []string{"queue", "journal"} {
			if entries, _ := os.ReadDir(filepath.Join(state, d)); len(entries) > 0 {
				busy = true
			}
		}
		if !busy || time.Now().After(deadline) {
			var left []string
			_ = filepath.WalkDir(state, func(p string, e os.DirEntry, err error) error {
				if err == nil && !e.IsDir() {
					rel, _ := filepath.Rel(state, p)
					left = append(left, rel)
				}
				return nil
			})
			if busy {
				s.t.Errorf("precinto's queue or journal is still busy after %v: %v", within, left)
			}
			return left
		}
		time.Sleep(time.Second)
	}
}

// awaitSealed waits until marker is in no file below s.home outside
// precinto's capsules: what Claude wrote of a session (its transcript holds
// even a blocked prompt, SPEC §19) is sealed once the session ended.
func (s *sandbox) awaitSealed(marker string, within time.Duration) {
	s.t.Helper()
	deadline := time.Now().Add(within)
	for {
		hits := testkit.GrepTree(s.t, s.home, marker, "capsules")
		if len(hits) == 0 {
			return
		}
		if time.Now().After(deadline) {
			s.t.Fatalf("plaintext with the marker remains after the session ended: %v", hits)
		}
		time.Sleep(2 * time.Second)
	}
}

// writeConfig protects s.root the way `precinto protect` records it.
func (s *sandbox) writeConfig() { s.writeConfigWith(nil) }

// writeConfigWith writes the configuration of writeConfig changed by edit.
// Before the first vault exists the daemon pins the strictest of it and
// the defaults (D68), so a test may only make the policy stricter here.
func (s *sandbox) writeConfigWith(edit func(*config.Config)) {
	s.t.Helper()
	cfg := config.Default()
	cfg.Roots = []config.Root{{ID: "root-acme", Path: s.root, MD: config.MDLedger, Harnesses: []string{"claude-code", "codex"}, ProtectedAt: time.Now().UTC()}}
	if edit != nil {
		edit(&cfg)
	}
	if err := config.Save(filepath.Join(s.base, "config.toml"), cfg); err != nil {
		s.t.Fatal(err)
	}
	if err := config.WriteRootsList(filepath.Join(s.base, "roots.list"), cfg); err != nil {
		s.t.Fatal(err)
	}
}

// run executes argv in dir with the sandbox environment (plus extra), no
// controlling terminal, a timeout, and returns combined output and the exit
// code.
func (s *sandbox) run(dir string, timeout time.Duration, extra []string, argv ...string) (string, int) {
	s.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Dir = dir
	cmd.Env = append(append([]string(nil), s.env...), extra...)
	cmd.Stdin = strings.NewReader("")
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	cmd.WaitDelay = 10 * time.Second // a straggler holding the output pipe cannot stall Wait
	err := cmd.Run()
	code := 0
	var ee *exec.ExitError
	switch {
	case errors.As(err, &ee):
		code = ee.ExitCode()
	case err != nil:
		s.t.Fatalf("%v: %v\n%s", argv, err, out.String())
	}
	return out.String(), code
}

// claude runs `claude -p` with precinto's plugin directory (or another one)
// in dir and returns its output and exit code.
func (s *sandbox) claude(dir, pluginDir, prompt string, args ...string) (string, int) {
	s.t.Helper()
	argv := append([]string{filepath.Join(s.fakeBin, "claude"), "-p", "--model", "haiku", "--plugin-dir", pluginDir, "--output-format", "json"}, args...)
	return s.run(dir, 5*time.Minute, nil, append(argv, prompt)...)
}

// startAgent runs the testing build's daemon in the foreground (as the
// test's own child) and waits for its socket.
func (s *sandbox) startAgent() {
	s.t.Helper()
	cmd := exec.Command(s.bin, "agent", "--foreground")
	cmd.Dir = "/"
	cmd.Env = append([]string(nil), s.env...)
	log, err := os.Create(filepath.Join(s.home, "agent.log"))
	if err != nil {
		s.t.Fatal(err)
	}
	cmd.Stdout, cmd.Stderr = log, log
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		s.t.Fatal(err)
	}
	s.agent = cmd
	sock := filepath.Join(s.runDir, "agent.sock")
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(sock); err == nil {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	s.t.Fatalf("the agent did not listen on %s", sock)
}

// stopAgent stops the daemon this test started (and nothing else).
func (s *sandbox) stopAgent() {
	if s.agent == nil || s.agent.Process == nil {
		return
	}
	_ = s.agent.Process.Signal(syscall.SIGTERM)
	done := make(chan struct{})
	go func() { _ = s.agent.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		_ = s.agent.Process.Kill()
		<-done
	}
	s.agent = nil
}

// ptySession is one process of the test on a pseudo-terminal of its own
// (pty.Start: a new session with the terminal as its controlling one).
// Closing the master hangs the session up, and the test's cleanup kills
// that process group and reaps it, so nothing outlives the test.
type ptySession struct {
	t      *testing.T
	cmd    *exec.Cmd
	master *os.File

	mu   sync.Mutex
	out  bytes.Buffer
	done chan struct{}
	err  error // the exit, once done is closed
}

// pty starts argv in dir with the sandbox environment on a pseudo-terminal.
func (s *sandbox) pty(dir string, argv ...string) *ptySession {
	s.t.Helper()
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Dir = dir
	cmd.Env = append([]string(nil), s.env...)
	f, err := pty.StartWithSize(cmd, &pty.Winsize{Rows: 50, Cols: 160})
	if err != nil {
		s.t.Fatal(err)
	}
	p := &ptySession{t: s.t, cmd: cmd, master: f, done: make(chan struct{})}
	go func() {
		buf := make([]byte, 32<<10)
		for {
			n, err := f.Read(buf)
			if n > 0 {
				p.mu.Lock()
				p.out.Write(buf[:n])
				p.mu.Unlock()
			}
			if err != nil {
				return
			}
		}
	}()
	go func() {
		p.err = cmd.Wait()
		close(p.done)
	}()
	s.t.Cleanup(func() {
		select {
		case <-p.done:
		default:
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) // the session pty.Start created
			<-p.done
		}
		_ = f.Close()
	})
	return p
}

func (p *ptySession) text() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.out.String()
}

func (p *ptySession) send(keys string) {
	p.t.Helper()
	if _, err := io.WriteString(p.master, keys); err != nil {
		p.t.Fatalf("type into the terminal: %v", err)
	}
}

// expect waits up to timeout for sub after offset from and returns the
// offset just past it.
func (p *ptySession) expect(sub string, from int, timeout time.Duration) int {
	p.t.Helper()
	end := time.Now().Add(timeout)
	for {
		if i := strings.Index(p.text()[from:], sub); i >= 0 {
			return from + i + len(sub)
		}
		select {
		case <-p.done:
			if i := strings.Index(p.text()[from:], sub); i >= 0 {
				return from + i + len(sub)
			}
			p.t.Fatalf("%v exited (%v) before %q:\n%s", p.cmd.Args, p.err, sub, tail(p.text()[from:]))
		case <-time.After(50 * time.Millisecond):
		}
		if time.Now().After(end) {
			p.t.Fatalf("%v: no %q within %v:\n%s", p.cmd.Args, sub, timeout, tail(p.text()[from:]))
		}
	}
}

func tail(s string) string {
	if len(s) > 4000 {
		return s[len(s)-4000:]
	}
	return s
}

// question is one prompt of the CLI the answerer recognises by its exact
// catalog text (CC-38, D70: every prompt a test waits for is a catalog
// message): re matches the text ui.Format renders, with the placeholders
// a test cannot know as wildcards; reply is typed after it, followed by
// Enter; policy questions are answered by answerOptions.acceptPolicy; a
// question with fail set ends the test instead (the run went wrong and
// would only loop or hang).
type question struct {
	re     *regexp.Regexp
	reply  string
	policy bool
	fail   string
}

// catalog matches ui.Format(id, v) as printed, every occurrence of the
// sentinels in wild (values put into v for placeholders the test cannot
// know) matching any text of one line.
func catalog(id ui.MsgID, v ui.Vars, wild ...string) *regexp.Regexp {
	q := regexp.QuoteMeta(ui.Format(id, v))
	for _, w := range wild {
		q = strings.ReplaceAll(q, regexp.QuoteMeta(w), `[^\r\n]*?`)
	}
	return regexp.MustCompile(q)
}

// answerOptions changes how the answerer replies.
type answerOptions struct {
	// acceptPolicy confirms the weakening config.toml changes that unlock
	// lists after C13.policy (D48); otherwise they are declined.
	acceptPolicy bool
}

// questions are the prompts init, protect and unlock can show in a
// sandbox, with its folder as the CLI and the daemon render it there.
func questions() []question {
	folder := "~/work/acme"
	const n = 987654 // the {n} the test cannot know
	return []question{
		{re: catalog(ui.MsgPassphraseNew, ui.Vars{}), reply: e2ePassphrase},
		{re: catalog(ui.MsgPassphraseAgain, ui.Vars{}), reply: e2ePassphrase},
		// The daemon relays the passphrase factor's prompt as C2.passphrase
		// for the folder (agent unlock.go isPassphrasePrompt).
		{re: catalog(ui.MsgUnlockPassphrase, ui.Vars{Folder: folder}), reply: e2ePassphrase},
		{re: catalog(ui.MsgCodexConsent, ui.Vars{Folder: folder}), reply: "y"},
		// A test never installs a LaunchAgent: it would load into the
		// user's own launchd session.
		{re: catalog(ui.MsgServiceOffer, ui.Vars{}), reply: "n"},
		{re: catalog(ui.MsgInitRemote, ui.Vars{}), reply: "n"},
		{re: catalog(ui.MsgPassphraseWeak, ui.Vars{}), fail: "the sandbox passphrase was refused as weak"},
		{re: catalog(ui.MsgPassphraseDiff, ui.Vars{}), fail: "the passphrase was not read the same twice"},
		{re: catalog(ui.MsgRecoveryAgain, ui.Vars{}), fail: "init showed the recovery key although --recovery-out was given"},
		{re: catalog(ui.MsgRecoveryLost, ui.Vars{}), fail: "init lost the recovery key"},
		{re: catalog(ui.MsgUnlockBadSecret, ui.Vars{Folder: folder}), fail: "the daemon refused the sandbox passphrase"},
		{re: catalog(ui.MsgUnlockCancelled, ui.Vars{Folder: folder}), fail: "the unlock was cancelled"},
		{re: catalog(ui.MsgInitRefuseAgent, ui.Vars{}), fail: "init refused an agent context (is PRECINTO_TEST_ANCESTRY_STOP honoured?)"},
		{re: catalog(ui.MsgRefuseAgent, ui.Vars{Action: "\x00a", Folder: "\x00f", Command: "\x00c"}, "\x00a", "\x00f", "\x00c"), fail: "refused as an agent context"},
		{re: catalog(ui.MsgNeedTerminal, ui.Vars{Command: "\x00c"}, "\x00c"), fail: "the command saw no terminal"},
		// unlock lists pending weakening edits (C13.policy, with {n} the
		// test cannot know) and then asks whether to confirm them
		// (C13.confirm).
		{re: regexp.MustCompile(catalog(ui.MsgPolicyPending, ui.Vars{N: n}, "987654").String() + `[\s\S]*?` + catalog(ui.MsgPolicyConfirm, ui.Vars{}).String()), policy: true},
	}
}

// answerer drives a CLI that needs a terminal (init, protect, unlock) on a
// pseudo-terminal, answering each catalog prompt it shows (questions) as
// it appears, and returns the output. It fails the test when the command
// fails, shows a prompt that means the run went wrong, or does not finish
// within timeout.
func (s *sandbox) answerer(dir string, timeout time.Duration, argv ...string) string {
	s.t.Helper()
	return s.answer(answerOptions{}, dir, timeout, argv...)
}

func (s *sandbox) answer(o answerOptions, dir string, timeout time.Duration, argv ...string) string {
	s.t.Helper()
	p := s.pty(dir, argv...)
	qs := questions()
	answered := 0
	end := time.Now().Add(timeout)
	for time.Now().Before(end) {
		fresh := p.text()[answered:]
		first, at, to := -1, len(fresh), 0
		for i, q := range qs {
			if loc := q.re.FindStringIndex(fresh); loc != nil && loc[0] < at {
				first, at, to = i, loc[0], loc[1]
			}
		}
		if first >= 0 {
			q := qs[first]
			if q.fail != "" {
				_ = syscall.Kill(-p.cmd.Process.Pid, syscall.SIGKILL)
				s.t.Fatalf("%v: %s:\n%s", argv, q.fail, tail(p.text()))
			}
			reply := q.reply
			if q.policy {
				reply = "n"
				if o.acceptPolicy {
					reply = "y"
				}
			}
			time.Sleep(100 * time.Millisecond) // the prompt's read has started
			p.send(reply + "\r")
			answered += to
			continue
		}
		select {
		case <-p.done:
			// Read what the process printed last before deciding.
			time.Sleep(100 * time.Millisecond)
			if p.err != nil {
				s.t.Fatalf("%v: %v\n%s", argv, p.err, tail(p.text()))
			}
			return p.text()
		case <-time.After(50 * time.Millisecond):
		}
	}
	_ = syscall.Kill(-p.cmd.Process.Pid, syscall.SIGKILL)
	s.t.Fatalf("%v did not finish within %v:\n%s", argv, timeout, tail(p.text()))
	return ""
}

// initVault creates a passphrase-only vault, protects s.root through the
// CLI and leaves the folder locked (the daemon is running).
func (s *sandbox) initVault() {
	s.t.Helper()
	s.startAgent()
	s.answerer(s.home, 2*time.Minute, s.bin, "init", "--factor", "passphrase", "--recovery-out", filepath.Join(s.home, "recovery.txt"))
	s.answerer(s.home, 2*time.Minute, s.bin, "protect", s.root)
	if out, code := s.run(s.home, time.Minute, nil, s.bin, "lock"); code != 0 {
		s.t.Fatalf("precinto lock: %d\n%s", code, out)
	}
}

// claudeResult is the JSON of `claude -p --output-format json`.
type claudeResult struct {
	SessionID string `json:"session_id"`
	Result    string `json:"result"`
	IsError   bool   `json:"is_error"`
	NumTurns  int    `json:"num_turns"`
}

func parseClaude(out string) claudeResult {
	var r claudeResult
	if i := strings.Index(out, "{"); i >= 0 {
		_ = json.Unmarshal([]byte(out[i:]), &r)
	}
	return r
}

// leakCheck fails if the marker is anywhere in precinto's base outside the
// capsules (I7, SEC-17, SEC-22).
func (s *sandbox) leakCheck(marker string) {
	s.t.Helper()
	if hits := testkit.GrepTree(s.t, s.base, marker, "capsules"); len(hits) > 0 {
		s.t.Errorf("marker in precinto's state: %v", hits)
	}
}
