//go:build darwin || linux

// Package wrappere2e holds the opt-in end-to-end tests of `precinto run`
// (docs/TESTPLAN.md §9: E2E-3, E2E-4, E2E-5 wrapped part, E2E-6 wrapper
// part, E2E-7). They run only with PRECINTO_E2E=1 (make test-e2e), drive a
// testing build of precinto on pseudo-terminals inside a testkit fake HOME,
// and never touch the user's data: a real claude runs with a throwaway
// CLAUDE_CONFIG_DIR and CLAUDE_SECURESTORAGE_CONFIG_DIR="" (TESTPLAN §2),
// Codex only ever sees synthetic homes.
package wrappere2e

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/creack/pty"

	"github.com/precinto/precinto/internal/harness/claude/claudetest"
	"github.com/precinto/precinto/internal/paths"
	"github.com/precinto/precinto/internal/platform"
	"github.com/precinto/precinto/internal/testkit"
	"github.com/precinto/precinto/internal/ui"
)

const (
	e2eTimeout = 90 * time.Second
	passphrase = "e2e-synthetic-passphrase-0001" // a throwaway vault's factor
	// helperLife bounds the synthetic Codex TUI and the job-control shell
	// (their -max-life): longer than any E2E scenario.
	helperLife = "15m"
)

var startEnv = paths.FromOS()

// e2eToken is carried in the argv of the helper programs these tests start
// (the synthetic Codex TUI, the job-control shell), so the ones left when
// the package ends are its own (TESTPLAN §1 rule 8).
var e2eToken string

func TestMain(m *testing.M) {
	var b [16]byte
	_, _ = rand.Read(b[:]) // never fails (Go ≥ 1.24)
	e2eToken = "precinto-wrapper-e2e-" + hex.EncodeToString(b[:])
	code := m.Run()
	if left := sweepToken(e2eToken, 3*time.Second); left > 0 {
		fmt.Fprintf(os.Stderr, "FAIL: %d helper process(es) outlived their test and were killed\n", left)
		if code == 0 {
			code = 1
		}
	}
	testkit.RemoveBinaries() // nothing left in TMPDIR (TESTPLAN §1.8)
	os.Exit(code)
}

// sweepToken gives the processes whose argv carries token up to grace to
// exit, then SIGKILLs (ProcID-verified) those left and returns how many
// there were.
func sweepToken(token string, grace time.Duration) int {
	deadline := time.Now().Add(grace)
	for {
		all, err := platform.System().List()
		if err != nil {
			return 0
		}
		var left []platform.ProcInfo
		for _, p := range all {
			if p.ID.PID == os.Getpid() || p.State == platform.StateZombie {
				continue
			}
			for _, a := range p.Argv {
				if strings.Contains(a, token) {
					left = append(left, p)
					break
				}
			}
		}
		if len(left) == 0 || time.Now().After(deadline) {
			for _, p := range left {
				_ = platform.Signal(p.ID, syscall.SIGKILL)
			}
			return len(left)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func requireE2E(t *testing.T) {
	t.Helper()
	if startEnv.Get(paths.EnvE2E) != "1" {
		t.Skip("opt-in: set PRECINTO_E2E=1 (make test-e2e)")
	}
}

// world is one fake HOME with a testing build of precinto, an initialised
// vault and the fixture folder protected.
type world struct {
	t    *testing.T
	h    *testkit.Home
	bin  string
	path string // PATH of every process: fake harnesses first, then system dirs
	env  map[string]string
}

func newWorld(t *testing.T, extraPath ...string) *world {
	t.Helper()
	requireE2E(t)
	h := testkit.NewHome(t)
	w := &world{t: t, h: h, bin: testkit.BuildBinary(t, "testing"), env: map[string]string{}}
	w.path = strings.Join(append(extraPath, "/usr/bin:/bin:/usr/sbin:/sbin"), ":")
	w.env["TERM"] = "xterm-256color"
	w.env["CLAUDE_SECURESTORAGE_CONFIG_DIR"] = ""
	w.setup()
	return w
}

func (w *world) environ() []string {
	e := w.h.Env.With("PATH", w.path)
	for k, v := range w.env {
		e = e.With(k, v)
	}
	return e.Environ()
}

// folder is the fixture folder as precinto names it ({folder}).
func (w *world) folder() string { return paths.Tilde(w.h.HomeDir, w.h.Root) }

// setup initialises the vault with a passphrase factor (recovery key to a
// file, so no screen to type back) and protects the fixture folder,
// answering the CLI's questions on a terminal.
func (w *world) setup() {
	w.t.Helper()
	rec := filepath.Join(w.h.Dir, "recovery.txt")
	s := w.start("init", "--factor", "passphrase", "--recovery-out", rec)
	s.answer(w.initRules()...)
	if code := s.wait(); code != 0 {
		w.t.Fatalf("precinto init: exit %d\n%s", code, s.text())
	}
	p := w.start("protect", w.h.Root)
	p.answer(w.cliRules()...)
	p.wait() // the fake home lists the folder already; an "already protected" exit is fine
	st := w.start("status")
	if code := st.wait(); code != 0 && code != 3 {
		w.t.Fatalf("precinto status: exit %d\n%s", code, st.text())
	}
}

// session is one process on its own pseudo-terminal.
type session struct {
	t      *testing.T
	cmd    *exec.Cmd
	master *os.File

	mu   sync.Mutex
	out  bytes.Buffer
	done chan struct{}
	code int
}

func (w *world) start(args ...string) *session {
	w.t.Helper()
	return w.startIn(w.h.Root, append([]string{w.bin}, args...)...)
}

func (w *world) startIn(dir string, argv ...string) *session {
	w.t.Helper()
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Env = w.environ()
	cmd.Dir = dir
	master, err := pty.StartWithSize(cmd, &pty.Winsize{Rows: 40, Cols: 120})
	if err != nil {
		w.t.Fatal(err)
	}
	s := &session{t: w.t, cmd: cmd, master: master, done: make(chan struct{})}
	go func() {
		buf := make([]byte, 64<<10)
		for {
			n, err := master.Read(buf)
			if n > 0 {
				s.mu.Lock()
				s.out.Write(buf[:n])
				s.mu.Unlock()
			}
			if err != nil {
				return
			}
		}
	}()
	go func() {
		_ = cmd.Wait()
		s.code = cmd.ProcessState.ExitCode()
		if ws, ok := cmd.ProcessState.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
			s.code = 128 + int(ws.Signal())
		}
		close(s.done)
	}()
	w.t.Cleanup(func() {
		select {
		case <-s.done:
		default:
			_ = cmd.Process.Kill()
			<-s.done
		}
		_ = master.Close()
	})
	return s
}

func (s *session) text() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.out.String()
}

func (s *session) mark() int { return len(s.text()) }

func (s *session) since(m int) string {
	t := s.text()
	if m > len(t) {
		return ""
	}
	return t[m:]
}

func (s *session) send(text string) {
	s.t.Helper()
	if _, err := s.master.Write([]byte(text)); err != nil {
		s.t.Fatal(err)
	}
}

func (s *session) expect(sub string, from int) int {
	s.t.Helper()
	deadline := time.Now().Add(e2eTimeout)
	for time.Now().Before(deadline) {
		if i := strings.Index(s.since(from), sub); i >= 0 {
			return from + i + len(sub)
		}
		select {
		case <-s.done:
			if i := strings.Index(s.since(from), sub); i >= 0 {
				return from + i + len(sub)
			}
			s.t.Fatalf("process exited (%d) before %q:\n%q", s.code, sub, tail(s.since(from)))
		case <-time.After(20 * time.Millisecond):
		}
	}
	s.t.Fatalf("timed out waiting for %q:\n%q", sub, tail(s.since(from)))
	return 0
}

func (s *session) wait() int {
	s.t.Helper()
	select {
	case <-s.done:
		return s.code
	case <-time.After(e2eTimeout):
		s.t.Fatalf("process did not exit:\n%q", tail(s.text()))
		return -1
	}
}

// rule answers a prompt: when the prompt shows up in new output, reply is
// typed. Every prompt is matched by its exact catalog text, ui.Format of
// the message id (CC-38, D70: B.*, C2.passphrase, C9.*, C10.consent,
// C13.confirm), never by a literal or a pattern of its wording.
type rule struct {
	text  string
	reply string
}

func (r rule) matches(s string) bool { return strings.Contains(s, r.text) }

func say(id ui.MsgID, v ui.Vars, reply string) rule {
	return rule{text: ui.Format(id, v), reply: reply}
}

// initRules answer precinto init: the new passphrase twice, no background
// service (B.service would install a LaunchAgent) and no second factor in
// a remote terminal (B.remote: the factor is a passphrase already).
func (w *world) initRules() []rule {
	return []rule{
		say(ui.MsgPassphraseNew, ui.Vars{}, passphrase+"\r"),
		say(ui.MsgPassphraseAgain, ui.Vars{}, passphrase+"\r"),
		say(ui.MsgServiceOffer, ui.Vars{}, "n\r"),
		say(ui.MsgInitRemote, ui.Vars{}, "n\r"),
	}
}

// cliRules answer the unlock prompt of the fixture folder (C2.passphrase),
// protect's Codex question (C10.consent) and keep pending policy edits
// pending (C13.confirm, its default).
func (w *world) cliRules() []rule {
	return []rule{
		say(ui.MsgUnlockPassphrase, ui.Vars{Folder: w.folder()}, passphrase+"\r"),
		say(ui.MsgCodexConsent, ui.Vars{Folder: w.folder()}, "y\r"),
		say(ui.MsgPolicyConfirm, ui.Vars{}, "n\r"),
	}
}

// launchRules are cliRules plus yes to precinto run's own questions before
// a launch (C9.codex and its variants for a home without precinto's plugin
// or with stale trust, D98/D99; C9.bare).
func (w *world) launchRules() []rule {
	return append([]rule{
		say(ui.MsgCodexUntrusted, ui.Vars{}, "y\r"),
		say(ui.MsgCodexNoPlugin, ui.Vars{Folder: w.folder()}, "y\r"),
		say(ui.MsgCodexModified, ui.Vars{}, "y\r"),
		say(ui.MsgBareWarning, ui.Vars{}, "y\r"),
	}, w.cliRules()...)
}

// answer replies to prompts until the process exits.
func (s *session) answer(rules ...rule) {
	s.t.Helper()
	seen := 0
	deadline := time.Now().Add(e2eTimeout)
	for time.Now().Before(deadline) {
		select {
		case <-s.done:
			return
		case <-time.After(50 * time.Millisecond):
		}
		fresh := s.since(seen)
		for _, r := range rules {
			if r.matches(fresh) {
				seen += len(fresh)
				s.send(r.reply)
				break
			}
		}
	}
}

func tail(s string) string {
	if len(s) > 4000 {
		return s[len(s)-4000:]
	}
	return s
}

// lock and unlock run `precinto lock`/`unlock` like the user would in
// another terminal tab.
func (w *world) lock(args ...string) {
	w.t.Helper()
	s := w.start(append([]string{"lock"}, args...)...)
	s.answer(w.cliRules()...)
	if code := s.wait(); code != 0 {
		w.t.Fatalf("precinto lock %v: exit %d\n%s", args, code, s.text())
	}
}

func (w *world) unlock() {
	w.t.Helper()
	s := w.start("unlock", "--root", w.h.Root)
	s.answer(w.cliRules()...)
	if code := s.wait(); code != 0 {
		w.t.Fatalf("precinto unlock: exit %d\n%s", code, s.text())
	}
}

// sealSession seals the folder's synthetic Claude session sid with precinto
// seal. Its writer is a process that already exited (--wait-pid, R20), so
// no quiet window applies and the transcript leaves the disk at once.
func (w *world) sealSession(sid string) {
	w.t.Helper()
	writer := exec.Command("/bin/sh", "-c", "exit 0")
	writer.Env = []string{}
	if err := writer.Start(); err != nil {
		w.t.Fatal(err)
	}
	id, err := platform.Identify(writer.Process.Pid) // not reaped yet: the pid is the writer's
	_ = writer.Wait()
	if err != nil {
		w.t.Fatal(err)
	}
	s := w.start("seal", "--session", sid, "--adopt", "--wait-pid", id.String())
	s.answer(w.cliRules()...)
	if code := s.wait(); code != 0 {
		w.t.Fatalf("precinto seal: exit %d\n%s", code, tail(s.text()))
	}
}

// fakeCodex installs the scripted TUI of the wrapper tests as `codex` (the
// synthetic Codex TUI of E2E-4).
func fakeCodex(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	root, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(goTool(t), "build", "-o", filepath.Join(dir, "codex"), "./internal/wrapper/testdata/tuichild")
	cmd.Dir = root
	cmd.Env = goEnv()
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build the synthetic codex: %v\n%s", err, out)
	}
	return dir
}

// codexArgv is the argv of the synthetic Codex TUI with args: its hard
// lifetime and the package token. Its lifeline is the PTY of the wrapper
// that runs it (fd 3 is the wrapper's lease).
func codexArgv(args ...string) []string {
	return append([]string{"codex", "-max-life", helperLife, "-test-token", e2eToken}, args...)
}

// goTool is the go command of the toolchain running the tests.
func goTool(t *testing.T) string {
	t.Helper()
	if p := filepath.Join(startEnv.Get("GOROOT"), "bin", "go"); startEnv.Get("GOROOT") != "" {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	p, err := paths.LookPath(startEnv, "go")
	if err != nil {
		t.Skip("no go tool to build the test helpers")
	}
	return p
}

func goEnv() []string {
	var env []string
	for _, kv := range startEnv.Environ() {
		k, _, _ := strings.Cut(kv, "=")
		if k == "PATH" || k == "HOME" || k == "TMPDIR" || strings.HasPrefix(k, "GO") {
			env = append(env, kv)
		}
	}
	return append(env, "CGO_ENABLED=0")
}

// harness finds an installed harness: PRECINTO_E2E_<NAME> (an absolute
// path) first, else PATH, or skips. A machine can carry several installs of
// one harness, so the test logs which one it runs (TESTPLAN §2).
func harness(t *testing.T, name string) string {
	t.Helper()
	p := startEnv.Get("PRECINTO_E2E_" + strings.ToUpper(name))
	if p == "" {
		var err error
		if p, err = paths.LookPath(startEnv, name); err != nil {
			t.Skipf("%s is not installed", name)
		}
	} else if !filepath.IsAbs(p) {
		t.Fatalf("PRECINTO_E2E_%s=%q: give an absolute path", strings.ToUpper(name), p)
	}
	real, _ := filepath.EvalSymlinks(p)
	t.Logf("%s: %s", name, real)
	return p
}

// realClaude returns the directory of an installed claude, or skips.
func realClaude(t *testing.T) string {
	t.Helper()
	return filepath.Dir(harness(t, "claude"))
}

// TestE2E4LockScreenSyntheticTUI is E2E-4 with the synthetic Codex TUI:
// overlay on lock, input dropped, replay of the pre-lock output on unlock,
// and the tail-only replay once the output outgrew the 8 MiB ring.
func TestE2E4LockScreenSyntheticTUI(t *testing.T) {
	requireE2E(t)
	w := newWorld(t, fakeCodex(t))
	run := w.start(append([]string{"run", "--harness", "codex", "--"}, codexArgv("-burst", "130000")...)...)
	run.answer(w.launchRules()...) // C10.consent / C9.codex on the first Codex launch
	m := run.expect("READY", 0)
	run.send("o")
	run.expect("OUT-1", m)

	lockMark := run.mark()
	w.lock()
	run.expect(ui.Format(ui.MsgOverlayTitle, ui.Vars{}), lockMark)
	run.send("o") // dropped on the lock screen
	time.Sleep(500 * time.Millisecond)

	unlockMark := run.mark()
	w.unlock()
	run.expect("OUT-1", unlockMark) // the pre-lock line is back
	time.Sleep(500 * time.Millisecond)
	if strings.Contains(run.since(unlockMark), "OUT-2") {
		t.Fatal("a key typed on the lock screen reached the TUI")
	}

	// Outgrow the ring: only the tail comes back, then the TUI repaints.
	m = run.mark()
	run.send("b")
	run.expect("BURST-END", m)
	w.lock()
	unlockMark = run.mark()
	w.unlock()
	run.expect("BURST-END", unlockMark)
	run.expect("WINCH", unlockMark)
	replay := run.since(unlockMark)
	if strings.Contains(replay, "BURST-00000 ") || strings.Contains(replay, "OUT-1") {
		t.Fatal("output older than the 8 MiB ring was replayed")
	}
	run.send("q")
	if code := run.wait(); code != 0 {
		t.Fatalf("precinto run: exit %d", code)
	}
}

// TestE2E4LockScreenClaudeInline is E2E-4 with a real Claude in its default
// inline mode: what Claude printed before the lock (its start-up banner) is
// visible again after the unlock although the lock cleared the scrollback.
func TestE2E4LockScreenClaudeInline(t *testing.T) {
	requireE2E(t)
	w := newWorld(t, realClaude(t))
	run := w.start("run", "--harness", "claude-code", "--", "claude", "--model", "haiku")
	run.answer(w.launchRules()...)
	run.expect("Claude Code", 0)
	time.Sleep(2 * time.Second) // let the first frame settle
	lockMark := run.mark()
	w.lock()
	run.expect(ui.Format(ui.MsgOverlayTitle, ui.Vars{}), lockMark)
	unlockMark := run.mark()
	w.unlock()
	run.expect("Claude Code", unlockMark)
	run.send("\x04\x04") // Ctrl-D twice exits Claude
	run.wait()
}

// TestE2E3ResumeRestoresTheSession is E2E-3: a session sealed at exit is
// restored by `precinto run claude --resume <sid>` before Claude starts, so
// Claude continues with the full context.
func TestE2E3ResumeRestoresTheSession(t *testing.T) {
	requireE2E(t)
	w := newWorld(t, realClaude(t))
	marker := testkit.Marker(t)
	first := w.start("run", "--harness", "claude-code", "--", "claude", "-p", "--model", "haiku",
		"--output-format", "json", "Remember the code word "+marker+" and reply only OK.")
	first.answer(w.launchRules()...)
	if code := first.wait(); code != 0 {
		t.Fatalf("first run: exit %d\n%s", code, first.text())
	}
	sid := sessionID(t, first.text())
	if !strings.Contains(first.text(), "sealed this session") {
		t.Logf("no C6 line seen (sealing may have been deferred):\n%s", tail(first.text()))
	}
	second := w.start("run", "--harness", "claude-code", "--", "claude", "-p", "--model", "haiku",
		"--resume", sid, "What is the code word? Reply with the code word only.")
	second.answer(w.launchRules()...)
	if code := second.wait(); code != 0 {
		t.Fatalf("resume: exit %d\n%s", code, second.text())
	}
	if !strings.Contains(second.text(), marker) {
		t.Fatalf("the resumed session lost its context:\n%s", tail(second.text()))
	}
}

// e2e3SID is the fixture session of the E2E-3 variants.
const e2e3SID = "00000000-0000-4000-8000-0000000000e3"

// TestE2E3ResumeMergesFragmentAndMissingNewline is E2E-3's fragment and
// missing-newline variants on the restore fixtures of REST-4 and REST-5: a
// synthetic session is sealed, Claude recreates its transcript as a linked
// fragment (E8), and, in the second variant, the sealed transcript's last
// record had lost its newline in a crash. `precinto run claude --resume`
// merges capsule and fragment before Claude starts, and Claude resumes with
// the full context.
func TestE2E3ResumeMergesFragmentAndMissingNewline(t *testing.T) {
	requireE2E(t)
	claudeDir := realClaude(t)
	for _, v := range []struct {
		name      string
		noNewline bool
	}{{"fragment", false}, {"missing newline", true}} {
		t.Run(v.name, func(t *testing.T) {
			w := newWorld(t, claudeDir)
			marker := testkit.Marker(t)
			l := &claudetest.Layout{ConfigDir: w.h.ClaudeConfig, TmpDir: w.h.ClaudeTmp, CacheDir: w.h.ClaudeCache}
			s := claudetest.Session{SID: e2e3SID, Cwd: w.h.Root, Marker: marker, NoNewline: v.noNewline,
				ModTime: time.Now().Add(-time.Hour)}
			transcript := l.WriteSession(t, s)[0]
			w.sealSession(s.SID)
			if _, err := os.Lstat(transcript); !errors.Is(err, fs.ErrNotExist) {
				t.Fatalf("the synthetic session was not sealed (%v)", err)
			}
			l.AppendFragment(t, s, 2) // Claude recreated <sid>.jsonl after the move (E8)
			run := w.start("run", "--harness", "claude-code", "--", "claude", "-p", "--model", "haiku",
				"--resume", s.SID, "Earlier messages of this conversation begin with a token that starts with precinto-marker-. Reply with that token only.")
			run.answer(w.launchRules()...)
			if code := run.wait(); code != 0 {
				t.Fatalf("resume: exit %d\n%s", code, tail(run.text()))
			}
			if !strings.Contains(run.text(), marker) {
				t.Fatalf("the resumed session lost its context:\n%s", tail(run.text()))
			}
		})
	}
}

var sidRe = regexp.MustCompile(`"session_id"\s*:\s*"([0-9a-f-]{36})"`)

func sessionID(t *testing.T, out string) string {
	t.Helper()
	if m := sidRe.FindStringSubmatch(out); m != nil {
		return m[1]
	}
	var v struct {
		SessionID string `json:"session_id"`
	}
	if i := strings.Index(out, "{"); i >= 0 && json.Unmarshal([]byte(out[i:]), &v) == nil && v.SessionID != "" {
		return v.SessionID
	}
	t.Fatalf("no session id in:\n%s", tail(out))
	return ""
}

// TestE2E7HookPresence is E2E-7: with precinto's plugin not installed in
// the throwaway Claude config, and with --bare, no hook event arrives, so
// C9.claude is printed after the session ends.
func TestE2E7HookPresence(t *testing.T) {
	requireE2E(t)
	w := newWorld(t, realClaude(t))
	want := ui.Format(ui.MsgClaudeNoHooks, ui.Vars{})
	plain := w.start("run", "--harness", "claude-code", "--", "claude", "-p", "--model", "haiku", "Reply OK.")
	plain.answer(w.launchRules()...)
	plain.wait()
	if !strings.Contains(plain.text(), want[:40]) {
		t.Errorf("plugin not installed: C9.claude missing:\n%s", tail(plain.text()))
	}
	bare := w.start("run", "--harness", "claude-code", "--", "claude", "--bare", "-p", "--model", "haiku", "Reply OK.")
	bare.expect(ui.Format(ui.MsgBareWarning, ui.Vars{}), 0) // C9.bare asks before launching
	bare.answer(w.launchRules()...)
	bare.wait()
	if !strings.Contains(bare.text(), want[:40]) {
		t.Errorf("--bare: C9.claude missing:\n%s", tail(bare.text()))
	}
}

// TestE2E5WrappedSessionEndsAlone is the wrapper's part of E2E-5: `precinto
// lock --end` ends a wrapped session (Codex quit keys, then its own
// session), prints C5, resets the terminal, and the terminal's "login
// shell" (a job-control shell stand-in) and its other jobs survive.
func TestE2E5WrappedSessionEndsAlone(t *testing.T) {
	requireE2E(t)
	codexDir := fakeCodex(t)
	w := newWorld(t, codexDir)
	shellBin := filepath.Join(t.TempDir(), "jobshell")
	root, _ := filepath.Abs("../../..")
	build := exec.Command(goTool(t), "build", "-o", shellBin, "./internal/wrapper/testdata/jobshell")
	build.Dir, build.Env = root, goEnv()
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build jobshell: %v\n%s", err, out)
	}
	ctlR, ctlW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer ctlW.Close()
	// The shell's lifeline is the terminal: it dies with its master.
	argv := append([]string{shellBin, "-ctl", "3", "-max-life", helperLife, "-test-token", e2eToken,
		w.bin, "run", "--harness", "codex", "--"}, codexArgv()...)
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Env, cmd.Dir = w.environ(), w.h.Root
	cmd.ExtraFiles = []*os.File{ctlR}
	master, err := pty.StartWithSize(cmd, &pty.Winsize{Rows: 40, Cols: 120})
	if err != nil {
		t.Fatal(err)
	}
	ctlR.Close()
	waited := make(chan error, 1)
	go func() { waited <- cmd.Wait() }()
	t.Cleanup(func() {
		select {
		case <-waited:
		default:
			_ = cmd.Process.Kill()
			<-waited
		}
		_ = master.Close()
	})
	var mu sync.Mutex
	var out bytes.Buffer
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := master.Read(buf)
			mu.Lock()
			out.Write(buf[:n])
			mu.Unlock()
			if err != nil {
				return
			}
		}
	}()
	text := func() string { mu.Lock(); defer mu.Unlock(); return out.String() }
	waitText := func(sub string) {
		deadline := time.Now().Add(e2eTimeout)
		for !strings.Contains(text(), sub) {
			if time.Now().After(deadline) {
				t.Fatalf("timed out waiting for %q:\n%q", sub, tail(text()))
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	waitText("READY")
	w.lock("--end")
	waitText("CTRL-C 2") // the Codex quit keys reached the TUI
	waitText("JOBSHELL exit")
	select {
	case err := <-waited:
		waited <- err // for the cleanup
		if ee, ok := err.(*exec.ExitError); ok && ee.Sys().(syscall.WaitStatus).Signaled() {
			t.Fatalf("the terminal's shell was killed: %v", err)
		}
	case <-time.After(e2eTimeout):
		t.Fatal("the terminal's shell did not exit")
	}
	if !strings.Contains(text(), "ended 1 session(s)") {
		t.Errorf("C5 missing:\n%q", tail(text()))
	}
}

// TestE2E6CodexHomeThroughTheWrapper is the wrapper's part of E2E-6: `precinto
// run codex exec --ephemeral …` creates and seeds the folder's Codex home,
// and the snapshot is sealed after the child exits.
func TestE2E6CodexHomeThroughTheWrapper(t *testing.T) {
	requireE2E(t)
	w := newWorld(t, filepath.Dir(harness(t, "codex")))
	run := w.start("run", "--harness", "codex", "--", "codex", "exec", "--ephemeral", "Reply OK.")
	run.answer(w.launchRules()...)
	run.wait() // no Codex login in the synthetic home: only the home and the seal matter
	home := w.h.Layout.CodexHome("root-acme")
	if _, err := os.Stat(filepath.Join(home, "config.toml")); err != nil {
		t.Fatalf("the per-root Codex home was not seeded: %v", err)
	}
	caps, _ := filepath.Glob(filepath.Join(w.h.Layout.CapsulesDir, "codex", "*", "*.pcap"))
	if len(caps) == 0 {
		t.Fatalf("no codex-home snapshot sealed after exit:\n%s", tail(run.text()))
	}
	t.Logf("%d capsule(s) sealed", len(caps))
}
