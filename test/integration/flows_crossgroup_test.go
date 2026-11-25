//go:build crossgroup

package integration_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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

	"filippo.io/age"

	"github.com/precinto/precinto/internal/config"
	"github.com/precinto/precinto/internal/fsx"
	"github.com/precinto/precinto/internal/paths"
	"github.com/precinto/precinto/internal/testkit"
	"github.com/precinto/precinto/internal/ui"
)

// testPassphrase is the synthetic passphrase of the throwaway vaults (the
// passphrase factor: the Secure Enclave is never used by tests).
const testPassphrase = "integration-only passphrase 4 vaults"

// The init prompts the flows answer: the catalog texts (CC-38, D70).
var (
	promptNewPassphrase   = ui.Format(ui.MsgPassphraseNew, ui.Vars{})
	promptAgainPassphrase = ui.Format(ui.MsgPassphraseAgain, ui.Vars{})
	promptService         = ui.Format(ui.MsgServiceOffer, ui.Vars{})
)

// The fixture session of the flows (D62 fixture form).
const flowSID = "00000000-0000-4000-8000-0000000000f1"

// startAgent starts `precinto agent --foreground` in h's fake HOME as the
// test's own child and stops it at cleanup.
func startAgent(t *testing.T, exe string, h *testkit.Home) {
	t.Helper()
	startDaemon(t, exe, childEnv(h, nil).Environ(), h.Layout.Socket)
}

// startDaemon starts `exe agent --foreground` with exactly env (a new
// session, cwd /), waits until it listens on socket, and returns a stop
// function (SIGTERM to the process this test started, SIGKILL after 10 s),
// which the cleanup calls too. stop also waits for the workers the daemon
// spawned (detached, they outlive it) to stop writing into the fake home
// (testkit.Settle, TESTPLAN §1.8), so a cleanup never removes a tree a
// worker still writes to and the next daemon starts on a settled home.
func startDaemon(t *testing.T, exe string, env []string, socket string) (stop func()) {
	t.Helper()
	cmd := exec.Command(exe, "agent", "--foreground")
	cmd.Env = env
	cmd.Dir = "/"
	cmd.SysProcAttr = testkit.NewSession()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	var once sync.Once
	stop = func() {
		once.Do(func() {
			_ = cmd.Process.Signal(syscall.SIGTERM)
			select {
			case <-done:
			case <-time.After(10 * time.Second):
				_ = cmd.Process.Kill()
				<-done
			}
			// A stopped daemon leaves its socket file: the next daemon
			// replaces it, and waits below must not see the old one.
			_ = os.Remove(socket)
			testkit.Settle(t, settleWait, []string{exe}, fakeHomeDirs(env, socket)...)
		})
	}
	t.Cleanup(stop)
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(socket); err == nil {
			return stop
		}
		select {
		case err := <-done:
			done <- err
			t.Fatalf("agent exited early: %v", err)
		case <-time.After(50 * time.Millisecond):
		}
	}
	t.Fatal("agent did not bind its socket")
	return stop
}

// fakeHomeDirs are the directories of a fake home a daemon and its workers
// write to: HOME, PRECINTO_HOME and the run directories of env, and the
// socket's directory.
func fakeHomeDirs(env []string, socket string) []string {
	e := paths.FromEnviron(env)
	var dirs []string
	for _, k := range []string{"HOME", paths.EnvHome, paths.EnvRuntimeDir, paths.EnvXDGRuntimeDir} {
		if v := e.Get(k); filepath.IsAbs(v) && filepath.Clean(v) != "/" {
			dirs = append(dirs, v)
		}
	}
	return append(dirs, filepath.Dir(socket))
}

// fastPolicy shortens the stability window to the smallest value
// config.Validate accepts (10 s, D63), so seals decide quickly.
func fastPolicy(t *testing.T, h *testkit.Home) {
	t.Helper()
	h.Cfg.Policy.QuietWindow = config.Duration(10 * time.Second)
	saveConfig(t, h)
}

// flowFloor is the policy.min_free of the main flow's fake home: the
// smallest floor config.Validate accepts (D76), so the flow seals and
// restores on a nearly full disk too.
const flowFloor = config.MinMinFree

// saveConfig writes h.Cfg to the fake home's config.toml.
func saveConfig(t *testing.T, h *testkit.Home) {
	t.Helper()
	if err := config.Save(h.Layout.ConfigFile, h.Cfg); err != nil {
		t.Fatal(err)
	}
}

// initVaults runs `precinto init --factor passphrase` on a terminal, the
// recovery key written to a file (D7: only on a human TTY).
func initVaults(t *testing.T, exe string, h *testkit.Home) string {
	t.Helper()
	rec := filepath.Join(h.Dir, "recovery.txt")
	p := startPTY(t, exe, h, h.HomeDir, nil, "init", "--factor", "passphrase", "--recovery-out", rec)
	p.expect(promptNewPassphrase)
	p.send(testPassphrase + "\r")
	p.expect(promptAgainPassphrase)
	p.send(testPassphrase + "\r")
	if runtime.GOOS == "darwin" {
		p.expect(promptService)
		p.send("n\r")
	}
	if code := p.wait(); code != 0 {
		t.Fatalf("init exit %d: %q", code, p.output())
	}
	fi, err := os.Stat(rec)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("recovery file %v %v", fi, err)
	}
	return rec
}

// unlockFolder unlocks dir on a terminal with the passphrase.
func unlockFolder(t *testing.T, exe string, h *testkit.Home, dir string) {
	t.Helper()
	p := startPTY(t, exe, h, dir, nil, "unlock", "--root", dir)
	p.expect("passphrase")
	p.send(testPassphrase + "\r")
	if code := p.wait(); code != 0 {
		t.Fatalf("unlock exit %d: %q", code, p.output())
	}
	// C2.ok, up to the deadlines (they depend on the clock).
	ok := ui.Format(ui.MsgUnlockOK, ui.Vars{Folder: paths.Tilde(h.HomeDir, dir), N: h.Cfg.Policy.RestoreRecent})
	ok = ok[:strings.Index(ok, " Locks after")]
	if !strings.Contains(p.output(), ok) {
		t.Fatalf("no C2.ok (%q): %q", ok, p.output())
	}
}

type statusJSON struct {
	V         int `json:"v"`
	Attention []struct {
		Code  string `json:"code"`
		Count int    `json:"count"`
	} `json:"attention"`
	Vault struct {
		Initialized        bool       `json:"initialized"`
		RecoveryTested     bool       `json:"recovery_tested"`
		RecoveryVerifiedAt *time.Time `json:"recovery_verified_at"`
	} `json:"vault"`
	Folders []struct {
		ID          string `json:"id"`
		Path        string `json:"path"`
		State       string `json:"state"`
		Unencrypted struct {
			Files int `json:"files"`
		} `json:"unencrypted"`
	} `json:"folders"`
	Agent struct {
		Running bool `json:"running"`
	} `json:"agent"`
}

// pendingPolicy is the count of the pending-policy attention item (D48).
func (s statusJSON) pendingPolicy() int {
	for _, a := range s.Attention {
		if a.Code == "pending-policy" {
			return a.Count
		}
	}
	return 0
}

func status(t *testing.T, exe string, h *testkit.Home) statusJSON {
	t.Helper()
	r := precinto(t, exe, h, h.Root, nil, "", "status", "--json")
	if r.code != 0 {
		t.Fatalf("status: %+v", r)
	}
	var s statusJSON
	if err := json.Unmarshal([]byte(r.stdout), &s); err != nil {
		t.Fatalf("status JSON: %v\n%s", err, r.stdout)
	}
	if s.V != 1 {
		t.Fatalf("status schema %d", s.V)
	}
	return s
}

var wroteRE = regexp.MustCompile(`wrote session \S+ sha256=([0-9a-f]{64})`)

// The main flow: init, protect, status, run (fake harness, exit code
// propagated, sealed after exit), lock, unlock, restore (exact bytes),
// and no marker left in plaintext anywhere outside the capsules (I7).
func TestFlowInitProtectRunLockUnlockRestore(t *testing.T) {
	exe := needBinary(t)
	h := newHome(t)
	h.Cfg.Policy.MinFree = flowFloor // D76: written before init, like a user's edit
	fastPolicy(t, h)
	rec := initVaults(t, exe, h)

	// SEC-21: recover --verify succeeds with the key init wrote, needs
	// --insecure-key-file for a plain file, and fails on another key. It is
	// run by a human on a terminal: without one it is refused (D59).
	if r := precinto(t, exe, h, h.HomeDir, nil, "", "recover", "--verify", "--key-file", rec); r.code != 2 {
		t.Fatalf("recover without --insecure-key-file: %+v", r)
	}
	if r := precinto(t, exe, h, h.HomeDir, nil, "", "recover", "--verify", "--key-file", rec, "--insecure-key-file"); r.code != 3 {
		t.Fatalf("recover --verify without a terminal: %+v", r)
	}
	if s := status(t, exe, h); s.Vault.RecoveryTested {
		t.Fatalf("recovery key tested before recover --verify: %+v", s.Vault)
	}
	p := startPTY(t, exe, h, h.HomeDir, nil, "recover", "--verify", "--key-file", rec, "--insecure-key-file")
	if code := p.wait(); code != 0 || !strings.Contains(p.output(), "opens your sealed folders") {
		t.Fatalf("recover --verify: exit %d: %q", code, p.output())
	}
	// CC-07: the test is recorded, so status stops saying "never tested".
	if s := status(t, exe, h); !s.Vault.RecoveryTested || s.Vault.RecoveryVerifiedAt == nil {
		t.Fatalf("recover --verify not recorded: %+v", s.Vault)
	}
	wrong := filepath.Join(h.Dir, "wrong.txt")
	if err := os.WriteFile(wrong, []byte(otherRecoveryKey(t)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	p = startPTY(t, exe, h, h.HomeDir, nil, "recover", "--verify", "--key-file", wrong, "--insecure-key-file")
	if code := p.wait(); code == 0 || strings.Contains(p.output(), "opens your sealed folders") {
		t.Fatalf("a foreign recovery key verified: exit %d: %q", code, p.output())
	}

	startAgent(t, exe, h)

	// testkit lists root-acme without a vault: protect creates it (the
	// retry path of a protect whose vault_create failed).
	p = startPTY(t, exe, h, h.HomeDir, nil, "protect", h.Root)
	p.expect("passphrase")
	p.send(testPassphrase + "\r")
	if code := p.wait(); code != 0 {
		t.Fatalf("protect exit %d: %q", code, p.output())
	}
	s := status(t, exe, h)
	if !s.Agent.Running || len(s.Folders) != 1 || s.Folders[0].State != "unlocked" {
		t.Fatalf("status after protect %+v", s)
	}
	// D76, D48, D68: lowering min_free below the 2 GiB default weakens
	// protection, so the first pin (written by protect) kept the default
	// and the edit waits for a confirmation in a terminal, which an unlock
	// there asks for (the folder is unlocked already: no prompt).
	if n := s.pendingPolicy(); n != 1 {
		t.Fatalf("min_free lowered in config.toml: %d pending policy changes, want 1: %+v", n, s.Attention)
	}
	p = startPTY(t, exe, h, h.Root, nil, "unlock", "--root", h.Root)
	p.expect(ui.Format(ui.MsgPolicyReview, ui.Vars{N: 1})) // the terminal review (C13.review, UX-14)
	p.expect("policy.min_free")
	p.send("y\r")
	if code := p.wait(); code != 0 {
		t.Fatalf("unlock confirming the policy: exit %d: %q", code, p.output())
	}
	if n := status(t, exe, h).pendingPolicy(); n != 0 {
		t.Fatalf("confirmed policy still pending (%d)", n)
	}

	fake := buildHelper(t, "testdata/fakeharness", "claude")
	marker := testkit.Marker(t)
	env := map[string]string{
		"PATH":                filepath.Dir(fake) + ":" + h.Env.Get("PATH"),
		"FAKE_HARNESS_MARKER": marker,
		"FAKE_HARNESS_EXIT":   "3",
	}
	r := precinto(t, exe, h, h.Root, env, "", "run", "--no-pty", "--", "claude", "--resume", flowSID, "-p", "hello")
	if r.code != 3 {
		t.Fatalf("run exit %d, want the child's 3: %+v", r.code, r)
	}
	m := wroteRE.FindStringSubmatch(r.stdout)
	if m == nil {
		t.Fatalf("fake harness output missing: %q", r.stdout)
	}
	want := m[1]
	transcript := transcriptPath(h, flowSID)

	// Sealed after exit (the writer is known to have exited, R20), or by
	// the queue worker shortly after, keeping the 512 MiB floor free.
	if err := fsx.CheckSpace(h.Layout.CapsulesDir, 64<<20, fsx.Floor{MinBytes: int64(flowFloor)}); err != nil {
		t.Fatalf("this volume cannot hold the session while keeping policy.min_free (%d bytes) free: %v", int64(flowFloor), err)
	}
	if !waitGone(transcript) {
		t.Fatalf("%s still in plaintext after the run (run's messages: %q)", transcript, r.stderr)
	}
	if hits := testkit.GrepTree(t, h.Dir, marker, "capsules"); len(hits) > 0 {
		t.Fatalf("marker in plaintext after the seal (I7): %v", hits)
	}
	if r := precinto(t, exe, h, h.Root, nil, "", "ls", "--json"); r.code != 0 || !strings.Contains(r.stdout, `"kind": "claude-session"`) {
		t.Fatalf("ls: %+v", r)
	}

	if r := precinto(t, exe, h, h.Root, nil, "", "lock"); r.code != 0 {
		t.Fatalf("lock: %+v", r)
	}
	if s := status(t, exe, h); s.Folders[0].State != "locked" {
		t.Fatalf("not locked: %+v", s)
	}
	// Restoring a locked folder is refused (exit 3).
	if r := precinto(t, exe, h, h.Root, nil, "", "restore", "--session", flowSID); r.code != 3 {
		t.Fatalf("restore while locked: %+v", r)
	}
	unlockFolder(t, exe, h, h.Root)
	// The unlock starts the background restore of the recent sessions
	// (C2.ok, SPEC §11.6), which may be placing this one: the explicit
	// restore then has nothing left to do, and the file appears once the
	// worker's unit is complete.
	r = precinto(t, exe, h, h.Root, nil, "", "restore", "--session", flowSID)
	if r.code != 0 {
		t.Fatalf("restore: %+v", r)
	}
	if !waitPresent(transcript) {
		t.Fatalf("restored transcript missing (restore said %q)", r.stdout)
	}
	b, err := os.ReadFile(transcript)
	if err != nil {
		t.Fatalf("restored transcript: %v", err)
	}
	if got := sha256.Sum256(b); hex.EncodeToString(got[:]) != want {
		t.Fatal("restored transcript differs from the sealed bytes (I2)")
	}
	if fi, _ := os.Stat(transcript); fi.Mode().Perm() != 0o600 {
		t.Fatalf("restored mode %v (I8)", fi.Mode().Perm())
	}

	// SPEC §17, D76: precinto never seals into the floor; it keeps the
	// plaintext and says so (C6.failed, "disk full"). A floor larger than
	// any volume shows it on every disk; raising min_free is a
	// strengthening edit, so it applies at once (D48).
	h.Cfg.Policy.MinFree = 1 << 50
	saveConfig(t, h)
	full := "00000000-0000-4000-8000-0000000000f2"
	r = precinto(t, exe, h, h.Root, env, "", "run", "--no-pty", "--", "claude", "--resume", full, "-p", "hello")
	if r.code != 3 || !strings.Contains(r.stderr, "disk full") {
		t.Fatalf("run with the floor above the free space: exit %d, want the child's 3 and C6.failed (disk full): %q", r.code, r.stderr)
	}
	if !wroteRE.MatchString(r.stdout) {
		t.Fatalf("fake harness output missing: %q", r.stdout)
	}
	if _, err := os.Lstat(transcriptPath(h, full)); err != nil {
		t.Fatalf("the transcript is gone although nothing could be sealed: %v", err)
	}
}

// otherRecoveryKey is a fresh X25519 identity that is not the install's
// recovery key (generated, never stored in testdata).
func otherRecoveryKey(t *testing.T) string {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	return id.String()
}

// transcriptPath is where the fake harness writes the session.
func transcriptPath(h *testkit.Home, sid string) string {
	slug := strings.NewReplacer("/", "-", ".", "-").Replace(h.Root)
	return filepath.Join(h.ClaudeConfig, "projects", slug, sid+".jsonl")
}

// waitPresent reports whether p exists (is restored) within a minute.
func waitPresent(p string) bool {
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Lstat(p); err == nil {
			return true
		}
		time.Sleep(100 * time.Millisecond)
	}
	return false
}

// waitGone reports whether p disappears (is sealed) within a minute.
func waitGone(p string) bool {
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Lstat(p); os.IsNotExist(err) {
			return true
		}
		time.Sleep(200 * time.Millisecond)
	}
	return false
}

// Refusals through the real binary and the real agent-context detection
// (SEC-21, SEC-26, SEC-28): an agent marker in the environment refuses
// init, vault repair and the destructive commands with exit 3.
func TestFlowAgentContextRefusals(t *testing.T) {
	exe := needBinary(t)
	h := newHome(t)
	agent := map[string]string{"CLAUDECODE": "1"}
	for _, args := range [][]string{
		{"init"},
		{"vault", "repair", "--root", h.Root},
		{"forget", "0123456789abcdef0123456789abcdef"},
		{"prune", "--diverged"},
		{"unprotect", h.Root},
		{"factor", "list"},
		{"recover", "--verify"},
	} {
		r := precinto(t, exe, h, h.Root, agent, "", args...)
		if r.code != 3 {
			t.Errorf("%v with CLAUDECODE=1: exit %d (%s)", args, r.code, r.stderr)
		}
	}
	// Without a controlling terminal (a pipe, no /dev/tty) the same
	// commands are refused too (D59; SEC-26 for vault repair).
	for _, args := range [][]string{
		{"forget", "0123456789abcdef0123456789abcdef"},
		{"vault", "repair", "--root", h.Root},
		{"vault", "repair", "--root", h.Root, "--recovery"},
	} {
		if r := precinto(t, exe, h, h.Root, nil, "", args...); r.code != 3 {
			t.Errorf("%v without a terminal: %+v", args, r)
		}
	}
}
