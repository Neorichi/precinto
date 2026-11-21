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
	"syscall"
	"testing"
	"time"

	"filippo.io/age"

	"github.com/precinto/precinto/internal/config"
	"github.com/precinto/precinto/internal/testkit"
)

// testPassphrase is the synthetic passphrase of the throwaway vaults (the
// passphrase factor: the Secure Enclave is never used by tests).
const testPassphrase = "integration-only passphrase 4 vaults"

// The fixture session of the flows (D62 fixture form).
const flowSID = "00000000-0000-4000-8000-0000000000f1"

// startAgent starts `precinto agent --foreground` as the test's own child
// and stops it at cleanup (SIGTERM to the process this test started).
func startAgent(t *testing.T, exe string, h *testkit.Home) {
	t.Helper()
	cmd := exec.Command(exe, "agent", "--foreground")
	cmd.Env = childEnv(h, nil).Environ()
	cmd.Dir = "/"
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	t.Cleanup(func() {
		_ = cmd.Process.Signal(syscall.SIGTERM)
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			_ = cmd.Process.Kill()
			<-done
		}
	})
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(h.Layout.Socket); err == nil {
			return
		}
		select {
		case err := <-done:
			t.Fatalf("agent exited early: %v", err)
		case <-time.After(50 * time.Millisecond):
		}
	}
	t.Fatal("agent did not bind its socket")
}

// fastPolicy shortens the stability window so seals decide quickly.
func fastPolicy(t *testing.T, h *testkit.Home) {
	t.Helper()
	h.Cfg.Policy.QuietWindow = config.Duration(time.Second)
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
	p.expect("Choose a precinto passphrase")
	p.send(testPassphrase + "\r")
	p.expect("Type the passphrase again")
	p.send(testPassphrase + "\r")
	if runtime.GOOS == "darwin" {
		p.expect("Seal in the background")
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
	if !strings.Contains(p.output(), "unlocked") {
		t.Fatalf("no C2.ok: %q", p.output())
	}
}

type statusJSON struct {
	V       int `json:"v"`
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
	h := testkit.NewHome(t)
	fastPolicy(t, h)
	rec := initVaults(t, exe, h)

	// SEC-21: recover --verify succeeds with the key init wrote, needs
	// --insecure-key-file for a plain file, and fails on another key.
	if r := precinto(t, exe, h, h.HomeDir, nil, "", "recover", "--verify", "--key-file", rec); r.code != 2 {
		t.Fatalf("recover without --insecure-key-file: %+v", r)
	}
	if r := precinto(t, exe, h, h.HomeDir, nil, "", "recover", "--verify", "--key-file", rec, "--insecure-key-file"); r.code != 0 {
		t.Fatalf("recover --verify: %+v", r)
	}
	wrong := filepath.Join(h.Dir, "wrong.txt")
	if err := os.WriteFile(wrong, []byte(otherRecoveryKey(t)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if r := precinto(t, exe, h, h.HomeDir, nil, "", "recover", "--verify", "--key-file", wrong, "--insecure-key-file"); r.code == 0 {
		t.Fatalf("a foreign recovery key verified: %+v", r)
	}

	startAgent(t, exe, h)

	// testkit lists root-acme without a vault: protect creates it (the
	// retry path of a protect whose vault_create failed).
	p := startPTY(t, exe, h, h.HomeDir, nil, "protect", h.Root)
	p.expect("passphrase")
	p.send(testPassphrase + "\r")
	if code := p.wait(); code != 0 {
		t.Fatalf("protect exit %d: %q", code, p.output())
	}
	s := status(t, exe, h)
	if !s.Agent.Running || len(s.Folders) != 1 || s.Folders[0].State != "unlocked" {
		t.Fatalf("status after protect %+v", s)
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
	// the queue worker shortly after.
	waitGone(t, transcript)
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
	if r := precinto(t, exe, h, h.Root, nil, "", "restore", "--session", flowSID); r.code != 0 {
		t.Fatalf("restore: %+v", r)
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

func waitGone(t *testing.T, p string) {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Lstat(p); os.IsNotExist(err) {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("%s still in plaintext", p)
}

// Refusals through the real binary and the real agent-context detection
// (SEC-21, SEC-26, SEC-28): an agent marker in the environment refuses
// init, vault repair and the destructive commands with exit 3.
func TestFlowAgentContextRefusals(t *testing.T) {
	exe := needBinary(t)
	h := testkit.NewHome(t)
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
	// commands are refused too (D59).
	r := precinto(t, exe, h, h.Root, nil, "", "forget", "0123456789abcdef0123456789abcdef")
	if r.code != 3 {
		t.Errorf("forget without a terminal: %+v", r)
	}
}
