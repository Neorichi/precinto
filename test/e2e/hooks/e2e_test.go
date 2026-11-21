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
	"syscall"
	"testing"
	"time"

	"github.com/creack/pty"

	"github.com/precinto/precinto/internal/config"
	"github.com/precinto/precinto/internal/testkit"
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
		real, err := exec.LookPath(h) // the runner's PATH, only to find the harness
		if err != nil {
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
	return s
}

// writeConfig protects s.root the way `precinto protect` records it.
func (s *sandbox) writeConfig() {
	s.t.Helper()
	cfg := config.Default()
	cfg.Roots = []config.Root{{ID: "root-acme", Path: s.root, MD: config.MDLedger, Harnesses: []string{"claude-code", "codex"}, ProtectedAt: time.Now().UTC()}}
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

// answerer drives a CLI that needs a terminal (init, protect, unlock) on a
// pseudo-terminal: it types the sandbox passphrase at passphrase prompts,
// accepts yes/no questions and types back requested confirmation words.
func (s *sandbox) answerer(dir string, timeout time.Duration, argv ...string) string {
	s.t.Helper()
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Dir = dir
	cmd.Env = append([]string(nil), s.env...)
	f, err := pty.Start(cmd)
	if err != nil {
		s.t.Fatal(err)
	}
	defer f.Close()
	var out bytes.Buffer
	typed := regexp.MustCompile(`[Tt]ype "([^"]+)"`)
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	buf := make([]byte, 4096)
	answered := 0
	end := time.Now().Add(timeout)
	for time.Now().Before(end) {
		_ = f.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		n, rerr := f.Read(buf)
		out.Write(buf[:n])
		tail := out.String()[answered:]
		switch {
		case strings.Contains(strings.ToLower(tail), "passphrase") && strings.HasSuffix(strings.TrimSpace(tail), ":"):
			_, _ = io.WriteString(f, e2ePassphrase+"\r")
			answered = out.Len()
		case strings.Contains(tail, "[Y/n]") || strings.Contains(tail, "[y/N]"):
			_, _ = io.WriteString(f, "y\r")
			answered = out.Len()
		case typed.MatchString(tail):
			_, _ = io.WriteString(f, typed.FindStringSubmatch(tail)[1]+"\r")
			answered = out.Len()
		}
		select {
		case err := <-done:
			if err != nil {
				s.t.Fatalf("%v: %v\n%s", argv, err, out.String())
			}
			return out.String()
		default:
		}
		if rerr != nil && !errors.Is(rerr, os.ErrDeadlineExceeded) && !errors.Is(rerr, io.EOF) && !strings.Contains(rerr.Error(), "input/output error") {
			break
		}
	}
	_ = cmd.Process.Kill()
	s.t.Fatalf("%v did not finish:\n%s", argv, out.String())
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
