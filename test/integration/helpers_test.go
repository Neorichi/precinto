// Package integration_test holds G7's cross-package flows (docs/TESTPLAN.md
// §3): the testing binary from testkit.BuildBinary runs in a testkit fake
// HOME, never against real user data. Flows that need every group's real
// implementation carry the build tag crossgroup (`make crossgroup`); the
// rest run with `make test`.
package integration_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
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

	"github.com/precinto/precinto/internal/paths"
	"github.com/precinto/precinto/internal/platform"
	"github.com/precinto/precinto/internal/testkit"
)

// binTimeout bounds one invocation of the binary.
const binTimeout = 2 * time.Minute

// result is one finished invocation.
type result struct {
	code           int
	stdout, stderr string
}

// needBinary skips slow binary-building tests in -short mode.
func needBinary(t *testing.T) string {
	t.Helper()
	if testing.Short() {
		t.Skip("builds the precinto binary (slow)")
	}
	exe := testkit.BuildBinary(t)
	ownBinary(filepath.Dir(exe), false)
	return exe
}

// Directories holding the binaries this package built (the testing build,
// the production build, helper programs): every process running one of
// them was started by these tests, directly or through a daemon they
// started, so TestMain may wait for and end them (TESTPLAN §1.8). The
// directories this package created itself are removed at the end.
var (
	ownMu      sync.Mutex
	ownDirs    = map[string]bool{}
	ownCreated = map[string]bool{}
)

func ownBinary(dir string, created bool) {
	ownMu.Lock()
	defer ownMu.Unlock()
	ownDirs[dir] = true
	// The kernel reports executables by their resolved path (darwin's
	// TMPDIR is below the /var symlink).
	if real, err := filepath.EvalSymlinks(dir); err == nil {
		ownDirs[real] = true
	}
	if created {
		ownCreated[dir] = true
	}
}

// TestMain fails the package when a process running one of its binaries
// outlives the tests (a helper without a lifeline, a daemon or worker that
// was not stopped): it waits up to leakWait for them to exit, then kills
// them (they run binaries only these tests built) and exits non-zero.
func TestMain(m *testing.M) {
	code := m.Run()
	if left := waitOwnProcesses(leakWait); len(left) > 0 {
		fmt.Fprintf(os.Stderr, "integration: %d test process(es) outlived the tests and were killed: %s\n", len(left), strings.Join(left, "; "))
		if code == 0 {
			code = 1
		}
	}
	ownMu.Lock()
	for d := range ownCreated {
		_ = os.RemoveAll(d)
	}
	ownMu.Unlock()
	testkit.RemoveBinaries() // the testing build (TESTPLAN §1.8: nothing left in TMPDIR)
	os.Exit(code)
}

// settleOwn makes the test wait, before the fake home it has just created
// is removed (t.Cleanup runs last-in first-out), until no process runs a
// binary of this package: the daemons, CLIs and helpers the test started
// and the workers they spawned (detached, with no file of the home open
// between two steps). The package's tests run one at a time, so every such
// process is this test's. One still running after settleWait is reported
// and killed (TESTPLAN §1.8).
func settleOwn(t *testing.T) {
	t.Helper()
	t.Cleanup(func() {
		if left := waitOwnProcesses(settleWait); len(left) > 0 {
			t.Errorf("%d process(es) this test started outlived it and were killed: %s", len(left), strings.Join(left, "; "))
		}
	})
}

// settleWait bounds how long the processes a test started (a stopped
// daemon's workers above all) may keep running or writing into its fake
// home after it (a sweep's quiet window is 10 s with fastPolicy).
const settleWait = 90 * time.Second

// newHome is testkit.NewHome with settleOwn: the home is removed only after
// every process the test started there has exited.
func newHome(t *testing.T) *testkit.Home {
	t.Helper()
	h := testkit.NewHome(t)
	settleOwn(t)
	return h
}

// leakWait bounds how long detached workers (a daemon's start-up sweep,
// a post-unlock restore) may take to finish after the last test.
const leakWait = 20 * time.Second

// waitOwnProcesses waits until no live process runs a binary of ownDirs,
// killing what is left after d; it returns those, as "pid exe".
func waitOwnProcesses(d time.Duration) []string {
	ownMu.Lock()
	dirs := make([]string, 0, len(ownDirs))
	for dir := range ownDirs {
		dirs = append(dirs, dir+string(filepath.Separator))
	}
	ownMu.Unlock()
	if len(dirs) == 0 {
		return nil
	}
	procs := platform.System()
	self := os.Getpid()
	find := func() []platform.ProcInfo {
		all, err := procs.List()
		if err != nil {
			return nil
		}
		var out []platform.ProcInfo
		for _, p := range all {
			if p.ID.PID == self || p.State == platform.StateZombie || p.Exe == "" {
				continue
			}
			for _, dir := range dirs {
				if strings.HasPrefix(p.Exe, dir) {
					out = append(out, p)
					break
				}
			}
		}
		return out
	}
	deadline := time.Now().Add(d)
	for {
		left := find()
		if len(left) == 0 {
			return nil
		}
		if time.Now().After(deadline) {
			var names []string
			for _, p := range left {
				if procs.Alive(p.ID) {
					_ = syscall.Kill(p.ID.PID, syscall.SIGKILL) // runs a binary these tests built
				}
				names = append(names, fmt.Sprintf("%d %s", p.ID.PID, filepath.Base(p.Exe)))
			}
			return names
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// childEnv is the fake home's environment plus extra variables. It is built
// from h.Env only: nothing of the test process (agent markers, the real
// HOME, PRECINTO_*) reaches the child.
func childEnv(h *testkit.Home, extra map[string]string) paths.Env {
	env := h.Env
	for k, v := range extra {
		env = env.With(k, v)
	}
	return env
}

// precinto runs the binary exe in h's fake HOME from dir with stdin.
func precinto(t *testing.T, exe string, h *testkit.Home, dir string, extra map[string]string, stdin string, args ...string) result {
	t.Helper()
	return runEnv(t, exe, childEnv(h, extra).Environ(), dir, stdin, args...)
}

// runEnv runs exe with exactly env, from dir, with stdin, in a new session
// without a controlling terminal, and waits for it.
func runEnv(t *testing.T, exe string, env []string, dir string, stdin string, args ...string) result {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), binTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe, args...)
	cmd.Env = env
	cmd.Dir = dir
	cmd.Stdin = strings.NewReader(stdin)
	// A new session without a controlling terminal: the binary can never
	// prompt on the terminal running the tests (and /dev/tty fails, as in
	// a hook or a reparented agent process).
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	var so, se bytes.Buffer
	cmd.Stdout, cmd.Stderr = &so, &se
	// A worker the binary spawned must not inherit these pipes; if one did,
	// Wait gives up after WaitDelay (and the test fails) instead of hanging.
	cmd.WaitDelay = 10 * time.Second
	err := cmd.Run()
	code := 0
	if err != nil {
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			t.Fatalf("precinto %v: %v", args, err)
		}
		code = ee.ExitCode()
	}
	return result{code: code, stdout: so.String(), stderr: se.String()}
}

// moduleRoot finds the repository root from the test's directory.
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

var (
	helperMu    sync.Mutex
	helperBuilt = map[string]string{}
)

// buildHelper builds a testdata main package (relative to this directory)
// as dir/name once per test process and returns the binary's path.
func buildHelper(t *testing.T, pkg, name string) string {
	t.Helper()
	helperMu.Lock()
	defer helperMu.Unlock()
	key := pkg + " " + name
	if p, ok := helperBuilt[key]; ok {
		return p
	}
	dir, err := os.MkdirTemp("", "precinto-helper-")
	if err != nil {
		t.Fatal(err)
	}
	ownBinary(dir, true)
	out := filepath.Join(dir, name)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, goTool(t), "build", "-o", out, "./"+filepath.ToSlash(filepath.Join("test", "integration", pkg)))
	cmd.Dir = moduleRoot(t)
	cmd.Env = goEnv()
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build %s: %v\n%s", pkg, err, b)
	}
	helperBuilt[key] = out
	return out
}

// goTool is the go command of the toolchain running the tests (go test
// sets GOROOT for the test binary), else the first go on PATH.
func goTool(t *testing.T) string {
	t.Helper()
	e := paths.FromOS()
	if r := e.Get("GOROOT"); filepath.IsAbs(r) {
		if p := filepath.Join(r, "bin", "go"); fileExecutable(p) {
			return p
		}
	}
	p, err := paths.LookPath(e, "go")
	if err != nil {
		t.Fatalf("no go command: %v", err)
	}
	return p
}

func fileExecutable(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.Mode().IsRegular() && fi.Mode().Perm()&0o111 != 0
}

// goEnv is the explicit environment of `go build`: the Go toolchain
// configuration of the test process, nothing else.
func goEnv() []string {
	keep := map[string]bool{"PATH": true, "HOME": true, "TMPDIR": true, "USER": true, "XDG_CACHE_HOME": true}
	var env []string
	for _, kv := range paths.FromOS().Environ() {
		k, _, _ := strings.Cut(kv, "=")
		if k == "GOOS" || k == "GOARCH" {
			continue
		}
		if keep[k] || strings.HasPrefix(k, "GO") || strings.HasPrefix(k, "CGO_") {
			env = append(env, kv)
		}
	}
	return env
}

// ptySession drives the binary on a pseudo-terminal (init, protect and
// unlock need a terminal for their prompts).
type ptySession struct {
	t       *testing.T
	cmd     *exec.Cmd
	tty     *os.File
	mu      sync.Mutex
	out     bytes.Buffer
	seen    int
	done    chan error
	drained chan struct{} // closed when the terminal has nothing more to read
}

// startPTY starts exe on a new pseudo-terminal in h's fake HOME.
func startPTY(t *testing.T, exe string, h *testkit.Home, dir string, extra map[string]string, args ...string) *ptySession {
	t.Helper()
	return startPTYEnv(t, exe, childEnv(h, extra).With("TERM", "xterm-256color").Environ(), dir, args...)
}

// startPTYEnv starts exe with exactly env on a new pseudo-terminal (its
// controlling terminal: exe leads a new session). The cleanup asks it to
// stop (SIGTERM, then SIGKILL after ptyGrace) and closes the terminal,
// which hangs up whatever it started on it.
func startPTYEnv(t *testing.T, exe string, env []string, dir string, args ...string) *ptySession {
	t.Helper()
	cmd := exec.Command(exe, args...)
	cmd.Env = env
	cmd.Dir = dir
	f, err := pty.StartWithSize(cmd, &pty.Winsize{Rows: 40, Cols: 120})
	if err != nil {
		t.Fatalf("pty: %v", err)
	}
	p := &ptySession{t: t, cmd: cmd, tty: f, done: make(chan error, 1), drained: make(chan struct{})}
	go func() {
		defer close(p.drained)
		buf := make([]byte, 4096)
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
	go func() { p.done <- cmd.Wait() }()
	t.Cleanup(func() {
		select {
		case err := <-p.done:
			p.done <- err
		default:
			_ = cmd.Process.Signal(syscall.SIGTERM) // started by this test
			select {
			case err := <-p.done:
				p.done <- err
			case <-time.After(ptyGrace):
				_ = cmd.Process.Kill()
				p.done <- <-p.done
			}
		}
		f.Close()
	})
	return p
}

// ptyGrace is how long a process on a test terminal gets to stop.
const ptyGrace = 5 * time.Second

// expect waits until the output after the previous match contains s.
func (p *ptySession) expect(s string) {
	p.t.Helper()
	p.expectAny(s)
}

// expectAny waits until the output after the previous match contains one
// of ss and returns its index (the earliest one when several appear). When
// the process exits first, what it wrote is read to the end before the
// output is judged (the reader may lag behind under load).
func (p *ptySession) expectAny(ss ...string) int {
	p.t.Helper()
	deadline := time.Now().Add(binTimeout)
	exited := false
	for {
		p.mu.Lock()
		rest := p.out.String()[p.seen:]
		best, at := -1, len(rest)
		for i, s := range ss {
			if j := strings.Index(rest, s); j >= 0 && j < at {
				best, at = i, j
			}
		}
		if best >= 0 {
			p.seen += at + len(ss[best])
			p.mu.Unlock()
			return best
		}
		p.mu.Unlock()
		if exited {
			err := <-p.done
			p.done <- err
			p.t.Fatalf("process exited (%v) before printing any of %q; output: %q", err, ss, p.output())
		}
		if time.Now().After(deadline) {
			p.t.Fatalf("timed out waiting for any of %q; output: %q", ss, p.output())
		}
		select {
		case err := <-p.done:
			p.done <- err
			// Look once more after the reader reached the end (bounded:
			// a descendant may keep the terminal open).
			select {
			case <-p.drained:
			case <-time.After(5 * time.Second):
			}
			exited = true
		case <-time.After(20 * time.Millisecond):
		}
	}
}

var procIDRE = regexp.MustCompile(`procid=([0-9]+:[0-9]+)`)

// expectProcID waits for the "fakeharness: procid=PID:START" line of a
// fake harness in handshake mode and returns PID:START.
func (p *ptySession) expectProcID() string {
	p.t.Helper()
	p.expect("procid=")
	deadline := time.Now().Add(binTimeout)
	for time.Now().Before(deadline) {
		p.mu.Lock()
		out := p.out.String()
		start := p.seen - len("procid=")
		m := procIDRE.FindStringSubmatchIndex(out[start:])
		if m != nil && strings.ContainsAny(out[start+m[1]:], "\r\n") {
			id := out[start+m[2] : start+m[3]]
			p.seen = start + m[1]
			p.mu.Unlock()
			return id
		}
		p.mu.Unlock()
		time.Sleep(20 * time.Millisecond)
	}
	p.t.Fatalf("no procid line; output: %q", p.output())
	return ""
}

// send types s (a carriage return ends a line on a terminal).
func (p *ptySession) send(s string) {
	p.t.Helper()
	if _, err := io.WriteString(p.tty, s); err != nil {
		p.t.Fatalf("pty write: %v", err)
	}
}

// wait returns the exit code, once the output is read to the end (so
// output() holds everything the process wrote).
func (p *ptySession) wait() int {
	p.t.Helper()
	select {
	case err := <-p.done:
		p.done <- err
		select {
		case <-p.drained:
		case <-time.After(5 * time.Second): // a descendant keeps the terminal open
		}
		if err == nil {
			return 0
		}
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return ee.ExitCode()
		}
		p.t.Fatalf("wait: %v", err)
	case <-time.After(binTimeout):
		p.t.Fatalf("timed out; output: %q", p.output())
	}
	return -1
}

func (p *ptySession) output() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.out.String()
}
