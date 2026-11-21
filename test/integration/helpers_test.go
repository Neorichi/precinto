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
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/creack/pty"

	"github.com/precinto/precinto/internal/paths"
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
	return testkit.BuildBinary(t)
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
	ctx, cancel := context.WithTimeout(context.Background(), binTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe, args...)
	cmd.Env = childEnv(h, extra).Environ()
	cmd.Dir = dir
	cmd.Stdin = strings.NewReader(stdin)
	// A new session without a controlling terminal: the binary can never
	// prompt on the terminal running the tests (and /dev/tty fails, as in
	// a hook or a reparented agent process).
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	var so, se bytes.Buffer
	cmd.Stdout, cmd.Stderr = &so, &se
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
	t    *testing.T
	cmd  *exec.Cmd
	tty  *os.File
	mu   sync.Mutex
	out  bytes.Buffer
	seen int
	done chan error
}

// startPTY starts exe on a new pseudo-terminal in h's fake HOME.
func startPTY(t *testing.T, exe string, h *testkit.Home, dir string, extra map[string]string, args ...string) *ptySession {
	t.Helper()
	cmd := exec.Command(exe, args...)
	cmd.Env = childEnv(h, extra).With("TERM", "xterm-256color").Environ()
	cmd.Dir = dir
	f, err := pty.StartWithSize(cmd, &pty.Winsize{Rows: 40, Cols: 120})
	if err != nil {
		t.Fatalf("pty: %v", err)
	}
	p := &ptySession{t: t, cmd: cmd, tty: f, done: make(chan error, 1)}
	go func() {
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
		case <-p.done:
		default:
			_ = cmd.Process.Kill() // started by this test
			<-p.done
		}
		f.Close()
	})
	return p
}

// expect waits until the output after the previous match contains s.
func (p *ptySession) expect(s string) {
	p.t.Helper()
	deadline := time.Now().Add(binTimeout)
	for time.Now().Before(deadline) {
		p.mu.Lock()
		rest := p.out.String()[p.seen:]
		if i := strings.Index(rest, s); i >= 0 {
			p.seen += i + len(s)
			p.mu.Unlock()
			return
		}
		p.mu.Unlock()
		select {
		case err := <-p.done:
			p.done <- err
			p.mu.Lock()
			rest = p.out.String()[p.seen:]
			p.mu.Unlock()
			if strings.Contains(rest, s) {
				continue
			}
			p.t.Fatalf("process exited (%v) before printing %q; output: %q", err, s, p.output())
		case <-time.After(20 * time.Millisecond):
		}
	}
	p.t.Fatalf("timed out waiting for %q; output: %q", s, p.output())
}

// send types s (a carriage return ends a line on a terminal).
func (p *ptySession) send(s string) {
	p.t.Helper()
	if _, err := io.WriteString(p.tty, s); err != nil {
		p.t.Fatalf("pty write: %v", err)
	}
}

// wait returns the exit code.
func (p *ptySession) wait() int {
	p.t.Helper()
	select {
	case err := <-p.done:
		p.done <- err
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
