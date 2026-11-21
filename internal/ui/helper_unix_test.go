//go:build darwin || linux

package ui_test

import (
	"bufio"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/precinto/precinto/internal/paths"
	"github.com/precinto/precinto/internal/platform"
	"github.com/precinto/precinto/internal/ui"
)

// helperEnv selects a helper mode when the test binary re-executes itself
// as a child process (new session, optionally with a pty as its
// controlling terminal).
const helperEnv = "UI_TEST_HELPER"

// helperPrompt is the prompt of the "secret" helper.
const helperPrompt = "helper passphrase:"

func TestMain(m *testing.M) {
	if mode := paths.FromOS().Get(helperEnv); mode != "" {
		os.Exit(runHelper(mode))
	}
	os.Exit(m.Run())
}

// runHelper runs in the child: it writes one report line to fd 3, then
// waits until the parent closes fd 4, so the parent can inspect the
// terminal while the child (its session leader) is still alive.
func runHelper(mode string) int {
	report := os.NewFile(3, "report")
	release := os.NewFile(4, "release")
	var msg string
	switch mode {
	case "ctty":
		pid := os.Getpid()
		procs := fakeProcs{pid: {ID: platform.ProcID{PID: pid, StartUS: 1}, PPID: 1, Exe: "/usr/libexec/ui-helper"}}
		agent, evidence := ui.AgentContextWith(paths.FromMap(nil), procs, noMarkers, pid, ui.HasControllingTerminal)
		msg = fmt.Sprintf("ctty=%t agent=%t evidence=%s", ui.HasControllingTerminal(), agent, evidence)
	case "opentty":
		tty, err := ui.OpenTTY()
		if err != nil {
			msg = "open=error"
		} else {
			msg = "open=ok"
			if err := tty.Close(); err != nil {
				msg = "open=close-error"
			}
		}
	case "secret":
		msg = helperSecret()
	default:
		msg = "unknown helper mode"
	}
	fmt.Fprintln(report, msg)
	_ = report.Close()
	_, _ = io.Copy(io.Discard, release)
	return 0
}

// helperSecret reads a secret from the controlling terminal through
// OpenTTY and reports the outcome, whether the terminal attributes were
// restored, and a digest of the (synthetic) secret.
func helperSecret() string {
	tty, err := ui.OpenTTY()
	if err != nil {
		return "result=open-error"
	}
	defer tty.Close()
	before, err := getTermios(0)
	if err != nil {
		return "result=tcgetattr-error"
	}
	buf, err := tty.Secret(helperPrompt)
	after, aerr := getTermios(0)
	restored := aerr == nil && sameMode(before, after)
	switch {
	case errors.Is(err, ui.ErrCancelled):
		return fmt.Sprintf("result=cancelled restored=%t", restored)
	case err != nil:
		return fmt.Sprintf("result=error restored=%t", restored)
	}
	defer buf.Destroy()
	return fmt.Sprintf("result=ok restored=%t sha256=%x", restored, sha256.Sum256(buf.Bytes()))
}

// helperProc is a running helper child.
type helperProc struct {
	t       *testing.T
	cmd     *exec.Cmd
	report  *bufio.Reader
	release *os.File
	done    chan error
}

// startHelper re-executes the test binary in mode, in a new session
// (Setsid). With p, the pty slave is the child's stdio; with ctty it also
// becomes the child's controlling terminal. The child's environment is
// explicit and minimal.
func startHelper(t *testing.T, mode string, p *pty, ctty bool) *helperProc {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("test binary: %v", err)
	}
	repR, repW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	relR, relW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe, "-test.run=^$")
	cmd.Env = []string{helperEnv + "=" + mode, "HOME=" + t.TempDir(), "PATH=/usr/bin:/bin", "LC_ALL=C"}
	cmd.ExtraFiles = []*os.File{repW, relR}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if p != nil {
		cmd.Stdin, cmd.Stdout, cmd.Stderr = p.slave, p.slave, p.slave
		if ctty {
			cmd.SysProcAttr.Setctty = true
			cmd.SysProcAttr.Ctty = 0
		}
	}
	if err := cmd.Start(); err != nil {
		_ = repR.Close()
		_ = repW.Close()
		_ = relR.Close()
		_ = relW.Close()
		t.Skipf("cannot start a helper in a new session: %v", err)
	}
	_ = repW.Close()
	_ = relR.Close()
	h := &helperProc{t: t, cmd: cmd, report: bufio.NewReader(repR), release: relW, done: make(chan error, 1)}
	go func() { h.done <- cmd.Wait() }()
	t.Cleanup(func() {
		_ = h.release.Close()
		select {
		case <-h.done:
		case <-time.After(waitTimeout):
			_ = cmd.Process.Kill() // our own child
			<-h.done
		}
		_ = repR.Close()
	})
	return h
}

// result reads the child's report line.
func (h *helperProc) result() string {
	h.t.Helper()
	ch := make(chan string, 1)
	go func() {
		line, _ := h.report.ReadString('\n')
		ch <- strings.TrimSpace(line)
	}()
	select {
	case line := <-ch:
		return line
	case <-time.After(waitTimeout):
		h.t.Fatal("the helper did not report")
	}
	return ""
}

// finish lets the child exit and checks that it did so cleanly.
func (h *helperProc) finish() {
	h.t.Helper()
	_ = h.release.Close()
	select {
	case err := <-h.done:
		if err != nil {
			h.t.Errorf("helper exited with %v", err)
		}
		h.done <- err // for the cleanup
	case <-time.After(waitTimeout):
		h.t.Fatal("the helper did not exit")
	}
}

// signal sends sig to the child this test started.
func (h *helperProc) signal(sig syscall.Signal) {
	h.t.Helper()
	if err := h.cmd.Process.Signal(sig); err != nil {
		h.t.Fatalf("signal %v: %v", sig, err)
	}
}
