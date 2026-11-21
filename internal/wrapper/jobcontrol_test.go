//go:build darwin || linux

package wrapper_test

import (
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"
)

// helperCmd runs the test binary as a wrapper process (TestMain's helper
// mode) on the test terminal.
func helperCmd(t *testing.T, tp *termPair, mode string, args ...string) *exec.Cmd {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(self, args...)
	cmd.Env = append(childEnv(t).Environ(), helperEnv+"="+mode)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = tp.slave, tp.slave, tp.slave
	return cmd
}

// asSessionLeader makes cmd lead a new session whose controlling terminal
// is its stdin (the test terminal), like a login shell.
func asSessionLeader(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
}

func waitCmd(t *testing.T, cmd *exec.Cmd) int {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case <-done:
		return cmd.ProcessState.ExitCode()
	case <-time.After(3 * waitTimeout):
		_ = cmd.Process.Kill()
		t.Fatal("helper process did not exit")
		return -1
	}
}

// TestJobControlStopsAndContinues is SPEC §15.1 step 8 (UX14): when the
// child stops, the wrapper gives the terminal back (cooked again) and stops
// itself like a shell job; on fg it re-enters raw mode, continues the child
// and repaints.
func TestJobControlStopsAndContinues(t *testing.T) {
	if testing.Short() {
		t.Skip("subprocess job control")
	}
	bins := helpers(t)
	tp := newTerm(t, 100, 30)
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctlR, ctlW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer ctlW.Close()
	shell := exec.Command(bins.jobshell, self, bins.tui)
	shell.Env = append(childEnv(t).Environ(), helperEnv+"=proxy")
	shell.Stdin, shell.Stdout, shell.Stderr = tp.slave, tp.slave, tp.slave
	shell.ExtraFiles = []*os.File{ctlR}
	asSessionLeader(shell)
	if err := shell.Start(); err != nil {
		t.Fatal(err)
	}
	ctlR.Close()
	t.Cleanup(func() { _ = shell.Process.Kill() })

	tp.waitForRe(readyRe, 0)
	m := tp.mark()
	tp.typeKeys("z") // the child stops itself
	tp.waitFor("STOPPING", m)
	tp.waitFor("JOBSHELL stopped", m)
	// The wrapper restored the terminal: the line discipline echoes again.
	echoMark := tp.mark()
	tp.typeKeys("1234")
	tp.waitFor("1234", echoMark)

	contMark := tp.mark()
	if _, err := ctlW.Write([]byte("fg\n")); err != nil {
		t.Fatal(err)
	}
	tp.waitFor("RESUMED", contMark)
	tp.waitFor("WINCH 99x30", contMark) // repaint after continuing
	// Raw mode again: keys reach the child unechoed and one at a time.
	tp.typeKeys("q")
	tp.waitFor("BYE", contMark)
	tp.waitFor("JOBSHELL exit 0", contMark)
	if code := waitCmd(t, shell); code != 0 {
		t.Fatalf("shell exit %d", code)
	}
}

// TestWindowSizePropagates resizes the real terminal of a wrapper process:
// the kernel's SIGWINCH reaches the wrapper, which resizes the child's PTY.
func TestWindowSizePropagates(t *testing.T) {
	if testing.Short() {
		t.Skip("subprocess")
	}
	bins := helpers(t)
	tp := newTerm(t, 100, 30)
	cmd := helperCmd(t, tp, "proxy", bins.tui)
	asSessionLeader(cmd)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill() })
	tp.waitFor("size=100x30", 0)
	m := tp.mark()
	tp.resize(132, 43)
	tp.waitFor("WINCH 132x43", m)
	tp.typeKeys("x")
	if code := waitCmd(t, cmd); code != 7 {
		t.Fatalf("wrapper exit %d, want the child's 7", code)
	}
}

// TestDirectModeForwardsSignals: in --no-pty mode the child leads its own
// session, so the terminal's Ctrl-C reaches only the wrapper (the
// foreground job), which forwards SIGINT (D57).
func TestDirectModeForwardsSignals(t *testing.T) {
	if testing.Short() {
		t.Skip("subprocess")
	}
	bins := helpers(t)
	tp := newTerm(t, 100, 30)
	cmd := helperCmd(t, tp, "run", "-no-pty", bins.tui, "-cooked")
	asSessionLeader(cmd)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill() })
	rd := parseReady(tp.waitForRe(readyRe, 0))
	if rd.sid != rd.pid || rd.sid == cmd.Process.Pid {
		t.Fatalf("direct child pid %d sid %d (wrapper %d): not its own session", rd.pid, rd.sid, cmd.Process.Pid)
	}
	m := tp.mark()
	tp.typeKeys("\x03") // the line discipline sends SIGINT to the wrapper
	tp.waitFor("INT", m)
	if code := waitCmd(t, cmd); code != 130 {
		t.Fatalf("wrapper exit %d, want 130 (the child's SIGINT exit)", code)
	}
}
