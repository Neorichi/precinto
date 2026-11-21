//go:build darwin || linux

package wrapper_test

import (
	"os"
	"os/exec"
	"syscall"
	"testing"
)

// helperArgv is the argv of the test binary as a wrapper process (TestMain's
// helper mode) whose lifeline is its fd 3, then args (its mode's flags and
// the child's argv).
func helperArgv(t *testing.T, args ...string) []string {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return append([]string{self, "-lifeline", "3", "-test-token", testToken}, args...)
}

// helperCmd runs the test binary as a wrapper process on the test terminal,
// with a lifeline of the test.
func helperCmd(t *testing.T, tp *termPair, mode string, args ...string) *exec.Cmd {
	t.Helper()
	argv := helperArgv(t, args...)
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Env = append(childEnv(t).Environ(), helperEnv+"="+mode)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = tp.slave, tp.slave, tp.slave
	cmd.ExtraFiles = []*os.File{newLifeline(t).r}
	return cmd
}

// asSessionLeader makes cmd lead a new session whose controlling terminal
// is its stdin (the test terminal), like a login shell.
func asSessionLeader(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
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
	ctlR, ctlW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer ctlW.Close()
	// jobshell → the wrapper process (its job) → the scripted child, every
	// one of them on the test's lifeline (fd 3 of each).
	argv := append([]string{bins.jobshell, "-lifeline", "3", "-ctl", "4", "-test-token", testToken},
		helperArgv(t, bins.child()...)...)
	shell := exec.Command(argv[0], argv[1:]...)
	shell.Env = append(childEnv(t).Environ(), helperEnv+"=proxy")
	shell.Stdin, shell.Stdout, shell.Stderr = tp.slave, tp.slave, tp.slave
	shell.ExtraFiles = []*os.File{newLifeline(t).r, ctlR}
	asSessionLeader(shell)
	sh := startHelper(t, shell)
	ctlR.Close()

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
	if code := sh.wait(t); code != 0 {
		t.Fatalf("shell exit %d", code)
	}
}

// TestJobShellSeesASigstopStop pins the test's own job-control shell: a job
// stopped by SIGSTOP (which darwin's syscall.WaitStatus.Stopped reports as
// "continued") is a stop, so the shell takes the terminal back and the job
// is continued on fg instead of being left stopped and orphaned.
func TestJobShellSeesASigstopStop(t *testing.T) {
	if testing.Short() {
		t.Skip("subprocess job control")
	}
	bins := helpers(t)
	tp := newTerm(t, 100, 30)
	ctlR, ctlW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer ctlW.Close()
	argv := append([]string{bins.jobshell, "-lifeline", "3", "-ctl", "4", "-test-token", testToken}, bins.child()...)
	shell := exec.Command(argv[0], argv[1:]...)
	shell.Env = childEnv(t).Environ()
	shell.Stdin, shell.Stdout, shell.Stderr = tp.slave, tp.slave, tp.slave
	shell.ExtraFiles = []*os.File{newLifeline(t).r, ctlR}
	asSessionLeader(shell)
	sh := startHelper(t, shell)
	ctlR.Close()
	tp.waitForRe(readyRe, 0)
	m := tp.mark()
	tp.typeKeys("z") // the job stops itself with SIGSTOP
	tp.waitFor("JOBSHELL stopped", m)
	if _, err := ctlW.Write([]byte("fg\n")); err != nil {
		t.Fatal(err)
	}
	tp.waitFor("RESUMED", m)
	tp.typeKeys("q")
	tp.waitFor("JOBSHELL exit 0", m)
	if code := sh.wait(t); code != 0 {
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
	cmd := helperCmd(t, tp, "proxy", bins.child()...)
	asSessionLeader(cmd)
	h := startHelper(t, cmd)
	tp.waitFor("size=100x30", 0)
	m := tp.mark()
	tp.resize(132, 43)
	tp.waitFor("WINCH 132x43", m)
	tp.typeKeys("x")
	if code := h.wait(t); code != 7 {
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
	cmd := helperCmd(t, tp, "run", append([]string{"-no-pty"}, bins.child("-cooked")...)...)
	asSessionLeader(cmd)
	h := startHelper(t, cmd)
	rd := parseReady(tp.waitForRe(readyRe, 0))
	if rd.sid != rd.pid || rd.sid == cmd.Process.Pid {
		t.Fatalf("direct child pid %d sid %d (wrapper %d): not its own session", rd.pid, rd.sid, cmd.Process.Pid)
	}
	m := tp.mark()
	tp.typeKeys("\x03") // the line discipline sends SIGINT to the wrapper
	tp.waitFor("INT", m)
	if code := h.wait(t); code != 130 {
		t.Fatalf("wrapper exit %d, want 130 (the child's SIGINT exit)", code)
	}
}
