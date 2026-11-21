//go:build darwin || linux

package platform_test

import (
	"bufio"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/precinto/precinto/internal/platform"
)

// Helper processes of these tests are the test binary itself (or a copy)
// in a helper mode of TestHelperSleep. Each one carries a lifeline: its
// stdin is a pipe whose write end only the test holds, and it exits as
// soon as that pipe closes, which also happens when the test binary dies,
// so a helper never outlives its test (TESTPLAN §1). Spawned helpers (no
// stdin) watch their parent instead. Every helper also has a hard lifetime
// of helperLifetime. t.Cleanup closes the lifeline, then kills and reaps.

// helperLifetime caps every helper process.
const helperLifetime = 60 * time.Second

// helperArgs is the argv tail that selects a helper mode.
func helperArgs(mode string, extra ...string) []string {
	return append([]string{"-test.run=^TestHelperSleep$", "-test.count=1", "--", mode}, extra...)
}

// startHelper starts exe (the test binary or a copy) in helper mode with a
// lifeline, in dir, optionally as a session leader (Setsid), and waits
// until it reported ready; the identity is measured after that, so exec is
// complete.
func startHelper(t *testing.T, exe, dir string, setsid bool, mode string, extra ...string) *child {
	t.Helper()
	cmd := exec.Command(exe, helperArgs(mode, extra...)...)
	cmd.Env = []string{"HOME=/nonexistent"}
	cmd.Dir = dir
	if setsid {
		cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	}
	lifeR, lifeW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stdin = lifeR
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	lifeR.Close()
	c := &child{cmd: cmd, life: lifeW}
	t.Cleanup(func() {
		lifeW.Close() // the helper exits on its own …
		if cmd.ProcessState == nil {
			done := make(chan struct{})
			go func() { _, _ = cmd.Process.Wait(); close(done) }()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				_ = cmd.Process.Kill() // … or is killed: our own child only
				<-done
			}
		}
	})
	ready := make(chan string, 1)
	go func() {
		line, _ := bufio.NewReader(out).ReadString('\n')
		ready <- strings.TrimSpace(line)
		_, _ = io.Copy(io.Discard, out)
	}()
	select {
	case line := <-ready:
		if !strings.HasPrefix(line, "ready") {
			t.Fatalf("helper %s said %q", mode, line)
		}
		c.ready = line
	case <-time.After(20 * time.Second):
		t.Fatalf("helper %s never got ready", mode)
	}
	id, err := platform.Identify(cmd.Process.Pid)
	if err != nil {
		t.Fatalf("helper %s: %v", mode, err)
	}
	c.id = id
	return c
}

// selfExe is the test binary.
func selfExe(t *testing.T) string {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return exe
}

// TestHelperSleep is the body of helper processes (a no-op test
// otherwise). Modes:
//
//	helper-sleep          ready, then wait for the lifeline (stdin) to close
//	helper-hold FILE      open FILE (kept), ready, then like helper-sleep
//	helper-group          start a helper-member in this session (sharing
//	                      the lifeline), ready, then like helper-sleep
//	helper-member         wait for the lifeline to close (no ready line)
//	helper-orphan         spawned without stdin: exit when the parent changes
func TestHelperSleep(t *testing.T) {
	mode, extra := "", []string(nil)
	for i, a := range os.Args {
		if a == "--" && i+1 < len(os.Args) {
			mode, extra = os.Args[i+1], os.Args[i+2:]
		}
	}
	if mode == "" {
		return
	}
	go func() {
		time.Sleep(helperLifetime)
		os.Exit(71)
	}()
	untilLifelineCloses := func() {
		_, _ = io.Copy(io.Discard, os.Stdin)
		os.Exit(0)
	}
	switch mode {
	case "helper-sleep":
		os.Stdout.WriteString("ready\n")
		untilLifelineCloses()
	case "helper-hold":
		f, err := os.Open(extra[0])
		if err != nil {
			os.Exit(2)
		}
		defer f.Close()
		os.Stdout.WriteString("ready\n")
		untilLifelineCloses()
	case "helper-group":
		exe, err := os.Executable()
		if err != nil {
			os.Exit(2)
		}
		m := exec.Command(exe, helperArgs("helper-member")...)
		m.Env = []string{"HOME=/nonexistent"}
		m.Stdin = os.Stdin // the same lifeline
		if err := m.Start(); err != nil {
			os.Exit(3)
		}
		os.Stdout.WriteString("ready member=" + strconv.Itoa(m.Process.Pid) + "\n")
		untilLifelineCloses()
	case "helper-member":
		untilLifelineCloses()
	case "helper-orphan":
		ppid := os.Getppid()
		for os.Getppid() == ppid {
			time.Sleep(50 * time.Millisecond)
		}
		os.Exit(0)
	}
	os.Exit(9)
}
