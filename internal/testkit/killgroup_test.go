package testkit_test

import (
	"os/exec"
	"runtime"
	"testing"
	"time"

	"github.com/precinto/precinto/internal/testkit"
)

// KillGroup ends the process group a NewSession child leads, the child
// and what it started, and refuses the pids kill(2) would read as "every
// process" or "my own group".
func TestKillGroup(t *testing.T) {
	for _, pid := range []int{-1, 0, 1} {
		if err := testkit.KillGroup(pid); err == nil {
			t.Errorf("KillGroup(%d) accepted", pid)
		}
	}
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("no process groups here")
	}
	// A shell that starts a grandchild and waits: both are in the group.
	cmd := exec.Command("/bin/sh", "-c", "sleep 30 & wait")
	cmd.Env = []string{"PATH=/usr/bin:/bin"}
	cmd.SysProcAttr = testkit.NewSession()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	t.Cleanup(func() { _ = cmd.Process.Kill() }) // started by this test
	time.Sleep(100 * time.Millisecond)
	if err := testkit.KillGroup(cmd.Process.Pid); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("the group leader exited normally")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the group leader outlived KillGroup")
	}
}
