//go:build darwin || linux

package vault

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// reapLeakedHelpers kills and reaps every child of this test process still
// present after the tests (live or unreaped), reports them, and returns how
// many there were. They are this process's own children, started by the
// tests or by the code under test.
func reapLeakedHelpers() int {
	kids, err := childProcesses()
	if err != nil {
		fmt.Fprintf(os.Stderr, "vault: helper leak check skipped: %v\n", err)
		return 0
	}
	if len(kids) == 0 {
		return 0
	}
	fmt.Fprintf(os.Stderr, "vault: %d helper processes outlived the tests (pids %v); killed\n", len(kids), kids)
	for _, pid := range kids {
		_ = syscall.Kill(pid, syscall.SIGKILL)
		var ws syscall.WaitStatus
		_, _ = syscall.Wait4(pid, &ws, 0, nil)
	}
	return len(kids)
}

// childProcesses lists the children of this process from ps output (POSIX
// columns), the ps run itself excepted.
func childProcesses() ([]int, error) {
	var ps string
	for _, p := range []string{"/bin/ps", "/usr/bin/ps"} {
		if fi, err := os.Stat(p); err == nil && fi.Mode().IsRegular() {
			ps = p
			break
		}
	}
	if ps == "" {
		return nil, fmt.Errorf("no ps")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, ps, "-A", "-o", "pid=", "-o", "ppid=")
	cmd.Env = []string{"PATH=/bin:/usr/bin", "LC_ALL=C"}
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	self, psPid := os.Getpid(), cmd.Process.Pid
	if err := cmd.Wait(); err != nil {
		return nil, err
	}
	var kids []int
	for _, line := range strings.Split(out.String(), "\n") {
		f := strings.Fields(line)
		if len(f) != 2 {
			continue
		}
		pid, err1 := strconv.Atoi(f[0])
		ppid, err2 := strconv.Atoi(f[1])
		if err1 == nil && err2 == nil && ppid == self && pid != psPid {
			kids = append(kids, pid)
		}
	}
	return kids, nil
}
