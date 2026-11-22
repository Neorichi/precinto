package testkit

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/precinto/precinto/internal/platform"
)

// settleQuietScans is how many process-table scans in a row must find no
// writer before a tree counts as settled: a worker between two file
// operations holds nothing for an instant, but its log descriptor (the
// daemon log, spawn stdio) and its locks stay open while it lives.
const (
	settleQuietScans = 3
	settlePoll       = 100 * time.Millisecond
)

// settle implements Settle.
func settle(t testing.TB, timeout time.Duration, exes []string, dirs []string) {
	t.Helper()
	left := awaitWriters(timeout, dirs, exes)
	if len(left) == 0 {
		return
	}
	var names []string
	for _, h := range left {
		names = append(names, fmt.Sprintf("pid %d %s (%s)", h.Proc.ID.PID, filepath.Base(exeOf(h.Proc)), h.Path))
	}
	sort.Strings(names)
	t.Errorf("testkit.Settle: %d process(es) still write below %s after %v: %s", len(left), strings.Join(dirs, ", "), timeout, strings.Join(names, "; "))
	// A process that writes into the test's own fake home and runs a
	// binary the test built was started by it (directly, or as a worker of
	// a daemon it started): end it so the tree can be removed. Nothing
	// else is ever signalled.
	killed := false
	for _, h := range left {
		if runsBinary(h.Proc, exes) && h.Proc.ID.PID != os.Getpid() {
			_ = platform.Signal(h.Proc.ID, syscall.SIGKILL)
			killed = true
		}
	}
	if killed {
		awaitWriters(10*time.Second, dirs, exes)
	}
}

// awaitWriters waits until no process other than this one holds a file
// open below dirs for settleQuietScans scans in a row, at most timeout,
// and returns the holders of the last scan otherwise (a scan error counts
// as a writer). A process that runs one of exes while its open files
// cannot be read counts as a writer below dirs: on Linux a hardened
// precinto is not dumpable, so its fd/ is refused like its exe (D65,
// D154), and only its end says it no longer writes there.
func awaitWriters(timeout time.Duration, dirs, exes []string) []platform.Holder {
	var abs []string
	for _, d := range dirs {
		if filepath.IsAbs(d) {
			abs = append(abs, filepath.Clean(d))
		}
	}
	if len(abs) == 0 {
		return nil
	}
	procs := platform.System()
	self := os.Getpid()
	deadline := time.Now().Add(timeout)
	quiet := 0
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		hs, err := procs.OpenFilesUnder(ctx, abs)
		cancel()
		var left []platform.Holder
		for _, h := range hs {
			if h.Proc.ID.PID != self {
				left = append(left, h)
			}
		}
		left = append(left, opaque(procs, exes, self)...)
		if err == nil && len(left) == 0 {
			if quiet++; quiet >= settleQuietScans {
				return nil
			}
		} else {
			quiet = 0
		}
		if time.Now().After(deadline) {
			if err != nil && len(left) == 0 {
				left = []platform.Holder{{Path: "process table: " + err.Error()}}
			}
			return left
		}
		time.Sleep(settlePoll)
	}
}

// opaque lists, as holders, the live processes other than self that run
// one of exes while their executable cannot be read: on Linux a hardened
// precinto (D65), whose open files cannot be read either.
func opaque(procs platform.ProcTable, exes []string, self int) []platform.Holder {
	if len(exes) == 0 {
		return nil
	}
	all, err := procs.List()
	if err != nil {
		return nil
	}
	var out []platform.Holder
	for _, p := range all {
		if p.ID.PID == self || p.State == platform.StateZombie || p.Exe != "" {
			continue
		}
		if runsBinary(p, exes) {
			out = append(out, platform.Holder{Proc: p, Path: "open files unreadable"})
		}
	}
	return out
}

// exeOf returns the executable p runs, as the kernel reports it. On Linux
// a hardened precinto is not dumpable (PR_SET_DUMPABLE 0), so a process of
// the same user is refused its /proc/<pid>/exe and fd/ and its Exe is ""
// (D65): then an absolute argv[0] whose base name is the process's command
// name (cut to 15 bytes by the kernel) stands in, resolved the way the
// kernel resolves an executable. That is best effort, as D65 is: a process
// of the user that copies both names claims a binary it does not run
// (D154). "" when neither is known.
func exeOf(p platform.ProcInfo) string {
	if p.Exe != "" {
		return p.Exe
	}
	if len(p.Argv) == 0 || !filepath.IsAbs(p.Argv[0]) || p.Comm == "" || p.Comm != kernelName(p.Argv[0]) {
		return ""
	}
	a0 := filepath.Clean(p.Argv[0])
	if r, err := filepath.EvalSymlinks(a0); err == nil {
		return r
	}
	return a0
}

// kernelName is the command name the Linux kernel records for a process
// that executes path: the base name, cut to 15 bytes (TASK_COMM_LEN).
func kernelName(path string) string {
	b := filepath.Base(path)
	if len(b) > 15 {
		b = b[:15]
	}
	return b
}

// runsBinary reports whether p runs one of exes (exeOf).
func runsBinary(p platform.ProcInfo, exes []string) bool { return runsOneOf(exeOf(p), exes) }

// runsOneOf reports whether exe is one of exes (compared after resolving
// symlinks: the kernel reports executables by their real path).
func runsOneOf(exe string, exes []string) bool {
	if exe == "" {
		return false
	}
	for _, e := range exes {
		if e == "" {
			continue
		}
		if exe == e {
			return true
		}
		if r, err := filepath.EvalSymlinks(e); err == nil && exe == r {
			return true
		}
	}
	return false
}
