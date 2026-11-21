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
	left := awaitWriters(timeout, dirs)
	if len(left) == 0 {
		return
	}
	var names []string
	for _, h := range left {
		names = append(names, fmt.Sprintf("pid %d %s (%s)", h.Proc.ID.PID, filepath.Base(h.Proc.Exe), h.Path))
	}
	sort.Strings(names)
	t.Errorf("testkit.Settle: %d process(es) still write below %s after %v: %s", len(left), strings.Join(dirs, ", "), timeout, strings.Join(names, "; "))
	// A process that writes into the test's own fake home and runs a
	// binary the test built was started by it (directly, or as a worker of
	// a daemon it started): end it so the tree can be removed. Nothing
	// else is ever signalled.
	killed := false
	for _, h := range left {
		if runsOneOf(h.Proc.Exe, exes) && h.Proc.ID.PID != os.Getpid() {
			_ = platform.Signal(h.Proc.ID, syscall.SIGKILL)
			killed = true
		}
	}
	if killed {
		awaitWriters(10*time.Second, dirs)
	}
}

// awaitWriters waits until no process other than this one holds a file
// open below dirs for settleQuietScans scans in a row, at most timeout,
// and returns the holders of the last scan otherwise (a scan error counts
// as a writer).
func awaitWriters(timeout time.Duration, dirs []string) []platform.Holder {
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
