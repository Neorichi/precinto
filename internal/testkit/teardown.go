package testkit

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/precinto/precinto/internal/paths"
	"github.com/precinto/precinto/internal/platform"
)

// Bounds of StopInstallation.
const (
	teardownStopTimeout = 30 * time.Second       // `precinto agent --stop`
	teardownSettle      = 3 * time.Second        // processes ending by themselves
	teardownTermWait    = 10 * time.Second       // after SIGTERM
	teardownKillWait    = 5 * time.Second        // after SIGKILL
	teardownPoll        = 100 * time.Millisecond // process-table scans
)

// stopInstallation implements StopInstallation.
func stopInstallation(t testing.TB, bin string, env []string, dirs []string) {
	t.Helper()
	if bin == "" {
		return
	}
	if why := foreignInstallation(env); why != "" {
		// Never the user's own agent: without a throwaway HOME or
		// PRECINTO_HOME, `agent --stop` would reach the real one.
		t.Errorf("testkit.StopInstallation: refusing to stop an agent: %s", why)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), teardownStopTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "agent", "--stop")
	cmd.Env = append([]string(nil), env...)
	cmd.Dir = "/"
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	cmd.WaitDelay = 5 * time.Second
	if err := cmd.Run(); err != nil {
		t.Errorf("testkit.StopInstallation: precinto agent --stop: %v\n%s", err, out.String())
	}
	// The agent's workers (sweep, seal --queue, restore) and stray CLIs
	// run the test's binary: a moment to end by themselves, then SIGTERM
	// (a seal is crash-safe), then SIGKILL.
	awaitGone(bin, teardownSettle)
	signalAll(bin, syscall.SIGTERM)
	if left := awaitGone(bin, teardownTermWait); len(left) > 0 {
		t.Errorf("testkit.StopInstallation: %d process(es) of %s did not end on SIGTERM and were killed: %s",
			len(left), filepath.Base(bin), strings.Join(describe(left), "; "))
		signalAll(bin, syscall.SIGKILL)
		awaitGone(bin, teardownKillWait)
	}
	if left := leftovers(bin, dirs); len(left) > 0 {
		t.Errorf("testkit.StopInstallation: %d process(es) of this test's installation still run: %s",
			len(left), strings.Join(describe(left), "; "))
	}
}

// foreignInstallation says why env may not be a test's own installation
// ("" when it is one): it must name an absolute HOME other than this
// process's, or set PRECINTO_HOME (honoured by the testing build), so that
// `precinto agent --stop` never reaches the user's real agent.
func foreignInstallation(env []string) string {
	vars := map[string]string{}
	for _, kv := range env {
		if k, v, ok := strings.Cut(kv, "="); ok {
			vars[k] = v
		}
	}
	if h := vars[paths.EnvHome]; filepath.IsAbs(h) {
		return ""
	}
	home := vars["HOME"]
	if !filepath.IsAbs(home) {
		return "the environment names no HOME"
	}
	if real := paths.FromOS().Get("HOME"); real != "" && filepath.Clean(real) == filepath.Clean(home) {
		return "the environment's HOME is this process's, not a throwaway one"
	}
	return ""
}

// awaitGone waits at most d until no live process runs bin and returns
// those left.
func awaitGone(bin string, d time.Duration) []platform.ProcInfo {
	deadline := time.Now().Add(d)
	for {
		left := leftovers(bin, nil)
		if len(left) == 0 || time.Now().After(deadline) {
			return left
		}
		time.Sleep(teardownPoll)
	}
}

// signalAll sends sig to every live process that runs bin (ProcID-checked:
// never a process that took a pid since the scan). They run a binary the
// test built: the only processes testkit ever signals.
func signalAll(bin string, sig syscall.Signal) {
	for _, p := range leftovers(bin, nil) {
		if runsOneOf(p.Exe, []string{bin}) {
			_ = platform.Signal(p.ID, sig)
		}
	}
}

// leftovers lists the live processes other than this one that run bin, or
// whose arguments name a path below one of dirs.
func leftovers(bin string, dirs []string) []platform.ProcInfo {
	all, err := platform.System().List()
	if err != nil {
		return nil
	}
	var roots []string
	for _, d := range dirs {
		if !filepath.IsAbs(d) {
			continue
		}
		roots = append(roots, filepath.Clean(d))
		if r, err := filepath.EvalSymlinks(d); err == nil && r != d {
			roots = append(roots, r)
		}
	}
	self := os.Getpid()
	var out []platform.ProcInfo
	for _, p := range all {
		if p.ID.PID == self || p.State == platform.StateZombie {
			continue
		}
		if runsOneOf(p.Exe, []string{bin}) || namesOneOf(p.Argv, roots) {
			out = append(out, p)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID.PID < out[j].ID.PID })
	return out
}

// namesOneOf reports whether an argument is a path below one of roots.
func namesOneOf(argv, roots []string) bool {
	for _, a := range argv {
		if !filepath.IsAbs(a) {
			continue
		}
		for _, r := range roots {
			if paths.Within(r, a) {
				return true
			}
		}
	}
	return false
}

// describe renders processes as "pid name args…" (no environment).
func describe(ps []platform.ProcInfo) []string {
	out := make([]string, 0, len(ps))
	for _, p := range ps {
		name := filepath.Base(p.Exe)
		if name == "." || name == "" {
			name = p.Comm
		}
		args := ""
		if len(p.Argv) > 1 {
			args = " " + strings.Join(p.Argv[1:], " ")
		}
		out = append(out, fmt.Sprintf("%d %s%s", p.ID.PID, name, args))
	}
	return out
}
