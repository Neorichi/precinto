//go:build crossgroup

package claude_test

// Cross-group Claude liveness with G2's real process table: a registry
// spoof naming a live process (SEC-20), and D47's cwd rule against a real
// process whose executable is named claude (a helper built from
// testdata/sleeper: a copied platform binary is killed at exec by macOS
// launch constraints and would only ever be a zombie).

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/precinto/precinto/internal/capsule"
	"github.com/precinto/precinto/internal/harness"
	"github.com/precinto/precinto/internal/harness/claude"
	"github.com/precinto/precinto/internal/live"
	"github.com/precinto/precinto/internal/platform"
)

// SEC-20 (G3 + G2): a fake sessions/<pid>.json naming a live process with
// its correct start holds the session live, as weak evidence, and the hold
// is capped (reported) after hold_cap. The registry's startedAt is a wall
// time, so the entry is written from platform.StartTime (D66), never from
// the raw StartUS (µs since boot on linux).
func TestCrossSEC20RegistrySpoofIsHeldThenCapped(t *testing.T) {
	f := newFx(t)
	f.e.Procs = platform.System()
	f.session(sid1, f.h.Root, nil)
	self := platform.Self()
	started := platform.StartTime(self)
	if started.IsZero() {
		t.Fatal("platform.StartTime of the test process is unknown")
	}
	f.l.WriteRegistryEntry(t, claude.RegistryEntry{PID: self.PID, SessionID: sid1, StartedAt: started, Valid: true})
	u := sessionUnit(t, f, sid1)
	evs, err := f.a.Probe(context.Background(), f.e, u)
	if err != nil {
		t.Fatal(err)
	}
	var reg *live.Evidence
	for i := range evs {
		if evs[i].Reason == live.ReasonRegistry {
			reg = &evs[i]
		}
	}
	if reg == nil || !reg.Weak || reg.Proc != self {
		t.Fatalf("spoofed registry: %+v", evs)
	}
	// A registry entry that started before the process (reused pid, D18)
	// is not the process's: no registry evidence.
	f.l.WriteRegistryEntry(t, claude.RegistryEntry{PID: self.PID, SessionID: sid1, StartedAt: started.Add(-time.Hour), Valid: true})
	evs, err = f.a.Probe(context.Background(), f.e, u)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range evs {
		if e.Reason == live.ReasonRegistry {
			t.Fatalf("an entry written an hour before the process started was evidence: %+v", e)
		}
	}
	f.l.WriteRegistryEntry(t, claude.RegistryEntry{PID: self.PID, SessionID: sid1, StartedAt: started, Valid: true})
	evs, _ = f.a.Probe(context.Background(), f.e, u)

	engine := &live.Engine{Procs: f.e.Procs, Clock: f.h.Clock, LeasesDir: f.h.Layout.LeasesDir,
		Observer: live.NewObserver(f.h.Clock), Quiet: time.Second, HoldCap: time.Hour}
	subject := live.Subject{Key: u.Key, Paths: u.Paths, LeaseKeys: u.LeaseKeys}
	engine.Decide(context.Background(), subject, evs)
	f.h.Clock.Advance(2 * time.Second)
	v, _ := engine.Decide(context.Background(), subject, evs)
	if !v.Live || v.Capped {
		t.Fatalf("before hold_cap: %+v", v)
	}
	f.h.Clock.Advance(time.Hour)
	v, _ = engine.Decide(context.Background(), subject, evs)
	if !v.Live || !v.Capped {
		t.Fatalf("after hold_cap: %+v, want live and hold-capped", v)
	}
}

// D47 with a real process: a program whose executable is named claude,
// running with its cwd in the folder, keeps the project unit live.
func TestCrossProjectLiveWhileClaudeRunsInTheFolder(t *testing.T) {
	f := newFx(t)
	f.e.Procs = platform.System()
	_, paths := f.session(sid1, f.h.Root, nil)
	f.taint(sid1, platform.ProcID{})
	exe := buildSleeper(t, filepath.Join(t.TempDir(), "claude"))
	pid := startSleeper(t, exe, f.h.Root)
	pu, ok := find(f.scan(harness.Scope{}), capsule.KindClaudeProject, slugOf(t, paths))
	if !ok {
		t.Fatal("no project unit")
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		evs, err := f.a.Probe(context.Background(), f.e, pu)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range evs {
			if e.Reason == live.ReasonProcess && e.Proc.PID == pid {
				if !e.Weak {
					t.Fatalf("a process found by its executable name is weak evidence: %+v", e)
				}
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("the claude process in the folder was not evidence: %v", evs)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// buildSleeper builds testdata/sleeper to out with the toolchain running
// the tests (go test sets GOROOT for the test binary).
func buildSleeper(t *testing.T, out string) string {
	t.Helper()
	gotool := goTool(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, gotool, "build", "-buildvcs=false", "-o", out, "./testdata/sleeper")
	cmd.Env = buildEnv()
	var log bytes.Buffer
	cmd.Stdout, cmd.Stderr = &log, &log
	if err := cmd.Run(); err != nil {
		t.Fatalf("go build ./testdata/sleeper: %v\n%s", err, log.Bytes())
	}
	return out
}

// goTool returns the go command of the toolchain running the tests.
func goTool(t *testing.T) string {
	t.Helper()
	var cands []string
	if r := os.Getenv("GOROOT"); filepath.IsAbs(r) {
		cands = append(cands, filepath.Join(r, "bin", "go"))
	}
	//lint:ignore SA1019 the fallback when go test did not set GOROOT
	if r := runtime.GOROOT(); filepath.IsAbs(r) {
		cands = append(cands, filepath.Join(r, "bin", "go"))
	}
	for _, c := range cands {
		if fi, err := os.Stat(c); err == nil && fi.Mode().IsRegular() && fi.Mode().Perm()&0o111 != 0 {
			return c
		}
	}
	p, err := exec.LookPath("go")
	if err != nil {
		t.Fatalf("no go command to build the helper: %v", err)
	}
	return p
}

// buildEnv is the explicit environment of `go build`: the Go toolchain
// configuration of the test process, pinned to the host, and nothing else.
func buildEnv() []string {
	keep := map[string]bool{"PATH": true, "HOME": true, "USER": true, "LOGNAME": true, "TMPDIR": true,
		"XDG_CACHE_HOME": true, "SDKROOT": true, "DEVELOPER_DIR": true}
	var env []string
	for _, kv := range os.Environ() {
		k, _, _ := strings.Cut(kv, "=")
		if k == "GOOS" || k == "GOARCH" || k == "GOTOOLCHAIN" || k == "CGO_ENABLED" {
			continue
		}
		if keep[k] || strings.HasPrefix(k, "GO") {
			env = append(env, kv)
		}
	}
	return append(env, "GOOS="+runtime.GOOS, "GOARCH="+runtime.GOARCH, "GOTOOLCHAIN=local", "CGO_ENABLED=0")
}

// startSleeper starts exe in dir with an empty environment and its stdin as
// a lifeline, waits until the real process table shows it alive (measured,
// not a zombie) and returns its pid. Cleanup closes the lifeline, kills and
// reaps it: the helper never outlives the test.
func startSleeper(t *testing.T, exe, dir string) int {
	t.Helper()
	cmd := exec.Command(exe)
	cmd.Dir = dir
	cmd.Env = []string{}
	lifeline, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = lifeline.Close()
		_ = cmd.Process.Kill() // our own child, not reaped yet: its pid cannot have been reused
		_ = cmd.Wait()
	})
	ready := make(chan error, 1)
	go func() {
		buf := make([]byte, len("ready\n"))
		_, err := io.ReadFull(stdout, buf)
		if err == nil && string(buf) != "ready\n" {
			err = errors.New("unexpected output from the helper")
		}
		ready <- err
	}()
	select {
	case err := <-ready:
		if err != nil {
			t.Fatalf("helper died: %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("helper died: no ready line")
	}
	procs := platform.System()
	deadline := time.Now().Add(10 * time.Second)
	for {
		id, err := platform.Identify(cmd.Process.Pid)
		if err == nil {
			info, lerr := procs.Lookup(cmd.Process.Pid)
			if lerr == nil && info.ID == id && info.State != platform.StateZombie {
				return cmd.Process.Pid
			}
			err = lerr
			if err == nil {
				err = errors.New("zombie or identity changed")
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("helper died: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
