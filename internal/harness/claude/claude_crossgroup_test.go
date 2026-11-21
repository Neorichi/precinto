//go:build crossgroup

package claude_test

// Cross-group Claude liveness with G2's real process table: a registry
// spoof naming a live process (SEC-20), and D47's cwd rule against a real
// process whose executable is named claude. Compiles now, runs at
// integration.

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
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
// is capped (reported) after hold_cap.
func TestCrossSEC20RegistrySpoofIsHeldThenCapped(t *testing.T) {
	f := newFx(t)
	f.e.Procs = platform.System()
	f.session(sid1, f.h.Root, nil)
	self := platform.Self()
	started := time.UnixMicro(self.StartUS)
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
	exe := filepath.Join(t.TempDir(), "claude")
	data, err := os.ReadFile("/bin/sleep")
	if err != nil {
		t.Skipf("no /bin/sleep to copy: %v", err)
	}
	if err := os.WriteFile(exe, data, 0o700); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe, "30")
	cmd.Dir = f.h.Root
	cmd.Env = []string{}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = cmd.Process.Kill() // our own child
		_ = cmd.Wait()
	}()
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
			if e.Reason == live.ReasonProcess && e.Proc.PID == cmd.Process.Pid {
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("the claude process in the folder was not evidence: %v", evs)
		}
		time.Sleep(50 * time.Millisecond)
	}
}
