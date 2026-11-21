//go:build crossgroup

package codex_test

// Cross-group Codex liveness: E6 through G2's real open-file scan
// (platform.System().OpenFilesUnder, lsof on darwin). Compiles now, runs
// at integration.

import (
	"context"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/precinto/precinto/internal/harness"
	"github.com/precinto/precinto/internal/harness/codex/codextest"
	"github.com/precinto/precinto/internal/live"
	"github.com/precinto/precinto/internal/platform"
)

// A process holding a rollout open in the per-root home keeps the home
// live; once it exits the home is quiet (HA9, HA17: checked through open
// descriptors, never by flocking Codex's locks).
func TestCrossProbeRealOpenFiles(t *testing.T) {
	if testing.Short() {
		t.Skip("lsof-based scan is slow")
	}
	f := newFx(t)
	f.e.Procs = platform.System()
	f.seed(codextest.Options{Rollouts: 1})
	units, err := f.a.Scan(context.Background(), f.e, harness.Scope{})
	if err != nil || len(units) != 1 {
		t.Fatalf("scan: %v %v", units, err)
	}
	rollout := filepath.Join(f.home, filepath.FromSlash(units[0].Files[0].Rel))
	// One process holds the rollout open and waits on its stdin, the
	// lifeline: it exits when the test closes it or dies (no child of its
	// own could outlive the test holding the file).
	holder := exec.Command("/bin/sh", "-c", `exec 3<"$1"; read -r _`, "sh", rollout)
	holder.Env = []string{"PATH=/usr/bin:/bin"}
	lifeline, err := holder.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := holder.Start(); err != nil {
		t.Fatal(err)
	}
	reaped := false
	t.Cleanup(func() {
		_ = lifeline.Close()
		if !reaped {
			_ = holder.Process.Kill() // our own child, not reaped yet
			_ = holder.Wait()
		}
	})
	deadline := time.Now().Add(10 * time.Second)
	for {
		evs, err := f.a.Probe(context.Background(), f.e, units[0])
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, e := range evs {
			if e.Reason == live.ReasonOpenFD && e.Proc.PID == holder.Process.Pid {
				found = true
			}
		}
		if found {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the holder was not found: %v", evs)
		}
		time.Sleep(100 * time.Millisecond)
	}
	_ = lifeline.Close()
	_ = holder.Process.Kill()
	_ = holder.Wait()
	reaped = true
	evs, err := f.a.Probe(context.Background(), f.e, units[0])
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range evs {
		if e.Reason == live.ReasonOpenFD && e.Proc.PID == holder.Process.Pid {
			t.Fatalf("an exited holder is still evidence: %v", evs)
		}
	}
}
