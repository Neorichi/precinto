package live_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/precinto/precinto/internal/fsx"
	"github.com/precinto/precinto/internal/live"
	"github.com/precinto/precinto/internal/platform"
	"github.com/precinto/precinto/internal/platform/fakeplatform"
)

const quiet = 120 * time.Second

// rig is an engine over a fake process table and clock, with real files.
// The fake clock starts at the real time so file mtimes written by the test
// are never "in the future" (R16).
type rig struct {
	t      *testing.T
	dir    string
	procs  *fakeplatform.Procs
	clock  *fakeplatform.Clock
	engine *live.Engine
}

func newRig(t *testing.T) *rig {
	t.Helper()
	dir := t.TempDir()
	clock := fakeplatform.NewClock(time.Now())
	r := &rig{t: t, dir: dir, procs: fakeplatform.NewProcs(), clock: clock}
	r.engine = &live.Engine{
		Procs: r.procs, Clock: clock, LeasesDir: filepath.Join(dir, "leases"),
		Observer: live.NewObserver(clock), Quiet: quiet, HoldCap: 24 * time.Hour,
	}
	return r
}

// file writes a unit file and returns its path.
func (r *rig) file(rel, data string) string {
	r.t.Helper()
	p := filepath.Join(r.dir, "unit", rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		r.t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(data), 0o600); err != nil {
		r.t.Fatal(err)
	}
	return p
}

func (r *rig) decide(s live.Subject, extra ...live.Evidence) live.Verdict {
	r.t.Helper()
	v, err := r.engine.Decide(context.Background(), s, extra)
	if err != nil {
		r.t.Fatalf("Decide: %v", err)
	}
	return v
}

func reasons(v live.Verdict) map[live.Reason]bool {
	out := map[live.Reason]bool{}
	for _, e := range v.Evidence {
		out[e.Reason] = true
	}
	return out
}

// settle observes s twice a quiet window apart, so file stability is no
// longer evidence.
func (r *rig) settle(s live.Subject) live.Verdict {
	r.t.Helper()
	r.decide(s)
	r.clock.Advance(quiet)
	return r.decide(s)
}

func proc(pid int, start int64) platform.ProcInfo {
	return platform.ProcInfo{ID: platform.ProcID{PID: pid, StartUS: start}, PPID: 1, Exe: "/opt/harness/bin/claude"}
}

func TestStableUnitIsNotLive(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	s := live.Subject{Key: "unit-stable", Paths: []string{r.file("a.jsonl", "x\n"), filepath.Join(r.dir, "unit")}}
	v := r.decide(s)
	if !v.Live || !reasons(v)[live.ReasonUnstable] {
		t.Fatalf("first observation: %+v, want live (not yet observed for the window)", v)
	}
	r.clock.Advance(quiet - time.Second)
	if v := r.decide(s); !v.Live {
		t.Fatalf("stable before the window elapsed: %+v", v)
	}
	r.clock.Advance(time.Second)
	if v := r.decide(s); v.Live || v.Warm || v.Capped || len(v.Evidence) != 0 {
		t.Fatalf("after the quiet window: %+v, want not live", v)
	}
}

func TestChangesRestartTheWindow(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	p := r.file("a.jsonl", "x\n")
	s := live.Subject{Key: "unit-change", Paths: []string{filepath.Join(r.dir, "unit")}}
	r.decide(s)
	r.clock.Advance(quiet)
	// An append (size change) and a new file (listing change) restart it.
	f, _ := os.OpenFile(p, os.O_WRONLY|os.O_APPEND, 0)
	f.Write([]byte("y\n"))
	f.Close()
	v := r.decide(s)
	if !v.Live || !reasons(v)[live.ReasonUnstable] {
		t.Fatalf("after an append: %+v", v)
	}
	for _, e := range v.Evidence {
		if e.Reason == live.ReasonUnstable && e.Weak {
			t.Fatalf("a size change is strong evidence, got weak: %+v", e)
		}
	}
	r.clock.Advance(quiet)
	r.file("sub/b.jsonl", "z\n")
	if v := r.decide(s); !v.Live {
		t.Fatalf("a new file deep in the unit did not restart the window")
	}
	r.clock.Advance(quiet)
	if v := r.decide(s); v.Live {
		t.Fatalf("still live after a quiet window: %+v", v)
	}
	// Only the mtime changes: still live, but weak (S14).
	later := time.Now().Add(-time.Hour)
	os.Chtimes(p, later, later)
	v = r.decide(s)
	if !v.Live {
		t.Fatal("an mtime change was not noticed")
	}
	for _, e := range v.Evidence {
		if e.Reason == live.ReasonUnstable && !e.Weak {
			t.Fatalf("an mtime-only change must be weak evidence: %+v", e)
		}
	}
}

func TestFutureMtimeIsLive(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	p := r.file("a.jsonl", "x\n")
	future := r.clock.Now().Add(time.Hour)
	os.Chtimes(p, future, future)
	s := live.Subject{Key: "unit-future", Paths: []string{p}}
	v := r.settle(s)
	if !v.Live || !reasons(v)[live.ReasonFutureTime] {
		t.Fatalf("future mtime: %+v", v)
	}
	// A wall clock stepped back 2 h puts every recent mtime in the future.
	r2 := newRig(t)
	s2 := live.Subject{Key: "unit-back", Paths: []string{r2.file("b.jsonl", "x\n")}}
	r2.settle(s2)
	r2.clock.StepWall(-2 * time.Hour)
	if v := r2.decide(s2); !v.Live || !reasons(v)[live.ReasonFutureTime] {
		t.Fatalf("after a wall step back: %+v", v)
	}
}

// LeaseKeys beyond the unit key (the Codex home) are probed too, and the
// unit key is probed even when the caller forgets it.
func TestEveryLeaseKeyIsProbed(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	s := live.Subject{Key: "unit-a", LeaseKeys: []string{"home-key"}, Paths: []string{r.file("a", "x")}}
	r.settle(s)
	for _, k := range []string{"home-key", "unit-a"} {
		h, err := live.Acquire(r.engine.LeasesDir, []string{k}, live.Lease{})
		if err != nil {
			t.Fatal(err)
		}
		if v := r.decide(s); !reasons(v)[live.ReasonLease] {
			t.Errorf("lease %s not seen: %+v", k, v)
		}
		h.Release()
	}
}

// R20: when the wrapper reaped the only known writer and nothing else
// holds the unit, the stability window is skipped.
func TestWriterExitedSkipsTheWindow(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	s := live.Subject{Key: "unit-exited", Paths: []string{r.file("a", "x")}, WriterExited: true}
	if v := r.decide(s); v.Live {
		t.Fatalf("writer exited, no other evidence: %+v", v)
	}
	// Any other evidence brings the window back.
	r.procs.Add(proc(600, 1))
	s.Procs = []platform.ProcID{{PID: 600, StartUS: 1}}
	if v := r.decide(s); !v.Live || !reasons(v)[live.ReasonLedgerProc] || !reasons(v)[live.ReasonUnstable] {
		t.Fatalf("with a live ledger process: %+v", v)
	}
	s.Procs = nil
	if v := r.decide(s, live.Evidence{Reason: live.ReasonWarm}); !v.Live {
		t.Fatalf("warm evidence must keep the window: %+v", v)
	}
}

func TestRestoredRecentlyIsLive(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	s := live.Subject{Key: "unit-restored", Paths: []string{r.file("a", "x")}}
	r.settle(s)
	s.RestoredAt = r.clock.Now().Add(-10 * time.Second)
	if v := r.decide(s); !v.Live {
		t.Fatalf("restored 10 s ago: %+v", v)
	}
	s.RestoredAt = r.clock.Now().Add(-quiet - time.Second)
	if v := r.decide(s); v.Live {
		t.Fatalf("restored long ago: %+v", v)
	}
	s.RestoredAt = r.clock.Now().Add(time.Hour)
	if v := r.decide(s); !v.Live {
		t.Fatalf("restore time in the future: %+v", v)
	}
}

// Any doubt means live (HA9, R11), and an error never comes with a
// not-live verdict.
func TestFailuresMeanLive(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	s := live.Subject{Key: "unit-fail", Paths: []string{r.file("a", "x")}}
	r.settle(s)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if v, err := r.engine.Decide(ctx, s, nil); err == nil || !v.Live {
		t.Fatalf("cancelled: %+v %v", v, err)
	}
	for name, e := range map[string]*live.Engine{
		"nil engine": nil,
		"no procs":   {Clock: r.clock, LeasesDir: r.engine.LeasesDir, Observer: r.engine.Observer},
		"no clock":   {Procs: r.procs, LeasesDir: r.engine.LeasesDir, Observer: r.engine.Observer},
	} {
		if v, err := e.Decide(context.Background(), s, nil); err == nil || !v.Live {
			t.Errorf("%s: %+v %v", name, v, err)
		}
	}
	if v, err := r.engine.Decide(context.Background(), live.Subject{Paths: s.Paths}, nil); err != nil || !v.Live {
		t.Errorf("subject without a key: %+v %v", v, err)
	}
	noLeases := *r.engine
	noLeases.LeasesDir = ""
	if v, _ := noLeases.Decide(context.Background(), s, nil); !v.Live || !reasons(v)[live.ReasonUnknown] {
		t.Errorf("no lease dir: %+v", v)
	}
	noObserver := *r.engine
	noObserver.Observer = nil
	if v, _ := noObserver.Decide(context.Background(), s, nil); !v.Live {
		t.Errorf("no observer: %+v", v)
	}
	bad := s
	bad.Paths = []string{"relative/path"}
	if v, _ := r.engine.Decide(context.Background(), bad, nil); !v.Live || !reasons(v)[live.ReasonUnknown] {
		t.Errorf("unobservable path: %+v", v)
	}
	// A lease file that is not a regular file cannot be probed: live.
	weird := live.Subject{Key: "weird", Paths: s.Paths}
	os.MkdirAll(filepath.Join(r.engine.LeasesDir, "weird.lease"), 0o700)
	if v, _ := r.engine.Decide(context.Background(), weird, nil); !v.Live || !reasons(v)[live.ReasonLease] {
		t.Errorf("unprobeable lease: %+v", v)
	}
	// An unreadable unit directory cannot be observed: live.
	if os.Getuid() != 0 {
		locked := filepath.Join(r.dir, "locked")
		os.MkdirAll(filepath.Join(locked, "d"), 0o700)
		os.Chmod(locked, 0o000)
		t.Cleanup(func() { os.Chmod(locked, 0o700) })
		u := live.Subject{Key: "unit-eacces", Paths: []string{filepath.Join(locked, "d")}}
		r.decide(u)
		r.clock.Advance(quiet)
		if v := r.decide(u); !v.Live || !reasons(v)[live.ReasonUnknown] {
			t.Errorf("EACCES while observing: %+v", v)
		}
	}
}

// S14: units held only by weak evidence for longer than hold_cap are
// reported; strong evidence is never capped.
func TestHoldCaps(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	r.engine.HoldCap = 24 * time.Hour
	s := live.Subject{Key: "unit-cap", Paths: []string{r.file("a", "x")}}
	r.settle(s)
	weak := live.Evidence{Reason: live.ReasonProcess, Weak: true, Detail: "claude runs"}
	first := r.decide(s, weak)
	if !first.Live || first.Capped || first.HeldSince.IsZero() {
		t.Fatalf("first weak hold: %+v", first)
	}
	r.clock.Advance(23 * time.Hour)
	if v := r.decide(s, weak); v.Capped || !v.HeldSince.Equal(first.HeldSince) {
		t.Fatalf("23 h: %+v", v)
	}
	r.clock.Advance(time.Hour)
	if v := r.decide(s, weak); !v.Capped {
		t.Fatalf("24 h of weak evidence: %+v, want capped", v)
	}
	// Strong evidence: not capped, held since the first live sighting.
	if v := r.decide(s, weak, live.Evidence{Reason: live.ReasonRegistry}); v.Capped || !v.HeldSince.Equal(first.HeldSince) {
		t.Fatalf("strong evidence: %+v", v)
	}
	// The weak-only period restarts after strong evidence.
	if v := r.decide(s, weak); v.Capped {
		t.Fatalf("weak period did not restart: %+v", v)
	}
	// Either clock expiring caps (a wall jump of a day).
	r.clock.StepWall(25 * time.Hour)
	if v := r.decide(s, weak); !v.Capped {
		t.Fatalf("wall clock past the cap: %+v", v)
	}
	// Not live: forgotten; the next hold starts over.
	if v := r.decide(s); v.Live || !v.HeldSince.IsZero() {
		t.Fatalf("not live: %+v", v)
	}
	if v := r.decide(s, weak); v.Capped || !v.HeldSince.Equal(r.clock.Now()) {
		t.Fatalf("new hold: %+v", v)
	}
	// A spoofed registry entry (SEC-20, weak) is capped the same way.
	r.engine.HoldCap = time.Hour
	spoof := live.Evidence{Reason: live.ReasonRegistry, Weak: true, Detail: "pid not a harness process"}
	r.decide(s, spoof)
	r.clock.Advance(time.Hour)
	if v := r.decide(s, spoof); !v.Live || !v.Capped {
		t.Fatalf("spoofed registry after hold_cap: %+v", v)
	}
}

func TestObserverAPI(t *testing.T) {
	t.Parallel()
	clock := fakeplatform.NewClock(time.Now())
	o := live.NewObserver(clock)
	dir := t.TempDir()
	p := filepath.Join(dir, "f")
	os.WriteFile(p, []byte("x"), 0o600)
	missing := filepath.Join(dir, "missing")
	paths := []string{p, missing}
	if stable, err := o.Observe("k", paths, time.Minute); err != nil || stable {
		t.Fatalf("first Observe = %v, %v", stable, err)
	}
	clock.Advance(time.Minute)
	if stable, err := o.Observe("k", paths, time.Minute); err != nil || !stable {
		t.Fatalf("second Observe = %v, %v", stable, err)
	}
	// A missing path appearing is a change.
	os.WriteFile(missing, []byte("y"), 0o600)
	if stable, _ := o.Observe("k", paths, time.Minute); stable {
		t.Fatal("a new file did not change the observation")
	}
	clock.Advance(time.Minute)
	if stable, _ := o.Observe("k", paths, time.Minute); !stable {
		t.Fatal("not stable after the window")
	}
	o.Forget("k")
	if stable, _ := o.Observe("k", paths, time.Minute); stable {
		t.Fatal("Forget kept the history")
	}
	if stable, err := o.Observe("k", paths, 0); err != nil || !stable {
		t.Fatalf("q=0: second identical observation must be stable: %v %v", stable, err)
	}
	if _, err := o.Observe("k", []string{"rel"}, time.Minute); err == nil {
		t.Fatal("a relative path was accepted")
	}
	var nilObs *live.Observer
	if stable, err := nilObs.Observe("k", paths, time.Minute); err == nil || stable {
		t.Fatal("a nil observer reported stability")
	}
	nilObs.Forget("k") // no panic
}

func TestStillQuiet(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	p := r.file("a.jsonl", "x\n")
	st, err := fsx.Lstat(p)
	if err != nil {
		t.Fatal(err)
	}
	s := live.Subject{Key: "unit-quiet", Paths: []string{p}}
	snaps := map[string]fsx.Stat{p: st}
	ctx := context.Background()
	if ok, err := r.engine.StillQuiet(ctx, s, snaps); !ok || err != nil {
		t.Fatalf("quiet unit: %v %v", ok, err)
	}
	// A ledger process came alive.
	r.procs.Add(proc(700, 1))
	s.Procs = []platform.ProcID{{PID: 700, StartUS: 1}}
	if ok, _ := r.engine.StillQuiet(ctx, s, snaps); ok {
		t.Fatal("live ledger process ignored")
	}
	s.Procs = nil
	// A lease was taken.
	h, err := live.Acquire(r.engine.LeasesDir, []string{"unit-quiet"}, live.Lease{})
	if err != nil {
		t.Fatal(err)
	}
	if ok, _ := r.engine.StillQuiet(ctx, s, snaps); ok {
		t.Fatal("lease ignored")
	}
	h.Release()
	// The file was appended to.
	f, _ := os.OpenFile(p, os.O_WRONLY|os.O_APPEND, 0)
	f.Write([]byte("y\n"))
	f.Close()
	if ok, _ := r.engine.StillQuiet(ctx, s, snaps); ok {
		t.Fatal("changed file ignored")
	}
	// The file vanished.
	os.Remove(p)
	if ok, _ := r.engine.StillQuiet(ctx, s, snaps); ok {
		t.Fatal("vanished file reported quiet")
	}
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	if ok, err := r.engine.StillQuiet(cctx, s, nil); ok || err == nil {
		t.Fatal("cancelled context reported quiet")
	}
	var nilEngine *live.Engine
	if ok, err := nilEngine.StillQuiet(ctx, s, nil); ok || err == nil {
		t.Fatal("nil engine reported quiet")
	}
}

func TestLeasesCoexistAndDescribeHolders(t *testing.T) {
	t.Parallel()
	dir := filepath.Join(t.TempDir(), "state", "leases")
	key := "0123456789abcdef0123456789abcdef"
	if held, leases, err := live.Probe(dir, key); held || leases != nil || err != nil {
		t.Fatalf("never leased: %v %v %v", held, leases, err)
	}
	a, err := live.Acquire(dir, []string{key}, live.Lease{Proc: platform.ProcID{PID: 10, StartUS: 1}, Root: "root-acme"})
	if err != nil {
		t.Fatal(err)
	}
	b, err := live.Acquire(dir, []string{key, "codex-home-key"}, live.Lease{Proc: platform.ProcID{PID: 11, StartUS: 2}, Root: "root-acme"})
	if err != nil {
		t.Fatalf("a second wrapper could not share the lease: %v", err)
	}
	fi, err := os.Stat(filepath.Join(dir, key+".lease"))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("lease file mode %v %v", fi.Mode().Perm(), err)
	}
	if err := b.SetChild(platform.ProcID{PID: 12, StartUS: 3}); err != nil {
		t.Fatal(err)
	}
	held, leases, err := live.Probe(dir, key)
	if err != nil || !held || len(leases) != 2 {
		t.Fatalf("Probe = %v %+v %v", held, leases, err)
	}
	if leases[0].Proc.PID != 10 || leases[1].Proc.PID != 11 || leases[1].Child.PID != 12 || leases[1].Key != key || leases[1].At.IsZero() {
		t.Fatalf("descriptions = %+v", leases)
	}
	if got := len(b.Inheritable()); got != 2 {
		t.Fatalf("Inheritable = %d descriptors, want 2", got)
	}
	if err := a.Release(); err != nil {
		t.Fatal(err)
	}
	if held, _, _ := live.Probe(dir, key); !held {
		t.Fatal("releasing one holder released the other")
	}
	if err := b.Add("late-unit"); err != nil {
		t.Fatal(err)
	}
	if held, _, _ := live.Probe(dir, "late-unit"); !held {
		t.Fatal("Add did not lease the new key")
	}
	if err := b.Add(key); err != nil {
		t.Fatalf("re-adding a held key: %v", err)
	}
	if err := b.Release(); err != nil {
		t.Fatal(err)
	}
	if err := b.Release(); err != nil {
		t.Fatalf("second Release: %v", err)
	}
	for _, k := range []string{key, "codex-home-key", "late-unit"} {
		if held, leases, err := live.Probe(dir, k); held || leases != nil || err != nil {
			t.Errorf("%s after release: %v %v %v", k, held, leases, err)
		}
	}
	if err := b.Add("x"); err == nil || b.Inheritable() != nil || b.SetChild(platform.ProcID{}) == nil {
		t.Fatal("a released Held still works")
	}
	// Lease files are never deleted; a new sole holder drops the stale
	// descriptions.
	c, err := live.Acquire(dir, []string{key}, live.Lease{Proc: platform.ProcID{PID: 20, StartUS: 4}})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Release()
	if _, leases, _ := live.Probe(dir, key); len(leases) != 1 || leases[0].Proc.PID != 20 {
		t.Fatalf("stale descriptions survived: %+v", leases)
	}
}

func TestLeaseKeysAndDirectories(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	for _, k := range []string{"", "../x", "a/b", ".hidden", "x\x00y"} {
		if _, err := live.Acquire(dir, []string{k}, live.Lease{}); err == nil {
			t.Errorf("Acquire accepted key %q", k)
		}
		if held, _, err := live.Probe(dir, k); !held || err == nil {
			t.Errorf("Probe(%q) = %v %v, want held with an error", k, held, err)
		}
	}
	if _, err := live.Acquire("relative", []string{"k"}, live.Lease{}); err == nil {
		t.Error("relative lease directory accepted")
	}
	// A failed Acquire leaves nothing held.
	if _, err := live.Acquire(dir, []string{"good", "../bad"}, live.Lease{}); err == nil {
		t.Fatal("partial acquire succeeded")
	}
	if held, _, _ := live.Probe(dir, "good"); held {
		t.Fatal("a failed Acquire kept a lease")
	}
	h, err := live.Acquire(dir, nil, live.Lease{})
	if err != nil {
		t.Fatalf("empty Acquire: %v", err)
	}
	if len(h.Inheritable()) != 0 {
		t.Fatal("empty Held has descriptors")
	}
	h.Release()
	var nilHeld *live.Held
	if nilHeld.Release() != nil || nilHeld.Add("k") == nil || nilHeld.Inheritable() != nil {
		t.Fatal("nil Held misbehaves")
	}
}
