//go:build crossgroup && (darwin || linux)

package wrapper_test

// Cross-group tests: they need internal/platform (G2: Identify,
// SignalGroup), internal/ipc and internal/agent/agenttest. Built with
// -tags testing,crossgroup the local seams of seams_local_test.go are off,
// so the wrapper uses the real platform functions everywhere.

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/precinto/precinto/internal/agent/agenttest"
	"github.com/precinto/precinto/internal/harness"
	"github.com/precinto/precinto/internal/ipc"
	"github.com/precinto/precinto/internal/platform"
	"github.com/precinto/precinto/internal/testkit"
	"github.com/precinto/precinto/internal/ui"
	"github.com/precinto/precinto/internal/wrapper"
)

// TestCrossgroupChildProcIDIsMeasured: Proxy.Child is the ProcID that
// platform.Identify measures (pid plus kernel start time), never pid alone.
func TestCrossgroupChildProcIDIsMeasured(t *testing.T) {
	r := startRig(t, wrapper.ProxyOptions{}, nil)
	want, err := platform.Identify(r.ready.pid)
	if err != nil {
		t.Fatal(err)
	}
	if got := r.p.Child(); got != want || got.StartUS == 0 {
		t.Fatalf("Child() = %+v, platform.Identify = %+v", got, want)
	}
	r.term.typeKeys("q")
	if code := r.wait(); code != 0 {
		t.Fatalf("exit %d", code)
	}
}

// TestCrossgroupTerminateEndsTheWholeChildSession is SEC-30 with the real
// platform.SignalGroup: a helper that moved to a process group of its own
// inside the child's session is ended too (a process-group kill would miss
// it), while a process of the test's session survives.
func TestCrossgroupTerminateEndsTheWholeChildSession(t *testing.T) {
	bins := helpers(t)
	child, sibling := newLifeline(t), newLifeline(t)
	sib := testSibling(t, bins.tui, sibling)
	defer func() { _ = sib.Process.Kill(); _ = sib.Wait() }()
	r := startRig(t, wrapper.ProxyOptions{}, []*os.File{child.w}, "-ignore-term")
	child.handOff()
	m := r.term.mark()
	r.term.typeKeys("G")
	r.term.waitFor("GRANDCHILD pid=", m)
	if err := r.p.Terminate(wrapper.TerminateOptions{Grace: 300 * time.Millisecond}); err != nil {
		t.Fatal(err)
	}
	if !child.closedWithin(waitTimeout) {
		t.Fatal("a helper in its own process group of the child's session survived")
	}
	if sibling.closedWithin(300 * time.Millisecond) {
		t.Fatal("a process outside the child's session was killed")
	}
}

// agentBackend is the fake backend with a real in-process daemon: Daemon
// dials agenttest, and RecordLaunch makes the scripted child look like a
// Claude process in the protected folder to the daemon's fake process table.
type agentBackend struct {
	*fakeBackend
	agent *agenttest.Agent
	home  *testkit.Home
	t     *testing.T
}

func (b *agentBackend) Daemon(ctx context.Context) (wrapper.Daemon, error) {
	b.record("Daemon")
	return b.agent.Dial(b.t), nil
}

func (b *agentBackend) RecordLaunch(ctx context.Context, plan harness.LaunchPlan, child platform.ProcID) error {
	b.home.Procs.Add(platform.ProcInfo{ID: child, PPID: os.Getpid(), Exe: "/usr/local/bin/claude", Comm: "2.1.329"})
	b.home.Procs.SetCwd(child.PID, b.home.Root)
	return b.fakeBackend.RecordLaunch(ctx, plan, child)
}

// TestCrossgroupRunAgainstTheDaemon drives Run through the real protocol:
// the wrapper registers and subscribes; `precinto lock` shows the lock
// screen; `precinto lock --end` ends the child's session.
func TestCrossgroupRunAgainstTheDaemon(t *testing.T) {
	bins := helpers(t)
	h := testkit.NewHome(t)
	a := agenttest.Start(t, h.Layout, h.Clock, h.Procs)
	defer a.Stop()
	h.Procs.Add(platform.ProcInfo{ID: platform.Self(), Exe: "/usr/local/bin/precinto"})

	plan := managedPlan(harness.ClaudeCode, bins.tui)
	plan.Roots = h.Cfg.Roots
	b := &agentBackend{fakeBackend: newFakeBackend(plan), agent: a, home: h, t: t}
	tp := newTerm(t, 100, 30)
	o := runOptions(t, tp, b.fakeBackend, &syncBuffer{})
	o.Backend = b
	o.Env = h.Env
	res := startRun(context.Background(), o)
	tp.waitForRe(readyRe, 0)

	c := a.Dial(t)
	defer c.Close()
	deadline := time.Now().Add(waitTimeout)
	for {
		st, err := c.Status(context.Background())
		if err == nil && len(st.Sessions) > 0 && st.Sessions[0].Wrapper {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the daemon never saw the wrapped session: %+v %v", st, err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	m := tp.mark()
	if _, err := c.Lock(context.Background(), ipc.LockReq{All: true}); err != nil {
		t.Fatal(err)
	}
	tp.waitFor(ui.Format(ui.MsgOverlayTitle, ui.Vars{}), m)
	if _, err := c.Lock(context.Background(), ipc.LockReq{All: true, End: true}); err != nil {
		t.Fatal(err)
	}
	out := waitRun(t, res)
	if out.code == 0 {
		t.Fatalf("the child was not ended: exit %d", out.code)
	}
	if !strings.Contains(tp.output(), ui.Format(ui.MsgOverlayEnding, ui.Vars{})) {
		t.Error("the overlay did not show the ending line")
	}
}
