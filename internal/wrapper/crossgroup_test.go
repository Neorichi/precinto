//go:build crossgroup && (darwin || linux)

package wrapper_test

// Cross-group tests: the wrapper against the in-process daemon
// (internal/agent/agenttest, G2) over a real vault (vaulttest, G1). Like
// the unit suite, they use the real internal/platform (Identify,
// SignalGroup).

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/Neorichi/precinto/internal/agent/agenttest"
	"github.com/Neorichi/precinto/internal/harness"
	"github.com/Neorichi/precinto/internal/ipc"
	"github.com/Neorichi/precinto/internal/platform"
	"github.com/Neorichi/precinto/internal/testkit"
	"github.com/Neorichi/precinto/internal/ui"
	"github.com/Neorichi/precinto/internal/vault/vaulttest"
	"github.com/Neorichi/precinto/internal/wrapper"
)

func init() {
	// The real daemon beats every second; the production timeout (2 s,
	// SPEC §15.3) plus room for a loaded machine.
	testHeartbeat = 3 * time.Second
}

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
	child, sibling := newProbe(t), newProbe(t)
	testSibling(t, bins, sibling)
	r := startRig(t, wrapper.ProxyOptions{}, child, "-ignore-term")
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
}

// Daemon dials the daemon for a wrapper goroutine (the subscription and its
// redial after a loss, the request connection): an error, never a t.Fatal,
// also after the test ended (CC-53).
func (b *agentBackend) Daemon(ctx context.Context) (wrapper.Daemon, error) {
	b.record("Daemon")
	c, err := b.agent.Client(ctx)
	if err != nil {
		return nil, err
	}
	return c, nil
}

func (b *agentBackend) RecordLaunch(ctx context.Context, plan harness.LaunchPlan, child platform.ProcID) error {
	b.home.Procs.Add(platform.ProcInfo{ID: child, PPID: os.Getpid(), Exe: "/usr/local/bin/claude", Comm: "2.1.329"})
	b.home.Procs.SetCwd(child.PID, b.home.Root)
	return b.fakeBackend.RecordLaunch(ctx, plan, child)
}

// TestCrossgroupRunAgainstTheDaemon drives Run through the real protocol
// (SEC-30 ended by `lock --end`): the folder's vault is unlocked before the
// launch, so the subscription starts unlocked (D71); the wrapper registers
// its child; `precinto lock` shows the lock screen; `precinto lock --end`
// ends the child and the helper it left in its own session, while a
// process of the test's session survives. For the PTY child and the
// direct-mode (--no-pty) child.
func TestCrossgroupRunAgainstTheDaemon(t *testing.T) {
	t.Run("pty", func(t *testing.T) { runAgainstTheDaemon(t, false) })
	t.Run("direct", func(t *testing.T) { runAgainstTheDaemon(t, true) })
}

func runAgainstTheDaemon(t *testing.T, direct bool) {
	bins := helpers(t)
	h := testkit.NewHome(t)
	rootID := h.Cfg.Roots[0].ID
	fx := vaulttest.New(t, h.Layout.Base, rootID)
	a := agenttest.Start(t, h.Layout, h.Clock, h.Procs)
	h.Procs.Add(platform.ProcInfo{ID: platform.Self(), Exe: "/usr/local/bin/precinto"})
	a.UnlockForTest(t, []string{rootID}, fx.Recovery.String())

	childLife, sibLife := newProbe(t), newProbe(t)
	testSibling(t, bins, sibLife)

	plan := managedPlan(harness.ClaudeCode, bins.childWithProbe()...)
	plan.Roots = h.Cfg.Roots
	fb := newFakeBackend(plan)
	fb.lease = &fakeLease{files: []*os.File{childLife.w}}
	b := &agentBackend{fakeBackend: fb, agent: a, home: h}
	tp := newTerm(t, 100, 30)
	o := runOptions(t, tp, fb, &syncBuffer{})
	o.Backend, o.Env = b, h.Env
	typeKeys := tp.typeKeys
	var pr *pipeReader
	if direct {
		inR, inW, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		outR, outW, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = inW.Close(); _ = inR.Close(); _ = outW.Close(); _ = outR.Close() })
		o.NoPTY, o.Stdin, o.Stdout = true, inR, outW
		pr = newPipeReader(t, outR)
		typeKeys = func(s string) {
			t.Helper()
			if _, err := inW.Write([]byte(s)); err != nil {
				t.Fatal(err)
			}
		}
	}
	res := startRun(t, o)
	if direct {
		pr.waitForRe(readyRe)
	} else {
		tp.waitForRe(readyRe, 0)
	}
	fb.waitLaunched(t)
	childLife.handOff()
	typeKeys("g")
	if direct {
		pr.waitFor("GRANDCHILD pid=")
	} else {
		tp.waitFor("GRANDCHILD pid=", 0)
	}

	c := a.Dial(t)
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
	if !direct {
		tp.waitFor(ui.Format(ui.MsgOverlayTitle, ui.Vars{}), m)
	}
	if _, err := c.Lock(context.Background(), ipc.LockReq{All: true, End: true}); err != nil {
		t.Fatal(err)
	}
	out := waitRun(t, res)
	if out.code != 143 || out.err != nil {
		t.Fatalf("Run = %d, %v; want 143 (the child ended on SIGTERM)", out.code, out.err)
	}
	if !childLife.closedWithin(waitTimeout) {
		t.Fatal("the helper the child left in its own session survived lock --end")
	}
	if sibLife.closedWithin(300 * time.Millisecond) {
		t.Fatal("a process of the test's own session was killed")
	}
	if !direct {
		tp.waitFor(ui.Format(ui.MsgOverlayEnding, ui.Vars{}), m)
	}
}
