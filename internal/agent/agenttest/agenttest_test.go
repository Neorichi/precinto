package agenttest_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/precinto/precinto/internal/agent/agenttest"
	"github.com/precinto/precinto/internal/config"
	"github.com/precinto/precinto/internal/ipc"
	"github.com/precinto/precinto/internal/platform"
	"github.com/precinto/precinto/internal/platform/fakeplatform"
	"github.com/precinto/precinto/internal/testkit"
	"github.com/precinto/precinto/internal/vault/vaulttest"
)

func TestStartGateLockSpawned(t *testing.T) {
	h := testkit.NewHome(t)
	a := agenttest.Start(t, h.Layout, h.Clock, h.Procs)
	c := a.Dial(t)
	ctx := context.Background()
	st, err := c.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Vaults) != 2 || st.Vaults[0].State != "locked" {
		t.Fatalf("status vaults = %+v (every vault locked at start)", st.Vaults)
	}
	g, err := c.Gate(ctx, ipc.GateReq{Harness: "claude-code", Host: "claude-code", Event: "UserPromptSubmit", SID: "00000000-0000-4000-8000-000000000001", Cwd: h.Root})
	if err != nil {
		t.Fatal(err)
	}
	if g.Verdict != ipc.VerdictBlock || !strings.Contains(g.UserMessage, "acme") {
		t.Fatalf("gate in a locked folder = %+v", g)
	}
	g, err = c.Gate(ctx, ipc.GateReq{Harness: "claude-code", Event: "PreToolUse", SID: "00000000-0000-4000-8000-000000000002", Cwd: h.HomeDir})
	if err != nil || g.Verdict != ipc.VerdictAllow {
		t.Fatalf("gate outside folders = %+v %v (unmanaged: allow)", g, err)
	}
	if _, err := c.Lock(ctx, ipc.LockReq{All: true}); err != nil {
		t.Fatal(err)
	}
	if sp := a.Spawned(); len(sp) == 0 || !slices.Equal(sp[0][1:], []string{"sweep", "--quiet"}) {
		t.Fatalf("spawned = %q (recovery + full sweep at start)", sp)
	}
	a.SetScreen(platform.ScreenState{Locked: true, LockKnown: true})
	time.Sleep(50 * time.Millisecond)
	st, _ = c.Status(ctx)
	if !st.ScreenWatch {
		t.Fatalf("screen watch = %v", st.ScreenWatch)
	}
}

func TestRegisterSubscribeAndStop(t *testing.T) {
	h := testkit.NewHome(t)
	a := agenttest.Start(t, h.Layout, h.Clock, h.Procs)
	c := a.Dial(t)
	ctx := context.Background()
	sub, err := c.Subscribe(ctx, ipc.SubscribeReq{RootIDs: []string{"root-acme"}, Wrapper: true})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case ev := <-sub:
		if ev.Kind != ipc.EventLocked {
			t.Fatalf("first event = %+v", ev)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no initial state")
	}
	// A fake harness process registers (the fake table is the daemon's).
	h.Procs.Add(platform.ProcInfo{ID: platform.ProcID{PID: 4242, StartUS: h.Clock.Now().UnixMicro()}, PPID: 1, Exe: "/opt/homebrew/bin/claude", Argv: []string{"claude"}})
	sid := "00000000-0000-4000-8000-000000000003"
	if err := c.Register(ctx, ipc.RegisterReq{Harness: "claude-code", SID: sid, PID: 4242, Cwd: h.Root}); err != nil {
		t.Fatal(err)
	}
	st, _ := c.Status(ctx)
	if len(st.Sessions) != 1 || st.Sessions[0].SID != sid || st.Sessions[0].State != "paused" {
		t.Fatalf("sessions = %+v", st.Sessions)
	}
	if err := c.Activity(ctx, ipc.ActivityReq{Harness: "claude-code", SID: sid, Kind: ipc.ActStop}); err != nil {
		t.Fatal(err)
	}
	// No vault exists in a bare layout: unlock fails cleanly.
	if _, err := c.Unlock(ctx, ipc.UnlockReq{RootIDs: []string{"root-acme"}, TTY: true}, nil); err == nil {
		t.Fatal("unlock without a vault succeeded")
	}
	// The process exits: the session goes away.
	h.Procs.Exit(4242, false)
	deadline := time.Now().Add(5 * time.Second)
	for {
		st, _ = c.Status(ctx)
		if len(st.Sessions) == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("session of an exited process kept: %+v", st.Sessions)
		}
		time.Sleep(10 * time.Millisecond)
	}
	a.Stop()
	a.Stop() // idempotent
	select {
	case _, ok := <-sub:
		for ok {
			_, ok = <-sub
		}
	case <-time.After(5 * time.Second):
		t.Fatal("subscription survived Stop")
	}
}

// CC-53: Client is a non-fatal dial, safe from any goroutine and after the
// agent stopped (an error, never a panic).
func TestClientNonFatal(t *testing.T) {
	h := testkit.NewHome(t)
	a := agenttest.Start(t, h.Layout, h.Clock, h.Procs)
	c, err := a.Client(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	done := make(chan error, 1)
	go func() {
		c, err := a.Client(context.Background())
		if err == nil {
			c.Close()
		}
		done <- err
	}()
	if err := <-done; err != nil {
		t.Fatalf("Client from another goroutine: %v", err)
	}
	a.Stop()
	if c, err := a.Client(context.Background()); err == nil {
		c.Close()
		t.Fatal("Client succeeded after the agent stopped")
	}
}

// CC-53: UnlockForTest unlocks a vault with the recovery factor.
func TestUnlockForTest(t *testing.T) {
	h := testkit.NewHome(t)
	fx := vaulttest.New(t, h.Base, "root-acme")
	a := agenttest.Start(t, h.Layout, h.Clock, h.Procs)
	a.UnlockForTest(t, []string{"root-acme"}, fx.Recovery.String())
	c := a.Dial(t)
	st, err := c.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	unlocked := false
	for _, v := range st.Vaults {
		unlocked = unlocked || (v.VaultID == "root-acme" && v.State == "unlocked")
	}
	if !unlocked {
		t.Fatalf("root-acme not unlocked: %+v", st.Vaults)
	}
}

// TestUnlockForTestWhateverTheClock (D77): the daemon's state machine runs
// on the clock the test gives it, while the deadline of a request is real
// time on both sides (UnlockForTest sends time.Now plus a minute, the
// daemon checks it with the system clock). So an unlock works with a daemon
// clock frozen decades or a year away from the system clock, and the grant
// still expires by the daemon's clock alone.
func TestUnlockForTestWhateverTheClock(t *testing.T) {
	const year = 365 * 24 * time.Hour
	for name, start := range map[string]time.Time{
		"30 years before epoch":      testkit.Epoch.Add(-30 * year),
		"70 years after epoch":       testkit.Epoch.Add(70 * year),
		"a year behind the system":   time.Now().Add(-year).Round(0),
		"a year ahead of the system": time.Now().Add(year).Round(0),
	} {
		t.Run(name, func(t *testing.T) {
			h := testkit.NewHome(t)
			fx := vaulttest.New(t, h.Base, "root-acme")
			clock := fakeplatform.NewClock(start)
			a := agenttest.Start(t, h.Layout, clock, h.Procs)
			a.UnlockForTest(t, []string{"root-acme"}, fx.Recovery.String())
			c := a.Dial(t)
			state := func() (string, string) {
				st, err := c.Status(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				for _, v := range st.Vaults {
					if v.VaultID == "root-acme" {
						return v.State, v.Reason
					}
				}
				return "", ""
			}
			if s, _ := state(); s != "unlocked" {
				t.Fatalf("root-acme %q after the unlock, want unlocked", s)
			}
			clock.Advance(16 * time.Minute) // past idle_soft on the daemon's clock only
			deadline := time.Now().Add(10 * time.Second)
			for {
				if s, why := state(); s == "locked" && why == "idle" {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("not locked at idle_soft of the daemon's clock")
				}
				time.Sleep(10 * time.Millisecond)
			}
		})
	}
}

// CC-53: a goroutine that outlives its test (a fake backend's dialer) gets
// an error from Client, never a panic: Client never touches the testing.T.
func TestClientAfterTheTestEnded(t *testing.T) {
	release := make(chan struct{})
	result := make(chan error, 1)
	t.Run("inner", func(t *testing.T) {
		h := testkit.NewHome(t)
		a := agenttest.Start(t, h.Layout, h.Clock, h.Procs)
		go func() {
			<-release
			defer func() {
				if r := recover(); r != nil {
					result <- fmt.Errorf("Client panicked after the test ended: %v", r)
				}
			}()
			c, err := a.Client(context.Background())
			if err == nil {
				c.Close()
				result <- errors.New("Client succeeded after the test and its agent ended")
				return
			}
			result <- nil
		}()
	})
	close(release) // the subtest, its cleanups and the agent are gone
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("Client hung after the test ended")
	}
}

// CC-15: agenttest's Pinentry is a stub: an unlock that would need
// pinentry (no terminal to relay to, passphrase factor) fails with no_ui
// and runs no program; a hook-raised one never gets that far.
func TestPinentryIsAStub(t *testing.T) {
	h := testkit.NewHome(t)
	vaulttest.New(t, h.Layout.Base, "root-acme") // passphrase + recovery factors
	cfg := h.Cfg
	cfg.Policy.UnlockOnPrompt = true
	if err := config.Save(h.Layout.ConfigFile, cfg); err != nil {
		t.Fatal(err)
	}
	if err := config.SavePinned(h.Layout.PolicyPinned, config.Pinned{Version: config.PinnedVersion, Config: cfg, MACs: map[string]string{}}); err != nil {
		t.Fatal(err)
	}
	a := agenttest.Start(t, h.Layout, h.Clock, h.Procs)
	c := a.Dial(t)
	ctx := context.Background()
	children := func() int {
		ps, err := platform.System().List()
		if err != nil {
			t.Fatal(err)
		}
		n := 0
		for _, p := range ps {
			if p.PPID == os.Getpid() && strings.Contains(strings.ToLower(filepath.Base(p.Exe)), "pinentry") {
				n++
			}
		}
		return n
	}
	before := children()
	_, err := c.Unlock(ctx, ipc.UnlockReq{RootIDs: []string{"root-acme"}, Factor: "passphrase", Deadline: time.Now().Add(time.Minute)}, nil)
	var e *ipc.Error
	if !errors.As(err, &e) || e.Code != ipc.CodeNoUI {
		t.Fatalf("unlock through pinentry = %v, want no_ui", err)
	}
	// A hook-raised unlock after a human prompt: no GUI factor without a
	// pinentry program, so no_ui before any dialog.
	h.Procs.Add(platform.ProcInfo{ID: platform.ProcID{PID: 4242, StartUS: h.Clock.Now().UnixMicro()}, PPID: 1, Exe: "/opt/homebrew/bin/claude", Argv: []string{"claude"}})
	sid := "00000000-0000-4000-8000-000000000005"
	if err := c.Register(ctx, ipc.RegisterReq{Harness: "claude-code", SID: sid, PID: 4242, Cwd: h.Root}); err != nil {
		t.Fatal(err)
	}
	a.SetScreen(platform.ScreenState{LockKnown: true, IdleKnown: true, HIDIdle: time.Second})
	time.Sleep(50 * time.Millisecond)
	if _, err := c.Gate(ctx, ipc.GateReq{Harness: "claude-code", Host: "claude-code", Event: "UserPromptSubmit", SID: sid, PromptID: "p1", Cwd: h.Root}); err != nil {
		t.Fatal(err)
	}
	_, err = c.Unlock(ctx, ipc.UnlockReq{RootIDs: []string{"root-acme"}, FromHook: true, SID: sid, Deadline: time.Now().Add(time.Minute)}, nil)
	if !errors.As(err, &e) || e.Code != ipc.CodeNoUI {
		t.Fatalf("hook-raised unlock = %v, want no_ui", err)
	}
	if children() != before {
		t.Fatal("a pinentry program ran")
	}
	st, _ := c.Status(ctx)
	for _, v := range st.Vaults {
		if v.State != "locked" {
			t.Fatalf("vault %s is %s", v.VaultID, v.State)
		}
	}
}

// D71 and CC-53 the way a wrapper uses the agent (the wrapper's own
// crossgroup test adds the PTY): UnlockForTest, a wrapped registration and
// subscription from Client, the initial unlocked state, the lock event and
// an end event addressed to this wrapper.
func TestWrapperFlow(t *testing.T) {
	h := testkit.NewHome(t)
	fx := vaulttest.New(t, h.Layout.Base, "root-acme")
	a := agenttest.Start(t, h.Layout, h.Clock, h.Procs)
	a.UnlockForTest(t, []string{"root-acme"}, fx.Recovery.String())
	ctx := context.Background()
	c, err := a.Client(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	child := platform.ProcInfo{ID: platform.ProcID{PID: 4343, StartUS: h.Clock.Now().UnixMicro()}, PPID: os.Getpid(), Exe: "/usr/local/bin/claude", Comm: "2.1.329"}
	h.Procs.Add(child)
	sid := "00000000-0000-4000-8000-000000000006"
	if err := c.Register(ctx, ipc.RegisterReq{Harness: "claude-code", SID: sid, PID: child.ID.PID, Cwd: h.Root, Wrapper: true, WrapperPID: os.Getpid(), Version: "2.1.329"}); err != nil {
		t.Fatal(err)
	}
	sub, err := c.Subscribe(ctx, ipc.SubscribeReq{RootIDs: []string{"root-acme"}, SID: sid, Wrapper: true})
	if err != nil {
		t.Fatal(err)
	}
	next := func(kind ipc.EventKind) ipc.Event {
		t.Helper()
		timeout := time.After(10 * time.Second)
		for {
			select {
			case ev, ok := <-sub:
				if !ok {
					t.Fatalf("subscription closed waiting for %s", kind)
				}
				if ev.Kind == kind {
					return ev
				}
				if ev.Kind != ipc.EventHeartbeat {
					t.Fatalf("got %+v waiting for %s", ev, kind)
				}
			case <-timeout:
				t.Fatalf("no %s event", kind)
			}
		}
	}
	if ev := next(ipc.EventUnlocked); !slices.Equal(ev.RootIDs, []string{"root-acme"}) || !slices.Equal(ev.Factors, []string{"passphrase"}) {
		t.Fatalf("initial event = %+v", ev)
	}
	st, err := c.Status(ctx)
	if err != nil || len(st.Sessions) != 1 || !st.Sessions[0].Wrapper || st.Sessions[0].Version != "2.1.329" {
		t.Fatalf("sessions = %+v %v", st.Sessions, err)
	}
	if _, err := c.Lock(ctx, ipc.LockReq{All: true}); err != nil {
		t.Fatal(err)
	}
	next(ipc.EventLocked)
	if _, err := c.Lock(ctx, ipc.LockReq{All: true, End: true}); err != nil {
		t.Fatal(err)
	}
	if ev := next(ipc.EventEnd); !slices.Equal(ev.SIDs, []string{sid}) {
		t.Fatalf("end event = %+v", ev)
	}
}
