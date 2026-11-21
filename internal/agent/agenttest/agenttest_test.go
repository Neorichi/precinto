package agenttest_test

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/precinto/precinto/internal/agent/agenttest"
	"github.com/precinto/precinto/internal/ipc"
	"github.com/precinto/precinto/internal/platform"
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
