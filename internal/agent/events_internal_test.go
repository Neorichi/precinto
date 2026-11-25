package agent

import (
	"context"
	"os"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/Neorichi/precinto/internal/ipc"
	"github.com/Neorichi/precinto/internal/platform"
	"github.com/Neorichi/precinto/internal/vault"
)

// CC-32: a single-flight unlock in progress shows as "unlocking" to a
// concurrent status; the folder's factor kinds are in status (CC-40).
func TestStatusShowsUnlocking(t *testing.T) {
	x := startTD(t, func(x *td, _ *Options) { // before serve's start-up factor load
		x.vaults.set(func(f *fakeVaults) {
			f.metas["root-acme"] = vault.Meta{ID: "root-acme", Factors: []vault.Factor{
				{Name: "recovery", Kind: vault.FactorRecovery}, {Name: "passphrase", Kind: vault.FactorPassphrase},
				{Name: "yubikey", Kind: vault.FactorPlugin}, {Name: "se", Kind: vault.FactorSE, GUI: true}}}
		})
	})
	c := x.dial()
	ctx := context.Background()
	state := func() ipc.VaultStatus {
		st, err := c.Status(ctx)
		if err != nil {
			t.Fatal(err)
		}
		for _, v := range st.Vaults {
			if v.VaultID == "root-acme" {
				return v
			}
		}
		t.Fatal("root-acme not in status")
		return ipc.VaultStatus{}
	}
	if v := state(); v.State != "locked" || !slices.Equal(v.Factors, []string{"se", "plugin", "passphrase"}) {
		t.Fatalf("before = %+v (factors in unlock order, never recovery)", v)
	}
	x.vaults.set(func(f *fakeVaults) { f.block = make(chan struct{}) })
	done := make(chan error, 1)
	go func() {
		cu := x.dial2()
		defer cu.Close()
		_, err := cu.Unlock(ctx, ipc.UnlockReq{RootIDs: []string{"root-acme"}, TTY: true}, nil)
		done <- err
	}()
	x.eventually("unlocking", func() bool { return state().State == "unlocking" })
	close(x.vaults.block)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if v := state(); v.State != "unlocked" {
		t.Fatalf("after = %+v", v)
	}
}

// dial2 is dial without t.Cleanup bookkeeping, safe from a goroutine.
func (x *td) dial2() *ipc.Client {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := ipc.Dial(ctx, ipc.DialOptions{Layout: x.h.Layout, Client: "test", Timeout: 5 * time.Second, Insecure: true})
	if err != nil {
		return nil
	}
	return c
}

// collect drains a subscription in the background.
type collected struct {
	mu  sync.Mutex
	evs []ipc.Event
}

func collect(ch <-chan ipc.Event) *collected {
	c := &collected{}
	go func() {
		for ev := range ch {
			c.mu.Lock()
			c.evs = append(c.evs, ev)
			c.mu.Unlock()
		}
	}()
	return c
}

func (c *collected) kinds() []ipc.EventKind {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []ipc.EventKind
	for _, ev := range c.evs {
		if ev.Kind != ipc.EventHeartbeat {
			out = append(out, ev.Kind)
		}
	}
	return out
}

func (c *collected) first() ipc.Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.evs) == 0 {
		return ipc.Event{}
	}
	return c.evs[0]
}

func (c *collected) ended() []ipc.Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []ipc.Event
	for _, ev := range c.evs {
		if ev.Kind == ipc.EventEnd {
			out = append(out, ev)
		}
	}
	return out
}

// D71: every subscription starts with the folder's state (with its factor
// kinds, CC-40), and EventEnd goes only to the subscriptions of the wrapper
// whose session ends: under a screen lock the idle wrapped session of a
// folder ends after screen_lock_hard_after while a busy one of the same
// folder keeps its turn (D24), so its wrapper must not hear the end.
func TestEndEventsAreAddressed(t *testing.T) {
	x := startTD(t)
	ctx := context.Background()
	self := x.dial()
	if _, err := x.unlockTTY(self, nil, "root-acme"); err != nil {
		t.Fatal(err)
	}
	type wrapperProc struct {
		peer  platform.Peer
		child platform.ProcInfo
		sid   string
		subs  *collected
	}
	mk := func(pid int, sid string) *wrapperProc {
		w := &wrapperProc{sid: sid}
		w.peer = platform.Peer{UID: os.Getuid(), PID: pid, Proc: platform.ProcInfo{ID: platform.ProcID{PID: pid, StartUS: int64(pid)}, PPID: 1, TTY: "/dev/ttys020", Exe: "/opt/precinto/bin/precinto"}}
		x.h.Procs.Add(w.peer.Proc)
		w.child = x.addProc(pid+1, pid, pid+1, "/opt/homebrew/bin/claude", "claude")
		x.setPeer(&w.peer, true)
		c := x.dial()
		if err := c.Register(ctx, ipc.RegisterReq{Harness: "claude-code", SID: sid, PID: w.child.ID.PID, Cwd: x.h.Root, Wrapper: true, WrapperPID: pid}); err != nil {
			t.Fatal(err)
		}
		sub, err := c.Subscribe(ctx, ipc.SubscribeReq{RootIDs: []string{"root-acme"}, SID: sid, Wrapper: true})
		if err != nil {
			t.Fatal(err)
		}
		w.subs = collect(sub)
		return w
	}
	idle, busy := mk(9100, sidA), mk(9200, sidB)
	x.setPeer(nil, true)
	for _, w := range []*wrapperProc{idle, busy} {
		if s := x.d.snap.Load().snap.Sessions[w.sid]; !s.Info.Wrapper || s.Info.WrapperPID != w.peer.Proc.ID {
			t.Fatalf("%s not registered as wrapped by its wrapper: %+v", w.sid, s.Info)
		}
		x.eventually("initial state", func() bool { return w.subs.first().Kind != "" })
		if ev := w.subs.first(); ev.Kind != ipc.EventUnlocked || !slices.Equal(ev.RootIDs, []string{"root-acme"}) || !slices.Equal(ev.Factors, []string{"se"}) {
			t.Fatalf("first event = %+v (one unlocked event naming the folder and its factors)", ev)
		}
	}
	// The busy session is mid-turn.
	if err := self.Activity(ctx, ipc.ActivityReq{Harness: "claude-code", SID: sidB, Kind: ipc.ActPrompt, PromptID: "p1"}); err != nil {
		t.Fatal(err)
	}
	x.eventually("busy", func() bool { return x.d.snap.Load().snap.Sessions[sidB].Busy })
	x.setScreen(platform.ScreenState{Locked: true, LockKnown: true})
	x.eventually("screen lock locks the folder", func() bool { return x.vaultState("root-acme") == VaultLocked })
	x.h.Clock.Advance(9 * time.Minute)
	_ = self.Activity(ctx, ipc.ActivityReq{Harness: "claude-code", SID: sidB, Kind: ipc.ActTool}) // still working
	x.d.apply(ctx, Input{Kind: InTick})                                                           // the machine has applied the activity before the clock moves
	x.h.Clock.Advance(7 * time.Minute)                                                            // 16 min of screen lock
	x.eventually("the idle session's wrapper hears the end", func() bool { return len(idle.subs.ended()) == 1 })
	time.Sleep(100 * time.Millisecond)
	if ev := idle.subs.ended()[0]; !slices.Equal(ev.SIDs, []string{sidA}) || ev.Reason != "screen" {
		t.Fatalf("end event = %+v", ev)
	}
	if got := busy.subs.ended(); len(got) != 0 {
		t.Fatalf("the busy session's wrapper got %+v (D71: addressed, never broadcast)", got)
	}
	if !slices.Contains(busy.subs.kinds(), ipc.EventLocked) {
		t.Fatalf("busy wrapper events = %v (it still hears the lock)", busy.subs.kinds())
	}
}
