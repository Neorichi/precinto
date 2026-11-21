package hook_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/precinto/precinto/internal/hook"
	"github.com/precinto/precinto/internal/ipc"
	"github.com/precinto/precinto/internal/testkit"
)

// deadlineDaemon answers a locked, unlock-eligible gate, then allows, and
// keeps the unlock request and the deadline of the context it came with.
type deadlineDaemon struct {
	mu    sync.Mutex
	gates int
	req   ipc.UnlockReq
	ctxDL time.Time
	sent  bool
}

func (d *deadlineDaemon) Gate(context.Context, ipc.GateReq) (ipc.GateResp, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.gates++
	if d.gates == 1 {
		return ipc.GateResp{Verdict: ipc.VerdictBlock, State: "locked", RootIDs: []string{"root-acme"},
			UnlockEligible: true, Origin: ipc.OriginHuman}, nil
	}
	return ipc.GateResp{Verdict: ipc.VerdictAllow, State: "unlocked", RootIDs: []string{"root-acme"}}, nil
}
func (d *deadlineDaemon) Activity(context.Context, ipc.ActivityReq) error { return nil }
func (d *deadlineDaemon) Register(context.Context, ipc.RegisterReq) error { return nil }
func (d *deadlineDaemon) Unlock(ctx context.Context, r ipc.UnlockReq, _ ipc.UIHandler) (ipc.UnlockResp, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.req, d.sent = r, true
	d.ctxDL, _ = ctx.Deadline()
	return ipc.UnlockResp{Unlocked: []string{"root-acme"}}, nil
}
func (d *deadlineDaemon) Close() error { return nil }

// TestUnlockDeadlineIsRealTime (D77): the deadline of a hook-raised unlock
// is real time — the unlock context's own deadline, at most UnlockWait
// ahead of the system clock — whatever the hook's decision clock (Deps.Now)
// says, because the daemon checks it against its own clock: a decision
// clock decades away from the system clock still gets its unlock.
func TestUnlockDeadlineIsRealTime(t *testing.T) {
	const year = 365 * 24 * time.Hour
	wait := hook.Timings(hook.HostClaude, hook.UserPromptSubmit).UnlockWait
	for name, now := range map[string]time.Time{
		"epoch":                      testkit.Epoch,
		"30 years before epoch":      testkit.Epoch.Add(-30 * year),
		"70 years after epoch":       testkit.Epoch.Add(70 * year),
		"a year behind the system":   time.Now().Add(-year),
		"a year ahead of the system": time.Now().Add(year),
	} {
		t.Run(name, func(t *testing.T) {
			deps, _, _ := testDeps(t, nil)
			deps.Cfg.Policy.UnlockOnPrompt = true
			deps.Now = func() time.Time { return now }
			dd := &deadlineDaemon{}
			deps.Dial = func(context.Context) (hook.Daemon, error) { return dd, nil }
			deps.DialUnlock = deps.Dial
			ctx, cancel := context.WithTimeout(context.Background(), 85*time.Second)
			defer cancel()
			before := time.Now()
			d := hook.Handle(ctx, deps, hook.Payload{Host: hook.HostClaude, Label: "claude-code", Event: hook.UserPromptSubmit,
				SID: "00000000-0000-4000-8000-000000000001", PromptID: "00000000-0000-4000-8000-0000000000a1", Cwd: "/u/work/acme"})
			after := time.Now()
			dd.mu.Lock()
			defer dd.mu.Unlock()
			if !dd.sent {
				t.Fatalf("no unlock was raised: %+v", d)
			}
			if d.Verdict != ipc.VerdictAllow {
				t.Errorf("after the unlock: %+v, want allow", d)
			}
			dl := dd.req.Deadline
			if !dl.Equal(dd.ctxDL) {
				t.Errorf("deadline %v is not the unlock context's %v", dl, dd.ctxDL)
			}
			if dl.Before(before) || dl.After(after.Add(wait)) {
				t.Errorf("deadline %v not within real time [%v, %v] (decision clock %v)", dl, before, after.Add(wait), now)
			}
		})
	}
}
