package agent_test

import (
	"strings"
	"testing"
	"time"

	"github.com/Neorichi/precinto/internal/agent"
	"github.com/Neorichi/precinto/internal/config"
	"github.com/Neorichi/precinto/internal/ipc"
	"github.com/Neorichi/precinto/internal/platform"
	"github.com/Neorichi/precinto/internal/platform/fakeplatform"
)

func TestClampTTL(t *testing.T) {
	p := config.Default().Policy
	for _, tc := range []struct{ ttl, want time.Duration }{
		{0, 8 * time.Hour}, {-time.Hour, 8 * time.Hour}, {time.Hour, time.Hour},
		{8 * time.Hour, 8 * time.Hour}, {1000 * time.Hour, 8 * time.Hour},
	} {
		if got := agent.ClampTTL(p, tc.ttl); got != tc.want {
			t.Errorf("ClampTTL(%v) = %v, want %v", tc.ttl, got, tc.want)
		}
	}
	p.MaxUnlock = config.Duration(48 * time.Hour)
	if got := agent.ClampTTL(p, 1000*time.Hour); got != 24*time.Hour {
		t.Errorf("cap = %v, want 24 h (S8)", got)
	}
	p.MaxUnlock = 0
	if got := agent.ClampTTL(p, 0); got != 8*time.Hour {
		t.Errorf("zero max_unlock = %v (never unlimited)", got)
	}
}

func TestKillGrace(t *testing.T) {
	for budget, want := range map[time.Duration]time.Duration{
		0: 8 * time.Second, 1500 * time.Millisecond: 8 * time.Second, 3 * time.Second: 9 * time.Second,
		60 * time.Second: 66 * time.Second, 5 * time.Minute: 70 * time.Second, -time.Second: 8 * time.Second,
	} {
		if got := agent.KillGrace(budget); got != want {
			t.Errorf("KillGrace(%v) = %v, want %v", budget, got, want)
		}
	}
}

func TestRateLimiter(t *testing.T) {
	c := fakeplatform.NewClock(epoch)
	r := agent.NewRateLimiter(config.Default().Policy, c)
	for i := 0; i < 3; i++ {
		if ok, _ := r.Allow(rootA, false); !ok {
			t.Fatalf("prompt %d refused", i)
		}
	}
	ok, wait := r.Allow(rootA, false)
	if ok || wait <= 0 || wait > time.Minute {
		t.Fatalf("4th prompt in a minute = %v %v (3/min, D27)", ok, wait)
	}
	if ok, _ := r.Allow(rootB, false); !ok {
		t.Fatal("limits are per folder")
	}
	c.Advance(time.Minute)
	if ok, _ := r.Allow(rootA, false); !ok {
		t.Fatal("window did not slide")
	}
	// A cancel backs off 30 s; a cancel in a hook also stops hook prompts
	// for 10 min.
	c.Advance(time.Minute)
	r.Cancelled(rootA, true)
	if ok, wait := r.Allow(rootA, false); ok || wait != 30*time.Second {
		t.Fatalf("after cancel = %v %v", ok, wait)
	}
	c.Advance(31 * time.Second)
	if ok, _ := r.Allow(rootA, false); !ok {
		t.Fatal("terminal prompt refused after the back-off")
	}
	if ok, wait := r.Allow(rootA, true); ok || wait <= 0 {
		t.Fatalf("hook prompt during the cooldown = %v %v", ok, wait)
	}
	c.Advance(10 * time.Minute)
	if ok, _ := r.Allow(rootA, true); !ok {
		t.Fatal("hook prompt refused after the cooldown")
	}
	// A terminal cancel does not start the hook cooldown.
	r.Cancelled(rootB, false)
	c.Advance(31 * time.Second)
	if ok, _ := r.Allow(rootB, true); !ok {
		t.Fatal("terminal cancel blocked hook prompts")
	}
	// Zero prompts per minute means none (D62).
	p := config.Default().Policy
	p.PromptRatePerMinute = 0
	if ok, _ := agent.NewRateLimiter(p, c).Allow(rootA, false); ok {
		t.Fatal("prompt_rate_per_minute=0 allowed a prompt")
	}
}

// ancestry helpers: nearest first.
func proc(pid int, exe string, argv ...string) platform.ProcInfo {
	return platform.ProcInfo{ID: platform.ProcID{PID: pid, StartUS: int64(pid)}, Exe: exe, Argv: argv, PPID: pid - 1}
}

func peerWith(tty string) platform.Peer {
	return platform.Peer{UID: 501, PID: 7000, Proc: platform.ProcInfo{ID: platform.ProcID{PID: 7000, StartUS: 7000}, Exe: "/usr/local/bin/precinto", TTY: tty}}
}

func TestAuthorize(t *testing.T) {
	shell := []platform.ProcInfo{proc(6000, "/bin/zsh", "-zsh"), proc(5000, "/Applications/iTerm.app/Contents/MacOS/iTerm2")}
	underClaude := append([]platform.ProcInfo{proc(6500, "/bin/sh", "sh", "-c", "precinto unlock"), proc(6400, "/Users/x/.local/share/claude/versions/2.1.329")}, shell...)
	underCodexNode := append([]platform.ProcInfo{proc(6500, "/usr/bin/env"), proc(6400, "/opt/homebrew/bin/node", "node", "/opt/homebrew/lib/node_modules/@openai/codex/bin/codex.js")}, shell...)
	underClaudeBin := append([]platform.ProcInfo{proc(6400, "/opt/homebrew/bin/claude", "claude")}, shell...)
	daemonWorker := []platform.ProcInfo{{ID: platform.Self(), PPID: 1, Exe: "/usr/local/bin/precinto"}}
	tty, noTTY := peerWith("/dev/ttys003"), peerWith("")

	ok := func(e *ipc.Error) bool { return e == nil }
	refusedAgent := func(e *ipc.Error) bool {
		return e != nil && e.Code == ipc.CodeAgentContext && strings.Contains(e.Msg, "AI agent")
	}
	for _, tc := range []struct {
		name     string
		peer     platform.Peer
		anc      []platform.ProcInfo
		op       ipc.Op
		purpose  string
		roots    []string
		sessRoot []string
		want     func(*ipc.Error) bool
	}{
		{"user unlocks any folder", tty, shell, ipc.OpUnlock, "", []string{rootA, rootB}, nil, ok},
		{"agent unlocks its own folder", tty, underClaude, ipc.OpUnlock, "", []string{rootA}, []string{rootA}, ok},
		{"agent unlocks another folder", tty, underClaude, ipc.OpUnlock, "", []string{rootB}, []string{rootA}, refusedAgent},
		{"codex via node script", tty, underCodexNode, ipc.OpUnlock, "", []string{rootB}, []string{rootA}, refusedAgent},
		{"claude binary on PATH", tty, underClaudeBin, ipc.OpUnlock, "", []string{rootB}, nil, refusedAgent},
		{"agent factor add", tty, underClaude, ipc.OpFactorAdd, "", nil, nil, refusedAgent},
		{"agent vault repair", tty, underClaude, ipc.OpVaultRepair, "", []string{rootA}, []string{rootA}, refusedAgent},
		{"agent policy confirm", tty, underClaude, ipc.OpPolicy, "", nil, nil, refusedAgent},
		{"no tty factor add (D59)", noTTY, shell, ipc.OpFactorAdd, "", nil, nil, refusedAgent},
		{"no tty vault repair", noTTY, shell, ipc.OpVaultRepair, "", []string{rootA}, nil, refusedAgent},
		{"user factor add", tty, shell, ipc.OpFactorAdd, "", nil, nil, ok},
		{"agent keys of its folder", tty, underClaude, ipc.OpKeys, ipc.PurposeRestore, []string{rootA}, []string{rootA}, ok},
		{"agent keys of another folder", tty, underClaude, ipc.OpKeys, ipc.PurposeCat, []string{rootB}, []string{rootA}, refusedAgent},
		{"no tty targeted restore", noTTY, shell, ipc.OpKeys, ipc.PurposeRestore, []string{rootA}, nil, ok},
		{"worker is never an agent", noTTY, append(daemonWorker, underClaude...), ipc.OpFactorAdd, "", nil, nil, ok},
		{"lock is always allowed", tty, underClaude, ipc.OpLock, "", []string{rootB}, nil, ok},
	} {
		if got := agent.Authorize(tc.peer, tc.anc, tc.op, tc.purpose, tc.roots, tc.sessRoot); !tc.want(got) {
			t.Errorf("%s: %v", tc.name, got)
		}
	}
	// The daemon's own process (in-process clients) is trusted.
	self := platform.Peer{UID: 501, PID: platform.Self().PID}
	if e := agent.Authorize(self, underClaude, ipc.OpFactorAdd, "", nil, nil); e != nil {
		t.Fatalf("in-process peer: %v", e)
	}
}

func TestGateFromSnapshot(t *testing.T) {
	p := config.Default().Policy
	s := &agent.Snapshot{At: epoch, Vaults: map[string]agent.VaultSnapshot{
		rootA: {State: agent.VaultUnlocked},
		rootB: {State: agent.VaultLocked, Reason: "idle"},
	}, Sessions: map[string]agent.SessionSnapshot{
		sidU: {State: agent.SessionPaused, Busy: true, BusyAtLock: true, LockedAt: epoch.Add(-time.Minute)},
	}}
	q := func(ev agent.GateEvent, sid string, roots ...string) ipc.GateResp {
		return agent.GateFromSnapshot(s, p, agent.GateQuery{Event: ev, SID: sid, RootIDs: roots})
	}
	if r := q(agent.GatePrompt, "", rootA); r.Verdict != ipc.VerdictAllow || r.State != "unlocked" {
		t.Fatalf("unlocked = %+v", r)
	}
	r := q(agent.GatePrompt, "", rootA, rootB)
	if r.Verdict != ipc.VerdictBlock || r.Reason != "idle" || !strings.Contains(r.UserMessage, "idle 15 min") || !strings.Contains(r.UserMessage, rootB) {
		t.Fatalf("one locked folder blocks: %+v", r)
	}
	if r := q(agent.GatePrompt, "", "root-unknown"); r.Verdict != ipc.VerdictBlock {
		t.Fatalf("unknown folder = %+v", r)
	}
	if r := q(agent.GateTool, sidU, rootB); r.Verdict != ipc.VerdictAllow || r.State != "paused" {
		t.Fatalf("in-turn tool = %+v", r)
	}
	s.At = epoch.Add(31 * time.Minute)
	if r := q(agent.GateTool, sidU, rootB); r.Verdict != ipc.VerdictDeny || !strings.Contains(r.ModelMessage, "Do not retry") {
		t.Fatalf("after busy_grace = %+v", r)
	}
	if r := q(agent.GateCompact, "", rootB); r.Verdict != ipc.VerdictBlock || !strings.Contains(r.UserMessage, "compaction") {
		t.Fatalf("compaction = %+v", r)
	}
	if r := q(agent.GateEvent("SomethingNew"), "", rootB); r.Verdict != ipc.VerdictBlock {
		t.Fatalf("unknown event = %+v (gated like a prompt)", r)
	}
	if r := agent.GateFromSnapshot(nil, p, agent.GateQuery{Event: agent.GatePrompt, RootIDs: []string{rootA}}); r.Verdict != ipc.VerdictBlock {
		t.Fatalf("nil snapshot = %+v (fail closed)", r)
	}
}
