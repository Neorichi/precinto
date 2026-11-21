package agent_test

import (
	"slices"
	"testing"
	"time"

	"github.com/precinto/precinto/internal/agent"
	"github.com/precinto/precinto/internal/config"
	"github.com/precinto/precinto/internal/ipc"
	"github.com/precinto/precinto/internal/platform"
	"github.com/precinto/precinto/internal/platform/fakeplatform"
)

var epoch = time.Date(2026, 11, 21, 9, 0, 0, 0, time.UTC)

const (
	rootA = "root-acme"
	rootB = "root-beta"
	sidW  = "00000000-0000-4000-8000-0000000000a1" // wrapped session
	sidU  = "00000000-0000-4000-8000-0000000000b2" // unwrapped session
)

func newM(t *testing.T, edit func(*config.Policy)) (*agent.Machine, *fakeplatform.Clock) {
	t.Helper()
	p := config.Default().Policy
	if edit != nil {
		edit(&p)
	}
	c := fakeplatform.NewClock(epoch)
	return agent.NewMachine(p, c), c
}

func kinds(acts []agent.Action) []agent.ActionKind {
	var k []agent.ActionKind
	for _, a := range acts {
		k = append(k, a.Kind)
	}
	return k
}

func has(acts []agent.Action, k agent.ActionKind) bool { return slices.Contains(kinds(acts), k) }

func vaultState(m *agent.Machine, id string) agent.VaultState {
	return m.Snapshot().Vaults[id].State
}

func unlock(m *agent.Machine, ids ...string) []agent.Action {
	return m.Apply(agent.Input{Kind: agent.InUnlock, Vaults: ids})
}

func wrapped(sid string, roots ...string) *agent.SessionInfo {
	return &agent.SessionInfo{Harness: "claude-code", SID: sid, Proc: platform.ProcID{PID: 4100, StartUS: 1},
		RootIDs: roots, Wrapper: true, WrapperPID: platform.ProcID{PID: 4000, StartUS: 1}, Registered: true}
}

func unwrapped(sid string, pid int, roots ...string) *agent.SessionInfo {
	return &agent.SessionInfo{Harness: "claude-code", SID: sid, Proc: platform.ProcID{PID: pid, StartUS: 1},
		RootIDs: roots, Registered: true, HooksSeen: true}
}

func gate(m *agent.Machine, ev agent.GateEvent, sid string, roots ...string) ipc.GateResp {
	return m.Gate(agent.GateQuery{Event: ev, SID: sid, RootIDs: roots, Origin: ipc.OriginHuman})
}

func TestEveryVaultLockedAtStart(t *testing.T) {
	m, _ := newM(t, nil)
	r := gate(m, agent.GatePrompt, "", rootA)
	if r.Verdict != ipc.VerdictBlock || r.State != "locked" || r.Reason != "start" || r.UserMessage == "" {
		t.Fatalf("unknown folder = %+v (locked, fail closed)", r)
	}
	if r := gate(m, agent.GateTool, "", rootA); r.Verdict != ipc.VerdictDeny || r.ModelMessage == "" {
		t.Fatalf("tool = %+v", r)
	}
	if r := gate(m, agent.GateTool, ""); r.Verdict != ipc.VerdictAllow {
		t.Fatalf("unmanaged = %+v", r)
	}
	if r := gate(m, agent.GateStart, "", rootA); r.Verdict != ipc.VerdictAllow || r.ModelMessage == "" {
		t.Fatalf("SessionStart never blocks: %+v", r)
	}
}

func TestUnlockActionsAndTTLClamp(t *testing.T) {
	m, _ := newM(t, nil)
	acts := m.Apply(agent.Input{Kind: agent.InUnlock, Vaults: []string{rootA}, TTL: 1000 * time.Hour})
	if !has(acts, agent.ActPublish) || !has(acts, agent.ActRestoreRoots) || !has(acts, agent.ActAuditCapsules) {
		t.Fatalf("unlock actions = %v", kinds(acts))
	}
	vs := m.Snapshot().Vaults[rootA]
	if vs.State != agent.VaultUnlocked || !vs.AbsDeadline.Equal(epoch.Add(8*time.Hour)) {
		t.Fatalf("vault = %+v (ttl clamped to max_unlock, S8)", vs)
	}
	if r := gate(m, agent.GatePrompt, "", rootA); r.Verdict != ipc.VerdictAllow {
		t.Fatalf("unlocked gate = %+v", r)
	}
	// The global vault is restored only on request (D36).
	acts = unlock(m, "global")
	if has(acts, agent.ActRestoreRoots) {
		t.Fatal("global vault auto-restored")
	}
}

func TestIdleLockOnlyOnVerifiedHumanInput(t *testing.T) {
	m, c := newM(t, nil)
	m.Apply(agent.Input{Kind: agent.InRegister, Session: wrapped(sidW, rootA)})
	m.Apply(agent.Input{Kind: agent.InRegister, Session: unwrapped(sidU, 4200, rootA)})
	unlock(m, rootA)
	step := func(d time.Duration) []agent.Action {
		c.Advance(d)
		return m.Apply(agent.Input{Kind: agent.InTick})
	}
	step(10 * time.Minute)
	// Wrapper keystrokes without the verified flag are dropped (D54).
	m.Apply(agent.Input{Kind: agent.InActivity, SID: sidW, Activity: ipc.ActInput})
	// Unwrapped sessions have no wrapper: their "input" never counts.
	m.Apply(agent.Input{Kind: agent.InActivity, SID: sidU, Activity: ipc.ActInput, FromWrapper: true})
	// Stop, StopFailure, idle prompts and tools never extend the unlock.
	for _, k := range []ipc.ActivityKind{ipc.ActStop, ipc.ActStopFailure, ipc.ActIdlePrompt, ipc.ActTool, ipc.ActInterrupt, ipc.ActPermission} {
		m.Apply(agent.Input{Kind: agent.InActivity, SID: sidU, Activity: k})
	}
	// Prompts whose recorded origin is automated or unknown do not either.
	for i, o := range []ipc.PromptOrigin{ipc.OriginAutomated, ipc.OriginUnknown} {
		id := []string{"p-auto", "p-unknown"}[i]
		m.Apply(agent.Input{Kind: agent.InGateOrigin, SID: sidU, PromptID: id, Origin: o})
		m.Apply(agent.Input{Kind: agent.InActivity, SID: sidU, PromptID: id, Activity: ipc.ActPrompt})
	}
	// A prompt with no recorded origin does not count.
	m.Apply(agent.Input{Kind: agent.InActivity, SID: sidU, PromptID: "never-gated", Activity: ipc.ActPrompt})
	acts := step(5 * time.Minute)
	if vaultState(m, rootA) != agent.VaultLocked || !has(acts, agent.ActWipeKey) || acts[0].Kind != agent.ActWipeKey {
		t.Fatalf("not locked at idle_soft: %v (SEC-27: the idle deadline never moves)", kinds(acts))
	}
	if m.Snapshot().Vaults[rootA].Reason != "idle" {
		t.Fatalf("reason = %q", m.Snapshot().Vaults[rootA].Reason)
	}

	// Verified wrapper input and human prompts do move it.
	unlock(m, rootA)
	step(14 * time.Minute)
	m.Apply(agent.Input{Kind: agent.InActivity, SID: sidW, Activity: ipc.ActEnter, FromWrapper: true})
	step(14 * time.Minute)
	if vaultState(m, rootA) != agent.VaultUnlocked {
		t.Fatal("verified wrapper input did not reset the idle clock")
	}
	m.Apply(agent.Input{Kind: agent.InGateOrigin, SID: sidU, PromptID: "p-human", Origin: ipc.OriginHuman})
	m.Apply(agent.Input{Kind: agent.InActivity, SID: sidU, PromptID: "p-human", Activity: ipc.ActPrompt})
	step(14 * time.Minute)
	if vaultState(m, rootA) != agent.VaultUnlocked {
		t.Fatal("a human prompt did not reset the idle clock")
	}
	// The record is consumed once.
	m.Apply(agent.Input{Kind: agent.InActivity, SID: sidU, PromptID: "p-human", Activity: ipc.ActPrompt})
	step(2 * time.Minute)
	if vaultState(m, rootA) != agent.VaultLocked {
		t.Fatal("a replayed prompt activity moved the idle clock")
	}
}

func TestGateOriginExpires(t *testing.T) {
	m, c := newM(t, nil)
	m.Apply(agent.Input{Kind: agent.InRegister, Session: unwrapped(sidU, 4200, rootA)})
	unlock(m, rootA)
	m.Apply(agent.Input{Kind: agent.InGateOrigin, SID: sidU, PromptID: "p1", Origin: ipc.OriginHuman})
	c.Advance(11 * time.Minute) // > busy_timeout (and > idle_soft? no: 11 < 15)
	m.Apply(agent.Input{Kind: agent.InTick})
	m.Apply(agent.Input{Kind: agent.InActivity, SID: sidU, PromptID: "p1", Activity: ipc.ActPrompt})
	c.Advance(5 * time.Minute)
	m.Apply(agent.Input{Kind: agent.InTick})
	if vaultState(m, rootA) != agent.VaultLocked {
		t.Fatal("an expired origin record moved the idle clock")
	}
}

func TestMaxUnlockAndExpiryNotice(t *testing.T) {
	m, c := newM(t, func(p *config.Policy) { p.IdleSoft = config.Duration(24 * time.Hour) })
	m.Apply(agent.Input{Kind: agent.InRegister, Session: wrapped(sidW, rootA)})
	unlock(m, rootA)
	var notices int
	for i := 0; i < 8*60; i++ {
		c.Advance(time.Minute)
		// Every Apply evaluates deadlines: collect the actions of both.
		acts := m.Apply(agent.Input{Kind: agent.InActivity, SID: sidW, Activity: ipc.ActInput, FromWrapper: true})
		acts = append(acts, m.Apply(agent.Input{Kind: agent.InTick})...)
		for _, a := range acts {
			if a.Kind == agent.ActNotifyExpiring {
				notices++
				if !a.Event.Deadline.Equal(epoch.Add(8 * time.Hour)) {
					t.Fatalf("notice deadline = %v", a.Event.Deadline)
				}
				if elapsed := c.Now().Sub(epoch); elapsed != 7*time.Hour+50*time.Minute {
					t.Fatalf("notice at %v, want 10 min before the limit", elapsed)
				}
			}
		}
		if i < 8*60-1 && vaultState(m, rootA) != agent.VaultUnlocked {
			t.Fatalf("locked early at %v", c.Now().Sub(epoch))
		}
	}
	if notices != 1 {
		t.Fatalf("expiry notices = %d, want exactly one (C8)", notices)
	}
	if vs := m.Snapshot().Vaults[rootA]; vs.State != agent.VaultLocked || vs.Reason != "limit" {
		t.Fatalf("after max_unlock: %+v (human input never extends the absolute deadline)", vs)
	}
	// --extend takes a fresh grant.
	unlock(m, rootA)
	c.Advance(7 * time.Hour)
	m.Apply(agent.Input{Kind: agent.InUnlock, Vaults: []string{rootA}, Extend: true})
	c.Advance(2 * time.Hour)
	m.Apply(agent.Input{Kind: agent.InTick})
	if vaultState(m, rootA) != agent.VaultUnlocked {
		t.Fatal("extend did not move the absolute deadline")
	}
	// A plain unlock of an unlocked vault does not.
	m.Apply(agent.Input{Kind: agent.InUnlock, Vaults: []string{rootA}})
	c.Advance(6*time.Hour + time.Minute)
	m.Apply(agent.Input{Kind: agent.InTick})
	if vaultState(m, rootA) != agent.VaultLocked {
		t.Fatal("re-unlocking extended the grant without --extend")
	}
}

func TestDeadlinesOnBothClocks(t *testing.T) {
	// Wall stepped back: the monotonic clock still fires (IM15).
	m, c := newM(t, nil)
	unlock(m, rootA)
	c.StepWall(-2 * time.Hour)
	c.Advance(15 * time.Minute)
	m.Apply(agent.Input{Kind: agent.InTick})
	if vaultState(m, rootA) != agent.VaultLocked {
		t.Fatal("wall step back delayed the idle lock")
	}
	// Machine slept: wall fires even though monotonic did not move.
	m2, c2 := newM(t, nil)
	unlock(m2, rootA)
	c2.Sleep(time.Hour)
	m2.Apply(agent.Input{Kind: agent.InTick})
	if vaultState(m2, rootA) != agent.VaultLocked {
		t.Fatal("sleep did not expire the idle deadline on the wall clock")
	}
}

func TestSleepJumpLocks(t *testing.T) {
	m, _ := newM(t, nil)
	unlock(m, rootA, rootB)
	acts := m.Apply(agent.Input{Kind: agent.InJump, Jump: platform.Jump{Wall: time.Hour}})
	if vaultState(m, rootA) != agent.VaultLocked || vaultState(m, rootB) != agent.VaultLocked {
		t.Fatal("sleep/wake did not lock every folder (D24)")
	}
	if acts[0].Kind != agent.ActWipeKey || acts[1].Kind != agent.ActWipeKey {
		t.Fatalf("keys not wiped first: %v", kinds(acts))
	}
	if m.Snapshot().Vaults[rootA].Reason != "sleep" {
		t.Fatal("reason")
	}
}

func TestScreenLockSoftAndHard(t *testing.T) {
	m, c := newM(t, nil)
	idle := unwrapped("00000000-0000-4000-8000-0000000000c1", 4301, rootA)
	busy := unwrapped("00000000-0000-4000-8000-0000000000c2", 4302, rootA)
	bg := unwrapped("00000000-0000-4000-8000-0000000000c3", 4303, rootA)
	bg.Background = true
	for _, s := range []*agent.SessionInfo{idle, busy, bg} {
		m.Apply(agent.Input{Kind: agent.InRegister, Session: s})
	}
	unlock(m, rootA)
	m.Apply(agent.Input{Kind: agent.InActivity, SID: busy.SID, Activity: ipc.ActPrompt})
	acts := m.Apply(agent.Input{Kind: agent.InScreenLocked})
	if vaultState(m, rootA) != agent.VaultLocked || m.Snapshot().Vaults[rootA].Reason != "screen" {
		t.Fatalf("screen lock did not lock at once: %v", kinds(acts))
	}
	// Screen unlock is advisory: it never unlocks (I6).
	m.Apply(agent.Input{Kind: agent.InScreenUnlocked})
	if vaultState(m, rootA) != agent.VaultLocked {
		t.Fatal("an OS event unlocked a folder")
	}
	m.Apply(agent.Input{Kind: agent.InScreenLocked})
	ended := map[string]bool{}
	for i := 0; i < 40; i++ {
		c.Advance(time.Minute)
		// keep the busy session busy (registry says so)
		acts := m.Apply(agent.Input{Kind: agent.InBusy, SID: busy.SID, Busy: true})
		for _, a := range append(acts, m.Apply(agent.Input{Kind: agent.InTick})...) {
			if a.Kind == agent.ActEndSessions {
				for _, s := range a.Sessions {
					ended[s.SID] = true
					if a.Grace != 8*time.Second {
						t.Fatalf("grace = %v", a.Grace)
					}
				}
				switch {
				case i+1 == 15 && !ended[idle.SID]:
					t.Fatalf("idle session not ended at 15 min")
				case ended[busy.SID] && i+1 < 30:
					t.Fatalf("busy session ended at %d min, before busy_grace", i+1)
				}
			}
		}
	}
	if !ended[idle.SID] || !ended[busy.SID] || ended[bg.SID] {
		t.Fatalf("ended = %v (background sessions are never ended, D25)", ended)
	}
}

func TestScreenLockDisabledByPolicy(t *testing.T) {
	m, _ := newM(t, func(p *config.Policy) { p.LockOnScreenLock = false })
	unlock(m, rootA)
	m.Apply(agent.Input{Kind: agent.InScreenLocked})
	if vaultState(m, rootA) != agent.VaultUnlocked {
		t.Fatal("lock_on_screen_lock=false still locked")
	}
}

func TestBusyGraceGating(t *testing.T) {
	for _, tc := range []struct {
		name      string
		lock      func(m *agent.Machine, c *fakeplatform.Clock)
		toolsOpen bool
	}{
		{"idle trigger", func(m *agent.Machine, c *fakeplatform.Clock) {
			// A long turn: tool hooks keep it busy, never the idle clock.
			for i := 0; i < 15; i++ {
				c.Advance(time.Minute)
				m.Apply(agent.Input{Kind: agent.InActivity, SID: sidU, Activity: ipc.ActTool})
			}
		}, true},
		{"manual lock", func(m *agent.Machine, c *fakeplatform.Clock) {
			m.Apply(agent.Input{Kind: agent.InLock, Vaults: []string{rootA}})
		}, false},
		{"manual lock --let-finish", func(m *agent.Machine, c *fakeplatform.Clock) {
			m.Apply(agent.Input{Kind: agent.InLock, Vaults: []string{rootA}, LetFinish: true})
		}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, c := newM(t, nil)
			m.Apply(agent.Input{Kind: agent.InRegister, Session: unwrapped(sidU, 4200, rootA)})
			unlock(m, rootA)
			m.Apply(agent.Input{Kind: agent.InActivity, SID: sidU, Activity: ipc.ActPrompt})
			tc.lock(m, c)
			if vaultState(m, rootA) != agent.VaultLocked {
				t.Fatal("not locked")
			}
			if r := gate(m, agent.GatePrompt, sidU, rootA); r.Verdict != ipc.VerdictBlock || r.State != "paused" {
				t.Fatalf("prompt = %+v (always blocked)", r)
			}
			want := ipc.VerdictDeny
			if tc.toolsOpen {
				want = ipc.VerdictAllow
			}
			for _, ev := range []agent.GateEvent{agent.GateTool, agent.GatePermission} {
				if r := gate(m, ev, sidU, rootA); r.Verdict != want {
					t.Fatalf("%s during the turn = %v, want %v", ev, r.Verdict, want)
				}
			}
			if r := gate(m, agent.GateCompact, sidU, rootA); (r.Verdict == ipc.VerdictAllow) != tc.toolsOpen {
				t.Fatalf("compaction = %v", r.Verdict)
			}
			if !tc.toolsOpen {
				return
			}
			// Grace ends with the turn (Stop) …
			m.Apply(agent.Input{Kind: agent.InActivity, SID: sidU, Activity: ipc.ActStop})
			if r := gate(m, agent.GateTool, sidU, rootA); r.Verdict != ipc.VerdictDeny {
				t.Fatalf("tool after Stop = %v", r.Verdict)
			}
		})
	}
	// … or at busy_grace.
	m, c := newM(t, nil)
	m.Apply(agent.Input{Kind: agent.InRegister, Session: unwrapped(sidU, 4200, rootA)})
	unlock(m, rootA)
	m.Apply(agent.Input{Kind: agent.InActivity, SID: sidU, Activity: ipc.ActPrompt})
	for i := 0; i < 15; i++ {
		c.Advance(time.Minute)
		m.Apply(agent.Input{Kind: agent.InActivity, SID: sidU, Activity: ipc.ActTool})
	}
	if r := gate(m, agent.GateTool, sidU, rootA); r.Verdict != ipc.VerdictAllow {
		t.Fatalf("tool right after the idle lock = %v (in-turn grace)", r.Verdict)
	}
	for i := 0; i < 31; i++ {
		c.Advance(time.Minute)
		m.Apply(agent.Input{Kind: agent.InActivity, SID: sidU, Activity: ipc.ActTool})
	}
	if r := gate(m, agent.GateTool, sidU, rootA); r.Verdict != ipc.VerdictDeny {
		t.Fatalf("tool after busy_grace = %v", r.Verdict)
	}
}

func TestAutomatedPromptsNeverEligible(t *testing.T) {
	m, _ := newM(t, func(p *config.Policy) { p.UnlockOnPrompt = true })
	for o, want := range map[ipc.PromptOrigin]bool{ipc.OriginHuman: true, ipc.OriginAutomated: false, ipc.OriginUnknown: false} {
		r := m.Gate(agent.GateQuery{Event: agent.GatePrompt, RootIDs: []string{rootA}, Origin: o})
		if r.Verdict != ipc.VerdictBlock || r.UnlockEligible != want {
			t.Fatalf("%s: %+v (automated prompts never raise a dialog, D26)", o, r)
		}
	}
	m2, _ := newM(t, nil) // unlock_on_prompt ships false (D60)
	if r := m2.Gate(agent.GateQuery{Event: agent.GatePrompt, RootIDs: []string{rootA}, Origin: ipc.OriginHuman}); r.UnlockEligible {
		t.Fatal("eligible with unlock_on_prompt=false")
	}
	m.Apply(agent.Input{Kind: agent.InScreenLocked})
	if r := m.Gate(agent.GateQuery{Event: agent.GatePrompt, RootIDs: []string{rootA}, Origin: ipc.OriginHuman}); r.UnlockEligible {
		t.Fatal("eligible while the screen is locked")
	}
}

func TestLockEndAndCompactionWait(t *testing.T) {
	m, _ := newM(t, nil)
	w := wrapped(sidW, rootA)
	u := unwrapped(sidU, 4200, rootA)
	cx := &agent.SessionInfo{Harness: "codex", SID: "00000000-0000-7000-8000-000000000001", Proc: platform.ProcID{PID: 4400, StartUS: 1}, RootIDs: []string{rootA}, Registered: true}
	comp := unwrapped("00000000-0000-4000-8000-0000000000d1", 4500, rootA)
	other := unwrapped("00000000-0000-4000-8000-0000000000e1", 4600, rootB)
	for _, s := range []*agent.SessionInfo{w, u, cx, comp, other} {
		m.Apply(agent.Input{Kind: agent.InRegister, Session: s})
	}
	unlock(m, rootA, rootB)
	m.Apply(agent.Input{Kind: agent.InActivity, SID: comp.SID, Activity: ipc.ActCompactBegin})
	acts := m.Apply(agent.Input{Kind: agent.InLock, Vaults: []string{rootA}, End: true})
	got := map[string]time.Duration{}
	for _, a := range acts {
		if a.Kind == agent.ActEndSessions {
			for _, s := range a.Sessions {
				got[s.SID] = a.Grace
			}
		}
	}
	if got[sidW] != 8*time.Second || got[sidU] != 8*time.Second || got[cx.SID] != 9*time.Second {
		t.Fatalf("ended = %v (grace max(8s, budget+6s))", got)
	}
	if _, ok := got[comp.SID]; ok {
		t.Fatal("a compacting session was ended without --force")
	}
	if _, ok := got[other.SID]; ok || vaultState(m, rootB) != agent.VaultUnlocked {
		t.Fatal("lock --root reached another folder")
	}
	if m.Snapshot().Sessions[sidW].State != agent.SessionEnding {
		t.Fatal("ending state")
	}
	// Compaction ends: the deferred end follows.
	acts = m.Apply(agent.Input{Kind: agent.InActivity, SID: comp.SID, Activity: ipc.ActCompactEnd})
	if !has(acts, agent.ActEndSessions) {
		t.Fatal("deferred end not emitted after compaction ended")
	}
	// A compaction that never ends is waited for at most 5 min.
	m2, c2 := newM(t, nil)
	m2.Apply(agent.Input{Kind: agent.InRegister, Session: comp})
	unlock(m2, rootA)
	m2.Apply(agent.Input{Kind: agent.InActivity, SID: comp.SID, Activity: ipc.ActCompactBegin})
	m2.Apply(agent.Input{Kind: agent.InLock, All: true, End: true})
	c2.Advance(4 * time.Minute)
	if has(m2.Apply(agent.Input{Kind: agent.InTick}), agent.ActEndSessions) {
		t.Fatal("ended before the compaction wait")
	}
	c2.Advance(time.Minute)
	if !has(m2.Apply(agent.Input{Kind: agent.InTick}), agent.ActEndSessions) {
		t.Fatal("not ended after 5 min of compaction")
	}
	// --force does not wait.
	m3, _ := newM(t, nil)
	m3.Apply(agent.Input{Kind: agent.InRegister, Session: comp})
	m3.Apply(agent.Input{Kind: agent.InActivity, SID: comp.SID, Activity: ipc.ActCompactBegin})
	if !has(m3.Apply(agent.Input{Kind: agent.InLock, All: true, End: true, Force: true}), agent.ActEndSessions) {
		t.Fatal("--force waited for compaction")
	}
}

func TestIdleHard(t *testing.T) {
	m, c := newM(t, nil)
	m.Apply(agent.Input{Kind: agent.InRegister, Session: unwrapped(sidU, 4200, rootA)})
	unlock(m, rootA)
	var at time.Duration
	for i := 1; i <= 70 && at == 0; i++ {
		c.Advance(time.Minute)
		if has(m.Apply(agent.Input{Kind: agent.InTick}), agent.ActEndSessions) {
			at = c.Now().Sub(epoch)
		}
	}
	if at != 60*time.Minute {
		t.Fatalf("idle_hard ended the session at %v, want 60 min", at)
	}
	m2, c2 := newM(t, func(p *config.Policy) { p.IdleHard = 0 })
	m2.Apply(agent.Input{Kind: agent.InRegister, Session: unwrapped(sidU, 4200, rootA)})
	unlock(m2, rootA)
	c2.Advance(10 * time.Hour)
	if has(m2.Apply(agent.Input{Kind: agent.InTick}), agent.ActEndSessions) {
		t.Fatal(`idle_hard "0" means never`)
	}
}

func TestUngatedSessionsEndedAtLock(t *testing.T) {
	m, _ := newM(t, nil)
	unlock(m, rootA)
	scan := &agent.SessionInfo{Harness: "claude-code", SID: sidU, Proc: platform.ProcID{PID: 4700, StartUS: 1}, RootIDs: []string{rootA}}
	if acts := m.Apply(agent.Input{Kind: agent.InUngated, Session: scan}); has(acts, agent.ActEndSessions) {
		t.Fatal("ungated session ended while its folder is unlocked")
	}
	acts := m.Apply(agent.Input{Kind: agent.InLock, Vaults: []string{rootA}})
	if !has(acts, agent.ActEndSessions) {
		t.Fatalf("ungated session not ended at lock: %v (D52)", kinds(acts))
	}
	// Found while the folder is already locked: ended at once.
	m2, _ := newM(t, nil)
	if !has(m2.Apply(agent.Input{Kind: agent.InUngated, Session: scan}), agent.ActEndSessions) {
		t.Fatal("ungated session in a locked folder not ended")
	}
	// A registration (hooks work after all) makes it a gated session.
	m3, _ := newM(t, nil)
	unlock(m3, rootA)
	m3.Apply(agent.Input{Kind: agent.InUngated, Session: scan})
	m3.Apply(agent.Input{Kind: agent.InRegister, Session: unwrapped(sidU, 4700, rootA)})
	if has(m3.Apply(agent.Input{Kind: agent.InLock, Vaults: []string{rootA}}), agent.ActEndSessions) {
		t.Fatal("a registered session was ended by a plain lock")
	}
}

func TestRegisterMergesWrapperAndHook(t *testing.T) {
	m, _ := newM(t, nil)
	proc := platform.ProcID{PID: 4100, StartUS: 1}
	m.Apply(agent.Input{Kind: agent.InRegister, Session: &agent.SessionInfo{Harness: "claude-code", Proc: proc, RootIDs: []string{rootA}, Wrapper: true, WrapperPID: platform.ProcID{PID: 4000, StartUS: 1}, Registered: true}})
	m.Apply(agent.Input{Kind: agent.InRegister, Session: &agent.SessionInfo{Harness: "claude-code", SID: sidW, Proc: proc, RootIDs: []string{rootB}, Registered: true, HooksSeen: true}})
	snap := m.Snapshot()
	if len(snap.Sessions) != 1 {
		t.Fatalf("sessions = %v", snap.Sessions)
	}
	s := snap.Sessions[sidW]
	if !s.Info.Wrapper || !s.Info.HooksSeen || !slices.Contains(s.Info.RootIDs, rootA) || !slices.Contains(s.Info.RootIDs, rootB) {
		t.Fatalf("merged = %+v (roots are sticky, the wrapper flag is kept)", s.Info)
	}
	// Paused while any of its folders is locked (multi-root, UX18).
	unlock(m, rootA)
	if m.Snapshot().Sessions[sidW].State != agent.SessionPaused {
		t.Fatal("a session with a locked folder is running")
	}
	unlock(m, rootB)
	if m.Snapshot().Sessions[sidW].State != agent.SessionRunning {
		t.Fatal("not running with every folder unlocked")
	}
	m.Apply(agent.Input{Kind: agent.InUnregister, SID: sidW})
	if len(m.Snapshot().Sessions) != 0 {
		t.Fatal("unregister")
	}
}

func TestSharedIdleClock(t *testing.T) {
	m, c := newM(t, func(p *config.Policy) { p.PerRootAuth = false })
	m.Apply(agent.Input{Kind: agent.InRegister, Session: wrapped(sidW, rootA)})
	unlock(m, rootA, rootB)
	c.Advance(14 * time.Minute)
	m.Apply(agent.Input{Kind: agent.InActivity, SID: sidW, Activity: ipc.ActInput, FromWrapper: true})
	c.Advance(14 * time.Minute)
	m.Apply(agent.Input{Kind: agent.InTick})
	if vaultState(m, rootB) != agent.VaultUnlocked {
		t.Fatal("per_root_auth=false: folders do not share one idle clock")
	}
}

func TestSnapshotIsACopyAndNextDeadline(t *testing.T) {
	m0, _ := newM(t, nil)
	if _, ok := m0.NextDeadline(); ok {
		t.Fatal("deadline with everything locked and no session")
	}
	m, c := newM(t, nil)
	m.Apply(agent.Input{Kind: agent.InRegister, Session: wrapped(sidW, rootA)})
	if next, ok := m.NextDeadline(); !ok || !next.Equal(epoch.Add(60*time.Minute)) {
		t.Fatalf("paused session: NextDeadline = %v %v, want idle_hard", next, ok)
	}
	unlock(m, rootA)
	s := m.Snapshot()
	s.Sessions[sidW].Info.RootIDs[0] = "mutated"
	s.Vaults[rootA] = agent.VaultSnapshot{}
	if m.Snapshot().Sessions[sidW].Info.RootIDs[0] != rootA || m.Snapshot().Vaults[rootA].State != agent.VaultUnlocked {
		t.Fatal("Snapshot shares memory with the machine")
	}
	next, ok := m.NextDeadline()
	if !ok || !next.Equal(epoch.Add(15*time.Minute)) {
		t.Fatalf("NextDeadline = %v %v, want the idle deadline", next, ok)
	}
	if !m.Snapshot().Vaults[rootA].IdleDeadline.Equal(next) {
		t.Fatal("IdleDeadline")
	}
	c.Advance(15 * time.Minute)
	m.Apply(agent.Input{Kind: agent.InTick})
	if vaultState(m, rootA) != agent.VaultLocked {
		t.Fatal("not locked at NextDeadline")
	}
}

func TestPolicyChangeApplies(t *testing.T) {
	m, c := newM(t, nil)
	unlock(m, rootA)
	p := config.Default().Policy
	p.IdleSoft = config.Duration(5 * time.Minute)
	m.Apply(agent.Input{Kind: agent.InPolicy, Policy: &p, Vaults: []string{rootA, "root-new"}})
	if _, ok := m.Snapshot().Vaults["root-new"]; !ok || vaultState(m, "root-new") != agent.VaultLocked {
		t.Fatal("a new folder must start locked")
	}
	c.Advance(5 * time.Minute)
	m.Apply(agent.Input{Kind: agent.InTick})
	if vaultState(m, rootA) != agent.VaultLocked {
		t.Fatal("a stricter idle_soft did not apply at once")
	}
}
