package agent

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/Neorichi/precinto/internal/harness/claude"
	"github.com/Neorichi/precinto/internal/ipc"
	"github.com/Neorichi/precinto/internal/paths"
	"github.com/Neorichi/precinto/internal/platform"
	"github.com/Neorichi/precinto/internal/vault"
)

const (
	sidA = "00000000-0000-4000-8000-000000000a01"
	sidB = "00000000-0000-4000-8000-000000000b01"
)

func TestDaemonGateFailsClosed(t *testing.T) {
	x := startTD(t)
	c := x.dial()
	ctx := context.Background()
	root := x.h.Root
	for _, ev := range []string{"UserPromptSubmit", "PreToolUse", "PreCompact", "PermissionRequest", "beforeSubmitPrompt", "Unknown"} {
		g, err := c.Gate(ctx, ipc.GateReq{Harness: "claude-code", Host: "claude-code", Event: ev, SID: sidA, Cwd: root})
		if err != nil || g.Verdict == ipc.VerdictAllow {
			t.Fatalf("%s in a locked folder = %+v %v", ev, g, err)
		}
		if !strings.Contains(g.UserMessage+g.ModelMessage, "~/work/acme") {
			t.Fatalf("%s message names no folder: %+v", ev, g)
		}
	}
	// A tool path inside the folder taints a session started elsewhere.
	g, _ := c.Gate(ctx, ipc.GateReq{Harness: "claude-code", Event: "PreToolUse", SID: sidB, Cwd: x.h.HomeDir, Paths: []string{root + "/notes.md"}})
	if g.Verdict != ipc.VerdictDeny {
		t.Fatalf("tool path in the folder = %+v (HA10)", g)
	}
	g, _ = c.Gate(ctx, ipc.GateReq{Harness: "claude-code", Event: "PreToolUse", SID: sidB, Cwd: x.h.HomeDir})
	if g.Verdict != ipc.VerdictDeny {
		t.Fatalf("taint is not sticky: %+v", g)
	}
	// Advisory root ids the configuration does not know are ignored.
	g, _ = c.Gate(ctx, ipc.GateReq{Harness: "claude-code", Event: "PreToolUse", SID: "00000000-0000-4000-8000-000000000c01", Cwd: x.h.HomeDir, Roots: []string{"bogus"}})
	if g.Verdict != ipc.VerdictAllow {
		t.Fatalf("unknown advisory root = %+v", g)
	}
	// Unlocked: allowed; Codex outside its sealed home: blocked (D31).
	if _, err := x.unlockTTY(c, nil, "root-acme"); err != nil {
		t.Fatal(err)
	}
	g, _ = c.Gate(ctx, ipc.GateReq{Harness: "claude-code", Event: "PreToolUse", SID: sidA, Cwd: root})
	if g.Verdict != ipc.VerdictAllow {
		t.Fatalf("unlocked = %+v", g)
	}
	g, _ = c.Gate(ctx, ipc.GateReq{Harness: "codex", Host: "codex", Event: "UserPromptSubmit", SID: "00000000-0000-7000-8000-000000000001", Cwd: root, CodexHome: x.h.CodexUser})
	if g.Verdict != ipc.VerdictBlock || !strings.Contains(g.UserMessage, "precinto run codex") {
		t.Fatalf("codex in the user's own home = %+v", g)
	}
	g, _ = c.Gate(ctx, ipc.GateReq{Harness: "codex", Host: "codex", Event: "UserPromptSubmit", SID: "00000000-0000-7000-8000-000000000001", Cwd: root, CodexHome: x.h.Layout.CodexHome("root-acme")})
	if g.Verdict != ipc.VerdictAllow {
		t.Fatalf("codex in its sealed home = %+v", g)
	}
}

func TestDeadlineReadsLockedBeforeTheTick(t *testing.T) {
	x := startTD(t)
	c := x.dial()
	if _, err := x.unlockTTY(c, nil, "root-acme"); err != nil {
		t.Fatal(err)
	}
	// Stop the tick loop from catching up: the published snapshot is stale.
	x.h.Clock.Advance(16 * time.Minute)
	g, err := c.Gate(context.Background(), ipc.GateReq{Harness: "claude-code", Event: "PreToolUse", SID: sidA, Cwd: x.h.Root})
	if err != nil || g.Verdict != ipc.VerdictDeny {
		t.Fatalf("expired grant still allowed: %+v %v", g, err)
	}
}

// TestIdleClockSpoofing is SEC-27: nothing but verified human input moves
// the idle deadline.
func TestIdleClockSpoofing(t *testing.T) {
	x := startTD(t)
	c := x.dial()
	ctx := context.Background()
	claudeP := x.addProc(4100, 4000, 4000, "/opt/homebrew/bin/claude", "claude")
	// The wrapper is the in-process client: it registers itself.
	if err := c.Register(ctx, ipc.RegisterReq{Harness: "claude-code", SID: sidA, PID: claudeP.ID.PID, Cwd: x.h.Root, Wrapper: true, WrapperPID: os.Getpid()}); err != nil {
		t.Fatal(err)
	}
	if s := x.d.snap.Load().snap.Sessions[sidA]; !s.Info.Wrapper {
		t.Fatalf("wrapper registration not verified: %+v", s.Info)
	}
	// Someone else's wrapper registration is recorded as unwrapped.
	other := x.addProc(4200, 1, 4200, "/opt/homebrew/bin/claude", "claude")
	if err := c.Register(ctx, ipc.RegisterReq{Harness: "claude-code", SID: sidB, PID: other.ID.PID, Cwd: x.h.Root, Wrapper: true, WrapperPID: 4199}); err != nil {
		t.Fatal(err)
	}
	if s := x.d.snap.Load().snap.Sessions[sidB]; s.Info.Wrapper {
		t.Fatal("register wrapper=true accepted for someone else's pid")
	}
	if _, err := x.unlockTTY(c, nil, "root-acme"); err != nil {
		t.Fatal(err)
	}
	idleDeadline := func() time.Time { return x.d.snap.Load().snap.Vaults["root-acme"].IdleDeadline }
	start := idleDeadline()
	x.h.Clock.Advance(time.Minute)
	// A peer that is not the registered wrapper sends keystrokes.
	spoof := platform.Peer{UID: os.Getuid(), PID: 4300, Proc: platform.ProcInfo{ID: platform.ProcID{PID: 4300, StartUS: 9}}}
	x.setPeer(&spoof, true)
	c2 := x.dial()
	for _, k := range []ipc.ActivityKind{ipc.ActInput, ipc.ActEnter} {
		_ = c2.Activity(ctx, ipc.ActivityReq{SID: sidA, Kind: k})
	}
	// Prompts whose gate origin was automated (HID idle 10 min) or unknown.
	x.setScreen(platform.ScreenState{LockKnown: true, IdleKnown: true, HIDIdle: 10 * time.Minute})
	_, _ = c2.Gate(ctx, ipc.GateReq{Harness: "claude-code", Event: "UserPromptSubmit", SID: sidB, PromptID: "p1", Cwd: x.h.Root})
	_ = c2.Activity(ctx, ipc.ActivityReq{SID: sidB, Kind: ipc.ActPrompt, PromptID: "p1"})
	x.setScreen(platform.ScreenState{LockKnown: true})
	_, _ = c2.Gate(ctx, ipc.GateReq{Harness: "claude-code", Event: "UserPromptSubmit", SID: sidB, PromptID: "p2", Cwd: x.h.Root})
	_ = c2.Activity(ctx, ipc.ActivityReq{SID: sidB, Kind: ipc.ActPrompt, PromptID: "p2"})
	// Hook activity never extends the unlock.
	for _, k := range []ipc.ActivityKind{ipc.ActStop, ipc.ActTool, ipc.ActIdlePrompt} {
		_ = c2.Activity(ctx, ipc.ActivityReq{SID: sidB, Kind: k})
	}
	time.Sleep(50 * time.Millisecond)
	if !idleDeadline().Equal(start) {
		t.Fatalf("idle deadline moved: %v → %v", start, idleDeadline())
	}
	x.h.Clock.Advance(14 * time.Minute)
	x.eventually("lock at idle_soft", func() bool { return x.vaultState("root-acme") == VaultLocked })

	// The verified wrapper's Enter, and a human prompt, do move it.
	x.setPeer(nil, true)
	if _, err := x.unlockTTY(c, nil, "root-acme"); err != nil {
		t.Fatal(err)
	}
	before := idleDeadline()
	x.h.Clock.Advance(time.Minute)
	if err := c.Activity(ctx, ipc.ActivityReq{SID: sidA, Kind: ipc.ActEnter}); err != nil {
		t.Fatal(err)
	}
	x.eventually("wrapper Enter moved the idle clock", func() bool { return idleDeadline().After(before) })
	// The Enter makes the next prompt of the wrapped session human (D37).
	g, err := c.Gate(ctx, ipc.GateReq{Harness: "claude-code", Event: "UserPromptSubmit", SID: sidA, PromptID: "p3", Cwd: x.h.Root})
	if err != nil || g.Origin != ipc.OriginHuman {
		t.Fatalf("origin after Enter = %+v %v", g, err)
	}
	x.h.Clock.Advance(4 * time.Second)
	g, _ = c.Gate(ctx, ipc.GateReq{Harness: "claude-code", Event: "UserPromptSubmit", SID: sidA, PromptID: "p4", Cwd: x.h.Root})
	if g.Origin != ipc.OriginAutomated {
		t.Fatalf("origin 4 s after Enter = %s", g.Origin)
	}
	// Unwrapped: HID idle ≤ 5 s is human.
	x.setScreen(platform.ScreenState{LockKnown: true, IdleKnown: true, HIDIdle: time.Second})
	g, _ = c.Gate(ctx, ipc.GateReq{Harness: "claude-code", Event: "UserPromptSubmit", SID: sidB, PromptID: "p5", Cwd: x.h.Root})
	if g.Origin != ipc.OriginHuman {
		t.Fatalf("unwrapped origin with HID idle 1 s = %s", g.Origin)
	}
	before = idleDeadline()
	x.h.Clock.Advance(time.Minute)
	_ = c.Activity(ctx, ipc.ActivityReq{SID: sidB, Kind: ipc.ActPrompt, PromptID: "p5"})
	x.eventually("human prompt moved the idle clock", func() bool { return idleDeadline().After(before) })
}

// TestRegisterVerifiesTheProcess is SEC-19: only a live harness process
// can be registered, and gate pids are measured, never trusted.
func TestRegisterVerifiesTheProcess(t *testing.T) {
	x := startTD(t)
	c := x.dial()
	ctx := context.Background()
	vim := x.addProc(5100, 1, 5100, "/usr/bin/vim", "vim")
	err := c.Register(ctx, ipc.RegisterReq{Harness: "claude-code", SID: sidA, PID: vim.ID.PID, Cwd: x.h.Root})
	if ipcCode(err) != ipc.CodeUnauthorized {
		t.Fatalf("register of a non-harness pid = %v", err)
	}
	if err := c.Register(ctx, ipc.RegisterReq{Harness: "claude-code", SID: sidA, PID: 5999, Cwd: x.h.Root}); ipcCode(err) != ipc.CodeBadRequest {
		t.Fatalf("register of a missing pid = %v", err)
	}
	cl := x.addProc(5200, 1, 5200, "/usr/local/bin/codex", "codex")
	if err := c.Register(ctx, ipc.RegisterReq{Harness: "claude-code", SID: sidA, PID: cl.ID.PID, Cwd: x.h.Root}); ipcCode(err) != ipc.CodeUnauthorized {
		t.Fatalf("register of a codex pid as claude = %v", err)
	}
	// A gate naming a forged pid binds no process to the session.
	_, _ = c.Gate(ctx, ipc.GateReq{Harness: "claude-code", Event: "UserPromptSubmit", SID: sidB, PID: vim.ID.PID, Cwd: x.h.Root})
	time.Sleep(50 * time.Millisecond)
	if s, ok := x.d.snap.Load().snap.Sessions[sidB]; ok && !s.Info.Proc.IsZero() {
		t.Fatalf("a forged gate pid was adopted: %+v", s.Info)
	}
	x.d.mu.Lock()
	signalable := x.d.signalable[vim.ID]
	x.d.mu.Unlock()
	if signalable {
		t.Fatal("a forged pid became signalable")
	}
}

func TestUnlockFlows(t *testing.T) {
	x := startTD(t)
	c := x.dial()
	ctx := context.Background()
	// TTL clamp (SEC-15 ttl=1000h).
	r, err := c.Unlock(ctx, ipc.UnlockReq{RootIDs: []string{"root-acme"}, TTY: true, TTL: 1000 * time.Hour}, nil)
	if err != nil || !r.Until.Equal(x.h.Clock.Now().Add(8*time.Hour)) {
		t.Fatalf("Unlock = %+v %v (ttl clamped to 8 h)", r, err)
	}
	if sp := x.spawnedArgs(); !slices.ContainsFunc(sp, func(a []string) bool {
		return slices.Equal(a, []string{"restore", "--root", x.h.Root, "--recent", "5", "--md", "--history", "--background"})
	}) {
		t.Fatalf("no background restore after unlock: %q (SPEC §11.6)", sp)
	}
	// Already unlocked: no new prompt.
	n := x.vaults.count("root-acme")
	if _, err := x.unlockTTY(c, nil, "root-acme"); err != nil || x.vaults.count("root-acme") != n {
		t.Fatalf("re-unlock prompted again: %v", err)
	}
	// Several folders need typed confirmation on a terminal (D40) …
	if _, err := c.Unlock(ctx, ipc.UnlockReq{RootIDs: []string{"root-acme", "root-beta"}, TTY: true}, nil); ipcCode(err) != ipc.CodeBadRequest {
		t.Fatalf("multi-folder without confirmation = %v", err)
	}
	// … and then cost one presence prompt per folder.
	if _, err := c.Unlock(ctx, ipc.UnlockReq{All: true, TTY: true, Confirmed: true}, nil); err != nil {
		t.Fatal(err)
	}
	if x.vaults.count("root-beta") != 1 {
		t.Fatalf("beta prompts = %d", x.vaults.count("root-beta"))
	}
	// Not the same executable: refused before any prompt.
	x.setPeer(&platform.Peer{UID: os.Getuid(), PID: 4300, Proc: platform.ProcInfo{ID: platform.ProcID{PID: 4300, StartUS: 9}, TTY: "/dev/ttys009"}}, false)
	c2 := x.dial()
	if _, err := c2.Lock(ctx, ipc.LockReq{All: true}); err != nil {
		t.Fatal(err) // lock needs only the uid
	}
	if _, err := c2.Unlock(ctx, ipc.UnlockReq{RootIDs: []string{"root-acme"}, TTY: true}, nil); ipcCode(err) != ipc.CodeUnauthorized {
		t.Fatalf("other executable = %v", err)
	}
}

func TestUnlockRelaysPassphrase(t *testing.T) {
	x := startTD(t)
	x.vaults.set(func(f *fakeVaults) { f.ask = true })
	c := x.dial()
	ui := &scripted{secret: "correct horse battery"}
	if _, err := x.unlockTTY(c, ui, "root-acme"); err != nil {
		t.Fatal(err)
	}
	if len(ui.prompts) != 1 || !strings.Contains(ui.prompts[0], "~/work/acme") {
		t.Fatalf("prompt = %q (built by the daemon, naming the folder, D27)", ui.prompts)
	}
	x.d.mu.Lock()
	pinned := x.d.pol.hasPinned
	x.d.mu.Unlock()
	if !pinned {
		t.Fatal("a TTY unlock did not pin the policy (D55)")
	}
	if !x.keys.Has("root-acme") {
		t.Fatal("identity not in the key holder")
	}
	// Wrong passphrase: refused, nothing unlocked.
	x2 := startTD(t)
	x2.vaults.set(func(f *fakeVaults) { f.ask = true })
	c2 := x2.dial()
	if _, err := x2.unlockTTY(c2, &scripted{secret: "wrong"}, "root-acme"); ipcCode(err) != ipc.CodeVerify {
		t.Fatalf("wrong passphrase = %v", err)
	}
	if x2.vaultState("root-acme") != VaultLocked {
		t.Fatal("unlocked with a wrong passphrase")
	}
}

func TestUnlockRateLimitAndSingleFlight(t *testing.T) {
	x := startTD(t)
	c := x.dial()
	ctx := context.Background()
	x.vaults.set(func(f *fakeVaults) { f.unwrapErr["root-acme"] = vault.ErrCancelled })
	if _, err := x.unlockTTY(c, nil, "root-acme"); ipcCode(err) != ipc.CodeCancelled {
		t.Fatalf("cancel = %v", err)
	}
	if _, err := x.unlockTTY(c, nil, "root-acme"); ipcCode(err) != ipc.CodeRateLimited {
		t.Fatalf("prompt right after a cancel = %v (30 s back-off, D27)", err)
	}
	if x.vaults.count("root-acme") != 1 {
		t.Fatal("a rate-limited request still prompted")
	}
	x.h.Clock.Advance(31 * time.Second)
	x.vaults.set(func(f *fakeVaults) { delete(f.unwrapErr, "root-acme") })
	// Concurrent requests share one prompt (single flight).
	x.vaults.set(func(f *fakeVaults) { f.block = make(chan struct{}) })
	var wg sync.WaitGroup
	errs := make([]error, 3)
	for i := range errs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ci := x.dial()
			_, errs[i] = ci.Unlock(ctx, ipc.UnlockReq{RootIDs: []string{"root-acme"}, TTY: true}, nil)
		}()
	}
	x.eventually("the leader prompts", func() bool { return x.vaults.count("root-acme") == 2 })
	time.Sleep(50 * time.Millisecond)
	close(x.vaults.block)
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			t.Fatalf("shared unlock failed: %v", err)
		}
	}
	if n := x.vaults.count("root-acme"); n != 2 {
		t.Fatalf("prompts = %d, want 1 more (concurrent requesters share the result)", n-1)
	}
	// Three prompts per minute at most.
	x2 := startTD(t)
	c2 := x2.dial()
	x2.vaults.set(func(f *fakeVaults) { f.unwrapErr["root-beta"] = vault.ErrWrongIdentity })
	for i := 0; i < 3; i++ {
		_, _ = x2.unlockTTY(c2, nil, "root-beta")
	}
	if _, err := x2.unlockTTY(c2, nil, "root-beta"); ipcCode(err) != ipc.CodeRateLimited {
		t.Fatalf("4th prompt in a minute = %v", err)
	}
}

func TestUnlockTampered(t *testing.T) {
	x := startTD(t)
	c := x.dial()
	x.vaults.set(func(f *fakeVaults) { f.verifyErr["root-acme"] = vault.ErrMACMismatch })
	if _, err := x.unlockTTY(c, nil, "root-acme"); ipcCode(err) != ipc.CodeVerify {
		t.Fatalf("MAC mismatch = %v (refuse the grant, D5)", err)
	}
	if x.keys.Has("root-acme") || x.vaultState("root-acme") != VaultLocked {
		t.Fatal("tampered vault unlocked")
	}
	st, _ := c.Status(context.Background())
	if !slices.ContainsFunc(st.Attention, func(a ipc.Attention) bool {
		return a.Code == ipc.AttnVaultTampered && strings.Contains(a.Fix, "vault repair --root ~/work/acme")
	}) {
		t.Fatalf("attention = %+v", st.Attention)
	}
}

func TestUnlockAgentAndTerminalRules(t *testing.T) {
	x := startTD(t)
	ctx := context.Background()
	// An agent (claude ancestor) whose session runs in root-acme.
	x.addProc(6000, 1, 6000, "/bin/zsh", "-zsh")
	x.addProc(6100, 6000, 6000, "/opt/homebrew/bin/claude", "claude")
	x.h.Procs.SetCwd(6100, x.h.Root)
	x.addProc(6200, 6100, 6000, "/bin/sh", "sh", "-c", "precinto unlock")
	agentPeer := platform.Peer{UID: os.Getuid(), PID: 6300, Proc: platform.ProcInfo{ID: platform.ProcID{PID: 6300, StartUS: 1}, PPID: 6200, TTY: "/dev/ttys004"}}
	x.h.Procs.Add(agentPeer.Proc)
	x.setPeer(&agentPeer, true)
	c := x.dial()
	_, err := c.Unlock(ctx, ipc.UnlockReq{RootIDs: []string{"root-beta"}, TTY: true}, nil)
	if ipcCode(err) != ipc.CodeAgentContext || x.vaults.count("root-beta") != 0 {
		t.Fatalf("agent unlocking another folder = %v (refused without a dialog, SEC-24)", err)
	}
	if _, err := c.Unlock(ctx, ipc.UnlockReq{RootIDs: []string{"root-acme"}, TTY: true}, nil); err != nil {
		t.Fatalf("agent unlocking its own folder = %v", err)
	}
	// A peer without a terminal may only unlock the folder of its cwd.
	nt := platform.Peer{UID: os.Getuid(), PID: 6400, Proc: platform.ProcInfo{ID: platform.ProcID{PID: 6400, StartUS: 1}, PPID: 1}}
	x.h.Procs.Add(nt.Proc)
	x.h.Procs.SetCwd(6400, x.h.HomeDir)
	x.setPeer(&nt, true)
	c2 := x.dial()
	if _, err := c2.Unlock(ctx, ipc.UnlockReq{RootIDs: []string{"root-beta"}}, nil); ipcCode(err) != ipc.CodeAgentContext || x.vaults.count("root-beta") != 0 {
		t.Fatalf("reparented peer without a terminal unlocking a folder = %v (C12.agent, no dialog, SEC-24)", err)
	}
	// Its own cwd's folder stays possible.
	x.h.Procs.SetCwd(6400, x.h.Root)
	if _, err := c2.Unlock(ctx, ipc.UnlockReq{RootIDs: []string{"root-acme"}}, nil); err != nil && ipcCode(err) == ipc.CodeAgentContext {
		t.Fatalf("no-TTY unlock of the cwd's folder = %v", err)
	}
	// Hook-raised unlocks need unlock_on_prompt (ships false, D60).
	if _, err := c2.Unlock(ctx, ipc.UnlockReq{RootIDs: []string{"root-beta"}, FromHook: true, SID: sidA}, nil); err == nil {
		t.Fatal("hook unlock with unlock_on_prompt=false")
	}
}

func TestKeyRelease(t *testing.T) {
	x := startTD(t)
	c := x.dial()
	ctx := context.Background()
	x.caps.add("md/aaaa/g000001.pcap", "root-acme", "root-acme")
	x.caps.add("md/bbbb/g000001.pcap", "root-beta", "root-beta")
	x.caps.add("claude-code/cccc/g000002.pcap", "root-acme", "root-acme", "root-beta")
	x.caps.add("md/dddd/g000001.pcap", "root-acme", "root-acme")
	x.caps.mu.Lock()
	m := x.caps.manifests["md/dddd/g000001.pcap"]
	m.UnitKey = "another-unit"
	x.caps.manifests["md/dddd/g000001.pcap"] = m
	x.caps.mu.Unlock()
	if _, err := x.unlockTTY(c, nil, "root-acme"); err != nil {
		t.Fatal(err)
	}
	refs := []ipc.CapsuleRef{{Path: "md/aaaa/g000001.pcap"}, {Path: "md/bbbb/g000001.pcap"}, {Path: "claude-code/cccc/g000002.pcap"},
		{Path: "md/dddd/g000001.pcap"}, {Path: "md/eeee/g000001.pcap"}, {Path: "../../etc/passwd.pcap"}, {Path: "md/aaaa/notes.md"}}
	ks, resp, err := c.Keys(ctx, ipc.KeysReq{Capsules: refs, Purpose: ipc.PurposeRestore})
	if err != nil {
		t.Fatal(err)
	}
	defer ks.Destroy()
	if len(resp.Granted) != 1 || resp.Granted[0].Path != "md/aaaa/g000001.pcap" {
		t.Fatalf("granted = %+v", resp.Granted)
	}
	want := map[string]ipc.Code{
		"md/bbbb/g000001.pcap":          ipc.CodeLocked,    // root B locked (D1)
		"claude-code/cccc/g000002.pcap": ipc.CodeLocked,    // every root must be unlocked
		"md/dddd/g000001.pcap":          ipc.CodeVerify,    // manifest does not match the log
		"md/eeee/g000001.pcap":          ipc.CodeNotLogged, // no provenance (D8)
		"../../etc/passwd.pcap":         ipc.CodeBadRequest,
		"md/aaaa/notes.md":              ipc.CodeBadRequest,
	}
	for p, code := range want {
		if resp.Denied[p] != code {
			t.Errorf("denied[%s] = %q, want %q", p, resp.Denied[p], code)
		}
	}
	key, ok := ks.Key("md/aaaa/g000001.pcap")
	if !ok || string(key.Bytes()) != string(fileKeyOf(x.caps.headers["md/aaaa/g000001.pcap"])) {
		t.Fatal("wrong key released")
	}
	// After a lock nothing is released.
	if _, err := c.Lock(ctx, ipc.LockReq{All: true}); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(x.keys.droppedIDs(), "root-acme") {
		t.Fatal("lock did not wipe the key before answering (I15)")
	}
	_, resp, _ = c.Keys(ctx, ipc.KeysReq{Capsules: refs[:1], Purpose: ipc.PurposeRestore})
	if len(resp.Granted) != 0 || resp.Denied["md/aaaa/g000001.pcap"] != ipc.CodeLocked {
		t.Fatalf("after lock = %+v", resp)
	}
	// Bad purpose; other executable.
	if _, _, err := c.Keys(ctx, ipc.KeysReq{Purpose: "steal"}); ipcCode(err) != ipc.CodeBadRequest {
		t.Fatalf("bad purpose = %v", err)
	}
	x.setPeer(&platform.Peer{UID: os.Getuid(), PID: 4300, Proc: platform.ProcInfo{ID: platform.ProcID{PID: 4300, StartUS: 9}, TTY: "/dev/ttys009"}}, false)
	c2 := x.dial()
	if _, _, err := c2.Keys(ctx, ipc.KeysReq{Capsules: refs[:1], Purpose: ipc.PurposeRestore}); ipcCode(err) != ipc.CodeUnauthorized {
		t.Fatalf("other executable = %v", err)
	}
}

func TestKeyReleaseAgentContextAndPresence(t *testing.T) {
	x := startTD(t)
	ctx := context.Background()
	x.caps.add("md/aaaa/g000001.pcap", "root-acme", "root-acme")
	x.caps.add("md/bbbb/g000001.pcap", "root-beta", "root-beta")
	c := x.dial()
	if _, err := c.Unlock(ctx, ipc.UnlockReq{All: true, TTY: true, Confirmed: true}, nil); err != nil {
		t.Fatal(err)
	}
	refs := []ipc.CapsuleRef{{Path: "md/aaaa/g000001.pcap"}, {Path: "md/bbbb/g000001.pcap"}}
	// Agent in root-acme.
	x.addProc(6000, 1, 6000, "/bin/zsh", "-zsh")
	x.addProc(6100, 6000, 6000, "/opt/homebrew/bin/claude", "claude")
	x.h.Procs.SetCwd(6100, x.h.Root)
	ap := platform.Peer{UID: os.Getuid(), PID: 6300, Proc: platform.ProcInfo{ID: platform.ProcID{PID: 6300, StartUS: 1}, PPID: 6100, TTY: "/dev/ttys004"}}
	x.h.Procs.Add(ap.Proc)
	x.setPeer(&ap, true)
	ca := x.dial()
	before := x.vaults.count("root-acme")
	ks, resp, err := ca.Keys(ctx, ipc.KeysReq{Capsules: refs, Purpose: ipc.PurposeCat})
	if err != nil {
		t.Fatal(err)
	}
	ks.Destroy()
	if resp.Denied["md/bbbb/g000001.pcap"] != ipc.CodeAgentContext {
		t.Fatalf("agent got another folder's key: %+v (D1, D28)", resp)
	}
	if len(resp.Granted) != 1 || x.vaults.count("root-acme") != before+1 {
		t.Fatalf("own folder needs fresh presence: granted %+v, prompts %d", resp.Granted, x.vaults.count("root-acme")-before)
	}
	// Presence refused: denied.
	x.vaults.set(func(f *fakeVaults) { f.unwrapErr["root-acme"] = vault.ErrNoUI })
	_, resp, _ = ca.Keys(ctx, ipc.KeysReq{Capsules: refs[:1], Purpose: ipc.PurposeRestore})
	if len(resp.Granted) != 0 {
		t.Fatalf("released without presence: %+v", resp)
	}
	x.vaults.set(func(f *fakeVaults) { delete(f.unwrapErr, "root-acme") })
	// No terminal, not a worker: content purposes need presence, targeted
	// restores do not (D59).
	nt := platform.Peer{UID: os.Getuid(), PID: 6400, Proc: platform.ProcInfo{ID: platform.ProcID{PID: 6400, StartUS: 1}, PPID: 1}}
	x.h.Procs.Add(nt.Proc)
	x.setPeer(&nt, true)
	cn := x.dial()
	before = x.vaults.count("root-beta")
	ks, resp, _ = cn.Keys(ctx, ipc.KeysReq{Capsules: refs[1:], Purpose: ipc.PurposeRestore})
	ks.Destroy()
	if len(resp.Granted) != 1 || x.vaults.count("root-beta") != before {
		t.Fatalf("targeted restore without a terminal: %+v", resp)
	}
	ks, resp, _ = cn.Keys(ctx, ipc.KeysReq{Capsules: refs[1:], Purpose: ipc.PurposeRestoreAll})
	ks.Destroy()
	if len(resp.Granted) != 1 || x.vaults.count("root-beta") != before+1 {
		t.Fatalf("restore --all without a terminal skipped presence: %+v", resp)
	}
}

// TestProtocolNeverReturnsIdentities fuzzes the daemon with every
// operation and checks no answer carries an identity (SEC-15).
func TestProtocolNeverReturnsIdentities(t *testing.T) {
	x := startTD(t)
	c := x.dial()
	ctx := context.Background()
	x.caps.add("md/aaaa/g000001.pcap", "root-acme", "root-acme")
	if _, err := c.Unlock(ctx, ipc.UnlockReq{All: true, TTY: true, Confirmed: true}, nil); err != nil {
		t.Fatal(err)
	}
	var seen []string
	check := func(v any) {
		s := strings.ToUpper(strings.TrimSpace(strings.ReplaceAll(strings.ReplaceAll(toString(v), "-", ""), "_", "")))
		if strings.Contains(s, "AGESECRETKEY") || strings.Contains(s, "FAKEROOT") {
			t.Fatalf("an identity left the daemon: %v", v)
		}
		seen = append(seen, s[:min(len(s), 10)])
	}
	st, _ := c.Status(ctx)
	check(st)
	for _, ev := range []string{"UserPromptSubmit", "PreToolUse", "SessionStart"} {
		g, _ := c.Gate(ctx, ipc.GateReq{Event: ev, SID: sidA, Cwd: x.h.Root})
		check(g)
	}
	ks, kr, _ := c.Keys(ctx, ipc.KeysReq{Capsules: []ipc.CapsuleRef{{Path: "md/aaaa/g000001.pcap"}}, Purpose: ipc.PurposeRestore})
	check(kr)
	if k, ok := ks.Key("md/aaaa/g000001.pcap"); !ok || strings.Contains(string(k.Bytes()), "AGE-SECRET") {
		t.Fatal("released secret is not a file key")
	}
	ks.Destroy()
	p, _ := c.Policy(ctx, ipc.PolicyReq{})
	check(p)
	l, _ := c.Lock(ctx, ipc.LockReq{RootIDs: []string{"root-beta"}})
	check(l)
	if len(seen) == 0 {
		t.Fatal("nothing checked")
	}
}

func TestLockEndsSessionsSafely(t *testing.T) {
	var mu sync.Mutex
	var exited []int
	x := startTD(t, func(x *td, o *Options) {
		// The unwrapped claude ignores SIGTERM; grace waits are cut short.
		x.waitExit = func(ctx context.Context, id platform.ProcID) error { return context.DeadlineExceeded }
		x.signal = func(id platform.ProcID, sig syscall.Signal) {
			if sig == syscall.SIGKILL {
				mu.Lock()
				exited = append(exited, id.PID)
				mu.Unlock()
				x.h.Procs.Exit(id.PID, false)
			}
		}
	})
	c := x.dial()
	ctx := context.Background()
	sub, err := c.Subscribe(ctx, ipc.SubscribeReq{RootIDs: []string{"root-acme"}, Wrapper: true})
	if err != nil {
		t.Fatal(err)
	}
	// The user's terminal session 7000: login shell, an unwrapped claude
	// with an MCP server child and a grandchild, and a sibling job.
	shell := x.addProc(7000, 1, 7000, "/bin/zsh", "-zsh")
	cl := x.addProc(7100, 7000, 7000, "/opt/homebrew/bin/claude", "claude")
	mcp := x.addProc(7200, 7100, 7000, "/opt/homebrew/bin/node", "node", "server.js")
	grand := x.addProc(7300, 7200, 7000, "/usr/bin/python3", "python3")
	job := x.addProc(7400, 7000, 7000, "/usr/bin/make", "make")
	x.h.Procs.SetCwd(7100, x.h.Root)
	bg := x.addProc(7500, 1, 7500, "/opt/homebrew/bin/claude", "claude")
	cx := x.addProc(7600, 1, 7600, "/usr/local/bin/codex", "codex")
	wc := x.addProc(7700, 1, 7700, "/opt/homebrew/bin/claude", "claude")
	for _, r := range []ipc.RegisterReq{
		{Harness: "claude-code", SID: sidA, PID: cl.ID.PID, Cwd: x.h.Root, TTY: "/dev/ttys004"},
		{Harness: "claude-code", SID: "00000000-0000-4000-8000-0000000000f1", PID: bg.ID.PID, Cwd: x.h.Root, Background: true},
		{Harness: "codex", SID: "00000000-0000-7000-8000-0000000000f2", PID: cx.ID.PID, Cwd: x.h.Root},
		{Harness: "claude-code", SID: "00000000-0000-4000-8000-0000000000f3", PID: wc.ID.PID, Cwd: x.h.Root, Wrapper: true, WrapperPID: os.Getpid()},
	} {
		if err := c.Register(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := x.unlockTTY(c, nil, "root-acme"); err != nil {
		t.Fatal(err)
	}
	resp, err := c.Lock(ctx, ipc.LockReq{RootIDs: []string{"root-acme"}, End: true})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(resp.Ended, sidA) || slices.Contains(resp.Ended, "00000000-0000-4000-8000-0000000000f1") {
		t.Fatalf("ended = %v", resp.Ended)
	}
	// The wrapped session gets an end event for its wrapper.
	gotEnd := false
	timeout := time.After(5 * time.Second)
	for !gotEnd {
		select {
		case ev := <-sub:
			gotEnd = ev.Kind == ipc.EventEnd && slices.Contains(ev.SIDs, "00000000-0000-4000-8000-0000000000f3")
		case <-timeout:
			t.Fatal("no end event for the wrapped session")
		}
	}
	x.eventually("unwrapped claude ended", func() bool {
		mu.Lock()
		defer mu.Unlock()
		return slices.Contains(exited, cl.ID.PID) && slices.Contains(exited, grand.ID.PID)
	})
	signalled := map[int][]syscall.Signal{}
	for _, s := range x.rec.snapshot() {
		signalled[s.ID.PID] = append(signalled[s.ID.PID], s.Sig)
		if s.ID != cl.ID && s.ID != mcp.ID && s.ID != grand.ID {
			t.Fatalf("signalled %+v (only the verified claude and its descendants, D57)", s)
		}
	}
	if !slices.Equal(signalled[cl.ID.PID], []syscall.Signal{syscall.SIGTERM, syscall.SIGKILL}) {
		t.Fatalf("claude got %v, want SIGTERM then SIGKILL", signalled[cl.ID.PID])
	}
	for _, p := range []platform.ProcInfo{shell, job, bg, cx, wc} {
		if len(signalled[p.ID.PID]) > 0 {
			t.Fatalf("pid %d (%s) was signalled", p.ID.PID, p.Exe)
		}
	}
	x.eventually("terminal scrubbed after the verified exit", func() bool {
		x.rec.mu.Lock()
		defer x.rec.mu.Unlock()
		return slices.Contains(x.rec.scrubbed, "/dev/ttys004")
	})
}

// TestUngatedScan is SEC-29: unregistered harness processes in a locked
// folder.
func TestUngatedScan(t *testing.T) {
	x := startTD(t)
	ccDir := x.h.ClaudeConfig
	old := epochT.Add(-time.Hour)
	interactive := x.addProc(8100, 8000, 8000, "/opt/homebrew/bin/claude", "claude")
	x.addProc(8000, 1, 8000, "/bin/zsh", "-zsh") // its login shell, same session
	background := x.addProc(8200, 1, 8200, "/opt/homebrew/bin/claude", "claude")
	cx := x.addProc(8300, 1, 8300, "/usr/local/bin/codex", "codex")
	noReg := x.addProc(8400, 1, 8400, "/opt/homebrew/bin/claude", "claude")
	outside := x.addProc(8500, 1, 8500, "/opt/homebrew/bin/claude", "claude")
	for _, pid := range []int{8100, 8200, 8300, 8400} {
		x.h.Procs.SetCwd(pid, x.h.Root)
	}
	x.h.Procs.SetCwd(8500, x.h.HomeDir)
	x.mu.Lock()
	x.registry[ccDir] = []claude.RegistryEntry{
		{PID: 8100, SessionID: sidA, Kind: "interactive", Entrypoint: "cli", StartedAt: old.Add(2 * time.Second), Valid: true},
		{PID: 8200, SessionID: sidB, Kind: "interactive", Entrypoint: "cli", StartedAt: old.Add(time.Second), Valid: true},
	}
	x.jobs = []claude.Job{{ID: "j1", SessionID: sidB, State: "running", Valid: true}}
	x.mu.Unlock()
	x.eventually("scan finds the interactive claude", func() bool {
		for _, s := range x.rec.snapshot() {
			if s.ID == interactive.ID {
				return true
			}
		}
		return false
	})
	time.Sleep(50 * time.Millisecond)
	for _, s := range x.rec.snapshot() {
		if s.ID != interactive.ID {
			t.Fatalf("signalled %+v: only the interactive claude may be ended", s)
		}
	}
	c := x.dial()
	st, _ := c.Status(context.Background())
	reported := map[int]bool{}
	for _, a := range st.Attention {
		if a.Code == ipc.AttnUngatedSession {
			reported[a.PID] = true
		}
	}
	for _, p := range []platform.ProcInfo{background, cx, noReg} {
		if !reported[p.ID.PID] {
			t.Errorf("pid %d not reported as ungated: %+v", p.ID.PID, st.Attention)
		}
	}
	if reported[outside.ID.PID] || reported[interactive.ID.PID] {
		t.Fatalf("reported = %v", reported)
	}
}

func TestSubscribeStream(t *testing.T) {
	x := startTD(t)
	c := x.dial()
	ctx := context.Background()
	sub, err := c.Subscribe(ctx, ipc.SubscribeReq{RootIDs: []string{"root-acme"}, Wrapper: true})
	if err != nil {
		t.Fatal(err)
	}
	next := func(kind ipc.EventKind) ipc.Event {
		t.Helper()
		timeout := time.After(5 * time.Second)
		for {
			select {
			case ev, ok := <-sub:
				if !ok {
					t.Fatal("stream closed")
				}
				if ev.Kind == kind {
					return ev
				}
			case <-timeout:
				t.Fatalf("no %s event", kind)
			}
		}
	}
	if ev := next(ipc.EventLocked); ev.Reason != "start" {
		t.Fatalf("initial state = %+v", ev)
	}
	if _, err := x.unlockTTY(c, nil, "root-acme"); err != nil {
		t.Fatal(err)
	}
	next(ipc.EventUnlocked)
	next(ipc.EventHeartbeat)
	if _, err := c.Lock(ctx, ipc.LockReq{RootIDs: []string{"root-beta"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Lock(ctx, ipc.LockReq{RootIDs: []string{"root-acme"}}); err != nil {
		t.Fatal(err)
	}
	if ev := next(ipc.EventLocked); ev.Reason != "manual" || !slices.Equal(ev.RootIDs, []string{"root-acme"}) {
		t.Fatalf("lock event = %+v", ev)
	}
	x.stop()
	timeout := time.After(5 * time.Second)
	for {
		select {
		case _, ok := <-sub:
			if !ok {
				return
			}
		case <-timeout:
			t.Fatal("stream not closed when the daemon stopped")
		}
	}
}

func TestWorkersAndShutdown(t *testing.T) {
	x := startTD(t)
	c := x.dial()
	ctx := context.Background()
	if _, err := x.unlockTTY(c, nil, "root-acme"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Lock(ctx, ipc.LockReq{RootIDs: []string{"root-acme"}}); err != nil {
		t.Fatal(err)
	}
	sp := x.spawnedArgs()
	if !slices.Equal(sp[0], []string{"sweep", "--quiet"}) ||
		!slices.ContainsFunc(sp, func(a []string) bool { return slices.Equal(a, []string{"sweep", "--lock", "--root", x.h.Root}) }) {
		t.Fatalf("spawned = %q", sp)
	}
	for _, kv := range x.d.workerEnv() {
		k, _, _ := strings.Cut(kv, "=")
		if strings.HasPrefix(k, "CLAUDE") || strings.HasPrefix(k, "CODEX") || strings.HasPrefix(k, "DYLD_") {
			t.Fatalf("worker environment carries %s", k)
		}
	}
	if _, err := x.unlockTTY(c, nil, "root-beta"); err != nil {
		t.Fatal(err)
	}
	if err := c.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case <-x.done:
		x.cancel = nil
	case <-time.After(5 * time.Second):
		t.Fatal("shutdown did not stop the daemon")
	}
	if len(x.keys.IDs()) != 0 {
		t.Fatal("shutdown left keys")
	}
}

func TestIdleExit(t *testing.T) {
	x := startTD(t, func(x *td, o *Options) { o.IdleExit = time.Minute })
	c := x.dial()
	sub, err := c.Subscribe(context.Background(), ipc.SubscribeReq{RootIDs: []string{"root-acme"}})
	if err != nil {
		t.Fatal(err)
	}
	x.h.Clock.Advance(2 * time.Minute)
	time.Sleep(100 * time.Millisecond)
	x.h.Clock.Advance(2 * time.Minute)
	select {
	case <-x.done:
		t.Fatal("exited with a subscriber")
	case <-time.After(100 * time.Millisecond):
	}
	c.Close()
	for range sub {
	}
	deadline := time.After(5 * time.Second)
	for {
		x.h.Clock.Advance(30 * time.Second)
		select {
		case <-x.done:
			x.cancel = nil
			return
		case <-deadline:
			t.Fatal("no idle exit (R19)")
		case <-time.After(20 * time.Millisecond):
		}
	}
}

func toString(v any) string { return fmt.Sprintf("%+v", v) }

// D156: under WSL a Claude session in a folder that manages Claude, whose
// config folder (from its transcript path) or temporary folder (from its
// scratchpad) is on a Windows drive, is blocked even while the folder is
// unlocked (C3.windrive): its files would hold the folder's content where
// Windows programs write unseen and no sweep seals. SessionStart is not
// gated by it; a folder that manages only Codex is not concerned.
func TestGateBlocksAClaudeSessionOnAWindowsDrive(t *testing.T) {
	x := startTD(t)
	c := x.dial()
	ctx := context.Background()
	root := x.h.Root
	if _, err := x.unlockTTY(c, nil, "root-acme"); err != nil {
		t.Fatal(err)
	}
	winCfg := filepath.Join(x.h.Dir, "mnt-c", ".claude")
	winTmp := filepath.Join(x.h.Dir, "mnt-c", "tmp")
	x.mu.Lock()
	x.drive = func(p string) error {
		if paths.Within(filepath.Join(x.h.Dir, "mnt-c"), p) {
			return &paths.DriveError{Path: p}
		}
		return nil
	}
	x.mu.Unlock()
	req := func(ev, cfg, tmp string) ipc.GateReq {
		return ipc.GateReq{Harness: "claude-code", Host: "claude-code", Event: ev, SID: sidA, Cwd: root, ConfigDir: cfg, TmpDir: tmp}
	}
	if g, err := c.Gate(ctx, req("UserPromptSubmit", x.h.ClaudeConfig, x.h.ClaudeTmp)); err != nil || g.Verdict != ipc.VerdictAllow {
		t.Fatalf("folders off the drive = %+v %v", g, err)
	}
	for _, tc := range []struct{ ev, cfg, tmp string }{
		{"UserPromptSubmit", winCfg, x.h.ClaudeTmp},
		{"PreToolUse", x.h.ClaudeConfig, winTmp},
		{"PermissionRequest", winCfg, ""},
	} {
		g, err := c.Gate(ctx, req(tc.ev, tc.cfg, tc.tmp))
		want := ipc.VerdictBlock
		if tc.ev != "UserPromptSubmit" {
			want = ipc.VerdictDeny
		}
		if err != nil || g.Verdict != want || g.Reason != "windows-drive" || !strings.Contains(g.UserMessage, "Windows drive") || !strings.Contains(g.UserMessage, "~/work/acme") {
			t.Fatalf("%s with a folder on a drive = %+v %v", tc.ev, g, err)
		}
	}
	if g, _ := c.Gate(ctx, req("SessionStart", winCfg, winTmp)); g.Reason == "windows-drive" {
		t.Fatalf("SessionStart gated by the drive check: %+v", g)
	}
	// Outside every protected folder nothing is managed.
	g, _ := c.Gate(ctx, ipc.GateReq{Harness: "claude-code", Host: "claude-code", Event: "PreToolUse", SID: "00000000-0000-4000-8000-000000000c09", Cwd: x.h.HomeDir, ConfigDir: winCfg})
	if g.Verdict != ipc.VerdictAllow {
		t.Fatalf("unmanaged session = %+v", g)
	}
}
