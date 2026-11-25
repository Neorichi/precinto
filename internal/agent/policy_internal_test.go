package agent

import (
	"context"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/awnumar/memguard"

	"github.com/Neorichi/precinto/internal/config"
	"github.com/Neorichi/precinto/internal/ipc"
	"github.com/Neorichi/precinto/internal/platform"
	"github.com/Neorichi/precinto/internal/vault"
)

// restart stops x's daemon and starts a new one on the same home, with an
// empty key holder (a daemon that exited and was autostarted again).
func (x *td) restart(opts ...tdOpt) {
	x.t.Helper()
	x.stop()
	x.keys = newFakeKeyring()
	o := Options{Layout: x.h.Layout, Env: x.h.Env, Exe: "/opt/precinto/bin/precinto", Version: "test",
		Clock: x.h.Clock, Procs: x.h.Procs, IdleExit: 100 * 365 * 24 * time.Hour, Tick: 10 * time.Millisecond,
		Spawn: x.spawn, Screen: x.readScreen, Harden: func() error { return nil }}
	for _, f := range opts {
		f(x, &o)
	}
	x.done = make(chan error, 1)
	x.start(o)
}

func (x *td) attention(c *ipc.Client) map[string]ipc.Attention {
	st, err := c.Status(context.Background())
	if err != nil {
		x.t.Fatal(err)
	}
	out := map[string]ipc.Attention{}
	for _, a := range st.Attention {
		out[a.Code] = a
	}
	return out
}

// TestPolicyPinning is SEC-23: weakening edits made while locked do not
// survive a daemon restart, and a forged pinned file raises
// policy-tampered.
func TestPolicyPinning(t *testing.T) {
	x := startTD(t)
	c := x.dial()
	if _, err := x.unlockTTY(c, nil, "root-acme"); err != nil {
		t.Fatal(err)
	}
	pinned, ok, err := config.LoadPinned(x.h.Layout.PolicyPinned)
	if err != nil || !ok || pinned.MACs["root-acme"] == "" || pinned.Config.Policy.IdleSoft.D() != 15*time.Minute {
		t.Fatalf("policy.pinned = %+v %v %v", pinned, ok, err)
	}
	// While locked, an agent weakens config.toml: idle_soft 0-ish and a
	// root removed.
	cfg := x.h.Cfg
	cfg.Policy.IdleSoft = config.Duration(10 * time.Hour)
	cfg.Roots = slices.DeleteFunc(slices.Clone(cfg.Roots), func(r config.Root) bool { return r.ID == "root-beta" })
	if err := config.Save(x.h.Layout.ConfigFile, cfg); err != nil {
		t.Fatal(err)
	}
	x.restart()
	c = x.dial()
	eff := x.d.effective()
	if eff.Policy.IdleSoft.D() != 15*time.Minute {
		t.Fatalf("effective idle_soft = %v after restart (D55: pinned wins)", eff.Policy.IdleSoft.D())
	}
	if _, ok := eff.RootByID("root-beta"); !ok {
		t.Fatal("removed root no longer protected")
	}
	att := x.attention(c)
	if a, ok := att[ipc.AttnPendingPolicy]; !ok || a.Count == 0 {
		t.Fatalf("pending-policy missing: %+v", att)
	}
	if _, ok := att[ipc.AttnPolicyTampered]; ok {
		t.Fatal("a genuine pin reported as tampered")
	}
	p, err := c.Policy(context.Background(), ipc.PolicyReq{})
	if err != nil || len(p.Pending) == 0 {
		t.Fatalf("pending = %+v %v", p, err)
	}
	// A plain TTY unlock does not adopt the weakening edits …
	if _, err := x.unlockTTY(c, nil, "root-acme"); err != nil {
		t.Fatal(err)
	}
	if x.d.effective().Policy.IdleSoft.D() != 15*time.Minute {
		t.Fatal("weakening edit adopted without confirmation")
	}
	// … confirming them does (same connection, after a TTY unlock).
	if _, err := c.Policy(context.Background(), ipc.PolicyReq{Confirm: true}); err != nil {
		t.Fatal(err)
	}
	if x.d.effective().Policy.IdleSoft.D() != 10*time.Hour {
		t.Fatal("confirmed edit not applied")
	}
	// Confirmation from a connection that did not unlock is refused.
	c2 := x.dial()
	if _, err := c2.Policy(context.Background(), ipc.PolicyReq{Confirm: true}); ipcCode(err) != ipc.CodeUnauthorized {
		t.Fatalf("confirm without unlock = %v", err)
	}

	// A forged pinned file (bad MAC) raises policy-tampered at the next
	// unlock, and the defaults join the strictest merge.
	pinned, _, _ = config.LoadPinned(x.h.Layout.PolicyPinned)
	pinned.MACs["root-acme"] = strings.Repeat("0", 64)
	if err := config.SavePinned(x.h.Layout.PolicyPinned, pinned); err != nil {
		t.Fatal(err)
	}
	x.restart()
	c = x.dial()
	if _, err := x.unlockTTY(c, nil, "root-acme"); err != nil {
		t.Fatal(err)
	}
	x.eventually("policy-tampered", func() bool { _, ok := x.attention(c)[ipc.AttnPolicyTampered]; return ok })
	if x.d.effective().Policy.IdleSoft.D() != 15*time.Minute {
		t.Fatalf("defaults did not join the merge: idle_soft %v", x.d.effective().Policy.IdleSoft.D())
	}
}

func TestPinnedMissingWithVaults(t *testing.T) {
	x := startTD(t)
	c := x.dial()
	if _, ok := x.attention(c)[ipc.AttnPolicyTampered]; !ok {
		t.Fatal("vaults exist but no policy.pinned: must be policy-tampered (D55)")
	}
	_ = os.Remove(x.h.Layout.PolicyPinned)
}

// TestVaultRepair is SEC-26 (daemon side) with the CC-32 protocol: a dry
// run (Confirmed=false) unwraps, checks genuineness and reports the diff
// without writing anything; the confirmed call on the same connection
// within the hold uses the identity of the dry run (no second presence
// prompt); another connection, a lock or an expired hold unwraps again.
func TestVaultRepair(t *testing.T) {
	x := startTD(t)
	ctx := context.Background()
	x.h.Clock.Advance(2 * time.Hour) // capsules below are sealed in the past
	x.vaults.set(func(f *fakeVaults) {
		f.metas["root-acme"] = vault.Meta{ID: "root-acme", LastAudit: epochT.Add(30 * time.Minute)}
	})
	x.caps.add("md/old1/g000001.pcap", "root-acme", "root-acme")
	x.caps.mu.Lock()
	e := x.caps.entries["md/old1/g000001.pcap"]
	e.SealedAt = epochT // before last_audit: proves the key is genuine
	x.caps.entries["md/old1/g000001.pcap"] = e
	x.caps.mu.Unlock()
	x.caps.add("md/new1/g000001.pcap", "root-acme", "root-acme") // sealed after last_audit
	x.caps.mu.Lock()
	e = x.caps.entries["md/new1/g000001.pcap"]
	e.RecipientsFpr = "fpr-foreign"
	x.caps.entries["md/new1/g000001.pcap"] = e
	x.caps.mu.Unlock()

	// Without a terminal: refused.
	nt := platform.Peer{UID: os.Getuid(), PID: 6400, Proc: platform.ProcInfo{ID: platform.ProcID{PID: 6400, StartUS: 1}, PPID: 1}}
	x.h.Procs.Add(nt.Proc)
	x.setPeer(&nt, true)
	c := x.dial()
	for _, confirmed := range []bool{false, true} {
		if _, err := c.VaultRepair(ctx, ipc.VaultRepairReq{VaultID: "root-acme", Confirmed: confirmed}, nil, nil); ipcCode(err) != ipc.CodeAgentContext {
			t.Fatalf("repair without a terminal (confirmed %v) = %v", confirmed, err)
		}
	}
	// From an agent: refused.
	x.addProc(6100, 1, 6100, "/opt/homebrew/bin/claude", "claude")
	ap := platform.Peer{UID: os.Getuid(), PID: 6300, Proc: platform.ProcInfo{ID: platform.ProcID{PID: 6300, StartUS: 1}, PPID: 6100, TTY: "/dev/ttys004"}}
	x.h.Procs.Add(ap.Proc)
	x.setPeer(&ap, true)
	c = x.dial()
	if _, err := c.VaultRepair(ctx, ipc.VaultRepairReq{VaultID: "root-acme", Confirmed: true}, nil, nil); ipcCode(err) != ipc.CodeAgentContext {
		t.Fatalf("repair from an agent = %v", err)
	}
	if len(x.vaults.repairs) != 0 || x.vaults.count("root-acme") != 0 {
		t.Fatal("refused repair changed something or prompted")
	}
	// The user on a terminal: the dry run reports what a repair would do
	// and writes nothing.
	tty := platform.Peer{UID: os.Getuid(), PID: 6500, Proc: platform.ProcInfo{ID: platform.ProcID{PID: 6500, StartUS: 1}, PPID: 1, TTY: "/dev/ttys005"}}
	x.h.Procs.Add(tty.Proc)
	x.setPeer(&tty, true)
	c = x.dial()
	ui := &scripted{}
	plan, err := c.VaultRepair(ctx, ipc.VaultRepairReq{VaultID: "root-acme"}, nil, ui)
	if err != nil {
		t.Fatal(err)
	}
	if !plan.RecipientChanged || !slices.Equal(plan.Exposed, []string{"md/new1/g000001.pcap"}) {
		t.Fatalf("dry run = %+v", plan)
	}
	if len(x.vaults.repairs) != 0 {
		t.Fatal("the dry run wrote something")
	}
	if x.keys.Has("root-acme") || x.vaultState("root-acme") != VaultLocked {
		t.Fatal("the dry run unlocked the vault")
	}
	if len(ui.prompts) != 0 {
		t.Fatalf("the daemon relayed a confirmation (the client asks it now): %q", ui.prompts)
	}
	if n := x.vaults.count("root-acme"); n != 1 {
		t.Fatalf("dry run unwraps = %d", n)
	}
	// Confirmed on the same connection: no second presence prompt.
	r, err := c.VaultRepair(ctx, ipc.VaultRepairReq{VaultID: "root-acme", Confirmed: true}, nil, ui)
	if err != nil {
		t.Fatal(err)
	}
	if !r.RecipientChanged || !slices.Equal(r.Exposed, []string{"md/new1/g000001.pcap"}) || !slices.Equal(x.vaults.repairs, []string{"root-acme"}) {
		t.Fatalf("repair = %+v, repairs %v", r, x.vaults.repairs)
	}
	if n := x.vaults.count("root-acme"); n != 1 {
		t.Fatalf("the confirmed call unwrapped again (%d unwraps)", n)
	}
	if x.vaultState("root-acme") != VaultUnlocked {
		t.Fatal("repaired vault not unlocked")
	}
	x.d.mu.Lock()
	held := len(x.d.repairs)
	x.d.mu.Unlock()
	if held != 0 {
		t.Fatalf("%d repair identities still held after the confirmed call", held)
	}
	// A dry run on one connection, the confirmed call on another: unwraps
	// again (the identity is bound to its connection).
	if _, err := c.Lock(ctx, ipc.LockReq{All: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.VaultRepair(ctx, ipc.VaultRepairReq{VaultID: "root-acme"}, nil, ui); err != nil {
		t.Fatal(err)
	}
	c2 := x.dial()
	if _, err := c2.VaultRepair(ctx, ipc.VaultRepairReq{VaultID: "root-acme", Confirmed: true}, nil, ui); err != nil {
		t.Fatal(err)
	}
	if n := x.vaults.count("root-acme"); n != 3 {
		t.Fatalf("unwraps = %d, want 3 (the other connection unwraps again)", n)
	}
	// A lock between the dry run and the confirmation wipes the identity.
	if _, err := c.VaultRepair(ctx, ipc.VaultRepairReq{VaultID: "root-acme"}, nil, ui); err != nil {
		t.Fatal(err)
	}
	x.d.mu.Lock()
	held = len(x.d.repairs)
	x.d.mu.Unlock()
	if held != 1 {
		t.Fatalf("held = %d after a dry run", held)
	}
	if _, err := c2.Lock(ctx, ipc.LockReq{RootIDs: []string{"root-beta"}}); err != nil {
		t.Fatal(err)
	}
	x.eventually("any lock wipes the dry run's identity", func() bool {
		x.d.mu.Lock()
		defer x.d.mu.Unlock()
		return len(x.d.repairs) == 0
	})
	if _, err := c.VaultRepair(ctx, ipc.VaultRepairReq{VaultID: "root-acme", Confirmed: true}, nil, ui); err != nil {
		t.Fatal(err)
	}
	if n := x.vaults.count("root-acme"); n != 5 {
		t.Fatalf("unwraps = %d, want 5 (wiped by the lock)", n)
	}
	// An expired hold (120 s on either clock) unwraps again.
	if _, err := c.VaultRepair(ctx, ipc.VaultRepairReq{VaultID: "root-acme"}, nil, ui); err != nil {
		t.Fatal(err)
	}
	x.h.Clock.Advance(121 * time.Second)
	if _, err := c.VaultRepair(ctx, ipc.VaultRepairReq{VaultID: "root-acme", Confirmed: true}, nil, ui); err != nil {
		t.Fatal(err)
	}
	if n := x.vaults.count("root-acme"); n != 7 {
		t.Fatalf("unwraps = %d, want 7 (hold expired)", n)
	}
	// The connection closing wipes a held identity too.
	c3 := x.dial()
	if _, err := c3.VaultRepair(ctx, ipc.VaultRepairReq{VaultID: "root-acme"}, nil, ui); err != nil {
		t.Fatal(err)
	}
	c3.Close()
	x.eventually("closing the connection wipes the identity", func() bool {
		x.d.mu.Lock()
		defer x.d.mu.Unlock()
		return len(x.d.repairs) == 0
	})
	// A key that opens no older capsule is not genuine: nothing changes.
	x.vaults.set(func(f *fakeVaults) {
		f.metas["root-beta"] = vault.Meta{ID: "root-beta", LastAudit: epochT.Add(30 * time.Minute)}
	})
	x.caps.add("md/beta/g000001.pcap", "root-beta", "root-beta")
	x.caps.mu.Lock()
	e = x.caps.entries["md/beta/g000001.pcap"]
	e.SealedAt = epochT
	x.caps.entries["md/beta/g000001.pcap"] = e
	x.caps.mu.Unlock()
	n := len(x.vaults.repairs)
	for _, confirmed := range []bool{false, true} {
		if _, err := c.VaultRepair(ctx, ipc.VaultRepairReq{VaultID: "root-beta", Confirmed: confirmed}, nil, ui); ipcCode(err) != ipc.CodeVerify {
			t.Fatalf("not genuine (confirmed %v) = %v (C14.notgenuine)", confirmed, err)
		}
	}
	if len(x.vaults.repairs) != n {
		t.Fatal("a non-genuine key repaired the vault")
	}
	// The recovery recipient changed and no recovery key: ErrNeedRecovery,
	// in the dry run already.
	x.vaults.set(func(f *fakeVaults) { f.repairErr = vault.ErrNeedRecovery })
	for _, confirmed := range []bool{false, true} {
		if _, err := c.VaultRepair(ctx, ipc.VaultRepairReq{VaultID: "root-acme", Confirmed: confirmed}, nil, ui); ipcCode(err) != ipc.CodeUnauthorized {
			t.Fatalf("need recovery (confirmed %v) = %v", confirmed, err)
		}
	}
}

// TestVaultRepairRecoveryKeyMustMatch: with --recovery the confirmed call
// reuses the dry run's identity only when it sends the same recovery key.
func TestVaultRepairRecoveryKeyMustMatch(t *testing.T) {
	x := startTD(t)
	ctx := context.Background()
	c := x.dial()
	ui := &scripted{}
	key := func(s string) *memguard.LockedBuffer { return memguard.NewBufferFromBytes([]byte(s)) }
	k := key("AGE-SECRET-KEY-1RECOVERYONE")
	if _, err := c.VaultRepair(ctx, ipc.VaultRepairReq{VaultID: "root-acme", UseRecovery: true}, k, ui); err != nil {
		t.Fatal(err)
	}
	k.Destroy()
	if n := x.vaults.count("root-acme"); n != 1 {
		t.Fatalf("unwraps = %d", n)
	}
	k = key("AGE-SECRET-KEY-1RECOVERYTWO")
	if _, err := c.VaultRepair(ctx, ipc.VaultRepairReq{VaultID: "root-acme", UseRecovery: true, Confirmed: true}, k, ui); err != nil {
		t.Fatal(err)
	}
	k.Destroy()
	if n := x.vaults.count("root-acme"); n != 2 {
		t.Fatalf("unwraps = %d, want 2 (another recovery key unwraps again)", n)
	}
	k = key("AGE-SECRET-KEY-1RECOVERYONE")
	if _, err := c.VaultRepair(ctx, ipc.VaultRepairReq{VaultID: "root-acme", UseRecovery: true}, k, ui); err != nil {
		t.Fatal(err)
	}
	k.Destroy()
	k = key("AGE-SECRET-KEY-1RECOVERYONE")
	if _, err := c.VaultRepair(ctx, ipc.VaultRepairReq{VaultID: "root-acme", UseRecovery: true, Confirmed: true}, k, ui); err != nil {
		t.Fatal(err)
	}
	k.Destroy()
	if n := x.vaults.count("root-acme"); n != 3 {
		t.Fatalf("unwraps = %d, want 3 (the same key reuses the dry run)", n)
	}
	if _, err := c.VaultRepair(ctx, ipc.VaultRepairReq{VaultID: "root-acme", UseRecovery: true}, nil, ui); ipcCode(err) != ipc.CodeBadRequest {
		t.Fatalf("--recovery without the key = %v", err)
	}
}

func TestVaultCreateAndFactorAdd(t *testing.T) {
	x := startTD(t)
	c := x.dial()
	ctx := context.Background()
	gamma := x.h.Protect(t, "work/gamma")
	x.h.Clock.Advance(time.Second)
	if err := c.VaultCreate(ctx, ipc.VaultCreateReq{RootID: gamma.ID, RootPath: gamma.Path}, nil); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(x.vaults.created, gamma.ID) || x.vaultState(gamma.ID) != VaultUnlocked {
		t.Fatal("new vault not created unlocked")
	}
	if err := c.VaultCreate(ctx, ipc.VaultCreateReq{RootID: "root-nope", RootPath: "/nope"}, nil); ipcCode(err) != ipc.CodeBadRequest {
		t.Fatalf("unknown root = %v", err)
	}
	// Factor add needs every vault unlocked.
	if err := c.FactorAdd(ctx, ipc.FactorAddReq{Kind: "passphrase"}, &scripted{secret: "correct horse battery staple"}); ipcCode(err) != ipc.CodeLocked {
		t.Fatalf("factor add with locked vaults = %v", err)
	}
	x.addVault(gamma.ID)
	if _, err := c.Unlock(ctx, ipc.UnlockReq{All: true, TTY: true, Confirmed: true}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := x.unlockTTY(c, nil, vault.GlobalID); err != nil {
		t.Fatal(err)
	}
	ui := &scripted{secret: "correct horse battery staple"}
	if err := c.FactorAdd(ctx, ipc.FactorAddReq{Kind: "passphrase"}, ui); err != nil {
		t.Fatal(err)
	}
	if len(x.vaults.factors) != 4 {
		t.Fatalf("factors = %v (every vault)", x.vaults.factors)
	}
	if err := c.FactorAdd(ctx, ipc.FactorAddReq{Kind: "telepathy"}, ui); ipcCode(err) != ipc.CodeBadRequest {
		t.Fatalf("unknown kind = %v", err)
	}
}

func TestHookRaisedUnlock(t *testing.T) {
	x := startTD(t)
	// unlock_on_prompt on (it ships off until the E2E passes, D60).
	cfg := x.h.Cfg
	cfg.Policy.UnlockOnPrompt = true
	if err := config.Save(x.h.Layout.ConfigFile, cfg); err != nil {
		t.Fatal(err)
	}
	// Pin it so the change is not a pending weakening edit: a confirmed
	// TTY unlock writes a genuine pin (D91: a pin without a vault MAC is
	// forged), then the folder locks again with the daemon's restart.
	x.restart()
	ctx := context.Background()
	c0 := x.dial()
	if _, err := x.unlockTTY(c0, nil, "root-acme"); err != nil {
		t.Fatal(err)
	}
	if _, err := c0.Policy(ctx, ipc.PolicyReq{Confirm: true}); err != nil {
		t.Fatal(err)
	}
	x.restart()
	c := x.dial()
	cl := x.addProc(4100, 1, 4100, "/opt/homebrew/bin/claude", "claude")
	if err := c.Register(ctx, ipc.RegisterReq{Harness: "claude-code", SID: sidA, PID: cl.ID.PID, Cwd: x.h.Root, TTY: "/dev/ttys006"}); err != nil {
		t.Fatal(err)
	}
	// An automated prompt (HID idle 10 min): blocked, not eligible.
	x.setScreen(platform.ScreenState{LockKnown: true, IdleKnown: true, HIDIdle: 10 * time.Minute})
	x.eventually("screen known", func() bool { return x.d.snap.Load().screenKnown })
	g, _ := c.Gate(ctx, ipc.GateReq{Harness: "claude-code", Event: "UserPromptSubmit", SID: sidA, PromptID: "p1", Cwd: x.h.Root})
	if g.Verdict != ipc.VerdictBlock || g.UnlockEligible {
		t.Fatalf("automated prompt = %+v (never raises a dialog, D26)", g)
	}
	if _, err := c.Unlock(ctx, ipc.UnlockReq{RootIDs: []string{"root-acme"}, FromHook: true, SID: sidA}, nil); ipcCode(err) != ipc.CodeNoUI {
		t.Fatalf("hook unlock after an automated prompt = %v", err)
	}
	// A human prompt: eligible; the hook's unlock proceeds through a GUI
	// factor and the session's terminal gets the OSC 9 notice first.
	x.setScreen(platform.ScreenState{LockKnown: true, IdleKnown: true, HIDIdle: time.Second})
	x.guiFactor("root-acme")
	x.eventually("factor cache", func() bool { return x.guiFactor("root-acme") })
	g, _ = c.Gate(ctx, ipc.GateReq{Harness: "claude-code", Event: "UserPromptSubmit", SID: sidA, PromptID: "p2", Cwd: x.h.Root})
	if g.Origin != ipc.OriginHuman || !g.UnlockEligible {
		t.Fatalf("human prompt = %+v", g)
	}
	if _, err := c.Unlock(ctx, ipc.UnlockReq{RootIDs: []string{"root-acme"}, FromHook: true, SID: sidA}, nil); err != nil {
		t.Fatalf("hook unlock = %v", err)
	}
	x.rec.mu.Lock()
	notified := slices.Clone(x.rec.notified)
	x.rec.mu.Unlock()
	if !slices.Equal(notified, []string{"/dev/ttys006"}) {
		t.Fatalf("notified = %v (D60)", notified)
	}
	// The screen is locked: no hook dialog.
	if _, err := c.Lock(ctx, ipc.LockReq{All: true}); err != nil {
		t.Fatal(err)
	}
	x.setScreen(platform.ScreenState{Locked: true, LockKnown: true, IdleKnown: true, HIDIdle: time.Second})
	x.eventually("screen locked", func() bool { return x.d.snap.Load().screenLocked })
	if _, err := c.Unlock(ctx, ipc.UnlockReq{RootIDs: []string{"root-acme"}, FromHook: true, SID: sidA}, nil); ipcCode(err) != ipc.CodeNoUI {
		t.Fatalf("hook unlock while the screen is locked = %v", err)
	}
}

// guiFactor on td loads the factor cache synchronously for tests.
func (x *td) guiFactor(id string) bool { x.d.loadFactors(id); return x.d.guiFactor(id) }

// CC-32: a screen lock wipes a held repair identity even when every vault
// is locked already (no key to wipe).
func TestScreenLockWipesHeldRepair(t *testing.T) {
	x := startTD(t)
	c := x.dial()
	if _, err := c.VaultRepair(context.Background(), ipc.VaultRepairReq{VaultID: "root-acme"}, nil, &scripted{}); err != nil {
		t.Fatal(err)
	}
	held := func() int {
		x.d.mu.Lock()
		defer x.d.mu.Unlock()
		return len(x.d.repairs)
	}
	if held() != 1 {
		t.Fatal("no identity held after the dry run")
	}
	x.setScreen(platform.ScreenState{Locked: true, LockKnown: true})
	x.eventually("the screen lock wipes it", func() bool { return held() == 0 })
}
