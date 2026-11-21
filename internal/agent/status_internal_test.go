package agent

import (
	"context"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/precinto/precinto/internal/config"
	"github.com/precinto/precinto/internal/ipc"
	"github.com/precinto/precinto/internal/platform"
	"github.com/precinto/precinto/internal/ui"
	"github.com/precinto/precinto/internal/vault"
)

// CC-49: status shows the harness version a registration reported; a value
// that is not a plain version string is dropped (status prints it).
func TestSessionVersionFromRegister(t *testing.T) {
	x := startTD(t)
	c := x.dial()
	ctx := context.Background()
	ok := x.addProc(5400, 1, 5400, "/opt/homebrew/bin/claude", "claude")
	bad := x.addProc(5410, 1, 5410, "/opt/homebrew/bin/claude", "claude")
	if err := c.Register(ctx, ipc.RegisterReq{Harness: "claude-code", SID: sidA, PID: ok.ID.PID, Cwd: x.h.Root, Version: "2.1.329"}); err != nil {
		t.Fatal(err)
	}
	if err := c.Register(ctx, ipc.RegisterReq{Harness: "claude-code", SID: sidB, PID: bad.ID.PID, Cwd: x.h.Root, Version: "2.1\x1b[31mred"}); err != nil {
		t.Fatal(err)
	}
	st, err := c.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, s := range st.Sessions {
		got[s.SID] = s.Version
	}
	if got[sidA] != "2.1.329" || got[sidB] != "" {
		t.Fatalf("versions = %v", got)
	}
}

// CC-50: a factor test unwraps with the named factor and checks the
// identity, then drops it: the folder stays locked, no worker is spawned,
// the policy is not re-pinned; agents and hooks cannot run one.
func TestFactorTest(t *testing.T) {
	x := startTD(t)
	c := x.dial()
	ctx := context.Background()
	spawned := len(x.spawnedArgs())
	r, err := c.Unlock(ctx, ipc.UnlockReq{RootIDs: []string{"root-acme"}, TTY: true, Test: true, Factor: "se"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Unlocked) != 0 || x.vaultState("root-acme") != VaultLocked || x.keys.Has("root-acme") {
		t.Fatalf("a factor test unlocked the folder: %+v", r)
	}
	if x.vaults.count("root-acme") != 1 {
		t.Fatalf("unwraps = %d", x.vaults.count("root-acme"))
	}
	if len(x.spawnedArgs()) != spawned {
		t.Fatalf("a factor test spawned %q", x.spawnedArgs()[spawned:])
	}
	if _, ok, _ := config.LoadPinned(x.h.Layout.PolicyPinned); ok {
		t.Fatal("a factor test pinned the policy")
	}
	// A tampered vault fails the test like an unlock (exit 5) and says so.
	x.vaults.set(func(f *fakeVaults) { f.verifyErr["root-beta"] = vault.ErrMACMismatch })
	if _, err := c.Unlock(ctx, ipc.UnlockReq{RootIDs: []string{"root-beta"}, TTY: true, Test: true}, nil); ipcCode(err) != ipc.CodeVerify {
		t.Fatalf("factor test of a tampered vault = %v", err)
	}
	if !x.hasAttention(ipc.AttnVaultTampered, "~/work/beta") {
		t.Fatal("no vault-tampered attention")
	}
	// From a hook: refused.
	if _, err := c.Unlock(ctx, ipc.UnlockReq{RootIDs: []string{"root-acme"}, Test: true, FromHook: true, SID: sidA}, nil); ipcCode(err) != ipc.CodeBadRequest {
		t.Fatalf("factor test from a hook = %v", err)
	}
	// From an agent (a claude ancestor): refused, no prompt.
	x.addProc(6100, 1, 6100, "/opt/homebrew/bin/claude", "claude")
	x.h.Procs.SetCwd(6100, x.h.Root)
	ap := platform.Peer{UID: os.Getuid(), PID: 6300, Proc: platform.ProcInfo{ID: platform.ProcID{PID: 6300, StartUS: 1}, PPID: 6100, TTY: "/dev/ttys004"}}
	x.h.Procs.Add(ap.Proc)
	x.setPeer(&ap, true)
	ca := x.dial()
	n := x.vaults.count("root-acme")
	if _, err := ca.Unlock(ctx, ipc.UnlockReq{RootIDs: []string{"root-acme"}, TTY: true, Test: true}, nil); ipcCode(err) != ipc.CodeAgentContext || x.vaults.count("root-acme") != n {
		t.Fatalf("factor test from an agent = %v", err)
	}
}

// CC-08: a wrong passphrase or recovery key is bad_secret (exit 3, C2.badsecret),
// counts toward the prompt rate limit like a cancel, and is never a tamper
// alert.
func TestBadSecret(t *testing.T) {
	x := startTD(t)
	c := x.dial()
	x.vaults.set(func(f *fakeVaults) { f.unwrapErr["root-acme"] = vault.ErrBadSecret })
	_, err := x.unlockTTY(c, nil, "root-acme")
	var e *ipc.Error
	if ipcCode(err) != ipc.CodeBadSecret || !asErr(err, &e) || e.Msg != ui.Format(ui.MsgUnlockBadSecret, ui.Vars{Folder: "~/work/acme"}) || e.ExitCode() != 3 {
		t.Fatalf("wrong secret = %v", err)
	}
	if _, err := x.unlockTTY(c, nil, "root-acme"); ipcCode(err) != ipc.CodeRateLimited {
		t.Fatalf("retry right after a wrong secret = %v (back-off like a cancel, D27)", err)
	}
	for i := 0; i < 2; i++ {
		x.h.Clock.Advance(31 * time.Second)
		if _, err := x.unlockTTY(c, nil, "root-acme"); ipcCode(err) != ipc.CodeBadSecret {
			t.Fatalf("wrong secret %d = %v", i+2, err)
		}
	}
	if n := x.vaults.count("root-acme"); n != 3 {
		t.Fatalf("prompts = %d, want 3 (the rate-limited retry never prompted)", n)
	}
	if x.hasAttention(ipc.AttnVaultTampered, "") {
		t.Fatal("a wrong secret raised a tamper alert")
	}
	// Key-release presence answered with a wrong secret: bad_secret too.
	x.vaults.set(func(f *fakeVaults) { delete(f.unwrapErr, "root-acme") })
	x.h.Clock.Advance(31 * time.Second)
	if _, err := x.unlockTTY(c, nil, "root-acme"); err != nil {
		t.Fatal(err)
	}
	x.caps.add("md/aaaa/g000001.pcap", "root-acme", "root-acme")
	x.vaults.set(func(f *fakeVaults) { f.unwrapErr["root-acme"] = vault.ErrBadSecret })
	agent := x.markerPeer(7800, x.h.Root) // an agent context working in the folder
	x.setPeer(&agent, true)
	cm := x.dial()
	ks, resp, err := cm.Keys(context.Background(), ipc.KeysReq{Capsules: []ipc.CapsuleRef{{Path: "md/aaaa/g000001.pcap"}}, Purpose: ipc.PurposeCat, AgentMarkers: []string{"CLAUDECODE"}})
	if err != nil {
		t.Fatal(err)
	}
	ks.Destroy()
	if resp.Denied["md/aaaa/g000001.pcap"] != ipc.CodeBadSecret {
		t.Fatalf("presence with a wrong secret = %+v", resp)
	}
}

func asErr(err error, target **ipc.Error) bool {
	e, ok := err.(*ipc.Error)
	if ok {
		*target = e
	}
	return ok
}

// CC-40: locked, unlocked and expiring events carry the folder's factor
// kinds in unlock order.
func TestEventsCarryFactors(t *testing.T) {
	x := startTD(t)
	x.vaults.set(func(f *fakeVaults) {
		f.metas["root-acme"] = vault.Meta{ID: "root-acme", Factors: []vault.Factor{
			{Name: "passphrase", Kind: vault.FactorPassphrase}, {Name: "recovery", Kind: vault.FactorRecovery}}}
	})
	x.d.refreshFactors("root-acme")
	c := x.dial()
	ctx := context.Background()
	sub, err := c.Subscribe(ctx, ipc.SubscribeReq{RootIDs: []string{"root-acme"}})
	if err != nil {
		t.Fatal(err)
	}
	got := collect(sub)
	if _, err := x.unlockTTY(c, nil, "root-acme"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Lock(ctx, ipc.LockReq{RootIDs: []string{"root-acme"}}); err != nil {
		t.Fatal(err)
	}
	x.eventually("locked, unlocked, locked", func() bool {
		return slices.Equal(got.kinds(), []ipc.EventKind{ipc.EventLocked, ipc.EventUnlocked, ipc.EventLocked})
	})
	got.mu.Lock()
	defer got.mu.Unlock()
	for _, ev := range got.evs {
		if ev.Kind == ipc.EventHeartbeat {
			continue
		}
		if !slices.Equal(ev.Factors, []string{"passphrase"}) {
			t.Fatalf("%s event factors = %v", ev.Kind, ev.Factors)
		}
	}
	if strings.Contains(strings.Join(got.evs[0].Factors, ","), "recovery") {
		t.Fatal("recovery named as a factor")
	}
}
