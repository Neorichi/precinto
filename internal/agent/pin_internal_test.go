package agent

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/Neorichi/precinto/internal/config"
	"github.com/Neorichi/precinto/internal/ipc"
	"github.com/Neorichi/precinto/internal/platform"
	"github.com/Neorichi/precinto/internal/vault"
)

// freshInstall is a td option: `precinto init` ran (the global vault
// exists) but no folder has a vault yet, and nothing is pinned.
func freshInstall(x *td, _ *Options) {
	for _, id := range []string{"root-acme", "root-beta"} {
		if err := os.RemoveAll(x.h.Layout.VaultDir(id)); err != nil {
			x.t.Fatal(err)
		}
	}
	_ = os.Remove(x.h.Layout.PolicyPinned)
}

// weakIdleSoft is a td option: config.toml was edited to a weaker idle
// lock than the default before the daemon starts.
func weakIdleSoft(x *td, _ *Options) {
	cfg, err := config.Load(x.h.Layout.ConfigFile)
	if err != nil {
		x.t.Fatal(err)
	}
	cfg.Policy.IdleSoft = config.Duration(45 * time.Minute)
	if err := config.Save(x.h.Layout.ConfigFile, cfg); err != nil {
		x.t.Fatal(err)
	}
}

// D68: before the first root vault a missing pin is the normal first-run
// state (no policy-tampered) and the defaults are the floor; the first
// vault_create pins that policy (never a weakening) with the new vault's
// MAC; a weaker config.toml stays pending until a confirmation.
func TestFirstPinAtFirstProtect(t *testing.T) {
	x := startTD(t, freshInstall, weakIdleSoft)
	c := x.dial()
	ctx := context.Background()
	if _, ok := x.attention(c)[ipc.AttnPolicyTampered]; ok {
		t.Fatal("a fresh install (no root vault) reports policy-tampered")
	}
	if got := x.d.effective().Policy.IdleSoft.D(); got != 15*time.Minute {
		t.Fatalf("effective idle_soft before the first pin = %v, want the default 15m (Strictest of config.toml and the defaults)", got)
	}
	if a, ok := x.attention(c)[ipc.AttnPendingPolicy]; !ok || a.Count == 0 {
		t.Fatalf("the weaker config.toml is not pending: %+v", x.attention(c))
	}
	if _, ok, _ := config.LoadPinned(x.h.Layout.PolicyPinned); ok {
		t.Fatal("pinned before any vault_create")
	}
	// The first protect: vault_create of root-acme pins what is enforced.
	acme, _ := x.h.Cfg.RootByID("root-acme")
	if err := c.VaultCreate(ctx, ipc.VaultCreateReq{RootID: acme.ID, RootPath: acme.Path}, nil); err != nil {
		t.Fatal(err)
	}
	x.addVault(acme.ID)
	pinned, ok, err := config.LoadPinned(x.h.Layout.PolicyPinned)
	if err != nil || !ok {
		t.Fatalf("no first pin: %v", err)
	}
	if pinned.Config.Policy.IdleSoft.D() != 15*time.Minute {
		t.Fatalf("first pin idle_soft = %v (it pins what is enforced, never a weakening)", pinned.Config.Policy.IdleSoft.D())
	}
	if pinned.MACs[acme.ID] == "" {
		t.Fatalf("first pin MACs = %v (the new vault's MAC)", pinned.MACs)
	}
	if _, ok := x.attention(c)[ipc.AttnPolicyTampered]; ok {
		t.Fatal("policy-tampered after the first pin")
	}
	if got := x.d.effective().Policy.IdleSoft.D(); got != 15*time.Minute {
		t.Fatalf("effective idle_soft after the first pin = %v", got)
	}
	if _, ok := x.attention(c)[ipc.AttnPendingPolicy]; !ok {
		t.Fatal("the weakening edit stopped being pending at the first pin")
	}
	// A daemon restart keeps it: the pin is genuine.
	x.restart()
	c = x.dial()
	if _, ok := x.attention(c)[ipc.AttnPolicyTampered]; ok {
		t.Fatal("the first pin reads as tampered after a restart")
	}
	// The user confirms the weaker value at a TTY unlock (D68).
	if _, err := c.Unlock(ctx, ipc.UnlockReq{RootIDs: []string{acme.ID}, TTY: true, ConfirmDiff: true}, nil); err != nil {
		t.Fatal(err)
	}
	if got := x.d.effective().Policy.IdleSoft.D(); got != 45*time.Minute {
		t.Fatalf("confirmed idle_soft = %v", got)
	}
}

// D68: once a root vault exists a missing pin is tampering, and a later
// folder's vault_create adds that folder to a genuine pin (so removing it
// from config.toml is a weakening edit) without adopting a pending
// weakening.
func TestLaterProtectJoinsThePin(t *testing.T) {
	x := startTD(t, freshInstall)
	c := x.dial()
	ctx := context.Background()
	acme, _ := x.h.Cfg.RootByID("root-acme")
	if err := c.VaultCreate(ctx, ipc.VaultCreateReq{RootID: acme.ID, RootPath: acme.Path}, nil); err != nil {
		t.Fatal(err)
	}
	x.addVault(acme.ID)
	gamma := x.h.Protect(t, "work/gamma")
	x.h.Clock.Advance(time.Second)
	// The user at a terminal protects it (a precinto peer with a TTY).
	user := platform.Peer{UID: os.Getuid(), PID: 6600, Proc: platform.ProcInfo{ID: platform.ProcID{PID: 6600, StartUS: 1}, PPID: 1, TTY: "/dev/ttys013"}}
	x.h.Procs.Add(user.Proc)
	x.setPeer(&user, true)
	cu := x.dial()
	if err := cu.VaultCreate(ctx, ipc.VaultCreateReq{RootID: gamma.ID, RootPath: gamma.Path}, nil); err != nil {
		t.Fatal(err)
	}
	x.addVault(gamma.ID)
	pinned, _, err := config.LoadPinned(x.h.Layout.PolicyPinned)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := pinned.Config.RootByID(gamma.ID); !ok {
		t.Fatal("the new folder did not join the pin")
	}
	// An agent removes it from config.toml: it stays protected and the
	// removal is a pending weakening edit.
	cfg, _ := config.Load(x.h.Layout.ConfigFile)
	var kept []config.Root
	for _, r := range cfg.Roots {
		if r.ID != gamma.ID {
			kept = append(kept, r)
		}
	}
	cfg.Roots = kept
	if err := config.Save(x.h.Layout.ConfigFile, cfg); err != nil {
		t.Fatal(err)
	}
	x.d.reloadPolicy(ctx)
	if _, ok := x.d.effective().RootByID(gamma.ID); !ok {
		t.Fatal("a folder removed from config.toml lost its protection")
	}
	if _, ok := x.attention(cu)[ipc.AttnPendingPolicy]; !ok {
		t.Fatal("the removal is not pending")
	}
	// Deleting the pin once root vaults exist is tampering (D55).
	if err := os.Remove(x.h.Layout.PolicyPinned); err != nil {
		t.Fatal(err)
	}
	x.restart()
	c = x.dial()
	if _, ok := x.attention(c)[ipc.AttnPolicyTampered]; !ok {
		t.Fatal("a missing pin with root vaults is not policy-tampered")
	}
	// vault_create of yet another folder never heals a tampered policy.
	delta := x.h.Protect(t, "work/delta")
	x.setPeer(&user, true)
	cu = x.dial()
	if err := cu.VaultCreate(ctx, ipc.VaultCreateReq{RootID: delta.ID, RootPath: delta.Path}, nil); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := config.LoadPinned(x.h.Layout.PolicyPinned); ok {
		t.Fatal("vault_create re-pinned a tampered policy without confirmation")
	}
	if _, ok := x.attention(cu)[ipc.AttnPolicyTampered]; !ok {
		t.Fatal("policy-tampered cleared by vault_create")
	}
}

// D68: a forged pin is never re-pinned without confirmation, even by a TTY
// unlock with nothing weakening pending; with ConfirmDiff it is.
func TestForgedPinNeedsConfirmation(t *testing.T) {
	x := startTD(t)
	if err := os.WriteFile(x.h.Layout.PolicyPinned, []byte("not a pin"), 0o600); err != nil {
		t.Fatal(err)
	}
	x.restart()
	c := x.dial()
	if _, ok := x.attention(c)[ipc.AttnPolicyTampered]; !ok {
		t.Fatal("an undecodable pin is not policy-tampered")
	}
	if _, err := x.unlockTTY(c, nil, "root-acme"); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := config.LoadPinned(x.h.Layout.PolicyPinned); ok || err == nil {
		t.Fatal("a plain TTY unlock rewrote a forged pin")
	}
	if _, err := c.Unlock(context.Background(), ipc.UnlockReq{RootIDs: []string{vault.GlobalID}, TTY: true, ConfirmDiff: true}, nil); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := config.LoadPinned(x.h.Layout.PolicyPinned); !ok || err != nil {
		t.Fatalf("a confirmed unlock did not re-pin: %v", err)
	}
	if _, ok := x.attention(c)[ipc.AttnPolicyTampered]; ok {
		t.Fatal("policy-tampered after the confirmation")
	}
}
