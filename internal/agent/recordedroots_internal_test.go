package agent

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/precinto/precinto/internal/config"
	"github.com/precinto/precinto/internal/ipc"
	"github.com/precinto/precinto/internal/vault"
)

// D145 (SEC-48, S6-1): a pin whose only MAC is a well-formed "global"
// entry — checked only by unlock --global — no longer authenticates
// settings that name folders: a one-shot writer that drops root-beta from
// config.toml and plants such a pin gets policy-tampered at the next start,
// and while tampered every folder a vault records stays enforced (locked,
// in roots.list) and its removal shows in the review of the next terminal
// unlock (S6-R-SEC-F1: before, the folder left enforcement even under
// policy-tampered, since the defaults hold no folder).
func TestGlobalOnlyMACPinKeepsDroppedFolderProtected(t *testing.T) {
	x := startTD(t)
	beta, _ := x.h.Cfg.RootByID("root-beta")
	x.vaults.set(func(f *fakeVaults) {
		f.metas["root-beta"] = vault.Meta{ID: "root-beta", RootPath: beta.Path, Factors: []vault.Factor{{Name: "se", Kind: vault.FactorSE, GUI: true}}}
	})
	c := x.dial()
	if _, err := x.unlockTTY(c, nil, "root-acme"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Lock(context.Background(), ipc.LockReq{All: true}); err != nil {
		t.Fatal(err)
	}
	cfg := x.h.Cfg
	cfg.Roots = slices.DeleteFunc(slices.Clone(cfg.Roots), func(r config.Root) bool { return r.ID == "root-beta" })
	if err := config.Save(x.h.Layout.ConfigFile, cfg); err != nil {
		t.Fatal(err)
	}
	x.plant(config.Pinned{Config: cfg, MACs: map[string]string{config.PinnedGlobalVault: strings.Repeat("0", 64)}})

	x.restart()
	c = x.dial()
	if _, ok := x.attention(c)[ipc.AttnPolicyTampered]; !ok {
		t.Fatal("a pin of settings that name a folder, with only a global MAC, is not policy-tampered")
	}
	if _, ok := x.d.effective().RootByID("root-beta"); !ok {
		t.Fatal("the folder the forged pin and config.toml dropped left enforcement")
	}
	if x.vaultState("root-beta") != VaultLocked {
		t.Fatalf("root-beta is %v, want locked", x.vaultState("root-beta"))
	}
	x.eventually("root-beta in roots.list", func() bool {
		list, _ := config.ReadRootsList(x.h.Layout.RootsList)
		return slices.Contains(list, beta.Path)
	})
	resp, err := x.unlockTTY(c, nil, "root-acme")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, p := range resp.Pending {
		found = found || strings.HasPrefix(p, "roots[root-beta]")
	}
	if !found {
		t.Fatalf("the review does not list root-beta's removal: %q", resp.Pending)
	}
}

// D145: the daemon never writes a pin the shape check calls forged. An
// unlock --global confirming settings that name folders, while no folder
// is unlocked, leaves the pin alone (its MAC would be "global" only); the
// next terminal unlock of a folder signs it with that folder's key.
func TestGlobalUnlockNeverWritesAGlobalOnlyPin(t *testing.T) {
	x := startTD(t)
	c := x.dial()
	if _, err := x.unlockTTY(c, nil, "root-acme"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Lock(context.Background(), ipc.LockReq{All: true}); err != nil {
		t.Fatal(err)
	}
	before := x.pinBytes()
	cfg := x.weakened(false) // a weakening edit to confirm
	_ = cfg
	x.restart()
	c = x.dial()
	if _, err := c.Unlock(context.Background(), ipc.UnlockReq{Global: true, TTY: true, ConfirmDiff: true}, nil); err != nil {
		t.Fatal(err)
	}
	if string(x.pinBytes()) != string(before) {
		p, _, _ := config.LoadPinned(x.h.Layout.PolicyPinned)
		t.Fatalf("unlock --global re-pinned settings that name folders with MACs %v", p.MACs)
	}
	if _, err := c.Unlock(context.Background(), ipc.UnlockReq{RootIDs: []string{"root-acme"}, TTY: true, ConfirmDiff: true}, nil); err != nil {
		t.Fatal(err)
	}
	p, ok, err := config.LoadPinned(x.h.Layout.PolicyPinned)
	if err != nil || !ok || p.MACs["root-acme"] == "" {
		t.Fatalf("the folder unlock did not sign the confirmed settings: %+v %v", p.MACs, err)
	}
	if err := p.CheckShape(func(string) bool { return true }); err != nil {
		t.Fatalf("the pin written has a forged shape: %v", err)
	}
}

// D145: the same holds when the forgery shows only at an unlock (D91's
// tripwire): a pin dropping root-beta with a well-formed but wrong MAC of
// root-acme is unverified at start; the terminal unlock of root-acme finds
// the MAC wrong, raises policy-tampered, and root-beta is enforced again.
func TestMACMismatchKeepsDroppedFolderProtected(t *testing.T) {
	x := startTD(t)
	beta, _ := x.h.Cfg.RootByID("root-beta")
	x.vaults.set(func(f *fakeVaults) {
		f.metas["root-beta"] = vault.Meta{ID: "root-beta", RootPath: beta.Path, Factors: []vault.Factor{{Name: "se", Kind: vault.FactorSE, GUI: true}}}
	})
	c := x.dial()
	if _, err := x.unlockTTY(c, nil, "root-acme"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Lock(context.Background(), ipc.LockReq{All: true}); err != nil {
		t.Fatal(err)
	}
	cfg := x.weakened(true) // root-beta dropped from config.toml
	x.plant(config.Pinned{Config: cfg, MACs: map[string]string{"root-acme": strings.Repeat("0", 64)}})
	x.restart()
	c = x.dial()
	if _, err := x.unlockTTY(c, nil, "root-acme"); err != nil {
		t.Fatal(err)
	}
	x.eventually("policy-tampered", func() bool { _, ok := x.attention(c)[ipc.AttnPolicyTampered]; return ok })
	x.eventually("root-beta enforced", func() bool { _, ok := x.d.effective().RootByID("root-beta"); return ok })
	if x.vaultState("root-beta") != VaultLocked {
		t.Fatalf("root-beta is %v, want locked", x.vaultState("root-beta"))
	}
}
