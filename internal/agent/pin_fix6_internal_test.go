package agent

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/precinto/precinto/internal/config"
	"github.com/precinto/precinto/internal/ipc"
)

// D137 (S6-4, SEC-44): a pin no vault key has authenticated in this
// daemon's lifetime can only strengthen. A one-shot writer weakens
// config.toml and plants a pin of the same settings with a well-formed MAC
// for a folder that stays locked: from the restart on, the defaults are
// enforced, the terminal unlock of another folder reviews the settings,
// and when the user declines they stay out of force.
func TestUnverifiedPinOnlyStrengthens(t *testing.T) {
	x := startTD(t)
	c := x.dial()
	if _, err := x.unlockTTY(c, nil, "root-acme"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Lock(context.Background(), ipc.LockReq{All: true}); err != nil {
		t.Fatal(err)
	}
	cfg := x.weakened(false) // idle_soft 10h, lock_on_screen_lock off
	x.plant(config.Pinned{Config: cfg, MACs: map[string]string{"root-beta": strings.Repeat("0", 64)}})
	x.restart()
	c = x.dial()
	def := config.Default().Policy
	if p := x.d.effective().Policy; p.IdleSoft != def.IdleSoft || p.LockOnScreenLock != def.LockOnScreenLock {
		t.Fatalf("after the restart: idle_soft %v, lock_on_screen_lock %v: the unverified pin's settings are enforced", p.IdleSoft.D(), p.LockOnScreenLock)
	}
	resp, err := x.unlockTTY(c, nil, "root-acme")
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Pending) != 2 {
		t.Fatalf("review %q, want the two weakened settings", resp.Pending)
	}
	// The user answers no: the CLI sends no confirmation.
	if p := x.d.effective().Policy; p.IdleSoft != def.IdleSoft || p.LockOnScreenLock != def.LockOnScreenLock {
		t.Fatalf("after the declined review: idle_soft %v, lock_on_screen_lock %v", p.IdleSoft.D(), p.LockOnScreenLock)
	}
	// Unlocking the folder the forged MAC names finds the forgery.
	if _, err := x.unlockTTY(c, nil, "root-beta"); err != nil {
		t.Fatal(err)
	}
	if _, ok := x.attention(c)[ipc.AttnPolicyTampered]; !ok {
		t.Fatal("the forged MAC was not detected")
	}
}

// A genuine pin of weaker settings applies again as soon as an unlock of a
// folder it lists verifies it, and once the user confirms at a terminal
// unlock of a folder it does not list. unlock_on_prompt keeps the pinned
// value meanwhile (a hook-raised unlock is one that verifies the pin).
func TestGenuineWeakPinAppliesOnceVerified(t *testing.T) {
	x := startTD(t)
	cfg := x.h.Cfg
	cfg.Policy.IdleSoft = config.Duration(time.Hour)
	cfg.Policy.UnlockOnPrompt = true
	if err := config.Save(x.h.Layout.ConfigFile, cfg); err != nil {
		t.Fatal(err)
	}
	x.restart()
	c := x.dial()
	if _, err := x.unlockTTY(c, nil, "root-acme"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Policy(context.Background(), ipc.PolicyReq{Confirm: true}); err != nil {
		t.Fatal(err)
	}
	if p := x.d.effective().Policy; p.IdleSoft.D() != time.Hour {
		t.Fatalf("confirmed: idle_soft %v", p.IdleSoft.D())
	}
	for _, folder := range []string{"root-acme", "root-beta"} {
		x.restart()
		c = x.dial()
		p := x.d.effective().Policy
		if p.IdleSoft != config.Default().Policy.IdleSoft || !p.UnlockOnPrompt {
			t.Fatalf("restart: idle_soft %v unlock_on_prompt %v", p.IdleSoft.D(), p.UnlockOnPrompt)
		}
		if _, ok := x.attention(c)[ipc.AttnPendingPolicy]; ok {
			t.Fatal("a confirmed pin waiting for its verification is shown as pending edits")
		}
		resp, err := x.unlockTTY(c, nil, folder)
		if err != nil {
			t.Fatal(err)
		}
		if folder == "root-beta" {
			// The pin lists only root-acme: the user confirms again.
			if len(resp.Pending) == 0 {
				t.Fatal("no review for a pin the unlock could not verify")
			}
			if p := x.d.effective().Policy; p.IdleSoft.D() == time.Hour {
				t.Fatal("unverified settings applied before the confirmation")
			}
			if _, err := c.Policy(context.Background(), ipc.PolicyReq{Confirm: true}); err != nil {
				t.Fatal(err)
			}
		} else if len(resp.Pending) != 0 {
			t.Fatalf("review %q after an unlock that verified the pin", resp.Pending)
		}
		if p := x.d.effective().Policy; p.IdleSoft.D() != time.Hour {
			t.Fatalf("%s: idle_soft %v after the pin was verified", folder, p.IdleSoft.D())
		}
		if _, err := c.Lock(context.Background(), ipc.LockReq{All: true}); err != nil {
			t.Fatal(err)
		}
	}
}

// per_root_auth = false keeps its pinned value while the pin waits for its
// verification: the first terminal unlock after a restart still covers
// every folder (D40), one presence prompt each.
func TestUnverifiedPinKeepsPerRootAuth(t *testing.T) {
	x := startTD(t)
	cfg := x.h.Cfg
	cfg.Policy.PerRootAuth = false
	if err := config.Save(x.h.Layout.ConfigFile, cfg); err != nil {
		t.Fatal(err)
	}
	x.restart()
	c := x.dial()
	if _, err := c.Unlock(context.Background(), ipc.UnlockReq{RootIDs: []string{"root-acme"}, TTY: true, Confirmed: true}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Policy(context.Background(), ipc.PolicyReq{Confirm: true}); err != nil {
		t.Fatal(err)
	}
	x.restart()
	c = x.dial()
	if x.d.effective().Policy.PerRootAuth {
		t.Fatal("per_root_auth reverted to the default while the pin waits for its verification")
	}
	resp, err := c.Unlock(context.Background(), ipc.UnlockReq{RootIDs: []string{"root-acme"}, TTY: true, Confirmed: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Unlocked) != 2 {
		t.Fatalf("unlocked %v, want every folder", resp.Unlocked)
	}
}
