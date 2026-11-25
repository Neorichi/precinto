package agent

import (
	"strings"
	"testing"
	"time"

	"github.com/Neorichi/precinto/internal/config"
	"github.com/Neorichi/precinto/internal/ipc"
	"github.com/Neorichi/precinto/internal/ui"
	"github.com/Neorichi/precinto/internal/vault"
)

// UX-08: the refusal that follows a cancelled or mistyped unlock (the
// D27 back-off) is catalog text naming the folder, why precinto waits and
// how long is left (C2.wait); the per-minute limit says that instead
// (C2.toomany). Neither is the old uncatalogued "too many unlock prompts".
func TestUnlockBackoffMessages(t *testing.T) {
	x := startTD(t)
	c := x.dial()
	x.vaults.set(func(f *fakeVaults) { f.unwrapErr["root-acme"] = vault.ErrCancelled })
	if _, err := x.unlockTTY(c, nil, "root-acme"); ipcCode(err) != ipc.CodeCancelled {
		t.Fatalf("cancel = %v", err)
	}
	for _, left := range []time.Duration{30 * time.Second, 18 * time.Second} {
		_, err := x.unlockTTY(c, nil, "root-acme")
		var e *ipc.Error
		want := ui.Format(ui.MsgUnlockWait, ui.Vars{Folder: "~/work/acme", Wait: left})
		if ipcCode(err) != ipc.CodeRateLimited || !asErr(err, &e) || e.Msg != want {
			t.Fatalf("retry with %s left = %v, want %q", left, err, want)
		}
		x.h.Clock.Advance(12 * time.Second)
	}
	// A wrong passphrase arms the same wait.
	x2 := startTD(t)
	c2 := x2.dial()
	x2.vaults.set(func(f *fakeVaults) { f.unwrapErr["root-acme"] = vault.ErrBadSecret })
	_, _ = x2.unlockTTY(c2, nil, "root-acme")
	_, err := x2.unlockTTY(c2, nil, "root-acme")
	var e *ipc.Error
	if !asErr(err, &e) || e.Msg != ui.Format(ui.MsgUnlockWait, ui.Vars{Folder: "~/work/acme", Wait: 30 * time.Second}) {
		t.Fatalf("after a wrong secret = %v", err)
	}
	// Three prompts a minute at most.
	x3 := startTD(t)
	c3 := x3.dial()
	x3.vaults.set(func(f *fakeVaults) { f.unwrapErr["root-beta"] = vault.ErrWrongIdentity })
	for i := 0; i < 3; i++ {
		_, _ = x3.unlockTTY(c3, nil, "root-beta")
	}
	_, err = x3.unlockTTY(c3, nil, "root-beta")
	want := ui.Format(ui.MsgUnlockTooMany, ui.Vars{Folder: "~/work/beta", N: 3, Wait: time.Minute})
	if !asErr(err, &e) || e.Code != ipc.CodeRateLimited || e.Msg != want {
		t.Fatalf("4th prompt in a minute = %v, want %q", err, want)
	}
	// prompt_rate_per_minute = 0 turns prompts off (the strictest value):
	// no wait ends that, so the refusal names the setting and what to
	// change, never "at most 0 times a minute, try again in 1 min".
	x4 := startTD(t)
	c4 := x4.dial()
	p := config.Default().Policy
	p.PromptRatePerMinute = 0
	x4.d.updateLimiter(p)
	for i := 0; i < 2; i++ {
		_, err = x4.unlockTTY(c4, nil, "root-acme")
		want = ui.Format(ui.MsgUnlockPromptsOff, ui.Vars{Folder: "~/work/acme"})
		if !asErr(err, &e) || e.Code != ipc.CodeRateLimited || e.Msg != want {
			t.Fatalf("prompts off, try %d = %v, want %q", i+1, err, want)
		}
		if strings.Contains(e.Msg, "0 times") || strings.Contains(e.Msg, "Try again in") {
			t.Fatalf("prompts off promises a retry: %q", e.Msg)
		}
		x4.h.Clock.Advance(2 * time.Minute)
	}
	x4.vaults.mu.Lock()
	n := x4.vaults.unwraps["root-acme"]
	x4.vaults.mu.Unlock()
	if n != 0 {
		t.Fatalf("%d prompts were raised while prompts are off", n)
	}
}

// UX-15: an unlock no prompt can serve names what is missing for that
// folder's way to unlock: a passphrase (or a security key) needs a
// terminal (C2.needtty); the Mac password dialog that cannot appear under
// tmux or SSH (C2.nogui) is only for a folder unlocked with the Secure
// Enclave.
func TestUnlockNoUIMessageByFactor(t *testing.T) {
	x := startTD(t, func(x *td, _ *Options) { // before serve's start-up factor load
		x.vaults.set(func(f *fakeVaults) {
			f.metas["root-acme"] = vault.Meta{ID: "root-acme", Factors: []vault.Factor{
				{Name: "passphrase", Kind: vault.FactorPassphrase}, {Name: "recovery", Kind: vault.FactorRecovery}}}
			f.unwrapErr["root-acme"] = vault.ErrNoUI
			f.unwrapErr["root-beta"] = vault.ErrNoUI // the fake's default: a Secure Enclave factor
		})
	})
	c := x.dial()
	for id, want := range map[string]string{
		"root-acme": ui.Format(ui.MsgUnlockNeedTTY, ui.Vars{Folder: "~/work/acme", Factor: "precinto passphrase"}),
		"root-beta": ui.Format(ui.MsgUnlockNoGUI, ui.Vars{Folder: "~/work/beta"}),
	} {
		_, err := x.unlockTTY(c, nil, id)
		var e *ipc.Error
		if !asErr(err, &e) || e.Code != ipc.CodeNoUI || e.Msg != want {
			t.Errorf("%s: %v, want %q", id, err, want)
		}
	}
}
