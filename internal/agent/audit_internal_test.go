package agent

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/Neorichi/precinto/internal/ipc"
	"github.com/Neorichi/precinto/internal/vault"
)

func (x *td) audited(id string) (time.Time, bool) {
	x.vaults.mu.Lock()
	defer x.vaults.mu.Unlock()
	at, ok := x.vaults.audited[id]
	return at, ok
}

func (x *td) hasAttention(code, folder string) bool {
	x.d.mu.Lock()
	defer x.d.mu.Unlock()
	for _, a := range x.d.attention {
		if a.Code == code && (folder == "" || a.Folder == folder) {
			return true
		}
	}
	return false
}

// CC-07: after a clean unlock audit the daemon moves last_audit to the
// audit's start in vault.toml (Store.MarkAudited), so the next daemon starts
// from there; an audit that finds an exposure leaves it in place.
func TestAuditWatermarkIsPersisted(t *testing.T) {
	x := startTD(t)
	x.h.Clock.Advance(2 * time.Hour)
	x.caps.add("md/aaaa/g000001.pcap", "root-acme", "root-acme") // sealed epoch+1h to the vault's own recipients
	c := x.dial()
	start := x.h.Clock.Now()
	if _, err := x.unlockTTY(c, nil, "root-acme"); err != nil {
		t.Fatal(err)
	}
	x.eventually("last_audit saved", func() bool { at, ok := x.audited("root-acme"); return ok && at.Equal(start) })
	if x.hasAttention(ipc.AttnExposed, "") {
		t.Fatal("a clean audit reported exposures")
	}

	// A capsule sealed to a foreign recipient set after the watermark: the
	// next audit reports it and keeps the watermark (so every unlock and
	// vault repair still see it).
	x.caps.add("md/bbbb/g000001.pcap", "root-acme", "root-acme")
	x.caps.mu.Lock()
	e := x.caps.entries["md/bbbb/g000001.pcap"]
	e.SealedAt, e.RecipientsFpr = start.Add(time.Minute), "fpr-foreign"
	x.caps.entries["md/bbbb/g000001.pcap"] = e
	x.caps.mu.Unlock()
	x.h.Clock.Advance(time.Hour)
	if _, err := c.Lock(context.Background(), ipc.LockReq{All: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := x.unlockTTY(c, nil, "root-acme"); err != nil {
		t.Fatal(err)
	}
	x.eventually("exposure reported", func() bool { return x.hasAttention(ipc.AttnExposed, "~/work/acme") })
	time.Sleep(50 * time.Millisecond)
	if at, _ := x.audited("root-acme"); !at.Equal(start) {
		t.Fatalf("last_audit moved to %v past an exposed capsule (was %v)", at, start)
	}
}

// CC-07: a last_audit later than now (forged or clock-skewed) counts as
// zero: every capsule is audited.
func TestFutureLastAuditCountsAsZero(t *testing.T) {
	x := startTD(t)
	x.h.Clock.Advance(2 * time.Hour)
	x.vaults.set(func(f *fakeVaults) {
		f.metas["root-acme"] = vault.Meta{ID: "root-acme", LastAudit: epochT.Add(100 * time.Hour),
			Factors: []vault.Factor{{Name: "se", Kind: vault.FactorSE, GUI: true}}}
	})
	x.caps.add("md/cccc/g000001.pcap", "root-acme", "root-acme")
	x.caps.mu.Lock()
	e := x.caps.entries["md/cccc/g000001.pcap"]
	e.RecipientsFpr = "fpr-foreign" // sealed epoch+1h, long before the forged watermark
	x.caps.entries["md/cccc/g000001.pcap"] = e
	x.caps.mu.Unlock()
	c := x.dial()
	if _, err := x.unlockTTY(c, nil, "root-acme"); err != nil {
		t.Fatal(err)
	}
	x.eventually("the capsule before the forged watermark is audited", func() bool { return x.hasAttention(ipc.AttnExposed, "~/work/acme") })
	// vault repair's exposed list ignores the forged watermark too.
	if got := x.d.exposedSince("root-acme", "fpr-root-acme", epochT.Add(100*time.Hour)); !slices.Equal(got, []string{"md/cccc/g000001.pcap"}) {
		t.Fatalf("exposedSince with a future watermark = %v", got)
	}
}

// CC-10, CC-09: factor_add wraps the new factor from the identities the
// key holder already has (no unwrap, no presence prompt), into every
// vault, with a fresh passphrase copy per vault; a plugin factor carries
// its presence policy, and one without a policy or an acknowledgement is
// refused before anything happens.
func TestFactorAddUsesTheKeyHolder(t *testing.T) {
	x := startTD(t)
	c := x.dial()
	ctx := context.Background()
	if _, err := c.Unlock(ctx, ipc.UnlockReq{All: true, TTY: true, Confirmed: true}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := x.unlockTTY(c, nil, vault.GlobalID); err != nil {
		t.Fatal(err)
	}
	unwraps := func() int {
		return x.vaults.count("root-acme") + x.vaults.count("root-beta") + x.vaults.count(vault.GlobalID)
	}
	before := unwraps()
	ui := &scripted{secret: "correct horse battery staple"}
	if err := c.FactorAdd(ctx, ipc.FactorAddReq{Kind: "passphrase"}, ui); err != nil {
		t.Fatal(err)
	}
	if unwraps() != before {
		t.Fatalf("factor add unwrapped %d vaults again (CC-10: no extra presence)", unwraps()-before)
	}
	if len(ui.prompts) != 1 {
		t.Fatalf("prompts = %q (the new passphrase, once)", ui.prompts)
	}
	x.vaults.mu.Lock()
	factors := slices.Clone(x.vaults.factors)
	specs := slices.Clone(x.vaults.specs)
	x.vaults.mu.Unlock()
	slices.Sort(factors)
	if want := []string{"global:passphrase", "root-acme:passphrase", "root-beta:passphrase"}; !slices.Equal(factors, want) {
		t.Fatalf("factors = %v, want %v", factors, want)
	}
	for _, s := range specs {
		if s.Passphrase == nil || string(s.Passphrase.Bytes()) != "correct horse battery staple" {
			t.Fatal("a vault got no copy of the passphrase")
		}
		s.Passphrase.Destroy()
	}
	// A plugin factor without a presence policy or an acknowledgement.
	plugin := ipc.FactorAddReq{Kind: "plugin", Recipient: "age1yubikey1example", IdentityStub: "AGE-PLUGIN-YUBIKEY-1EXAMPLE", PluginPath: "/opt/homebrew/bin/age-plugin-yubikey"}
	if err := c.FactorAdd(ctx, plugin, ui); ipcCode(err) != ipc.CodeBadRequest {
		t.Fatalf("plugin factor without a presence policy = %v (S10)", err)
	}
	plugin.PresencePolicy = "touch-always"
	if err := c.FactorAdd(ctx, plugin, ui); err != nil {
		t.Fatal(err)
	}
	x.vaults.mu.Lock()
	last := x.vaults.specs[len(x.vaults.specs)-1]
	x.vaults.mu.Unlock()
	if last.Kind != vault.FactorPlugin || last.PresencePolicy != "touch-always" || last.NoPresenceAck || last.Passphrase != nil {
		t.Fatalf("plugin spec = %+v", last)
	}
	// A vault that locked meanwhile: nothing is wrapped from a missing key.
	if _, err := c.Lock(ctx, ipc.LockReq{RootIDs: []string{"root-beta"}}); err != nil {
		t.Fatal(err)
	}
	if err := c.FactorAdd(ctx, ipc.FactorAddReq{Kind: "passphrase"}, ui); ipcCode(err) != ipc.CodeLocked {
		t.Fatalf("factor add with a locked vault = %v", err)
	}
}
