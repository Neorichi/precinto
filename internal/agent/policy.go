package agent

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"

	"github.com/precinto/precinto/internal/config"
	"github.com/precinto/precinto/internal/ipc"
	"github.com/precinto/precinto/internal/vault"
)

func globalVault() string { return vault.GlobalID }

// fileStamp identifies a version of a file cheaply (size and mtime).
func fileStamp(path string) string {
	st, err := os.Stat(path)
	if err != nil {
		return "missing"
	}
	return fmt.Sprintf("%d:%d", st.Size(), st.ModTime().UnixNano())
}

// installed reports whether precinto was initialized here: a vault exists.
func (d *daemon) installed() bool {
	ents, err := os.ReadDir(d.l.VaultsDir)
	return err == nil && len(ents) > 0
}

// loadPolicy computes the effective policy at start (D48, D55): the
// stricter of config.toml and state/policy.pinned. A pinned file that does
// not decode, or that is missing although vaults exist, is tampering: the
// compiled-in defaults join the strictest merge until the next TTY
// confirmation rewrites it.
func (d *daemon) loadPolicy() {
	cfg, err := config.Load(d.l.ConfigFile)
	if err != nil {
		d.logf("config.toml unreadable (%v): using the defaults and the pinned policy", err)
		cfg = config.Default()
	}
	pinned, ok, perr := config.LoadPinned(d.l.PolicyPinned)
	d.mu.Lock()
	defer d.mu.Unlock()
	d.pol = policyState{cfg: cfg, cfgStamp: fileStamp(d.l.ConfigFile), pinned: pinned, hasPinned: ok && perr == nil}
	// A pin that does not decode is forged. A missing pin although vaults
	// exist is treated as tampering too (deleting it must not hand control
	// to config.toml), but may be re-pinned at a TTY unlock when
	// config.toml weakens nothing (first run after init).
	d.pol.forged = perr != nil
	d.pol.tampered = d.pol.forged || (!ok && perr == nil && d.installed())
	d.recomputeLocked()
}

// recomputeLocked derives eff and pending from the loaded pieces (d.mu held).
func (d *daemon) recomputeLocked() {
	p := &d.pol
	eff := p.cfg
	if p.hasPinned {
		eff = config.Strictest(p.cfg, p.pinned.Config)
	}
	if p.tampered {
		eff = config.Strictest(eff, config.Default())
	}
	p.eff = eff
	// Pending = what adopting config.toml would weaken relative to what is
	// enforced now (the pin, and the defaults while tampered).
	p.pending = nil
	for _, c := range config.Diff(eff, p.cfg) {
		if c.Weakening {
			p.pending = append(p.pending, c)
		}
	}
	d.attentionPolicyLocked()
}

// attentionPolicyLocked mirrors the policy state into attention items.
func (d *daemon) attentionPolicyLocked() {
	set := func(a ipc.Attention, on bool) {
		key := a.Code + "\x00\x000"
		if on {
			d.attention[key] = a
		} else {
			delete(d.attention, key)
		}
	}
	set(ipc.Attention{Code: ipc.AttnPolicyTampered, Fix: "precinto unlock"}, d.pol.tampered)
	set(ipc.Attention{Code: ipc.AttnPendingPolicy, Count: len(d.pol.pending), Fix: "precinto unlock"}, len(d.pol.pending) > 0)
}

// pendingText lists pending weakening changes as content-free strings.
func pendingText(cs []config.Change) []string {
	out := make([]string, 0, len(cs))
	for _, c := range cs {
		out = append(out, c.Key+": "+c.Old+" → "+c.New)
	}
	return out
}

// reloadPolicy re-reads config.toml when it changed (tick). Strengthening
// edits apply at once; weakening ones stay pending (D48). A config that no
// longer loads keeps the last good one (never weaken on error).
func (d *daemon) reloadPolicy(ctx context.Context) {
	stamp := fileStamp(d.l.ConfigFile)
	d.mu.Lock()
	same := stamp == d.pol.cfgStamp
	d.mu.Unlock()
	if same {
		return
	}
	cfg, err := config.Load(d.l.ConfigFile)
	d.mu.Lock()
	d.pol.cfgStamp = stamp
	if err != nil {
		d.mu.Unlock()
		d.logf("config.toml changed but does not load (%v): keeping the previous policy", err)
		return
	}
	before := d.pol.eff
	d.pol.cfg = cfg
	d.recomputeLocked()
	eff := d.pol.eff
	d.mu.Unlock()
	d.applyEffective(ctx, before, eff)
}

// applyEffective hands a new effective policy to the machine, declares new
// folders (locked) and rewrites roots.list when the roots changed.
func (d *daemon) applyEffective(ctx context.Context, before, eff config.Config) {
	p := eff.Policy
	// InPolicy also declares the configuration's vaults: new folders start
	// locked (Input.Vaults carries them).
	d.apply(ctx, Input{Kind: InPolicy, Policy: &p, Vaults: vaultIDs(eff)})
	if !slices.Equal(rootPaths(before), rootPaths(eff)) {
		d.writeRootsList()
	}
}

func rootPaths(c config.Config) []string {
	var ps []string
	for _, r := range c.Roots {
		ps = append(ps, r.ID+"="+r.Path)
	}
	slices.Sort(ps)
	return ps
}

// verifyPinnedMAC checks the pinned policy's MAC for a vault that was just
// unlocked (D55). A listed vault whose MAC is missing or wrong raises
// policy-tampered and makes the defaults join the strictest merge.
func (d *daemon) verifyPinnedMAC(ctx context.Context, id string) {
	d.mu.Lock()
	if !d.pol.hasPinned {
		d.mu.Unlock()
		return
	}
	want, listed := d.pol.pinned.MACs[id]
	data := config.Canonical(d.pol.pinned.Config)
	d.mu.Unlock()
	if !listed {
		return
	}
	got, err := d.deps.keyring.MAC(id, vault.InfoPolicy, data)
	if err == nil && want != "" && got == want {
		return
	}
	d.mu.Lock()
	before := d.pol.eff
	already := d.pol.forged
	d.pol.tampered, d.pol.forged = true, true
	d.recomputeLocked()
	eff := d.pol.eff
	d.mu.Unlock()
	if !already {
		d.logf("policy.pinned MAC mismatch for %s: strictest settings until the next confirmation", id)
		d.applyEffective(ctx, before, eff)
	}
}

// pinPolicy writes state/policy.pinned after a TTY-confirmed unlock (D55):
// the current config.toml plus one MAC per vault unlocked now. Without an
// explicit confirmation it refuses while weakening edits are pending or
// the pin was found forged (the user must see C13.tampered and confirm),
// so a forged pin never heals itself.
func (d *daemon) pinPolicy(ctx context.Context, confirmed bool) error {
	d.mu.Lock()
	cfg := d.pol.cfg
	blocked := len(d.pol.pending) > 0 || d.pol.forged
	d.mu.Unlock()
	if blocked && !confirmed {
		return errPending
	}
	macs := map[string]string{}
	data := config.Canonical(cfg)
	for _, id := range d.deps.keyring.IDs() {
		mac, err := d.deps.keyring.MAC(id, vault.InfoPolicy, data)
		if err != nil {
			return fmt.Errorf("agent: policy MAC: %w", err)
		}
		macs[id] = mac
	}
	p := config.Pinned{Version: config.PinnedVersion, ConfirmedAt: d.clock.Now().UTC(), Config: cfg, MACs: macs}
	if err := config.SavePinned(d.l.PolicyPinned, p); err != nil {
		return err
	}
	d.mu.Lock()
	before := d.pol.eff
	d.pol.pinned, d.pol.hasPinned, d.pol.tampered, d.pol.forged = p, true, false, false
	d.recomputeLocked()
	eff := d.pol.eff
	d.mu.Unlock()
	d.applyEffective(ctx, before, eff)
	return nil
}

// errPending reports unconfirmed weakening edits.
var errPending = errors.New("agent: weakening configuration changes need confirmation")

// policyOp lists pending weakening changes or confirms them (D48): only a
// same-executable peer that unlocked on a terminal over this connection,
// never from an agent context.
func (d *daemon) policyOp(cs *connState, r ipc.PolicyReq) ipc.Response {
	d.mu.Lock()
	pending := pendingText(d.pol.pending)
	d.mu.Unlock()
	if !r.Confirm {
		return ipc.Response{Policy: &ipc.PolicyResp{Pending: pending}}
	}
	if !cs.same {
		return errResp(ipc.CodeUnauthorized, "precinto: only precinto itself can confirm settings")
	}
	if e := authorize(cs.peer, d.ancestry(cs.peer), ipc.OpPolicy, "", nil, nil, d.folder); e != nil {
		return ipc.Response{Err: e}
	}
	if !cs.ttyUnlocked {
		return errResp(ipc.CodeUnauthorized, "precinto: confirm settings right after unlocking in a terminal")
	}
	if err := d.pinPolicy(context.Background(), true); err != nil {
		return errResp(ipc.CodeInternal, "precinto: could not save the confirmed settings")
	}
	return ipc.Response{Policy: &ipc.PolicyResp{}}
}
