package agent

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
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

// loadPolicy computes the effective policy at start (D48, D55, D68): the
// stricter of config.toml and state/policy.pinned. A pinned file that does
// not decode (or is not a regular file of the user, CC-47) is forged:
// policy-tampered, and the compiled-in defaults join the strictest merge
// until a confirmed TTY unlock rewrites it. A missing pin is the normal
// first-run state while no root vault exists (the defaults join the merge,
// no policy-tampered); once a root vault exists it is tampering too
// (deleting it must not hand control to config.toml), healed only by a
// TTY unlock with nothing weakening pending or by a confirmation.
func (d *daemon) loadPolicy() {
	cfg, err := config.Load(d.l.ConfigFile)
	if err != nil {
		d.logf("config.toml unreadable (%v): using the defaults and the pinned policy", err)
		cfg = config.Default()
	}
	pinned, ok, perr := config.LoadPinned(d.l.PolicyPinned)
	rootVault := d.rootVaultExists()
	// D91: a pin that decodes but has a shape precinto never writes (no
	// MAC, a malformed one, one for a vault outside its settings or for a
	// vault that does not exist) is forged as well.
	var serr error
	if ok && perr == nil && rootVault {
		serr = pinned.CheckShape(d.vaultExists)
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.pol = policyState{cfg: cfg, cfgStamp: fileStamp(d.l.ConfigFile), pinned: pinned, hasPinned: ok && perr == nil}
	d.pol.forged = perr != nil || serr != nil
	d.pol.tampered = d.pol.forged || (!ok && perr == nil && rootVault)
	if serr != nil {
		d.logf("policy.pinned is forged (%v): strictest settings until the next confirmation", serr)
	}
	d.recomputeLocked()
}

// recomputeLocked derives eff and pending from the loaded pieces (d.mu held).
func (d *daemon) recomputeLocked() {
	p := &d.pol
	eff := p.cfg
	if p.hasPinned {
		eff = config.Strictest(p.cfg, p.pinned.Config)
	}
	if p.tampered || !p.hasPinned {
		// Without a trusted pin the defaults are the floor: first run
		// (D68) and policy-tampered (D55) alike.
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
		d.mu.Lock()
		d.pol.verified = true // D91: authenticated by a vault key
		d.mu.Unlock()
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

// pinPolicy writes state/policy.pinned after a TTY unlock by a human (D55,
// D68): the current config.toml plus one MAC per vault unlocked now.
// Without an explicit confirmation (ConfirmDiff, `policy confirm`) it
// re-pins only when nothing weakening is pending and the pin was not
// found forged (the user must see C13.tampered and confirm), so a forged
// pin never heals itself.
//
// D91: a pin no vault key has authenticated in this daemon's lifetime
// (the daemon restarted and no folder the pin lists was unlocked yet) is
// never re-pinned without a confirmation either: re-pinning it would give
// a forged pin genuine MACs.
func (d *daemon) pinPolicy(ctx context.Context, confirmed bool) error {
	d.mu.Lock()
	cfg := d.pol.cfg
	blocked := len(d.pol.pending) > 0 || d.pol.forged || (d.pol.hasPinned && !d.pol.verified)
	d.mu.Unlock()
	if blocked && !confirmed {
		return errPending
	}
	return d.writePin(ctx, cfg)
}

// unverifiedPending lists, for a TTY unlock whose re-pin waits because no
// vault key authenticated the pin yet (D91), what config.toml weakens
// relative to the compiled-in defaults: the settings the user confirms.
func (d *daemon) unverifiedPending() []config.Change {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.pol.hasPinned || d.pol.verified || len(d.pol.pending) > 0 {
		return nil
	}
	var out []config.Change
	for _, c := range config.Diff(config.Default(), d.pol.cfg) {
		if c.Weakening {
			out = append(out, c)
		}
	}
	return out
}

// pinFirst writes the first pin when the first root vault is created
// (D68): the policy enforced now (Strictest of config.toml and the
// defaults, never a weakening) with the MACs of the vaults unlocked now
// (the new one included). An existing pin is left to the usual rules.
func (d *daemon) pinFirst(ctx context.Context) error {
	d.mu.Lock()
	exists := d.pol.hasPinned || d.pol.forged
	eff := d.pol.eff
	d.mu.Unlock()
	if exists {
		return d.pinEnforced(ctx)
	}
	if _, err := os.Lstat(d.l.PolicyPinned); !errors.Is(err, fs.ErrNotExist) {
		return errPending // a pin appeared on disk meanwhile: never overwrite it blindly
	}
	return d.writePin(ctx, eff)
}

// pinEnforced re-pins the policy the daemon enforces now (it can only
// strengthen the pin: a folder just protected joins it, a pending
// weakening edit stays pending). Refused while the policy is tampered:
// only a confirmation heals that.
func (d *daemon) pinEnforced(ctx context.Context) error {
	d.mu.Lock()
	eff := d.pol.eff
	blocked := d.pol.tampered || d.pol.forged || !d.pol.hasPinned || !d.pol.verified
	d.mu.Unlock()
	if blocked {
		return errPending
	}
	return d.writePin(ctx, eff)
}

// errNoPinVault: no unlocked vault may sign the pin (D91).
var errNoPinVault = errors.New("agent: no unlocked vault of these settings to sign the pinned policy")

// writePin saves cfg as the pinned policy (D91): one MAC per unlocked
// vault that is "global" or a root of cfg; when the settings are the ones
// pinned before, the earlier MACs of vaults locked now are kept, so a pin
// collects one MAC per folder (and a planted entry stays a tripwire,
// checked at that vault's next unlock). It refuses when no vault
// qualifies: a pin without a MAC is forged.
func (d *daemon) writePin(ctx context.Context, cfg config.Config) error {
	macs := map[string]string{}
	data := config.Canonical(cfg)
	qualifies := func(id string) bool {
		_, isRoot := cfg.RootByID(id)
		return isRoot || id == vault.GlobalID
	}
	for _, id := range d.deps.keyring.IDs() {
		if !qualifies(id) {
			continue
		}
		mac, err := d.deps.keyring.MAC(id, vault.InfoPolicy, data)
		if err != nil {
			return fmt.Errorf("agent: policy MAC: %w", err)
		}
		macs[id] = mac
	}
	if len(macs) == 0 {
		return errNoPinVault
	}
	d.mu.Lock()
	prev, hadPin := d.pol.pinned, d.pol.hasPinned
	d.mu.Unlock()
	if hadPin && string(config.Canonical(prev.Config)) == string(data) {
		for id, mac := range prev.MACs {
			if _, have := macs[id]; !have && qualifies(id) && !d.deps.keyring.Has(id) {
				macs[id] = mac
			}
		}
	}
	p := config.Pinned{Version: config.PinnedVersion, ConfirmedAt: d.clock.Now().UTC(), Config: cfg, MACs: macs}
	if err := config.SavePinned(d.l.PolicyPinned, p); err != nil {
		return err
	}
	d.mu.Lock()
	before := d.pol.eff
	d.pol.pinned, d.pol.hasPinned, d.pol.tampered, d.pol.forged, d.pol.verified = p, true, false, false, true
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
	if e := authorizeFacts(d.peerFacts(cs.peer, nil), ipc.OpPolicy, "", nil, nil, d.folder); e != nil {
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
