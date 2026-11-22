package agent

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/awnumar/memguard"

	"github.com/precinto/precinto/internal/ipc"
	"github.com/precinto/precinto/internal/ui"
	"github.com/precinto/precinto/internal/vault"
)

// repairHold is how long a vault_repair dry run keeps the identity it
// unwrapped for the confirmed call on the same connection (CC-32).
const repairHold = 120 * time.Second

// vaultCreate creates the vault of a root just protected (D1); the new
// identity stays unlocked. The first root vault also writes the first
// policy pin (D68).
func (d *daemon) vaultCreate(ctx context.Context, cs *connState, req ipc.Request) ipc.Response {
	r := *req.VaultCreate
	if !cs.same {
		return errResp(ipc.CodeUnauthorized, "precinto: only precinto itself can create vaults")
	}
	d.reloadPolicy(ctx) // protect wrote config.toml just before
	root, ok := d.effective().RootByID(r.RootID)
	if !ok || root.Path != filepath.Clean(r.RootPath) {
		return errResp(ipc.CodeBadRequest, "precinto: that folder is not in config.toml")
	}
	if d.vaultExists(r.RootID) {
		return errResp(ipc.CodeBadRequest, "precinto: that folder already has a vault")
	}
	first := !d.rootVaultExists()
	f := d.peerFacts(cs.peer, nil)
	u := d.newRelayUI(ctx, cs, req.ID, true, r.RootID)
	identity, err := d.deps.vaults.create(ctx, r.RootID, root.Path, u)
	if err != nil {
		return ipc.Response{Err: d.unlockErr(r.RootID, err)}
	}
	if err := d.deps.keyring.Put(r.RootID, identity); err != nil {
		return errResp(ipc.CodeInternal, "precinto: could not keep the new vault unlocked")
	}
	d.apply(ctx, Input{Kind: InUnlock, Vaults: []string{r.RootID}})
	d.refreshFactors(r.RootID)
	switch {
	case first:
		// D68: the first root vault pins the policy enforced now
		// (Strictest of config.toml and the defaults), whoever asked: it
		// can never weaken anything.
		if err := d.pinFirst(ctx); err != nil {
			d.logf("first policy pin: %v", err)
		}
	case !f.agent && !f.noCTTY:
		// A later folder joins the pin (so removing it from config.toml
		// is a weakening edit), never adopting a pending one.
		if err := d.pinEnforced(ctx); err != nil && !errors.Is(err, errPending) {
			d.logf("pin policy: %v", err)
		}
	}
	return ipc.Response{}
}

// factorAdd enrolls a factor in every vault (SPEC §13.3): every vault must
// be unlocked, the request comes from precinto with a terminal and never
// from an agent context. The factor is wrapped from the identity the key
// holder already has (Keyring.WithIdentityBuffer, CC-10): no new unwrap
// and no extra presence prompt; a passphrase factor gets a fresh copy of
// the passphrase per vault (AddFactor consumes it).
func (d *daemon) factorAdd(ctx context.Context, cs *connState, req ipc.Request) ipc.Response {
	r := *req.FactorAdd
	if !cs.same {
		return errResp(ipc.CodeUnauthorized, "precinto: only precinto itself can add factors")
	}
	if e := authorizeFacts(d.peerFacts(cs.peer, nil), ipc.OpFactorAdd, "", nil, nil, d.folder); e != nil {
		return ipc.Response{Err: e}
	}
	kind := vault.FactorKind(r.Kind)
	switch kind {
	case vault.FactorSE, vault.FactorPlugin, vault.FactorPassphrase:
	default:
		return errResp(ipc.CodeBadRequest, "precinto: unknown factor kind")
	}
	if kind == vault.FactorPlugin && r.PresencePolicy == "" && !r.NoPresenceAck {
		// S10: a plugin factor states how it asks for presence, or the
		// user acknowledges that it may not ask at all.
		return errResp(ipc.CodeBadRequest, "precinto: a plugin factor needs --presence POLICY or --no-presence-ack")
	}
	var ids []string
	for _, id := range vaultIDs(d.effective()) {
		if d.vaultExists(id) {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	if len(ids) == 0 {
		return errResp(ipc.CodeBadRequest, "precinto: no vault yet: run precinto init")
	}
	for _, id := range ids {
		if !d.deps.keyring.Has(id) {
			return errResp(ipc.CodeLocked, "precinto: unlock every folder (precinto unlock --all) before adding a factor")
		}
	}
	u := d.newRelayUI(ctx, cs, req.ID, true, vault.GlobalID)
	var pass *memguard.LockedBuffer
	if kind == vault.FactorPassphrase {
		p, err := u.Secret("new passphrase")
		if err != nil {
			return ipc.Response{Err: d.unlockErr(vault.GlobalID, err)}
		}
		pass = p
		defer pass.Destroy()
	}
	for _, id := range ids {
		spec := vault.FactorSpec{Kind: kind, Recipient: r.Recipient, IdentityStub: r.IdentityStub, PluginPath: r.PluginPath,
			PresencePolicy: r.PresencePolicy, NoPresenceAck: r.NoPresenceAck}
		if pass != nil {
			spec.Passphrase = memguard.NewBufferFromBytes(append([]byte(nil), pass.Bytes()...))
		}
		vu := d.newRelayUI(ctx, cs, req.ID, true, id)
		err := d.deps.keyring.WithIdentityBuffer(id, func(identity *memguard.LockedBuffer) error {
			return d.deps.vaults.addFactor(ctx, id, identity, spec, vu)
		})
		if spec.Passphrase != nil {
			spec.Passphrase.Destroy() // consumed by AddFactor; destroyed here too if it never ran
		}
		if err != nil {
			return ipc.Response{Err: d.factorErr(id, err)}
		}
		d.refreshFactors(id)
	}
	return ipc.Response{}
}

// factorErr maps a factor enrollment failure.
func (d *daemon) factorErr(id string, err error) *ipc.Error {
	switch {
	case errors.Is(err, vault.ErrWeakPassphrase):
		return &ipc.Error{Code: ipc.CodeBadRequest, Msg: "precinto: that passphrase is too weak (at least 12 characters and 80 bits)"}
	case errors.Is(err, fs.ErrExist):
		return &ipc.Error{Code: ipc.CodeBadRequest, Msg: "precinto: " + d.folder(id) + " already has a factor of that name"}
	case errors.Is(err, vault.ErrLocked):
		return &ipc.Error{Code: ipc.CodeLocked, Msg: "precinto: unlock every folder (precinto unlock --all) before adding a factor"}
	case errors.Is(err, vault.ErrCancelled), errors.Is(err, vault.ErrNoUI), errors.Is(err, vault.ErrBadSecret),
		errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded), isVerifyErr(err),
		errors.Is(err, vault.ErrNotFound):
		return d.unlockErr(id, err)
	}
	d.logf("factor add to %s failed: %v", id, err)
	return &ipc.Error{Code: ipc.CodeBadRequest, Msg: "precinto: the factor could not be added to " + d.folder(id) + "; check the plugin path, recipient and identity stub"}
}

// selfPID is the daemon's pid (in-process clients have no terminal of
// their own to check).
func selfPID() int { return os.Getpid() }

// recoveryUI answers the vault's recovery-key prompt with the key the user
// typed (sent in one 'S' frame); everything else goes to the terminal.
type recoveryUI struct {
	*relayUI
	key *memguard.LockedBuffer
}

func (u recoveryUI) Secret(string) (*memguard.LockedBuffer, error) {
	return memguard.NewBufferFromBytes(append([]byte(nil), u.key.Bytes()...)), nil
}

// pendingRepair is the identity a vault_repair dry run unwrapped (CC-32).
// It is bound to its connection (connState.repair) for repairHold and is
// wiped by any lock, by the connection closing and by the hold expiring;
// the confirmed call on the same connection takes it out of the registry
// before using it, so nothing wipes it under its feet.
type pendingRepair struct {
	vaultID     string
	useRecovery bool
	recoverySum [32]byte // SHA-256 of the dry run's recovery key: the confirmed call must send the same one
	identity    *memguard.LockedBuffer
	at          instant     // when the dry run unwrapped it (the hold is checked on both clocks)
	timer       *time.Timer // wipes it after repairHold even if no request comes
	once        sync.Once
}

func (p *pendingRepair) wipe() {
	p.once.Do(func() {
		if p.timer != nil {
			p.timer.Stop()
		}
		if p.identity != nil {
			p.identity.Destroy()
		}
	})
}

// holdRepair binds identity to cs for the confirmed call (the previous
// pending repair of cs is wiped).
func (d *daemon) holdRepair(cs *connState, p *pendingRepair) {
	d.mu.Lock()
	old := cs.repair
	cs.repair = p
	d.repairs[p] = struct{}{}
	if old != nil {
		delete(d.repairs, old)
	}
	p.timer = time.AfterFunc(repairHold, func() { d.dropRepair(cs, p) })
	d.mu.Unlock()
	if old != nil {
		old.wipe()
	}
}

// takeRepair returns the pending repair of cs if it matches the request
// (same vault, same recovery key), removed from the registry: the caller
// owns its identity. Anything else is wiped.
func (d *daemon) takeRepair(cs *connState, r ipc.VaultRepairReq, recovery *memguard.LockedBuffer) *pendingRepair {
	d.mu.Lock()
	p := cs.repair
	cs.repair = nil
	live := false
	if p != nil {
		_, live = d.repairs[p]
		delete(d.repairs, p)
	}
	d.mu.Unlock()
	if p == nil {
		return nil
	}
	if p.timer != nil {
		p.timer.Stop()
	}
	match := live && p.vaultID == r.VaultID && p.useRecovery == r.UseRecovery && !p.at.elapsed(d.now(), repairHold)
	if match && r.UseRecovery {
		sum := sha256.Sum256(recovery.Bytes())
		match = subtle.ConstantTimeCompare(sum[:], p.recoverySum[:]) == 1
	}
	if !match {
		p.wipe()
		return nil
	}
	return p
}

// dropRepair wipes the pending repair p of cs if it is still pending.
func (d *daemon) dropRepair(cs *connState, p *pendingRepair) {
	d.mu.Lock()
	_, live := d.repairs[p]
	delete(d.repairs, p)
	if cs != nil && cs.repair == p {
		cs.repair = nil
	}
	d.mu.Unlock()
	if live {
		p.wipe()
	}
}

// wipeRepairs wipes every pending repair identity (any lock, shutdown).
func (d *daemon) wipeRepairs() {
	d.mu.Lock()
	ps := make([]*pendingRepair, 0, len(d.repairs))
	for p := range d.repairs {
		ps = append(ps, p)
	}
	clear(d.repairs)
	d.mu.Unlock()
	for _, p := range ps {
		p.wipe()
	}
}

// vaultRepair rewrites a tampered recipient set (D53): a same-executable
// peer on a terminal, never an agent context; the identity is unwrapped
// with a factor (or the recovery key) and must open an older capsule of the
// vault when one exists. Confirmed=false is a dry run (CC-32): the same
// checks and the diff a repair would make, computed on a scratch copy of
// the vault's metadata, nothing written; the identity then stays bound to
// this connection for repairHold so the confirmed call (after the client
// showed the diff and obtained the typed word) needs no second presence
// prompt. Capsules sealed since the last audit to a foreign recipient set
// are reported as exposed.
func (d *daemon) vaultRepair(ctx context.Context, cs *connState, req ipc.Request, sec []*memguard.LockedBuffer) ipc.Response {
	r := *req.VaultRepair
	if !cs.same {
		return errResp(ipc.CodeUnauthorized, "precinto: only precinto itself can repair a vault")
	}
	if e := authorizeFacts(d.peerFacts(cs.peer, nil), ipc.OpVaultRepair, "", []string{r.VaultID}, nil, d.folder); e != nil {
		return ipc.Response{Err: e}
	}
	if cs.peer.Proc.TTY == "" && cs.peer.PID != selfPID() {
		return errResp(ipc.CodeNoUI, "precinto: vault repair needs a terminal")
	}
	id := r.VaultID
	if _, ok := d.effective().RootByID(id); (!ok && id != vault.GlobalID) || !d.vaultExists(id) {
		return errResp(ipc.CodeBadRequest, "precinto: no such vault")
	}
	folder := d.folder(id)
	var recovery *memguard.LockedBuffer
	if r.UseRecovery {
		if len(sec) != 1 || sec[0].Size() == 0 {
			return errResp(ipc.CodeBadRequest, "precinto: vault repair --recovery needs the recovery key")
		}
		recovery = sec[0]
	}
	var identity *memguard.LockedBuffer
	defer func() {
		if identity != nil {
			identity.Destroy()
		}
	}()
	if r.Confirmed {
		if p := d.takeRepair(cs, r, recovery); p != nil {
			identity, p.identity = p.identity, nil
			p.wipe()
		}
	} else if p := d.takeRepair(cs, ipc.VaultRepairReq{}, nil); p != nil {
		p.wipe() // a new dry run replaces the previous one
	}
	if identity == nil {
		u := d.newRelayUI(ctx, cs, req.ID, true, id)
		var err error
		if r.UseRecovery {
			identity, err = d.deps.vaults.unwrap(ctx, id, string(vault.FactorRecovery), recoveryUI{u, recovery})
		} else {
			identity, err = d.deps.vaults.unwrap(ctx, id, "", u)
		}
		if err != nil {
			identity = nil
			return ipc.Response{Err: d.unlockErr(id, err)}
		}
	}
	meta, err := d.deps.vaults.meta(id)
	if err != nil {
		return ipc.Response{Err: d.unlockErr(id, err)}
	}
	if genuine, err := d.genuine(id, identity, meta.LastAudit); err != nil || !genuine {
		return errResp(ipc.CodeVerify, ui.Format(ui.MsgVaultNotGenuine, ui.Vars{Folder: folder, Global: id == vault.GlobalID}))
	}
	if !r.Confirmed {
		res, fpr, err := d.deps.vaults.repairPlan(id, identity, recovery, d.clock.Now())
		if err != nil {
			return ipc.Response{Err: d.repairErr(id, err)}
		}
		exposed := d.exposedSince(id, fpr, res.LastAudit)
		p := &pendingRepair{vaultID: id, useRecovery: r.UseRecovery, identity: identity, at: d.now()}
		if recovery != nil {
			p.recoverySum = sha256.Sum256(recovery.Bytes())
		}
		identity = nil // owned by the pending repair now
		d.holdRepair(cs, p)
		d.logf("vault repair dry run of %s (%d exposed)", id, len(exposed))
		return ipc.Response{Repair: &ipc.VaultRepairResp{RecipientChanged: res.RecipientChanged, RecoveryChanged: res.RecoveryChanged, Exposed: exposed}}
	}
	res, err := d.deps.vaults.repair(id, identity, recovery, d.clock.Now())
	if err != nil {
		return ipc.Response{Err: d.repairErr(id, err)}
	}
	fpr, _ := d.deps.vaults.fingerprint(id)
	exposed := d.exposedSince(id, fpr, res.LastAudit)
	if err := d.deps.keyring.Put(id, identity); err == nil {
		identity = nil // owned by the key holder now
		d.apply(ctx, Input{Kind: InUnlock, Vaults: []string{id}})
		if !d.deps.keyring.Has(id) {
			// A lock arrived meanwhile: the lock wins (I15).
			d.apply(ctx, Input{Kind: InLock, Vaults: []string{id}})
		}
	}
	d.setAttention(ipc.Attention{Code: ipc.AttnVaultTampered, Folder: folder}, false)
	if len(exposed) > 0 {
		d.setAttention(ipc.Attention{Code: ipc.AttnExposed, Folder: folder, Count: len(exposed), Fix: "precinto status"}, true)
	}
	d.refreshFactors(id)
	d.logf("repaired vault %s (%d exposed)", id, len(exposed))
	return ipc.Response{Repair: &ipc.VaultRepairResp{RecipientChanged: res.RecipientChanged, RecoveryChanged: res.RecoveryChanged, Exposed: exposed}}
}

// repairErr maps a repair (or dry-run) failure.
func (d *daemon) repairErr(id string, err error) *ipc.Error {
	if errors.Is(err, vault.ErrNeedRecovery) {
		return &ipc.Error{Code: ipc.CodeUnauthorized, Msg: "precinto: the recovery key is needed: precinto vault repair " + targetArg(id, d.folder) + " --recovery"}
	}
	return d.unlockErr(id, err)
}

// genuine reports whether identity opens the header of at least one
// capsule of vault id logged before lastAudit; with no such capsule it
// cannot be checked and is accepted (SPEC §19).
func (d *daemon) genuine(id string, identity *memguard.LockedBuffer, lastAudit time.Time) (bool, error) {
	entries, err := d.deps.logged()
	if err != nil {
		return false, err
	}
	checked := false
	for _, e := range entries {
		if e.VaultID != id || e.Deleted || !e.SealedAt.Before(lastAudit) {
			continue
		}
		hdr, sha, err := d.deps.readHeader(e.Path)
		if err != nil || sha != e.HeaderSHA256 {
			continue
		}
		checked = true
		if d.deps.opens(identity, hdr) {
			return true, nil
		}
	}
	return !checked, nil
}

// exposedSince lists capsules of vault id sealed after since whose
// recipients fingerprint is not fpr (the repaired vault's). A since later
// than now counts as zero (CC-07): a forged future last_audit never hides
// a capsule. With no fingerprint nothing can be compared.
func (d *daemon) exposedSince(id, fpr string, since time.Time) []string {
	if fpr == "" {
		return nil
	}
	if since.After(d.clock.Now()) {
		since = time.Time{}
	}
	entries, err := d.deps.logged()
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if e.VaultID == id && !e.Deleted && e.SealedAt.After(since) && e.RecipientsFpr != fpr {
			out = append(out, e.Path)
		}
	}
	sort.Strings(out)
	return out
}

// rootVaultExists reports whether any root vault exists (a vaults/<id>/
// with vault.toml other than the global vault): before the first protect a
// missing policy pin is the normal first-run state (D68).
func (d *daemon) rootVaultExists() bool {
	ents, err := os.ReadDir(d.l.VaultsDir)
	if err != nil {
		// Unreadable: assume a root vault exists (a missing pin is then
		// tampering, the strict reading).
		return !errors.Is(err, fs.ErrNotExist)
	}
	for _, e := range ents {
		if e.Name() == vault.GlobalID || !validName(e.Name()) {
			continue
		}
		if d.vaultExists(e.Name()) {
			return true
		}
	}
	return false
}
