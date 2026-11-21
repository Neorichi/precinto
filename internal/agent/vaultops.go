package agent

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/awnumar/memguard"

	"github.com/precinto/precinto/internal/ipc"
	"github.com/precinto/precinto/internal/ui"
	"github.com/precinto/precinto/internal/vault"
)

// vaultCreate creates the vault of a root just protected (D1); the new
// identity stays unlocked.
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
	anc := d.ancestry(cs.peer)
	f := factsOf(cs.peer, anc)
	u := d.newRelayUI(ctx, cs, req.ID, true, r.RootID)
	identity, err := d.deps.vaults.create(ctx, r.RootID, root.Path, u)
	if err != nil {
		return ipc.Response{Err: d.unlockErr(r.RootID, err)}
	}
	if err := d.deps.keyring.Put(r.RootID, identity); err != nil {
		return errResp(ipc.CodeInternal, "precinto: could not keep the new vault unlocked")
	}
	d.apply(ctx, Input{Kind: InUnlock, Vaults: []string{r.RootID}})
	d.mu.Lock()
	delete(d.gui, r.RootID)
	d.mu.Unlock()
	if !f.agent && !f.noCTTY {
		if err := d.pinPolicy(ctx, false); err != nil && !errors.Is(err, errPending) {
			d.logf("pin policy: %v", err)
		}
	}
	return ipc.Response{}
}

// factorAdd enrolls a factor in every vault (SPEC §13.3): every vault must
// be unlocked, the request comes from precinto with a terminal and never
// from an agent context, and each vault is unwrapped afresh (the identity
// itself never leaves the key holder).
func (d *daemon) factorAdd(ctx context.Context, cs *connState, req ipc.Request) ipc.Response {
	r := *req.FactorAdd
	if !cs.same {
		return errResp(ipc.CodeUnauthorized, "precinto: only precinto itself can add factors")
	}
	if e := authorize(cs.peer, d.ancestry(cs.peer), ipc.OpFactorAdd, "", nil, nil, d.folder); e != nil {
		return ipc.Response{Err: e}
	}
	kind := vault.FactorKind(r.Kind)
	switch kind {
	case vault.FactorSE, vault.FactorPlugin, vault.FactorPassphrase:
	default:
		return errResp(ipc.CodeBadRequest, "precinto: unknown factor kind")
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
		identity, err := d.deps.vaults.unwrap(ctx, id, "", d.newRelayUI(ctx, cs, req.ID, true, id))
		if err != nil {
			return ipc.Response{Err: d.unlockErr(id, err)}
		}
		spec := vault.FactorSpec{Kind: kind, Recipient: r.Recipient, IdentityStub: r.IdentityStub, PluginPath: r.PluginPath}
		if pass != nil {
			spec.Passphrase = memguard.NewBufferFromBytes(append([]byte(nil), pass.Bytes()...))
		}
		err = d.deps.vaults.addFactor(ctx, id, identity, spec, u)
		identity.Destroy()
		if spec.Passphrase != nil {
			spec.Passphrase.Destroy()
		}
		if err != nil {
			if errors.Is(err, vault.ErrWeakPassphrase) {
				return errResp(ipc.CodeBadRequest, "precinto: that passphrase is too weak (at least 12 characters and 80 bits)")
			}
			return ipc.Response{Err: d.unlockErr(id, err)}
		}
		d.mu.Lock()
		delete(d.gui, id)
		d.mu.Unlock()
	}
	return ipc.Response{}
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

// vaultRepair rewrites a tampered recipient set (D53): a same-executable
// peer on a terminal, never an agent context; the identity is unwrapped
// with a factor (or the recovery key) and must open an older capsule of the
// vault when one exists; the user confirms; capsules sealed since the last
// audit to a foreign recipient set are reported as exposed.
func (d *daemon) vaultRepair(ctx context.Context, cs *connState, req ipc.Request, sec []*memguard.LockedBuffer) ipc.Response {
	r := *req.VaultRepair
	if !cs.same {
		return errResp(ipc.CodeUnauthorized, "precinto: only precinto itself can repair a vault")
	}
	if e := authorize(cs.peer, d.ancestry(cs.peer), ipc.OpVaultRepair, "", []string{r.VaultID}, nil, d.folder); e != nil {
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
	u := d.newRelayUI(ctx, cs, req.ID, true, id)
	var identity *memguard.LockedBuffer
	var recovery *memguard.LockedBuffer
	var err error
	if r.UseRecovery {
		if len(sec) != 1 || sec[0].Size() == 0 {
			return errResp(ipc.CodeBadRequest, "precinto: vault repair --recovery needs the recovery key")
		}
		recovery = sec[0]
		identity, err = d.deps.vaults.unwrap(ctx, id, string(vault.FactorRecovery), recoveryUI{u, recovery})
	} else {
		identity, err = d.deps.vaults.unwrap(ctx, id, "", u)
	}
	if err != nil {
		return ipc.Response{Err: d.unlockErr(id, err)}
	}
	defer func() {
		if identity != nil {
			identity.Destroy()
		}
	}()
	meta, err := d.deps.vaults.meta(id)
	if err != nil {
		return ipc.Response{Err: d.unlockErr(id, err)}
	}
	if genuine, err := d.genuine(id, identity, meta.LastAudit); err != nil || !genuine {
		return errResp(ipc.CodeVerify, ui.Format(ui.MsgVaultNotGenuine, ui.Vars{Folder: folder}))
	}
	if !r.Confirmed {
		ok, err := u.Confirm(ui.Format(ui.MsgVaultRepairConfirm, ui.Vars{Folder: folder}), "repair", "cancel")
		if err != nil || !ok {
			return errResp(ipc.CodeCancelled, ui.Format(ui.MsgUnlockCancelled, ui.Vars{Folder: folder}))
		}
	}
	res, err := d.deps.vaults.repair(id, identity, recovery, d.clock.Now())
	if err != nil {
		if errors.Is(err, vault.ErrNeedRecovery) {
			return errResp(ipc.CodeUnauthorized, "precinto: the recovery key is needed: precinto vault repair --root "+folder+" --recovery")
		}
		return ipc.Response{Err: d.unlockErr(id, err)}
	}
	exposed := d.exposedSince(id, res.LastAudit)
	if err := d.deps.keyring.Put(id, identity); err == nil {
		identity = nil // owned by the key holder now
		d.apply(ctx, Input{Kind: InUnlock, Vaults: []string{id}})
	}
	d.setAttention(ipc.Attention{Code: ipc.AttnVaultTampered, Folder: folder}, false)
	if len(exposed) > 0 {
		d.setAttention(ipc.Attention{Code: ipc.AttnExposed, Folder: folder, Count: len(exposed), Fix: "precinto status"}, true)
	}
	d.logf("repaired vault %s (%d exposed)", id, len(exposed))
	return ipc.Response{Repair: &ipc.VaultRepairResp{RecipientChanged: res.RecipientChanged, RecoveryChanged: res.RecoveryChanged, Exposed: exposed}}
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
// recipients fingerprint is not the repaired vault's.
func (d *daemon) exposedSince(id string, since time.Time) []string {
	fpr, err := d.deps.vaults.fingerprint(id)
	if err != nil {
		return nil
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
