package agent

import (
	"context"
	"errors"
	"slices"
	"sort"

	"github.com/awnumar/memguard"

	"github.com/precinto/precinto/internal/ipc"
	"github.com/precinto/precinto/internal/sweep/capslog"
	"github.com/precinto/precinto/internal/vault"
)

// maxKeysPerRequest bounds one key release (one secret frame per key).
const maxKeysPerRequest = 1024

// keyCandidate is a capsule that passed provenance and scope checks.
type keyCandidate struct {
	rel    string
	header []byte
	entry  capslog.Entry
}

// keys releases per-capsule file keys (SPEC §13.5, D39): only to a peer
// running this executable, only for capsules in the capsule log, only when
// every root of the capsule is unlocked, after fresh presence where the
// agent-context rules require it (D28, D59). Identities never leave the
// daemon.
func (d *daemon) keys(ctx context.Context, cs *connState, r ipc.KeysReq) (ipc.Response, []*memguard.LockedBuffer) {
	if !cs.same {
		return errResp(ipc.CodeUnauthorized, "precinto: only precinto itself can receive keys"), nil
	}
	switch r.Purpose {
	case ipc.PurposeRestore, ipc.PurposeRestoreAll, ipc.PurposeOpen, ipc.PurposeCat, ipc.PurposeList:
	default:
		return errResp(ipc.CodeBadRequest, "precinto: unknown key purpose"), nil
	}
	if len(r.Capsules) > maxKeysPerRequest {
		return errResp(ipc.CodeBadRequest, "precinto: too many capsules in one request"), nil
	}
	anc := d.ancestry(cs.peer)
	f := factsOf(cs.peer, anc)
	sessRoots := d.sessionRoots(f)
	resp := ipc.KeysResp{Granted: []ipc.KeyGrant{}, Denied: map[string]ipc.Code{}}
	var cands []keyCandidate
	seen := map[string]bool{}
	for _, ref := range r.Capsules {
		rel := ref.Path
		if seen[rel] {
			continue
		}
		seen[rel] = true
		if _, _, err := capsuleRel(rel); err != nil {
			resp.Denied[rel] = ipc.CodeBadRequest
			continue
		}
		header, sha, err := d.deps.readHeader(rel)
		if err != nil {
			resp.Denied[rel] = ipc.CodeNotLogged // missing, unsafe or unreadable: no provenance
			continue
		}
		e, err := d.deps.lookup(rel, sha)
		if err != nil {
			resp.Denied[rel] = ipc.CodeNotLogged
			continue
		}
		roots := dedupe(append([]string{e.VaultID}, e.RootIDs...))
		if !d.allUnlocked(roots) {
			resp.Denied[rel] = ipc.CodeLocked
			continue
		}
		if e := authorize(cs.peer, anc, ipc.OpKeys, r.Purpose, roots, sessRoots, d.folder); e != nil {
			resp.Denied[rel] = e.Code
			continue
		}
		cands = append(cands, keyCandidate{rel: rel, header: header, entry: e})
	}
	if f.needsPresence(r.Purpose) && len(cands) > 0 {
		cands = d.presenceFor(ctx, cs, cands, resp.Denied)
	}
	var keys []*memguard.LockedBuffer
	for _, c := range cands {
		key, err := d.deps.keyring.FileKey(c.entry.VaultID, c.header)
		if err != nil {
			if errors.Is(err, vault.ErrLocked) {
				resp.Denied[c.rel] = ipc.CodeLocked
			} else {
				resp.Denied[c.rel] = ipc.CodeVerify
			}
			continue
		}
		if !d.manifestMatches(c, key) {
			key.Destroy()
			resp.Denied[c.rel] = ipc.CodeVerify
			continue
		}
		keys = append(keys, key)
		resp.Granted = append(resp.Granted, ipc.KeyGrant{Path: c.rel, VaultID: c.entry.VaultID})
	}
	if len(resp.Denied) == 0 {
		resp.Denied = nil
	}
	d.logf("keys: %d granted, %d denied (purpose %s, pid %d)", len(resp.Granted), len(resp.Denied), r.Purpose, cs.peer.PID)
	return ipc.Response{Keys: &resp}, keys
}

// allUnlocked reports whether every vault of ids holds its key now.
func (d *daemon) allUnlocked(ids []string) bool {
	v := d.view()
	for _, id := range ids {
		vs, ok := v.vaults[id]
		if !ok || vs.State != VaultUnlocked || !d.deps.keyring.Has(id) {
			return false
		}
	}
	return true
}

// manifestMatches decrypts the manifest head and checks its vault, unit
// and kind against the log entry (SPEC §13.5). A manifest that cannot be
// read for lack of the capsule format (an older capsule) is accepted only
// if the read fails for a reason other than a mismatch.
func (d *daemon) manifestMatches(c keyCandidate, key *memguard.LockedBuffer) bool {
	m, err := d.deps.manifest(c.rel, key.Bytes())
	if err != nil {
		return false
	}
	return m.VaultID == c.entry.VaultID && m.UnitKey == c.entry.Unit && string(m.Kind) == c.entry.Kind &&
		slices.Equal(sortedCopy(m.RootIDs), sortedCopy(c.entry.RootIDs))
}

func sortedCopy(s []string) []string {
	out := append([]string(nil), s...)
	sort.Strings(out)
	return out
}

// presenceFor obtains fresh user presence for each vault of cands (one
// unwrap through a dialog, D28): the requester has no terminal relay for
// Keys, so only factors that prompt without a terminal (Secure Enclave,
// pinentry) can prove presence. Capsules of a vault without presence are
// denied.
func (d *daemon) presenceFor(ctx context.Context, cs *connState, cands []keyCandidate, denied map[string]ipc.Code) []keyCandidate {
	ok := map[string]ipc.Code{}
	for _, c := range cands {
		id := c.entry.VaultID
		if _, done := ok[id]; done {
			continue
		}
		u := d.newRelayUI(ctx, cs, 0, false, id)
		identity, err := d.deps.vaults.unwrap(ctx, id, "", u)
		switch {
		case err == nil:
			identity.Destroy()
			ok[id] = ""
		case errors.Is(err, vault.ErrCancelled):
			ok[id] = ipc.CodeCancelled
		case errors.Is(err, vault.ErrBadSecret):
			ok[id] = ipc.CodeBadSecret
		default:
			ok[id] = ipc.CodeAgentContext
		}
	}
	var out []keyCandidate
	for _, c := range cands {
		if code := ok[c.entry.VaultID]; code != "" {
			denied[c.rel] = code
			continue
		}
		out = append(out, c)
	}
	return out
}
