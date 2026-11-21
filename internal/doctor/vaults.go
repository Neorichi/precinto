package doctor

import (
	"errors"
	"io/fs"
	"time"

	"github.com/precinto/precinto/internal/fsx"
	"github.com/precinto/precinto/internal/ui"
	"github.com/precinto/precinto/internal/vault"
)

// Vault checks (SPEC §4; D3, D5, D7, D53). They read vault.toml and the
// tripwire copy through internal/vault; no key is involved, so the
// recipients MAC itself is checked only by the agent at unlock (its
// attention items are merged into the findings).

// vaultInfo is what doctor read of one vault.
type vaultInfo struct {
	id      string
	v       *vault.Vault
	openErr error
	fpr     string // recipients fingerprint, when the tripwire check passed
	recErr  error
}

// vaultIDs lists the vaults doctor checks: one per protected root, plus
// the global vault.
func (e *env) vaultIDs() []string {
	ids := make([]string, 0, len(e.o.Cfg.Roots)+1)
	for _, r := range e.o.Cfg.Roots {
		ids = append(ids, r.ID)
	}
	return append(ids, vault.GlobalID)
}

// vault returns what doctor read of vault id (loaded once).
func (e *env) vault(id string) *vaultInfo {
	if vi, ok := e.vaults[id]; ok {
		return vi
	}
	vi := &vaultInfo{id: id}
	vi.v, vi.openErr = e.d.OpenVault(id)
	if vi.openErr == nil {
		vi.fpr, vi.recErr = e.d.VaultRecipients(id)
	}
	e.vaults[id] = vi
	return vi
}

// initialized reports whether `precinto init` has run; known is false when
// that cannot be told.
func (e *env) initialized() (done, known bool) {
	ok, err := e.d.VaultInitialized()
	return ok, err == nil
}

// repairCommand is the fix of a tampered vault (D53).
func (e *env) repairCommand(id string) string {
	if id == vault.GlobalID {
		return "precinto vault repair --global"
	}
	if r, ok := e.o.Cfg.RootByID(id); ok {
		return "precinto vault repair --root " + e.arg(r.Path)
	}
	return "precinto vault repair"
}

func checkVaultTampered(e *env) []Finding {
	if done, known := e.initialized(); known && !done {
		if len(e.o.Cfg.Roots) == 0 {
			return []Finding{info(CheckVaultTampered, "precinto is not set up yet", "precinto init")}
		}
		return []Finding{fail(CheckVaultTampered, "precinto is not set up (no vaults), so nothing in the protected folders can be sealed", "precinto init")}
	}
	var out []Finding
	for _, id := range e.vaultIDs() {
		vi := e.vault(id)
		switch {
		case errors.Is(vi.openErr, vault.ErrNotFound):
			out = append(out, fail(CheckVaultTampered, e.folderOf(id)+" has no vault, so precinto cannot seal anything there",
				"restore precinto's vaults folder from a backup; otherwise protect the folder again (older capsules then open only with the recovery key)"))
		case vi.openErr != nil:
			out = append(out, warn(CheckVaultTampered, "could not read the vault of "+e.folderOf(id)+" ("+errClass(vi.openErr)+")", e.repairCommand(id)))
		case errors.Is(vi.recErr, vault.ErrRecipientsChanged):
			out = append(out, fail(CheckVaultTampered, catalog(ui.MsgVaultTampered, ui.Vars{Folder: e.folderOf(id)}), e.repairCommand(id)))
		case vi.recErr != nil:
			out = append(out, warn(CheckVaultTampered, "could not check the recipients of "+e.folderOf(id)+"'s vault ("+errClass(vi.recErr)+"); sealing there may be paused", e.repairCommand(id)))
		}
	}
	if len(out) == 0 {
		out = append(out, ok(CheckVaultTampered, "every vault matches its verified recipients (the tripwire copy)"))
	}
	return out
}

func checkExposed(e *env) []Finding {
	log, err := e.capsuleLog()
	if err != nil {
		return []Finding{info(CheckExposed, "could not read the capsule log ("+errClass(err)+"), so sealed capsules were not audited", "")}
	}
	counts := map[string]int{}
	for _, en := range log {
		vi := e.vault(en.VaultID)
		if vi.openErr != nil || vi.recErr != nil || vi.fpr == "" {
			continue // a tampered or unreadable vault is reported by vault-tampered
		}
		if en.RecipientsFpr != vi.fpr {
			counts[en.VaultID]++
		}
	}
	var out []Finding
	for _, id := range sortedKeys(counts) {
		out = append(out, fail(CheckExposed, plural(counts[id], "capsule", "capsules")+" of "+e.folderOf(id)+" "+verb(counts[id], "was", "were")+" sealed to a different set of keys than its vault's: whoever changed the vault file may be able to read "+verb(counts[id], "it", "them"),
			"treat what those sessions contain as exposed (precinto cannot re-encrypt them yet); precinto status lists them"))
	}
	if len(out) == 0 && len(log) > 0 {
		out = append(out, ok(CheckExposed, "every logged capsule was sealed to its vault's keys"))
	}
	return out
}

func checkRecoveryTested(e *env) []Finding {
	if done, known := e.initialized(); known && !done {
		return nil
	}
	var newest time.Time
	read := false
	for _, id := range e.vaultIDs() {
		vi := e.vault(id)
		if vi.v == nil {
			continue
		}
		read = true
		if t := vi.v.Meta.RecoveryVerifiedAt; t.After(newest) {
			newest = t
		}
	}
	switch {
	case !read:
		return nil // the vaults are unreadable: vault-tampered reports it
	case newest.IsZero():
		return []Finding{warn(CheckRecoveryTested, "the recovery key has never been tested: if you lose your unlock factors, sealed sessions open only with it",
			"precinto recover --verify")}
	}
	return []Finding{ok(CheckRecoveryTested, "the recovery key was last tested on "+newest.UTC().Format("2006-01-02"))}
}

// minScryptLogN is the passphrase work-factor floor (D3).
const minScryptLogN = 19

// checkPluginPin reports plugin-backed factors whose pinned binary no
// longer matches its SHA-256 (unlock with that factor fails, exit 5) and
// names the command that re-pins it (D75). Like the vault before every use
// (pinHash), it requires the pinned path to be a regular file, never a
// symlink, and only hashes it. Each distinct pin is checked once: a factor
// may carry another pin in another vault.
func checkPluginPin(e *env) []Finding {
	type pin struct{ name, path, sha string }
	var pins []pin
	seen := map[pin]bool{}
	for _, id := range e.vaultIDs() {
		vi := e.vault(id)
		if vi.v == nil {
			continue
		}
		for _, f := range vi.v.Meta.Factors {
			if (f.Kind != vault.FactorSE && f.Kind != vault.FactorPlugin) || f.PluginPath == "" {
				continue
			}
			p := pin{f.Name, f.PluginPath, f.PluginSHA256} // compared exactly, as the vault does
			if !seen[p] {
				seen[p] = true
				pins = append(pins, p)
			}
		}
	}
	if len(pins) == 0 {
		return nil
	}
	var out []Finding
	for _, p := range pins {
		name := oneLine(p.name)
		repin := "precinto factor repin " + name
		what := "the " + name + " unlock method's plugin " + e.show(p.path)
		if p.sha == "" {
			out = append(out, fail(CheckPluginPin, what+" has no pinned hash: unlocking with it fails until it is re-pinned", repin))
			continue
		}
		if st, err := fsx.Lstat(p.path); err == nil && !st.IsRegular() {
			out = append(out, fail(CheckPluginPin, what+" is no longer a regular file (precinto never runs a linked plugin): unlocking with it fails", "put the plugin binary itself at "+e.arg(p.path)+", then run: "+repin))
			continue
		}
		sum, err := e.sha256File(p.path)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			out = append(out, fail(CheckPluginPin, what+" is missing: unlocking with it fails", "reinstall the plugin there, then run: "+repin))
		case err != nil:
			out = append(out, warn(CheckPluginPin, what+" could not be checked ("+errClass(err)+"): unlocking with it may fail", repin))
		case sum != p.sha:
			out = append(out, fail(CheckPluginPin, what+" changed since it was pinned (an upgrade?): unlocking with it fails until it is re-pinned", repin))
		}
	}
	if len(out) == 0 {
		out = append(out, ok(CheckPluginPin, "every pinned plugin matches its recorded hash"))
	}
	return out
}

func checkPassphraseFactor(e *env) []Finding {
	var with, weak []string
	read := false
	for _, id := range e.vaultIDs() {
		vi := e.vault(id)
		if vi.v == nil {
			continue
		}
		read = true
		for _, f := range vi.v.Meta.Factors {
			if f.Kind != vault.FactorPassphrase {
				continue
			}
			with = append(with, e.folderOf(id))
			if f.ScryptLogN > 0 && f.ScryptLogN < minScryptLogN {
				weak = append(weak, e.folderOf(id))
			}
		}
	}
	if !read {
		return nil
	}
	var out []Finding
	if len(weak) > 0 {
		out = append(out, warn(CheckPassphraseFactor, "the passphrase of "+joinNames(weak)+" uses a scrypt work factor below the minimum (2^19), which makes it faster to guess",
			"add the passphrase again so it is re-wrapped with the current work factor: precinto factor list"))
	}
	if len(with) > 0 {
		out = append(out, warn(CheckPassphraseFactor, "a passphrase unlocks "+joinNames(with)+": anyone with a copy of the vault files can try to guess it offline",
			"use a long passphrase (7 random words); on a Mac prefer the Mac password factor: precinto factor list"))
	}
	if len(out) == 0 {
		out = append(out, ok(CheckPassphraseFactor, "no vault can be unlocked with a passphrase"))
	}
	return out
}
