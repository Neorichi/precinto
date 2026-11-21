package vault

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"filippo.io/age"
	"github.com/BurntSushi/toml"
	"github.com/awnumar/memguard"

	"github.com/precinto/precinto/internal/fsx"
)

const (
	metaFile     = "vault.toml"
	maxMetaBytes = 1 << 20
	verifiedExt  = ".recipients"
)

// verifiedCopy is state/verified/<vault-id>.recipients: the recipient set
// the daemon last verified with the vault identity (D5 tripwire).
type verifiedCopy struct {
	Format            int       `toml:"format"`
	ID                string    `toml:"id"`
	Family            string    `toml:"family"`
	Recipient         string    `toml:"recipient"`
	RecoveryRecipient string    `toml:"recovery_recipient"`
	VerifiedAt        time.Time `toml:"verified_at"`
}

func (c verifiedCopy) matches(m Meta) bool {
	return c.Family == m.Family && c.Recipient == m.Recipient && c.RecoveryRecipient == m.RecoveryRecipient
}

// validVaultID: a root id or "global", usable as a directory name.
func validVaultID(id string) bool {
	if id == "" || len(id) > 128 || id[0] == '.' || id[0] == '-' {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.') {
			return false
		}
	}
	return true
}

func readVaultFile(dir, name string, max int64) ([]byte, error) {
	d, err := fsx.OpenBase(filepath.Clean(dir))
	if err != nil {
		return nil, err
	}
	defer d.Close()
	f, st, err := d.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if st.Size > max {
		return nil, fmt.Errorf("vault: %s is too large", name)
	}
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, fmt.Errorf("vault: %s is too large", name)
	}
	return b, nil
}

func writeVaultFile(dir, name string, data []byte) error {
	return fsx.WriteFileAtomic(filepath.Join(filepath.Clean(dir), name), data, 0o600)
}

func removeVaultFile(dir, name string) error {
	d, err := fsx.OpenBase(filepath.Clean(dir))
	if err != nil {
		return err
	}
	defer d.Close()
	if err := d.Remove(name); err != nil {
		return err
	}
	return d.Sync()
}

func decodeStrict(b []byte, v any) error {
	md, err := toml.Decode(string(b), v)
	if err != nil {
		return err
	}
	if und := md.Undecoded(); len(und) > 0 {
		return fmt.Errorf("unknown key %q", und[0].String())
	}
	return nil
}

func readMeta(dir string) (Meta, error) {
	b, err := readVaultFile(dir, metaFile, maxMetaBytes)
	if err != nil {
		return Meta{}, err
	}
	var m Meta
	if err := decodeStrict(b, &m); err != nil {
		return Meta{}, fmt.Errorf("vault: %s/%s: %w", filepath.Base(dir), metaFile, err)
	}
	if m.Format != FormatVersion {
		return Meta{}, fmt.Errorf("vault: %s/%s has format %d", filepath.Base(dir), metaFile, m.Format)
	}
	return m, nil
}

func writeMeta(dir string, m Meta) error {
	var buf bytes.Buffer
	if err := toml.NewEncoder(&buf).Encode(m); err != nil {
		return err
	}
	return writeVaultFile(dir, metaFile, buf.Bytes())
}

func (s *Store) vaultDir(id string) string { return filepath.Join(s.VaultsDir, id) }

func (s *Store) readVerified(id string) (verifiedCopy, error) {
	b, err := readVaultFile(s.VerifiedDir, id+verifiedExt, maxMetaBytes)
	if err != nil {
		return verifiedCopy{}, err
	}
	var c verifiedCopy
	if err := decodeStrict(b, &c); err != nil {
		return verifiedCopy{}, fmt.Errorf("vault: verified copy of %s: %w", id, err)
	}
	if c.Format != FormatVersion || c.ID != id {
		return verifiedCopy{}, fmt.Errorf("vault: verified copy of %s is not for this vault", id)
	}
	return c, nil
}

func (s *Store) writeVerified(m Meta, now time.Time) error {
	if err := fsx.MkdirPrivate(s.VerifiedDir); err != nil {
		return err
	}
	var buf bytes.Buffer
	c := verifiedCopy{Format: FormatVersion, ID: m.ID, Family: m.Family, Recipient: m.Recipient, RecoveryRecipient: m.RecoveryRecipient, VerifiedAt: now.UTC()}
	if err := toml.NewEncoder(&buf).Encode(c); err != nil {
		return err
	}
	return writeVaultFile(s.VerifiedDir, m.ID+verifiedExt, buf.Bytes())
}

func (s *Store) initialized() (bool, error) {
	m, err := readMeta(s.vaultDir(GlobalID))
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return m.RecoveryRecipient != "", nil
}

func (s *Store) ensureDirs() error {
	for _, d := range []string{s.VaultsDir, s.VerifiedDir, s.FactorsDir} {
		if !filepath.IsAbs(d) {
			return fmt.Errorf("vault: store directory %q is not absolute", d)
		}
		if err := fsx.MkdirPrivate(d); err != nil {
			return err
		}
		if err := fsx.CheckPrivateDir(d); err != nil {
			return err
		}
	}
	return nil
}

func nowFunc(f func() time.Time) time.Time {
	if f != nil {
		return f().UTC()
	}
	return time.Now().UTC()
}

func (s *Store) init(ctx context.Context, o InitOptions) (*memguard.LockedBuffer, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	now := nowFunc(o.Now)
	var plans []*factorPlan
	defer func() {
		for _, p := range plans {
			p.destroy()
		}
	}()
	var planErr error
	for _, spec := range o.Factors {
		if planErr != nil { // consume every passphrase, even after an error
			if spec.Passphrase != nil {
				spec.Passphrase.Destroy()
			}
			continue
		}
		p, err := planFactor(spec, now)
		if err != nil {
			planErr = err
			continue
		}
		plans = append(plans, p)
	}
	if planErr != nil {
		return nil, planErr
	}
	if len(plans) == 0 {
		return nil, fmt.Errorf("%w: init needs at least one factor besides the recovery key", ErrLastFactor)
	}
	if err := uniqueNames(plans); err != nil {
		return nil, err
	}
	if ok, err := s.initialized(); err != nil {
		return nil, err
	} else if ok {
		return nil, fmt.Errorf("vault: already initialized: %w", fs.ErrExist)
	}
	if err := s.ensureDirs(); err != nil {
		return nil, err
	}
	recovery, err := newIdentity()
	if err != nil {
		return nil, err
	}
	recoveryRcpt, err := recipientOf(recovery)
	if err != nil {
		recovery.Destroy()
		return nil, err
	}
	global, err := s.createVault(ctx, GlobalID, "", recoveryRcpt, plans, o.UI, now)
	if err != nil {
		recovery.Destroy()
		return nil, err
	}
	global.Destroy() // unlocked later through a factor; Init only creates it
	for _, p := range plans {
		if p.factor.Kind == FactorSE {
			_ = writeVaultFile(s.FactorsDir, "se.identity", []byte(p.factor.IdentityStub+"\n"))
		}
	}
	return recovery, nil
}

func uniqueNames(plans []*factorPlan) error {
	seen := map[string]bool{string(FactorRecovery): true}
	for _, p := range plans {
		if seen[p.factor.Name] {
			return fmt.Errorf("vault: factor name %q used twice", p.factor.Name)
		}
		seen[p.factor.Name] = true
	}
	return nil
}

// createVault writes a complete vault directory under a temporary name,
// renames it into place (no-replace), so a vault is never seen half made,
// then writes the verified copy.
func (s *Store) createVault(ctx context.Context, id, rootPath, recoveryRcpt string, plans []*factorPlan, ui UI, now time.Time) (*memguard.LockedBuffer, error) {
	identity, err := newIdentity()
	if err != nil {
		return nil, err
	}
	ok := false
	defer func() {
		if !ok {
			identity.Destroy()
		}
	}()
	recipient, err := recipientOf(identity)
	if err != nil {
		return nil, err
	}
	if _, err := age.ParseX25519Recipient(recoveryRcpt); err != nil || recoveryRcpt == recipient {
		return nil, errors.New("vault: bad recovery recipient")
	}
	var rnd [6]byte
	_, _ = rand.Read(rnd[:])
	tmpName := "." + id + ".new-" + hex.EncodeToString(rnd[:])
	tmpDir := filepath.Join(s.VaultsDir, tmpName)
	if err := fsx.MkdirPrivate(tmpDir); err != nil {
		return nil, err
	}
	defer func() {
		if !ok {
			if st, err := fsx.OpenStaging(tmpDir); err == nil {
				_ = st.Remove()
			}
		}
	}()
	m := Meta{Format: FormatVersion, ID: id, RootPath: rootPath, CreatedAt: now, Family: Family, Recipient: recipient, RecoveryRecipient: recoveryRcpt}
	all := append([]*factorPlan(nil), plans...)
	all = append(all, &factorPlan{factor: Factor{Name: string(FactorRecovery), Kind: FactorRecovery, Recipient: recoveryRcpt, AddedAt: now}})
	for _, p := range all {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		f := p.factor
		f.AddedAt = now
		ct, err := wrapIdentity(ctx, f, identity, p.passphrase, ui)
		if err != nil {
			return nil, err
		}
		if err := writeVaultFile(tmpDir, identityFileName(f.Name), ct); err != nil {
			return nil, err
		}
		m.Factors = append(m.Factors, f)
	}
	if m.RecipientsMAC, err = macWith(identity, InfoRecipients, canonicalSet(m.Family, m.Recipient, m.RecoveryRecipient)); err != nil {
		return nil, err
	}
	if err := writeMeta(tmpDir, m); err != nil {
		return nil, err
	}
	vd, err := fsx.OpenBase(filepath.Clean(s.VaultsDir))
	if err != nil {
		return nil, err
	}
	defer vd.Close()
	if err := vd.Rename(tmpName, id, fsx.NoReplace); err != nil {
		if errors.Is(err, fsx.ErrExist) {
			return nil, fmt.Errorf("vault: %s already exists: %w", id, fs.ErrExist)
		}
		return nil, err
	}
	// The tripwire copy is written only once this creator's directory won
	// the no-replace rename: a concurrent loser never overwrites it. If
	// this write fails the vault exists without a copy, so sealing is
	// refused until the next unlock's Verify writes it.
	if err := s.writeVerified(m, now); err != nil {
		return nil, fmt.Errorf("vault: %s created, but its verified recipient set was not written (unlock it to complete): %w", id, err)
	}
	ok = true
	return identity, nil
}

func (s *Store) create(ctx context.Context, id, rootPath string, ui UI) (*memguard.LockedBuffer, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if !validVaultID(id) || id == GlobalID {
		return nil, fmt.Errorf("vault: bad vault id %q", id)
	}
	global, err := s.open(GlobalID)
	if errors.Is(err, ErrNotFound) {
		return nil, fmt.Errorf("%w: precinto is not initialized", ErrNotFound)
	}
	if err != nil {
		return nil, err
	}
	// The recovery recipient comes from the verified copy of the global
	// vault: never from an unverified vault.toml (D5).
	vc, err := s.readVerified(GlobalID)
	if err != nil {
		return nil, fmt.Errorf("%w: the global vault has no verified recipient set", ErrRecipientsChanged)
	}
	if !vc.matches(global.Meta) {
		return nil, ErrRecipientsChanged
	}
	if _, err := s.open(id); err == nil {
		return nil, fmt.Errorf("vault: %s already exists: %w", id, fs.ErrExist)
	} else if !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	now := time.Now().UTC()
	var plans []*factorPlan
	defer func() {
		for _, p := range plans {
			p.destroy()
		}
	}()
	for _, f := range global.Meta.Factors {
		switch f.Kind {
		case FactorRecovery:
			continue
		case FactorPassphrase:
			pass, err := s.confirmPassphrase(ctx, global, f, ui)
			if err != nil {
				return nil, err
			}
			plans = append(plans, &factorPlan{factor: f, passphrase: pass})
		default:
			plans = append(plans, &factorPlan{factor: f})
		}
	}
	if len(plans) == 0 {
		return nil, ErrLastFactor
	}
	if err := s.ensureDirs(); err != nil {
		return nil, err
	}
	return s.createVault(ctx, id, rootPath, vc.RecoveryRecipient, plans, ui, now)
}

// confirmPassphrase asks for the install's passphrase and checks it against
// the global vault's passphrase file, so every vault shares one passphrase.
func (s *Store) confirmPassphrase(ctx context.Context, global *Vault, f Factor, ui UI) (*memguard.LockedBuffer, error) {
	if ui == nil || !ui.Interactive() {
		return nil, ErrNoUI
	}
	ct, err := readVaultFile(global.Dir, identityFileName(f.Name), maxIdentityFile)
	if err != nil {
		return nil, err
	}
	if err := checkScryptFile(ct, f.ScryptLogN); err != nil {
		return nil, err
	}
	pass, err := ui.Secret(promptPassphrase)
	if err != nil {
		return nil, err
	}
	sid, err := age.NewScryptIdentity(view(pass.Bytes()))
	if err != nil {
		pass.Destroy()
		return nil, ErrBadSecret
	}
	sid.SetMaxWorkFactor(f.ScryptLogN)
	r, err := age.Decrypt(bytes.NewReader(ct), sid)
	if err != nil {
		pass.Destroy()
		return nil, unwrapError(ctx, err, FactorPassphrase)
	}
	gid, err := readIdentity(r) // the global identity: verified, then wiped
	if err != nil {
		pass.Destroy()
		return nil, fmt.Errorf("%w: identity file content", ErrWrongIdentity)
	}
	gid.Destroy()
	return pass, nil
}

func (s *Store) list() ([]string, error) {
	d, err := fsx.OpenBase(filepath.Clean(s.VaultsDir))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer d.Close()
	ents, err := d.ReadDir("")
	if err != nil {
		return nil, err
	}
	var ids []string
	for _, e := range ents {
		if e.Type != fsx.TypeDir || !validVaultID(e.Name) {
			continue
		}
		if st, err := d.Lstat(e.Name + "/" + metaFile); err == nil && st.IsRegular() {
			ids = append(ids, e.Name)
		}
	}
	sort.Strings(ids)
	return ids, nil
}

func (s *Store) open(id string) (*Vault, error) {
	if !validVaultID(id) {
		return nil, fmt.Errorf("%w: bad vault id %q", ErrNotFound, id)
	}
	dir := s.vaultDir(id)
	m, err := readMeta(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%w: %s", ErrNotFound, id)
	}
	if err != nil {
		return nil, err
	}
	if m.ID != id {
		return nil, fmt.Errorf("vault: %s/%s names vault %q", id, metaFile, m.ID)
	}
	return &Vault{Dir: dir, Meta: m}, nil
}

func (s *Store) recipients(id string) ([]age.Recipient, string, error) {
	v, err := s.open(id)
	if err != nil {
		return nil, "", err
	}
	m := v.Meta
	if m.Family != Family {
		return nil, "", fmt.Errorf("%w: family %q", ErrRecipientsChanged, m.Family)
	}
	vc, err := s.readVerified(id)
	if err != nil {
		return nil, "", fmt.Errorf("%w: no verified copy for %s", ErrRecipientsChanged, id)
	}
	if !vc.matches(m) {
		return nil, "", ErrRecipientsChanged
	}
	vr, err := age.ParseX25519Recipient(m.Recipient)
	if err != nil {
		return nil, "", fmt.Errorf("%w: malformed vault recipient", ErrRecipientsChanged)
	}
	rr, err := age.ParseX25519Recipient(m.RecoveryRecipient)
	if err != nil || m.RecoveryRecipient == m.Recipient {
		return nil, "", fmt.Errorf("%w: malformed recovery recipient", ErrRecipientsChanged)
	}
	return []age.Recipient{vr, rr}, fingerprint(m.Family, m.Recipient, m.RecoveryRecipient), nil
}

func (s *Store) verify(v *Vault, identity *memguard.LockedBuffer) error {
	if v == nil {
		return ErrNotFound
	}
	r, err := recipientOf(identity)
	if err != nil {
		return err
	}
	if r != v.Meta.Recipient {
		return ErrWrongIdentity
	}
	if v.Meta.Family != Family {
		return ErrMACMismatch
	}
	mac, err := macWith(identity, InfoRecipients, canonicalSet(v.Meta.Family, v.Meta.Recipient, v.Meta.RecoveryRecipient))
	if err != nil {
		return err
	}
	if !macEqual(mac, v.Meta.RecipientsMAC) {
		return ErrMACMismatch
	}
	vc, err := s.readVerified(v.Meta.ID)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		// First verification since the copy was lost: the MAC vouches for
		// the set.
	case err != nil:
		return err
	case !vc.matches(v.Meta):
		// Only Repair may move the tripwire (D53): a consistent but
		// different set means vault.toml and its identity files were
		// replaced together.
		return ErrRecipientsChanged
	}
	return s.writeVerified(v.Meta, time.Now())
}

func (s *Store) repair(v *Vault, o RepairOptions) (RepairResult, error) {
	if v == nil {
		return RepairResult{}, ErrNotFound
	}
	recipient, err := recipientOf(o.Identity)
	if err != nil {
		return RepairResult{}, err
	}
	var recovery string
	if o.Recovery != nil {
		rid, err := ParseRecoveryKey(o.Recovery)
		if err != nil {
			return RepairResult{}, err
		}
		recovery = rid.(*age.X25519Identity).Recipient().String()
	} else {
		vc, err := s.readVerified(v.Meta.ID)
		if err != nil || v.Meta.RecoveryRecipient != vc.RecoveryRecipient {
			return RepairResult{}, ErrNeedRecovery
		}
		recovery = vc.RecoveryRecipient
	}
	if recovery == recipient {
		return RepairResult{}, errors.New("vault: the recovery key equals the vault key")
	}
	now := nowFunc(o.Now)
	mac, err := macWith(o.Identity, InfoRecipients, canonicalSet(Family, recipient, recovery))
	if err != nil {
		return RepairResult{}, err
	}
	var res RepairResult
	m, err := updateMetaAt(v.Dir, func(m *Meta) (bool, error) {
		res = RepairResult{
			RecipientChanged: recipient != m.Recipient,
			RecoveryChanged:  recovery != m.RecoveryRecipient,
			LastAudit:        m.LastAudit,
		}
		m.Family, m.Recipient, m.RecoveryRecipient, m.RecipientsMAC = Family, recipient, recovery, mac
		m.LastAudit = now
		return true, nil
	})
	if err != nil {
		return RepairResult{}, err
	}
	if err := s.writeVerified(m, now); err != nil {
		return RepairResult{}, err
	}
	v.Meta = m
	return res, nil
}

func (s *Store) remove(id string) error {
	if !validVaultID(id) {
		return fmt.Errorf("%w: bad vault id %q", ErrNotFound, id)
	}
	if id == GlobalID {
		return errors.New("vault: the global vault is never removed")
	}
	dir := s.vaultDir(id)
	d, err := fsx.OpenBase(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("%w: %s", ErrNotFound, id)
	}
	if err != nil {
		return err
	}
	ents, err := d.ReadDir("")
	if err != nil {
		d.Close()
		return err
	}
	// Only files this package writes are removed; anything else stops the
	// removal before it starts (fail closed).
	for _, e := range ents {
		ours := e.Name == metaFile || strings.HasPrefix(e.Name, "identity.") && strings.HasSuffix(e.Name, ".age") ||
			strings.HasPrefix(e.Name, "."+metaFile+".tmp-") || strings.HasPrefix(e.Name, ".identity.")
		if e.Type != fsx.TypeRegular || !ours {
			d.Close()
			return fmt.Errorf("vault: %s holds an unexpected entry %q; not removed", id, e.Name)
		}
	}
	for _, e := range ents {
		if err := d.Remove(e.Name); err != nil {
			d.Close()
			return err
		}
	}
	d.Close()
	vd, err := fsx.OpenBase(filepath.Clean(s.VaultsDir))
	if err != nil {
		return err
	}
	defer vd.Close()
	if err := vd.Remove(id); err != nil {
		return err
	}
	if err := vd.Sync(); err != nil {
		return err
	}
	if err := removeVaultFile(s.VerifiedDir, id+verifiedExt); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}
