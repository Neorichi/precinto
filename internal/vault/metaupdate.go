package vault

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/precinto/precinto/internal/fsx"
)

// metaLockWait bounds how long a vault.toml rewrite waits for another one.
const metaLockWait = 10 * time.Second

// metaLockPath is the lock file serializing read-modify-write updates of
// the vault directory dir's vault.toml. It lives next to the vault
// directories (a dot name is never a vault id) and, like every lock file,
// is never deleted.
func metaLockPath(dir string) string {
	return filepath.Join(filepath.Dir(dir), "."+filepath.Base(dir)+".lock")
}

// updateMetaAt re-reads vault.toml of the vault directory dir under its
// lock, applies fn and writes the result atomically when fn reports a
// change. It returns the metadata as now on disk. Every vault.toml rewrite
// goes through it, so concurrent updates (MarkAudited while a factor is
// added) never lose each other's fields.
func updateMetaAt(dir string, fn func(m *Meta) (changed bool, err error)) (Meta, error) {
	ctx, cancel := context.WithTimeout(context.Background(), metaLockWait)
	defer cancel()
	lk, err := fsx.WaitLock(ctx, metaLockPath(dir), false)
	if err != nil {
		return Meta{}, fmt.Errorf("vault: lock %s: %w", filepath.Base(dir), err)
	}
	defer lk.Unlock()
	m, err := readMeta(dir)
	if err != nil {
		return Meta{}, err
	}
	if m.ID != filepath.Base(dir) {
		return Meta{}, fmt.Errorf("vault: %s/%s names vault %q", filepath.Base(dir), metaFile, m.ID)
	}
	changed, err := fn(&m)
	if err != nil || !changed {
		return m, err
	}
	if err := writeMeta(dir, m); err != nil {
		return Meta{}, err
	}
	return m, nil
}

// updateMeta is updateMetaAt for vault id of s.
func (s *Store) updateMeta(id string, fn func(m *Meta) (changed bool, err error)) error {
	if !validVaultID(id) {
		return fmt.Errorf("%w: bad vault id %q", ErrNotFound, id)
	}
	if _, err := s.open(id); err != nil {
		return err
	}
	_, err := updateMetaAt(s.vaultDir(id), fn)
	return err
}

// checkNotFuture refuses a time later than now (with no skew allowance:
// callers pass a time they measured).
func checkNotFuture(what string, at time.Time) error {
	if at.IsZero() {
		return fmt.Errorf("vault: %s needs a time", what)
	}
	if at.After(time.Now()) {
		return fmt.Errorf("vault: %s %s is in the future", what, at.UTC().Format(time.RFC3339))
	}
	return nil
}

func (s *Store) markAudited(id string, at time.Time) error {
	if err := checkNotFuture("last_audit", at); err != nil {
		return err
	}
	at = at.UTC()
	return s.updateMeta(id, func(m *Meta) (bool, error) {
		// A last_audit later than now (a forged or clock-skewed value)
		// counts as zero for readers: the audit just done replaces it.
		if !m.LastAudit.After(time.Now()) && !at.After(m.LastAudit) {
			return false, nil // never backwards
		}
		m.LastAudit = at
		return true, nil
	})
}

func (s *Store) markRecoveryVerified(at time.Time) error {
	if err := checkNotFuture("recovery_verified_at", at); err != nil {
		return err
	}
	at = at.UTC()
	ids, err := s.list()
	if err != nil {
		return err
	}
	if len(ids) == 0 {
		return fmt.Errorf("%w: no vaults", ErrNotFound)
	}
	var errs []error
	for _, id := range ids {
		err := s.updateMeta(id, func(m *Meta) (bool, error) {
			if !m.RecoveryVerifiedAt.After(time.Now()) && !at.After(m.RecoveryVerifiedAt) {
				return false, nil
			}
			m.RecoveryVerifiedAt = at
			return true, nil
		})
		if err != nil {
			errs = append(errs, fmt.Errorf("vault %s: %w", id, err))
		}
	}
	return errors.Join(errs...)
}

// checkRepinBinary requires the binary at path to be a regular file (not a
// symlink) owned by root or the current user and writable by nobody else.
func checkRepinBinary(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fmt.Errorf("vault: plugin path %q is not absolute and clean", path)
	}
	st, err := fsx.Lstat(path)
	if err != nil {
		return err
	}
	switch {
	case !st.IsRegular():
		return fmt.Errorf("%w: plugin %s is not a regular file", fsx.ErrUnsafe, path)
	case st.UID != 0 && int(st.UID) != os.Geteuid():
		return fmt.Errorf("%w: plugin %s is owned by uid %d (neither root nor you)", fsx.ErrUnsafe, path, st.UID)
	case st.Mode&0o022 != 0:
		return fmt.Errorf("%w: plugin %s is group- or other-writable (mode %04o)", fsx.ErrUnsafe, path, st.Mode&0o7777)
	}
	return nil
}

func (s *Store) repinPlugin(name string) (string, string, error) {
	if !validFactorName(name) {
		return "", "", fmt.Errorf("vault: bad factor name %q", name)
	}
	ids, err := s.list()
	if err != nil {
		return "", "", err
	}
	var path, oldSHA string
	var holders []string
	for _, id := range ids {
		v, err := s.open(id)
		if err != nil {
			return "", "", err
		}
		f, _, ok := v.factor(name)
		if !ok {
			continue
		}
		if f.Kind != FactorSE && f.Kind != FactorPlugin {
			return "", "", fmt.Errorf("vault: factor %q is not plugin-backed", name)
		}
		switch {
		case path == "":
			path, oldSHA = f.PluginPath, f.PluginSHA256
		case f.PluginPath != path:
			return "", "", fmt.Errorf("vault: factor %q pins different binaries in different vaults", name)
		}
		holders = append(holders, id)
	}
	if len(holders) == 0 {
		return "", "", fmt.Errorf("%w: factor %q", ErrNotFound, name)
	}
	if err := checkRepinBinary(path); err != nil {
		return "", "", err
	}
	newSHA, err := pinHash(path)
	if err != nil {
		return "", "", err
	}
	var errs []error
	for _, id := range holders {
		err := s.updateMeta(id, func(m *Meta) (bool, error) {
			for i := range m.Factors {
				if m.Factors[i].Name != name {
					continue
				}
				if m.Factors[i].PluginPath != path {
					return false, fmt.Errorf("vault: factor %q changed while re-pinning", name)
				}
				if m.Factors[i].PluginSHA256 == newSHA {
					return false, nil
				}
				m.Factors[i].PluginSHA256 = newSHA
				return true, nil
			}
			return false, fmt.Errorf("%w: factor %q", ErrNotFound, name)
		})
		if err != nil {
			errs = append(errs, fmt.Errorf("vault %s: %w", id, err))
		}
	}
	return oldSHA, newSHA, errors.Join(errs...)
}
