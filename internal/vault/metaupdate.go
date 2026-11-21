package vault

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
	"unicode"
	"unicode/utf8"

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
// symlink) owned by root or the current user and writable by nobody else
// (D75).
func checkRepinBinary(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fmt.Errorf("vault: plugin path %q is not absolute and clean", path)
	}
	st, err := fsx.Lstat(path)
	if err != nil {
		return err
	}
	return checkRepinStat(path, st, uint32(os.Geteuid()))
}

// checkRepinStat is the D75 rule on the lstat of a plugin binary.
func checkRepinStat(path string, st fsx.Stat, euid uint32) error {
	switch {
	case !st.IsRegular():
		return fmt.Errorf("%w: plugin %s is not a regular file", fsx.ErrUnsafe, path)
	case st.UID != 0 && st.UID != euid:
		return fmt.Errorf("%w: plugin %s is owned by uid %d (neither root nor you)", fsx.ErrUnsafe, path, st.UID)
	case st.Mode&0o022 != 0:
		return fmt.Errorf("%w: plugin %s is group- or other-writable (mode %04o)", fsx.ErrUnsafe, path, st.Mode&0o7777)
	}
	return nil
}

// enrolledPath is the path a plugin factor was enrolled with (D80): its
// PluginLink, or the pinned PluginPath for a factor enrolled before D80.
// A repin never changes it, so it names the factor's binary in every vault
// even while some vaults still pin the binary before a repin and others
// the one after (a repin that failed half way).
func enrolledPath(f Factor) string {
	if f.PluginLink != "" {
		return f.PluginLink
	}
	return f.PluginPath
}

// unsafeShownPath reports a path that is not valid UTF-8 or holds C0, DEL,
// C1 or Unicode format (Cf: bidi overrides, zero-width) characters (D96).
func unsafeShownPath(p string) bool {
	if !utf8.ValidString(p) {
		return true
	}
	for _, r := range p {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) || unicode.Is(unicode.Cf, r) {
			return true
		}
	}
	return false
}

// pluginTarget implements PluginTarget: the enrolled path resolved through
// symlinks, which must keep the pinned binary's name and pass
// checkRepinBinary (D75, D80).
func pluginTarget(f Factor) (string, error) {
	link := enrolledPath(f)
	if !filepath.IsAbs(link) || filepath.Clean(link) != link || f.PluginPath == "" {
		return "", fmt.Errorf("%w: factor %q has no absolute enrolled plugin path", fsx.ErrUnsafe, f.Name)
	}
	if unsafeShownPath(link) || unsafeShownPath(f.PluginPath) {
		return "", fmt.Errorf("%w: the plugin paths of factor %q hold control or invisible characters", fsx.ErrUnsafe, f.Name)
	}
	real, err := filepath.EvalSymlinks(link)
	if err != nil {
		return "", err
	}
	real = filepath.Clean(real)
	if unsafeShownPath(real) {
		// D96: a genuine Homebrew path never holds them; shown to the
		// user who decides the repin, they could repaint the screen.
		return "", fmt.Errorf("%w: the binary the plugin link of factor %q leads to has control or invisible characters in its path", fsx.ErrUnsafe, f.Name)
	}
	if want := filepath.Base(f.PluginPath); filepath.Base(real) != want {
		return "", fmt.Errorf("%w: %q resolves to %q, not to a binary named %q", fsx.ErrUnsafe, link, real, want)
	}
	if err := checkRepinBinary(real); err != nil {
		return "", err
	}
	return real, nil
}

func (s *Store) repinPlugin(name string) (string, string, error) {
	if !validFactorName(name) {
		return "", "", fmt.Errorf("vault: bad factor name %q", name)
	}
	ids, err := s.list()
	if err != nil {
		return "", "", err
	}
	var pinned Factor
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
		// Vaults may pin different binaries of one enrolled path after a
		// repin that failed half way; this repin brings them all to the
		// binary the path leads to now.
		switch {
		case len(holders) == 0:
			pinned = f
		case enrolledPath(f) != enrolledPath(pinned) || filepath.Base(f.PluginPath) != filepath.Base(pinned.PluginPath):
			return "", "", fmt.Errorf("vault: factor %q was enrolled with different binaries in different vaults", name)
		}
		holders = append(holders, id)
	}
	if len(holders) == 0 {
		return "", "", fmt.Errorf("%w: factor %q", ErrNotFound, name)
	}
	target, err := pluginTarget(pinned)
	if err != nil {
		return "", "", err
	}
	newSHA, err := pinHash(target)
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
				if enrolledPath(m.Factors[i]) != enrolledPath(pinned) || filepath.Base(m.Factors[i].PluginPath) != filepath.Base(pinned.PluginPath) {
					return false, fmt.Errorf("vault: factor %q changed while re-pinning", name)
				}
				if m.Factors[i].PluginSHA256 == newSHA && m.Factors[i].PluginPath == target {
					return false, nil
				}
				if m.Factors[i].PluginLink == "" {
					m.Factors[i].PluginLink = enrolledPath(m.Factors[i]) // enrolled before D80: that path is the link from now on
				}
				m.Factors[i].PluginPath, m.Factors[i].PluginSHA256 = target, newSHA
				return true, nil
			}
			return false, fmt.Errorf("%w: factor %q", ErrNotFound, name)
		})
		if err != nil {
			errs = append(errs, fmt.Errorf("vault %s: %w", id, err))
		}
	}
	return pinned.PluginSHA256, newSHA, errors.Join(errs...)
}
