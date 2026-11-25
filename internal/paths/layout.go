package paths

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Neorichi/precinto/internal/fsx"
)

// newLayout implements NewLayout for an explicit GOOS and override decision.
//
// Without overrides the base is DefaultBase and the run directory is
// <base>/run on darwin and $XDG_RUNTIME_DIR/precinto on linux, falling back
// to <base>/run when XDG_RUNTIME_DIR is unset, relative or "/" (headless
// linux without logind, SPEC §12.5).
//
// With overrides, PRECINTO_HOME replaces the base and PRECINTO_RUNTIME_DIR
// the run directory; an empty value counts as unset. When only PRECINTO_HOME
// is set the run directory is <PRECINTO_HOME>/run on every OS, so a testing
// or PRECINTO_DEV instance never shares the real daemon's socket directory.
// An override that is set but not an absolute clean path is an error, never
// a silent fallback to the real locations (fail closed).
func newLayout(e Env, goos string, overrides bool) (Layout, error) {
	var base, runDir string
	if overrides {
		var err error
		if base, err = overridePath(e, EnvHome); err != nil {
			return Layout{}, err
		}
		if runDir, err = overridePath(e, EnvRuntimeDir); err != nil {
			return Layout{}, err
		}
	}
	baseOverridden := base != ""
	if base == "" {
		b, err := defaultBaseFor(e, goos)
		if err != nil {
			return Layout{}, err
		}
		base = b
	}
	if runDir == "" {
		runDir = filepath.Join(base, "run")
		if goos == "linux" && !baseOverridden {
			// As DefaultBase does for XDG_DATA_HOME: a relative value is
			// ignored (XDG spec), an absolute one is cleaned.
			if x := e.Get(EnvXDGRuntimeDir); filepath.IsAbs(x) && filepath.Clean(x) != "/" {
				runDir = filepath.Join(filepath.Clean(x), "precinto")
			}
		}
	}
	return LayoutAt(base, runDir)
}

// checkLayoutDrives applies check (CheckDrive) to the base and to a run
// directory outside it (D156): precinto keeps its vaults, capsules,
// staging, per-folder Codex homes and socket only off Windows drives.
func checkLayoutDrives(l Layout, check func(string) error) error {
	if err := check(l.Base); err != nil {
		return err
	}
	if l.RunDir != "" && !Within(l.Base, l.RunDir) {
		return check(l.RunDir)
	}
	return nil
}

// overridePath returns the value of an override variable, "" when it is
// unset or empty, and an error when it is not an absolute clean path.
func overridePath(e Env, key string) (string, error) {
	v := e.Get(key)
	if v == "" {
		return "", nil
	}
	if c, ok := Clean(v); !ok || c == "/" {
		return "", fmt.Errorf("paths: %s is not an absolute clean path", key)
	}
	return v, nil
}

// File-type bits of st_mode (identical on darwin and linux).
const (
	modeTypeMask = 0o170000
	modeSymlink  = 0o120000
)

// layoutDir is one directory EnsureDirs manages.
type layoutDir struct {
	name string // Layout field, for error messages
	path string
}

// dirs lists every directory of l, parents before children, without
// duplicates. Every entry must be an absolute clean path other than "/".
func (l Layout) dirs() ([]layoutDir, error) {
	all := []layoutDir{
		{"Base", l.Base},
		{"BinLink parent", parentOf(l.BinLink)},
		{"VaultsDir", l.VaultsDir},
		{"FactorsDir", l.FactorsDir},
		{"CapsulesDir", l.CapsulesDir},
		{"HomesDir", l.HomesDir},
		{"StagingDir", l.StagingDir},
		{"QuarantineDir", l.QuarantineDir},
		{"StateDir", l.StateDir},
		{"VerifiedDir", l.VerifiedDir},
		{"GensDir", l.GensDir},
		{"ReceiptsDir", l.ReceiptsDir},
		{"LeasesDir", l.LeasesDir},
		{"SessionsDir", l.SessionsDir},
		{"ProjectsDir", l.ProjectsDir},
		{"JournalDir", l.JournalDir},
		{"QueueDir", l.QueueDir},
		{"LocksDir", l.LocksDir},
		{"HookDedupeDir", l.HookDedupeDir},
		{"LogsDir", l.LogsDir},
		{"RunDir", l.RunDir},
	}
	seen := make(map[string]bool, len(all))
	out := make([]layoutDir, 0, len(all))
	for _, d := range all {
		if c, ok := Clean(d.path); !ok || c == "/" {
			return nil, fmt.Errorf("paths: layout %s %q is not an absolute clean path", d.name, d.path)
		}
		if seen[d.path] {
			continue
		}
		seen[d.path] = true
		out = append(out, d)
	}
	sort.SliceStable(out, func(i, j int) bool { return depth(out[i].path) < depth(out[j].path) })
	return out, nil
}

// parentOf returns the directory of a file path, or "" for "".
func parentOf(p string) string {
	if p == "" {
		return ""
	}
	return filepath.Dir(p)
}

// depth counts the components of a clean absolute path.
func depth(p string) int { return strings.Count(p, "/") }

// ensureDirs implements Layout.EnsureDirs. Directories are visited parents
// first; a missing one is created with mode 0700 (and chmod'ed to exactly
// 0700 when the umask removed owner bits); missing parents of the base and
// of the run directory are created with mode 0700 as well. Existing
// directories are never modified: a symlink, a non-directory, a foreign
// owner or group/other permission bits fail with fsx.ErrUnsafe (the
// fsx.CheckPrivateDir rule), so a misconfigured override such as
// PRECINTO_RUNTIME_DIR=/tmp is refused instead of being chmod'ed. A final
// pass re-checks every directory after all of them exist.
func (l Layout) ensureDirs() error {
	dirs, err := l.dirs()
	if err != nil {
		return err
	}
	for _, d := range dirs {
		if err := ensurePrivateDir(d.path); err != nil {
			return err
		}
	}
	for _, d := range dirs {
		if err := checkPrivateDir(d.path); err != nil {
			return err
		}
	}
	return nil
}

// ensurePrivateDir creates path (and missing parents) with mode 0700 when it
// does not exist, then checks it with checkPrivateDir.
func ensurePrivateDir(path string) error {
	if err := mkdirPrivate(path); err != nil {
		return err
	}
	return checkPrivateDir(path)
}

// mkdirPrivate creates the missing components of path, outermost first, each
// with mode 0700 regardless of the umask (a umask can only clear bits, and
// clearing owner bits would make the next component uncreatable). Existing
// components, including a symlinked trusted ancestor such as /tmp on
// darwin, are left untouched.
//
// TODO(lead): mkdirPrivate and checkPrivateDir are local adapters for
// fsx.MkdirPrivate and fsx.CheckPrivateDir, which were scaffold stubs when
// paths was written (wave 1). Once G1 lands them, ensurePrivateDir should
// call fsx.MkdirPrivate(path) then fsx.CheckPrivateDir(path), and both
// adapters go away; keep the behaviour the layout tests pin (umask-proof
// 0700 for every created component, existing directories never chmod'ed,
// symlinks, foreign owners and group/other bits refused with fsx.ErrUnsafe,
// a final re-check pass after every directory exists).
func mkdirPrivate(path string) error {
	var missing []string
	for p := path; ; p = filepath.Dir(p) {
		_, err := fsx.Lstat(p)
		if err == nil {
			break
		}
		if !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("paths: %w", err)
		}
		missing = append(missing, p)
		if filepath.Dir(p) == p {
			break
		}
	}
	for i := len(missing) - 1; i >= 0; i-- {
		p := missing[i]
		if err := os.Mkdir(p, 0o700); err != nil {
			if errors.Is(err, fs.ErrExist) {
				continue // created concurrently; checkPrivateDir judges it
			}
			return fmt.Errorf("paths: create %s: %w", p, err)
		}
		st, err := fsx.Lstat(p)
		if err != nil {
			return fmt.Errorf("paths: %w", err)
		}
		if st.IsDir() && st.UID == uint32(os.Geteuid()) && st.Perm() != 0o700 {
			if err := os.Chmod(p, 0o700); err != nil {
				return fmt.Errorf("paths: chmod %s: %w", p, err)
			}
		}
	}
	return nil
}

// checkPrivateDir requires path to be a directory (not a symlink) owned by
// the effective uid with no group or other permission bits.
func checkPrivateDir(path string) error {
	st, err := fsx.Lstat(path)
	if err != nil {
		return fmt.Errorf("paths: %w", err)
	}
	switch {
	case st.Mode&modeTypeMask == modeSymlink:
		return fmt.Errorf("%w: %s is a symlink", fsx.ErrUnsafe, path)
	case !st.IsDir():
		return fmt.Errorf("%w: %s is not a directory", fsx.ErrUnsafe, path)
	case st.UID != uint32(os.Geteuid()):
		return fmt.Errorf("%w: %s is owned by uid %d", fsx.ErrUnsafe, path, st.UID)
	case st.Perm()&0o077 != 0:
		return fmt.Errorf("%w: %s has mode %04o (want 0700)", fsx.ErrUnsafe, path, st.Mode&0o7777)
	}
	return nil
}
