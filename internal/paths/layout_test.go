package paths_test

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/precinto/precinto/internal/fsx"
	"github.com/precinto/precinto/internal/paths"
)

// shortDir returns a fresh, symlink-free directory with a short path: the
// macOS t.TempDir is too long for a socket below it.
func shortDir(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("/tmp", "pt-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = filepath.WalkDir(d, func(p string, e fs.DirEntry, err error) error {
			if err == nil && e.IsDir() {
				_ = os.Chmod(p, 0o700)
			}
			return nil
		})
		if err := os.RemoveAll(d); err != nil {
			t.Errorf("cleanup: %v", err)
		}
	})
	real, err := filepath.EvalSymlinks(d)
	if err != nil {
		t.Fatal(err)
	}
	return real
}

func defaultBase(t *testing.T, home string) string {
	t.Helper()
	b, err := paths.DefaultBase(paths.FromMap(map[string]string{"HOME": home}))
	if err != nil {
		t.Skip("unsupported OS:", err)
	}
	return b
}

func TestNewLayoutDefault(t *testing.T) {
	base := defaultBase(t, "/u")
	l, err := paths.NewLayout(paths.FromMap(map[string]string{"HOME": "/u"}))
	if err != nil {
		t.Fatal(err)
	}
	want, err := paths.LayoutAt(base, filepath.Join(base, "run"))
	if err != nil {
		t.Fatal(err)
	}
	if l != want {
		t.Errorf("NewLayout = %+v\nwant %+v", l, want)
	}
	if runtime.GOOS == "linux" {
		l, err := paths.NewLayout(paths.FromMap(map[string]string{"HOME": "/u", paths.EnvXDGRuntimeDir: "/run/user/7"}))
		if err != nil || l.RunDir != "/run/user/7/precinto" || l.Socket != "/run/user/7/precinto/agent.sock" {
			t.Errorf("linux run dir: %+v %v", l, err)
		}
	}
}

// TestNewLayoutOverrides is the D6 table: PRECINTO_HOME/PRECINTO_RUNTIME_DIR
// are honoured by testing builds, or with PRECINTO_DEV=1 and no agent marker.
func TestNewLayoutOverrides(t *testing.T) {
	def := defaultBase(t, "/u")
	defLayout, err := paths.NewLayout(paths.FromMap(map[string]string{"HOME": "/u"}))
	if err != nil {
		t.Fatal(err)
	}
	over := map[string]string{"HOME": "/u", paths.EnvHome: "/b", paths.EnvRuntimeDir: "/r"}
	with := func(extra map[string]string) map[string]string {
		m := map[string]string{}
		for k, v := range over {
			m[k] = v
		}
		for k, v := range extra {
			m[k] = v
		}
		return m
	}
	for _, c := range []struct {
		name    string
		env     map[string]string
		honored bool // in a production build
	}{
		{"production ignores overrides", over, false},
		{"PRECINTO_DEV honours them", with(map[string]string{paths.EnvDev: "1"}), true},
		{"PRECINTO_DEV in Claude", with(map[string]string{paths.EnvDev: "1", paths.EnvClaudeCode: "1"}), false},
		{"PRECINTO_DEV in a Codex hook", with(map[string]string{paths.EnvDev: "1", paths.EnvPluginRoot: "/p"}), false},
		{"PRECINTO_DEV in the wrapper", with(map[string]string{paths.EnvDev: "1", paths.EnvActive: "1"}), false},
	} {
		t.Run(c.name, func(t *testing.T) {
			l, err := paths.NewLayout(paths.FromMap(c.env))
			if err != nil {
				t.Fatal(err)
			}
			if c.honored || paths.TestingBuild() {
				if l.Base != "/b" || l.RunDir != "/r" || l.Socket != "/r/agent.sock" || l.ConfigFile != "/b/config.toml" {
					t.Errorf("overrides not honoured: %+v", l)
				}
				return
			}
			if l != defLayout || l.Base != def {
				t.Errorf("overrides honoured in a production build: %+v", l)
			}
		})
	}
}

func TestNewLayoutOverrideRules(t *testing.T) {
	dev := func(m map[string]string) paths.Env {
		m[paths.EnvDev] = "1"
		return paths.FromMap(m)
	}
	// Only PRECINTO_HOME: the run directory follows the overridden base, so
	// a test instance never shares the real daemon's socket directory.
	l, err := paths.NewLayout(dev(map[string]string{"HOME": "/u", paths.EnvHome: "/b", paths.EnvXDGRuntimeDir: "/run/user/7"}))
	if err != nil || l.Base != "/b" || l.RunDir != "/b/run" {
		t.Errorf("base override only: %+v %v", l, err)
	}
	// Only PRECINTO_RUNTIME_DIR.
	base := defaultBase(t, "/u")
	l, err = paths.NewLayout(dev(map[string]string{"HOME": "/u", paths.EnvRuntimeDir: "/r"}))
	if err != nil || l.Base != base || l.RunDir != "/r" {
		t.Errorf("run dir override only: %+v %v", l, err)
	}
	// HOME is not needed when the base is overridden.
	if l, err := paths.NewLayout(dev(map[string]string{paths.EnvHome: "/b"})); err != nil || l.Base != "/b" {
		t.Errorf("base override without HOME: %+v %v", l, err)
	}
	// Empty overrides count as unset.
	if l, err := paths.NewLayout(dev(map[string]string{"HOME": "/u", paths.EnvHome: "", paths.EnvRuntimeDir: ""})); err != nil || l.Base != base {
		t.Errorf("empty overrides: %+v %v", l, err)
	}
	// A bad override fails closed instead of falling back to the real base.
	for _, bad := range []map[string]string{
		{"HOME": "/u", paths.EnvHome: "relative"},
		{"HOME": "/u", paths.EnvHome: "/b/"},
		{"HOME": "/u", paths.EnvHome: "/b/../c"},
		{"HOME": "/u", paths.EnvHome: "/"},
		{"HOME": "/u", paths.EnvRuntimeDir: "run"},
		{"HOME": "/u", paths.EnvRuntimeDir: "/"},
	} {
		if l, err := paths.NewLayout(dev(bad)); err == nil {
			t.Errorf("NewLayout(%v) = %+v, want error", bad, l)
		}
	}
	// The same bad values are ignored when overrides are not allowed.
	if !paths.TestingBuild() {
		if _, err := paths.NewLayout(paths.FromMap(map[string]string{"HOME": "/u", paths.EnvHome: "relative"})); err != nil {
			t.Errorf("ignored override still parsed: %v", err)
		}
	}
}

func TestNewLayoutErrors(t *testing.T) {
	if _, err := paths.NewLayout(paths.FromMap(nil)); err == nil {
		t.Error("NewLayout without HOME succeeded")
	}
	if _, err := paths.NewLayout(paths.FromMap(map[string]string{"HOME": "relative"})); err == nil {
		t.Error("NewLayout with a relative HOME succeeded")
	}
	long := "/" + strings.Repeat("h", 100)
	if _, err := paths.NewLayout(paths.FromMap(map[string]string{"HOME": long})); !errors.Is(err, paths.ErrSocketPath) {
		t.Errorf("long HOME: err = %v, want ErrSocketPath", err)
	}
	e := paths.FromMap(map[string]string{"HOME": "/u", paths.EnvDev: "1", paths.EnvRuntimeDir: long})
	if _, err := paths.NewLayout(e); !errors.Is(err, paths.ErrSocketPath) {
		t.Errorf("long PRECINTO_RUNTIME_DIR: err = %v, want ErrSocketPath", err)
	}
	// 104 bytes is too long, 103 fits (exclusive bound).
	for _, n := range []int{paths.MaxSocketPath - 1, paths.MaxSocketPath} {
		dir := "/" + strings.Repeat("r", n-len("/")-len("/agent.sock"))
		_, err := paths.NewLayout(paths.FromMap(map[string]string{"HOME": "/u", paths.EnvDev: "1", paths.EnvRuntimeDir: dir}))
		if tooLong := errors.Is(err, paths.ErrSocketPath); tooLong != (n >= paths.MaxSocketPath) {
			t.Errorf("socket path of %d bytes: err = %v", n, err)
		}
	}
}

func layoutDirs(l paths.Layout) []string {
	return []string{
		l.Base, filepath.Dir(l.BinLink), l.VaultsDir, l.FactorsDir, l.CapsulesDir, l.HomesDir, l.StagingDir,
		l.QuarantineDir, l.StateDir, l.VerifiedDir, l.GensDir, l.ReceiptsDir, l.LeasesDir, l.SessionsDir,
		l.ProjectsDir, l.JournalDir, l.QueueDir, l.LocksDir, l.LogsDir, l.RunDir,
	}
}

func checkPrivate(t *testing.T, dir string) {
	t.Helper()
	fi, err := os.Lstat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !fi.IsDir() || fi.Mode().Perm() != 0o700 {
		t.Errorf("%s: mode %v, want a 0700 directory", dir, fi.Mode())
	}
}

func TestEnsureDirs(t *testing.T) {
	root := shortDir(t)
	// Missing parents of the base and of the run directory are created too.
	l, err := paths.LayoutAt(filepath.Join(root, "a", "b", "base"), filepath.Join(root, "run", "r"))
	if err != nil {
		t.Fatal(err)
	}
	if err := l.EnsureDirs(); err != nil {
		t.Fatal(err)
	}
	for _, d := range layoutDirs(l) {
		checkPrivate(t, d)
	}
	checkPrivate(t, filepath.Join(root, "a"))
	checkPrivate(t, filepath.Join(root, "run"))
	// Idempotent; files already present are left alone.
	if err := os.WriteFile(l.ConfigFile, []byte("version = 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := l.EnsureDirs(); err != nil {
		t.Fatalf("second EnsureDirs: %v", err)
	}
	if b, err := os.ReadFile(l.ConfigFile); err != nil || string(b) != "version = 1\n" {
		t.Errorf("config.toml changed: %q %v", b, err)
	}
	// The darwin layout keeps the run directory inside the base.
	l2, err := paths.LayoutAt(filepath.Join(root, "base2"), filepath.Join(root, "base2", "run"))
	if err != nil {
		t.Fatal(err)
	}
	if err := l2.EnsureDirs(); err != nil {
		t.Fatal(err)
	}
	checkPrivate(t, l2.RunDir)
}

func TestEnsureDirsRefusesUnsafe(t *testing.T) {
	type setup func(t *testing.T, l paths.Layout)
	for _, c := range []struct {
		name  string
		setup setup
	}{
		{"base with group bits", func(t *testing.T, l paths.Layout) { mkdir(t, l.Base, 0o750) }},
		{"base world readable", func(t *testing.T, l paths.Layout) { mkdir(t, l.Base, 0o755) }},
		{"base is a symlink", func(t *testing.T, l paths.Layout) {
			target := filepath.Join(filepath.Dir(l.Base), "elsewhere")
			mkdir(t, target, 0o700)
			symlink(t, target, l.Base)
		}},
		{"base is a file", func(t *testing.T, l paths.Layout) { writeFile(t, l.Base) }},
		{"state is a symlink", func(t *testing.T, l paths.Layout) {
			mkdir(t, l.Base, 0o700)
			target := filepath.Join(filepath.Dir(l.Base), "elsewhere")
			mkdir(t, target, 0o700)
			symlink(t, target, l.StateDir)
		}},
		{"locks is a symlink", func(t *testing.T, l paths.Layout) {
			mkdir(t, l.StateDir, 0o700)
			target := filepath.Join(filepath.Dir(l.Base), "elsewhere")
			mkdir(t, target, 0o700)
			symlink(t, target, l.LocksDir)
		}},
		{"capsules is a file", func(t *testing.T, l paths.Layout) {
			mkdir(t, l.Base, 0o700)
			writeFile(t, l.CapsulesDir)
		}},
		{"run dir world writable", func(t *testing.T, l paths.Layout) { mkdir(t, l.RunDir, 0o777) }},
	} {
		t.Run(c.name, func(t *testing.T) {
			root := shortDir(t)
			l, err := paths.LayoutAt(filepath.Join(root, "base"), filepath.Join(root, "run"))
			if err != nil {
				t.Fatal(err)
			}
			c.setup(t, l)
			before := snapshotModes(t, root)
			err = l.EnsureDirs()
			if !errors.Is(err, fsx.ErrUnsafe) {
				t.Fatalf("EnsureDirs = %v, want fsx.ErrUnsafe", err)
			}
			// Existing entries are never chmod'ed or replaced.
			after := snapshotModes(t, root)
			for p, m := range before {
				if after[p] != m {
					t.Errorf("%s changed from %v to %v", p, m, after[p])
				}
			}
		})
	}
}

// TestEnsureDirsForeignOwner uses a root-owned system directory as the run
// directory: it must be refused and, above all, never chmod'ed.
func TestEnsureDirsForeignOwner(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: no foreign-owned directory to test with")
	}
	sys, err := filepath.EvalSymlinks("/tmp")
	if err != nil {
		t.Skip(err)
	}
	before, err := os.Lstat(sys)
	if err != nil {
		t.Skip(err)
	}
	root := shortDir(t)
	l, err := paths.LayoutAt(filepath.Join(root, "base"), sys)
	if err != nil {
		t.Fatal(err)
	}
	if err := l.EnsureDirs(); !errors.Is(err, fsx.ErrUnsafe) {
		t.Fatalf("EnsureDirs with a root-owned run dir = %v, want fsx.ErrUnsafe", err)
	}
	if after, err := os.Lstat(sys); err != nil || after.Mode() != before.Mode() {
		t.Fatalf("%s mode changed: %v -> %v (%v)", sys, before.Mode(), after.Mode(), err)
	}
}

func TestEnsureDirsInvalidLayout(t *testing.T) {
	if err := (paths.Layout{}).EnsureDirs(); err == nil {
		t.Error("EnsureDirs of a zero Layout succeeded")
	}
	root := shortDir(t)
	l, err := paths.LayoutAt(filepath.Join(root, "base"), filepath.Join(root, "run"))
	if err != nil {
		t.Fatal(err)
	}
	l.QueueDir = "relative/queue"
	if err := l.EnsureDirs(); err == nil {
		t.Error("EnsureDirs with a relative directory succeeded")
	}
	if _, err := os.Lstat(filepath.Join(root, "base")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("an invalid layout created directories: %v", err)
	}
}

func mkdir(t *testing.T, p string, perm fs.FileMode) {
	t.Helper()
	if err := os.MkdirAll(p, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, perm); err != nil {
		t.Fatal(err)
	}
}

func symlink(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
}

func writeFile(t *testing.T, p string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
}

// snapshotModes records the mode of every entry below root (not following
// symlinks).
func snapshotModes(t *testing.T, root string) map[string]fs.FileMode {
	t.Helper()
	out := map[string]fs.FileMode{}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		fi, err := d.Info()
		if err != nil {
			return err
		}
		out[p] = fi.Mode()
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestVaultDirAndFromOS(t *testing.T) {
	l, err := paths.LayoutAt("/b", "/r")
	if err != nil {
		t.Fatal(err)
	}
	if got := l.VaultDir("root-acme"); got != "/b/vaults/root-acme" {
		t.Errorf("VaultDir = %q", got)
	}
	// FromOS is a snapshot: later changes to the process do not show.
	t.Setenv("PRECINTO_PATHS_TEST", "before")
	e := paths.FromOS()
	t.Setenv("PRECINTO_PATHS_TEST", "after")
	if got := e.Get("PRECINTO_PATHS_TEST"); got != "before" {
		t.Errorf("FromOS snapshot = %q", got)
	}
}
