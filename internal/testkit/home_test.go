package testkit_test

import (
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Neorichi/precinto/internal/config"
	"github.com/Neorichi/precinto/internal/paths"
	"github.com/Neorichi/precinto/internal/platform"
	"github.com/Neorichi/precinto/internal/testkit"
)

func TestNewHomeTree(t *testing.T) {
	h := testkit.NewHome(t)
	want := map[string]string{
		"HomeDir":      filepath.Join(h.Dir, "home"),
		"Root":         filepath.Join(h.Dir, "home", "work", "acme"),
		"Base":         filepath.Join(h.Dir, "base"),
		"ClaudeConfig": filepath.Join(h.Dir, "claude"),
		"ClaudeTmp":    filepath.Join(h.Dir, "claude-tmp"),
		"CodexUser":    filepath.Join(h.Dir, "codex-user"),
	}
	if runtime.GOOS == "linux" {
		want["ClaudeCache"] = filepath.Join(h.Dir, "xdg", "cache", "claude-cli-nodejs")
	} else {
		want["ClaudeCache"] = filepath.Join(h.Dir, "home", "Library", "Caches", "claude-cli-nodejs")
	}
	got := map[string]string{
		"HomeDir": h.HomeDir, "Root": h.Root, "Base": h.Base, "ClaudeConfig": h.ClaudeConfig,
		"ClaudeTmp": h.ClaudeTmp, "CodexUser": h.CodexUser, "ClaudeCache": h.ClaudeCache,
	}
	for k, w := range want {
		if got[k] != w {
			t.Errorf("%s = %q, want %q", k, got[k], w)
		}
	}
	// Every path is absolute, clean and symlink-free (fsx refuses symlinked
	// components, and /var and /tmp are symlinks on darwin).
	for k, p := range map[string]string{"Dir": h.Dir, "RunDir": h.RunDir, "Root": h.Root, "ClaudeCache": h.ClaudeCache} {
		if real, err := filepath.EvalSymlinks(p); err != nil || real != p {
			t.Errorf("%s %q resolves to %q (%v)", k, p, real, err)
		}
	}
	// The whole tree is 0700.
	for _, top := range []string{h.Dir, h.RunDir} {
		err := filepath.WalkDir(top, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				if fi, err := d.Info(); err != nil || fi.Mode().Perm() != 0o700 {
					t.Errorf("%s: mode %v (%v), want 0700", p, fi.Mode(), err)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, d := range []string{h.Root, h.ClaudeCache, filepath.Join(h.Dir, "xdg", "state"), filepath.Join(h.Dir, "tmp")} {
		if fi, err := os.Stat(d); err != nil || !fi.IsDir() {
			t.Errorf("%s missing: %v", d, err)
		}
	}
	// The layout is the one paths derives for the base and the short run dir.
	l, err := paths.LayoutAt(h.Base, h.RunDir)
	if err != nil || h.Layout != l {
		t.Errorf("Layout = %+v, want LayoutAt(Base, RunDir) %+v (%v)", h.Layout, l, err)
	}
	if len(h.Layout.Socket) >= paths.MaxSocketPath {
		t.Errorf("socket path %q is %d bytes", h.Layout.Socket, len(h.Layout.Socket))
	}
	for _, d := range []string{h.Layout.StateDir, h.Layout.LocksDir, h.Layout.CapsulesDir, h.Layout.LogsDir} {
		if fi, err := os.Stat(d); err != nil || !fi.IsDir() {
			t.Errorf("layout directory %s missing: %v", d, err)
		}
	}
	if err := h.Layout.EnsureDirs(); err != nil {
		t.Errorf("EnsureDirs on a fresh home: %v", err)
	}
}

func TestNewHomeEnv(t *testing.T) {
	h := testkit.NewHome(t)
	want := map[string]string{
		"HOME":                   h.HomeDir,
		"PATH":                   "/usr/bin:/bin:/usr/sbin:/sbin",
		"TMPDIR":                 filepath.Join(h.Dir, "tmp"),
		paths.EnvHome:            h.Base,
		paths.EnvRuntimeDir:      h.RunDir,
		paths.EnvClaudeConfigDir: h.ClaudeConfig,
		paths.EnvClaudeTmpDir:    h.ClaudeTmp,
		paths.EnvCodexHome:       h.CodexUser,
		paths.EnvXDGDataHome:     filepath.Join(h.Dir, "xdg", "data"),
		"XDG_STATE_HOME":         filepath.Join(h.Dir, "xdg", "state"),
		"XDG_CACHE_HOME":         filepath.Join(h.Dir, "xdg", "cache"),
		"XDG_CONFIG_HOME":        filepath.Join(h.Dir, "xdg", "config"),
		paths.EnvXDGRuntimeDir:   filepath.Join(h.RunDir, "xdg"),
		// D64: testing binaries end their ancestry walk at this process.
		paths.EnvTestAncestryStop: platform.Self().String(),
	}
	for k, w := range want {
		if v, ok := h.Env.Lookup(k); !ok || v != w {
			t.Errorf("Env %s = %q, want %q", k, v, w)
		}
	}
	if n := len(h.Env.Environ()); n != len(want) {
		t.Errorf("Env has %d variables, want exactly %d: %q", n, len(want), h.Env.Environ())
	}
	if m := paths.AgentMarkers(h.Env); len(m) != 0 {
		t.Errorf("Env carries agent markers %q", m)
	}
	// Whatever the build flavour, paths resolves this environment inside the
	// sandbox: the overrides in a testing build, the fake HOME otherwise.
	l, err := paths.NewLayout(h.Env)
	switch {
	case paths.TestingBuild():
		if err != nil || l != h.Layout {
			t.Errorf("testing build: NewLayout = %+v, %v; want h.Layout", l, err)
		}
	case err == nil:
		if !paths.Within(h.Dir, l.Base) || !paths.Within(h.Dir, l.RunDir) {
			t.Errorf("production build: NewLayout left the sandbox: %+v", l)
		}
	}
	if paths.OverridesAllowed(h.Env) != paths.TestingBuild() {
		t.Error("the fake home enables PRECINTO_DEV overrides")
	}
}

// TestNewHomeNeverRealHome: no value of Env refers to the real HOME (or
// anything below it) unless it lies inside the sandbox itself.
func TestNewHomeNeverRealHome(t *testing.T) {
	realHome := os.Getenv("HOME")
	if realHome == "" || !filepath.IsAbs(realHome) {
		t.Skip("no absolute HOME in the test environment")
	}
	resolved, err := filepath.EvalSymlinks(realHome)
	if err != nil {
		resolved = realHome
	}
	h := testkit.NewHome(t)
	for _, kv := range h.Env.Environ() {
		k, v, _ := strings.Cut(kv, "=")
		if k == paths.EnvTestAncestryStop {
			// D64: the test process's PID:START, not a path.
			if v != platform.Self().String() {
				t.Errorf("Env %s=%q, want the test process %s", k, v, platform.Self())
			}
			continue
		}
		for _, p := range filepath.SplitList(v) {
			if !filepath.IsAbs(p) {
				t.Errorf("Env %s=%q holds a relative path", k, v)
			}
			if paths.Within(h.Dir, p) || paths.Within(h.RunDir, p) {
				continue
			}
			if paths.Within(realHome, p) || paths.Within(resolved, p) {
				t.Errorf("Env %s=%q points at the real HOME %q", k, v, realHome)
			}
		}
	}
	for _, p := range []string{h.HomeDir, h.Base, h.ClaudeConfig, h.ClaudeTmp, h.ClaudeCache, h.CodexUser, h.Root, h.RunDir, h.Layout.Socket} {
		if p == realHome || (paths.Within(realHome, p) && !paths.Within(h.Dir, p)) {
			t.Errorf("%s is inside the real HOME", p)
		}
	}
}

func TestNewHomeConfig(t *testing.T) {
	h := testkit.NewHome(t)
	if err := h.Cfg.Validate(); err != nil {
		t.Fatalf("Cfg invalid: %v", err)
	}
	r, ok := h.Cfg.RootByID("root-acme")
	if !ok || r.Path != h.Root || !r.ProtectedAt.Equal(testkit.Epoch) {
		t.Fatalf("root-acme = %+v %v", r, ok)
	}
	if got, ok := h.Cfg.RootFor(filepath.Join(h.Root, "docs", "notes.md")); !ok || got.ID != "root-acme" {
		t.Errorf("RootFor = %+v %v", got, ok)
	}
	homes := h.Cfg.Harness["claude-code"].Homes
	if len(homes) != 1 || homes[0].Dir != h.ClaudeConfig || homes[0].Tmp != h.ClaudeTmp || homes[0].Cache != h.ClaudeCache {
		t.Errorf("claude-code homes = %+v", homes)
	}
	disk, err := config.Load(h.Layout.ConfigFile)
	if err != nil {
		t.Fatalf("config.toml: %v", err)
	}
	if cs := config.Diff(h.Cfg, disk); len(cs) != 0 {
		t.Errorf("config.toml differs from Cfg: %+v", cs)
	}
	roots, err := config.ReadRootsList(h.Layout.RootsList)
	if err != nil || !slices.Equal(roots, []string{h.Root}) {
		t.Errorf("roots.list = %q %v", roots, err)
	}
	for _, f := range []string{h.Layout.ConfigFile, h.Layout.RootsList} {
		if fi, err := os.Stat(f); err != nil || fi.Mode().Perm() != 0o600 {
			t.Errorf("%s: %v %v", f, fi.Mode(), err)
		}
	}
	if !h.Clock.Now().Equal(testkit.Epoch) || h.Clock.Mono() != 0 {
		t.Errorf("Clock starts at %v / %v", h.Clock.Now(), h.Clock.Mono())
	}
	if ps, err := h.Procs.List(); err != nil || len(ps) != 0 {
		t.Errorf("Procs = %+v %v", ps, err)
	}
}

func TestNewHomeIsolatedAndPure(t *testing.T) {
	before := os.Environ()
	a, b := testkit.NewHome(t), testkit.NewHome(t)
	if a.Dir == b.Dir || a.RunDir == b.RunDir || a.Layout.Socket == b.Layout.Socket {
		t.Errorf("two homes share directories: %s %s", a.Dir, b.Dir)
	}
	if after := os.Environ(); !slices.Equal(before, after) {
		t.Error("NewHome changed the process environment")
	}
}

func TestNewHomeCleanup(t *testing.T) {
	var dir, run string
	t.Run("home", func(t *testing.T) {
		h := testkit.NewHome(t)
		dir, run = h.Dir, h.RunDir
		// A read-only directory left by an EACCES test must not break removal.
		if err := os.Chmod(h.Root, 0o500); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(h.Layout.StateDir, 0o000); err != nil {
			t.Fatal(err)
		}
	})
	for _, d := range []string{dir, run} {
		if _, err := os.Lstat(d); !os.IsNotExist(err) {
			t.Errorf("%s still exists after the test: %v", d, err)
		}
	}
}

func TestSetenv(t *testing.T) {
	// Pretend the suite runs inside Claude Code with a developer override.
	t.Setenv(paths.EnvClaudeCode, "1")
	t.Setenv("CODEX_THREAD_ID", "outer")
	t.Setenv(paths.EnvCodexSQLiteHome, "/somewhere/real")
	t.Setenv(paths.EnvDev, "1")
	origHome := os.Getenv("HOME")
	var h *testkit.Home
	t.Run("inside", func(t *testing.T) {
		h = testkit.NewHome(t)
		h.Setenv(t)
		for _, kv := range h.Env.Environ() {
			k, v, _ := strings.Cut(kv, "=")
			if got := os.Getenv(k); got != v {
				t.Errorf("%s = %q, want %q", k, got, v)
			}
		}
		for _, k := range []string{paths.EnvClaudeCode, "CODEX_THREAD_ID", paths.EnvCodexSQLiteHome, paths.EnvDev} {
			if _, set := os.LookupEnv(k); set {
				t.Errorf("%s still set", k)
			}
		}
		if m := paths.AgentMarkers(paths.FromOS()); len(m) != 0 {
			t.Errorf("agent markers left in the process: %q", m)
		}
		l, err := paths.NewLayout(paths.FromOS())
		if err == nil && !paths.Within(h.Dir, l.Base) {
			t.Errorf("after Setenv the layout leaves the sandbox: %+v", l)
		}
	})
	// Everything is restored when the test ends.
	if os.Getenv("HOME") != origHome || os.Getenv(paths.EnvClaudeCode) != "1" || os.Getenv("CODEX_THREAD_ID") != "outer" ||
		os.Getenv(paths.EnvCodexSQLiteHome) != "/somewhere/real" || os.Getenv(paths.EnvDev) != "1" {
		t.Errorf("environment not restored: HOME=%q", os.Getenv("HOME"))
	}
	if _, set := os.LookupEnv(paths.EnvHome); set && os.Getenv(paths.EnvHome) == h.Base {
		t.Error("PRECINTO_HOME of the fake home leaked out of the test")
	}
}

func TestProtect(t *testing.T) {
	h := testkit.NewHome(t)
	h.Clock.Advance(time.Hour)
	r := h.Protect(t, "work/beta")
	if r.ID != "root-beta" || r.Path != filepath.Join(h.HomeDir, "work", "beta") || !r.ProtectedAt.Equal(testkit.Epoch.Add(time.Hour)) {
		t.Errorf("Protect = %+v", r)
	}
	if fi, err := os.Stat(r.Path); err != nil || !fi.IsDir() || fi.Mode().Perm() != 0o700 {
		t.Errorf("%s: %v %v", r.Path, fi, err)
	}
	r2 := h.Protect(t, "clients/Beta Two")
	r3 := h.Protect(t, "other/beta")
	if r2.ID != "root-beta-two" || r3.ID != "root-beta-2" {
		t.Errorf("ids %q %q", r2.ID, r3.ID)
	}
	nested := h.Protect(t, "work/acme/inner")
	if got, ok := h.Cfg.RootFor(filepath.Join(nested.Path, "x")); !ok || got.ID != nested.ID {
		t.Errorf("nested root not the deepest: %+v", got)
	}
	disk, err := config.Load(h.Layout.ConfigFile)
	if err != nil || len(disk.Roots) != 5 || len(config.Diff(h.Cfg, disk)) != 0 {
		t.Fatalf("config.toml after Protect: %d roots, %v", len(disk.Roots), err)
	}
	roots, err := config.ReadRootsList(h.Layout.RootsList)
	if err != nil || len(roots) != 5 || !slices.Contains(roots, r.Path) {
		t.Errorf("roots.list = %q %v", roots, err)
	}
	for _, bad := range []string{"", "/abs", "../outside", "work/../x", "work/", "./work"} {
		mustFatal(t, "testkit.Protect", func(tb testing.TB) { h.Protect(tb, bad) })
	}
	mustFatal(t, "already protected", func(tb testing.TB) { h.Protect(tb, "work/acme") })
	if err := os.Symlink(h.Root, filepath.Join(h.HomeDir, "link")); err != nil {
		t.Fatal(err)
	}
	mustFatal(t, "symlink", func(tb testing.TB) { h.Protect(tb, "link") })
}

func TestShortTempDir(t *testing.T) {
	var d string
	t.Run("dir", func(t *testing.T) {
		d = testkit.ShortTempDir(t)
		if len(d) > 40 || !filepath.IsAbs(d) {
			t.Errorf("ShortTempDir = %q", d)
		}
		if real, err := filepath.EvalSymlinks(d); err != nil || real != d {
			t.Errorf("%s is not resolved: %q %v", d, real, err)
		}
		if fi, err := os.Stat(d); err != nil || fi.Mode().Perm() != 0o700 {
			t.Errorf("%s: %v %v", d, fi, err)
		}
		if d2 := testkit.ShortTempDir(t); d2 == d {
			t.Error("ShortTempDir returned the same directory twice")
		}
		// A socket fits below it.
		ln, err := net.Listen("unix", filepath.Join(d, "agent.sock"))
		if err != nil {
			t.Fatalf("listen below %s: %v", d, err)
		}
		ln.Close()
		if err := os.Chmod(d, 0o500); err != nil {
			t.Fatal(err)
		}
	})
	if _, err := os.Lstat(d); !os.IsNotExist(err) {
		t.Errorf("%s not removed: %v", d, err)
	}
}
