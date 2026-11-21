package testkit

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/precinto/precinto/internal/config"
	"github.com/precinto/precinto/internal/paths"
	"github.com/precinto/precinto/internal/platform"
	"github.com/precinto/precinto/internal/platform/fakeplatform"
)

// startEnv is the process environment when the package was initialised,
// before any test could replace it (Home.Setenv): BuildBinary needs the real
// Go configuration and Hygiene the real HOME. It is read through paths, the
// only package that reads the environment.
var startEnv = paths.FromOS()

// rootID is the id of the protected root every fake home starts with.
const rootID = "root-acme"

// systemPath is the PATH of every fake home: system directories only, so a
// child never finds a real installed precinto, harness or tool through the
// user's own PATH (the shim's lookup order, HOOKS-IO §5).
const systemPath = "/usr/bin:/bin:/usr/sbin:/sbin"

// Variables Setenv removes from the test process (besides every agent
// marker the process carries) unless the fake home sets them: they would
// point the code under test at the developer's real data or arm behaviour
// the test did not ask for.
var neutralisedVars = []string{
	paths.EnvCodexSQLiteHome,
	paths.EnvClaudeProjectName,
	paths.EnvDev,
	paths.EnvCrashpoint,
}

// newHome implements NewHome (docs/TESTPLAN.md §2):
//
//	<Dir>/home                  HOME; work/acme is the root "root-acme"
//	<Dir>/base                  PRECINTO_HOME (Layout.EnsureDirs applied)
//	<Dir>/claude, claude-tmp    CLAUDE_CONFIG_DIR, CLAUDE_CODE_TMPDIR
//	<Dir>/codex-user            CODEX_HOME (the user's, never ~/.codex)
//	<Dir>/xdg/{data,state,cache,config}  XDG_*_HOME
//	<Dir>/tmp                   TMPDIR
//	/tmp/pt-…                   PRECINTO_RUNTIME_DIR (ShortTempDir), and
//	/tmp/pt-…/xdg               XDG_RUNTIME_DIR
//
// The Claude cache (claude-cli-nodejs) lives where Claude puts it for this
// HOME: HOME/Library/Caches on darwin, $XDG_CACHE_HOME on linux. Every path
// is symlink-free (the temp dirs are resolved, /var and /tmp are symlinks on
// darwin) and every directory has mode 0700. Env is built from scratch, so
// nothing in it refers to the real HOME.
func newHome(t testing.TB) *Home {
	t.Helper()
	dir := realTempDir(t)
	h := &Home{
		Dir:          dir,
		HomeDir:      filepath.Join(dir, "home"),
		Base:         filepath.Join(dir, "base"),
		ClaudeConfig: filepath.Join(dir, "claude"),
		ClaudeTmp:    filepath.Join(dir, "claude-tmp"),
		CodexUser:    filepath.Join(dir, "codex-user"),
		RunDir:       ShortTempDir(t),
	}
	h.Root = filepath.Join(h.HomeDir, "work", "acme")
	xdg := func(kind string) string { return filepath.Join(dir, "xdg", kind) }
	if runtime.GOOS == "linux" {
		h.ClaudeCache = filepath.Join(xdg("cache"), "claude-cli-nodejs")
	} else {
		h.ClaudeCache = filepath.Join(h.HomeDir, "Library", "Caches", "claude-cli-nodejs")
	}
	tmp := filepath.Join(dir, "tmp")
	xdgRuntime := filepath.Join(h.RunDir, "xdg")

	// Removal of a tree a test left read-only must not fail the test:
	// registered after t.TempDir's own cleanup, so it runs first.
	t.Cleanup(func() { makeRemovable(dir) })
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("testkit.NewHome: %v", err)
	}
	for _, d := range []string{h.HomeDir, h.Root, h.Base, h.ClaudeConfig, h.ClaudeTmp, h.ClaudeCache,
		h.CodexUser, xdg("data"), xdg("state"), xdg("cache"), xdg("config"), tmp} {
		mkdirTree(t, dir, d)
	}
	mkdirTree(t, h.RunDir, xdgRuntime)

	h.Env = paths.FromMap(map[string]string{
		"HOME":                   h.HomeDir,
		"PATH":                   systemPath,
		"TMPDIR":                 tmp,
		paths.EnvHome:            h.Base,
		paths.EnvRuntimeDir:      h.RunDir,
		paths.EnvClaudeConfigDir: h.ClaudeConfig,
		paths.EnvClaudeTmpDir:    h.ClaudeTmp,
		paths.EnvCodexHome:       h.CodexUser,
		paths.EnvXDGDataHome:     xdg("data"),
		"XDG_STATE_HOME":         xdg("state"),
		"XDG_CACHE_HOME":         xdg("cache"),
		"XDG_CONFIG_HOME":        xdg("config"),
		paths.EnvXDGRuntimeDir:   xdgRuntime,
		// D64: a -tags testing binary run by this test ends its harness
		// ancestry walk at the test process, so suites started from inside
		// an agent session still exercise the human paths below it.
		paths.EnvTestAncestryStop: platform.Self().String(),
	})
	l, err := paths.LayoutAt(h.Base, h.RunDir)
	if err != nil {
		t.Fatalf("testkit.NewHome: %v", err)
	}
	h.Layout = l
	if err := l.EnsureDirs(); err != nil {
		t.Fatalf("testkit.NewHome: %v", err)
	}

	h.Cfg = config.Default()
	h.Cfg.Roots = []config.Root{newRoot(rootID, h.Root, Epoch)}
	cc := h.Cfg.Harness["claude-code"]
	cc.Homes = []config.Home{{Dir: h.ClaudeConfig, Tmp: h.ClaudeTmp, Cache: h.ClaudeCache, SeenAt: Epoch}}
	h.Cfg.Harness["claude-code"] = cc
	h.save(t)

	h.Clock = fakeplatform.NewClock(Epoch)
	h.Procs = fakeplatform.NewProcs()
	return h
}

// newRoot is a root as `precinto protect` records it.
func newRoot(id, path string, at time.Time) config.Root {
	return config.Root{
		ID: id, Path: path, MD: config.MDLedger,
		Harnesses: []string{"claude-code", "codex"}, ProtectedAt: at.UTC(),
	}
}

// save writes config.toml and roots.list (what `precinto protect` writes).
func (h *Home) save(t testing.TB) {
	t.Helper()
	if err := config.Save(h.Layout.ConfigFile, h.Cfg); err != nil {
		t.Fatalf("testkit: write config.toml: %v", err)
	}
	if err := config.WriteRootsList(h.Layout.RootsList, h.Cfg); err != nil {
		t.Fatalf("testkit: write roots.list: %v", err)
	}
}

// setenv implements Home.Setenv. Besides every variable of h.Env it removes,
// for the duration of the test, the agent markers of the test process (the
// suite may run inside Claude Code or Codex, whose markers would turn every
// command into an agent context) and the variables of neutralisedVars, so
// a test sets the variables it needs (a marker, PRECINTO_CRASHPOINT) after
// calling Setenv. t.Setenv records each previous value and restores it at
// cleanup (and refuses parallel tests, whose environment is shared).
func (h *Home) setenv(t testing.TB) {
	t.Helper()
	for _, kv := range h.Env.Environ() {
		k, v, _ := strings.Cut(kv, "=")
		t.Setenv(k, v)
	}
	cur := paths.FromOS()
	drop := append(paths.AgentMarkers(cur), neutralisedVars...)
	for _, k := range drop {
		if _, set := cur.Lookup(k); !set {
			continue
		}
		if _, ours := h.Env.Lookup(k); ours {
			continue
		}
		t.Setenv(k, "")
		if err := os.Unsetenv(k); err != nil {
			t.Fatalf("testkit.Setenv: unset %s: %v", k, err)
		}
	}
}

// protect implements Home.Protect: rel is a clean path relative to HomeDir;
// the folder is created (0700) and protected under a readable, unique id
// ("root-<name>", "root-<name>-2", …) with ProtectedAt from h.Clock.
func (h *Home) protect(t testing.TB, rel string) config.Root {
	t.Helper()
	if rel == "" || filepath.IsAbs(rel) || !filepath.IsLocal(rel) || filepath.Clean(rel) != rel {
		t.Fatalf("testkit.Protect(%q): want a clean path relative to the fake HOME", rel)
	}
	p := filepath.Join(h.HomeDir, rel)
	mkdirTree(t, h.HomeDir, p)
	if real, err := filepath.EvalSymlinks(p); err != nil || real != p {
		t.Fatalf("testkit.Protect(%q): %s is not a symlink-free directory (%v)", rel, p, err)
	}
	for _, r := range h.Cfg.Roots {
		if r.Path == p {
			t.Fatalf("testkit.Protect(%q): already protected as %s", rel, r.ID)
		}
	}
	at := Epoch
	if h.Clock != nil {
		at = h.Clock.Now()
	}
	r := newRoot(h.freeID(filepath.Base(p)), p, at)
	h.Cfg.Roots = append(h.Cfg.Roots, r)
	h.save(t)
	return r
}

// freeID derives a root id from a folder name that no root uses yet.
func (h *Home) freeID(name string) string {
	var b strings.Builder
	for _, c := range strings.ToLower(name) {
		if ('a' <= c && c <= 'z') || ('0' <= c && c <= '9') {
			b.WriteRune(c)
		} else {
			b.WriteByte('-')
		}
	}
	slug := strings.Trim(b.String(), "-")
	if slug == "" {
		slug = "folder"
	}
	id := "root-" + slug
	for n := 2; ; n++ {
		if _, taken := h.Cfg.RootByID(id); !taken {
			return id
		}
		id = "root-" + slug + "-" + strconv.Itoa(n)
	}
}

// shortTempDir implements ShortTempDir: a fresh 0700 directory /tmp/pt-…
// (resolved: /private/tmp/pt-… on darwin), removed when the test ends. If
// /tmp is unusable, a t.TempDir short enough for a socket is used instead.
func shortTempDir(t testing.TB) string {
	t.Helper()
	d, err := os.MkdirTemp("/tmp", "pt-")
	if err != nil {
		fallback := realTempDir(t)
		if len(filepath.Join(fallback, "agent.sock")) >= paths.MaxSocketPath {
			t.Fatalf("testkit.ShortTempDir: %v (and %s is too long for a socket)", err, fallback)
		}
		if err := os.Chmod(fallback, 0o700); err != nil {
			t.Fatalf("testkit.ShortTempDir: %v", err)
		}
		return fallback
	}
	t.Cleanup(func() {
		makeRemovable(d)
		if err := os.RemoveAll(d); err != nil {
			t.Errorf("testkit.ShortTempDir: cleanup: %v", err)
		}
	})
	real, err := filepath.EvalSymlinks(d)
	if err != nil {
		t.Fatalf("testkit.ShortTempDir: %v", err)
	}
	if n := len(filepath.Join(real, "agent.sock")); n >= paths.MaxSocketPath {
		t.Fatalf("testkit.ShortTempDir: %s leaves no room for a socket (%d bytes)", real, n)
	}
	return real
}

// realTempDir returns t.TempDir() without symlinked components.
func realTempDir(t testing.TB) string {
	t.Helper()
	d, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("testkit: %v", err)
	}
	return d
}

// mkdirTree creates dir and its missing parents below top, each with mode
// 0700 whatever the umask.
func mkdirTree(t testing.TB, top, dir string) {
	t.Helper()
	rel, err := filepath.Rel(top, dir)
	if err != nil || !filepath.IsLocal(rel) {
		t.Fatalf("testkit: %s is not below %s", dir, top)
	}
	cur := top
	for _, c := range strings.Split(rel, string(filepath.Separator)) {
		if c == "." {
			continue
		}
		cur = filepath.Join(cur, c)
		err := os.Mkdir(cur, 0o700)
		if errors.Is(err, fs.ErrExist) {
			continue
		}
		if err == nil {
			err = os.Chmod(cur, 0o700)
		}
		if err != nil {
			t.Fatalf("testkit: %v", err)
		}
	}
}

// makeRemovable gives the owner rwx on every directory below root (tests of
// EACCES leave read-only trees behind), so that RemoveAll can succeed.
func makeRemovable(root string) {
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err == nil && d.IsDir() {
			_ = os.Chmod(p, 0o700)
		}
		return nil
	})
}
