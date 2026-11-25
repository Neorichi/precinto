package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Neorichi/precinto/internal/fsx"
	"github.com/Neorichi/precinto/internal/harness"
)

// integrate claude-code: version check (≥ 2.1.295, D22), <base>/bin/precinto
// link (D6), home and binary registered, plugin installed through the
// harness's own plugin CLI — all in the fake HOME, the harness CLI faked.
func TestIntegrateClaude(t *testing.T) {
	e := newEnv(t)
	bin := fakePluginDir(t, e, "claude")
	exe := filepath.Join(e.h.Dir, "precinto-bin")
	if err := os.WriteFile(exe, []byte("x"), 0o700); err != nil {
		t.Fatal(err)
	}
	e.execOut["--version"] = []byte("2.1.329 (Claude Code)\n")
	a := e.app()
	a.sys.executable = func() (string, error) { return exe, nil }
	if code := a.run([]string{"integrate", "claude-code"}); code != exitOK {
		t.Fatalf("exit %d (%s)", code, e.stderr())
	}
	var argv []string
	for _, x := range e.execs {
		argv = append(argv, strings.Join(x.Argv[1:], " "))
		for _, kv := range x.Env {
			if strings.HasPrefix(kv, "PRECINTO_") {
				t.Fatalf("harness CLI got %s", kv)
			}
		}
	}
	// D116: the marketplace is precinto's own folder, written from the
	// binary, never a network name.
	want := "--version|plugin marketplace add " + e.h.Layout.Marketplace + "|plugin install precinto@precinto"
	if strings.Join(argv, "|") != want {
		t.Fatalf("commands %q, want %q", strings.Join(argv, "|"), want)
	}
	link, err := os.Readlink(e.h.Layout.BinLink)
	if err != nil || link != exe {
		t.Fatalf("bin link %q %v", link, err)
	}
	c := e.loadConfig()
	if c.Harness["claude-code"].Bin != filepath.Join(bin, "claude") {
		t.Fatalf("bin %q", c.Harness["claude-code"].Bin)
	}
}

func TestIntegrateRefusesOldClaude(t *testing.T) {
	e := newEnv(t)
	fakePluginDir(t, e, "claude")
	e.execOut["--version"] = []byte("2.1.200 (Claude Code)\n")
	if code := e.run("integrate", "claude-code"); code != exitError {
		t.Fatalf("exit %d", code)
	}
	if len(e.execs) != 1 {
		t.Fatal("installed into an old Claude")
	}
	// UX-18: the refusal names the command that updates the harness.
	if !strings.Contains(e.stderr(), "claude 2.1.200 is older than 2.1.295") || !strings.Contains(e.stderr(), "claude update") {
		t.Fatalf("stderr %q does not name claude update", e.stderr())
	}
	if _, err := os.Lstat(e.h.Layout.BinLink); !os.IsNotExist(err) {
		t.Fatal("bin link written for a refused integration")
	}
	// An unreadable version refuses too (fail closed).
	e = newEnv(t)
	fakePluginDir(t, e, "claude")
	e.execOut["--version"] = []byte("dev build\n")
	if code := e.run("integrate", "claude-code"); code != exitError {
		t.Fatalf("unreadable version: exit %d", code)
	}
}

// --print changes nothing.
func TestIntegratePrint(t *testing.T) {
	e := newEnv(t)
	fakePluginDir(t, e, "codex")
	e.execOut["--version"] = []byte("codex-cli 0.154.0\n")
	if code := e.run("integrate", "codex", "--print"); code != exitOK {
		t.Fatalf("exit %d (%s)", code, e.stderr())
	}
	// D94: Codex 0.154's plugin CLI installs with `add` (no `install`).
	if !strings.Contains(e.stdout(), "plugin add precinto@precinto") || strings.Contains(e.stdout(), "plugin install") || len(e.execs) != 1 {
		t.Fatalf("stdout %q execs %d", e.stdout(), len(e.execs))
	}
	if _, err := os.Lstat(e.h.Layout.BinLink); !os.IsNotExist(err) {
		t.Fatal("--print wrote the bin link")
	}
	// D116: it names the local marketplace integrate would write, and
	// writes nothing.
	if !strings.Contains(e.stdout(), " plugin marketplace add "+shellWord(e.h.Layout.Marketplace)+"\n") || strings.Contains(e.stdout(), "precinto/precinto") {
		t.Fatalf("stdout %q", e.stdout())
	}
	if _, err := os.Lstat(e.h.Layout.Marketplace); !os.IsNotExist(err) {
		t.Fatal("--print wrote the marketplace")
	}
	if !strings.Contains(e.stderr(), "--print changed nothing") || !strings.Contains(e.stderr(), "which need that folder") {
		t.Fatalf("stderr %q", e.stderr())
	}
}

// Experimental harnesses and hosts need --experimental (D33).
func TestIntegrateExperimental(t *testing.T) {
	e := newEnv(t)
	e.eng.invs[harness.ID("gemini")] = harness.Inventory{ID: "gemini", Status: "experimental"}
	if code := e.run("integrate", "gemini"); code != exitUsage {
		t.Fatalf("exit %d", code)
	}
	if code := e.run("integrate", "gemini", "--experimental"); code != exitOK {
		t.Fatalf("exit %d (%s)", code, e.stderr())
	}
	if h := e.loadConfig().Harness["gemini"]; !h.Enabled || !h.Experimental {
		t.Fatalf("gemini %+v", h)
	}
	e = newEnv(t)
	if code := e.run("integrate", "cursor"); code != exitUsage {
		t.Fatalf("cursor: exit %d", code)
	}
	if code := e.run("integrate", "cursor", "--experimental"); code != exitOK || !strings.Contains(e.stdout(), "experimental") {
		t.Fatalf("cursor: exit %d %q", code, e.stdout())
	}
	if code := e.run("integrate", "nosuch", "--experimental"); code != exitUsage {
		t.Fatalf("unknown: exit %d", code)
	}
}

func TestVersionCompare(t *testing.T) {
	cases := []struct {
		a, b string
		less bool
	}{
		{"2.1.294", "2.1.295", true}, {"2.1.295", "2.1.295", false}, {"2.1.329", "2.1.295", false},
		{"0.154.0", "0.154.0", false}, {"0.153.9", "0.154.0", true}, {"x", "1.0.0", true}, {"10.0.0", "9.9.9", false},
	}
	for _, c := range cases {
		if got := versionLess(c.a, c.b); got != c.less {
			t.Errorf("versionLess(%s, %s) = %v", c.a, c.b, got)
		}
	}
}

// UX-04, D116: integrate installs precinto's plugin from bytes the binary
// carries: it writes them, exactly the embedded tree, to <base>/marketplace
// and adds that absolute local folder as the marketplace, for Claude Code
// and Codex alike. The Codex plugin root it writes is byte-identical to the
// recorded list (D78). The tree is byte-stable: a second integrate leaves
// it untouched, and a changed or extra file is replaced by the embedded
// tree.
func TestIntegrateUsesTheEmbeddedMarketplace(t *testing.T) {
	e := newEnv(t)
	fakePluginDir(t, e, "claude")
	e.execOut["--version"] = []byte("2.1.329 (Claude Code)\n")
	if code := e.integrate("claude-code"); code != exitOK {
		t.Fatalf("exit %d (%s)", code, e.stderr())
	}
	dir := e.execs[1].Argv[4]
	if strings.Join(e.execs[1].Argv[1:4], " ") != "plugin marketplace add" || !filepath.IsAbs(dir) || dir != e.h.Layout.Marketplace {
		t.Fatalf("marketplace argument %q", e.execs[1].Argv)
	}
	for _, m := range []string{".claude-plugin/marketplace.json", ".agents/plugins/marketplace.json"} {
		if st, err := os.Stat(filepath.Join(dir, m)); err != nil || !st.Mode().IsRegular() {
			t.Fatalf("%s: %v", m, err)
		}
	}
	checkTree(t, dir)
	codexHashes(t, filepath.Join(dir, "plugins", "codex"))

	before := treeStamps(t, dir)
	// A second integrate in the same base, for Codex, adds the same
	// folder and leaves every file as it was.
	fakePluginDir(t, e, "codex")
	e.execOut["--version"] = []byte("codex-cli 0.154.0\n")
	e.execs = nil
	if code := e.integrate("codex"); code != exitOK {
		t.Fatalf("codex: exit %d (%s)", code, e.stderr())
	}
	if got := strings.Join(e.execs[1].Argv[1:], " "); got != "plugin marketplace add "+dir {
		t.Fatalf("codex marketplace command %q", got)
	}
	if got := strings.Join(e.execs[2].Argv[1:], " "); got != "plugin add precinto@precinto" {
		t.Fatalf("codex plugin command %q", got)
	}
	if after := treeStamps(t, dir); after != before {
		t.Fatalf("a second integrate rewrote the marketplace:\n%s\n%s", before, after)
	}
	// A changed file and an extra file are replaced by the embedded tree.
	hook := filepath.Join(dir, "plugins", "codex", "hooks", "codex.json")
	if err := os.WriteFile(hook, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "plugins", "codex", "extra.txt"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	e.execs = nil
	if code := e.integrate("codex"); code != exitOK {
		t.Fatalf("repair: exit %d (%s)", code, e.stderr())
	}
	checkTree(t, dir)
	codexHashes(t, filepath.Join(dir, "plugins", "codex"))
	es, err := os.ReadDir(e.h.Layout.Base)
	if err != nil {
		t.Fatal(err)
	}
	for _, x := range es {
		if strings.HasPrefix(x.Name(), ".marketplace") {
			t.Errorf("left %s in the base", x.Name())
		}
	}
}

// integrate runs `precinto integrate args…` with this binary's path an
// existing file of the fake HOME (the link integrate writes resolves it).
func (e *env) integrate(args ...string) int {
	e.t.Helper()
	exe := filepath.Join(e.h.Dir, "precinto-bin")
	if _, err := os.Stat(exe); err != nil {
		if err := os.WriteFile(exe, []byte("x"), 0o700); err != nil {
			e.t.Fatal(err)
		}
	}
	a := e.app()
	a.sys.executable = func() (string, error) { return exe, nil }
	return a.run(append([]string{"integrate"}, args...))
}

// checkTree requires dir to hold exactly the embedded plugin files, with
// their bytes.
func checkTree(t *testing.T, dir string) {
	t.Helper()
	want, err := embeddedPlugins()
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	err = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		b, ok := want[filepath.ToSlash(rel)]
		got, rerr := os.ReadFile(p)
		if !ok || rerr != nil || !bytes.Equal(got, b) {
			t.Errorf("%s is not the embedded file", rel)
		}
		n++
		return nil
	})
	if err != nil || n != len(want) {
		t.Fatalf("%d files (want %d): %v", n, len(want), err)
	}
}

// codexHashes requires the Codex plugin root to match the SHA-256 list of
// D78, the same one the repository's plugins/codex is checked against.
func codexHashes(t *testing.T, root string) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "test", "integration", "testdata", "codex-plugin.sha256"))
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, line := range strings.Split(string(b), "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		sum, rel, ok := strings.Cut(line, "  ")
		if !ok {
			t.Fatalf("bad line %q", line)
		}
		data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
		if err != nil {
			t.Fatal(err)
		}
		if h := sha256.Sum256(data); hex.EncodeToString(h[:]) != sum {
			t.Errorf("%s: the written Codex plugin differs from the recorded hash", rel)
		}
		n++
	}
	es := 0
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			es++
		}
		return err
	})
	if n == 0 || es != n {
		t.Fatalf("the Codex plugin root holds %d files, the list %d", es, n)
	}
}

// treeStamps renders the inode, size and mtime of every entry of dir.
func treeStamps(t *testing.T, dir string) string {
	t.Helper()
	var b strings.Builder
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		st, err := os.Lstat(p)
		if err != nil {
			return err
		}
		fmt.Fprintf(&b, "%s %d %d %v\n", p, inodeOf(p), st.Size(), st.ModTime().UnixNano())
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return b.String()
}

func inodeOf(p string) uint64 {
	if st, err := fsx.Lstat(p); err == nil {
		return st.Ino
	}
	return 0
}

// UX-04: a plugin command that fails changes nothing of precinto's own
// settings: config.toml keeps its bytes, the binary link is not written,
// and the message names what failed, says nothing was changed and prints
// the commands it runs, ready to paste.
func TestIntegrateFailureChangesNothing(t *testing.T) {
	for _, id := range []string{"claude-code", "codex"} {
		e := newEnv(t)
		exe := "claude"
		version := "2.1.329 (Claude Code)\n"
		if id == "codex" {
			exe, version = "codex", "codex-cli 0.154.0\n"
		}
		bin := fakePluginDir(t, e, exe)
		e.execOut["--version"] = []byte(version)
		e.execErr["plugin"] = errors.New("exit status 1")
		before, err := os.ReadFile(e.h.Layout.ConfigFile)
		if err != nil {
			t.Fatal(err)
		}
		if code := e.integrate(id); code != exitError {
			t.Fatalf("%s: exit %d (%s)", id, code, e.stderr())
		}
		if after, _ := os.ReadFile(e.h.Layout.ConfigFile); !bytes.Equal(before, after) {
			t.Errorf("%s: config.toml changed:\n%s\n%s", id, before, after)
		}
		if _, err := os.Lstat(e.h.Layout.BinLink); !os.IsNotExist(err) {
			t.Errorf("%s: the binary link was written for a failed integration", id)
		}
		if len(e.execs) != 2 {
			t.Errorf("%s: ran %d commands after the failed one", id, len(e.execs)-2)
		}
		out := e.stderr()
		for _, w := range []string{exe + " plugin marketplace add failed,", "precinto's settings were not changed", "precinto integrate " + id + " again"} {
			if !strings.Contains(out, w) {
				t.Errorf("%s: stderr %q lacks %q", id, out, w)
			}
		}
		// The commands are whole lines a user can paste: two spaces, the
		// command, nothing else (no "precinto:" prefix).
		verb := "install"
		if id == "codex" {
			verb = "add"
		}
		for _, c := range [][]string{
			{filepath.Join(bin, exe), "plugin", "marketplace", "add", e.h.Layout.Marketplace},
			{filepath.Join(bin, exe), "plugin", verb, "precinto@precinto"},
		} {
			if line := "\n  " + shellJoin(c) + "\n"; !strings.Contains(out, line) {
				t.Errorf("%s: stderr %q lacks the line %q", id, out, line)
			}
		}
		if strings.Contains(out, "precinto:   ") {
			t.Errorf("%s: a command line carries the precinto: prefix: %q", id, out)
		}
		if _, err := os.Stat(filepath.Join(e.h.Layout.Marketplace, ".claude-plugin", "marketplace.json")); err != nil {
			t.Errorf("%s: the printed commands name a marketplace folder that was not written: %v", id, err)
		}
	}
}

// UX-03: on a first run the plugin commands create the Claude home, so
// integrate resolves and registers it after them; a session sealed from
// it later is then restorable.
func TestIntegrateRegistersTheClaudeHomeThePluginCreated(t *testing.T) {
	e := newEnv(t)
	c := e.loadConfig()
	cc := c.Harness["claude-code"]
	cc.Homes = nil
	c.Harness["claude-code"] = cc
	e.saveConfig(c)
	if err := os.RemoveAll(e.h.ClaudeConfig); err != nil {
		t.Fatal(err)
	}
	fakePluginDir(t, e, "claude")
	e.execOut["--version"] = []byte("2.1.329 (Claude Code)\n")
	a := e.app()
	inner := a.sys.exec
	a.sys.exec = func(ctx context.Context, x execSpec) ([]byte, error) {
		if len(x.Argv) > 1 && x.Argv[1] == "plugin" {
			if err := os.MkdirAll(e.h.ClaudeConfig, 0o700); err != nil {
				return nil, err
			}
		}
		return inner(ctx, x)
	}
	exe := filepath.Join(e.h.Dir, "precinto-bin")
	if err := os.WriteFile(exe, []byte("x"), 0o700); err != nil {
		t.Fatal(err)
	}
	a.sys.executable = func() (string, error) { return exe, nil }
	if code := a.run([]string{"integrate", "claude-code"}); code != exitOK {
		t.Fatalf("exit %d (%s)", code, e.stderr())
	}
	homes := e.loadConfig().Harness["claude-code"].Homes
	want, _ := filepath.EvalSymlinks(e.h.ClaudeConfig)
	if len(homes) != 1 || homes[0].Dir != want {
		t.Fatalf("homes %+v, want %s registered", homes, want)
	}
}

// The commands integrate prints and suggests can be pasted into a shell:
// a word with a space (macOS: Application Support) is quoted.
func TestShellJoin(t *testing.T) {
	for argv, want := range map[string]string{
		"/usr/bin/claude|plugin|install|precinto@precinto":                                             "/usr/bin/claude plugin install precinto@precinto",
		"/opt/claude|plugin|marketplace|add|/Users/u/Library/Application Support/precinto/marketplace": "/opt/claude plugin marketplace add '/Users/u/Library/Application Support/precinto/marketplace'",
		"x|it's":  `x 'it'\''s'`,
		"x|":      "x ''",
		"x|$(rm)": "x '$(rm)'",
	} {
		if got := shellJoin(strings.Split(argv, "|")); got != want {
			t.Errorf("shellJoin(%q) = %q, want %q", argv, got, want)
		}
	}
}

// D148 (S6-7, D6-4): Claude Code loads precinto's plugin in place from
// <base>/marketplace, so no integrate leaves it without one. An integrate
// stopped between the two renames of a swap (a crash, a power loss) left
// the working tree only under its hidden name; the next integrate puts it
// back first, even when that integrate fails too, and a later successful
// one leaves no hidden tree behind.
func TestIntegrateRestoresAMarketplaceAnInterruptedSwapLeftHidden(t *testing.T) {
	e := newEnv(t)
	fakePluginDir(t, e, "claude")
	e.execOut["--version"] = []byte("2.1.329 (Claude Code)\n")
	if code := e.integrate("claude-code"); code != exitOK {
		t.Fatalf("exit %d (%s)", code, e.stderr())
	}
	dir := e.h.Layout.Marketplace
	hidden := filepath.Join(e.h.Layout.Base, ".marketplace.old-0123456789ab")
	if err := os.Rename(dir, hidden); err != nil { // the crash between the renames
		t.Fatal(err)
	}
	e.execErr["plugin"] = errors.New("exit status 1")
	e.execs = nil
	if code := e.integrate("claude-code"); code != exitError {
		t.Fatalf("a failing plugin command: exit %d (%s)", code, e.stderr())
	}
	checkTree(t, dir) // the working tree is back, byte for byte
	delete(e.execErr, "plugin")
	e.execs = nil
	if code := e.integrate("claude-code"); code != exitOK {
		t.Fatalf("exit %d (%s)", code, e.stderr())
	}
	checkTree(t, dir)
	es, err := os.ReadDir(e.h.Layout.Base)
	if err != nil {
		t.Fatal(err)
	}
	for _, x := range es {
		if strings.HasPrefix(x.Name(), ".marketplace") {
			t.Errorf("left %s in the base", x.Name())
		}
	}
}

// D148: one integrate replaces the marketplace at a time (state/locks/
// marketplace.lock), so the hidden trees found at its start are an
// interrupted integrate's: a half-built ".marketplace.new-*" tree is
// removed, whether the live tree is replaced or already matches. While
// another process holds the lock, integrate waits, then says so and
// changes nothing.
func TestIntegrateRemovesHalfBuiltTreesUnderItsLock(t *testing.T) {
	e := newEnv(t)
	fakePluginDir(t, e, "claude")
	e.execOut["--version"] = []byte("2.1.329 (Claude Code)\n")
	halfBuilt := func() string {
		t.Helper()
		p := filepath.Join(e.h.Layout.Base, ".marketplace.new-0123456789ab")
		if err := os.MkdirAll(filepath.Join(p, "plugin"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(p, "plugin", "partial"), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	if err := os.MkdirAll(e.h.Layout.Base, 0o700); err != nil {
		t.Fatal(err)
	}
	p := halfBuilt()
	if code := e.integrate("claude-code"); code != exitOK {
		t.Fatalf("exit %d (%s)", code, e.stderr())
	}
	if fileExists(p) {
		t.Fatal("a half-built tree is left next to a new marketplace")
	}
	checkTree(t, e.h.Layout.Marketplace)
	p = halfBuilt()
	e.execs = nil
	if code := e.integrate("claude-code"); code != exitOK {
		t.Fatalf("exit %d (%s)", code, e.stderr())
	}
	if fileExists(p) {
		t.Fatal("a half-built tree is left next to a marketplace that already matched")
	}

	// Another integrate holds the lock.
	defer func(d time.Duration) { marketplaceLockWait = d }(marketplaceLockWait)
	marketplaceLockWait = 50 * time.Millisecond
	lk, err := fsx.WaitLock(context.Background(), e.h.Layout.LockFile("marketplace"), false)
	if err != nil {
		t.Fatal(err)
	}
	defer lk.Unlock()
	p = halfBuilt()
	e.execs, e.err = nil, bytes.Buffer{}
	if code := e.integrate("claude-code"); code != exitError {
		t.Fatalf("with the lock held: exit %d (%s)", code, e.stderr())
	}
	if !strings.Contains(e.stderr(), "another precinto integrate is replacing the plugin folder; try again") || !fileExists(p) {
		t.Fatalf("with the lock held: stderr %q, half-built tree kept %v", e.stderr(), fileExists(p))
	}
	checkTree(t, e.h.Layout.Marketplace)
}
