package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/precinto/precinto"
	"github.com/precinto/precinto/internal/config"
	"github.com/precinto/precinto/internal/fsx"
	"github.com/precinto/precinto/internal/harness"
	"github.com/precinto/precinto/internal/paths"
)

// pluginRef is precinto's plugin in its marketplace, both named
// "precinto" (SPEC §21). The marketplace is <base>/marketplace, written
// from the binary (precinto.Plugins): .claude-plugin/marketplace.json for
// Claude Code, .agents/plugins/marketplace.json for Codex (D116).
const pluginRef = paths.ClaudePluginID

// Hosts that load precinto's shared plugin directory but are experimental
// (HOOKS-IO §4): integrate only prints what they cannot gate.
var experimentalHosts = map[string]string{
	"cursor":  "Cursor can't block a prompt reliably and fails open unless failClosed is set; install the plugin from plugin/.cursor-plugin.",
	"copilot": "Copilot can't block prompts (only tools); run it through precinto run so the lock screen covers it.",
	"droid":   "Droid loads the Claude plugin (claude plugin install " + pluginRef + " in Droid); tool names differ, so test the gate first.",
}

var versionRE = regexp.MustCompile(`\b(\d+)\.(\d+)\.(\d+)\b`)

func cmdIntegrate(a *app, args []string) int {
	f := newFlags("integrate")
	printOnly := f.Bool("print", false, "print the commands instead of running them (changes nothing)")
	experimental := f.Bool("experimental", false, "allow experimental harnesses and hosts")
	pos, err := f.parse(args)
	if code, ok := a.handleParse(f, err); !ok {
		return code
	}
	if len(pos) != 1 {
		return a.usageFail(f, "integrate needs one harness (claude-code, codex, or an experimental one)")
	}
	h := pos[0]
	switch h {
	case "claude", string(harness.ClaudeCode):
		return a.integrateBuiltin(harness.ClaudeCode, "claude", *printOnly)
	case string(harness.Codex):
		return a.integrateBuiltin(harness.Codex, "codex", *printOnly)
	}
	if note, ok := experimentalHosts[h]; ok {
		if !*experimental {
			a.say(textNeedExp, h)
			return exitUsage
		}
		a.sayOut(textIntegrateHost, h, note)
		return exitOK
	}
	return a.integrateGeneric(h, *experimental, *printOnly)
}

// integrateBuiltin checks the harness version, links <base>/bin/precinto
// to this binary (the shim's first choice, D6), registers the harness home
// and installs precinto's plugin through the harness's own plugin CLI. It
// never writes Codex trust hashes: the user trusts the hooks in Codex.
func (a *app) integrateBuiltin(id harness.ID, exeName string, printOnly bool) int {
	cfg, err := a.config()
	if err != nil {
		return a.fail("integrate", err)
	}
	hc := cfg.Harness[string(id)]
	bin := hc.Bin
	if bin == "" {
		bin, err = paths.LookPath(a.env, exeName)
		if err != nil {
			a.say(textNoHarnessBin, exeName)
			return exitError
		}
	}
	ctx := context.Background()
	min := hc.MinVersion
	if min == "" {
		min = config.Default().Harness[string(id)].MinVersion
	}
	out, err := a.sys.exec(ctx, execSpec{Argv: []string{bin, "--version"}, Env: harnessEnv(a.env), Timeout: 30 * time.Second})
	if err != nil {
		return a.fail("integrate", fmt.Errorf("%s --version failed", exeName))
	}
	have, ok := parseVersion(string(out))
	if !ok {
		return a.fail("integrate", fmt.Errorf("could not read the %s version", exeName))
	}
	if versionLess(have, min) {
		a.say(textIntegrateOld, exeName, have, min, exeName)
		return exitError
	}
	l, err := a.layout()
	if err != nil {
		return a.fail("integrate", err)
	}
	// D116: the plugin comes from this binary, through a local marketplace
	// under precinto's own directory; no network marketplace is involved.
	cmds := [][]string{
		{bin, "plugin", "marketplace", "add", l.Marketplace},
		{bin, "plugin", pluginInstallVerb(id), pluginRef},
	}
	if printOnly {
		a.say(textIntegratePrint, string(id), a.display(l.Marketplace))
		for _, c := range cmds {
			fmt.Fprintln(a.out, shellJoin(c))
		}
		return exitOK
	}
	if _, err := a.writeMarketplace(); err != nil {
		return a.fail("integrate", err)
	}
	for _, c := range cmds {
		if _, err := a.sys.exec(ctx, execSpec{Argv: c, Env: harnessEnv(a.env), Stdout: a.out, Stderr: a.err, Timeout: 5 * time.Minute}); err != nil {
			// Nothing of precinto's own settings changed yet (UX-04): say
			// what failed and how to look at it.
			a.say(textIntegrateFailed, exeName+" "+strings.Join(c[1:len(c)-1], " "), string(id))
			for _, c := range cmds {
				// Ready to paste: no "precinto:" prefix on a command line.
				fmt.Fprintf(a.err, textIntegrateCmd+"\n", shellJoin(c))
			}
			return exitError
		}
	}
	// The plugin is installed: only now does precinto record the harness,
	// link its binary for the shim, and register the Claude home, which
	// the plugin commands create on a first run (UX-03).
	link, err := a.writeBinLink()
	if err != nil {
		return a.fail("integrate", err)
	}
	a.say(textIntegrateBin, a.display(link))
	next := cfg
	next.Harness = cloneHarness(cfg.Harness)
	nh := next.Harness[string(id)]
	nh.Enabled, nh.Bin = true, bin
	next.Harness[string(id)] = nh
	if id == harness.ClaudeCode {
		if home, ok := a.claudeHomeFromEnv(); ok {
			addHome(next.Harness, string(id), home)
		}
	}
	if err := a.saveConfig(next); err != nil {
		return a.fail("integrate", err)
	}
	a.say(textIntegrateDone, exeName)
	if id == harness.Codex {
		a.say(textCodexTrust)
	}
	return exitOK
}

// marketplaceMode is the mode a file of the written marketplace gets: the
// shims are executable (Cursor and Copilot may run them directly), every
// other file is private data. Directories are 0700.
func marketplaceMode(rel string) fs.FileMode {
	if path.Base(path.Dir(rel)) == "scripts" {
		return 0o700
	}
	return 0o600
}

// writeMarketplace makes <base>/marketplace hold exactly the embedded
// marketplace manifests and plugin roots (precinto.Plugins), byte for byte
// (D116), and returns its path. A tree that already matches is left alone,
// so the files stay byte-stable (newer Codex versions trust a plugin by
// its files, D78); otherwise a complete tree is built next to it and
// renamed into place, so that a harness never reads a partial one and no
// stray file ever sits inside a plugin root.
func (a *app) writeMarketplace() (string, error) {
	l, err := a.layout()
	if err != nil {
		return "", err
	}
	if err := l.EnsureDirs(); err != nil {
		return "", err
	}
	want, err := embeddedPlugins()
	if err != nil {
		return "", err
	}
	if sameTree(l.Marketplace, want) {
		return l.Marketplace, nil
	}
	base, err := fsx.OpenBase(l.Base)
	if err != nil {
		return "", err
	}
	defer base.Close()
	name := filepath.Base(l.Marketplace)
	tmp := "." + name + ".new-" + randomHex()
	tmpPath := filepath.Join(l.Base, tmp)
	built := false
	defer func() {
		if !built {
			removeTree(tmpPath)
		}
	}()
	for _, rel := range sortedKeys(want) {
		dir, file := path.Split(tmp + "/" + rel)
		f, _, err := base.CreateTemp(strings.TrimSuffix(dir, "/"), file)
		if err != nil {
			return "", err
		}
		_, werr := f.Write(want[rel])
		if werr == nil {
			werr = fsx.FullSync(f)
		}
		if cerr := f.Close(); werr == nil {
			werr = cerr
		}
		if werr != nil {
			return "", werr
		}
		if m := marketplaceMode(rel); m != 0o600 {
			if err := base.Chmod(tmp+"/"+rel, m); err != nil {
				return "", err
			}
		}
	}
	old := ""
	if _, err := base.Lstat(name); err == nil {
		old = "." + name + ".old-" + randomHex()
		if err := base.Rename(name, old, fsx.NoReplace); err != nil {
			return "", err
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return "", err
	}
	if err := base.Rename(tmp, name, fsx.NoReplace); err != nil {
		return "", err
	}
	built = true
	if err := base.Sync(); err != nil {
		return "", err
	}
	if old != "" {
		removeTree(filepath.Join(l.Base, old))
	}
	return l.Marketplace, nil
}

// embeddedPlugins returns every embedded file by its path.
func embeddedPlugins() (map[string][]byte, error) {
	out := map[string][]byte{}
	err := fs.WalkDir(precinto.Plugins, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := fs.ReadFile(precinto.Plugins, p)
		out[p] = b
		return err
	})
	return out, err
}

// sameTree reports whether dir holds exactly the files of want, with
// their bytes and marketplaceMode, and nothing else (no symlink, no other
// file, no extra directory).
func sameTree(dir string, want map[string][]byte) bool {
	d, err := fsx.OpenBase(dir)
	if err != nil {
		return false
	}
	defer d.Close()
	dirs := map[string]bool{}
	for rel := range want {
		for p := path.Dir(rel); p != "."; p = path.Dir(p) {
			dirs[p] = true
		}
	}
	seen := 0
	same := true
	err = d.Walk("", func(e fsx.WalkEntry) error {
		switch {
		case e.Hazard != "":
			same = false
		case e.Type == fsx.TypeDir:
			same = same && dirs[e.Rel] && e.Stat.Mode&0o777 == 0o700
		case e.Type == fsx.TypeRegular:
			b, ok := want[e.Rel]
			if !ok || e.Stat.Size != int64(len(b)) || fs.FileMode(e.Stat.Mode&0o777) != marketplaceMode(e.Rel) {
				same = false
				break
			}
			f, _, err := d.Open(e.Rel)
			if err != nil {
				same = false
				break
			}
			got, err := readBounded(f, int64(len(b))+1)
			f.Close()
			same = same && err == nil && bytes.Equal(got, b)
			seen++
		default:
			same = false
		}
		if !same {
			return fs.SkipAll
		}
		return nil
	})
	return err == nil && same && seen == len(want)
}

// removeTree deletes a private directory tree precinto wrote under its
// base (a staging or replaced marketplace); a failure leaves it for the
// next integrate.
func removeTree(p string) {
	if st, err := fsx.OpenStaging(p); err == nil {
		_ = st.Remove()
		st.Dir.Close()
	}
}

func randomHex() string {
	var rnd [6]byte
	_, _ = rand.Read(rnd[:])
	return hex.EncodeToString(rnd[:])
}

func sortedKeys(m map[string][]byte) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// shellJoin renders argv as one shell command line a user can paste: a
// word with anything but letters, digits and /._-+:,@%= is single-quoted
// (the marketplace path holds a space on macOS: Application Support).
func shellJoin(argv []string) string {
	out := make([]string, len(argv))
	for i, w := range argv {
		out[i] = shellWord(w)
	}
	return strings.Join(out, " ")
}

func shellWord(w string) string {
	if w != "" && strings.Trim(w, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/._-+:,@%=") == "" {
		return w
	}
	return "'" + strings.ReplaceAll(w, "'", `'\''`) + "'"
}

// integrateGeneric enables an experimental data-driven inventory
// (wrapper-only, D33).
func (a *app) integrateGeneric(id string, experimental, printOnly bool) int {
	ctx := context.Background()
	eng, err := a.engine(ctx, true)
	if err != nil {
		return a.fail("integrate", err)
	}
	inv, ok := eng.Inventory(harness.ID(id))
	if !ok {
		return a.fail("integrate", usageErrorf("unknown harness %q", id))
	}
	if inv.Status == "experimental" && !experimental {
		a.say(textNeedExp, id)
		return exitUsage
	}
	if printOnly {
		a.sayOut(textIntegrateExp, id, id)
		return exitOK
	}
	cfg, err := a.config()
	if err != nil {
		return a.fail("integrate", err)
	}
	next := cfg
	next.Harness = cloneHarness(cfg.Harness)
	nh := next.Harness[id]
	nh.Enabled, nh.Experimental = true, inv.Status == "experimental"
	next.Harness[id] = nh
	if err := a.saveConfig(next); err != nil {
		return a.fail("integrate", err)
	}
	a.sayOut(textIntegrateExp, id, id)
	return exitOK
}

// writeBinLink points <base>/bin/precinto at this binary (realpath),
// replacing an older link atomically. The shim runs it first (HOOKS-IO §5).
func (a *app) writeBinLink() (string, error) {
	l, err := a.layout()
	if err != nil {
		return "", err
	}
	if err := l.EnsureDirs(); err != nil {
		return "", err
	}
	exe, err := a.sys.executable()
	if err != nil {
		return "", err
	}
	target, err := filepath.EvalSymlinks(exe)
	if err != nil {
		return "", err
	}
	if st, err := fsx.Lstat(l.BinLink); err == nil && st.Mode&0o170000 != 0o120000 {
		return "", fmt.Errorf("%w: %s exists and is not a link", fsx.ErrUnsafe, a.display(l.BinLink))
	} else if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return "", err
	}
	var rnd [6]byte
	_, _ = rand.Read(rnd[:])
	tmp := l.BinLink + ".tmp-" + hex.EncodeToString(rnd[:])
	if err := os.Symlink(target, tmp); err != nil {
		return "", err
	}
	if err := os.Rename(tmp, l.BinLink); err != nil {
		os.Remove(tmp)
		return "", err
	}
	if err := fsx.SyncDir(filepath.Dir(l.BinLink)); err != nil {
		return "", err
	}
	return l.BinLink, nil
}

// parseVersion finds the first x.y.z in a --version output.
func parseVersion(s string) (string, bool) {
	m := versionRE.FindString(s)
	return m, m != ""
}

// versionLess reports whether a < b for x.y.z versions; an unreadable
// minimum never makes a version acceptable.
func versionLess(a, b string) bool {
	pa, okA := versionParts(a)
	pb, okB := versionParts(b)
	if !okA || !okB {
		return true
	}
	for i := 0; i < 3; i++ {
		if pa[i] != pb[i] {
			return pa[i] < pb[i]
		}
	}
	return false
}

func versionParts(v string) ([3]int, bool) {
	var out [3]int
	m := versionRE.FindStringSubmatch(v)
	if m == nil {
		return out, false
	}
	for i := 0; i < 3; i++ {
		n, err := strconv.Atoi(m[i+1])
		if err != nil {
			return out, false
		}
		out[i] = n
	}
	return out, true
}

// pluginInstallVerb is the harness plugin CLI's install subcommand (D94):
// Claude Code `claude plugin install <p>@<m>`, Codex (0.154: add, list,
// marketplace, remove) `codex plugin add <p>@<m>`.
func pluginInstallVerb(id harness.ID) string {
	if id == harness.Codex {
		return "add"
	}
	return "install"
}
