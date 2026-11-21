package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/precinto/precinto/internal/config"
	"github.com/precinto/precinto/internal/fsx"
	"github.com/precinto/precinto/internal/harness"
	"github.com/precinto/precinto/internal/paths"
)

// The marketplace precinto's plugins are published in (SPEC §21): the
// repository's .claude-plugin/marketplace.json (Claude, Droid, Copilot) and
// .agents/plugins/marketplace.json (Codex), both named "precinto".
const (
	marketplaceSource = "precinto/precinto"
	pluginRef         = paths.ClaudePluginID
)

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
	experimental := f.Bool("experimental", false, "allow experimental harnesses and hosts (D33)")
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
		a.say(textIntegrateOld, exeName, have, min)
		return exitError
	}
	cmds := [][]string{
		{bin, "plugin", "marketplace", "add", marketplaceSource},
		{bin, "plugin", pluginInstallVerb(id), pluginRef},
	}
	if printOnly {
		for _, c := range cmds {
			fmt.Fprintln(a.out, strings.Join(c, " "))
		}
		return exitOK
	}
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
	for _, c := range cmds {
		if _, err := a.sys.exec(ctx, execSpec{Argv: c, Env: harnessEnv(a.env), Stdout: a.out, Stderr: a.err, Timeout: 5 * time.Minute}); err != nil {
			return a.fail("integrate", fmt.Errorf("%s failed", strings.Join(c[1:], " ")))
		}
	}
	a.say(textIntegrateDone, exeName)
	if id == harness.Codex {
		a.say(textCodexTrust)
	}
	return exitOK
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
