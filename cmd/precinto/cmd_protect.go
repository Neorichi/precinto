package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/precinto/precinto/internal/capsule"
	"github.com/precinto/precinto/internal/config"
	"github.com/precinto/precinto/internal/fsx"
	"github.com/precinto/precinto/internal/harness"
	"github.com/precinto/precinto/internal/ipc"
	"github.com/precinto/precinto/internal/paths"
	"github.com/precinto/precinto/internal/sweep"
	"github.com/precinto/precinto/internal/ui"
	"github.com/precinto/precinto/internal/vault"
)

// markerExclude is the line protect adds to .git/info/exclude (SPEC §8.4).
const markerExclude = "*.md.precinto"

// Bounds of the repository search below a folder at protect time.
const (
	gitSearchDepth   = 4
	gitSearchEntries = 20000
)

func cmdProtect(a *app, args []string) int {
	f := newFlags("protect")
	md := f.String("md", "", "which Markdown files to seal, `ledger|all|off`: the notes agents wrote (the default), all of them or none")
	onEnter := f.String("on-enter", "", "what a shell does when it enters the folder, `prompt|notify|off` (default: policy.on_enter)")
	harnessList := f.String("harness", "", "the harnesses precinto manages here, a comma-separated `LIST` (default: claude-code,codex)")
	claudeSettings := f.Bool("claude-settings", false, "also write precinto's Claude settings to DIR/.claude/settings.local.json")
	pos, err := f.parse(args)
	if code, ok := a.handleParse(f, err); !ok {
		return code
	}
	if len(pos) != 1 {
		return a.usageFail(f, "protect needs exactly one folder")
	}
	if err := oneOfFlag("md", *md, config.MDLedger, config.MDAll, config.MDOff); err != nil {
		return a.usageFail(f, err.Error())
	}
	if err := oneOfFlag("on-enter", *onEnter, config.OnEnterPrompt, config.OnEnterNotify, config.OnEnterOff); err != nil {
		return a.usageFail(f, err.Error())
	}
	// SPEC §4.6 (D95): vault_create relays the install passphrase to this
	// terminal, so protect hardens (no core dumps, no debugger, never as
	// root) before it opens the terminal or dials the daemon.
	if err := a.sys.harden(); err != nil {
		return a.fail("protect", err)
	}
	dir, err := a.resolveDir(pos[0])
	if err != nil {
		return a.fail("protect", err)
	}
	cfg, err := a.config()
	if err != nil {
		return a.fail("protect", err)
	}
	l, err := a.layout()
	if err != nil {
		return a.fail("protect", err)
	}
	disp := a.display(dir)
	if dir == "/" || paths.Within(dir, l.Base) || paths.Within(l.Base, dir) || paths.Within(dir, l.RunDir) || paths.Within(l.RunDir, dir) {
		a.say(textOwnData, disp)
		return exitError
	}
	for _, h := range a.harnessHomes(cfg) {
		if paths.Within(h, dir) {
			a.say(textHarnessData, disp)
			return exitError
		}
	}
	harnesses, err := a.protectHarnesses(cfg, *harnessList)
	if err != nil {
		return a.usageFail(f, err.Error())
	}
	vs, err := a.vaults()
	if err != nil {
		return a.fail("protect", err)
	}
	if done, err := vs.Initialized(); err != nil {
		return a.fail("protect", err)
	} else if !done {
		a.line(ui.MsgNotInitialized, ui.Vars{})
		return exitError
	}
	ctx := context.Background()
	var t terminal
	if a.sys.interactive() {
		if tt, err := a.sys.openTTY(); err == nil {
			t = tt
			defer t.Close()
		}
	}

	reused := false
	root, existing := rootByPath(cfg, dir)
	if existing {
		// A protected folder whose vault was never created (an earlier
		// protect failed at vault_create) gets it now.
		if _, err := vs.Meta(root.ID); err == nil {
			a.say(textAlreadyProt, disp)
			return exitOK
		} else if !errors.Is(err, vault.ErrNotFound) {
			return a.fail("protect", err)
		}
	} else {
		if over := cfg.Overlapping(dir); len(over) > 0 {
			a.say(textOverlap, disp, a.display(over[0].Path))
			if t == nil {
				return exitError
			}
			ok, err := t.YesNo(textOverlapAsk, false)
			if err != nil || !ok {
				a.say(textNotConfirmed)
				return exitLocked
			}
		}
		// D72: the folder manages Codex only with the user's consent,
		// recorded in its harness list: --harness naming codex is that
		// consent; otherwise C10.consent is asked when Codex is installed
		// and a terminal can answer, and `precinto run codex` asks it
		// later when the folder does not list codex.
		if slices.Contains(harnesses, string(harness.Codex)) && *harnessList == "" {
			consent := false
			if t != nil && a.codexInstalled(cfg) {
				ok, err := t.YesNo(ui.Format(ui.MsgCodexConsent, ui.Vars{Folder: disp}), true)
				consent = err == nil && ok
			}
			if !consent {
				harnesses = slices.DeleteFunc(harnesses, func(h string) bool { return h == string(harness.Codex) })
			}
		}
		// D74: a folder protected before keeps its id, so its retired
		// vault and every capsule sealed for it serve again.
		id := config.NewRootID()
		if old, ok := a.retiredVault(vs, cfg, dir); ok {
			id, reused = old, true
		}
		root = config.Root{
			ID:             id,
			Path:           dir,
			MD:             *md,
			OnEnter:        *onEnter,
			Harnesses:      harnesses,
			ClaudeSettings: *claudeSettings,
			ProtectedAt:    a.now().UTC(),
		}
		if root.MD == "" {
			root.MD = config.MDLedger
		}
		home, addClaudeHome := config.Home{}, false
		if slices.Contains(harnesses, string(harness.ClaudeCode)) {
			home, addClaudeHome = a.claudeHomeFromEnv()
		}
		// The folder is listed (config.toml and roots.list, which the
		// shim reads) before its vault exists: from now on hooks fail
		// closed there (I5). It is added to config.toml as it is on disk
		// now (D144): a folder another command protected or unprotected
		// meanwhile stays as that command left it.
		saved, err := a.editConfig(func(disk config.Config) (config.Config, error) {
			if r, ok := rootByPath(disk, dir); ok {
				root, existing = r, true // protected meanwhile by another command
				return disk, errNoEdit
			}
			next := disk
			next.Roots = append(append([]config.Root(nil), disk.Roots...), root)
			next.Harness = cloneHarness(disk.Harness)
			if addClaudeHome {
				addHome(next.Harness, string(harness.ClaudeCode), home)
			}
			return next, nil
		})
		if err != nil && !errors.Is(err, errNoEdit) {
			return a.fail("protect", err)
		}
		cfg = saved
		if existing {
			if _, err := vs.Meta(root.ID); err == nil {
				a.say(textAlreadyProt, disp)
				return exitOK
			}
			reused = false
		}
	}

	if reused {
		// The vault exists and stays locked until unlocked: nothing to
		// create (the daemon reads the new config.toml on its next tick).
		a.say(textProtectReused, disp, disp)
	} else {
		var relay ipc.UIHandler = headlessUI{w: a.err}
		if t != nil {
			relay = t
		}
		c, err := a.dial(ctx, true)
		if err == nil {
			err = c.VaultCreate(ctx, ipc.VaultCreateReq{RootID: root.ID, RootPath: root.Path}, relay)
			c.Close()
		}
		if err != nil {
			code := a.fail("protect", err)
			a.say(textVaultRetry, disp, disp)
			return code
		}
	}

	if root.ClaudeSettings {
		if p, err := a.writeClaudeSettings(ctx, cfg, root); err != nil {
			a.say("protect: %s", oneLineText(err.Error()))
		} else {
			a.say(textSettingsDone, a.display(p))
		}
	}
	a.offerGitExclude(t, root)
	if top, ok := gitTop(root.Path); ok && top != root.Path && !paths.Within(root.Path, top) {
		a.say(textRepoOutside, disp, a.display(top))
	}
	// Seal what is already there (keyless; the new vault stays unlocked, so
	// a sweep leaves the folder's units alone until it locks).
	if eng, err := a.engine(ctx, false); err == nil {
		_, _ = eng.Sweep(ctx, sweep.Options{Scope: harness.Scope{RootIDs: []string{root.ID}}, Reason: "manual", Quiet: true})
	}
	a.say(textProtected, disp, disp)
	return exitOK
}

// retiredVault finds the vault of a folder that was unprotected (D74): a
// root vault no configured folder uses whose recorded root_path is dir
// after realpath; the newest one when there are several.
func (a *app) retiredVault(vs vaultStore, cfg config.Config, dir string) (string, bool) {
	ids, err := vs.List()
	if err != nil {
		return "", false
	}
	best, bestAt := "", time.Time{}
	for _, id := range ids {
		if id == vault.GlobalID {
			continue
		}
		if _, used := cfg.RootByID(id); used {
			continue
		}
		m, err := vs.Meta(id)
		if err != nil || m.RootPath == "" {
			continue
		}
		p := filepath.Clean(m.RootPath)
		if real, err := a.sys.realpath(p); err == nil {
			p = real
		}
		if p == dir && (best == "" || m.CreatedAt.After(bestAt)) {
			best, bestAt = id, m.CreatedAt
		}
	}
	return best, best != ""
}

// codexInstalled reports whether Codex can run here: the configured
// [harness.codex].bin, or codex on PATH.
func (a *app) codexInstalled(cfg config.Config) bool {
	if bin := cfg.Harness[string(harness.Codex)].Bin; filepath.IsAbs(bin) {
		if fi, err := os.Stat(bin); err == nil && fi.Mode().IsRegular() && fi.Mode().Perm()&0o111 != 0 {
			return true
		}
	}
	_, err := paths.LookPath(a.env, "codex")
	return err == nil
}

// addCodexConsent records a yes to C10.consent from `precinto run codex`
// (D72): codex joins the folder's harness list, a strengthening edit (D48),
// in config.toml as it is on disk (D144).
func (a *app) addCodexConsent(rootID string) error {
	_, err := a.editConfig(func(disk config.Config) (config.Config, error) {
		next := disk
		next.Roots = append([]config.Root(nil), disk.Roots...)
		for i, r := range next.Roots {
			if r.ID != rootID {
				continue
			}
			if slices.Contains(r.Harnesses, string(harness.Codex)) {
				return disk, errNoEdit
			}
			hs := append([]string(nil), r.Harnesses...)
			if len(hs) == 0 {
				hs = []string{string(harness.ClaudeCode)} // an empty list meant both built-ins
			}
			r.Harnesses = append(hs, string(harness.Codex))
			next.Roots[i] = r
			return next, nil
		}
		return disk, errNoEdit
	})
	if errors.Is(err, errNoEdit) {
		return nil
	}
	return err
}

// rootByPath returns the root whose path is exactly dir.
func rootByPath(cfg config.Config, dir string) (config.Root, bool) {
	for _, r := range cfg.Roots {
		if r.Path == dir {
			return r, true
		}
	}
	return config.Root{}, false
}

// protectHarnesses parses --harness (default: the enabled built-ins).
func (a *app) protectHarnesses(cfg config.Config, list string) ([]string, error) {
	if list == "" {
		var out []string
		for _, h := range []string{string(harness.ClaudeCode), string(harness.Codex)} {
			if cfg.Harness[h].Enabled {
				out = append(out, h)
			}
		}
		return out, nil
	}
	var out []string
	for _, h := range strings.Split(list, ",") {
		h = strings.TrimSpace(h)
		if h == "" {
			continue
		}
		if _, known := cfg.Harness[h]; !known && h != string(harness.ClaudeCode) && h != string(harness.Codex) {
			return nil, usageErrorf("unknown harness %q (known: %s)", h, strings.Join(knownHarnesses(cfg), ", "))
		}
		if !slices.Contains(out, h) {
			out = append(out, h)
		}
	}
	if len(out) == 0 {
		return nil, usageErrorf("--harness needs at least one harness")
	}
	return out, nil
}

func knownHarnesses(cfg config.Config) []string {
	set := map[string]bool{string(harness.ClaudeCode): true, string(harness.Codex): true}
	for h := range cfg.Harness {
		set[h] = true
	}
	var out []string
	for h := range set {
		out = append(out, h)
	}
	return sortedStrings(out)
}

func cloneHarness(m map[string]config.Harness) map[string]config.Harness {
	out := make(map[string]config.Harness, len(m))
	for k, v := range m {
		v.Homes = append([]config.Home(nil), v.Homes...)
		out[k] = v
	}
	return out
}

// addHome registers h for harness id (deduplicated by directory; a home
// seen again refreshes SeenAt). Adding a home strengthens protection (D48).
func addHome(m map[string]config.Harness, id string, h config.Home) {
	hc := m[id]
	for i, old := range hc.Homes {
		if old.Dir == h.Dir {
			if h.Tmp != "" {
				old.Tmp = h.Tmp
			}
			if h.Cache != "" {
				old.Cache = h.Cache
			}
			old.SeenAt = h.SeenAt
			hc.Homes[i] = old
			m[id] = hc
			return
		}
	}
	hc.Homes = append(hc.Homes, h)
	m[id] = hc
}

// claudeHomeFromEnv resolves the Claude home of this environment (SPEC
// §7.0): CLAUDE_CONFIG_DIR or ~/.claude, its tmp dir (CLAUDE_CODE_TMPDIR or
// /private/tmp/claude-<uid>) and its cache, realpath'd once. A home that
// does not exist yet is not registered.
func (a *app) claudeHomeFromEnv() (config.Home, bool) {
	home := a.home()
	dir := a.env.Get(paths.EnvClaudeConfigDir)
	def := dir == ""
	if def {
		if home == "" {
			return config.Home{}, false
		}
		dir = filepath.Join(home, ".claude")
	}
	if !filepath.IsAbs(dir) {
		return config.Home{}, false
	}
	real, err := a.sys.realpath(filepath.Clean(dir))
	if err != nil {
		return config.Home{}, false
	}
	h := config.Home{Dir: real, SeenAt: a.now().UTC(), Default: def}
	tmp := a.env.Get(paths.EnvClaudeTmpDir)
	if !filepath.IsAbs(tmp) {
		tmp = "/tmp/claude-" + strconv.Itoa(a.sys.uid())
		if a.sys.goos == "darwin" {
			tmp = "/private" + tmp
		}
	}
	if r, err := a.sys.realpath(filepath.Clean(tmp)); err == nil {
		h.Tmp = r
	}
	var cache string
	if a.sys.goos == "darwin" {
		if home != "" {
			cache = filepath.Join(home, "Library", "Caches", "claude-cli-nodejs")
		}
	} else if x := a.env.Get("XDG_CACHE_HOME"); filepath.IsAbs(x) {
		cache = filepath.Join(filepath.Clean(x), "claude-cli-nodejs")
	} else if home != "" {
		cache = filepath.Join(home, ".cache", "claude-cli-nodejs")
	}
	if cache != "" {
		if r, err := a.sys.realpath(cache); err == nil {
			h.Cache = r
		}
	}
	return h, true
}

// writeClaudeSettings merges precinto's Claude settings (D32:
// idleCompaction, awaySummaryEnabled and precomputeCompactionEnabled off)
// into DIR/.claude/settings.local.json, keeping every other key.
func (a *app) writeClaudeSettings(ctx context.Context, cfg config.Config, r config.Root) (string, error) {
	eng, err := a.engine(ctx, false)
	if err != nil {
		return "", err
	}
	var want map[string]any
	if err := json.Unmarshal([]byte(eng.ClaudeSettingsJSON(cfg.Policy)), &want); err != nil {
		return "", err
	}
	dir := filepath.Join(r.Path, ".claude")
	if st, err := fsx.Lstat(dir); err == nil {
		if !st.IsDir() {
			return "", fmt.Errorf("%w: %s is not a directory", fsx.ErrUnsafe, a.display(dir))
		}
	} else if errors.Is(err, fs.ErrNotExist) {
		if err := os.Mkdir(dir, 0o700); err != nil {
			return "", err
		}
	} else {
		return "", err
	}
	p := filepath.Join(dir, "settings.local.json")
	cur := map[string]any{}
	if fh, err := os.OpenFile(p, os.O_RDONLY|syscall.O_NOFOLLOW, 0); err == nil {
		b, rerr := readBounded(fh, 1<<20)
		fh.Close()
		if rerr != nil {
			return "", rerr
		}
		if len(bytes.TrimSpace(b)) > 0 {
			if err := json.Unmarshal(b, &cur); err != nil {
				return "", fmt.Errorf("%s is not a JSON object; left unchanged", a.display(p))
			}
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return "", err
	}
	for k, v := range want {
		cur[k] = v
	}
	b, err := json.MarshalIndent(cur, "", "  ")
	if err != nil {
		return "", err
	}
	return p, fsx.WriteFileAtomic(p, append(b, '\n'), 0o600)
}

// removeClaudeSettings undoes protect --claude-settings (DC-42): it
// removes from DIR/.claude/settings.local.json the keys that still hold
// the value precinto wrote, keeping every other key (and any key the user
// changed since). It returns the file's path when it changed it.
func (a *app) removeClaudeSettings(eng engine, cfg config.Config, r config.Root) (string, error) {
	var ours map[string]any
	if err := json.Unmarshal([]byte(eng.ClaudeSettingsJSON(cfg.Policy)), &ours); err != nil {
		return "", err
	}
	p := filepath.Join(r.Path, ".claude", "settings.local.json")
	fh, err := os.OpenFile(p, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if errors.Is(err, fs.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	if st, err := fsx.Fstat(fh); err != nil || !st.IsRegular() {
		fh.Close()
		return "", fmt.Errorf("%w: %s is not a regular file; left unchanged", fsx.ErrUnsafe, a.display(p))
	}
	b, err := readBounded(fh, 1<<20)
	fh.Close()
	if err != nil {
		return "", err
	}
	cur := map[string]any{}
	if len(bytes.TrimSpace(b)) > 0 {
		if err := json.Unmarshal(b, &cur); err != nil {
			return "", fmt.Errorf("%s is not a JSON object; left unchanged", a.display(p))
		}
	}
	changed := false
	for k, v := range ours {
		if have, ok := cur[k]; ok && reflect.DeepEqual(have, v) {
			delete(cur, k)
			changed = true
		}
	}
	if !changed {
		return "", nil
	}
	out, err := json.MarshalIndent(cur, "", "  ")
	if err != nil {
		return "", err
	}
	return p, fsx.WriteFileAtomic(p, append(out, '\n'), 0o600)
}

// offerGitExclude offers (consent, default yes) to add *.md.precinto to
// .git/info/exclude of every repository in the folder and of the
// repository containing it: local and never committed, the only repository
// file precinto writes besides markers and --claude-settings (SPEC §8.4).
// Without a terminal nothing is written.
func (a *app) offerGitExclude(t terminal, r config.Root) {
	if t == nil {
		return
	}
	repos := gitDirsUnder(r.Path)
	if top, ok := gitTop(r.Path); ok {
		if gd := filepath.Join(top, ".git"); !slices.Contains(repos, gd) {
			repos = append(repos, gd)
		}
	}
	var todo []string
	for _, gd := range repos {
		if !excludeHas(filepath.Join(gd, "info", "exclude"), markerExclude) {
			todo = append(todo, gd)
		}
	}
	if len(todo) == 0 {
		return
	}
	ok, err := t.YesNo(fmt.Sprintf(textGitExcludeAsk, len(todo), a.display(r.Path)), true)
	if err != nil || !ok {
		return
	}
	for _, gd := range todo {
		if err := appendExclude(gd, markerExclude); err != nil {
			a.say("protect: %s: %s", a.display(gd), oneLineText(err.Error()))
		}
	}
}

// gitDirsUnder lists .git directories (not worktree files) below dir,
// bounded in depth and entries, skipping dependency and hidden folders.
func gitDirsUnder(dir string) []string {
	var out []string
	seen := 0
	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		seen++
		if seen > gitSearchEntries {
			return fs.SkipAll
		}
		if !d.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(dir, p)
		if rel != "." && strings.Count(rel, string(filepath.Separator)) >= gitSearchDepth {
			return fs.SkipDir
		}
		name := d.Name()
		if name == ".git" {
			out = append(out, p)
			return fs.SkipDir
		}
		if p != dir && (strings.HasPrefix(name, ".") || name == "node_modules" || name == "vendor") {
			return fs.SkipDir
		}
		return nil
	})
	return out
}

// gitTop returns the directory of the repository containing dir (the
// nearest ancestor with a .git directory or file).
func gitTop(dir string) (string, bool) {
	for d := dir; ; d = filepath.Dir(d) {
		if _, err := os.Lstat(filepath.Join(d, ".git")); err == nil {
			return d, true
		}
		if filepath.Dir(d) == d {
			return "", false
		}
	}
}

// excludeHas reports whether an exclude file already lists line.
func excludeHas(path, line string) bool {
	fh, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return false
	}
	defer fh.Close()
	sc := bufio.NewScanner(fh)
	for sc.Scan() {
		if strings.TrimSpace(sc.Text()) == line {
			return true
		}
	}
	return false
}

// appendExclude appends line to gitDir/info/exclude (never through a
// symlink).
func appendExclude(gitDir, line string) error {
	st, err := fsx.Lstat(gitDir)
	if err != nil || !st.IsDir() {
		return fmt.Errorf("%w: not a git directory", fsx.ErrUnsafe)
	}
	info := filepath.Join(gitDir, "info")
	if err := os.Mkdir(info, 0o755); err != nil && !errors.Is(err, fs.ErrExist) {
		return err
	}
	if st, err := fsx.Lstat(info); err != nil || !st.IsDir() {
		return fmt.Errorf("%w: .git/info is not a directory", fsx.ErrUnsafe)
	}
	p := filepath.Join(info, "exclude")
	fh, err := os.OpenFile(p, os.O_WRONLY|os.O_APPEND|os.O_CREATE|syscall.O_NOFOLLOW, 0o644)
	if err != nil {
		return err
	}
	defer fh.Close()
	if st, err := fsx.Fstat(fh); err != nil || !st.IsRegular() {
		return fmt.Errorf("%w: .git/info/exclude is not a regular file", fsx.ErrUnsafe)
	}
	prefix := ""
	if st, err := fh.Stat(); err == nil && st.Size() > 0 && !endsWithNewline(p) {
		prefix = "\n"
	}
	_, err = fh.WriteString(prefix + line + "\n")
	return err
}

func endsWithNewline(p string) bool {
	fh, err := os.OpenFile(p, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return true
	}
	defer fh.Close()
	st, err := fh.Stat()
	if err != nil || st.Size() == 0 {
		return true
	}
	b := make([]byte, 1)
	if _, err := fh.ReadAt(b, st.Size()-1); err != nil {
		return true
	}
	return b[0] == '\n'
}

func cmdUnprotect(a *app, args []string) int {
	f := newFlags("unprotect")
	pos, err := f.parse(args)
	if code, ok := a.handleParse(f, err); !ok {
		return code
	}
	if len(pos) != 1 {
		return a.usageFail(f, "unprotect needs exactly one protected folder")
	}
	cfg, err := a.config()
	if err != nil {
		return a.fail("unprotect", err)
	}
	dir := mustAbs(a, pos[0])
	if real, err := a.sys.realpath(dir); err == nil {
		dir = real
	}
	root, ok := rootByPath(cfg, dir)
	if !ok {
		return a.fail("unprotect", notProtectedError{dir: a.display(dir)})
	}
	disp := a.display(root.Path)
	// D59: typed confirmation on a TTY; refused in agent contexts and
	// without a controlling terminal (SEC-28).
	if err := a.refuseAgent(refusal{action: "stop protecting", folder: disp, command: "unprotect " + disp}); err != nil {
		return exitLocked
	}
	t, err := a.needTerminal("unprotect")
	if err != nil {
		return exitLocked
	}
	defer t.Close()
	if err := a.sys.harden(); err != nil {
		return a.fail("unprotect", err)
	}
	ctx := context.Background()
	eng, err := a.engine(ctx, false)
	if err != nil {
		return a.fail("unprotect", err)
	}
	units, err := eng.List(ctx, sweep.ListOptions{RootIDs: []string{root.ID}})
	if err != nil {
		return a.fail("unprotect", err)
	}
	a.say(textUnprotectList, disp, len(units))
	for _, u := range units {
		a.say(textUnprotectUnit, u.Unit, u.Kind, len(u.Gens))
	}
	if err := a.typedConfirm(t, fmt.Sprintf(textUnprotectWhat, disp), wordUnprotect); err != nil {
		return exitLocked
	}
	if err := a.ensureUnlocked(ctx, []config.Root{root}, t); err != nil {
		return a.fail("unprotect", err)
	}
	// Restore everything first; on any failure protection is kept and
	// nothing is deleted (never delete, keep protection: fail closed).
	if len(units) > 0 {
		keys := a.keys()
		defer keys.close()
		abort, stop := a.watchLocks(ctx, []string{root.ID}, keys.destroy)
		defer stop()
		rep, err := a.restoreAll(ctx, eng, keys, root, abort)
		if err != nil {
			a.say(textUnprotectKept, disp, oneLineText(err.Error()))
			return exitForRestore(err)
		}
		if closed(abort) {
			// Locked while restoring: units rolled back stay sealed, so the
			// folder keeps its protection (fail closed).
			a.printRestore(rep)
			a.say(textUnprotectKept, disp, "it locked during the restore")
			return exitLocked
		}
		a.printRestore(rep)
	}
	// The folder leaves config.toml as it is on disk now (D144): folders
	// other commands protected or unprotected meanwhile stay as they left
	// them.
	saved, err := a.editConfig(func(disk config.Config) (config.Config, error) {
		if _, ok := disk.RootByID(root.ID); !ok {
			return disk, errNoEdit // removed meanwhile by another command
		}
		next := disk
		next.Roots = slices.DeleteFunc(append([]config.Root(nil), disk.Roots...), func(r config.Root) bool { return r.ID == root.ID })
		return next, nil
	})
	if err != nil && !errors.Is(err, errNoEdit) {
		return a.fail("unprotect", err)
	}
	if root.ClaudeSettings {
		if p, err := a.removeClaudeSettings(eng, cfg, root); err != nil {
			a.say("unprotect: %s", oneLineText(err.Error()))
		} else if p != "" {
			a.say(textSettingsRemoved, a.display(p))
		}
	}
	// Removing a folder weakens protection: the daemon keeps it until the
	// change is confirmed in a terminal (D48). Every pending change is
	// listed and confirmed explicitly: the typed "unprotect" covered only
	// this folder, not other edits an agent may have made (D146). Only a
	// confirmed removal (or one nothing held back) is "no longer
	// protected": otherwise the agent keeps locking and gating the folder,
	// and its lock seals it again.
	if !a.confirmRemoval(ctx, t, root, saved) {
		a.say(textUnprotectWaits, disp, ui.ShellWord(a.home(), root.Path))
		return exitLocked
	}
	a.say(textUnprotectDone, disp)
	return exitOK
}

// restoreAll restores every sealed unit of a folder: sessions, project,
// plans, the Codex home, notes and history (unprotect, restore --all).
func (a *app) restoreAll(ctx context.Context, eng engine, keys sweep.KeySource, root config.Root, abort <-chan struct{}) (*sweep.Report, error) {
	sel := []harness.Selector{
		{Kind: capsule.KindClaudeSession, RootID: root.ID},
		{Kind: capsule.KindClaudeProject, RootID: root.ID},
		{Kind: capsule.KindClaudePlan, RootID: root.ID},
		{Kind: capsule.KindCodexHome, RootID: root.ID},
	}
	total := &sweep.Report{}
	rep, err := eng.Restore(ctx, keys, sweep.RestoreRequest{Select: sel, Budget: math.MaxInt64, Purpose: ipc.PurposeRestoreAll, StopOnErr: true, Abort: abort})
	mergeReport(total, rep)
	if err != nil {
		return total, err
	}
	rep, err = eng.RestoreMarkdown(ctx, keys, root)
	mergeReport(total, rep)
	if err != nil {
		return total, err
	}
	rep, err = eng.MergeHistory(ctx, keys, root.ID)
	mergeReport(total, rep)
	return total, err
}

// ensureUnlocked unlocks the folders that are locked, in this terminal
// (wrapper.Backend.EnsureUnlocked and unprotect).
func (a *app) ensureUnlocked(ctx context.Context, roots []config.Root, relay ipc.UIHandler) error {
	if len(roots) == 0 {
		return nil
	}
	c, err := a.dial(ctx, true)
	if err != nil {
		return err
	}
	defer c.Close()
	st, err := c.Status(ctx)
	if err != nil {
		return err
	}
	open := unlockedVaults(st)
	var locked []string
	var first string
	for _, r := range roots {
		if !open[r.ID] {
			locked = append(locked, r.ID)
			if first == "" {
				first = a.display(r.Path)
			}
		}
	}
	if len(locked) == 0 {
		return nil
	}
	tty := relay != nil
	if _, headless := relay.(headlessUI); headless || relay == nil {
		tty = false
	}
	confirmed := len(locked) == 1
	if !confirmed {
		// D40: several folders are confirmed by typing "unlock".
		if !tty {
			return refusedError{reason: "several folders need a terminal"}
		}
		ok, err := relay.Confirm(ui.Format(ui.MsgUnlockConfirmAll, ui.Vars{N: len(locked), Folder: first}), wordUnlock, "")
		if err != nil {
			return err
		}
		if !ok {
			a.say(textNotConfirmed)
			return refusedError{reason: "not confirmed"}
		}
		confirmed = true
	}
	if relay == nil {
		relay = headlessUI{w: a.err}
	}
	_, err = c.Unlock(ctx, ipc.UnlockReq{RootIDs: locked, TTY: tty, Confirmed: confirmed, Deadline: wireDeadline(3 * time.Minute)}, relay)
	return err
}

// confirmRemoval reviews, right after unprotect saved config.toml, the
// weakening changes that wait for a confirmation — the folder's removal
// and any other edit — and confirms them after an explicit yes (D48,
// D146). Everything goes over one connection: the agent re-reads
// config.toml before it lists them, and a confirmation is accepted only
// after a terminal unlock on that connection (D91). settings is
// config.toml as saved, the settings being confirmed. It reports whether
// the folder is no longer protected: the changes were confirmed, or the
// agent holds nothing back (the confirmed settings never named the
// folder). A removal left unconfirmed — declined, refused, or with no
// agent to ask (it is started as for the unlock before; one that cannot
// start enforces the confirmed settings again at its next start) — is
// false: the agent keeps protecting the folder until a terminal unlock
// confirms it. The agent's refusal is printed as its own line.
func (a *app) confirmRemoval(ctx context.Context, t terminal, root config.Root, settings config.Config) bool {
	c, err := a.dial(ctx, true)
	if err != nil {
		a.sayErr("unprotect", err)
		return false
	}
	defer c.Close()
	p, err := c.Policy(ctx, ipc.PolicyReq{})
	if err != nil {
		a.sayErr("unprotect", err)
		return false
	}
	if len(p.Pending) == 0 {
		return true
	}
	open := map[string]bool{}
	if st, err := c.Status(ctx); err == nil {
		open = unlockedVaults(st)
	}
	names := config.WithRoots(settings, root)
	ok, err := a.confirmChanges(ctx, c, t, p.Pending, settings, names, open, false)
	if err != nil {
		a.sayErr("unprotect", err)
	}
	return err == nil && ok
}

// confirmChanges shows the pending weakening changes on t, naming folders
// (names maps root ids to folders), and on an explicit yes confirms them
// over c (D48, D123). The agent signs the settings it pins with the key of
// a vault of those settings (D145): one of their folders, or the global
// vault when they name none; when no such vault is unlocked, it asks
// (C13.signer) to unlock one — the global vault, or the first of their
// folders — on c, which is also the terminal unlock the confirmation needs
// on that connection; ttyDone says c made one already. It reports whether
// the changes were confirmed; a refusal of the agent is its error.
func (a *app) confirmChanges(ctx context.Context, c daemonClient, t terminal, pending []string, settings, names config.Config, open map[string]bool, ttyDone bool) (bool, error) {
	a.showPending(pending, names)
	if ok, err := t.YesNo(ui.Format(ui.MsgPolicyConfirm, ui.Vars{}), false); err != nil || !ok {
		return false, nil
	}
	signer, folder := pinSigner(settings, open)
	signerName := "the global vault"
	if signer != vault.GlobalID {
		signerName = a.display(folder)
	}
	if !open[signer] || !ttyDone {
		if !open[signer] {
			if ok, err := t.YesNo(ui.Format(ui.MsgPolicySigner, ui.Vars{Folder: signerName}), true); err != nil || !ok {
				return false, nil
			}
		}
		req := ipc.UnlockReq{TTY: true, Confirmed: true, Deadline: wireDeadline(unlockDeadline)}
		if signer == vault.GlobalID {
			req.Global = true
		} else {
			req.RootIDs = []string{signer}
		}
		if _, err := c.Unlock(ctx, req, t); err != nil {
			// A cancel or a wrong secret is said as an unlock says it,
			// naming the folder or "the global vault" (never its id).
			switch {
			case isCancel(err):
				a.line(ui.MsgUnlockCancelled, ui.Vars{Folder: signerName})
				return false, shownError{reason: "cancelled", code: exitLocked}
			case isBadSecret(err):
				a.line(ui.MsgUnlockBadSecret, ui.Vars{Folder: signerName})
				return false, shownError{reason: "bad secret", code: exitLocked}
			}
			return false, err
		}
	}
	if _, err := c.Policy(ctx, ipc.PolicyReq{Confirm: true}); err != nil {
		return false, err
	}
	return true, nil
}

// pinSigner is the vault whose key signs a pin of settings (D145): an
// unlocked folder of the settings, else their first folder by path (to
// unlock), or the global vault when they name no folder; folder is that
// folder's path ("" for the global vault).
func pinSigner(settings config.Config, open map[string]bool) (id, folder string) {
	if len(settings.Roots) == 0 {
		return vault.GlobalID, ""
	}
	roots := append([]config.Root(nil), settings.Roots...)
	slices.SortFunc(roots, func(x, y config.Root) int { return strings.Compare(x.Path, y.Path) })
	for _, r := range roots {
		if open[r.ID] {
			return r.ID, r.Path
		}
	}
	return roots[0].ID, roots[0].Path
}

// showPending prints the pending changes for the terminal review that
// follows (C13.review: the user decides now, so never C13.policy's "at
// your next unlock", UX-14), a folder's by its path, never its id (D146).
func (a *app) showPending(pending []string, names config.Config) {
	a.line(ui.MsgPolicyReview, ui.Vars{N: len(pending)})
	for _, ch := range pending {
		a.say(textPolicyLine, oneLineText(a.pendingLine(ch, names)))
	}
}

// pendingLine renders one pending change of the agent ("key: old → new",
// content-free) for the review: a change of folder id, roots[<id>]…,
// names the folder (names, else the path the change carries), and a
// folder that stops or starts being protected says so.
func (a *app) pendingLine(line string, names config.Config) string {
	rest, ok := strings.CutPrefix(line, "roots[")
	if !ok {
		return line
	}
	id, rest, ok := strings.Cut(rest, "]")
	if !ok {
		return line
	}
	folder := ""
	if r, ok := names.RootByID(id); ok {
		folder = a.display(r.Path)
	}
	if body, ok := strings.CutPrefix(rest, ": "); ok {
		old, new, ok := strings.Cut(body, " → ")
		if !ok {
			return line
		}
		switch {
		case folder == "" && old != "":
			folder = a.display(old)
		case folder == "" && new != "":
			folder = a.display(new)
		}
		switch {
		case folder == "":
			return line
		case new == "":
			return folder + ": " + textNoLongerProtected
		case old == "":
			return folder + ": " + textNewlyProtected
		}
		return line
	}
	if field, ok := strings.CutPrefix(rest, "."); ok && folder != "" {
		return folder + ": " + strings.Replace(field, ": ", " ", 1)
	}
	return line
}
