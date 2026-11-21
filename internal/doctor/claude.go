package doctor

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/precinto/precinto/internal/harness"
	"github.com/precinto/precinto/internal/ui"
)

// Claude Code checks (HOOKS-IO §2, §6; SPEC §7.1; D14, D22, D32, D56).

const (
	claudeMinVersion      = "2.1.295" // onFailure: block (D22, HOOKS-IO §6)
	claudeVerifiedDefault = ">=2.1.295 <=2.1.329"
	claudeNPMPackage      = "@anthropic-ai/claude-code"
	maxHistoryLine        = 16 << 20
)

// claude returns what doctor found of the Claude Code installation.
func (e *env) claude() *install {
	if e.claudeIn != nil {
		return e.claudeIn
	}
	in := &install{}
	in.exe = e.findExecutable("claude", e.o.Cfg.Harness[string(harness.ClaudeCode)].Bin)
	if in.exe != "" {
		in.version, in.versionOK = versionOfExecutable(in.exe, claudeNPMPackage)
	}
	in.running = e.runningOf(isClaudeProcess, claudeProcessVersion)
	e.claudeIn = in
	return in
}

// claudePresent reports whether Claude Code is installed or has been used
// here (an executable, a running process or a config dir).
func (e *env) claudePresent() bool {
	in := e.claude()
	return in.exe != "" || len(in.running) > 0 || len(e.claudeConfigDirs()) > 0
}

func checkClaudeVersion(e *env) []Finding {
	if !e.claudePresent() {
		return nil
	}
	in := e.claude()
	min := e.minVersion(harness.ClaudeCode, claudeMinVersion)
	verified := e.verifiedRange(harness.ClaudeCode, claudeVerifiedDefault)
	var out []Finding
	switch {
	case in.exe == "":
		out = append(out, info(CheckClaudeVersion, "the claude executable was not found, so its version was not checked", ""))
	case !in.versionOK:
		out = append(out, info(CheckClaudeVersion, "could not tell the version of Claude Code at "+e.show(in.exe), "claude --version"))
	case in.version.compare(min) < 0:
		out = append(out, fail(CheckClaudeVersion, fmt.Sprintf("Claude Code %s is older than %s: its hooks cannot block when precinto fails (onFailure), so prompts in a locked folder can go through", in.version, min),
			"claude update"))
	default:
		if inR, ok := inRange(in.version, verified); ok && !inR {
			out = append(out, info(CheckClaudeVersion, fmt.Sprintf("Claude Code %s is newer than the versions precinto was verified with (%s)", in.version, verified), ""))
		}
	}
	for _, r := range in.running {
		if r.versionOK && r.version.compare(min) < 0 {
			out = append(out, fail(CheckClaudeVersion, fmt.Sprintf("a running Claude Code session (pid %d) is version %s, older than %s: its prompts are not blocked when precinto fails", r.pid, r.version, min),
				"quit that session and start it again after claude update"))
		}
	}
	if len(out) == 0 {
		out = append(out, ok(CheckClaudeVersion, fmt.Sprintf("Claude Code %s (at least %s)", in.version, min)))
	}
	return out
}

// installedPrecintoPlugin reports whether a config dir's
// plugins/installed_plugins.json lists precinto's plugin (false as well
// when the file is missing or unreadable).
func installedPrecintoPlugin(configDir string) bool {
	b, err := readRegular(filepath.Join(configDir, "plugins", "installed_plugins.json"), maxSettingsBytes)
	if err != nil {
		return false
	}
	var top map[string]json.RawMessage
	if json.Unmarshal(b, &top) != nil {
		return false
	}
	ids := top
	if raw, ok := top["plugins"]; ok {
		ids = nil
		if json.Unmarshal(raw, &ids) != nil {
			return false
		}
	}
	for id := range ids {
		if isPrecintoPlugin(id) {
			return true
		}
	}
	return false
}

func checkClaudePlugin(e *env) []Finding {
	if !e.claudePresent() {
		return nil
	}
	var out []Finding
	dirs := e.claudeConfigDirs()
	for _, d := range dirs {
		enabled, disabled := false, ""
		for _, f := range []string{filepath.Join(d, "settings.json"), filepath.Join(d, "settings.local.json")} {
			s := e.settingsAt(f)
			if s == nil {
				continue
			}
			for id, on := range s.plugins {
				if !isPrecintoPlugin(id) {
					continue
				}
				if on {
					enabled = true
				} else {
					disabled = f
				}
			}
		}
		installed := installedPrecintoPlugin(d)
		switch {
		case disabled != "":
			out = append(out, fail(CheckClaudePlugin, "precinto's Claude Code plugin is disabled in "+e.show(disabled)+": Claude sessions are not paused when a folder locks",
				"precinto integrate claude-code"))
		case enabled:
		case installed:
			out = append(out, warn(CheckClaudePlugin, "precinto's Claude Code plugin is installed for "+e.show(d)+" but not enabled in its settings",
				"precinto integrate claude-code"))
		default:
			// Not listed anywhere (or the plugin list is unreadable): a
			// plugin loaded some other way cannot be seen, so fail closed.
			out = append(out, fail(CheckClaudePlugin, "precinto's Claude Code plugin is not installed for "+e.show(d)+": Claude sessions are not paused when a folder locks",
				"precinto integrate claude-code"))
		}
	}
	if len(out) == 0 && len(dirs) > 0 {
		out = append(out, ok(CheckClaudePlugin, "precinto's Claude Code plugin is installed and enabled"))
	}
	return out
}

func checkClaudeHooksOff(e *env) []Finding {
	var out []Finding
	for _, f := range e.userSettingsFiles() {
		if s := e.settingsAt(f); s != nil && s.disableAllHooks {
			out = append(out, fail(CheckClaudeHooksOff, e.show(f)+" turns off every hook (disableAllHooks): no Claude session can be paused when a folder locks",
				"remove disableAllHooks from "+e.show(f)))
		}
	}
	for _, r := range e.o.Cfg.Roots {
		if !rootProtects(r, harness.ClaudeCode) {
			continue
		}
		for _, f := range e.rootSettingsFiles(r.Path) {
			if owner, ok := e.rootFor(f, harness.ClaudeCode); ok && owner.ID != r.ID {
				continue // a nested folder's file: reported under that folder (D36)
			}
			s := e.settingsAt(f)
			if s == nil {
				continue
			}
			if s.disableAllHooks {
				out = append(out, fail(CheckClaudeHooksOff, e.show(f)+" turns off every hook (disableAllHooks): Claude sessions in "+e.folder(r)+" cannot be paused when it locks",
					"remove disableAllHooks from "+e.show(f)))
			}
			var off []string
			for id, on := range s.plugins {
				if isPrecintoPlugin(id) && !on {
					off = append(off, id)
				}
			}
			if len(off) > 0 {
				out = append(out, fail(CheckClaudeHooksOff, e.show(f)+" disables precinto's plugin ("+joinNames(off)+"): Claude sessions in "+e.folder(r)+" cannot be paused when it locks",
					"remove "+joinNames(off)+" from enabledPlugins in "+e.show(f)))
			}
		}
	}
	if len(out) == 0 {
		out = append(out, ok(CheckClaudeHooksOff, "no Claude settings file turns precinto's hooks off"))
	}
	return out
}

func checkClaudeSettings(e *env) []Finding {
	var want map[string]json.RawMessage
	var out []Finding
	used := 0
	for _, r := range e.o.Cfg.Roots {
		if !r.ClaudeSettings || !rootProtects(r, harness.ClaudeCode) {
			continue
		}
		used++
		if want == nil {
			if err := json.Unmarshal([]byte(e.d.ClaudeSettingsJSON(e.o.Cfg.Policy)), &want); err != nil || len(want) == 0 {
				return []Finding{info(CheckClaudeSettings, "could not determine the settings protect --claude-settings writes", "")}
			}
		}
		// Effective values: the project file, overridden by the local one.
		eff := map[string]json.RawMessage{}
		for _, name := range []string{"settings.json", "settings.local.json"} {
			s := e.settingsAt(filepath.Join(r.Path, ".claude", name))
			if s == nil {
				continue
			}
			if s.err != nil {
				out = append(out, warn(CheckClaudeSettings, "could not read "+e.show(s.path)+" ("+errClass(s.err)+"), so its settings were not checked", "fix the file, then run: precinto protect "+e.arg(r.Path)+" --claude-settings"))
				continue
			}
			for k, v := range s.top {
				eff[k] = v
			}
		}
		var drifted []string
		for k, v := range want {
			if !jsonEqual(eff[k], v) {
				drifted = append(drifted, k)
			}
		}
		if len(drifted) > 0 {
			out = append(out, warn(CheckClaudeSettings, "the Claude settings precinto wrote in "+e.folder(r)+"/.claude were changed ("+joinNames(drifted)+"): Claude may compact or summarize while the folder is locked",
				"precinto protect "+e.arg(r.Path)+" --claude-settings"))
		}
	}
	if len(out) == 0 && used > 0 {
		out = append(out, ok(CheckClaudeSettings, "the Claude settings written by protect --claude-settings are in place"))
	}
	return out
}

// jsonEqual compares two JSON values semantically.
func jsonEqual(a, b json.RawMessage) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	var x, y any
	if json.Unmarshal(a, &x) != nil || json.Unmarshal(b, &y) != nil {
		return false
	}
	xb, _ := json.Marshal(x)
	yb, _ := json.Marshal(y)
	return bytes.Equal(xb, yb)
}

func checkClaudeSettingsEnv(e *env) []Finding {
	files := e.userSettingsFiles()
	for _, r := range e.o.Cfg.Roots {
		if rootProtects(r, harness.ClaudeCode) {
			files = append(files, e.rootSettingsFiles(r.Path)...)
		}
	}
	var out []Finding
	seen := map[string]bool{}
	for _, f := range files {
		if seen[f] {
			continue // a nested folder's file, found from both folders
		}
		seen[f] = true
		s := e.settingsAt(f)
		switch {
		case s == nil:
		case s.err != nil:
			out = append(out, warn(CheckClaudeSettingsEnv, "could not read "+e.show(f)+" ("+errClass(s.err)+"), so its env was not checked",
				"check the file by hand: an env with PRECINTO_*, HOME, XDG_*, PATH, DYLD_* or LD_* keys reaches every precinto hook"))
		default:
			if bad := flaggedEnvKeys(s.env); len(bad) > 0 {
				out = append(out, fail(CheckClaudeSettingsEnv, e.show(f)+" sets "+joinNames(bad)+" in env: these reach every precinto hook and can change where it looks for precinto",
					`remove `+joinNames(bad)+` from "env" in `+e.show(f)))
			}
		}
	}
	if len(out) == 0 {
		out = append(out, ok(CheckClaudeSettingsEnv, "no Claude settings file sets PRECINTO_*, HOME, XDG_*, PATH, DYLD_* or LD_* in env"))
	}
	return out
}

func checkClaudeRetention(e *env) []Finding {
	var out []Finding
	for _, d := range e.claudeConfigDirs() {
		days, err := e.d.CleanupPeriodDays(d)
		switch {
		case err != nil:
			out = append(out, info(CheckClaudeRetention, "could not read cleanupPeriodDays from the settings in "+e.show(d), ""))
		case days <= 2:
			out = append(out, warn(CheckClaudeRetention, fmt.Sprintf("Claude deletes sessions older than %d days when it starts (cleanupPeriodDays), so precinto restores sessions only when you ask for them (the sealed copies are kept)", days),
				"set cleanupPeriodDays to 30 or more in "+e.show(filepath.Join(d, "settings.json"))))
		default:
			out = append(out, info(CheckClaudeRetention, fmt.Sprintf("Claude deletes sessions older than %d days when it starts (cleanupPeriodDays); precinto keeps the sealed copies and restores sessions up to %d days old by itself, older ones with precinto resume --pick", days, days-2), ""))
		}
	}
	return out
}

// legacyStateFiles returns ~/.claude.json, the copy Claude keeps inside a
// custom config dir, and their backups.
func (e *env) legacyStateFiles() []string {
	var out []string
	add := func(p string) {
		for _, x := range out {
			if x == p {
				return
			}
		}
		if fi, err := os.Stat(p); err == nil && fi.Mode().IsRegular() {
			out = append(out, p)
		}
	}
	glob := func(dir, prefix string) {
		es, _ := listDir(dir)
		for _, en := range es {
			if strings.HasPrefix(en.Name(), prefix) {
				add(filepath.Join(dir, en.Name()))
			}
		}
	}
	if e.home != "" {
		add(filepath.Join(e.home, ".claude.json"))
		glob(e.home, ".claude.json.backup")
	}
	for _, d := range e.claudeConfigDirs() {
		add(filepath.Join(d, ".claude.json"))
		glob(d, ".claude.json.backup")
		glob(filepath.Join(d, "backups"), ".claude.json.backup")
	}
	return out
}

func checkClaudeLegacy(e *env) []Finding {
	var out []Finding
	for _, f := range e.legacyStateFiles() {
		prompts, history, err := e.legacyProjectFields(f)
		if err != nil {
			out = append(out, info(CheckClaudeLegacy, "could not check "+e.show(f)+" for saved prompts ("+errClass(err)+")", ""))
			continue
		}
		for _, r := range e.o.Cfg.Roots {
			if n := prompts[r.ID]; n > 0 {
				out = append(out, warn(CheckClaudeLegacy, e.show(f)+" still holds the first prompt of "+plural(n, "session", "sessions")+" from "+e.folder(r)+" (lastSessionFirstPrompt), outside the vault",
					"quit Claude, then delete the lastSessionFirstPrompt entries of "+e.folder(r)+" from "+e.show(f)+" (precinto cannot remove them yet)"))
			}
			if n := history[r.ID]; n > 0 {
				out = append(out, warn(CheckClaudeLegacy, e.show(f)+" still holds an old prompt history for "+plural(n, "project", "projects")+" in "+e.folder(r)+", outside the vault",
					"quit Claude, then delete the history entries of "+e.folder(r)+" from "+e.show(f)))
			}
		}
	}
	for _, d := range e.claudeConfigDirs() {
		sm := filepath.Join(d, "session-memory")
		if isDir(sm) {
			out = append(out, warn(CheckClaudeLegacy, e.show(sm)+" holds Claude session memory outside precinto's inventory: it is never sealed",
				"remove "+e.arg(sm)+" while no Claude session runs"))
		}
	}
	if len(out) == 0 && len(e.claudeConfigDirs()) > 0 {
		out = append(out, ok(CheckClaudeLegacy, "no legacy Claude copies of prompts from protected folders were found"))
	}
	return out
}

// legacyProjectFields counts, per root id, the projects of a ~/.claude.json
// file inside that root whose lastSessionFirstPrompt is set and whose old
// per-project prompt history is not empty. Values are never kept.
func (e *env) legacyProjectFields(path string) (prompts, history map[string]int, err error) {
	b, err := readRegular(path, maxStateBytes)
	if err != nil {
		return nil, nil, err
	}
	var top struct {
		Projects map[string]map[string]json.RawMessage `json:"projects"`
	}
	if err := json.Unmarshal(b, &top); err != nil {
		return nil, nil, errInvalidJSON
	}
	prompts, history = map[string]int{}, map[string]int{}
	for p, fields := range top.Projects {
		r, inside := e.rootFor(p, harness.ClaudeCode)
		if !inside {
			continue
		}
		if raw, ok := fields["lastSessionFirstPrompt"]; ok {
			var s string
			if json.Unmarshal(raw, &s) == nil && s != "" {
				prompts[r.ID]++
			}
		}
		if raw, ok := fields["history"]; ok {
			var h []json.RawMessage
			if json.Unmarshal(raw, &h) == nil && len(h) > 0 {
				history[r.ID]++
			}
		}
	}
	return prompts, history, nil
}

func checkHistoryPending(e *env) []Finding {
	var out []Finding
	total := map[string]int{}
	var order []string
	for _, d := range e.claudeConfigDirs() {
		counts, unreadable, err := e.historyCounts(filepath.Join(d, "history.jsonl"))
		if err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				out = append(out, info(CheckHistoryPending, "could not read "+e.show(filepath.Join(d, "history.jsonl"))+" ("+errClass(err)+")", ""))
			}
			continue
		}
		if unreadable > 0 {
			out = append(out, info(CheckHistoryPending, plural(unreadable, "line", "lines")+" of "+e.show(filepath.Join(d, "history.jsonl"))+" could not be attributed to a folder", ""))
		}
		for id, n := range counts {
			if _, seen := total[id]; !seen {
				order = append(order, id)
			}
			total[id] += n
		}
	}
	sort.Strings(order)
	for _, id := range order {
		n := total[id]
		out = append(out, warn(CheckHistoryPending, plural(n, "line", "lines")+" of Claude's prompt history from "+e.folderOf(id)+" "+verb(n, "is", "are")+" still in plaintext: history moves into the vault only while no Claude session runs anywhere (SPEC §19)",
			"quit every Claude session, then run: precinto sweep"))
	}
	if len(out) == 0 && len(e.claudeConfigDirs()) > 0 {
		out = append(out, ok(CheckHistoryPending, "Claude's prompt history holds no lines from protected folders"))
	}
	return out
}

// historyCounts counts the lines of history.jsonl whose project lies in a
// protected folder (D36: the deepest root), with the adapter's line parser.
// Lines are dropped as soon as they are parsed; nothing of them is kept.
func (e *env) historyCounts(path string) (counts map[string]int, unreadable int, err error) {
	f, _, err := openRegular(path)
	if err != nil {
		return nil, 0, err
	}
	defer f.Close()
	counts = map[string]int{}
	r := bufio.NewReaderSize(f, 64<<10)
	for {
		if err := e.ctx.Err(); err != nil {
			return nil, 0, err
		}
		line, tooLong, err := readLine(r, maxHistoryLine)
		if err != nil && !errors.Is(err, io.EOF) {
			return nil, 0, err
		}
		if len(bytes.TrimSpace(line)) > 0 || tooLong {
			if tooLong {
				unreadable++
			} else if hl := e.d.HistoryLine(line); !hl.Valid {
				unreadable++
			} else if root, ok := e.rootFor(hl.Project, harness.ClaudeCode); ok {
				counts[root.ID]++
			}
		}
		if errors.Is(err, io.EOF) {
			return counts, unreadable, nil
		}
	}
}

// readLine returns the next line of r without its newline; a line longer
// than max is consumed and reported as tooLong (its bytes are discarded).
func readLine(r *bufio.Reader, max int) (line []byte, tooLong bool, err error) {
	for {
		chunk, err := r.ReadSlice('\n')
		if !tooLong {
			if len(line)+len(chunk) > max {
				tooLong, line = true, nil
			} else {
				line = append(line, chunk...)
			}
		}
		switch {
		case errors.Is(err, bufio.ErrBufferFull):
			continue
		case err != nil:
			return line, tooLong, err
		}
		return bytes.TrimSuffix(line, []byte("\n")), tooLong, nil
	}
}

// holdLinks reports history hold links (.precinto-hold-<op>) a rotation
// left in a config dir: a hard link to the old history.jsonl, so a copy of
// the history lines (SPEC §7.1.4). One named by a pending journal record
// is finished by the next sweep.
func (e *env) holdLinks(configDir string) []Finding {
	es, err := listDir(configDir)
	if err != nil {
		return nil
	}
	pending, _ := e.journalPending()
	named := map[string]bool{}
	for _, r := range pending {
		if r.Hold != "" {
			named[filepath.Base(r.Hold)] = true
		}
	}
	var out []Finding
	for _, en := range es {
		if !strings.HasPrefix(en.Name(), ".precinto-hold-") {
			continue
		}
		p := filepath.Join(configDir, en.Name())
		if named[en.Name()] {
			out = append(out, info(CheckInterrupted, "an interrupted history rotation left "+e.show(p)+"; the next sweep finishes it", "precinto sweep"))
		} else {
			out = append(out, warn(CheckInterrupted, e.show(p)+" is a leftover copy of Claude's prompt history from an interrupted rotation",
				"run precinto sweep; if it stays, remove "+e.arg(p)+" while no Claude session runs"))
		}
	}
	return out
}

// claudeTmpDirs returns the registered Claude temp dirs and the default one
// of this environment.
func (e *env) claudeTmpDirs() []string {
	var cands []string
	for _, h := range e.o.Cfg.Harness[string(harness.ClaudeCode)].Homes {
		cands = append(cands, h.Tmp)
	}
	if d := e.o.Env.Get("CLAUDE_CODE_TMPDIR"); filepath.IsAbs(d) {
		cands = append(cands, filepath.Clean(d))
	} else if e.d.EUID >= 0 {
		base := "/tmp"
		if e.d.GOOS == "darwin" {
			base = "/private/tmp"
		}
		cands = append(cands, filepath.Join(base, fmt.Sprintf("claude-%d", e.d.EUID)))
	}
	var out []string
	seen := map[string]bool{}
	for _, c := range cands {
		if c == "" || !filepath.IsAbs(c) || seen[c] {
			continue
		}
		seen[c] = true
		out = append(out, filepath.Clean(c))
	}
	return out
}

// codexWrongHomeText renders C9.codexoutside for a finding.
func codexWrongHomeText(n int, folder string) string {
	return catalog(ui.MsgCodexOutside, ui.Vars{N: n, Folder: folder})
}
