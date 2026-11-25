package doctor_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Neorichi/precinto/internal/config"
	"github.com/Neorichi/precinto/internal/doctor"
	"github.com/Neorichi/precinto/internal/harness/claude/claudetest"
	"github.com/Neorichi/precinto/internal/paths"
	"github.com/Neorichi/precinto/internal/platform"
	"github.com/Neorichi/precinto/internal/sweep/journal"
	"github.com/Neorichi/precinto/internal/testkit"
)

// nativeClaude installs a fake native Claude (…/claude/versions/<v>, with
// bin/claude linking to it) and puts its bin directory first on PATH.
func (f *fixture) nativeClaude(v string) string {
	f.t.Helper()
	dir := filepath.Join(f.h.Dir, "install-"+v)
	exe := writeFile(f.t, filepath.Join(dir, "share", "claude", "versions", v), "#!/bin/sh\n", 0o700)
	bin := mkdir(f.t, filepath.Join(dir, "bin"), 0o700)
	if err := os.Symlink(exe, filepath.Join(bin, "claude")); err != nil {
		f.t.Fatal(err)
	}
	f.setEnv("PATH", bin+":/usr/bin:/bin")
	return exe
}

func TestClaudeVersion(t *testing.T) {
	f := newFixture(t)
	f.nativeClaude("2.1.100")
	got := want(t, f.run(), doctor.CheckClaudeVersion, doctor.Fail, "Claude Code 2.1.100 is older than 2.1.295")
	if got.Fix != "claude update" {
		t.Errorf("fix %q", got.Fix)
	}

	f = newFixture(t)
	f.nativeClaude("2.1.329")
	want(t, f.run(), doctor.CheckClaudeVersion, doctor.OK, "2.1.329")

	f = newFixture(t)
	f.nativeClaude("2.1.400")
	want(t, f.run(), doctor.CheckClaudeVersion, doctor.Info, "newer than the versions precinto was verified with")

	// A configured min_version above the contract floor wins.
	f = newFixture(t)
	f.nativeClaude("2.1.300")
	cc := f.o.Cfg.Harness["claude-code"]
	cc.MinVersion = "2.1.320"
	f.o.Cfg.Harness = map[string]config.Harness{"claude-code": cc, "codex": f.o.Cfg.Harness["codex"]}
	want(t, f.run(), doctor.CheckClaudeVersion, doctor.Fail, "2.1.300 is older than 2.1.320")

	// npm install: the version comes from the package's package.json.
	f = newFixture(t)
	pkg := filepath.Join(f.h.Dir, "npm", "lib", "node_modules", "@anthropic-ai", "claude-code")
	cli := writeFile(t, filepath.Join(pkg, "cli.js"), "#!/usr/bin/env node\n", 0o700)
	writeJSON(t, filepath.Join(pkg, "package.json"), map[string]string{"name": "@anthropic-ai/claude-code", "version": "2.1.310"})
	bin := mkdir(t, filepath.Join(f.h.Dir, "npm", "bin"), 0o700)
	if err := os.Symlink(cli, filepath.Join(bin, "claude")); err != nil {
		t.Fatal(err)
	}
	f.setEnv("PATH", bin)
	want(t, f.run(), doctor.CheckClaudeVersion, doctor.OK, "2.1.310")

	// A binary whose version cannot be told.
	f = newFixture(t)
	plain := mkdir(t, filepath.Join(f.h.Dir, "plain"), 0o700)
	writeFile(t, filepath.Join(plain, "claude"), "#!/bin/sh\n", 0o700)
	f.setEnv("PATH", plain)
	want(t, f.run(), doctor.CheckClaudeVersion, doctor.Info, "could not tell the version")

	// A running session of an old version (its kernel name is the version).
	f = newFixture(t)
	f.nativeClaude("2.1.329")
	f.h.Procs.Add(platform.ProcInfo{ID: platform.ProcID{PID: 4100, StartUS: 1}, PPID: 1,
		Exe: "/opt/claude/versions/2.1.200", Comm: "2.1.200", Argv: []string{"claude"}})
	want(t, f.run(), doctor.CheckClaudeVersion, doctor.Fail, "pid 4100", "2.1.200")

	// No Claude here at all: nothing to check.
	f = newFixture(t)
	f.o.Cfg.Harness = map[string]config.Harness{"claude-code": {Enabled: true, MinVersion: "2.1.295"}, "codex": f.o.Cfg.Harness["codex"]}
	f.setEnv("CLAUDE_CONFIG_DIR", filepath.Join(f.h.Dir, "no-claude"))
	none(t, f.run(), doctor.CheckClaudeVersion)
}

func TestClaudePlugin(t *testing.T) {
	f := newFixture(t)
	got := want(t, f.run(), doctor.CheckClaudePlugin, doctor.Fail, "is not installed")
	if got.Fix != "precinto integrate claude-code" {
		t.Errorf("fix %q", got.Fix)
	}

	f.installClaudePlugin()
	want(t, f.run(), doctor.CheckClaudePlugin, doctor.OK)

	// Disabled at user level (a local file overriding the shared one).
	writeJSON(t, filepath.Join(f.h.ClaudeConfig, "settings.local.json"), map[string]any{"enabledPlugins": map[string]bool{paths.ClaudePluginID: false}})
	want(t, f.run(), doctor.CheckClaudePlugin, doctor.Fail, "is disabled in")

	// Installed but not enabled anywhere.
	g := newFixture(t)
	g.installClaudePlugin()
	writeJSON(t, filepath.Join(g.h.ClaudeConfig, "settings.json"), map[string]any{"enabledPlugins": map[string]bool{"other@x": true}})
	want(t, g.run(), doctor.CheckClaudePlugin, doctor.Warn, "installed", "not enabled")

	// Only exactly paths.ClaudePluginID is precinto's plugin (CC-37): a
	// precinto plugin of another marketplace, installed and enabled, is not.
	h := newFixture(t)
	other := "precinto@elsewhere"
	writeJSON(t, filepath.Join(h.h.ClaudeConfig, "plugins", "installed_plugins.json"), map[string]any{
		"version": 2,
		"plugins": map[string]any{other: []any{map[string]any{"scope": "user", "version": "0.2.0"}}},
	})
	writeJSON(t, filepath.Join(h.h.ClaudeConfig, "settings.json"), map[string]any{"enabledPlugins": map[string]bool{other: true, "x" + paths.ClaudePluginID: true}})
	want(t, h.run(), doctor.CheckClaudePlugin, doctor.Fail, "is not installed")
}

func TestClaudeHooksOff(t *testing.T) {
	f := newFixture(t)
	want(t, f.run(), doctor.CheckClaudeHooksOff, doctor.OK)

	local := writeJSON(t, filepath.Join(f.h.Root, ".claude", "settings.local.json"), map[string]any{"disableAllHooks": true})
	// Only paths.ClaudePluginID is precinto's plugin (CC-37): a same-named
	// plugin of another marketplace is not.
	shared := writeJSON(t, filepath.Join(f.h.Root, ".claude", "settings.json"), map[string]any{"enabledPlugins": map[string]bool{paths.ClaudePluginID: false, "precinto@elsewhere": false}})
	user := writeJSON(t, filepath.Join(f.h.ClaudeConfig, "settings.json"), map[string]any{"disableAllHooks": true})
	fs := f.run()
	want(t, fs, doctor.CheckClaudeHooksOff, doctor.Fail, f.tilde(local)+" turns off every hook", f.tilde(f.h.Root))
	got := want(t, fs, doctor.CheckClaudeHooksOff, doctor.Fail, f.tilde(shared)+" disables precinto's plugin ("+paths.ClaudePluginID+")")
	if strings.Contains(got.Message, "precinto@elsewhere") {
		t.Errorf("another marketplace's plugin counted as precinto's: %s", got.Message)
	}
	want(t, fs, doctor.CheckClaudeHooksOff, doctor.Fail, f.tilde(user)+" turns off every hook")

	// disableAllHooks false is fine.
	writeJSON(t, local, map[string]any{"disableAllHooks": false})
	for _, x := range of(f.run(), doctor.CheckClaudeHooksOff) {
		if strings.Contains(x.Message, f.tilde(local)) {
			t.Errorf("disableAllHooks=false reported: %q", x.Message)
		}
	}
}

// TestClaudeSettingsInSubfolders (FX-G7sup-06, SPEC §16.1): a session
// started in a subfolder reads that subfolder's .claude settings, so they
// are scanned up to 4 levels below the folder, skipping .git, node_modules
// and vendor and never following a symlinked directory. A nested
// protected folder's files are reported under that folder only (D36).
func TestClaudeSettingsInSubfolders(t *testing.T) {
	f := newFixture(t)
	off := map[string]any{"disableAllHooks": true}
	app := writeJSON(t, filepath.Join(f.h.Root, "app", ".claude", "settings.local.json"), off)
	deep := writeJSON(t, filepath.Join(f.h.Root, "a", "b", "c", "d", ".claude", "settings.json"), map[string]any{"env": map[string]string{"PRECINTO_BIN": "x"}})
	tooDeep := writeJSON(t, filepath.Join(f.h.Root, "a", "b", "c", "d", "e", ".claude", "settings.json"), off)
	var skipped []string
	for _, d := range []string{"node_modules", ".git", "vendor"} {
		skipped = append(skipped, writeJSON(t, filepath.Join(f.h.Root, d, "pkg", ".claude", "settings.json"), off))
	}
	elsewhere := writeJSON(t, filepath.Join(f.h.Dir, "elsewhere", "proj", ".claude", "settings.json"), off)
	if err := os.Symlink(filepath.Join(f.h.Dir, "elsewhere"), filepath.Join(f.h.Root, "link")); err != nil {
		t.Fatal(err)
	}
	// A linked .claude of a subfolder is read, as Claude reads it.
	linked := writeJSON(t, filepath.Join(f.h.Dir, "dotfiles", "claude", "settings.json"), off)
	mkdir(t, filepath.Join(f.h.Root, "tool"), 0o700)
	if err := os.Symlink(filepath.Dir(linked), filepath.Join(f.h.Root, "tool", ".claude")); err != nil {
		t.Fatal(err)
	}
	inner := f.h.Protect(t, "work/acme/inner")
	f.o.Cfg = f.h.Cfg
	innerFile := writeJSON(t, filepath.Join(inner.Path, ".claude", "settings.local.json"), off)

	fs := f.run()
	folder := f.tilde(f.h.Root)
	want(t, fs, doctor.CheckClaudeHooksOff, doctor.Fail, f.tilde(app)+" turns off every hook", "in "+folder+" cannot")
	want(t, fs, doctor.CheckClaudeHooksOff, doctor.Fail, f.tilde(filepath.Join(f.h.Root, "tool", ".claude", "settings.json"))+" turns off every hook")
	want(t, fs, doctor.CheckClaudeSettingsEnv, doctor.Fail, f.tilde(deep)+" sets PRECINTO_BIN in env")
	got := want(t, fs, doctor.CheckClaudeHooksOff, doctor.Fail, f.tilde(innerFile))
	if !strings.Contains(got.Message, "in "+f.tilde(inner.Path)+" cannot") {
		t.Errorf("a nested folder's file is not reported under that folder: %q", got.Message)
	}
	n := 0
	for _, x := range of(fs, doctor.CheckClaudeHooksOff) {
		if strings.Contains(x.Message, f.tilde(innerFile)) {
			n++
		}
		for _, p := range append(skipped, tooDeep, elsewhere, filepath.Join(f.h.Root, "link", "proj", ".claude", "settings.json")) {
			if strings.Contains(x.Message, f.tilde(p)+" ") {
				t.Errorf("%s reported: %q", p, x.Message)
			}
		}
	}
	if n != 1 {
		t.Errorf("the nested folder's file was reported %d times", n)
	}
}

func TestClaudeSettingsDrift(t *testing.T) {
	f := newFixture(t)
	none(t, f.run(), doctor.CheckClaudeSettings) // no folder uses protect --claude-settings
	f.o.Cfg.Roots[0].ClaudeSettings = true
	writeFile(t, filepath.Join(f.h.Root, ".claude", "settings.json"), claudeSettingsJSON, 0o644)
	want(t, f.run(), doctor.CheckClaudeSettings, doctor.OK)

	// The local file turns idle compaction back on; another key vanished.
	writeJSON(t, filepath.Join(f.h.Root, ".claude", "settings.local.json"), map[string]any{"idleCompaction": true})
	writeFile(t, filepath.Join(f.h.Root, ".claude", "settings.json"), `{"idleCompaction":false,"awaySummaryEnabled":false}`, 0o644)
	got := want(t, f.run(), doctor.CheckClaudeSettings, doctor.Warn, "idleCompaction, precomputeCompactionEnabled")
	if !strings.Contains(got.Fix, "precinto protect "+f.tilde(f.h.Root)+" --claude-settings") {
		t.Errorf("fix %q", got.Fix)
	}
}

// TestClaudeSettingsEnv is the doctor side of TESTPLAN SEC-31 and D56:
// PRECINTO_*, HOME, XDG_*, PATH, DYLD_* and LD_* in the env of any Claude
// settings file are reported, by key name only.
func TestClaudeSettingsEnv(t *testing.T) {
	f := newFixture(t)
	fake := filepath.Join(f.h.Dir, testkit.Marker(t))
	f.secret(fake)
	local := writeJSON(t, filepath.Join(f.h.Root, ".claude", "settings.local.json"), map[string]any{
		"env": map[string]string{"PRECINTO_DEV": "1", "PRECINTO_BIN": fake, "PRECINTO_HOME": fake, "EDITOR": "vi"},
	})
	value := testkit.Marker(t)
	f.secret(value)
	user := writeJSON(t, filepath.Join(f.h.ClaudeConfig, "settings.json"), map[string]any{
		"env": map[string]string{"PATH": value, "HOME": value, "XDG_DATA_HOME": value, "LD_PRELOAD": value,
			"DYLD_INSERT_LIBRARIES": value, "HOMEBREW_PREFIX": value, "path": value, "PRECINTOX": value, "MY_PATH": value},
	})
	fs := f.run()
	got := want(t, fs, doctor.CheckClaudeSettingsEnv, doctor.Fail, f.tilde(local)+" sets PRECINTO_BIN, PRECINTO_DEV, PRECINTO_HOME in env")
	if !strings.Contains(got.Fix, f.tilde(local)) || strings.Contains(got.Message, "EDITOR") {
		t.Errorf("finding %+v", got)
	}
	got = want(t, fs, doctor.CheckClaudeSettingsEnv, doctor.Fail, f.tilde(user)+" sets DYLD_INSERT_LIBRARIES, HOME, LD_PRELOAD, PATH, XDG_DATA_HOME in env")
	for _, benign := range []string{"HOMEBREW_PREFIX", "PRECINTOX", "MY_PATH", "path,"} {
		if strings.Contains(got.Message, benign) {
			t.Errorf("%s flagged: %q", benign, got.Message)
		}
	}

	// D92: other hosts' markers in settings env change how hooks detect
	// their host.
	hosts := writeJSON(t, filepath.Join(f.h.Root, ".claude", "settings.json"), map[string]any{
		"env": map[string]string{"COPILOT_X": "1", "CURSOR_VERSION": "2", "DROID_PLUGIN_ROOT": "/d", "FACTORY_PROJECT_DIR": "/f", "PLUGIN_ROOT": "/p"},
	})
	want(t, f.run(), doctor.CheckClaudeSettingsEnv, doctor.Fail, f.tilde(hosts)+" sets COPILOT_X, CURSOR_VERSION, DROID_PLUGIN_ROOT, FACTORY_PROJECT_DIR, PLUGIN_ROOT in env")
	if err := os.Remove(hosts); err != nil {
		t.Fatal(err)
	}

	// A file that is not JSON cannot be checked: say so.
	bad := writeFile(t, filepath.Join(f.h.Root, ".claude", "settings.other.json"), "{not json", 0o600)
	want(t, f.run(), doctor.CheckClaudeSettingsEnv, doctor.Warn, "could not read "+f.tilde(bad), "invalid JSON")

	// A FIFO planted as a settings file never blocks doctor.
	g := newFixture(t)
	fifo := filepath.Join(g.h.Root, ".claude", "settings.local.json")
	mkdir(t, filepath.Dir(fifo), 0o700)
	if err := testkit.Mkfifo(fifo, 0o600); err != nil {
		t.Skip("mkfifo:", err)
	}
	done := make(chan []doctor.Finding, 1)
	go func() {
		fs, _ := doctor.RunWith(context.Background(), g.o, g.d)
		done <- fs
	}()
	select {
	case fs := <-done:
		want(t, fs, doctor.CheckClaudeSettingsEnv, doctor.Warn, "not a regular file")
	case <-time.After(20 * time.Second):
		t.Fatal("doctor blocked on a FIFO settings file")
	}
}

func TestClaudeRetention(t *testing.T) {
	f := newFixture(t)
	want(t, f.run(), doctor.CheckClaudeRetention, doctor.Info, "older than 30 days", "up to 28 days old")
	f.d.CleanupPeriodDays = func(string) (int, error) { return 2, nil }
	got := want(t, f.run(), doctor.CheckClaudeRetention, doctor.Warn, "older than 2 days")
	if !strings.Contains(got.Fix, "cleanupPeriodDays") {
		t.Errorf("fix %q", got.Fix)
	}
	f.d.CleanupPeriodDays = func(string) (int, error) { return 0, errors.New("bad settings") }
	want(t, f.run(), doctor.CheckClaudeRetention, doctor.Info, "could not read cleanupPeriodDays")
}

func TestClaudeLegacy(t *testing.T) {
	f := newFixture(t)
	want(t, f.run(), doctor.CheckClaudeLegacy, doctor.OK)
	prompt := testkit.Marker(t)
	f.secret(prompt)
	state := map[string]any{"projects": map[string]any{
		filepath.Join(f.h.Root, "app"): map[string]any{"lastSessionFirstPrompt": prompt, "history": []any{map[string]string{"display": prompt}}},
		f.h.Root:                       map[string]any{"lastSessionFirstPrompt": "", "history": []any{}},
		filepath.Join(f.h.Dir, "else"): map[string]any{"lastSessionFirstPrompt": prompt},
	}}
	home := writeJSON(t, filepath.Join(f.h.HomeDir, ".claude.json"), state)
	backup := writeJSON(t, filepath.Join(f.h.ClaudeConfig, "backups", ".claude.json.backup.1763715600000"), state)
	fs := f.run()
	folder := f.tilde(f.h.Root)
	want(t, fs, doctor.CheckClaudeLegacy, doctor.Warn, f.tilde(home)+" still holds the first prompt of 1 session from "+folder)
	want(t, fs, doctor.CheckClaudeLegacy, doctor.Warn, f.tilde(home)+" still holds an old prompt history for 1 project in "+folder)
	want(t, fs, doctor.CheckClaudeLegacy, doctor.Warn, f.tilde(backup)+" still holds the first prompt")

	sm := mkdir(t, filepath.Join(f.h.ClaudeConfig, "session-memory"), 0o700)
	want(t, f.run(), doctor.CheckClaudeLegacy, doctor.Warn, f.tilde(sm)+" holds Claude session memory")

	writeFile(t, home, "{oops", 0o600)
	want(t, f.run(), doctor.CheckClaudeLegacy, doctor.Info, "could not check "+f.tilde(home))
}

func TestHistoryPending(t *testing.T) {
	f := newFixture(t)
	want(t, f.run(), doctor.CheckHistoryPending, doctor.OK)

	l := claudetest.New(t, f.h.Dir) // ConfigDir is the fake home's CLAUDE_CONFIG_DIR
	if l.ConfigDir != f.h.ClaudeConfig {
		t.Fatalf("claudetest config dir %s, fake home %s", l.ConfigDir, f.h.ClaudeConfig)
	}
	marker := testkit.Marker(t)
	f.secret(marker)
	l.WriteHistory(t, filepath.Join(f.h.Root, "app"), "00000000-0000-4000-8000-000000000001", 3, marker)
	l.WriteHistory(t, filepath.Join(f.h.Dir, "elsewhere"), "00000000-0000-4000-8000-000000000002", 2, marker)
	hist := filepath.Join(f.h.ClaudeConfig, "history.jsonl")
	af, err := os.OpenFile(hist, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	af.WriteString("not json at all\n\n")
	af.Close()
	fs := f.run()
	got := want(t, fs, doctor.CheckHistoryPending, doctor.Warn, "3 lines of Claude's prompt history from "+f.tilde(f.h.Root))
	if got.Fix != "quit every Claude session, then run: precinto sweep" {
		t.Errorf("fix %q", got.Fix)
	}
	want(t, fs, doctor.CheckHistoryPending, doctor.Info, "1 line of")

	// A hold link left by an interrupted rotation: a copy of the history.
	hold := filepath.Join(f.h.ClaudeConfig, ".precinto-hold-0001")
	if err := os.Link(hist, hold); err != nil {
		t.Fatal(err)
	}
	want(t, f.run(), doctor.CheckInterrupted, doctor.Warn, f.tilde(hold)+" is a leftover copy")
	mkdir(t, f.h.Layout.JournalDir, 0o700)
	f.d.JournalPending = func() ([]*journal.Record, error) {
		return []*journal.Record{{ID: "0001", Kind: journal.KindHistoryRotate, Phase: journal.PhaseHeld, Hold: ".precinto-hold-0001"}}, nil
	}
	want(t, f.run(), doctor.CheckInterrupted, doctor.Info, "the next sweep finishes it")
}
