package hook_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/Neorichi/precinto/internal/hook"
	"github.com/Neorichi/precinto/internal/testkit"
	"github.com/Neorichi/precinto/internal/ui"
)

// repo is the repository root seen from internal/hook.
const repo = "../.."

func repoFile(t *testing.T, rel string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(repo, filepath.FromSlash(rel)))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// docBlock returns the ```json block that follows heading in HOOKS-IO.md.
func docBlock(t *testing.T, heading string) []byte {
	t.Helper()
	doc := string(repoFile(t, "docs/HOOKS-IO.md"))
	i := strings.Index(doc, heading)
	if i < 0 {
		t.Fatalf("HOOKS-IO.md has no %q", heading)
	}
	j := strings.Index(doc[i:], "```json\n")
	if j < 0 {
		t.Fatalf("no json block after %q", heading)
	}
	start := i + j + len("```json\n")
	end := strings.Index(doc[start:], "```")
	return []byte(doc[start : start+end])
}

// TestHooksFilesExact: the shipped hooks files are byte for byte the
// normative blocks of HOOKS-IO §2.2 and §3.2.
func TestHooksFilesExact(t *testing.T) {
	for file, heading := range map[string]string{
		"plugin/hooks/hooks.json":        "### 2.2 `plugin/hooks/hooks.json` (exact)",
		"plugins/codex/hooks/codex.json": "### 3.2 `plugins/codex/hooks/codex.json` (exact)",
	} {
		if got, want := repoFile(t, file), docBlock(t, heading); !bytes.Equal(got, want) {
			t.Errorf("%s differs from HOOKS-IO.md (%d vs %d bytes)", file, len(got), len(want))
		}
	}
}

// Mirror of Codex 0.154's HooksFile (codex-rs/config/src/hook_config.rs):
// deny_unknown_fields at the top level, the 12 event names, and only the
// handler keys precinto may use (D61: type, command, timeout, async).
type codexHooksFile struct {
	Description string `json:"description"`
	Hooks       struct {
		PreToolUse        []codexMatcherGroup `json:"PreToolUse"`
		PermissionRequest []codexMatcherGroup `json:"PermissionRequest"`
		PostToolUse       []codexMatcherGroup `json:"PostToolUse"`
		PreCompact        []codexMatcherGroup `json:"PreCompact"`
		PostCompact       []codexMatcherGroup `json:"PostCompact"`
		SessionStart      []codexMatcherGroup `json:"SessionStart"`
		SessionEnd        []codexMatcherGroup `json:"SessionEnd"`
		UserPromptSubmit  []codexMatcherGroup `json:"UserPromptSubmit"`
		SubagentStart     []codexMatcherGroup `json:"SubagentStart"`
		SubagentStop      []codexMatcherGroup `json:"SubagentStop"`
		Stop              []codexMatcherGroup `json:"Stop"`
		Interrupt         []codexMatcherGroup `json:"Interrupt"`
	} `json:"hooks"`
}

type codexMatcherGroup struct {
	Matcher *string              `json:"matcher"`
	Hooks   []codexHookHandlerV1 `json:"hooks"`
}

type codexHookHandlerV1 struct {
	Type    string `json:"type"`
	Command string `json:"command"`
	Timeout *int   `json:"timeout"`
	Async   bool   `json:"async"`
}

// TestCodexHooksFileSchema (HOOK-3, D61).
func TestCodexHooksFileSchema(t *testing.T) {
	raw := repoFile(t, "plugins/codex/hooks/codex.json")
	var f codexHooksFile
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		t.Fatalf("codex.json does not decode as Codex 0.154's HooksFile: %v", err)
	}
	// The mirror itself rejects what Codex would reject.
	for _, bad := range []string{
		`{"hooks":{},"modules":{}}`,
		`{"hooks":{"UserPromptSubmit":[{"hooks":[{"type":"command","command":"x","onFailure":"block"}]}]}}`,
		`{"hooks":{"CwdChanged":[]}}`,
	} {
		d := json.NewDecoder(strings.NewReader(bad))
		d.DisallowUnknownFields()
		var g codexHooksFile
		if d.Decode(&g) == nil {
			t.Errorf("the mirror accepted %s", bad)
		}
	}
}

// hookHandler is a handler of hooks.json or codex.json (generic view).
type hookHandler struct {
	Type      string  `json:"type"`
	Command   string  `json:"command"`
	Timeout   *int    `json:"timeout"`
	Async     bool    `json:"async"`
	OnFailure *string `json:"onFailure"`
}

type hooksFile struct {
	Description string `json:"description"`
	Hooks       map[string][]struct {
		Matcher *string       `json:"matcher"`
		Hooks   []hookHandler `json:"hooks"`
	} `json:"hooks"`
}

func loadHooksFile(t *testing.T, rel string) hooksFile {
	t.Helper()
	var f hooksFile
	dec := json.NewDecoder(bytes.NewReader(repoFile(t, rel)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		t.Fatalf("%s: %v", rel, err)
	}
	return f
}

// TestHooksFilesMatchTimings: every declared timeout is the harness timeout
// of hook.Timings, gate events fail closed on Claude, and every command
// invokes the shim with the right label and event (D22, D61).
func TestHooksFilesMatchTimings(t *testing.T) {
	type check struct {
		file    string
		host    hook.Host
		command func(ev string) string
	}
	for _, c := range []check{
		{"plugin/hooks/hooks.json", hook.HostClaude, func(ev string) string {
			return `sh "${CLAUDE_PLUGIN_ROOT}/scripts/precinto-hook" claude-code ` + ev
		}},
		{"plugins/codex/hooks/codex.json", hook.HostCodex, func(ev string) string {
			return `sh "$PLUGIN_ROOT/scripts/precinto-hook" codex ` + ev
		}},
	} {
		f := loadHooksFile(t, c.file)
		for name, groups := range f.Hooks {
			ev := hook.Event(name)
			if len(groups) != 1 || len(groups[0].Hooks) != 1 {
				t.Errorf("%s %s: want exactly one group with one handler", c.file, name)
				continue
			}
			h := groups[0].Hooks[0]
			tm := hook.Timings(c.host, ev)
			if h.Type != "command" || h.Command != c.command(name) {
				t.Errorf("%s %s: command %q", c.file, name, h.Command)
			}
			switch {
			case h.Async:
				if tm.HarnessTimeout != 0 || h.Timeout != nil {
					t.Errorf("%s %s: async handler with timeout %v / Timings %v", c.file, name, h.Timeout, tm.HarnessTimeout)
				}
			case c.host == hook.HostClaude && ev == hook.SessionEnd:
				// The shared SessionEnd budget: plugin timeouts do not raise it.
				if h.Timeout != nil || tm.HarnessTimeout != 1500*time.Millisecond {
					t.Errorf("%s SessionEnd: timeout %v", c.file, h.Timeout)
				}
			default:
				if h.Timeout == nil || time.Duration(*h.Timeout)*time.Second != tm.HarnessTimeout {
					t.Errorf("%s %s: declared timeout %v, Timings says %v", c.file, name, h.Timeout, tm.HarnessTimeout)
				}
			}
			wantBlock := c.host == hook.HostClaude && hook.IsGate(c.host, ev)
			if gotBlock := h.OnFailure != nil && *h.OnFailure == "block"; gotBlock != wantBlock {
				t.Errorf("%s %s: onFailure %v, want block=%v", c.file, name, h.OnFailure, wantBlock)
			}
			if c.host == hook.HostCodex && (h.OnFailure != nil || strings.Contains(h.Command, "${")) {
				t.Errorf("%s %s: no onFailure and no braces in Codex commands (D61)", c.file, name)
			}
		}
	}
	// Every gate event is registered (HOOKS-IO §2.2, §3.2).
	for _, c := range []struct {
		file string
		host hook.Host
	}{{"plugin/hooks/hooks.json", hook.HostClaude}, {"plugins/codex/hooks/codex.json", hook.HostCodex}} {
		f := loadHooksFile(t, c.file)
		for _, ev := range []string{"UserPromptSubmit", "PreToolUse", "PermissionRequest", "PreCompact", "SessionStart", "SessionEnd"} {
			if _, ok := f.Hooks[ev]; !ok {
				t.Errorf("%s does not register %s", c.file, ev)
			}
		}
	}
}

// TestExperimentalHooksFiles checks the UNVERIFIED Cursor and Copilot drafts
// against hook.Timings and the shim's gate list.
func TestExperimentalHooksFiles(t *testing.T) {
	var cursor struct {
		Version int `json:"version"`
		Hooks   map[string][]struct {
			Command    string `json:"command"`
			Timeout    int    `json:"timeout"`
			FailClosed bool   `json:"failClosed"`
		} `json:"hooks"`
	}
	dec := json.NewDecoder(bytes.NewReader(repoFile(t, "plugin/hooks/cursor.json")))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cursor); err != nil || cursor.Version != 1 {
		t.Fatalf("cursor.json: %v (version %d)", err, cursor.Version)
	}
	for name, hs := range cursor.Hooks {
		ev := hook.ParseEvent(name)
		h := hs[0]
		if h.Command != `sh "${CURSOR_PLUGIN_ROOT}/scripts/precinto-hook" cursor `+name {
			t.Errorf("cursor %s: command %q", name, h.Command)
		}
		tm := hook.Timings(hook.HostCursor, ev)
		if d := time.Duration(h.Timeout) * time.Second; d <= tm.Deadline {
			t.Errorf("cursor %s: timeout %v not above the hook deadline %v", name, d, tm.Deadline)
		}
		if h.FailClosed != hook.IsGate(hook.HostCursor, ev) {
			t.Errorf("cursor %s: failClosed %v", name, h.FailClosed)
		}
	}
	var copilot struct {
		Version int `json:"version"`
		Hooks   map[string][]struct {
			Type       string `json:"type"`
			Bash       string `json:"bash"`
			TimeoutSec int    `json:"timeoutSec"`
		} `json:"hooks"`
	}
	dec = json.NewDecoder(bytes.NewReader(repoFile(t, "plugin/hooks/copilot.json")))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&copilot); err != nil || copilot.Version != 1 {
		t.Fatalf("copilot.json: %v", err)
	}
	for name, hs := range copilot.Hooks {
		h := hs[0]
		ev := hook.ParseEvent(name)
		if h.Type != "command" || h.Bash != "precinto hook copilot "+name {
			t.Errorf("copilot %s: %+v", name, h)
		}
		tm := hook.Timings(hook.HostCopilot, ev)
		if d := time.Duration(h.TimeoutSec) * time.Second; d != tm.HarnessTimeout || d <= tm.Deadline {
			t.Errorf("copilot %s: timeoutSec %d vs Timings %+v", name, h.TimeoutSec, tm)
		}
	}
}

// TestManifests: one manifest per vendor (D41); the Claude manifest keeps
// the default hooks/commands/skills locations; no file Codex can read has a
// "modules" key (HOOKS-IO §2.2).
func TestManifests(t *testing.T) {
	for _, m := range []struct {
		file, hooks string
	}{
		{"plugin/.claude-plugin/plugin.json", ""},
		{"plugin/.cursor-plugin/plugin.json", "./hooks/cursor.json"},
		{"plugin/.github/plugin/plugin.json", "./hooks/copilot.json"},
		{"plugins/codex/.codex-plugin/plugin.json", "./hooks/codex.json"},
	} {
		var v map[string]any
		if err := json.Unmarshal(repoFile(t, m.file), &v); err != nil {
			t.Fatalf("%s: %v", m.file, err)
		}
		if v["name"] != "precinto" || v["version"] == nil || v["description"] == nil {
			t.Errorf("%s: name/version/description %v", m.file, v)
		}
		got, _ := v["hooks"].(string)
		if got != m.hooks {
			t.Errorf("%s: hooks %q, want %q", m.file, got, m.hooks)
		}
		if m.hooks != "" {
			root := filepath.Dir(filepath.Dir(m.file))
			if m.file == "plugin/.github/plugin/plugin.json" {
				root = "plugin"
			}
			if _, err := os.Stat(filepath.Join(repo, root, m.hooks)); err != nil {
				t.Errorf("%s: %v", m.file, err)
			}
		}
		for _, k := range []string{"modules", "commands", "skills", "agents"} {
			if _, ok := v[k]; ok {
				t.Errorf("%s: key %q", m.file, k)
			}
		}
	}
	// The Codex plugin root holds exactly its manifest, hooks file and shim.
	var files []string
	err := filepath.WalkDir(filepath.Join(repo, "plugins/codex"), func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			rel, _ := filepath.Rel(filepath.Join(repo, "plugins/codex"), p)
			files = append(files, filepath.ToSlash(rel))
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(files)
	if want := []string{".codex-plugin/plugin.json", "hooks/codex.json", "scripts/precinto-hook"}; strings.Join(files, ",") != strings.Join(want, ",") {
		t.Errorf("plugins/codex holds %v, want %v", files, want)
	}
}

// TestMarketplaces follows SPEC §21.
func TestMarketplaces(t *testing.T) {
	for file, source := range map[string]string{
		".claude-plugin/marketplace.json":  "./plugin",
		".agents/plugins/marketplace.json": "./plugins/codex",
	} {
		var m struct {
			Name  string `json:"name"`
			Owner struct {
				Name string `json:"name"`
			} `json:"owner"`
			Plugins []struct {
				Name        string `json:"name"`
				Source      string `json:"source"`
				Description string `json:"description"`
			} `json:"plugins"`
		}
		dec := json.NewDecoder(bytes.NewReader(repoFile(t, file)))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&m); err != nil {
			t.Fatalf("%s: %v", file, err)
		}
		if m.Name == "" || m.Owner.Name == "" || len(m.Plugins) != 1 || m.Plugins[0].Name != "precinto" || m.Plugins[0].Source != source {
			t.Errorf("%s: %+v", file, m)
		}
		if st, err := os.Stat(filepath.Join(repo, source)); err != nil || !st.IsDir() {
			t.Errorf("%s: source %s: %v", file, source, err)
		}
	}
}

// TestCommandsAndSkill: lock and status only — an unlock command would be
// a gate bypass (S20) — and a skill that keeps the model away from unlock,
// restore, cat, open and recover and from asking for secrets.
func TestCommandsAndSkill(t *testing.T) {
	entries, err := os.ReadDir(filepath.Join(repo, "plugin/commands"))
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	if strings.Join(names, ",") != "lock.md,status.md" {
		t.Errorf("commands %v, want lock.md and status.md only", names)
	}
	front := regexp.MustCompile(`(?s)\A---\n(.*?)\n---\n`)
	for _, c := range []struct{ file, runs string }{
		{"plugin/commands/lock.md", "precinto lock\n"},
		{"plugin/commands/status.md", "precinto status\n"},
	} {
		b := string(repoFile(t, c.file))
		fm := front.FindStringSubmatch(b)
		if fm == nil || !strings.Contains(fm[1], "description: ") || !strings.Contains(fm[1], "allowed-tools: Bash(") {
			t.Errorf("%s: frontmatter %q", c.file, fm)
		}
		if !strings.Contains(b, "```\n"+c.runs+"```") {
			t.Errorf("%s does not run %q", c.file, c.runs)
		}
		if strings.Contains(fm[1], "unlock") {
			t.Errorf("%s may run precinto unlock", c.file)
		}
	}
	skill := string(repoFile(t, "plugin/skills/precinto/SKILL.md"))
	fm := front.FindStringSubmatch(skill)
	if fm == nil || !strings.Contains(fm[1], "name: precinto") || !strings.Contains(fm[1], "description: ") {
		t.Fatalf("SKILL.md frontmatter %q", fm)
	}
	for _, cmd := range []string{"precinto unlock", "precinto restore", "precinto cat", "precinto open", "precinto recover"} {
		if !strings.Contains(skill, "`"+cmd+"`") {
			t.Errorf("SKILL.md does not name %s", cmd)
		}
	}
	for _, phrase := range []string{"Never run", "Never ask the user to type a password, passphrase, PIN or recovery key in the chat", ".md.precinto"} {
		if !strings.Contains(skill, phrase) {
			t.Errorf("SKILL.md lacks %q", phrase)
		}
	}
	// User-facing vocabulary (SPEC §16.3).
	for _, file := range []string{"plugin/skills/precinto/SKILL.md", "plugin/commands/lock.md", "plugin/commands/status.md"} {
		if m := regexp.MustCompile(`\b(root|grant|soft|hard)\b`).FindString(string(repoFile(t, file))); m != "" {
			t.Errorf("%s uses %q", file, m)
		}
	}
}

// TestShimsIdentical: both shims are the same bytes (HOOKS-IO §5), their
// static text is ui.MsgShimFailed byte for byte, and they never read a
// PRECINTO_* variable (D56).
func TestShimsIdentical(t *testing.T) {
	a := repoFile(t, "plugin/scripts/precinto-hook")
	b := repoFile(t, "plugins/codex/scripts/precinto-hook")
	if !bytes.Equal(a, b) {
		t.Fatal("plugin/scripts/precinto-hook and plugins/codex/scripts/precinto-hook differ")
	}
	m := regexp.MustCompile(`(?m)^msg='([^']*)'$`).FindSubmatch(a)
	if m == nil {
		t.Fatal("the shim has no msg='…' line")
	}
	if want := ui.Format(ui.MsgShimFailed, ui.Vars{}); string(m[1]) != want {
		t.Errorf("shim text %q, want ui.MsgShimFailed %q", m[1], want)
	}
	if regexp.MustCompile(`\$\{?PRECINTO_`).Match(a) {
		t.Error("the shim reads a PRECINTO_* variable")
	}
	for _, f := range []string{"plugin/scripts/precinto-hook", "plugins/codex/scripts/precinto-hook"} {
		st, err := os.Stat(filepath.Join(repo, f))
		if err != nil || st.Mode().Perm()&0o111 == 0 {
			t.Errorf("%s is not executable: %v", f, err)
		}
	}
}

// TestCodexPluginByteStable records the SHA-256 of every file of the Codex
// plugin root (D41, D104): newer Codex versions hash these bytes for hook
// trust (0.154 hashes the hook declarations), so a change must be
// deliberate (update with -update, and re-run E2E-9, D61).
func TestCodexPluginByteStable(t *testing.T) {
	root := filepath.Join(repo, "plugins/codex")
	var lines []string
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(b)
		rel, _ := filepath.Rel(root, p)
		lines = append(lines, fmt.Sprintf("%s  %s", hex.EncodeToString(sum[:]), filepath.ToSlash(rel)))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// WalkDir visits in lexical path order, so the list is sorted by path.
	testkit.Golden(t, "plugins-codex.sha256", []byte(strings.Join(lines, "\n")+"\n"))
}

// TestPluginHygiene: no real path, email, token or non-fixture UUID in the
// shipped plugin files.
func TestPluginHygiene(t *testing.T) {
	for _, d := range []string{"plugin", "plugins", ".claude-plugin", ".agents"} {
		testkit.Hygiene(t, filepath.Join(repo, d))
	}
}
