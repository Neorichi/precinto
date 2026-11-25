package hook_test

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/precinto/precinto/internal/hook"
	"github.com/precinto/precinto/internal/paths"
	"github.com/precinto/precinto/internal/testkit"
)

// writeRegistry writes Claude's live-session registry entry
// <config>/sessions/<pid>.json with the keys Claude Code 2.1.329 writes
// (values synthetic).
func writeRegistry(t *testing.T, config string, pid int, body string) string {
	t.Helper()
	dir := filepath.Join(config, "sessions")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, strconv.Itoa(pid)+".json")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func registryBody(pid int, version string) string {
	return `{"pid":` + strconv.Itoa(pid) + `,"sessionId":"` + sidC + `","cwd":"/u/work/acme","startedAt":1795212335106,` +
		`"procStart":"Thu Nov 20 23:05:34 2026","version":"` + version + `","kind":"interactive","entrypoint":"cli"}`
}

// D103 (L1): Claude Code 2.1.329 sets CLAUDE_CODE_EXECPATH only for its
// Bash-tool processes, never for hooks (0 of 91 captured hook runs); the
// version comes from the `version` key of the registry entry
// <config>/sessions/<CLAUDE_PID>.json that Claude writes for its own
// process before SessionStart. The entry must be a regular file of that
// pid, read without following a symlink, and the value a version string.
func TestDecodeClaudeVersionFromTheRegistry(t *testing.T) {
	config := t.TempDir()
	const pid = 26256
	reg := writeRegistry(t, config, pid, registryBody(pid, "2.1.329"))
	raw := mustJSON(t, map[string]any{
		"session_id": sidC, "cwd": "/u/work/acme", "source": "startup",
		"transcript_path": filepath.Join(config, "projects", "-u-work-acme", sidC+".jsonl"),
	})
	decode := func(env map[string]string) hook.Payload {
		t.Helper()
		p, err := hook.Decode(hook.HostClaude, "claude-code", hook.SessionStart, raw, paths.FromMap(env), nil)
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	env := map[string]string{"HOME": "/u", "CLAUDE_PID": strconv.Itoa(pid), "CLAUDECODE": "1", "CLAUDE_CODE_ENTRYPOINT": "cli"}
	if p := decode(env); p.HarnessVersion != "2.1.329" || p.ConfigDir != config {
		t.Fatalf("version %q (config %q), want 2.1.329 from the registry entry", p.HarnessVersion, p.ConfigDir)
	}
	// CLAUDE_CONFIG_DIR locates the registry when there is no transcript.
	noTranscript := mustJSON(t, map[string]any{"session_id": sidC, "cwd": "/u/work/acme"})
	p, err := hook.Decode(hook.HostClaude, "claude-code", hook.UserPromptSubmit, noTranscript,
		paths.FromMap(map[string]string{"HOME": "/u", "CLAUDE_PID": strconv.Itoa(pid), "CLAUDE_CONFIG_DIR": config}), nil)
	if err != nil || p.HarnessVersion != "2.1.329" {
		t.Fatalf("CLAUDE_CONFIG_DIR: version %q, %v", p.HarnessVersion, err)
	}

	// Nothing that is not this process's own entry with a version string
	// gives a version.
	for name, body := range map[string]string{
		"another pid":       registryBody(pid+1, "2.1.329"),
		"not a version":     registryBody(pid, "2.1.329; rm -rf"),
		"an empty version":  registryBody(pid, ""),
		"a version object":  `{"pid":` + strconv.Itoa(pid) + `,"version":{"VERSION":"2.1.329"}}`,
		"not JSON":          "2.1.329",
		"a too long string": registryBody(pid, strings.Repeat("1.", 40)+"1"),
	} {
		if err := os.WriteFile(reg, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if p := decode(env); p.HarnessVersion != "" {
			t.Errorf("%s: version %q", name, p.HarnessVersion)
		}
	}
	// A symlinked or special entry is never read (no FIFO hang either).
	if err := os.Remove(reg); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "elsewhere.json")
	if err := os.WriteFile(target, []byte(registryBody(pid, "2.1.329")), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, reg); err != nil {
		t.Fatal(err)
	}
	if p := decode(env); p.HarnessVersion != "" {
		t.Errorf("symlinked registry entry read: version %q", p.HarnessVersion)
	}
	if err := os.Remove(reg); err != nil {
		t.Fatal(err)
	}
	if err := testkit.Mkfifo(reg, 0o600); err != nil {
		t.Fatal(err)
	}
	if p := decode(env); p.HarnessVersion != "" {
		t.Errorf("FIFO registry entry: version %q", p.HarnessVersion)
	}
	// Without CLAUDE_PID there is no entry to read; CLAUDE_CODE_EXECPATH
	// (a Bash-tool process) still names the version by its basename.
	if p := decode(map[string]string{"HOME": "/u", "CLAUDECODE": "1"}); p.HarnessVersion != "" {
		t.Errorf("no CLAUDE_PID: version %q", p.HarnessVersion)
	}
	if p := decode(map[string]string{"HOME": "/u", "CLAUDECODE": "1", "CLAUDE_CODE_EXECPATH": "/u/.local/share/claude/versions/2.1.329"}); p.HarnessVersion != "2.1.329" {
		t.Errorf("CLAUDE_CODE_EXECPATH: version %q", p.HarnessVersion)
	}
	// Another host never reads Claude's registry.
	if err := os.Remove(reg); err != nil {
		t.Fatal(err)
	}
	writeRegistry(t, config, pid, registryBody(pid, "2.1.329"))
	if p, err := hook.Decode(hook.HostCursor, "cursor", hook.SessionStart, raw, paths.FromMap(env), nil); err != nil || p.HarnessVersion != "" {
		t.Errorf("cursor: version %q, %v", p.HarnessVersion, err)
	}
}
