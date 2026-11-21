package paths_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/precinto/precinto/internal/paths"
)

func TestAgentMarkers(t *testing.T) {
	for _, c := range []struct {
		name string
		env  map[string]string
		want []string
	}{
		{name: "empty", env: nil, want: nil},
		{
			// What a human's own shell may carry: harness configuration is
			// never evidence of an agent context.
			name: "user configuration only",
			env: map[string]string{
				"HOME": "/u", "PATH": "/usr/bin:/bin", "SHELL": "/bin/zsh", "TERM": "xterm-256color",
				paths.EnvClaudeConfigDir: "/u/.claude", paths.EnvClaudeTmpDir: "/u/tmp",
				paths.EnvCodexHome: "/u/.codex", paths.EnvCodexSQLiteHome: "/u/.codex",
				"ANTHROPIC_API_KEY": "x", "OPENAI_API_KEY": "x", "CLAUDE_CODE_USE_BEDROCK": "1",
				paths.EnvDev: "1", paths.EnvHome: "/b", paths.EnvRuntimeDir: "/r",
				"KIMI_": "not a family member", "MY_PLUGIN_ROOT_DIR": "/x",
			},
			want: nil,
		},
		{
			name: "claude hook",
			env: map[string]string{
				paths.EnvClaudeCode: "1", paths.EnvClaudeProjectDir: "/u/work/acme",
				paths.EnvClaudePID: "4242", paths.EnvClaudePluginRoot: "/u/.claude/plugins/p",
				"CLAUDE_CODE_SESSION_ID": "s", "CLAUDE_CODE_ENTRYPOINT": "cli", "CLAUDE_CODE_EXECPATH": "/x/2.1.329",
				paths.EnvClaudeConfigDir: "/u/.claude",
			},
			want: []string{"CLAUDECODE", "CLAUDE_CODE_ENTRYPOINT", "CLAUDE_CODE_EXECPATH", "CLAUDE_CODE_SESSION_ID",
				"CLAUDE_PID", "CLAUDE_PLUGIN_ROOT", "CLAUDE_PROJECT_DIR"},
		},
		{
			// PreToolUse/PreCompact/PermissionRequest never carry CLAUDE_PID
			// (D56): CLAUDE_PROJECT_DIR alone is enough.
			name: "claude gate hook without CLAUDE_PID",
			env:  map[string]string{paths.EnvClaudeProjectDir: "/u/work/acme"},
			want: []string{"CLAUDE_PROJECT_DIR"},
		},
		{
			name: "codex plugin hook",
			env: map[string]string{
				paths.EnvPluginRoot: "/u/.codex/plugins/p", "PLUGIN_DATA": "/u/.codex/plugins/data/p",
				paths.EnvClaudePluginRoot: "/u/.codex/plugins/p", "CLAUDE_PLUGIN_DATA": "/u/.codex/plugins/data/p",
				paths.EnvCodexHome: "/b/homes/codex/root-acme",
			},
			want: []string{"CLAUDE_PLUGIN_DATA", "CLAUDE_PLUGIN_ROOT", "PLUGIN_DATA", "PLUGIN_ROOT"},
		},
		{
			name: "codex shell tool",
			env: map[string]string{
				"CODEX_THREAD_ID": "t", "CODEX_SESSION_ID": "s", "CODEX_VERSION": "0.154.0", "CODEX_CI": "1",
				"CODEX_SANDBOX": "seatbelt", "CODEX_SANDBOX_NETWORK_DISABLED": "1",
				"CODEX_PERMISSION_PROFILE": "p", "CODEX_ESCALATE_SOCKET": "3",
				"NO_COLOR": "1", "TERM": "dumb", "PAGER": "cat", paths.EnvCodexHome: "/u/.codex",
			},
			want: []string{"CODEX_CI", "CODEX_ESCALATE_SOCKET", "CODEX_PERMISSION_PROFILE", "CODEX_SANDBOX",
				"CODEX_SANDBOX_NETWORK_DISABLED", "CODEX_SESSION_ID", "CODEX_THREAD_ID", "CODEX_VERSION"},
		},
		{
			name: "codex user shell command",
			env:  map[string]string{"CODEX_THREAD_ID": "t"},
			want: []string{"CODEX_THREAD_ID"},
		},
		{
			name: "other hosts and the wrapper",
			env: map[string]string{
				"KIMI_SESSION": "k", "KIMI_CLI": "1", "GEMINI_SESSION_ID": "g", "CURSOR_PLUGIN_ROOT": "/c",
				"DROID_PLUGIN_ROOT": "/d", "FACTORY_PROJECT_DIR": "/f", paths.EnvActive: "1",
			},
			want: []string{"CURSOR_PLUGIN_ROOT", "DROID_PLUGIN_ROOT", "FACTORY_PROJECT_DIR", "GEMINI_SESSION_ID",
				"KIMI_CLI", "KIMI_SESSION", "PRECINTO_ACTIVE"},
		},
		{
			// Set but empty still counts (fail closed).
			name: "empty values",
			env:  map[string]string{paths.EnvClaudeCode: "", "CODEX_THREAD_ID": ""},
			want: []string{"CLAUDECODE", "CODEX_THREAD_ID"},
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			got := paths.AgentMarkers(paths.FromMap(c.env))
			if !slices.Equal(got, c.want) {
				t.Errorf("AgentMarkers = %q, want %q", got, c.want)
			}
		})
	}
}

// TestAgentMarkersDocumented checks every marker the AgentMarkers doc comment
// names, one at a time.
func TestAgentMarkersDocumented(t *testing.T) {
	for _, name := range []string{
		"CLAUDECODE", "CLAUDE_CODE_ENTRYPOINT", "CLAUDE_CODE_SESSION_ID", "CLAUDE_PID",
		"CODEX_THREAD_ID", "KIMI_SESSION_ID", "GEMINI_SESSION_ID", "PRECINTO_ACTIVE",
		paths.EnvClaudeProjectDir, paths.EnvPluginRoot, paths.EnvClaudePluginRoot,
	} {
		got := paths.AgentMarkers(paths.FromMap(map[string]string{name: "1", "HOME": "/u"}))
		if !slices.Equal(got, []string{name}) {
			t.Errorf("AgentMarkers({%s}) = %q", name, got)
		}
	}
}

func TestAgentMarkersSortedAndFromEnviron(t *testing.T) {
	e := paths.FromEnviron([]string{"PRECINTO_ACTIVE=1", "CODEX_THREAD_ID=t", "CLAUDECODE=1", "CLAUDECODE=1", "PATH=/bin"})
	got := paths.AgentMarkers(e)
	if !slices.IsSorted(got) || strings.Join(got, ",") != "CLAUDECODE,CODEX_THREAD_ID,PRECINTO_ACTIVE" {
		t.Errorf("AgentMarkers = %q", got)
	}
	// The result is a fresh slice: callers may modify it.
	got[0] = "changed"
	if again := paths.AgentMarkers(e); again[0] != "CLAUDECODE" {
		t.Errorf("AgentMarkers shares state: %q", again)
	}
}

func TestOverridesAllowed(t *testing.T) {
	for _, c := range []struct {
		name string
		env  map[string]string
		dev  bool // the PRECINTO_DEV rule alone
	}{
		{"nothing", map[string]string{"HOME": "/u"}, false},
		{"dev", map[string]string{paths.EnvDev: "1"}, true},
		{"dev not exactly 1", map[string]string{paths.EnvDev: "true"}, false},
		{"dev empty", map[string]string{paths.EnvDev: ""}, false},
		{"dev in claude", map[string]string{paths.EnvDev: "1", paths.EnvClaudeCode: "1"}, false},
		{"dev in a claude gate hook", map[string]string{paths.EnvDev: "1", paths.EnvClaudeProjectDir: "/u/w"}, false},
		{"dev in a codex hook", map[string]string{paths.EnvDev: "1", paths.EnvPluginRoot: "/p"}, false},
		{"dev in a codex tool", map[string]string{paths.EnvDev: "1", "CODEX_THREAD_ID": "t"}, false},
		{"dev in the wrapper", map[string]string{paths.EnvDev: "1", paths.EnvActive: "1"}, false},
	} {
		want := paths.TestingBuild() || c.dev
		if got := paths.OverridesAllowed(paths.FromMap(c.env)); got != want {
			t.Errorf("%s: OverridesAllowed = %v, want %v (testing build %v)", c.name, got, want, paths.TestingBuild())
		}
	}
}
