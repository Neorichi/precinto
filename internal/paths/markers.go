package paths

import (
	"sort"
	"strings"
)

// Agent-context markers (D6, D7, D28, D56; HOOKS-IO §0.7, §2.3, §3.1, §3.3).
//
// A marker counts when the variable is set, even to an empty value: an
// assignment such as CLAUDECODE= is still evidence of an agent context, and
// every caller treats a marker as a reason to refuse or to ask for fresh
// presence (fail closed). Variables a human sets to configure a harness
// (CLAUDE_CONFIG_DIR, CLAUDE_CODE_TMPDIR, CODEX_HOME, CODEX_SQLITE_HOME,
// API keys) are deliberately not markers: a broad CLAUDE_* or CODEX_* rule
// would refuse init and unlock in the user's own terminal.
var agentMarkerNames = []string{
	// Claude Code hooks and tool commands (HOOKS-IO §2.3, verified 2.1.329;
	// D56): CLAUDECODE=1 is set for hooks and Bash tool commands.
	"CLAUDECODE",
	"CLAUDE_CODE_ENTRYPOINT",
	"CLAUDE_CODE_EXECPATH",
	"CLAUDE_CODE_SESSION_ID",
	"CLAUDE_ENV_FILE",
	EnvClaudePID,
	EnvClaudeProjectDir,
	EnvClaudePluginRoot,
	"CLAUDE_PLUGIN_DATA",

	// Codex 0.154 plugin hooks (verified in the rust-v0.154.0 source):
	// codex-rs/hooks/src/engine/discovery.rs (append_plugin_hook_sources)
	// adds PLUGIN_ROOT, PLUGIN_DATA and their CLAUDE_* aliases to the handler
	// environment; codex-rs/hooks/src/engine/command_runner.rs (build_command)
	// clears the environment and replays the session snapshot
	// (codex-rs/hooks/src/registry.rs, Hooks::new) plus those variables.
	// Hooks configured outside a plugin get no Codex-specific variable.
	EnvPluginRoot,
	"PLUGIN_DATA",

	// Codex 0.154 model shell commands and user shell commands (verified):
	//   - CODEX_THREAD_ID, CODEX_SESSION_ID, CODEX_VERSION:
	//     codex-rs/protocol/src/shell_environment.rs (populate_env, step 6),
	//     codex-rs/core/src/exec_env.rs (inject_session_env),
	//     codex-rs/core/src/unified_exec/process_manager.rs
	//     (open_session_with_sandbox), codex-rs/core/src/tasks/user_shell.rs;
	//   - CODEX_CI=1: codex-rs/core/src/unified_exec/process_manager.rs
	//     (UNIFIED_EXEC_ENV, apply_unified_exec_env);
	//   - CODEX_PERMISSION_PROFILE: codex-rs/core/src/exec_env.rs
	//     (inject_permission_profile_env), when a named profile is active;
	//   - CODEX_SANDBOX=seatbelt and CODEX_SANDBOX_NETWORK_DISABLED=1:
	//     codex-rs/core/src/spawn.rs, codex-rs/core/src/sandboxing/mod.rs;
	//   - CODEX_ESCALATE_SOCKET: codex-rs/core/src/tools/runtimes/zsh_fork/
	//     unix_escalation.rs (zsh-fork escalation).
	"CODEX_CI",
	"CODEX_ESCALATE_SOCKET",
	"CODEX_PERMISSION_PROFILE",
	"CODEX_SANDBOX",
	"CODEX_SANDBOX_NETWORK_DISABLED",
	"CODEX_SESSION_ID",
	"CODEX_THREAD_ID",
	"CODEX_VERSION",

	// Other hosts' hook markers (HOOKS-IO §0.7; plugin-root variables exist
	// only in hook processes) and the hosts named by the AgentMarkers doc.
	"CURSOR_PLUGIN_ROOT",
	"DROID_PLUGIN_ROOT",
	"FACTORY_PROJECT_DIR",
	"GEMINI_SESSION_ID",

	// The wrapper's child and everything it starts (recursion guard).
	EnvActive,
}

// agentMarkerPrefixes are marker families matched by prefix.
var agentMarkerPrefixes = []string{
	"KIMI_",
}

// agentMarkerSet indexes agentMarkerNames.
var agentMarkerSet = func() map[string]bool {
	m := make(map[string]bool, len(agentMarkerNames))
	for _, n := range agentMarkerNames {
		m[n] = true
	}
	return m
}()

// isAgentMarker reports whether name is an agent-context marker.
func isAgentMarker(name string) bool {
	if agentMarkerSet[name] {
		return true
	}
	for _, p := range agentMarkerPrefixes {
		if strings.HasPrefix(name, p) && len(name) > len(p) {
			return true
		}
	}
	return false
}

// agentMarkers implements AgentMarkers: the names of the markers set in e,
// sorted, or nil when there is none.
func agentMarkers(e Env) []string {
	var out []string
	for k := range e.m {
		if isAgentMarker(k) {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// overridesAllowed implements OverridesAllowed for an explicit build flavour
// (D6): a testing build always honours PRECINTO_HOME/PRECINTO_RUNTIME_DIR;
// any other build only with PRECINTO_DEV=1 (exactly "1") and no agent
// marker.
func overridesAllowed(e Env, testing bool) bool {
	if testing {
		return true
	}
	return e.Get(EnvDev) == "1" && len(agentMarkers(e)) == 0
}
