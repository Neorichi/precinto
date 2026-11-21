package hook

import (
	"bytes"
	"encoding/json"

	"github.com/precinto/precinto/internal/paths"
)

// Host markers in the hook environment (HOOKS-IO §0.7, D56, D92). Codex
// sets PLUGIN_ROOT (and the CLAUDE_PLUGIN_ROOT alias) for plugin hooks;
// Claude sets only CLAUDE_PLUGIN_ROOT, plus CLAUDECODE=1 and usually
// CLAUDE_PID. Both pass the user's whole environment to hooks, so another
// host's variables (CURSOR_*, COPILOT_*, DROID_*, FACTORY_*) are often
// merely inherited: they only break ties when neither Claude's nor
// Codex's markers are there, by exact name.
const (
	envCursorVersion    = "CURSOR_VERSION"
	envCursorPluginRoot = "CURSOR_PLUGIN_ROOT"
	envDroidPluginRoot  = "DROID_PLUGIN_ROOT"
	envFactoryProject   = "FACTORY_PROJECT_DIR"
)

// labelHosts are the argv labels precinto's hooks files pass (HOOKS-IO
// §0.7 step 4): hooks.json says claude-code (Droid reads it too),
// codex.json codex, cursor.json cursor, copilot.json copilot.
var labelHosts = map[string]Host{
	string(HostClaude):  HostClaude,
	string(HostCodex):   HostCodex,
	string(HostCursor):  HostCursor,
	string(HostCopilot): HostCopilot,
	string(HostDroid):   HostDroid,
}

// detectHost implements DetectHost (D92). The first match wins; a missing
// marker only moves the decision to a later rule, never to "allow":
//
//  1. the codex label (codex.json lives only in the Codex plugin, which
//     only Codex loads), or turn_id in the payload: Codex;
//  2. the cursor and copilot labels: their hosts;
//  3. a camelCase event name, which only Copilot and Cursor generate:
//     Cursor when Cursor's own variables are set, else Copilot;
//  4. Claude's markers (CLAUDE_PID, CLAUDECODE=1, CLAUDE_PROJECT_DIR)
//     with Claude's PascalCase payload: Claude, whatever other hosts'
//     variables the environment inherited;
//  5. PLUGIN_ROOT without Claude's markers: Codex;
//  6. only then other hosts' variables, by exact name: Cursor, Droid;
//  7. the label.
func detectHost(label string, env paths.Env, raw []byte) Host {
	set := func(k string) bool { _, ok := env.Lookup(k); return ok }
	nonEmpty := func(k string) bool { return env.Get(k) != "" }

	if label == string(HostCodex) || payloadHasKey(raw, "turn_id") {
		return HostCodex
	}
	if label == string(HostCursor) || label == string(HostCopilot) {
		return labelHosts[label]
	}
	cursorEnv := set(envCursorVersion) || set(envCursorPluginRoot)
	if camelCase(payloadEventName(raw)) {
		if cursorEnv {
			return HostCursor
		}
		return HostCopilot
	}
	claudeMarkers := nonEmpty(paths.EnvClaudePID) || env.Get(paths.EnvClaudeCode) == "1" || nonEmpty(paths.EnvClaudeProjectDir)
	if claudeMarkers {
		return HostClaude
	}
	if set(paths.EnvPluginRoot) && !set(paths.EnvClaudePID) && !set(paths.EnvClaudeCode) {
		return HostCodex
	}
	if cursorEnv {
		return HostCursor
	}
	if set(envDroidPluginRoot) || set(envFactoryProject) {
		return HostDroid
	}
	if h, ok := labelHosts[label]; ok {
		return h
	}
	return HostUnknown
}

// payloadHasKey reports whether raw is a JSON object with a non-null
// top-level key. It parses only when the quoted key occurs at all, so the
// common case costs one scan.
func payloadHasKey(raw []byte, key string) bool {
	if !bytes.Contains(raw, []byte(`"`+key+`"`)) {
		return false
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(raw, &top); err != nil {
		return false
	}
	v, ok := top[key]
	return ok && !bytes.Equal(bytes.TrimSpace(v), []byte("null"))
}

// payloadEventName returns the event name the payload carries
// (hook_event_name, or Copilot-style hookEventName), "" if none.
func payloadEventName(raw []byte) string {
	if !bytes.Contains(raw, []byte(`"hook_event_name"`)) && !bytes.Contains(raw, []byte(`"hookEventName"`)) {
		return ""
	}
	var v struct {
		Snake *string `json:"hook_event_name"`
		Camel *string `json:"hookEventName"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		return ""
	}
	if v.Snake != nil {
		return *v.Snake
	}
	if v.Camel != nil {
		return *v.Camel
	}
	return ""
}
