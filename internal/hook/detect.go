package hook

import (
	"bytes"
	"encoding/json"
	"strings"

	"github.com/precinto/precinto/internal/paths"
)

// Host markers in the hook environment (HOOKS-IO §0.7, D56). Codex sets
// PLUGIN_ROOT (and the CLAUDE_PLUGIN_ROOT alias) for plugin hooks; Claude
// sets only CLAUDE_PLUGIN_ROOT, plus CLAUDECODE=1 and usually CLAUDE_PID.
const (
	envCursorVersion    = "CURSOR_VERSION"
	envCursorPluginRoot = "CURSOR_PLUGIN_ROOT"
	envCopilotPrefix    = "COPILOT_"
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

// detectHost implements DetectHost. The first match wins; a missing marker
// only moves the decision to a later rule, never to "allow".
func detectHost(label string, env paths.Env, raw []byte) Host {
	set := func(k string) bool { _, ok := env.Lookup(k); return ok }
	nonEmpty := func(k string) bool { return env.Get(k) != "" }

	// 1. Other hosts' markers.
	if set(envCursorVersion) || set(envCursorPluginRoot) {
		return HostCursor
	}
	if hasPrefixVar(env, envCopilotPrefix) || camelCase(payloadEventName(raw)) {
		return HostCopilot
	}
	if set(envDroidPluginRoot) || set(envFactoryProject) {
		return HostDroid
	}
	// 2. Codex markers: turn_id in the payload, or PLUGIN_ROOT with the codex
	// label or without Claude's markers.
	if payloadHasKey(raw, "turn_id") {
		return HostCodex
	}
	if set(paths.EnvPluginRoot) && (label == string(HostCodex) || (!set(paths.EnvClaudePID) && !set(paths.EnvClaudeCode))) {
		return HostCodex
	}
	// 3. Claude markers.
	if nonEmpty(paths.EnvClaudePID) || env.Get(paths.EnvClaudeCode) == "1" || nonEmpty(paths.EnvClaudeProjectDir) {
		return HostClaude
	}
	// 4. The label names the hooks file that invoked the hook.
	if h, ok := labelHosts[label]; ok {
		return h
	}
	return HostUnknown
}

// hasPrefixVar reports whether any variable whose name starts with prefix
// is set.
func hasPrefixVar(env paths.Env, prefix string) bool {
	for _, kv := range env.Environ() {
		if strings.HasPrefix(kv, prefix) {
			return true
		}
	}
	return false
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
