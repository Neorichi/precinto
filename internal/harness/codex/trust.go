package codex

// Codex 0.154 hook trust of precinto's plugin (D98, D99). Codex runs a
// plugin hook only when its plugin is enabled and installed in the
// CODEX_HOME in use and the hook's [hooks.state."<key>"] trusted_hash equals
// the hash of the hook's current declaration (codex-rs/hooks/src/engine/
// discovery.rs hook_trust_status: any other stored hash is "Modified" and
// the handler is not registered).

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/Neorichi/precinto/internal/fsx"
)

// Errors of HooksTrusted for the states that are known but not "trusted".
var (
	// ErrHooksModified: trust entries exist for precinto's hooks but hold
	// the hash of other declarations (another version of hooks/codex.json,
	// or another normalization by Codex): Codex skips the hooks until the
	// user reviews them in /hooks again (D98).
	ErrHooksModified = errors.New("codex: precinto's hooks are trusted for other hook declarations")
	// ErrPluginMissing: the home's config.toml enables no precinto plugin,
	// or the plugin is not installed in the home's plugins/cache: Codex
	// loads no precinto hook there, so /hooks cannot list them (D99).
	ErrPluginMissing = errors.New("codex: the home does not load precinto's Codex plugin")
)

// trustState is what a Codex home says about precinto's hooks.
type trustState int

const (
	trustUnknown       trustState = iota // config.toml cannot be read or parsed
	trustPluginMissing                   // no enabled and installed precinto plugin
	trustUntrusted                       // a hook has no trust entry, or is disabled
	trustModified                        // a hook is trusted for another declaration
	trustTrusted                         // every hook is trusted for its current declaration
)

// hookHandler is one handler of a Codex hooks file as Codex 0.154
// deserializes it (codex-rs/config/src/hook_config.rs, HookHandlerConfig::
// Command): optional values are pointers.
type hookHandler struct {
	Type                   string  `json:"type"`
	Command                string  `json:"command"`
	CommandWindows         *string `json:"commandWindows"`
	Timeout                *uint64 `json:"timeout"`
	Async                  bool    `json:"async"`
	StatusMessage          *string `json:"statusMessage"`
	AdditionalContextLimit *uint64 `json:"additionalContextLimit"`
}

// hookDecl is one handler of plugins/codex/hooks/codex.json: its event (the
// file's PascalCase name), matcher group and handler index, matcher and
// handler.
type hookDecl struct {
	Event        string
	Group, Index int
	Matcher      *string
	Handler      hookHandler
}

func strp(s string) *string { return &s }
func u64p(n uint64) *uint64 { return &n }

// precintoCommand is the shell form of every hook command (HOOKS-IO §3.1):
// $PLUGIN_ROOT without braces, which Codex never expands in the hashed
// declaration (it substitutes ${VAR} placeholders only into the command
// it runs).
func precintoCommand(event string) string {
	return `sh "$PLUGIN_ROOT/scripts/precinto-hook" codex ` + event
}

// precintoHooks mirrors plugins/codex/hooks/codex.json (HOOKS-IO §3.2),
// one group with one handler per event. A test decodes the shipped file and
// requires it to equal this table, and pins the hashes derived from it
// (test/integration/testdata/codex-trust.sha256), so the hashes HooksTrusted
// expects never drift from the hooks precinto ships.
var precintoHooks = []hookDecl{
	{Event: "SessionStart", Matcher: strp("*"), Handler: hookHandler{Type: "command", Command: precintoCommand("SessionStart"), Timeout: u64p(10)}},
	{Event: "UserPromptSubmit", Handler: hookHandler{Type: "command", Command: precintoCommand("UserPromptSubmit"), Timeout: u64p(90)}},
	{Event: "PreToolUse", Matcher: strp("*"), Handler: hookHandler{Type: "command", Command: precintoCommand("PreToolUse"), Timeout: u64p(10)}},
	{Event: "PermissionRequest", Matcher: strp("*"), Handler: hookHandler{Type: "command", Command: precintoCommand("PermissionRequest"), Timeout: u64p(10)}},
	{Event: "PostToolUse", Matcher: strp("apply_patch|Edit|Write"), Handler: hookHandler{Type: "command", Command: precintoCommand("PostToolUse"), Timeout: u64p(10)}},
	{Event: "PreCompact", Matcher: strp("*"), Handler: hookHandler{Type: "command", Command: precintoCommand("PreCompact"), Timeout: u64p(10)}},
	{Event: "PostCompact", Matcher: strp("*"), Handler: hookHandler{Type: "command", Command: precintoCommand("PostCompact"), Async: true}},
	{Event: "Stop", Handler: hookHandler{Type: "command", Command: precintoCommand("Stop"), Async: true}},
	{Event: "Interrupt", Handler: hookHandler{Type: "command", Command: precintoCommand("Interrupt"), Timeout: u64p(3)}},
	{Event: "SessionEnd", Handler: hookHandler{Type: "command", Command: precintoCommand("SessionEnd"), Timeout: u64p(3)}},
}

// eventLabels are Codex 0.154's event key labels, used in trust keys and in
// the hashed identity (codex-rs/hooks/src/lib.rs hook_event_key_label).
var eventLabels = map[string]string{
	"PreToolUse": "pre_tool_use", "PermissionRequest": "permission_request", "PostToolUse": "post_tool_use",
	"PreCompact": "pre_compact", "PostCompact": "post_compact", "SessionStart": "session_start",
	"SessionEnd": "session_end", "UserPromptSubmit": "user_prompt_submit", "SubagentStart": "subagent_start",
	"SubagentStop": "subagent_stop", "Stop": "stop", "Interrupt": "interrupt",
}

// matcherIgnored are the events whose matcher Codex drops (codex-rs/hooks/
// src/events/common.rs matcher_pattern_for_event).
var matcherIgnored = map[string]bool{"UserPromptSubmit": true, "Stop": true, "Interrupt": true}

// contextEvents are the events that keep additionalContextLimit (the others
// cannot emit additionalContext); defaultContextLimit is dropped too
// (codex-rs/hooks/src/output_spill.rs DEFAULT_HOOK_OUTPUT_TOKEN_LIMIT).
var contextEvents = map[string]bool{"PreToolUse": true, "PostToolUse": true, "SessionStart": true, "UserPromptSubmit": true, "SubagentStart": true}

const defaultContextLimit = 2500

// normalizedTimeout is Codex 0.154's normalize_command_hook: SessionEnd and
// Interrupt default to 1 s and are clamped to 1–3 s; every other event
// defaults to 600 s and is at least 1 s.
func normalizedTimeout(event string, t *uint64) uint64 {
	if event == "SessionEnd" || event == "Interrupt" {
		v := uint64(1)
		if t != nil {
			v = *t
		}
		return min(max(v, 1), 3)
	}
	v := uint64(600)
	if t != nil {
		v = *t
	}
	return max(v, 1)
}

// hookHash is Codex 0.154's trust hash of one command handler
// (codex-rs/hooks/src/engine/discovery.rs hook_hash, codex-rs/config/src/
// fingerprint.rs version_for_toml):
//
//  1. the handler is normalized: the command exactly as written (on unix
//     commandWindows is dropped; no placeholder is expanded), the timeout
//     normalized (normalizedTimeout), async as written, statusMessage as
//     written, additionalContextLimit only for contextEvents and only when
//     it is not the default;
//  2. the matcher is kept only for events that dispatch on one;
//  3. the identity {"event_name": <event label>, "matcher": <matcher>,
//     "hooks": [<handler>]} with the handler {"type":"command",
//     "command", "timeout", "async", "statusMessage",
//     "additionalContextLimit"} is serialized to TOML, which omits every
//     absent (None) value, then to JSON;
//  4. that JSON is made canonical: object keys sorted bytewise at every
//     level, no whitespace, serde_json's string escaping (canonicalJSON);
//  5. the hash is "sha256:" and the lowercase hex SHA-256 of those bytes.
//
// It reports false for an event Codex does not know or a handler that is
// not a command (precinto ships only command handlers).
func hookHash(event string, matcher *string, h hookHandler) (string, bool) {
	identity, ok := hookIdentity(event, matcher, h)
	if !ok {
		return "", false
	}
	sum := sha256.Sum256([]byte(identity))
	return "sha256:" + hex.EncodeToString(sum[:]), true
}

// hookIdentity returns the canonical JSON that hookHash hashes (steps 1–4).
func hookIdentity(event string, matcher *string, h hookHandler) (string, bool) {
	label, ok := eventLabels[event]
	if !ok || h.Type != "command" {
		return "", false
	}
	handler := map[string]any{
		"type":    "command",
		"command": h.Command,
		"timeout": normalizedTimeout(event, h.Timeout),
		"async":   h.Async,
	}
	if h.StatusMessage != nil {
		handler["statusMessage"] = *h.StatusMessage
	}
	if l := h.AdditionalContextLimit; l != nil && contextEvents[event] && *l != defaultContextLimit {
		handler["additionalContextLimit"] = *l
	}
	identity := map[string]any{"event_name": label, "hooks": []any{handler}}
	if matcher != nil && !matcherIgnored[event] {
		identity["matcher"] = *matcher
	}
	var b strings.Builder
	canonicalJSON(&b, identity)
	return b.String(), true
}

// canonicalJSON writes v as compact JSON with object keys sorted bytewise
// (Rust's String order), as serde_json::to_vec writes the canonical value
// of version_for_toml. Values: map[string]any, []any, string, bool, uint64.
func canonicalJSON(b *strings.Builder, v any) {
	switch x := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			jsonString(b, k)
			b.WriteByte(':')
			canonicalJSON(b, x[k])
		}
		b.WriteByte('}')
	case []any:
		b.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				b.WriteByte(',')
			}
			canonicalJSON(b, e)
		}
		b.WriteByte(']')
	case string:
		jsonString(b, x)
	case bool:
		b.WriteString(strconv.FormatBool(x))
	case uint64:
		b.WriteString(strconv.FormatUint(x, 10))
	default:
		panic(fmt.Sprintf("codex: canonicalJSON: unsupported %T", v))
	}
}

// jsonString writes s with serde_json's escaping: '"' and '\\' escaped,
// \b \f \n \r \t by name, every other byte below 0x20 as \u00xx (lowercase
// hex), everything else (DEL and non-ASCII UTF-8 included) as is.
func jsonString(b *strings.Builder, s string) {
	const hexDigits = "0123456789abcdef"
	b.WriteByte('"')
	for i := 0; i < len(s); i++ {
		switch c := s[i]; c {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if c < 0x20 {
				b.WriteString(`\u00`)
				b.WriteByte(hexDigits[c>>4])
				b.WriteByte(hexDigits[c&0xf])
			} else {
				b.WriteByte(c)
			}
		}
	}
	b.WriteByte('"')
}

// trustKeyTail is the part of a trust key after "<plugin id>:<file>:":
// "<event label>:<group>:<handler>" (codex-rs/hooks/src/lib.rs hook_key).
func trustKeyTail(d hookDecl) string {
	return eventLabels[d.Event] + ":" + strconv.Itoa(d.Group) + ":" + strconv.Itoa(d.Index)
}

// precintoTrust maps the trust key tail of every precinto hook to the hash
// Codex 0.154 computes for its declaration.
var precintoTrust = func() map[string]string {
	out := make(map[string]string, len(precintoHooks))
	for _, d := range precintoHooks {
		h, ok := hookHash(d.Event, d.Matcher, d.Handler)
		if !ok {
			panic("codex: precinto hook " + d.Event + " has no Codex trust hash")
		}
		out[trustKeyTail(d)] = h
	}
	return out
}()

// currentTrust returns the hash Codex 0.154 computes for the current
// declaration of the precinto hook a trust key names ("precinto@<market>:
// hooks/codex.json:<event>:<g>:<h>"); false for any other key.
func currentTrust(key string) (string, bool) {
	id, tail, ok := parseTrustKey(key)
	if !ok {
		return "", false
	}
	if name, _, _ := strings.Cut(id, "@"); name != pluginName {
		return "", false
	}
	want, ok := precintoTrust[tail]
	return want, ok
}

// parseTrustKey splits a trust key of precinto's hooks file
// "<plugin id>:hooks/codex.json:<event>:<group>:<handler>" into the plugin
// id and the tail.
func parseTrustKey(key string) (id, tail string, ok bool) {
	parts := strings.Split(key, ":")
	if len(parts) != 5 || parts[1] != sourceHooksFile || !isIndex(parts[3]) || !isIndex(parts[4]) {
		return "", "", false
	}
	return parts[0], strings.Join(parts[2:], ":"), true
}

func isIndex(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// homeTrust evaluates precinto's hooks in a Codex home. With user set it
// evaluates the home as PrepareHome will leave it when seeding from user
// (PlanLaunch asks its question before Prepare runs): config.toml as
// plannedConfig writes it, and the user's plugins/ when it exists (the
// home's plugins/ becomes a link to it). With user "" it reads the home as
// it is (doctor).
func homeTrust(home, user string) (trustState, error) {
	if !filepath.IsAbs(home) {
		return trustUnknown, fmt.Errorf("codex: home %q is not absolute", home)
	}
	home = filepath.Clean(home)
	var text string
	if user != "" {
		_, out, _, err := plannedConfig(home, filepath.Clean(user), false)
		if err != nil {
			return trustUnknown, err
		}
		text = out
	} else {
		data, _, err := readFileBounded(filepath.Join(home, configName))
		switch {
		case errors.Is(err, fs.ErrNotExist):
		case err != nil:
			return trustUnknown, err
		default:
			text = string(data)
		}
	}
	doc, err := parseTOML(text)
	if err != nil {
		return trustUnknown, nil
	}
	pluginsDir := filepath.Join(home, "plugins")
	if user != "" {
		if st, err := fsx.Lstat(filepath.Join(user, "plugins")); err == nil && st.IsDir() {
			pluginsDir = filepath.Join(filepath.Clean(user), "plugins")
		}
	}
	ids := loadedPluginIDs(doc, pluginsDir)
	if len(ids) == 0 {
		return trustPluginMissing, nil
	}
	// Codex runs the hooks of every loaded plugin: one plugin id trusted
	// is enough; one whose trust precinto cannot read (unknown) is never
	// reported as modified or untrusted.
	states := doc.hookStates()
	best, unknown := trustUntrusted, false
	for _, id := range ids {
		switch s := pluginTrust(id, states); {
		case s == trustUnknown:
			unknown = true
		case s > best:
			best = s
		}
	}
	if unknown && best != trustTrusted {
		return trustUnknown, nil
	}
	return best, nil
}

// pluginTrust evaluates the trust entries of one loaded plugin id: trusted
// when every precinto hook has an entry with its current hash and is not
// disabled; modified when an entry holds another hash; else untrusted. An
// entry that holds another hash next to a trusted_content_hash was written
// by a Codex newer than the verified 0.154, which may hash declarations
// another way: then the state is unknown, never "modified".
func pluginTrust(id string, states map[string]*hookState) trustState {
	trusted, modified, newer := 0, false, false
	for k, hs := range states {
		kid, tail, ok := parseTrustKey(k)
		if !ok || kid != id {
			continue
		}
		want, ours := precintoTrust[tail]
		if !ours || hs.trustedHash == "" {
			continue
		}
		if hs.trustedHash != want {
			modified = true
			newer = newer || hs.contentHash != ""
			continue
		}
		if hs.enabled == nil || *hs.enabled {
			trusted++
		}
	}
	switch {
	case modified && newer:
		return trustUnknown
	case modified:
		return trustModified
	case trusted == len(precintoTrust):
		return trustTrusted
	}
	return trustUntrusted
}

// loadedPluginIDs returns the precinto plugin ids ("precinto@<marketplace>")
// a home loads: enabled in config.toml (a [plugins."<id>"] entry whose
// enabled is not false: Codex defaults it to true) and installed in
// pluginsDir/cache/<marketplace>/precinto/<version>/.
func loadedPluginIDs(doc *tomlDoc, pluginsDir string) []string {
	var out []string
	fields := doc.familyFields("plugins")
	ids := make([]string, 0, len(fields))
	for id := range fields {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		name, market, ok := strings.Cut(id, "@")
		if !ok || name != pluginName || market == "" || market != filepath.Base(market) || strings.HasPrefix(market, ".") {
			continue
		}
		if v, ok := fields[id]["enabled"].(bool); ok && !v {
			continue
		}
		if pluginInstalled(filepath.Join(pluginsDir, "cache", market, pluginName)) {
			out = append(out, id)
		}
	}
	return out
}

// pluginInstalled reports whether a plugin's cache directory holds a
// version directory (Codex loads the active version below it).
func pluginInstalled(dir string) bool {
	des, err := os.ReadDir(dir)
	if err != nil {
		return false
	}
	for _, de := range des {
		if strings.HasPrefix(de.Name(), ".") {
			continue
		}
		if st, err := os.Stat(filepath.Join(dir, de.Name())); err == nil && st.IsDir() {
			return true
		}
	}
	return false
}
