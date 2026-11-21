package codex

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// moduleRoot finds the repository root (go.mod) above the test's directory.
func moduleRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for d := wd; ; d = filepath.Dir(d) {
		if _, err := os.Stat(filepath.Join(d, "go.mod")); err == nil {
			return d
		}
		if filepath.Dir(d) == d {
			t.Fatal("go.mod not found")
		}
	}
}

// goldenTrust reads test/integration/testdata/codex-trust.sha256 (next to
// the D78 byte list): "<tail>  <hash>" lines, "#" comments.
func goldenTrust(t *testing.T) map[string]string {
	t.Helper()
	f, err := os.Open(filepath.Join(moduleRoot(t), "test", "integration", "testdata", "codex-trust.sha256"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	out := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		tail, hash, ok := strings.Cut(line, "  ")
		if !ok {
			t.Fatalf("bad golden line %q", line)
		}
		out[tail] = hash
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// D98 (M3): the hashes HooksTrusted expects are Codex 0.154's hashes of the
// shipped declarations, pinned in testdata from an independent derivation.
func TestTrustHashesGolden(t *testing.T) {
	want := goldenTrust(t)
	if len(want) != len(precintoHooks) {
		t.Fatalf("golden list has %d hooks, the table %d", len(want), len(precintoHooks))
	}
	if !reflect.DeepEqual(precintoTrust, want) {
		for tail, h := range precintoTrust {
			if want[tail] != h {
				t.Errorf("%s: trust.go derives %s, the golden list says %q", tail, h, want[tail])
			}
		}
		t.Fatal("trust hashes differ from test/integration/testdata/codex-trust.sha256")
	}
}

// D98: the table trust.go hashes is plugins/codex/hooks/codex.json, as
// Codex 0.154 decodes it (top-level keys description and hooks only).
func TestHookTableIsTheShippedFile(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(moduleRoot(t), "plugins", "codex", "hooks", "codex.json"))
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Description string `json:"description"`
		Hooks       map[string][]struct {
			Matcher *string       `json:"matcher"`
			Hooks   []hookHandler `json:"hooks"`
		} `json:"hooks"`
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&file); err != nil {
		t.Fatalf("codex.json: %v", err)
	}
	got := map[string]hookDecl{}
	for event, groups := range file.Hooks {
		for g, group := range groups {
			for i, h := range group.Hooks {
				d := hookDecl{Event: event, Group: g, Index: i, Matcher: group.Matcher, Handler: h}
				got[trustKeyTail(d)] = d
			}
		}
	}
	if len(got) != len(precintoHooks) {
		t.Fatalf("codex.json has %d handlers, the table %d", len(got), len(precintoHooks))
	}
	for _, d := range precintoHooks {
		f, ok := got[trustKeyTail(d)]
		if !ok || !reflect.DeepEqual(f, d) {
			t.Errorf("%s: codex.json %+v, table %+v", trustKeyTail(d), f, d)
		}
		if h, _ := hookHash(f.Event, f.Matcher, f.Handler); h != precintoTrust[trustKeyTail(d)] {
			t.Errorf("%s: the file hashes to %s", trustKeyTail(d), h)
		}
	}
}

// The normalization and canonical JSON of hookHash, case by case (Codex
// 0.154 discovery.rs normalize_command_hook, hook_hash; fingerprint.rs).
func TestHookIdentityNormalization(t *testing.T) {
	cmd := hookHandler{Type: "command", Command: "x"}
	with := func(f func(*hookHandler)) hookHandler {
		h := cmd
		f(&h)
		return h
	}
	for _, c := range []struct {
		name, event string
		matcher     *string
		h           hookHandler
		want        string
	}{
		{"default timeout", "PreToolUse", strp("*"), cmd,
			`{"event_name":"pre_tool_use","hooks":[{"async":false,"command":"x","timeout":600,"type":"command"}],"matcher":"*"}`},
		{"no matcher key", "PreToolUse", nil, cmd,
			`{"event_name":"pre_tool_use","hooks":[{"async":false,"command":"x","timeout":600,"type":"command"}]}`},
		{"matcher dropped", "UserPromptSubmit", strp("*"), cmd,
			`{"event_name":"user_prompt_submit","hooks":[{"async":false,"command":"x","timeout":600,"type":"command"}]}`},
		{"zero timeout", "Stop", nil, with(func(h *hookHandler) { h.Timeout = u64p(0) }),
			`{"event_name":"stop","hooks":[{"async":false,"command":"x","timeout":1,"type":"command"}]}`},
		{"session end default", "SessionEnd", nil, cmd,
			`{"event_name":"session_end","hooks":[{"async":false,"command":"x","timeout":1,"type":"command"}]}`},
		{"session end clamped", "SessionEnd", nil, with(func(h *hookHandler) { h.Timeout = u64p(30) }),
			`{"event_name":"session_end","hooks":[{"async":false,"command":"x","timeout":3,"type":"command"}]}`},
		{"interrupt clamped up", "Interrupt", nil, with(func(h *hookHandler) { h.Timeout = u64p(0) }),
			`{"event_name":"interrupt","hooks":[{"async":false,"command":"x","timeout":1,"type":"command"}]}`},
		{"async session end kept", "SessionEnd", nil, with(func(h *hookHandler) { h.Async = true }),
			`{"event_name":"session_end","hooks":[{"async":true,"command":"x","timeout":1,"type":"command"}]}`},
		{"status message, windows command dropped", "PostCompact", nil,
			with(func(h *hookHandler) { h.StatusMessage, h.CommandWindows = strp("saving"), strp("y") }),
			`{"event_name":"post_compact","hooks":[{"async":false,"command":"x","statusMessage":"saving","timeout":600,"type":"command"}]}`},
		{"context limit kept", "SessionStart", nil, with(func(h *hookHandler) { h.AdditionalContextLimit = u64p(10) }),
			`{"event_name":"session_start","hooks":[{"additionalContextLimit":10,"async":false,"command":"x","timeout":600,"type":"command"}]}`},
		{"default context limit dropped", "SessionStart", nil, with(func(h *hookHandler) { h.AdditionalContextLimit = u64p(2500) }),
			`{"event_name":"session_start","hooks":[{"async":false,"command":"x","timeout":600,"type":"command"}]}`},
		{"context limit of an event without context dropped", "Stop", nil, with(func(h *hookHandler) { h.AdditionalContextLimit = u64p(10) }),
			`{"event_name":"stop","hooks":[{"async":false,"command":"x","timeout":600,"type":"command"}]}`},
		{"serde_json escaping", "Stop", nil, with(func(h *hookHandler) { h.Command = "a\"b\\c\x01\x1f\x7f\b\f\n\r\té<&>/" }),
			`{"event_name":"stop","hooks":[{"async":false,"command":"a\"b\\c\u0001\u001f` + "\x7f" + `\b\f\n\r\té<&>/","timeout":600,"type":"command"}]}`},
		{"braces never expanded", "Stop", nil, with(func(h *hookHandler) { h.Command = `sh "${PLUGIN_ROOT}/x"` }),
			`{"event_name":"stop","hooks":[{"async":false,"command":"sh \"${PLUGIN_ROOT}/x\"","timeout":600,"type":"command"}]}`},
	} {
		got, ok := hookIdentity(c.event, c.matcher, c.h)
		if !ok || got != c.want {
			t.Errorf("%s:\n got %s\nwant %s", c.name, got, c.want)
		}
	}
	if _, ok := hookHash("Notification", nil, cmd); ok {
		t.Error("an event Codex does not know was hashed")
	}
	if _, ok := hookHash("Stop", nil, hookHandler{Type: "prompt"}); ok {
		t.Error("a prompt handler was hashed")
	}
	// The hash of a precinto hook, end to end (the golden list's line).
	if h, _ := hookHash("Stop", nil, precintoHooks[7].Handler); h != "sha256:1b33a3dcc4d8c2afba360875738f78e8917aab4a77b75d7fa7f5b1a7a0e9549a" {
		t.Errorf("Stop hash %s", h)
	}
}
