package hook_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/precinto/precinto/internal/hook"
	"github.com/precinto/precinto/internal/ipc"
	"github.com/precinto/precinto/internal/ui"
)

// Mirrors of the Codex 0.154 output schemas
// (codex-rs/hooks/schema/generated/*.command.output.schema.json), every
// object with additionalProperties: false (HOOK-3).

type codexUniversal struct {
	Continue       *bool   `json:"continue"`
	StopReason     *string `json:"stopReason"`
	SuppressOutput *bool   `json:"suppressOutput"`
	SystemMessage  *string `json:"systemMessage"`
}

type codexPreCompactOutput struct {
	codexUniversal
}

type codexUserPromptSubmitOutput struct {
	codexUniversal
	Decision           *string `json:"decision"`
	Reason             *string `json:"reason"`
	HookSpecificOutput *struct {
		HookEventName     string  `json:"hookEventName"`
		AdditionalContext *string `json:"additionalContext"`
	} `json:"hookSpecificOutput"`
}

type codexPreToolUseOutput struct {
	codexUniversal
	Decision           *string `json:"decision"`
	Reason             *string `json:"reason"`
	HookSpecificOutput *struct {
		HookEventName            string          `json:"hookEventName"`
		AdditionalContext        *string         `json:"additionalContext"`
		PermissionDecision       *string         `json:"permissionDecision"`
		PermissionDecisionReason *string         `json:"permissionDecisionReason"`
		UpdatedInput             json.RawMessage `json:"updatedInput"`
	} `json:"hookSpecificOutput"`
}

type codexSessionStartOutput struct {
	codexUniversal
	HookSpecificOutput *struct {
		HookEventName     string  `json:"hookEventName"`
		AdditionalContext *string `json:"additionalContext"`
	} `json:"hookSpecificOutput"`
}

func strictDecode(t *testing.T, b []byte, v any) {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		t.Fatalf("output %s does not match the schema: %v", b, err)
	}
	if dec.More() {
		t.Fatalf("output %s has trailing data", b)
	}
}

// TestCodexOutputsMatchSchemas decodes every Codex stdout precinto can
// produce with deny-unknown-fields mirrors (HOOK-3).
func TestCodexOutputsMatchSchemas(t *testing.T) {
	events := []hook.Event{hook.SessionStart, hook.UserPromptSubmit, hook.PreToolUse, hook.PermissionRequest,
		hook.PostToolUse, hook.PreCompact, hook.PostCompact, hook.Stop, hook.Interrupt, hook.SessionEnd}
	decisions := []hook.Decision{
		{Verdict: ipc.VerdictAllow},
		{Verdict: ipc.VerdictAllow, Context: "ctx"},
		{Verdict: ipc.VerdictBlock, UserMessage: "u", ModelMessage: "m"},
		{Verdict: ipc.VerdictDeny, UserMessage: "u", ModelMessage: "m"},
	}
	for _, ev := range events {
		for _, d := range append(decisions, hook.Decision{}) {
			out := hook.Encode(hook.HostCodex, ev, d)
			outputs := [][]byte{out.Stdout, hook.FailClosed(hook.HostCodex, ev, "~/work/acme").Stdout}
			for _, stdout := range outputs {
				if len(stdout) == 0 {
					continue
				}
				switch ev {
				case hook.PreCompact:
					var o codexPreCompactOutput
					strictDecode(t, stdout, &o)
					if o.Continue == nil || *o.Continue || o.StopReason == nil || *o.StopReason == "" {
						t.Errorf("PreCompact block %s: want continue false and a stop reason", stdout)
					}
				case hook.UserPromptSubmit:
					var o codexUserPromptSubmitOutput
					strictDecode(t, stdout, &o)
				case hook.PreToolUse:
					var o codexPreToolUseOutput
					strictDecode(t, stdout, &o)
				case hook.SessionStart:
					var o codexSessionStartOutput
					strictDecode(t, stdout, &o)
				default:
					t.Errorf("%s: unexpected stdout %s", ev, stdout)
				}
			}
		}
	}
}

// TestCodexBlocks pins HOOKS-IO §3.4: stderr reasons with ExitBlockCode2,
// PreCompact JSON with exit 0, nothing for SessionStart in v0.2.
func TestCodexBlocks(t *testing.T) {
	block := hook.Decision{Verdict: ipc.VerdictBlock, UserMessage: "user text", ModelMessage: "model text"}
	deny := hook.Decision{Verdict: ipc.VerdictDeny, UserMessage: "user text", ModelMessage: "model text"}
	cases := []struct {
		ev     hook.Event
		d      hook.Decision
		stdout string
		stderr string
		exit   int
	}{
		{hook.UserPromptSubmit, block, "", "user text\n", hook.ExitBlockCode2},
		{hook.PreToolUse, deny, "", "model text\n", hook.ExitBlockCode2},
		{hook.PermissionRequest, deny, "", "model text\n", hook.ExitBlockCode2},
		{hook.PreCompact, block, `{"continue":false,"stopReason":"user text"}`, "", hook.ExitOK},
		{hook.SessionStart, hook.Decision{Verdict: ipc.VerdictAllow, Context: "ctx"}, "", "", hook.ExitOK},
		{hook.PostToolUse, block, "", "", hook.ExitOK},
		{hook.Stop, block, "", "", hook.ExitOK},
		{hook.Interrupt, block, "", "", hook.ExitOK},
		{hook.SessionEnd, block, "", "", hook.ExitOK},
	}
	for _, c := range cases {
		out := hook.Encode(hook.HostCodex, c.ev, c.d)
		if string(out.Stdout) != c.stdout || string(out.Stderr) != c.stderr || out.Exit != c.exit {
			t.Errorf("Encode(codex, %s) = %q %q %d, want %q %q %d", c.ev, out.Stdout, out.Stderr, out.Exit, c.stdout, c.stderr, c.exit)
		}
	}
}

// Strict mirrors of the Claude outputs of HOOKS-IO §2.4 (exactly these
// keys, all present).
type claudePromptBlock struct {
	Decision           string `json:"decision"`
	Reason             string `json:"reason"`
	HookSpecificOutput struct {
		HookEventName          string `json:"hookEventName"`
		SuppressOriginalPrompt bool   `json:"suppressOriginalPrompt"`
	} `json:"hookSpecificOutput"`
}

type claudeToolDeny struct {
	Continue           bool   `json:"continue"`
	StopReason         string `json:"stopReason"`
	HookSpecificOutput struct {
		HookEventName            string `json:"hookEventName"`
		PermissionDecision       string `json:"permissionDecision"`
		PermissionDecisionReason string `json:"permissionDecisionReason"`
	} `json:"hookSpecificOutput"`
}

type claudePermissionDeny struct {
	HookSpecificOutput struct {
		HookEventName string `json:"hookEventName"`
		Decision      struct {
			Behavior string `json:"behavior"`
			Message  string `json:"message"`
		} `json:"decision"`
	} `json:"hookSpecificOutput"`
}

type claudeCompactBlock struct {
	Decision string `json:"decision"`
	Reason   string `json:"reason"`
}

func TestClaudeBlocks(t *testing.T) {
	block := hook.Decision{Verdict: ipc.VerdictBlock, UserMessage: "user text", ModelMessage: "model text"}
	deny := hook.Decision{Verdict: ipc.VerdictDeny, UserMessage: "precinto: ~/work/acme is locked", ModelMessage: "model text"}
	for _, host := range []hook.Host{hook.HostClaude, hook.HostDroid} {
		out := hook.Encode(host, hook.UserPromptSubmit, block)
		want := `{"decision":"block","reason":"user text","hookSpecificOutput":{"hookEventName":"UserPromptSubmit","suppressOriginalPrompt":true}}`
		if string(out.Stdout) != want || out.Exit != 0 || len(out.Stderr) != 0 {
			t.Errorf("%s UserPromptSubmit: %q", host, out.Stdout)
		}
		var p claudePromptBlock
		strictDecode(t, out.Stdout, &p)

		out = hook.Encode(host, hook.PreToolUse, deny)
		want = `{"continue":false,"stopReason":"precinto: ~/work/acme is locked","hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"model text"}}`
		if string(out.Stdout) != want || out.Exit != 0 {
			t.Errorf("%s PreToolUse: %q", host, out.Stdout)
		}
		var d claudeToolDeny
		strictDecode(t, out.Stdout, &d)

		out = hook.Encode(host, hook.PermissionRequest, deny)
		want = `{"hookSpecificOutput":{"hookEventName":"PermissionRequest","decision":{"behavior":"deny","message":"model text"}}}`
		if string(out.Stdout) != want || out.Exit != 0 {
			t.Errorf("%s PermissionRequest: %q", host, out.Stdout)
		}
		var pr claudePermissionDeny
		strictDecode(t, out.Stdout, &pr)

		out = hook.Encode(host, hook.PreCompact, block)
		want = `{"decision":"block","reason":"user text"}`
		if string(out.Stdout) != want || out.Exit != 0 {
			t.Errorf("%s PreCompact: %q", host, out.Stdout)
		}
		var c claudeCompactBlock
		strictDecode(t, out.Stdout, &c)

		out = hook.Encode(host, hook.SessionStart, hook.Decision{Verdict: ipc.VerdictAllow, Context: "ctx"})
		want = `{"hookSpecificOutput":{"hookEventName":"SessionStart","additionalContext":"ctx"}}`
		if string(out.Stdout) != want || out.Exit != 0 {
			t.Errorf("%s SessionStart: %q", host, out.Stdout)
		}
	}
}

// TestNeverBlockNonGates: PostToolUse, Stop, SessionEnd, … never exit 2 and
// never print, whatever the decision says (HOOKS-IO §2.4, §3.4).
func TestNeverBlockNonGates(t *testing.T) {
	hosts := []hook.Host{hook.HostClaude, hook.HostCodex, hook.HostCursor, hook.HostCopilot, hook.HostDroid, hook.HostUnknown}
	events := []hook.Event{hook.PostToolUse, hook.PostCompact, hook.Stop, hook.StopFailure, hook.Interrupt,
		hook.Notification, hook.CwdChanged, hook.DirectoryAdded, hook.SessionEnd, hook.Event("FileChanged")}
	for _, h := range hosts {
		for _, ev := range events {
			for _, v := range []ipc.Verdict{ipc.VerdictBlock, ipc.VerdictDeny} {
				out := hook.Encode(h, ev, hook.Decision{Verdict: v, UserMessage: "u", ModelMessage: "m", Context: "c"})
				if out.Exit != 0 || len(out.Stdout) != 0 || len(out.Stderr) != 0 {
					t.Errorf("Encode(%s, %s, %s) = %+v, want silent exit 0", h, ev, v, out)
				}
			}
			if out := hook.FailClosed(h, ev, "~/work/acme"); out.Exit != 0 || len(out.Stdout) != 0 || len(out.Stderr) != 0 {
				t.Errorf("FailClosed(%s, %s) = %+v, want silent exit 0", h, ev, out)
			}
		}
	}
}

// TestAllowIsSilent: allow prints nothing on every host and event.
func TestAllowIsSilent(t *testing.T) {
	for _, h := range []hook.Host{hook.HostClaude, hook.HostCodex, hook.HostCursor, hook.HostCopilot, hook.HostDroid, hook.HostUnknown} {
		for _, ev := range []hook.Event{hook.UserPromptSubmit, hook.PreToolUse, hook.PermissionRequest, hook.PreCompact, hook.SessionStart} {
			out := hook.Encode(h, ev, hook.Decision{Verdict: ipc.VerdictAllow})
			if out.Exit != 0 || len(out.Stdout) != 0 || len(out.Stderr) != 0 {
				t.Errorf("allow on %s/%s = %+v", h, ev, out)
			}
		}
	}
}

// TestFailClosedOutputs: every gate event of every host has a blocking
// static output with catalog text and no empty reason (I5).
func TestFailClosedOutputs(t *testing.T) {
	folder := "~/work/acme"
	for _, ev := range []hook.Event{hook.UserPromptSubmit, hook.PreToolUse, hook.PermissionRequest, hook.PreCompact} {
		out := hook.FailClosed(hook.HostClaude, ev, folder)
		if out.Exit != 0 || len(out.Stdout) == 0 {
			t.Errorf("claude %s: %+v", ev, out)
		}
		out = hook.FailClosed(hook.HostCodex, ev, folder)
		if ev == hook.PreCompact {
			if out.Exit != 0 || !strings.Contains(string(out.Stdout), `"continue":false`) {
				t.Errorf("codex PreCompact: %+v", out)
			}
		} else if out.Exit != hook.ExitBlockCode2 || len(bytes.TrimSpace(out.Stderr)) == 0 || len(out.Stdout) != 0 {
			t.Errorf("codex %s: %+v", ev, out)
		}
		if out := hook.FailClosed(hook.HostUnknown, ev, folder); out.Exit != hook.ExitFailure {
			t.Errorf("unknown %s: exit %d, want ExitFailure (the shim decides)", ev, out.Exit)
		}
	}
	prompt := string(hook.FailClosed(hook.HostClaude, hook.UserPromptSubmit, folder).Stdout)
	if !strings.Contains(prompt, ui.Format(ui.MsgAgentDown, ui.Vars{Folder: folder})) {
		t.Errorf("prompt fail-closed text: %s", prompt)
	}
	var tool claudeToolDeny
	strictDecode(t, hook.FailClosed(hook.HostClaude, hook.PreToolUse, folder).Stdout, &tool)
	if tool.HookSpecificOutput.PermissionDecisionReason != ui.Format(ui.MsgToolDenied, ui.Vars{Folder: folder}) ||
		tool.StopReason != "precinto: ~/work/acme is locked" || tool.Continue {
		t.Errorf("tool fail-closed output: %+v", tool)
	}
	// An empty folder still renders a well-formed text.
	if out := hook.FailClosed(hook.HostClaude, hook.UserPromptSubmit, ""); strings.Contains(string(out.Stdout), "so  stays") {
		t.Errorf("empty folder: %s", out.Stdout)
	}
}

// TestEmptyReasonIsNeverEmitted: a block with no text still carries a
// reason (an empty Codex reason lets the prompt proceed).
func TestEmptyReasonIsNeverEmitted(t *testing.T) {
	out := hook.Encode(hook.HostCodex, hook.UserPromptSubmit, hook.Decision{Verdict: ipc.VerdictBlock})
	if out.Exit != hook.ExitBlockCode2 || strings.TrimSpace(string(out.Stderr)) != ui.Format(ui.MsgShimFailed, ui.Vars{}) {
		t.Errorf("empty Codex reason: %+v", out)
	}
	out = hook.Encode(hook.HostClaude, hook.PreToolUse, hook.Decision{Verdict: ipc.VerdictDeny})
	var d claudeToolDeny
	strictDecode(t, out.Stdout, &d)
	if d.StopReason == "" || d.HookSpecificOutput.PermissionDecisionReason == "" {
		t.Errorf("empty Claude reasons: %s", out.Stdout)
	}
}

// TestMessagesAreOneLine: control characters and newlines from a daemon
// text never reach the harness (a newline would end Codex's reason).
func TestMessagesAreOneLine(t *testing.T) {
	out := hook.Encode(hook.HostCodex, hook.UserPromptSubmit, hook.Decision{Verdict: ipc.VerdictBlock, UserMessage: "line1\nline2\x1b[31m\ttab"})
	if got := string(out.Stderr); got != "line1 line2[31m tab\n" {
		t.Errorf("stderr %q", got)
	}
}

func TestLockedLine(t *testing.T) {
	if got := hook.LockedLine("~/work/acme"); got != "precinto: ~/work/acme is locked" {
		t.Errorf("LockedLine = %q", got)
	}
}

func TestHeadlessUI(t *testing.T) {
	var h hook.HeadlessUI
	if err := h.Display("x"); err != nil {
		t.Errorf("Display: %v", err)
	}
	if b, err := h.Secret("x"); err == nil || b != nil {
		t.Errorf("Secret must refuse: %v", err)
	}
	if ok, err := h.Confirm("x", "yes", "no"); ok || err == nil {
		t.Errorf("Confirm must refuse: %v %v", ok, err)
	}
}
