package hook

import (
	"bytes"
	"encoding/json"
	"strings"

	"github.com/precinto/precinto/internal/ipc"
	"github.com/precinto/precinto/internal/ui"
)

// maxMessage bounds a block text taken from the daemon (it is rendered
// from the catalog; the bound only protects the harness's output limits).
const maxMessage = 2000

// Output shapes. Field order is the key order of HOOKS-IO §2.4 and §3.4;
// every struct holds exactly the keys the host accepts (Codex output
// structs deny unknown fields).

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

type claudeStartContext struct {
	HookSpecificOutput struct {
		HookEventName     string `json:"hookEventName"`
		AdditionalContext string `json:"additionalContext"`
	} `json:"hookSpecificOutput"`
}

type codexCompactBlock struct {
	Continue   bool   `json:"continue"`
	StopReason string `json:"stopReason"`
}

// Cursor and Copilot shapes are UNVERIFIED drafts (HOOKS-IO §4).

type cursorPromptBlock struct {
	Continue    bool   `json:"continue"`
	UserMessage string `json:"user_message"`
}

type cursorToolDeny struct {
	Permission   string `json:"permission"`
	UserMessage  string `json:"user_message"`
	AgentMessage string `json:"agent_message"`
}

type copilotToolDeny struct {
	PermissionDecision       string `json:"permissionDecision"`
	PermissionDecisionReason string `json:"permissionDecisionReason"`
}

// encode implements Encode.
func encode(host Host, ev Event, d Decision) Output {
	blocking := d.Verdict == ipc.VerdictBlock || d.Verdict == ipc.VerdictDeny
	if !blocking || !isGate(host, ev) {
		// Allow, or an event that never blocks: nothing on stdout, except the
		// locked-folder notice of a Claude SessionStart (Codex: none in v0.2).
		if ev == SessionStart && d.Context != "" && claudeFormat(host) {
			var o claudeStartContext
			o.HookSpecificOutput.HookEventName = string(SessionStart)
			o.HookSpecificOutput.AdditionalContext = oneLine(d.Context)
			return jsonOutput(o)
		}
		return Output{Exit: ExitOK}
	}
	user := nonEmpty(d.UserMessage)
	model := nonEmpty(d.ModelMessage)
	switch host {
	case HostCodex:
		switch ev {
		case PreCompact:
			// The only way to block a Codex compaction (HOOKS-IO §3.4).
			return jsonOutput(codexCompactBlock{Continue: false, StopReason: user})
		case PreToolUse, PermissionRequest:
			return Output{Stderr: []byte(model + "\n"), Exit: ExitBlockCode2}
		default: // UserPromptSubmit
			return Output{Stderr: []byte(user + "\n"), Exit: ExitBlockCode2}
		}
	case HostCursor:
		if ev == UserPromptSubmit {
			return jsonOutput(cursorPromptBlock{Continue: false, UserMessage: user})
		}
		return jsonOutput(cursorToolDeny{Permission: "deny", UserMessage: user, AgentMessage: model})
	case HostCopilot:
		return jsonOutput(copilotToolDeny{PermissionDecision: "deny", PermissionDecisionReason: model})
	case HostUnknown:
		// No format to answer in: the shim applies its roots.list rule.
		return Output{Exit: ExitFailure}
	}
	// claude-code, Droid.
	switch ev {
	case UserPromptSubmit:
		var o claudePromptBlock
		o.Decision = "block"
		o.Reason = user
		o.HookSpecificOutput.HookEventName = string(UserPromptSubmit)
		o.HookSpecificOutput.SuppressOriginalPrompt = true
		return jsonOutput(o)
	case PreToolUse:
		var o claudeToolDeny
		o.Continue = false
		o.StopReason = user
		o.HookSpecificOutput.HookEventName = string(PreToolUse)
		o.HookSpecificOutput.PermissionDecision = "deny"
		o.HookSpecificOutput.PermissionDecisionReason = model
		return jsonOutput(o)
	case PermissionRequest:
		var o claudePermissionDeny
		o.HookSpecificOutput.HookEventName = string(PermissionRequest)
		o.HookSpecificOutput.Decision.Behavior = "deny"
		o.HookSpecificOutput.Decision.Message = model
		return jsonOutput(o)
	default: // PreCompact
		return jsonOutput(claudeCompactBlock{Decision: "block", Reason: user})
	}
}

// failClosed implements FailClosed.
func failClosed(host Host, ev Event, folder string) Output {
	if host == HostUnknown {
		if isGate(host, ev) {
			return Output{Exit: ExitFailure}
		}
		return Output{Exit: ExitOK}
	}
	return encode(host, ev, failDecision(ev, folder, false))
}

// failDecision is the block/deny of a gate event in a managed session when
// precinto cannot decide, and the locked-folder notice of SessionStart.
// down reports an unreachable or untrusted daemon (ipc.ErrNoDaemon,
// ipc.ErrUntrustedServer): the agent stopped (it exits when idle while
// every folder is locked), so the prompt text is C3.agentdown. Every other
// cause (decode error, deadline, panic, a failing gate query, an unknown
// verdict) is C3.failed (CC-38, HOOKS-IO §2.4).
func failDecision(ev Event, folder string, down bool) Decision {
	v := ui.Vars{Folder: displayFolder(folder)}
	switch ev {
	case UserPromptSubmit:
		if down {
			return Decision{Verdict: ipc.VerdictBlock, UserMessage: ui.Format(ui.MsgAgentDown, v)}
		}
		return Decision{Verdict: ipc.VerdictBlock, UserMessage: ui.Format(ui.MsgGateFailed, v)}
	case PreToolUse, PermissionRequest:
		return Decision{Verdict: ipc.VerdictDeny, UserMessage: ui.Format(ui.MsgToolStop, v), ModelMessage: ui.Format(ui.MsgToolDenied, v)}
	case PreCompact:
		return Decision{Verdict: ipc.VerdictBlock, UserMessage: ui.Format(ui.MsgCompactPaused, v)}
	case SessionStart:
		return Decision{Verdict: ipc.VerdictAllow, Context: ui.Format(ui.MsgStartLockedModel, v)}
	}
	return Decision{Verdict: ipc.VerdictAllow}
}

// displayFolder keeps message texts well formed when no folder is known.
func displayFolder(folder string) string {
	if folder = oneLine(folder); folder == "" {
		return "~"
	}
	return folder
}

// nonEmpty returns a one-line, bounded s, or the static D.shim text when s
// is empty: an empty reason would let Codex proceed (HOOKS-IO §3.4).
func nonEmpty(s string) string {
	if s = oneLine(s); s != "" {
		return s
	}
	return ui.Format(ui.MsgShimFailed, ui.Vars{})
}

// oneLine strips control characters (a newline would end Codex's stderr
// reason early; the texts are single lines) and bounds the length.
func oneLine(s string) string {
	b := ui.SanitizeTerminal([]byte(s))
	b = bytes.ReplaceAll(b, []byte("\n"), []byte(" "))
	b = bytes.ReplaceAll(b, []byte("\t"), []byte(" "))
	out := strings.TrimSpace(string(b))
	if len(out) > maxMessage {
		out = strings.ToValidUTF8(out[:maxMessage], "")
	}
	return out
}

// jsonOutput renders one JSON object on stdout without a trailing newline
// (the shim's command substitution would drop it anyway), exit 0.
func jsonOutput(v any) Output {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		// Unreachable: every output type is plain strings and booleans.
		return Output{Exit: ExitFailure}
	}
	return Output{Stdout: bytes.TrimSuffix(b.Bytes(), []byte("\n")), Exit: ExitOK}
}
