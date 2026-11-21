package hook

import (
	"strings"
	"time"
)

// knownEvents are the events precinto's hooks files register, in Claude's
// PascalCase spelling (Codex uses the same names).
var knownEvents = map[Event]bool{
	SessionStart: true, UserPromptSubmit: true, PreToolUse: true, PermissionRequest: true,
	PostToolUse: true, PreCompact: true, PostCompact: true, Stop: true, StopFailure: true,
	Interrupt: true, Notification: true, CwdChanged: true, DirectoryAdded: true, SessionEnd: true,
}

// eventAliases maps other hosts' camelCase event names onto Event (HOOKS-IO
// §4; the Cursor and Copilot names are UNVERIFIED drafts, D41).
var eventAliases = map[string]Event{
	// Cursor
	"beforeSubmitPrompt":   UserPromptSubmit,
	"preToolUse":           PreToolUse,
	"beforeShellExecution": PreToolUse,
	"beforeMCPExecution":   PreToolUse,
	"beforeReadFile":       PreToolUse,
	"postToolUse":          PostToolUse,
	"afterFileEdit":        PostToolUse,
	"preCompact":           PreCompact,
	"stop":                 Stop,
	"sessionStart":         SessionStart,
	"sessionEnd":           SessionEnd,
	// Copilot CLI
	"userPromptSubmitted": UserPromptSubmit,
	"errorOccurred":       StopFailure,
}

// parseEvent maps an event name from argv onto Event. Unknown names are
// kept as they are: they are never gate events, so they exit 0.
func parseEvent(name string) Event {
	if knownEvents[Event(name)] {
		return Event(name)
	}
	if e, ok := eventAliases[name]; ok {
		return e
	}
	return Event(name)
}

// camelCase reports whether an event name is spelled the way Cursor and
// Copilot spell theirs (host marker, HOOKS-IO §0.7).
func camelCase(name string) bool {
	return name != "" && name[0] >= 'a' && name[0] <= 'z' && !strings.ContainsAny(name, "_- ")
}

// claudeFormat reports whether host answers in Claude's hook format: Claude
// itself and Droid, which installs Claude plugins (HOOKS-IO §4).
func claudeFormat(host Host) bool { return host == HostClaude || host == HostDroid }

// isGate implements IsGate.
func isGate(host Host, ev Event) bool {
	switch host {
	case HostCursor:
		// beforeSubmitPrompt and the tool gates; preCompact is observe-only.
		return ev == UserPromptSubmit || ev == PreToolUse
	case HostCopilot:
		// userPromptSubmitted cannot block; preCompact is observe-only.
		return ev == PreToolUse
	}
	switch ev {
	case UserPromptSubmit, PreToolUse, PermissionRequest, PreCompact:
		return true
	}
	return false
}

// defaultTiming applies to events no hooks file registers for the host.
var defaultTiming = Timing{Deadline: 3 * time.Second}

// timings implements Timings (docs/HOOKS-IO.md §1). HarnessTimeout is 0 for
// async events, whose timeout the harness does not enforce; SessionEnd on
// Claude has the shared 1.5 s budget instead of a declared timeout.
func timings(host Host, ev Event) Timing {
	const s = time.Second
	gate := Timing{HarnessTimeout: 10 * s, Deadline: 7 * s}
	prompt := Timing{HarnessTimeout: 90 * s, Deadline: 85 * s, UnlockWait: 60 * s}
	quick := Timing{HarnessTimeout: 10 * s, Deadline: 5 * s}
	async := Timing{Deadline: 5 * s}
	switch host {
	case HostCodex:
		switch ev {
		case UserPromptSubmit:
			return prompt
		case PreToolUse, PermissionRequest, PreCompact:
			return gate
		case SessionStart, PostToolUse:
			return quick
		case Interrupt, SessionEnd:
			return Timing{HarnessTimeout: 3 * s, Deadline: 2 * s}
		case Stop, PostCompact:
			return async
		}
		return defaultTiming
	case HostCopilot:
		// plugin/hooks/copilot.json declares timeoutSec 10 everywhere; its
		// prompt hook cannot block, so it never waits for an unlock.
		switch ev {
		case PreToolUse:
			return gate
		case SessionStart, UserPromptSubmit, PostToolUse, SessionEnd, StopFailure:
			return quick
		}
		return defaultTiming
	}
	// claude-code and the Claude-format hosts (Droid shares hooks.json;
	// cursor.json declares the same values).
	switch ev {
	case UserPromptSubmit:
		return prompt
	case PreToolUse, PermissionRequest, PreCompact:
		return gate
	case SessionStart, PostToolUse:
		return quick
	case CwdChanged, DirectoryAdded:
		return Timing{HarnessTimeout: 5 * s, Deadline: 3 * s}
	case Stop, StopFailure, Notification, PostCompact:
		return async
	case SessionEnd:
		return Timing{HarnessTimeout: 1500 * time.Millisecond, Deadline: 1 * s}
	}
	return defaultTiming
}
