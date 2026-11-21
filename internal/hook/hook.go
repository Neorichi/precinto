package hook

import (
	"context"
	"io"
	"time"

	"github.com/precinto/precinto/internal/config"
	"github.com/precinto/precinto/internal/ipc"
	"github.com/precinto/precinto/internal/ledger"
	"github.com/precinto/precinto/internal/paths"
	"github.com/precinto/precinto/internal/platform"
	"github.com/precinto/precinto/internal/sweep/queue"
)

// Exit codes of the binary in hook mode (D43, D56). The POSIX shim passes
// stdout through on ExitOK, maps ExitBlockCode2 to 2, and treats any other
// exit (ExitFailure, a Go runtime exit 2, a signal) like a missing binary:
// it discards stdout and, for gate events whose $PWD or
// $CLAUDE_PROJECT_DIR lies inside a root of roots.list, prints the host's
// static block (text ui.MsgShimFailed); otherwise it exits 0.
const (
	ExitOK         = 0
	ExitBlockCode2 = 10 // intended "exit 2" block (Codex UserPromptSubmit, PreToolUse, PermissionRequest)
	ExitFailure    = 1  // internal failure (never used deliberately for a managed gate event: FailClosed instead)
)

// MaxPayload bounds stdin; larger payloads are treated as a decode failure
// (fail closed for managed gate events).
const MaxPayload = 64 << 20

// Host is the harness that actually invoked the hook (HA21).
type Host string

// Hosts.
const (
	HostClaude  Host = "claude-code"
	HostCodex   Host = "codex"
	HostCursor  Host = "cursor"  // experimental (D41)
	HostCopilot Host = "copilot" // experimental (D41)
	HostDroid   Host = "droid"   // Claude-compatible payloads, Droid tool names
	HostUnknown Host = "unknown" // neither markers nor the argv label name a host: gate events inside a root exit ExitFailure (the shim then blocks), others exit 0
)

// Event is a hook event name in Claude's PascalCase spelling; decoders map
// other hosts' names (camelCase) onto it.
type Event string

// Events.
const (
	SessionStart      Event = "SessionStart"
	UserPromptSubmit  Event = "UserPromptSubmit"
	PreToolUse        Event = "PreToolUse"
	PermissionRequest Event = "PermissionRequest"
	PostToolUse       Event = "PostToolUse"
	PreCompact        Event = "PreCompact"
	PostCompact       Event = "PostCompact"
	Stop              Event = "Stop"
	StopFailure       Event = "StopFailure"
	Interrupt         Event = "Interrupt"
	Notification      Event = "Notification"
	CwdChanged        Event = "CwdChanged"
	DirectoryAdded    Event = "DirectoryAdded"
	SessionEnd        Event = "SessionEnd"
)

// IsGate reports whether ev can block on host (prompt, tool, compaction or
// permission gate).
func IsGate(host Host, ev Event) bool { panic("unimplemented: hook.IsGate") }

// Timing is the harness timeout declared in the hooks file and the hook's
// own deadline, which must end strictly before it (D22).
type Timing struct {
	HarnessTimeout time.Duration
	Deadline       time.Duration // print a decision and exit before this
	UnlockWait     time.Duration // max time waiting for a GUI unlock (UserPromptSubmit only)
}

// Timings returns the normative timing for host/event (docs/HOOKS-IO.md §1).
func Timings(host Host, ev Event) Timing { panic("unimplemented: hook.Timings") }

// DetectHost identifies the real host (HA21, D56; docs/HOOKS-IO.md §0.7),
// first match wins: other-host markers (CURSOR_VERSION/CURSOR_PLUGIN_ROOT ⇒
// cursor; COPILOT_* or camelCase event names ⇒ copilot;
// DROID_PLUGIN_ROOT/FACTORY_PROJECT_DIR ⇒ droid); Codex markers (turn_id in
// the payload, or PLUGIN_ROOT set with label "codex" or with neither
// CLAUDE_PID nor CLAUDECODE); Claude markers (CLAUDE_PID, CLAUDECODE=1,
// CLAUDE_PROJECT_DIR); otherwise the argv label itself, which names the
// hooks file that invoked it. HostUnknown only for an unrecognised label
// with no markers. A missing marker never makes a gate fail open.
func DetectHost(label string, env paths.Env, raw []byte) Host {
	panic("unimplemented: hook.DetectHost")
}

// Payload is the normalized, content-free view of one invocation. Raw
// prompts, tool input/output and summaries are never retained.
type Payload struct {
	Host           Host
	Label          string // harness label from argv
	Event          Event
	SID            string
	PromptID       string
	TurnID         string
	TranscriptPath string
	Cwd            string
	ProjectDir     string // CLAUDE_PROJECT_DIR
	ConfigDir      string // derived from transcript_path / CLAUDE_CONFIG_DIR / CODEX_HOME
	ScratchpadDir  string
	Source         string // SessionStart source
	Reason         string // SessionEnd reason
	Trigger        string // PreCompact trigger
	ToolName       string
	Notification   string   // notification_type (idle_prompt…)
	Paths          []string // absolute paths from tool_input (file_path, notebook_path, path), apply_patch headers
	MarkdownPaths  []string // subset of Paths written by Write/Edit/MultiEdit/NotebookEdit/apply_patch ending .md/.mdx/.markdown
	OldCwd, NewCwd string
	AddedDirs      []string
	HarnessPID     int             // CLAUDE_PID, or nearest ancestor whose executable is codex (HA17)
	HarnessProc    platform.ProcID // measured by precinto
	HarnessVersion string
	Entrypoint     string // CLAUDE_CODE_ENTRYPOINT
	CodexHome      string // CODEX_HOME seen by the hook (D31 check)
	AgentID        string // subagent context
}

// Decode reads at most MaxPayload bytes of raw (already read from stdin)
// and the environment into a Payload.
func Decode(host Host, label string, ev Event, raw []byte, env paths.Env, procs platform.ProcTable) (Payload, error) {
	panic("unimplemented: hook.Decode")
}

// Decision is what the hook answers.
type Decision struct {
	Verdict      ipc.Verdict // allow | block | deny
	UserMessage  string      // shown to the user (block reason, PreCompact stderr)
	ModelMessage string      // PreToolUse deny reason addressed to the model
	Context      string      // SessionStart additionalContext (locked folder notice)
}

// Output is the rendered answer.
type Output struct {
	Stdout []byte
	Stderr []byte
	Exit   int
}

// Encode renders d for host/event exactly as docs/HOOKS-IO.md specifies
// (Claude: decision JSON on stdout with exit 0; Codex UserPromptSubmit,
// PreToolUse and PermissionRequest: fixed stderr reason with
// ExitBlockCode2; Codex PreCompact: {"continue":false,"stopReason":…};
// Codex SessionStart: nothing in v0.2; allow: empty stdout, exit 0). It
// never emits keys a host does not accept (Codex deny_unknown_fields).
func Encode(host Host, ev Event, d Decision) Output { panic("unimplemented: hook.Encode") }

// FailClosed returns the static block/deny output used on every error path
// of a gate event in a managed session (daemon unreachable, decode error,
// deadline, panic) (I5), in the format of host (the detected host, which
// defaults to the argv label, D56).
func FailClosed(host Host, ev Event, folder string) Output { panic("unimplemented: hook.FailClosed") }

// Daemon is the subset of the ipc client the hook uses (fakeable;
// *ipc.Client implements it, asserted in cmd/precinto).
type Daemon interface {
	Gate(ctx context.Context, r ipc.GateReq) (ipc.GateResp, error)
	Activity(ctx context.Context, r ipc.ActivityReq) error
	Register(ctx context.Context, r ipc.RegisterReq) error
	Unlock(ctx context.Context, r ipc.UnlockReq, ui ipc.UIHandler) (ipc.UnlockResp, error)
	Close() error
}

// Ledger is the subset of the ledger the hook uses (fakeable;
// *ledger.Ledger implements it).
type Ledger interface {
	Append(e ledger.Event) error
	Get(harness, sid string) (ledger.Session, error)
}

// Deps are the hook's dependencies; every field is fakeable so golden tests
// need no other group's implementation.
type Deps struct {
	Cfg    config.Config
	Layout paths.Layout
	Env    paths.Env
	Ledger Ledger
	Procs  platform.ProcTable
	// Identify measures the ProcID of the harness pid (platform.Identify).
	Identify func(pid int) (platform.ProcID, error)
	Now      func() time.Time
	// Dial connects without autostart within ipc.GateBudget.
	Dial func(ctx context.Context) (Daemon, error)
	// DialUnlock connects with autostart for the slow unlock path only
	// (IM7).
	DialUnlock func(ctx context.Context) (Daemon, error)
	// Enqueue writes a seal request (SessionEnd) and Spawn starts the
	// detached `precinto seal --queue` worker (Setsid, stdio /dev/null).
	Enqueue func(r queue.Request) (string, error)
	Spawn   func(argv []string) error
}

// Handle runs the decision logic for one decoded payload: ledger taint and
// facts, gate for managed sessions (fail closed when the daemon is
// unreachable), optional GUI unlock for human prompts, activity, and the
// SessionEnd seal request. It never blocks SessionStart and never prompts
// from it.
func Handle(ctx context.Context, d Deps, p Payload) Decision { panic("unimplemented: hook.Handle") }

// Main is the whole `precinto hook <label> <event>` command: platform
// hardening, deadline from Timings, panic recovery (fail closed for managed
// gate events, exit 0 otherwise), Decode, Handle, Encode. It returns the
// process exit code.
func Main(args []string, stdin io.Reader, stdout, stderr io.Writer, env paths.Env) int {
	panic("unimplemented: hook.Main")
}
