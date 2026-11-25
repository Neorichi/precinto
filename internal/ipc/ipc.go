package ipc

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/awnumar/memguard"

	"github.com/Neorichi/precinto/internal/fsx"
	"github.com/Neorichi/precinto/internal/paths"
	"github.com/Neorichi/precinto/internal/platform"
)

// Protocol constants.
const (
	Version  = 1
	MaxFrame = 1 << 20

	// GateBudget is the total time a hook may spend dialing and asking the
	// daemon (SPEC §14.2). On expiry the hook fails closed for managed
	// sessions.
	GateBudget = 150 * time.Millisecond
)

// FrameKind tags a frame.
type FrameKind byte

// Frame kinds.
const (
	FrameJSON   FrameKind = 'J'
	FrameSecret FrameKind = 'S'
)

// WriteFrame writes one frame.
func WriteFrame(w io.Writer, kind FrameKind, payload []byte) error {
	return writeFrame(w, kind, payload)
}

// ReadFrame reads one frame into buf (grown up to MaxFrame) and returns the
// payload slice aliasing buf; callers wipe buf after secret frames.
func ReadFrame(r io.Reader, buf []byte) (FrameKind, []byte, error) {
	return readFrame(r, buf)
}

// Op names a request.
type Op string

// Operations (SPEC §13.3).
const (
	OpHello       Op = "hello"
	OpStatus      Op = "status"
	OpGate        Op = "gate"
	OpActivity    Op = "activity"
	OpRegister    Op = "register"
	OpUnregister  Op = "unregister"
	OpUnlock      Op = "unlock"
	OpUIReply     Op = "ui_reply" // client → daemon answer to a UIRequest during Unlock
	OpLock        Op = "lock"
	OpKeys        Op = "keys"
	OpSubscribe   Op = "subscribe"
	OpVaultCreate Op = "vault_create"
	OpFactorAdd   Op = "factor_add"
	OpVaultRepair Op = "vault_repair" // rewrite a tampered recipient set after a TTY unwrap (D53)
	OpPolicy      Op = "policy"       // confirm pending weakening changes (D48)
	OpShutdown    Op = "shutdown"
)

// Code is a machine-readable error code; ExitCode maps it to SPEC §16.2.
type Code string

// Error codes.
const (
	CodeLocked       Code = "locked"        // exit 3
	CodeUnauthorized Code = "unauthorized"  // exit 3
	CodeAgentContext Code = "agent_context" // exit 3 (D28)
	CodeCancelled    Code = "cancelled"     // exit 3
	CodeBadSecret    Code = "bad_secret"    // exit 3: wrong passphrase or recovery key (vault.ErrBadSecret, C2.badsecret)
	CodeNoUI         Code = "no_ui"         // exit 3 (D27)
	CodeRateLimited  Code = "rate_limited"  // exit 3 (D27)
	CodeLive         Code = "live"          // exit 4
	CodeVerify       Code = "verify"        // exit 5 (MAC mismatch, recipients changed, repair check failed)
	CodeBadRequest   Code = "bad_request"   // exit 2
	CodeVersion      Code = "version"       // exit 1
	CodeNotLogged    Code = "not_logged"    // exit 5 (provenance, D8)
	CodeInternal     Code = "internal"      // exit 1
)

// Error is the error object of a Response.
type Error struct {
	Code Code   `json:"code"`
	Msg  string `json:"msg"` // user-facing, from the ui catalog; never OS error text
}

// Error implements error.
func (e *Error) Error() string { return string(e.Code) + ": " + e.Msg }

// ExitCode maps the error to the CLI exit codes of SPEC §16.2.
func (e *Error) ExitCode() int {
	switch e.Code {
	case CodeLocked, CodeUnauthorized, CodeAgentContext, CodeCancelled, CodeBadSecret, CodeNoUI, CodeRateLimited:
		return 3
	case CodeLive:
		return 4
	case CodeVerify, CodeNotLogged:
		return 5
	case CodeBadRequest:
		return 2
	default:
		return 1
	}
}

// ErrUntrustedServer is returned by Dial when the socket directory or the
// server executable fails mutual authentication (D6).
var ErrUntrustedServer = errors.New("ipc: daemon identity mismatch; run precinto agent --restart")

// ErrNoDaemon is returned by Dial when no daemon listens and autostart is
// off or failed.
var ErrNoDaemon = errors.New("ipc: precinto agent is not running")

// Request is one JSON control frame from a client. Exactly one payload
// pointer matching Op is set. Secrets frames that follow are counted by
// Secrets.
type Request struct {
	V           int             `json:"v"`
	ID          uint64          `json:"id"`
	Op          Op              `json:"op"`
	Secrets     int             `json:"secrets,omitempty"`
	Hello       *Hello          `json:"hello,omitempty"`
	Gate        *GateReq        `json:"gate,omitempty"`
	Activity    *ActivityReq    `json:"activity,omitempty"`
	Register    *RegisterReq    `json:"register,omitempty"`
	Unregister  *UnregisterReq  `json:"unregister,omitempty"`
	Unlock      *UnlockReq      `json:"unlock,omitempty"`
	UIReply     *UIReply        `json:"ui_reply,omitempty"`
	Lock        *LockReq        `json:"lock,omitempty"`
	Keys        *KeysReq        `json:"keys,omitempty"`
	Subscribe   *SubscribeReq   `json:"subscribe,omitempty"`
	VaultCreate *VaultCreateReq `json:"vault_create,omitempty"`
	FactorAdd   *FactorAddReq   `json:"factor_add,omitempty"`
	VaultRepair *VaultRepairReq `json:"vault_repair,omitempty"`
	Policy      *PolicyReq      `json:"policy,omitempty"`
}

// Response is one JSON control frame from the daemon. During Unlock the
// daemon may send Responses carrying UI (a prompt to relay) before the final
// one; Subscribe streams Responses carrying Event.
type Response struct {
	V       int              `json:"v"`
	ID      uint64           `json:"id"`
	OK      bool             `json:"ok"`
	Err     *Error           `json:"err,omitempty"`
	Secrets int              `json:"secrets,omitempty"`
	Hello   *HelloResp       `json:"hello,omitempty"`
	Status  *StatusResp      `json:"status,omitempty"`
	Gate    *GateResp        `json:"gate,omitempty"`
	Unlock  *UnlockResp      `json:"unlock,omitempty"`
	Lock    *LockResp        `json:"lock,omitempty"`
	Keys    *KeysResp        `json:"keys,omitempty"`
	UI      *UIRequest       `json:"ui,omitempty"`
	Event   *Event           `json:"event,omitempty"`
	Repair  *VaultRepairResp `json:"repair,omitempty"`
	Policy  *PolicyResp      `json:"policy,omitempty"`
}

// Hello opens every connection.
type Hello struct {
	Client  string `json:"client"` // "hook" | "cli" | "wrapper" | "sweep" | "shell"
	Version string `json:"version"`
}

// HelloResp answers Hello.
type HelloResp struct {
	Version  string    `json:"version"`
	PID      int       `json:"pid"`
	Started  time.Time `json:"started"`
	Protocol int       `json:"protocol"`
}

// Verdict is a gate decision.
type Verdict string

// Verdicts.
const (
	VerdictAllow Verdict = "allow"
	VerdictBlock Verdict = "block" // prompt / compaction blocked
	VerdictDeny  Verdict = "deny"  // tool or permission denied
)

// PromptOrigin classifies a UserPromptSubmit (D23, D26, D37, D54). Only the
// daemon computes it (wrapper Enter timestamps, system HID idle); a
// client never supplies one.
type PromptOrigin string

// Prompt origins.
const (
	OriginHuman     PromptOrigin = "human"
	OriginAutomated PromptOrigin = "automated"
	OriginUnknown   PromptOrigin = "unknown" // HID idle unreadable: never moves the idle clock, never raises a dialog (D54)
)

// GateReq asks whether a hook event may proceed. The daemon computes the
// root set itself from the ledger and the facts below; Roots is advisory
// (HA10). The daemon never trusts a ProcID from a client: it measures PID
// itself (SPEC §9.1).
type GateReq struct {
	Harness    string   `json:"harness"` // label from argv
	Host       string   `json:"host"`    // detected real host (HA21, D56)
	Event      string   `json:"event"`   // harness event name
	SID        string   `json:"sid"`
	PromptID   string   `json:"prompt_id,omitempty"`
	TurnID     string   `json:"turn_id,omitempty"`
	Cwd        string   `json:"cwd"`
	ProjectDir string   `json:"project_dir,omitempty"` // CLAUDE_PROJECT_DIR
	Paths      []string `json:"paths,omitempty"`       // absolute tool paths / added dirs
	Roots      []string `json:"roots,omitempty"`       // root ids the hook computed
	ToolName   string   `json:"tool_name,omitempty"`
	Trigger    string   `json:"trigger,omitempty"` // PreCompact manual|auto
	PID        int      `json:"pid,omitempty"`     // harness pid (CLAUDE_PID, or the nearest codex ancestor); measured again by the daemon
	CodexHome  string   `json:"codex_home,omitempty"`
	// ConfigDir and TmpDir are, for Claude Code, the session's config
	// folder (from transcript_path) and temporary folder (from the
	// scratchpad path): under WSL the daemon blocks the session in a
	// folder that manages Claude when one is on a Windows drive (D156).
	// Advisory: they can only make the gate stricter.
	ConfigDir string `json:"config_dir,omitempty"`
	TmpDir    string `json:"tmp_dir,omitempty"`
}

// GateResp is the daemon's decision; texts come from the ui catalog and are
// built from verified data (D27).
type GateResp struct {
	Verdict        Verdict      `json:"verdict"`
	Reason         string       `json:"reason,omitempty"` // ui.Reason code
	UserMessage    string       `json:"user_message,omitempty"`
	ModelMessage   string       `json:"model_message,omitempty"` // PreToolUse deny text addressed to the model
	State          string       `json:"state"`                   // "unlocked" | "locked" | "paused"
	RootIDs        []string     `json:"root_ids,omitempty"`
	Origin         PromptOrigin `json:"origin,omitempty"`          // computed by the daemon and recorded for (sid, prompt id) (D54)
	UnlockEligible bool         `json:"unlock_eligible,omitempty"` // a hook may attempt a GUI unlock now (D27, D37)
}

// ActivityKind is a session activity signal.
type ActivityKind string

// Activity kinds. Only two kinds move the idle clock (D23, D54): Input and
// Enter, accepted only from a peer that runs the same executable and whose
// measured ProcID equals the session's registered wrapper (others are
// dropped); and Prompt, only when the origin the daemon itself computed at
// gate time for (sid, prompt/turn id) was OriginHuman.
const (
	ActInput        ActivityKind = "input"        // wrapper: human keystrokes (filtered, rate-limited)
	ActEnter        ActivityKind = "enter"        // wrapper: an Enter keystroke reached the PTY (D37)
	ActPrompt       ActivityKind = "prompt"       // UserPromptSubmit allowed; matched to the gate's recorded origin
	ActTool         ActivityKind = "tool"         // Pre/PostToolUse
	ActStop         ActivityKind = "stop"         // Stop: turn ended
	ActStopFailure  ActivityKind = "stop_failure" // StopFailure
	ActInterrupt    ActivityKind = "interrupt"    // Codex Interrupt
	ActIdlePrompt   ActivityKind = "idle_prompt"  // Notification(idle_prompt): clears busy, no idle reset (HA7)
	ActPermission   ActivityKind = "permission"   // waiting on a permission/elicitation: counts as idle
	ActCompactBegin ActivityKind = "compact_begin"
	ActCompactEnd   ActivityKind = "compact_end"
	ActSessionEnd   ActivityKind = "session_end"
)

// ActivityReq reports activity; fire-and-forget is allowed. It carries no
// origin: the daemon uses only the origin it computed itself at gate time
// (D54), and accepts Input/Enter only from the verified wrapper peer.
type ActivityReq struct {
	Harness  string       `json:"harness"`
	SID      string       `json:"sid"`
	Kind     ActivityKind `json:"kind"`
	PromptID string       `json:"prompt_id,omitempty"`
	TurnID   string       `json:"turn_id,omitempty"`
	At       time.Time    `json:"at"` // the client's time of the activity, informational: the daemon times activity with its own clock (D54, D77)
}

// RegisterReq announces a live harness process. The daemon measures the
// ProcID itself from PID and verifies the executable against the harness
// inventory before accepting (S14). Wrapper=true is accepted only from a
// peer that runs the same executable and whose measured ProcID is
// WrapperPID (the wrapper registers itself); otherwise the registration is
// recorded as unwrapped and Input/Enter activity for it is dropped (D54).
type RegisterReq struct {
	Harness    string   `json:"harness"`
	SID        string   `json:"sid,omitempty"` // empty for a wrapper launch before the sid is known
	PID        int      `json:"pid"`
	Cwd        string   `json:"cwd"`
	ProjectDir string   `json:"project_dir,omitempty"`
	RootIDs    []string `json:"root_ids,omitempty"`
	Wrapper    bool     `json:"wrapper"`
	WrapperPID int      `json:"wrapper_pid,omitempty"` // must equal the peer's own pid
	TTY        string   `json:"tty,omitempty"`         // the session's terminal (hook-dialog OSC 9 notice, D60; TTY scrub)
	ConfigDir  string   `json:"config_dir,omitempty"`
	Version    string   `json:"version,omitempty"`
	Background bool     `json:"background,omitempty"`
	TermITerm  bool     `json:"term_iterm,omitempty"`
}

// UnregisterReq removes a wrapper registration after the child exited.
type UnregisterReq struct {
	Harness string `json:"harness"`
	SID     string `json:"sid,omitempty"`
	PID     int    `json:"pid"`
}

// UnlockReq asks the daemon to unwrap vault identities with user presence.
// The daemon runs the factor (age plugin or scrypt) itself and relays UI
// through UIRequest frames to this connection (D4).
type UnlockReq struct {
	RootIDs     []string      `json:"root_ids,omitempty"`
	All         bool          `json:"all,omitempty"`    // every root (one prompt per root, D40)
	Global      bool          `json:"global,omitempty"` // the global vault (D1)
	Factor      string        `json:"factor,omitempty"`
	TTL         time.Duration `json:"ttl,omitempty"` // clamped to min(max_unlock, 24h) (S8)
	Extend      bool          `json:"extend,omitempty"`
	TTY         bool          `json:"tty"`       // the client can prompt on a terminal
	Confirmed   bool          `json:"confirmed"` // the client obtained typed confirmation for multi-root
	FromHook    bool          `json:"from_hook,omitempty"`
	SID         string        `json:"sid,omitempty"`          // hook: the session requesting it
	Deadline    time.Time     `json:"deadline"`               // real time (the client's time.Now): the daemon bounds the unlock with it on its own clock; never from a test clock (D77)
	ConfirmDiff bool          `json:"confirm_diff,omitempty"` // also confirm pending policy changes (D48)
	// AgentMarkers are the client's own paths.AgentMarkers: a
	// self-restricting claim. The daemon unions it with the ancestry and
	// no-controlling-terminal rules it measures itself and never treats an
	// empty list as proof of a human (D28, D59).
	AgentMarkers []string `json:"agent_markers,omitempty"`
	// Test is a factor test (precinto factor test): unwrap with Factor and
	// verify, then drop; no grant, no restore worker, no policy re-pin.
	Test bool `json:"test,omitempty"`
}

// UnlockResp lists what was unlocked.
type UnlockResp struct {
	Unlocked []string  `json:"unlocked"` // vault ids
	Until    time.Time `json:"until"`    // absolute deadline
	Pending  []string  `json:"pending,omitempty"`
}

// UIKind is a relayed prompt kind.
type UIKind string

// UI kinds.
const (
	UIDisplay UIKind = "display"
	UISecret  UIKind = "secret"
	UIConfirm UIKind = "confirm"
	UIWait    UIKind = "wait"
)

// UIRequest is a prompt the daemon relays to the client during Unlock.
type UIRequest struct {
	Seq    int    `json:"seq"`
	Kind   UIKind `json:"kind"`
	Prompt string `json:"prompt"`
	Yes    string `json:"yes,omitempty"`
	No     string `json:"no,omitempty"`
}

// UIReply answers a UIRequest; a secret answer follows in one 'S' frame.
type UIReply struct {
	Seq       int  `json:"seq"`
	OK        bool `json:"ok"` // false = cancelled
	Choice    bool `json:"choice,omitempty"`
	HasSecret bool `json:"has_secret,omitempty"`
}

// LockReq locks folders.
type LockReq struct {
	RootIDs   []string `json:"root_ids,omitempty"`
	All       bool     `json:"all,omitempty"` // default scope of `precinto lock` (UX16)
	End       bool     `json:"end,omitempty"` // also end sessions (alias --hard)
	Force     bool     `json:"force,omitempty"`
	LetFinish bool     `json:"let_finish,omitempty"`
}

// LockResp reports the result; a lock always completes (I15).
type LockResp struct {
	Locked   []string `json:"locked"`
	Ended    []string `json:"ended,omitempty"`    // session ids
	Unsealed []string `json:"unsealed,omitempty"` // unit keys still plaintext, with reasons in status
}

// CapsuleRef names one capsule for key release.
type CapsuleRef struct {
	Path string `json:"path"` // relative to CapsulesDir
}

// Key-release purposes (KeysReq.Purpose). The agent-context rules of D28
// and D59 depend on them.
const (
	PurposeRestore    = "restore"     // targeted restores: wrapper launch, the daemon's post-unlock restore worker, restore --root/--session
	PurposeRestoreAll = "restore-all" // precinto restore --all
	PurposeOpen       = "open"        // precinto open
	PurposeCat        = "cat"         // precinto cat (TTY or --to FILE)
	PurposeList       = "list"        // ls titles
)

// MaxKeysPerRequest bounds a keys request: it names at most this many
// capsules (bad_request otherwise). Clients batch and destroy each file key
// as soon as its capsule is decrypted, so locked memory stays small.
const MaxKeysPerRequest = 256

// KeysReq asks for per-capsule file keys (D39).
type KeysReq struct {
	Capsules []CapsuleRef `json:"capsules"` // at most MaxKeysPerRequest
	Purpose  string       `json:"purpose"`  // one of the Purpose* constants
	// AgentMarkers are the client's own paths.AgentMarkers: a
	// self-restricting claim. The daemon unions it with the ancestry and
	// no-controlling-terminal rules it measures itself and never treats an
	// empty list as proof of a human (D28, D59).
	AgentMarkers []string `json:"agent_markers,omitempty"`
}

// KeyGrant describes one released key; the key itself follows in an 'S'
// frame, in Granted order.
type KeyGrant struct {
	Path    string `json:"path"`
	VaultID string `json:"vault_id"`
}

// KeysResp answers Keys.
type KeysResp struct {
	Granted []KeyGrant      `json:"granted"`
	Denied  map[string]Code `json:"denied,omitempty"`
}

// EventKind is a lock event pushed to subscribers.
type EventKind string

// Event kinds.
const (
	EventLocked   EventKind = "locked"
	EventUnlocked EventKind = "unlocked"
	// EventEnd is sent only on the subscriptions of wrappers whose session
	// the daemon ends (registration wrapper ProcID = subscribing peer), with
	// SIDs when known (D71): end these sessions now (hard lock).
	EventEnd       EventKind = "end"
	EventExpiring  EventKind = "expiring"
	EventHeartbeat EventKind = "heartbeat" // every 1 s; 2 s without one ⇒ wrapper locks locally
)

// Event is pushed on a subscription.
type Event struct {
	Kind     EventKind `json:"kind"`
	RootIDs  []string  `json:"root_ids,omitempty"`
	SIDs     []string  `json:"sids,omitempty"`
	Reason   string    `json:"reason,omitempty"` // ui.Reason
	Message  string    `json:"message,omitempty"`
	At       time.Time `json:"at"`
	Deadline time.Time `json:"deadline,omitempty"`
	Busy     bool      `json:"busy,omitempty"`
	// Factors are the folder's enrolled factor kinds in unlock order ("se",
	// "plugin", "passphrase"; never "recovery"), on locked, unlocked and
	// expiring events (ui.FactorName names one for {factor}).
	Factors []string `json:"factors,omitempty"`
}

// SubscribeReq subscribes to events for roots and/or a session.
type SubscribeReq struct {
	RootIDs []string `json:"root_ids"`
	SID     string   `json:"sid,omitempty"`
	Wrapper bool     `json:"wrapper"`
}

// VaultCreateReq creates the per-root vault at protect time (D1).
type VaultCreateReq struct {
	RootID   string `json:"root_id"`
	RootPath string `json:"root_path"`
}

// FactorAddReq enrolls a factor in every vault (all must be unlocked).
type FactorAddReq struct {
	Kind         string `json:"kind"`
	Recipient    string `json:"recipient,omitempty"`
	IdentityStub string `json:"identity_stub,omitempty"`
	PluginPath   string `json:"plugin_path,omitempty"`
	// PresencePolicy is a plugin factor's presence policy ("touch-always",
	// "touch-cached", "pin-always", "pin-once", "tpm-pin"); "" requires
	// NoPresenceAck (S10, vault.FactorSpec).
	PresencePolicy string `json:"presence_policy,omitempty"`
	NoPresenceAck  bool   `json:"no_presence_ack,omitempty"`
}

// VaultRepairReq asks the daemon to repair a vault whose recipient set
// failed the MAC or tripwire check (`precinto vault repair`, D53). Only from
// a same-executable peer with a TTY, never from an agent context. With
// UseRecovery the recovery identity follows in one 'S' frame (typed by the
// user); otherwise the daemon unwraps with a factor through relayed UI.
type VaultRepairReq struct {
	VaultID     string `json:"vault_id"` // root id or "global"
	UseRecovery bool   `json:"use_recovery,omitempty"`
	// Confirmed false is a dry run: unwrap (presence), genuineness check,
	// diff in VaultRepairResp, nothing written; the identity stays bound to
	// that connection for at most 120 s and any lock wipes it. true writes
	// (and unwraps again only on another connection or after that).
	Confirmed bool `json:"confirmed"`
}

// VaultRepairResp reports a repair.
type VaultRepairResp struct {
	RecipientChanged bool     `json:"recipient_changed"`
	RecoveryChanged  bool     `json:"recovery_changed"`
	Exposed          []string `json:"exposed,omitempty"` // capsule paths sealed since last_audit to a foreign recipient set
}

// PolicyReq confirms or lists pending weakening config changes (D48).
type PolicyReq struct {
	Confirm bool `json:"confirm"`
}

// PolicyResp lists pending changes.
type PolicyResp struct {
	Pending []string `json:"pending"`
}

// VaultStatus is one folder (vault) in status.
type VaultStatus struct {
	VaultID      string    `json:"vault_id"`
	RootPath     string    `json:"root_path,omitempty"`
	State        string    `json:"state"` // "locked" | "unlocking" (a single-flight unlock is in progress) | "unlocked"
	Reason       string    `json:"reason,omitempty"`
	Since        time.Time `json:"since"`
	IdleDeadline time.Time `json:"idle_deadline,omitempty"`
	AbsDeadline  time.Time `json:"abs_deadline,omitempty"`
	LastHuman    time.Time `json:"last_human,omitempty"`
	// Factors are the folder's enrolled factor kinds in unlock order ("se",
	// "plugin", "passphrase"; never "recovery").
	Factors []string `json:"factors,omitempty"`
}

// SessionStatus is one live or paused session in status.
type SessionStatus struct {
	Harness    string          `json:"harness"`
	SID        string          `json:"sid"`
	Proc       platform.ProcID `json:"proc"`
	RootIDs    []string        `json:"root_ids"`
	State      string          `json:"state"` // "running" | "paused" | "ending"
	Busy       bool            `json:"busy"`
	Wrapper    bool            `json:"wrapper"`
	Background bool            `json:"background"`
	HooksSeen  bool            `json:"hooks_seen"`
	Registered bool            `json:"registered"` // false: found by the process-table scan only (D52, D57)
	TTY        string          `json:"tty,omitempty"`
	Version    string          `json:"version,omitempty"` // harness version from register (SPEC §16.4 AGENTS line)
}

// Attention codes: one kebab-case vocabulary shared by `status` and
// `doctor` (internal/doctor reuses these constants as check codes).
const (
	AttnUnsealed        = "unsealed"          // plaintext of a locked folder, with reasons (§17)
	AttnHoldCapped      = "hold-capped"       // weak liveness holds beyond hold_cap (S14)
	AttnHistoryPending  = "history-pending"   // protected lines still in history.jsonl (§19)
	AttnPendingPolicy   = "pending-policy"    // weakening config edits awaiting confirmation (D48)
	AttnPolicyTampered  = "policy-tampered"   // state/policy.pinned failed its MAC (D55)
	AttnQuarantine      = "quarantine"        // capsules without provenance (D8)
	AttnRecoveryTested  = "recovery-tested"   // recovery key never tested (D7)
	AttnUnhardenedBuild = "unhardened-build"  // not signed with hardened runtime (S15)
	AttnCodexHooksTrust = "codex-hooks-trust" // Codex has not trusted precinto's hooks (UX10)
	AttnCodexWrongHome  = "codex-wrong-home"  // Codex wrote a protected folder's history to the user's home (HA1)
	AttnConflict        = "conflict"          // kept-both copies awaiting precinto resolve (D11)
	AttnUngatedSession  = "ungated-session"   // a session in a folder runs without a working gate (D52)
	AttnVaultTampered   = "vault-tampered"    // recipients MAC/tripwire failed: sealing paused; fix: precinto vault repair (D53)
	AttnExposed         = "exposed-capsules"  // capsules sealed to a foreign recipient set (D5 audit)
)

// Attention is one "needs attention" item (UX22).
type Attention struct {
	Code    string `json:"code"` // one of the Attn* constants
	Folder  string `json:"folder,omitempty"`
	Count   int    `json:"count,omitempty"`
	PID     int    `json:"pid,omitempty"`
	Detail  string `json:"detail,omitempty"`
	Fix     string `json:"fix,omitempty"`     // the command that fixes it, e.g. "precinto vault repair --root ~/work/acme"
	Harness string `json:"harness,omitempty"` // {harness} of C9.ungated
}

// StatusResp is the daemon side of `precinto status` (the CLI adds on-disk
// facts; schema v1 in SPEC §16.4).
type StatusResp struct {
	Version       string          `json:"version"`
	PID           int             `json:"pid"`
	Started       time.Time       `json:"started"`
	Vaults        []VaultStatus   `json:"vaults"`
	Sessions      []SessionStatus `json:"sessions"`
	Attention     []Attention     `json:"attention"`
	ScreenWatch   bool            `json:"screen_watch"`
	LastSweep     time.Time       `json:"last_sweep,omitempty"`
	PendingPolicy []string        `json:"pending_policy,omitempty"`
}

// UIHandler is the client side of relayed UI during Unlock.
type UIHandler interface {
	Display(msg string) error
	Secret(prompt string) (*memguard.LockedBuffer, error)
	Confirm(prompt, yes, no string) (bool, error)
}

// DialOptions configures Dial.
type DialOptions struct {
	Layout    paths.Layout
	Client    string        // Hello.Client
	Timeout   time.Duration // total dial+hello budget (hooks: GateBudget)
	Autostart bool          // start `<Exe> agent` detached if absent (never for the hook fast path)
	Exe       string        // absolute path of the precinto binary for autostart
	Env       []string      // allowlisted environment for the autostarted daemon
	// Insecure skips the executable identity check; only honoured in
	// -tags testing builds (tests that run the agent in-process).
	Insecure bool
}

// Client is a connection to the daemon. Not safe for concurrent requests.
type Client struct {
	mu     sync.Mutex
	opts   DialOptions
	w      *wire // nil once closed or broken
	nextID uint64
	hello  HelloResp
	subs   map[*wire]struct{}
	closed bool
}

// Dial authenticates the daemon (D6) and performs Hello. With Autostart it
// starts the daemon under run/agent.lock when absent and waits for it.
func Dial(ctx context.Context, o DialOptions) (*Client, error) { return dial(ctx, o) }

// Close closes the connection.
func (c *Client) Close() error { return c.close() }

// Status returns the daemon status.
func (c *Client) Status(ctx context.Context) (StatusResp, error) {
	resp, err := c.simple(ctx, Request{Op: OpStatus})
	if err != nil {
		return StatusResp{}, err
	}
	if resp.Status == nil {
		return StatusResp{}, errProtocol("status response without status")
	}
	return *resp.Status, nil
}

// Gate asks for a gate decision (answered from an in-memory snapshot).
func (c *Client) Gate(ctx context.Context, r GateReq) (GateResp, error) {
	resp, err := c.simple(ctx, Request{Op: OpGate, Gate: &r})
	if err != nil {
		return GateResp{}, err
	}
	if resp.Gate == nil {
		return GateResp{}, errProtocol("gate response without decision")
	}
	return *resp.Gate, nil
}

// Activity reports activity.
func (c *Client) Activity(ctx context.Context, r ActivityReq) error {
	_, err := c.simple(ctx, Request{Op: OpActivity, Activity: &r})
	return err
}

// Register announces a harness process.
func (c *Client) Register(ctx context.Context, r RegisterReq) error {
	_, err := c.simple(ctx, Request{Op: OpRegister, Register: &r})
	return err
}

// Unregister removes a wrapper registration.
func (c *Client) Unregister(ctx context.Context, r UnregisterReq) error {
	_, err := c.simple(ctx, Request{Op: OpUnregister, Unregister: &r})
	return err
}

// Unlock requests an unlock and relays UI prompts to ui until the final
// response.
func (c *Client) Unlock(ctx context.Context, r UnlockReq, ui UIHandler) (UnlockResp, error) {
	resp, sec, err := c.do(ctx, Request{Op: OpUnlock, Unlock: &r}, nil, ui)
	destroyAll(sec)
	if err != nil {
		return UnlockResp{}, err
	}
	if resp.Unlock == nil {
		return UnlockResp{}, errProtocol("unlock response without result")
	}
	return *resp.Unlock, nil
}

// Lock locks folders (and optionally ends sessions).
func (c *Client) Lock(ctx context.Context, r LockReq) (LockResp, error) {
	resp, err := c.simple(ctx, Request{Op: OpLock, Lock: &r})
	if err != nil {
		return LockResp{}, err
	}
	if resp.Lock == nil {
		return LockResp{}, errProtocol("lock response without result")
	}
	return *resp.Lock, nil
}

// KeySet holds released file keys in locked buffers. It implements
// sweep.FileKeys directly (asserted in cmd/precinto).
type KeySet struct {
	mu   sync.Mutex
	keys map[string]*memguard.LockedBuffer
}

// Key returns the file key of a capsule path relative to CapsulesDir.
func (k *KeySet) Key(path string) (*memguard.LockedBuffer, bool) { return k.key(path) }

// Destroy wipes every key (also called on any lock event).
func (k *KeySet) Destroy() { k.destroy() }

// Keys requests file keys; denied capsules are listed in the response.
func (c *Client) Keys(ctx context.Context, r KeysReq) (*KeySet, KeysResp, error) {
	return c.keys(ctx, r)
}

// Subscribe streams events; the channel closes on disconnect, which
// wrappers treat as a lock (SPEC §15.3). The stream starts with one locked
// or unlocked event per subscribed folder (D71), none when r names no
// folder. Subscribe returns once the daemon has registered the
// subscription, so no later state change is missed (D153).
func (c *Client) Subscribe(ctx context.Context, r SubscribeReq) (<-chan Event, error) {
	return c.subscribe(ctx, r)
}

// VaultCreate creates the per-root vault (UI may be relayed for
// passphrase factors).
func (c *Client) VaultCreate(ctx context.Context, r VaultCreateReq, ui UIHandler) error {
	_, sec, err := c.do(ctx, Request{Op: OpVaultCreate, VaultCreate: &r}, nil, ui)
	destroyAll(sec)
	return err
}

// FactorAdd enrolls a factor in every vault.
func (c *Client) FactorAdd(ctx context.Context, r FactorAddReq, ui UIHandler) error {
	_, sec, err := c.do(ctx, Request{Op: OpFactorAdd, FactorAdd: &r}, nil, ui)
	destroyAll(sec)
	return err
}

// VaultRepair repairs a tampered vault (D53). recovery, when r.UseRecovery
// is set, is sent in one 'S' frame and destroyed by the caller afterwards;
// factor prompts are relayed to ui.
func (c *Client) VaultRepair(ctx context.Context, r VaultRepairReq, recovery *memguard.LockedBuffer, ui UIHandler) (VaultRepairResp, error) {
	return c.vaultRepair(ctx, r, recovery, ui)
}

// Policy lists or confirms pending weakening changes.
func (c *Client) Policy(ctx context.Context, r PolicyReq) (PolicyResp, error) {
	resp, err := c.simple(ctx, Request{Op: OpPolicy, Policy: &r})
	if err != nil {
		return PolicyResp{}, err
	}
	if resp.Policy == nil {
		return PolicyResp{}, nil
	}
	return *resp.Policy, nil
}

// Shutdown asks the daemon to wipe keys and exit.
func (c *Client) Shutdown(ctx context.Context) error {
	_, err := c.simple(ctx, Request{Op: OpShutdown})
	return err
}

// Listener is the daemon side: it owns run/agent.lock for its lifetime.
type Listener struct {
	mu     sync.Mutex
	lock   *fsx.Lock
	ln     *net.UnixListener
	socket string
	closed bool
}

// Listen verifies RunDir (fsx.CheckPrivateDir), takes an exclusive flock on
// AgentLock (ErrLocked if another daemon runs), unlinks a stale socket only
// while holding it, and binds under umask 0177 (socket mode 0600).
func Listen(l paths.Layout) (*Listener, error) { return listen(l) }

// Accept waits for a connection and verifies the peer uid.
func (l *Listener) Accept() (*Conn, error) { return l.accept() }

// Close unlinks the socket (still holding the lock) and releases the lock.
func (l *Listener) Close() error { return l.close() }

// Conn is one accepted connection.
type Conn struct {
	peer platform.Peer
	w    *wire
}

// Peer returns the verified peer credentials.
func (c *Conn) Peer() platform.Peer { return c.peer }

// PeerSameExecutable reports whether the peer runs this binary (dev+inode,
// D6). Required for keys, unlock, vault_create, factor_add, vault_repair,
// policy confirmation, wrapper registrations and Input/Enter activity
// (SPEC §13.2, D39, D54).
func (c *Conn) PeerSameExecutable() bool { return c.peerSameExecutable() }

// ReadRequest reads the next JSON request and its secret frames into
// locked buffers.
func (c *Conn) ReadRequest() (Request, []*memguard.LockedBuffer, error) {
	return c.readRequest()
}

// WriteResponse writes a response followed by its secret frames (each
// buffer is written then left for the caller to destroy).
func (c *Conn) WriteResponse(r Response, secrets ...*memguard.LockedBuffer) error {
	return c.writeResponse(r, secrets)
}

// Close closes the connection.
func (c *Conn) Close() error { return c.w.close() }
