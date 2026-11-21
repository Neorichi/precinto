package agent

import (
	"context"
	"time"

	"github.com/awnumar/memguard"

	"github.com/precinto/precinto/internal/config"
	"github.com/precinto/precinto/internal/ipc"
	"github.com/precinto/precinto/internal/paths"
	"github.com/precinto/precinto/internal/platform"
)

// Options configures Run.
type Options struct {
	Layout     paths.Layout
	Env        paths.Env
	Exe        string // absolute path of this binary (workers are spawned from it)
	Version    string
	Foreground bool
	Clock      platform.Clock
	Procs      platform.ProcTable
	// IdleExit: exit after this long with no unlocked vault, no subscriber,
	// an empty queue and no pending journal (default 10m, R19).
	IdleExit time.Duration
	// Tick is the trigger polling period (default 3s: screen lock, HID idle,
	// registry busy state, deadlines).
	Tick time.Duration

	// Test seams (internal/agent/agenttest sets them; nil selects the real
	// implementation). Spawn starts `<Exe> sweep|seal|restore` workers
	// (default platform.Spawn); Screen polls the console (default
	// platform.ReadScreen); Harden runs platform.Harden and
	// CheckLoaderEnv (agenttest passes a no-op so the go test binary is
	// never hardened or re-executed); Pinentry runs pinentry for hook-raised
	// unlocks of passphrase/plugin factors (default: the pinentry binary
	// found next to the user's PATH, D4).
	Spawn    func(argv []string, o platform.SpawnOptions) (platform.ProcID, error)
	Screen   func(ctx context.Context) (platform.ScreenState, error)
	Harden   func() error
	Pinentry func(ctx context.Context, desc, prompt string) (*memguard.LockedBuffer, error)
}

// Run is `precinto agent`: Options.Harden (platform.Harden and
// CheckLoaderEnv); ipc.Listen (holding run/agent.lock); treat every vault
// as locked; load the effective policy as the stricter of config.toml and
// state/policy.pinned (D55); spawn one recovery+full sweep worker;
// bootstrap sessions from the ledger and the harness registries; then serve
// requests and triggers until ctx ends or the idle-exit rule fires.
func Run(ctx context.Context, o Options) error { panic("unimplemented: agent.Run") }

// VaultState is the key state of one vault (UX16: two independent state
// machines, vault key state and session state).
type VaultState string

// Vault states.
const (
	VaultLocked   VaultState = "locked"
	VaultUnlocked VaultState = "unlocked"
)

// SessionState is the state of one live session.
type SessionState string

// Session states.
const (
	SessionRunning SessionState = "running" // all its roots unlocked
	SessionPaused  SessionState = "paused"  // some root locked: gated (and overlaid if wrapped)
	SessionEnding  SessionState = "ending"  // termination requested
)

// GateEvent is a normalized gate event.
type GateEvent string

// Gate events.
const (
	GatePrompt     GateEvent = "prompt"     // UserPromptSubmit / beforeSubmitPrompt
	GateTool       GateEvent = "tool"       // PreToolUse
	GateCompact    GateEvent = "compact"    // PreCompact
	GatePermission GateEvent = "permission" // PermissionRequest
	GateStart      GateEvent = "start"      // SessionStart (never blocks; returns context text)
)

// InputKind is a state-machine input.
type InputKind string

// Inputs.
const (
	InUnlock         InputKind = "unlock"      // a vault was unwrapped (Vault, TTL, Extend)
	InLock           InputKind = "lock"        // manual lock (Vaults/All, End, Force, LetFinish)
	InActivity       InputKind = "activity"    // ipc.ActivityReq: Input/Enter move the idle clock only with FromWrapper; Prompt only if the recorded origin of (SID, PromptID) is human (D54)
	InGateOrigin     InputKind = "gate_origin" // the origin the daemon computed when answering a prompt gate for (SID, PromptID), enqueued before the gate response is written; consumed by the matching Prompt activity, expires after busy_timeout (D54)
	InRegister       InputKind = "register"    // a harness process registered (Session)
	InUnregister     InputKind = "unregister"  // the process exited
	InUngated        InputKind = "ungated"     // the process-table scan found an unregistered harness process in a root with no hook event or registration within the hook-presence window (Session, D52, D57)
	InBusy           InputKind = "busy"        // registry/hook busy observation (Busy)
	InScreenLocked   InputKind = "screen_locked"
	InScreenUnlocked InputKind = "screen_unlocked" // advisory only: never unlocks (D24, I6)
	InHIDActivity    InputKind = "hid_activity"    // system HID idle reset observed (D37 evidence only)
	InJump           InputKind = "jump"            // wall/monotonic jump ⇒ sleep/wake ⇒ lock (D24)
	InTick           InputKind = "tick"
	InPolicy         InputKind = "policy" // new effective policy (D48)
)

// Input is one event fed to the machine. Connection handlers fill it only
// with facts the daemon verified itself.
type Input struct {
	Kind     InputKind
	Vaults   []string
	All      bool
	SID      string
	PromptID string // prompt_id (Claude) or turn_id (Codex): pairs a Prompt activity with its InGateOrigin
	Session  *SessionInfo
	Activity ipc.ActivityKind
	Origin   ipc.PromptOrigin // InGateOrigin only: computed by the daemon, never taken from a client
	// FromWrapper is set by the connection handler only when the peer passed
	// ipc.Conn.PeerSameExecutable and its measured ProcID equals the
	// session's registered WrapperPID; Input/Enter activity without it is
	// ignored (D54).
	FromWrapper bool
	Busy        bool
	End         bool
	Force       bool
	LetFinish   bool
	TTL         time.Duration
	Extend      bool
	Policy      *config.Policy
	Jump        platform.Jump
}

// SessionInfo is what the machine knows about a live session.
type SessionInfo struct {
	Harness    string
	SID        string
	Proc       platform.ProcID
	RootIDs    []string        // vault ids of its managed roots
	Wrapper    bool            // registration verified as coming from the wrapper itself (D54)
	WrapperPID platform.ProcID // the wrapper process (measured by the daemon)
	Background bool            // supervised: never terminated by signals (D25)
	TTY        string
	HooksSeen  bool
	Registered bool // false: found only by the process-table scan (D52, D57)
}

// ActionKind is an effect the daemon must perform after Apply.
type ActionKind string

// Actions.
const (
	ActWipeKey        ActionKind = "wipe_key"         // Keyring.Drop(Vault) — immediate, never deferred (I15)
	ActPublish        ActionKind = "publish"          // send Event to subscribers
	ActSealRoots      ActionKind = "seal_roots"       // spawn `precinto sweep --lock --root …`
	ActEndSessions    ActionKind = "end_sessions"     // wrapped: EventEnd (the wrapper ends its own PTY/Setsid child); unwrapped Claude (registered or scan-found, D52): ProcID-verified SIGTERM→SIGKILL of the process and its ProcID-verified descendants found by PPID walk, never by session id (D57); background/supervised sessions are never included (D25)
	ActScrubTTY       ActionKind = "scrub_tty"        // after a verified exit (UX13)
	ActRestoreRoots   ActionKind = "restore_roots"    // spawn `precinto restore --background --root …` after unlock (UX12)
	ActNotifyExpiring ActionKind = "notify_expiring"  // 10 min before max_unlock (C8)
	ActWriteRootsList ActionKind = "write_roots_list" // D22
	ActAuditCapsules  ActionKind = "audit_capsules"   // after unlock: recipients_fpr audit since LastAudit (D5)
)

// Action is one effect.
type Action struct {
	Kind     ActionKind
	Vault    string
	RootIDs  []string
	Sessions []SessionInfo
	Event    ipc.Event
	Reason   string // ui.Reason
	// Grace is the SIGTERM→SIGKILL delay for ActEndSessions:
	// max(8s, SessionEnd budget + 6s), capped at 70s (R20).
	Grace time.Duration
}

// GateQuery is a gate request after root resolution.
type GateQuery struct {
	Event       GateEvent
	SID         string
	RootIDs     []string         // resolved by the daemon: ledger taint ∪ project dir ∪ cwd ∪ paths (HA10)
	Origin      ipc.PromptOrigin // computed by the daemon (wrapper Enter ≤ 3 s before, else HID idle ≤ 5 s), D37
	FromWrapper bool
	Trigger     string // compaction trigger
}

// Snapshot is an immutable copy of the machine state used to answer gates
// without locks or I/O.
type Snapshot struct {
	At       time.Time
	Vaults   map[string]VaultSnapshot
	Sessions map[string]SessionSnapshot // by SID
}

// VaultSnapshot is one vault's state.
type VaultSnapshot struct {
	State        VaultState
	Reason       string
	Since        time.Time
	IdleDeadline time.Time
	AbsDeadline  time.Time
	LastHuman    time.Time
}

// SessionSnapshot is one session's state.
type SessionSnapshot struct {
	Info        SessionInfo
	State       SessionState
	Busy        bool
	BusyAtLock  bool      // was mid-turn when its root locked: tools allowed until Stop or busy_grace (UX2)
	LockedAt    time.Time // when the session became paused
	CompactBusy bool
}

// Machine is the pure lock state machine. Not safe for concurrent use; the
// daemon serializes inputs and publishes Snapshots.
type Machine struct {
	policy config.Policy
	clock  platform.Clock
}

// NewMachine builds a machine with every vault locked.
func NewMachine(p config.Policy, c platform.Clock) *Machine { panic("unimplemented: agent.NewMachine") }

// Apply consumes one input and returns the actions to perform, in order.
// Rules (SPEC §12): lock transitions are immediate; only verified human
// input moves the idle clock — wrapper Input/Enter with FromWrapper, and
// Prompt activity whose recorded gate origin is human; unknown and
// automated origins never do (D23, D54); busy sessions finish their turn
// up to busy_grace (D24, UX2); background sessions are never signalled
// (D25); automated prompts never raise unlock dialogs (D26); no OS event
// unlocks (I6).
func (m *Machine) Apply(in Input) []Action { panic("unimplemented: agent.Machine.Apply") }

// Gate decides a query against the current state.
func (m *Machine) Gate(q GateQuery) ipc.GateResp { panic("unimplemented: agent.Machine.Gate") }

// Snapshot returns the current state.
func (m *Machine) Snapshot() Snapshot { panic("unimplemented: agent.Machine.Snapshot") }

// NextDeadline is the earliest time Apply(InTick) must run.
func (m *Machine) NextDeadline() (time.Time, bool) {
	panic("unimplemented: agent.Machine.NextDeadline")
}

// GateFromSnapshot answers a gate query from a published snapshot (what
// the connection handlers use).
func GateFromSnapshot(s *Snapshot, p config.Policy, q GateQuery) ipc.GateResp {
	panic("unimplemented: agent.GateFromSnapshot")
}

// ClampTTL returns min(ttl, policy.max_unlock, 24h); ttl<=0 means max_unlock (S8).
func ClampTTL(p config.Policy, ttl time.Duration) time.Duration {
	panic("unimplemented: agent.ClampTTL")
}

// KillGrace returns the SIGTERM→SIGKILL delay for a harness given its
// SessionEnd budget (R20).
func KillGrace(sessionEndBudget time.Duration) time.Duration {
	panic("unimplemented: agent.KillGrace")
}

// RateLimiter enforces at most n unlock prompts per minute, a backoff after
// a cancel, and a per-root hook cooldown (D27). Unlock is single-flight per
// vault: concurrent requesters share the result.
type RateLimiter struct {
	perMinute int
}

// NewRateLimiter returns a limiter from policy.
func NewRateLimiter(p config.Policy, c platform.Clock) *RateLimiter {
	panic("unimplemented: agent.NewRateLimiter")
}

// Allow reports whether a prompt for vault may be raised now (fromHook
// applies the hook cooldown after a cancel).
func (r *RateLimiter) Allow(vault string, fromHook bool) (bool, time.Duration) {
	panic("unimplemented: agent.RateLimiter.Allow")
}

// Cancelled records a cancel for vault.
func (r *RateLimiter) Cancelled(vault string, fromHook bool) {
	panic("unimplemented: agent.RateLimiter.Cancelled")
}

// Authorize applies the agent-context rules (D28, D59). A peer is in an
// agent context when an ancestor's executable is a known harness or its
// environment carries agent markers; walking stops at the daemon itself, so
// workers the daemon spawned are never agent contexts. For such peers:
// unlocking any root other than the roots of the session it runs in is
// refused (CodeAgentContext, C12.agent, no dialog); key releases of any
// purpose need fresh presence even when the root is unlocked; factor_add,
// vault_repair and policy confirmation are refused. A peer without a
// controlling TTY (setsid, double fork) that is not a daemon worker is
// treated the same way for the explicit content-revealing purposes
// ipc.PurposeRestoreAll, PurposeOpen, PurposeCat and PurposeList (D59).
// purpose is ipc.KeysReq.Purpose for OpKeys, "" otherwise. A nil result
// means allowed (possibly after the presence prompt the caller raises).
func Authorize(peer platform.Peer, ancestry []platform.ProcInfo, op ipc.Op, purpose string, rootIDs []string, sessionRoots []string) *ipc.Error {
	panic("unimplemented: agent.Authorize")
}
