package wrapper

import (
	"context"
	"io"
	"os"
	"os/exec"
	"sync"
	"time"

	"github.com/precinto/precinto/internal/config"
	"github.com/precinto/precinto/internal/harness"
	"github.com/precinto/precinto/internal/ipc"
	"github.com/precinto/precinto/internal/paths"
	"github.com/precinto/precinto/internal/platform"
)

// RestoreSummary is the content-free result of a restore step.
type RestoreSummary struct {
	Units     int
	Files     int
	Bytes     int64
	Conflicts int
	Skipped   int
	Notices   []string // ui catalog lines (e.g. MsgResumeOld)
}

// SealSummary is the content-free result of seal-after-exit.
type SealSummary struct {
	SID      string
	Files    int
	Bytes    int64
	Deferred bool   // still live: queued (MsgSealDeferred)
	Failed   string // error class (MsgSealFailed)
}

// Lease is a held launch lease (live.Held behind an interface; *live.Held
// implements it, asserted in cmd/precinto).
type Lease interface {
	Add(keys ...string) error
	SetChild(child platform.ProcID) error
	Inheritable() []*os.File
	Release() error
}

// Daemon is the subset of the ipc client the wrapper uses (fakeable;
// *ipc.Client implements it, asserted in cmd/precinto). G6 tests use a fake
// and never need a real daemon.
type Daemon interface {
	Register(ctx context.Context, r ipc.RegisterReq) error
	Unregister(ctx context.Context, r ipc.UnregisterReq) error
	Subscribe(ctx context.Context, r ipc.SubscribeReq) (<-chan ipc.Event, error)
	Activity(ctx context.Context, r ipc.ActivityReq) error
	Unlock(ctx context.Context, r ipc.UnlockReq, ui ipc.UIHandler) (ipc.UnlockResp, error)
	Close() error
}

// Backend is everything the wrapper needs from the rest of precinto.
// cmd/precinto implements it with internal/harness, internal/sweep,
// internal/live, internal/ledger and internal/ipc.
type Backend interface {
	// Plan asks the harness adapter for the launch plan.
	Plan(ctx context.Context, h harness.ID, cwd string, argv []string) (harness.LaunchPlan, error)
	// EnsureUnlocked unlocks the plan's roots in this terminal if needed
	// (TTY prompts or a relayed Secure Enclave dialog). ui is the terminal.
	EnsureUnlocked(ctx context.Context, roots []config.Root, ui ipc.UIHandler) error
	// AcquireLease takes the launch lease before any restore (SPEC §9.3).
	AcquireLease(ctx context.Context, plan harness.LaunchPlan) (Lease, error)
	// RestoreSync restores plan.Sync before exec; abort is closed on lock.
	RestoreSync(ctx context.Context, plan harness.LaunchPlan, abort <-chan struct{}) (RestoreSummary, error)
	// RestoreBackground restores plan.Background after exec (best effort).
	RestoreBackground(ctx context.Context, plan harness.LaunchPlan, abort <-chan struct{})
	// Daemon returns a new connection on every call (autostarted); the
	// wrapper keeps one for the subscription stream and one for requests
	// (register, activity, unlock-from-overlay), and dials again after a
	// loss.
	Daemon(ctx context.Context) (Daemon, error)
	// RecordLaunch writes the ledger "launch" event for a launch whose
	// session id is known before exec (resume targets), carrying the lease
	// keys and harness homes; a no-op when the sid is not known yet.
	RecordLaunch(ctx context.Context, plan harness.LaunchPlan, child platform.ProcID) error
	// SealAfterExit seals the session's units after the child was reaped
	// (writer known exited, R20), or queues them if still live.
	SealAfterExit(ctx context.Context, plan harness.LaunchPlan, child platform.ProcID) (SealSummary, error)
	// HooksSeen reports whether a hook event arrived for the child (UX10).
	HooksSeen(ctx context.Context, plan harness.LaunchPlan, child platform.ProcID) (bool, error)
}

// Options configures Run.
type Options struct {
	Harness harness.ID
	Argv    []string // argv[0] is the harness executable name or path
	Cwd     string
	Env     paths.Env
	NoPTY   bool
	Stdin   *os.File
	Stdout  *os.File
	Stderr  io.Writer
	Policy  config.Policy
	Backend Backend
}

// Run is `precinto run`: Plan; passthrough modes exec directly; otherwise
// confirm (plan.Confirm), EnsureUnlocked, plan.Prepare, AcquireLease,
// RestoreSync, start the child (PTY when stdin and stdout are terminals and
// the mode is interactive, else direct: started with Setsid so it is the
// leader of its own session, with SIGINT, SIGQUIT, SIGTERM and SIGHUP
// forwarded to it, D57), RecordLaunch, register, subscribe, forward
// activity, handle lock/unlock/end events, RestoreBackground, wait, reset
// the terminal, plan.Finish, release the lease, SealAfterExit, print one
// summary line. Returns the child's exit code, or ExitNotStarted when the
// child never started (err says why).
func Run(ctx context.Context, o Options) (int, error) { return run(ctx, o) }

// ExitNotStarted is Run's code when the child never started; err says why
// and cmd/precinto maps it with the API §5 table (e.g. sweep.ErrConflict →
// 4, ipc codes → 3). Otherwise Run returns the child's own code.
const ExitNotStarted = -1

// ProxyOptions configures the PTY proxy.
type ProxyOptions struct {
	ScrollbackBytes int  // ring of ALL child output since start, replayed at unlock (default 8 MiB, D30, D60)
	ITerm           bool // TERM_PROGRAM=iTerm.app: add OSC 1337;ClearScrollback
	ClearScrollback bool // policy.clear_scrollback_on_lock (D30)
	// OnHuman is called (rate-limited by the caller) for filtered human
	// input; enter reports an Enter keystroke (D37).
	OnHuman func(enter bool)
}

// Proxy runs a child on a PTY bound to the user's terminal.
type Proxy struct {
	cmd *exec.Cmd
	s   *proxyState
}

// StartProxy starts cmd on a new PTY, puts tty in raw mode, propagates
// SIGWINCH, and forwards I/O until Wait returns.
func StartProxy(cmd *exec.Cmd, tty *os.File, o ProxyOptions) (*Proxy, error) {
	return startProxy(cmd, tty, tty, o)
}

// Overlay is the lock screen content (SPEC §16.3 C4).
type Overlay struct {
	Folder string
	Reason string // ui.Reason text
	Factor string // "Mac password", "passphrase", "YubiKey"
	Busy   bool   // show the busy line
	// Harness is {harness} of C4.busy: the inventory display name
	// ("Claude Code", "Codex").
	Harness string
}

// Lock stops forwarding input (keys are dropped, not queued), keeps
// recording child output in the scrollback ring (which holds output since
// the child started, not only since the lock) while tracking terminal
// modes, clears the screen (and scrollback when configured), and draws the
// overlay on the alternate screen unless the child already uses it (D30,
// IM16).
func (p *Proxy) Lock(o Overlay) error {
	if p == nil || p.s == nil {
		return errFinished
	}
	return p.s.lock(o)
}

// Unlock clears the overlay and the screen, replays the ring from its safe
// boundary (Scrollback.Bytes) so inline-mode TUIs such as Claude's default
// mode get their finished messages back, restores tracked modes (1049,
// 1000–1006, 2004, 1004, 25, kitty flags) and forces a repaint by resizing
// to cols−1 then cols 50 ms apart (a same-size SIGWINCH does not repaint
// Node/ratatui TUIs). When the ring wrapped, only its tail is replayed
// before the repaint (output older than the ring is not shown again, SPEC
// §19).
func (p *Proxy) Unlock() error {
	if p == nil || p.s == nil {
		return errFinished
	}
	return p.s.unlock()
}

// Locked reports whether the overlay is shown.
func (p *Proxy) Locked() bool { return p != nil && p.s != nil && p.s.locked.Load() }

// OverlayKeys returns keys pressed on the overlay: Enter (unlock) and
// Ctrl-D (end session); everything else is dropped and is never activity.
func (p *Proxy) OverlayKeys() <-chan byte {
	if p == nil || p.s == nil {
		return nil
	}
	return p.s.keys
}

// TerminateOptions configures Terminate.
type TerminateOptions struct {
	QuitKeys []byte        // sent through the PTY first (Codex: Ctrl-C twice, R20/HA19)
	KeysWait time.Duration // wait after QuitKeys (3s)
	Grace    time.Duration // SIGTERM→SIGKILL delay (harness.KillGrace; LaunchPlan.KillGrace)
}

// Terminate ends the child: optional quit keys, SIGTERM, wait Grace,
// SIGKILL, then SIGKILL of the child's remaining session
// (platform.SignalGroup with the child's pid: the PTY child is the leader
// of a session the wrapper created, never the user's terminal session;
// R11, D57).
func (p *Proxy) Terminate(o TerminateOptions) error {
	if p == nil || p.s == nil {
		return errFinished
	}
	return p.s.terminate(o)
}

// Child returns the child's ProcID.
func (p *Proxy) Child() platform.ProcID {
	if p == nil || p.s == nil {
		return platform.ProcID{}
	}
	return p.s.child
}

// Wait waits for the child, handles job control (on a stop, restore the
// outer terminal and stop the wrapper itself; on SIGCONT re-enter raw mode,
// continue the child and repaint, UX14) and returns its exit code.
func (p *Proxy) Wait() (int, error) {
	if p == nil || p.s == nil {
		return 1, errFinished
	}
	return p.s.wait()
}

// Scrollback is a bounded ring buffer of all raw child output since the
// child started (D30, D60). It holds terminal output of the session in
// wrapper memory only and is wiped at exit.
type Scrollback struct {
	buf     []byte
	mu      sync.Mutex
	max     int
	start   int   // index of the oldest byte once the ring is full
	n       int   // bytes kept
	total   int64 // bytes written since the start (stream offset of the end)
	wrapped bool
	sc      scanner
	// lines are the stream offsets of the line starts found in ground state
	// (just after a '\n' outside any sequence), oldest first.
	lines []int64
}

// NewScrollback returns a buffer of max bytes.
func NewScrollback(max int) *Scrollback {
	if max < 0 {
		max = 0
	}
	return &Scrollback{max: max}
}

// Write appends output, dropping the oldest bytes beyond the bound.
func (s *Scrollback) Write(b []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.write(b)
	return len(b), nil
}

// Bytes returns the buffered output for replay. Before the ring wraps it
// is every byte since start; after, it starts at a safe boundary — the
// first line start after the oldest kept byte, never inside an escape
// sequence or UTF-8 rune — preceded by an SGR reset.
func (s *Scrollback) Bytes() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.bytes()
}

// Wrapped reports whether output was dropped (the replay is only the tail).
func (s *Scrollback) Wrapped() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.wrapped
}

// Wipe zeroes the buffer.
func (s *Scrollback) Wipe() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.wipe()
}

// Modes tracks DEC private modes and keyboard protocol state set by the
// child, including while locked.
type Modes struct {
	set         map[int]bool // DEC private modes the child set (value: on)
	mu          sync.Mutex
	sc          scanner
	keypad      bool          // DECKPAM application keypad
	mok         int           // xterm modifyOtherKeys level
	kitty       [2]kittyStack // kitty keyboard flags: main and alternate screen
	alt         int           // alternate-screen mode in use (47, 1047, 1049) or 0
	altSwitches int           // alternate-screen transitions seen
}

// NewModes returns an empty tracker.
func NewModes() *Modes { return &Modes{set: map[int]bool{}} }

// Feed parses child output for CSI ? Pm h/l, CSI > … u / CSI < u (kitty).
func (m *Modes) Feed(b []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.feed(b)
}

// Restore returns the sequence re-establishing the tracked modes.
func (m *Modes) Restore() []byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.restoreFrom(NewModes())
}

// Reset returns the sequence that turns every tracked mode off (TTY reset
// at exit and before the lock overlay).
func (m *Modes) Reset() []byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.resetSeq()
}

// HumanInput reports whether b contains human keystrokes after removing
// sequences terminals send on their own (focus CSI I/O, mouse CSI M and
// CSI < … M/m, cursor reports CSI … R, DA replies CSI ? … c, kitty replies
// CSI ? … u, OSC replies) and whether it contains Enter (UX15, D37).
func HumanInput(b []byte) (human, enter bool) { return humanInput(b) }

// ResetSequence is the full terminal reset of SPEC §15.4 (optionally with
// clear screen + scrollback and iTerm2 ClearScrollback).
func ResetSequence(clear, iterm bool) []byte { return resetSequence(clear, iterm) }
