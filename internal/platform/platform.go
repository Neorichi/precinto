package platform

import (
	"context"
	"errors"
	"net"
	"os"
	"syscall"
	"time"

	"github.com/precinto/precinto/internal/paths"
)

// Errors.
var (
	ErrNoProcess   = errors.New("platform: no such process")
	ErrNotSame     = errors.New("platform: process identity changed")
	ErrUnsupported = errors.New("platform: unsupported on this OS")
	ErrRoot        = errors.New("platform: refusing to run as root")
	ErrUnsafeEnv   = errors.New("platform: unsafe loader environment (DYLD_*/LD_*)")
)

// ProcID is one process incarnation as measured by precinto: pid plus the
// kernel start time, with BootID guarding reboots on linux. ProcIDs are
// compared by equality only; never computed as now−elapsed and never taken
// from a harness (R9, S14). Use StartTime to compare a start with a wall
// clock time (D66).
type ProcID struct {
	PID int `json:"pid"`
	// StartUS is the kernel start time in µs: wall time on darwin
	// (p_starttime), µs since boot on linux (/proc/<pid>/stat field 22 ×
	// 10^6/CLK_TCK), so a wall-clock step never changes a measured
	// identity; compared by equality only.
	StartUS int64  `json:"start_us"`
	BootID  string `json:"boot_id,omitempty"` // linux only
}

// StartTime returns the wall-clock start of id for comparisons with
// harness timestamps (D18 registry startedAt, hook windows): darwin's
// StartUS as is; on linux the current btime is added to a ProcID measured
// on this boot (one with a BootID; a ProcID without one, such as a test
// fake, is taken as wall time). It is the zero time when btime cannot be
// read. See D66.
func StartTime(id ProcID) time.Time { return startTime(id) }

// IsZero reports whether id is unset. Implemented in the scaffold.
func (id ProcID) IsZero() bool { return id.PID == 0 && id.StartUS == 0 && id.BootID == "" }

// String formats "PID:START" (the --wait-pid syntax).
func (id ProcID) String() string { return formatProcID(id) }

// ParseProcID parses "PID:START".
func ParseProcID(s string) (ProcID, error) { return parseProcID(s) }

// ProcState is the scheduler state of a process.
type ProcState string

// Process states.
const (
	StateRunning ProcState = "running"
	StateStopped ProcState = "stopped"
	StateZombie  ProcState = "zombie" // counts as exited everywhere (R8)
	StateUnknown ProcState = "unknown"
)

// ProcInfo is a snapshot of one process.
type ProcInfo struct {
	ID    ProcID
	PPID  int
	UID   int
	PGID  int
	SID   int       // session id (setsid)
	State ProcState // zombie counts as exited
	Exe   string    // absolute executable path (kern.procargs2 / /proc/<pid>/exe); "" if unknown
	Comm  string    // kernel short name; for Claude Code this is its version string: never match on it
	Argv  []string  // best effort; may be empty
	TTY   string    // controlling terminal device path, "" if none
}

// ProcTable is the process-table view used by liveness, hooks and the
// daemon; tests substitute internal/platform/fakeplatform. Every
// process-derived liveness fact (E6, E7, D47, D52) goes through it so it
// can be faked.
type ProcTable interface {
	// Lookup returns the current process with pid, or ErrNoProcess.
	Lookup(pid int) (ProcInfo, error)
	// Alive reports whether id still exists with the same start time and is
	// not a zombie.
	Alive(id ProcID) bool
	// List returns every process of the current uid.
	List() ([]ProcInfo, error)
	// Cwd returns the current working directory of id ("" with nil error
	// if it cannot be determined; callers treat unknown as "may be
	// inside"); ErrNotSame if id is gone or changed (darwin proc_pidinfo
	// PROC_PIDVNODEPATHINFO or lsof -d cwd; linux /proc/<pid>/cwd).
	Cwd(id ProcID) (string, error)
	// OpenFilesUnder returns processes holding open descriptors on files
	// below any of dirs (darwin: lsof +D/-F; linux: /proc/*/fd). An error
	// means the caller must treat the paths as live (HA9, R11).
	OpenFilesUnder(ctx context.Context, dirs []string) ([]Holder, error)
}

// System returns the real process table.
func System() ProcTable { return systemTable{} }

// Self returns the identity of the current process.
func Self() ProcID { return self() }

// Identify measures the ProcID of a live pid.
func Identify(pid int) (ProcID, error) { return identify(pid) }

// Ancestors returns up to max ancestors of pid, nearest first, by walking
// PPIDs with t.Lookup; the walk stops at pid 0/1, at a lookup error or at a
// loop. An error is returned only if pid itself cannot be looked up.
// Implemented in the scaffold.
func Ancestors(t ProcTable, pid int, max int) ([]ProcInfo, error) {
	p, err := t.Lookup(pid)
	if err != nil {
		return nil, err
	}
	var out []ProcInfo
	seen := map[int]bool{pid: true}
	for len(out) < max && p.PPID > 1 && !seen[p.PPID] {
		seen[p.PPID] = true
		q, err := t.Lookup(p.PPID)
		if err != nil {
			break
		}
		out = append(out, q)
		p = q
	}
	return out, nil
}

// Descendants returns every live descendant of root found by walking PPIDs
// in one t.List() snapshot (a child must have started no earlier than its
// parent, so a reused pid is never adopted), each re-verified with t.Alive.
// It is how precinto finds the helpers of an unwrapped harness it ends
// (D57): never by session or process-group id. Call it before signalling
// root: once root exits its children are reparented and no longer found.
// Implemented in the scaffold.
func Descendants(t ProcTable, root ProcID) ([]ProcInfo, error) {
	all, err := t.List()
	if err != nil {
		return nil, err
	}
	children := map[int][]ProcInfo{}
	for _, p := range all {
		children[p.PPID] = append(children[p.PPID], p)
	}
	var out []ProcInfo
	queue := []ProcID{root}
	seen := map[int]bool{root.PID: true}
	for len(queue) > 0 {
		parent := queue[0]
		queue = queue[1:]
		for _, c := range children[parent.PID] {
			if seen[c.ID.PID] || c.ID.StartUS < parent.StartUS || !t.Alive(c.ID) {
				continue
			}
			seen[c.ID.PID] = true
			out = append(out, c)
			queue = append(queue, c.ID)
		}
	}
	return out, nil
}

// Holder is a process with an open descriptor on a path.
type Holder struct {
	Proc ProcInfo
	Path string
}

// Signal sends sig to id after re-verifying (pid, start time) immediately
// before kill(2) (linux: pidfd_send_signal). ErrNotSame if the process
// changed (S14).
func Signal(id ProcID, sig syscall.Signal) error { return signalProc(id, sig) }

// SignalGroup signals the remaining processes whose session id is
// leader.PID. It refuses (ErrNotSame) when a process with that pid exists
// with another start time (the session id was reused), refuses sid ≤ 1 and
// the caller's own session, and never signals the caller. Only for
// sessions precinto created itself — the wrapper's PTY child or a
// direct-mode child started with Setsid, both session leaders — never for
// an unwrapped harness, whose session is the user's terminal session (its
// login shell and every other job of that tab) (R11, D57). Members are
// re-verified one by one like Signal.
func SignalGroup(leader ProcID, sig syscall.Signal) error { return signalGroup(leader, sig) }

// WaitExit blocks until id has exited (zombie counts as exited) or ctx ends;
// darwin kqueue EVFILT_PROC/NOTE_EXIT, linux pidfd poll, fallback polling.
func WaitExit(ctx context.Context, id ProcID) error { return waitExit(ctx, id) }

// SpawnOptions configures a detached child.
type SpawnOptions struct {
	Dir     string
	Env     []string // full environment (allowlisted by the caller)
	LogPath string   // stdout/stderr destination; "" means /dev/null
}

// Spawn starts argv detached (Setsid, stdin /dev/null) and does not wait.
// argv[0] must be absolute.
func Spawn(argv []string, o SpawnOptions) (ProcID, error) { return spawn(argv, o) }

// Executable returns the absolute path and Stat-like identity of the running
// binary (os.Executable resolved once at startup).
func Executable() (path string, dev, ino uint64, err error) { return executable() }

// SameExecutable reports whether pid runs the same file (dev+inode) as the
// current binary (D6 mutual authentication).
func SameExecutable(pid int) (bool, error) { return sameExecutable(pid) }

// Peer holds the verified credentials of a Unix-socket peer.
type Peer struct {
	UID  int
	PID  int
	Proc ProcInfo // resolved at accept time; Proc.ID guards PID reuse
}

// PeerOf returns the peer credentials of c (darwin LOCAL_PEERCRED +
// LOCAL_PEERPID; linux SO_PEERCRED).
func PeerOf(c *net.UnixConn) (Peer, error) { return peerOf(c) }

// Harden must be the first call of every subcommand that may hold secrets or
// plaintext (agent, unlock, hook, run, seal, sweep, restore, open, cat,
// recover): refuse uid 0, setrlimit(RLIMIT_CORE, 0), PT_DENY_ATTACH (darwin)
// or prctl(PR_SET_DUMPABLE, 0) (linux) (SPEC §4.6, S15).
func Harden() error { return harden() }

// CheckLoaderEnv returns ErrUnsafeEnv if environ contains DYLD_* or LD_*
// variables; the daemon refuses to start (or re-execs with a clean env).
func CheckLoaderEnv(environ []string) error { return checkLoaderEnv(environ) }

// Clock is wall time plus a monotonic reading. Deadlines are evaluated
// against both (R16, IM15): a deadline expires if either clock says so.
type Clock interface {
	// Now returns wall-clock time with the monotonic reading stripped.
	Now() time.Time
	// Mono returns a monotonic duration since an arbitrary fixed origin.
	Mono() time.Duration
}

// SystemClock returns the real clock.
func SystemClock() Clock { return systemClock{} }

// ScreenState is one observation of the console.
type ScreenState struct {
	Locked    bool
	LockKnown bool          // false if the state cannot be determined (headless, SSH)
	HIDIdle   time.Duration // time since the last keyboard/mouse event
	IdleKnown bool
	At        time.Time
}

// ReadScreen polls the console once (darwin: `/usr/sbin/ioreg -n Root -d1`
// IOConsoleLocked and IOHIDSystem HIDIdleTime, ~25 ms; linux: loginctl
// LockedHint and IdleSinceHint).
func ReadScreen(ctx context.Context) (ScreenState, error) { return readScreen(ctx) }

// Jump is a detected wall-vs-monotonic discontinuity (sleep/wake or clock
// step).
type Jump struct {
	Wall time.Duration // wall-clock delta between ticks
	Mono time.Duration // monotonic delta between ticks
	At   time.Time
}

// WatchJumps ticks every interval and sends a Jump whenever wall time moved
// more than threshold beyond monotonic time (D24 sleep/wake ⇒ lock at wake).
func WatchJumps(ctx context.Context, c Clock, every, threshold time.Duration, out chan<- Jump) {
	watchJumps(ctx, c, every, threshold, out)
}

// UIContext describes where an unlock prompt could appear (D27).
type UIContext struct {
	TTY  bool // the requester owns a terminal (stdin and stdout are TTYs)
	GUI  bool // a GUI dialog can appear (darwin Aqua session with graphic access)
	Tmux bool // $TMUX or $STY set
	SSH  bool // $SSH_CONNECTION/$SSH_TTY set
}

// DetectUIContext inspects e and the current process (D27): SE dialogs are
// impossible in SSH and detached tmux/screen sessions.
func DetectUIContext(e paths.Env, stdin, stdout *os.File) UIContext {
	return detectUIContext(e, stdin, stdout)
}

// ScrubOptions controls TTY scrubbing after a harness has exited.
type ScrubOptions struct {
	ITerm  bool   // also send OSC 1337;ClearScrollback
	Clear  bool   // clear screen and scrollback (policy clear_terminal_on_end)
	Banner string // printed after the reset, one line
}

// ScrubTTY opens tty with O_WRONLY|O_NOCTTY (only if owned by the current
// uid) and writes the reset sequence of SPEC §15.4, then runs `stty sane`
// on it (darwin -f, linux -F).
func ScrubTTY(tty string, o ScrubOptions) error { return scrubTTY(tty, o) }

// DiskEncryption reports FileVault (darwin `fdesetup status`) or an
// encrypted home (linux, best effort); known=false if undeterminable.
func DiskEncryption(ctx context.Context) (on, known bool, err error) {
	return diskEncryption(ctx)
}

// ExcludeFromBackup adds a sticky Time Machine exclusion (`tmutil
// addexclusion`, no root needed); no-op on linux.
func ExcludeFromBackup(ctx context.Context, path string) error {
	return excludeFromBackup(ctx, path)
}

// BackupExcluded is a read-only Time Machine query: `tmutil
// destinationinfo`, then `tmutil isexcluded path`, with an explicit minimal
// environment and a 10 s timeout per run. known=false off darwin or when
// no backup destination is configured (nothing is backed up; err is nil
// then), or when the answer could not be read (err says why).
func BackupExcluded(ctx context.Context, path string) (excluded, known bool, err error) {
	return backupExcluded(ctx, path)
}

// CloudSynced reports whether path is inside a known cloud-synced location
// (~/Library/Mobile Documents, ~/Library/CloudStorage, iCloud Desktop &
// Documents, Dropbox, OneDrive).
func CloudSynced(path string) bool { return cloudSynced(path) }

// SpotlightIndexed reports whether Spotlight indexes path (`mdfind -onlyin
// <path> -count 'kMDItemFSName == *.md'` > 0); known=false off darwin.
func SpotlightIndexed(ctx context.Context, path string) (indexed, known bool, err error) {
	return spotlightIndexed(ctx, path)
}
