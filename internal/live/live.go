package live

import (
	"context"
	"errors"
	"os"
	"sync"
	"time"

	"github.com/Neorichi/precinto/internal/fsx"
	"github.com/Neorichi/precinto/internal/platform"
)

// Reason names one piece of liveness evidence.
type Reason string

// Evidence reasons.
const (
	ReasonLedgerProc Reason = "ledger-proc"  // a ledger process of the session is alive (same start time)
	ReasonRegistry   Reason = "registry"     // harness registry names the unit with a live pid (D18)
	ReasonRegistryIO Reason = "registry-err" // registry unreadable/half-written/unknown schema (R8)
	ReasonLease      Reason = "lease"        // a launch lease is held (R4)
	ReasonJob        Reason = "job"          // a background/supervised job references the unit (D25, R11)
	ReasonWriterLock Reason = "writer-lock"  // a harness writer lock is held (R17)
	ReasonOpenFD     Reason = "open-fd"      // a process holds a descriptor below the unit (HA9)
	ReasonProcess    Reason = "process"      // a harness process is running (global/project units, D21)
	ReasonUnstable   Reason = "unstable"     // files changed within the stability window (R16)
	// ReasonUnobserved: first observation, the unit was not yet seen across
	// a full quiet window (weak); a caller without earlier observations
	// waits Quiet once and decides again (D63).
	ReasonUnobserved Reason = "unobserved"
	ReasonFutureTime Reason = "future-mtime" // mtime in the future: treated as live (R16)
	ReasonWarm       Reason = "warm"         // non-current session of a live process, not yet stable (D20)
	ReasonForkParent Reason = "fork-parent"  // a live session references this transcript (R21)
	ReasonPlanSlug   Reason = "plan-slug"    // a live session references this plan slug (D46)
	ReasonUnknown    Reason = "unknown"      // evidence could not be evaluated: live by default
)

// Evidence is one reason a unit may still be written.
type Evidence struct {
	Reason Reason
	Proc   platform.ProcID // zero if not process-based
	Path   string          // file or lock involved, if any
	Detail string          // short, content-free
	// Weak marks evidence based only on a process name or file times; such
	// holds are capped and reported after policy.hold_cap (S14).
	Weak bool
}

// Verdict is the engine's decision for one unit.
type Verdict struct {
	Live      bool
	Warm      bool // non-current session of a live process (D20): sealable once stable; status shows "sealing after /clear"
	Evidence  []Evidence
	HeldSince time.Time // first time this unit was seen live (for hold caps)
	Capped    bool      // held by weak evidence longer than hold_cap: report it
}

// Subject is what the engine evaluates.
type Subject struct {
	Key        string            // unit key
	Paths      []string          // absolute files and directories of the unit
	Procs      []platform.ProcID // ledger processes that own the unit (current session owners only, D20)
	LeaseKeys  []string          // lease names to probe (unit key, codex home key)
	RestoredAt time.Time         // receipt time, if restored under the current grant
	// WriterExited is set when the wrapper reaped the only known writer and no
	// other evidence exists: the stability window may be skipped (R20).
	WriterExited bool
}

// Engine combines evidence. It is safe for concurrent use.
type Engine struct {
	Procs     platform.ProcTable
	Clock     platform.Clock
	LeasesDir string
	Observer  *Observer     // nil: no unit is ever stable
	Quiet     time.Duration // policy.quiet_window; ≤ 0 means 120 s, never immediate
	HoldCap   time.Duration // policy.hold_cap
}

// Decide evaluates s plus adapter-supplied evidence. It adds ledger-proc,
// lease and stability evidence itself. Weak evidence (capped by HoldCap,
// S14) is: a harness process by name, a future mtime, a change of file
// times only, a first observation (ReasonUnobserved), a restore within the
// quiet window, and a registry naming a non-harness pid. A nil Observer
// means not stable.
func (e *Engine) Decide(ctx context.Context, s Subject, extra []Evidence) (Verdict, error) {
	return e.decide(ctx, s, extra)
}

// StillQuiet re-checks, immediately before an unlink, that s shows no new
// evidence and its files keep their snapshot identity (SPEC §10.3 step 6).
func (e *Engine) StillQuiet(ctx context.Context, s Subject, snaps map[string]fsx.Stat) (bool, error) {
	return e.stillQuiet(ctx, s, snaps)
}

// Observer tracks file identities across observations on the monotonic
// clock: a unit is stable when every file's (dev, ino, size, mtime, ctime)
// and every directory listing were identical in two observations at least Q
// apart (R16). Every sealing process starts without observations (sweeps,
// seals and the queue worker are separate processes, SPEC §13.1): a sweep
// decides once, waits Q once and decides again (D63).
type Observer struct {
	clock platform.Clock
	mu    sync.Mutex
	units map[string]*history   // stability history per unit key
	holds map[string]*holdState // hold-cap tracking per unit key
}

// NewObserver returns an observer using c.
func NewObserver(c platform.Clock) *Observer { return newObserver(c) }

// Observe records the current identities of paths under key and reports
// whether they have been stable for at least q.
func (o *Observer) Observe(key string, paths []string, q time.Duration) (stable bool, err error) {
	return o.observe(key, paths, q)
}

// Forget drops the history of key.
func (o *Observer) Forget(key string) { o.forget(key) }

// ErrLeaseHeld is returned by sealers that find a lease.
var ErrLeaseHeld = errors.New("live: unit is leased by a running launch")

// Lease describes a launch lease (written by the wrapper before restoring,
// held until its child has been reaped, R4).
type Lease struct {
	Key   string          `json:"key"` // unit key, or the codex home key
	Proc  platform.ProcID `json:"proc"`
	Root  string          `json:"root"` // root id
	Child platform.ProcID `json:"child,omitempty"`
	At    time.Time       `json:"at"`
}

// Held is a set of leases held by this process (shared flocks on
// state/leases/<key>.lease plus a JSON description).
type Held struct {
	mu       sync.Mutex
	dir      string
	desc     Lease // written for every key (Key filled per lease)
	leases   []*heldLease
	released bool
}

// Acquire takes shared leases for every key (creating lease files 0600) and
// records proc. Leases on the same key by several wrappers coexist. The
// shared flock is taken with a bounded wait (2 s), so a concurrent probe's
// momentary LOCK_EX|LOCK_NB never fails a launch.
func Acquire(dir string, keys []string, l Lease) (*Held, error) { return acquire(dir, keys, l) }

// Add takes shared leases on more keys (units resolved after the launch
// started, e.g. by a restore Selector) before their plaintext is placed,
// with Acquire's bounded wait.
func (h *Held) Add(keys ...string) error { return h.add(keys...) }

// SetChild records the harness child pid in the lease descriptions.
func (h *Held) SetChild(child platform.ProcID) error { return h.setChild(child) }

// Inheritable returns the locked descriptors so a wrapper that execs the
// harness directly (--no-pty exec mode) can clear FD_CLOEXEC and keep the
// lease for the harness's lifetime.
func (h *Held) Inheritable() []*os.File { return h.inheritable() }

// Release drops every lease.
func (h *Held) Release() error { return h.release() }

// Probe reports whether any process holds a lease on key, and the lease
// descriptions found while it is held. It is fsx.ProbeHeld on the lease
// file: a missing file was never leased; an inode swap during the probe or
// any probe error reports held=true.
func Probe(dir, key string) (held bool, leases []Lease, err error) {
	return probe(dir, key)
}
