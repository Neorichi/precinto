package live

import (
	"context"
	"errors"
	"os"
	"time"

	"github.com/precinto/precinto/internal/fsx"
	"github.com/precinto/precinto/internal/platform"
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
	Observer  *Observer
	Quiet     time.Duration // policy.quiet_window
	HoldCap   time.Duration // policy.hold_cap
}

// Decide evaluates s plus adapter-supplied evidence. It adds ledger-proc,
// lease and stability evidence itself.
func (e *Engine) Decide(ctx context.Context, s Subject, extra []Evidence) (Verdict, error) {
	panic("unimplemented: live.Engine.Decide")
}

// StillQuiet re-checks, immediately before an unlink, that s shows no new
// evidence and its files keep their snapshot identity (SPEC §10.3 step 6).
func (e *Engine) StillQuiet(ctx context.Context, s Subject, snaps map[string]fsx.Stat) (bool, error) {
	panic("unimplemented: live.Engine.StillQuiet")
}

// Observer tracks file identities across observations on the monotonic
// clock: a unit is stable when every file's (dev, ino, size, mtime, ctime)
// and every directory listing were identical in two observations at least Q
// apart (R16). The daemon keeps one long-lived Observer so sweeps can decide
// at once; a CLI sweep without the daemon waits Q.
type Observer struct {
	clock platform.Clock
}

// NewObserver returns an observer using c.
func NewObserver(c platform.Clock) *Observer { panic("unimplemented: live.NewObserver") }

// Observe records the current identities of paths under key and reports
// whether they have been stable for at least q.
func (o *Observer) Observe(key string, paths []string, q time.Duration) (stable bool, err error) {
	panic("unimplemented: live.Observer.Observe")
}

// Forget drops the history of key.
func (o *Observer) Forget(key string) { panic("unimplemented: live.Observer.Forget") }

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
	locks []*fsx.Lock
}

// Acquire takes shared leases for every key (creating lease files 0600) and
// records proc. Leases on the same key by several wrappers coexist.
func Acquire(dir string, keys []string, l Lease) (*Held, error) { panic("unimplemented: live.Acquire") }

// Add takes shared leases on more keys (units resolved after the launch
// started, e.g. by a restore Selector) before their plaintext is placed.
func (h *Held) Add(keys ...string) error { panic("unimplemented: live.Held.Add") }

// SetChild records the harness child pid in the lease descriptions.
func (h *Held) SetChild(child platform.ProcID) error { panic("unimplemented: live.Held.SetChild") }

// Inheritable returns the locked descriptors so a wrapper that execs the
// harness directly (--no-pty exec mode) can clear FD_CLOEXEC and keep the
// lease for the harness's lifetime.
func (h *Held) Inheritable() []*os.File { panic("unimplemented: live.Held.Inheritable") }

// Release drops every lease.
func (h *Held) Release() error { panic("unimplemented: live.Held.Release") }

// Probe reports whether any process holds a lease on key, and the lease
// descriptions found; an inode mismatch or probe error reports held=true.
func Probe(dir, key string) (held bool, leases []Lease, err error) {
	panic("unimplemented: live.Probe")
}
