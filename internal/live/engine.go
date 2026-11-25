package live

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"strconv"
	"time"

	"github.com/Neorichi/precinto/internal/fsx"
	"github.com/Neorichi/precinto/internal/platform"
)

// defaultQuiet is the stability window used when an Engine has none
// (policy.quiet_window, SPEC §12.2): a missing setting never makes units
// stable at once.
const defaultQuiet = 120 * time.Second

// errEngine: the engine lacks a dependency, so nothing can be evaluated.
var errEngine = errors.New("live: engine is not configured")

// procText formats a ProcID for evidence details ("PID:START").
func procText(id platform.ProcID) string {
	return strconv.Itoa(id.PID) + ":" + strconv.FormatInt(id.StartUS, 10)
}

func (e *Engine) quiet() time.Duration {
	if e.Quiet > 0 {
		return e.Quiet
	}
	return defaultQuiet
}

// leaseKeys returns the unit key plus s.LeaseKeys, deduplicated: the unit
// key is always probed, so a caller that forgets it cannot miss a lease.
func leaseKeys(s Subject) []string {
	var keys []string
	seen := map[string]bool{}
	for _, k := range append([]string{s.Key}, s.LeaseKeys...) {
		if k != "" && !seen[k] {
			seen[k] = true
			keys = append(keys, k)
		}
	}
	return keys
}

// liveVerdict is the answer to every failure: live, with the reason.
func liveVerdict(detail string) Verdict {
	return Verdict{Live: true, Evidence: []Evidence{{Reason: ReasonUnknown, Detail: detail}}}
}

// decide implements Decide: the union of evidence (SPEC §9.2, D18).
// Adapter evidence (extra) is taken as given; the engine adds E1 (ledger
// processes alive with the same start time, zombies dead), E3 (leases) and
// E5 (stability on the monotonic clock, future mtimes, a restore within
// the quiet window). ReasonWarm evidence (D20) keeps a unit live only until
// it is stable. E5 is skipped when the wrapper reaped the only known writer
// and nothing else holds the unit (R20). Any failure to read evidence adds
// ReasonUnknown and makes the unit live; Decide never returns Live=false
// together with an error.
func (e *Engine) decide(ctx context.Context, s Subject, extra []Evidence) (Verdict, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return liveVerdict("cancelled"), err
	}
	if e == nil || e.Procs == nil || e.Clock == nil {
		return liveVerdict("engine not configured"), errEngine
	}
	if s.Key == "" {
		// Leases and stability history are kept per unit key: without one
		// nothing can be proven.
		return liveVerdict("subject without a unit key"), nil
	}
	var v Verdict
	add := func(ev Evidence) { v.Evidence = append(v.Evidence, ev) }
	warm := false
	var warmEv Evidence
	for _, ev := range extra {
		if ev.Reason == ReasonWarm {
			warm, warmEv = true, ev
			continue
		}
		add(ev)
	}

	// E1: a ledger process that owns the unit is alive (ProcID equality;
	// a zombie or a reused pid is not alive).
	for _, p := range s.Procs {
		if !p.IsZero() && e.Procs.Alive(p) {
			add(Evidence{Reason: ReasonLedgerProc, Proc: p, Detail: "pid " + procText(p)})
		}
	}

	// E3: launch leases.
	for _, k := range leaseKeys(s) {
		if e.LeasesDir == "" {
			add(Evidence{Reason: ReasonUnknown, Detail: "no lease directory"})
			break
		}
		held, leases, err := probe(e.LeasesDir, k)
		if err != nil || held {
			ev := Evidence{Reason: ReasonLease, Path: filepath.Join(e.LeasesDir, k+leaseExt), Detail: "lease held"}
			if err != nil {
				ev.Detail = "lease probe failed"
			}
			if len(leases) > 0 {
				ev.Proc = leases[len(leases)-1].Proc
			}
			add(ev)
		}
	}
	if err := ctx.Err(); err != nil {
		add(Evidence{Reason: ReasonUnknown, Detail: "cancelled"})
		v.Live = true
		return v, err
	}

	// E5: stability, unless the only known writer was reaped (R20).
	skip := s.WriterExited && len(v.Evidence) == 0 && !warm
	stable := true
	if !skip {
		now := e.Clock.Now()
		if !s.RestoredAt.IsZero() && (s.RestoredAt.After(now) || now.Sub(s.RestoredAt) < e.quiet()) {
			add(Evidence{Reason: ReasonUnstable, Detail: "restored within the quiet window", Weak: true})
		}
		switch {
		case e.Observer == nil:
			stable = false
			add(Evidence{Reason: ReasonUnstable, Detail: "no stability observer", Weak: true})
		default:
			l, err := e.Observer.look(s.Key, s.Paths, e.quiet())
			switch {
			case err != nil:
				stable = false
				add(Evidence{Reason: ReasonUnknown, Detail: "stability check failed"})
			default:
				if l.future != "" {
					stable = false
					add(Evidence{Reason: ReasonFutureTime, Path: l.future, Detail: "mtime in the future", Weak: true})
				}
				switch {
				case l.stable:
				case l.first || l.pending:
					// Not yet seen unchanged across a full window: the
					// caller waits Quiet once and decides again (D63).
					stable = false
					add(Evidence{Reason: ReasonUnobserved, Detail: "not yet observed for the quiet window", Weak: true})
				default:
					stable = false
					add(Evidence{Reason: ReasonUnstable, Detail: "files changed within the quiet window", Weak: l.timesOnly})
				}
			}
		}
	}
	if warm {
		v.Warm = true
		if !stable {
			if warmEv.Detail == "" {
				warmEv.Detail = "non-current session of a live process"
			}
			add(warmEv)
		}
	}
	v.Live = len(v.Evidence) > 0
	weakOnly := v.Live
	for _, ev := range v.Evidence {
		if !ev.Weak {
			weakOnly = false
			break
		}
	}
	if e.Observer != nil {
		v.HeldSince, v.Capped = e.Observer.hold(s.Key, v.Live, weakOnly, e.HoldCap)
	} else if v.Live {
		v.HeldSince = e.Clock.Now()
		v.Capped = weakOnly && e.HoldCap <= 0
	}
	return v, nil
}

// stillQuiet implements StillQuiet (SPEC §10.3 step 6): immediately before
// an unlink, no ledger process came alive, no lease is held, and every
// snapshotted file still has its identity. Anything else, including a file
// that vanished or a read error, answers false.
func (e *Engine) stillQuiet(ctx context.Context, s Subject, snaps map[string]fsx.Stat) (bool, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if e == nil || e.Procs == nil {
		return false, errEngine
	}
	for _, p := range s.Procs {
		if !p.IsZero() && e.Procs.Alive(p) {
			return false, nil
		}
	}
	for _, k := range leaseKeys(s) {
		if e.LeasesDir == "" {
			return false, fmt.Errorf("%w: no lease directory", errEngine)
		}
		held, _, err := probe(e.LeasesDir, k)
		if err != nil {
			return false, err
		}
		if held {
			return false, nil
		}
	}
	for p, want := range snaps {
		cur, err := fsx.Lstat(p)
		if errors.Is(err, fs.ErrNotExist) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		if !cur.Unchanged(want) {
			return false, nil
		}
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	return true, nil
}
