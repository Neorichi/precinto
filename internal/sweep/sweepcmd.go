package sweep

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/precinto/precinto/internal/capsule"
	"github.com/precinto/precinto/internal/config"
	"github.com/precinto/precinto/internal/fsx"
	"github.com/precinto/precinto/internal/harness"
	"github.com/precinto/precinto/internal/sweep/capslog"
	"github.com/precinto/precinto/internal/sweep/journal"
	"github.com/precinto/precinto/internal/sweep/queue"
	"github.com/precinto/precinto/internal/vault"
)

// Sweep is `precinto sweep`: take state/locks/sweep.lock (TryLock; if busy,
// touch sweep.requested and return ErrBusy unless o.Wait), Recover, drain
// the queue, scan every adapter's homes, seal every non-live,
// non-leased unit whose roots are locked (units restored under a current
// grant are left alone, R4), rotate global stores, apply the Markdown
// policy, then rescan once if sweep.requested was touched meanwhile.
func Sweep(ctx context.Context, e Env, o Options) (*Report, error) {
	r := newRun(e, prodPorts(e))
	return r.sweep(ctx, o)
}

func (r *run) sweep(ctx context.Context, o Options) (*Report, error) {
	r.onQuiet = o.OnQuietWait
	lk, err := r.sweepLock(ctx, o)
	if err != nil {
		return r.finish(), err
	}
	defer lk.Unlock()
	r.locked = true
	for pass := 0; pass < 2; pass++ {
		po := o
		if pass == 1 {
			if !r.exists(r.l.SweepRequested) || o.DryRun {
				break // a dry run leaves the request to a real sweep
			}
			po = rescanOptions(o)
		}
		if !o.DryRun {
			// A dry run seals nothing, so it answers no request (D138).
			r.clear(r.l.SweepRequested)
		}
		if err := ctx.Err(); err != nil {
			return r.finish(), err
		}
		r.resetQuiet()
		r.sweepOnce(ctx, po)
	}
	if !o.DryRun {
		_ = r.touch(r.l.SweepLast)
	}
	return r.finish(), nil
}

// rescanOptions are the options of the rescan a lock holder runs for the
// sweeps it turned away (they only touched sweep.requested, SPEC §10.2):
// every locked folder, whatever the holder's own scope, so a lock sweep of
// another folder (`sweep --lock --root R`) is never lost.
func rescanOptions(o Options) Options {
	return Options{Reason: "sweep", Quiet: o.Quiet, Lock: o.Lock, Deadline: o.Deadline}
}

// sweepLock takes state/locks/sweep.lock without waiting: when another
// process holds it, sweep.requested is touched (the holder rescans once
// before it exits) and ErrBusy is returned, unless o.Wait (SPEC §10.2).
func (r *run) sweepLock(ctx context.Context, o Options) (*fsx.Lock, error) {
	lk, err := r.lockName("sweep")
	if errors.Is(err, fsx.ErrLocked) {
		if !o.Wait {
			if terr := r.touch(r.l.SweepRequested); terr != nil {
				return nil, terr
			}
			return nil, ErrBusy
		}
		lk, err = r.waitLockName(ctx, "sweep")
	}
	return lk, err
}

// sweepOnce is one pass of a sweep.
func (r *run) sweepOnce(ctx context.Context, o Options) {
	if err := r.recoverAll(ctx); err == nil {
		r.quarantine(ctx)
	} else {
		r.add(UnitResult{Outcome: OutFailed, Detail: codeFailed + ": unreadable journal records; quarantine skipped"})
	}
	// Queued sessions are sealed whatever their folder's state, together
	// with the sweep's own units, so that one quiet-window wait covers
	// both (D63); a queued job also seals a session a restore placed after
	// the request unless its folder is open when it is sealed (D133), so a
	// unit queued here needs no job of the sweep's own.
	qs, jobs := r.queueJobs(ctx, o)
	queued := map[string]bool{}
	for _, j := range jobs {
		queued[j.u.Key] = true
	}
	unlocked := r.unlocked(ctx)
	// A sweep scoped to processes (Scope.Procs: a wrapper's own sessions,
	// CC-21) seals those sessions only: no notes, no global stores.
	own := len(o.Scope.Procs) > 0
	// Markdown candidates are gathered before sessions are sealed: their
	// ledgers and transcripts move into capsules (S6, S13).
	notes := map[string]map[string]*noteCand{}
	for _, root := range r.e.Cfg.Roots {
		if !own && r.inScope(o.Scope, root.ID) && !unlocked[root.ID] && root.MD != config.MDOff {
			notes[root.ID] = r.noteCandidates(ctx, root)
		}
	}
	for _, u := range r.scanAll(ctx, o) {
		if queued[u.Key] {
			continue // sealed for its queued request
		}
		if !r.unitLocked(u, unlocked) {
			r.add(UnitResult{Harness: string(u.Harness), Kind: u.Kind, Unit: u.Key, Outcome: OutSkipped,
				Files: len(u.Files), Bytes: unitBytes(u), Detail: "restored: folder unlocked"})
			continue
		}
		if u.Adopted && !o.Adopt && !o.Scope.Adopt && !r.adoptByPolicy(u) && !r.managed(u.Key) {
			r.add(UnitResult{Harness: string(u.Harness), Kind: u.Kind, Unit: u.Key, Outcome: OutSkipped,
				Files: len(u.Files), Bytes: unitBytes(u), Detail: "adopted: seal --adopt"})
			continue
		}
		// Locked now; checked again when it is sealed (folders.go).
		jo := o
		jo.lockedOnly = true
		jobs = append(jobs, sealJob{u: u, o: jo})
	}
	// D63: every subject of this run gets its first look before the
	// single quiet-window wait: sessions in sealJobs' first pass, notes,
	// the writers of notes that are not sealed with them, and history here.
	sealing := map[string]bool{}
	for _, j := range jobs {
		sealing[j.u.Key] = true
	}
	rotate := !own && !unlocked[globalVault] && (len(o.Scope.RootIDs) == 0 || o.Scope.Global)
	primed := false
	for _, root := range r.e.Cfg.Roots {
		if c, ok := notes[root.ID]; ok && r.primeNotes(ctx, root, c, sealing) {
			primed = true
		}
	}
	if rotate && r.primeHistory(ctx) {
		primed = true
	}
	disarm := r.armDrain(o, qs)
	results := r.sealJobs(ctx, jobs, o.Deadline, false, primed)
	disarm()
	r.finishQueue(o, qs, results)
	// The history and the notes are decided after the quiet wait: by the
	// folders' state then (the global vault, their folder), not at the
	// run's start (folders.go).
	r.staleView()
	if rotate && !r.folders(ctx, false).unlocked[globalVault] {
		r.rotateHistory(ctx)
	}
	no := o
	no.lockedOnly = true
	for _, root := range r.e.Cfg.Roots {
		if c, ok := notes[root.ID]; ok {
			r.sealMarkdown(ctx, root, no, c)
		}
	}
}

// managed reports whether precinto already holds generations of the unit
// or restored it (a receipt): such a unit is sealed by sweeps even when
// the adapter found it only by its project or transcripts (the ledger
// moved into its capsule, S13), never left behind as adopted plaintext.
// Any doubt (unreadable receipt or log) keeps the adoption rule.
func (r *run) managed(key string) bool {
	if _, ok, err := r.loadReceipt(key); err == nil && ok {
		return true
	}
	entries, err := r.log.Unit(key)
	return err == nil && len(entries) > 0
}

// globalVault is the vault of unattributable global stores and generic
// units (D1, D36, D33): vault.GlobalID.
const globalVault = vault.GlobalID

// unlocked returns the unlocked root ids; an error or no Grants means
// "every root is locked" (R4).
func (r *run) unlocked(ctx context.Context) map[string]bool {
	if r.e.Grants == nil {
		return map[string]bool{}
	}
	m, err := r.e.Grants(ctx)
	if err != nil || m == nil {
		return map[string]bool{}
	}
	return m
}

// unitLocked reports whether every root of the unit (or its vault, for
// units without roots) is locked.
func (r *run) unitLocked(u harness.Unit, unlocked map[string]bool) bool {
	ids := u.RootIDs
	if len(ids) == 0 {
		ids = []string{u.VaultID}
	}
	for _, id := range ids {
		if unlocked[id] {
			return false
		}
	}
	return true
}

// adoptInScope reports a folder in scope whose policy seals adopted
// sessions (md = "all", SPEC §7.1.1).
func (r *run) adoptInScope(s harness.Scope) bool {
	for _, root := range r.e.Cfg.Roots {
		if root.MD == config.MDAll && r.inScope(s, root.ID) {
			return true
		}
	}
	return false
}

// adoptByPolicy: md = "all" sweeps also seal adopted sessions (SPEC §7.1.1).
func (r *run) adoptByPolicy(u harness.Unit) bool {
	for _, id := range u.RootIDs {
		if root, ok := r.e.Cfg.RootByID(id); ok && root.MD == config.MDAll {
			return true
		}
	}
	return false
}

// inScope reports whether a root is in the scope of a run.
func (r *run) inScope(s harness.Scope, rootID string) bool {
	return len(s.RootIDs) == 0 || contains(s.RootIDs, rootID)
}

// scanAll scans every adapter (generic inventories only for Dormant) with
// the run's scope, Procs included (CC-21). Sessions found only by their
// transcripts' cwd are asked for (Scope.Adopt) when the run seals them:
// seal --adopt, or a folder in scope with md = "all" (S6).
func (r *run) scanAll(ctx context.Context, o Options) []harness.Unit {
	scope := o.Scope
	if o.Adopt || r.adoptInScope(scope) {
		scope.Adopt = true
	}
	var out []harness.Unit
	for _, ad := range r.e.Adapters {
		if ad == nil {
			continue
		}
		builtin := ad.ID() == harness.ClaudeCode || ad.ID() == harness.Codex
		if o.Dormant != "" && string(ad.ID()) != o.Dormant {
			continue
		}
		if o.Dormant == "" && !builtin {
			continue // experimental inventories seal only via seal --dormant (D33)
		}
		units, err := ad.Scan(ctx, r.e.Harness, scope)
		if err != nil {
			r.add(failed(UnitResult{Harness: string(ad.ID())}, err))
			continue
		}
		for _, u := range units {
			if u.Kind == capsule.KindClaudeHistory || u.Kind == capsule.KindCodexBlob {
				continue
			}
			out = append(out, u)
		}
	}
	return out
}

// touch writes the current time to a coordination file.
func (r *run) touch(p string) error {
	if err := ensurePrivateDir(path.Dir(p)); err != nil {
		return err
	}
	return fsx.WriteFileAtomic(p, []byte(r.now().Format(time.RFC3339Nano)+"\n"), 0o600)
}

func (r *run) exists(p string) bool {
	_, err := fsx.Lstat(p)
	return err == nil
}

func (r *run) clear(p string) {
	if r.exists(p) {
		_ = removeFile(p)
	}
}

// DrainQueue processes state/queue requests whose wait conditions hold.
func DrainQueue(ctx context.Context, e Env, o Options) (*Report, error) {
	return newRun(e, prodPorts(e)).drainCommand(ctx, o)
}

// drainCommand is DrainQueue. Only the sweep-lock holder drains the queue
// (SPEC §10.6): a worker that finds the lock held touches sweep.requested
// and returns ErrBusy (the CLI exits 0), and the holder runs a rescan —
// the queue drain included — before it exits; this worker does the same
// for sweeps it turned away. At most one process seals queued and swept
// units at a time, each with at most Env.Parallel seals and large units
// alone (R19, CONC-1).
func (r *run) drainCommand(ctx context.Context, o Options) (*Report, error) {
	r.onQuiet = o.OnQuietWait
	if err := ctx.Err(); err != nil {
		return r.finish(), err
	}
	lk, err := r.sweepLock(ctx, o)
	if err != nil {
		return r.finish(), err
	}
	defer lk.Unlock()
	r.locked = true
	r.recoverAll(ctx)
	r.drainQueue(ctx, o)
	if r.exists(r.l.SweepRequested) && ctx.Err() == nil && !o.DryRun {
		// A sweep (or another queue worker) was turned away while this
		// worker held the lock: run it, the queue drain included. A dry
		// run leaves the request to a real sweep, as sweep does (D138).
		r.clear(r.l.SweepRequested)
		r.resetQuiet()
		r.sweepOnce(ctx, rescanOptions(o))
		_ = r.touch(r.l.SweepLast)
	}
	return r.finish(), nil
}

// backoff is the retry delay after n failed attempts (never spinning;
// at least 60 s after a full disk, SPEC §17).
func backoff(n int, noSpace bool) time.Duration {
	d := 10 * time.Second
	for i := 1; i < n && d < 30*time.Minute; i++ {
		d *= 2
	}
	d = min(d, 30*time.Minute)
	if noSpace && d < time.Minute {
		d = time.Minute
	}
	return d
}

// drainQueue seals the queued sessions whose writer is gone (SPEC §10.6),
// all requests in one pair of decision passes around the run's single
// quiet-window wait (D63); requests whose writer exits during that wait
// are sealed in it (D131).
func (r *run) drainQueue(ctx context.Context, o Options) {
	qs, jobs := r.queueJobs(ctx, o)
	if len(jobs) == 0 {
		return
	}
	disarm := r.armDrain(o, qs)
	results := r.sealJobs(ctx, jobs, o.Deadline, false, false)
	disarm()
	r.finishQueue(o, qs, results)
}

// queuedReq is a queue request being drained and the jobs that seal it.
type queuedReq struct {
	req  queue.Request
	jobs []int // indices into the job list
}

// queueJobs turns the requests whose wait conditions hold into seal jobs,
// reporting (and removing) the requests that need nothing more. A unit
// named by several requests is sealed once; its job carries the newest
// request time (Options.queuedAt), so a unit restored after every request
// that names it is left in place (U6-3, D133).
func (r *run) queueJobs(ctx context.Context, o Options) ([]queuedReq, []sealJob) {
	return r.queueJobsIf(ctx, o, nil)
}

// queueJobsIf is queueJobs over the requests keep accepts (nil: all).
func (r *run) queueJobsIf(ctx context.Context, o Options, keep func(queue.Request, time.Time) bool) ([]queuedReq, []sealJob) {
	reqs, err := queue.List(r.l.QueueDir)
	if err != nil {
		r.add(failed(UnitResult{}, err))
		return nil, nil
	}
	now := r.now()
	var qs []queuedReq
	var jobs []sealJob
	at := map[string]int{} // unit key → job index
	// A dry run reports and changes nothing, the queue included.
	remove := func(id string) {
		if !o.DryRun {
			_ = queue.Remove(r.l.QueueDir, id)
		}
	}
	for _, q := range reqs {
		if ctx.Err() != nil {
			break
		}
		if keep != nil && !keep(q, now) {
			continue
		}
		if !q.NotBefore.IsZero() && now.Before(q.NotBefore) {
			continue
		}
		if !q.Deadline.IsZero() && now.After(q.Deadline) {
			r.add(UnitResult{Harness: q.Harness, Unit: q.UnitKey, Outcome: OutSkipped,
				Detail: "gave up waiting for the writer; a later sweep seals it"})
			remove(q.ID)
			continue
		}
		if !q.WaitFor.IsZero() && (r.e.Procs == nil || r.e.Procs.Alive(q.WaitFor)) {
			continue // the writer still runs (R8)
		}
		ad := adapterFor(r.e, harness.ID(q.Harness))
		if ad == nil {
			r.add(UnitResult{Harness: q.Harness, Unit: q.UnitKey, Outcome: OutFailed, Detail: codeFailed + ": unknown harness in a queued request"})
			remove(q.ID)
			continue
		}
		scope := harness.Scope{Adopt: true}
		if q.SID != "" {
			scope = harness.Scope{SIDs: []string{q.SID}}
		}
		units, err := ad.Scan(ctx, r.e.Harness, scope)
		if err != nil {
			r.add(failed(UnitResult{Harness: q.Harness, Unit: q.UnitKey}, err))
			if !o.DryRun {
				r.retry(q, false)
			}
			continue
		}
		qo := o
		qo.Reason = q.Reason
		qo.queuedAt, qo.queued = q.At, true
		if !q.WaitFor.IsZero() {
			// The writer is gone (checked above): R20 lets the seal skip
			// the stability window when nothing else holds the unit.
			w := q.WaitFor
			qo.WaitFor = &w
		}
		qr := queuedReq{req: q}
		for _, u := range units {
			if !((q.UnitKey != "" && u.Key == q.UnitKey) || (q.SID != "" && u.UnitID == q.SID)) {
				continue
			}
			k, ok := at[u.Key]
			if !ok {
				k = len(jobs)
				at[u.Key] = k
				jobs = append(jobs, sealJob{u: u, o: qo})
			} else if cur := jobs[k].o.queuedAt; !cur.IsZero() && (q.At.IsZero() || q.At.After(cur)) {
				jobs[k].o.queuedAt = q.At // the newest request counts; one without a time disables the check
			}
			qr.jobs = append(qr.jobs, k)
		}
		if len(qr.jobs) == 0 {
			remove(q.ID) // nothing left in plaintext
			continue
		}
		qs = append(qs, qr)
	}
	return qs, jobs
}

// finishQueue removes the requests whose units are done and backs off the
// others (at least 60 s after a full disk, SPEC §17). A dry run changes
// nothing: its "sealed" results sealed nothing (D138).
func (r *run) finishQueue(o Options, qs []queuedReq, results []UnitResult) {
	if o.DryRun {
		return
	}
	for _, q := range qs {
		done, noSpaceSeen := true, false
		for _, k := range q.jobs {
			if k >= len(results) {
				done = false
				continue
			}
			switch res := results[k]; {
			case res.Outcome == OutSkipped && res.Detail == "deadline":
				done = false // not attempted: the next drain does it
			case res.Outcome == OutSealed, res.Outcome == OutUnchanged, res.Outcome == OutSkipped, res.Outcome == OutInaccessible:
			default:
				done = false
				if strings.HasPrefix(res.Detail, codeNoSpace+":") {
					noSpaceSeen = true
				}
			}
		}
		if done {
			_ = queue.Remove(r.l.QueueDir, q.req.ID)
		} else {
			r.retry(q.req, noSpaceSeen)
		}
	}
}

// retry reschedules a queued request with back-off.
func (r *run) retry(q queue.Request, noSpace bool) {
	q.Attempts++
	q.NotBefore = r.now().Add(backoff(q.Attempts, noSpace))
	_ = queue.Update(r.l.QueueDir, q)
}

// Quarantine moves capsules that are not in the provenance log to
// <base>/quarantine and reports them (S3, D8). It runs only after Recover
// has processed every journal record and never touches a capsule named by
// a pending journal record.
func Quarantine(ctx context.Context, e Env) (*Report, error) {
	r := newRun(e, prodPorts(e))
	if err := ctx.Err(); err != nil {
		return r.finish(), err
	}
	if err := r.recoverAll(ctx); err != nil {
		return r.finish(), fmt.Errorf("sweep: quarantine refused: %w", err)
	}
	err := r.quarantine(ctx)
	return r.finish(), err
}

// quarantine moves every unlogged capsule of the store into
// quarantine/<op-id>/, mirroring its store path. It
// refuses to act while any journal record is unreadable or still pending:
// such a record could name a capsule that is precinto's own (O7).
func (r *run) quarantine(ctx context.Context) error {
	pending, err := r.jr.Pending()
	if err != nil {
		return err
	}
	protect := map[string]bool{}
	for _, rec := range pending {
		for _, p := range recordedCapsules(rec) {
			protect[p] = true
		}
	}
	all, err := r.log.All()
	if err != nil {
		return err
	}
	logged := map[string]string{}
	for _, en := range all {
		logged[en.Path] = en.HeaderSHA256
	}
	if _, err := fsx.Lstat(r.l.CapsulesDir); err != nil {
		if isMissing(err) {
			return nil
		}
		return err
	}
	root, err := r.p.fs.OpenBase(r.l.CapsulesDir)
	if err != nil {
		return err
	}
	defer root.Close()
	var moves []string
	err = root.Walk(".", func(we fsx.WalkEntry) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		rel := strings.TrimPrefix(we.Rel, "./")
		if rel == "." || rel == "" {
			return nil
		}
		if protect[rel] {
			if we.Type == fsx.TypeDir {
				return fs.SkipDir
			}
			return nil
		}
		if we.Type == fsx.TypeDir {
			return nil
		}
		if we.Type != fsx.TypeRegular || we.Hazard != fsx.HazardNone || !strings.HasSuffix(rel, capsule.FileExt) {
			return nil
		}
		hdr, ok := logged[rel]
		if ok {
			dir, name := path.Split(rel)
			d, err := root.OpenDir(path.Clean(dir), false)
			if err == nil {
				_, sum, herr := r.p.codec.ReadHeader(d, name)
				d.Close()
				if herr == nil && sum == hdr {
					return nil
				}
			}
		}
		moves = append(moves, rel)
		return nil
	})
	if err != nil {
		return err
	}
	if len(moves) == 0 {
		return nil
	}
	if err := ensurePrivateDir(r.l.QuarantineDir); err != nil {
		return err
	}
	q, err := r.p.fs.OpenBase(r.l.QuarantineDir)
	if err != nil {
		return err
	}
	defer q.Close()
	op := journal.NewID()
	sort.Strings(moves)
	for _, rel := range moves {
		res := UnitResult{Outcome: OutQuarantined}
		parts := strings.Split(rel, "/")
		if len(parts) >= 2 {
			res.Harness = parts[0]
			if validKey(parts[1]) {
				res.Unit = parts[1]
			}
		}
		// D82: a capsule inside a unit directory is moved only under that
		// unit's lock, after the journal and the log are read again. Every
		// operation that writes a capsule holds the lock from its journal
		// record to its log append, so a seal committed by another process
		// since the walk began is logged now and stays; a unit whose lock
		// is held is left for the next sweep.
		var lk *fsx.Lock
		if len(parts) >= 3 && res.Unit != "" {
			l, err := r.lockUnit(res.Unit)
			if errors.Is(err, fsx.ErrLocked) {
				continue // an operation on the unit is in flight
			}
			if err != nil {
				r.add(failed(res, err))
				continue
			}
			lk = l
			own, err := r.ownCapsule(root, rel)
			if err != nil || own {
				lk.Unlock()
				if err != nil {
					r.add(failed(res, err))
				}
				continue
			}
		}
		err := r.moveToQuarantine(root, q, op, rel)
		if lk != nil {
			lk.Unlock()
		}
		if err != nil {
			r.add(failed(res, err))
			continue
		}
		res.Detail = "no provenance: moved to quarantine"
		r.add(res)
	}
	return nil
}

// ownCapsule re-checks one quarantine candidate under its unit lock
// (D82): it is precinto's own when a pending journal record names it or
// when the log now holds it with the header it has on disk.
func (r *run) ownCapsule(root dirHandle, rel string) (bool, error) {
	pending, err := r.jr.Pending()
	if err != nil {
		return false, err
	}
	for _, rec := range pending {
		for _, p := range recordedCapsules(rec) {
			if p == rel || strings.HasPrefix(rel, p+"/") {
				return true, nil
			}
		}
	}
	dir, name := path.Split(rel)
	d, err := root.OpenDir(path.Clean(dir), false)
	if err != nil {
		if isMissing(err) {
			return true, nil // gone meanwhile: nothing to move
		}
		return false, err
	}
	_, sum, herr := r.p.codec.ReadHeader(d, name)
	d.Close()
	if herr != nil {
		if isMissing(herr) {
			return true, nil
		}
		return false, nil // unreadable header: not provably ours
	}
	if _, err := r.log.Lookup(rel, sum); err == nil {
		return true, nil
	} else if !errors.Is(err, capslog.ErrNotLogged) {
		return false, err
	}
	return false, nil
}

// moveToQuarantine renames one capsule of the store (rel, relative to
// CapsulesDir) into quarantine/<op>/, mirroring its store path.
func (r *run) moveToQuarantine(root, q dirHandle, op, rel string) error {
	dir, name := path.Split(rel)
	src, err := root.OpenDir(path.Clean(dir), false)
	if err != nil {
		return err
	}
	defer src.Close()
	dst, err := q.OpenDir(path.Join(op, path.Clean(dir)), true)
	if err != nil {
		return err
	}
	defer dst.Close()
	return src.RenameTo(name, dst, name, fsx.NoReplace)
}
