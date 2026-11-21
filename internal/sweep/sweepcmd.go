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
	"github.com/precinto/precinto/internal/sweep/journal"
	"github.com/precinto/precinto/internal/sweep/queue"
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
	lk, err := r.lockName("sweep")
	if errors.Is(err, fsx.ErrLocked) {
		if !o.Wait {
			if terr := r.touch(r.l.SweepRequested); terr != nil {
				return r.finish(), terr
			}
			return r.finish(), ErrBusy
		}
		lk, err = r.waitLockName(ctx, "sweep")
	}
	if err != nil {
		return r.finish(), err
	}
	defer lk.Unlock()
	for pass := 0; pass < 2; pass++ {
		if pass == 1 && !r.exists(r.l.SweepRequested) {
			break
		}
		r.clear(r.l.SweepRequested)
		if err := ctx.Err(); err != nil {
			return r.finish(), err
		}
		r.sweepOnce(ctx, o)
	}
	_ = r.touch(r.l.SweepLast)
	return r.finish(), nil
}

// sweepOnce is one pass of a sweep.
func (r *run) sweepOnce(ctx context.Context, o Options) {
	if err := r.recoverAll(ctx); err == nil {
		r.quarantine(ctx)
	} else {
		r.add(UnitResult{Outcome: OutFailed, Detail: codeFailed + ": unreadable journal records; quarantine skipped"})
	}
	r.drainQueue(ctx, o)
	unlocked := r.unlocked(ctx)
	// Markdown candidates are gathered before sessions are sealed: their
	// ledgers and transcripts move into capsules (S6, S13).
	notes := map[string]map[string]*noteCand{}
	for _, root := range r.e.Cfg.Roots {
		if r.inScope(o.Scope, root.ID) && !unlocked[root.ID] && root.MD != config.MDOff {
			notes[root.ID] = r.noteCandidates(ctx, root)
		}
	}
	var sealable []harness.Unit
	for _, u := range r.scanAll(ctx, o) {
		if !r.unitLocked(u, unlocked) {
			r.add(UnitResult{Harness: string(u.Harness), Kind: u.Kind, Unit: u.Key, Outcome: OutSkipped,
				Files: len(u.Files), Bytes: unitBytes(u), Detail: "restored: folder unlocked"})
			continue
		}
		if u.Adopted && !o.Adopt && !r.adoptByPolicy(u) {
			r.add(UnitResult{Harness: string(u.Harness), Kind: u.Kind, Unit: u.Key, Outcome: OutSkipped,
				Files: len(u.Files), Bytes: unitBytes(u), Detail: "adopted: seal --adopt"})
			continue
		}
		sealable = append(sealable, u)
	}
	r.sealAll(ctx, sealable, o, false)
	if !unlocked[globalVault] && (len(o.Scope.RootIDs) == 0 || o.Scope.Global) {
		r.rotateHistory(ctx)
	}
	for _, root := range r.e.Cfg.Roots {
		if c, ok := notes[root.ID]; ok {
			r.sealMarkdown(ctx, root, o, c)
		}
	}
}

// globalVault is the vault of unattributable global stores (D1, D36).
const globalVault = "global"

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

// scanAll scans every adapter (generic inventories only for Dormant).
func (r *run) scanAll(ctx context.Context, o Options) []harness.Unit {
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
		units, err := ad.Scan(ctx, r.e.Harness, o.Scope)
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
	r := newRun(e, prodPorts(e))
	if err := ctx.Err(); err != nil {
		return r.finish(), err
	}
	r.recoverAll(ctx)
	r.drainQueue(ctx, o)
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

// drainQueue seals the queued sessions whose writer is gone (SPEC §10.6).
func (r *run) drainQueue(ctx context.Context, o Options) {
	reqs, err := queue.List(r.l.QueueDir)
	if err != nil {
		r.add(failed(UnitResult{}, err))
		return
	}
	now := r.now()
	for _, q := range reqs {
		if ctx.Err() != nil {
			return
		}
		if !q.NotBefore.IsZero() && now.Before(q.NotBefore) {
			continue
		}
		if !q.Deadline.IsZero() && now.After(q.Deadline) {
			r.add(UnitResult{Harness: q.Harness, Unit: q.UnitKey, Outcome: OutSkipped,
				Detail: "gave up waiting for the writer; a later sweep seals it"})
			_ = queue.Remove(r.l.QueueDir, q.ID)
			continue
		}
		if !q.WaitFor.IsZero() && (r.e.Procs == nil || r.e.Procs.Alive(q.WaitFor)) {
			continue // the writer still runs (R8)
		}
		ad := adapterFor(r.e, harness.ID(q.Harness))
		if ad == nil {
			r.add(UnitResult{Harness: q.Harness, Unit: q.UnitKey, Outcome: OutFailed, Detail: codeFailed + ": unknown harness in a queued request"})
			_ = queue.Remove(r.l.QueueDir, q.ID)
			continue
		}
		scope := harness.Scope{All: true}
		if q.SID != "" {
			scope = harness.Scope{SIDs: []string{q.SID}}
		}
		units, err := ad.Scan(ctx, r.e.Harness, scope)
		if err != nil {
			r.add(failed(UnitResult{Harness: q.Harness, Unit: q.UnitKey}, err))
			r.retry(q, false)
			continue
		}
		var mine []harness.Unit
		for _, u := range units {
			if (q.UnitKey != "" && u.Key == q.UnitKey) || (q.SID != "" && u.UnitID == q.SID) {
				mine = append(mine, u)
			}
		}
		if len(mine) == 0 {
			_ = queue.Remove(r.l.QueueDir, q.ID) // nothing left in plaintext
			continue
		}
		qo := o
		qo.Reason = q.Reason
		results := r.sealAll(ctx, mine, qo, false)
		done, noSpaceSeen := true, false
		for _, res := range results {
			switch res.Outcome {
			case OutSealed, OutUnchanged, OutSkipped, OutInaccessible:
			default:
				done = false
				if strings.HasPrefix(res.Detail, codeNoSpace+":") {
					noSpaceSeen = true
				}
			}
		}
		if done {
			_ = queue.Remove(r.l.QueueDir, q.ID)
		} else {
			r.retry(q, noSpaceSeen)
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

// quarantine moves every unlogged capsule (and stray operation directory)
// of the store into quarantine/<op-id>/, mirroring its store path. It
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
			if isOpDir(path.Base(rel)) {
				moves = append(moves, rel) // a stray operation directory
				return fs.SkipDir
			}
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
		dir, name := path.Split(rel)
		src, err := root.OpenDir(path.Clean(dir), false)
		if err != nil {
			r.add(failed(res, err))
			continue
		}
		dst, err := q.OpenDir(path.Join(op, path.Clean(dir)), true)
		if err != nil {
			src.Close()
			r.add(failed(res, err))
			continue
		}
		err = src.RenameTo(name, dst, name, fsx.NoReplace)
		src.Close()
		dst.Close()
		if err != nil {
			r.add(failed(res, err))
			continue
		}
		res.Detail = "no provenance: moved to quarantine"
		r.add(res)
	}
	return nil
}
