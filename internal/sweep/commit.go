package sweep

import (
	"context"
	"errors"
	"path"

	"github.com/precinto/precinto/internal/capsule"
	"github.com/precinto/precinto/internal/sweep/capslog"
	"github.com/precinto/precinto/internal/sweep/journal"
)

// sealPoints are the failpoints a commit evaluates after its milestones
// (docs/TESTPLAN.md §4); unit seals use the seal.* names, history and
// Codex commits their own (or none).
type sealPoints struct {
	prepared, tmpWritten, logged, committed string
}

var unitSealPoints = sealPoints{prepared: "seal.prepared", tmpWritten: "seal.tmp_written", logged: "seal.logged", committed: "seal.committed"}

// commitSpec is one capsule to write under an already begun journal
// record.
type commitSpec struct {
	rec        *journal.Record
	unitDir    dirHandle // capsules/<store>/<unit>
	outDir     dirHandle // where the capsule is committed (unitDir, or its blobs/ subdirectory)
	capsuleRel string    // the capsule relative to unitDir (journaled as Record.Capsule)
	name       string    // final file name in outDir
	logPath    string    // relative to CapsulesDir
	gen        uint64
	req        sealRequest
	entry      capslog.Entry // filled with the hashes and appended after the rename
	points     sealPoints
	// preparePhase, when set, is the milestone journaled together with the
	// names before anything is written (rescue); otherwise the names are
	// saved within the current phase.
	preparePhase journal.Phase
	// beforeRename runs between the capsule's verification and its commit
	// rename (the codex.manifest failpoint), from Seal's PhaseVerified.
	beforeRename func() error
}

// tmpRel is the temporary capsule.Seal writes, relative to the unit
// directory: capsule.TmpName of the final name, next to it.
func (c *commitSpec) tmpRel() string {
	return path.Join(path.Dir(c.capsuleRel), capsule.TmpName(c.name))
}

// commitError says what a failed commit left behind.
type commitError struct {
	err error
	// keepRecord: the journal record must stay for recovery (cleanup
	// failed, or the capsule is committed and logged but the committed
	// milestone could not be journaled).
	keepRecord bool
	// committed: the capsule is renamed and logged.
	committed bool
}

func (c *commitError) Error() string { return c.err.Error() }
func (c *commitError) Unwrap() error { return c.err }

// keepRecord reports whether err requires leaving the journal record.
func keepRecord(err error) bool {
	var ce *commitError
	return errors.As(err, &ce) && ce.keepRecord
}

// commit writes one capsule crash-safely (SPEC §10.3 steps 3–5, D58):
//
//  1. journal the temporary (Record.Tmp = capsule.TmpName of the final
//     name, D58a), the final name (Record.Capsule) and the generation
//     before anything is written;
//  2. capsule.Seal writes Out/TmpName(Name), verifies it and commits it
//     to Out/Name with a no-replace rename straight into the unit
//     directory (tmp_written is journaled from its OnPhase callback); there
//     is no per-operation directory and no second rename;
//  3. the capsule-log entry is appended (FullSync), and only then is
//     committed journaled.
//
// On any failure before the log append nothing of the attempt is left:
// Seal removes its temporary on every error return, and a capsule renamed
// but not logged is deleted (it can never be re-verified, D58b).
func (r *run) commit(ctx context.Context, c *commitSpec) (*capsule.Sealed, error) {
	rec := c.rec
	rec.Tmp = c.tmpRel()
	rec.Capsule = c.capsuleRel
	rec.Gen = c.gen
	var err error
	if c.preparePhase != "" {
		err = r.jr.Advance(rec, c.preparePhase)
	} else {
		err = r.jr.Save(rec)
	}
	if err != nil {
		return nil, &commitError{err: err}
	}
	if err := hit(c.points.prepared); err != nil {
		return nil, &commitError{err: err}
	}
	req := c.req
	req.Out = c.outDir
	req.Name = c.name
	req.OnPhase = func(p capsule.Phase, _ *capsule.Sealed) error {
		switch p {
		case capsule.PhaseTmpWritten:
			if err := r.jr.Advance(rec, journal.PhaseTmpWritten); err != nil {
				return err
			}
			return hit(c.points.tmpWritten)
		case capsule.PhaseVerified:
			if c.beforeRename != nil {
				return c.beforeRename()
			}
		}
		return nil
	}
	sealed, err := r.p.codec.Seal(ctx, req)
	if err != nil {
		return nil, r.abandon(c, err)
	}
	en := c.entry
	en.Path = c.logPath
	en.SHA256 = sealed.SHA256
	en.HeaderSHA256 = sealed.HeaderSHA256
	en.Size = sealed.Size
	if err := r.log.Append(en); err != nil {
		// Not logged: never restorable, never re-verifiable. Remove it now
		// rather than leave it to recovery.
		if rerr := c.outDir.Remove(c.name); rerr != nil && !isMissing(rerr) {
			return nil, &commitError{err: errors.Join(err, rerr), keepRecord: true}
		}
		return nil, &commitError{err: err}
	}
	if err := hit(c.points.logged); err != nil {
		// Logged but the milestone is not journaled (SEAL-7).
		return sealed, &commitError{err: err, keepRecord: true, committed: true}
	}
	if err := r.jr.Advance(rec, journal.PhaseCommitted); err != nil {
		// Logged but the milestone is not journaled: recovery finds the
		// capsule logged and continues as committed (SEAL-7).
		return sealed, &commitError{err: err, keepRecord: true, committed: true}
	}
	if err := hit(c.points.committed); err != nil {
		return sealed, &commitError{err: err, keepRecord: true, committed: true}
	}
	return sealed, nil
}

// abandon cleans up a failed attempt (D58b): the temporary if it is still
// there, and a capsule of the final name that Seal committed before it
// failed but that the log does not have (an unlogged capsule is ours: it
// can never be re-verified). A logged or foreign capsule there is kept.
func (r *run) abandon(c *commitSpec, cause error) error {
	var errs []error
	if err := c.unitDir.Remove(c.tmpRel()); err != nil && !isMissing(err) {
		errs = append(errs, err)
	}
	state, err := r.inspectCapsule(c.unitDir, c.capsuleRel, c.logPath)
	switch {
	case err != nil:
		errs = append(errs, err)
	case state == capsOrphan:
		if err := c.unitDir.Remove(c.capsuleRel); err != nil && !isMissing(err) {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return &commitError{err: errors.Join(append([]error{cause}, errs...)...), keepRecord: true}
	}
	return &commitError{err: cause}
}
