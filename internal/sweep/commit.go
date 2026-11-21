package sweep

import (
	"context"
	"errors"

	"github.com/precinto/precinto/internal/capsule"
	"github.com/precinto/precinto/internal/fsx"
	"github.com/precinto/precinto/internal/sweep/capslog"
	"github.com/precinto/precinto/internal/sweep/journal"
)

// sealPoints are the failpoints a commit evaluates after its milestones
// (docs/TESTPLAN.md §4); unit seals use the seal.* names, history and
// Codex commits their own (or none).
type sealPoints struct {
	prepared, tmpWritten, committed string
}

var unitSealPoints = sealPoints{prepared: "seal.prepared", tmpWritten: "seal.tmp_written", committed: "seal.committed"}

// commitSpec is one capsule to write under an already begun journal
// record.
type commitSpec struct {
	rec        *journal.Record
	unitDir    dirHandle // capsules/<store>/<unit>: holds the operation directory
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
	// beforeRename runs between the capsule write and its commit rename
	// (the codex.manifest failpoint).
	beforeRename func() error
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
//  1. journal the operation directory (Record.Tmp), the final name
//     (Record.Capsule) and the generation before anything is written;
//  2. capsule.Seal writes, verifies and renames the capsule inside that
//     private operation directory (tmp_written is journaled from its
//     OnPhase callback);
//  3. a no-replace rename commits it into the unit directory, which is
//     fsynced;
//  4. the capsule-log entry is appended (FullSync), and only then is
//     committed journaled.
//
// On any failure before the log append nothing of the attempt is left: the
// operation directory is removed, and a capsule renamed but not logged is
// deleted (it can never be re-verified, D58).
func (r *run) commit(ctx context.Context, c *commitSpec) (*capsule.Sealed, error) {
	rec := c.rec
	rec.Tmp = opDirName(rec.ID)
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
	op, err := c.unitDir.OpenDir(rec.Tmp, true)
	if err != nil {
		return nil, r.abandon(c, err)
	}
	defer op.Close()
	req := c.req
	req.Out = op
	req.Name = c.name
	req.OnPhase = func(p capsule.Phase, _ *capsule.Sealed) error {
		if p != capsule.PhaseTmpWritten {
			return nil
		}
		if err := r.jr.Advance(rec, journal.PhaseTmpWritten); err != nil {
			return err
		}
		return hit(c.points.tmpWritten)
	}
	sealed, err := r.p.codec.Seal(ctx, req)
	if err != nil {
		return nil, r.abandon(c, err)
	}
	if c.beforeRename != nil {
		if err := c.beforeRename(); err != nil {
			return nil, r.abandon(c, err)
		}
	}
	if err := op.RenameTo(c.name, c.outDir, c.name, fsx.NoReplace); err != nil {
		return nil, r.abandon(c, err)
	}
	_ = removeOpDir(c.unitDir, rec.Tmp) // empty now; recovery removes it otherwise
	if r.p.afterRename != nil {
		r.p.afterRename()
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
	if r.p.afterLog != nil {
		r.p.afterLog()
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

// abandon cleans up a failed attempt: the operation directory, and a
// capsule already renamed into place but not logged.
func (r *run) abandon(c *commitSpec, cause error) error {
	if err := removeOpDir(c.unitDir, c.rec.Tmp); err != nil {
		return &commitError{err: errors.Join(cause, err), keepRecord: true}
	}
	return &commitError{err: cause}
}
