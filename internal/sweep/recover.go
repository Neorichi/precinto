package sweep

import (
	"context"
	"errors"
	"fmt"
	"path"
	"strconv"
	"strings"

	"github.com/precinto/precinto/internal/capsule"
	"github.com/precinto/precinto/internal/fsx"
	"github.com/precinto/precinto/internal/harness"
	"github.com/precinto/precinto/internal/sweep/capslog"
	"github.com/precinto/precinto/internal/sweep/journal"
)

// Recover finishes or rolls back every pending journal record without any
// key (SPEC §10.5). Each phase is the last completed milestone: prepared or
// tmp_written → remove the temporary; if the capsule named by
// Record.Capsule exists and is logged continue as committed, if it exists
// unlogged (a crash between rename and log append) remove it; keep
// plaintext;
// committed/unlinking → require the capsule to exist and be logged, then
// resume identity-checked unlinks (otherwise treat as tmp_written);
// staged/placing → roll forward; held/sealed/rewritten → finish the
// history protocol from the hold link and the journaled offsets. It runs
// before any Quarantine, so precinto's own crash leftovers are never
// reported as forgeries.
func Recover(ctx context.Context, e Env) (*Report, error) {
	r := newRun(e, prodPorts(e))
	err := r.recoverAll(ctx)
	return r.finish(), err
}

// recoverAll processes every pending record, oldest first. A record whose
// lock is held belongs to an operation still running in another process
// and is left alone. Unreadable records are returned as the error (and
// make Quarantine refuse to run).
func (r *run) recoverAll(ctx context.Context) error {
	recs, perr := r.jr.Pending()
	for _, rec := range recs {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if res := r.recoverOne(ctx, rec); res != nil {
			r.add(*res)
		}
	}
	return perr
}

// recoverOne dispatches one record by kind.
func (r *run) recoverOne(ctx context.Context, rec *journal.Record) *UnitResult {
	switch rec.Kind {
	case journal.KindSeal, journal.KindMarkdown:
		return r.recoverSeal(ctx, rec)
	case journal.KindRestore, journal.KindCodexRestore:
		return r.recoverRestore(ctx, rec)
	case journal.KindHistoryRotate:
		return r.recoverHistory(ctx, rec)
	case journal.KindHistoryMerge:
		return r.recoverMerge(ctx, rec)
	case journal.KindCodexSnapshot:
		return r.recoverCodexSnapshot(ctx, rec)
	case journal.KindPrune:
		return r.recoverPrune(ctx, rec)
	}
	return &UnitResult{Unit: rec.Unit, Harness: rec.Harness, Outcome: OutFailed,
		Detail: codeFailed + ": unknown journal record kind"}
}

// recoveredResult is the report line of a recovered record.
func recoveredResult(rec *journal.Record, kind capsule.Kind, o Outcome, detail string) *UnitResult {
	return &UnitResult{Harness: rec.Harness, Kind: kind, Unit: rec.Unit, Outcome: o, Gen: rec.Gen,
		Files: len(rec.Files), Detail: detail}
}

// capsuleState is what recovery finds at a journaled capsule name.
type capsuleState int

const (
	capsAbsent  capsuleState = iota // nothing at the name
	capsLogged                      // present, and the log has it with this header
	capsOrphan                      // present, and the log has no entry for the path: our crash leftover
	capsForeign                     // present, but the log names another capsule there: not ours to delete
)

// inspectCapsule classifies the capsule rel (relative to unitDir) whose
// log path is logPath.
func (r *run) inspectCapsule(unitDir dirHandle, rel, logPath string) (capsuleState, error) {
	if unitDir == nil || rel == "" {
		return capsAbsent, nil
	}
	st, err := unitDir.Lstat(rel)
	if err != nil {
		if isMissing(err) {
			return capsAbsent, nil
		}
		return capsAbsent, err
	}
	if !st.IsRegular() {
		return capsForeign, nil
	}
	_, hsum, err := r.p.codec.ReadHeader(unitDir, rel)
	if err != nil {
		// Unreadable as a capsule: decide by the log alone.
		hsum = ""
	}
	if hsum != "" {
		if _, err := r.log.Lookup(logPath, hsum); err == nil {
			return capsLogged, nil
		} else if !errors.Is(err, capslog.ErrNotLogged) {
			return capsAbsent, err
		}
	}
	all, err := r.log.All()
	if err != nil {
		return capsAbsent, err
	}
	for _, en := range all {
		if en.Path == logPath {
			return capsForeign, nil
		}
	}
	return capsOrphan, nil
}

// storeOfRecord is the capsule store of a journaled operation.
func storeOfRecord(rec *journal.Record) string {
	if rec.Kind == journal.KindMarkdown {
		return "md"
	}
	return rec.Harness
}

// basesOfRecord opens the base directories a record's files live in.
func (r *run) basesOfRecord(rec *journal.Record) (map[capsule.BaseID]dirHandle, map[capsule.BaseID]string, error) {
	handles := map[capsule.BaseID]dirHandle{}
	dirs := map[capsule.BaseID]string{}
	for _, jf := range rec.Files {
		id, abs := decodeBase(jf.Base)
		if _, ok := handles[id]; ok {
			continue
		}
		if abs == "" {
			closeAll(handles)
			return nil, nil, fmt.Errorf("%w: journaled base %s without a directory", fsx.ErrUnsafe, id)
		}
		d, err := r.p.fs.OpenBase(abs)
		if err != nil {
			closeAll(handles)
			return nil, nil, err
		}
		handles[id], dirs[id] = d, abs
	}
	return handles, dirs, nil
}

// noteValue returns the value of a "key=value" note.
func noteValue(rec *journal.Record, key string) string {
	for _, n := range rec.Notes {
		if v, ok := strings.CutPrefix(n, key+"="); ok {
			return v
		}
	}
	return ""
}

// recoverSeal finishes or rolls back a seal (SPEC §10.5, D58b): the
// operation directory always goes; a capsule at the journaled name that
// is present and logged makes the seal continue as committed (resume
// identity-checked unlinks, finish the receipt and the ledger); one that is
// present without any log entry is deleted (the ephemeral key that could
// verify it is gone); plaintext is never touched otherwise.
func (r *run) recoverSeal(ctx context.Context, rec *journal.Record) *UnitResult {
	kind := capsule.Kind("")
	if rec.Kind == journal.KindMarkdown {
		kind = capsule.KindMarkdown
	}
	if !validKey(rec.Unit) {
		return recoveredResult(rec, kind, OutFailed, codeUnitKey+": journal record with an invalid unit key")
	}
	lk, err := r.lockUnit(rec.Unit)
	if err != nil {
		if errors.Is(err, fsx.ErrLocked) {
			return nil // still in flight in another process
		}
		return recoveredResult(rec, kind, OutFailed, failDetail(err))
	}
	defer lk.Unlock()

	store := storeOfRecord(rec)
	capsRoot, unitDir, err := r.openCapsDir(store, rec.Unit, false)
	if err != nil && !isMissing(err) {
		return recoveredResult(rec, kind, OutFailed, failDetail(err))
	}
	if capsRoot != nil {
		defer capsRoot.Close()
		defer unitDir.Close()
	}
	if unitDir != nil && rec.Tmp != "" && isOpDir(rec.Tmp) {
		if err := removeOpDir(unitDir, rec.Tmp); err != nil {
			return recoveredResult(rec, kind, OutFailed, failDetail(err))
		}
	}
	state, err := r.inspectCapsule(unitDir, rec.Capsule, logPathOf(store, rec.Unit, rec.Capsule))
	if err != nil {
		return recoveredResult(rec, kind, OutFailed, failDetail(err))
	}
	if rec.Capsule != "" && strings.Contains(rec.Capsule, "/") {
		state = capsForeign // seal records never name nested capsules
	}
	committed := state == capsLogged
	switch {
	case committed:
		// Continue as committed (SEAL-7, SEAL-8, SEAL-9).
	case state == capsOrphan:
		// SEAL-6: renamed but never logged. Delete it; the number is
		// never reused (gaps are allowed).
		if err := unitDir.Remove(rec.Capsule); err != nil && !isMissing(err) {
			return recoveredResult(rec, kind, OutFailed, failDetail(err))
		}
		if rec.Phase != journal.PhaseRescue {
			return r.doneRecovered(rec, kind, OutSkipped, "recovered: unlogged capsule removed, plaintext kept")
		}
	default:
		if rec.Phase != journal.PhaseRescue {
			return r.doneRecovered(rec, kind, OutSkipped, "recovered: rolled back, plaintext kept")
		}
	}
	// committed, unlinking, or a rescue whose main generation committed.
	bases, baseDirs, err := r.basesOfRecord(rec)
	if err != nil {
		return recoveredResult(rec, kind, OutFailed, failDetail(err))
	}
	defer closeAll(bases)
	u := harness.Unit{Harness: harness.ID(rec.Harness), Kind: kind, Key: rec.Unit, Home: harness.Home{Bases: baseDirs}}
	if kind == capsule.KindMarkdown {
		if err := r.ensureMarkerForRecord(rec, bases); err != nil {
			return recoveredResult(rec, kind, OutFailed, failDetail(err))
		}
	}
	ur := r.unlinkFiles(ctx, u, bases, rec, false, unitSealPoints)
	r.pruneDirs(u, bases, rec)
	gen := rec.Gen
	if !committed {
		// The rescue capsule is gone: the newest logged generation stands.
		entries, err := r.log.Unit(rec.Unit)
		if err != nil {
			return recoveredResult(rec, kind, OutFailed, failDetail(err))
		}
		n, ok := newestEntry(entries)
		if !ok {
			return recoveredResult(rec, kind, OutFailed, codeNotLogged+": no logged generation for a committed seal")
		}
		gen = n.Gen
	}
	old, hasOld, err := r.loadReceipt(rec.Unit)
	if err != nil {
		return recoveredResult(rec, kind, OutFailed, failDetail(err))
	}
	var oldp *receiptDisk
	if hasOld {
		oldp = &old
	}
	// The unchanged path journals the receipt generation: keep its hashes.
	shas := map[fileKey]string{}
	if oldp != nil && oldp.Gen == gen {
		for _, rf := range oldp.Files {
			shas[fileKey{rf.Base, rf.Rel}] = rf.SHA256
		}
	}
	if err := r.rewriteReceipt(rec.Unit, kind, rec.Harness, bases, rec, shas, gen, oldp, baseDirs); err != nil {
		return recoveredResult(rec, kind, OutFailed, failDetail(err))
	}
	if sid, n := noteValue(rec, "ledger-sid"), noteValue(rec, "ledger-n"); sid != "" && n != "" {
		if ln, err := strconv.ParseInt(n, 10, 64); err == nil && ln > 0 {
			_ = r.p.ledger.Archive(rec.Harness, sid, ln)
		}
	}
	o := OutSealed
	detail := "recovered: seal finished"
	if ur.removeFailed > 0 {
		o, detail = OutRemoveFailed, fmt.Sprintf("recovered: %d file(s) could not be removed", ur.removeFailed)
	}
	rec.Gen = gen
	return r.doneRecovered(rec, kind, o, detail)
}

// doneRecovered removes a finished record and reports it.
func (r *run) doneRecovered(rec *journal.Record, kind capsule.Kind, o Outcome, detail string) *UnitResult {
	if err := r.jr.Done(rec); err != nil {
		return recoveredResult(rec, kind, OutFailed, failDetail(err))
	}
	return recoveredResult(rec, kind, o, detail)
}

// recoverPrune rolls a confirmed deletion forward: every listed capsule is
// marked deleted in the log and removed (D15; the user confirmed it).
func (r *run) recoverPrune(ctx context.Context, rec *journal.Record) *UnitResult {
	lk, err := r.lockName("prune")
	if err != nil {
		if errors.Is(err, fsx.ErrLocked) {
			return nil
		}
		return recoveredResult(rec, "", OutFailed, failDetail(err))
	}
	defer lk.Unlock()
	if err := r.finishDeletions(rec); err != nil {
		return recoveredResult(rec, "", OutFailed, failDetail(err))
	}
	return r.doneRecovered(rec, "", OutSkipped, "recovered: deletions finished")
}

// recordedCapsules lists the capsule paths (relative to CapsulesDir) a
// pending record names, so Quarantine never touches them.
func recordedCapsules(rec *journal.Record) []string {
	var out []string
	switch rec.Kind {
	case journal.KindSeal, journal.KindMarkdown, journal.KindCodexSnapshot:
		store := storeOfRecord(rec)
		if rec.Capsule != "" {
			out = append(out, logPathOf(store, rec.Unit, rec.Capsule))
		}
		if rec.Tmp != "" {
			out = append(out, logPathOf(store, rec.Unit, rec.Tmp))
		}
		if rec.Kind == journal.KindCodexSnapshot {
			for _, jf := range rec.Files {
				if id, _ := decodeBase(jf.Base); id == baseBlob {
					out = append(out, logPathOf(store, rec.Unit, jf.Rel))
				}
			}
		}
	case journal.KindPrune:
		for _, jf := range rec.Files {
			out = append(out, jf.Rel)
		}
	case journal.KindHistoryRotate:
		// History generations are sealed under their own seal records.
	}
	for i := range out {
		out[i] = path.Clean(out[i])
	}
	return out
}
