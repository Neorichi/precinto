package sweep

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"time"

	"github.com/precinto/precinto/internal/capsule"
	"github.com/precinto/precinto/internal/fsx"
	"github.com/precinto/precinto/internal/harness"
	"github.com/precinto/precinto/internal/live"
	"github.com/precinto/precinto/internal/sweep/capslog"
	"github.com/precinto/precinto/internal/sweep/journal"
)

// planFile is the name of the placement plan inside the primary staging
// directory. It holds paths and hashes only (no content) and lets recovery
// roll a staged unit forward without any key (SPEC §11.5, D58d).
const planFile = "plan.json"

// restorePlan is plan.json.
type restorePlan struct {
	V          int                       `json:"v"`
	Kind       capsule.Kind              `json:"kind"`
	Harness    string                    `json:"harness"`
	Unit       string                    `json:"unit"`
	Gen        uint64                    `json:"gen"`
	VaultID    string                    `json:"vault_id"`
	RootIDs    []string                  `json:"root_ids"`
	Bases      map[capsule.BaseID]string `json:"bases"`
	Stagings   []string                  `json:"stagings,omitempty"` // secondary stagings (other devices); index k+1
	Files      []plannedFile             `json:"files"`
	Snapshot   bool                      `json:"snapshot,omitempty"`
	Blobs      map[string]string         `json:"blobs,omitempty"`      // codex: rel → blob key (receipt)
	Quarantine string                    `json:"quarantine,omitempty"` // codex: absolute dir for displaced -wal/-shm/-journal
	ConflictAt time.Time                 `json:"conflict_at"`
	ClampTo    time.Time                 `json:"clamp_to,omitempty"` // D14: mtimes not older than this
	Marker     string                    `json:"marker,omitempty"`   // notes: marker rel removed after placement
	// UnitID and HomeID are the authenticated unit id and the registered
	// home of the unit: placement asks the adapter about this unit's
	// liveness by them, also when recovery rolls the restore forward (D84).
	UnitID string `json:"unit_id,omitempty"`
	HomeID string `json:"home_id,omitempty"`
	// Absent lists the entries of the restored generations this restore
	// leaves out (an unsafe base, TargetRules.Skip): the receipt records
	// them as absent, so a re-seal without them is partial (D85).
	Absent []ReceiptFile `json:"absent,omitempty"`
}

// plannedFile is one placement.
type plannedFile struct {
	Base       capsule.BaseID    `json:"base"`
	Rel        string            `json:"rel"`
	Stage      int               `json:"stage"`  // 0 = primary staging, k = Stagings[k-1]
	Staged     string            `json:"staged"` // relative to that staging directory
	Policy     harness.Placement `json:"policy"`
	Mode       uint32            `json:"mode"`
	MtimeNS    int64             `json:"mtime_ns"`
	Size       int64             `json:"size"`
	SHA        string            `json:"sha256"`
	FromGen    uint64            `json:"from_gen"`
	Dir        bool              `json:"dir,omitempty"`
	Group      string            `json:"group,omitempty"`
	Style      conflictStyle     `json:"conflict_style,omitempty"`
	ConflictOK bool              `json:"conflict_ok,omitempty"` // a conflict copy may be written next to Rel
	Last       bool              `json:"last,omitempty"`        // placed after every other entry (TargetRules.Last, REST-3)
	// The receipt of a version merged from two generations covers only the
	// older (C) prefix, so a re-seal stores the merge as a new generation
	// instead of dropping it as unchanged.
	ReceiptSize int64  `json:"receipt_size,omitempty"`
	ReceiptSHA  string `json:"receipt_sha256,omitempty"`
	ReceiptGen  uint64 `json:"receipt_gen,omitempty"`
}

// stagedGen is one extracted generation.
type stagedGen struct {
	entry  capslog.Entry
	man    capsule.Manifest
	staged []capsule.Staged
	dir    dirHandle // its sub-staging directory
	prefix string    // its name inside the primary staging
}

// writePlan stores plan.json in the primary staging (atomic, fsynced).
func (r *run) writePlan(st stagingHandle, p *restorePlan) error {
	p.V = 1
	b, err := json.Marshal(p)
	if err != nil {
		return err
	}
	return fsx.WriteFileAtomic(filepath.Join(st.Path(), planFile), b, 0o600)
}

// readPlan reads plan.json of a staging directory.
func (r *run) readPlan(st stagingHandle) (*restorePlan, error) {
	b, _, err := readAllBounded(st.Dir(), planFile, 256<<20)
	if err != nil {
		return nil, err
	}
	var p restorePlan
	if err := json.Unmarshal(b, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

// removeStagings removes the primary staging and every secondary one.
func (r *run) removeStagings(primary stagingHandle, p *restorePlan) error {
	var errs []error
	if p != nil {
		for _, s := range p.Stagings {
			if st, err := r.p.fs.OpenStaging(s); err == nil {
				errs = append(errs, st.Remove())
			}
		}
	}
	if primary != nil {
		errs = append(errs, primary.Remove())
	}
	return errors.Join(errs...)
}

// subStaging creates the staging of one capsule inside the primary
// staging (planned paths are relative to the primary); anywhere else is
// refused rather than mis-addressed.
func (r *run) subStaging(primary stagingHandle, target, name string) (stagingHandle, error) {
	sub, err := r.p.fs.NewStaging(primary.Path(), target, name)
	if err != nil {
		return nil, err
	}
	if filepath.Clean(sub.Path()) != filepath.Join(primary.Path(), name) {
		_ = sub.Remove()
		return nil, fmt.Errorf("%w: staging not on the target volume", fsx.ErrUnsafe)
	}
	return sub, nil
}

// extract decrypts one logged capsule into sub (validated by check).
func (r *run) extract(ctx context.Context, en capslog.Entry, kg *keyGuard, sub stagingHandle, check func(capsule.Entry) error, target string) (capsule.Manifest, []capsule.Staged, error) {
	f, err := r.openCapsule(en)
	if err != nil {
		return capsule.Manifest{}, nil, err
	}
	defer f.Close()
	limits := capsule.Limits{MaxFiles: capsule.MaxEntries, MaxTotal: math.MaxInt64}
	if avail, _, err := r.p.fs.Space(target); err == nil {
		if a := int64(avail) - r.e.Floor.MinBytes; a > 0 {
			limits.MaxTotal = a
		} else {
			limits.MaxTotal = 0
		}
	}
	var man capsule.Manifest
	var staged []capsule.Staged
	err = kg.with(en.Path, func(key []byte) error {
		var err error
		man, staged, err = r.p.codec.Extract(ctx, f, extractRequest{FileKey: key, Staging: sub, Limits: limits, Check: check})
		return err
	})
	if err != nil {
		return capsule.Manifest{}, nil, err
	}
	if err := checkManifest(man, en); err != nil {
		return capsule.Manifest{}, nil, err
	}
	return man, staged, nil
}

// layeredOpts adapts the layered restore to notes.
type layeredOpts struct {
	style    conflictStyle        // conflict copy naming
	retarget func(f *plannedFile) // rewrites targets after the fold (notes: marker location)
	marker   string               // marker removed after placement (notes)
}

// restoreLayered restores a layered unit: the newest generation plus,
// through non-successor links, older versions folded in by the placement
// table (SPEC §10.4, D42).
func (r *run) restoreLayered(ctx, actx context.Context, p *restoreUnitPlan, a authenticated, kg *keyGuard, req RestoreRequest, aborted func() bool) UnitResult {
	return r.restoreLayeredWith(ctx, actx, p, a, kg, req, aborted, layeredOpts{style: conflictRestored})
}

// restoreLayeredWith is restoreLayered with note options.
func (r *run) restoreLayeredWith(ctx, actx context.Context, p *restoreUnitPlan, a authenticated, kg *keyGuard, req RestoreRequest, aborted func() bool, lo layeredOpts) UnitResult {
	res := planResult(p)
	target := firstBase(a.rules.Bases)
	if target == "" {
		return failed(res, fmt.Errorf("%w: no target base", harness.ErrUnregistered))
	}
	total, perBase := plannedBytes(p.mans)
	total = max(total, p.bytes)
	if err := r.checkRestoreSpace(a.rules.Bases, target, total, perBase); err != nil {
		res = failed(res, noSpace(err))
		res.Outcome = OutSkipped
		return res
	}
	rec, err := r.jr.Begin(journal.KindRestore, string(p.ref.Harness), p.ref.Key)
	if err != nil {
		return failed(res, err)
	}
	st, err := r.p.fs.NewStaging(r.l.StagingDir, target, rec.ID)
	if err != nil {
		_ = r.jr.Done(rec)
		return failed(res, noSpace(err))
	}
	rec.Staging = st.Path()
	plan := &restorePlan{
		Kind: p.ref.Kind, Harness: string(p.ref.Harness), Unit: p.ref.Key, Gen: p.newest.Gen,
		VaultID: p.ref.VaultID, RootIDs: p.ref.RootIDs, Bases: a.rules.Bases, ConflictAt: r.now(),
		UnitID: a.unitID, HomeID: a.ref.HomeID,
	}
	if p.mtimeNow {
		plan.ClampTo = r.now().Add(-24 * time.Hour)
	}
	rollback := func(cause error, o Outcome, detail string) UnitResult {
		_ = r.removeStagings(st, plan)
		_ = r.jr.Done(rec)
		if cause != nil {
			return failed(res, cause)
		}
		res.Outcome, res.Detail = o, detail
		return res
	}
	if err := r.jr.Save(rec); err != nil {
		return rollback(err, "", "")
	}
	if err := r.writePlan(st, plan); err != nil {
		return rollback(err, "", "")
	}
	check := checkEntries(a.rules, true)
	var gens []stagedGen
	for _, en := range p.entries {
		if aborted() {
			return rollback(nil, OutSkipped, "lock: rolled back before staging")
		}
		prefix := "g" + strconv.FormatUint(en.Gen, 10)
		sub, err := r.subStaging(st, target, prefix)
		if err != nil {
			return rollback(noSpace(err), "", "")
		}
		man, staged, err := r.extract(actx, en, kg, sub, check, target)
		if err != nil {
			if aborted() {
				return rollback(nil, OutSkipped, "lock: rolled back before staging")
			}
			return rollback(noSpace(err), "", "")
		}
		kg.forget(en.Path) // decrypted: its key goes now (CC-17)
		gens = append(gens, stagedGen{entry: en, man: man, staged: staged, dir: sub.Dir(), prefix: prefix})
	}
	gens, skipped, absent := skipUnsafe(gens, a.rules)
	plan.Absent = absent
	files, merged, conflicts, err := r.foldGenerations(ctx, gens, a.rules, st.Dir(), plan.ConflictAt, lo.style)
	if err != nil {
		return rollback(err, "", "")
	}
	if lo.retarget != nil {
		for i := range files {
			lo.retarget(&files[i])
		}
	}
	plan.Files = files
	plan.Marker = lo.marker
	sortPlacements(plan.Files)
	if err := r.splitDevices(st, plan, target); err != nil {
		return rollback(err, "", "")
	}
	if err := r.writePlan(st, plan); err != nil {
		return rollback(err, "", "")
	}
	if req.BeforePlace != nil {
		if err := req.BeforePlace(p.ref.Key); err != nil {
			return rollback(err, "", "")
		}
	}
	if aborted() {
		return rollback(nil, OutSkipped, "lock: rolled back before staging")
	}
	out := r.stageAndPlace(ctx, st, plan, rec, a.ad)
	out.Lineage = res.Lineage
	out.mergedFold += merged
	out.conflictFold += conflicts
	final := out.result(res)
	if out.err == nil {
		r.reportSkipped(final, skipped)
	}
	return final
}

// skipUnsafe drops the entries of bases the adapter reports unsafe now
// (TargetRules.Skip) from the staged generations: they are never placed
// and the capsule keeps them (SPEC §11.5, CC-22). It returns, per reason,
// how many distinct files were left out, and those files (newest version
// first) as absent receipt entries (D85).
func skipUnsafe(gens []stagedGen, rules harness.TargetRules) ([]stagedGen, map[string]int, []ReceiptFile) {
	if len(rules.Skip) == 0 {
		return gens, nil, nil
	}
	skipped := map[string]int{}
	seen := map[fileKey]bool{}
	var absent []ReceiptFile
	out := make([]stagedGen, 0, len(gens))
	for _, g := range gens {
		ng := g
		ng.man.Files = nil
		for _, en := range g.man.Files {
			if _, skip := rules.Skip[en.Base]; skip {
				if k := (fileKey{en.Base, en.Rel}); !en.Dir && !seen[k] {
					seen[k] = true
					skipped[rules.Skip[en.Base]]++
					absent = append(absent, ReceiptFile{Base: en.Base, Rel: en.Rel, SHA256: en.SHA256, Size: en.Size, FromGen: g.entry.Gen, Absent: true})
				}
				continue
			}
			ng.man.Files = append(ng.man.Files, en)
		}
		ng.staged = nil
		for _, s := range g.staged {
			if _, skip := rules.Skip[s.Entry.Base]; !skip {
				ng.staged = append(ng.staged, s)
			}
		}
		out = append(out, ng)
	}
	return out, skipped, absent
}

// reportSkipped adds one skipped result per reason for the entries a
// restore left out (CC-22: OutSkipped, Detail the adapter's reason, e.g.
// "unsafe tmp"); the unit's own result says what was placed.
func (r *run) reportSkipped(res UnitResult, skipped map[string]int) {
	reasons := make([]string, 0, len(skipped))
	for why := range skipped {
		reasons = append(reasons, why)
	}
	sort.Strings(reasons)
	for _, why := range reasons {
		s := UnitResult{Harness: res.Harness, Kind: res.Kind, Unit: res.Unit, Gen: res.Gen, Outcome: OutSkipped,
			Files: skipped[why], Detail: why}
		if s.Detail == "" {
			s.Detail = "unsafe base"
		}
		r.add(s)
	}
}

// placeOutcome counts what placement did.
type placeOutcome struct {
	err          error
	placed       int
	noop         int
	kept         int
	merged       int
	conflicts    int
	mergedFold   int
	conflictFold int
	Lineage      capsule.Lineage
}

func (o placeOutcome) result(res UnitResult) UnitResult {
	res.Files = o.placed + o.noop + o.kept + o.merged
	if o.err != nil {
		if errors.Is(o.err, ErrLive) {
			return liveResult(res, live.Verdict{Live: true}, true, "unit became live while placing")
		}
		return failed(res, o.err)
	}
	res.Outcome = OutRestored
	switch {
	case o.conflicts+o.conflictFold > 0:
		res.Outcome = OutConflict
		res.Detail = fmt.Sprintf("%d conflict(s) kept as copies", o.conflicts+o.conflictFold)
	case o.merged+o.mergedFold > 0:
		res.Outcome = OutMerged
	}
	return res
}

// stageAndPlace journals the staged plan, places every file and writes the
// receipt (shared by restore and keyless roll-forward).
func (r *run) stageAndPlace(ctx context.Context, st stagingHandle, plan *restorePlan, rec *journal.Record, ad harness.Adapter) placeOutcome {
	stagings := []dirHandle{st.Dir()}
	for _, s := range plan.Stagings {
		sh, err := r.p.fs.OpenStaging(s)
		if err != nil {
			return placeOutcome{err: err}
		}
		stagings = append(stagings, sh.Dir())
	}
	rec.Files = rec.Files[:0]
	for _, pf := range plan.Files {
		var snap fsx.Stat
		if !pf.Dir {
			s, err := stagings[pf.Stage].Lstat(pf.Staged)
			if err != nil {
				return placeOutcome{err: err}
			}
			snap = s
		}
		rec.Files = append(rec.Files, journal.File{Base: string(pf.Base), Dir: plan.Bases[pf.Base], Rel: pf.Rel, Snap: snap})
	}
	if err := r.jr.Advance(rec, journal.PhaseStaged); err != nil {
		return placeOutcome{err: err}
	}
	if err := r.hit("restore.staged"); err != nil {
		return placeOutcome{err: err}
	}
	return r.placeAndFinish(ctx, st, plan, rec, stagings, ad)
}

// placeAndFinish places the files not yet done, writes the receipt,
// removes the stagings and finishes the record.
func (r *run) placeAndFinish(ctx context.Context, st stagingHandle, plan *restorePlan, rec *journal.Record, stagings []dirHandle, ad harness.Adapter) placeOutcome {
	bases := map[capsule.BaseID]dirHandle{}
	defer closeAll(bases)
	for id, p := range plan.Bases {
		if p == "" {
			continue
		}
		d, err := r.p.fs.OpenBase(p)
		if err != nil {
			return placeOutcome{err: err}
		}
		bases[id] = d
	}
	pc := &placeCtx{r: r, plan: plan, rec: rec, stagings: stagings, bases: bases}
	ref := harness.UnitRef{Harness: harness.ID(plan.Harness), Kind: plan.Kind, Key: plan.Unit, HomeID: plan.HomeID, VaultID: plan.VaultID, RootIDs: plan.RootIDs}
	rules := harness.TargetRules{Bases: plan.Bases}
	pc.live = func() bool { isLive, _, _ := r.restoreLive(ctx, ad, ref, plan.UnitID, rules); return isLive }
	// D84: whenever a target already exists (a placement may replace,
	// merge or union into it), liveness is decided before the first file
	// is placed; a live unit is rolled back with nothing placed.
	if !anyDone(rec) && pc.targetExists() && pc.live() {
		if err := r.removeStagings(st, plan); err != nil {
			return placeOutcome{err: errors.Join(errAbortLive, err)}
		}
		if err := r.jr.Done(rec); err != nil {
			return placeOutcome{err: errors.Join(errAbortLive, err)}
		}
		return placeOutcome{err: errAbortLive}
	}
	if plan.Quarantine != "" {
		if err := ensurePrivateDir(plan.Quarantine); err == nil {
			if q, err := r.p.fs.OpenBase(plan.Quarantine); err == nil {
				pc.quarantine = q
				defer q.Close()
			}
		}
	}
	var outcome placeOutcome
	for i := range plan.Files {
		if i < len(rec.Files) && rec.Files[i].Done {
			pc.rerecord(i) // placed before a crash: its receipt line was lost
			continue
		}
		if err := pc.placeOne(ctx, i); err != nil {
			outcome.err = err
			break
		}
		if i < len(rec.Files) {
			rec.Files[i].Done = true
		}
		var err error
		if rec.Phase != journal.PhasePlacing {
			err = r.jr.Advance(rec, journal.PhasePlacing)
		} else {
			err = r.jr.Save(rec)
		}
		if err != nil {
			outcome.err = err
			break
		}
		if err := r.hit("restore.placing"); err != nil {
			outcome.err = err
			break
		}
	}
	outcome.placed, outcome.noop, outcome.kept, outcome.merged, outcome.conflicts = pc.placed, pc.noop, pc.kept, pc.merged, pc.conflicts
	if errors.Is(outcome.err, ErrLive) && anyDone(rec) && plan.UnitID != "" {
		// D84: the unit became live after some of its files were placed.
		// The record and the stagings stay, so recovery rolls the restore
		// forward once the unit is quiet; no receipt is written for a
		// unit without its last files (the transcript is placed last).
		return outcome
	}
	if err := r.writeRestoreReceipt(plan, append(pc.receipt, pc.absent...), bases); err != nil && outcome.err == nil {
		outcome.err = err
	}
	if outcome.err == nil {
		if err := r.hit("restore.receipt"); err != nil {
			outcome.err = err
		}
	}
	if plan.Marker != "" && outcome.err == nil {
		if root := bases[capsule.BaseRoot]; root != nil {
			r.removeMarker(root, plan.Marker, plan.Unit)
		}
	}
	if err := r.removeStagings(st, plan); err != nil && outcome.err == nil {
		outcome.err = err
	}
	if err := r.jr.Done(rec); err != nil && outcome.err == nil {
		outcome.err = err
	}
	return outcome
}

// anyDone reports whether a restore record marks a placed file.
func anyDone(rec *journal.Record) bool {
	for _, f := range rec.Files {
		if f.Done {
			return true
		}
	}
	return false
}

// targetExists reports whether a planned file's target is already there.
func (pc *placeCtx) targetExists() bool {
	for _, pf := range pc.plan.Files {
		if pf.Dir {
			continue
		}
		b := pc.bases[pf.Base]
		if b == nil {
			continue
		}
		if _, err := b.Lstat(pf.Rel); err == nil {
			return true
		}
	}
	return false
}

// writeRestoreReceipt writes the receipt of a restore (SPEC §11.5 step 5):
// the files placed now, plus files of an older receipt that this restore
// did not touch and that still have their recorded identity.
func (r *run) writeRestoreReceipt(plan *restorePlan, files []ReceiptFile, bases map[capsule.BaseID]dirHandle) error {
	present := 0
	have := map[fileKey]bool{}
	for _, f := range files {
		have[fileKey{f.Base, f.Rel}] = true
		if !f.Absent {
			present++
		}
	}
	if present == 0 {
		return nil
	}
	// D85: entries this restore left out are absent, unless placed.
	for _, f := range plan.Absent {
		if k := (fileKey{f.Base, f.Rel}); !have[k] {
			have[k] = true
			files = append(files, f)
		}
	}
	rd := receiptDisk{Receipt: Receipt{Unit: plan.Unit, Gen: plan.Gen, RestoredAt: r.now(), Files: files},
		Kind: plan.Kind, Harness: plan.Harness, Bases: plan.Bases, Blobs: plan.Blobs}
	old, ok, err := r.loadReceipt(plan.Unit)
	if err == nil && ok {
		for _, f := range old.Files {
			if have[fileKey{f.Base, f.Rel}] {
				continue
			}
			if f.Absent {
				rd.Files = append(rd.Files, f)
				continue
			}
			d := bases[f.Base]
			if d == nil {
				continue
			}
			if st, err := d.Lstat(f.Rel); err == nil && st.Unchanged(f.Snap) {
				rd.Files = append(rd.Files, f)
				if old.Blobs != nil && rd.Blobs != nil {
					if b, ok := old.Blobs[f.Rel]; ok {
						rd.Blobs[f.Rel] = b
					}
				}
			}
		}
		if old.Gen > rd.Gen {
			rd.Gen = old.Gen
		}
	}
	return r.writeReceipt(rd)
}

// sortPlacements orders placements: entries the adapter marks Last
// (TargetRules.Last: Claude's <sid>.jsonl, REST-3) after every other one;
// before them, and as the tie-break among them, directories, then
// ordinary files, then append-only JSONL files deepest first, so a
// session's main transcript (the shallowest) is placed last even without
// the adapter's rule (SPEC §11.5 step 4, R6).
func sortPlacements(files []plannedFile) {
	rank := func(f plannedFile) int {
		n := 1
		switch {
		case f.Dir:
			n = 0
		case f.Policy == harness.PlaceJSONLAppend:
			n = 2
		}
		if f.Last {
			n += 3
		}
		return n
	}
	sort.SliceStable(files, func(a, b int) bool {
		ra, rb := rank(files[a]), rank(files[b])
		if ra != rb {
			return ra < rb
		}
		if ra%3 == 2 {
			if da, db := depth(files[a].Rel), depth(files[b].Rel); da != db {
				return da > db
			}
		}
		if files[a].Base != files[b].Base {
			return files[a].Base < files[b].Base
		}
		return files[a].Rel < files[b].Rel
	})
}

// splitDevices moves staged files whose target base lives on another file
// system into a staging directory on that file system (renames must not
// cross devices). Secondary stagings are recorded in the plan before they
// receive anything, so recovery can always remove them.
func (r *run) splitDevices(st stagingHandle, plan *restorePlan, target string) error {
	primaryDev, err := st.Dir().Device()
	if err != nil {
		return err
	}
	devOf := map[capsule.BaseID]uint64{}
	for id, p := range plan.Bases {
		d, err := r.p.fs.OpenBase(p)
		if err != nil {
			return err
		}
		dev, err := d.Device()
		d.Close()
		if err != nil {
			return err
		}
		devOf[id] = dev
	}
	stageOf := map[uint64]int{primaryDev: 0}
	var handles []stagingHandle
	for i := range plan.Files {
		pf := &plan.Files[i]
		if pf.Dir {
			continue
		}
		dev := devOf[pf.Base]
		k, ok := stageOf[dev]
		if !ok {
			sh, err := r.p.fs.NewStaging(r.l.StagingDir, plan.Bases[pf.Base], path.Base(st.Path())+"-"+strconv.Itoa(len(handles)+1))
			if err != nil {
				return err
			}
			handles = append(handles, sh)
			plan.Stagings = append(plan.Stagings, sh.Path())
			if err := r.writePlan(st, plan); err != nil {
				return err
			}
			k = len(handles)
			stageOf[dev] = k
		}
		if k == 0 {
			continue
		}
		dst := handles[k-1].Dir()
		name := "f" + strconv.Itoa(i)
		if err := copyFile(st.Dir(), pf.Staged, dst, name); err != nil {
			return err
		}
		pf.Stage, pf.Staged = k, name
	}
	return nil
}

// copyFile copies src/srcRel to a new file dst/dstRel (O_EXCL, fsynced).
func copyFile(src dirHandle, srcRel string, dst dirHandle, dstRel string) error {
	in, _, err := src.Open(srcRel)
	if err != nil {
		return err
	}
	defer in.Close()
	out, name, err := dst.CreateTemp(".", ".copy-*")
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		if !ok {
			out.Close()
			_ = dst.Remove(name)
		}
	}()
	if _, err := out.ReadFrom(in); err != nil {
		return err
	}
	if err := fsx.FullSync(out); err != nil {
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	if err := dst.Rename(name, dstRel, fsx.NoReplace); err != nil {
		return err
	}
	ok = true
	return nil
}

// foldGenerations resolves the versions of every path across the chain
// (newest first): a path absent from newer generations comes from the
// older one; two versions go through the placement table with the newer
// as F and the older as C; an unresolvable pair keeps the newer at the
// path and the older at <name>.precinto-g<k><ext> (SPEC §10.4).
func (r *run) foldGenerations(ctx context.Context, gens []stagedGen, rules harness.TargetRules, primary dirHandle, at time.Time, style conflictStyle) ([]plannedFile, int, int, error) {
	type cur struct {
		pf   plannedFile
		dir  dirHandle
		rel  string
		snap fsx.Stat
	}
	policy := func(en capsule.Entry) harness.Placement {
		if rules.Policy == nil {
			return harness.PlaceExact
		}
		return rules.Policy(en)
	}
	resolved := map[fileKey]*cur{}
	var order []fileKey
	var extra []plannedFile
	dirs := map[fileKey]plannedFile{}
	var dirOrder []fileKey
	merged, conflicts := 0, 0
	usedConflict := map[fileKey]bool{}
	lineageOf := map[uint64]capsule.Lineage{}
	for _, g := range gens {
		lineageOf[g.entry.Gen] = capsule.Lineage(g.entry.Lineage)
	}
	for _, g := range gens {
		for _, en := range g.man.Files {
			if !en.Dir {
				continue
			}
			k := fileKey{en.Base, en.Rel}
			if _, ok := dirs[k]; !ok {
				dirs[k] = plannedFile{Base: en.Base, Rel: en.Rel, Dir: true, Mode: en.Mode, MtimeNS: en.MtimeNS, FromGen: g.entry.Gen}
				dirOrder = append(dirOrder, k)
			}
		}
		for _, s := range g.staged {
			en := s.Entry
			if en.Dir {
				continue
			}
			k := fileKey{en.Base, en.Rel}
			pol := policy(en)
			v := &cur{
				pf: plannedFile{Base: en.Base, Rel: en.Rel, Staged: path.Join(g.prefix, s.StagedRel), Policy: pol,
					Mode: en.Mode, MtimeNS: en.MtimeNS, Size: en.Size, SHA: en.SHA256, FromGen: g.entry.Gen, Group: en.Group,
					Style: style, ConflictOK: rules.Allow != nil && rules.Allow(en.Base, conflictName(en.Rel, style, at, 0)),
					Last: rules.Last != nil && rules.Last(en)},
				dir: g.dir, rel: s.StagedRel, snap: s.Stat,
			}
			c, ok := resolved[k]
			if !ok {
				resolved[k] = v
				order = append(order, k)
				continue
			}
			facts, err := r.gatherFacts(ctx, pol,
				version{dir: v.dir, rel: v.rel, size: v.pf.Size, sha: v.pf.SHA, snap: v.snap},
				version{dir: c.dir, rel: c.rel, size: c.pf.Size, sha: c.pf.SHA, snap: c.snap})
			if err != nil {
				return nil, 0, 0, err
			}
			act := decidePlacement(facts)
			if act == actConflict && supersedable(pol) {
				// D87: a generation that is not diverged holds, at an
				// exact-placement path, a newer version of what was
				// placed there: it supersedes the older one.
				if l := lineageOf[c.pf.FromGen]; l != "" && l != capsule.LineageDiverged {
					act = actKeep
				}
			}
			switch act {
			case actNoop, actKeep:
				// The newer version contains (or supersedes) the older one.
			case actReplace:
				resolved[k] = v
			case actMerge:
				name, n, err := writeMerged(primary,
					version{dir: v.dir, rel: v.rel, size: v.pf.Size, sha: v.pf.SHA, snap: v.snap},
					version{dir: c.dir, rel: c.rel, size: c.pf.Size, sha: c.pf.SHA, snap: c.snap})
				if err != nil {
					return nil, 0, 0, err
				}
				sum, st, err := hashFile(primary, name)
				if err != nil {
					return nil, 0, 0, err
				}
				m := *c
				m.pf.Staged, m.pf.Size, m.pf.SHA = name, n, sum
				m.pf.ReceiptSize, m.pf.ReceiptSHA, m.pf.ReceiptGen = v.pf.Size, v.pf.SHA, v.pf.FromGen
				m.dir, m.rel, m.snap = primary, name, st
				resolved[k] = &m
				merged++
			case actUnion:
				name, err := writeUnion(primary, c.dir, c.rel, v.dir, v.rel)
				if err != nil {
					return nil, 0, 0, err
				}
				sum, st, err := hashFile(primary, name)
				if err != nil {
					return nil, 0, 0, err
				}
				m := *c
				m.pf.Staged, m.pf.Size, m.pf.SHA = name, st.Size, sum
				m.pf.ReceiptSize, m.pf.ReceiptSHA, m.pf.ReceiptGen = c.pf.Size, c.pf.SHA, c.pf.FromGen
				m.dir, m.rel, m.snap = primary, name, st
				resolved[k] = &m
				merged++
			default:
				conflicts++
				crel := genConflictName(en.Rel, g.entry.Gen)
				ck := fileKey{en.Base, crel}
				if rules.Allow != nil && rules.Allow(en.Base, crel) && !usedConflict[ck] {
					usedConflict[ck] = true
					cp := v.pf
					cp.Rel = crel
					cp.ConflictOK = rules.Allow(en.Base, conflictName(crel, style, at, 0))
					extra = append(extra, cp)
				}
			}
		}
	}
	var out []plannedFile
	for _, k := range dirOrder {
		if _, isFile := resolved[k]; !isFile {
			out = append(out, dirs[k])
		}
	}
	for _, k := range order {
		out = append(out, resolved[k].pf)
	}
	out = append(out, extra...)
	return out, merged, conflicts, nil
}

// writeUnion writes F's bytes followed by C's lines that F lacks.
func writeUnion(dst dirHandle, fdir dirHandle, frel string, cdir dirHandle, crel string) (string, error) {
	const max = 256 << 20
	fb, _, err := readAllBounded(fdir, frel, max)
	if err != nil {
		return "", err
	}
	cb, _, err := readAllBounded(cdir, crel, max)
	if err != nil {
		return "", err
	}
	out, name, err := dst.CreateTemp(".", ".union-*")
	if err != nil {
		return "", err
	}
	ok := false
	defer func() {
		if !ok {
			out.Close()
			_ = dst.Remove(name)
		}
	}()
	if _, err := out.Write(fb); err != nil {
		return "", err
	}
	if len(fb) > 0 && fb[len(fb)-1] != '\n' {
		if _, err := out.Write([]byte{'\n'}); err != nil {
			return "", err
		}
	}
	for _, l := range unionLines(cb, fb) {
		if _, err := out.Write(append(l, '\n')); err != nil {
			return "", err
		}
	}
	if err := fsx.FullSync(out); err != nil {
		return "", err
	}
	if err := out.Close(); err != nil {
		return "", err
	}
	ok = true
	return name, nil
}

// placeCtx carries one unit's placement.
type placeCtx struct {
	r          *run
	plan       *restorePlan
	rec        *journal.Record
	stagings   []dirHandle
	bases      map[capsule.BaseID]dirHandle
	quarantine dirHandle
	live       func() bool
	receipt    []ReceiptFile
	absent     []ReceiptFile // versions not placed (a conflict without a copy name), D85

	placed, noop, kept, merged, conflicts int
}

// mtimeOf is the mtime to restore, with the D14 clamp.
func (pc *placeCtx) mtimeOf(pf *plannedFile) time.Time {
	t := time.Unix(0, pf.MtimeNS)
	if !pc.plan.ClampTo.IsZero() && t.Before(pc.plan.ClampTo) {
		t = pc.plan.ClampTo
	}
	return t
}

// record adds a receipt line for a file now at rel with identity st.
func (pc *placeCtx) record(pf *plannedFile, rel string, st fsx.Stat) {
	size, sha, gen := pf.Size, pf.SHA, pf.FromGen
	if pf.ReceiptSHA != "" {
		size, sha, gen = pf.ReceiptSize, pf.ReceiptSHA, pf.ReceiptGen
	}
	pc.receipt = append(pc.receipt, ReceiptFile{Base: pf.Base, Rel: rel, Snap: st, SHA256: sha, Size: size, FromGen: gen})
}

// rerecord rebuilds the receipt line of a file placed before a crash: it
// is recorded only if the target still holds the planned bytes (or starts
// with them: kept supersets and merges), so the receipt never claims an
// origin it cannot prove.
func (pc *placeCtx) rerecord(i int) {
	pf := &pc.plan.Files[i]
	if pf.Dir {
		return
	}
	b := pc.bases[pf.Base]
	if b == nil {
		return
	}
	st, err := b.Lstat(pf.Rel)
	if err != nil || !st.IsRegular() {
		return
	}
	size, sha := pf.Size, pf.SHA
	if pf.ReceiptSHA != "" {
		size, sha = pf.ReceiptSize, pf.ReceiptSHA
	}
	if st.Size < size {
		return
	}
	got, err := hashPrefix(b, pf.Rel, size, &st)
	if err != nil || got != sha {
		return
	}
	cp := *pf
	cp.ReceiptSize, cp.ReceiptSHA = size, sha
	cp.ReceiptGen = pf.FromGen
	if pf.ReceiptSHA != "" {
		cp.ReceiptGen = pf.ReceiptGen
	}
	pc.record(&cp, pf.Rel, st)
}

// placeOne applies the placement table to plan.Files[i] (SPEC §11.3).
func (pc *placeCtx) placeOne(ctx context.Context, i int) error {
	r := pc.r
	pf := &pc.plan.Files[i]
	b := pc.bases[pf.Base]
	if b == nil || !cleanRel(pf.Rel) {
		return fmt.Errorf("%w: placement outside the unit's bases", fsx.ErrUnsafe)
	}
	if pf.Dir {
		d, err := b.OpenDir(pf.Rel, true)
		if err != nil {
			return err
		}
		return d.Close()
	}
	if pf.Stage < 0 || pf.Stage >= len(pc.stagings) {
		return fmt.Errorf("%w: unknown staging", fsx.ErrUnsafe)
	}
	sd := pc.stagings[pf.Stage]
	parentRel, name := path.Split(pf.Rel)
	pd := b
	if parentRel != "" {
		d, err := b.OpenDir(path.Clean(parentRel), true)
		if err != nil {
			return err
		}
		defer d.Close()
		pd = d
	}
	if pc.plan.Snapshot && pc.quarantine != nil {
		if err := pc.displaceSidecars(pd, parentRel, name); err != nil {
			return err
		}
	}
	if err := sd.Chmod(pf.Staged, restorePerm(pf.Mode)); err != nil {
		return err
	}
	if err := sd.Chtimes(pf.Staged, pc.mtimeOf(pf)); err != nil {
		return err
	}
	for attempt := 0; attempt < 4; attempt++ {
		st, err := pd.Lstat(name)
		if err != nil && isMissing(err) {
			err := sd.RenameTo(pf.Staged, pd, name, fsx.NoReplace)
			if errors.Is(err, fsx.ErrExist) {
				continue // appeared meanwhile: re-evaluate (REST-4)
			}
			if err != nil {
				return err
			}
			after, err := pd.Lstat(name)
			if err != nil {
				return err
			}
			pc.record(pf, pf.Rel, after)
			pc.placed++
			return nil
		}
		if err != nil {
			if isAccess(err) {
				return fmt.Errorf("%w: %s", ErrInaccessible, safeMsg(err))
			}
			return err
		}
		if !st.IsRegular() || st.Nlink > 1 {
			return pc.conflict(sd, pd, pf, parentRel)
		}
		fsha, fst, err := hashFile(pd, name)
		if errors.Is(err, fsx.ErrChanged) {
			continue
		}
		if err != nil {
			return err
		}
		facts, err := r.gatherFacts(ctx, pf.Policy,
			version{dir: sd, rel: pf.Staged, size: pf.Size, sha: pf.SHA},
			version{dir: pd, rel: name, size: fst.Size, sha: fsha, snap: fst})
		if errors.Is(err, fsx.ErrChanged) {
			continue
		}
		if err != nil {
			return err
		}
		switch decidePlacement(facts) {
		case actNoop:
			pc.record(pf, pf.Rel, fst)
			pc.noop++
			return nil
		case actKeep:
			pc.record(pf, pf.Rel, fst) // the receipt covers only C's prefix
			pc.kept++
			return nil
		case actReplace:
			if pc.live() {
				return errAbortLive
			}
			if now, err := pd.Lstat(name); err != nil || !now.Unchanged(fst) {
				continue
			}
			if err := sd.RenameTo(pf.Staged, pd, name, fsx.Replace); err != nil {
				return err
			}
			after, err := pd.Lstat(name)
			if err != nil {
				return err
			}
			pc.record(pf, pf.Rel, after)
			pc.placed++
			return nil
		case actMerge:
			if pc.live() {
				return errAbortLive
			}
			tmp, _, err := writeMerged(sd,
				version{dir: sd, rel: pf.Staged, size: pf.Size, sha: pf.SHA},
				version{dir: pd, rel: name, size: fst.Size, sha: fsha, snap: fst})
			if errors.Is(err, fsx.ErrChanged) {
				continue
			}
			if err != nil {
				return err
			}
			if now, err := pd.Lstat(name); err != nil || !now.Unchanged(fst) {
				_ = sd.Remove(tmp)
				continue
			}
			if err := sd.Chmod(tmp, restorePerm(pf.Mode)); err != nil {
				return err
			}
			if err := sd.RenameTo(tmp, pd, name, fsx.Replace); err != nil {
				_ = sd.Remove(tmp)
				return err
			}
			after, err := pd.Lstat(name)
			if err != nil {
				return err
			}
			// Merged: the receipt covers C, so the next seal keeps C+F as
			// a new generation (F was never sealed).
			cp := *pf
			cp.ReceiptSHA, cp.ReceiptSize, cp.ReceiptGen = pf.SHA, pf.Size, pf.FromGen
			if pf.ReceiptSHA != "" {
				cp.ReceiptSHA, cp.ReceiptSize, cp.ReceiptGen = pf.ReceiptSHA, pf.ReceiptSize, pf.ReceiptGen
			}
			pc.record(&cp, pf.Rel, after)
			pc.merged++
			return nil
		case actUnion:
			if pc.live() {
				return errAbortLive
			}
			if err := pc.appendMissingLines(sd, pf, pd, name, fst); err != nil {
				if errors.Is(err, fsx.ErrChanged) {
					continue
				}
				return err
			}
			pc.merged++
			return nil
		default:
			return pc.conflict(sd, pd, pf, parentRel)
		}
	}
	return errAbortLive // the target kept changing under us: someone writes it
}

// conflict writes the staged version under a conflict name next to the
// existing file, which is left untouched (I13). Without an allowed name
// the version stays only in its capsule; either way it is reported.
func (pc *placeCtx) conflict(sd, pd dirHandle, pf *plannedFile, parentRel string) error {
	pc.conflicts++
	if !pf.ConflictOK {
		// D85: the version stays only in its generation; the receipt
		// records it as absent, so the plaintext there re-seals as changed.
		if !pc.plan.Snapshot {
			pc.absent = append(pc.absent, ReceiptFile{Base: pf.Base, Rel: pf.Rel, SHA256: pf.SHA, Size: pf.Size, FromGen: pf.FromGen, Absent: true})
		}
		return nil
	}
	for k := 0; k < 100; k++ {
		crel := conflictName(pf.Rel, pf.Style, pc.plan.ConflictAt, k)
		cname := path.Base(crel)
		st, err := pd.Lstat(cname)
		if err != nil && isMissing(err) {
			err := sd.RenameTo(pf.Staged, pd, cname, fsx.NoReplace)
			if errors.Is(err, fsx.ErrExist) {
				continue
			}
			if err != nil {
				return err
			}
			after, err := pd.Lstat(cname)
			if err != nil {
				return err
			}
			pc.record(pf, path.Join(path.Clean("/" + parentRel)[1:], cname), after)
			return nil
		}
		if err != nil {
			return err
		}
		if st.IsRegular() && st.Size == pf.Size {
			if sum, _, err := hashFile(pd, cname); err == nil && sum == pf.SHA {
				return nil // this conflict copy already exists
			}
		}
	}
	return nil
}

// appendMissingLines adds the staged version's lines that the existing
// file lacks, with O_APPEND relative to its parent's directory handle
// (fsx.Dir.AppendLine, CC-05), never rewriting it (line-union).
func (pc *placeCtx) appendMissingLines(sd dirHandle, pf *plannedFile, pd dirHandle, name string, fst fsx.Stat) error {
	const max = 256 << 20
	cb, _, err := readAllBounded(sd, pf.Staged, max)
	if err != nil {
		return err
	}
	fb, st, err := readAllBounded(pd, name, max)
	if err != nil {
		return err
	}
	if !st.Unchanged(fst) {
		return fsx.ErrChanged
	}
	if len(fb) > 0 && fb[len(fb)-1] != '\n' {
		if err := pd.AppendLine(name, nil); err != nil {
			return err
		}
	}
	for _, l := range unionLines(cb, fb) {
		if len(l) > fsx.MaxLine {
			continue // never appendable in one write; the capsule keeps it
		}
		if err := pd.AppendLine(name, l); err != nil {
			return err
		}
	}
	return nil
}

// displaceSidecars moves existing -wal/-shm/-journal files next to a
// database being placed into quarantine, never deleting them, unless the
// snapshot itself places that sidecar (SPEC §7.2, CODX-2).
func (pc *placeCtx) displaceSidecars(pd dirHandle, parentRel, name string) error {
	if pc.r.p.codexClass == nil {
		return nil
	}
	rel := path.Join(path.Clean("/" + parentRel)[1:], name)
	if pc.r.p.codexClass(rel) != "sqlite-main" {
		return nil
	}
	planned := map[string]string{}
	for _, f := range pc.plan.Files {
		planned[f.Rel] = f.SHA
	}
	for _, suf := range []string{"-wal", "-shm", "-journal"} {
		side := name + suf
		st, err := pd.Lstat(side)
		if err != nil {
			if isMissing(err) {
				continue
			}
			return err
		}
		if want, ok := planned[path.Join(path.Clean("/" + parentRel)[1:], side)]; ok && st.IsRegular() {
			if got, _, err := hashFile(pd, side); err == nil && got == want {
				continue // the snapshot's own sidecar is already in place
			}
		}
		qrel := path.Join(pc.rec.ID, "codex", path.Clean("/" + parentRel)[1:])
		qd, err := pc.quarantine.OpenDir(qrel, true)
		if err != nil {
			return err
		}
		err = pd.RenameTo(side, qd, side, fsx.NoReplace)
		qd.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

// recoverRestore rolls a restore forward from staging (staged, placing) or
// back (nothing staged yet), keyless (SPEC §10.5, REST-1, REST-3).
func (r *run) recoverRestore(ctx context.Context, rec *journal.Record) *UnitResult {
	kind := capsule.Kind("")
	if !validKey(rec.Unit) {
		return recoveredResult(rec, kind, OutFailed, codeUnitKey+": journal record with an invalid unit key")
	}
	lk, err := r.lockUnit(rec.Unit)
	if err != nil {
		if errors.Is(err, fsx.ErrLocked) {
			return nil
		}
		return recoveredResult(rec, kind, OutFailed, failDetail(err))
	}
	defer lk.Unlock()
	if rec.Staging == "" {
		return r.doneRecovered(rec, kind, OutSkipped, "recovered: nothing staged")
	}
	st, err := r.p.fs.OpenStaging(rec.Staging)
	if err != nil {
		if isMissing(err) {
			return r.doneRecovered(rec, kind, OutSkipped, "recovered: nothing staged")
		}
		return recoveredResult(rec, kind, OutFailed, failDetail(err))
	}
	plan, perr := r.readPlan(st)
	if perr == nil {
		kind = plan.Kind
	}
	switch rec.Phase {
	case journal.PhaseStaged, journal.PhasePlacing:
		if perr != nil {
			return recoveredResult(rec, kind, OutFailed, codeFailed+": staged restore without a readable plan")
		}
	default:
		_ = r.removeStagings(st, plan)
		return r.doneRecovered(rec, kind, OutSkipped, "recovered: rolled back, nothing placed")
	}
	stagings := []dirHandle{st.Dir()}
	for _, s := range plan.Stagings {
		sh, err := r.p.fs.OpenStaging(s)
		if err != nil {
			return recoveredResult(rec, kind, OutFailed, failDetail(err))
		}
		stagings = append(stagings, sh.Dir())
	}
	out := r.placeAndFinish(ctx, st, plan, rec, stagings, adapterFor(r.e, harness.ID(plan.Harness)))
	res := out.result(UnitResult{Harness: plan.Harness, Kind: plan.Kind, Unit: plan.Unit, Gen: plan.Gen})
	if out.err == nil {
		res.Detail = "recovered: rolled forward from staging"
	}
	return &res
}
