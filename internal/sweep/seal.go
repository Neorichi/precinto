package sweep

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/precinto/precinto/internal/capsule"
	"github.com/precinto/precinto/internal/fsx"
	"github.com/precinto/precinto/internal/harness"
	"github.com/precinto/precinto/internal/ledger"
	"github.com/precinto/precinto/internal/live"
	"github.com/precinto/precinto/internal/platform"
	"github.com/precinto/precinto/internal/sweep/capslog"
	"github.com/precinto/precinto/internal/sweep/journal"
)

// bigUnit is the size above which a unit seals alone (R19); a variable
// only so tests can lower it.
var bigUnit int64 = 1 << 30

// maxKeptFDs bounds the descriptors kept open after unlinking for the
// rescue check (SPEC §10.3 step 7); append-only files are kept first.
const maxKeptFDs = 256

// Seal seals the given units now (seal command, wrapper exit, queue
// worker), honouring liveness and leases; it never needs a key.
func Seal(ctx context.Context, e Env, units []harness.Unit, o Options) (*Report, error) {
	r := newRun(e, prodPorts(e))
	return r.sealCommand(ctx, units, o)
}

// sealCommand is Seal: recovery first (SPEC §10.5), then the units.
func (r *run) sealCommand(ctx context.Context, units []harness.Unit, o Options) (*Report, error) {
	r.onQuiet = o.OnQuietWait
	if err := ctx.Err(); err != nil {
		return r.finish(), err
	}
	r.recoverAll(ctx)
	r.sealAll(ctx, units, o, true)
	return r.finish(), nil
}

// sealAll seals units with at most Env.Parallel (default 2) seals at once;
// a unit above 1 GiB runs alone (R19). Results keep the input order.
// Units live only by evidence the run's single quiet-window wait resolves
// are decided again after it (D63, sealJobs).
func (r *run) sealAll(ctx context.Context, units []harness.Unit, o Options, explicit bool) []UnitResult {
	return r.sealJobs(ctx, jobsOf(units, o), o.Deadline, explicit, false)
}

// sealPass is one decision pass over jobs (no report entries): at most
// Env.Parallel (default 2) seals at once, a unit above 1 GiB alone (R19).
// Only this goroutine takes tokens, so a big unit waits for the running
// seals to return theirs; every wait ends with ctx, and the jobs not
// started then are reported skipped.
func (r *run) sealPass(ctx context.Context, jobs []sealJob, explicit bool) []UnitResult {
	par := r.e.Parallel
	if par <= 0 {
		par = 2
	}
	tokens := make(chan struct{}, par)
	results := make([]UnitResult, len(jobs))
	var wg sync.WaitGroup
	for i, j := range jobs {
		if ctx.Err() != nil || (!j.o.Deadline.IsZero() && r.now().After(j.o.Deadline)) {
			res := resultOf(j.u)
			res.Outcome, res.Detail = OutSkipped, "deadline"
			results[i] = res
			continue
		}
		n := 1
		if unitBytes(j.u) > bigUnit {
			n = par
		}
		got := 0
	acquire:
		for got < n {
			select {
			case tokens <- struct{}{}:
				got++
			case <-ctx.Done():
				break acquire
			}
		}
		if got < n {
			for ; got > 0; got-- {
				<-tokens
			}
			res := resultOf(j.u)
			res.Outcome, res.Detail = OutSkipped, "deadline"
			results[i] = res
			continue
		}
		wg.Add(1)
		go func(i, n int, j sealJob) {
			defer wg.Done()
			defer func() {
				for k := 0; k < n; k++ {
					<-tokens
				}
			}()
			results[i] = r.sealOne(ctx, j.u, j.o, explicit)
		}(i, n, j)
	}
	wg.Wait()
	return results
}

func unitBytes(u harness.Unit) int64 {
	var n int64
	for _, f := range u.Files {
		n += f.Snap.Size
	}
	return n
}

// resultOf starts the result of a unit.
func resultOf(u harness.Unit) UnitResult {
	return UnitResult{Harness: string(u.Harness), Kind: u.Kind, Unit: u.Key, Files: len(u.Files), Bytes: unitBytes(u)}
}

// sealOne dispatches by kind.
func (r *run) sealOne(ctx context.Context, u harness.Unit, o Options, explicit bool) UnitResult {
	switch u.Kind {
	case capsule.KindCodexHome:
		return r.sealCodexHome(ctx, u, o, explicit, false)
	case capsule.KindCodexBlob, capsule.KindClaudeHistory:
		res := resultOf(u)
		res.Outcome, res.Detail = OutSkipped, "sealed by its own protocol"
		return res
	default:
		return r.sealLayered(ctx, u, o, explicit)
	}
}

// failed fills res for an error.
func failed(res UnitResult, err error) UnitResult {
	code, class := failureCode(err)
	res.Class = class
	res.Detail = code + ": " + safeMsg(err)
	switch code {
	case codeInaccessible:
		res.Outcome = OutInaccessible
	case codeLive, codeChanged:
		res.Outcome = OutLive
	default:
		res.Outcome = OutFailed
	}
	if class == fsx.ClassBusy {
		res.Outcome = OutSkipped
		res.Detail = "busy: " + safeMsg(err)
	}
	return res
}

// liveResult fills res for a unit that is (or became) live. Explicit seals
// report it as a failure (exit 4); sweeps only as an outcome.
func liveResult(res UnitResult, v live.Verdict, explicit bool, why string) UnitResult {
	res.Outcome = OutLive
	res.Evidence = v.Evidence
	var reasons []string
	for _, ev := range v.Evidence {
		if ev.Reason == live.ReasonLease {
			res.Outcome = OutLeased
		}
		reasons = append(reasons, string(ev.Reason))
	}
	if v.Warm && res.Outcome == OutLive {
		res.Outcome = OutWarm
	}
	if why == "" {
		why = strings.Join(dedupe(reasons), ",")
	}
	if why == "" {
		why = "evidence"
	}
	if explicit {
		res.Detail = codeLive + ": " + why
	} else {
		res.Detail = why
	}
	return res
}

// subjectOf is the liveness subject of a unit.
func subjectOf(u harness.Unit, rd *receiptDisk) live.Subject {
	s := live.Subject{Key: u.Key, Procs: u.Procs, LeaseKeys: dedupe(append([]string{u.Key}, u.LeaseKeys...))}
	s.Paths = append(s.Paths, u.Paths...)
	if len(s.Paths) == 0 {
		for _, f := range u.Files {
			if b := u.Home.Bases[f.Base]; b != "" {
				s.Paths = append(s.Paths, filepath.Join(b, filepath.FromSlash(f.Rel)))
			}
		}
	}
	if rd != nil {
		s.RestoredAt = rd.RestoredAt
	}
	return s
}

// checkLive evaluates a unit's liveness: adapter evidence plus the
// engine's ledger, lease and stability evidence. Any error is "live".
func (r *run) checkLive(ctx context.Context, ad harness.Adapter, u harness.Unit, rd *receiptDisk) (live.Verdict, bool) {
	return r.checkLiveAfter(ctx, ad, u, rd, false)
}

// checkLiveAfter is checkLive; writerExited marks a unit whose only known
// writer was reaped (--wait-pid, wrapper exit): with no other evidence the
// engine skips the stability window (R20, D63).
func (r *run) checkLiveAfter(ctx context.Context, ad harness.Adapter, u harness.Unit, rd *receiptDisk, writerExited bool) (live.Verdict, bool) {
	var extra []live.Evidence
	if ad != nil {
		ev, err := ad.Probe(ctx, r.e.Harness, u)
		if err != nil {
			return live.Verdict{Live: true, Evidence: []live.Evidence{{Reason: live.ReasonUnknown, Detail: "probe failed"}}}, true
		}
		extra = ev
	}
	s := subjectOf(u, rd)
	s.WriterExited = writerExited
	v, err := r.p.live.Decide(ctx, s, extra)
	if err != nil {
		return live.Verdict{Live: true, Evidence: []live.Evidence{{Reason: live.ReasonUnknown, Detail: "liveness failed"}}}, true
	}
	return v, v.Live
}

// waitExit waits until id has exited (zombies count as exited), polling the
// process table with back-off (R8). Without a process table the writer
// cannot be proven gone.
func (r *run) waitExit(ctx context.Context, id platform.ProcID, deadline time.Time) error {
	if r.e.Procs == nil {
		return fmt.Errorf("%w: no process table to wait for the writer", ErrLive)
	}
	wait := 100 * time.Millisecond
	for r.e.Procs.Alive(id) {
		if !deadline.IsZero() && r.now().After(deadline) {
			return fmt.Errorf("%w: writer still running at the deadline", ErrLive)
		}
		if err := r.p.sleep(ctx, wait); err != nil {
			return err
		}
		wait = min(2*wait, 2*time.Second)
	}
	return nil
}

// openBases opens every base a unit uses.
func (r *run) openBases(u harness.Unit) (map[capsule.BaseID]dirHandle, error) {
	need := map[capsule.BaseID]bool{}
	for _, f := range u.Files {
		need[f.Base] = true
	}
	for _, f := range u.Dirs {
		need[f.Base] = true
	}
	out := map[capsule.BaseID]dirHandle{}
	for b := range need {
		p := u.Home.Bases[b]
		if p == "" || !filepath.IsAbs(p) {
			closeAll(out)
			return nil, fmt.Errorf("%w: base %s of the unit is not resolved", harness.ErrUnregistered, b)
		}
		d, err := r.p.fs.OpenBase(p)
		if err != nil {
			closeAll(out)
			return nil, err
		}
		out[b] = d
	}
	return out, nil
}

func closeAll(m map[capsule.BaseID]dirHandle) {
	for _, d := range m {
		d.Close()
	}
}

// refresh re-lstats the planned files under the unit lock. A file whose
// identity moved since the scan, or that vanished, makes the unit live
// (retry later); a hazard is reported and never sealed or deleted.
func (r *run) refresh(bases map[capsule.BaseID]dirHandle, files []harness.File) ([]harness.File, []harness.Hazard, error) {
	uid := uint32(os.Getuid())
	var out []harness.File
	var hz []harness.Hazard
	for _, f := range files {
		d := bases[f.Base]
		st, err := d.Lstat(f.Rel)
		switch {
		case err != nil && isMissing(err):
			return nil, nil, fmt.Errorf("%w: a file of the unit vanished", fsx.ErrChanged)
		case err != nil && isAccess(err):
			return nil, nil, fmt.Errorf("%w: %s", ErrInaccessible, safeMsg(err))
		case err != nil:
			return nil, nil, err
		}
		switch {
		case !st.IsRegular():
			hz = append(hz, harness.Hazard{Base: f.Base, Rel: f.Rel, Hazard: hazardOf(st)})
			continue
		case st.Nlink > 1:
			hz = append(hz, harness.Hazard{Base: f.Base, Rel: f.Rel, Hazard: fsx.HazardHardlink})
			continue
		case st.UID != uid:
			hz = append(hz, harness.Hazard{Base: f.Base, Rel: f.Rel, Hazard: fsx.HazardForeign})
			continue
		}
		if f.Snap.Ino != 0 && !st.Unchanged(f.Snap) {
			return nil, nil, fmt.Errorf("%w: a file changed since the scan", fsx.ErrChanged)
		}
		f.Snap = st
		out = append(out, f)
	}
	return out, hz, nil
}

func hazardOf(st fsx.Stat) fsx.Hazard {
	const typeMask, typeLink = 0o170000, 0o120000
	if st.Mode&typeMask == typeLink {
		return fsx.HazardSymlink
	}
	return fsx.HazardSpecial
}

// sessionLedgerSID is the ledger session of a unit (claude sessions).
func sessionLedgerSID(u harness.Unit) string {
	if u.Kind == capsule.KindClaudeSession {
		return u.UnitID
	}
	return ""
}

// rootPathOf returns the configured path of the unit's primary root.
func (r *run) rootPathOf(u harness.Unit) string {
	if len(u.RootIDs) == 0 {
		return ""
	}
	if root, ok := r.e.Cfg.RootByID(u.RootIDs[0]); ok {
		return root.Path
	}
	return ""
}

// sealLayered seals a layered unit (Claude kinds, notes, generic, global
// stores): SPEC §10.3.
func (r *run) sealLayered(ctx context.Context, u harness.Unit, o Options, explicit bool) UnitResult {
	res, _ := r.sealLayeredIf(ctx, u, o, explicit, false)
	return res
}

// sealLayeredIf is sealLayered; with unchangedOnly it acts only when every
// file equals its receipt (the plaintext is dropped without a new
// generation) and otherwise returns acted=false having written nothing:
// a note restored at a moved marker's location is dropped under the unit
// it was restored from, never sealed into it (D83).
func (r *run) sealLayeredIf(ctx context.Context, u harness.Unit, o Options, explicit, unchangedOnly bool) (res UnitResult, acted bool) {
	res = r.sealLayeredUnit(ctx, u, o, explicit, unchangedOnly)
	if res.Detail == detailNotUnchanged {
		return res, false
	}
	return res, true
}

// detailNotUnchanged is the internal result of sealLayeredUnit with
// unchangedOnly when the files differ from their receipt.
const detailNotUnchanged = "not unchanged"

func (r *run) sealLayeredUnit(ctx context.Context, u harness.Unit, o Options, explicit, unchangedOnly bool) UnitResult {
	res := resultOf(u)
	if !validKey(u.Key) {
		return failed(res, fmt.Errorf("%w: invalid unit key", harness.ErrUnitKey))
	}
	ad := adapterFor(r.e, u.Harness)
	lk, err := r.lockUnit(u.Key)
	if err != nil {
		return failed(res, err)
	}
	defer lk.Unlock()

	exited := false
	if o.WaitFor != nil {
		if err := r.waitExit(ctx, *o.WaitFor, o.Deadline); err != nil {
			return liveResult(res, live.Verdict{Live: true}, explicit, "writer running")
		}
		exited = true // R20: the only known writer was reaped
	}
	rd, hasRc, err := r.loadReceipt(u.Key)
	if err != nil {
		return failed(res, err)
	}
	var rcp *receiptDisk
	if hasRc {
		rcp = &rd
	}
	if v, isLive := r.checkLiveAfter(ctx, ad, u, rcp, exited); isLive {
		return liveResult(res, v, explicit, "")
	}
	recips, err := r.p.vaults.recipients(u.VaultID)
	if err != nil {
		return failed(res, err)
	}
	bases, err := r.openBases(u)
	if err != nil {
		return failed(res, err)
	}
	defer closeAll(bases)
	files, hz, err := r.refresh(bases, u.Files)
	if err != nil {
		if errors.Is(err, fsx.ErrChanged) {
			return liveResult(res, live.Verdict{Live: true}, explicit, "changed")
		}
		return failed(res, err)
	}
	res.Hazards = append(append([]harness.Hazard(nil), u.Hazards...), hz...)
	res.Files = len(files)
	var total int64
	for _, f := range files {
		total += f.Snap.Size
	}
	res.Bytes = total
	if len(files) == 0 {
		res.Outcome, res.Detail = OutSkipped, "nothing sealable"
		return res
	}
	if err := r.p.fs.CheckSpace(r.l.CapsulesDir, total, r.e.Floor); err != nil {
		return failed(res, noSpace(err))
	}
	logged, err := r.log.Unit(u.Key)
	if err != nil {
		return failed(res, err)
	}
	lp, err := planLineage(files, rcp, logged, dirHasher{bases: bases})
	if err != nil {
		if errors.Is(err, fsx.ErrChanged) || isMissing(err) {
			return liveResult(res, live.Verdict{Live: true}, explicit, "changed")
		}
		return failed(res, err)
	}
	if unchangedOnly && !lp.Unchanged {
		res.Outcome, res.Detail = OutSkipped, detailNotUnchanged
		return res
	}
	res.Lineage = lp.Lineage
	if o.DryRun {
		res.Outcome, res.Detail = OutSealed, "dry-run"
		if lp.Unchanged {
			res.Outcome = OutUnchanged
		}
		return res
	}
	r.rememberNotes(ctx, ad, u)
	if err := r.indexProject(u); err != nil {
		return failed(res, err)
	}
	capsRoot, caps, err := r.openCapsDir(storeOf(u.Harness, u.Kind), u.Key, true)
	if err != nil {
		return failed(res, err)
	}
	defer capsRoot.Close()
	defer caps.Close()
	us := &unitSeal{r: r, u: u, ad: ad, bases: bases, files: files, rd: rcp, caps: caps, recips: recips, res: res, explicit: explicit}
	if lp.Unchanged {
		return us.dropUnchanged(ctx)
	}
	return us.sealNew(ctx, lp)
}

// indexProject records the projects/<P> directories of a Claude session
// in the project index before its plaintext goes (DC-30, SPEC §11.2): once
// the session's ledger moved into its capsule (S13) the index still ties
// the project to the session's roots, so a restored session is found and
// sealed again at the next lock, and a deleted projects/<P> is recreated
// at restore. An index that already records the roots and the start cwd
// is not rewritten.
func (r *run) indexProject(u harness.Unit) error {
	if u.Kind != capsule.KindClaudeSession || r.e.Harness.Index == nil || len(u.RootIDs) == 0 {
		return nil
	}
	cfg := u.Home.Bases[capsule.BaseClaudeConfig]
	if cfg == "" || !filepath.IsAbs(cfg) {
		return nil
	}
	x := r.e.Harness.Index(string(u.Harness))
	if x == nil {
		return nil
	}
	var cwds []string
	if filepath.IsAbs(u.ProjectDir) {
		cwds = []string{u.ProjectDir}
	}
	for _, p := range projectDirsOf(u) {
		if have, ok, err := x.Lookup(cfg, p); err == nil && ok && subset(u.RootIDs, have.RootIDs) && subset(cwds, have.Cwds) {
			continue
		}
		if err := x.Put(ledger.Project{Harness: string(u.Harness), ConfigDir: cfg, Slug: p, Cwds: cwds,
			RootIDs: append([]string(nil), u.RootIDs...)}); err != nil {
			return err
		}
	}
	return nil
}

// projectDirsOf lists the projects/<P> directory names a session's files
// live in, as found on disk (precinto never computes Claude slugs).
func projectDirsOf(u harness.Unit) []string {
	var out []string
	for _, f := range u.Files {
		if f.Base != capsule.BaseClaudeConfig {
			continue
		}
		rest, ok := strings.CutPrefix(f.Rel, "projects/")
		if !ok {
			continue
		}
		if p, _, ok := strings.Cut(rest, "/"); ok && p != "" {
			out = append(out, p)
		}
	}
	return dedupe(out)
}

// subset reports whether every value of a is in b.
func subset(a, b []string) bool {
	for _, v := range a {
		if !contains(b, v) {
			return false
		}
	}
	return true
}

// noSpace normalizes a free-space failure to ErrNoSpace (SPEC §17).
func noSpace(err error) error {
	if errors.Is(err, ErrNoSpace) {
		return err
	}
	if errors.Is(err, fsx.ErrNoSpace) || classOf(err) == fsx.ClassNoSpace {
		return fmt.Errorf("%w: %s", ErrNoSpace, safeMsg(err))
	}
	return err
}

// unitSeal is the state of one unit seal after planning.
type unitSeal struct {
	r      *run
	u      harness.Unit
	ad     harness.Adapter
	bases  map[capsule.BaseID]dirHandle
	files  []harness.File
	rd     *receiptDisk
	caps   dirHandle
	recips recipientSet
	res    UnitResult
	// explicit: an explicit seal reports a unit that turns out live as a
	// failure (exit 4); a sweep only as an outcome.
	explicit bool
}

// journalKind is the journal record kind of the unit's seal.
func (us *unitSeal) journalKind() journal.Kind {
	if us.u.Kind == capsule.KindMarkdown {
		return journal.KindMarkdown
	}
	return journal.KindSeal
}

// beforeUnlink is the step between the commit and the deletion of the
// originals: a note's marker is written first (SPEC §8.4); if it cannot
// be, the note stays in plaintext (its receipt lets the next sweep retry
// without a new generation).
func (us *unitSeal) beforeUnlink() error {
	if us.u.Kind != capsule.KindMarkdown || len(us.files) != 1 {
		return nil
	}
	root := us.bases[capsule.BaseRoot]
	if root == nil {
		return fmt.Errorf("%w: note without its folder", fsx.ErrUnsafe)
	}
	return us.r.ensureMarker(root, us.files[0].Rel, us.u.Key)
}

func (us *unitSeal) journalFiles() []journal.File {
	out := make([]journal.File, 0, len(us.files))
	for _, f := range us.files {
		out = append(out, journal.File{Base: string(f.Base), Dir: us.u.Home.Bases[f.Base], Rel: f.Rel, Snap: f.Snap})
	}
	return out
}

// sealNew writes a new generation, then deletes the originals.
func (us *unitSeal) sealNew(ctx context.Context, lp lineagePlan) UnitResult {
	r, u, res := us.r, us.u, us.res
	n, err := r.nextGen(ctx, u.Key, us.caps)
	if err != nil {
		return failed(res, err)
	}
	sid := sessionLedgerSID(u)
	var ledRaw []byte
	var ledN int64
	if sid != "" {
		ledRaw, ledN, err = r.p.ledger.Snapshot(string(u.Harness), sid)
		if err != nil {
			return failed(res, err)
		}
	}
	rec, err := r.jr.Begin(us.journalKind(), string(u.Harness), u.Key)
	if err != nil {
		return failed(res, err)
	}
	rec.Files = us.journalFiles()
	if sid != "" && ledN > 0 {
		rec.LedgerSID, rec.LedgerN = sid, ledN // S13: archived by recovery after a commit
	}
	title, last := u.Title, u.LastActivity
	if us.ad != nil && (title == "" || last.IsZero()) {
		if t, l, err := us.ad.Describe(ctx, r.e.Harness, u); err == nil {
			if title == "" {
				title = t
			}
			if last.IsZero() {
				last = l
			}
		}
	}
	if last.IsZero() {
		for _, f := range us.files {
			if t := time.Unix(0, f.Snap.MtimeNS).UTC(); t.After(last) {
				last = t
			}
		}
	}
	man := capsule.Manifest{
		Format: capsule.FormatVersion, Kind: u.Kind, Harness: string(u.Harness),
		UnitKey: u.Key, UnitID: u.UnitID, VaultID: u.VaultID, RootIDs: append([]string(nil), u.RootIDs...),
		RootPath: r.rootPathOf(u), ProjectDir: u.ProjectDir,
		Gen: n, Parent: lp.Parent, Lineage: lp.Lineage, CreatedAt: r.now(), Sealer: r.e.Sealer,
		RecipientsFpr: us.recips.fpr, Title: title, LastActivity: last, Ledger: ledRaw,
	}
	var inputs []sealInput
	for _, f := range us.files {
		inputs = append(inputs, sealInput{
			Base: f.Base, Dir: us.bases[f.Base], Rel: f.Rel,
			Path: filepath.Join(u.Home.Bases[f.Base], filepath.FromSlash(f.Rel)),
			Snap: f.Snap, Append: f.Append, Group: f.Group,
		})
	}
	var dirs []capsule.Entry
	for _, d := range u.Dirs {
		dirs = append(dirs, capsule.Entry{Base: d.Base, Rel: d.Rel, Dir: true, Mode: d.Snap.Mode & 0o7777, MtimeNS: d.Snap.MtimeNS})
	}
	store := storeOf(u.Harness, u.Kind)
	name := capsule.GenName(n)
	spec := &commitSpec{
		rec: rec, unitDir: us.caps, outDir: us.caps, capsuleRel: name, name: name,
		logPath: logPathOf(store, u.Key, name), gen: n,
		req:    sealRequest{Manifest: man, Inputs: inputs, Dirs: dirs, Recipients: us.recips},
		entry:  us.entry(n, lp.Parent, lp.Lineage, last),
		points: unitSealPoints,
	}
	sealed, err := r.commit(ctx, spec)
	if err != nil {
		if !keepRecord(err) {
			_ = r.jr.Done(rec)
		}
		if errors.Is(err, capsule.ErrChanged) || errors.Is(err, fsx.ErrChanged) {
			return liveResult(res, live.Verdict{Live: true}, us.explicit, "changed while sealing")
		}
		return failed(res, err)
	}
	res.Gen, res.Lineage = n, lp.Lineage
	shas := map[fileKey]string{}
	for _, en := range sealed.Manifest.Files {
		shas[fileKey{en.Base, en.Rel}] = en.SHA256
	}
	return us.finishUnlink(ctx, rec, n, shas, OutSealed, ledN)
}

// dropUnchanged deletes plaintext equal to its receipt without a new
// generation (D10): prepared and committed both name the receipt's
// generation, which is already logged (SPEC §10.3 step 3).
func (us *unitSeal) dropUnchanged(ctx context.Context) UnitResult {
	r, u, res := us.r, us.u, us.res
	rec, err := r.jr.Begin(us.journalKind(), string(u.Harness), u.Key)
	if err != nil {
		return failed(res, err)
	}
	rec.Gen = us.rd.Gen
	rec.Capsule = capsule.GenName(us.rd.Gen)
	rec.Files = us.journalFiles()
	if err := r.jr.Save(rec); err != nil {
		_ = r.jr.Done(rec)
		return failed(res, err)
	}
	if err := r.hit(unitSealPoints.prepared); err != nil {
		return failed(res, err)
	}
	if err := r.jr.Advance(rec, journal.PhaseCommitted); err != nil {
		_ = r.jr.Done(rec)
		return failed(res, err)
	}
	if err := r.hit(unitSealPoints.committed); err != nil {
		return failed(res, err)
	}
	res.Gen, res.Lineage = us.rd.Gen, capsule.LineageSuccessor
	shas := map[fileKey]string{}
	for _, rf := range us.rd.Files {
		shas[fileKey{rf.Base, rf.Rel}] = rf.SHA256
	}
	return us.finishUnlink(ctx, rec, us.rd.Gen, shas, OutUnchanged, 0)
}

// entry is the capsule-log entry of a generation of this unit.
func (us *unitSeal) entry(gen, parent uint64, l capsule.Lineage, last time.Time) capslog.Entry {
	u := us.u
	var bytes int64
	for _, f := range us.files {
		bytes += f.Snap.Size
	}
	return capslog.Entry{
		V: capslog.Version, Kind: string(u.Kind), Harness: storeOf(u.Harness, u.Kind), Unit: u.Key,
		VaultID: u.VaultID, RootIDs: append([]string(nil), u.RootIDs...), Gen: gen, Parent: parent,
		Lineage: string(l), SealedAt: us.r.now(), RecipientsFpr: us.recips.fpr,
		Files: len(us.files), Bytes: bytes, LastActivity: last,
	}
}

// finishUnlink runs SPEC §10.3 steps 6–8 after a commit.
func (us *unitSeal) finishUnlink(ctx context.Context, rec *journal.Record, gen uint64, shas map[fileKey]string, ok Outcome, ledN int64) UnitResult {
	r, u, res := us.r, us.u, us.res
	// D82: the plaintext goes only while the generation that holds it is
	// still in the store (defence in depth: quarantine moves a capsule
	// only under the unit lock this seal holds).
	if st, err := us.caps.Lstat(capsule.GenName(gen)); err != nil || !st.IsRegular() {
		if err == nil {
			err = fsx.ErrUnsafe
		}
		_ = r.jr.Done(rec)
		res = failed(res, err)
		res.Detail = "capsule missing after commit: plaintext kept (" + safeMsg(err) + ")"
		return res
	}
	var ur unlinkResult
	ignored := 0
	if err := us.beforeUnlink(); err != nil {
		ur.stayed = len(rec.Files)
		res.Detail = "marker: " + safeMsg(err)
	} else {
		ur = r.unlinkFiles(ctx, u, us.bases, rec, true, unitSealPoints)
		ignored = r.pruneDirs(u, us.bases, rec)
	}
	newest := gen
	if g, sealedShas, err := r.rescue(ctx, u, rec, ur.kept, gen, us.files, us.recips, us.caps, us.bases); err != nil {
		res.Detail = "rescue: " + safeMsg(err)
		if keepRecord(err) {
			return failed(res, err)
		}
	} else if g != 0 {
		newest = g
		for k, v := range sealedShas {
			shas[k] = v
		}
	}
	if err := r.rewriteReceipt(u.Key, u.Kind, string(u.Harness), us.bases, rec, shas, newest, us.rd, u.Home.Bases); err != nil {
		return failed(res, err)
	}
	if err := r.hit("seal.receipt"); err != nil {
		return failed(res, err)
	}
	if sid := sessionLedgerSID(u); sid != "" && ledN > 0 && ur.removedAll {
		if err := r.p.ledger.Archive(string(u.Harness), sid, ledN); err != nil {
			res.Detail = "ledger archive: " + safeMsg(err)
		}
	}
	if ur.removeFailed > 0 {
		rec.Notes = append(rec.Notes, "remove-failed="+strconv.Itoa(ur.removeFailed))
		_ = r.jr.Save(rec)
	}
	if err := r.jr.Done(rec); err != nil {
		return failed(res, err)
	}
	res.Gen = newest
	res.Outcome = ok
	switch {
	case ur.removeFailed > 0:
		res.Outcome = OutRemoveFailed
		res.Class = fsx.ClassAccess
		res.Detail = fmt.Sprintf("%d file(s) could not be removed", ur.removeFailed)
	case ur.stayed > 0:
		res.Detail = fmt.Sprintf("%d file(s) changed after hashing stay for the next generation", ur.stayed)
	}
	return prunedDetail(res, ignored)
}

// keptFD is the open descriptor of an unlinked file, kept for the rescue
// check.
type keptFD struct {
	f    *os.File
	file harness.File
}

// unlinkResult summarizes step 6.
type unlinkResult struct {
	kept         []keptFD
	removeFailed int  // EACCES/EPERM on unlink: plaintext kept (SPEC §17)
	stayed       int  // changed since hashing, live again, or a hazard
	removedAll   bool // every journaled file is gone
}

// unlinkFiles deletes the journaled originals (SPEC §10.3 step 6): each
// one only if liveness still holds still (StillQuiet) and its lstat still
// equals the snapshot with nlink 1 (UnlinkIfUnchanged), keeping its
// descriptor open for the rescue check. Progress is journaled per file.
func (r *run) unlinkFiles(ctx context.Context, u harness.Unit, bases map[capsule.BaseID]dirHandle, rec *journal.Record, keep bool, pts sealPoints) unlinkResult {
	var ur unlinkResult
	subj := subjectOf(u, nil)
	order := make([]int, 0, len(rec.Files))
	for i := range rec.Files {
		order = append(order, i)
	}
	// Keep descriptors of append-only files first.
	appendOnly := map[fileKey]bool{}
	for _, f := range u.Files {
		appendOnly[fileKey{f.Base, f.Rel}] = f.Append
	}
	sort.SliceStable(order, func(a, b int) bool {
		fa, fb := rec.Files[order[a]], rec.Files[order[b]]
		ida := capsule.BaseID(fa.Base)
		idb := capsule.BaseID(fb.Base)
		return appendOnly[fileKey{ida, fa.Rel}] && !appendOnly[fileKey{idb, fb.Rel}]
	})
	journalOK := true
	for _, i := range order {
		jf := &rec.Files[i]
		if jf.Done {
			continue
		}
		if !journalOK || ctx.Err() != nil {
			ur.stayed++
			continue
		}
		id, abs := capsule.BaseID(jf.Base), jf.Dir
		if id == baseBlob {
			continue // codex snapshot bookkeeping, not plaintext
		}
		d := bases[id]
		if d == nil {
			ur.stayed++
			continue
		}
		quiet, err := r.p.live.StillQuiet(ctx, subj, map[string]fsx.Stat{filepath.Join(abs, filepath.FromSlash(jf.Rel)): jf.Snap})
		if err != nil || !quiet {
			ur.stayed++
			continue
		}
		fh, st, err := d.Open(jf.Rel)
		switch {
		case err != nil && isMissing(err):
			// Already gone (a previous attempt unlinked it).
		case err != nil && isAccess(err):
			ur.removeFailed++
			continue
		case err != nil:
			ur.stayed++
			continue
		case !st.Unchanged(jf.Snap):
			fh.Close()
			ur.stayed++
			continue
		}
		if fh != nil {
			uerr := d.UnlinkIfUnchanged(jf.Rel, jf.Snap)
			switch {
			case uerr == nil, isMissing(uerr):
			case isAccess(uerr):
				fh.Close()
				ur.removeFailed++
				continue
			default: // ErrChanged, ErrHardlink, I/O: the file stays
				fh.Close()
				ur.stayed++
				continue
			}
			if keep && len(ur.kept) < maxKeptFDs {
				ur.kept = append(ur.kept, keptFD{f: fh, file: harness.File{Base: id, Rel: jf.Rel, Snap: jf.Snap, Append: appendOnly[fileKey{id, jf.Rel}]}})
			} else {
				fh.Close()
			}
		}
		jf.Done = true
		if rec.Phase != journal.PhaseUnlinking {
			err = r.jr.Advance(rec, journal.PhaseUnlinking)
		} else {
			err = r.jr.Save(rec)
		}
		if err != nil {
			journalOK = false // stop deleting: the journal must stay truthful
			continue
		}
		_ = r.hit("seal.unlinking")
	}
	ur.removedAll = true
	for _, jf := range rec.Files {
		if id := capsule.BaseID(jf.Base); !jf.Done && id != baseBlob {
			ur.removedAll = false
		}
	}
	return ur
}

// pruneDirs removes directories emptied by the seal: only directories the
// adapter listed in Unit.Prune ("<base id>:<rel>" entries, CC-19) that held
// files of this unit, deepest first, never non-empty ones, never a base
// root and never above the listed directory. It returns the number of
// entries it ignored: a bare rel, an unknown base, or a rel that is not
// clean (an adapter bug, reported by the caller).
func (r *run) pruneDirs(u harness.Unit, bases map[capsule.BaseID]dirHandle, rec *journal.Record) int {
	if len(u.Prune) == 0 {
		return 0
	}
	type entry struct {
		base capsule.BaseID
		rel  string
	}
	var entries []entry
	ignored := 0
	for _, p := range u.Prune {
		b, rel, ok := strings.Cut(p, ":")
		if !ok || b == "" || u.Home.Bases[capsule.BaseID(b)] == "" || !cleanRel(rel) {
			ignored++
			continue
		}
		entries = append(entries, entry{base: capsule.BaseID(b), rel: rel})
	}
	for id, d := range bases {
		var rels []string
		for _, e := range entries {
			if e.base != id {
				continue
			}
			prel := e.rel
			for _, jf := range rec.Files {
				fid := capsule.BaseID(jf.Base)
				if fid != id || !jf.Done || !strings.HasPrefix(jf.Rel, prel+"/") {
					continue
				}
				rels = append(rels, path.Dir(jf.Rel))
			}
			for _, dd := range u.Dirs {
				if dd.Base == id && (dd.Rel == prel || strings.HasPrefix(dd.Rel, prel+"/")) {
					rels = append(rels, dd.Rel)
				}
			}
			stop := path.Dir(prel)
			if stop == "." {
				stop = ""
			}
			rels = dedupe(rels)
			sortByDepthDesc(rels)
			for _, rel := range rels {
				_ = d.RemoveEmptyDirs(rel, stop)
			}
			rels = rels[:0]
		}
	}
	return ignored
}

// prunedDetail reports prune entries an adapter listed in a form sweep
// ignores (bare rels, unknown bases), without overwriting another detail.
func prunedDetail(res UnitResult, ignored int) UnitResult {
	if ignored > 0 && res.Detail == "" {
		res.Detail = fmt.Sprintf("%d prune entr%s without a known base ignored", ignored, map[bool]string{true: "y", false: "ies"}[ignored == 1])
	}
	return res
}

// rescue implements SPEC §10.3 step 7: after the grace, each kept
// descriptor is fstat'ed; files that grew are sealed through their
// descriptors as a rescue generation (journaled before it is written). It
// returns the rescue generation (0 if none) and the hashes it sealed.
func (r *run) rescue(ctx context.Context, u harness.Unit, rec *journal.Record, kept []keptFD, parent uint64, parentFiles []harness.File, recips recipientSet, caps dirHandle, bases map[capsule.BaseID]dirHandle) (uint64, map[fileKey]string, error) {
	defer func() {
		for _, k := range kept {
			k.f.Close()
		}
	}()
	if len(kept) == 0 {
		return 0, nil, nil
	}
	if err := r.p.sleep(ctx, r.p.rescueWait); err != nil {
		return 0, nil, nil
	}
	var grown []keptFD
	var cur []fsx.Stat
	for _, k := range kept {
		st, err := fsx.Fstat(k.f)
		if err == nil && st.Size > k.file.Snap.Size {
			grown = append(grown, k)
			cur = append(cur, st)
		}
	}
	if len(grown) == 0 {
		return 0, nil, nil
	}
	g, err := r.nextGen(ctx, u.Key, caps)
	if err != nil {
		return 0, nil, err
	}
	l := capsule.LineagePartial
	if len(grown) == len(parentFiles) {
		l = capsule.LineageSuccessor
	}
	var inputs []sealInput
	var bytes int64
	for i, k := range grown {
		inputs = append(inputs, sealInput{
			Base: k.file.Base, Dir: bases[k.file.Base], Rel: k.file.Rel, Snap: cur[i], Open: k.f, Append: k.file.Append,
			Path: filepath.Join(u.Home.Bases[k.file.Base], filepath.FromSlash(k.file.Rel)),
		})
		bytes += cur[i].Size
	}
	name := capsule.GenName(g)
	man := capsule.Manifest{
		Format: capsule.FormatVersion, Kind: u.Kind, Harness: string(u.Harness), UnitKey: u.Key, UnitID: u.UnitID,
		VaultID: u.VaultID, RootIDs: append([]string(nil), u.RootIDs...), RootPath: r.rootPathOf(u),
		ProjectDir: u.ProjectDir, Gen: g, Parent: parent, Lineage: l, CreatedAt: r.now(), Sealer: r.e.Sealer,
		RecipientsFpr: recips.fpr, Title: u.Title, LastActivity: r.now(),
	}
	spec := &commitSpec{
		rec: rec, unitDir: caps, outDir: caps, capsuleRel: name, name: name,
		logPath: logPathOf(storeOf(u.Harness, u.Kind), u.Key, name), gen: g,
		req: sealRequest{Manifest: man, Inputs: inputs, Recipients: recips},
		entry: capslog.Entry{
			V: capslog.Version, Kind: string(u.Kind), Harness: storeOf(u.Harness, u.Kind), Unit: u.Key,
			VaultID: u.VaultID, RootIDs: append([]string(nil), u.RootIDs...), Gen: g, Parent: parent,
			Lineage: string(l), SealedAt: r.now(), RecipientsFpr: recips.fpr, Files: len(grown), Bytes: bytes,
			LastActivity: r.now(),
		},
		preparePhase: journal.PhaseRescue,
		points:       sealPoints{prepared: "seal.rescue"},
	}
	sealed, err := r.commit(ctx, spec)
	if err != nil {
		if !keepRecord(err) {
			// The attempt left nothing; the main generation stands.
			rec.Tmp, rec.Capsule, rec.Gen = "", capsule.GenName(parent), parent
			_ = r.jr.Advance(rec, journal.PhaseUnlinking)
		}
		return 0, nil, err
	}
	shas := map[fileKey]string{}
	for _, en := range sealed.Manifest.Files {
		shas[fileKey{en.Base, en.Rel}] = en.SHA256
	}
	return g, shas, nil
}

// rewriteReceipt implements SPEC §10.3 step 8 (D58c): the receipt lists
// every journaled file still present as plaintext, at generation gen with
// identity and SHA-256 as sealed, and is deleted when none remains. A
// file whose sealed hash is unknown (recovery) is hashed now if its
// identity still equals the snapshot, and left out otherwise (it re-seals
// as new; its older bytes stay in their generation).
func (r *run) rewriteReceipt(unit string, kind capsule.Kind, h string, bases map[capsule.BaseID]dirHandle, rec *journal.Record, shas map[fileKey]string, gen uint64, old *receiptDisk, baseDirs map[capsule.BaseID]string) error {
	var files, absent []ReceiptFile
	journaled := map[fileKey]bool{}
	for _, jf := range rec.Files {
		id := capsule.BaseID(jf.Base)
		journaled[fileKey{id, jf.Rel}] = true
		sum := shas[fileKey{id, jf.Rel}]
		if jf.Done {
			// D85: deleted by this seal; the receipt, if it stays, keeps
			// it as absent so the next generation is partial.
			absent = append(absent, ReceiptFile{Base: id, Rel: jf.Rel, SHA256: sum, Size: jf.Snap.Size, FromGen: gen, Absent: true})
			continue
		}
		d := bases[id]
		if d == nil {
			continue
		}
		st, err := d.Lstat(jf.Rel)
		if err != nil && isMissing(err) {
			absent = append(absent, ReceiptFile{Base: id, Rel: jf.Rel, SHA256: sum, Size: jf.Snap.Size, FromGen: gen, Absent: true})
			continue
		}
		if sum == "" {
			if err != nil || !st.Unchanged(jf.Snap) {
				continue
			}
			s, err := hashPrefix(d, jf.Rel, jf.Snap.Size, &jf.Snap)
			if err != nil {
				continue
			}
			sum = s
		}
		files = append(files, ReceiptFile{Base: id, Rel: jf.Rel, Snap: jf.Snap, SHA256: sum, Size: jf.Snap.Size, FromGen: gen})
	}
	if len(files) == 0 {
		return r.deleteReceipt(unit)
	}
	if old != nil {
		for _, f := range old.Files {
			if f.Absent && !journaled[fileKey{f.Base, f.Rel}] {
				absent = append(absent, f)
			}
		}
	}
	for _, f := range absent {
		if f.SHA256 != "" {
			files = append(files, f)
		}
	}
	rd := receiptDisk{Receipt: Receipt{Unit: unit, Gen: gen, RestoredAt: r.now(), Files: files, Kept: true}, Kind: kind, Harness: h, Bases: map[capsule.BaseID]string{}}
	if old != nil && !old.RestoredAt.IsZero() {
		rd.RestoredAt = old.RestoredAt
	}
	for id, p := range baseDirs {
		rd.Bases[id] = p
	}
	if old != nil && len(old.Blobs) > 0 {
		rd.Blobs = map[string]string{}
		for _, f := range files {
			if b := old.Blobs[f.Rel]; b != "" {
				rd.Blobs[f.Rel] = b
			}
		}
	}
	return r.writeReceipt(rd)
}
