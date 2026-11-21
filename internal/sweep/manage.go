package sweep

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/precinto/precinto/internal/capsule"
	"github.com/precinto/precinto/internal/fsx"
	"github.com/precinto/precinto/internal/harness"
	"github.com/precinto/precinto/internal/sweep/capslog"
	"github.com/precinto/precinto/internal/sweep/journal"
)

// removeFile removes a precinto-owned metadata file and fsyncs its
// directory (missing is fine).
func removeFile(p string) error {
	err := os.Remove(p)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	return fsx.SyncDir(filepath.Dir(p))
}

// Prune deletes generations fully subsumed by a successor chain, keeping
// KeepLast and every generation needed by a layered restore (D9, D42). The
// CLI calls it only after typed confirmation on a TTY (except DryRun) and
// never from an agent context (D59).
func Prune(ctx context.Context, e Env, o PruneOptions) (*Report, error) {
	r := newRun(e, prodPorts(e))
	return r.prune(ctx, o)
}

// keepSet computes the generations retention must keep (SPEC §10.4):
// the last keepLast, the chain a layered restore of the newest needs (for
// snapshots: the authoritative one), every diverged generation unless
// diverged pruning was asked for, and every generation a receipt points at.
func keepSet(entries []capslog.Entry, keepLast int, pruneDiverged bool, rd *receiptDisk, snapshot bool) map[uint64]bool {
	keep := map[uint64]bool{}
	var gens []capslog.Entry
	for _, en := range entries {
		if !en.Blob {
			gens = append(gens, en)
		}
	}
	sort.Slice(gens, func(a, b int) bool { return gens[a].Gen > gens[b].Gen })
	for i, en := range gens {
		if i < keepLast {
			keep[en.Gen] = true
		}
		if capsule.Lineage(en.Lineage) == capsule.LineageDiverged && !pruneDiverged {
			keep[en.Gen] = true
		}
	}
	if snapshot {
		if a, ok, _ := authoritativeSnapshot(gens); ok {
			keep[a.Gen] = true
		}
		if len(gens) > 0 {
			keep[gens[0].Gen] = true
		}
	} else {
		for _, en := range chain(gens) {
			keep[en.Gen] = true
		}
	}
	if rd != nil {
		keep[rd.Gen] = true
		for _, f := range rd.Files {
			keep[f.FromGen] = true
		}
	}
	return keep
}

func (r *run) prune(ctx context.Context, o PruneOptions) (*Report, error) {
	if err := ctx.Err(); err != nil {
		return r.finish(), err
	}
	r.recoverAll(ctx)
	lk, err := r.lockName("prune")
	if err != nil {
		return r.finish(), err
	}
	defer lk.Unlock()
	keepLast := o.KeepLast
	if keepLast <= 0 {
		keepLast = 3
	}
	all, err := r.log.All()
	if err != nil {
		return r.finish(), err
	}
	groups := unitGroups(all)
	var units []string
	if o.Unit != "" {
		units = []string{o.Unit}
	} else {
		for u := range groups {
			units = append(units, u)
		}
		sort.Strings(units)
	}
	for _, unit := range units {
		if ctx.Err() != nil {
			break
		}
		r.add(r.pruneUnit(unit, keepLast, o))
	}
	return r.finish(), nil
}

// pruneUnit prunes one unit under its lock, re-reading the log there so a
// concurrent seal's newer generation is never touched (CONC-3).
func (r *run) pruneUnit(unit string, keepLast int, o PruneOptions) UnitResult {
	res := UnitResult{Unit: unit}
	lk, err := r.lockUnit(unit)
	if err != nil {
		return failed(res, err)
	}
	defer lk.Unlock()
	entries, err := r.log.Unit(unit)
	if err != nil {
		return failed(res, err)
	}
	if len(entries) == 0 {
		res.Outcome, res.Detail = OutSkipped, "nothing sealed"
		return res
	}
	newest, _ := newestEntry(entries)
	res.Harness, res.Kind = newest.Harness, capsule.Kind(newest.Kind)
	rd, hasRc, err := r.loadReceipt(unit)
	if err != nil {
		return failed(res, err)
	}
	var rcp *receiptDisk
	if hasRc {
		rcp = &rd
	}
	if capsule.Kind(newest.Kind) == capsule.KindClaudeHistory {
		// Each history generation holds other lines (the extract of one
		// rotation); merge-back needs every one of them, so none is ever
		// subsumed by a successor (only forget deletes history).
		res.Outcome, res.Detail = OutSkipped, "nothing to prune: every history generation is needed by merge-back"
		return res
	}
	snapshot := isSnapshotKind(capsule.Kind(newest.Kind))
	keep := keepSet(entries, keepLast, o.Diverged, rcp, snapshot)
	var del []string
	for _, en := range entries {
		if en.Blob || keep[en.Gen] {
			continue
		}
		if o.OlderThan > 0 && en.SealedAt.After(r.now().Add(-o.OlderThan)) {
			continue
		}
		del = append(del, en.Path)
	}
	var delGens []uint64
	for _, en := range entries {
		for _, p := range del {
			if en.Path == p {
				delGens = append(delGens, en.Gen)
			}
		}
	}
	if snapshot {
		del = append(del, r.unreferencedBlobs(unit, entries, delGens, rcp)...)
	}
	if len(del) == 0 {
		res.Outcome, res.Detail = OutSkipped, "nothing to prune"
		return res
	}
	res.Files, res.Bytes = len(del), capsuleBytes(entries, del)
	if o.DryRun {
		res.Outcome, res.Detail = OutPruned, fmt.Sprintf("dry-run: would delete %d capsule(s)", len(del))
		return res
	}
	if err := r.deleteCapsules(unit, newest.Harness, del, delGens); err != nil {
		return failed(res, err)
	}
	res.Outcome, res.Detail = OutPruned, fmt.Sprintf("%d capsule(s) deleted", len(del))
	return res
}

// capsuleBytes sums the logged sizes of the capsules at paths.
func capsuleBytes(entries []capslog.Entry, paths []string) int64 {
	want := map[string]bool{}
	for _, p := range paths {
		want[p] = true
	}
	var n int64
	for _, en := range entries {
		if want[en.Path] {
			n += en.Size
		}
	}
	return n
}

// unreferencedBlobs lists blob capsules no kept snapshot (nor the receipt)
// references once delGens are gone.
func (r *run) unreferencedBlobs(unit string, entries []capslog.Entry, delGens []uint64, rd *receiptDisk) []string {
	refs := r.readRefs(unit)
	gone := map[string]bool{}
	for _, g := range delGens {
		gone[strconv.FormatUint(g, 10)] = true
	}
	kept := map[string]bool{}
	for _, en := range entries {
		if en.Blob {
			continue
		}
		g := strconv.FormatUint(en.Gen, 10)
		if gone[g] {
			continue
		}
		if keys, ok := refs.Gens[g]; ok {
			for _, k := range keys {
				kept[k] = true
			}
		} else {
			return nil // an unindexed kept snapshot: keep every blob (fail safe)
		}
	}
	if rd != nil {
		for _, k := range rd.Blobs {
			kept[k] = true
		}
	}
	candidates := map[string]bool{}
	for g, keys := range refs.Gens {
		if gone[g] {
			for _, k := range keys {
				candidates[k] = true
			}
		}
	}
	all, err := r.log.All()
	if err != nil {
		return nil
	}
	var out []string
	for _, en := range all {
		if en.Blob && candidates[en.Unit] && !kept[en.Unit] {
			out = append(out, en.Path)
		}
	}
	return out
}

// deleteCapsules journals and performs a confirmed deletion (D15): every
// path is marked deleted in the log, then removed.
func (r *run) deleteCapsules(unit, h string, paths []string, gens []uint64) error {
	rec, err := r.jr.Begin(journal.KindPrune, h, unit)
	if err != nil {
		return err
	}
	for _, p := range paths {
		rec.Files = append(rec.Files, journal.File{Base: "capsules", Rel: p})
	}
	if err := r.jr.Save(rec); err != nil {
		_ = r.jr.Done(rec)
		return err
	}
	if err := r.finishDeletions(rec); err != nil {
		return err
	}
	if len(gens) > 0 {
		refs := r.readRefs(unit)
		changed := false
		for _, g := range gens {
			k := strconv.FormatUint(g, 10)
			if _, ok := refs.Gens[k]; ok {
				delete(refs.Gens, k)
				changed = true
			}
		}
		if changed {
			_ = r.writeRefs(unit, refs)
		}
	}
	return r.jr.Done(rec)
}

// finishDeletions marks every journaled capsule deleted and removes it
// (idempotent: recovery rolls a deletion forward).
func (r *run) finishDeletions(rec *journal.Record) error {
	all, err := r.log.All()
	if err != nil {
		return err
	}
	live := map[string]bool{}
	for _, en := range all {
		live[en.Path] = true
	}
	root, err := r.p.fs.OpenBase(r.l.CapsulesDir)
	if err != nil {
		return err
	}
	defer root.Close()
	for i := range rec.Files {
		jf := &rec.Files[i]
		if jf.Done {
			continue
		}
		if live[jf.Rel] {
			if err := r.log.MarkDeleted(jf.Rel, r.now()); err != nil {
				return err
			}
		}
		if _, _, _, ok := splitLogPath(jf.Rel); !ok {
			continue
		}
		if err := root.Remove(jf.Rel); err != nil && !isMissing(err) {
			return err
		}
		jf.Done = true
		if err := r.jr.Save(rec); err != nil {
			return err
		}
	}
	return nil
}

// Forget deletes every generation of a unit after typed confirmation on a
// TTY by the caller (`precinto forget`; refused from agent contexts, D59),
// logging deletion records (I12).
func Forget(ctx context.Context, e Env, unit string) (*Report, error) {
	r := newRun(e, prodPorts(e))
	if err := ctx.Err(); err != nil {
		return r.finish(), err
	}
	r.recoverAll(ctx)
	res := UnitResult{Unit: unit}
	if !validKey(unit) {
		r.add(failed(res, fmt.Errorf("%w: invalid unit key", harness.ErrUnitKey)))
		return r.finish(), nil
	}
	lk, err := r.lockUnit(unit)
	if err != nil {
		r.add(failed(res, err))
		return r.finish(), nil
	}
	defer lk.Unlock()
	entries, err := r.log.Unit(unit)
	if err != nil {
		return r.finish(), err
	}
	if len(entries) == 0 {
		res.Outcome, res.Detail = OutSkipped, "nothing sealed"
		r.add(res)
		return r.finish(), nil
	}
	newest, _ := newestEntry(entries)
	res.Harness, res.Kind = newest.Harness, capsule.Kind(newest.Kind)
	var del []string
	var gens []uint64
	for _, en := range entries {
		del = append(del, en.Path)
		gens = append(gens, en.Gen)
	}
	if isSnapshotKind(capsule.Kind(newest.Kind)) {
		refs := r.readRefs(unit)
		want := map[string]bool{}
		for _, keys := range refs.Gens {
			for _, k := range keys {
				want[k] = true
			}
		}
		all, err := r.log.All()
		if err == nil {
			for _, en := range all {
				if en.Blob && want[en.Unit] {
					del = append(del, en.Path)
				}
			}
		}
	}
	if err := r.deleteCapsules(unit, newest.Harness, del, gens); err != nil {
		r.add(failed(res, err))
		return r.finish(), nil
	}
	_ = r.deleteReceipt(unit)
	_ = removeFile(r.refsPath(unit))
	res.Outcome, res.Detail, res.Files = OutForgotten, fmt.Sprintf("%d capsule(s) deleted", len(del)), len(del)
	r.add(res)
	return r.finish(), nil
}

// conflictCopyRe recognises conflict copy names (D11, SPEC §10.4).
var conflictCopyRe = regexp.MustCompile(`(\.precinto-restored(\.\d+)?$)|(\.conflict-\d{8}-\d{4}(\.\d+)?\.[A-Za-z]+$)|(\.precinto-g\d+(\.[^./]+)?$)`)

// isConflictCopy reports whether rel names a conflict copy.
func isConflictCopy(rel string) bool { return conflictCopyRe.MatchString(path.Base(rel)) }

// originalOf derives the path a conflict copy shadows.
func originalOf(rel string) string {
	dir, base := path.Split(rel)
	if i := strings.Index(base, ".precinto-restored"); i > 0 {
		return dir + base[:i]
	}
	if m := regexp.MustCompile(`^(.*)\.conflict-\d{8}-\d{4}(\.\d+)?(\.[A-Za-z]+)$`).FindStringSubmatch(base); m != nil {
		return dir + m[1] + m[3]
	}
	if m := regexp.MustCompile(`^(.*)\.precinto-g\d+(\.[^./]+)?$`).FindStringSubmatch(base); m != nil {
		return dir + m[1] + m[2]
	}
	return rel
}

// Resolve keeps one side of a Markdown or file conflict (`precinto
// resolve`), sealing the other as a retained generation.
func Resolve(ctx context.Context, e Env, keys KeySource, path string, keep string) (*Report, error) {
	r := newRun(e, prodPorts(e))
	return r.resolve(ctx, keys, path, keep)
}

func (r *run) resolve(ctx context.Context, keys KeySource, p string, keep string) (*Report, error) {
	keepCapsule := false
	switch keep {
	case "capsule":
		keepCapsule = true
	case "plaintext":
	default:
		return r.finish(), fmt.Errorf("sweep: --keep must be capsule or plaintext, not %q", keep)
	}
	r.recoverAll(ctx)
	rd, copyRF, origRel, base, err := r.findConflict(p)
	if err != nil {
		return r.finish(), err
	}
	res := UnitResult{Unit: rd.Unit, Kind: rd.Kind, Harness: rd.Harness}
	lk, err := r.lockUnit(rd.Unit)
	if err != nil {
		r.add(failed(res, err))
		return r.finish(), nil
	}
	defer lk.Unlock()
	d, err := r.p.fs.OpenBase(base)
	if err != nil {
		r.add(failed(res, err))
		return r.finish(), nil
	}
	defer d.Close()
	cst, err := d.Lstat(copyRF.Rel)
	if err != nil || !cst.Unchanged(copyRF.Snap) {
		r.add(failed(res, fmt.Errorf("%w: the conflict copy changed; seal it first", fsx.ErrChanged)))
		return r.finish(), nil
	}
	if keepCapsule {
		// Retain the existing plaintext as a generation, then put the
		// capsule's version in its place.
		side, err := r.sideOf(ctx, keys, rd)
		if err != nil {
			r.add(failed(res, err))
			return r.finish(), nil
		}
		if err := r.retainFile(ctx, side, rd, copyRF.Base, base, origRel); err != nil {
			r.add(failed(res, err))
			return r.finish(), nil
		}
		ost, err := d.Lstat(origRel)
		if err != nil {
			r.add(failed(res, err))
			return r.finish(), nil
		}
		dir := path.Dir(origRel)
		pd := d
		if dir != "." {
			if pd, err = d.OpenDir(dir, false); err != nil {
				r.add(failed(res, err))
				return r.finish(), nil
			}
			defer pd.Close()
		}
		if now, err := pd.Lstat(path.Base(origRel)); err != nil || !now.Unchanged(ost) {
			r.add(failed(res, fmt.Errorf("%w: the file changed while resolving", fsx.ErrChanged)))
			return r.finish(), nil
		}
		if err := pd.Rename(path.Base(copyRF.Rel), path.Base(origRel), fsx.Replace); err != nil {
			r.add(failed(res, err))
			return r.finish(), nil
		}
		after, _ := d.Lstat(origRel)
		// D88: the chosen side is sealed as the newest generation, a
		// partial one whose parent is the generation before the retained
		// one, so the restore chain never reaches the rejected side (kept
		// as a diverged generation until pruned) and the next lock and
		// unlock keep the user's choice.
		from := copyRF.FromGen
		if g, err := r.sealSide(ctx, side, rd.Unit, copyRF.Base, base, origRel, capsule.LineagePartial); err == nil {
			from = g
			rd.Gen = g
		} else {
			res.Detail = "chosen side not sealed: " + safeMsg(err)
		}
		r.replaceReceiptFile(rd, copyRF, ReceiptFile{Base: copyRF.Base, Rel: origRel, Snap: after, SHA256: copyRF.SHA256, Size: copyRF.Size, FromGen: from})
	} else {
		// The capsule keeps the other version; the copy goes.
		if err := d.UnlinkIfUnchanged(copyRF.Rel, copyRF.Snap); err != nil {
			r.add(failed(res, err))
			return r.finish(), nil
		}
		r.replaceReceiptFile(rd, copyRF, ReceiptFile{})
	}
	res.Outcome = OutRestored
	if res.Detail == "" {
		res.Detail = "conflict resolved"
	}
	r.add(res)
	return r.finish(), nil
}

// findConflict locates a conflict copy (or the file it shadows) in the
// receipts.
func (r *run) findConflict(p string) (receiptDisk, ReceiptFile, string, string, error) {
	ents, err := os.ReadDir(r.l.ReceiptsDir)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return receiptDisk{}, ReceiptFile{}, "", "", err
	}
	clean := filepath.Clean(p)
	for _, de := range ents {
		unit, ok := strings.CutSuffix(de.Name(), ".json")
		if !ok || !validKey(unit) {
			continue
		}
		rd, ok, err := r.loadReceipt(unit)
		if err != nil || !ok {
			continue
		}
		for _, f := range rd.Files {
			base := rd.Bases[f.Base]
			if base == "" || f.Absent || !isConflictCopy(f.Rel) {
				continue
			}
			orig := originalOf(f.Rel)
			if filepath.Join(base, filepath.FromSlash(f.Rel)) == clean || filepath.Join(base, filepath.FromSlash(orig)) == clean {
				return rd, f, orig, base, nil
			}
		}
	}
	return receiptDisk{}, ReceiptFile{}, "", "", fmt.Errorf("sweep: no recorded conflict for this file")
}

// replaceReceiptFile swaps (or, with a zero replacement, drops) one file
// of a receipt.
func (r *run) replaceReceiptFile(rd receiptDisk, old ReceiptFile, nf ReceiptFile) {
	var files []ReceiptFile
	for _, f := range rd.Files {
		if f.Base == old.Base && f.Rel == old.Rel {
			continue
		}
		if nf.Rel != "" && f.Base == nf.Base && f.Rel == nf.Rel {
			continue
		}
		files = append(files, f)
	}
	if nf.Rel != "" {
		files = append(files, nf)
	}
	rd.Files = files
	present := 0
	for _, f := range files {
		if !f.Absent {
			present++
		}
	}
	if present == 0 {
		_ = r.deleteReceipt(rd.Unit)
		return
	}
	_ = r.writeReceipt(rd)
}

// resolveSide is what resolve seals a conflict side from: the unit's
// newest logged generation and its manifest (the unit id must
// authenticate at restore).
type resolveSide struct {
	newest capslog.Entry
	man    capsule.Manifest
}

// sideOf reads the newest manifest of rd's unit (keys with purpose
// "restore").
func (r *run) sideOf(ctx context.Context, keys KeySource, rd receiptDisk) (resolveSide, error) {
	entries, err := r.log.Unit(rd.Unit)
	if err != nil {
		return resolveSide{}, err
	}
	newest, ok := newestEntry(entries)
	if !ok {
		return resolveSide{}, fmt.Errorf("%w: nothing sealed for this unit", ErrNotLogged)
	}
	if keys == nil {
		return resolveSide{}, fmt.Errorf("%w: no key source", ErrKeyDenied)
	}
	kg := &keyGuard{}
	defer kg.destroy()
	fk, err := keys.FileKeys(ctx, []string{newest.Path}, "restore")
	if err != nil {
		return resolveSide{}, fmt.Errorf("%w: %s", ErrKeyDenied, safeMsg(err))
	}
	kg.add(fk)
	m, err := r.readManifest(ctx, newest, kg)
	if err != nil {
		return resolveSide{}, err
	}
	if err := checkManifest(m, newest); err != nil {
		return resolveSide{}, err
	}
	return resolveSide{newest: newest, man: m}, nil
}

// retainFile seals one plaintext file of a unit as a retained (diverged)
// generation without deleting it.
func (r *run) retainFile(ctx context.Context, side resolveSide, rd receiptDisk, b capsule.BaseID, base, rel string) error {
	_, err := r.sealSide(ctx, side, rd.Unit, b, base, rel, capsule.LineageDiverged)
	return err
}

// sealSide seals the plaintext file rel (base b) of a unit as one new
// generation whose parent is side's newest generation, keeping the file
// (keyless: only recipients are needed). It returns the generation.
func (r *run) sealSide(ctx context.Context, side resolveSide, unit string, b capsule.BaseID, base, rel string, l capsule.Lineage) (uint64, error) {
	newest, m := side.newest, side.man
	d, err := r.p.fs.OpenBase(base)
	if err != nil {
		return 0, err
	}
	defer d.Close()
	st, err := d.Lstat(rel)
	if err != nil {
		return 0, err
	}
	recips, err := r.p.vaults.recipients(newest.VaultID)
	if err != nil {
		return 0, err
	}
	store := newest.Harness
	capsRoot, caps, err := r.openCapsDir(store, unit, true)
	if err != nil {
		return 0, err
	}
	defer capsRoot.Close()
	defer caps.Close()
	g, err := r.nextGen(ctx, unit, caps)
	if err != nil {
		return 0, err
	}
	rec, err := r.jr.Begin(journal.KindSeal, store, unit)
	if err != nil {
		return 0, err
	}
	name := capsule.GenName(g)
	man := m
	man.Files, man.Ledger = nil, nil
	man.Gen, man.Parent, man.Lineage, man.CreatedAt, man.Sealer, man.RecipientsFpr = g, newest.Gen, l, r.now(), r.e.Sealer, recips.fpr
	en := newest
	en.Gen, en.Parent, en.Lineage, en.SealedAt, en.RecipientsFpr, en.Files, en.Bytes = g, newest.Gen, string(l), r.now(), recips.fpr, 1, st.Size
	spec := &commitSpec{rec: rec, unitDir: caps, outDir: caps, capsuleRel: name, name: name,
		logPath: logPathOf(store, unit, name), gen: g,
		req: sealRequest{Manifest: man, Recipients: recips, Inputs: []sealInput{{Base: b, Dir: d, Rel: rel, Snap: st,
			Path: filepath.Join(base, filepath.FromSlash(rel))}}},
		entry: en}
	if _, err := r.commit(ctx, spec); err != nil {
		if !keepRecord(err) {
			_ = r.jr.Done(rec)
		}
		return 0, err
	}
	return g, r.jr.Done(rec)
}

// List returns units from the capsule log and the on-disk scan.
func List(ctx context.Context, e Env, o ListOptions) ([]UnitInfo, error) {
	r := newRun(e, prodPorts(e))
	return r.list(ctx, o)
}

func (r *run) list(ctx context.Context, o ListOptions) ([]UnitInfo, error) {
	all, err := r.log.All()
	if err != nil {
		return nil, err
	}
	wantRoot := func(ids []string) bool {
		if len(o.RootIDs) == 0 {
			return true
		}
		for _, id := range ids {
			if contains(o.RootIDs, id) {
				return true
			}
		}
		return false
	}
	quarantined := r.quarantinedUnits()
	byUnit := map[string]*UnitInfo{}
	var order []string
	for unit, entries := range unitGroups(all) {
		n, ok := newestEntry(entries)
		if !ok || !wantRoot(n.RootIDs) {
			continue
		}
		info := &UnitInfo{Harness: n.Harness, Kind: capsule.Kind(n.Kind), Unit: unit, RootIDs: n.RootIDs,
			Bytes: n.Bytes, LastActivity: lastActivity(n), Quarantined: quarantined[unit]}
		for _, en := range entries {
			info.Gens = append(info.Gens, generationOf(en))
		}
		byUnit[unit] = info
		order = append(order, unit)
	}
	// Plaintext on disk: receipts (restored units) and adapter scans.
	for unit, info := range byUnit {
		if rd, ok, err := r.loadReceipt(unit); err == nil && ok {
			info.Plaintext = true
			info.Reason = "restored"
			for _, f := range rd.Files {
				if !f.Absent && isConflictCopy(f.Rel) {
					info.Conflicts++
				}
			}
			if info.Conflicts > 0 {
				info.Reason = "conflict"
			}
		}
	}
	unlocked := r.unlocked(ctx)
	for _, ad := range r.e.Adapters {
		if ad == nil {
			continue
		}
		// A home that could not be read still lets the others count.
		units, _ := ad.Scan(ctx, r.e.Harness, harness.Scope{RootIDs: o.RootIDs})
		for _, u := range units {
			if !wantRoot(append(append([]string(nil), u.RootIDs...), u.VaultID)) {
				continue
			}
			info := byUnit[u.Key]
			if info == nil {
				info = &UnitInfo{Harness: string(u.Harness), Kind: u.Kind, Unit: u.Key, RootIDs: u.RootIDs, LastActivity: u.LastActivity}
				byUnit[u.Key] = info
				order = append(order, u.Key)
			}
			info.Plaintext = true
			info.Bytes = unitBytes(u)
			if info.Reason == "" || info.Reason == "restored" {
				info.Reason = r.plaintextReason(ctx, ad, u, unlocked)
			}
		}
	}
	if o.Keys != nil {
		r.fillTitles(ctx, o.Keys, byUnit, all)
	}
	sort.Strings(order)
	var out []UnitInfo
	for _, unit := range dedupe(order) {
		info := byUnit[unit]
		if o.Conflicts && info.Conflicts == 0 {
			continue
		}
		out = append(out, *info)
	}
	return out, nil
}

// fillTitles decrypts the newest manifests for titles (purpose "list").
func (r *run) fillTitles(ctx context.Context, keys KeySource, byUnit map[string]*UnitInfo, all []capslog.Entry) {
	groups := unitGroups(all)
	var paths []string
	newest := map[string]capslog.Entry{}
	for unit := range byUnit {
		if n, ok := newestEntry(groups[unit]); ok {
			paths = append(paths, n.Path)
			newest[unit] = n
		}
	}
	if len(paths) == 0 {
		return
	}
	kg := &keyGuard{}
	defer kg.destroy()
	if err := r.fetchKeys(ctx, keys, kg, paths, "list"); err != nil {
		return
	}
	for unit, n := range newest {
		if m, err := r.readManifest(ctx, n, kg); err == nil && checkManifest(m, n) == nil {
			byUnit[unit].Title = m.Title
		}
		kg.forget(n.Path)
	}
}

// quarantinedUnits lists unit keys with capsules in quarantine.
func (r *run) quarantinedUnits() map[string]bool {
	out := map[string]bool{}
	if _, err := fsx.Lstat(r.l.QuarantineDir); err != nil {
		return out
	}
	q, err := r.p.fs.OpenBase(r.l.QuarantineDir)
	if err != nil {
		return out
	}
	defer q.Close()
	_ = q.Walk(".", func(we fsx.WalkEntry) error {
		parts := strings.Split(strings.TrimPrefix(we.Rel, "./"), "/")
		if len(parts) >= 3 && validKey(parts[2]) {
			out[parts[2]] = true
		}
		return nil
	})
	return out
}

// plaintextReason classifies a unit's plaintext for status and ls from
// what is on disk now, without new state (SPEC §9.5, §16.4, D63): one look
// only, so evidence the next sweep's quiet wait resolves (a first
// observation, a restore within the window) is "deferred", while weak
// evidence that never resolves by waiting holds a unit of a locked folder
// "hold-capped". A locked folder's unit whose plaintext still matches a
// committed receipt is "remove-failed" (the seal committed, the unlink was
// refused); EACCES/EPERM met while summarizing is "inaccessible".
func (r *run) plaintextReason(ctx context.Context, ad harness.Adapter, u harness.Unit, unlocked map[string]bool) string {
	if r.inaccessibleUnit(u) {
		return "inaccessible"
	}
	locked := r.unitLocked(u, unlocked)
	rd, hasRc, err := r.loadReceipt(u.Key)
	if err != nil && isAccess(err) {
		return "inaccessible"
	}
	var rcp *receiptDisk
	if hasRc {
		rcp = &rd
	}
	if v, isLive := r.checkLive(ctx, ad, u, rcp); isLive {
		switch {
		case !weakOnly(v.Evidence):
			return "running"
		case !quietOnly(v.Evidence):
			if locked {
				return reasonHoldCapped
			}
			return "running"
		}
	}
	switch {
	case hasRc && !locked:
		return "restored"
	case hasRc && r.removeFailed(u, rd):
		return "remove-failed"
	}
	return "deferred"
}

// inaccessibleUnit reports a unit whose scan met EACCES/EPERM, or whose
// files can no longer be lstat'ed for that reason (TCC, §17).
func (r *run) inaccessibleUnit(u harness.Unit) bool {
	if accessHazards(u) > 0 {
		return true
	}
	for _, f := range u.Files {
		b := u.Home.Bases[f.Base]
		if b == "" {
			continue
		}
		if _, err := fsx.Lstat(filepath.Join(b, filepath.FromSlash(f.Rel))); err != nil && isAccess(err) {
			return true
		}
	}
	return false
}

// accessHazards counts the entries a scan could not read (EACCES/EPERM).
func accessHazards(u harness.Unit) int {
	n := 0
	for _, h := range u.Hazards {
		if h.Hazard == fsx.HazardAccess {
			n++
		}
	}
	return n
}

// removeFailed reports plaintext identical to a committed receipt: the
// receipt's generation is logged and every file of the unit is listed in
// it with the identity it had when that generation was sealed or placed.
func (r *run) removeFailed(u harness.Unit, rd receiptDisk) bool {
	if len(u.Files) == 0 {
		return false
	}
	entries, err := r.log.Unit(u.Key)
	if err != nil {
		return false
	}
	committed := false
	for _, en := range entries {
		committed = committed || en.Gen == rd.Gen
	}
	if !committed {
		return false
	}
	idx := receiptIndex(&rd)
	for _, f := range u.Files {
		rf, ok := idx[fileKey{f.Base, f.Rel}]
		if !ok || !f.Snap.Unchanged(rf.Snap) {
			return false
		}
	}
	return true
}

// PlaintextSummary scans without sealing.
func PlaintextSummary(ctx context.Context, e Env) ([]Plaintext, error) {
	r := newRun(e, prodPorts(e))
	return r.plaintextSummary(ctx)
}

func (r *run) plaintextSummary(ctx context.Context) ([]Plaintext, error) {
	byRoot := map[string]*Plaintext{}
	get := func(id string) *Plaintext {
		p := byRoot[id]
		if p == nil {
			p = &Plaintext{RootID: id, ByReason: map[string]int{}}
			byRoot[id] = p
		}
		return p
	}
	unlocked := r.unlocked(ctx)
	for _, ad := range r.e.Adapters {
		if ad == nil {
			continue
		}
		// A home that could not be read still lets the others count.
		units, _ := ad.Scan(ctx, r.e.Harness, harness.Scope{Adopt: true})
		for _, u := range units {
			id := u.VaultID
			if len(u.RootIDs) > 0 {
				id = u.RootIDs[0]
			}
			reason := r.plaintextReason(ctx, ad, u, unlocked)
			n := len(u.Files) + accessHazards(u)
			p := get(id)
			p.Files += n
			p.Bytes += unitBytes(u)
			p.ByReason[reason] += n
		}
		if ad.ID() == harness.ClaudeCode {
			if homes, err := ad.Homes(ctx, r.e.Harness); err == nil {
				for _, h := range homes {
					pending, err := r.historyPending(h)
					if err != nil {
						continue
					}
					for id, n := range pending {
						get(id).ByReason["history_pending"] += n
					}
				}
			}
		}
	}
	for _, root := range r.e.Cfg.Roots {
		for rel := range r.noteCandidates(ctx, root) {
			if st, err := fsx.Lstat(filepath.Join(root.Path, filepath.FromSlash(rel))); err == nil && st.IsRegular() {
				p := get(root.ID)
				p.Files++
				p.Bytes += st.Size
				p.ByReason["notes"]++
			}
		}
	}
	var out []Plaintext
	for _, p := range byRoot {
		out = append(out, *p)
	}
	sort.Slice(out, func(a, b int) bool { return out[a].RootID < out[b].RootID })
	return out, nil
}
