package sweep

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"time"

	"github.com/Neorichi/precinto/internal/capsule"
	"github.com/Neorichi/precinto/internal/fsx"
	"github.com/Neorichi/precinto/internal/harness"
	"github.com/Neorichi/precinto/internal/harness/codex"
	"github.com/Neorichi/precinto/internal/live"
	"github.com/Neorichi/precinto/internal/sweep/capslog"
	"github.com/Neorichi/precinto/internal/sweep/journal"
)

// baseBlob marks the journal files of a codex-snapshot record that name
// blob capsules (relative to the home's unit capsule directory) rather
// than plaintext.
const baseBlob capsule.BaseID = "precinto-blob"

// blobsDir is the subdirectory of a codex home's capsule directory that
// holds its blob capsules (SPEC §6.1).
const blobsDir = "blobs"

// snapRefs is state/gens/<home-unit>.refs.json: the blob unit keys each
// snapshot generation references, so keyless prune and restore planning
// know them without decrypting manifests. Written before the snapshot
// commits; entries for generations that never committed are ignored.
type snapRefs struct {
	V    int                 `json:"v"`
	Gens map[string][]string `json:"gens"` // generation → blob unit keys
}

func (r *run) refsPath(unit string) string {
	return filepath.Join(r.l.GensDir, unit+".refs.json")
}

// maxRefsBytes bounds a snapshot refs index read (blob keys only).
const maxRefsBytes = 64 << 20

// readRefs reads state/gens/<unit>.refs.json (readState: regular,
// bounded, never blocking); anything unreadable reads as empty, which
// makes prune keep every blob (fail safe).
func (r *run) readRefs(unit string) snapRefs {
	refs := snapRefs{V: 1, Gens: map[string][]string{}}
	if !validKey(unit) {
		return refs
	}
	b, err := readState(r.refsPath(unit), maxRefsBytes)
	if err != nil {
		return refs
	}
	var got snapRefs
	if err := json.Unmarshal(b, &got); err == nil && got.Gens != nil {
		refs.Gens = got.Gens
	}
	return refs
}

func (r *run) writeRefs(unit string, refs snapRefs) error {
	if err := ensurePrivateDir(r.l.GensDir); err != nil {
		return err
	}
	refs.V = 1
	b, err := json.Marshal(refs)
	if err != nil {
		return err
	}
	return fsx.WriteFileAtomic(r.refsPath(unit), b, 0o600)
}

// newBlobID returns a random blob id (the unit id of a codex-blob, D45).
func newBlobID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// blobGroup is the files one blob holds: one file, or one SQLite group
// (*.sqlite + -wal + -journal, read in one pass; -shm is never sealed).
type blobGroup struct {
	id    string
	files []harness.File
}

func (r *run) blobGroups(files []harness.File) []blobGroup {
	byID := map[string]*blobGroup{}
	var order []string
	for _, f := range files {
		if r.p.codexClass != nil && r.p.codexClass(f.Rel) == codex.ClassSHM {
			continue
		}
		id := f.Group
		if id == "" {
			id = "file:" + f.Rel
		}
		g := byID[id]
		if g == nil {
			g = &blobGroup{id: id}
			byID[id] = g
			order = append(order, id)
		}
		g.files = append(g.files, f)
	}
	out := make([]blobGroup, 0, len(order))
	for _, id := range order {
		g := byID[id]
		sort.Slice(g.files, func(a, b int) bool { return g.files[a].Rel < g.files[b].Rel })
		out = append(out, *g)
	}
	return out
}

// authoritativeSnapshot is the snapshot a restore places: the newest
// generation that is not diverged. A diverged snapshot newer than it is an
// unresolved divergence (R12) until `codex reconcile`.
func authoritativeSnapshot(entries []capslog.Entry) (auth capslog.Entry, ok bool, diverged bool) {
	var newest capslog.Entry
	haveNewest := false
	for _, en := range entries {
		if en.Blob {
			continue
		}
		if !haveNewest || en.Gen > newest.Gen {
			newest, haveNewest = en, true
		}
		if capsule.Lineage(en.Lineage) == capsule.LineageDiverged {
			continue
		}
		if !ok || en.Gen > auth.Gen {
			auth, ok = en, true
		}
	}
	diverged = haveNewest && capsule.Lineage(newest.Lineage) == capsule.LineageDiverged && (!ok || newest.Gen > auth.Gen)
	return auth, ok, diverged
}

// snapshotLineage is the lineage of a Codex snapshot (D86, SPEC §7.2):
// a home restored from the authoritative snapshot (its receipt names
// that generation) that Codex then changed in place, as every session
// does (SQLite write transactions, WAL checkpoints, appended rollouts),
// is that snapshot's successor (partial when receipt files are missing):
// snapshots restore exactly the newest one, so nothing needs folding.
// Diverged stays for plaintext without a receipt while generations exist
// (and for a receipt of an older, non-authoritative generation): content
// precinto did not place, which the launch refuses (R12).
func snapshotLineage(lp lineagePlan, rd *receiptDisk, logged []capslog.Entry) (capsule.Lineage, uint64) {
	if lp.Lineage != capsule.LineageDiverged || rd == nil {
		return lp.Lineage, lp.Parent
	}
	auth, ok, _ := authoritativeSnapshot(logged)
	if !ok || auth.Gen != rd.Gen {
		return lp.Lineage, lp.Parent
	}
	if len(lp.Missing) > 0 {
		return capsule.LineagePartial, rd.Gen
	}
	return capsule.LineageSuccessor, rd.Gen
}

// sealCodexHome seals a per-root Codex home as one snapshot generation
// (SPEC §7.2, D42): blobs for changed files and groups (unchanged ones
// reuse the receipt's blob), then the manifest generation listing every
// content file; plaintext goes only after the manifest commit. With keep,
// the plaintext is sealed but never deleted (divergence, R12).
func (r *run) sealCodexHome(ctx context.Context, u harness.Unit, o Options, explicit, keep bool) UnitResult {
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
	return r.sealCodexLocked(ctx, ad, u, o, explicit, keep, "")
}

// sealCodexLocked is sealCodexHome under the unit lock. forceLineage, when
// set, overrides the computed lineage (reconcile).
func (r *run) sealCodexLocked(ctx context.Context, ad harness.Adapter, u harness.Unit, o Options, explicit, keep bool, forceLineage capsule.Lineage) UnitResult {
	res := resultOf(u)
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
	if leave, why := r.leaveInPlace(ctx, u, o, rd, hasRc); leave {
		res.Outcome, res.Detail = OutSkipped, why
		return res
	}
	var rcp *receiptDisk
	if hasRc {
		rcp = &rd
	}
	if !keep {
		if v, isLive := r.checkLiveAfter(ctx, ad, u, rcp, exited); isLive {
			return liveResult(res, v, explicit, "")
		}
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
	var content []harness.File
	for _, f := range u.Files {
		if r.p.codexClass != nil && r.p.codexClass(f.Rel) == codex.ClassSHM {
			continue // -shm is never sealed
		}
		content = append(content, f)
	}
	files, hz, err := r.refresh(bases, content)
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
	if forceLineage != "" {
		lp.Lineage = forceLineage
		if n, ok := newestEntry(logged); ok {
			lp.Parent = n.Gen
		}
		lp.Unchanged = false
	} else {
		lp.Lineage, lp.Parent = snapshotLineage(lp, rcp, logged)
	}
	// A snapshot is unchanged only if the file set equals the receipt's:
	// a deleted rollout must not come back (CODX-4).
	if len(lp.Missing) > 0 {
		lp.Unchanged = false
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
	capsRoot, caps, err := r.openCapsDir(storeOf(u.Harness, u.Kind), u.Key, true)
	if err != nil {
		return failed(res, err)
	}
	defer capsRoot.Close()
	defer caps.Close()
	us := &unitSeal{r: r, u: u, ad: ad, bases: bases, files: files, rd: rcp, caps: caps, recips: recips, res: res, explicit: explicit}
	if lp.Unchanged && !keep {
		return us.dropUnchanged(ctx)
	}
	return r.sealSnapshot(ctx, us, lp, keep)
}

// sealSnapshot writes the blobs and the manifest generation.
func (r *run) sealSnapshot(ctx context.Context, us *unitSeal, lp lineagePlan, keep bool) UnitResult {
	u, res := us.u, us.res
	rootID := firstRoot(u.RootIDs, r)
	if rootID == "" && len(u.RootIDs) > 0 {
		rootID = u.RootIDs[0]
	}
	classOf := map[fileKey]classifiedFile{}
	for _, c := range lp.Files {
		classOf[fileKey{c.File.Base, c.File.Rel}] = c
	}
	all, err := r.log.All()
	if err != nil {
		return failed(res, err)
	}
	blobLogged := map[string]capslog.Entry{}
	for _, en := range all {
		if en.Blob {
			blobLogged[en.Unit] = en
		}
	}
	type plannedBlob struct {
		g      blobGroup
		key    string
		id     string
		reused bool
	}
	var blobs []plannedBlob
	for _, g := range r.blobGroups(us.files) {
		reuse := ""
		if us.rd != nil && us.rd.Blobs != nil {
			for i, f := range g.files {
				c := classOf[fileKey{f.Base, f.Rel}]
				k := us.rd.Blobs[f.Rel]
				if c.Class != classUnchanged || k == "" || (i > 0 && k != reuse) {
					reuse = ""
					break
				}
				reuse = k
			}
		}
		if _, ok := blobLogged[reuse]; reuse != "" && ok {
			blobs = append(blobs, plannedBlob{g: g, key: reuse, reused: true})
			continue
		}
		id, err := newBlobID()
		if err != nil {
			return failed(res, err)
		}
		key, err := harness.UnitKeyFor(r.e.Harness.Salt, capsule.KindCodexBlob, harness.Codex, "", rootID, id)
		if err != nil {
			return failed(res, err)
		}
		blobs = append(blobs, plannedBlob{g: g, key: key, id: id})
	}
	rec, err := r.jr.Begin(journal.KindCodexSnapshot, string(u.Harness), u.Key)
	if err != nil {
		return failed(res, err)
	}
	rec.Files = us.journalFiles()
	blobDir, err := us.caps.OpenDir(blobsDir, true)
	if err != nil {
		_ = r.jr.Done(rec)
		return failed(res, err)
	}
	defer blobDir.Close()
	shas := map[fileKey]string{}
	if us.rd != nil {
		for _, rf := range us.rd.Files {
			shas[fileKey{rf.Base, rf.Rel}] = rf.SHA256
		}
	}
	blobOf := map[string]string{} // rel → blob key
	store := storeOf(u.Harness, u.Kind)
	for _, b := range blobs {
		for _, f := range b.g.files {
			blobOf[f.Rel] = b.key
		}
		if b.reused {
			continue
		}
		var inputs []sealInput
		var bytes int64
		for _, f := range b.g.files {
			inputs = append(inputs, sealInput{Base: f.Base, Dir: us.bases[f.Base], Rel: f.Rel,
				Path: filepath.Join(u.Home.Bases[f.Base], filepath.FromSlash(f.Rel)), Snap: f.Snap, Group: f.Group, Append: f.Append})
			bytes += f.Snap.Size
		}
		name := b.key + capsule.FileExt
		man := capsule.Manifest{Format: capsule.FormatVersion, Kind: capsule.KindCodexBlob, Harness: string(harness.Codex),
			UnitKey: b.key, UnitID: b.id, VaultID: u.VaultID, RootIDs: append([]string(nil), u.RootIDs...),
			RootPath: r.rootPathOf(u), Gen: 1, Lineage: capsule.LineageFresh, CreatedAt: r.now(), Sealer: r.e.Sealer,
			RecipientsFpr: us.recips.fpr}
		spec := &commitSpec{
			rec: rec, unitDir: us.caps, outDir: blobDir, capsuleRel: path.Join(blobsDir, name), name: name,
			logPath: logPathOf(store, u.Key, blobsDir, name), gen: 0,
			req: sealRequest{Manifest: man, Inputs: inputs, Recipients: us.recips},
			entry: capslog.Entry{V: capslog.Version, Kind: string(capsule.KindCodexBlob), Harness: string(harness.Codex),
				Unit: b.key, VaultID: u.VaultID, RootIDs: append([]string(nil), u.RootIDs...), Gen: 1,
				Lineage: string(capsule.LineageFresh), Blob: true, SealedAt: r.now(), RecipientsFpr: us.recips.fpr,
				Files: len(inputs), Bytes: bytes},
		}
		sealed, err := r.commit(ctx, spec)
		if err != nil {
			if !keepRecord(err) {
				r.collectBlobs(rec)
				_ = r.jr.Done(rec)
			}
			if errors.Is(err, capsule.ErrChanged) || errors.Is(err, fsx.ErrChanged) {
				return liveResult(res, live.Verdict{Live: true}, us.explicit, "changed while sealing")
			}
			return failed(res, err)
		}
		for _, en := range sealed.Manifest.Files {
			shas[fileKey{en.Base, en.Rel}] = en.SHA256
		}
		rec.Files = append(rec.Files, journal.File{Base: string(baseBlob), Rel: path.Join(blobsDir, name), Done: true})
		if err := r.jr.Save(rec); err != nil {
			return failed(res, err)
		}
		if err := r.hit("codex.blob"); err != nil {
			return failed(res, err)
		}
	}
	// The manifest generation: every content file with its blob.
	n, err := r.nextGen(ctx, u.Key, us.caps)
	if err != nil {
		r.collectBlobs(rec)
		_ = r.jr.Done(rec)
		return failed(res, err)
	}
	var entries []capsule.Entry
	var keys []string
	for _, f := range us.files {
		if _, ok := blobOf[f.Rel]; !ok {
			continue
		}
		sum := shas[fileKey{f.Base, f.Rel}]
		if sum == "" {
			s, err := hashPrefix(us.bases[f.Base], f.Rel, f.Snap.Size, &f.Snap)
			if err != nil {
				r.collectBlobs(rec)
				_ = r.jr.Done(rec)
				return liveResult(res, live.Verdict{Live: true}, us.explicit, "changed while sealing")
			}
			sum = s
			shas[fileKey{f.Base, f.Rel}] = s
		}
		entries = append(entries, capsule.Entry{Base: f.Base, Rel: f.Rel, Mode: f.Snap.Mode & 0o7777, MtimeNS: f.Snap.MtimeNS,
			Size: f.Snap.Size, SHA256: sum, Blob: blobOf[f.Rel], Group: f.Group})
		keys = append(keys, blobOf[f.Rel])
	}
	refs := r.readRefs(u.Key)
	refs.Gens[strconv.FormatUint(n, 10)] = dedupe(keys)
	if err := r.writeRefs(u.Key, refs); err != nil {
		r.collectBlobs(rec)
		_ = r.jr.Done(rec)
		return failed(res, err)
	}
	last := u.LastActivity
	for _, f := range us.files {
		if t := time.Unix(0, f.Snap.MtimeNS).UTC(); t.After(last) {
			last = t
		}
	}
	name := capsule.GenName(n)
	man := capsule.Manifest{Format: capsule.FormatVersion, Kind: u.Kind, Harness: string(u.Harness), UnitKey: u.Key,
		UnitID: u.UnitID, VaultID: u.VaultID, RootIDs: append([]string(nil), u.RootIDs...), RootPath: r.rootPathOf(u),
		Gen: n, Parent: lp.Parent, Lineage: lp.Lineage, CreatedAt: r.now(), Sealer: r.e.Sealer,
		RecipientsFpr: us.recips.fpr, LastActivity: last}
	entry := us.entry(n, lp.Parent, lp.Lineage, last)
	entry.Snapshot = true
	spec := &commitSpec{
		rec: rec, unitDir: us.caps, outDir: us.caps, capsuleRel: name, name: name,
		logPath: logPathOf(store, u.Key, name), gen: n,
		// Blob entries carry no tar member: they travel in Dirs (see the
		// change request on capsule.SealRequest).
		req:          sealRequest{Manifest: man, Dirs: entries, Recipients: us.recips},
		entry:        entry,
		beforeRename: func() error { return r.hit("codex.manifest") },
	}
	if _, err := r.commit(ctx, spec); err != nil {
		if !keepRecord(err) {
			r.collectBlobs(rec)
			_ = r.jr.Done(rec)
		}
		return failed(res, err)
	}
	res.Gen, res.Lineage = n, lp.Lineage
	if keep {
		if err := r.writeSnapshotReceipt(u, us.bases, us.files, shas, blobOf, n, us.rd); err != nil {
			return failed(res, err)
		}
		_ = r.jr.Done(rec)
		res.Outcome = OutSealed
		res.Detail = "plaintext kept"
		return res
	}
	ur := r.unlinkFiles(ctx, u, us.bases, rec, false, unitSealPoints)
	ignored := r.pruneDirs(u, us.bases, rec)
	if err := r.rewriteReceiptBlobs(u, us.bases, rec, shas, blobOf, n, us.rd); err != nil {
		return failed(res, err)
	}
	if err := r.jr.Done(rec); err != nil {
		return failed(res, err)
	}
	res.Outcome = OutSealed
	if ur.removeFailed > 0 {
		res.Outcome, res.Class = OutRemoveFailed, fsx.ClassAccess
		res.Detail = fmt.Sprintf("%d file(s) could not be removed", ur.removeFailed)
	}
	return prunedDetail(res, ignored)
}

// collectBlobs removes the blobs an uncommitted snapshot wrote (CODX-1:
// orphan blobs are collected; their plaintext was never deleted).
func (r *run) collectBlobs(rec *journal.Record) {
	_, unitDir, err := r.openCapsDir(storeOfRecord(rec), rec.Unit, false)
	if err != nil {
		return
	}
	defer unitDir.Close()
	for _, jf := range rec.Files {
		if id := capsule.BaseID(jf.Base); id != baseBlob || !jf.Done {
			continue
		}
		lp := logPathOf(storeOfRecord(rec), rec.Unit, jf.Rel)
		_ = r.log.MarkDeleted(lp, r.now())
		_ = unitDir.Remove(jf.Rel)
	}
}

// rewriteReceiptBlobs is rewriteReceipt plus the blob map of snapshots.
func (r *run) rewriteReceiptBlobs(u harness.Unit, bases map[capsule.BaseID]dirHandle, rec *journal.Record, shas map[fileKey]string, blobOf map[string]string, gen uint64, old *receiptDisk) error {
	if err := r.rewriteReceipt(u.Key, u.Kind, string(u.Harness), bases, rec, shas, gen, old, u.Home.Bases); err != nil {
		return err
	}
	rd, ok, err := r.loadReceipt(u.Key)
	if err != nil || !ok {
		return err
	}
	rd.Blobs = map[string]string{}
	for _, f := range rd.Files {
		if b := blobOf[f.Rel]; b != "" {
			rd.Blobs[f.Rel] = b
		}
	}
	return r.writeReceipt(rd)
}

// writeSnapshotReceipt records every present file as sealed in snapshot
// gen (plaintext kept: reconcile, divergence).
func (r *run) writeSnapshotReceipt(u harness.Unit, bases map[capsule.BaseID]dirHandle, files []harness.File, shas map[fileKey]string, blobOf map[string]string, gen uint64, old *receiptDisk) error {
	rd := receiptDisk{Receipt: Receipt{Unit: u.Key, Gen: gen, RestoredAt: r.now()}, Kind: u.Kind, Harness: string(u.Harness),
		Bases: u.Home.Bases, Blobs: map[string]string{}}
	for _, f := range files {
		sum := shas[fileKey{f.Base, f.Rel}]
		if sum == "" {
			continue
		}
		rd.Files = append(rd.Files, ReceiptFile{Base: f.Base, Rel: f.Rel, Snap: f.Snap, SHA256: sum, Size: f.Snap.Size, FromGen: gen})
		if b := blobOf[f.Rel]; b != "" {
			rd.Blobs[f.Rel] = b
		}
	}
	return r.writeReceipt(rd)
}

// recoverCodexSnapshot finishes or rolls back a snapshot seal: a committed
// and logged manifest generation continues as committed; otherwise the
// in-flight capsule is handled like a seal's and every blob this
// operation committed is collected (CODX-1).
func (r *run) recoverCodexSnapshot(ctx context.Context, rec *journal.Record) *UnitResult {
	if !validKey(rec.Unit) {
		return recoveredResult(rec, capsule.KindCodexHome, OutFailed, codeUnitKey+": journal record with an invalid unit key")
	}
	lk, err := r.lockUnit(rec.Unit)
	if err != nil {
		if errors.Is(err, fsx.ErrLocked) {
			return nil
		}
		return recoveredResult(rec, capsule.KindCodexHome, OutFailed, failDetail(err))
	}
	defer lk.Unlock()
	store := storeOfRecord(rec)
	capsRoot, unitDir, err := r.openCapsDir(store, rec.Unit, false)
	if err != nil && !isMissing(err) {
		return recoveredResult(rec, capsule.KindCodexHome, OutFailed, failDetail(err))
	}
	if capsRoot != nil {
		defer capsRoot.Close()
		defer unitDir.Close()
	}
	if unitDir != nil && rec.Tmp != "" {
		// D58b: the journaled temporary of capsule.Seal, if a crash left it.
		if err := removeTmp(unitDir, rec.Tmp); err != nil {
			return recoveredResult(rec, capsule.KindCodexHome, OutFailed, failDetail(err))
		}
	}
	state, err := r.inspectCapsule(unitDir, rec.Capsule, logPathOf(store, rec.Unit, rec.Capsule))
	if err != nil {
		return recoveredResult(rec, capsule.KindCodexHome, OutFailed, failDetail(err))
	}
	_, isGen := capsule.ParseGenName(rec.Capsule)
	if state == capsOrphan && unitDir != nil {
		_ = unitDir.Remove(rec.Capsule)
	}
	if !(isGen && state == capsLogged) {
		// The snapshot never committed: the previous one stays
		// authoritative, the blobs of this attempt go, plaintext stays.
		if !isGen && state == capsLogged {
			rec.Files = append(rec.Files, journal.File{Base: string(baseBlob), Rel: rec.Capsule, Done: true})
		}
		r.collectBlobs(rec)
		return r.doneRecovered(rec, capsule.KindCodexHome, OutSkipped, "recovered: snapshot rolled back, plaintext kept")
	}
	var content []journal.File
	for _, jf := range rec.Files {
		if id := capsule.BaseID(jf.Base); id != baseBlob {
			content = append(content, jf)
		}
	}
	work := *rec
	work.Files = content
	bases, baseDirs, err := r.basesOfRecord(&work)
	if err != nil {
		return recoveredResult(rec, capsule.KindCodexHome, OutFailed, failDetail(err))
	}
	defer closeAll(bases)
	u := harness.Unit{Harness: harness.ID(rec.Harness), Kind: capsule.KindCodexHome, Key: rec.Unit, Home: harness.Home{Bases: baseDirs}}
	ur := r.unlinkFiles(ctx, u, bases, &work, false, unitSealPoints)
	rec.Files = append(work.Files, blobFilesOf(rec)...)
	old, hasOld, _ := r.loadReceipt(rec.Unit)
	var oldp *receiptDisk
	if hasOld {
		oldp = &old
	}
	if err := r.rewriteReceipt(rec.Unit, capsule.KindCodexHome, rec.Harness, bases, &work, nil, rec.Gen, oldp, baseDirs); err != nil {
		return recoveredResult(rec, capsule.KindCodexHome, OutFailed, failDetail(err))
	}
	o := OutSealed
	if ur.removeFailed > 0 {
		o = OutRemoveFailed
	}
	return r.doneRecovered(rec, capsule.KindCodexHome, o, "recovered: snapshot finished")
}

func blobFilesOf(rec *journal.Record) []journal.File {
	var out []journal.File
	for _, jf := range rec.Files {
		if id := capsule.BaseID(jf.Base); id == baseBlob {
			out = append(out, jf)
		}
	}
	return out
}

// snapshotBlobPaths lists the blob capsule paths of a snapshot plan from
// the refs index (so all keys are requested at once).
func (r *run) snapshotBlobPaths(p *restoreUnitPlan) []string {
	if !isSnapshotKind(p.ref.Kind) {
		return nil
	}
	keys := r.readRefs(p.ref.Key).Gens[strconv.FormatUint(p.newest.Gen, 10)]
	if len(keys) == 0 {
		return nil
	}
	all, err := r.log.All()
	if err != nil {
		return nil
	}
	want := map[string]bool{}
	for _, k := range keys {
		want[k] = true
	}
	var out []string
	for _, en := range all {
		if en.Blob && want[en.Unit] {
			out = append(out, en.Path)
		}
	}
	return out
}

// restoreSnapshot places exactly the authoritative snapshot of a Codex home,
// all-or-nothing through staging (SPEC §7.2). Plaintext that diverges from
// it makes the restore refuse (exit 4) after sealing that plaintext as a
// diverged generation, deleting nothing (R12, CODX-7).
func (r *run) restoreSnapshot(ctx, actx context.Context, p *restoreUnitPlan, a authenticated, man capsule.Manifest, kg *keyGuard, keys KeySource, req RestoreRequest, purpose string, aborted func() bool) UnitResult {
	res := planResult(p)
	entries, err := r.log.Unit(p.ref.Key)
	if err != nil {
		return failed(res, err)
	}
	authEntry, ok, divergedNewer := authoritativeSnapshot(entries)
	if divergedNewer {
		res.Outcome, res.Detail = OutConflict, codeConflict+": the home diverged from its snapshot (precinto codex reconcile)"
		return res
	}
	if !ok {
		return failed(res, fmt.Errorf("%w: no authoritative snapshot", ErrNotLogged))
	}
	if authEntry.Gen != p.newest.Gen {
		p.newest, p.entries = authEntry, []capslog.Entry{authEntry}
		if err := r.checkProvenance(authEntry); err != nil {
			return failed(res, err)
		}
		if err := r.fetchKeys(actx, keys, kg, []string{authEntry.Path}, purpose); err != nil {
			return failed(res, fmt.Errorf("%w: %s", ErrKeyDenied, safeMsg(err)))
		}
		m, err := r.readManifest(actx, authEntry, kg)
		if err != nil {
			return failed(res, err)
		}
		if err := checkManifest(m, authEntry); err != nil {
			return failed(res, err)
		}
		man = m
	}
	res.Gen = p.newest.Gen
	// A snapshot places all or nothing: a base the adapter reports unsafe
	// now (TargetRules.Skip) skips the whole unit, reported; the capsule
	// keeps it.
	for _, en := range man.Files {
		if why, skip := a.rules.Skip[en.Base]; skip {
			res.Outcome, res.Detail = OutSkipped, why
			if res.Detail == "" {
				res.Detail = "unsafe base"
			}
			return res
		}
	}
	check := entryCheck(a.rules)
	for _, en := range man.Files {
		if err := check(en); err != nil {
			return failed(res, err)
		}
		if en.Blob == "" || !validKey(en.Blob) {
			return failed(res, fmt.Errorf("%w: snapshot entry without a blob", capsule.ErrFormat))
		}
	}
	// Divergence: plaintext present that the receipt of this snapshot
	// does not cover.
	if div, err := r.codexDiverged(ctx, a, man); err != nil {
		return failed(res, err)
	} else if div != nil {
		sres := r.sealCodexLocked(ctx, a.ad, *div, Options{Reason: "codex-divergence"}, true, true, capsule.LineageDiverged)
		res.Outcome = OutConflict
		res.Detail = codeConflict + ": plaintext diverged from the snapshot; sealed as generation " + strconv.FormatUint(sres.Gen, 10)
		if sres.Outcome == OutFailed {
			res.Detail = codeConflict + ": plaintext diverged from the snapshot (" + sres.Detail + ")"
		}
		return res
	}
	blobEntries := map[string]capslog.Entry{}
	all, err := r.log.All()
	if err != nil {
		return failed(res, err)
	}
	for _, en := range all {
		if en.Blob {
			blobEntries[en.Unit] = en
		}
	}
	var need []capslog.Entry
	seen := map[string]bool{}
	for _, en := range man.Files {
		if seen[en.Blob] {
			continue
		}
		seen[en.Blob] = true
		be, ok := blobEntries[en.Blob]
		if !ok {
			return failed(res, fmt.Errorf("%w: a blob of the snapshot is not logged", ErrNotLogged))
		}
		if err := r.checkProvenance(be); err != nil {
			return failed(res, err)
		}
		need = append(need, be)
	}
	var blobPaths []string
	for _, be := range need {
		blobPaths = append(blobPaths, be.Path)
	}
	if err := r.fetchKeys(actx, keys, kg, blobPaths, purpose); err != nil {
		return failed(res, fmt.Errorf("%w: %s", ErrKeyDenied, safeMsg(err)))
	}
	var bytes int64
	for _, be := range need {
		bytes += be.Bytes
	}
	target := firstBase(a.rules.Bases)
	if target == "" {
		return failed(res, fmt.Errorf("%w: no target base", harness.ErrUnregistered))
	}
	perBase := map[capsule.BaseID]int64{}
	for _, en := range man.Files {
		perBase[en.Base] += en.Size
	}
	if err := r.checkRestoreSpace(a.rules.Bases, target, bytes, perBase); err != nil {
		res = failed(res, noSpace(err))
		res.Outcome = OutSkipped
		return res
	}
	rec, err := r.jr.Begin(journal.KindCodexRestore, string(p.ref.Harness), p.ref.Key)
	if err != nil {
		return failed(res, err)
	}
	st, err := r.p.fs.NewStaging(r.l.StagingDir, target, rec.ID)
	if err != nil {
		_ = r.jr.Done(rec)
		return failed(res, noSpace(err))
	}
	rec.Staging = st.Path()
	plan := &restorePlan{Kind: p.ref.Kind, Harness: string(p.ref.Harness), Unit: p.ref.Key, Gen: p.newest.Gen,
		VaultID: p.ref.VaultID, RootIDs: p.ref.RootIDs, Bases: a.rules.Bases, Snapshot: true, Blobs: map[string]string{},
		Quarantine: r.l.QuarantineDir, ConflictAt: r.now(), UnitID: a.unitID, HomeID: a.ref.HomeID}
	rollback := func(cause error, detail string) UnitResult {
		_ = r.removeStagings(st, plan)
		_ = r.jr.Done(rec)
		if cause != nil {
			return failed(res, cause)
		}
		res.Outcome, res.Detail = OutSkipped, detail
		return res
	}
	if err := r.jr.Save(rec); err != nil {
		return rollback(err, "")
	}
	if err := r.writePlan(st, plan); err != nil {
		return rollback(err, "")
	}
	type stagedRef struct {
		prefix string
		staged capsule.Staged
	}
	byRel := map[string]stagedRef{}
	for _, be := range need {
		if aborted() {
			return rollback(nil, "lock: rolled back before staging")
		}
		prefix := "b-" + be.Unit
		sub, err := r.subStaging(st, target, prefix)
		if err != nil {
			return rollback(noSpace(err), "")
		}
		bm, staged, err := r.extract(actx, be, kg, sub, check, target)
		if err != nil {
			if aborted() {
				return rollback(nil, "lock: rolled back before staging")
			}
			return rollback(noSpace(err), "")
		}
		kg.forget(be.Path) // decrypted: its key goes now (CC-17)
		if k, err := harness.UnitKeyFor(r.e.Harness.Salt, capsule.KindCodexBlob, harness.Codex, "", firstRoot(be.RootIDs, r), bm.UnitID); err != nil || k != be.Unit {
			return rollback(fmt.Errorf("%w: blob id does not match its key", harness.ErrUnitKey), "")
		}
		for _, s := range staged {
			byRel[s.Entry.Rel] = stagedRef{prefix: prefix, staged: s}
		}
	}
	for _, en := range man.Files {
		s, ok := byRel[en.Rel]
		if !ok || s.staged.Entry.SHA256 != en.SHA256 || s.staged.Entry.Size != en.Size {
			return rollback(fmt.Errorf("%w: snapshot and blob disagree", capsule.ErrFormat), "")
		}
		pol := harness.PlaceExact
		if a.rules.Policy != nil {
			pol = a.rules.Policy(en)
		}
		plan.Files = append(plan.Files, plannedFile{Base: en.Base, Rel: en.Rel, Staged: path.Join(s.prefix, s.staged.StagedRel),
			Policy: pol, Mode: en.Mode, MtimeNS: en.MtimeNS, Size: en.Size, SHA: en.SHA256, FromGen: p.newest.Gen, Group: en.Group})
		plan.Blobs[en.Rel] = en.Blob
	}
	sortPlacements(plan.Files)
	if err := r.splitDevices(st, plan, target); err != nil {
		return rollback(err, "")
	}
	if err := r.writePlan(st, plan); err != nil {
		return rollback(err, "")
	}
	if req.BeforePlace != nil {
		if err := req.BeforePlace(p.ref.Key); err != nil {
			return rollback(err, "")
		}
	}
	if aborted() {
		return rollback(nil, "lock: rolled back before staging")
	}
	out := r.stageAndPlace(ctx, st, plan, rec, a.ad)
	final := out.result(res)
	if out.conflicts > 0 && final.Outcome == OutConflict {
		// Databases never merge: a snapshot conflict refuses the launch.
		final.Detail = codeConflict + ": " + final.Detail
	}
	return final
}

// codexDiverged scans the home's plaintext: files the snapshot's receipt
// does not cover (new, changed, or from another generation) diverge,
// unless they are byte-identical to the snapshot. It returns the unit to
// seal as a diverged generation, or nil.
func (r *run) codexDiverged(ctx context.Context, a authenticated, man capsule.Manifest) (*harness.Unit, error) {
	if a.ad == nil {
		return nil, nil
	}
	rootID := firstRoot(man.RootIDs, r)
	units, err := a.ad.Scan(ctx, r.e.Harness, harness.Scope{RootIDs: []string{rootID}, Kinds: []capsule.Kind{capsule.KindCodexHome}})
	if err != nil {
		return nil, err
	}
	snap := map[string]capsule.Entry{}
	for _, en := range man.Files {
		snap[en.Rel] = en
	}
	rd, hasRc, err := r.loadReceipt(man.UnitKey)
	if err != nil {
		return nil, err
	}
	idx := receiptIndex(nil)
	if hasRc && rd.Gen == man.Gen {
		idx = receiptIndex(&rd)
	}
	for _, u := range units {
		if u.Key != man.UnitKey {
			continue
		}
		bases, err := r.openBases(u)
		if err != nil {
			return nil, err
		}
		present := map[string]bool{}
		for _, f := range u.Files {
			present[f.Rel] = true
		}
		diverged := false
		for _, f := range u.Files {
			if r.p.codexClass != nil {
				switch r.p.codexClass(f.Rel) {
				case codex.ClassSHM:
					continue
				case codex.ClassSQLiteSide:
					// A stray -wal/-journal without its database is moved to
					// quarantine when the snapshot is placed (CODX-2).
					if f.Group != "" && !present[f.Group] {
						continue
					}
				}
			}
			if rf := idx[fileKey{f.Base, f.Rel}]; rf != nil {
				if c, err := classifyFile(f, rf, dirHasher{bases: bases}); err == nil && c == classUnchanged {
					continue
				}
			}
			if en, ok := snap[f.Rel]; ok && en.Size == f.Snap.Size {
				if sum, err := hashPrefix(bases[f.Base], f.Rel, f.Snap.Size, nil); err == nil && sum == en.SHA256 {
					continue
				}
			}
			diverged = true
			break
		}
		closeAll(bases)
		if diverged {
			uu := u
			return &uu, nil
		}
	}
	return nil, nil
}

// ReconcileCodex resolves a per-root Codex home whose plaintext diverged
// from its newest snapshot (R12): the other side is kept as a retained
// generation; nothing is deleted.
func ReconcileCodex(ctx context.Context, e Env, keys KeySource, rootID string, prefer CodexPrefer) (*Report, error) {
	r := newRun(e, prodPorts(e))
	return r.reconcileCodex(ctx, keys, rootID, prefer)
}

func (r *run) reconcileCodex(ctx context.Context, keys KeySource, rootID string, prefer CodexPrefer) (*Report, error) {
	if prefer != PreferCapsule && prefer != PreferPlaintext {
		return r.finish(), fmt.Errorf("sweep: unknown reconcile preference %q", prefer)
	}
	if _, ok := r.e.Cfg.RootByID(rootID); !ok {
		return r.finish(), fmt.Errorf("%w: unknown folder", harness.ErrNotManaged)
	}
	r.recoverAll(ctx)
	ad := adapterFor(r.e, harness.Codex)
	if ad == nil {
		return r.finish(), fmt.Errorf("%w: codex", harness.ErrUnknownHarness)
	}
	key, err := harness.UnitKeyFor(r.e.Harness.Salt, capsule.KindCodexHome, harness.Codex, "", rootID, "")
	if err != nil {
		return r.finish(), err
	}
	units, err := ad.Scan(ctx, r.e.Harness, harness.Scope{RootIDs: []string{rootID}, Kinds: []capsule.Kind{capsule.KindCodexHome}})
	if err != nil {
		return r.finish(), err
	}
	var plain *harness.Unit
	for i := range units {
		if units[i].Key == key && len(units[i].Files) > 0 {
			plain = &units[i]
		}
	}
	lk, err := r.lockUnit(key)
	if err != nil {
		return r.finish(), err
	}
	// 1. Plaintext present: keep it as a retained generation first.
	if plain != nil {
		res := r.sealCodexLocked(ctx, ad, *plain, Options{Reason: "codex-reconcile"}, true, true, capsule.LineageDiverged)
		r.add(res)
		if res.Outcome != OutSealed && res.Outcome != OutUnchanged {
			lk.Unlock()
			return r.finish(), nil
		}
	}
	entries, err := r.log.Unit(key)
	if err != nil {
		lk.Unlock()
		return r.finish(), err
	}
	// 2. Re-commit the preferred side as the newest authoritative snapshot.
	var src capslog.Entry
	found := false
	for _, en := range entries {
		if en.Blob {
			continue
		}
		div := capsule.Lineage(en.Lineage) == capsule.LineageDiverged
		if (prefer == PreferPlaintext && div) || (prefer == PreferCapsule && !div) {
			if !found || en.Gen > src.Gen {
				src, found = en, true
			}
		}
	}
	if !found {
		lk.Unlock()
		r.add(UnitResult{Harness: string(harness.Codex), Kind: capsule.KindCodexHome, Unit: key, Outcome: OutSkipped, Detail: "nothing to reconcile"})
		return r.finish(), nil
	}
	res := r.recommitSnapshot(ctx, keys, src)
	r.add(res)
	lk.Unlock()
	if res.Outcome != OutSealed {
		return r.finish(), nil
	}
	if prefer == PreferCapsule && plain != nil {
		// The plaintext is retained in its generation: remove it, then put
		// the capsule side in place.
		u := *plain
		if lk2, err := r.lockUnit(key); err == nil {
			bases, err := r.openBases(u)
			if err == nil {
				rec := &journal.Record{}
				if jr, err := r.jr.Begin(journal.KindSeal, string(harness.Codex), key); err == nil {
					rec = jr
					us := &unitSeal{r: r, u: u, bases: bases, files: u.Files}
					rec.Files = us.journalFiles()
					rec.Capsule, rec.Gen = capsule.GenName(src.Gen), src.Gen
					if err := r.jr.Advance(rec, journal.PhaseCommitted); err == nil {
						r.unlinkFiles(ctx, u, bases, rec, false, unitSealPoints)
						r.pruneDirs(u, bases, rec)
					}
					_ = r.deleteReceipt(key)
					_ = r.jr.Done(rec)
				}
				closeAll(bases)
			}
			lk2.Unlock()
		}
		rep, err := r.restore(ctx, keys, RestoreRequest{Units: []harness.UnitRef{{Harness: harness.Codex, Kind: capsule.KindCodexHome, Key: key}}, Purpose: "restore"})
		return rep, err
	}
	return r.finish(), nil
}

// recommitSnapshot writes a new snapshot generation with the entries of
// src (blobs reused), lineage successor of src: it becomes the
// authoritative snapshot.
func (r *run) recommitSnapshot(ctx context.Context, keys KeySource, src capslog.Entry) UnitResult {
	res := UnitResult{Harness: string(harness.Codex), Kind: capsule.KindCodexHome, Unit: src.Unit}
	if keys == nil {
		return failed(res, fmt.Errorf("%w: no key source", ErrKeyDenied))
	}
	if err := r.checkProvenance(src); err != nil {
		return failed(res, err)
	}
	kg := &keyGuard{}
	defer kg.destroy()
	fk, err := keys.FileKeys(ctx, []string{src.Path}, "restore") // one capsule (≤ maxKeysPerRequest)
	if err != nil {
		return failed(res, fmt.Errorf("%w: %s", ErrKeyDenied, safeMsg(err)))
	}
	kg.add(fk)
	m, err := r.readManifest(ctx, src, kg)
	if err != nil {
		return failed(res, err)
	}
	if err := checkManifest(m, src); err != nil {
		return failed(res, err)
	}
	recips, err := r.p.vaults.recipients(src.VaultID)
	if err != nil {
		return failed(res, err)
	}
	capsRoot, caps, err := r.openCapsDir(src.Harness, src.Unit, true)
	if err != nil {
		return failed(res, err)
	}
	defer capsRoot.Close()
	defer caps.Close()
	n, err := r.nextGen(ctx, src.Unit, caps)
	if err != nil {
		return failed(res, err)
	}
	refs := r.readRefs(src.Unit)
	var keysOf []string
	for _, en := range m.Files {
		keysOf = append(keysOf, en.Blob)
	}
	refs.Gens[strconv.FormatUint(n, 10)] = dedupe(keysOf)
	if err := r.writeRefs(src.Unit, refs); err != nil {
		return failed(res, err)
	}
	rec, err := r.jr.Begin(journal.KindCodexSnapshot, src.Harness, src.Unit)
	if err != nil {
		return failed(res, err)
	}
	name := capsule.GenName(n)
	man := m
	man.Files = nil
	man.Gen, man.Parent, man.Lineage, man.CreatedAt, man.Sealer, man.RecipientsFpr = n, src.Gen, capsule.LineageSuccessor, r.now(), r.e.Sealer, recips.fpr
	en := src
	en.Path, en.Gen, en.Parent, en.Lineage, en.SealedAt, en.RecipientsFpr = "", n, src.Gen, string(capsule.LineageSuccessor), r.now(), recips.fpr
	spec := &commitSpec{rec: rec, unitDir: caps, outDir: caps, capsuleRel: name, name: name,
		logPath: logPathOf(src.Harness, src.Unit, name), gen: n,
		req:   sealRequest{Manifest: man, Dirs: m.Files, Recipients: recips},
		entry: en, beforeRename: func() error { return r.hit("codex.manifest") }}
	if _, err := r.commit(ctx, spec); err != nil {
		if !keepRecord(err) {
			_ = r.jr.Done(rec)
		}
		return failed(res, err)
	}
	_ = r.jr.Done(rec)
	res.Outcome, res.Gen, res.Lineage = OutSealed, n, capsule.LineageSuccessor
	return res
}
