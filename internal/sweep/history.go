package sweep

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/precinto/precinto/internal/capsule"
	"github.com/precinto/precinto/internal/fsx"
	"github.com/precinto/precinto/internal/harness"
	"github.com/precinto/precinto/internal/sweep/capslog"
	"github.com/precinto/precinto/internal/sweep/journal"
)

const (
	historyRel    = "history.jsonl"
	pasteCacheDir = "paste-cache"
	// maxHistoryBytes bounds what one rotation reads into memory.
	maxHistoryBytes = 1 << 30
	globalClaudeLk  = "global-claude-code"
)

// maxTailRanges bounds one run of the tail loop: a writer that never
// pauses leaves the rotation at rewritten, and the next sweep's recovery
// resumes it from the journaled offset (ports.maxTail lowers it in tests).
const maxTailRanges = 1000

// errTailBusy stops a tail loop whose hold inode keeps growing.
var errTailBusy = errors.New("sweep: history is still being appended; the next sweep resumes the rotation")

// RotateHistory extracts protected-root lines of Claude's history.jsonl
// into per-root history generations with the hold-link protocol (D21, D36,
// SPEC §7.1.4). Only when no Claude process is running anywhere.
func RotateHistory(ctx context.Context, e Env) (*Report, error) {
	r := newRun(e, prodPorts(e))
	if err := ctx.Err(); err != nil {
		return r.finish(), err
	}
	r.recoverAll(ctx)
	if r.primeHistory(ctx) {
		r.waitQuiet(ctx, time.Time{}) // D63: one look, one quiet window, then decide
	}
	r.rotateHistory(ctx)
	return r.finish(), nil
}

// rotateHistory rotates every registered Claude home.
func (r *run) rotateHistory(ctx context.Context) {
	ad := adapterFor(r.e, harness.ClaudeCode)
	if ad == nil {
		return
	}
	homes, err := ad.Homes(ctx, r.e.Harness)
	if err != nil {
		r.add(failed(UnitResult{Harness: string(harness.ClaudeCode), Kind: capsule.KindClaudeHistory}, err))
		return
	}
	for _, h := range homes {
		if ctx.Err() != nil {
			return
		}
		if res := r.rotateHome(ctx, ad, h); res != nil {
			r.add(*res)
		}
	}
}

// historyJournalKey is the journal unit of a home's rotation (a global
// store key of the history file itself, so two rotations of one home
// conflict).
func (r *run) historyJournalKey(h harness.Home) (string, error) {
	return harness.UnitKeyFor(r.e.Harness.Salt, capsule.KindGlobalStore, harness.ClaudeCode, h.ID, "", historyRel)
}

// histSplit is one range of history.jsonl split by root.
type histSplit struct {
	byRoot map[string][][]byte // root id → extracted lines (no '\n')
	kept   [][]byte
	keptN  int64           // bytes of kept lines including their '\n'
	paste  map[string]bool // paste-cache entries referenced only by extracted lines
}

// splitHistory filters complete lines: a line whose project lies inside a
// root belongs to the deepest such root (D36); everything else, invalid
// lines included, is kept.
func (r *run) splitHistory(data []byte) histSplit {
	s := histSplit{byRoot: map[string][][]byte{}, paste: map[string]bool{}}
	keptRefs := map[string]bool{}
	extRefs := map[string]bool{}
	for _, line := range splitLines(data) {
		var hl harnessHistoryLine
		if r.p.historyLine != nil {
			h := r.p.historyLine(line)
			hl = harnessHistoryLine{project: h.Project, refs: h.PasteRefs, valid: h.Valid}
		}
		if hl.valid && hl.project != "" && filepath.IsAbs(hl.project) {
			if root, ok := r.e.Cfg.RootFor(hl.project); ok {
				s.byRoot[root.ID] = append(s.byRoot[root.ID], line)
				for _, p := range hl.refs {
					extRefs[p] = true
				}
				continue
			}
		}
		s.kept = append(s.kept, line)
		s.keptN += int64(len(line)) + 1
		for _, p := range hl.refs {
			keptRefs[p] = true
		}
	}
	for p := range extRefs {
		if !keptRefs[p] && cleanRel(p) && path.Base(p) == p {
			s.paste[p] = true
		}
	}
	return s
}

type harnessHistoryLine struct {
	project string
	refs    []string
	valid   bool
}

// completePrefix returns the length of data up to and including its last
// '\n' (a torn last line waits for the tail loop).
func completePrefix(data []byte) int {
	return bytes.LastIndexByte(data, '\n') + 1
}

// shellSnapshotsDir holds Claude's environment dumps (SPEC §7.1.1).
const shellSnapshotsDir = "shell-snapshots"

// pruneShellSnapshots deletes stale $CC/shell-snapshots/*.sh — environment
// dumps left by crashes — older than one day and open by no process; they
// are never sealed (SPEC §7.1.1). The caller established that no Claude
// process runs. Any doubt (unreadable process table, changed file) keeps
// the file.
func (r *run) pruneShellSnapshots(ctx context.Context, base dirHandle) {
	ents, err := base.ReadDir(shellSnapshotsDir)
	if err != nil || len(ents) == 0 || r.e.Procs == nil {
		return
	}
	dir := filepath.Join(base.Path(), shellSnapshotsDir)
	holders, err := r.e.Procs.OpenFilesUnder(ctx, []string{dir})
	if err != nil {
		return
	}
	open := map[string]bool{}
	for _, h := range holders {
		open[filepath.Clean(h.Path)] = true
	}
	cutoff := r.now().Add(-24 * time.Hour)
	for _, e := range ents {
		if e.Type != fsx.TypeRegular || !strings.HasSuffix(e.Name, ".sh") || e.Stat.Nlink != 1 {
			continue
		}
		if !time.Unix(0, e.Stat.MtimeNS).Before(cutoff) || open[filepath.Join(dir, e.Name)] {
			continue
		}
		_ = base.UnlinkIfUnchanged(path.Join(shellSnapshotsDir, e.Name), e.Stat)
	}
}

// rotation is one rotation of one home.
type rotation struct {
	r      *run
	ad     harness.Adapter
	h      harness.Home
	rec    *journal.Record
	base   dirHandle
	cfgDir string
}

// rotateHome runs the protocol for one home if its history holds lines of
// protected roots and no Claude process runs.
func (r *run) rotateHome(ctx context.Context, ad harness.Adapter, h harness.Home) *UnitResult {
	cfgDir := h.Bases[capsule.BaseClaudeConfig]
	if cfgDir == "" {
		return nil
	}
	jkey, err := r.historyJournalKey(h)
	if err != nil {
		return nil
	}
	res := UnitResult{Harness: string(harness.ClaudeCode), Kind: capsule.KindClaudeHistory, Unit: jkey}
	lk, err := r.lockName(globalClaudeLk)
	if err != nil {
		res.Outcome, res.Detail = OutSkipped, "busy: another rotation runs"
		return &res
	}
	defer lk.Unlock()
	pseudo, _ := r.historySubject(h)
	if v, isLive := r.checkLive(ctx, ad, pseudo, nil); isLive {
		res = liveResult(res, v, false, "")
		res.Detail = "history_pending: " + res.Detail
		return &res
	}
	base, err := r.p.fs.OpenBase(cfgDir)
	if err != nil {
		f := failed(res, err)
		return &f
	}
	defer base.Close()
	r.pruneShellSnapshots(ctx, base)
	st, err := base.Lstat(historyRel)
	if err != nil {
		if isMissing(err) {
			return nil
		}
		f := failed(res, err)
		return &f
	}
	if !st.IsRegular() || st.Nlink != 1 {
		res.Outcome, res.Detail = OutSkipped, "history file is not a plain file"
		return &res
	}
	data, _, err := readAllBounded(base, historyRel, maxHistoryBytes)
	if err != nil {
		f := failed(res, err)
		return &f
	}
	if len(r.splitHistory(data[:completePrefix(data)]).byRoot) == 0 {
		return nil // nothing protected: never rewrite the file
	}
	rec, err := r.jr.Begin(journal.KindHistoryRotate, string(harness.ClaudeCode), jkey)
	if err != nil {
		f := failed(res, err)
		return &f
	}
	rec.Files = []journal.File{{Base: string(capsule.BaseClaudeConfig), Dir: cfgDir, Rel: historyRel, Snap: st}}
	rec.Hold = ".precinto-hold-" + rec.ID
	if err := r.jr.Save(rec); err != nil {
		_ = r.jr.Done(rec)
		f := failed(res, err)
		return &f
	}
	ro := &rotation{r: r, ad: ad, h: h, rec: rec, base: base, cfgDir: cfgDir}
	return ro.run(ctx)
}

// run executes the protocol from the record's last milestone (fresh
// rotations and recovery share it).
func (ro *rotation) run(ctx context.Context) *UnitResult {
	r, rec := ro.r, ro.rec
	res := UnitResult{Harness: string(harness.ClaudeCode), Kind: capsule.KindClaudeHistory, Unit: rec.Unit}
	fail := func(err error) *UnitResult {
		f := failed(res, err)
		return &f
	}
	if rec.Phase == journal.PhasePrepared {
		// Step 2: hold the inode.
		if err := ro.base.Link(historyRel, rec.Hold); err != nil {
			return fail(err)
		}
		rec.HoldSize = rec.Files[0].Snap.Size
		if err := r.jr.Advance(rec, journal.PhaseHeld); err != nil {
			return fail(err)
		}
		if err := r.hit("history.held"); err != nil {
			return fail(err)
		}
	}
	if rec.Phase == journal.PhaseHeld {
		// Step 3: tail reconcile before the rename — seal every extracted
		// line of [0, S1) first.
		data, _, err := readAllBounded(ro.base, rec.Hold, maxHistoryBytes)
		if err != nil {
			return fail(err)
		}
		s1 := int64(completePrefix(data))
		split := r.splitHistory(data[:s1])
		paste, err := ro.pasteFiles(split.paste)
		if err != nil {
			return fail(err)
		}
		if _, err := ro.sealLines(ctx, split.byRoot, paste); err != nil {
			return fail(err)
		}
		rec.Files = append(rec.Files[:1], paste...)
		rec.Pending = s1
		if err := r.jr.Advance(rec, journal.PhaseSealed); err != nil {
			return fail(err)
		}
		if err := r.hit("history.sealed"); err != nil {
			return fail(err)
		}
	}
	if rec.Phase == journal.PhaseSealed {
		// Step 4: rename the kept lines in — unless that already happened.
		hold, err := ro.base.Lstat(rec.Hold)
		if err != nil {
			return fail(err)
		}
		cur, err := ro.base.Lstat(historyRel)
		renamed := err == nil && !cur.SameFile(hold) || err != nil && isMissing(err)
		if err != nil && !isMissing(err) {
			return fail(err)
		}
		data, _, err := readAllBounded(ro.base, rec.Hold, maxHistoryBytes)
		if err != nil {
			return fail(err)
		}
		if int64(len(data)) < rec.Pending {
			return fail(fmt.Errorf("%w: hold shorter than its journaled offset", fsx.ErrChanged))
		}
		split := r.splitHistory(data[:rec.Pending])
		if !renamed {
			if err := ro.rewrite(split.kept); err != nil {
				return fail(err)
			}
			if err := r.hit("history.renamed"); err != nil {
				return fail(err)
			}
		}
		rec.Offset = rec.Pending
		rec.NewBase = split.keptN
		if err := r.jr.Advance(rec, journal.PhaseRewritten); err != nil {
			return fail(err)
		}
	}
	if rec.Phase == journal.PhaseRewritten {
		if err := ro.tail(ctx); err != nil {
			if errors.Is(err, errTailBusy) {
				// The record stays at rewritten: recovery resumes the tail.
				res.Outcome, res.Detail = OutSkipped, "history_pending: still being appended"
				return &res
			}
			return fail(err)
		}
		// Step 6: extracted paste-cache files and the hold go.
		for _, jf := range rec.Files[1:] {
			if err := ro.base.UnlinkIfUnchanged(jf.Rel, jf.Snap); err != nil && !isMissing(err) {
				res.Detail = "a paste-cache entry changed and stays"
			}
		}
		if err := ro.base.Remove(rec.Hold); err != nil && !isMissing(err) {
			return fail(err)
		}
		if err := r.jr.Done(rec); err != nil {
			return fail(err)
		}
		res.Outcome = OutSealed
		return &res
	}
	return fail(fmt.Errorf("sweep: history rotation in unexpected phase %s", rec.Phase))
}

// pasteFiles snapshots the paste-cache entries to move with the lines.
func (ro *rotation) pasteFiles(names map[string]bool) ([]journal.File, error) {
	var out []journal.File
	var sorted []string
	for n := range names {
		sorted = append(sorted, n)
	}
	sort.Strings(sorted)
	for _, n := range sorted {
		rel := path.Join(pasteCacheDir, n)
		st, err := ro.base.Lstat(rel)
		if err != nil {
			if isMissing(err) {
				continue
			}
			return nil, err
		}
		if !st.IsRegular() || st.Nlink != 1 {
			continue
		}
		out = append(out, journal.File{Base: string(capsule.BaseClaudeConfig), Dir: ro.cfgDir, Rel: rel, Snap: st})
	}
	return out, nil
}

// sealLines commits one history generation per root holding lines
// (successor of that root's newest history generation). Paste files go
// with the root whose lines reference them; here every extracted entry
// is referenced only by extracted lines, so each root gets the entries
// its lines name.
func (ro *rotation) sealLines(ctx context.Context, byRoot map[string][][]byte, paste []journal.File) (int, error) {
	r := ro.r
	ids := make([]string, 0, len(byRoot))
	for id := range byRoot {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	sealed := 0
	for _, id := range ids {
		lines := byRoot[id]
		var mine []journal.File
		refs := map[string]bool{}
		for _, l := range lines {
			if r.p.historyLine != nil {
				for _, p := range r.p.historyLine(l).PasteRefs {
					refs[p] = true
				}
			}
		}
		for _, pf := range paste {
			if refs[path.Base(pf.Rel)] {
				mine = append(mine, pf)
			}
		}
		if _, err := ro.sealRoot(ctx, id, lines, mine); err != nil {
			return sealed, err
		}
		sealed++
	}
	return sealed, nil
}

// sealRoot commits one claude-history generation of a root: the lines as a
// history.jsonl member (read through an already unlinked temporary, so no
// extra plaintext copy outlives the seal) plus its paste-cache entries.
func (ro *rotation) sealRoot(ctx context.Context, rootID string, lines [][]byte, paste []journal.File) (uint64, error) {
	r := ro.r
	key, err := harness.UnitKeyFor(r.e.Harness.Salt, capsule.KindClaudeHistory, harness.ClaudeCode, ro.h.ID, rootID, "")
	if err != nil {
		return 0, err
	}
	lk, err := r.lockUnit(key)
	if err != nil {
		return 0, err
	}
	defer lk.Unlock()
	recips, err := r.p.vaults.recipients(rootID)
	if err != nil {
		return 0, err
	}
	if err := ensurePrivateDir(r.l.StagingDir); err != nil {
		return 0, err
	}
	sdir, err := r.p.fs.OpenBase(r.l.StagingDir)
	if err != nil {
		return 0, err
	}
	defer sdir.Close()
	tmp, name, err := sdir.CreateTemp(".", ".history-lines-*")
	if err != nil {
		return 0, err
	}
	defer tmp.Close()
	removed := false
	defer func() {
		if !removed {
			_ = sdir.Remove(name)
		}
	}()
	var n int64
	for _, l := range lines {
		w, err := tmp.Write(append(append([]byte(nil), l...), '\n'))
		if err != nil {
			return 0, err
		}
		n += int64(w)
	}
	if err := fsx.FullSync(tmp); err != nil {
		return 0, err
	}
	if err := sdir.Remove(name); err != nil {
		return 0, err
	}
	removed = true
	if _, err := tmp.Seek(0, io.SeekStart); err != nil {
		return 0, err
	}
	tst, err := fsx.Fstat(tmp)
	if err != nil {
		return 0, err
	}
	inputs := []sealInput{{Base: capsule.BaseClaudeConfig, Dir: sdir, Rel: historyRel, Snap: tst, Open: tmp, Append: true,
		Path: filepath.Join(ro.cfgDir, historyRel)}}
	bytesN := n
	for _, pf := range paste {
		inputs = append(inputs, sealInput{Base: capsule.BaseClaudeConfig, Dir: ro.base, Rel: pf.Rel, Snap: pf.Snap,
			Path: filepath.Join(ro.cfgDir, filepath.FromSlash(pf.Rel))})
		bytesN += pf.Snap.Size
	}
	capsRoot, caps, err := r.openCapsDir(string(harness.ClaudeCode), key, true)
	if err != nil {
		return 0, err
	}
	defer capsRoot.Close()
	defer caps.Close()
	entries, err := r.log.Unit(key)
	if err != nil {
		return 0, err
	}
	parent, lineage := uint64(0), capsule.LineageFresh
	if ne, ok := newestEntry(entries); ok {
		parent, lineage = ne.Gen, capsule.LineageSuccessor
	}
	g, err := r.nextGen(ctx, key, caps)
	if err != nil {
		return 0, err
	}
	rec, err := r.jr.Begin(journal.KindSeal, string(harness.ClaudeCode), key)
	if err != nil {
		return 0, err
	}
	gname := capsule.GenName(g)
	root, _ := r.e.Cfg.RootByID(rootID)
	man := capsule.Manifest{Format: capsule.FormatVersion, Kind: capsule.KindClaudeHistory, Harness: string(harness.ClaudeCode),
		UnitKey: key, UnitID: rootID, VaultID: rootID, RootIDs: []string{rootID}, RootPath: root.Path, Gen: g, Parent: parent,
		Lineage: lineage, CreatedAt: r.now(), Sealer: r.e.Sealer, RecipientsFpr: recips.fpr, LastActivity: r.now()}
	spec := &commitSpec{rec: rec, unitDir: caps, outDir: caps, capsuleRel: gname, name: gname,
		logPath: logPathOf(string(harness.ClaudeCode), key, gname), gen: g,
		req: sealRequest{Manifest: man, Inputs: inputs, Recipients: recips},
		entry: capslog.Entry{V: capslog.Version, Kind: string(capsule.KindClaudeHistory), Harness: string(harness.ClaudeCode),
			Unit: key, VaultID: rootID, RootIDs: []string{rootID}, Gen: g, Parent: parent, Lineage: string(lineage),
			SealedAt: r.now(), RecipientsFpr: recips.fpr, Files: len(inputs), Bytes: bytesN, LastActivity: r.now()}}
	if _, err := r.commit(ctx, spec); err != nil {
		if !keepRecord(err) {
			_ = r.jr.Done(rec)
		}
		return 0, err
	}
	if err := r.jr.Done(rec); err != nil {
		return 0, err
	}
	return g, nil
}

// rewrite writes the kept lines to a temporary (0600) next to
// history.jsonl and renames it over the file (step 4).
func (ro *rotation) rewrite(kept [][]byte) error {
	f, name, err := ro.base.CreateTemp(".", ".history.jsonl.tmp-*")
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		if !ok {
			f.Close()
			_ = ro.base.Remove(name)
		}
	}()
	for _, l := range kept {
		if _, err := f.Write(append(append([]byte(nil), l...), '\n')); err != nil {
			return err
		}
	}
	if err := fsx.FullSync(f); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := ro.base.Rename(name, historyRel, fsx.Replace); err != nil {
		return err
	}
	ok = true
	return nil
}

// tail is step 5: late appends through descriptors opened before the
// rename land in the hold inode; each range [offset, EOF) is sealed and
// its kept lines appended with line-union semantics after new_base, then
// the offset is journaled, until nothing arrives for tailQuiet.
func (ro *rotation) tail(ctx context.Context) error {
	r, rec := ro.r, ro.rec
	quietFor := time.Duration(0)
	step := min(100*time.Millisecond, max(r.p.tailQuiet, time.Millisecond))
	limit := maxTailRanges
	if r.p.maxTail > 0 && r.p.maxTail < limit {
		limit = r.p.maxTail
	}
	for ranges := 0; ; {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if ranges >= limit {
			return errTailBusy
		}
		st, err := ro.base.Lstat(rec.Hold)
		if err != nil {
			return err
		}
		if st.Size <= rec.Offset {
			if quietFor >= r.p.tailQuiet {
				return nil
			}
			if err := r.p.sleep(ctx, step); err != nil {
				return err
			}
			quietFor += step
			continue
		}
		data, _, err := readAllBounded(ro.base, rec.Hold, maxHistoryBytes)
		if err != nil {
			return err
		}
		if int64(len(data)) <= rec.Offset {
			continue
		}
		chunk := data[rec.Offset:]
		end := completePrefix(chunk)
		if end == 0 {
			// Only a torn line so far: wait for the rest; once quiet, keep
			// it as its own line (bytes are never dropped).
			if quietFor < r.p.tailQuiet {
				if err := r.p.sleep(ctx, step); err != nil {
					return err
				}
				quietFor += step
				continue
			}
			chunk = append(append([]byte(nil), chunk...), '\n')
			end = len(chunk)
		}
		quietFor = 0
		ranges++
		rec.Pending = rec.Offset + int64(end)
		if end > len(data[rec.Offset:]) {
			rec.Pending = int64(len(data))
		}
		if err := r.jr.Save(rec); err != nil {
			return err
		}
		split := r.splitHistory(chunk[:end])
		if len(split.byRoot) > 0 {
			paste, err := ro.pasteFiles(split.paste)
			if err != nil {
				return err
			}
			if _, err := ro.sealLines(ctx, split.byRoot, paste); err != nil {
				return err
			}
			rec.Files = append(rec.Files, paste...)
		}
		if err := ro.appendKept(split.kept); err != nil {
			return err
		}
		if err := r.hit("history.tail"); err != nil {
			return err
		}
		rec.Offset = rec.Pending
		if err := r.jr.Save(rec); err != nil {
			return err
		}
	}
}

// appendKept appends kept lines to history.jsonl with O_APPEND relative to
// the Claude home's directory handle (fsx.Dir.AppendLine: never through a
// symlink, never a FIFO, CC-05), skipping lines already present
// byte-for-byte after new_base (line union: a re-run never appends a line
// twice, HIST-4).
func (ro *rotation) appendKept(kept [][]byte) error {
	if len(kept) == 0 {
		return nil
	}
	data, _, err := readAllBounded(ro.base, historyRel, maxHistoryBytes)
	if err != nil && !isMissing(err) {
		return err
	}
	have := map[string]bool{}
	if int64(len(data)) > ro.rec.NewBase {
		for _, l := range splitLines(data[ro.rec.NewBase:]) {
			have[string(l)] = true
		}
	}
	if len(data) > 0 && data[len(data)-1] != '\n' {
		if err := ro.base.AppendLine(historyRel, nil); err != nil {
			return err
		}
	}
	for _, l := range kept {
		if have[string(l)] || len(l) > fsx.MaxLine {
			continue
		}
		if err := ro.base.AppendLine(historyRel, l); err != nil {
			return err
		}
		have[string(l)] = true
	}
	return nil
}

// recoverHistory resumes a rotation from its last milestone (SPEC §7.1.4
// recovery): prepared removes a hold link naming the recorded inode and
// changes nothing else; held redoes step 3; sealed redoes step 4 unless
// the rename happened (then journals rewritten with offset = pending);
// rewritten resumes the tail loop.
func (r *run) recoverHistory(ctx context.Context, rec *journal.Record) *UnitResult {
	res := UnitResult{Harness: rec.Harness, Kind: capsule.KindClaudeHistory, Unit: rec.Unit}
	lk, err := r.lockName(globalClaudeLk)
	if err != nil {
		if errors.Is(err, fsx.ErrLocked) {
			return nil
		}
		f := failed(res, err)
		return &f
	}
	defer lk.Unlock()
	if len(rec.Files) == 0 {
		return r.doneRecovered(rec, capsule.KindClaudeHistory, OutSkipped, "recovered: nothing held")
	}
	id, cfgDir := capsule.BaseID(rec.Files[0].Base), rec.Files[0].Dir
	if id != capsule.BaseClaudeConfig || cfgDir == "" {
		f := failed(res, fmt.Errorf("%w: malformed history record", fsx.ErrUnsafe))
		return &f
	}
	base, err := r.p.fs.OpenBase(cfgDir)
	if err != nil {
		f := failed(res, err)
		return &f
	}
	defer base.Close()
	if rec.Phase == journal.PhasePrepared {
		if rec.Hold != "" {
			if st, err := base.Lstat(rec.Hold); err == nil && st.SameFile(rec.Files[0].Snap) {
				if err := base.Remove(rec.Hold); err != nil && !isMissing(err) {
					f := failed(res, err)
					return &f
				}
			}
		}
		return r.doneRecovered(rec, capsule.KindClaudeHistory, OutSkipped, "recovered: rotation not started")
	}
	if _, err := base.Lstat(rec.Hold); err != nil {
		f := failed(res, fmt.Errorf("%w: hold link missing", fsx.ErrChanged))
		return &f
	}
	h := harness.Home{Harness: harness.ClaudeCode, Bases: map[capsule.BaseID]string{capsule.BaseClaudeConfig: cfgDir}}
	if ad := adapterFor(r.e, harness.ClaudeCode); ad != nil {
		if homes, err := ad.Homes(ctx, r.e.Harness); err == nil {
			for _, hh := range homes {
				if hh.Bases[capsule.BaseClaudeConfig] == cfgDir {
					h = hh
				}
			}
		}
	}
	if h.ID == "" {
		f := failed(res, fmt.Errorf("%w: the rotated home is no longer registered", harness.ErrUnregistered))
		return &f
	}
	ro := &rotation{r: r, ad: adapterFor(r.e, harness.ClaudeCode), h: h, rec: rec, base: base, cfgDir: cfgDir}
	out := ro.run(ctx)
	if out != nil && out.Outcome == OutSealed {
		out.Detail = "recovered: rotation finished"
	}
	return out
}

// MergeHistory appends a root's sealed history lines that are not already
// present byte-for-byte (idempotent), restoring referenced paste-cache
// entries (SPEC §7.1.4).
func MergeHistory(ctx context.Context, e Env, keys KeySource, rootID string) (*Report, error) {
	r := newRun(e, prodPorts(e))
	if err := ctx.Err(); err != nil {
		return r.finish(), err
	}
	r.recoverAll(ctx)
	r.mergeHistory(ctx, keys, rootID)
	return r.finish(), nil
}

func (r *run) mergeHistory(ctx context.Context, keys KeySource, rootID string) {
	ad := adapterFor(r.e, harness.ClaudeCode)
	if ad == nil {
		return
	}
	if _, ok := r.e.Cfg.RootByID(rootID); !ok {
		r.add(UnitResult{Harness: string(harness.ClaudeCode), Kind: capsule.KindClaudeHistory, Outcome: OutFailed,
			Detail: codeFailed + ": unknown folder"})
		return
	}
	homes, err := ad.Homes(ctx, r.e.Harness)
	if err != nil {
		r.add(failed(UnitResult{Harness: string(harness.ClaudeCode), Kind: capsule.KindClaudeHistory}, err))
		return
	}
	for _, h := range homes {
		key, err := harness.UnitKeyFor(r.e.Harness.Salt, capsule.KindClaudeHistory, harness.ClaudeCode, h.ID, rootID, "")
		if err != nil {
			continue
		}
		entries, err := r.log.Unit(key)
		if err != nil || len(entries) == 0 {
			continue
		}
		r.add(r.mergeHome(ctx, keys, h, key, rootID, entries))
	}
}

// mergeHome merges every history generation of one (home, root).
func (r *run) mergeHome(ctx context.Context, keys KeySource, h harness.Home, key, rootID string, entries []capslog.Entry) UnitResult {
	res := UnitResult{Harness: string(harness.ClaudeCode), Kind: capsule.KindClaudeHistory, Unit: key}
	cfgDir := h.Bases[capsule.BaseClaudeConfig]
	if cfgDir == "" || keys == nil {
		return failed(res, fmt.Errorf("%w: no home or key source", ErrKeyDenied))
	}
	lk, err := r.lockUnit(key)
	if err != nil {
		return failed(res, err)
	}
	defer lk.Unlock()
	var paths []string
	for _, en := range entries {
		if err := r.checkProvenance(en); err != nil {
			return failed(res, err)
		}
		paths = append(paths, en.Path)
	}
	kg := &keyGuard{}
	defer kg.destroy()
	if err := r.fetchKeys(ctx, keys, kg, paths, "restore"); err != nil {
		return failed(res, fmt.Errorf("%w: %s", ErrKeyDenied, safeMsg(err)))
	}
	rules := harness.TargetRules{Bases: map[capsule.BaseID]string{capsule.BaseClaudeConfig: cfgDir},
		Allow: func(b capsule.BaseID, rel string) bool {
			if b != capsule.BaseClaudeConfig {
				return false
			}
			if rel == historyRel {
				return true
			}
			dir, name := path.Split(rel)
			return dir == pasteCacheDir+"/" && name != "" && cleanRel(rel)
		}}
	for _, en := range entries {
		m, err := r.readManifest(ctx, en, kg)
		if err != nil {
			return failed(res, err)
		}
		if err := checkManifest(m, en); err != nil {
			return failed(res, err)
		}
		k, err := harness.UnitKeyFor(r.e.Harness.Salt, capsule.KindClaudeHistory, harness.ClaudeCode, h.ID, rootID, m.UnitID)
		if err != nil || k != key {
			return failed(res, fmt.Errorf("%w: history unit id does not match its key", harness.ErrUnitKey))
		}
	}
	rec, err := r.jr.Begin(journal.KindHistoryMerge, string(harness.ClaudeCode), key)
	if err != nil {
		return failed(res, err)
	}
	if err := ensurePrivateDir(r.l.StagingDir); err != nil {
		_ = r.jr.Done(rec)
		return failed(res, err)
	}
	st, err := r.p.fs.NewStaging(r.l.StagingDir, cfgDir, rec.ID)
	if err != nil {
		_ = r.jr.Done(rec)
		return failed(res, noSpace(err))
	}
	rec.Staging = st.Path()
	_ = r.jr.Save(rec)
	defer func() {
		_ = st.Remove()
		_ = r.jr.Done(rec)
	}()
	var lines [][]byte
	type pasteVersion struct {
		dir  dirHandle
		rel  string
		size int64
		sha  string
		mode uint32
		mt   int64
	}
	paste := map[string]pasteVersion{}
	for _, en := range entries {
		sub, err := r.p.fs.NewStaging(st.Path(), cfgDir, "g"+strconv.FormatUint(en.Gen, 10))
		if err != nil {
			return failed(res, err)
		}
		_, staged, err := r.extract(ctx, en, kg, sub, entryCheck(rules), cfgDir)
		if err != nil {
			return failed(res, err)
		}
		kg.forget(en.Path) // decrypted: its key goes now (CC-17)
		for _, s := range staged {
			if s.Entry.Rel == historyRel {
				b, _, err := readAllBounded(sub.Dir(), s.StagedRel, maxHistoryBytes)
				if err != nil {
					return failed(res, err)
				}
				lines = append(lines, splitLines(b)...)
				continue
			}
			paste[s.Entry.Rel] = pasteVersion{dir: sub.Dir(), rel: s.StagedRel, size: s.Entry.Size, sha: s.Entry.SHA256, mode: s.Entry.Mode, mt: s.Entry.MtimeNS}
		}
	}
	base, err := r.p.fs.OpenBase(cfgDir)
	if err != nil {
		return failed(res, err)
	}
	defer base.Close()
	cur, _, err := readAllBounded(base, historyRel, maxHistoryBytes)
	if err != nil && !isMissing(err) {
		return failed(res, err)
	}
	missing := unionLines(joinLines(lines), cur)
	// Timestamp order (stable for equal or unknown times).
	sort.SliceStable(missing, func(a, b int) bool {
		if r.p.historyLine == nil {
			return false
		}
		return r.p.historyLine(missing[a]).Timestamp.Before(r.p.historyLine(missing[b]).Timestamp)
	})
	// Appends go through the home's directory handle (CC-05).
	if len(cur) > 0 && cur[len(cur)-1] != '\n' {
		if err := base.AppendLine(historyRel, nil); err != nil {
			return failed(res, err)
		}
	}
	for _, l := range missing {
		if len(l) > fsx.MaxLine {
			continue
		}
		if err := base.AppendLine(historyRel, l); err != nil {
			return failed(res, err)
		}
	}
	// Paste-cache entries: exact placement, never overwriting.
	for rel, pv := range paste {
		if _, err := base.Lstat(rel); err == nil || !isMissing(err) {
			continue
		}
		pd, err := base.OpenDir(pasteCacheDir, true)
		if err != nil {
			return failed(res, err)
		}
		_ = pv.dir.Chmod(pv.rel, restorePerm(pv.mode))
		_ = pv.dir.Chtimes(pv.rel, time.Unix(0, pv.mt))
		err = pv.dir.RenameTo(pv.rel, pd, path.Base(rel), fsx.NoReplace)
		pd.Close()
		if err != nil && !errors.Is(err, fsx.ErrExist) {
			return failed(res, err)
		}
	}
	res.Files = len(missing)
	if len(missing) == 0 {
		res.Outcome = OutUnchanged
	} else {
		res.Outcome = OutMerged
		res.Detail = fmt.Sprintf("%d line(s) merged", len(missing))
	}
	return res
}

// joinLines joins lines with '\n' terminators.
func joinLines(lines [][]byte) []byte {
	var b bytes.Buffer
	for _, l := range lines {
		b.Write(l)
		b.WriteByte('\n')
	}
	return b.Bytes()
}

// recoverMerge: merge-back is idempotent (line union), so an interrupted
// merge only leaves staging to remove (HIST-5).
func (r *run) recoverMerge(ctx context.Context, rec *journal.Record) *UnitResult {
	if validKey(rec.Unit) {
		lk, err := r.lockUnit(rec.Unit)
		if err != nil {
			if errors.Is(err, fsx.ErrLocked) {
				return nil
			}
		} else {
			defer lk.Unlock()
		}
	}
	if rec.Staging != "" {
		if st, err := r.p.fs.OpenStaging(rec.Staging); err == nil {
			_ = st.Remove()
		}
	}
	return r.doneRecovered(rec, capsule.KindClaudeHistory, OutSkipped, "recovered: merge-back cleaned up")
}

// historyPending counts, per root, the lines of a home's history.jsonl
// that still wait for a rotation (status "history pending", SPEC §19).
func (r *run) historyPending(h harness.Home) (map[string]int, error) {
	cfgDir := h.Bases[capsule.BaseClaudeConfig]
	if cfgDir == "" {
		return nil, nil
	}
	base, err := r.p.fs.OpenBase(cfgDir)
	if err != nil {
		return nil, err
	}
	defer base.Close()
	b, _, err := readAllBounded(base, historyRel, maxHistoryBytes)
	if err != nil {
		if isMissing(err) {
			return nil, nil
		}
		return nil, err
	}
	out := map[string]int{}
	for id, ls := range r.splitHistory(b[:completePrefix(b)]).byRoot {
		out[id] = len(ls)
	}
	return out, nil
}
