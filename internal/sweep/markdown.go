package sweep

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/precinto/precinto/internal/capsule"
	"github.com/precinto/precinto/internal/config"
	"github.com/precinto/precinto/internal/fsx"
	"github.com/precinto/precinto/internal/harness"
	"github.com/precinto/precinto/internal/live"
	"github.com/precinto/precinto/internal/paths"
	"github.com/precinto/precinto/internal/sweep/journal"
)

// MarkerText returns the exact bytes of the in-tree marker of a sealed note
// (SPEC §8.4): two lines, the second naming the unit key. ui.MsgNoteMarker
// mirrors it (plus this final newline); a cmd/precinto test asserts both
// are identical. Implemented in the scaffold.
func MarkerText(unitKey string) []byte {
	return []byte("This note is sealed by precinto. Run `precinto unlock` in this folder to open it.\nid: " + unitKey + "\n")
}

// markerSuffix marks a sealed note's in-tree marker: <name>.md.precinto.
const markerSuffix = ".precinto"

// maxMarkerBytes bounds a marker read (SPEC: at most 4 KiB).
const maxMarkerBytes = 4 << 10

// mdHarness is the pseudo-harness of notes: their capsules live in
// capsules/md/ (SPEC §6.1) and their unit keys do not depend on a harness.
const mdHarness harness.ID = "md"

// ParseMarker reads a *.md.precinto marker (at most 4 KiB, opened
// O_NOFOLLOW, regular file) and returns the unit key it names, or
// ErrNotMarker. Callers still require the unit to be logged (§11.1).
func ParseMarker(path string) (unitKey string, err error) {
	if !strings.HasSuffix(path, markerSuffix) || !isNoteName(strings.TrimSuffix(path, markerSuffix)) {
		return "", fmt.Errorf("%w: not a *.md.precinto file", ErrNotMarker)
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return "", fmt.Errorf("%w: a symlink", ErrNotMarker)
		}
		return "", err
	}
	defer f.Close()
	st, err := fsx.Fstat(f)
	if err != nil {
		return "", err
	}
	if !st.IsRegular() {
		return "", fmt.Errorf("%w: not a regular file", ErrNotMarker)
	}
	if st.Size > maxMarkerBytes {
		return "", fmt.Errorf("%w: too large", ErrNotMarker)
	}
	b, err := io.ReadAll(io.LimitReader(f, maxMarkerBytes+1))
	if err != nil {
		return "", err
	}
	return parseMarkerBytes(b)
}

// parseMarkerBytes accepts exactly MarkerText(key) for a well-formed key.
func parseMarkerBytes(b []byte) (string, error) {
	if len(b) > maxMarkerBytes {
		return "", fmt.Errorf("%w: too large", ErrNotMarker)
	}
	_, rest, ok := bytes.Cut(b, []byte("\nid: "))
	if !ok {
		return "", fmt.Errorf("%w: no id line", ErrNotMarker)
	}
	key := strings.TrimSuffix(string(rest), "\n")
	if !validKey(key) || !bytes.Equal(b, MarkerText(key)) {
		return "", fmt.Errorf("%w: malformed", ErrNotMarker)
	}
	return key, nil
}

// noteExts are the Markdown extensions of the policy (SPEC §8.1).
var noteExts = []string{".md", ".mdx", ".markdown"}

// isNoteName reports a Markdown file name (case-insensitive extension).
func isNoteName(name string) bool {
	ext := strings.ToLower(path.Ext(name))
	for _, e := range noteExts {
		if ext == e {
			return true
		}
	}
	return false
}

// noteDenyDirs are directory components no note target may pass (SPEC
// §11.2 md row); compared case-insensitively on darwin.
var noteDenyDirs = []string{".git", ".claude", ".codex", ".cursor", ".agents", ".vscode", "node_modules"}

// noteTargetOK applies the md row of SPEC §11.2 to a root-relative path
// (the git-tracked check is separate).
func noteTargetOK(rel string) bool {
	if !cleanRel(rel) || !isNoteName(rel) {
		return false
	}
	for _, c := range strings.Split(path.Dir(rel), "/") {
		for _, d := range noteDenyDirs {
			if c == d || (runtime.GOOS == "darwin" && strings.EqualFold(c, d)) {
				return false
			}
		}
	}
	return true
}

// noteTargetAliasFree repeats the deny-list check against the identity of
// existing deny-listed directories of the root (SPEC §11.2): a parent that
// is the same directory as root/.git (or any other deny-listed one) under
// another spelling — case or Unicode normalization on APFS — is refused.
func noteTargetAliasFree(rootDir dirHandle, rel string) bool {
	var denied []fsx.Stat
	for _, d := range noteDenyDirs {
		if st, err := rootDir.Lstat(d); err == nil && st.IsDir() {
			denied = append(denied, st)
		}
	}
	dir := path.Dir(rel)
	if dir == "." || len(denied) == 0 {
		return true
	}
	cur := ""
	for _, c := range strings.Split(dir, "/") {
		cur = path.Join(cur, c)
		st, err := rootDir.Lstat(cur)
		if err != nil {
			if isMissing(err) {
				return true // nothing below exists yet: names were checked
			}
			return false
		}
		for _, d := range denied {
			if st.SameFile(d) {
				return false
			}
		}
	}
	return true
}

// globMatch matches a root-relative slash path against an exclude glob
// anywhere in the tree ("**" spans components; a pattern also matches at
// any depth), so excludes only ever widen (never seal more than intended).
func globMatch(pattern, rel string) bool {
	pat := strings.Split(strings.Trim(pattern, "/"), "/")
	comps := strings.Split(rel, "/")
	for start := 0; start < len(comps); start++ {
		if matchComps(pat, comps[start:]) {
			return true
		}
	}
	return false
}

func matchComps(pat, comps []string) bool {
	if len(pat) == 0 {
		return len(comps) == 0
	}
	if pat[0] == "**" {
		for i := 0; i <= len(comps); i++ {
			if matchComps(pat[1:], comps[i:]) {
				return true
			}
		}
		return false
	}
	if len(comps) == 0 {
		return false
	}
	p, c := pat[0], comps[0]
	if runtime.GOOS == "darwin" {
		p, c = strings.ToLower(p), strings.ToLower(c)
	}
	if ok, err := path.Match(p, c); err != nil || !ok {
		return false
	}
	return matchComps(pat[1:], comps[1:])
}

// noteExcluded applies the default excludes and the root's md_exclude.
func noteExcluded(root config.Root, rel string) bool {
	for _, g := range config.DefaultMDExclude {
		if globMatch(g, rel) {
			return true
		}
	}
	for _, g := range root.MDExclude {
		if globMatch(g, rel) {
			return true
		}
	}
	return false
}

// gitCache caches one tracked set per repository per run (SPEC §8.2).
type gitCache struct {
	repos map[string]map[string]bool // nil value: lookup failed ⇒ tracked
}

// tracked reports whether abs (a file inside some repository) is
// git-tracked. Any failure means tracked (never seal on doubt).
func (r *run) tracked(ctx context.Context, gc *gitCache, abs string) bool {
	repo := findRepo(abs)
	if repo == "" {
		return false
	}
	set, ok := gc.repos[repo]
	if !ok {
		var err error
		if r.p.git == nil {
			err = errors.New("no git")
		} else {
			set, err = r.p.git.Tracked(ctx, repo)
		}
		if err != nil {
			set = nil
		}
		if gc.repos == nil {
			gc.repos = map[string]map[string]bool{}
		}
		gc.repos[repo] = set
	}
	if set == nil {
		return true
	}
	rel, err := filepath.Rel(repo, abs)
	if err != nil {
		return true
	}
	return set[filepath.ToSlash(rel)]
}

// findRepo returns the nearest ancestor of abs holding a .git entry.
func findRepo(abs string) string {
	for d := filepath.Dir(abs); ; d = filepath.Dir(d) {
		if _, err := fsx.Lstat(filepath.Join(d, ".git")); err == nil {
			return d
		}
		if parent := filepath.Dir(d); parent == d {
			return ""
		}
	}
}

// noteUnit builds the unit of one note.
func (r *run) noteUnit(root config.Root, rel string, st fsx.Stat) (harness.Unit, error) {
	key, err := harness.UnitKeyFor(r.e.Harness.Salt, capsule.KindMarkdown, mdHarness, "", root.ID, rel)
	if err != nil {
		return harness.Unit{}, err
	}
	abs := filepath.Join(root.Path, filepath.FromSlash(rel))
	return harness.Unit{
		Harness: mdHarness, Kind: capsule.KindMarkdown, Key: key, UnitID: rel, VaultID: root.ID,
		RootIDs: []string{root.ID},
		Home:    harness.Home{Harness: mdHarness, Bases: map[capsule.BaseID]string{capsule.BaseRoot: root.Path}, RootID: root.ID},
		Files:   []harness.File{{Base: capsule.BaseRoot, Rel: rel, Snap: st, Placement: harness.PlaceMarkdown}},
		Mode:    harness.GenLayered, Paths: []string{abs}, LastActivity: time.Unix(0, st.MtimeNS).UTC(),
	}, nil
}

// SealMarkdown applies a root's Markdown policy (SPEC §8): candidates from
// the ledger, transcripts and (md=all) a scan; excludes; git-tracked check
// via a hardened git invocation; no seal while a session that wrote the note
// is live or busy (D17); store capsule + in-tree marker (D16).
func SealMarkdown(ctx context.Context, e Env, root config.Root, o Options) (*Report, error) {
	r := newRun(e, prodPorts(e))
	if err := ctx.Err(); err != nil {
		return r.finish(), err
	}
	r.recoverAll(ctx)
	cands := r.noteCandidates(ctx, root)
	if r.primeNotes(ctx, root, cands, nil) {
		r.waitQuiet(ctx, o.Deadline) // D63: one look, one quiet window, then decide
	}
	r.sealMarkdown(ctx, root, o, cands)
	return r.finish(), nil
}

// noteCand is one candidate note and the sessions known to have written it.
type noteCand struct {
	rel     string
	writers []harness.Unit     // session units still present as plaintext
	procs   []ledgerProcsEntry // ledger sessions that list it
	pending bool               // from the pending-notes index (its session is sealed)
}

type ledgerProcsEntry struct {
	harness string
	sid     string
	ended   bool
}

// noteCandidates gathers a root's candidates (SPEC §8.1): the pending
// index, the ledger, the transcripts of the root's sessions, and with
// md=all every Markdown file under the root.
func (r *run) noteCandidates(ctx context.Context, root config.Root) map[string]*noteCand {
	out := map[string]*noteCand{}
	if root.MD == config.MDOff {
		return out
	}
	add := func(abs string) *noteCand {
		if !filepath.IsAbs(abs) || !paths.Within(root.Path, abs) || !isNoteName(abs) {
			return nil
		}
		rel, err := filepath.Rel(root.Path, abs)
		if err != nil || rel == "." {
			return nil
		}
		rel = filepath.ToSlash(rel)
		c := out[rel]
		if c == nil {
			c = &noteCand{rel: rel}
			out[rel] = c
		}
		return c
	}
	for _, p := range r.pendingNotes(root.ID) {
		if c := add(p); c != nil {
			c.pending = true
		}
	}
	for _, ad := range r.e.Adapters {
		if ad == nil {
			continue
		}
		sessions, err := r.p.ledger.List(string(ad.ID()))
		if err == nil {
			for _, s := range sessions {
				for _, p := range s.Markdown {
					if c := add(p); c != nil {
						c.procs = append(c.procs, ledgerProcsEntry{harness: s.Harness, sid: s.SID, ended: s.Ended})
					}
				}
			}
		}
		units, err := ad.Scan(ctx, r.e.Harness, harness.Scope{RootIDs: []string{root.ID}})
		if err != nil {
			continue
		}
		for _, u := range units {
			if u.Kind != capsule.KindClaudeSession && u.Kind != capsule.KindCodexHome && u.Kind != capsule.KindGeneric {
				continue
			}
			mps, err := ad.MarkdownPaths(ctx, r.e.Harness, u)
			if err != nil {
				continue
			}
			for _, p := range mps {
				if c := add(p); c != nil {
					c.writers = append(c.writers, u)
				}
			}
		}
	}
	if root.MD == config.MDAll {
		r.walkNotes(root, func(rel string) {
			add(filepath.Join(root.Path, filepath.FromSlash(rel)))
		})
	}
	return out
}

// walkNotes visits every Markdown file under the root, skipping excluded
// and deny-listed directories; hazards are never followed.
func (r *run) walkNotes(root config.Root, fn func(rel string)) {
	d, err := r.p.fs.OpenBase(root.Path)
	if err != nil {
		return
	}
	defer d.Close()
	_ = d.Walk(".", func(we fsx.WalkEntry) error {
		rel := strings.TrimPrefix(we.Rel, "./")
		if rel == "." || rel == "" {
			return nil
		}
		if we.Type == fsx.TypeDir {
			if noteExcluded(root, rel+"/x") || !noteTargetOK(rel+"/x.md") {
				return fs.SkipDir
			}
			return nil
		}
		if we.Type == fsx.TypeRegular && we.Hazard == fsx.HazardNone && isNoteName(rel) {
			fn(rel)
		}
		return nil
	})
}

// sealMarkdown seals the sealable candidates of one root.
func (r *run) sealMarkdown(ctx context.Context, root config.Root, o Options, cands map[string]*noteCand) {
	if root.MD == config.MDOff || len(cands) == 0 {
		return
	}
	if busy, err := r.rootBusy(ctx, root); busy || err != nil {
		r.add(UnitResult{Harness: string(mdHarness), Kind: capsule.KindMarkdown, Outcome: OutSkipped,
			Detail: "deferred: a session in the folder is busy"})
		return
	}
	rels := make([]string, 0, len(cands))
	for rel := range cands {
		rels = append(rels, rel)
	}
	sort.Strings(rels)
	rootDir, err := r.p.fs.OpenBase(root.Path)
	if err != nil {
		r.add(failed(UnitResult{Harness: string(mdHarness), Kind: capsule.KindMarkdown}, err))
		return
	}
	defer rootDir.Close()
	gc := &gitCache{}
	var unlocked map[string]bool
	quiet := r.e.Cfg.Policy.QuietWindow.D()
	for _, rel := range rels {
		if ctx.Err() != nil {
			return
		}
		c := cands[rel]
		res := UnitResult{Harness: string(mdHarness), Kind: capsule.KindMarkdown}
		st, err := rootDir.Lstat(rel)
		if err != nil {
			if isMissing(err) {
				r.forgetPendingNote(ctx, root.ID, filepath.Join(root.Path, filepath.FromSlash(rel)))
				continue
			}
			r.add(failed(res, err))
			continue
		}
		u, err := r.noteUnit(root, rel, st)
		if err != nil {
			r.add(failed(res, err))
			continue
		}
		res = resultOf(u)
		abs := filepath.Join(root.Path, filepath.FromSlash(rel))
		switch {
		case !st.IsRegular() || st.Nlink > 1:
			res.Outcome, res.Detail = OutSkipped, "hazard: not a plain file"
			res.Hazards = []harness.Hazard{{Base: capsule.BaseRoot, Rel: rel, Hazard: hazardKind(st)}}
		case !noteTargetOK(rel) || noteExcluded(root, rel):
			res.Outcome, res.Detail = OutSkipped, "excluded"
		case !root.IncludeTracked && r.tracked(ctx, gc, abs):
			res.Outcome, res.Detail = OutSkipped, "git-tracked"
		case quiet > 0 && time.Unix(0, st.MtimeNS).After(r.now().Add(-quiet)):
			res.Outcome, res.Detail = OutLive, "changed within the quiet window"
		case r.e.Cfg.Policy.MDSealOn == config.MDSealOnEnd && !c.writersEnded():
			res.Outcome, res.Detail = OutSkipped, "deferred until its session ends"
		default:
			if v, isLive := r.noteLive(ctx, u, c); isLive {
				res = liveResult(res, v, false, "")
				if unlocked == nil {
					unlocked = r.unlocked(ctx)
				}
				if r.holdCapped(res, u, unlocked) {
					res.Detail = reasonHoldCapped
				}
				break
			}
			res = r.sealLayered(ctx, u, o, false)
			if res.Outcome == OutSealed || res.Outcome == OutUnchanged {
				r.forgetPendingNote(ctx, root.ID, abs)
			}
		}
		r.add(res)
	}
}

func hazardKind(st fsx.Stat) fsx.Hazard {
	if st.IsRegular() {
		return fsx.HazardHardlink
	}
	return hazardOf(st)
}

// writersEnded reports whether every known writer session has ended.
func (c *noteCand) writersEnded() bool {
	if len(c.writers) > 0 {
		return false
	}
	for _, p := range c.procs {
		if !p.ended {
			return false
		}
	}
	return true
}

// rootBusy asks the busy port (D17).
func (r *run) rootBusy(ctx context.Context, root config.Root) (bool, error) {
	if r.p.busy == nil {
		return false, nil
	}
	return r.p.busy.RootBusy(ctx, r.e, root.Path)
}

// noteLive decides a note's liveness (I1): live while a session that wrote
// it is live, plus the engine's lease and stability evidence for the note
// itself. A writer this run sealed is not live (its plaintext is in its
// capsule now).
func (r *run) noteLive(ctx context.Context, u harness.Unit, c *noteCand) (live.Verdict, bool) {
	for _, w := range c.writers {
		if r.sealedNow(w.Key) {
			continue
		}
		if v, isLive := r.checkLive(ctx, adapterFor(r.e, w.Harness), w, nil); isLive {
			return v, true
		}
	}
	s := subjectOf(u, nil)
	v, err := r.p.live.Decide(ctx, s, nil)
	if err != nil {
		return live.Verdict{Live: true, Evidence: []live.Evidence{{Reason: live.ReasonUnknown}}}, true
	}
	return v, v.Live
}

// ensureMarker writes <note>.precinto naming key next to the note (0600,
// exclusive). An existing marker for the same key is kept; a file there
// that is not this note's marker is never replaced (the note then
// restores at its authenticated relpath, D51).
func (r *run) ensureMarker(rootDir dirHandle, noteRel, key string) error {
	mrel := noteRel + markerSuffix
	if st, err := rootDir.Lstat(mrel); err == nil {
		if st.IsRegular() {
			if b, _, err := readAllBounded(rootDir, mrel, maxMarkerBytes); err == nil {
				if k, err := parseMarkerBytes(b); err == nil && k == key {
					return nil
				}
			}
		}
		return nil
	} else if !isMissing(err) {
		return err
	}
	f, tmp, err := rootDir.CreateTemp(path.Dir(mrel), ".precinto-marker-*")
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		if !ok {
			f.Close()
			_ = rootDir.Remove(tmp)
		}
	}()
	if _, err := f.Write(MarkerText(key)); err != nil {
		return err
	}
	if err := fsx.FullSync(f); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := rootDir.Rename(tmp, mrel, fsx.NoReplace); err != nil {
		if errors.Is(err, fsx.ErrExist) {
			_ = rootDir.Remove(tmp)
			ok = true
			return nil
		}
		return err
	}
	ok = true
	return nil
}

// ensureMarkerForRecord re-creates a note's marker during recovery.
func (r *run) ensureMarkerForRecord(rec *journal.Record, bases map[capsule.BaseID]dirHandle) error {
	rootDir := bases[capsule.BaseRoot]
	if rootDir == nil || len(rec.Files) != 1 {
		return nil
	}
	return r.ensureMarker(rootDir, rec.Files[0].Rel, rec.Unit)
}

// removeMarker removes a marker after its note was placed, only if it
// still names key.
func (r *run) removeMarker(rootDir dirHandle, mrel, key string) {
	b, st, err := readAllBounded(rootDir, mrel, maxMarkerBytes)
	if err != nil {
		return
	}
	if k, err := parseMarkerBytes(b); err != nil || k != key {
		return
	}
	_ = rootDir.UnlinkIfUnchanged(mrel, st)
}

// RestoreMarkdown restores a root's sealed notes at unlock: marker location
// minus suffix when a valid marker exists, else the authenticated original
// relpath (D16; SPEC §8.5).
func RestoreMarkdown(ctx context.Context, e Env, keys KeySource, root config.Root) (*Report, error) {
	return newRun(e, prodPorts(e)).restoreMarkdown(ctx, keys, root)
}

func (r *run) restoreMarkdown(ctx context.Context, keys KeySource, root config.Root) (*Report, error) {
	all, err := r.log.All()
	if err != nil {
		return r.finish(), err
	}
	var refs []harness.UnitRef
	for unit, entries := range unitGroups(all) {
		n, ok := newestEntry(entries)
		if !ok || n.Kind != string(capsule.KindMarkdown) || !contains(n.RootIDs, root.ID) {
			continue
		}
		refs = append(refs, harness.UnitRef{Harness: mdHarness, Kind: capsule.KindMarkdown, Key: unit, VaultID: n.VaultID, RootIDs: n.RootIDs})
	}
	sort.Slice(refs, func(a, b int) bool { return refs[a].Key < refs[b].Key })
	if len(refs) == 0 {
		r.recoverAll(ctx)
		return r.finish(), nil
	}
	return r.restore(ctx, keys, RestoreRequest{Units: refs, Purpose: "restore"})
}

// OpenNotes restores the notes named by markers in place (`precinto
// open`): RestoreMarkdown restricted to those units, purpose "open".
func OpenNotes(ctx context.Context, e Env, keys KeySource, markers []string) (*Report, error) {
	return newRun(e, prodPorts(e)).openNotes(ctx, keys, markers)
}

func (r *run) openNotes(ctx context.Context, keys KeySource, markers []string) (*Report, error) {
	var refs []harness.UnitRef
	r.forced = map[string]string{}
	for _, m := range markers {
		key, err := ParseMarker(m)
		if err != nil {
			return r.finish(), err
		}
		entries, err := r.log.Unit(key)
		if err != nil {
			return r.finish(), err
		}
		n, ok := newestEntry(entries)
		if !ok || n.Kind != string(capsule.KindMarkdown) {
			r.add(UnitResult{Harness: string(mdHarness), Kind: capsule.KindMarkdown, Unit: key, Outcome: OutFailed,
				Detail: codeNotLogged + ": the marker names no logged note"})
			continue
		}
		r.forced[key] = m
		refs = append(refs, harness.UnitRef{Harness: mdHarness, Kind: capsule.KindMarkdown, Key: key, VaultID: n.VaultID, RootIDs: n.RootIDs})
	}
	if len(refs) == 0 {
		return r.finish(), nil
	}
	return r.restore(ctx, keys, RestoreRequest{Units: refs, Purpose: "open"})
}

// markersOf scans a root once per run for markers, by unit key.
func (r *run) markersOf(root config.Root) map[string][]string {
	r.mu.Lock()
	if m, ok := r.markers[root.ID]; ok {
		r.mu.Unlock()
		return m
	}
	r.mu.Unlock()
	found := map[string][]string{}
	d, err := r.p.fs.OpenBase(root.Path)
	if err == nil {
		_ = d.Walk(".", func(we fsx.WalkEntry) error {
			rel := strings.TrimPrefix(we.Rel, "./")
			if rel == "." || rel == "" {
				return nil
			}
			if we.Type == fsx.TypeDir {
				if !noteTargetOK(rel + "/x.md") {
					return fs.SkipDir
				}
				return nil
			}
			if we.Type != fsx.TypeRegular || we.Hazard != fsx.HazardNone || !strings.HasSuffix(rel, markerSuffix) || we.Stat.Size > maxMarkerBytes {
				return nil
			}
			b, _, err := readAllBounded(d, rel, maxMarkerBytes)
			if err != nil {
				return nil
			}
			if k, err := parseMarkerBytes(b); err == nil {
				found[k] = append(found[k], rel)
			}
			return nil
		})
		d.Close()
	}
	r.mu.Lock()
	if r.markers == nil {
		r.markers = map[string]map[string][]string{}
	}
	r.markers[root.ID] = found
	r.mu.Unlock()
	return found
}

// noteTarget picks where a note restores (SPEC §8.5, D51, SEC-3): a valid
// marker carrying its key — inside the root, a note name, outside the deny
// list, with the note's own file name (a marker pointing at another
// note's unit is rejected) — wins; the marker at the authenticated relpath
// is preferred, and two valid markers elsewhere are ambiguous. Otherwise
// the note goes back to its authenticated relpath.
func noteTarget(relpath string, markers []string, forced string) (target, marker string) {
	valid := func(m string) (string, bool) {
		note := strings.TrimSuffix(m, markerSuffix)
		if note == m || !noteTargetOK(note) || path.Base(note) != path.Base(relpath) {
			return "", false
		}
		return note, true
	}
	if forced != "" {
		if note, ok := valid(forced); ok {
			return note, forced
		}
		return "", ""
	}
	var cands []string
	for _, m := range markers {
		if note, ok := valid(m); ok {
			if note == relpath {
				return note, m
			}
			cands = append(cands, m)
		}
	}
	if len(cands) == 1 {
		note, _ := valid(cands[0])
		return note, cands[0]
	}
	return relpath, ""
}

// restoreNote restores one note through the layered path with note rules.
func (r *run) restoreNote(ctx, actx context.Context, p *restoreUnitPlan, a authenticated, man capsule.Manifest, kg *keyGuard, req RestoreRequest, aborted func() bool) UnitResult {
	res := planResult(p)
	relpath := a.unitID
	root, ok := r.e.Cfg.RootByID(firstRoot(p.ref.RootIDs, r))
	if !ok || !noteTargetOK(relpath) {
		return failed(res, fmt.Errorf("%w: note path not allowed", capsule.ErrUnsafe))
	}
	gc := &gitCache{}
	forced := ""
	if r.forced != nil {
		if m, ok := r.forced[p.ref.Key]; ok {
			rel, err := filepath.Rel(root.Path, m)
			if err != nil || !paths.Within(root.Path, m) {
				return failed(res, fmt.Errorf("%w: marker outside the note's folder", capsule.ErrUnsafe))
			}
			forced = filepath.ToSlash(rel)
		}
	}
	target, marker := noteTarget(relpath, r.markersOf(root)[p.ref.Key], forced)
	if target == "" {
		return failed(res, fmt.Errorf("%w: marker not valid for this note", capsule.ErrUnsafe))
	}
	rootDir, err := r.p.fs.OpenBase(root.Path)
	if err != nil {
		return failed(res, err)
	}
	aliasFree := func(rel string) bool { return noteTargetAliasFree(rootDir, rel) }
	if !aliasFree(target) {
		target, marker = relpath, ""
	}
	ok = aliasFree(relpath)
	rootDir.Close()
	if !ok {
		return failed(res, fmt.Errorf("%w: note path aliases a protected directory", capsule.ErrUnsafe))
	}
	if r.tracked(ctx, gc, filepath.Join(root.Path, filepath.FromSlash(target))) {
		if target == relpath {
			return failed(res, fmt.Errorf("%w: note target is git-tracked", capsule.ErrUnsafe))
		}
		target, marker = relpath, ""
		if r.tracked(ctx, gc, filepath.Join(root.Path, filepath.FromSlash(target))) {
			return failed(res, fmt.Errorf("%w: note target is git-tracked", capsule.ErrUnsafe))
		}
	}
	a.rules = harness.TargetRules{
		Bases: map[capsule.BaseID]string{capsule.BaseRoot: root.Path},
		Allow: func(b capsule.BaseID, rel string) bool {
			return b == capsule.BaseRoot && (rel == relpath || rel == target || isConflictOf(rel, target))
		},
		Policy: func(capsule.Entry) harness.Placement { return harness.PlaceMarkdown },
		Mode:   harness.GenLayered,
	}
	out := r.restoreLayeredWith(ctx, actx, p, a, kg, req, aborted, layeredOpts{
		style: conflictNote,
		retarget: func(pf *plannedFile) {
			if pf.Rel == relpath {
				pf.Rel = target
			}
			pf.ConflictOK = true
		},
		marker: marker,
	})
	if out.Outcome == OutRestored && marker == "" {
		out.Detail = "restored at its original path"
	}
	return out
}

// isConflictOf reports whether rel is a conflict copy name of target.
func isConflictOf(rel, target string) bool {
	if path.Dir(rel) != path.Dir(target) {
		return false
	}
	ext := path.Ext(target)
	stem := strings.TrimSuffix(path.Base(target), ext)
	b := path.Base(rel)
	return strings.HasPrefix(b, stem+".conflict-") && strings.HasSuffix(b, ext)
}

// firstRoot returns the first configured root id of ids.
func firstRoot(ids []string, r *run) string {
	for _, id := range ids {
		if _, ok := r.e.Cfg.RootByID(id); ok {
			return id
		}
	}
	return ""
}

// CatNote decrypts the newest generation of the logged note a marker names
// and writes its bytes to w (`precinto cat`; the CLI sanitizes for a TTY,
// S17). Keys come from keys with purpose "cat" (fresh presence from agent
// contexts, D28).
func CatNote(ctx context.Context, e Env, keys KeySource, marker string, w io.Writer) error {
	r := newRun(e, prodPorts(e))
	return r.catNote(ctx, keys, marker, w)
}

func (r *run) catNote(ctx context.Context, keys KeySource, marker string, w io.Writer) error {
	key, err := ParseMarker(marker)
	if err != nil {
		return err
	}
	if keys == nil {
		return fmt.Errorf("%w: no key source", ErrKeyDenied)
	}
	entries, err := r.log.Unit(key)
	if err != nil {
		return err
	}
	en, ok := newestEntry(entries)
	if !ok || en.Kind != string(capsule.KindMarkdown) {
		return fmt.Errorf("%w: the marker names no logged note", ErrNotLogged)
	}
	root, ok := r.e.Cfg.RootByID(firstRoot(en.RootIDs, r))
	if !ok || !paths.Within(root.Path, marker) {
		return fmt.Errorf("%w: marker outside the note's folder", capsule.ErrUnsafe)
	}
	if err := r.checkProvenance(en); err != nil {
		return err
	}
	kg := &keyGuard{}
	defer kg.destroy()
	fk, err := keys.FileKeys(ctx, []string{en.Path}, "cat")
	if err != nil {
		return fmt.Errorf("%w: %s", ErrKeyDenied, safeMsg(err))
	}
	kg.add(fk)
	m, err := r.readManifest(ctx, en, kg)
	if err != nil {
		return err
	}
	if err := checkManifest(m, en); err != nil {
		return err
	}
	ref := harness.UnitRef{Harness: mdHarness, Kind: capsule.KindMarkdown, Key: key, VaultID: en.VaultID, RootIDs: en.RootIDs}
	a, err := r.authenticate(ctx, ref, m.UnitID, en)
	if err != nil {
		return err
	}
	if !noteTargetOK(a.unitID) {
		return fmt.Errorf("%w: note path not allowed", capsule.ErrUnsafe)
	}
	if err := ensurePrivateDir(r.l.StagingDir); err != nil {
		return err
	}
	st, err := r.p.fs.NewStaging(r.l.StagingDir, r.l.StagingDir, journal.NewID())
	if err != nil {
		return err
	}
	defer st.Remove()
	rules := harness.TargetRules{Bases: map[capsule.BaseID]string{capsule.BaseRoot: root.Path},
		Allow: func(b capsule.BaseID, rel string) bool { return b == capsule.BaseRoot && rel == a.unitID }}
	_, staged, err := r.extract(ctx, en, kg, st, entryCheck(rules), r.l.StagingDir)
	if err != nil {
		return err
	}
	if len(staged) != 1 {
		return fmt.Errorf("%w: a note capsule holds one file", capsule.ErrFormat)
	}
	f, _, err := st.Dir().Open(staged[0].StagedRel)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(w, f)
	return err
}

// The pending-notes index (state/notes.json) keeps, per root, the
// absolute paths of Markdown an agent wrote in sessions that were sealed
// before their folder locked, so md_seal_on=lock still finds them after
// the session's ledger and transcript moved into its capsule. It holds
// paths only (SPEC §6.3).
type notesIndex struct {
	V     int                 `json:"v"`
	Roots map[string][]string `json:"roots"`
}

func (r *run) notesIndexPath() string { return r.l.NotesIndex }

// maxNotesIndexBytes bounds the pending-notes index read (paths only).
const maxNotesIndexBytes = 16 << 20

// readNotesIndex reads state/notes.json (readState: regular, bounded,
// never blocking on a FIFO); anything unreadable reads as empty.
func (r *run) readNotesIndex() notesIndex {
	idx := notesIndex{V: 1, Roots: map[string][]string{}}
	b, err := readState(r.notesIndexPath(), maxNotesIndexBytes)
	if err != nil {
		return idx
	}
	_ = json.Unmarshal(b, &idx)
	if idx.Roots == nil {
		idx.Roots = map[string][]string{}
	}
	return idx
}

func (r *run) updateNotesIndex(ctx context.Context, fn func(*notesIndex)) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	lk, err := r.waitLockName(ctx, "notes")
	if err != nil {
		return
	}
	defer lk.Unlock()
	idx := r.readNotesIndex()
	fn(&idx)
	b, err := json.Marshal(idx)
	if err != nil {
		return
	}
	_ = fsx.WriteFileAtomic(r.notesIndexPath(), b, 0o600)
}

// pendingNotes returns the indexed notes of a root.
func (r *run) pendingNotes(rootID string) []string {
	return r.readNotesIndex().Roots[rootID]
}

// forgetPendingNote drops a note from the index.
func (r *run) forgetPendingNote(ctx context.Context, rootID, abs string) {
	r.updateNotesIndex(ctx, func(idx *notesIndex) {
		var keep []string
		for _, p := range idx.Roots[rootID] {
			if p != abs {
				keep = append(keep, p)
			}
		}
		if len(keep) == 0 {
			delete(idx.Roots, rootID)
		} else {
			idx.Roots[rootID] = keep
		}
	})
}

// rememberNotes records, before a session's plaintext goes, the Markdown
// paths its transcript and ledger show inside roots (S6).
func (r *run) rememberNotes(ctx context.Context, ad harness.Adapter, u harness.Unit) {
	if u.Kind != capsule.KindClaudeSession && u.Kind != capsule.KindCodexHome && u.Kind != capsule.KindGeneric {
		return
	}
	var ps []string
	if ad != nil {
		if mp, err := ad.MarkdownPaths(ctx, r.e.Harness, u); err == nil {
			ps = append(ps, mp...)
		}
	}
	if sid := sessionLedgerSID(u); sid != "" {
		if sessions, err := r.p.ledger.List(string(u.Harness)); err == nil {
			for _, s := range sessions {
				if s.SID == sid {
					ps = append(ps, s.Markdown...)
				}
			}
		}
	}
	byRoot := map[string][]string{}
	for _, p := range ps {
		if !filepath.IsAbs(p) || !isNoteName(p) {
			continue
		}
		if root, ok := r.e.Cfg.RootFor(p); ok && root.MD != config.MDOff {
			byRoot[root.ID] = append(byRoot[root.ID], filepath.Clean(p))
		}
	}
	if len(byRoot) == 0 {
		return
	}
	r.updateNotesIndex(ctx, func(idx *notesIndex) {
		for id, ps := range byRoot {
			idx.Roots[id] = dedupe(append(idx.Roots[id], ps...))
		}
	})
}
