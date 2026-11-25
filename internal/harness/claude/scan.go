package claude

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Neorichi/precinto/internal/capsule"
	"github.com/Neorichi/precinto/internal/fsx"
	"github.com/Neorichi/precinto/internal/harness"
)

// maxUnitEntries bounds the entries of one unit (a capsule holds at most
// capsule.MaxEntries); a larger unit is an error, never a partial unit.
const maxUnitEntries = capsule.MaxEntries

// errTooManyEntries is returned when a unit exceeds maxUnitEntries.
var errTooManyEntries = errors.New("claude: unit has too many entries")

// builder accumulates one unit's files while walking a home.
type builder struct {
	kind    capsule.Kind
	id      string
	files   []harness.File
	dirs    []harness.File
	hazards []harness.Hazard
	prune   []string // "base:rel", deepest first after finish
	paths   []string
	seen    map[string]bool
	last    time.Time
	notes   []string

	projects    []string // project directory names (sessions: projects/<P> and $TMP/<P>)
	transcripts []string // absolute main transcripts (projects/<P>/<sid>.jsonl)
	subagents   []string // absolute subagent transcripts
	jobs        []string // job ids whose records name the session
}

// walker walks one home and sorts every entry into its unit.
type walker struct {
	ctx     context.Context
	h       home
	units   map[string]*builder // kind + "\x00" + id
	order   []string
	plans   []planFile
	visited int
}

type planFile struct {
	name string // file name below plans/
	snap fsx.Stat
}

func newWalker(ctx context.Context, h home) *walker {
	return &walker{ctx: ctx, h: h, units: map[string]*builder{}}
}

func (w *walker) unit(kind capsule.Kind, id string) *builder {
	k := string(kind) + "\x00" + id
	b := w.units[k]
	if b == nil {
		b = &builder{kind: kind, id: id, seen: map[string]bool{}}
		w.units[k] = b
		w.order = append(w.order, k)
	}
	return b
}

func (w *walker) tick() error {
	w.visited++
	if w.visited%1024 == 0 {
		return w.ctx.Err()
	}
	return nil
}

// hazardOf classifies a non-directory entry: symlinks, special files,
// hard links and foreign-owned files are reported, never sealed.
func hazardOf(st fsx.Stat) fsx.Hazard {
	switch {
	case st.Mode&0o170000 == 0o120000:
		return fsx.HazardSymlink
	case !st.IsRegular() && !st.IsDir():
		return fsx.HazardSpecial
	case int(st.UID) != os.Getuid():
		return fsx.HazardForeign
	case st.IsRegular() && st.Nlink > 1:
		return fsx.HazardHardlink
	}
	return fsx.HazardNone
}

// addEntry records one entry (file, empty-dir marker or hazard) in b.
func (w *walker) addEntry(b *builder, base capsule.BaseID, abs, rel string, st fsx.Stat) error {
	key := string(base) + ":" + rel
	if b.seen[key] {
		return nil
	}
	b.seen[key] = true
	if len(b.files)+len(b.dirs)+len(b.hazards) >= maxUnitEntries {
		return errTooManyEntries
	}
	if hz := hazardOf(st); hz != fsx.HazardNone {
		b.hazards = append(b.hazards, harness.Hazard{Base: base, Rel: rel, Hazard: hz})
		return nil
	}
	if st.IsDir() {
		return nil
	}
	f := harness.File{Base: base, Rel: rel, Snap: st, Placement: harness.PlaceExact}
	if base == capsule.BaseClaudeConfig && b.kind == capsule.KindClaudeSession {
		parts := strings.Split(rel, "/")
		if main, sub := isTranscript(parts, b.id); main || sub {
			f.Placement, f.Append, f.Last = harness.PlaceJSONLAppend, true, main
			if main {
				b.transcripts = append(b.transcripts, abs)
			} else {
				b.subagents = append(b.subagents, abs)
			}
		}
	}
	b.files = append(b.files, f)
	b.paths = append(b.paths, abs)
	if t := time.Unix(0, st.MtimeNS); t.After(b.last) {
		b.last = t
	}
	return nil
}

// addTree records the directory abs (base-relative rel) and everything
// below it in b, never following symlinks. Empty directories are recorded
// (SPEC §5 rule 1); every directory of the subtree is pruned when empty
// after sealing.
func (w *walker) addTree(b *builder, base capsule.BaseID, abs, rel string) error {
	if err := w.tick(); err != nil {
		return err
	}
	st, err := fsx.Lstat(abs)
	if notExist(err) {
		return nil // vanished while scanning
	}
	if err != nil {
		b.hazards = append(b.hazards, harness.Hazard{Base: base, Rel: rel, Hazard: fsx.HazardAccess})
		return nil
	}
	if !st.IsDir() {
		return w.addEntry(b, base, abs, rel, st)
	}
	if hz := hazardOf(st); hz == fsx.HazardForeign {
		b.hazards = append(b.hazards, harness.Hazard{Base: base, Rel: rel, Hazard: hz})
		return nil
	}
	des, err := os.ReadDir(abs)
	if notExist(err) {
		return nil
	}
	if err != nil {
		// EACCES/EPERM (TCC): the subtree is inaccessible, never missing.
		b.hazards = append(b.hazards, harness.Hazard{Base: base, Rel: rel, Hazard: fsx.HazardAccess})
		return nil
	}
	key := string(base) + ":" + rel
	if !b.seen[key] {
		b.seen[key] = true
		b.paths = append(b.paths, abs)
		b.prune = append(b.prune, key)
	}
	if len(des) == 0 {
		b.dirs = append(b.dirs, harness.File{Base: base, Rel: rel, Snap: st})
		return nil
	}
	for _, de := range des {
		if err := w.addTree(b, base, filepath.Join(abs, de.Name()), rel+"/"+de.Name()); err != nil {
			return err
		}
	}
	return nil
}

// walkConfig walks $CC: projects/, plans/ and the global stores by their
// own rules, jobs/ by their state records, and every other top-level
// entry (except the deny-list) for sid-named components (I10).
func (w *walker) walkConfig(wantGlobal bool) error {
	cc := w.h.configDir()
	des, err := os.ReadDir(cc)
	if err != nil {
		return fmt.Errorf("claude: read config dir: %w", err)
	}
	for _, de := range des {
		name := de.Name()
		abs := filepath.Join(cc, name)
		switch {
		case denied(name), skipped(name):
		case sameName(name, "projects"):
			if err := w.walkProjects(abs); err != nil {
				return err
			}
		case sameName(name, "plans"):
			w.collectPlans(abs)
		case sameName(name, "jobs"):
			if err := w.walkJobs(cc); err != nil {
				return err
			}
		case sameName(name, "history.jsonl"), sameName(name, "paste-cache"):
			// history rotation (internal/sweep, SPEC §7.1.4)
		case sameName(name, storeUsage):
			if wantGlobal {
				if err := w.addTree(w.unit(capsule.KindGlobalStore, storeUsage), capsule.BaseClaudeConfig, abs, name); err != nil {
					return err
				}
			}
		case sameName(name, "feedback"):
			if err := w.walkFeedback(abs, name, wantGlobal); err != nil {
				return err
			}
		default:
			if err := w.searchSIDs(capsule.BaseClaudeConfig, abs, name, 1, ""); err != nil {
				return err
			}
		}
	}
	return nil
}

func (w *walker) walkFeedback(abs, rel string, wantGlobal bool) error {
	des, err := os.ReadDir(abs)
	if err != nil {
		return nil // not a directory, vanished or unreadable: no unit there
	}
	for _, de := range des {
		cabs, crel := filepath.Join(abs, de.Name()), rel+"/"+de.Name()
		if sameName(de.Name(), "drafts") {
			if wantGlobal {
				if err := w.addTree(w.unit(capsule.KindGlobalStore, storeFeedback), capsule.BaseClaudeConfig, cabs, crel); err != nil {
					return err
				}
			}
			continue
		}
		if err := w.searchSIDs(capsule.BaseClaudeConfig, cabs, crel, 2, ""); err != nil {
			return err
		}
	}
	return nil
}

// searchSIDs looks for sid-named entries at depth ≤ sidSearchDepth below a
// base; a match takes its whole subtree into that session's unit.
func (w *walker) searchSIDs(base capsule.BaseID, abs, rel string, depth int, project string) error {
	if err := w.tick(); err != nil {
		return err
	}
	name := filepath.Base(abs)
	if sid, ok := sidOf(name); ok && !(base == capsule.BaseClaudeTmp && depth == 1) {
		b := w.unit(capsule.KindClaudeSession, sid)
		if project != "" {
			b.projects = appendUnique(b.projects, project)
		}
		return w.addTree(b, base, abs, rel)
	}
	if depth >= sidSearchDepth {
		return nil
	}
	st, err := fsx.Lstat(abs)
	if err != nil || !st.IsDir() {
		return nil // files without a sid belong to no unit; symlinks are never followed
	}
	des, err := os.ReadDir(abs)
	if err != nil {
		// Unreadable or vanished: nothing below can be attributed to a
		// session, and nothing is ever treated as deleted.
		return nil
	}
	for _, de := range des {
		if err := w.searchSIDs(base, filepath.Join(abs, de.Name()), rel+"/"+de.Name(), depth+1, project); err != nil {
			return err
		}
	}
	return nil
}

// walkProjects sorts projects/<P>/ entries: sid-named ones into sessions,
// memory/ and other files into the project unit P.
func (w *walker) walkProjects(abs string) error {
	des, err := os.ReadDir(abs)
	if err != nil {
		return fmt.Errorf("claude: read projects: %w", err)
	}
	for _, pde := range des {
		p := pde.Name()
		pabs := filepath.Join(abs, p)
		if !pde.IsDir() || !safeComponent(p) {
			continue
		}
		entries, err := os.ReadDir(pabs)
		if err != nil {
			w.unit(capsule.KindClaudeProject, p).hazards = append(w.unit(capsule.KindClaudeProject, p).hazards,
				harness.Hazard{Base: capsule.BaseClaudeConfig, Rel: "projects/" + p, Hazard: fsx.HazardAccess})
			continue
		}
		for _, de := range entries {
			name := de.Name()
			eabs, erel := filepath.Join(pabs, name), "projects/"+p+"/"+name
			if sid, ok := sidOf(name); ok {
				b := w.unit(capsule.KindClaudeSession, sid)
				b.projects = appendUnique(b.projects, p)
				if err := w.addTree(b, capsule.BaseClaudeConfig, eabs, erel); err != nil {
					return err
				}
				continue
			}
			pb := w.unit(capsule.KindClaudeProject, p)
			if sameName(name, "memory") || !de.IsDir() {
				if err := w.addTree(pb, capsule.BaseClaudeConfig, eabs, erel); err != nil {
					return err
				}
				continue
			}
			// A subdirectory that is neither a session nor memory: no unit
			// can restore it, so it stays as it is (reported).
			pb.notes = appendUnique(pb.notes, "unknown directory left in place")
		}
	}
	return nil
}

func (w *walker) collectPlans(abs string) {
	des, err := os.ReadDir(abs)
	if err != nil {
		return
	}
	for _, de := range des {
		name := de.Name()
		if !strings.HasSuffix(strings.ToLower(name), ".md") || !safeComponent(name) {
			continue
		}
		st, err := fsx.Lstat(filepath.Join(abs, name))
		if err != nil {
			continue
		}
		w.plans = append(w.plans, planFile{name: name, snap: st})
	}
}

// walkJobs takes jobs/<id>/** into the session its record names (D25).
// Records without a readable session id cannot be attributed: they stay.
func (w *walker) walkJobs(cc string) error {
	jobs, err := readJobs(cc)
	if err != nil {
		return nil
	}
	for _, j := range jobs {
		sid, ok := sidOf(j.SessionID)
		if !j.Valid || !ok || len(j.SessionID) != uuidLen {
			continue
		}
		b := w.unit(capsule.KindClaudeSession, sid)
		b.jobs = appendUnique(b.jobs, j.ID)
		if err := w.addTree(b, capsule.BaseClaudeConfig, filepath.Join(cc, "jobs", j.ID), "jobs/"+j.ID); err != nil {
			return err
		}
	}
	return nil
}

// shared groups the walkers of homes that use one $TMP or $CACHE base:
// several Claude config dirs of a user share /private/tmp/claude-<uid> and
// the claude-cli-nodejs cache, so each base is walked once and every
// session or project directory found there goes to exactly one home.
type shared struct {
	dir   string
	cands []*walker
}

func groupBy(ws []*walker, dirOf func(home) string) []shared {
	var out []shared
	idx := map[string]int{}
	for _, w := range ws {
		d := dirOf(w.h)
		if d == "" {
			continue
		}
		i, ok := idx[d]
		if !ok {
			i = len(out)
			idx[d] = i
			out = append(out, shared{dir: d})
		}
		out[i].cands = append(out[i].cands, w)
	}
	return out
}

// tmpOwner picks the home of a session found in a shared $TMP: the home
// whose config dir holds files of the session, else the home the
// session's ledger names, else the first home using this base.
func tmpOwner(e harness.Env, cands []*walker, sid string) *walker {
	for _, w := range cands {
		if _, ok := w.units[string(capsule.KindClaudeSession)+"\x00"+sid]; ok {
			return w
		}
	}
	if e.Ledger != nil {
		if s, err := e.Ledger.Get(harnessName, sid); err == nil {
			for _, w := range cands {
				for _, d := range s.ConfigDirs {
					if filepath.IsAbs(d) && realpath(d) == realpath(w.h.configDir()) {
						return w
					}
				}
			}
		}
	}
	return cands[0]
}

// cacheOwner picks the home of a project directory found in a shared
// $CACHE: the home with projects/<P>, else the one the project index
// knows it for, else the first home using this base.
func cacheOwner(e harness.Env, cands []*walker, p string) *walker {
	for _, w := range cands {
		if isDir(filepath.Join(w.h.configDir(), "projects", p)) {
			return w
		}
	}
	if e.Index != nil {
		if x := e.Index(harnessName); x != nil {
			for _, w := range cands {
				if _, ok, err := x.Lookup(w.h.configDir(), p); err == nil && ok {
					return w
				}
			}
		}
	}
	return cands[0]
}

// walkTmp takes $TMP/<P>/…/<sid>/** into sessions (SPEC §7.1.1), each
// routed to its owning home.
func walkTmp(ctx context.Context, e harness.Env, g shared) error {
	des, err := os.ReadDir(g.dir)
	if notExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("claude: read tmp dir: %w", err)
	}
	for _, de := range des {
		p := de.Name()
		if !de.IsDir() || !safeComponent(p) {
			continue
		}
		if err := routeSIDs(ctx, e, g, filepath.Join(g.dir, p), p, 1, p); err != nil {
			return err
		}
	}
	return nil
}

// routeSIDs is searchSIDs for a shared $TMP: below <P>, a sid-named entry
// at depth 2 to sidSearchDepth takes its subtree into the owner's session.
func routeSIDs(ctx context.Context, e harness.Env, g shared, abs, rel string, depth int, project string) error {
	if err := g.cands[0].tick(); err != nil {
		return err
	}
	if depth > 1 {
		if sid, ok := sidOf(filepath.Base(abs)); ok {
			o := tmpOwner(e, g.cands, sid)
			b := o.unit(capsule.KindClaudeSession, sid)
			b.projects = appendUnique(b.projects, project)
			return o.addTree(b, capsule.BaseClaudeTmp, abs, rel)
		}
	}
	if depth >= sidSearchDepth {
		return nil
	}
	st, err := fsx.Lstat(abs)
	if err != nil || !st.IsDir() {
		return nil
	}
	des, err := os.ReadDir(abs)
	if err != nil {
		return nil
	}
	for _, de := range des {
		if err := routeSIDs(ctx, e, g, filepath.Join(abs, de.Name()), rel+"/"+de.Name(), depth+1, project); err != nil {
			return err
		}
	}
	return nil
}

// walkCache takes $CACHE/<P>/** (MCP logs) into project units, each
// routed to its owning home.
func walkCache(ctx context.Context, e harness.Env, g shared) error {
	des, err := os.ReadDir(g.dir)
	if notExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("claude: read cache dir: %w", err)
	}
	for _, de := range des {
		if err := ctx.Err(); err != nil {
			return err
		}
		p := de.Name()
		if !de.IsDir() || !safeComponent(p) {
			continue
		}
		o := cacheOwner(e, g.cands, p)
		if err := o.addTree(o.unit(capsule.KindClaudeProject, p), capsule.BaseClaudeCache, filepath.Join(g.dir, p), p); err != nil {
			return err
		}
	}
	return nil
}

// finish sorts a unit's entries deterministically (placement-last files at
// the end) and orders prune directories deepest first.
func (b *builder) finish() {
	sort.SliceStable(b.files, func(i, j int) bool {
		if b.files[i].Last != b.files[j].Last {
			return !b.files[i].Last
		}
		if b.files[i].Base != b.files[j].Base {
			return b.files[i].Base < b.files[j].Base
		}
		return b.files[i].Rel < b.files[j].Rel
	})
	sort.Slice(b.dirs, func(i, j int) bool {
		if b.dirs[i].Base != b.dirs[j].Base {
			return b.dirs[i].Base < b.dirs[j].Base
		}
		return b.dirs[i].Rel < b.dirs[j].Rel
	})
	sort.Slice(b.prune, func(i, j int) bool {
		di, dj := strings.Count(b.prune[i], "/"), strings.Count(b.prune[j], "/")
		if di != dj {
			return di > dj
		}
		return b.prune[i] < b.prune[j]
	})
	sort.Strings(b.paths)
}
