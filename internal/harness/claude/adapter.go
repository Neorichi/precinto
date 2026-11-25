package claude

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Neorichi/precinto/internal/capsule"
	"github.com/Neorichi/precinto/internal/config"
	"github.com/Neorichi/precinto/internal/fsx"
	"github.com/Neorichi/precinto/internal/harness"
	"github.com/Neorichi/precinto/internal/ledger"
	"github.com/Neorichi/precinto/internal/live"
	"github.com/Neorichi/precinto/internal/platform"
	"github.com/Neorichi/precinto/inventories"
)

const harnessName = string(harness.ClaudeCode)

// errNoSalt: unit keys cannot be derived without the install's name salt.
var errNoSalt = errors.New("claude: no name salt")

// adapter is the Claude Code adapter (capsule mode, SPEC §7.1).
type adapter struct {
	inv    harness.Inventory
	invErr error
	cache  factsCache
}

func newAdapter() harness.Adapter {
	inv, err := harness.LoadInventory(inventories.FS, harnessName)
	return &adapter{inv: inv, invErr: err}
}

func (a *adapter) ID() harness.ID { return harness.ClaudeCode }

func (a *adapter) Homes(ctx context.Context, e harness.Env) ([]harness.Home, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	hs := homes(e)
	out := make([]harness.Home, len(hs))
	for i, h := range hs {
		out[i] = h.Home
	}
	return out, nil
}

// RegisteredHomes implements harness.RegisteredHomer: every home config
// registers, also one Homes leaves out under WSL for lying on a Windows
// drive (D156), so that restore authenticates its capsules and Targets
// refuses the home for what it is.
func (a *adapter) RegisteredHomes(ctx context.Context, e harness.Env) ([]harness.Home, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	hs := registeredHomes(e.Cfg)
	out := make([]harness.Home, len(hs))
	for i, h := range hs {
		out[i] = h.Home
	}
	return out, nil
}

var _ harness.RegisteredHomer = (*adapter)(nil)

// session is what Scan knows about one session of a home.
type sessionInfo struct {
	ledger  ledger.Session
	hasLog  bool
	roots   []string
	adopted bool
	owners  []platform.ProcID
}

func (a *adapter) Scan(ctx context.Context, e harness.Env, s harness.Scope) ([]harness.Unit, error) {
	if a.invErr != nil {
		return nil, a.invErr
	}
	if len(e.Salt) == 0 {
		return nil, errNoSalt
	}
	var errs []error
	var walkers []*walker
	for _, h := range homes(e) {
		if !isDir(h.configDir()) {
			continue
		}
		w := newWalker(ctx, h)
		if err := w.walkConfig(s.Global && wantKind(s, capsule.KindGlobalStore)); err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			errs = append(errs, fmt.Errorf("claude: home %s: %w", h.ID, err))
			continue
		}
		walkers = append(walkers, w)
	}
	for _, g := range groupBy(walkers, home.tmpDir) {
		if err := walkTmp(ctx, e, g); err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			errs = append(errs, err)
		}
	}
	for _, g := range groupBy(walkers, home.cacheDir) {
		if err := walkCache(ctx, e, g); err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			errs = append(errs, err)
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var out []harness.Unit
	for _, w := range walkers {
		units, err := a.unitsOf(ctx, e, s, w)
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			errs = append(errs, fmt.Errorf("claude: home %s: %w", w.h.ID, err))
			continue
		}
		out = append(out, units...)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].Key < out[j].Key
	})
	return out, errors.Join(errs...)
}

// ownedBy applies Scope.Procs: with processes named, only sessions whose
// ledger current owner is one of them (the wrapper's own child).
func ownedBy(s harness.Scope, si sessionInfo) bool {
	if len(s.Procs) == 0 {
		return true
	}
	if !si.hasLog || si.ledger.CurrentProc.IsZero() {
		return false
	}
	for _, p := range s.Procs {
		if p == si.ledger.CurrentProc {
			return true
		}
	}
	return false
}

func wantKind(s harness.Scope, k capsule.Kind) bool {
	if len(s.Kinds) == 0 {
		return true
	}
	for _, x := range s.Kinds {
		if x == k {
			return true
		}
	}
	return false
}

// inScope reports whether a unit with roots is in the scope's roots.
func inScope(s harness.Scope, roots []string) bool {
	if len(s.RootIDs) == 0 {
		return len(roots) > 0
	}
	for _, r := range roots {
		for _, w := range s.RootIDs {
			if r == w {
				return true
			}
		}
	}
	return false
}

// knownRoots keeps the root ids config still protects, in order.
func knownRoots(c config.Config, ids []string) []string {
	var out []string
	for _, id := range ids {
		if _, ok := c.RootByID(id); ok {
			out = appendUnique(out, id)
		}
	}
	return out
}

func rootIDs(rs []config.Root) []string {
	out := make([]string, 0, len(rs))
	for _, r := range rs {
		out = append(out, r.ID)
	}
	return out
}

// unitsOf builds the units of one walked home.
func (a *adapter) unitsOf(ctx context.Context, e harness.Env, s harness.Scope, w *walker) ([]harness.Unit, error) {
	h := w.h
	var index *ledger.Index
	if e.Index != nil {
		index = e.Index(harnessName)
	}
	sessions := a.resolveSessions(ctx, e, s, h, w, index)

	var out []harness.Unit
	sidWanted := func(sid string) bool {
		if len(s.SIDs) == 0 {
			return true
		}
		for _, x := range s.SIDs {
			if strings.EqualFold(x, sid) {
				return true
			}
		}
		return false
	}
	// Sessions.
	slugRoots := map[string][]string{}
	for _, k := range w.order {
		b := w.units[k]
		if b.kind != capsule.KindClaudeSession {
			continue
		}
		si, ok := sessions[b.id]
		if !ok {
			continue
		}
		if wantKind(s, capsule.KindClaudePlan) && len(b.transcripts)+len(b.subagents) > 0 {
			for _, slug := range a.transcriptSlugs(ctx, append(append([]string{}, b.transcripts...), b.subagents...)) {
				for _, r := range si.roots {
					slugRoots[slug] = appendUnique(slugRoots[slug], r)
				}
			}
		}
		if !wantKind(s, capsule.KindClaudeSession) || !sidWanted(b.id) || !inScope(s, si.roots) || !ownedBy(s, si) {
			continue
		}
		u, err := a.unitOf(e, h, b, si.roots)
		if err != nil {
			return nil, err
		}
		u.Procs = si.owners
		u.Adopted = si.adopted
		u.ProjectDir = a.sessionProjectDir(ctx, e, si, b)
		out = append(out, u)
	}
	// Projects.
	if wantKind(s, capsule.KindClaudeProject) && len(s.SIDs) == 0 && len(s.Procs) == 0 {
		for _, k := range w.order {
			b := w.units[k]
			if b.kind != capsule.KindClaudeProject || len(b.files)+len(b.dirs)+len(b.hazards) == 0 {
				continue
			}
			roots := a.projectRoots(e, h, b.id, w, sessions, index)
			if !inScope(s, roots) {
				continue
			}
			u, err := a.unitOf(e, h, b, roots)
			if err != nil {
				return nil, err
			}
			u.ProjectDir = projectProjectDir(h, b.id, index)
			out = append(out, u)
		}
	}
	// Plans, by the slugs managed transcripts reference (D46).
	if wantKind(s, capsule.KindClaudePlan) && len(s.SIDs) == 0 && len(s.Procs) == 0 {
		plans := assignPlans(w.plans, slugRoots)
		slugs := make([]string, 0, len(plans))
		for slug := range plans {
			slugs = append(slugs, slug)
		}
		sort.Strings(slugs)
		for _, slug := range slugs {
			roots := knownRoots(e.Cfg, slugRoots[slug])
			if !inScope(s, roots) {
				continue
			}
			b := &builder{kind: capsule.KindClaudePlan, id: slug, seen: map[string]bool{}}
			for _, pf := range plans[slug] {
				abs := filepath.Join(h.configDir(), "plans", pf.name)
				if err := w.addEntry(b, capsule.BaseClaudeConfig, abs, "plans/"+pf.name, pf.snap); err != nil {
					return nil, err
				}
			}
			u, err := a.unitOf(e, h, b, roots)
			if err != nil {
				return nil, err
			}
			out = append(out, u)
		}
	}
	// Global stores (D36): global vault, no root.
	if s.Global && wantKind(s, capsule.KindGlobalStore) && len(s.SIDs) == 0 && len(s.Procs) == 0 {
		for _, k := range w.order {
			b := w.units[k]
			if b.kind != capsule.KindGlobalStore || len(b.files)+len(b.dirs)+len(b.hazards) == 0 {
				continue
			}
			u, err := a.unitOf(e, h, b, nil)
			if err != nil {
				return nil, err
			}
			out = append(out, u)
		}
	}
	return out, nil
}

// resolveSessions decides which sessions found on disk are managed and by
// which roots: a ledger taint (sticky), else adoption — the project index
// for the session's project directories, and, with Scope.Adopt or when the
// scope names the session, the cwd keys of its transcripts (S6). A session
// without a ledger that precinto restored (its unit has a receipt) is
// precinto's own, not adopted: its ledger went into the capsule at the seal
// (S13) and the project index recorded its roots then (DC-30), so the next
// sweep of its locked folder seals it again.
func (a *adapter) resolveSessions(ctx context.Context, e harness.Env, s harness.Scope, h home, w *walker, index *ledger.Index) map[string]sessionInfo {
	out := map[string]sessionInfo{}
	for _, k := range w.order {
		b := w.units[k]
		if b.kind != capsule.KindClaudeSession {
			continue
		}
		si := sessionInfo{}
		if e.Ledger != nil {
			if ls, err := e.Ledger.Get(harnessName, b.id); err == nil {
				si.ledger, si.hasLog = ls, true
				si.roots = knownRoots(e.Cfg, ls.RootIDs)
			}
		}
		if len(si.roots) == 0 {
			var adopt []string
			if index != nil {
				for _, p := range b.projects {
					if proj, ok, err := index.Lookup(h.configDir(), p); err == nil && ok {
						adopt = append(adopt, knownRoots(e.Cfg, proj.RootIDs)...)
					}
				}
			}
			named := false
			for _, x := range s.SIDs {
				named = named || strings.EqualFold(x, b.id)
			}
			if s.Adopt || named {
				for _, t := range append(append([]string{}, b.transcripts...), b.subagents...) {
					facts, err := a.facts(ctx, t)
					if err != nil {
						continue
					}
					adopt = append(adopt, rootIDs(e.Cfg.RootsFor(absOnly(facts.Cwds)...))...)
				}
			}
			for _, r := range adopt {
				si.roots = appendUnique(si.roots, r)
			}
			si.adopted = len(si.roots) > 0 && !restoredBefore(e, h, b.id)
		}
		if len(si.roots) == 0 {
			continue
		}
		if si.hasLog {
			si.owners = currentOwners(e, si.ledger)
		}
		out[b.id] = si
	}
	return out
}

// restoredBefore reports whether precinto placed this session's files: its
// unit has a receipt (state/receipts/<unit-key>.json, D10), written when a
// capsule is restored and kept while sealed files could not be removed.
func restoredBefore(e harness.Env, h home, sid string) bool {
	dir := e.Layout.ReceiptsDir
	if !filepath.IsAbs(dir) || len(e.Salt) == 0 {
		return false
	}
	key, err := harness.UnitKeyFor(e.Salt, capsule.KindClaudeSession, harness.ClaudeCode, h.ID, "", sid)
	if err != nil {
		return false
	}
	st, err := fsx.Lstat(filepath.Join(dir, key+".json"))
	return err == nil && st.IsRegular()
}

func absOnly(ps []string) []string {
	out := ps[:0:0]
	for _, p := range ps {
		if filepath.IsAbs(p) {
			out = append(out, p)
		}
	}
	return out
}

// currentOwners returns the ledger process that still owns s (D20): the
// current process, unless the session ended with /clear or /resume or the
// process has started a newer session since.
func currentOwners(e harness.Env, s ledger.Session) []platform.ProcID {
	p := s.CurrentProc
	if p.IsZero() || s.Warm() {
		return nil
	}
	if e.Ledger != nil {
		if cur, err := e.Ledger.ByProc(harnessName, p); err == nil {
			for _, c := range cur {
				if c.SID == s.SID {
					return []platform.ProcID{p}
				}
			}
			if len(cur) > 0 {
				return nil // moved on to a newer session
			}
		}
	}
	return []platform.ProcID{p}
}

// projectRoots returns the roots of project directory p: the index entry
// (and entries whose memory directory is p's), plus the roots of managed
// sessions stored in p.
func (a *adapter) projectRoots(e harness.Env, h home, p string, w *walker, sessions map[string]sessionInfo, index *ledger.Index) []string {
	var roots []string
	if index != nil {
		if proj, ok, err := index.Lookup(h.configDir(), p); err == nil && ok {
			roots = append(roots, proj.RootIDs...)
		}
		mem := filepath.Join(h.configDir(), "projects", p, "memory")
		if all, err := index.All(); err == nil {
			for _, proj := range all {
				if proj.MemoryDir != "" && filepath.Clean(proj.MemoryDir) == mem && filepath.Clean(proj.ConfigDir) == h.configDir() {
					roots = append(roots, proj.RootIDs...)
				}
			}
		}
	}
	for _, k := range w.order {
		b := w.units[k]
		if b.kind != capsule.KindClaudeSession {
			continue
		}
		si, ok := sessions[b.id]
		if !ok {
			continue
		}
		for _, bp := range b.projects {
			if sameName(bp, p) {
				roots = append(roots, si.roots...)
			}
		}
	}
	return knownRoots(e.Cfg, roots)
}

// assignPlans maps plan files to the longest known slug they belong to:
// <slug>.md and <slug>-*.md (D46).
func assignPlans(files []planFile, slugs map[string][]string) map[string][]planFile {
	known := make([]string, 0, len(slugs))
	for s := range slugs {
		known = append(known, s)
	}
	sort.Slice(known, func(i, j int) bool { return len(known[i]) > len(known[j]) })
	out := map[string][]planFile{}
	for _, f := range files {
		stem := f.name[:len(f.name)-len(filepath.Ext(f.name))]
		for _, s := range known {
			if sameName(stem, s) || (len(stem) > len(s)+1 && sameName(stem[:len(s)+1], s+"-")) {
				out[s] = append(out[s], f)
				break
			}
		}
	}
	return out
}

// transcriptSlugs returns every plan slug the transcripts reference.
func (a *adapter) transcriptSlugs(ctx context.Context, files []string) []string {
	var out []string
	for _, f := range files {
		ts, err := a.scanFull(ctx, f)
		if err != nil {
			continue
		}
		for _, s := range ts.slugs {
			out = appendUnique(out, s)
		}
	}
	return out
}

// sessionProjectDir is Unit.ProjectDir of a session (D73): its start cwd,
// realpath'd — the cwd of the ledger's start event, else the first cwd its
// main transcript records (the one Claude named projects/<P> after), else
// the first cwd the ledger knows; "" when none is known.
func (a *adapter) sessionProjectDir(ctx context.Context, e harness.Env, si sessionInfo, b *builder) string {
	if si.hasLog {
		if c := ledgerStartCwd(e, b.id); c != "" {
			return realpath(c)
		}
	}
	for _, t := range b.transcripts {
		facts, err := a.facts(ctx, t)
		if err != nil {
			continue
		}
		for _, c := range facts.Cwds {
			if filepath.IsAbs(c) {
				return realpath(c)
			}
		}
	}
	if si.hasLog {
		for _, c := range si.ledger.Cwds {
			if filepath.IsAbs(c) {
				return realpath(c)
			}
		}
	}
	return ""
}

// ledgerStartCwd is the cwd of the session's own start in its ledger: the
// first SessionStart with source startup or clear (a /clear starts a new
// session). A launch or resume names where the session was opened again, a
// compaction restart and a first-contact start (empty source, SPEC §14.3)
// where it was at that moment: none of them is where it started.
func ledgerStartCwd(e harness.Env, sid string) string {
	if e.Ledger == nil {
		return ""
	}
	raw, _, err := e.Ledger.Snapshot(harnessName, sid)
	if err != nil {
		return ""
	}
	for _, line := range bytes.Split(raw, []byte("\n")) {
		var ev ledger.Event
		if len(bytes.TrimSpace(line)) == 0 || json.Unmarshal(line, &ev) != nil || ev.Harness != harnessName || ev.SID != sid {
			continue
		}
		if ev.Type == ledger.TypeStart && (ev.Source == "startup" || ev.Source == "clear") && filepath.IsAbs(ev.Cwd) {
			return ev.Cwd
		}
	}
	return ""
}

// projectProjectDir is Unit.ProjectDir of a project unit (D73): the cwd
// the project index maps to <P> when it maps exactly one, else "".
func projectProjectDir(h home, slug string, index *ledger.Index) string {
	if index == nil {
		return ""
	}
	p, ok, err := index.Lookup(h.configDir(), slug)
	if err != nil || !ok {
		return ""
	}
	var cwds []string
	for _, c := range p.Cwds {
		if filepath.IsAbs(c) {
			cwds = appendUnique(cwds, realpath(c))
		}
	}
	if len(cwds) != 1 {
		return ""
	}
	return cwds[0]
}

// unitOf turns a builder into a harness.Unit sealed to roots[0] (the
// primary root, D1) or to the global vault when roots is empty.
func (a *adapter) unitOf(e harness.Env, h home, b *builder, roots []string) (harness.Unit, error) {
	b.finish()
	rootID, vault := "", "global"
	if len(roots) > 0 {
		rootID, vault = roots[0], roots[0]
	}
	key, err := harness.UnitKeyFor(e.Salt, b.kind, harness.ClaudeCode, h.ID, rootID, b.id)
	if err != nil {
		return harness.Unit{}, err
	}
	u := harness.Unit{
		Harness:      harness.ClaudeCode,
		Kind:         b.kind,
		Key:          key,
		UnitID:       b.id,
		VaultID:      vault,
		RootIDs:      append([]string(nil), roots...),
		Home:         h.Home,
		Files:        b.files,
		Dirs:         b.dirs,
		Hazards:      b.hazards,
		Prune:        b.prune,
		Mode:         harness.GenLayered,
		Paths:        b.paths,
		LeaseKeys:    []string{key},
		LastActivity: b.last,
		Note:         strings.Join(b.notes, "; "),
	}
	if !u.LastActivity.IsZero() {
		u.LastActivity = u.LastActivity.UTC()
	}
	return u, nil
}

func (a *adapter) MarkdownPaths(ctx context.Context, e harness.Env, u harness.Unit) ([]string, error) {
	if u.Kind != capsule.KindClaudeSession {
		return nil, nil
	}
	var out []string
	for _, f := range u.Files {
		if f.Base != capsule.BaseClaudeConfig || f.Placement != harness.PlaceJSONLAppend {
			continue
		}
		base, ok := u.Home.Bases[f.Base]
		if !ok {
			continue
		}
		facts, err := scanTranscript(ctx, filepath.Join(base, filepath.FromSlash(f.Rel)))
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			continue // vanished or unreadable: the hook ledger still has its paths
		}
		for _, p := range facts.MDPaths {
			out = appendUnique(out, p)
		}
	}
	sort.Strings(out)
	return out, nil
}

// Describe returns the unit's title and last activity for its manifest.
// The sealer calls it once per unit it seals, so it also records the unit's
// project directories in the project index (recordProjects, DC-30).
func (a *adapter) Describe(ctx context.Context, e harness.Env, u harness.Unit) (string, time.Time, error) {
	if ctx.Err() == nil {
		a.recordProjects(e, u)
	}
	last := u.LastActivity
	for _, f := range u.Files {
		if t := time.Unix(0, f.Snap.MtimeNS); f.Snap.MtimeNS != 0 && t.After(last) {
			last = t
		}
	}
	if u.Kind != capsule.KindClaudeSession {
		return "", last.UTC(), nil
	}
	// The main transcript (the largest when the session left several).
	var main string
	var size int64 = -1
	for _, f := range u.Files {
		if f.Last && f.Base == capsule.BaseClaudeConfig && f.Snap.Size > size {
			if base, ok := u.Home.Bases[f.Base]; ok {
				main, size = filepath.Join(base, filepath.FromSlash(f.Rel)), f.Snap.Size
			}
		}
	}
	if main == "" {
		return "", last.UTC(), nil
	}
	facts, err := scanTranscript(ctx, main)
	if err != nil {
		if ctx.Err() != nil {
			return "", time.Time{}, ctx.Err()
		}
		return "", last.UTC(), nil
	}
	if facts.LastAt.After(last) || last.IsZero() {
		if !facts.LastAt.IsZero() {
			last = facts.LastAt
		}
	}
	return facts.Title, last.UTC(), nil
}

// evidence helpers keep details short and content-free.
func ev(r live.Reason, detail string) live.Evidence { return live.Evidence{Reason: r, Detail: detail} }
