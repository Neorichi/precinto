package sweep

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"path"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/precinto/precinto/internal/capsule"
	"github.com/precinto/precinto/internal/harness"
	"github.com/precinto/precinto/internal/ledger"
	"github.com/precinto/precinto/internal/live"
	"github.com/precinto/precinto/internal/sweep/capslog"
)

// Restore restores units unit-atomically through staging (SPEC §11.5): for
// each unit, provenance check against the capsule log (D8), file keys from
// keys (D39), free-space check, Extract with adapter target rules, placement
// table (D11), receipts (D10). Newest-first within Budget.
func Restore(ctx context.Context, e Env, keys KeySource, r RestoreRequest) (*Report, error) {
	run := newRun(e, prodPorts(e))
	return run.restore(ctx, keys, r)
}

// restoreUnitPlan is one unit to restore and the capsules it needs.
type restoreUnitPlan struct {
	ref      harness.UnitRef
	entries  []capslog.Entry // layered: the chain, newest first; snapshot: the newest snapshot
	newest   capslog.Entry
	bytes    int64
	last     time.Time
	mtimeNow bool
	explicit bool
	// optional: from a harness.Selector with Optional (D132).
	optional bool
	// mans are the decrypted manifests of entries (restoreUnit), for the
	// per-volume free-space check.
	mans []capsule.Manifest
}

// keyGuard holds released file keys. Readers use a key only inside with();
// destroy waits for them, so a key is never wiped while in use, and every
// later use fails with ErrKeyDenied (R6: keys go at once on a lock).
type keyGuard struct {
	mu   sync.RWMutex
	sets []FileKeys
	dead bool
	once sync.Once
}

func (g *keyGuard) add(k FileKeys) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.dead {
		k.Destroy()
		return
	}
	g.sets = append(g.sets, k)
}

func (g *keyGuard) has(p string) bool {
	g.mu.RLock()
	defer g.mu.RUnlock()
	if g.dead {
		return false
	}
	for _, s := range g.sets {
		if b, ok := s.Key(p); ok && b != nil && b.IsAlive() {
			return true
		}
	}
	return false
}

func (g *keyGuard) with(p string, fn func(key []byte) error) error {
	g.mu.RLock()
	defer g.mu.RUnlock()
	if g.dead {
		return fmt.Errorf("%w: keys destroyed", ErrKeyDenied)
	}
	for _, s := range g.sets {
		if b, ok := s.Key(p); ok && b != nil && b.IsAlive() {
			return fn(b.Bytes())
		}
	}
	return fmt.Errorf("%w: no key released for a capsule", ErrKeyDenied)
}

// forget destroys the released key of one capsule once it is decrypted
// (CC-17); the sets keep their other keys. It waits for readers, so a key
// is never wiped while in use.
func (g *keyGuard) forget(p string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, s := range g.sets {
		if b, ok := s.Key(p); ok && b != nil {
			b.Destroy()
		}
	}
}

// maxKeysPerRequest is ipc.MaxKeysPerRequest (sweep never imports ipc): a
// keys request names at most this many capsules (KeySource, CC-17).
const maxKeysPerRequest = 256

// keysPerRequest is the request limit of this run (ports.maxKeys lowers
// it in tests).
func (r *run) keysPerRequest() int {
	if r.p.maxKeys > 0 && r.p.maxKeys < maxKeysPerRequest {
		return r.p.maxKeys
	}
	return maxKeysPerRequest
}

// fetchKeys obtains the file keys of paths in requests of at most
// keysPerRequest capsules and adds them to kg; capsules whose key kg
// already holds are not asked for again.
func (r *run) fetchKeys(ctx context.Context, keys KeySource, kg *keyGuard, paths []string, purpose string) error {
	if keys == nil {
		return fmt.Errorf("%w: no key source", ErrKeyDenied)
	}
	var need []string
	for _, p := range dedupe(paths) {
		if !kg.has(p) {
			need = append(need, p)
		}
	}
	for len(need) > 0 {
		n := min(len(need), r.keysPerRequest())
		fk, err := keys.FileKeys(ctx, need[:n], purpose)
		if err != nil {
			return err
		}
		kg.add(fk)
		need = need[n:]
	}
	return nil
}

func (g *keyGuard) destroy() {
	g.once.Do(func() {
		g.mu.Lock()
		defer g.mu.Unlock()
		g.dead = true
		for _, s := range g.sets {
			s.Destroy()
		}
		g.sets = nil
	})
}

// restore implements Restore.
func (r *run) restore(ctx context.Context, keys KeySource, req RestoreRequest) (*Report, error) {
	if err := ctx.Err(); err != nil {
		return r.finish(), err
	}
	r.recoverAll(ctx)
	if keys == nil {
		return r.finish(), fmt.Errorf("%w: no key source", ErrKeyDenied)
	}
	purpose := req.Purpose
	if purpose == "" {
		purpose = "restore"
	}
	kg := &keyGuard{}
	defer kg.destroy()

	// Abort (any lock event): keys go at once — extraction is cancelled
	// first so no key is wiped under a reader — and the restore stops
	// before the next unit; a unit already staged is rolled forward.
	actx, cancel := context.WithCancel(ctx)
	defer cancel()
	var aborted atomic.Bool
	done := make(chan struct{})
	defer close(done)
	if req.Abort != nil {
		go func() {
			select {
			case <-req.Abort:
				aborted.Store(true)
				cancel()
				kg.destroy()
			case <-done:
			}
		}()
	}

	plans, skipped, err := r.planRestore(actx, keys, kg, req, purpose)
	for _, s := range skipped {
		r.add(s)
	}
	if err != nil {
		return r.finish(), err
	}
	// Keys are requested per batch of whole units, at most
	// maxKeysPerRequest capsules (a unit with more alone, in several
	// requests), right before those units are restored, and each unit's
	// keys are destroyed once its capsules are decrypted (CC-17): the
	// locked memory a restore holds stays bounded.
	stopped := func(rest []*restoreUnitPlan) {
		for _, p := range rest {
			res := planResult(p)
			res.Outcome, res.Detail = OutSkipped, "lock: restore stopped"
			r.add(res)
		}
	}
	for i := 0; i < len(plans); {
		j, n := i, 0
		for j < len(plans) {
			k := len(r.planPaths(plans[j]))
			if j > i && n+k > r.keysPerRequest() {
				break
			}
			n += k
			j++
		}
		batch := plans[i:j]
		if aborted.Load() {
			stopped(plans[i:])
			break
		}
		var paths []string
		for _, p := range batch {
			paths = append(paths, r.planPaths(p)...)
		}
		if err := r.fetchKeys(actx, keys, kg, paths, purpose); err != nil {
			if aborted.Load() {
				stopped(plans[i:])
				break
			}
			for _, p := range plans[i:] {
				r.add(failed(planResult(p), fmt.Errorf("%w: %s", ErrKeyDenied, safeMsg(err))))
			}
			return r.finish(), nil
		}
		for k, p := range batch {
			if aborted.Load() {
				stopped(plans[i+k:])
				return r.finish(), nil
			}
			res := r.restoreUnit(ctx, actx, p, kg, keys, req, purpose, aborted.Load)
			r.add(res)
			for _, path := range r.planPaths(p) {
				kg.forget(path)
			}
			if req.StopOnErr && (res.Outcome == OutFailed || res.Outcome == OutLive) {
				return r.finish(), nil
			}
		}
		i = j
	}
	return r.finish(), nil
}

// planPaths lists every capsule a unit's restore decrypts: its chain (or
// snapshot) and, for snapshots, the blobs the snapshot references.
func (r *run) planPaths(p *restoreUnitPlan) []string {
	var out []string
	for _, en := range p.entries {
		out = append(out, en.Path)
	}
	return dedupe(append(out, r.snapshotBlobPaths(p)...))
}

func planResult(p *restoreUnitPlan) UnitResult {
	return UnitResult{Harness: string(p.ref.Harness), Kind: p.ref.Kind, Unit: p.ref.Key, Gen: p.newest.Gen,
		Lineage: capsule.Lineage(p.newest.Lineage), Bytes: p.bytes}
}

// unitGroups indexes the live log entries by unit (blobs excluded).
func unitGroups(all []capslog.Entry) map[string][]capslog.Entry {
	m := map[string][]capslog.Entry{}
	for _, en := range all {
		if en.Blob {
			continue
		}
		m[en.Unit] = append(m[en.Unit], en)
	}
	for k := range m {
		sort.SliceStable(m[k], func(a, b int) bool { return m[k][a].Gen < m[k][b].Gen })
	}
	return m
}

// lastActivity of a unit's newest entry (its seal time when unknown).
func lastActivity(en capslog.Entry) time.Time {
	if !en.LastActivity.IsZero() {
		return en.LastActivity
	}
	return en.SealedAt
}

// isSnapshotKind reports kinds restored as exactly the newest snapshot.
func isSnapshotKind(k capsule.Kind) bool { return k == capsule.KindCodexHome }

// newPlan builds the plan of one unit from its logged generations.
func newPlan(entries []capslog.Entry) *restoreUnitPlan {
	newest, ok := newestEntry(entries)
	if !ok {
		return nil
	}
	p := &restoreUnitPlan{
		ref: harness.UnitRef{Harness: harness.ID(newest.Harness), Kind: capsule.Kind(newest.Kind), Key: newest.Unit,
			VaultID: newest.VaultID, RootIDs: append([]string(nil), newest.RootIDs...)},
		newest: newest, last: lastActivity(newest),
	}
	if p.ref.Kind == capsule.KindMarkdown {
		p.ref.Harness = "md"
	}
	if isSnapshotKind(p.ref.Kind) || newest.Snapshot {
		p.entries = []capslog.Entry{newest}
	} else {
		p.entries = chain(entries)
	}
	for _, en := range p.entries {
		p.bytes += en.Bytes
	}
	return p
}

// planRestore resolves the request against the capsule log (and the
// manifests, for ProjectDir and Title selectors), newest first within the
// budgets (D38). It returns the plans and the results of skipped units.
func (r *run) planRestore(ctx context.Context, keys KeySource, kg *keyGuard, req RestoreRequest, purpose string) ([]*restoreUnitPlan, []UnitResult, error) {
	all, err := r.log.All()
	if err != nil {
		return nil, nil, err
	}
	groups := unitGroups(all)
	var plans []*restoreUnitPlan
	var skipped []UnitResult
	seen := map[string]bool{}
	for _, ref := range req.Units {
		if seen[ref.Key] {
			continue
		}
		seen[ref.Key] = true
		p := newPlan(groups[ref.Key])
		if p == nil {
			skipped = append(skipped, UnitResult{Harness: string(ref.Harness), Kind: ref.Kind, Unit: ref.Key,
				Outcome: OutSkipped, Detail: "nothing sealed"})
			continue
		}
		if ref.Kind != "" && ref.Kind != p.ref.Kind {
			skipped = append(skipped, UnitResult{Harness: string(ref.Harness), Kind: ref.Kind, Unit: ref.Key,
				Outcome: OutFailed, Detail: codeNotLogged + ": logged kind differs from the request"})
			continue
		}
		p.explicit, p.mtimeNow = true, req.MtimeNow
		plans = append(plans, p)
	}
	defBudget := req.Budget
	if defBudget <= 0 {
		defBudget = r.e.Cfg.Policy.RestoreMaxBytes
	}
	for _, sel := range req.Select {
		cands := r.selectCandidates(groups, sel, seen)
		if sel.ProjectDir != "" || sel.Title != "" || len(sel.SkipEntrypoints) > 0 {
			cands = r.filterByManifest(ctx, keys, kg, cands, sel, purpose)
		}
		sort.SliceStable(cands, func(a, b int) bool { return cands[a].last.After(cands[b].last) })
		keep := len(cands)
		if sel.Newest && keep > 1 {
			keep = 1
		}
		if sel.Recent > 0 && keep > sel.Recent {
			keep = sel.Recent
		}
		for _, p := range cands[keep:] {
			kg.forget(p.newest.Path) // read for the selector only
		}
		cands = cands[:keep]
		budget := sel.MaxBytes
		if budget <= 0 {
			budget = defBudget
		}
		var used int64
		for _, p := range cands {
			if seen[p.ref.Key] {
				continue
			}
			seen[p.ref.Key] = true
			if budget > 0 && used+p.bytes > budget {
				kg.forget(p.newest.Path)
				res := planResult(p)
				res.Outcome, res.Detail = OutSkipped, "budget"
				skipped = append(skipped, res)
				continue
			}
			used += p.bytes
			// A selector's units are clamped by its own MtimeNow only
			// (req.MtimeNow is for explicit Units): the recent sessions
			// `claude -c` restores beside its clamped newest one keep
			// their own times, which Claude's --continue orders by (D102).
			p.mtimeNow = sel.MtimeNow
			p.optional = sel.Optional
			plans = append(plans, p)
		}
	}
	return plans, skipped, nil
}

// selectCandidates applies the log-only filters of a selector. Units of
// the global vault (global stores, generic units: no folder) are restored
// only explicitly (D36, DC-24: restore --global [--harness H]): a selector
// matches them only when it names them — RootID vault.GlobalID (every
// global-vault unit), their kind (KindGlobalStore, KindGeneric) or their
// keys — so a folder's or an everything selector never does. The CLI
// narrows --harness H with the unit keys List reports for H.
func (r *run) selectCandidates(groups map[string][]capslog.Entry, sel harness.Selector, seen map[string]bool) []*restoreUnitPlan {
	keys := map[string]bool{}
	for _, k := range sel.Keys {
		keys[k] = true
	}
	namesGlobal := sel.RootID == globalVault || sel.Kind == capsule.KindGlobalStore || sel.Kind == capsule.KindGeneric || len(keys) > 0
	var out []*restoreUnitPlan
	for unit, entries := range groups {
		if seen[unit] || (len(keys) > 0 && !keys[unit]) {
			continue
		}
		p := newPlan(entries)
		if p == nil {
			continue
		}
		if sel.Kind != "" && p.ref.Kind != sel.Kind {
			continue
		}
		if p.ref.Kind == capsule.KindCodexBlob {
			continue
		}
		global := p.ref.VaultID == globalVault && len(p.ref.RootIDs) == 0
		switch {
		case global && !namesGlobal:
			continue
		case sel.RootID == globalVault:
			if !global {
				continue
			}
		case sel.RootID != "" && !contains(p.ref.RootIDs, sel.RootID):
			continue
		}
		if sel.MaxAge > 0 && p.last.Before(r.now().Add(-sel.MaxAge)) {
			continue
		}
		out = append(out, p)
	}
	sort.SliceStable(out, func(a, b int) bool { return out[a].ref.Key < out[b].ref.Key })
	return out
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// filterByManifest keeps candidates whose newest manifest matches the
// selector's ProjectDir/Title and whose ledger does not record the
// session's creation by one of its SkipEntrypoints (D102) (needs keys for
// those manifests only).
func (r *run) filterByManifest(ctx context.Context, keys KeySource, kg *keyGuard, cands []*restoreUnitPlan, sel harness.Selector, purpose string) []*restoreUnitPlan {
	var paths []string
	for _, p := range cands {
		paths = append(paths, p.newest.Path)
	}
	if len(paths) == 0 {
		return nil
	}
	if err := r.fetchKeys(ctx, keys, kg, paths, purpose); err != nil {
		return nil
	}
	var out []*restoreUnitPlan
	for _, p := range cands {
		m, err := r.readManifest(ctx, p.newest, kg)
		if err != nil {
			kg.forget(p.newest.Path)
			continue
		}
		if (sel.ProjectDir != "" && m.ProjectDir != sel.ProjectDir) ||
			(sel.Title != "" && !strings.Contains(strings.ToLower(m.Title), strings.ToLower(sel.Title))) ||
			(len(sel.SkipEntrypoints) > 0 && slices.Contains(sel.SkipEntrypoints, ledgerEntrypoint(m.Ledger, m.UnitID))) {
			kg.forget(p.newest.Path) // not restored: its key goes now
			continue
		}
		if !m.LastActivity.IsZero() {
			p.last = m.LastActivity
		}
		out = append(out, p)
	}
	return out
}

// creationSources are the SessionStart sources that create a session: a
// new session (startup) and the one /clear starts (clear). A resume,
// compact or fork start names a process that continued the session (or
// copied it), never the one that created it.
var creationSources = []string{"startup", "clear"}

// ledgerEntrypoint returns the entrypoint that the ledger lines of a
// manifest record for the creation of session sid ("cli", "sdk-cli"…): the
// entrypoint of its start line whose source is startup or clear, the
// process whose entrypoint heads the transcript, which is what Claude's
// --continue reads. It returns "" when no such line is there (D102): the
// session was created in an earlier generation (S13 moves only the lines
// since the previous seal into a manifest; a later `claude -p -c` adds a
// resume line of sdk-cli to an interactive session), or became managed
// after its start (a first-contact start), or was forked. Only these
// fields are decoded; lines of another session are skipped, as the ledger
// fold does.
func ledgerEntrypoint(raw []byte, sid string) string {
	for _, line := range bytes.Split(raw, []byte("\n")) {
		var e struct {
			Type       string `json:"type"`
			SID        string `json:"sid"`
			Source     string `json:"source"`
			Entrypoint string `json:"entrypoint"`
		}
		if json.Unmarshal(bytes.TrimSpace(line), &e) == nil && e.Type == string(ledger.TypeStart) &&
			slices.Contains(creationSources, e.Source) && e.Entrypoint != "" && strings.EqualFold(e.SID, sid) {
			return e.Entrypoint
		}
	}
	return ""
}

// splitLogPath splits a capsule log path into its unit directory parts and
// the capsule name relative to the unit directory.
func splitLogPath(p string) (store, unit, rel string, ok bool) {
	parts := strings.SplitN(p, "/", 3)
	if len(parts) != 3 || parts[0] == "" || !validKey(parts[1]) || parts[2] == "" {
		return "", "", "", false
	}
	if !filepath.IsLocal(parts[2]) || path.Clean(parts[2]) != parts[2] {
		return "", "", "", false
	}
	return parts[0], parts[1], parts[2], true
}

// checkProvenance requires the capsule at en.Path to carry the logged
// header (D8, D39): the header hash is the provenance key.
func (r *run) checkProvenance(en capslog.Entry) error {
	store, unit, rel, ok := splitLogPath(en.Path)
	if !ok {
		return fmt.Errorf("%w: malformed capsule path in the log", ErrNotLogged)
	}
	root, dir, err := r.openCapsDir(store, unit, false)
	if err != nil {
		return fmt.Errorf("%w: %s", ErrNotLogged, safeMsg(err))
	}
	defer root.Close()
	defer dir.Close()
	_, hsum, err := r.p.codec.ReadHeader(dir, rel)
	if err != nil {
		return fmt.Errorf("%w: %s", ErrNotLogged, safeMsg(err))
	}
	if _, err := r.log.Lookup(en.Path, hsum); err != nil {
		return err
	}
	return nil
}

// openCapsule opens the logged capsule file for reading.
func (r *run) openCapsule(en capslog.Entry) (io.ReadCloser, error) {
	store, unit, rel, ok := splitLogPath(en.Path)
	if !ok {
		return nil, fmt.Errorf("%w: malformed capsule path in the log", ErrNotLogged)
	}
	root, dir, err := r.openCapsDir(store, unit, false)
	if err != nil {
		return nil, err
	}
	f, _, err := dir.Open(rel)
	dir.Close()
	root.Close()
	if err != nil {
		return nil, err
	}
	return f, nil
}

// readManifest decrypts only the manifest of a logged capsule.
func (r *run) readManifest(ctx context.Context, en capslog.Entry, kg *keyGuard) (capsule.Manifest, error) {
	if err := r.checkProvenance(en); err != nil {
		return capsule.Manifest{}, err
	}
	f, err := r.openCapsule(en)
	if err != nil {
		return capsule.Manifest{}, err
	}
	defer f.Close()
	var m capsule.Manifest
	err = kg.with(en.Path, func(key []byte) error {
		var err error
		m, err = r.p.codec.OpenManifest(f, key)
		return err
	})
	return m, err
}

// checkManifest requires the manifest to agree with its log entry (SPEC
// §11.2): kind, unit key, vault, roots and generation.
func checkManifest(m capsule.Manifest, en capslog.Entry) error {
	switch {
	case string(m.Kind) != en.Kind,
		m.UnitKey != en.Unit,
		m.VaultID != en.VaultID,
		!sameSet(m.RootIDs, en.RootIDs),
		m.Gen != en.Gen:
		return fmt.Errorf("%w: manifest does not match its log entry", harness.ErrUnitKey)
	}
	return nil
}

// authenticated is a unit whose manifest unit id hashes to its logged unit
// key under a registered home or a configured root (SPEC §11.2).
type authenticated struct {
	ref    harness.UnitRef
	unitID string
	ad     harness.Adapter
	rules  harness.TargetRules
	root   string // configured root path (notes, codex)
}

// authenticate finds the registered home or configured root under which
// unitID hashes to the logged key, then asks the adapter for the allowed
// targets (adapters only ever see authenticated ids).
func (r *run) authenticate(ctx context.Context, ref harness.UnitRef, unitID string, en capslog.Entry) (authenticated, error) {
	salt := r.e.Harness.Salt
	if len(salt) == 0 {
		return authenticated{}, fmt.Errorf("%w: no name salt to authenticate unit ids", harness.ErrUnitKey)
	}
	var roots []string
	for _, id := range en.RootIDs {
		if _, ok := r.e.Cfg.RootByID(id); ok {
			roots = append(roots, id)
		}
	}
	a := authenticated{ref: ref, unitID: unitID}
	switch ref.Kind {
	case capsule.KindMarkdown:
		for _, id := range roots {
			k, err := harness.UnitKeyFor(salt, ref.Kind, ref.Harness, "", id, unitID)
			if err == nil && k == ref.Key {
				root, _ := r.e.Cfg.RootByID(id)
				a.root = root.Path
				a.ref.HomeID = ""
				return a, nil
			}
		}
		return authenticated{}, fmt.Errorf("%w: note id does not match its key", harness.ErrUnitKey)
	case capsule.KindCodexHome, capsule.KindCodexBlob:
		ad := adapterFor(r.e, harness.Codex)
		if ad == nil {
			return authenticated{}, fmt.Errorf("%w: no codex adapter", harness.ErrUnknownHarness)
		}
		homes, err := ad.Homes(ctx, r.e.Harness)
		if err != nil {
			return authenticated{}, err
		}
		for _, id := range roots {
			k, err := harness.UnitKeyFor(salt, ref.Kind, harness.Codex, "", id, unitID)
			if err != nil || k != ref.Key {
				continue
			}
			root, _ := r.e.Cfg.RootByID(id)
			a.root = root.Path
			for _, h := range homes {
				if h.RootID == id {
					a.ref.HomeID = h.ID
				}
			}
			a.ad = ad
			rules, err := ad.Targets(ctx, r.e.Harness, a.ref, unitID)
			if err != nil {
				return authenticated{}, err
			}
			a.rules = rules
			return a, nil
		}
		return authenticated{}, fmt.Errorf("%w: codex unit id does not match its key", harness.ErrUnitKey)
	}
	ad := adapterFor(r.e, ref.Harness)
	if ad == nil {
		return authenticated{}, fmt.Errorf("%w: %s", harness.ErrUnknownHarness, ref.Harness)
	}
	homes, err := ad.Homes(ctx, r.e.Harness)
	if err != nil {
		return authenticated{}, err
	}
	rootCands := append([]string{""}, roots...)
	for _, h := range homes {
		if h.ID == "" {
			continue
		}
		for _, id := range rootCands {
			k, err := harness.UnitKeyFor(salt, ref.Kind, ref.Harness, h.ID, id, unitID)
			if err != nil || k != ref.Key {
				continue
			}
			a.ref.HomeID = h.ID
			a.ad = ad
			if id != "" {
				root, _ := r.e.Cfg.RootByID(id)
				a.root = root.Path
			}
			rules, err := ad.Targets(ctx, r.e.Harness, a.ref, unitID)
			if err != nil {
				return authenticated{}, err
			}
			a.rules = rules
			return a, nil
		}
	}
	return authenticated{}, fmt.Errorf("%w: unit id does not match its key under any registered home", harness.ErrUnitKey)
}

// cleanRel reports a local, clean, slash-separated relative path.
func cleanRel(rel string) bool {
	return rel != "" && filepath.IsLocal(rel) && path.Clean(rel) == rel && !strings.HasPrefix(rel, "/")
}

// entryCheck validates every manifest entry against the trusted target
// rules before Extract writes anything (D8, S3).
func entryCheck(rules harness.TargetRules) func(capsule.Entry) error {
	return checkEntries(rules, false)
}

// checkEntries is entryCheck; with skips, an entry of a base the adapter
// reports unsafe now (TargetRules.Skip, e.g. a Claude $TMP that is not
// 0700/owned, S7) passes with a clean rel: it is staged, never placed, and
// reported (CC-22). An entry whose base is in neither Bases nor Skip
// rejects the whole capsule (exit 5).
func checkEntries(rules harness.TargetRules, skips bool) func(capsule.Entry) error {
	return func(en capsule.Entry) error {
		if _, skip := rules.Skip[en.Base]; skip && skips {
			if !cleanRel(en.Rel) {
				return fmt.Errorf("%w: entry path not clean", capsule.ErrUnsafe)
			}
			return nil
		}
		if _, ok := rules.Bases[en.Base]; !ok {
			return fmt.Errorf("%w: entry base not allowed", capsule.ErrUnsafe)
		}
		if !cleanRel(en.Rel) {
			return fmt.Errorf("%w: entry path not clean", capsule.ErrUnsafe)
		}
		if rules.Allow == nil || !rules.Allow(en.Base, en.Rel) {
			return fmt.Errorf("%w: entry outside the unit's targets", capsule.ErrUnsafe)
		}
		return nil
	}
}

// restoreLive reports process-based liveness of a unit about to be
// restored or merged into (I13: never merge into a live unit). Leases are
// not evidence here: the restoring wrapper holds them itself. A probe that
// fails counts as live (fail closed); its error is returned too.
func (r *run) restoreLive(ctx context.Context, ad harness.Adapter, ref harness.UnitRef, unitID string, rules harness.TargetRules) (bool, []live.Evidence, error) {
	if ad == nil {
		return false, nil, nil
	}
	// unitID is the authenticated manifest's (the sid of a session): the
	// adapter's probe looks the session up by it; "" when unknown.
	u := harness.Unit{Harness: ref.Harness, Kind: ref.Kind, Key: ref.Key, UnitID: unitID, VaultID: ref.VaultID, RootIDs: ref.RootIDs,
		Home: harness.Home{Harness: ref.Harness, ID: ref.HomeID, Bases: rules.Bases}}
	ev, err := ad.Probe(ctx, r.e.Harness, u)
	if err != nil {
		return true, ev, err
	}
	var held []live.Evidence
	for _, e := range ev {
		if e.Reason != live.ReasonLease {
			held = append(held, e)
		}
	}
	return len(held) > 0, held, nil
}

// plaintextOnDisk reports whether a file of manifest m is at its place now
// (lstat through the unit's bases, symlinks not followed; anything that
// cannot be looked at counts as not there).
func (r *run) plaintextOnDisk(m capsule.Manifest, bases map[capsule.BaseID]string) bool {
	open := map[capsule.BaseID]dirHandle{}
	defer closeAll(open)
	tried := map[capsule.BaseID]bool{}
	for _, f := range m.Files {
		if f.Dir {
			continue
		}
		d, ok := open[f.Base]
		if !ok {
			if tried[f.Base] || bases[f.Base] == "" {
				continue
			}
			tried[f.Base] = true
			h, err := r.p.fs.OpenBase(bases[f.Base])
			if err != nil {
				continue
			}
			d, open[f.Base] = h, h
		}
		if st, err := d.Lstat(f.Rel); err == nil && st.IsRegular() {
			return true
		}
	}
	return false
}

// checkRestoreSpace requires free space on every volume a restore writes
// (SPEC §11.5 step 2, D38): the staging volume (target, where the whole
// unit is decrypted) needs 1.1 × all the bytes, every other volume 1.1 ×
// the bytes placed on it (splitDevices copies them to a staging there).
// perBase holds the planned bytes per base; bases on target's volume are
// covered by the staging total.
func (r *run) checkRestoreSpace(bases map[capsule.BaseID]string, target string, total int64, perBase map[capsule.BaseID]int64) error {
	devOf := func(p string) (uint64, error) {
		d, err := r.p.fs.OpenBase(p)
		if err != nil {
			return 0, err
		}
		defer d.Close()
		return d.Device()
	}
	tdev, err := devOf(target)
	if err != nil {
		return err
	}
	need := map[uint64]int64{tdev: total}
	at := map[uint64]string{tdev: target}
	ids := make([]string, 0, len(perBase))
	for id := range perBase {
		ids = append(ids, string(id))
	}
	sort.Strings(ids)
	for _, id := range ids {
		p := bases[capsule.BaseID(id)]
		if p == "" {
			continue
		}
		dev, err := devOf(p)
		if err != nil {
			return err
		}
		if dev == tdev {
			continue
		}
		need[dev] += perBase[capsule.BaseID(id)]
		if at[dev] == "" {
			at[dev] = p
		}
	}
	devs := make([]uint64, 0, len(need))
	for dev := range need {
		devs = append(devs, dev)
	}
	sort.Slice(devs, func(a, b int) bool { return devs[a] < devs[b] })
	for _, dev := range devs {
		if err := r.p.fs.CheckSpace(at[dev], int64(math.Ceil(1.1*float64(need[dev]))), r.e.Floor); err != nil {
			return err
		}
	}
	return nil
}

// plannedBytes sums the file entries of manifests per base (an upper
// bound: generations folded into one path count each), and in total.
func plannedBytes(mans []capsule.Manifest) (int64, map[capsule.BaseID]int64) {
	var total int64
	per := map[capsule.BaseID]int64{}
	for _, m := range mans {
		for _, en := range m.Files {
			if en.Dir {
				continue
			}
			total += en.Size
			per[en.Base] += en.Size
		}
	}
	return total, per
}

// firstBase returns a deterministic target base directory.
func firstBase(bases map[capsule.BaseID]string) string {
	var ids []string
	for id := range bases {
		ids = append(ids, string(id))
	}
	sort.Strings(ids)
	for _, id := range ids {
		if p := bases[capsule.BaseID(id)]; p != "" {
			return p
		}
	}
	return ""
}

// errRolledBack marks a unit rolled back by an abort before staging.
var errRolledBack = errors.New("sweep: restore rolled back before staging")

// Results of an optional unit that is live at restore (D132): in use
// elsewhere with its plaintext on disk (left as it is), in use elsewhere
// while sealed (not restored: the launch goes on without it), or whose
// liveness probe failed (not restored either; the detail names the error).
const (
	detailInUse         = "in use elsewhere: left as it is"
	detailInUseSealed   = "in use elsewhere: not restored"
	detailProbeFailedAt = "not restored: its liveness check failed: "
)

// restoreUnit restores one unit (SPEC §11.5).
func (r *run) restoreUnit(ctx, actx context.Context, p *restoreUnitPlan, kg *keyGuard, keys KeySource, req RestoreRequest, purpose string, aborted func() bool) UnitResult {
	res := planResult(p)
	lk, err := r.lockUnit(p.ref.Key)
	if err != nil {
		return failed(res, err)
	}
	defer lk.Unlock()
	for _, en := range p.entries {
		if err := r.checkProvenance(en); err != nil {
			return failed(res, err)
		}
	}
	mans := make([]capsule.Manifest, len(p.entries))
	for i, en := range p.entries {
		m, err := r.readManifest(actx, en, kg)
		if err != nil {
			return failed(res, err)
		}
		if err := checkManifest(m, en); err != nil {
			return failed(res, err)
		}
		if i > 0 && m.UnitID != mans[0].UnitID {
			return failed(res, fmt.Errorf("%w: generations disagree on the unit id", harness.ErrUnitKey))
		}
		mans[i] = m
	}
	p.mans = mans
	auth, err := r.authenticate(ctx, p.ref, mans[0].UnitID, p.newest)
	if err != nil {
		return failed(res, err)
	}
	if p.ref.Kind == capsule.KindMarkdown {
		return r.restoreNote(ctx, actx, p, auth, mans[0], kg, req, aborted)
	}
	if isLive, ev, perr := r.restoreLive(ctx, auth.ad, auth.ref, mans[0].UnitID, auth.rules); isLive {
		if p.optional {
			// D132: a unit restored beside the launch's target that is in
			// use elsewhere is left as it is; the launch goes on.
			res.Outcome, res.Evidence = OutSkipped, ev
			switch {
			case perr != nil:
				res.Detail = detailProbeFailedAt + safeMsg(perr)
			case r.plaintextOnDisk(mans[0], auth.rules.Bases):
				res.Detail = detailInUse
			default:
				res.Detail = detailInUseSealed
			}
			return res
		}
		res = liveResult(res, live.Verdict{Live: true, Evidence: ev}, true, "unit live at restore")
		return res
	}
	if isSnapshotKind(p.ref.Kind) {
		return r.restoreSnapshot(ctx, actx, p, auth, mans[0], kg, keys, req, purpose, aborted)
	}
	return r.restoreLayered(ctx, actx, p, auth, kg, req, aborted)
}
