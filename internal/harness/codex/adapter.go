package codex

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/precinto/precinto/internal/capsule"
	"github.com/precinto/precinto/internal/config"
	"github.com/precinto/precinto/internal/fsx"
	"github.com/precinto/precinto/internal/harness"
	"github.com/precinto/precinto/internal/live"
	"github.com/precinto/precinto/internal/paths"
	"github.com/precinto/precinto/internal/platform"
	"github.com/precinto/precinto/inventories"
)

const (
	harnessName = string(harness.Codex)
	// Catalog ids carried by launch plans (rendered by the wrapper).
	msgConsent       = "C10.consent"      // first use of a folder's sealed Codex history
	msgUntrusted     = "C9.codex"         // precinto's hooks are not trusted in the home
	msgModified      = "C9.codexmodified" // trusted for other hook declarations: Codex 0.154 skips them (D98)
	msgPluginMissing = "C9.codexplugin"   // the home does not load precinto's plugin (D99)
	// hookPresenceWithin is Codex's UserPromptSubmit window after the first
	// Enter (SPEC §14.4).
	hookPresenceWithin = 5 * time.Second
	// sessionEndBudget is Codex's SessionEnd hook budget (HOOKS-IO §1).
	sessionEndBudget = 3 * time.Second
	maxHomeEntries   = capsule.MaxEntries
)

var errNoSalt = errors.New("codex: no name salt")

// adapter is the Codex adapter with per-root homes (D31, SPEC §7.2).
type adapter struct {
	inv    harness.Inventory
	invErr error
}

func newAdapter() harness.Adapter {
	inv, err := harness.LoadInventory(inventories.FS, harnessName)
	return &adapter{inv: inv, invErr: err}
}

func (a *adapter) ID() harness.ID { return harness.Codex }

func homeIDOf(dir string) string {
	sum := sha256.Sum256([]byte(dir))
	return hex.EncodeToString(sum[:])[:16]
}

// rootHome returns the per-root home of a root (D31).
func rootHome(e harness.Env, r config.Root) harness.Home {
	dir := e.Layout.CodexHome(r.ID)
	return harness.Home{
		Harness: harness.Codex,
		ID:      homeIDOf(resolve(dir)),
		Bases:   map[capsule.BaseID]string{capsule.BaseCodexHome: dir},
		RootID:  r.ID,
	}
}

func (a *adapter) Homes(ctx context.Context, e harness.Env) ([]harness.Home, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if e.Layout.HomesDir == "" {
		return nil, fmt.Errorf("codex: no layout")
	}
	out := make([]harness.Home, 0, len(e.Cfg.Roots))
	for _, r := range e.Cfg.Roots {
		out = append(out, rootHome(e, r))
	}
	return out, nil
}

func inScope(s harness.Scope, rootID string) bool {
	if len(s.RootIDs) == 0 {
		return true
	}
	for _, r := range s.RootIDs {
		if r == rootID {
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

// Scan returns one codex-home unit per protected root whose per-root home
// holds content (D31, D42): every file except the never-touch list, SQLite
// files in groups, -shm never. A Codex session is sealed with its home,
// never alone: a scope naming sessions (SIDs) returns the homes that hold
// one of them. Scope.Procs and Scope.Adopt are ignored: a home is no
// session, and there is nothing to adopt (CC-21).
func (a *adapter) Scan(ctx context.Context, e harness.Env, s harness.Scope) ([]harness.Unit, error) {
	if a.invErr != nil {
		return nil, a.invErr
	}
	if len(e.Salt) == 0 {
		return nil, errNoSalt
	}
	if !wantKind(s, capsule.KindCodexHome) {
		return nil, nil
	}
	var out []harness.Unit
	var errs []error
	for _, r := range e.Cfg.Roots {
		if !inScope(s, r.ID) {
			continue
		}
		u, ok, err := a.scanHome(ctx, e, r)
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			errs = append(errs, fmt.Errorf("codex: home of %s: %w", r.ID, err))
			continue
		}
		if ok && (len(s.SIDs) == 0 || holdsSession(e, u, s.SIDs)) {
			out = append(out, u)
		}
	}
	return out, errors.Join(errs...)
}

// holdsSession reports whether the home of u holds one of the sessions
// sids: its ledger names the home (CODEX_HOME, recorded by the hooks), or a
// rollout of the home carries the session id in its name
// (rollout-<time>-<id>.jsonl[.zst]).
func holdsSession(e harness.Env, u harness.Unit, sids []string) bool {
	home := u.Home.Bases[capsule.BaseCodexHome]
	real := resolve(home)
	for _, sid := range sids {
		id := strings.ToLower(sid)
		if id == "" {
			continue
		}
		for _, name := range []string{sid, id} {
			if e.Ledger == nil {
				break
			}
			s, err := e.Ledger.Get(harnessName, name)
			if err != nil {
				continue
			}
			for _, d := range s.ConfigDirs {
				if filepath.Clean(d) == home || resolve(d) == real {
					return true
				}
			}
		}
		for _, f := range u.Files {
			name := strings.ToLower(path.Base(f.Rel))
			if strings.HasPrefix(name, "rollout-") && strings.Contains(name, id) {
				return true
			}
		}
	}
	return false
}

func (a *adapter) scanHome(ctx context.Context, e harness.Env, r config.Root) (harness.Unit, bool, error) {
	h := rootHome(e, r)
	dir := h.Bases[capsule.BaseCodexHome]
	st, err := fsx.Lstat(dir)
	if errors.Is(err, os.ErrNotExist) {
		return harness.Unit{}, false, nil
	}
	if err != nil {
		return harness.Unit{}, false, err
	}
	if !st.IsDir() || int(st.UID) != os.Getuid() {
		return harness.Unit{}, false, errUnsafeHome
	}
	key, err := harness.UnitKeyFor(e.Salt, capsule.KindCodexHome, harness.Codex, "", r.ID, "")
	if err != nil {
		return harness.Unit{}, false, err
	}
	u := harness.Unit{
		Harness: harness.Codex, Kind: capsule.KindCodexHome, Key: key, UnitID: r.ID,
		VaultID: r.ID, RootIDs: []string{r.ID}, Home: h, Mode: harness.GenSnapshot,
		LeaseKeys: []string{key},
	}
	w := &homeWalker{ctx: ctx, base: dir, u: &u}
	if err := w.walk(dir, ""); err != nil {
		return harness.Unit{}, false, err
	}
	if len(u.Files)+len(u.Dirs)+len(u.Hazards) == 0 {
		return harness.Unit{}, false, nil
	}
	sort.Slice(u.Prune, func(i, j int) bool {
		di, dj := strings.Count(u.Prune[i], "/"), strings.Count(u.Prune[j], "/")
		if di != dj {
			return di > dj
		}
		return u.Prune[i] < u.Prune[j]
	})
	u.Paths = append([]string{dir}, u.Paths...)
	u.Procs = owners(e, dir)
	return u, true, nil
}

type homeWalker struct {
	ctx   context.Context
	base  string
	u     *harness.Unit
	count int
}

// walk records content below dir (home-relative rel), never following
// symlinks; never-touch entries are skipped, hazards reported.
func (w *homeWalker) walk(dir, rel string) error {
	des, err := os.ReadDir(dir)
	if err != nil {
		if rel == "" {
			return err
		}
		w.u.Hazards = append(w.u.Hazards, harness.Hazard{Base: capsule.BaseCodexHome, Rel: rel, Hazard: fsx.HazardAccess})
		return nil
	}
	if rel != "" && len(des) == 0 {
		st, err := fsx.Lstat(dir)
		if err == nil {
			w.u.Dirs = append(w.u.Dirs, harness.File{Base: capsule.BaseCodexHome, Rel: rel, Snap: st})
		}
	}
	for _, de := range des {
		w.count++
		if w.count%1024 == 0 {
			if err := w.ctx.Err(); err != nil {
				return err
			}
		}
		if w.count > maxHomeEntries {
			return fmt.Errorf("codex: home has more than %d entries", maxHomeEntries)
		}
		crel := de.Name()
		if rel != "" {
			crel = rel + "/" + de.Name()
		}
		abs := filepath.Join(dir, de.Name())
		class := classify(crel)
		if class == ClassNeverTouch || class == ClassSHM {
			continue
		}
		st, err := fsx.Lstat(abs)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			w.u.Hazards = append(w.u.Hazards, harness.Hazard{Base: capsule.BaseCodexHome, Rel: crel, Hazard: fsx.HazardAccess})
			continue
		}
		switch hz := hazardOf(st); {
		case hz != fsx.HazardNone:
			w.u.Hazards = append(w.u.Hazards, harness.Hazard{Base: capsule.BaseCodexHome, Rel: crel, Hazard: hz})
		case st.IsDir():
			w.u.Prune = append(w.u.Prune, string(capsule.BaseCodexHome)+":"+crel)
			w.u.Paths = append(w.u.Paths, abs)
			if err := w.walk(abs, crel); err != nil {
				return err
			}
		default:
			f := harness.File{Base: capsule.BaseCodexHome, Rel: crel, Snap: st, Placement: harness.PlaceExact}
			switch class {
			case ClassSQLiteMain, ClassSQLiteSide:
				f.Placement, f.Group = harness.PlaceSQLiteGroup, groupOf(crel)
			default:
				if lineUnion(crel) {
					f.Placement = harness.PlaceLineUnion
				}
				f.Append = strings.HasSuffix(strings.ToLower(crel), ".jsonl")
			}
			w.u.Files = append(w.u.Files, f)
			w.u.Paths = append(w.u.Paths, abs)
			if t := time.Unix(0, st.MtimeNS); t.After(w.u.LastActivity) {
				w.u.LastActivity = t.UTC()
			}
		}
	}
	return nil
}

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

// owners returns the current processes of ledger sessions that used home.
func owners(e harness.Env, home string) []platform.ProcID {
	if e.Ledger == nil {
		return nil
	}
	sessions, err := e.Ledger.List(harnessName)
	if err != nil {
		return nil
	}
	real := resolve(home)
	var out []platform.ProcID
	seen := map[platform.ProcID]bool{}
	for _, s := range sessions {
		uses := false
		for _, d := range s.ConfigDirs {
			if filepath.Clean(d) == home || resolve(d) == real {
				uses = true
			}
		}
		if uses && !s.CurrentProc.IsZero() && !seen[s.CurrentProc] {
			seen[s.CurrentProc] = true
			out = append(out, s.CurrentProc)
		}
	}
	return out
}

// Probe returns E6 evidence for a per-root home: any process holding a
// descriptor below it (writer and maintenance locks are found this way,
// never by flocking them, HA17). A failed check is live (HA9, R11).
func (a *adapter) Probe(ctx context.Context, e harness.Env, u harness.Unit) ([]live.Evidence, error) {
	if err := ctx.Err(); err != nil {
		return []live.Evidence{{Reason: live.ReasonUnknown, Detail: "cancelled"}}, err
	}
	if e.Procs == nil {
		return []live.Evidence{{Reason: live.ReasonUnknown, Detail: "no process table"}}, nil
	}
	home := u.Home.Bases[capsule.BaseCodexHome]
	if !filepath.IsAbs(home) {
		return []live.Evidence{{Reason: live.ReasonUnknown, Detail: "unit without a home"}}, nil
	}
	if st, err := fsx.Lstat(home); errors.Is(err, os.ErrNotExist) {
		return nil, nil
	} else if err != nil || !st.IsDir() {
		return []live.Evidence{{Reason: live.ReasonUnknown, Detail: "home unreadable"}}, nil
	}
	holders, err := e.Procs.OpenFilesUnder(ctx, []string{home})
	if err != nil {
		return []live.Evidence{{Reason: live.ReasonOpenFD, Path: home, Detail: "open-file check failed"}}, nil
	}
	locks := filepath.Join(home, "thread-writer-locks")
	maint := filepath.Join(home, "rollout-maintenance.lock")
	var out []live.Evidence
	for _, h := range holders {
		ev := live.Evidence{Reason: live.ReasonOpenFD, Proc: h.Proc.ID, Path: h.Path, Detail: "open descriptor below the home"}
		if paths.Within(locks, h.Path) || paths.Within(maint, h.Path) {
			ev.Reason, ev.Detail = live.ReasonWriterLock, "writer lock held"
		}
		out = append(out, ev)
	}
	return out, nil
}

// Targets allows exactly the content set of the root's own home (SPEC
// §11.2): never-touch files and -shm are rejected.
func (a *adapter) Targets(ctx context.Context, e harness.Env, ref harness.UnitRef, unitID string) (harness.TargetRules, error) {
	if err := ctx.Err(); err != nil {
		return harness.TargetRules{}, err
	}
	if ref.Harness != harness.Codex {
		return harness.TargetRules{}, fmt.Errorf("%w: %s", harness.ErrUnknownHarness, ref.Harness)
	}
	if len(ref.RootIDs) == 0 {
		return harness.TargetRules{}, fmt.Errorf("%w: no root", harness.ErrUnitKey)
	}
	root, ok := e.Cfg.RootByID(ref.RootIDs[0])
	if !ok {
		return harness.TargetRules{}, harness.ErrNotManaged
	}
	switch ref.Kind {
	case capsule.KindCodexHome:
		if unitID != "" && unitID != root.ID {
			return harness.TargetRules{}, fmt.Errorf("%w: codex home unit id", harness.ErrUnitKey)
		}
	case capsule.KindCodexBlob:
		if _, ok := relParts(unitID); !ok || strings.Contains(unitID, "/") {
			return harness.TargetRules{}, fmt.Errorf("%w: blob id", harness.ErrUnitKey)
		}
	default:
		return harness.TargetRules{}, fmt.Errorf("%w: kind %s is not a Codex kind", harness.ErrUnitKey, ref.Kind)
	}
	home := e.Layout.CodexHome(root.ID)
	return harness.TargetRules{
		Bases: map[capsule.BaseID]string{capsule.BaseCodexHome: home},
		Allow: func(base capsule.BaseID, rel string) bool {
			if base != capsule.BaseCodexHome {
				return false
			}
			switch classify(rel) {
			case ClassContent, ClassSQLiteMain, ClassSQLiteSide:
				return true
			}
			return false
		},
		Policy: func(en capsule.Entry) harness.Placement {
			switch classify(en.Rel) {
			case ClassSQLiteMain, ClassSQLiteSide:
				return harness.PlaceSQLiteGroup
			}
			if lineUnion(en.Rel) {
				return harness.PlaceLineUnion
			}
			return harness.PlaceExact
		},
		Mode: harness.GenSnapshot,
	}, nil
}

// PlanLaunch plans `precinto run codex` (SPEC §7.2): inside a protected
// root Codex runs on the root's sealed home (CODEX_HOME, CODEX_SQLITE_HOME,
// TMPDIR), seeded by Prepare, restored whole before exec and synced back
// by Finish; outside every root, and for passthrough commands, it runs
// unmanaged.
func (a *adapter) PlanLaunch(ctx context.Context, e harness.Env, cwd string, argv []string) (harness.LaunchPlan, error) {
	if err := ctx.Err(); err != nil {
		return harness.LaunchPlan{}, err
	}
	if a.invErr != nil {
		return harness.LaunchPlan{}, a.invErr
	}
	if len(argv) == 0 {
		return harness.LaunchPlan{}, fmt.Errorf("codex: empty argv")
	}
	if !filepath.IsAbs(cwd) {
		return harness.LaunchPlan{}, fmt.Errorf("codex: cwd %q is not absolute", cwd)
	}
	args := append([]string(nil), argv[1:]...)
	exe, err := a.resolveExe(e, argv[0])
	if err != nil {
		return harness.LaunchPlan{}, err
	}
	plan := harness.LaunchPlan{
		Harness: harness.Codex,
		Mode:    a.inv.Classify(args, true, true),
		Resume:  parseResume(args, a.inv),
		Argv:    append([]string{exe}, args...),
		// Codex installs no SIGTERM handler: Ctrl-C twice makes it exit
		// cleanly (HA19); its SessionEnd hooks get 3 s (HOOKS-IO §1).
		QuitKeys:  []byte{0x03, 0x03},
		KillGrace: harness.KillGrace(sessionEndBudget),
	}
	// Roots are realpath'd in config: a launch through a symlink into a
	// folder runs on the folder's sealed home too.
	root, ok := e.Cfg.RootFor(resolve(cwd))
	if !ok || plan.Mode == harness.LaunchPassthrough {
		plan.Mode = harness.LaunchPassthrough // unmanaged: the user's own home (D31)
		if ok {
			plan.Roots = []config.Root{root}
		}
		return plan, nil
	}
	user, err := userHome(e.Host)
	if err != nil {
		return harness.LaunchPlan{}, err
	}
	home := e.Layout.CodexHome(root.ID)
	if filepath.Clean(user) == filepath.Clean(home) {
		user = "" // running inside the sealed home already: nothing to seed from
	}
	key, err := harness.UnitKeyFor(e.Salt, capsule.KindCodexHome, harness.Codex, "", root.ID, "")
	if err != nil {
		return harness.LaunchPlan{}, err
	}
	seed := Seed{UserHome: user, RootHome: home}
	plan.Roots = []config.Root{root}
	plan.Env = launchEnv(home)
	plan.Sync = []harness.Selector{{Kind: capsule.KindCodexHome, RootID: root.ID, Keys: []string{key}}}
	plan.Lease = []string{key}
	plan.SealScope = harness.Scope{RootIDs: []string{root.ID}, Kinds: []capsule.Kind{capsule.KindCodexHome}}
	if plan.Resume.Kind == harness.ResumeSID && !plan.Resume.Fork {
		// The resumed session is known (CC-21): it is sealed with its home.
		plan.SealScope.SIDs = []string{plan.Resume.Value}
	}
	plan.HookCheck = harness.HookCheck{Event: "UserPromptSubmit", Within: hookPresenceWithin, OnInput: true}
	plan.Prepare = func(ctx context.Context) error { return prepareHome(ctx, seed) }
	plan.Finish = func(ctx context.Context, _ int) error {
		if seed.UserHome == "" {
			return nil
		}
		return syncAuthBack(ctx, seed)
	}
	folder := root.Path
	if h, err := paths.UserHome(e.Host); err == nil {
		folder = paths.Tilde(h, root.Path)
	}
	switch {
	case !managesCodex(root):
		// D72: consent is per folder, in config. A folder that does not
		// list codex asks first (yes adds it, a strengthening edit by the
		// caller; no starts nothing, CC-20); a missing home is only the
		// first launch of a folder that consented.
		plan.Confirm = msgConsent
		plan.MsgVars = map[string]string{"folder": folder}
	case homeExists(home):
		// Prepare seeds a new home from the user's config; an existing one
		// is checked for precinto's hooks as Prepare will leave it (the
		// plugin tables it adds and the plugins/ link, D99), before the
		// question is asked (UX10): the plugin must load, and its hooks be
		// trusted for their current declarations (D98).
		switch st, _ := homeTrust(home, user); st {
		case trustPluginMissing:
			plan.Confirm = msgPluginMissing
			plan.MsgVars = map[string]string{"folder": folder}
		case trustModified:
			// Codex 0.154 skips them; precinto cannot tell the version
			// here, so the question is worded conditionally (D98).
			plan.Confirm = msgModified
		case trustUntrusted:
			plan.Confirm = msgUntrusted
		}
	}
	return plan, nil
}

// managesCodex reports whether a folder manages Codex (D72): its harness
// list names codex; an empty list is the default, every built-in harness.
func managesCodex(r config.Root) bool {
	if len(r.Harnesses) == 0 {
		return true
	}
	for _, h := range r.Harnesses {
		if h == harnessName {
			return true
		}
	}
	return false
}

// homeExists reports whether the per-root home is a directory already.
func homeExists(home string) bool {
	st, err := fsx.Lstat(home)
	return err == nil && st.IsDir()
}

func (a *adapter) resolveExe(e harness.Env, name string) (string, error) {
	if filepath.IsAbs(name) {
		return filepath.Clean(name), nil
	}
	if bin := e.Cfg.Harness[harnessName].Bin; filepath.IsAbs(bin) {
		return filepath.Clean(bin), nil
	}
	p, err := paths.LookPath(e.Host, name)
	if err != nil {
		return "", fmt.Errorf("codex: %s not found: %w", name, err)
	}
	return p, nil
}

// parseResume classifies Codex resume arguments: `resume <id>`, `resume
// --last`, `resume` (picker) and `fork <id>`, also below `exec`.
func parseResume(args []string, inv harness.Inventory) harness.Resume {
	subs := inv.Resume.Subcommand
	if len(subs) == 0 {
		subs = []string{"resume", "fork"}
	}
	cont := inv.Resume.Continue
	if len(cont) == 0 {
		cont = []string{"--last"}
	}
	i := 0
	if len(args) > 0 && args[0] == "exec" {
		i = 1
	}
	if i >= len(args) || !oneOf(args[i], subs) {
		return harness.Resume{}
	}
	r := harness.Resume{Kind: harness.ResumePicker, Fork: args[i] == "fork"}
	for _, a := range args[i+1:] {
		if a == "--" {
			break
		}
		switch {
		case oneOf(a, cont):
			r.Kind, r.Value = harness.ResumeContinue, ""
		case !strings.HasPrefix(a, "-") && r.Kind == harness.ResumePicker:
			if isUUID(a) {
				r.Kind, r.Value = harness.ResumeSID, strings.ToLower(a)
			} else {
				r.Kind, r.Value = harness.ResumeName, a
			}
		}
	}
	return r
}

func oneOf(s string, list []string) bool {
	for _, x := range list {
		if s == x {
			return true
		}
	}
	return false
}

func isUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i := 0; i < 36; i++ {
		c := s[i]
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return false
			}
		default:
			if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
				return false
			}
		}
	}
	return true
}

// MarkdownPaths returns the Markdown files apply_patch calls in the home's
// rollouts wrote (S6, HA25).
func (a *adapter) MarkdownPaths(ctx context.Context, e harness.Env, u harness.Unit) ([]string, error) {
	home := u.Home.Bases[capsule.BaseCodexHome]
	if u.Kind != capsule.KindCodexHome || !filepath.IsAbs(home) {
		return nil, nil
	}
	var out []string
	seen := map[string]bool{}
	for _, f := range u.Files {
		name := filepath.Base(f.Rel)
		if !strings.HasPrefix(name, "rollout-") || !strings.HasSuffix(name, ".jsonl") {
			continue
		}
		mds, err := rolloutMarkdown(ctx, filepath.Join(home, filepath.FromSlash(f.Rel)))
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			continue
		}
		for _, p := range mds {
			if !seen[p] {
				seen[p] = true
				out = append(out, p)
			}
		}
	}
	sort.Strings(out)
	return out, nil
}

// Describe returns no title for a home snapshot (it holds many sessions)
// and its newest content time.
func (a *adapter) Describe(ctx context.Context, e harness.Env, u harness.Unit) (string, time.Time, error) {
	if err := ctx.Err(); err != nil {
		return "", time.Time{}, err
	}
	last := u.LastActivity
	for _, f := range u.Files {
		if t := time.Unix(0, f.Snap.MtimeNS); f.Snap.MtimeNS != 0 && t.After(last) {
			last = t
		}
	}
	return "", last.UTC(), nil
}
