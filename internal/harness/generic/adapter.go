package generic

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/precinto/precinto/internal/capsule"
	"github.com/precinto/precinto/internal/fsx"
	"github.com/precinto/precinto/internal/harness"
	"github.com/precinto/precinto/internal/live"
	"github.com/precinto/precinto/internal/paths"
	"github.com/precinto/precinto/internal/platform"
)

const (
	// partitionHomeID is the partition of files outside any project
	// partition (and of every file with partition = "home").
	partitionHomeID = "home"
	maxEntries      = capsule.MaxEntries
	maxLockBytes    = 64 << 10
)

var (
	errNoSalt = errors.New("generic: no name salt")
	// errPlaceholder: a base default needs a per-root placeholder, which
	// experimental harnesses do not have.
	errPlaceholder = errors.New("generic: base default uses an unsupported placeholder")
)

// adapter is one experimental, data-driven harness (D33): wrapper-only, no
// hooks, sealed only by `precinto seal --dormant <id> --experimental`
// (internal/sweep scans it only then), never restored automatically.
type adapter struct {
	inv harness.Inventory
}

func newAdapter(inv harness.Inventory) harness.Adapter { return &adapter{inv: inv} }

// adapters implements Adapters: every inventory that is not built in;
// experimental ones only when experimental is set.
func adapters(fsys fs.FS, experimental bool) ([]harness.Adapter, error) {
	invs, err := harness.LoadInventories(fsys)
	if err != nil {
		return nil, err
	}
	var out []harness.Adapter
	for _, inv := range invs {
		if inv.ID == string(harness.ClaudeCode) || inv.ID == string(harness.Codex) {
			continue
		}
		if inv.Status == "experimental" && !experimental {
			continue
		}
		out = append(out, newAdapter(inv))
	}
	return out, nil
}

func (a *adapter) ID() harness.ID { return harness.ID(a.inv.ID) }

func baseID(name string) capsule.BaseID {
	return capsule.BaseID(string(capsule.BaseGeneric) + ":" + name)
}

func homeID(dir string) string {
	sum := sha256.Sum256([]byte(dir))
	return hex.EncodeToString(sum[:])[:16]
}

func resolve(p string) string {
	if r, err := filepath.EvalSymlinks(p); err == nil {
		return r
	}
	return filepath.Clean(p)
}

// xdgDefaults are the XDG base directories relative to HOME when unset.
var xdgDefaults = map[string]string{
	"XDG_DATA_HOME": ".local/share", "XDG_CONFIG_HOME": ".config",
	"XDG_CACHE_HOME": ".cache", "XDG_STATE_HOME": ".local/state",
}

// resolveBase resolves one base in the harness's own environment: its
// relocation variable when set (absolute), else its default with ~, $VAR
// and {uid}/{base} expanded.
func resolveBase(b harness.BaseSpec, e harness.Env) (dir string, relocated bool, err error) {
	if b.Env != "" {
		if v := e.Host.Get(b.Env); filepath.IsAbs(v) {
			return resolve(v), true, nil
		}
	}
	d := b.Default
	if strings.Contains(d, "{root_id}") {
		return "", false, errPlaceholder
	}
	d = strings.ReplaceAll(d, "{uid}", strconv.Itoa(os.Getuid()))
	if strings.Contains(d, "{base}") {
		if e.Layout.Base == "" {
			return "", false, errPlaceholder
		}
		d = strings.ReplaceAll(d, "{base}", e.Layout.Base)
	}
	switch {
	case strings.HasPrefix(d, "~/"):
		h, err := paths.UserHome(e.Host)
		if err != nil {
			return "", false, err
		}
		d = filepath.Join(h, d[2:])
	case strings.HasPrefix(d, "$"):
		v, rest, _ := strings.Cut(d[1:], "/")
		val := e.Host.Get(v)
		if !filepath.IsAbs(val) {
			def, ok := xdgDefaults[v]
			if !ok {
				return "", false, fmt.Errorf("generic: %s is not set", v)
			}
			h, err := paths.UserHome(e.Host)
			if err != nil {
				return "", false, err
			}
			val = filepath.Join(h, def)
		}
		d = filepath.Join(val, rest)
	}
	if !filepath.IsAbs(d) {
		return "", false, fmt.Errorf("generic: base %s does not resolve to an absolute path", b.Name)
	}
	return resolve(d), false, nil
}

func (a *adapter) home(e harness.Env) (harness.Home, error) {
	bases := map[capsule.BaseID]string{}
	h := harness.Home{Harness: a.ID(), Default: true}
	for i, b := range a.inv.Bases {
		dir, relocated, err := resolveBase(b, e)
		if err != nil {
			return harness.Home{}, err
		}
		if relocated {
			h.Default = false
		}
		bases[baseID(b.Name)] = dir
		if i == 0 {
			h.ID = homeID(dir)
		}
	}
	h.Bases = bases
	return h, nil
}

func (a *adapter) Homes(ctx context.Context, e harness.Env) ([]harness.Home, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	h, err := a.home(e)
	if err != nil {
		return nil, err
	}
	return []harness.Home{h}, nil
}

// splitGlob splits "<base>:<glob>" (a bare glob uses the only base).
func (a *adapter) splitGlob(g string) (string, string, bool) {
	if b, rest, ok := strings.Cut(g, ":"); ok {
		return b, rest, true
	}
	if len(a.inv.Bases) == 1 {
		return a.inv.Bases[0].Name, g, true
	}
	return "", "", false
}

// matchGlob matches '/'-separated rel against a glob of path.Match
// components where "**" spans any number of components.
func matchGlob(pattern, rel string) bool {
	return matchParts(strings.Split(pattern, "/"), strings.Split(rel, "/"))
}

func matchParts(pat, parts []string) bool {
	for len(pat) > 0 {
		if pat[0] == "**" {
			if len(pat) == 1 {
				return true
			}
			for i := 0; i <= len(parts); i++ {
				if matchParts(pat[1:], parts[i:]) {
					return true
				}
			}
			return false
		}
		if len(parts) == 0 {
			return false
		}
		if ok, err := path.Match(pat[0], parts[0]); err != nil || !ok {
			return false
		}
		pat, parts = pat[1:], parts[1:]
	}
	return len(parts) == 0
}

// member reports whether (base, rel) is content of the inventory: matched
// by a content glob and by no exclude or never-touch glob.
func (a *adapter) member(base, rel string) bool {
	in := false
	for _, g := range a.inv.Content {
		if b, gl, ok := a.splitGlob(g); ok && b == base && matchGlob(gl, rel) {
			in = true
			break
		}
	}
	if !in {
		return false
	}
	for _, list := range [][]string{a.inv.Exclude, a.inv.NeverTouch} {
		for _, g := range list {
			if b, gl, ok := a.splitGlob(g); ok && b == base && matchGlob(gl, rel) {
				return false
			}
		}
	}
	return true
}

// partitionOf returns the partition id of a content file (D33): "home",
// the slug directory matched by slug_glob (project-slug), or the first
// directory below a content glob's fixed prefix (project-dir).
func (a *adapter) partitionOf(base, rel string) string {
	parts := strings.Split(rel, "/")
	switch a.inv.Partition {
	case "project-slug":
		b, gl, ok := a.splitGlob(a.inv.SlugGlob)
		if !ok || b != base {
			return partitionHomeID
		}
		n := len(strings.Split(gl, "/"))
		if len(parts) > n && matchGlob(gl, strings.Join(parts[:n], "/")) {
			return base + "/" + strings.Join(parts[:n], "/")
		}
	case "project-dir":
		for _, g := range a.inv.Content {
			b, gl, ok := a.splitGlob(g)
			if !ok || b != base {
				continue
			}
			prefix := fixedPrefix(gl)
			if len(parts) > len(prefix)+1 && hasPrefix(parts, prefix) {
				return base + "/" + strings.Join(parts[:len(prefix)+1], "/")
			}
		}
	}
	return partitionHomeID
}

func fixedPrefix(glob string) []string {
	var out []string
	for _, c := range strings.Split(glob, "/") {
		if strings.ContainsAny(c, "*?[\\") {
			break
		}
		out = append(out, c)
	}
	return out
}

func hasPrefix(parts, prefix []string) bool {
	if len(parts) < len(prefix) {
		return false
	}
	for i := range prefix {
		if parts[i] != prefix[i] {
			return false
		}
	}
	return true
}

func wantGeneric(s harness.Scope) bool {
	for _, k := range s.Kinds {
		if k == capsule.KindGeneric {
			return true
		}
	}
	return false
}

// Scan lists the experimental harness's partitions only when the scope
// asks for generic units explicitly (`seal --dormant`): an ordinary sweep
// never seals experimental data (SPEC §7.3). Units belong to the global
// vault: experimental stores cannot be attributed to a folder.
func (a *adapter) Scan(ctx context.Context, e harness.Env, s harness.Scope) ([]harness.Unit, error) {
	if !wantGeneric(s) || len(s.SIDs) > 0 || (len(s.RootIDs) > 0 && !s.Global) {
		return nil, nil
	}
	if len(e.Salt) == 0 {
		return nil, errNoSalt
	}
	h, err := a.home(e)
	if err != nil {
		return nil, err
	}
	units := map[string]*harness.Unit{}
	var order []string
	unit := func(part string) *harness.Unit {
		u := units[part]
		if u == nil {
			u = &harness.Unit{Harness: a.ID(), Kind: capsule.KindGeneric, UnitID: part, VaultID: "global",
				Home: h, Mode: harness.GenLayered}
			units[part] = u
			order = append(order, part)
		}
		return u
	}
	count := 0
	for _, b := range a.inv.Bases {
		root := h.Bases[baseID(b.Name)]
		err := filepath.WalkDir(root, func(p string, d fs.DirEntry, werr error) error {
			if werr != nil {
				if p == root && errors.Is(werr, fs.ErrNotExist) {
					return fs.SkipDir
				}
				if p == root {
					return werr
				}
				rel, _ := filepath.Rel(root, p)
				if a.member(b.Name, filepath.ToSlash(rel)) {
					u := unit(a.partitionOf(b.Name, filepath.ToSlash(rel)))
					u.Hazards = append(u.Hazards, harness.Hazard{Base: baseID(b.Name), Rel: filepath.ToSlash(rel), Hazard: fsx.HazardAccess})
				}
				return fs.SkipDir
			}
			if count++; count%1024 == 0 {
				if err := ctx.Err(); err != nil {
					return err
				}
			}
			if count > maxEntries {
				return fmt.Errorf("generic: %s has more than %d entries", a.inv.ID, maxEntries)
			}
			if p == root {
				return nil
			}
			rel, _ := filepath.Rel(root, p)
			rel = filepath.ToSlash(rel)
			if d.IsDir() {
				return nil
			}
			if !a.member(b.Name, rel) {
				return nil
			}
			st, err := fsx.Lstat(p)
			if err != nil {
				return nil
			}
			u := unit(a.partitionOf(b.Name, rel))
			if hz := hazardOf(st); hz != fsx.HazardNone {
				u.Hazards = append(u.Hazards, harness.Hazard{Base: baseID(b.Name), Rel: rel, Hazard: hz})
				return nil
			}
			u.Files = append(u.Files, harness.File{Base: baseID(b.Name), Rel: rel, Snap: st, Placement: harness.PlaceExact,
				Append: strings.HasSuffix(strings.ToLower(rel), ".jsonl")})
			u.Paths = append(u.Paths, p)
			if t := time.Unix(0, st.MtimeNS); t.After(u.LastActivity) {
				u.LastActivity = t.UTC()
			}
			return nil
		})
		if err != nil && !errors.Is(err, fs.SkipDir) {
			return nil, err
		}
	}
	sort.Strings(order)
	var out []harness.Unit
	for _, part := range order {
		u := units[part]
		key, err := harness.UnitKeyFor(e.Salt, capsule.KindGeneric, a.ID(), h.ID, "", part)
		if err != nil {
			return nil, err
		}
		u.Key, u.LeaseKeys = key, []string{key}
		out = append(out, *u)
	}
	return out, nil
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

// Probe enforces the dormant conditions of SPEC §7.3 as liveness evidence:
// no matching process runs, no lock is held, no process holds a file of
// the home open (open_fd_check), and no SQLite -wal/-shm/-journal exists.
// Any failure to check is evidence too.
func (a *adapter) Probe(ctx context.Context, e harness.Env, u harness.Unit) ([]live.Evidence, error) {
	if err := ctx.Err(); err != nil {
		return []live.Evidence{{Reason: live.ReasonUnknown, Detail: "cancelled"}}, err
	}
	if e.Procs == nil {
		return []live.Evidence{{Reason: live.ReasonUnknown, Detail: "no process table"}}, nil
	}
	var out []live.Evidence
	procs, err := e.Procs.List()
	if err != nil {
		out = append(out, live.Evidence{Reason: live.ReasonUnknown, Detail: "process table unreadable"})
	}
	for _, p := range procs {
		if a.inv.MatchProcess(p) {
			out = append(out, live.Evidence{Reason: live.ReasonProcess, Proc: p.ID, Detail: "harness process running", Weak: true})
		}
	}
	out = append(out, a.lockEvidence(ctx, e, u)...)
	if a.inv.OpenFDCheck {
		var dirs []string
		for _, d := range u.Home.Bases {
			if st, err := fsx.Lstat(d); err == nil && st.IsDir() {
				dirs = append(dirs, d)
			}
		}
		sort.Strings(dirs)
		if len(dirs) > 0 {
			holders, err := e.Procs.OpenFilesUnder(ctx, dirs)
			if err != nil {
				out = append(out, live.Evidence{Reason: live.ReasonOpenFD, Detail: "open-file check failed"})
			}
			for _, h := range holders {
				out = append(out, live.Evidence{Reason: live.ReasonOpenFD, Proc: h.Proc.ID, Path: h.Path, Detail: "open descriptor in the home"})
			}
		}
	}
	if p, ok := journalPresent(u); ok {
		out = append(out, live.Evidence{Reason: live.ReasonUnknown, Path: p, Detail: "SQLite journal present"})
	}
	return out, ctx.Err()
}

// lockEvidence checks the inventory's writer locks without taking them: a
// flock lock is held when a process has it open; a json-pid lock when its
// pid is alive (an unreadable record counts as held).
func (a *adapter) lockEvidence(ctx context.Context, e harness.Env, u harness.Unit) []live.Evidence {
	var out []live.Evidence
	for _, l := range a.inv.Locks {
		bn, gl, ok := a.splitGlob(l.Glob)
		if !ok {
			continue
		}
		root := u.Home.Bases[baseID(bn)]
		if root == "" {
			continue
		}
		matches, err := filepath.Glob(filepath.Join(root, filepath.FromSlash(gl)))
		if err != nil {
			out = append(out, live.Evidence{Reason: live.ReasonWriterLock, Detail: "lock glob invalid"})
			continue
		}
		switch l.Kind {
		case "flock":
			if len(matches) == 0 {
				continue
			}
			holders, err := e.Procs.OpenFilesUnder(ctx, matches)
			if err != nil {
				out = append(out, live.Evidence{Reason: live.ReasonWriterLock, Detail: "lock check failed"})
			}
			for _, h := range holders {
				out = append(out, live.Evidence{Reason: live.ReasonWriterLock, Proc: h.Proc.ID, Path: h.Path, Detail: "lock held"})
			}
		case "json-pid":
			for _, m := range matches {
				pid, ok := lockPID(m)
				if !ok {
					out = append(out, live.Evidence{Reason: live.ReasonWriterLock, Path: m, Detail: "lock record unreadable"})
					continue
				}
				info, err := e.Procs.Lookup(pid)
				if errors.Is(err, platform.ErrNoProcess) {
					continue
				}
				if err != nil || info.State != platform.StateZombie {
					out = append(out, live.Evidence{Reason: live.ReasonWriterLock, Proc: info.ID, Path: m, Detail: "lock held by a live pid"})
				}
			}
		}
	}
	return out
}

// lockPID reads the pid of a json-pid lock record ({"pid": N, …}).
func lockPID(path string) (int, bool) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return 0, false
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxLockBytes))
	if err != nil {
		return 0, false
	}
	var rec struct {
		PID *int `json:"pid"`
	}
	if json.Unmarshal(data, &rec) != nil || rec.PID == nil || *rec.PID <= 0 {
		return 0, false
	}
	return *rec.PID, true
}

// journalPresent reports a SQLite -wal, -shm or -journal file among the
// unit's files or next to one of them (a database in use, SPEC §7.3).
func journalPresent(u harness.Unit) (string, bool) {
	for _, f := range u.Files {
		root, ok := u.Home.Bases[f.Base]
		if !ok {
			continue
		}
		abs := filepath.Join(root, filepath.FromSlash(f.Rel))
		for _, suf := range journalSuffixes {
			if strings.HasSuffix(f.Rel, suf) {
				return abs, true
			}
			if _, err := fsx.Lstat(abs + suf); err == nil {
				return abs + suf, true
			}
		}
	}
	return "", false
}

var journalSuffixes = []string{"-wal", "-shm", "-journal"}

// Targets allows only the inventory's content set in a home registered in
// config (SPEC §7.0: restores naming an unregistered home are rejected; v0.2
// has no automatic restore for experimental harnesses).
func (a *adapter) Targets(ctx context.Context, e harness.Env, ref harness.UnitRef, unitID string) (harness.TargetRules, error) {
	if err := ctx.Err(); err != nil {
		return harness.TargetRules{}, err
	}
	if ref.Harness != a.ID() || ref.Kind != capsule.KindGeneric {
		return harness.TargetRules{}, fmt.Errorf("%w: %s/%s", harness.ErrUnknownHarness, ref.Harness, ref.Kind)
	}
	if unitID == "" || strings.Contains(unitID, "\x00") {
		return harness.TargetRules{}, fmt.Errorf("%w: partition id", harness.ErrUnitKey)
	}
	h, err := a.home(e)
	if err != nil {
		return harness.TargetRules{}, err
	}
	registered := false
	first := ""
	if len(a.inv.Bases) > 0 {
		first = h.Bases[baseID(a.inv.Bases[0].Name)]
	}
	for _, rh := range e.Cfg.Harness[a.inv.ID].Homes {
		if filepath.IsAbs(rh.Dir) && resolve(rh.Dir) == first {
			registered = true
		}
	}
	if !registered || h.ID != ref.HomeID {
		return harness.TargetRules{}, harness.ErrUnregistered
	}
	part := unitID
	return harness.TargetRules{
		Bases: h.Bases,
		Allow: func(base capsule.BaseID, rel string) bool {
			name, ok := strings.CutPrefix(string(base), string(capsule.BaseGeneric)+":")
			if !ok {
				return false
			}
			if _, ok := h.Bases[base]; !ok {
				return false
			}
			if rel == "" || !filepath.IsLocal(rel) || filepath.Clean(rel) != rel || strings.Contains(rel, "\\") {
				return false
			}
			return a.member(name, rel) && a.partitionOf(name, rel) == part
		},
		Policy: func(capsule.Entry) harness.Placement { return harness.PlaceExact },
		Mode:   harness.GenLayered,
	}, nil
}

// PlanLaunch runs the harness through the wrapper (gated by the lock
// screen only: experimental harnesses have no hooks) with nothing restored
// and nothing sealed automatically (SPEC §7.3).
func (a *adapter) PlanLaunch(ctx context.Context, e harness.Env, cwd string, argv []string) (harness.LaunchPlan, error) {
	if err := ctx.Err(); err != nil {
		return harness.LaunchPlan{}, err
	}
	if len(argv) == 0 {
		return harness.LaunchPlan{}, fmt.Errorf("generic: empty argv")
	}
	if !filepath.IsAbs(cwd) {
		return harness.LaunchPlan{}, fmt.Errorf("generic: cwd %q is not absolute", cwd)
	}
	exe := argv[0]
	if !filepath.IsAbs(exe) {
		if bin := e.Cfg.Harness[a.inv.ID].Bin; filepath.IsAbs(bin) {
			exe = bin
		} else {
			p, err := paths.LookPath(e.Host, exe)
			if err != nil {
				return harness.LaunchPlan{}, fmt.Errorf("generic: %s not found: %w", exe, err)
			}
			exe = p
		}
	}
	args := argv[1:]
	return harness.LaunchPlan{
		Harness:   a.ID(),
		Mode:      a.inv.Classify(args, true, true),
		Roots:     e.Cfg.RootsFor(filepath.Clean(cwd)),
		Argv:      append([]string{filepath.Clean(exe)}, args...),
		SealScope: harness.Scope{}, // nothing: Scan answers only explicit --dormant scopes
	}, nil
}

func (a *adapter) MarkdownPaths(context.Context, harness.Env, harness.Unit) ([]string, error) {
	return nil, nil
}

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
