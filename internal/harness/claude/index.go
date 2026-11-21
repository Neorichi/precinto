package claude

import (
	"path/filepath"
	"slices"
	"strings"

	"github.com/precinto/precinto/internal/capsule"
	"github.com/precinto/precinto/internal/harness"
	"github.com/precinto/precinto/internal/ledger"
)

// recordProjects writes to the project index (state/projects/claude-code.json)
// every project directory <P> a unit being sealed uses, with the unit's roots
// and, for the <P> of a session's own transcript, the session's start cwd
// (DC-30, SPEC §11.2). The sealer calls Describe once per unit it seals
// (SPEC §10.3), and nothing else does, so the index learns <P> exactly when
// a session is sealed, while read-only callers (status, doctor) never write
// it. The index lets a later restore recreate a deleted projects/<P> or
// $TMP/<P>, gives a restored session (whose ledger went into the capsule,
// S13) and the project unit their roots, and maps the start cwd to <P> for
// PlanLaunch's project selector. Entries are only ever merged in, never
// dropped. Best effort: an index that cannot be written leaves the seal as
// it is.
func (a *adapter) recordProjects(e harness.Env, u harness.Unit) {
	if e.Index == nil || (u.Kind != capsule.KindClaudeSession && u.Kind != capsule.KindClaudeProject) {
		return
	}
	x := e.Index(harnessName)
	if x == nil {
		return
	}
	cc := u.Home.Bases[capsule.BaseClaudeConfig]
	roots := knownRoots(e.Cfg, u.RootIDs)
	if !filepath.IsAbs(cc) || len(roots) == 0 {
		return
	}
	var order []string
	cwds := map[string][]string{}
	add := func(p, cwd string) {
		if !safeComponent(p) {
			return
		}
		if _, ok := cwds[p]; !ok {
			order = append(order, p)
			cwds[p] = nil
		}
		if filepath.IsAbs(cwd) {
			cwds[p] = appendUnique(cwds[p], filepath.Clean(cwd))
		}
	}
	switch u.Kind {
	case capsule.KindClaudeSession:
		sid := strings.ToLower(u.UnitID)
		for _, f := range append(append([]harness.File(nil), u.Files...), u.Dirs...) {
			parts, ok := cleanRel(f.Rel)
			if !ok {
				continue
			}
			switch f.Base {
			case capsule.BaseClaudeConfig:
				if len(parts) < 3 || !sameName(parts[0], "projects") {
					continue
				}
				cwd := ""
				if main, _ := isTranscript(parts, sid); main {
					cwd = u.ProjectDir // the <P> Claude named after the start cwd
				}
				add(parts[1], cwd)
			case capsule.BaseClaudeTmp:
				if _, p, ok := tmpSessionOf(parts); ok {
					add(p, "")
				}
			}
		}
	case capsule.KindClaudeProject:
		add(u.UnitID, u.ProjectDir)
	}
	for _, p := range order {
		want := ledger.Project{Harness: harnessName, ConfigDir: cc, Slug: p, Cwds: cwds[p], RootIDs: roots}
		if cur, ok, err := x.Lookup(cc, p); err == nil && ok && covers(cur, want) {
			continue // nothing new: no write
		}
		_ = x.Put(want)
	}
}

// covers reports whether the recorded project already holds every cwd and
// root id of want.
func covers(cur, want ledger.Project) bool {
	for _, c := range want.Cwds {
		if !slices.Contains(cur.Cwds, c) {
			return false
		}
	}
	for _, r := range want.RootIDs {
		if !slices.Contains(cur.RootIDs, r) {
			return false
		}
	}
	return true
}
