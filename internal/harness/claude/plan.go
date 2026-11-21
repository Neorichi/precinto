package claude

import (
	"context"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/precinto/precinto/internal/capsule"
	"github.com/precinto/precinto/internal/config"
	"github.com/precinto/precinto/internal/harness"
	"github.com/precinto/precinto/internal/paths"
	"github.com/precinto/precinto/internal/platform"
)

// Catalog ids used in launch plans. internal/harness cannot import
// internal/ui, so plans carry ui.MsgID values as strings and the wrapper
// renders them (ui.Format renders an unknown id as the id itself).
const (
	msgBareWarning  = "C9.bare"     // --bare in a protected folder
	msgResumeTwice  = "C7.twice"    // the session is open in another terminal
	msgSettingsKept = "C9.settings" // the user passed --settings: precinto added none (D32)
	// sessionEndBudget is Claude's SessionEnd hook budget (HOOKS-IO §1).
	sessionEndBudget = 1500 * time.Millisecond
	envAwaySummary   = "CLAUDE_CODE_ENABLE_AWAY_SUMMARY=0"
)

const (
	// hookPresenceWithin is the SessionStart window of the hook-presence
	// check (SPEC §14.4).
	hookPresenceWithin = 10 * time.Second
	// minRetention is the shortest automatic-restore age used when
	// cleanupPeriodDays leaves less than the D14 margin.
	minRetention = 12 * time.Hour
)

// PlanLaunch parses argv (argv[0] is the harness name) for cwd (SPEC
// §7.1.5, §15.1): the launch mode, the folders the launch touches (cwd and
// --add-dir), the resume target, what to restore before exec and in the
// background, the --settings injection (D32) and the confirmations.
func (a *adapter) PlanLaunch(ctx context.Context, e harness.Env, cwd string, argv []string) (harness.LaunchPlan, error) {
	if err := ctx.Err(); err != nil {
		return harness.LaunchPlan{}, err
	}
	if a.invErr != nil {
		return harness.LaunchPlan{}, a.invErr
	}
	if len(argv) == 0 {
		return harness.LaunchPlan{}, fmt.Errorf("claude: empty argv")
	}
	if !filepath.IsAbs(cwd) {
		return harness.LaunchPlan{}, fmt.Errorf("claude: cwd %q is not absolute", cwd)
	}
	// The realpath'd launch cwd: roots are realpath'd in config, and the
	// selectors below match Manifest.ProjectDir, the realpath'd start cwd,
	// exactly (D73), so a launch through a symlinked path selects the same.
	cwd = realpath(cwd)
	args := append([]string(nil), argv[1:]...)
	exe, err := a.resolveExe(e, argv[0])
	if err != nil {
		return harness.LaunchPlan{}, err
	}
	plan := harness.LaunchPlan{
		Harness:   harness.ClaudeCode,
		Mode:      a.inv.Classify(args, true, true),
		HookCheck: harness.HookCheck{Event: "SessionStart", Within: hookPresenceWithin},
		// Claude's SessionEnd hooks get 1.5 s (HOOKS-IO §1); it exits on
		// SIGTERM, so no quit keys.
		KillGrace: harness.KillGrace(sessionEndBudget),
	}
	resume, cont, fork := resumeFlagsOf(a.inv)
	plan.Resume = parseResume(args, resume, cont, fork)
	plan.Roots = e.Cfg.RootsFor(append([]string{cwd}, addDirs(args, cwd)...)...)
	// The primary root contains the start cwd (D1), else the deepest
	// touched one.
	if r, ok := e.Cfg.RootFor(cwd); ok {
		plan.Roots = append([]config.Root{r}, without(plan.Roots, r.ID)...)
	}
	if plan.Mode == harness.LaunchPassthrough || len(plan.Roots) == 0 {
		// Passthrough commands are neither gated nor restored (UX14); a
		// launch outside every folder has nothing to restore.
		plan.Argv = append([]string{exe}, args...)
		plan.SealScope = harness.Scope{RootIDs: rootIDs(plan.Roots)}
		return plan, nil
	}
	root := plan.Roots[0]
	plan.Env = []string{envAwaySummary}
	final := []string{exe}
	if !hasSettingsFlag(args) {
		final = append(final, "--settings", settingsJSON(e.Cfg.Policy))
	} else {
		plan.Notices = append(plan.Notices, msgSettingsKept) // SPEC §7.1.5, CC-38
	}
	final = append(final, args...)
	if hasArg(args, "--bare") {
		plan.Confirm = msgBareWarning
	}

	h, registered := launchHome(e)
	maxAge := retention(h)
	// Selectors match Manifest.ProjectDir exactly: the session's realpath'd
	// start cwd (D73); cwd is realpath'd above.
	recent := harness.Selector{Kind: capsule.KindClaudeSession, RootID: root.ID, ProjectDir: cwd,
		Recent: e.Cfg.Policy.RestoreRecent, MaxAge: maxAge, MaxBytes: e.Cfg.Policy.RestoreMaxBytes}
	project := a.projectSelector(e, h, registered, root, cwd)

	if sid, ok := a.resumeTarget(e, h, plan.Resume); ok && registered {
		key, err := harness.UnitKeyFor(e.Salt, capsule.KindClaudeSession, harness.ClaudeCode, h.ID, "", sid)
		if err != nil {
			return harness.LaunchPlan{}, err
		}
		plan.Sync = append(plan.Sync, harness.Selector{Kind: capsule.KindClaudeSession, Keys: []string{key}, MtimeNow: true})
		plan.Lease = append(plan.Lease, key)
		plan.SealScope.SIDs = []string{sid}
		if pid, open := a.openElsewhere(e, h, sid); open && !plan.Resume.Fork {
			// Opening a session twice can lose messages (C7.twice): the
			// plan opens a copy; answering no aborts the launch.
			plan.Confirm = msgResumeTwice
			plan.MsgVars = map[string]string{"sid": sid, "pid": strconv.Itoa(pid)}
			plan.Resume.Fork = true
			final = append(final, fork[0])
		}
	} else {
		switch plan.Resume.Kind {
		case harness.ResumeName:
			sel := recent
			sel.Title, sel.Recent, sel.MaxAge, sel.MtimeNow = plan.Resume.Value, 0, 0, true
			plan.Sync = append(plan.Sync, sel)
		case harness.ResumePicker:
			plan.Sync = append(plan.Sync, recent)
		case harness.ResumeContinue:
			sel := recent
			sel.Recent, sel.Newest, sel.MaxAge, sel.MtimeNow = 0, true, 0, true
			plan.Sync = append(plan.Sync, sel)
		}
	}
	plan.Sync = append(plan.Sync, project)
	plan.Lease = append(plan.Lease, project.Keys...)
	if plan.Resume.Kind != harness.ResumePicker {
		plan.Background = []harness.Selector{recent}
	}
	plan.Argv = final
	plan.SealScope.RootIDs = rootIDs(plan.Roots)
	return plan, nil
}

// resolveExe makes argv[0] absolute: an absolute argv[0] is kept, then the
// configured [harness.claude-code].bin, then PATH of the invoking
// environment.
func (a *adapter) resolveExe(e harness.Env, name string) (string, error) {
	if filepath.IsAbs(name) {
		return filepath.Clean(name), nil
	}
	if bin := e.Cfg.Harness[harnessName].Bin; filepath.IsAbs(bin) {
		return filepath.Clean(bin), nil
	}
	p, err := paths.LookPath(e.Host, name)
	if err != nil {
		return "", fmt.Errorf("claude: %s not found: %w", name, err)
	}
	return p, nil
}

func without(rs []config.Root, id string) []config.Root {
	var out []config.Root
	for _, r := range rs {
		if r.ID != id {
			out = append(out, r)
		}
	}
	return out
}

// launchHome is the home the launch will use: the child's CLAUDE_CONFIG_DIR
// or ~/.claude, matched against the registered homes (only those are
// restore targets, SPEC §7.0).
func launchHome(e harness.Env) (home, bool) {
	dir := defaultConfigDir(e.Host)
	for _, h := range registeredHomes(e.Cfg) {
		if dir != "" && (h.configDir() == dir || realpath(h.configDir()) == dir) {
			return h, true
		}
	}
	return newHome(dir, defaultTmp(e.Host), defaultCache(e.Host), true, false), false
}

// retention is D14's automatic-restore age: cleanupPeriodDays − 2 days.
func retention(h home) time.Duration {
	days, _ := cleanupPeriodDays(h.configDir())
	d := time.Duration(days-2) * 24 * time.Hour
	if d < minRetention {
		d = minRetention
	}
	return d
}

// projectSelector restores the project unit of cwd: by key when the
// project index maps cwd to its project directories (precinto never
// computes slugs), else by the manifests' project dir.
func (a *adapter) projectSelector(e harness.Env, h home, registered bool, root config.Root, cwd string) harness.Selector {
	sel := harness.Selector{Kind: capsule.KindClaudeProject, RootID: root.ID}
	if registered && e.Index != nil {
		if x := e.Index(harnessName); x != nil {
			if all, err := x.All(); err == nil {
				for _, p := range all {
					if filepath.Clean(p.ConfigDir) != h.configDir() || !safeComponent(p.Slug) {
						continue
					}
					for _, c := range p.Cwds {
						if filepath.Clean(c) == cwd {
							if key, err := harness.UnitKeyFor(e.Salt, capsule.KindClaudeProject, harness.ClaudeCode, h.ID, "", p.Slug); err == nil {
								sel.Keys = appendUnique(sel.Keys, key)
							}
						}
					}
				}
			}
		}
	}
	if len(sel.Keys) == 0 {
		sel.ProjectDir = cwd // realpath'd by PlanLaunch (D73)
	}
	return sel
}

// resumeTarget returns the session id an explicit resume names: a sid, a
// transcript path, or the session of a job record (attach/respawn).
func (a *adapter) resumeTarget(e harness.Env, h home, r harness.Resume) (string, bool) {
	if sid, ok := resumeSID(r); ok {
		return sid, true
	}
	if r.Kind == harness.ResumeJob {
		jobs, err := readJobs(h.configDir())
		if err != nil {
			return "", false
		}
		for _, j := range jobs {
			if j.ID == r.Value && j.Valid {
				if sid, ok := sidOf(j.SessionID); ok && len(j.SessionID) == uuidLen {
					return sid, true
				}
			}
		}
	}
	return "", false
}

// openElsewhere reports whether the registry shows sid running in another
// live Claude process (C7.twice).
func (a *adapter) openElsewhere(e harness.Env, h home, sid string) (int, bool) {
	if e.Procs == nil {
		return 0, false
	}
	reg, err := readRegistry(h.configDir())
	if err != nil {
		return 0, false
	}
	for _, r := range reg {
		if !r.Valid || !strings.EqualFold(r.SessionID, sid) {
			continue
		}
		info, err := e.Procs.Lookup(r.PID)
		if err == nil && info.State != platform.StateZombie && registryMatches(r, info) {
			return r.PID, true
		}
	}
	return 0, false
}
