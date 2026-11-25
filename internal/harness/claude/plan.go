package claude

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Neorichi/precinto/internal/capsule"
	"github.com/Neorichi/precinto/internal/config"
	"github.com/Neorichi/precinto/internal/harness"
	"github.com/Neorichi/precinto/internal/paths"
	"github.com/Neorichi/precinto/internal/platform"
)

// Catalog ids used in launch plans. internal/harness cannot import
// internal/ui, so plans carry ui.MsgID values as strings and the wrapper
// renders them (ui.Format renders an unknown id as the id itself).
const (
	msgBareWarning  = "C9.bare"     // --bare in a protected folder
	msgResumeTwice  = "C7.twice"    // the session is open in another terminal
	msgSettingsKept = "C9.settings" // the user passed --settings: precinto added none (D32)
	msgPurgeForget  = "C7.purge"    // claude purge: run it? precinto keeps its sealed copies (default no, D79)
	// cmdPurge is Claude's subcommand that deletes sessions (SPEC §7.1.5).
	cmdPurge = "purge"
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
	// D134: precinto reads the options as Claude does (bundled short
	// options, attached values); the child gets args unchanged.
	view, known := claudeView(args)
	exe, err := a.resolveExe(e, argv[0])
	if err != nil {
		return harness.LaunchPlan{}, err
	}
	plan := harness.LaunchPlan{
		Harness:   harness.ClaudeCode,
		Mode:      a.inv.Classify(view, true, true),
		HookCheck: harness.HookCheck{Event: "SessionStart", Within: hookPresenceWithin},
		// Claude's SessionEnd hooks get 1.5 s (HOOKS-IO §1); it exits on
		// SIGTERM, so no quit keys.
		KillGrace: harness.KillGrace(sessionEndBudget),
	}
	resume, cont, fork := resumeFlagsOf(a.inv)
	plan.Resume = parseResume(view, resume, cont, fork)
	purge := len(args) > 0 && args[0] == cmdPurge
	touched := append([]string{cwd}, addDirs(args, cwd)...)
	if purge {
		touched = append(touched, positionals(args[1:], cwd)...) // claude purge [path]
	}
	plan.Roots = e.Cfg.RootsFor(touched...)
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
	if purge {
		// claude purge [path] deletes sessions and runs none: it is gated
		// like any launch in the folder, but nothing is restored for it
		// and no session settings are added. precinto asks first (C7.purge,
		// default no, D79): yes runs claude purge and keeps every sealed
		// copy (capsules are deleted only by forget or prune, D15); no
		// starts nothing (exit 3, CC-20).
		plan.Argv = append([]string{exe}, args...)
		plan.Confirm = msgPurgeForget
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
	// D107: a fresh launch starts a session whose id precinto knows before
	// exec — the one the user named with --session-id, else one chosen
	// here — so the wrapper records it as the child's (and managed) before
	// any hook runs, and the seal after exit, which takes every session
	// the child owns, finds it without hooks.
	freshSID := ""
	if plan.Resume.Kind == harness.ResumeNone && !plan.Resume.Fork {
		sid, inject, err := freshSessionID(view)
		if err != nil {
			return harness.LaunchPlan{}, err
		}
		if inject && !known {
			// An option precinto cannot read might be one Claude refuses
			// --session-id with: no id is chosen, the hooks and the
			// registry watch record the session (D134).
			sid, inject = "", false
		}
		if inject {
			final = append(final, flagSessionID, sid)
		}
		freshSID = sid
	}
	final = append(final, args...)
	if hasArg(args, "--bare") {
		plan.Confirm = msgBareWarning
	}

	h, registered := launchHome(e)
	// D156: the session will write its transcripts and task files there;
	// under WSL a home on a Windows drive is one precinto could neither
	// seal nor restore into, so a managed launch with it is refused. The
	// child's own temporary and cache folders count too: its environment
	// (TMPDIR, CLAUDE_CODE_TMPDIR, XDG_CACHE_HOME) can name others than
	// those registered for the home, and those are where it writes.
	if err := checkHomeDrives(h); err != nil {
		return harness.LaunchPlan{}, err
	}
	for _, d := range []string{defaultTmp(e.Host), defaultCache(e.Host)} {
		if d == "" {
			continue
		}
		if err := checkDrive(d); err != nil {
			return harness.LaunchPlan{}, err
		}
	}
	maxAge := retention(h)
	// Selectors match Manifest.ProjectDir exactly: the session's realpath'd
	// start cwd (D73); cwd is realpath'd above.
	recent := harness.Selector{Kind: capsule.KindClaudeSession, RootID: root.ID, ProjectDir: cwd,
		Recent: e.Cfg.Policy.RestoreRecent, MaxAge: maxAge, MaxBytes: e.Cfg.Policy.RestoreMaxBytes}
	project := a.projectSelector(e, h, registered, root, cwd)
	var extra []harness.Selector // best effort before exec, after project (Optional, D132)

	if sid, ok := a.resumeTarget(e, h, plan.Resume); ok {
		if registered {
			key, err := harness.UnitKeyFor(e.Salt, capsule.KindClaudeSession, harness.ClaudeCode, h.ID, "", sid)
			if err != nil {
				return harness.LaunchPlan{}, err
			}
			plan.Sync = append(plan.Sync, harness.Selector{Kind: capsule.KindClaudeSession, Keys: []string{key}, MtimeNow: true})
			plan.Lease = append(plan.Lease, key)
			if pid, open := a.openElsewhere(e, h, sid); open && !plan.Resume.Fork {
				// Opening a session twice can lose messages (C7.twice): the
				// plan opens a copy; answering no aborts the launch.
				plan.Confirm = msgResumeTwice
				plan.MsgVars = map[string]string{"sid": sid, "pid": strconv.Itoa(pid)}
				plan.Resume.Fork = true
				final = append(final, fork[0])
			}
		}
		// The seal after exit is scoped to the resumed session (CC-21); a
		// fork writes a new session whose id is known only once it runs,
		// so its scope stays the child's sessions (Scope.Procs, added by
		// the backend).
		if !plan.Resume.Fork {
			plan.SealScope.SIDs = []string{sid}
		}
	} else {
		// restore_recent = 0 restores no recent session (a zero counter is
		// "none", D62), while a selector's Recent 0 is every match: the
		// recent selectors below are added only for a positive count.
		someRecent := recent.Recent > 0
		switch plan.Resume.Kind {
		case harness.ResumeName:
			sel := recent
			sel.Title, sel.Recent, sel.MaxAge, sel.MtimeNow = plan.Resume.Value, 0, 0, true
			plan.Sync = append(plan.Sync, sel)
		case harness.ResumePicker:
			if someRecent {
				// The picker lists them; one open elsewhere is in use
				// there, not a reason to refuse the launch (D132).
				pick := recent
				pick.Optional = true
				plan.Sync = append(plan.Sync, pick)
			}
		case harness.ResumeContinue:
			sel := recent
			sel.Recent, sel.Newest, sel.MaxAge, sel.MtimeNow = 0, true, 0, true
			if printMode(view) {
				// claude -p --continue picks the newest session of any kind.
				plan.Sync = append(plan.Sync, sel)
				break
			}
			// D102: an interactive --continue skips sessions created by
			// claude -p or an Agent SDK, and sessions whose first prompt
			// was /loop. The newest session it can pick by entrypoint is
			// restored first (clamped like any explicit resume, which
			// keeps it the newest); the folder's other recent sessions it
			// can pick follow before exec too, after the project unit
			// (best effort: under StopOnErr a failure among them must not
			// stop the targeted units) and unclamped, so Claude orders
			// them by their own times and the one it picks after a /loop
			// session (which precinto cannot tell) is there.
			sel.SkipEntrypoints = sdkEntrypoints
			plan.Sync = append(plan.Sync, sel)
			if someRecent {
				next := recent
				next.SkipEntrypoints = sdkEntrypoints
				next.Optional = true // D132: one in use elsewhere stays as it is
				extra = append(extra, next)
			}
		}
	}
	// D132: the project unit is in use (live) while another Claude runs
	// in the folder; it is left as it is there, and the launch goes on.
	project.Optional = true
	plan.Sync = append(plan.Sync, project)
	plan.Sync = append(plan.Sync, extra...)
	plan.Lease = append(plan.Lease, project.Keys...)
	if plan.Resume.Kind != harness.ResumePicker && recent.Recent > 0 {
		plan.Background = []harness.Selector{recent}
	}
	plan.Argv = final
	// The new session is named for the wrapper to record (D107), not in
	// the seal scope: like a fork's, the scope stays every session the
	// child owns (Scope.Procs, added by the backend), so the sessions it
	// switches to (/clear, /resume) are sealed too, whoever recorded them.
	plan.SessionID = freshSID
	plan.SealScope.RootIDs = rootIDs(plan.Roots)
	return plan, nil
}

// resolveExe makes argv[0] absolute: an absolute argv[0] is kept, then the
// configured [harness.claude-code].bin, then PATH of the invoking
// environment. Under WSL an executable that would run as a Windows
// program is refused (harness.CheckProgram, D156): WSL appends the
// Windows PATH, so `claude` can be a Windows install precinto cannot see.
func (a *adapter) resolveExe(e harness.Env, name string) (string, error) {
	exe, err := lookExe(e, name)
	if err != nil {
		return "", err
	}
	if err := checkProgram(e.Host, harness.ClaudeCode, exe); err != nil {
		return "", err
	}
	return exe, nil
}

func lookExe(e harness.Env, name string) (string, error) {
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
						// Index cwds are realpath'd start cwds (recorded at
						// the seal); cwd is the realpath'd launch cwd.
						if filepath.IsAbs(c) && (filepath.Clean(c) == cwd || realpath(c) == cwd) {
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
		if err == nil && info.State != platform.StateZombie && registryMatches(r, info, e.Layout.RunDir) {
			return r.PID, true
		}
	}
	return 0, false
}

// flagSessionID is Claude's option that names the id of the session a
// launch starts (a UUID; Claude refuses it with --continue or --resume
// unless --fork-session is given).
const flagSessionID = "--session-id"

// nonSessionVerbs are Claude subcommands under which the process starts no
// new session of its own (they manage other sessions, the installation or
// a server): a fresh launch whose first positional argument is one gets no
// session id (D107). Passthrough commands never reach PlanLaunch's fresh
// branch; they are listed too, so the rule holds whatever the inventory.
var nonSessionVerbs = []string{
	"agents", "attach", "auth", "auto-mode", "bridge", "daemon", "doctor", "gateway", "import", "install",
	"kill", "logs", "mcp", "migrate-installer", "plugin", "plugins", "purge", "rc", "remote", "remote-control",
	"respawn", "rm", "self-hosted-runner", "setup-token", "stop", "sync", "ultrareview", "update", "upgrade",
}

// noSessionFlags are options under which a launch starts no new local
// session in this process (a background agent, a shell job, the desktop
// app, a cloud or teleported session, the PR session picker, hooks only,
// or a session never written to disk): no session id is chosen (D107).
var noSessionFlags = []string{
	"--bg", "--background", "--exec", "--desktop", "--cloud", "--remote", "--environment", "--pool", "--teleport",
	"--from-pr", "--init-only", "--no-session-persistence",
}

// freshSessionID returns the id of the session a fresh launch with args
// starts (D107): the UUID the user passed with --session-id (kept as
// given, inject false), else a new random one (version 4) for PlanLaunch
// to pass (inject true). It returns "" for launches that start no new
// session here (nonSessionVerbs, noSessionFlags, an invalid --session-id
// value, which Claude refuses itself). Parsing stops at "--".
func freshSessionID(args []string) (sid string, inject bool, err error) {
	positional := false
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			break
		}
		if v, ok := strings.CutPrefix(a, flagSessionID+"="); ok {
			return userSessionID(v), false, nil
		}
		if a == flagSessionID {
			if i+1 < len(args) {
				return userSessionID(args[i+1]), false, nil
			}
			return "", false, nil
		}
		name, _, _ := strings.Cut(a, "=")
		if oneOf(name, noSessionFlags) {
			return "", false, nil
		}
		if !positional && a != "" && !strings.HasPrefix(a, "-") {
			positional = true
			if oneOf(a, nonSessionVerbs) {
				return "", false, nil
			}
		}
	}
	id, err := newSessionUUID()
	if err != nil {
		return "", false, fmt.Errorf("claude: choose a session id: %w", err)
	}
	return id, true, nil
}

// userSessionID is the session id a user's --session-id value names, in
// lower case; "" when it is not a UUID.
func userSessionID(v string) string {
	if !isUUID(v) {
		return ""
	}
	return strings.ToLower(v)
}

// newSessionUUID returns a random version-4 UUID in canonical lower case.
func newSessionUUID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = b[6]&0x0f | 0x40 // version 4
	b[8] = b[8]&0x3f | 0x80 // RFC 4122 variant
	h := hex.EncodeToString(b[:])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32], nil
}
