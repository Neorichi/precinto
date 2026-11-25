package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/precinto/precinto/internal/capsule"
	"github.com/precinto/precinto/internal/config"
	"github.com/precinto/precinto/internal/fsx"
	"github.com/precinto/precinto/internal/harness"
	"github.com/precinto/precinto/internal/ipc"
	"github.com/precinto/precinto/internal/sweep"
	"github.com/precinto/precinto/internal/ui"
)

// unitKeyRE matches a unit key (32 lowercase hex, D45).
var unitKeyRE = regexp.MustCompile(`^[0-9a-f]{32}$`)

func cmdSeal(a *app, args []string) int {
	f := newFlags("seal")
	harnessID := f.String("harness", "", "seal only units of harness `H`")
	session := f.String("session", "", "seal only the session `ID`")
	rootDir := f.String("root", "", "seal only units of the protected folder containing `DIR`")
	waitPID := f.String("wait-pid", "", "wait for process `PID:START` to exit first")
	queued := f.Bool("queue", false, "drain the seal queue (the detached SessionEnd worker)")
	adopt := f.Bool("adopt", false, "also seal transcripts found outside the ledger that reference a folder")
	dryRun := f.Bool("dry-run", false, "show what would be sealed")
	dormant := f.String("dormant", "", "seal the experimental harness `H` once (needs --experimental)")
	experimental := f.Bool("experimental", false, "allow experimental harness inventories")
	pos, err := f.parse(args)
	if code, ok := a.handleParse(f, err); !ok {
		return code
	}
	if len(pos) > 0 {
		return a.usageFail(f, "unexpected argument "+pos[0])
	}
	if *dormant != "" && !*experimental {
		a.say(textNeedExp, *dormant)
		return exitUsage
	}
	if *queued && (*session != "" || *dormant != "" || *rootDir != "") {
		return a.usageFail(f, "--queue drains the queue; it takes no other selection")
	}
	// D155: a seal deletes plaintext after a liveness check that reads
	// /proc, which WSL 1 only emulates, and Windows programs write every
	// file there; the detached --queue worker refuses too.
	if a.refuseWSL1() {
		return exitError
	}
	if err := a.sys.harden(); err != nil {
		return a.fail("seal", err)
	}
	sl, err := a.sealingApp()
	if err != nil {
		return a.fail("seal", err)
	}
	a, cfg, cfgErr := sl.a, sl.cfg, sl.cfgErr
	// D106: --adopt is part of the scope the adapters scan, not only an
	// option of the seal.
	o := sweep.Options{DryRun: *dryRun, Adopt: *adopt, Reason: "manual", Scope: harness.Scope{Adopt: *adopt}}
	if *waitPID != "" {
		id, err := a.sys.parseProcID(*waitPID)
		if err != nil {
			return a.usageFail(f, "--wait-pid wants PID:START")
		}
		o.WaitFor = &id
	}
	if *rootDir != "" {
		r, err := a.rootArg(cfg, *rootDir)
		if err != nil {
			return a.fail("seal", err)
		}
		o.Scope.RootIDs = []string{r.ID}
	}
	if *session != "" {
		o.Scope.SIDs = []string{*session}
	}
	ctx := context.Background()
	eng, err := a.engine(ctx, *experimental)
	if err != nil {
		return a.fail("seal", err)
	}
	if !*queued {
		o.OnQuietWait = a.quietWaitNotice()
	}
	var rep *sweep.Report
	switch {
	case *queued:
		o.Reason, o.Quiet = "session-end", true
		_, err = eng.DrainQueue(ctx, o)
		if errors.Is(err, sweep.ErrBusy) {
			return exitOK // the sweep-lock holder drains it (SPEC §10.6)
		}
		if err != nil {
			return exitFor(err) // detached worker: stdio is /dev/null
		}
		return exitOK
	case *dormant != "":
		o.Dormant = *dormant
		rep, err = eng.Seal(ctx, []harness.ID{harness.ID(*dormant)}, o.Scope, o)
	default:
		var hs []harness.ID
		if *harnessID != "" {
			hs = []harness.ID{harness.ID(*harnessID)}
		}
		rep, err = eng.Seal(ctx, hs, o.Scope, o)
	}
	shown := a.printSeal(rep, o.DryRun)
	if err != nil {
		code := a.failShown("seal", err, shown, false)
		a.reportBrokenConfig("seal", cfgErr)
		return code
	}
	a.reportBrokenConfig("seal", cfgErr)
	return exitOK
}

// sealing is what a sealing command (seal, sweep, the agent's lock worker
// sweep --lock, the SessionEnd worker seal --queue) works with (D142): the
// app whose engine it builds and the settings it seals with — the folders
// the agent enforces, as far as this process can tell (enforcedConfig)
// and as a running agent reports them (withAgentRoots), with config.toml's
// policy, or, when config.toml does not load, with the settings that stand
// in for it (D121): sealing only strengthens protection, so a broken file
// never stops it (UX-09) — and that file's error, which the command
// reports after the seal. A retired vault (D74) is none of those folders,
// broken file or not. Restores and edits keep refusing a config.toml that
// does not load. A --root DIR resolves against the same folders, so the
// lock worker finds a folder the agent enforces only because it found the
// confirmed settings tampered, and a folder no setting and no agent
// protects is "not inside a protected folder".
type sealing struct {
	a      *app
	cfg    config.Config
	cfgErr error
}

func (a *app) sealingApp() (sealing, error) {
	l, err := a.layout()
	if err != nil {
		return sealing{a: a}, err
	}
	cfg, cfgErr := a.config()
	if cfgErr != nil {
		cfg, _ = a.standInConfig(l)
	} else {
		cfg = a.enforcedConfig(cfg, l)
	}
	cfg = a.withAgentRoots(cfg)
	return sealing{a: a.withConfig(cfg), cfg: cfg, cfgErr: cfgErr}, nil
}

// quietWaitNotice is Options.OnQuietWait for a seal or sweep run from a
// terminal (D113): one line before the quiet-window wait, so the pause is
// not silent; nil when stdout is not a terminal.
func (a *app) quietWaitNotice() func(time.Duration) {
	if !a.sys.stdoutTTY() {
		return nil
	}
	return func(d time.Duration) {
		a.sayOut(textQuietWait, strings.TrimPrefix(ui.ReasonText(ui.ReasonIdle, d), "idle "))
	}
}

func cmdSweep(a *app, args []string) int {
	f := newFlags("sweep")
	rootDir := f.String("root", "", "sweep only the protected folder containing `DIR`")
	lock := f.Bool("lock", false, "sealing on behalf of a lock (the daemon's worker)")
	wait := f.Bool("wait", false, "wait for a running sweep instead of leaving it the rescan")
	dryRun := f.Bool("dry-run", false, "show what would be sealed")
	quiet := f.Bool("quiet", false, "print nothing unless something failed (the background service)")
	pos, err := f.parse(args)
	if code, ok := a.handleParse(f, err); !ok {
		return code
	}
	if len(pos) > 0 {
		return a.usageFail(f, "unexpected argument "+pos[0])
	}
	if a.refuseWSL1() { // D155: as seal
		return exitError
	}
	if err := a.sys.harden(); err != nil {
		return a.fail("sweep", err)
	}
	sl, err := a.sealingApp()
	if err != nil {
		return a.fail("sweep", err)
	}
	a, cfg, cfgErr := sl.a, sl.cfg, sl.cfgErr
	o := sweep.Options{Lock: *lock, Wait: *wait, DryRun: *dryRun, Quiet: *quiet, Reason: "sweep"}
	if *lock {
		o.Reason = "lock"
	}
	if !*quiet {
		o.OnQuietWait = a.quietWaitNotice()
	}
	if *rootDir != "" {
		r, err := a.rootArg(cfg, *rootDir)
		if err != nil {
			return a.fail("sweep", err)
		}
		o.Scope.RootIDs = []string{r.ID}
	}
	ctx := context.Background()
	eng, err := a.engine(ctx, false)
	if err != nil {
		return a.fail("sweep", err)
	}
	rep, err := eng.Sweep(ctx, o)
	if errors.Is(err, sweep.ErrBusy) && exitFor(err) <= exitError {
		// Another sweep holds the lock and rescans (SPEC §10.2).
		if !*quiet {
			a.sayOut(textBusySweep)
		}
		a.reportBrokenConfig("sweep", cfgErr)
		return exitOK
	}
	var shown []error
	if !*quiet {
		shown = a.printSeal(rep, o.DryRun)
	}
	if err != nil {
		code := a.failShown("sweep", err, shown, false)
		a.reportBrokenConfig("sweep", cfgErr)
		return code
	}
	a.reportBrokenConfig("sweep", cfgErr)
	return exitOK
}

func cmdRestore(a *app, args []string) int {
	f := newFlags("restore")
	rootDir := f.String("root", "", "restore units of the protected folder containing `DIR` (default: the working directory's)")
	session := f.String("session", "", "restore the Claude session `ID`")
	var recent optInt
	f.Var(&recent, "recent", "restore the `N` most recent sessions")
	all := f.Bool("all", false, "restore every sealed unit of the folder (from an agent session it asks for you again)")
	md := f.Bool("md", false, "restore sealed notes")
	history := f.Bool("history", false, "merge sealed prompt history back")
	global := f.Bool("global", false, "restore the global units: Claude's global stores and experimental harnesses' units (needs unlock --global)")
	globalHarness := f.String("harness", "", "with --global: only the global units of harness `H`")
	background := f.Bool("background", false, "quiet run (the daemon's post-unlock worker)")
	pos, err := f.parse(args)
	if code, ok := a.handleParse(f, err); !ok {
		return code
	}
	if len(pos) > 0 {
		return a.usageFail(f, "unexpected argument "+pos[0])
	}
	if *globalHarness != "" && !*global {
		return a.usageFail(f, "--harness selects the global units of one harness: use it with --global")
	}
	if err := a.sys.harden(); err != nil {
		return a.fail("restore", err)
	}
	cfg, err := a.config()
	if err != nil {
		return a.fail("restore", err)
	}
	var roots []config.Root
	switch {
	case *rootDir != "":
		r, err := a.rootArg(cfg, *rootDir)
		if err != nil {
			return a.fail("restore", err)
		}
		roots = []config.Root{r}
	default:
		if r, ok := a.cwdRoot(cfg); ok {
			roots = []config.Root{r}
		} else if *all {
			roots = cfg.Roots // restore --all outside a folder: every folder
		}
	}
	selecting := *session != "" || recent.set || *all || *md || *history || *global
	if (*all || *md || *history || recent.set || !selecting) && len(roots) == 0 {
		wd, _ := a.sys.getwd()
		return a.fail("restore", notProtectedError{dir: a.display(wd)})
	}
	if !selecting {
		// What an unlock restores (UX12): recent sessions and the project
		// unit, notes, and history when the policy merges it back.
		recent.v, recent.set, *md, *history = cfg.Policy.RestoreRecent, true, true, cfg.Policy.RestoreHistory
	}
	ctx := context.Background()
	eng, err := a.engine(ctx, false)
	if err != nil {
		return a.failRestore("restore", err)
	}
	keys := a.keys()
	defer keys.close()
	var watch []string
	for _, r := range roots {
		watch = append(watch, r.ID)
	}
	// A lock during the restore destroys the file keys at once and aborts
	// (rolling staged units forward), REST-8.
	abort, stop := a.watchLocks(ctx, watch, keys.destroy)
	defer stop()

	total := &sweep.Report{}
	var errs []error
	run := func(rep *sweep.Report, err error) {
		mergeReport(total, rep)
		if err != nil {
			errs = append(errs, err)
		}
	}
	purpose := ipc.PurposeRestore
	if *all {
		purpose = ipc.PurposeRestoreAll
	}
	var sel []harness.Selector
	budget := int64(0) // policy.restore_max_bytes
	if *session != "" {
		s, err := a.sessionSelector(ctx, eng, *session)
		if err != nil {
			return a.failRestore("restore", err)
		}
		sel = append(sel, s)
		budget = math.MaxInt64 // an explicit session is restored whatever the budget
	}
	for _, r := range roots {
		if *all {
			rep, err := a.restoreAll(ctx, eng, keys, r, abort)
			run(rep, err)
			continue
		}
		if recent.set {
			// Selector.Recent 0 means "every match": --recent 0 (or
			// restore_recent = 0, D62: a zero counter is "none") restores
			// no session at all.
			if recent.v > 0 {
				sel = append(sel, harness.Selector{Kind: capsule.KindClaudeSession, RootID: r.ID, Recent: recent.v, MaxAge: a.retentionAge(ctx, eng)})
			}
			sel = append(sel, harness.Selector{Kind: capsule.KindClaudeProject, RootID: r.ID, Newest: true})
		}
	}
	if *global {
		// DC-24: global units are restored only explicitly, after unlock
		// --global: Claude's global stores, and the units of experimental
		// harnesses (sealed to the global vault, their stores name no
		// folder), one harness with --harness.
		if *globalHarness == "" || *globalHarness == string(harness.ClaudeCode) {
			sel = append(sel, harness.Selector{Kind: capsule.KindGlobalStore})
		}
		if *globalHarness != string(harness.ClaudeCode) {
			keys, err := genericUnitKeys(ctx, eng, *globalHarness)
			if err != nil {
				return a.failRestore("restore", err)
			}
			if len(keys) > 0 {
				sel = append(sel, harness.Selector{Kind: capsule.KindGeneric, Keys: keys})
			}
		}
	}
	if len(sel) > 0 {
		run(eng.Restore(ctx, keys, sweep.RestoreRequest{Select: sel, Budget: budget, Purpose: purpose, Abort: abort}))
	}
	if !*all {
		for _, r := range roots {
			if *md {
				run(eng.RestoreMarkdown(ctx, keys, r))
			}
			if *history {
				run(eng.MergeHistory(ctx, keys, r.ID))
			}
		}
	}
	var shown []error
	if !*background {
		shown = a.printRestore(total)
	}
	if err := errors.Join(errs...); err != nil {
		if *background {
			return exitForRestore(err)
		}
		return a.failShown("restore", err, shown, true)
	}
	// A lock (or the loss of the daemon) during the restore destroyed the
	// keys and stopped it (REST-8): what is left stays sealed, so the
	// restore did not do what was asked.
	if closed(abort) {
		if !*background {
			a.say(textRestoreStopped)
		}
		return exitLocked
	}
	return exitOK
}

// closed reports whether ch is closed (a watchLocks abort fired).
func closed(ch <-chan struct{}) bool {
	select {
	case <-ch:
		return true
	default:
		return false
	}
}

// genericUnitKeys lists the unit keys of sealed generic units (D33), of
// harness h only when h is set.
func genericUnitKeys(ctx context.Context, eng engine, h string) ([]string, error) {
	units, err := eng.List(ctx, sweep.ListOptions{})
	if err != nil {
		return nil, err
	}
	var keys []string
	for _, u := range units {
		if u.Kind == capsule.KindGeneric && (h == "" || u.Harness == h) {
			keys = append(keys, u.Unit)
		}
	}
	sort.Strings(keys)
	return keys, nil
}

// sessionSelector selects one Claude session by sid in every registered
// Claude home (the unit key needs the home id, SPEC §6.2).
func (a *app) sessionSelector(ctx context.Context, eng engine, sid string) (harness.Selector, error) {
	homes, err := eng.Homes(ctx, harness.ClaudeCode)
	if err != nil {
		return harness.Selector{}, err
	}
	s := harness.Selector{Kind: capsule.KindClaudeSession}
	for _, h := range homes {
		k, err := eng.UnitKey(capsule.KindClaudeSession, harness.ClaudeCode, h.ID, "", sid)
		if err != nil {
			return harness.Selector{}, err
		}
		s.Keys = append(s.Keys, k)
	}
	if len(s.Keys) == 0 {
		return harness.Selector{}, fmt.Errorf("%w: no Claude home is registered", harness.ErrUnregistered)
	}
	return s, nil
}

// retentionAge is cleanupPeriodDays − 2 days of the default Claude home:
// automatic restores skip older sessions (D14).
func (a *app) retentionAge(ctx context.Context, eng engine) time.Duration {
	days := 30
	if homes, err := eng.Homes(ctx, harness.ClaudeCode); err == nil {
		for _, h := range homes {
			if dir := h.Bases[capsule.BaseClaudeConfig]; dir != "" {
				if n, err := eng.CleanupPeriodDays(dir); err == nil && n > 0 {
					days = n
				}
				if h.Default {
					break
				}
			}
		}
	}
	if days <= 2 {
		return 0
	}
	return time.Duration(days-2) * 24 * time.Hour
}

func cmdLs(a *app, args []string) int {
	f := newFlags("ls")
	rootDir := f.String("root", "", "list units of the protected folder containing `DIR`")
	conflicts := f.Bool("conflicts", false, "list only units with kept-both conflicts")
	asJSON := f.Bool("json", false, "print JSON")
	pos, err := f.parse(args)
	if code, ok := a.handleParse(f, err); !ok {
		return code
	}
	if len(pos) > 0 {
		return a.usageFail(f, "unexpected argument "+pos[0])
	}
	cfg, err := a.config()
	if err != nil {
		return a.fail("ls", err)
	}
	o := sweep.ListOptions{Conflicts: *conflicts}
	if *rootDir != "" {
		r, err := a.rootArg(cfg, *rootDir)
		if err != nil {
			return a.fail("ls", err)
		}
		o.RootIDs = []string{r.ID}
	}
	ctx := context.Background()
	eng, err := a.engine(ctx, false)
	if err != nil {
		return a.fail("ls", err)
	}
	// Titles are content: only for a human on a terminal, with key purpose
	// "list" (fresh presence from agent contexts, D28, D59).
	var keys *keySource
	if !*asJSON && a.sys.stdoutTTY() {
		if err := a.sys.harden(); err != nil {
			return a.fail("ls", err)
		}
		keys = a.keys()
		defer keys.close()
		o.Keys = keys
	}
	units, err := eng.List(ctx, o)
	if err != nil && o.Keys != nil && errors.Is(err, sweep.ErrKeyDenied) {
		o.Keys = nil
		units, err = eng.List(ctx, o)
	}
	if err != nil {
		return a.fail("ls", err)
	}
	sort.SliceStable(units, func(i, j int) bool {
		return units[i].LastActivity.After(units[j].LastActivity)
	})
	if *asJSON {
		return a.printUnitsJSON(cfg, units)
	}
	a.printUnits(cfg, units)
	return exitOK
}

// lsUnit is one line of `ls --json` (content-free: no titles in JSON).
type lsUnit struct {
	Harness      string   `json:"harness"`
	Kind         string   `json:"kind"`
	Unit         string   `json:"unit"`
	Folders      []string `json:"folders"`
	Generations  int      `json:"generations"`
	Newest       uint64   `json:"newest,omitempty"`
	Plaintext    bool     `json:"plaintext"`
	Reason       string   `json:"reason,omitempty"`
	Bytes        int64    `json:"bytes"`
	LastActivity string   `json:"last_activity,omitempty"`
	Conflicts    int      `json:"conflicts,omitempty"`
	Quarantined  bool     `json:"quarantined,omitempty"`
}

func (a *app) printUnitsJSON(cfg config.Config, units []sweep.UnitInfo) int {
	out := make([]lsUnit, 0, len(units))
	for _, u := range units {
		lu := lsUnit{
			Harness: u.Harness, Kind: string(u.Kind), Unit: u.Unit, Folders: a.folderNames(cfg, u.RootIDs),
			Generations: len(u.Gens), Plaintext: u.Plaintext, Reason: u.Reason, Bytes: u.Bytes,
			Conflicts: u.Conflicts, Quarantined: u.Quarantined,
		}
		if n := len(u.Gens); n > 0 {
			lu.Newest = u.Gens[n-1].Gen
		}
		if !u.LastActivity.IsZero() {
			lu.LastActivity = u.LastActivity.UTC().Format("2006-01-02T15:04:05Z07:00")
		}
		out = append(out, lu)
	}
	enc := json.NewEncoder(a.out)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		return a.fail("ls", err)
	}
	return exitOK
}

func (a *app) printUnits(cfg config.Config, units []sweep.UnitInfo) {
	if len(units) == 0 {
		fmt.Fprintln(a.out, "no sealed units.")
		return
	}
	for _, u := range units {
		state := "sealed"
		if u.Plaintext {
			state = "unencrypted"
			if u.Reason != "" {
				state += " (" + strings.ReplaceAll(u.Reason, "_", " ") + ")"
			}
		}
		if u.Quarantined {
			state = "quarantined"
		}
		last := ""
		if !u.LastActivity.IsZero() {
			last = u.LastActivity.In(a.sys.loc).Format("2006-01-02 15:04")
		}
		line := fmt.Sprintf("%-16s %-14s %-12s %3d gen  %8s  %s  %s", u.Unit[:min(12, len(u.Unit))], u.Kind,
			strings.Join(a.folderNames(cfg, u.RootIDs), ","), len(u.Gens), ui.HumanBytes(u.Bytes), last, state)
		if u.Conflicts > 0 {
			line += fmt.Sprintf("  %d conflict(s)", u.Conflicts)
		}
		if u.Title != "" {
			line += "  " + oneLineText(u.Title)
		}
		fmt.Fprintln(a.out, strings.TrimRight(line, " "))
	}
}

// folderNames displays root ids as folders.
func (a *app) folderNames(cfg config.Config, ids []string) []string {
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		if r, ok := cfg.RootByID(id); ok {
			out = append(out, a.display(r.Path))
		} else {
			out = append(out, id)
		}
	}
	return out
}

func cmdOpen(a *app, args []string) int {
	f := newFlags("open")
	pos, err := f.parse(args)
	if code, ok := a.handleParse(f, err); !ok {
		return code
	}
	if len(pos) == 0 {
		return a.usageFail(f, "open needs at least one FILE.md.precinto")
	}
	if err := a.sys.harden(); err != nil {
		return a.fail("open", err)
	}
	ctx := context.Background()
	eng, err := a.engine(ctx, false)
	if err != nil {
		return a.failRestore("open", err)
	}
	var markers []string
	for _, p := range pos {
		abs, err := a.absPath(p)
		if err != nil {
			return a.fail("open", err)
		}
		if _, err := eng.ParseMarker(abs); err != nil {
			return a.fail("open", fmt.Errorf("%s: %w", a.display(abs), err))
		}
		markers = append(markers, abs)
	}
	keys := a.keys()
	defer keys.close()
	abort, stop := a.watchLocks(ctx, nil, keys.destroy)
	defer stop()
	_ = abort // OpenNotes takes no abort channel; destroying the keys stops it.
	rep, err := eng.OpenNotes(ctx, keys, markers)
	if err != nil {
		return a.failRestore("open", err)
	}
	a.sayOut(textOpened, countOutcome(rep, sweep.OutRestored, sweep.OutMerged))
	if n := countOutcome(rep, sweep.OutConflict); n > 0 {
		a.sayOut(textConflicts, n)
	}
	return exitOK
}

func cmdCat(a *app, args []string) int {
	f := newFlags("cat")
	raw := f.Bool("raw", false, "print control characters unchanged")
	to := f.String("to", "", "write the note to `FILE` (new file, mode 0600) instead of the terminal")
	pos, err := f.parse(args)
	if code, ok := a.handleParse(f, err); !ok {
		return code
	}
	if len(pos) != 1 {
		return a.usageFail(f, "cat needs exactly one FILE.md.precinto")
	}
	// S17: plaintext goes only to a terminal (sanitized) or to --to FILE.
	if *to == "" && !a.sys.stdoutTTY() {
		a.say(textCatNeedTTY)
		return exitUsage
	}
	if err := a.sys.harden(); err != nil {
		return a.fail("cat", err)
	}
	marker, err := a.absPath(pos[0])
	if err != nil {
		return a.fail("cat", err)
	}
	ctx := context.Background()
	eng, err := a.engine(ctx, false)
	if err != nil {
		return a.failRestore("cat", err)
	}
	if _, err := eng.ParseMarker(marker); err != nil {
		return a.fail("cat", fmt.Errorf("%s: %w", a.display(marker), err))
	}
	var w io.Writer
	var out *os.File
	if *to != "" {
		dst, err := a.absPath(*to)
		if err != nil {
			return a.fail("cat", err)
		}
		out, err = os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL|fsx.ONoFollow, 0o600)
		if err != nil {
			if errors.Is(err, os.ErrExist) {
				a.say(textCatOutExists, a.display(dst))
				return exitError
			}
			return a.fail("cat", err)
		}
		w = out
	} else if *raw {
		w = a.out
	} else {
		w = &sanitizingWriter{w: a.out}
	}
	keys := a.keys()
	defer keys.close()
	err = eng.CatNote(ctx, keys, marker, w)
	if sw, ok := w.(*sanitizingWriter); ok {
		if ferr := sw.flush(); err == nil {
			err = ferr
		}
	}
	if out != nil {
		if cerr := out.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			os.Remove(out.Name())
		}
	}
	if err != nil {
		return a.failRestore("cat", err)
	}
	return exitOK
}

// sanitizingWriter strips terminal controls (ui.SanitizeTerminal) from a
// stream. An incomplete UTF-8 sequence at the end of a write is held back
// until the next one, so multi-byte text split across writes survives and a
// C1 control split across writes is still removed.
type sanitizingWriter struct {
	w       io.Writer
	pending []byte
}

func (s *sanitizingWriter) Write(p []byte) (int, error) {
	buf := append(s.pending, p...)
	cut := len(buf) - incompleteTail(buf)
	s.pending = append([]byte(nil), buf[cut:]...)
	if _, err := s.w.Write(ui.SanitizeTerminal(buf[:cut])); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (s *sanitizingWriter) flush() error {
	if len(s.pending) == 0 {
		return nil
	}
	_, err := s.w.Write(ui.SanitizeTerminal(s.pending))
	s.pending = nil
	return err
}

// incompleteTail returns how many bytes at the end of b start a UTF-8
// sequence that is not complete yet (0–3).
func incompleteTail(b []byte) int {
	for i := 1; i <= 3 && i <= len(b); i++ {
		c := b[len(b)-i]
		if c < 0x80 {
			return 0
		}
		if c >= 0xc0 { // lead byte
			need := 2
			switch {
			case c >= 0xf0:
				need = 4
			case c >= 0xe0:
				need = 3
			}
			if need > i {
				return i
			}
			return 0
		}
	}
	return 0
}

func cmdResolve(a *app, args []string) int {
	f := newFlags("resolve")
	keep := f.String("keep", "", "keep the `capsule|plaintext` version")
	pos, err := f.parse(args)
	if code, ok := a.handleParse(f, err); !ok {
		return code
	}
	if len(pos) != 1 {
		return a.usageFail(f, "resolve needs exactly one FILE")
	}
	if err := oneOfFlag("keep", *keep, "capsule", "plaintext"); err != nil {
		return a.usageFail(f, err.Error())
	}
	path, err := a.absPath(pos[0])
	if err != nil {
		return a.fail("resolve", err)
	}
	if *keep == "" {
		t, err := a.sys.openTTY()
		if err != nil {
			return a.usageFail(f, "--keep capsule|plaintext is needed without a terminal")
		}
		line, err := t.ReadLine(fmt.Sprintf(textResolveWhich, a.display(path)))
		t.Close()
		if err != nil {
			return a.fail("resolve", err)
		}
		*keep = strings.TrimSpace(line)
		if *keep != "capsule" && *keep != "plaintext" {
			a.say(textNotConfirmed)
			return exitLocked
		}
	}
	if err := a.sys.harden(); err != nil {
		return a.fail("resolve", err)
	}
	ctx := context.Background()
	eng, err := a.engine(ctx, false)
	if err != nil {
		return a.failRestore("resolve", err)
	}
	keys := a.keys()
	defer keys.close()
	if _, err := eng.Resolve(ctx, keys, path, *keep); err != nil {
		return a.failRestore("resolve", err)
	}
	a.sayOut(textResolved, a.display(path))
	return exitOK
}

func cmdForget(a *app, args []string) int {
	f := newFlags("forget")
	pos, err := f.parse(args)
	if code, ok := a.handleParse(f, err); !ok {
		return code
	}
	if len(pos) != 1 {
		return a.usageFail(f, "forget needs exactly one FILE or unit key")
	}
	cfg, err := a.config()
	if err != nil {
		return a.fail("forget", err)
	}
	ctx := context.Background()
	eng, err := a.engine(ctx, false)
	if err != nil {
		return a.fail("forget", err)
	}
	unit, name, err := a.unitOf(cfg, eng, pos[0])
	if err != nil {
		return a.fail("forget", err)
	}
	// D59: refused in agent contexts and without a controlling terminal;
	// typed confirmation on a TTY (SEC-28).
	if err := a.refuseAgent(refusal{action: "forget the sealed copies of", folder: name, command: "forget " + pos[0]}); err != nil {
		return exitLocked
	}
	t, err := a.needTerminal("forget")
	if err != nil {
		return exitLocked
	}
	defer t.Close()
	gens, err := eng.Generations(unit)
	if err != nil {
		return a.fail("forget", err)
	}
	if len(gens) == 0 {
		a.say(textForgetNone, name)
		return exitError
	}
	for _, g := range gens {
		a.say("  generation %d · %s · sealed %s", g.Gen, ui.HumanBytes(g.Size), g.SealedAt.In(a.sys.loc).Format("2006-01-02 15:04"))
	}
	if err := a.typedConfirm(t, fmt.Sprintf(textForgetWhat, len(gens), name), wordForget); err != nil {
		return exitLocked
	}
	rep, err := eng.Forget(ctx, unit)
	if err != nil {
		return a.fail("forget", err)
	}
	a.sayOut(textForgot, rep.Count(sweep.OutForgotten))
	if err := rep.Err(); err != nil {
		return a.fail("forget", err)
	}
	return exitOK
}

// unitOf resolves a forget argument: a unit key, a marker file, or a note
// path inside a protected folder (its md unit key, SPEC §6.2).
func (a *app) unitOf(cfg config.Config, eng engine, arg string) (unit, name string, err error) {
	if unitKeyRE.MatchString(arg) {
		return arg, arg, nil
	}
	abs, err := a.absPath(arg)
	if err != nil {
		return "", "", err
	}
	if strings.HasSuffix(abs, ".md.precinto") {
		k, err := eng.ParseMarker(abs)
		if err != nil {
			return "", "", fmt.Errorf("%s: %w", a.display(abs), err)
		}
		return k, a.display(strings.TrimSuffix(abs, ".precinto")), nil
	}
	r, ok := a.rootFor(cfg, abs)
	if !ok {
		return "", "", notProtectedError{dir: a.display(abs)}
	}
	p := abs
	if real, err := a.sys.realpath(filepath.Dir(abs)); err == nil {
		p = filepath.Join(real, filepath.Base(abs))
	}
	rel, err := filepath.Rel(r.Path, p)
	if err != nil || !filepath.IsLocal(rel) {
		return "", "", notProtectedError{dir: a.display(abs)}
	}
	k, err := eng.UnitKey(capsule.KindMarkdown, "", "", r.ID, filepath.ToSlash(rel))
	if err != nil {
		return "", "", err
	}
	return k, a.display(abs), nil
}

func cmdPrune(a *app, args []string) int {
	f := newFlags("prune")
	unit := f.String("unit", "", "prune only the unit `KEY`")
	var keep optInt
	f.Var(&keep, "keep", "keep the last `N` generations (default 3)")
	diverged := f.Bool("diverged", false, "also delete diverged generations")
	dryRun := f.Bool("dry-run", false, "only show what would be deleted")
	pos, err := f.parse(args)
	if code, ok := a.handleParse(f, err); !ok {
		return code
	}
	if len(pos) > 0 {
		return a.usageFail(f, "unexpected argument "+pos[0])
	}
	if *unit != "" && !unitKeyRE.MatchString(*unit) {
		return a.usageFail(f, "--unit wants a unit key (32 hex characters, see precinto ls)")
	}
	keepN := 3
	if keep.set {
		if keep.v < 1 {
			return a.usageFail(f, "--keep must be at least 1")
		}
		keepN = keep.v
	}
	var t terminal
	if !*dryRun {
		// D59: refused in agent contexts and without a controlling
		// terminal; typed confirmation on a TTY (SEC-28).
		if err := a.refuseAgent(refusal{action: "delete sealed generations of", folder: "your folders", command: "prune"}); err != nil {
			return exitLocked
		}
		if t, err = a.needTerminal("prune"); err != nil {
			return exitLocked
		}
		defer t.Close()
	}
	ctx := context.Background()
	eng, err := a.engine(ctx, false)
	if err != nil {
		return a.fail("prune", err)
	}
	o := sweep.PruneOptions{Unit: *unit, KeepLast: keepN, Diverged: *diverged, DryRun: true}
	plan, err := eng.Prune(ctx, o)
	if err != nil {
		return a.fail("prune", err)
	}
	units, gens := pruneCounts(plan)
	// SPEC §11.7: list what will be deleted before asking.
	for _, u := range plan.Units {
		if u.Outcome != sweep.OutPruned {
			continue
		}
		a.sayOut(textPruneLine, u.Unit, u.Kind, u.Files, ui.HumanBytes(u.Bytes))
	}
	if *dryRun {
		a.sayOut(textPruneDry, gens, units)
		return exitOK
	}
	if gens == 0 {
		a.sayOut(textNothingToDo)
		return exitOK
	}
	if err := a.typedConfirm(t, fmt.Sprintf(textPruneWhat, gens, units), wordPrune); err != nil {
		return exitLocked
	}
	o.DryRun = false
	rep, err := eng.Prune(ctx, o)
	if err != nil {
		return a.fail("prune", err)
	}
	pruned, _ := pruneCounts(rep)
	a.sayOut(textPruned, pruned)
	return exitOK
}

// pruneCounts counts the units and capsules a prune report names: one
// OutPruned result per unit, Files capsules each (CC-30).
func pruneCounts(r *sweep.Report) (units, gens int) {
	if r == nil {
		return 0, 0
	}
	seen := map[string]bool{}
	for _, u := range r.Units {
		if u.Outcome != sweep.OutPruned {
			continue
		}
		gens += u.Files
		if !seen[u.Unit] {
			seen[u.Unit] = true
			units++
		}
	}
	return units, gens
}

func cmdCodex(a *app, args []string) int {
	f := newFlags("codex")
	rootDir := f.String("root", "", "the protected folder `DIR`")
	prefer := f.String("prefer", "", "reconcile: keep the `capsule|plaintext` side in place")
	pos, err := f.parse(args)
	if code, ok := a.handleParse(f, err); !ok {
		return code
	}
	if len(pos) != 1 || (pos[0] != "reconcile" && pos[0] != "sync-config") {
		return a.usageFail(f, "codex needs reconcile or sync-config")
	}
	if *rootDir == "" {
		return a.usageFail(f, "--root DIR is required")
	}
	cfg, err := a.config()
	if err != nil {
		return a.fail("codex", err)
	}
	r, err := a.rootArg(cfg, *rootDir)
	if err != nil {
		return a.fail("codex", err)
	}
	ctx := context.Background()
	switch pos[0] {
	case "reconcile":
		if err := oneOfFlag("prefer", *prefer, string(sweep.PreferCapsule), string(sweep.PreferPlaintext)); err != nil || *prefer == "" {
			return a.usageFail(f, "--prefer capsule|plaintext is required")
		}
		if err := a.sys.harden(); err != nil {
			return a.fail("codex", err)
		}
		eng, err := a.engine(ctx, false)
		if err != nil {
			return a.fail("codex", err)
		}
		keys := a.keys()
		defer keys.close()
		if _, err := eng.ReconcileCodex(ctx, keys, r.ID, sweep.CodexPrefer(*prefer)); err != nil {
			return a.failRestore("codex", err)
		}
		a.sayOut(textReconciled, a.display(r.Path))
	case "sync-config":
		if *prefer != "" {
			return a.usageFail(f, "--prefer belongs to codex reconcile")
		}
		eng, err := a.engine(ctx, false)
		if err != nil {
			return a.fail("codex", err)
		}
		if err := eng.PrepareCodexHome(ctx, r.ID, true); err != nil {
			return a.fail("codex", err)
		}
		a.sayOut(textSyncedConfig, a.display(r.Path))
	}
	return exitOK
}
