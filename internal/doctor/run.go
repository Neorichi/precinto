package doctor

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/precinto/precinto/internal/config"
	"github.com/precinto/precinto/internal/harness"
	"github.com/precinto/precinto/internal/ipc"
	"github.com/precinto/precinto/internal/paths"
	"github.com/precinto/precinto/internal/sweep"
	"github.com/precinto/precinto/internal/sweep/capslog"
	"github.com/precinto/precinto/internal/sweep/journal"
)

// errNoLayout: Options.Layout is the zero value (or not absolute), so no
// precinto location can be checked.
var errNoLayout = errors.New("doctor: no precinto layout (Options.Layout is empty)")

// env is the state of one Run: the options, the dependencies and the
// inputs several checks share, each loaded at most once. Checks run one
// after the other, so it needs no locking.
type env struct {
	ctx  context.Context
	o    Options
	d    *deps
	now  time.Time
	home string // $HOME, "" when unset or relative
	sel  map[harness.ID]bool

	statusDone bool
	status     *ipc.StatusResp // nil: the agent is not running or did not answer
	statusErr  error

	logDone bool
	log     []capslog.Entry
	logErr  error

	journalDone bool
	pending     []*journal.Record
	pendingErr  error

	saltDone bool
	salt     []byte
	saltErr  error

	plainDone bool
	plain     []sweep.Plaintext
	plainErr  error

	claudeDirsDone bool
	claudeDirs     []string

	vaults   map[string]*vaultInfo
	settings map[string]*settingsFile
	claudeIn *install
	codexIn  *install
}

// run implements Run with explicit dependencies.
func run(ctx context.Context, o Options, d *deps) ([]Finding, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	sel, err := selectHarness(o.Harness)
	if err != nil {
		return nil, err
	}
	if c, ok := paths.Clean(o.Layout.Base); !ok || c == "/" {
		return nil, errNoLayout
	}
	e := &env{ctx: ctx, o: o, d: d, now: d.Now(), sel: sel,
		vaults: map[string]*vaultInfo{}, settings: map[string]*settingsFile{}}
	if h, err := paths.UserHome(o.Env); err == nil {
		e.home = h
	}
	var out []Finding
	for _, c := range registry() {
		if err := ctx.Err(); err != nil {
			return finalize(out), err
		}
		if c.leaks && !o.Leaks {
			continue
		}
		if c.harness != "" && !e.harnessSelected(c.harness) {
			continue
		}
		out = append(out, e.runCheck(c)...)
	}
	out = append(out, e.attentionFindings()...)
	return finalize(out), ctx.Err()
}

// selectHarness validates Options.Harness: "" selects every harness, a
// built-in id (or "claude", what users type) one of them, and the id of a
// data-driven inventory only the checks that are not harness specific.
func selectHarness(h string) (map[harness.ID]bool, error) {
	h = strings.TrimSpace(h)
	switch h {
	case "":
		return map[harness.ID]bool{harness.ClaudeCode: true, harness.Codex: true}, nil
	case string(harness.ClaudeCode), "claude":
		return map[harness.ID]bool{harness.ClaudeCode: true}, nil
	case string(harness.Codex):
		return map[harness.ID]bool{harness.Codex: true}, nil
	}
	if inventoryIDs()[h] {
		return map[harness.ID]bool{}, nil
	}
	return nil, fmt.Errorf("doctor: %w: %q", harness.ErrUnknownHarness, h)
}

// harnessSelected reports whether the checks of h run: h was selected and
// precinto manages it ([harness.<id>] enabled).
func (e *env) harnessSelected(h harness.ID) bool {
	if !e.sel[h] {
		return false
	}
	hc, ok := e.o.Cfg.Harness[string(h)]
	return !ok || hc.Enabled
}

// rootProtects reports whether r protects harness h (an empty list means
// the default, every built-in harness).
func rootProtects(r config.Root, h harness.ID) bool {
	if len(r.Harnesses) == 0 {
		return true
	}
	for _, x := range r.Harnesses {
		if x == string(h) {
			return true
		}
	}
	return false
}

// rootFor returns the deepest root containing p that protects h.
func (e *env) rootFor(p string, h harness.ID) (config.Root, bool) {
	var best config.Root
	found := false
	for _, r := range e.o.Cfg.Roots {
		if !rootProtects(r, h) || !paths.Within(r.Path, p) {
			continue
		}
		if !found || len(r.Path) > len(best.Path) {
			best, found = r, true
		}
	}
	return best, found
}

// internalErrorText is the message of a check that panicked: its other
// findings are lost, the rest of the run is not.
const internalErrorText = "this check could not run (internal error); the other checks are not affected"

// runCheck runs one check. A panic in a dependency (a bug, or a package of
// the tree that is not implemented yet) becomes a warning of that check
// instead of ending the whole run; its text is fixed, never the panic
// value, which could carry content.
func (e *env) runCheck(c check) (fs []Finding) {
	defer func() {
		if r := recover(); r != nil {
			fs = []Finding{{Code: c.code, Severity: Warn, Message: internalErrorText,
				Fix: "report this to the precinto maintainers, with the output of precinto version"}}
		}
	}()
	return c.run(e)
}

// toolTimeout bounds one call into an OS facility (fdesetup, mdfind,
// tmutil, lsof): doctor reports what it could not learn instead of
// hanging on a stuck tool.
const toolTimeout = 15 * time.Second

// bounded returns a context for one OS-facility call.
func (e *env) bounded() (context.Context, context.CancelFunc) {
	return context.WithTimeout(e.ctx, toolTimeout)
}

// daemon returns the agent's status, or nil when it does not run or did not
// answer (statusErr says why). It is asked once per Run.
func (e *env) daemon() *ipc.StatusResp {
	if !e.statusDone {
		e.statusDone = true
		st, err := e.d.DaemonStatus(e.ctx)
		if err == nil {
			e.status = &st
		}
		e.statusErr = err
	}
	return e.status
}

// unlocked reports whether the vault id is unlocked right now. Without an
// agent nothing is unlocked: keys live only in the agent (D4).
func (e *env) unlocked(id string) bool {
	st := e.daemon()
	return st != nil && unlockedVaults(*st)[id]
}

// capsuleLog returns the live capsule-log entries (loaded once).
func (e *env) capsuleLog() ([]capslog.Entry, error) {
	if !e.logDone {
		e.logDone = true
		if exists(e.o.Layout.CapsuleLog) {
			e.log, e.logErr = e.d.CapsuleLog()
		}
	}
	return e.log, e.logErr
}

// journalPending returns the unfinished journal records (loaded once).
func (e *env) journalPending() ([]*journal.Record, error) {
	if !e.journalDone {
		e.journalDone = true
		if exists(e.o.Layout.JournalDir) {
			e.pending, e.pendingErr = e.d.JournalPending()
		}
	}
	return e.pending, e.pendingErr
}

// nameSalt returns state/name.salt, or nil when it does not exist yet.
func (e *env) nameSalt() ([]byte, error) {
	if !e.saltDone {
		e.saltDone = true
		e.salt, e.saltErr = readSalt(e.o.Layout.NameSalt)
	}
	return e.salt, e.saltErr
}

// folder renders the display name of a root for messages.
func (e *env) folder(r config.Root) string { return e.show(r.Path) }

// folderOf renders the display name of a root id; the global vault and
// unknown ids get a descriptive name.
func (e *env) folderOf(id string) string {
	if r, ok := e.o.Cfg.RootByID(id); ok {
		return e.folder(r)
	}
	if id == "global" {
		return "the global vault (files of no folder)"
	}
	return "folder id " + oneLine(id)
}

// show renders a path for a one-line message: ~-shortened, without control
// characters.
func (e *env) show(p string) string { return oneLine(paths.Tilde(e.home, p)) }

// arg renders a path as a shell argument for a fix command.
func (e *env) arg(p string) string { return shellArg(e.home, p) }

// finalize orders findings by code (Codes order), drops "ok" findings of a
// code that also has a problem, and removes duplicates (the agent's
// attention items repeat what a check found).
func finalize(fs []Finding) []Finding {
	rank := codeRank()
	bad := map[string]bool{}
	for _, f := range fs {
		if f.Severity != OK {
			bad[f.Code] = true
		}
	}
	seen := map[string]bool{}
	out := make([]Finding, 0, len(fs))
	for _, f := range fs {
		if f.Severity == OK && bad[f.Code] {
			continue
		}
		key := f.Code + "\x00" + string(f.Severity) + "\x00" + f.Message
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, f)
	}
	sort.SliceStable(out, func(i, j int) bool {
		ri, ok := rank[out[i].Code]
		if !ok {
			ri = len(rank)
		}
		rj, ok := rank[out[j].Code]
		if !ok {
			rj = len(rank)
		}
		return ri < rj
	})
	return out
}

// inventoryIDs lists the ids of the embedded inventories (file names).
func inventoryIDs() map[string]bool {
	out := map[string]bool{}
	for _, name := range embeddedInventories() {
		out[strings.TrimSuffix(filepath.Base(name), ".toml")] = true
	}
	return out
}
