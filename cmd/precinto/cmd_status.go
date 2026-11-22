package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/precinto/precinto/internal/capsule"
	"github.com/precinto/precinto/internal/config"
	"github.com/precinto/precinto/internal/doctor"
	"github.com/precinto/precinto/internal/ipc"
	"github.com/precinto/precinto/internal/paths"
	"github.com/precinto/precinto/internal/shellinit"
	"github.com/precinto/precinto/internal/sweep"
	"github.com/precinto/precinto/internal/ui"
	"github.com/precinto/precinto/internal/vault"
)

// statusVersion is the schema version of `status --json` (SPEC §16.4).
const statusVersion = 1

// statusV1 is `precinto status --json` schema v1:
// {"v":1, "vault", "agent", "folders"[], "harnesses"[], "attention"[]}.
// Arrays are never null; times are RFC 3339 and omitted when unknown. It
// holds paths, counts and states only (I7).
type statusV1 struct {
	V         int             `json:"v"`
	Vault     statusVault     `json:"vault"`
	Agent     statusAgent     `json:"agent"`
	Folders   []statusFolder  `json:"folders"`
	Harnesses []statusHarness `json:"harnesses"`
	Attention []ipc.Attention `json:"attention"`

	// policy is the policy in force (floorPolicy: config.toml merged with
	// the confirmed settings, as the agent enforces it) that the human
	// output quotes; never part of the JSON.
	policy config.Policy
	// When config.toml does not load (UX-09): standIn names the settings
	// that stand in for it ("the settings confirmed last"), and configErr
	// is its error, so --check never passes.
	standIn   string
	configErr error
	// plainScanned: the plaintext summary ran (with config.toml or the
	// stand-in settings); plainNote: why it did not.
	plainScanned bool
	plainNote    string
}

type statusVault struct {
	Initialized        bool       `json:"initialized"`
	Factors            []string   `json:"factors"` // enrolled factor names, recovery excluded
	RecoveryTested     bool       `json:"recovery_tested"`
	RecoveryVerifiedAt *time.Time `json:"recovery_verified_at,omitempty"`
}

type statusAgent struct {
	Running     bool       `json:"running"`
	PID         int        `json:"pid,omitempty"`
	Version     string     `json:"version,omitempty"`
	Started     *time.Time `json:"started,omitempty"`
	ScreenWatch bool       `json:"screen_watch"`
	LastSweep   *time.Time `json:"last_sweep,omitempty"` // background re-seal heartbeat (state/sweep.last)
	Service     string     `json:"service"`              // "installed" | "not-installed" | "unavailable"
}

type statusFolder struct {
	ID           string          `json:"id"`
	Path         string          `json:"path"`
	State        string          `json:"state"` // "locked" | "unlocked"
	Reason       string          `json:"reason,omitempty"`
	Since        *time.Time      `json:"since,omitempty"`
	IdleDeadline *time.Time      `json:"idle_deadline,omitempty"`
	AbsDeadline  *time.Time      `json:"abs_deadline,omitempty"`
	Sessions     statusSessions  `json:"sessions"`
	Unencrypted  statusPlaintext `json:"unencrypted"`
	Harnesses    []string        `json:"harnesses"`
	MD           string          `json:"md"`
	OnEnter      string          `json:"on_enter"`
	Ungated      []statusUngated `json:"ungated,omitempty"`
	Background   int             `json:"background,omitempty"`
}

type statusSessions struct {
	Running  int `json:"running"`
	Working  int `json:"working"`
	Paused   int `json:"paused"`
	Restored int `json:"restored"`
	Sealed   int `json:"sealed"`
	Ungated  int `json:"ungated"`
}

type statusUngated struct {
	Harness string `json:"harness"`
	PID     int    `json:"pid"`
}

type statusPlaintext struct {
	Files    int            `json:"files"`
	Bytes    int64          `json:"bytes"`
	ByReason map[string]int `json:"by_reason"`
	// Incomplete: the counts may miss files, because config.toml does not
	// load (they were counted with the settings standing in for it) or the
	// folder could not be scanned; --check never passes on them (UX-09).
	Incomplete bool `json:"incomplete,omitempty"`
}

type statusHarness struct {
	ID           string     `json:"id"`
	Enabled      bool       `json:"enabled"`
	Experimental bool       `json:"experimental,omitempty"`
	Version      string     `json:"version,omitempty"` // reported at register by its running sessions (ipc.SessionStatus.Version)
	Hooks        string     `json:"hooks"`             // "ok" | "not-seen" | "unknown"
	Sessions     int        `json:"sessions"`
	Wrapper      bool       `json:"wrapper_installed"`
	SeenAt       *time.Time `json:"seen_at,omitempty"`
}

func cmdStatus(a *app, args []string) int {
	f := newFlags("status")
	asJSON := f.Bool("json", false, "print schema v1 JSON")
	check := f.Bool("check", false, "exit 3 when a locked folder still has unencrypted files")
	pos, err := f.parse(args)
	if code, ok := a.handleParse(f, err); !ok {
		return code
	}
	if len(pos) > 0 {
		return a.usageFail(f, "unexpected argument "+pos[0])
	}
	s, err := a.gatherStatus(context.Background())
	if err != nil {
		return a.fail("status", err)
	}
	if *asJSON {
		enc := json.NewEncoder(a.out)
		enc.SetIndent("", "  ")
		if err := enc.Encode(s); err != nil {
			return a.fail("status", err)
		}
	} else {
		a.printStatus(a.out, s)
	}
	if *check {
		return a.checkStatus(s)
	}
	return exitOK
}

// checkStatus is the exit code of `status --check`: 3 when a folder that
// is not unlocked has unencrypted files; else 1 when the check could not
// look everywhere (config.toml does not load, or a locked folder could not
// be scanned), so that a broken file never makes the check pass (UX-09);
// else 0.
func (a *app) checkStatus(s statusV1) int {
	unknown := false
	for _, fo := range s.Folders {
		if fo.State == "unlocked" {
			continue
		}
		if fo.Unencrypted.Files > 0 {
			return exitLocked
		}
		unknown = unknown || fo.Unencrypted.Incomplete
	}
	switch {
	case s.configErr != nil:
		a.say(textCheckConfig, configErrorText(s.configErr))
		return exitError
	case unknown:
		a.say(textCheckUnscanned, s.plainNote)
		return exitError
	}
	return exitOK
}

// gatherStatus combines the daemon status (when it runs), the on-disk
// plaintext summary, the capsule log and the vault metadata. Nothing is
// created on disk before init.
func (a *app) gatherStatus(ctx context.Context) (statusV1, error) {
	s := statusV1{V: statusVersion, Folders: []statusFolder{}, Harnesses: []statusHarness{}, Attention: []ipc.Attention{}}
	s.Vault.Factors = []string{}
	l, err := a.layout()
	if err != nil {
		return s, err
	}
	var local []ipc.Attention
	cfg, cfgErr := a.config()
	if cfgErr != nil {
		// UX-09: status still answers. The settings confirmed last (or the
		// defaults) stand in, with every folder whose vault records its
		// path and, below, the agent's view; the broken file is an
		// attention item with its line, key and reason.
		cfg, s.standIn = a.standInConfig(l)
		s.configErr = cfgErr
		local = append(local, ipc.Attention{Code: doctor.CheckConfig, Detail: configErrorText(cfgErr), Fix: textConfigFix})
	}

	if fileExists(l.Base) {
		if vs, err := a.vaults(); err == nil {
			if done, err := vs.Initialized(); err == nil && done {
				s.Vault.Initialized = true
				if m, err := vs.Meta(vault.GlobalID); err == nil {
					for _, fc := range m.Factors {
						if fc.Kind != vault.FactorRecovery {
							s.Vault.Factors = append(s.Vault.Factors, fc.Name)
						}
					}
					if !m.RecoveryVerifiedAt.IsZero() {
						t := m.RecoveryVerifiedAt
						s.Vault.RecoveryTested, s.Vault.RecoveryVerifiedAt = true, &t
					}
				}
			}
		}
	}
	if s.Vault.Initialized && !s.Vault.RecoveryTested {
		local = append(local, ipc.Attention{Code: ipc.AttnRecoveryTested, Detail: "recovery key: never tested", Fix: "precinto recover --verify"})
	}

	var st *ipc.StatusResp
	if c, err := a.dial(ctx, false); err == nil {
		if resp, err := c.Status(ctx); err == nil {
			st = &resp
		}
		c.Close()
	}
	// D142: the folders the agent enforces, not only config.toml's: a
	// folder whose removal waits for a confirmation (the confirmed
	// settings still hold it), the folders vaults record while the pin is
	// forged or missing, and every folder the agent itself reports, so
	// that --check never passes while one of them holds plaintext.
	cfg = a.enforcedConfig(cfg, l)
	if st != nil {
		cfg = config.WithRoots(cfg, agentRoots(*st)...)
	}
	// D145: settings that name no folder are checked only by unlock
	// --global; folders whose vault is kept but that nothing protects are
	// named, so a pin that dropped every folder never goes unseen.
	if rs := a.unprotectedFolders(cfg, l); len(rs) > 0 {
		local = append(local, a.unprotectedAttention(rs))
	}
	s.policy = floorPolicy(cfg, l)
	if st != nil {
		s.Agent.Running, s.Agent.PID, s.Agent.Version, s.Agent.ScreenWatch = true, st.PID, st.Version, st.ScreenWatch
		if !st.Started.IsZero() {
			t := st.Started
			s.Agent.Started = &t
		}
		if !st.LastSweep.IsZero() {
			t := st.LastSweep
			s.Agent.LastSweep = &t
		}
		if len(st.PendingPolicy) > 0 {
			local = append(local, ipc.Attention{Code: ipc.AttnPendingPolicy, Count: len(st.PendingPolicy), Fix: "precinto unlock"})
		}
	}
	if s.Agent.LastSweep == nil {
		if fi, err := os.Stat(l.SweepLast); err == nil {
			t := fi.ModTime().UTC()
			s.Agent.LastSweep = &t
		}
	}
	s.Agent.Service = a.serviceState()

	plain := map[string]sweep.Plaintext{}
	var units []sweep.UnitInfo
	var wrongHome map[string]int
	s.plainNote = textPlainNotSetUp
	if s.Vault.Initialized {
		// The engine is built from the folders listed below: config.toml's
		// (or the stand-in settings' when it does not load, UX-09) and
		// those the agent enforces (D142), so that each is scanned.
		src := a.withConfig(cfg)
		s.plainNote = textPlainUnscanned
		if eng, err := src.engine(ctx, false); err == nil {
			if ps, err := eng.PlaintextSummary(ctx); err == nil {
				s.plainScanned, s.plainNote = true, ""
				for _, p := range ps {
					plain[p.RootID] = p
				}
			}
			if us, err := eng.List(ctx, sweep.ListOptions{}); err == nil {
				units = us
			}
			// CC-18: Codex conversations of protected folders saved in the
			// user's own Codex home (started without precinto run codex).
			if n, err := eng.WrongHomeRollouts(ctx); err == nil {
				wrongHome = n
			}
		}
	}

	vaults := map[string]ipc.VaultStatus{}
	if st != nil {
		for _, v := range st.Vaults {
			vaults[v.VaultID] = v
		}
	}
	for _, r := range cfg.Roots {
		fo := statusFolder{
			ID: r.ID, Path: r.Path, State: "locked", Reason: string(ui.ReasonStart),
			Harnesses: append([]string{}, r.Harnesses...), MD: r.MD, OnEnter: cfg.EffectiveOnEnter(r),
			Unencrypted: statusPlaintext{ByReason: map[string]int{}},
		}
		if fo.MD == "" {
			fo.MD = config.MDLedger
		}
		if v, ok := vaults[r.ID]; ok {
			fo.State, fo.Reason = v.State, v.Reason
			fo.Since = timePtr(v.Since)
			if v.State == "unlocked" {
				fo.IdleDeadline, fo.AbsDeadline = timePtr(v.IdleDeadline), timePtr(v.AbsDeadline)
			}
		}
		if st != nil {
			for _, ss := range st.Sessions {
				if !slices.Contains(ss.RootIDs, r.ID) {
					continue
				}
				if ss.Background {
					fo.Background++
				}
				switch {
				case !ss.HooksSeen:
					fo.Sessions.Ungated++
					fo.Ungated = append(fo.Ungated, statusUngated{Harness: ss.Harness, PID: ss.Proc.PID})
				case ss.State == "paused" || ss.State == "ending":
					fo.Sessions.Paused++
				case ss.Busy:
					fo.Sessions.Working++
				default:
					fo.Sessions.Running++
				}
			}
		}
		for _, u := range units {
			if !slices.Contains(u.RootIDs, r.ID) || (u.Kind != capsule.KindClaudeSession && u.Kind != capsule.KindCodexHome) {
				continue
			}
			switch {
			case u.Plaintext && u.Reason == "restored":
				fo.Sessions.Restored++
			case !u.Plaintext && len(u.Gens) > 0:
				fo.Sessions.Sealed++
			}
		}
		if p, ok := plain[r.ID]; ok {
			fo.Unencrypted.Files, fo.Unencrypted.Bytes = p.Files, p.Bytes
			for k, v := range p.ByReason {
				fo.Unencrypted.ByReason[k] = v
			}
		}
		fo.Unencrypted.Incomplete = !s.plainScanned || cfgErr != nil
		if fo.State != "unlocked" && fo.Unencrypted.Files > 0 {
			fix := "precinto doctor"
			if fo.Unencrypted.ByReason["adopted"] > 0 {
				// Sweeps never seal sessions found only by their
				// transcripts' cwd; seal --adopt does (D113, CROSS from
				// group w). The folder is one shell word.
				fix = "precinto seal --adopt --root " + ui.ShellWord(a.home(), r.Path)
			}
			local = append(local, ipc.Attention{Code: ipc.AttnUnsealed, Folder: a.display(r.Path), Count: fo.Unencrypted.Files, Fix: fix})
		}
		// D63: plaintext a locked folder keeps only because of weak
		// liveness evidence (PlaintextSummary reason hold-capped).
		if n := fo.Unencrypted.ByReason[ipc.AttnHoldCapped]; n > 0 && fo.State != "unlocked" {
			local = append(local, ipc.Attention{Code: ipc.AttnHoldCapped, Folder: a.display(r.Path), Count: n, Fix: "precinto doctor"})
		}
		if n := wrongHome[r.ID]; n > 0 {
			local = append(local, ipc.Attention{Code: ipc.AttnCodexWrongHome, Folder: a.display(r.Path), Count: n,
				Detail: ui.Format(ui.MsgCodexOutside, ui.Vars{N: n, Folder: a.display(r.Path)}),
				Fix:    "precinto run codex"})
		}
		for _, u := range fo.Ungated {
			cmd := harnessCommand(u.Harness) // C9.ungated names what the user types: claude, not claude-code
			local = append(local, ipc.Attention{Code: ipc.AttnUngatedSession, Folder: a.display(r.Path), PID: u.PID, Harness: cmd,
				Detail: ui.Format(ui.MsgUngatedSession, ui.Vars{Harness: cmd, PID: u.PID, Folder: a.display(r.Path)}),
				Fix:    "precinto run " + cmd})
		}
		s.Folders = append(s.Folders, fo)
	}

	if n := countEntries(l.QuarantineDir); n > 0 {
		local = append(local, ipc.Attention{Code: ipc.AttnQuarantine, Count: n, Fix: "precinto doctor"})
	}

	wrapper := a.wrapperInstalled()
	ids := make([]string, 0, len(cfg.Harness))
	for id := range cfg.Harness {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		h := cfg.Harness[id]
		sh := statusHarness{ID: id, Enabled: h.Enabled, Experimental: h.Experimental, Hooks: "unknown", Wrapper: wrapper}
		var seen *time.Time
		for _, home := range h.Homes {
			if !home.SeenAt.IsZero() && (seen == nil || home.SeenAt.After(*seen)) {
				t := home.SeenAt
				seen = &t
			}
		}
		sh.SeenAt = seen
		if st != nil {
			any, ok := 0, 0
			for _, ss := range st.Sessions {
				if ss.Harness != id {
					continue
				}
				any++
				if ss.HooksSeen {
					ok++
				}
				if ss.Version != "" && (sh.Version == "" || cmpDotted(ss.Version, sh.Version) > 0) {
					sh.Version = ss.Version // the newest version running
				}
			}
			sh.Sessions = any
			switch {
			case ok > 0:
				sh.Hooks = "ok"
			case any > 0:
				sh.Hooks = "not-seen"
			}
		}
		s.Harnesses = append(s.Harnesses, sh)
	}

	s.Attention = mergeAttention(stAttention(st), local)
	return s, nil
}

// configErrorText is a config.toml error for an attention item or a
// finding: one line, without the error class prefix ("config.toml line 3,
// policy.min_free: size …").
func configErrorText(err error) string {
	return oneLineText(strings.TrimPrefix(err.Error(), config.ErrInvalid.Error()+": "))
}

// standInConfig is what stands in for a config.toml that does not load
// (UX-09): the settings confirmed last (state/policy.pinned), else the
// defaults, with the folders the agent enforces (enforcedConfig, D142):
// the confirmed settings' folders and, while the pin is missing or has a
// forged shape, every folder whose vault records its path (vault.toml
// root_path), so that status, doctor, their scans and the sealing commands
// still see each protected folder. A retired vault (D74) is not one: a
// broken config.toml never makes precinto seal or scan a folder the user
// stopped protecting. what names the settings for the user. Neither source
// is validated as a configuration: a folder whose path could not be saved
// (relative, unclean, "/", a control character) is left out
// (config.WithRoots, D149).
func (a *app) standInConfig(l paths.Layout) (cfg config.Config, what string) {
	cfg, what = config.Default(), textStandInDefaults
	if pinned, ok, err := config.LoadPinned(l.PolicyPinned); err == nil && ok {
		cfg, what = pinned.Config, textStandInPinned
	}
	pinnedRoots := cfg.Roots
	cfg.Roots = nil
	cfg = config.WithRoots(cfg, pinnedRoots...)
	return a.enforcedConfig(cfg, l), what
}

// addStandInRoot adds the folder id at path, with the default settings,
// to settings that lack it (config.WithRoots).
func addStandInRoot(cfg *config.Config, id, path string) {
	*cfg = config.WithRoots(*cfg, config.Root{ID: id, Path: path})
}

// withConfig returns a copy of a whose config() is cfg, for an engine
// built from settings standing in for a config.toml that does not load
// (UX-09).
func (a *app) withConfig(cfg config.Config) *app {
	b := newApp(a.stdio, a.env, a.sys)
	b.lay, b.layErr = a.layout()
	b.layDone = true
	b.cfg, b.cfgDone = cfg, true
	return b
}

func stAttention(st *ipc.StatusResp) []ipc.Attention {
	if st == nil {
		return nil
	}
	return st.Attention
}

// mergeAttention returns the daemon's items followed by local ones, each
// (code, folder) once.
func mergeAttention(lists ...[]ipc.Attention) []ipc.Attention {
	out := []ipc.Attention{}
	seen := map[string]bool{}
	for _, l := range lists {
		for _, at := range l {
			key := at.Code + "\x00" + at.Folder
			if at.PID != 0 {
				key += fmt.Sprintf("\x00%d", at.PID)
			}
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, at)
		}
	}
	return out
}

// cmpDotted compares dotted numeric versions ("2.1.329" > "2.1.30");
// non-numeric parts compare as strings.
func cmpDotted(a, b string) int {
	as, bs := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(as) || i < len(bs); i++ {
		var x, y string
		if i < len(as) {
			x = as[i]
		}
		if i < len(bs) {
			y = bs[i]
		}
		xn, xerr := strconv.Atoi(x)
		yn, yerr := strconv.Atoi(y)
		switch {
		case xerr == nil && yerr == nil && xn != yn:
			if xn < yn {
				return -1
			}
			return 1
		case (xerr != nil || yerr != nil) && x != y:
			return strings.Compare(x, y)
		}
	}
	return 0
}

func timePtr(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}

// countEntries counts the entries of a directory (0 if it cannot be read).
func countEntries(dir string) int {
	es, err := os.ReadDir(dir)
	if err != nil {
		return 0
	}
	return len(es)
}

// wrapperInstalled reports whether a shell rc file carries precinto's
// shell-init line (the harness functions route through precinto run).
func (a *app) wrapperInstalled() (installed bool) {
	home := a.home()
	if home == "" {
		return false
	}
	defer func() {
		// The shell package is another group's: a failure there must not
		// break status.
		if recover() != nil {
			installed = false
		}
	}()
	for _, sh := range []string{shellinit.Zsh, shellinit.Bash, shellinit.Fish} {
		line := a.sys.shell.InstallLine(sh)
		rc := a.sys.shell.RCFile(sh, home)
		if line == "" || rc == "" {
			continue
		}
		if b, err := os.ReadFile(rc); err == nil && strings.Contains(string(b), line) {
			return true
		}
	}
	return false
}

// printStatus renders the human status (SPEC §16.4).
func (a *app) printStatus(w io.Writer, s statusV1) {
	p := s.policy
	if !s.Vault.Initialized {
		fmt.Fprintf(w, "vault    not set up (run precinto init)\n")
	} else {
		rec := "never tested"
		if s.Vault.RecoveryVerifiedAt != nil {
			rec = "tested " + s.Vault.RecoveryVerifiedAt.In(a.sys.loc).Format("2006-01-02")
		}
		fmt.Fprintf(w, "vault    unlock with %s · recovery key: %s\n", strings.Join(orNone(s.Vault.Factors), ", "), rec)
	}
	if s.Agent.Running {
		watch := "off"
		if s.Agent.ScreenWatch {
			watch = "on"
		}
		fmt.Fprintf(w, "agent    running (pid %d) · screen-lock watch %s · background re-seal: %s\n", s.Agent.PID, watch, a.sweepAge(s.Agent))
	} else {
		fmt.Fprintf(w, "agent    not running (every folder is locked) · background re-seal: %s\n", a.sweepAge(s.Agent))
	}
	fmt.Fprintln(w, "\nFOLDERS")
	if len(s.Folders) == 0 {
		fmt.Fprintln(w, "  none (protect one with: precinto protect DIR)")
	}
	for _, fo := range s.Folders {
		state := "locked"
		if fo.State == "unlocked" {
			state = "unlocked"
			if fo.AbsDeadline != nil {
				state += " until " + fo.AbsDeadline.In(a.sys.loc).Format("15:04")
			}
			state += fmt.Sprintf(" (locks after %s idle)", strings.TrimPrefix(ui.ReasonText(ui.ReasonIdle, p.IdleSoft.D()), "idle "))
		} else if fo.Reason != "" {
			d := p.IdleSoft.D()
			if ui.Reason(fo.Reason) == ui.ReasonLimit {
				d = p.MaxUnlock.D()
			}
			state += " (" + ui.ReasonText(ui.Reason(fo.Reason), d) + ")"
		}
		fmt.Fprintf(w, "  %s  %s\n", a.display(fo.Path), state)
		ss := fo.Sessions
		fmt.Fprintf(w, "      sessions: %d running, %d working, %d paused, %d restored, %d sealed, %d without hooks\n",
			ss.Running, ss.Working, ss.Paused, ss.Restored, ss.Sealed, ss.Ungated)
		if fo.Background > 0 {
			fmt.Fprintf(w, "      background sessions: %d (never ended by precinto)\n", fo.Background)
		}
		u := fo.Unencrypted
		switch {
		case u.Incomplete && !s.plainScanned:
			fmt.Fprintf(w, "      unencrypted: unknown (%s)\n", s.plainNote)
		case u.Incomplete && u.Files > 0:
			fmt.Fprintf(w, "      unencrypted: %d files (%s)%s, found with %s (config.toml does not load)\n", u.Files, ui.HumanBytes(u.Bytes), reasonList(u.ByReason), s.standIn)
		case u.Incomplete:
			fmt.Fprintf(w, "      unencrypted: none found with %s (config.toml does not load)\n", s.standIn)
		case u.Files > 0:
			fmt.Fprintf(w, "      unencrypted: %d files (%s)%s\n", u.Files, ui.HumanBytes(u.Bytes), reasonList(u.ByReason))
		default:
			fmt.Fprintln(w, "      unencrypted: none")
		}
	}
	fmt.Fprintln(w, "\nAGENTS")
	for _, h := range s.Harnesses {
		state := "disabled"
		if h.Enabled {
			state = "enabled"
		}
		if h.Experimental {
			state += " (experimental, wrapper only)"
		}
		hooks := map[string]string{"ok": "hooks OK", "not-seen": "hooks not seen in its running sessions", "unknown": "hooks: no session seen"}[h.Hooks]
		wrap := "wrapper not installed (" + a.shellInitHint() + ")"
		if h.Wrapper {
			wrap = "wrapper installed"
		}
		if h.Version != "" {
			state += " · version " + oneLineText(h.Version)
		}
		fmt.Fprintf(w, "  %-12s %s · %s · %s\n", h.ID, state, hooks, wrap)
	}
	fmt.Fprintln(w, "\nNEEDS ATTENTION")
	if len(s.Attention) == 0 {
		fmt.Fprintln(w, "  nothing")
	}
	for _, at := range s.Attention {
		var parts []string
		if at.Folder != "" {
			parts = append(parts, at.Folder)
		}
		if at.Detail != "" {
			parts = append(parts, oneLineText(at.Detail))
		} else if at.Count > 0 {
			parts = append(parts, fmt.Sprintf("%d", at.Count))
		}
		line := "  " + at.Code
		if len(parts) > 0 {
			line += "  " + strings.Join(parts, " · ")
		}
		if at.Fix != "" {
			line += " · fix: " + at.Fix
		}
		fmt.Fprintln(w, line)
	}
}

// shellInitHint is the command that installs the shell integration
// (UX-12): shell-init needs the shell's name, taken from $SHELL when it is
// zsh, bash or fish.
func (a *app) shellInitHint() string {
	switch sh := filepath.Base(a.env.Get("SHELL")); sh {
	case shellinit.Zsh, shellinit.Bash, shellinit.Fish:
		return "precinto shell-init " + sh + " --install"
	}
	return "precinto shell-init zsh|bash|fish --install"
}

// sweepAge describes the background re-seal heartbeat.
func (a *app) sweepAge(ag statusAgent) string {
	var s string
	switch ag.Service {
	case "installed":
		s = "installed"
	case "unavailable":
		s = "not available on this system"
	default:
		s = "not installed"
	}
	if ag.LastSweep != nil {
		s += ", last sweep " + humanAge(a.now().Sub(*ag.LastSweep)) + " ago"
	}
	return s
}

// humanAge renders a positive duration coarsely ("3 min", "2 h", "4 days").
func humanAge(d time.Duration) string {
	switch {
	case d < time.Minute:
		return "under a minute"
	case d < time.Hour:
		return fmt.Sprintf("%d min", int(d/time.Minute))
	case d < 48*time.Hour:
		return fmt.Sprintf("%d h", int(d/time.Hour))
	default:
		return fmt.Sprintf("%d days", int(d/(24*time.Hour)))
	}
}

func reasonList(m map[string]int) string {
	if len(m) == 0 {
		return ""
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s %d", strings.ReplaceAll(k, "_", " "), m[k]))
	}
	return ": " + strings.Join(parts, ", ")
}

func orNone(s []string) []string {
	if len(s) == 0 {
		return []string{"(none)"}
	}
	return s
}

// harnessCommand is the command a harness id runs as, the {harness} of
// C9.ungated and of `precinto run {harness}` (claude-code runs as claude;
// the agent and doctor map it the same way).
func harnessCommand(id string) string { return strings.TrimSuffix(id, "-code") }
