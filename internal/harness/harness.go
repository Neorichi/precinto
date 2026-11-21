package harness

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"strings"
	"time"

	"github.com/precinto/precinto/internal/capsule"
	"github.com/precinto/precinto/internal/config"
	"github.com/precinto/precinto/internal/fsx"
	"github.com/precinto/precinto/internal/ledger"
	"github.com/precinto/precinto/internal/live"
	"github.com/precinto/precinto/internal/paths"
	"github.com/precinto/precinto/internal/platform"
)

// ID is a harness identifier.
type ID string

// Built-in harnesses (v0.1 scope, D41/D49).
const (
	ClaudeCode ID = "claude-code"
	Codex      ID = "codex"
)

// Errors.
var (
	ErrUnknownHarness = errors.New("harness: unknown harness")
	ErrNotManaged     = errors.New("harness: path is not inside a protected root")
	ErrUnregistered   = errors.New("harness: home is not registered")
	ErrWrongHome      = errors.New("harness: session does not use the folder's sealed home") // codex D31
	ErrUnitKey        = errors.New("harness: unit key parts missing or malformed")
)

// UnitKeyFor derives the unit key of a unit from the parts table of SPEC
// §6.2 (D45), so every group computes keys identically (implemented in the
// scaffold). unitID is the kind's own id: sid (claude-session), project
// directory name as found on disk (claude-project), slug (claude-plan),
// store name (global-store), random blob id (codex-blob), root-relative
// slash-separated path (md), partition id (generic). For claude-history
// and codex-home the root is the unit: unitID must be empty or equal
// rootID. homeID is Home.ID; rootID a config root id. Non-final parts must
// not contain 0x1f.
func UnitKeyFor(salt []byte, k capsule.Kind, h ID, homeID, rootID, unitID string) (string, error) {
	need := func(vals ...string) error {
		for _, v := range vals {
			if v == "" {
				return fmt.Errorf("%w: %s", ErrUnitKey, k)
			}
		}
		return nil
	}
	var parts []string
	switch k {
	case capsule.KindClaudeSession, capsule.KindClaudeProject, capsule.KindClaudePlan:
		if h != ClaudeCode {
			return "", fmt.Errorf("%w: %s belongs to %s", ErrUnitKey, k, ClaudeCode)
		}
		if err := need(homeID, unitID); err != nil {
			return "", err
		}
		sub := map[capsule.Kind]string{
			capsule.KindClaudeSession: "session",
			capsule.KindClaudeProject: "project",
			capsule.KindClaudePlan:    "plan",
		}[k]
		parts = []string{string(ClaudeCode), sub, homeID, unitID}
	case capsule.KindClaudeHistory:
		if h != ClaudeCode || (unitID != "" && unitID != rootID) {
			return "", fmt.Errorf("%w: %s", ErrUnitKey, k)
		}
		if err := need(homeID, rootID); err != nil {
			return "", err
		}
		parts = []string{string(ClaudeCode), "history", homeID, rootID}
	case capsule.KindGlobalStore:
		if err := need(string(h), homeID, unitID); err != nil {
			return "", err
		}
		parts = []string{string(h), "global", homeID, unitID}
	case capsule.KindCodexHome:
		if h != Codex || (unitID != "" && unitID != rootID) {
			return "", fmt.Errorf("%w: %s", ErrUnitKey, k)
		}
		if err := need(rootID); err != nil {
			return "", err
		}
		parts = []string{string(Codex), "home", rootID}
	case capsule.KindCodexBlob:
		if h != Codex {
			return "", fmt.Errorf("%w: %s", ErrUnitKey, k)
		}
		if err := need(rootID, unitID); err != nil {
			return "", err
		}
		parts = []string{string(Codex), "blob", rootID, unitID}
	case capsule.KindMarkdown:
		if err := need(rootID, unitID); err != nil {
			return "", err
		}
		parts = []string{"md", rootID, unitID}
	case capsule.KindGeneric:
		if err := need(string(h), homeID, unitID); err != nil {
			return "", err
		}
		parts = []string{string(h), "generic", homeID, unitID}
	default:
		return "", fmt.Errorf("%w: unknown kind %q", ErrUnitKey, k)
	}
	for _, p := range parts[:len(parts)-1] {
		if strings.ContainsRune(p, 0x1f) {
			return "", fmt.Errorf("%w: separator in a part", ErrUnitKey)
		}
	}
	return capsule.UnitKey(salt, parts...), nil
}

// Home is one resolved harness home. Bases maps every BaseID the harness
// uses to an absolute, realpath'd directory (SPEC §7.0, R22).
type Home struct {
	Harness ID
	ID      string // stable short id of the home (hash of its realpath): part of unit keys
	Bases   map[capsule.BaseID]string
	Default bool
	RootID  string // codex per-root homes: the owning root (D31); "" otherwise
}

// Placement is the restore/merge policy of one file (SPEC §11.3, D11).
type Placement string

// Placements.
const (
	PlaceExact       Placement = "exact"        // equal hash ⇒ no-op; otherwise conflict copy, never overwrite
	PlaceJSONLAppend Placement = "jsonl-append" // Claude transcripts/subagents: prefix/link/uuid rules
	PlaceLineUnion   Placement = "line-union"   // history.jsonl, session_index.jsonl: add missing lines
	PlaceSQLiteGroup Placement = "sqlite-group" // db + -wal + -journal as one unit; -shm never restored
	PlaceMarkdown    Placement = "md"           // note: exact, plus marker handling (D16)
)

// File is one planned file of a unit (snapshot taken at scan time).
type File struct {
	Base      capsule.BaseID
	Rel       string
	Snap      fsx.Stat
	Placement Placement
	Append    bool   // append-only (lineage by prefix hash, D10)
	Group     string // SQLite group id
	Last      bool   // place after every other file (Claude <sid>.jsonl, R6)
}

// Hazard is an entry found while scanning that is never sealed or deleted
// (symlink, FIFO, socket, device, hard link, unreadable): it is reported.
type Hazard struct {
	Base   capsule.BaseID
	Rel    string
	Hazard fsx.Hazard
}

// GenMode is how generations of a kind are restored (D42).
type GenMode string

// Generation modes.
const (
	GenLayered  GenMode = "layered"  // restore the union through non-successor links
	GenSnapshot GenMode = "snapshot" // restore exactly the newest snapshot (codex home)
)

// Unit is one sealable group of plaintext files.
type Unit struct {
	Harness ID
	Kind    capsule.Kind
	Key     string // unit key (capsule.UnitKey)
	UnitID  string // sid, slug, relpath… (private; never logged)
	VaultID string // sealing vault (D1, D36)
	RootIDs []string
	Home    Home
	Files   []File
	Dirs    []File // empty directories to record
	Hazards []Hazard
	// Prune lists "<base id>:<rel>" entries (e.g. "claude_tmp:<P>/<sid>"),
	// deepest first, of directories to remove when empty after sealing;
	// never a base root and never projects/<P>. One format, no bare rel.
	Prune        []string
	Mode         GenMode
	Procs        []platform.ProcID // ledger owners (current), for live.Subject
	Paths        []string          // absolute files/dirs for stability and fd checks
	LeaseKeys    []string
	Title        string // custom-title > ai-title > first prompt; stored only inside ciphertext
	LastActivity time.Time
	Adopted      bool   // found by transcript cwd or the project index, not by the ledger, and never restored by precinto (S6; a ledger-less unit with a receipt is precinto's own and re-sealed)
	Note         string // content-free scan note
	// ProjectDir is, for claude-session units, the session's start cwd,
	// realpath'd (the ledger start event, else the transcript's first cwd);
	// for claude-project units the cwd the project index maps to <P> when
	// unique, else "". Copied into capsule.Manifest.ProjectDir (D73).
	ProjectDir string
}

// UnitRef names a unit without its files (restore requests, leases).
type UnitRef struct {
	Harness ID
	Kind    capsule.Kind
	Key     string
	VaultID string
	RootIDs []string
	HomeID  string
}

// Ref returns the reference of u.
func (u Unit) Ref() UnitRef { return unitRef(u) }

// Scope limits a scan.
type Scope struct {
	RootIDs []string // empty = every root
	SIDs    []string // specific sessions
	// Kinds: empty = every kind except KindGeneric, which is scanned only
	// when listed (seal --dormant, D33).
	Kinds  []capsule.Kind
	Global bool // include global stores
	// Adopt also adopts sessions found only by transcript cwd (seal
	// --adopt, md="all" sweeps; S6).
	Adopt bool
	// Procs keeps only sessions whose ledger current owner is one of these
	// processes (the wrapper's seal after exit of a fresh session); units
	// that are not sessions are left out. Adapters without session units
	// (codex homes, generic partitions) ignore it.
	Procs []platform.ProcID
}

// Env is everything an adapter may read. Homes come from config and the
// ledger, never from the caller's environment alone (R22).
type Env struct {
	Cfg    config.Config
	Layout paths.Layout
	Ledger *ledger.Ledger
	Index  func(harness string) *ledger.Index
	Live   *live.Engine
	Procs  platform.ProcTable
	Clock  platform.Clock
	Salt   []byte
	Host   paths.Env // the invoking process environment (wrapper: the child's)
}

// TargetRules says where a capsule of a kind may restore, computed from
// trusted context (registered homes, config roots) and the manifest's unit
// id once it is authenticated against the logged unit key (D8, S3).
type TargetRules struct {
	Bases map[capsule.BaseID]string
	// Allow reports whether (base, rel) is a permitted target for this kind
	// and unit; it must reject anything outside the per-kind table of SPEC
	// §11.2, compare case-insensitively on darwin, and require Clean(rel).
	Allow func(base capsule.BaseID, rel string) bool
	// Policy returns the placement of an entry.
	Policy func(e capsule.Entry) Placement
	Mode   GenMode
	// Last reports entries placed after every other entry (Claude
	// <sid>.jsonl, REST-3); nil = no ordering constraint.
	Last func(e capsule.Entry) bool
	// Skip names bases that exist but are unsafe now (Claude $TMP not
	// 0700/owned, S7), with the reason: their entries are skipped and
	// reported, never written, and the rest of the unit restores. An entry
	// whose base is in neither Bases nor Skip still rejects the capsule
	// (exit 5).
	Skip map[capsule.BaseID]string
}

// LaunchMode is how the wrapper runs the child (UX14).
type LaunchMode string

// Launch modes.
const (
	LaunchInteractive LaunchMode = "interactive" // PTY proxy with overlay
	LaunchDirect      LaunchMode = "direct"      // gated and sealed, no PTY (-p, exec, pipes)
	LaunchPassthrough LaunchMode = "passthrough" // no gate, no restore (update, login, --version…)
)

// ResumeKind classifies resume arguments (HA23, IM13).
type ResumeKind string

// Resume kinds.
const (
	ResumeNone     ResumeKind = ""
	ResumeSID      ResumeKind = "sid"      // --resume <uuid>
	ResumePath     ResumeKind = "path"     // --resume /abs/<uuid>.jsonl
	ResumeName     ResumeKind = "name"     // --resume <title or search term>
	ResumePicker   ResumeKind = "picker"   // --resume / -r without a value
	ResumeContinue ResumeKind = "continue" // -c / --continue / codex resume --last
	ResumeJob      ResumeKind = "job"      // claude attach|respawn <job-id>
)

// Resume is the parsed resume target.
type Resume struct {
	Kind  ResumeKind
	Value string
	Fork  bool
}

// Selector picks sealed units to restore. internal/sweep resolves it
// against the capsule log and, for ProjectDir/Title, the manifests (which
// needs file keys); adapters only compute what they know (D38, D14).
type Selector struct {
	Kind       capsule.Kind
	RootID     string
	Keys       []string      // exact unit keys (e.g. resume by sid, computed with capsule.UnitKey)
	ProjectDir string        // the realpath'd launch cwd; matches Manifest.ProjectDir exactly (-c / --continue, D73)
	Title      string        // only units whose manifest title contains it (--resume <name>)
	Recent     int           // newest N by last activity; 0 = every match
	Newest     bool          // only the single newest match
	MaxAge     time.Duration // skip units whose last activity is older (D14: cleanupPeriodDays − 2 days); 0 = no limit
	MtimeNow   bool          // explicit resume of an old session: clamp mtimes to now − 1 day (D14)
	MaxBytes   int64         // budget for this selector; 0 = policy.restore_max_bytes
}

// LaunchPlan is what the wrapper executes for one harness invocation.
type LaunchPlan struct {
	Harness    ID
	Mode       LaunchMode
	Roots      []config.Root
	Resume     Resume
	Sync       []Selector // restore before exec, synchronously, in order
	Background []Selector // restore after exec, newest first, within budget (D38)
	Lease      []string   // lease keys known up front (e.g. the codex home key); restored units are added as they are placed
	Argv       []string   // final argv (argv[0] absolute), e.g. with --settings injected (D32)
	Env        []string   // environment additions (CODEX_HOME, CODEX_SQLITE_HOME, TMPDIR, CLAUDE_CODE_ENABLE_AWAY_SUMMARY=0…)
	// Notices are ui.MsgID values (harness packages cannot import
	// internal/ui), printed before exec; the wrapper renders them with
	// ui.Format and MsgVars.
	Notices []string
	// Confirm is a ui.MsgID asked on the TTY before launching (e.g.
	// C7.twice, C7.purge, C9.bare, C10.consent), "" if none: yes runs Argv
	// as planned (e.g. with --fork-session for C7.twice), no aborts the
	// launch with ui.ErrCancelled (exit 3).
	Confirm string
	// MsgVars are the {placeholder} values for Notices and Confirm, keyed
	// without braces ("sid", "pid", "folder").
	MsgVars map[string]string
	// QuitKeys are sent through the PTY before SIGTERM when precinto ends
	// the session (codex: Ctrl-C twice); nil = none.
	QuitKeys []byte
	// KillGrace is the SIGTERM→SIGKILL grace for this harness (KillGrace).
	KillGrace time.Duration
	// Prepare runs after unlock and before restore (codex per-root home
	// creation and seeding, D31).
	Prepare func(ctx context.Context) error
	// Finish runs after the child exited and before sealing (codex auth.json
	// sync back, D31).
	Finish func(ctx context.Context, exitCode int) error
	// SealScope selects the units to seal after exit (resolved again by
	// scanning). Adapters always set SIDs when the resume target is known;
	// the backend adds Procs=[child].
	SealScope Scope
	// HookCheck says how to verify hook health (UX10): event expected and
	// within how long after start.
	HookCheck HookCheck
}

// HookCheck configures the hook-presence check.
type HookCheck struct {
	Event   string
	Within  time.Duration
	OnInput bool // Codex: measured from the first Enter (SessionStart runs at the first turn)
}

// Adapter is implemented by each harness package.
type Adapter interface {
	// ID returns the harness id.
	ID() ID
	// Homes returns every registered home of this harness (config + ledger
	// + defaults); codex returns one home per protected root (D31).
	Homes(ctx context.Context, e Env) ([]Home, error)
	// Scan lists plaintext units in scope, fail-closed (unknown files that
	// carry a session id belong to that session unit, I10).
	Scan(ctx context.Context, e Env, s Scope) ([]Unit, error)
	// Probe returns harness-specific liveness evidence for u (registry, job
	// records, writer locks, open-file holders, harness processes). Errors
	// mean "treat as live".
	Probe(ctx context.Context, e Env, u Unit) ([]live.Evidence, error)
	// Targets returns restore rules for a logged capsule of kind/unit.
	// unitID is manifest.UnitID, which the caller (internal/sweep) has
	// already authenticated: UnitKeyFor(salt, ref.Kind, ref.Harness, the
	// registered home id or config root id, unitID) equals ref.Key, the
	// unit key of the capsule-log entry; otherwise the capsule is rejected
	// (exit 5) before Targets is called and before any write (SPEC §11.2).
	Targets(ctx context.Context, e Env, ref UnitRef, unitID string) (TargetRules, error)
	// PlanLaunch parses argv (argv[0] is the harness name) for cwd.
	PlanLaunch(ctx context.Context, e Env, cwd string, argv []string) (LaunchPlan, error)
	// MarkdownPaths returns absolute Markdown paths an agent wrote, derived
	// from the unit's own files (transcript tool inputs, apply_patch headers)
	// to complement the hook ledger (S6). Only paths are retained.
	MarkdownPaths(ctx context.Context, e Env, u Unit) ([]string, error)
	// Describe returns content-free metadata for a unit (title is returned
	// only to be written inside the capsule).
	Describe(ctx context.Context, e Env, u Unit) (title string, last time.Time, err error)
}

// KillGrace is the SIGTERM→SIGKILL grace for a harness whose SessionEnd
// hooks take up to sessionEnd: max(8 s, sessionEnd+6 s), capped at 70 s
// (SPEC §12.7).
func KillGrace(sessionEnd time.Duration) time.Duration {
	g := sessionEnd + 6*time.Second
	if g < 8*time.Second {
		g = 8 * time.Second
	}
	if g > 70*time.Second {
		g = 70 * time.Second
	}
	return g
}

// Register adds an adapter (called from cmd/precinto wiring).
func Register(a Adapter) { register(a) }

// Get returns the adapter for id.
func Get(id ID) (Adapter, bool) { return lookup(id) }

// All lists registered adapters in registration order.
func All() []Adapter { return registered() }

// Inventory is a data-driven harness description, inventories/<id>.toml
// (schema 1, D33, HA20). Built-in adapters also read theirs for process
// matching and passthrough lists.
type Inventory struct {
	Schema           int          `toml:"schema"`
	ID               string       `toml:"id"`
	Name             string       `toml:"name"`
	Status           string       `toml:"status"`            // "verified" | "experimental"
	VerifiedVersions string       `toml:"verified_versions"` // semver range verified; informational for experimental inventories (doctor warns outside it)
	Mode             string       `toml:"mode"`              // "capsule" (claude) | "home" (codex, generic)
	Bases            []BaseSpec   `toml:"bases"`
	Content          []string     `toml:"content"`       // globs relative to a base ("<base>:<glob>")
	NeverTouch       []string     `toml:"never_touch"`   // deny-list (codex, HA24)
	Exclude          []string     `toml:"exclude"`       // e.g. Antigravity paths under ~/.gemini
	Process          ProcessMatch `toml:"process"`       // how to recognise harness processes
	Locks            []LockSpec   `toml:"locks"`         // writer locks
	OpenFDCheck      bool         `toml:"open_fd_check"` // require no open fds before sealing
	Partition        string       `toml:"partition"`     // "home" | "project-slug" | "project-dir"
	SlugGlob         string       `toml:"slug_glob"`
	StopCmd          []string     `toml:"stop_cmd"`
	Passthrough      [][]string   `toml:"passthrough"` // argv prefixes that skip gate and restore (UX14)
	Direct           [][]string   `toml:"direct"`      // argv prefixes that run gated without a PTY
	Resume           ResumeSpec   `toml:"resume"`
	Notes            []string     `toml:"notes"`
}

// BaseSpec is one base directory of an inventory.
type BaseSpec struct {
	Name    string `toml:"name"`
	Default string `toml:"default"` // "~/.gemini", "$XDG_DATA_HOME/opencode"
	Env     string `toml:"env"`     // relocation variable
}

// ProcessMatch identifies harness processes (never by Claude's p_comm).
type ProcessMatch struct {
	ExeBasenames []string `toml:"exe_basenames"`
	ExePaths     []string `toml:"exe_paths"`  // globs
	ArgvRegex    []string `toml:"argv_regex"` // node/python CLIs
}

// LockSpec is one writer-lock convention.
type LockSpec struct {
	Glob string `toml:"glob"`
	Kind string `toml:"kind"` // "flock" | "json-pid"
}

// ResumeSpec describes resume flags (wrapper parsing).
type ResumeSpec struct {
	Flags      []string `toml:"flags"`      // "--resume", "-r"
	Continue   []string `toml:"continue"`   // "--continue", "-c"
	Fork       []string `toml:"fork"`       // "--fork-session"
	Subcommand []string `toml:"subcommand"` // codex: "resume", "fork"
}

// LoadInventory parses inventories/<name>.toml from fsys and validates it.
func LoadInventory(fsys fs.FS, name string) (Inventory, error) {
	return loadInventory(fsys, name)
}

// LoadInventories parses every *.toml in fsys.
func LoadInventories(fsys fs.FS) ([]Inventory, error) {
	return loadInventories(fsys)
}

// MatchProcess reports whether p is a process of inv.
func (inv Inventory) MatchProcess(p platform.ProcInfo) bool {
	return matchProcess(inv, p)
}

// Classify returns the launch mode of argv (argv[0] excluded) per the
// passthrough/direct lists, and whether stdin/stdout are terminals.
func (inv Inventory) Classify(args []string, stdinTTY, stdoutTTY bool) LaunchMode {
	return classify(inv, args, stdinTTY, stdoutTTY)
}
