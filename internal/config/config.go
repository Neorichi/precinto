package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/BurntSushi/toml"

	"github.com/precinto/precinto/internal/fsx"
	"github.com/precinto/precinto/internal/paths"
)

// SchemaVersion is the config.toml format version.
const SchemaVersion = 1

// Errors.
var (
	ErrInvalid = errors.New("config: invalid configuration")
	ErrOverlap = errors.New("config: root overlaps an existing root")
)

// Duration is a time.Duration encoded in TOML as a string accepted by
// time.ParseDuration; "0" means "never" where the key allows it.
type Duration time.Duration

// D returns the value as a time.Duration.
func (d Duration) D() time.Duration { return time.Duration(d) }

// UnmarshalText implements encoding.TextUnmarshaler: "0" or any value
// accepted by time.ParseDuration; negative values are rejected.
func (d *Duration) UnmarshalText(b []byte) error {
	s := string(b)
	if s == "0" {
		*d = 0
		return nil
	}
	v, err := time.ParseDuration(s)
	if err != nil || v < 0 {
		return fmt.Errorf("%w: duration %q", ErrInvalid, s)
	}
	*d = Duration(v)
	return nil
}

// MarshalText implements encoding.TextMarshaler with the shortest exact
// unit ("0", "90s", "15m", "8h"); other values use time.Duration.String.
func (d Duration) MarshalText() ([]byte, error) {
	v := time.Duration(d)
	switch {
	case v == 0:
		return []byte("0"), nil
	case v%time.Hour == 0:
		return []byte(strconv.FormatInt(int64(v/time.Hour), 10) + "h"), nil
	case v%time.Minute == 0:
		return []byte(strconv.FormatInt(int64(v/time.Minute), 10) + "m"), nil
	case v%time.Second == 0:
		return []byte(strconv.FormatInt(int64(v/time.Second), 10) + "s"), nil
	default:
		return []byte(v.String()), nil
	}
}

// MD policies for a root (SPEC §8).
const (
	MDLedger = "ledger" // default: Markdown the ledger or transcript shows an agent wrote
	MDAll    = "all"    // every *.md/*.mdx/*.markdown under the root (minus excludes)
	MDOff    = "off"
)

// OnEnter policies (D29).
const (
	OnEnterPrompt = "prompt"
	OnEnterNotify = "notify"
	OnEnterOff    = "off"
)

// MDSealOn values (SPEC §8.4).
const (
	MDSealOnLock = "lock" // seal notes at lock (and by sweeps while locked)
	MDSealOnEnd  = "end"  // seal notes only when the sessions that wrote them end
)

// Policy is the [policy] table. TOML keys are the snake_case tags.
type Policy struct {
	IdleSoft            Duration `toml:"idle_soft"`                // 15m: lock after this much human idle (D23)
	IdleHard            Duration `toml:"idle_hard"`                // 60m: end paused sessions; "0" never
	MaxUnlock           Duration `toml:"max_unlock"`               // 8h: absolute grant lifetime ⇒ lock (D24), capped at 24h
	LockOnScreenLock    bool     `toml:"lock_on_screen_lock"`      // true (D24)
	ScreenLockHardAfter Duration `toml:"screen_lock_hard_after"`   // 15m of continuous screen lock ⇒ end idle sessions (D24)
	BusyGrace           Duration `toml:"busy_grace"`               // 30m: busy turns may finish after a lock (D24)
	BusyTimeout         Duration `toml:"busy_timeout"`             // 10m without hook activity and registry not busy ⇒ not busy (D23)
	QuietWindow         Duration `toml:"quiet_window"`             // 120s stability window for unknown writers (SPEC §9.4)
	HoldCap             Duration `toml:"hold_cap"`                 // 24h: weak-evidence liveness holds are reported after this (S14)
	RestoreRecent       int      `toml:"restore_recent"`           // 5 (D38)
	RestoreMaxBytes     int64    `toml:"restore_max_bytes"`        // 1 GiB (D38)
	RestoreHistory      bool     `toml:"restore_history"`          // true: merge sealed history lines back at unlock
	PerRootAuth         bool     `toml:"per_root_auth"`            // true: each root needs its own presence prompt (D1, D40)
	UnlockOnPrompt      bool     `toml:"unlock_on_prompt"`         // false until the hook-dialog E2E passes (D60); human prompts only (D26, D27, D37)
	OnEnter             string   `toml:"on_enter"`                 // "prompt" (D29)
	MDSealOn            string   `toml:"md_seal_on"`               // "lock"
	ClearTerminalOnEnd  bool     `toml:"clear_terminal_on_end"`    // true: scrub the TTY when sessions are ended
	ClearScrollbackLock bool     `toml:"clear_scrollback_on_lock"` // true: wrapper clears scrollback at lock (D30)
	PromptRatePerMinute int      `toml:"prompt_rate_per_minute"`   // 3 (D27)
	PromptBackoff       Duration `toml:"prompt_backoff"`           // 30s after a cancel (D27)
	HookPromptCooldown  Duration `toml:"hook_prompt_cooldown"`     // 10m: no hook-raised dialog for a root after a cancel
}

// Root is one [[roots]] entry: a protected folder (never an in-repo marker).
type Root struct {
	ID             string    `toml:"id"`              // stable random id (vault id, D1)
	Path           string    `toml:"path"`            // absolute, clean, realpath'd at protect time
	MD             string    `toml:"md"`              // ledger|all|off
	MDExclude      []string  `toml:"md_exclude"`      // extra globs added to the default excludes
	IncludeTracked bool      `toml:"include_tracked"` // seal git-tracked Markdown too (default false)
	OnEnter        string    `toml:"on_enter"`        // overrides policy.on_enter when set
	Harnesses      []string  `toml:"harnesses"`       // default ["claude-code","codex"]
	ClaudeSettings bool      `toml:"claude_settings"` // protect --claude-settings was used (D32)
	ProtectedAt    time.Time `toml:"protected_at"`
}

// Home is a registered harness home (R22): sweeps visit every registered
// home, and restore requests naming an unregistered home are rejected.
type Home struct {
	Dir     string    `toml:"dir"`     // realpath of the config dir / home
	Tmp     string    `toml:"tmp"`     // claude: realpath of CLAUDE_CODE_TMPDIR or /private/tmp/claude-<uid>
	Cache   string    `toml:"cache"`   // claude: ~/Library/Caches/claude-cli-nodejs or $XDG_CACHE_HOME/...
	SeenAt  time.Time `toml:"seen_at"` // last time a hook or the wrapper reported it
	Default bool      `toml:"default"` // the harness default location
}

// Harness is a [harness.<id>] table.
type Harness struct {
	Enabled      bool   `toml:"enabled"`
	Experimental bool   `toml:"experimental"` // generic inventories (D33)
	Homes        []Home `toml:"homes"`
	Bin          string `toml:"bin"`         // absolute path of the harness executable used by the wrapper
	MinVersion   string `toml:"min_version"` // refuse integration below this version
}

// Config is the whole file.
type Config struct {
	Version int                `toml:"version"`
	Policy  Policy             `toml:"policy"`
	Roots   []Root             `toml:"roots"`
	Harness map[string]Harness `toml:"harness"`
}

// Default returns the normative defaults of SPEC §12.2.
func Default() Config {
	return Config{
		Version: SchemaVersion,
		Policy: Policy{
			IdleSoft:            Duration(15 * time.Minute),
			IdleHard:            Duration(60 * time.Minute),
			MaxUnlock:           Duration(8 * time.Hour),
			LockOnScreenLock:    true,
			ScreenLockHardAfter: Duration(15 * time.Minute),
			BusyGrace:           Duration(30 * time.Minute),
			BusyTimeout:         Duration(10 * time.Minute),
			QuietWindow:         Duration(120 * time.Second),
			HoldCap:             Duration(24 * time.Hour),
			RestoreRecent:       5,
			RestoreMaxBytes:     1 << 30,
			RestoreHistory:      true,
			PerRootAuth:         true,
			UnlockOnPrompt:      false, // D60: flips to true once the hook-dialog E2E passes on the pinned Claude version
			OnEnter:             OnEnterPrompt,
			MDSealOn:            MDSealOnLock,
			ClearTerminalOnEnd:  true,
			ClearScrollbackLock: true,
			PromptRatePerMinute: 3,
			PromptBackoff:       Duration(30 * time.Second),
			HookPromptCooldown:  Duration(10 * time.Minute),
		},
		Harness: map[string]Harness{
			"claude-code": {Enabled: true, MinVersion: "2.1.295"},
			"codex":       {Enabled: true, MinVersion: "0.154.0"},
		},
	}
}

// DefaultMDExclude are the globs never sealed by the Markdown policy
// (SPEC §8.2), in addition to git-tracked files.
var DefaultMDExclude = []string{
	"README.md", "CHANGELOG.md", "LICENSE.md", "CONTRIBUTING.md", "SECURITY.md",
	"CLAUDE.md", "AGENTS.md", "GEMINI.md", "**/SKILL.md",
	".git/**", ".claude/**", ".codex/**", ".cursor/**", ".agents/**", ".gemini/**", ".github/**",
	"node_modules/**", "vendor/**", ".venv/**",
}

// MaxUnlockCap is the hard cap on policy.max_unlock and on any unlock TTL.
const MaxUnlockCap = 24 * time.Hour

// Load parses path and validates it. A missing file yields Default().
// Keys absent from the file keep their defaults (a [harness.<id>] table
// without `enabled`/`min_version` keeps the built-in values); unknown keys
// are rejected (ErrInvalid), so a typo never silently weakens policy.
// Implemented in the scaffold.
func Load(path string) (Config, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return Default(), nil
	}
	if err != nil {
		return Config{}, err
	}
	c := Default()
	md, err := toml.NewDecoder(bytes.NewReader(b)).Decode(&c)
	if err != nil {
		return Config{}, fmt.Errorf("%w: %s", ErrInvalid, filepath.Base(path))
	}
	if und := md.Undecoded(); len(und) > 0 {
		return Config{}, fmt.Errorf("%w: unknown key %s", ErrInvalid, und[0])
	}
	def := Default()
	for id, h := range c.Harness {
		d, builtin := def.Harness[id]
		if !builtin {
			continue
		}
		if !md.IsDefined("harness", id, "enabled") {
			h.Enabled = d.Enabled
		}
		if !md.IsDefined("harness", id, "min_version") {
			h.MinVersion = d.MinVersion
		}
		c.Harness[id] = h
	}
	if err := c.Validate(); err != nil {
		return Config{}, err
	}
	return c, nil
}

// Save validates c and writes it atomically with mode 0600. Implemented in
// the scaffold.
func Save(path string, c Config) error {
	if err := c.Validate(); err != nil {
		return err
	}
	var b bytes.Buffer
	if err := toml.NewEncoder(&b).Encode(c); err != nil {
		return err
	}
	return fsx.WriteFileAtomic(path, b.Bytes(), 0o600)
}

// Validate rejects relative or unclean root paths, duplicate ids or paths,
// unknown enum values, negative or zero durations where a positive one is
// required, and durations above their caps. Implemented in the scaffold.
func (c Config) Validate() error {
	bad := func(format string, args ...any) error {
		return fmt.Errorf("%w: "+format, append([]any{ErrInvalid}, args...)...)
	}
	if c.Version != SchemaVersion {
		return bad("version %d (want %d)", c.Version, SchemaVersion)
	}
	p := c.Policy
	positive := map[string]Duration{
		"idle_soft": p.IdleSoft, "max_unlock": p.MaxUnlock, "busy_timeout": p.BusyTimeout,
		"quiet_window": p.QuietWindow, "hold_cap": p.HoldCap,
	}
	for k, d := range positive {
		if d <= 0 {
			return bad("policy.%s must be positive", k)
		}
	}
	nonNegative := map[string]Duration{
		"idle_hard": p.IdleHard, "screen_lock_hard_after": p.ScreenLockHardAfter, "busy_grace": p.BusyGrace,
		"prompt_backoff": p.PromptBackoff, "hook_prompt_cooldown": p.HookPromptCooldown,
	}
	for k, d := range nonNegative {
		if d < 0 {
			return bad("policy.%s is negative", k)
		}
	}
	if p.MaxUnlock.D() > MaxUnlockCap {
		return bad("policy.max_unlock above %s", MaxUnlockCap)
	}
	if p.RestoreRecent < 0 || p.RestoreMaxBytes < 0 || p.PromptRatePerMinute < 0 {
		return bad("policy counters must not be negative")
	}
	if !oneOf(p.OnEnter, OnEnterPrompt, OnEnterNotify, OnEnterOff) {
		return bad("policy.on_enter %q", p.OnEnter)
	}
	if !oneOf(p.MDSealOn, MDSealOnLock, MDSealOnEnd) {
		return bad("policy.md_seal_on %q", p.MDSealOn)
	}
	ids, roots := map[string]bool{}, map[string]bool{}
	for _, r := range c.Roots {
		if r.ID == "" || ids[r.ID] {
			return bad("root id %q missing or duplicate", r.ID)
		}
		ids[r.ID] = true
		if cp, ok := paths.Clean(r.Path); !ok || cp == "/" {
			return bad("root %s path is not an absolute clean path", r.ID)
		}
		if strings.ContainsFunc(r.Path, func(c rune) bool { return c < 0x20 || c == 0x7f }) {
			return bad("root %s path contains a control character", r.ID) // roots.list is line-based
		}
		if roots[r.Path] {
			return bad("root path listed twice")
		}
		roots[r.Path] = true
		if r.MD != "" && !oneOf(r.MD, MDLedger, MDAll, MDOff) {
			return bad("root %s md %q", r.ID, r.MD)
		}
		if r.OnEnter != "" && !oneOf(r.OnEnter, OnEnterPrompt, OnEnterNotify, OnEnterOff) {
			return bad("root %s on_enter %q", r.ID, r.OnEnter)
		}
	}
	for id, h := range c.Harness {
		for _, home := range h.Homes {
			if _, ok := paths.Clean(home.Dir); !ok {
				return bad("harness.%s home is not an absolute clean path", id)
			}
		}
	}
	return nil
}

func oneOf(v string, allowed ...string) bool {
	for _, a := range allowed {
		if v == a {
			return true
		}
	}
	return false
}

// RootFor returns the deepest root containing p (component-wise, see
// paths.Within).
func (c Config) RootFor(p string) (Root, bool) {
	rs := c.RootsFor(p)
	if len(rs) == 0 {
		return Root{}, false
	}
	return rs[0], true
}

// RootsFor returns the distinct roots containing any of ps, deepest first
// (ties by id, so the order is deterministic).
func (c Config) RootsFor(ps ...string) []Root {
	var out []Root
	for _, r := range c.Roots {
		for _, p := range ps {
			if p != "" && paths.Within(r.Path, p) {
				out = append(out, r)
				break
			}
		}
	}
	sortDeepestFirst(out)
	return out
}

func sortDeepestFirst(rs []Root) {
	depth := func(p string) int {
		n := 0
		for _, ch := range filepath.Clean(p) {
			if ch == '/' {
				n++
			}
		}
		return n
	}
	sort.SliceStable(rs, func(i, j int) bool {
		di, dj := depth(rs[i].Path), depth(rs[j].Path)
		if di != dj {
			return di > dj
		}
		return rs[i].ID < rs[j].ID
	})
}

// RootByID returns the root with id.
func (c Config) RootByID(id string) (Root, bool) {
	for _, r := range c.Roots {
		if r.ID == id {
			return r, true
		}
	}
	return Root{}, false
}

// Overlapping returns existing roots that contain or are contained by dir.
func (c Config) Overlapping(dir string) []Root {
	var out []Root
	for _, r := range c.Roots {
		if paths.Within(r.Path, dir) || paths.Within(dir, r.Path) {
			out = append(out, r)
		}
	}
	sortDeepestFirst(out)
	return out
}

// EffectiveOnEnter returns the root override or the policy value.
func (c Config) EffectiveOnEnter(r Root) string {
	if r.OnEnter != "" {
		return r.OnEnter
	}
	return c.Policy.OnEnter
}

// Change is one difference between two configurations.
type Change struct {
	Key       string // dotted key, e.g. "policy.idle_soft", "roots[<id>]"
	Old, New  string
	Weakening bool // removes or narrows protection (D48)
}

// Diff lists changes from old to new. A change is weakening if it removes a
// root or harness, raises a timer, disables a trigger, narrows md, or turns
// on a less strict option (D48).
func Diff(old, new Config) []Change { return diff(old, new) }

// Strictest merges a and b taking, per key, the more protective value; used
// by hooks with the daemon's pinned policy (D48).
func Strictest(a, b Config) Config { return strictest(a, b) }

// WriteRootsList writes the absolute root paths of c, one per line, to path
// atomically with mode 0600 (D22; read by the POSIX shim). Implemented in
// the scaffold.
func WriteRootsList(path string, c Config) error {
	if err := c.Validate(); err != nil {
		return err
	}
	var b strings.Builder
	for _, r := range c.Roots {
		b.WriteString(r.Path)
		b.WriteByte('\n')
	}
	return fsx.WriteFileAtomic(path, []byte(b.String()), 0o600)
}

// ReadRootsList reads a roots.list file (missing file: no roots); lines
// that are not absolute clean paths are ignored. Implemented in the
// scaffold.
func ReadRootsList(path string) ([]string, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []string
	for _, line := range strings.Split(string(b), "\n") {
		if p, ok := paths.Clean(line); ok {
			out = append(out, p)
		}
	}
	return out, nil
}

// NewRootID returns a fresh random root id (32 hex characters).
func NewRootID() string { return newRootID() }

// PinnedVersion is the state/policy.pinned format version.
const PinnedVersion = 1

// Pinned is state/policy.pinned (D48, D55): the configuration the user
// confirmed at the last TTY unlock, and one MAC per vault unlocked at that
// moment, MACs[vault id] = hex HMAC-SHA256(HKDF-SHA256(vault identity,
// vault.InfoPolicy), Canonical(Config)) (computed by the daemon with
// vault.Keyring.MAC). At start the daemon enforces Strictest(config.toml,
// Pinned.Config); when a vault listed in MACs is unlocked it verifies that
// MAC, and a missing or bad MAC is an attention item (policy-tampered) after
// which the daemon also takes Default() into the strictest merge until the
// next TTY confirmation rewrites the file.
type Pinned struct {
	Version     int               `json:"v"`
	ConfirmedAt time.Time         `json:"confirmed_at"`
	Config      Config            `json:"config"`
	MACs        map[string]string `json:"macs"`
}

// Canonical returns the deterministic encoding of c that policy MACs cover:
// JSON with roots sorted by id and homes by directory (map keys are sorted
// by encoding/json). Implemented in the scaffold.
func Canonical(c Config) []byte {
	cc := c
	cc.Roots = append([]Root(nil), c.Roots...)
	sort.Slice(cc.Roots, func(i, j int) bool { return cc.Roots[i].ID < cc.Roots[j].ID })
	if c.Harness != nil {
		cc.Harness = make(map[string]Harness, len(c.Harness))
		for id, h := range c.Harness {
			h.Homes = append([]Home(nil), h.Homes...)
			sort.Slice(h.Homes, func(i, j int) bool { return h.Homes[i].Dir < h.Homes[j].Dir })
			cc.Harness[id] = h
		}
	}
	b, err := json.Marshal(cc)
	if err != nil {
		panic("config: Canonical: " + err.Error()) // unreachable: Config has no unencodable fields
	}
	return b
}

// LoadPinned reads state/policy.pinned (ok=false if it does not exist). It
// does not verify MACs (the daemon does, with the vault keys); a file that
// does not decode is an error (the daemon reports policy-tampered).
// Implemented in the scaffold.
func LoadPinned(path string) (p Pinned, ok bool, err error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return Pinned{}, false, nil
	}
	if err != nil {
		return Pinned{}, false, err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil || p.Version != PinnedVersion {
		return Pinned{}, false, fmt.Errorf("%w: %s", ErrInvalid, filepath.Base(path))
	}
	return p, true, nil
}

// SavePinned writes p atomically with mode 0600. Implemented in the
// scaffold.
func SavePinned(path string, p Pinned) error {
	if p.Version == 0 {
		p.Version = PinnedVersion
	}
	b, err := json.Marshal(p)
	if err != nil {
		return err
	}
	return fsx.WriteFileAtomic(path, b, 0o600)
}
