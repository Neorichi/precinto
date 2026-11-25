package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
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
		return fmt.Errorf("%w: duration %q (use e.g. \"90s\", \"15m\" or \"8h\")", ErrInvalid, s)
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

// Size is a byte count encoded in TOML as a string: an integer with a
// binary unit ("512MiB", "2GiB", "1TiB"; "KiB" and "B" too, the unit's
// case ignored, one optional space) or a bare number of bytes; "0" means
// the key's default. Decimal units ("2GB") are rejected, so a size never
// silently means something else; negative, fractional and overflowing
// values are rejected too.
type Size int64

// Bytes returns the value in bytes.
func (s Size) Bytes() int64 { return int64(s) }

// sizeUnits are the accepted units, largest first (MarshalText picks the
// largest that divides the value).
var sizeUnits = []struct {
	name  string
	bytes int64
}{{"TiB", 1 << 40}, {"GiB", 1 << 30}, {"MiB", 1 << 20}, {"KiB", 1 << 10}, {"B", 1}}

// UnmarshalText implements encoding.TextUnmarshaler.
func (s *Size) UnmarshalText(b []byte) error {
	text := string(b)
	bad := func() error { return fmt.Errorf("%w: size %q (use e.g. \"512MiB\" or \"2GiB\")", ErrInvalid, text) }
	i := 0
	for i < len(text) && text[i] >= '0' && text[i] <= '9' {
		i++
	}
	if i == 0 || i > 19 {
		return bad()
	}
	n, err := strconv.ParseInt(text[:i], 10, 64)
	if err != nil {
		return bad()
	}
	unit := strings.TrimPrefix(text[i:], " ")
	mult := int64(1)
	if unit != "" {
		found := false
		for _, u := range sizeUnits {
			if strings.EqualFold(unit, u.name) {
				mult, found = u.bytes, true
				break
			}
		}
		if !found {
			return bad()
		}
	}
	if n > math.MaxInt64/mult {
		return bad()
	}
	*s = Size(n * mult)
	return nil
}

// MarshalText implements encoding.TextMarshaler with the largest binary
// unit that represents the value exactly ("0", "512MiB", "2GiB", "100B").
func (s Size) MarshalText() ([]byte, error) {
	v := int64(s)
	if v == 0 {
		return []byte("0"), nil
	}
	if v < 0 {
		return []byte(strconv.FormatInt(v, 10) + "B"), nil // invalid; Validate refuses it
	}
	for _, u := range sizeUnits {
		if v%u.bytes == 0 {
			return []byte(strconv.FormatInt(v/u.bytes, 10) + u.name), nil
		}
	}
	return []byte(strconv.FormatInt(v, 10) + "B"), nil // unreachable: "B" divides everything
}

// Free-space floor (policy.min_free, D76): the bytes every seal, restore
// and staging write leaves free on its volume. 0 means the default; any
// other value below the minimum is refused by Validate.
const (
	DefaultMinFree Size = 2 << 30
	MinMinFree     Size = 512 << 20
)

// MinFreeBytes returns the effective policy.min_free in bytes: the value,
// or DefaultMinFree when it is 0 (unset, e.g. a policy.pinned written
// before the key existed).
func (p Policy) MinFreeBytes() int64 {
	if p.MinFree == 0 {
		return int64(DefaultMinFree)
	}
	return int64(p.MinFree)
}

// Floor returns the free-space floor of the policy for sweep.Env (D76): a
// fixed MinFreeBytes, never a fraction of the volume.
func (p Policy) Floor() fsx.Floor { return fsx.Floor{MinBytes: p.MinFreeBytes()} }

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
	IdleSoft            Duration `toml:"idle_soft"`                  // 15m: lock after this much human idle (D23)
	IdleHard            Duration `toml:"idle_hard"`                  // 60m: end paused sessions; "0" never
	MaxUnlock           Duration `toml:"max_unlock"`                 // 8h: absolute grant lifetime ⇒ lock (D24), capped at 24h
	LockOnScreenLock    bool     `toml:"lock_on_screen_lock"`        // true (D24)
	ScreenLockHardAfter Duration `toml:"screen_lock_hard_after"`     // 15m of continuous screen lock ⇒ end idle sessions (D24)
	BusyGrace           Duration `toml:"busy_grace"`                 // 30m: busy turns may finish after a lock (D24)
	BusyTimeout         Duration `toml:"busy_timeout"`               // 10m without hook activity and registry not busy ⇒ not busy (D23)
	QuietWindow         Duration `toml:"quiet_window"`               // 120s stability window for unknown writers (SPEC §9.4)
	HoldCap             Duration `toml:"hold_cap"`                   // 24h: weak-evidence liveness holds are reported after this (S14)
	RestoreRecent       int      `toml:"restore_recent"`             // 5 (D38)
	RestoreMaxBytes     int64    `toml:"restore_max_bytes"`          // 1 GiB (D38)
	MinFree             Size     `toml:"min_free" json:",omitempty"` // 2GiB free-space floor of seals and restores, at least 512MiB (D76; 0 = default, omitted from Canonical)
	RestoreHistory      bool     `toml:"restore_history"`            // true: merge sealed history lines back at unlock
	PerRootAuth         bool     `toml:"per_root_auth"`              // true: each root needs its own presence prompt (D1, D40)
	UnlockOnPrompt      bool     `toml:"unlock_on_prompt"`           // false until the hook-dialog E2E passes (D60); human prompts only (D26, D27, D37)
	OnEnter             string   `toml:"on_enter"`                   // "prompt" (D29)
	MDSealOn            string   `toml:"md_seal_on"`                 // "lock"
	ClearTerminalOnEnd  bool     `toml:"clear_terminal_on_end"`      // true: scrub the TTY when sessions are ended
	ClearScrollbackLock bool     `toml:"clear_scrollback_on_lock"`   // true: wrapper clears scrollback at lock (D30)
	PromptRatePerMinute int      `toml:"prompt_rate_per_minute"`     // 3 (D27)
	PromptBackoff       Duration `toml:"prompt_backoff"`             // 30s after a cancel (D27)
	HookPromptCooldown  Duration `toml:"hook_prompt_cooldown"`       // 10m: no hook-raised dialog for a root after a cancel
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
			QuietWindow:         Duration(defaultQuietWindow),
			HoldCap:             Duration(24 * time.Hour),
			RestoreRecent:       5,
			RestoreMaxBytes:     1 << 30,
			MinFree:             DefaultMinFree,
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

// minPromptRate is the lowest policy.prompt_rate_per_minute Validate
// accepts (D130): unlock prompts cannot be turned off, since no wait would
// end a rate of 0 and precinto could never unlock a folder again. A pinned
// policy holding less is forged (Pinned.CheckShape), and Strictest never
// picks a value below it over a valid one.
const minPromptRate = 1

// quiet_window bounds (D63): 0 means the default; anything else below the
// minimum is refused by Validate.
const (
	minQuietWindow     = 10 * time.Second
	defaultQuietWindow = 120 * time.Second
)

// Load parses path and validates it. A missing file yields Default().
// Keys absent from the file keep their defaults (a [harness.<id>] table
// without `enabled`/`min_version` keeps the built-in values); unknown keys
// are rejected (ErrInvalid), so a typo never silently weakens policy. The
// file is opened O_RDONLY|O_NOFOLLOW|O_NONBLOCK and must be a regular file
// owned by the user of at most MaxFileBytes; anything else (a symlink,
// FIFO, directory, foreign or oversized file) is an error wrapping
// fsx.ErrUnsafe, never a hang.
func Load(path string) (Config, error) {
	b, err := readPolicyFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return Default(), nil
	}
	if err != nil {
		return Config{}, err
	}
	c := Default()
	file := filepath.Base(path)
	md, err := toml.NewDecoder(bytes.NewReader(b)).Decode(&c)
	if err != nil {
		return Config{}, loadError(file, err)
	}
	if und := md.Undecoded(); len(und) > 0 {
		return Config{}, unknownKeyError(file, b, und[0])
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
		where := file
		var ke *keyError
		if errors.As(err, &ke) {
			if n := keyLine(b, ke.key, ke.nth); n > 0 {
				where += " line " + strconv.Itoa(n)
			}
		}
		return Config{}, fmt.Errorf("%w: %s: %s", ErrInvalid, where, reason(err))
	}
	return c, nil
}

// unknownKeyError is the ErrInvalid of a key config.toml does not have,
// with the line that sets it and the key it probably meant ("config.toml
// line 3, policy.idle_sotf: unknown key (did you mean idle_soft?)").
func unknownKeyError(file string, src []byte, key toml.Key) error {
	where := file
	if n := keyLine(src, key, -1); n > 0 {
		where += " line " + strconv.Itoa(n)
	}
	hint := "check its spelling"
	if s := suggestKey(key); s != "" {
		hint = "did you mean " + s + "?"
	}
	return fmt.Errorf("%w: %s, %s: unknown key (%s)", ErrInvalid, where, key, hint)
}

// loadError is the ErrInvalid of a file the TOML decoder refused, located
// as the decoder knows it ("config.toml line 4, policy.min_free: size …")
// and kept on one line: the reason of a refused value carries its hint
// (UX-09), so the user fixes the file without guessing.
func loadError(file string, err error) error {
	where := file
	var pe toml.ParseError
	if errors.As(err, &pe) {
		if pe.Position.Line > 0 {
			where += " line " + strconv.Itoa(pe.Position.Line)
		}
		if pe.LastKey != "" {
			where += ", " + pe.LastKey
		}
		return fmt.Errorf("%w: %s: %s", ErrInvalid, where, reason(errors.New(pe.Message)))
	}
	return fmt.Errorf("%w: %s: %s", ErrInvalid, where, reason(err))
}

// reason is the text of err without a leading ErrInvalid text, on one
// line.
func reason(err error) string {
	s := strings.TrimPrefix(err.Error(), ErrInvalid.Error()+": ")
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		s = s[:i]
	}
	return s
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
	// badKey is bad for one key, which Load locates in the file (UX-09):
	// nth is the index of its [[roots]] or [[harness.<id>.homes]] table,
	// -1 for a key outside an array of tables.
	badKey := func(key string, nth int, format string, args ...any) error {
		return &keyError{key: strings.Split(key, "."), nth: nth, err: bad(format, args...)}
	}
	if c.Version != SchemaVersion {
		return badKey("version", -1, "version %d (want %d)", c.Version, SchemaVersion)
	}
	p := c.Policy
	positive := map[string]Duration{
		"idle_soft": p.IdleSoft, "max_unlock": p.MaxUnlock, "busy_timeout": p.BusyTimeout,
		"hold_cap": p.HoldCap,
	}
	for k, d := range positive {
		if d <= 0 {
			return badKey("policy."+k, -1, "policy.%s must be positive", k)
		}
	}
	// D63: every sealing process waits once for quiet_window, so it must
	// be long enough to see a writer pause; 0 keeps the 120 s default.
	if q := p.QuietWindow.D(); q != 0 && q < minQuietWindow {
		return badKey("policy.quiet_window", -1, "policy.quiet_window must be at least %s (0 means the %s default)", minQuietWindow, defaultQuietWindow)
	}
	nonNegative := map[string]Duration{
		"idle_hard": p.IdleHard, "screen_lock_hard_after": p.ScreenLockHardAfter, "busy_grace": p.BusyGrace,
		"prompt_backoff": p.PromptBackoff, "hook_prompt_cooldown": p.HookPromptCooldown,
	}
	for k, d := range nonNegative {
		if d < 0 {
			return badKey("policy."+k, -1, "policy.%s is negative", k)
		}
	}
	if p.MaxUnlock.D() > MaxUnlockCap {
		return badKey("policy.max_unlock", -1, "policy.max_unlock above %s", MaxUnlockCap)
	}
	for k, n := range map[string]int64{"restore_recent": int64(p.RestoreRecent), "restore_max_bytes": p.RestoreMaxBytes, "prompt_rate_per_minute": int64(p.PromptRatePerMinute)} {
		if n < 0 {
			return badKey("policy."+k, -1, "policy counters must not be negative")
		}
	}
	// D130: every unlock is a prompt, so a rate of 0 would lock the
	// folders for good (no wait ends it, and confirming a fix needs an
	// unlock in a terminal).
	if p.PromptRatePerMinute < minPromptRate {
		return badKey("policy.prompt_rate_per_minute", -1, "policy.prompt_rate_per_minute must be at least %d (unlock prompts cannot be turned off: precinto could never unlock the folder again)", minPromptRate)
	}
	// D76: the floor keeps precinto from filling the volume; 0 keeps the
	// 2 GiB default.
	if m := p.MinFree; m != 0 && m < MinMinFree {
		return badKey("policy.min_free", -1, "policy.min_free must be at least %s (0 means the %s default)", sizeText(MinMinFree), sizeText(DefaultMinFree))
	}
	if !oneOf(p.OnEnter, OnEnterPrompt, OnEnterNotify, OnEnterOff) {
		return badKey("policy.on_enter", -1, "policy.on_enter must be %s, %s or %s", OnEnterPrompt, OnEnterNotify, OnEnterOff)
	}
	if !oneOf(p.MDSealOn, MDSealOnLock, MDSealOnEnd) {
		return badKey("policy.md_seal_on", -1, "policy.md_seal_on must be %s or %s", MDSealOnLock, MDSealOnEnd)
	}
	ids, roots := map[string]bool{}, map[string]bool{}
	for i, r := range c.Roots {
		if r.ID == "" || ids[r.ID] {
			return badKey("roots.id", i, "root id %q missing or duplicate", r.ID)
		}
		ids[r.ID] = true
		if cp, ok := paths.Clean(r.Path); !ok || cp == "/" {
			return badKey("roots.path", i, "root %s path is not an absolute clean path", r.ID)
		}
		if strings.ContainsFunc(r.Path, func(c rune) bool { return c < 0x20 || c == 0x7f }) {
			return badKey("roots.path", i, "root %s path contains a control character", r.ID) // roots.list is line-based
		}
		if roots[r.Path] {
			return badKey("roots.path", i, "root path listed twice")
		}
		roots[r.Path] = true
		if r.MD != "" && !oneOf(r.MD, MDLedger, MDAll, MDOff) {
			return badKey("roots.md", i, "root %s md must be %s, %s or %s", r.ID, MDLedger, MDAll, MDOff)
		}
		if r.OnEnter != "" && !oneOf(r.OnEnter, OnEnterPrompt, OnEnterNotify, OnEnterOff) {
			return badKey("roots.on_enter", i, "root %s on_enter must be %s, %s or %s", r.ID, OnEnterPrompt, OnEnterNotify, OnEnterOff)
		}
	}
	for id, h := range c.Harness {
		for j, home := range h.Homes {
			if _, ok := paths.Clean(home.Dir); !ok {
				return &keyError{key: []string{"harness", id, "homes", "dir"}, nth: j, err: bad("harness.%s home is not an absolute clean path", id)}
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
// (ties by id, so the order is deterministic). On darwin a root whose
// path holds non-ASCII bytes is also matched by identity (D93): APFS
// ignores Unicode normalization, getcwd returns a name as stored (often
// NFD, as Finder creates it) while Claude Code reports its cwd in NFC, so
// both spellings of one folder must match.
func (c Config) RootsFor(ps ...string) []Root {
	var out []Root
	for _, r := range c.Roots {
		for _, p := range ps {
			if p != "" && (paths.Within(r.Path, p) || sameFolderWithin(r.Path, p)) {
				out = append(out, r)
				break
			}
		}
	}
	sortDeepestFirst(out)
	return out
}

// sameFolderWithin is RootsFor's identity fallback (D93): on darwin, for a
// root with non-ASCII bytes (only those can differ in normalization), p is
// within the root when an existing ancestor of p is the root's directory
// (fsx.Contains compares (dev, ino)).
func sameFolderWithin(root, p string) bool {
	if runtime.GOOS != "darwin" || isASCII(root) || !filepath.IsAbs(root) || !filepath.IsAbs(p) {
		return false
	}
	ok, err := fsx.Contains(root, p)
	return err == nil && ok
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

// storedSpelling returns the spelling of the existing directory p as the
// file system stores it (getcwd's answer on APFS), found by identity among
// the entries of each parent whose component holds non-ASCII bytes; ""
// when p does not resolve (D93).
func storedSpelling(p string) string {
	if isASCII(p) || !filepath.IsAbs(p) {
		return p
	}
	cur := "/"
	for _, c := range strings.Split(strings.TrimPrefix(filepath.Clean(p), "/"), "/") {
		next := filepath.Join(cur, c)
		if isASCII(c) {
			cur = next
			continue
		}
		want, err := fsx.Lstat(next)
		if err != nil {
			return ""
		}
		ents, err := os.ReadDir(cur)
		if err != nil {
			return ""
		}
		found := ""
		for _, e := range ents {
			if n := e.Name(); n == c {
				found = n
				break
			}
		}
		if found == "" {
			for _, e := range ents {
				n := e.Name()
				if isASCII(n) {
					continue
				}
				if st, err := fsx.Lstat(filepath.Join(cur, n)); err == nil && st.SameFile(want) {
					found = n
					break
				}
			}
		}
		if found == "" {
			return ""
		}
		cur = filepath.Join(cur, found)
	}
	return cur
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

// WithRoots returns c with every root of add whose id and path c does not
// have yet, in order, when the root has an id and a path Validate accepts
// (absolute, clean, not "/") without a control character (C0, DEL or C1):
// folders that another source records — the confirmed settings of
// state/policy.pinned, a vault's vault.toml root_path — added to settings
// that lack them (D121, D142, D145). Those sources are never validated as
// a configuration, so a root they hold that could not be saved is left
// out. Nothing in the result aliases c or add.
func WithRoots(c Config, add ...Root) Config {
	out := c
	out.Roots = append([]Root(nil), c.Roots...)
	for _, r := range add {
		p, ok := paths.Clean(r.Path)
		if r.ID == "" || !ok || p != r.Path || p == "/" || strings.ContainsFunc(p, isControl) {
			continue
		}
		known := false
		for _, x := range out.Roots {
			if x.ID == r.ID || x.Path == r.Path {
				known = true
				break
			}
		}
		if !known {
			r.MDExclude = append([]string(nil), r.MDExclude...)
			r.Harnesses = append([]string(nil), r.Harnesses...)
			out.Roots = append(out.Roots, r)
		}
	}
	return out
}

// isControl reports a C0, DEL or C1 control character.
func isControl(c rune) bool { return c < 0x20 || c == 0x7f || (c >= 0x80 && c <= 0x9f) }

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
		// D93: also the spelling the file system stores (getcwd's, which
		// Codex reports), so the byte-comparing shim matches both.
		if runtime.GOOS == "darwin" {
			if s := storedSpelling(r.Path); s != "" && s != r.Path && !strings.ContainsAny(s, "\n\r") {
				b.WriteString(s)
				b.WriteByte('\n')
			}
		}
	}
	return fsx.WriteFileAtomic(path, []byte(b.String()), 0o600)
}

// ReadRootsList reads a roots.list file (missing file: no roots); lines
// that are not absolute clean paths are ignored. The file is opened like
// Load's (regular, owned by the user, ≤ MaxFileBytes, else fsx.ErrUnsafe).
func ReadRootsList(path string) ([]string, error) {
	b, err := readPolicyFile(path)
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

// MaxFileBytes bounds config.toml, roots.list and state/policy.pinned.
const MaxFileBytes = 1 << 20

// readPolicyFile reads one of precinto's own configuration files without
// following a symlink or blocking on a FIFO; a missing file is
// os.ErrNotExist (callers treat it as "none").
func readPolicyFile(path string) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|fsx.ONoFollow|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return nil, fmt.Errorf("%w: %s is a symlink", fsx.ErrUnsafe, filepath.Base(path))
		}
		return nil, err
	}
	defer f.Close()
	st, err := fsx.Fstat(f)
	if err != nil {
		return nil, err
	}
	switch {
	case !st.IsRegular():
		return nil, fmt.Errorf("%w: %s is not a regular file", fsx.ErrUnsafe, filepath.Base(path))
	case int(st.UID) != os.Geteuid():
		return nil, fmt.Errorf("%w: %s is owned by uid %d", fsx.ErrUnsafe, filepath.Base(path), st.UID)
	case st.Size > MaxFileBytes:
		return nil, fmt.Errorf("%w: %s is larger than %d bytes", fsx.ErrUnsafe, filepath.Base(path), MaxFileBytes)
	}
	b, err := io.ReadAll(io.LimitReader(f, MaxFileBytes+1))
	if err != nil {
		return nil, err
	}
	if len(b) > MaxFileBytes {
		return nil, fmt.Errorf("%w: %s grew past %d bytes", fsx.ErrUnsafe, filepath.Base(path), MaxFileBytes)
	}
	return b, nil
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
// does not decode is an error (the daemon reports policy-tampered). It is
// opened like Load's file: a FIFO or symlink planted at the path is an
// error wrapping fsx.ErrUnsafe (policy-tampered), never a hang.
func LoadPinned(path string) (p Pinned, ok bool, err error) {
	b, err := readPolicyFile(path)
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

// PinnedGlobalVault is the vault id of the global stores (vault.GlobalID),
// the one MAC key of a pin that is not a root of its settings.
const PinnedGlobalVault = "global"

// ErrForgedPin is a decodable pin of a shape precinto never writes (D91).
var ErrForgedPin = errors.New("config: policy.pinned has a forged shape")

// CheckShape reports why a decodable pin is forged (D91): every pin
// precinto writes once a root vault exists carries at least one MAC, each
// 64 hex characters, keyed by "global" or a root of the pinned settings,
// naming a vault that exists (vaultExists: vaults/<id>/vault.toml). The
// daemon and doctor apply the same rule; MAC values are checked by the
// daemon with the vault keys at unlock.
//
// A pin whose settings name folders also carries a MAC keyed by one of
// those folders (D145): a "global" MAC is checked only by `unlock
// --global` and `recover`, so it alone never authenticates settings that
// name folders (the daemon's writePin refuses to write such a pin). And
// the pinned policy keeps unlock prompts on (prompt_rate_per_minute at
// least 1, D130), as every configuration precinto saves does.
func (p Pinned) CheckShape(vaultExists func(id string) bool) error {
	if len(p.MACs) == 0 {
		return fmt.Errorf("%w: carries no vault MAC", ErrForgedPin)
	}
	ids := make([]string, 0, len(p.MACs))
	for id := range p.MACs {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	rootMAC := false
	for _, id := range ids {
		if !hexMAC(p.MACs[id]) {
			return fmt.Errorf("%w: has a malformed MAC", ErrForgedPin)
		}
		_, isRoot := p.Config.RootByID(id)
		if !isRoot && id != PinnedGlobalVault {
			return fmt.Errorf("%w: has a MAC for a vault outside its settings", ErrForgedPin)
		}
		if vaultExists != nil && !vaultExists(id) {
			return fmt.Errorf("%w: has a MAC for a vault that does not exist", ErrForgedPin)
		}
		rootMAC = rootMAC || isRoot
	}
	if len(p.Config.Roots) > 0 && !rootMAC {
		return fmt.Errorf("%w: names folders but carries no MAC of theirs", ErrForgedPin)
	}
	if p.Config.Policy.PromptRatePerMinute < minPromptRate {
		return fmt.Errorf("%w: turns unlock prompts off", ErrForgedPin)
	}
	return nil
}

// hexMAC reports a hex HMAC-SHA256 (64 hex characters).
func hexMAC(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if !('0' <= c && c <= '9' || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F') {
			return false
		}
	}
	return true
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
