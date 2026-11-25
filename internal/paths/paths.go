package paths

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

// Environment variables precinto reads. Harness variables are read only to
// resolve harness homes in the harness's own context (SPEC §7.0). There is
// no PRECINTO_BIN: the hook shim never reads PRECINTO_* variables, because
// hooks always run in an agent context (D6, HOOKS-IO §5).
const (
	EnvHome       = "PRECINTO_HOME"        // base dir override (testing tag / PRECINTO_DEV only)
	EnvRuntimeDir = "PRECINTO_RUNTIME_DIR" // socket dir override (testing tag / PRECINTO_DEV only)
	EnvDev        = "PRECINTO_DEV"         // "1" enables overrides outside agent contexts
	EnvActive     = "PRECINTO_ACTIVE"      // set by the wrapper in the child; prevents recursion
	EnvE2E        = "PRECINTO_E2E"         // "1" enables opt-in E2E tests
	// EnvCrashpoint arms fault injection in binaries built with -tags
	// failpoints: cmd/precinto reads it here and calls failpoint.Set before
	// dispatching (docs/TESTPLAN.md §4). Ignored by every other build.
	EnvCrashpoint = "PRECINTO_CRASHPOINT"
	// EnvTestAncestryStop ("PID:START") ends the harness-ancestry walk of
	// ui.AgentContext and of the daemon's peer checks at that process, in
	// -tags testing builds only (D64); read it with TestAncestryStop.
	// Production builds never read it; hook mode and the shim ignore it.
	EnvTestAncestryStop = "PRECINTO_TEST_ANCESTRY_STOP"

	EnvClaudeConfigDir   = "CLAUDE_CONFIG_DIR"
	EnvClaudeTmpDir      = "CLAUDE_CODE_TMPDIR"
	EnvClaudeProjectName = "CLAUDE_CODE_PROJECT_DIR_NAME"
	EnvClaudePID         = "CLAUDE_PID"
	EnvClaudeProjectDir  = "CLAUDE_PROJECT_DIR"
	EnvClaudeCode        = "CLAUDECODE"         // "1" in Claude Code hooks and tools (host marker, D56)
	EnvClaudePluginRoot  = "CLAUDE_PLUGIN_ROOT" // Claude; Codex sets it too, as an alias of PLUGIN_ROOT
	EnvPluginRoot        = "PLUGIN_ROOT"        // Codex hooks (host marker without CLAUDE_PID, D56)
	EnvCodexHome         = "CODEX_HOME"
	EnvCodexSQLiteHome   = "CODEX_SQLITE_HOME"
	EnvXDGDataHome       = "XDG_DATA_HOME"
	EnvXDGRuntimeDir     = "XDG_RUNTIME_DIR"
)

// MaxSocketPath is the exclusive upper bound on the socket path length
// (darwin sun_path is 104 bytes; linux allows 108, precinto uses the
// stricter bound everywhere).
const MaxSocketPath = 104

// ErrSocketPath is returned when the socket path would be too long.
var ErrSocketPath = errors.New("paths: socket path too long (use a shorter PRECINTO_RUNTIME_DIR)")

// Env is an immutable snapshot of the environment. No package other than
// paths calls os.Getenv/os.Environ (enforced by internal/archtest).
type Env struct {
	m map[string]string
}

// FromOS snapshots the current process environment.
func FromOS() Env { return FromEnviron(os.Environ()) }

// FromMap builds an Env from a map (tests, hook payload environments).
func FromMap(m map[string]string) Env {
	c := make(map[string]string, len(m))
	for k, v := range m {
		c[k] = v
	}
	return Env{m: c}
}

// FromEnviron builds an Env from KEY=VALUE pairs; entries without '=' are
// ignored and a later duplicate wins (os/exec semantics).
func FromEnviron(kv []string) Env {
	m := make(map[string]string, len(kv))
	for _, e := range kv {
		k, v, ok := strings.Cut(e, "=")
		if !ok || k == "" {
			continue
		}
		m[k] = v
	}
	return Env{m: m}
}

// Get returns the value of key or "".
func (e Env) Get(key string) string { return e.m[key] }

// Lookup returns the value of key and whether it is set.
func (e Env) Lookup(key string) (string, bool) {
	v, ok := e.m[key]
	return v, ok
}

// With returns a copy of e with key set to value.
func (e Env) With(key, value string) Env {
	c := FromMap(e.m)
	c.m[key] = value
	return c
}

// Without returns a copy of e without the given keys.
func (e Env) Without(keys ...string) Env {
	c := FromMap(e.m)
	for _, k := range keys {
		delete(c.m, k)
	}
	return c
}

// Environ returns KEY=VALUE pairs in sorted order (child processes).
func (e Env) Environ() []string {
	out := make([]string, 0, len(e.m))
	for k, v := range e.m {
		out = append(out, k+"="+v)
	}
	sort.Strings(out)
	return out
}

// AgentMarkers returns the names of environment variables that indicate an
// AI-agent context (CLAUDECODE, CLAUDE_CODE_ENTRYPOINT, CLAUDE_CODE_SESSION_ID,
// CLAUDE_PID, CODEX_THREAD_ID-like markers, KIMI_*, GEMINI_SESSION_ID,
// PRECINTO_ACTIVE). Process ancestry and a missing controlling TTY are
// checked separately by ui.AgentContext and the daemon (D7, D28, D59).
func AgentMarkers(e Env) []string { return agentMarkers(e) }

// OverridesAllowed reports whether PRECINTO_HOME/PRECINTO_RUNTIME_DIR may be
// honoured: built with -tags testing, or PRECINTO_DEV=1 and AgentMarkers(e)
// is empty (D6). Hook mode never honours them (hooks run in agent
// contexts).
func OverridesAllowed(e Env) bool { return overridesAllowed(e, testingBuild) }

// TestingBuild reports whether the binary was built with -tags testing.
func TestingBuild() bool { return testingBuild }

// TestAncestryStop returns the PID:START value of EnvTestAncestryStop in a
// -tags testing build (ok=false when unset or malformed); ("", false) in
// every other build, which never reads the variable (the reading code is
// only in build_testing.go, D64). Callers end the harness-ancestry walk at
// the process whose measured ProcID equals it: that process and its
// ancestors are ignored, everything below is checked, and env markers and
// the no-controlling-terminal rule still apply.
func TestAncestryStop(e Env) (string, bool) { return testAncestryStop(e) }

// Names fixed by the product (owner-revisable, OD-05).
const (
	// ServiceLabel is the LaunchAgent label; its plist is
	// ~/Library/LaunchAgents/<label>.plist.
	ServiceLabel = "com.github.precinto.sweep"
	// ClaudePluginID is the Claude Code plugin id: plugin precinto of the
	// marketplace precinto (SPEC §21).
	ClaudePluginID = "precinto@precinto"
)

// UserHome returns $HOME, which must be absolute (precinto trusts HOME;
// see SPEC §19).
func UserHome(e Env) (string, error) {
	h := e.Get("HOME")
	if h == "" || !filepath.IsAbs(h) {
		return "", errors.New("paths: HOME is unset or not absolute")
	}
	return filepath.Clean(h), nil
}

// LookPath finds an executable regular file named name in the PATH of e
// (exec.LookPath reads the process environment, which only this package
// may do). A name containing '/' must be absolute and is checked as is.
// Prefer absolute system paths (/usr/sbin/lsof, /usr/sbin/ioreg) where
// they are fixed. A name that is not found is an error matching
// exec.ErrNotFound (`precinto run` exits 127 for it, UX-16). Implemented
// in the scaffold.
func LookPath(e Env, name string) (string, error) {
	check := func(p string) bool {
		fi, err := os.Stat(p)
		return err == nil && fi.Mode().IsRegular() && fi.Mode().Perm()&0o111 != 0
	}
	if strings.Contains(name, "/") {
		if filepath.IsAbs(name) && check(name) {
			return filepath.Clean(name), nil
		}
		return "", notFoundError{text: "paths: " + name + " is not an absolute executable"}
	}
	for _, dir := range filepath.SplitList(e.Get("PATH")) {
		if !filepath.IsAbs(dir) {
			continue // never resolve through relative PATH entries
		}
		if p := filepath.Join(dir, name); check(p) {
			return p, nil
		}
	}
	return "", notFoundError{text: "paths: " + name + " not found in PATH"}
}

// notFoundError is LookPath's failure: its own text, matching
// exec.ErrNotFound for errors.Is.
type notFoundError struct{ text string }

func (e notFoundError) Error() string { return e.text }
func (e notFoundError) Unwrap() error { return exec.ErrNotFound }

// Layout is every precinto-owned path. Directories are 0700, files 0600.
type Layout struct {
	Base string // ~/Library/Application Support/precinto | ${XDG_DATA_HOME:-~/.local/share}/precinto

	ConfigFile string // <base>/config.toml
	RootsList  string // <base>/roots.list (D22; read by the POSIX shim)
	BinLink    string // <base>/bin/precinto (pinned binary symlink written by integrate, D6)
	// Marketplace is <base>/marketplace: precinto's plugins and their two
	// marketplace manifests, written byte for byte from the binary by
	// integrate, which adds it to the harness as a local marketplace
	// (D116). Not created by EnsureDirs.
	Marketplace string

	VaultsDir     string // <base>/vaults/<vault-id>/ (D1)
	FactorsDir    string // <base>/factors/ (non-secret factor stubs, e.g. se.identity)
	CapsulesDir   string // <base>/capsules/<harness>/<unit-key>/g<N>.pcap (D9, D45)
	HomesDir      string // <base>/homes/codex/<root-id>/ (D31)
	StagingDir    string // <base>/staging/<op-id>/ (D12)
	QuarantineDir string // <base>/quarantine/<op-id>/ (unlogged capsules, displaced -wal files)

	StateDir       string // <base>/state
	NameSalt       string // state/name.salt (D45)
	CapsuleLog     string // state/capsules.log (D8)
	VerifiedDir    string // state/verified/<vault-id>.recipients (D5)
	GensDir        string // state/gens/<unit-key> (D9)
	ReceiptsDir    string // state/receipts/<unit-key>.json (D10)
	LeasesDir      string // state/leases/<unit-key>.lease (SPEC §9.3)
	SessionsDir    string // state/sessions/<harness>/<sid>.jsonl (ledger)
	ProjectsDir    string // state/projects/<harness>.json (project index)
	JournalDir     string // state/journal/<op-id>.json (I9)
	QueueDir       string // state/queue/<req-id>.json
	LocksDir       string // state/locks/*.lock (never deleted)
	PolicyPinned   string // state/policy.pinned: policy confirmed at the last TTY unlock, with per-vault MACs (D48, D55)
	HookDedupeDir  string // state/hookdedupe (HA21 duplicate suppression, content-free hashed names)
	NotesIndex     string // state/notes.json (pending-notes index: absolute note paths per root, no content)
	SweepRequested string // state/sweep.requested
	SweepLast      string // state/sweep.last (heartbeat for status)

	LogsDir string // <base>/logs
	LogFile string // logs/precinto.log (no content, HMAC'd paths only)

	RunDir    string // <base>/run (darwin) | $XDG_RUNTIME_DIR/precinto (linux) | PRECINTO_RUNTIME_DIR
	Socket    string // RunDir/agent.sock (len < 104 bytes)
	AgentLock string // RunDir/agent.lock (held by the daemon for its lifetime, D6)
}

// DefaultBase returns the OS default base directory for e (ignores
// overrides): darwin $HOME/Library/Application Support/precinto; linux
// ${XDG_DATA_HOME:-$HOME/.local/share}/precinto (a relative XDG_DATA_HOME is
// ignored, as the XDG spec requires).
func DefaultBase(e Env) (string, error) { return defaultBaseFor(e, runtime.GOOS) }

// defaultBaseFor is DefaultBase for an explicit GOOS, so that the linux
// rules are tested on darwin too.
func defaultBaseFor(e Env, goos string) (string, error) {
	home, err := UserHome(e)
	if err != nil {
		return "", err
	}
	switch goos {
	case "darwin":
		return filepath.Join(home, "Library", "Application Support", "precinto"), nil
	case "linux":
		if x := e.Get(EnvXDGDataHome); x != "" && filepath.IsAbs(x) {
			return filepath.Join(filepath.Clean(x), "precinto"), nil
		}
		return filepath.Join(home, ".local", "share", "precinto"), nil
	default:
		return "", fmt.Errorf("paths: unsupported OS %s (precinto runs on macOS and Linux)", goos)
	}
}

// NewLayout derives the Layout for e, honouring overrides only when
// OverridesAllowed(e). It fails if the socket path is 104 bytes or longer.
// Under WSL it also refuses a base or run directory on a Windows drive
// (CheckDrive, D156): the error is then a *DriveError and the Layout is
// returned complete, so that status and doctor can still report where it
// lies; every other caller stops on the error.
func NewLayout(e Env) (Layout, error) {
	l, err := newLayout(e, runtime.GOOS, OverridesAllowed(e))
	if err != nil {
		return l, err
	}
	return l, checkLayoutDrives(l, CheckDrive)
}

// HookLayout returns the default base and run dir for e, never honouring
// PRECINTO_* overrides (hook mode, D6/D56), in every build; it fails like
// NewLayout when the socket path is too long (ErrSocketPath). It does not
// check drives: on a layout NewLayout refuses, the daemon does not start,
// so a hook's gates fail closed in the protected folders (D156).
func HookLayout(e Env) (Layout, error) { return newLayout(e, runtime.GOOS, false) }

// LayoutAt derives a Layout for an explicit base and run directory (tests,
// and the daemon after it has resolved its own layout). Both must be
// absolute and clean; the socket path must be shorter than MaxSocketPath.
// It touches nothing on disk.
func LayoutAt(base, runDir string) (Layout, error) {
	if b, ok := Clean(base); !ok || b == "/" {
		return Layout{}, fmt.Errorf("paths: base %q is not an absolute clean path", base)
	}
	if _, ok := Clean(runDir); !ok {
		return Layout{}, fmt.Errorf("paths: run dir %q is not an absolute clean path", runDir)
	}
	j := filepath.Join
	st := j(base, "state")
	l := Layout{
		Base:          base,
		ConfigFile:    j(base, "config.toml"),
		RootsList:     j(base, "roots.list"),
		BinLink:       j(base, "bin", "precinto"),
		Marketplace:   j(base, "marketplace"),
		VaultsDir:     j(base, "vaults"),
		FactorsDir:    j(base, "factors"),
		CapsulesDir:   j(base, "capsules"),
		HomesDir:      j(base, "homes"),
		StagingDir:    j(base, "staging"),
		QuarantineDir: j(base, "quarantine"),

		StateDir:       st,
		NameSalt:       j(st, "name.salt"),
		CapsuleLog:     j(st, "capsules.log"),
		VerifiedDir:    j(st, "verified"),
		GensDir:        j(st, "gens"),
		ReceiptsDir:    j(st, "receipts"),
		LeasesDir:      j(st, "leases"),
		SessionsDir:    j(st, "sessions"),
		ProjectsDir:    j(st, "projects"),
		JournalDir:     j(st, "journal"),
		QueueDir:       j(st, "queue"),
		LocksDir:       j(st, "locks"),
		PolicyPinned:   j(st, "policy.pinned"),
		HookDedupeDir:  j(st, "hookdedupe"),
		NotesIndex:     j(st, "notes.json"),
		SweepRequested: j(st, "sweep.requested"),
		SweepLast:      j(st, "sweep.last"),

		LogsDir: j(base, "logs"),
		LogFile: j(base, "logs", "precinto.log"),

		RunDir:    runDir,
		Socket:    j(runDir, "agent.sock"),
		AgentLock: j(runDir, "agent.lock"),
	}
	if len(l.Socket) >= MaxSocketPath {
		return Layout{}, fmt.Errorf("%w: %d bytes", ErrSocketPath, len(l.Socket))
	}
	return l, nil
}

// EnsureDirs creates every Layout directory with mode 0700 and fails on
// symlinks or foreign owners (fsx.CheckPrivateDir).
func (l Layout) EnsureDirs() error { return l.ensureDirs() }

// VaultDir returns <base>/vaults/<vaultID>.
func (l Layout) VaultDir(vaultID string) string { return filepath.Join(l.VaultsDir, vaultID) }

// UnitCapsuleDir returns <base>/capsules/<harness>/<unitKey>.
func (l Layout) UnitCapsuleDir(harness, unitKey string) string {
	return filepath.Join(l.CapsulesDir, harness, unitKey)
}

// CodexHome returns <base>/homes/codex/<rootID> (D31).
func (l Layout) CodexHome(rootID string) string { return filepath.Join(l.HomesDir, "codex", rootID) }

// LockFile returns <base>/state/locks/<name>.lock for a lock name such as
// "sweep", "global-claude-code", "root-<id>", "unit-<key>", "unlock-<id>".
func (l Layout) LockFile(name string) string { return filepath.Join(l.LocksDir, name+".lock") }

// Within reports whether p equals root or lies below it, comparing cleaned
// absolute paths component by component (never by string prefix), with
// ASCII case folding on darwin. Relative paths are never within anything.
// Prefer fsx.Contains when both paths exist (it also handles Unicode
// normalization and case-insensitive volumes through (dev, ino)).
func Within(root, p string) bool {
	if !filepath.IsAbs(root) || !filepath.IsAbs(p) {
		return false
	}
	rc := components(filepath.Clean(root))
	pc := components(filepath.Clean(p))
	if len(pc) < len(rc) {
		return false
	}
	for i := range rc {
		if !sameComponent(rc[i], pc[i]) {
			return false
		}
	}
	return true
}

func components(clean string) []string {
	if clean == "/" {
		return nil
	}
	return strings.Split(strings.TrimPrefix(clean, "/"), "/")
}

func sameComponent(a, b string) bool {
	if runtime.GOOS != "darwin" {
		return a == b
	}
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		if lowerASCII(a[i]) != lowerASCII(b[i]) {
			return false
		}
	}
	return true
}

func lowerASCII(c byte) byte {
	if 'A' <= c && c <= 'Z' {
		return c + 'a' - 'A'
	}
	return c
}

// Clean returns filepath.Clean of an absolute path and reports whether the
// input was already clean and absolute.
func Clean(p string) (string, bool) {
	c := filepath.Clean(p)
	return c, c == p && filepath.IsAbs(p)
}

// Tilde shortens p for display ("~/work/acme"); p is returned unchanged
// when it is not within home.
func Tilde(home, p string) string {
	if home == "" || !Within(home, p) {
		return p
	}
	hc := components(filepath.Clean(home))
	pc := components(filepath.Clean(p))
	if len(pc) == len(hc) {
		return "~"
	}
	return "~/" + strings.Join(pc[len(hc):], "/")
}
