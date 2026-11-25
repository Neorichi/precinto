package doctor

import (
	"context"
	"io"

	"github.com/Neorichi/precinto/internal/config"
	"github.com/Neorichi/precinto/internal/ipc"
	"github.com/Neorichi/precinto/internal/paths"
	"github.com/Neorichi/precinto/internal/platform"
)

// Severity of a finding.
type Severity string

// Severities.
const (
	OK   Severity = "ok"
	Info Severity = "info"
	Warn Severity = "warn"
	Fail Severity = "fail"
)

// Check codes (stable; used by tests and `status`). Codes that also appear
// as status attention items reuse the ipc.Attn* constants, so `status` and
// `doctor` speak one kebab-case vocabulary.
const (
	// CheckConfig: config.toml does not load (its key, line and reason);
	// commands that read it stop until it is fixed (UX-09).
	CheckConfig            = "config"
	CheckDiskEncryption    = "disk-encryption" // FileVault / encrypted home (S18)
	CheckUnhardenedBuild   = ipc.AttnUnhardenedBuild
	CheckLoaderEnv         = "loader-env"          // DYLD_*/LD_* present
	CheckBaseSynced        = "base-synced"         // <base> inside a cloud-synced folder (S9)
	CheckBackups           = "backups"             // Time Machine covers harness plaintext dirs (S18)
	CheckSpotlight         = "spotlight"           // protected folders indexed (S17, UX21)
	CheckCloudRoot         = "cloud-root"          // protected folder is cloud-synced (S17)
	CheckClaudeVersion     = "claude-version"      // ≥ 2.1.295 for onFailure (D22)
	CheckClaudePlugin      = "claude-plugin"       // plugin installed and enabled
	CheckClaudeHooksOff    = "claude-hooks-off"    // disableAllHooks / plugin hooks removed in <root>/.claude/settings*.json (S6, S16)
	CheckClaudeSettings    = "claude-settings"     // drift from what protect --claude-settings wrote
	CheckClaudeSettingsEnv = "claude-settings-env" // PRECINTO_*, HOME, XDG_*, PATH, DYLD_* or LD_* keys in the "env" of any Claude settings file (user, <root>/.claude/settings*.json): they reach every hook process (S2, D56)
	CheckClaudeRetention   = "claude-retention"    // cleanupPeriodDays advice (D14)
	CheckClaudeLegacy      = "claude-legacy"       // lastSessionFirstPrompt, sessions-index.json, session-memory/ (critic)
	CheckCodexVersion      = "codex-version"       // pinned 0.154 range
	CheckCodexHooksTrust   = ipc.AttnCodexHooksTrust
	CheckCodexShellNoise   = "codex-shell-noise"    // `$SHELL -lc true` prints to stdout (HA6)
	CheckCodexWrongHome    = ipc.AttnCodexWrongHome // rollouts in the user's own Codex home whose session_meta cwd lies inside a root (reads only that field of each rollout's first line, ≤ 64 KiB): written outside the sealed per-root home and never sealed (D31, HA1); fix: precinto run codex
	CheckCodexOutsideRuns  = "codex-outside-runs"   // rollouts in a per-root home without a lease (R12)
	CheckRecoveryTested    = ipc.AttnRecoveryTested
	CheckPassphraseFactor  = "passphrase-factor" // offline-attackable (D3)
	CheckServiceRunning    = "service-running"   // background re-seal heartbeat (UX23)
	CheckServiceTCC        = "service-tcc"       // LaunchAgent cannot read a root (R15)
	CheckTerminalResidue   = "terminal-residue"  // iTerm2/Terminal.app restoration, tmux-resurrect…
	CheckQuarantine        = ipc.AttnQuarantine
	CheckUnsealed          = ipc.AttnUnsealed
	CheckHoldCapped        = ipc.AttnHoldCapped
	CheckResidue           = "residue" // shell-snapshots, usage-data, bash-edit-diff, hook_outputs (IM14)
	CheckPendingPolicy     = ipc.AttnPendingPolicy
	CheckPolicyTampered    = ipc.AttnPolicyTampered
	// CheckUnprotectedFolders: the confirmed settings name no folder, and
	// folders whose vault is kept are protected by nothing (D145). Such
	// settings are checked only by `precinto unlock --global`; also a
	// status item.
	CheckUnprotectedFolders = "unprotected-folders"
	CheckHistoryPending     = ipc.AttnHistoryPending
	CheckVaultTampered      = ipc.AttnVaultTampered
	CheckExposed            = ipc.AttnExposed
	CheckUngatedSession     = ipc.AttnUngatedSession
	CheckConflict           = ipc.AttnConflict
	// CheckPermissions: precinto's own directories and Claude's temp folder
	// are not private (owner, mode, symlinks; S7, D6).
	CheckPermissions = "permissions"
	// CheckAgentSocket: the run directory or socket is unusable or unsafe
	// (length, owner, mode, a non-socket; D6).
	CheckAgentSocket = "agent-socket"
	// CheckInterrupted: journal leftovers, abandoned restore staging and
	// history hold links of interrupted operations (D12, D58).
	CheckInterrupted = "interrupted"
	// CheckPluginPin: a pinned plugin binary no longer matches its SHA-256;
	// fix: precinto factor repin NAME (D75).
	CheckPluginPin = "plugin-pin"
	// CheckExperimentalVersion: an installed harness version outside an
	// experimental inventory's verified_versions (SPEC §7.3).
	CheckExperimentalVersion = "experimental-version"
	// CheckWSL: precinto runs under WSL 1, which it refuses (fail), or
	// under WSL 2; no finding outside WSL (D155, D156).
	CheckWSL = "wsl"
	// CheckWSLInterop: under WSL, Windows interoperability is on, so a
	// program of the distribution can become its superuser through
	// wsl.exe and read the agent's memory (warn, D155).
	CheckWSLInterop = "wsl-interop"
	// CheckWSLIdle: under WSL 2, the distribution stops after
	// instanceIdleTimeout, and the agent with it, so sealing waits for the
	// next precinto start (info, D155).
	CheckWSLIdle = "wsl-idle-shutdown"
	// CheckWindowsDrive: under WSL, a protected folder, a harness folder or
	// a folder of precinto is on a Windows drive, or precinto cannot tell
	// (fail, D156).
	CheckWindowsDrive = "windows-drive"
	// CheckWindowsHarnessData (--leaks): Claude Code or Codex data of a
	// Windows account in <mount root><drive>/Users/<name> (warn, D156).
	CheckWindowsHarnessData = "windows-harness-data"
)

// Finding is one result.
type Finding struct {
	Code     string   `json:"code"`
	Severity Severity `json:"severity"`
	Message  string   `json:"message"`       // one line, content-free
	Fix      string   `json:"fix,omitempty"` // command or setting that fixes it
}

// Options configures Run.
type Options struct {
	Cfg     config.Config
	Layout  paths.Layout
	Env     paths.Env
	Procs   platform.ProcTable
	Leaks   bool   // also scan residue locations (slow)
	Harness string // limit to one harness
	// ConfigErr is why config.toml did not load (config.Load), nil when it
	// did: the config check fails with it, and the other checks run with
	// Cfg, the settings confirmed last or the defaults (UX-09).
	ConfigErr error
}

// Run executes every applicable check.
func Run(ctx context.Context, o Options) ([]Finding, error) { return run(ctx, o, defaultDeps(o)) }

// Codes lists every check code in display order.
func Codes() []string { return codes() }

// Render writes fs for `precinto doctor`: one line per finding
// ("FAIL  code  message", the fix on the next line) and a summary line, or
// with asJSON the v1 document {"v":1,"worst":sev,"findings":[{"code",
// "severity","message","fix"}]}. Both sanitize every text again (a finding
// may come from the agent).
func Render(w io.Writer, fs []Finding, asJSON bool) error {
	if asJSON {
		return writeJSON(w, fs)
	}
	return writeHuman(w, fs)
}

// Worst returns the most severe severity among fs (OK when empty). The CLI
// exits 1 when it is Fail, 0 otherwise (SPEC §16.2; 2 is usage).
func Worst(fs []Finding) Severity { return worst(fs) }
