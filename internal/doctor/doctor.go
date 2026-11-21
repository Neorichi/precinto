package doctor

import (
	"context"

	"github.com/precinto/precinto/internal/config"
	"github.com/precinto/precinto/internal/ipc"
	"github.com/precinto/precinto/internal/paths"
	"github.com/precinto/precinto/internal/platform"
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
	CheckHistoryPending    = ipc.AttnHistoryPending
	CheckVaultTampered     = ipc.AttnVaultTampered
	CheckExposed           = ipc.AttnExposed
	CheckUngatedSession    = ipc.AttnUngatedSession
	CheckConflict          = ipc.AttnConflict
)

// Finding is one result.
type Finding struct {
	Code     string
	Severity Severity
	Message  string // one line, content-free
	Fix      string // command or setting that fixes it
}

// Options configures Run.
type Options struct {
	Cfg     config.Config
	Layout  paths.Layout
	Env     paths.Env
	Procs   platform.ProcTable
	Leaks   bool   // also scan residue locations (slow)
	Harness string // limit to one harness
}

// Run executes every applicable check.
func Run(ctx context.Context, o Options) ([]Finding, error) { panic("unimplemented: doctor.Run") }

// Codes lists every check code in display order.
func Codes() []string { panic("unimplemented: doctor.Codes") }
