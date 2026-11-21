package codex

import (
	"context"

	"github.com/precinto/precinto/internal/harness"
	"github.com/precinto/precinto/internal/paths"
)

// New returns the adapter.
func New() harness.Adapter { panic("unimplemented: codex.New") }

// Class is how a file below a per-root home is treated.
type Class string

// Classes.
const (
	ClassContent    Class = "content"     // sealed (everything not in never_touch: fail-closed, HA24)
	ClassNeverTouch Class = "never-touch" // auth.json, config.toml, plugins/, skills/, caches, locks…
	ClassSQLiteMain Class = "sqlite-main" // *_<N>.sqlite: group leader
	ClassSQLiteSide Class = "sqlite-side" // -wal / -journal: sealed and restored with the main file
	ClassSHM        Class = "shm"         // -shm: never sealed, never restored, moved to quarantine on restore
)

// Classify returns the class of a home-relative path.
func Classify(rel string) Class { panic("unimplemented: codex.Classify") }

// GroupOf returns the SQLite group id of a home-relative path ("" if none).
func GroupOf(rel string) string { panic("unimplemented: codex.GroupOf") }

// Seed describes how a per-root home is created and refreshed (D31, D44).
type Seed struct {
	UserHome string // ~/.codex (or the user's CODEX_HOME outside roots)
	RootHome string // <base>/homes/codex/<root-id>
	// ForceConfig re-copies config.toml even when the home already has one
	// (`precinto codex sync-config`); hooks trust entries of the per-root
	// home are kept.
	ForceConfig bool
}

// PrepareHome creates RootHome 0700 if missing and seeds it: copies
// config.toml once (or again with ForceConfig), removing sqlite_home and
// log_dir keys; synchronizes auth.json from UserHome when newer; and
// symlinks plugins/ and skills/ to UserHome. It never touches content
// files.
func PrepareHome(ctx context.Context, s Seed) error { panic("unimplemented: codex.PrepareHome") }

// SyncAuthBack copies RootHome/auth.json to UserHome/auth.json atomically
// when it is newer and differs (token refresh), after the child exited.
func SyncAuthBack(ctx context.Context, s Seed) error { panic("unimplemented: codex.SyncAuthBack") }

// LaunchEnv returns the environment additions for a managed launch:
// CODEX_HOME, CODEX_SQLITE_HOME (= home) and TMPDIR (= <home>/precinto-tmp,
// so hook-output spills are sealed with the home, D44).
func LaunchEnv(rootHome string) []string { panic("unimplemented: codex.LaunchEnv") }

// HooksTrusted reports, read-only, whether config.toml of home has a
// [hooks.state."…"] trusted_hash entry for every precinto hook (UX10).
func HooksTrusted(home string) (trusted bool, known bool, err error) {
	panic("unimplemented: codex.HooksTrusted")
}

// UserHome resolves the user's own Codex home (CODEX_HOME or ~/.codex) from e.
func UserHome(e paths.Env) (string, error) { panic("unimplemented: codex.UserHome") }

// ApplyPatchPaths extracts "*** Add File:", "*** Update File:" and
// "*** Move to:" paths from an apply_patch command, resolved against cwd
// (HA25). Only paths are returned.
func ApplyPatchPaths(patch []byte, cwd string) []string {
	panic("unimplemented: codex.ApplyPatchPaths")
}
