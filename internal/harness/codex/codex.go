package codex

import (
	"context"

	"github.com/Neorichi/precinto/internal/harness"
	"github.com/Neorichi/precinto/internal/paths"
)

// New returns the adapter.
func New() harness.Adapter { return newAdapter() }

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
func Classify(rel string) Class { return classify(rel) }

// GroupOf returns the SQLite group id of a home-relative path ("" if none).
func GroupOf(rel string) string { return groupOf(rel) }

// Seed describes how a per-root home is created and refreshed (D31, D44).
type Seed struct {
	UserHome string // ~/.codex (or the user's CODEX_HOME outside roots)
	// UserDefault reports that UserHome is the default ~/.codex (CODEX_HOME
	// unset or naming it): only there does SyncAuthBack create an auth.json
	// the user home lacks (D140).
	UserDefault bool
	RootHome    string // <base>/homes/codex/<root-id>
	// ForceConfig re-copies config.toml even when the home already has one
	// (`precinto codex sync-config`); hooks trust entries of the per-root
	// home are kept.
	ForceConfig bool
}

// PrepareHome creates RootHome 0700 if missing and seeds it: copies
// config.toml once (or again with ForceConfig), removing sqlite_home and
// log_dir keys, and at every call adds the [marketplaces.*] and
// [plugins.*] tables of the user's config.toml that RootHome's lacks
// (D99); synchronizes auth.json from UserHome when newer, never into a
// home that logged out, removing the other copy of logged-out credentials,
// and only with a UserHome that exists (D100); and symlinks plugins/ and
// skills/ to UserHome, moving a real directory Codex created there to
// <RootHome>.displaced/ first (never deleted, D99). It never touches
// content files.
func PrepareHome(ctx context.Context, s Seed) error { return prepareHome(ctx, s) }

// SyncAuthBack copies RootHome/auth.json to UserHome/auth.json atomically
// when it is newer and differs (token refresh), after the child exited; a
// logout on either side is never undone (D100). Into a user home that has
// no auth.json it copies only when UserDefault (D140).
func SyncAuthBack(ctx context.Context, s Seed) error { return syncAuthBack(ctx, s) }

// LaunchEnv returns the environment additions for a managed launch:
// CODEX_HOME, CODEX_SQLITE_HOME (= home) and TMPDIR (= <home>/precinto-tmp,
// so hook-output spills are sealed with the home, D44).
func LaunchEnv(rootHome string) []string { return launchEnv(rootHome) }

// HooksTrusted reports, read-only, whether Codex 0.154 runs precinto's
// hooks in home (UX10): config.toml enables a precinto plugin installed in
// home's plugins/cache, and has a [hooks.state."…"] entry for every hook of
// plugins/codex/hooks/codex.json whose trusted_hash equals the hash Codex
// computes for that hook's declaration and that is not disabled (D98).
// When the state is known but not trusted, err tells why: ErrPluginMissing
// (no such plugin) or ErrHooksModified (trusted for other declarations:
// Codex 0.154 skips them until reviewed again); nil means some hook is not
// trusted yet. known is false (with trusted false) when config.toml cannot
// be read or parsed — a read failure is also returned in err — and when
// entries with other hashes were written by a Codex newer than 0.154
// (they carry trusted_content_hash: that Codex may hash another way).
func HooksTrusted(home string) (trusted bool, known bool, err error) {
	return hooksTrusted(home)
}

// UserHome resolves the user's own Codex home (CODEX_HOME or ~/.codex) from e.
func UserHome(e paths.Env) (string, error) { return userHome(e) }

// ApplyPatchPaths extracts "*** Add File:", "*** Update File:" and
// "*** Move to:" paths from an apply_patch command, resolved against cwd
// (HA25). Only paths are returned.
func ApplyPatchPaths(patch []byte, cwd string) []string {
	return applyPatchPaths(patch, cwd)
}
