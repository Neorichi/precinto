package testkit

import (
	"testing"
	"time"

	"github.com/precinto/precinto/internal/config"
	"github.com/precinto/precinto/internal/paths"
	"github.com/precinto/precinto/internal/platform/fakeplatform"
)

// Home is a throwaway environment.
type Home struct {
	Dir          string // t.TempDir()
	HomeDir      string // Dir/home (HOME)
	Base         string // PRECINTO_HOME
	RunDir       string // short dir under /tmp (PRECINTO_RUNTIME_DIR)
	ClaudeConfig string // CLAUDE_CONFIG_DIR
	ClaudeTmp    string // CLAUDE_CODE_TMPDIR
	ClaudeCache  string // XDG/Library cache for claude-cli-nodejs
	CodexUser    string // the user's CODEX_HOME (never ~/.codex)
	Root         string // a protected root (HomeDir/work/acme)
	Env          paths.Env
	Layout       paths.Layout
	Cfg          config.Config
	Clock        *fakeplatform.Clock
	Procs        *fakeplatform.Procs
}

// NewHome creates the directories, writes config.toml with Root protected
// (id "root-acme"), and registers cleanup. It does not touch the process
// environment; call Setenv for tests that exec the binary.
func NewHome(t testing.TB) *Home {
	t.Helper()
	return newHome(t)
}

// Setenv sets every variable of h.Env on the test process (t.Setenv).
func (h *Home) Setenv(t testing.TB) {
	t.Helper()
	h.setenv(t)
}

// Protect adds another root and returns it.
func (h *Home) Protect(t testing.TB, rel string) config.Root {
	t.Helper()
	return h.protect(t, rel)
}

// ShortTempDir returns a fresh directory with a short absolute path (macOS
// t.TempDir paths exceed the 104-byte socket limit).
func ShortTempDir(t testing.TB) string {
	t.Helper()
	return shortTempDir(t)
}

// Epoch is the fixed wall time fake clocks start at.
var Epoch = time.Date(2026, 11, 21, 9, 0, 0, 0, time.UTC)

// Golden compares got with testdata/<name> (rewritten with -update).
func Golden(t testing.TB, name string, got []byte) {
	t.Helper()
	golden(t, name, got)
}

// Hygiene fails if any file below dir contains $HOME-like paths, emails,
// tokens, or UUIDs that are not fixtures (S13).
func Hygiene(t testing.TB, dir string) {
	t.Helper()
	hygiene(t, dir)
}

// BuildBinary builds cmd/precinto with -tags testing(,failpoints) once per
// test binary and returns its path (integration and crash tests).
func BuildBinary(t testing.TB, tags ...string) string {
	t.Helper()
	return buildBinary(t, "./cmd/precinto", tags)
}

// Marker returns a unique marker string for leak greps.
func Marker(t testing.TB) string {
	t.Helper()
	return marker(t)
}

// GrepTree reports files under dir containing marker (content leak check).
func GrepTree(t testing.TB, dir, marker string, exclude ...string) []string {
	t.Helper()
	return grepTree(t, dir, marker, exclude)
}
