package testkit

import (
	"syscall"
	"testing"
	"time"

	"github.com/Neorichi/precinto/internal/config"
	"github.com/Neorichi/precinto/internal/paths"
	"github.com/Neorichi/precinto/internal/platform"
	"github.com/Neorichi/precinto/internal/platform/fakeplatform"
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
// t.TempDir paths exceed the 104-byte socket limit), removed when the test
// ends; a process the test started that still writes there is waited for
// first (Settle), and reported when it outlives the wait.
func ShortTempDir(t testing.TB) string {
	t.Helper()
	return shortTempDir(t)
}

// Settle waits, at most timeout, until no process other than the test
// holds a file open below dirs: the daemons and binaries a test started,
// and the workers a daemon spawned (their log descriptor stays open while
// they live), write into the fake home until they exit, so a fake home is
// removed only after them (TESTPLAN §1.8). A process that runs one of exes
// while its open files cannot be read (on Linux a hardened precinto, D65)
// counts as writing there until it ends (D154). A process still writing
// then is a leak: Settle reports it with t.Errorf and kills it when it
// runs one of exes (binaries the test built, the only processes Settle
// ever signals). Call it after stopping a daemon the test started.
func Settle(t testing.TB, timeout time.Duration, exes []string, dirs ...string) {
	t.Helper()
	settle(t, timeout, exes, dirs)
}

// StopInstallation ends what a test's installation of the testing build
// left running, before its fake home is removed, and fails the test when
// something outlives it (TESTPLAN §1.8, D129): `bin agent --stop` with env
// (the installation's environment: HOME, PRECINTO_HOME,
// PRECINTO_RUNTIME_DIR…) stops its agent, whose keys are wiped, and waits
// until it no longer answers; every other process that runs bin — the
// workers the agent spawned (sweep, seal --queue, restore), a stray CLI —
// gets a moment to end by itself, then SIGTERM; one that needs SIGKILL
// fails the test, and so does any process still running bin or naming a
// path below dirs in its arguments afterwards. Only processes running bin
// (a binary the test built) are ever signalled; on Linux a hardened one is
// known by its argv[0] and command name (ExeOf, D154). Register it with
// t.Cleanup right after creating the fake home, so it runs after the
// cleanups of the sessions the test started and before the home is
// removed.
func StopInstallation(t testing.TB, bin string, env []string, dirs ...string) {
	t.Helper()
	stopInstallation(t, bin, env, dirs)
}

// Leftovers describes ("pid name args…") the live processes, other than
// this one, that run bin or name a path below dirs in their arguments: what
// a test's installation left running.
func Leftovers(bin string, dirs ...string) []string { return describe(leftovers(bin, dirs)) }

// ExeOf returns the executable p runs: p.Exe, or, when the kernel hides it
// (on Linux a hardened precinto is not dumpable, so its /proc/<pid>/exe is
// refused, D65), its absolute argv[0] when the command name agrees,
// resolved like the kernel resolves it. That is best effort (D154); ""
// when neither is known.
func ExeOf(p platform.ProcInfo) string { return exeOf(p) }

// Epoch is the fixed wall time frozen fake clocks start at. Fixture times
// derive from the clock of the code under test (Epoch for h.Clock), never
// from a copy of the date; code that compares its clock with times the
// kernel stamps or another process checks runs on
// fakeplatform.NewRealClock instead (TESTPLAN §1.4, D77), so no test
// depends on today's date.
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
// test binary and returns its path (integration and crash tests). The
// binaries live in a directory of this test process below TMPDIR; the
// package's TestMain removes it with RemoveBinaries.
func BuildBinary(t testing.TB, tags ...string) string {
	t.Helper()
	return buildBinary(t, "./cmd/precinto", tags)
}

// RemoveBinaries deletes the directory of the binaries BuildBinary built
// in this process, so a test run leaves nothing in TMPDIR (TESTPLAN §1.8).
// A package that builds binaries calls it from TestMain after m.Run, when
// no test and no process the tests started still runs them; a later
// BuildBinary in the same process fails. Without it the next test process
// that builds removes the directory, as an abandoned one.
func RemoveBinaries() { removeBinaries() }

// Mkfifo creates a FIFO at path with mode perm (mkfifo(2)), for tests that
// check that a FIFO is refused without blocking. It fails where precinto
// does not run (D34).
func Mkfifo(path string, perm uint32) error { return mkfifo(path, perm) }

// NewSession returns the SysProcAttr that starts a child in a new session
// without a controlling terminal (setsid), so it can never prompt on the
// terminal running the tests; nil where precinto does not run (D34).
func NewSession() *syscall.SysProcAttr { return newSession() }

// KillGroup sends SIGKILL to every process of the process group pid leads
// (a child started with NewSession, or by pty.Start, leads its own session
// and group), so its descendants end with it. Where precinto does not run
// (D34) there is no such group: it kills the process pid alone. A pid
// below 2 is refused: kill(2) would read it as "every process" or as the
// caller's own group. A test only kills groups it started.
func KillGroup(pid int) error { return killGroup(pid) }

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
