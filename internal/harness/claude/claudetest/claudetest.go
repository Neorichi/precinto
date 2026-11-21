package claudetest

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// Layout is a fake Claude installation.
type Layout struct {
	ConfigDir string
	TmpDir    string
	CacheDir  string
}

// Session describes a synthetic session.
type Session struct {
	SID       string
	Cwd       string
	Slug      string // projects/<Slug>; "" = derive a fixture slug
	Lines     int    // transcript records
	Subagents int
	Marker    string // unique marker text embedded in prompts/tool inputs
	NoNewline bool   // omit the trailing newline (crash simulation)
	MDWrites  []string
	PlanSlug  string
	ModTime   time.Time
}

// New creates the directory skeleton under dir.
func New(t testing.TB, dir string) *Layout {
	t.Helper()
	if dir == "" || !filepath.IsAbs(dir) {
		t.Fatalf("claudetest: New needs an absolute directory, got %q", dir)
	}
	dir = filepath.Clean(dir)
	// The names of the fake HOME conventions (docs/TESTPLAN.md §2).
	l := &Layout{
		ConfigDir: filepath.Join(dir, "claude"),
		TmpDir:    filepath.Join(dir, "claude-tmp"),
		CacheDir:  filepath.Join(dir, "cache", "claude-cli-nodejs"),
	}
	mkdirs(t, dir, filepath.Join(l.ConfigDir, "projects"))
	mkdirs(t, dir, filepath.Join(l.ConfigDir, "sessions"))
	mkdirs(t, dir, l.TmpDir)
	mkdirs(t, dir, l.CacheDir)
	// $TMP must be the user's and 0700, or precinto refuses it (SPEC §7.0).
	if err := os.Chmod(l.TmpDir, dirPerm); err != nil {
		t.Fatalf("claudetest: chmod %s: %v", l.TmpDir, err)
	}
	return l
}

// WriteSession writes the session files and returns every path created.
func (l *Layout) WriteSession(t testing.TB, s Session) []string {
	t.Helper()
	return newSessionWriter(t, l, s).write()
}

// AppendFragment simulates Claude recreating <sid>.jsonl after a move (E8):
// lines whose first parentUuid points into the original.
func (l *Layout) AppendFragment(t testing.TB, s Session, lines int) string {
	t.Helper()
	return appendFragment(t, l, s, lines)
}

// WriteRegistry writes sessions/<pid>.json (valid=false writes a truncated file).
func (l *Layout) WriteRegistry(t testing.TB, pid int, sid, cwd, status string, valid bool) string {
	t.Helper()
	return writeRegistry(t, l, pid, sid, cwd, status, valid)
}

// WriteHistory appends history.jsonl lines for (project, sid).
func (l *Layout) WriteHistory(t testing.TB, project, sid string, n int, marker string) {
	t.Helper()
	writeHistory(t, l, project, sid, n, marker)
}

// WriteJob writes jobs/<id>/state.json for a background session.
func (l *Layout) WriteJob(t testing.TB, id, sid, state string) {
	t.Helper()
	writeJob(t, l, id, sid, state)
}

// Appender simulates Claude's writer: open, append one record, close, every
// interval; recreates the file if it is missing. Stop ends it.
type Appender struct {
	stop       chan struct{}
	done       chan struct{}
	stopOnce   sync.Once
	reportOnce sync.Once

	t     testing.TB
	path  string
	every time.Duration
	nonce string

	// Owned by the writer (the test goroutine for the first record, then
	// the run goroutine); read by Stop after done is closed.
	head     chainHead // uuid of the last record written and the fields it repeats
	seq      int
	count    int
	failures int
	firstErr error
}

// StartAppender starts an appender on path.
func StartAppender(t testing.TB, path string, every time.Duration) *Appender {
	t.Helper()
	return startAppender(t, path, every)
}

// Stop stops the appender and returns the number of records written.
func (a *Appender) Stop() int { return a.stopAppender() }
