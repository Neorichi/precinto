package claudetest

import (
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
func New(t testing.TB, dir string) *Layout { panic("unimplemented: claudetest.New") }

// WriteSession writes the session files and returns every path created.
func (l *Layout) WriteSession(t testing.TB, s Session) []string {
	panic("unimplemented: claudetest.Layout.WriteSession")
}

// AppendFragment simulates Claude recreating <sid>.jsonl after a move (E8):
// lines whose first parentUuid points into the original.
func (l *Layout) AppendFragment(t testing.TB, s Session, lines int) string {
	panic("unimplemented: claudetest.Layout.AppendFragment")
}

// WriteRegistry writes sessions/<pid>.json (valid=false writes a truncated file).
func (l *Layout) WriteRegistry(t testing.TB, pid int, sid, cwd, status string, valid bool) string {
	panic("unimplemented: claudetest.Layout.WriteRegistry")
}

// WriteHistory appends history.jsonl lines for (project, sid).
func (l *Layout) WriteHistory(t testing.TB, project, sid string, n int, marker string) {
	panic("unimplemented: claudetest.Layout.WriteHistory")
}

// WriteJob writes jobs/<id>/state.json for a background session.
func (l *Layout) WriteJob(t testing.TB, id, sid, state string) {
	panic("unimplemented: claudetest.Layout.WriteJob")
}

// Appender simulates Claude's writer: open, append one record, close, every
// interval; recreates the file if it is missing. Stop ends it.
type Appender struct {
	stop chan struct{}
}

// StartAppender starts an appender on path.
func StartAppender(t testing.TB, path string, every time.Duration) *Appender {
	panic("unimplemented: claudetest.StartAppender")
}

// Stop stops the appender and returns the number of records written.
func (a *Appender) Stop() int { panic("unimplemented: claudetest.Appender.Stop") }
