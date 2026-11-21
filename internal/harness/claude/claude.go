package claude

import (
	"context"
	"io"
	"time"

	"github.com/precinto/precinto/internal/config"
	"github.com/precinto/precinto/internal/harness"
)

// New returns the adapter.
func New() harness.Adapter { panic("unimplemented: claude.New") }

// RegistryEntry is one ~/.claude/sessions/<pid>.json (Claude's live-session
// registry). Fields are read best-effort; Valid=false means the file was
// unreadable, half-written or of an unknown schema (treat its pid's
// sessions as live, R8, D18).
type RegistryEntry struct {
	Path       string
	PID        int
	SessionID  string
	Cwd        string
	Status     string // "busy" | "idle" | ""
	WaitingFor string // non-empty: permission/elicitation pending (counts as idle, HA7)
	Kind       string // "interactive" | background kinds
	Entrypoint string // "cli" | "sdk-cli" | ...
	StartedAt  time.Time
	Mtime      time.Time
	Valid      bool
}

// ReadRegistry reads every registry file of a config dir.
func ReadRegistry(configDir string) ([]RegistryEntry, error) {
	panic("unimplemented: claude.ReadRegistry")
}

// Busy reports whether an entry says the session is mid-turn (status busy
// and WaitingFor empty, HA7).
func (r RegistryEntry) Busy() bool { panic("unimplemented: claude.RegistryEntry.Busy") }

// Job is a background/supervised session record ($CC/jobs/<id>/state.json).
type Job struct {
	ID        string
	SessionID string
	State     string // running|stopped|...
	Valid     bool   // false: unknown schema ⇒ live
}

// ReadJobs reads job records of a config dir (D25, R11).
func ReadJobs(configDir string) ([]Job, error) { panic("unimplemented: claude.ReadJobs") }

// HistoryLine is the content-free view of one history.jsonl line; Raw is
// kept only in memory while rotating and is sealed, never logged.
type HistoryLine struct {
	Raw       []byte
	Project   string
	SessionID string
	Timestamp time.Time
	PasteRefs []string // paste-cache entry names referenced by pastedContents
	Valid     bool
}

// ParseHistoryLine parses one line without retaining anything but the
// fields above.
func ParseHistoryLine(b []byte) HistoryLine { panic("unimplemented: claude.ParseHistoryLine") }

// TranscriptFacts are paths and ids found in a transcript (never content).
type TranscriptFacts struct {
	Cwds       []string // every distinct `cwd` key
	Slug       string   // plan slug (`slug` key)
	MDPaths    []string // Write/Edit/MultiEdit/NotebookEdit tool_use file paths ending in .md/.mdx/.markdown
	ForkRefs   []string // parent session ids from fork-context-ref lines (R21)
	CopiedSIDs []string // other sessionIds present in copied lines
	Title      string   // last custom-title, else last ai-title, else first prompt (bounded)
	LastAt     time.Time
	Uuids      int  // number of records with a uuid (merge checks)
	TrailingNL bool // the file ends with '\n'
}

// ScanTranscript streams a transcript and extracts TranscriptFacts.
func ScanTranscript(ctx context.Context, path string) (TranscriptFacts, error) {
	panic("unimplemented: claude.ScanTranscript")
}

// Links are the JSONL linkage facts the placement table needs (SPEC §11.3,
// D11): the uuid of every record, the first record's parentUuid and
// logicalParentUuid, and whether the stream ends with '\n'. They hold ids
// only, never content.
type Links struct {
	UUIDs              map[string]bool
	FirstParent        string
	FirstLogicalParent string
	Records            int
	TrailingNL         bool
	Valid              bool // false: a line did not parse (callers treat the pair as a conflict)
}

// ScanLinks streams a Claude transcript or subagent JSONL (the staged
// capsule version C or the existing file F) and returns its Links, so
// internal/sweep never parses Claude records itself.
func ScanLinks(ctx context.Context, r io.Reader) (Links, error) {
	panic("unimplemented: claude.ScanLinks")
}

// SettingsJSON returns the inline JSON passed with --settings for managed
// launches (D32, HA12): idleCompaction=false, awaySummaryEnabled=false,
// precomputeCompactionEnabled=false.
func SettingsJSON(p config.Policy) string { panic("unimplemented: claude.SettingsJSON") }

// ParseResume classifies Claude resume flags (argv excludes argv[0]).
func ParseResume(args []string) harness.Resume { panic("unimplemented: claude.ParseResume") }

// CleanupPeriodDays returns Claude's effective cleanupPeriodDays from the
// user settings of configDir (default 30) for the retention rules of D14.
func CleanupPeriodDays(configDir string) (int, error) {
	panic("unimplemented: claude.CleanupPeriodDays")
}
