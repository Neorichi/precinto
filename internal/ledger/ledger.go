package ledger

import (
	"errors"
	"time"

	"github.com/Neorichi/precinto/internal/config"
	"github.com/Neorichi/precinto/internal/platform"
)

// Version is the ledger line format.
const Version = 1

// ErrNotFound means no ledger exists for the session.
var ErrNotFound = errors.New("ledger: no such session")

// Type is the kind of a ledger event.
type Type string

// Event types.
const (
	TypeLaunch       Type = "launch"        // wrapper, before exec (carries the lease and homes)
	TypeStart        Type = "start"         // SessionStart (source)
	TypeTaint        Type = "taint"         // the session became managed by Roots (sticky)
	TypeCwd          Type = "cwd"           // CwdChanged / payload cwd changed
	TypeDir          Type = "dir"           // DirectoryAdded / --add-dir
	TypeTouch        Type = "touch"         // a tool path inside a root
	TypeMarkdown     Type = "md"            // an agent wrote a Markdown file (Path)
	TypeCompactBegin Type = "compact_begin" // PreCompact allowed
	TypeCompactEnd   Type = "compact_end"   // PostCompact / SessionStart(compact) / Stop / StopFailure / end
	TypeEnd          Type = "end"           // SessionEnd (Reason); the process may still be alive (R8)
	TypeHooksSeen    Type = "hooks_seen"    // first hook event of a wrapped session (hook health, UX10)
)

// Event is one JSON line of state/sessions/<harness>/<sid>.jsonl.
type Event struct {
	V              int             `json:"v"`
	T              time.Time       `json:"t"`
	Type           Type            `json:"type"`
	Harness        string          `json:"harness"`
	Host           string          `json:"host,omitempty"` // real host when a Claude-format hook runs elsewhere (HA21)
	SID            string          `json:"sid"`
	Proc           platform.ProcID `json:"proc,omitempty"` // harness process, measured by precinto's own hook/wrapper process: liveness evidence only, never a reason to signal or release keys (SPEC §9.1)
	Wrapper        bool            `json:"wrapper,omitempty"`
	Cwd            string          `json:"cwd,omitempty"`
	ProjectDir     string          `json:"project_dir,omitempty"`
	Transcript     string          `json:"transcript,omitempty"` // as reported (SessionEnd's value is trusted over SessionStart's)
	ConfigDir      string          `json:"config_dir,omitempty"` // CLAUDE_CONFIG_DIR / CODEX_HOME realpath
	TmpDir         string          `json:"tmp_dir,omitempty"`    // payload scratchpad_dir's base, CLAUDE_CODE_TMPDIR
	Source         string          `json:"source,omitempty"`     // SessionStart source
	Reason         string          `json:"reason,omitempty"`     // SessionEnd reason
	Path           string          `json:"path,omitempty"`       // touch/md/dir path (absolute)
	Roots          []string        `json:"roots,omitempty"`      // root ids (taint)
	HarnessVersion string          `json:"harness_version,omitempty"`
	Entrypoint     string          `json:"entrypoint,omitempty"` // cli|sdk-cli|...
	Background     bool            `json:"background,omitempty"` // supervised/background session (D25)
	LeaseKey       string          `json:"lease_key,omitempty"`
}

// Ledger is the directory state/sessions.
type Ledger struct {
	Dir string
}

// Open returns the ledger rooted at dir.
func Open(dir string) *Ledger { return &Ledger{Dir: dir} }

// Append writes e (V and T filled if zero) with fsx.AppendLine. It creates
// the session file on the first event.
func (l *Ledger) Append(e Event) error { return l.appendEvent(e) }

// Session is the folded view of one session's events.
type Session struct {
	Harness     string
	SID         string
	Procs       []platform.ProcID // every process that ran the session, oldest first
	CurrentProc platform.ProcID   // last process with a start/launch event
	RootIDs     []string          // sticky managed roots (taint), first = primary
	Cwds        []string
	Dirs        []string
	Markdown    []string // absolute paths of agent-written Markdown
	ConfigDirs  []string
	TmpDirs     []string
	Transcript  string
	Started     time.Time
	LastEvent   time.Time
	Ended       bool
	EndReason   string // clear|resume|logout|prompt_input_exit|other
	EndProc     platform.ProcID
	Compacting  bool
	CompactAt   time.Time
	Wrapper     bool
	HooksSeen   bool
	Background  bool
	Version     string
	Entrypoint  string
}

// Managed reports whether the session has at least one managed root.
func (s Session) Managed() bool { return len(s.RootIDs) > 0 }

// Warm reports whether the session is non-current for a process that may
// still be alive: its latest end has reason clear|resume, or that process
// has a newer start (D20). Such a unit becomes sealable once stable.
func (s Session) Warm() bool {
	return s.Ended && (s.EndReason == "clear" || s.EndReason == "resume")
}

// Get folds the ledger of one session.
func (l *Ledger) Get(harness, sid string) (Session, error) { return l.get(harness, sid) }

// List folds every session ledger of harness.
func (l *Ledger) List(harness string) ([]Session, error) { return l.list(harness) }

// ByProc returns the sessions whose CurrentProc is id (D20: a process that
// moved to another session no longer owns the old one).
func (l *Ledger) ByProc(harness string, id platform.ProcID) ([]Session, error) {
	return l.byProc(harness, id)
}

// Snapshot returns the raw ledger bytes of a session and their length n,
// read once without modifying the file, for capsule.Manifest.Ledger before
// the seal (SPEC §10.3 step 4).
func (l *Ledger) Snapshot(harness, sid string) (raw []byte, n int64, err error) {
	return l.snapshot(harness, sid)
}

// Archive is called after the generation holding a Snapshot of length n is
// committed (S13, SPEC §10.3 step 8): it removes the session file if it
// still has length n; if events were appended after the snapshot it
// atomically keeps only the bytes after n (they go into the next
// generation), so no event is lost.
func (l *Ledger) Archive(harness, sid string, n int64) error {
	return l.archive(harness, sid, n)
}

// Taint computes the roots a set of directories and paths touch: every root
// of c containing any of them (deepest first). Hooks pass start cwd,
// CLAUDE_PROJECT_DIR, payload cwd, added dirs and tool paths (HA10).
// Implemented in the scaffold as c.RootsFor.
func Taint(c config.Config, dirsAndPaths ...string) []config.Root {
	return c.RootsFor(dirsAndPaths...)
}

// Project maps a harness project directory (Claude slug) to the cwds seen
// in it and their roots (IM12). Slugs are never computed by precinto.
type Project struct {
	Harness   string   `json:"harness"`
	ConfigDir string   `json:"config_dir"`
	Slug      string   `json:"slug"` // actual directory name under projects/
	Cwds      []string `json:"cwds"`
	RootIDs   []string `json:"root_ids"`
	MemoryDir string   `json:"memory_dir,omitempty"` // auto-memory dir used by sessions of this project (HA14)
}

// Index is the project index state/projects/<harness>.json.
type Index struct {
	Path string
}

// OpenIndex returns the index file of harness under dir.
func OpenIndex(dir, harness string) *Index { return openIndex(dir, harness) }

// Put merges p into the index atomically.
func (x *Index) Put(p Project) error { return x.put(p) }

// All returns every project.
func (x *Index) All() ([]Project, error) { return x.all() }

// Lookup returns the project of (configDir, slug).
func (x *Index) Lookup(configDir, slug string) (Project, bool, error) {
	return x.lookup(configDir, slug)
}
