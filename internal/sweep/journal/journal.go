package journal

import (
	"errors"
	"time"

	"github.com/precinto/precinto/internal/fsx"
)

// Version is the record format.
const Version = 1

// ErrConflict is returned when another record already covers the unit.
var ErrConflict = errors.New("journal: operation already in flight for this unit")

// Kind is the operation type.
type Kind string

// Operation kinds.
const (
	KindSeal          Kind = "seal"           // SPEC §10.3
	KindRestore       Kind = "restore"        // SPEC §11.5
	KindCodexSnapshot Kind = "codex-snapshot" // SPEC §7.2
	KindCodexRestore  Kind = "codex-restore"
	KindHistoryRotate Kind = "history-rotate" // SPEC §7.1.4
	KindHistoryMerge  Kind = "history-merge"
	KindMarkdown      Kind = "md"
	KindPrune         Kind = "prune"
)

// Phase is a completed, durable milestone: a record is advanced to a phase
// only after the step that phase names has finished and is durable, so
// recovery always acts on the last milestone reached (D58).
type Phase string

// Phases (each operation uses the subset listed in SPEC §10.3/§11.5/§7.1.4).
const (
	PhasePrepared   Phase = "prepared"    // sources snapshotted, generation reserved, Tmp and final Capsule name recorded
	PhaseTmpWritten Phase = "tmp_written" // capsule temporary written and FullSynced (not yet renamed or logged)
	PhaseCommitted  Phase = "committed"   // generation renamed no-replace, directory fsynced AND appended to the capsule log
	PhaseUnlinking  Phase = "unlinking"   // deleting originals (identity-checked); Files[i].Done marks progress
	PhaseRescue     Phase = "rescue"      // a late tail is being sealed into a rescue generation
	PhaseStaged     Phase = "staged"      // restore: unit decrypted into staging and verified
	PhasePlacing    Phase = "placing"     // restore: no-replace renames in progress; Files[i].Done marks progress
	PhaseHeld       Phase = "held"        // history: hold link created (HoldSize = S0)
	PhaseSealed     Phase = "sealed"      // history: extracted lines of [0, Pending) committed as generations
	PhaseRewritten  Phase = "rewritten"   // history: filtered file renamed in; Offset = S1, NewBase set
	PhaseDone       Phase = "done"
)

// File is one source or target recorded in a journal (no content).
type File struct {
	Base string   `json:"base"`
	Rel  string   `json:"rel"`
	Snap fsx.Stat `json:"snap"`
	Done bool     `json:"done,omitempty"` // unlinked / placed
}

// Record is state/journal/<id>.json.
type Record struct {
	V        int       `json:"v"`
	ID       string    `json:"id"` // ULID-like, sortable
	Kind     Kind      `json:"kind"`
	Unit     string    `json:"unit"` // unit key
	Harness  string    `json:"harness"`
	Phase    Phase     `json:"phase"`
	PID      int       `json:"pid"`
	Started  time.Time `json:"started"`
	Updated  time.Time `json:"updated"`
	Tmp      string    `json:"tmp,omitempty"`     // capsule temp name (relative to the unit capsule dir)
	Capsule  string    `json:"capsule,omitempty"` // final capsule name (g<N>.pcap), recorded at PhasePrepared, BEFORE the rename
	Gen      uint64    `json:"gen,omitempty"`
	Files    []File    `json:"files,omitempty"`
	Staging  string    `json:"staging,omitempty"` // absolute staging dir
	Hold     string    `json:"hold,omitempty"`    // history hold link name
	HoldSize int64     `json:"hold_size,omitempty"`
	// History rotation offsets in the hold inode (SPEC §7.1.4): Offset is
	// the end of the bytes fully processed (kept lines in the new file and
	// extracted lines sealed); Pending is the end of the range being
	// processed (> Offset while an iteration is in flight); NewBase is the
	// size of the rewritten history.jsonl right after the rename (tail
	// appends skip kept lines already present after it, so a re-run never
	// appends a line twice).
	Offset  int64    `json:"offset,omitempty"`
	Pending int64    `json:"pending,omitempty"`
	NewBase int64    `json:"new_base,omitempty"`
	Notes   []string `json:"notes,omitempty"` // content-free diagnostics
}

// Journal is the directory state/journal.
type Journal struct {
	Dir string
}

// Open returns the journal rooted at dir.
func Open(dir string) *Journal { panic("unimplemented: journal.Open") }

// Begin creates and persists a new record at PhasePrepared.
func (j *Journal) Begin(kind Kind, harness, unit string) (*Record, error) {
	panic("unimplemented: journal.Journal.Begin")
}

// Save persists r as is (FullSync of the record and its directory); used
// for progress within a phase (Files[i].Done, Offset, Pending).
func (j *Journal) Save(r *Record) error { panic("unimplemented: journal.Journal.Save") }

// Advance sets r.Phase = p and persists it. Call it AFTER the step named by
// p has completed and is durable (phases are milestones, D58).
func (j *Journal) Advance(r *Record, p Phase) error { panic("unimplemented: journal.Journal.Advance") }

// Done removes the record (fsync of the directory).
func (j *Journal) Done(r *Record) error { panic("unimplemented: journal.Journal.Done") }

// Pending lists unfinished records, oldest first.
func (j *Journal) Pending() ([]*Record, error) { panic("unimplemented: journal.Journal.Pending") }

// NewID returns a sortable unique operation id.
func NewID() string { panic("unimplemented: journal.NewID") }
