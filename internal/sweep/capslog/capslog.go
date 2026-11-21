package capslog

import (
	"errors"
	"time"
)

// Version is the line format.
const Version = 1

// ErrNotLogged means the capsule has no matching log entry (exit 5).
var ErrNotLogged = errors.New("capslog: capsule not in the provenance log")

// Entry is one log line.
type Entry struct {
	V             int       `json:"v"`
	Path          string    `json:"path"`          // relative to CapsulesDir, e.g. "claude-code/<unit>/g000003.pcap"
	SHA256        string    `json:"sha256"`        // whole ciphertext
	HeaderSHA256  string    `json:"header_sha256"` // age header: provenance key for key release (D39)
	Size          int64     `json:"size"`
	Kind          string    `json:"kind"`
	Harness       string    `json:"harness"`
	Unit          string    `json:"unit"`     // unit key
	VaultID       string    `json:"vault_id"` // sealing vault
	RootIDs       []string  `json:"root_ids"` // all must be unlocked for key release
	Gen           uint64    `json:"gen"`
	Parent        uint64    `json:"parent"`
	Lineage       string    `json:"lineage"`
	Snapshot      bool      `json:"snapshot,omitempty"` // codex-home: restore newest only (D42)
	Blob          bool      `json:"blob,omitempty"`
	SealedAt      time.Time `json:"sealed_at"`
	RecipientsFpr string    `json:"recipients_fpr"`
	Files         int       `json:"files"`
	Bytes         int64     `json:"bytes"` // plaintext total (restore free-space planning)
	LastActivity  time.Time `json:"last_activity,omitempty"`
	// Deleted marks a later "forget"/"prune" record for Path (append-only log).
	Deleted bool `json:"deleted,omitempty"`
}

// Log is the provenance log file.
type Log struct {
	Path string
}

// Open returns the log at path.
func Open(path string) *Log { panic("unimplemented: capslog.Open") }

// Append writes e as one line (fsx.AppendLine, FullSync).
func (l *Log) Append(e Entry) error { panic("unimplemented: capslog.Log.Append") }

// Lookup returns the live (not deleted) entry for path whose HeaderSHA256
// equals headerSHA256; ErrNotLogged otherwise.
func (l *Log) Lookup(path, headerSHA256 string) (Entry, error) {
	panic("unimplemented: capslog.Log.Lookup")
}

// Unit returns the live entries of a unit, ordered by Gen.
func (l *Log) Unit(unit string) ([]Entry, error) { panic("unimplemented: capslog.Log.Unit") }

// All returns every live entry (deleted ones folded away).
func (l *Log) All() ([]Entry, error) { panic("unimplemented: capslog.Log.All") }

// MarkDeleted appends a deletion record for path.
func (l *Log) MarkDeleted(path string, at time.Time) error {
	panic("unimplemented: capslog.Log.MarkDeleted")
}

// Compact rewrites the log without deleted entries (atomic; only under the
// sweep lock).
func (l *Log) Compact() error { panic("unimplemented: capslog.Log.Compact") }
