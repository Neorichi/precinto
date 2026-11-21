package journal

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/precinto/precinto/internal/fsx"
	"github.com/precinto/precinto/internal/fsx/failpoint"
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

// recordExt is the suffix of record files; temporaries start with a dot
// and are never listed by Pending.
const recordExt = ".json"

// maxRecordBytes bounds a record read (a unit with a million files still
// fits; anything larger is not a record precinto wrote).
const maxRecordBytes = 256 << 20

// Open returns the journal rooted at dir.
func Open(dir string) *Journal { return &Journal{Dir: dir} }

// Begin creates and persists a new record at PhasePrepared.
func (j *Journal) Begin(kind Kind, harness, unit string) (*Record, error) {
	// The record file is created exclusively: the bytes go to a hidden
	// temporary that is FullSynced and then hard-linked to <id>.json
	// (link(2) fails if the name exists), so a record is either absent or
	// complete — a crash never leaves a torn record behind. A pending
	// record for the same non-empty unit makes Begin return ErrConflict
	// (callers hold the unit lock, so the check is not racy between
	// precinto processes).
	if j == nil || j.Dir == "" {
		return nil, errors.New("journal: no directory")
	}
	if err := ensureDir(j.Dir); err != nil {
		return nil, err
	}
	if unit != "" {
		// Unreadable records cannot name a unit we could compare: they are
		// reported by Pending to recovery, not used to block new work.
		pending, _ := j.Pending()
		for _, p := range pending {
			if p.Unit == unit {
				return nil, fmt.Errorf("%w (%s, record %s)", ErrConflict, p.Kind, p.ID)
			}
		}
	}
	now := time.Now().UTC()
	r := &Record{
		V: Version, ID: NewID(), Kind: kind, Unit: unit, Harness: harness,
		Phase: PhasePrepared, PID: os.Getpid(), Started: now, Updated: now,
	}
	if err := failpoint.Hit("journal.save"); err != nil {
		return nil, err
	}
	data, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}
	if err := createExclusive(j.Dir, r.ID+recordExt, data); err != nil {
		return nil, err
	}
	return r, nil
}

// Save persists r as is (FullSync of the record and its directory); used
// for progress within a phase (Files[i].Done, Offset, Pending).
func (j *Journal) Save(r *Record) error {
	if j == nil || r == nil {
		return errors.New("journal: nil record")
	}
	if !validID(r.ID) {
		return fmt.Errorf("journal: invalid record id %q", r.ID)
	}
	if err := failpoint.Hit("journal.save"); err != nil {
		return err
	}
	r.V = Version
	r.Updated = time.Now().UTC()
	data, err := json.Marshal(r)
	if err != nil {
		return err
	}
	return fsx.WriteFileAtomic(filepath.Join(j.Dir, r.ID+recordExt), data, 0o600)
}

// Advance sets r.Phase = p and persists it. Call it AFTER the step named by
// p has completed and is durable (phases are milestones, D58).
func (j *Journal) Advance(r *Record, p Phase) error {
	if r == nil {
		return errors.New("journal: nil record")
	}
	old := r.Phase
	r.Phase = p
	if err := j.Save(r); err != nil {
		r.Phase = old // the record on disk still names the previous milestone
		return err
	}
	return nil
}

// Done removes the record (fsync of the directory).
func (j *Journal) Done(r *Record) error {
	if j == nil || r == nil {
		return errors.New("journal: nil record")
	}
	if !validID(r.ID) {
		return fmt.Errorf("journal: invalid record id %q", r.ID)
	}
	err := os.Remove(filepath.Join(j.Dir, r.ID+recordExt))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	r.Phase = PhaseDone
	return fsx.SyncDir(j.Dir)
}

// Pending lists unfinished records, oldest first.
func (j *Journal) Pending() ([]*Record, error) {
	// Records that cannot be read or decoded are reported in the returned
	// error (joined, one per file) while every readable record is still
	// returned, so recovery proceeds with what it can and callers that
	// must know every in-flight operation (Quarantine) can refuse to act.
	// A missing directory means no pending record.
	if j == nil || j.Dir == "" {
		return nil, errors.New("journal: no directory")
	}
	ents, err := os.ReadDir(j.Dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []*Record
	var bad []error
	for _, de := range ents {
		name := de.Name()
		id, ok := strings.CutSuffix(name, recordExt)
		if !ok || !validID(id) {
			continue // temporaries and foreign files
		}
		r, err := readRecord(filepath.Join(j.Dir, name))
		if err != nil {
			bad = append(bad, fmt.Errorf("journal: record %s: %w", id, err))
			continue
		}
		if r.ID != id {
			bad = append(bad, fmt.Errorf("journal: record %s names id %q", id, r.ID))
			continue
		}
		if r.Phase == PhaseDone {
			continue // finished; only its removal was interrupted
		}
		out = append(out, r)
	}
	sort.SliceStable(out, func(a, b int) bool { return out[a].ID < out[b].ID })
	return out, errors.Join(bad...)
}

// readRecord reads one record without following symlinks.
func readRecord(path string) (*Record, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := fsx.Fstat(f)
	if err != nil {
		return nil, err
	}
	if !st.IsRegular() {
		return nil, fmt.Errorf("%w: not a regular file", fsx.ErrUnsafe)
	}
	data, err := io.ReadAll(io.LimitReader(f, maxRecordBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxRecordBytes {
		return nil, errors.New("record too large")
	}
	var r Record
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// idState makes NewID strictly increasing within a process even when the
// wall clock does not move between calls (or steps back).
var idState struct {
	sync.Mutex
	last int64
}

// NewID returns a sortable unique operation id.
func NewID() string {
	// The id is 16 hex digits of the creation time in nanoseconds
	// (strictly increasing within a process), a dash and 8 random hex
	// digits, so ids of concurrent processes do not collide and sort by
	// creation time.
	idState.Lock()
	n := time.Now().UnixNano()
	if n <= idState.last {
		n = idState.last + 1
	}
	idState.last = n
	idState.Unlock()
	var rnd [4]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		// crypto/rand never fails on supported systems; fall back to the
		// pid so the id stays unique per process.
		pid := uint32(os.Getpid())
		rnd = [4]byte{byte(pid >> 24), byte(pid >> 16), byte(pid >> 8), byte(pid)}
	}
	return fmt.Sprintf("%016x-%s", uint64(n), hex.EncodeToString(rnd[:]))
}

// validID reports whether id has the form NewID produces (it is used as a
// file name, so nothing else is ever accepted).
func validID(id string) bool {
	if len(id) != 25 || id[16] != '-' {
		return false
	}
	for i, c := range id {
		if i == 16 {
			continue
		}
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// ensureDir creates dir (0700) if missing and requires a private
// directory owned by the current user that is not a symlink.
func ensureDir(dir string) error {
	st, err := fsx.Lstat(dir)
	if errors.Is(err, fs.ErrNotExist) {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
		st, err = fsx.Lstat(dir)
	}
	if err != nil {
		return err
	}
	if !st.IsDir() {
		return fmt.Errorf("%w: journal directory is not a directory", fsx.ErrUnsafe)
	}
	if int(st.UID) != os.Getuid() || st.Mode&0o077 != 0 {
		return fmt.Errorf("%w: journal directory is not private", fsx.ErrUnsafe)
	}
	return nil
}

// createExclusive writes data to dir/name, failing if the name exists. The
// data is FullSynced in a hidden temporary which is then hard-linked to the
// final name, so the record appears atomically and completely.
func createExclusive(dir, name string, data []byte) error {
	var f *os.File
	var tmp string
	for i := 0; ; i++ {
		tmp = filepath.Join(dir, "."+name+".tmp-"+strconv.Itoa(os.Getpid())+"-"+strconv.Itoa(i))
		var err error
		f, err = os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
		if err == nil {
			break
		}
		if !errors.Is(err, fs.ErrExist) || i >= 100 {
			return err
		}
	}
	defer os.Remove(tmp)
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := fsx.FullSync(f); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Link(tmp, filepath.Join(dir, name)); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return fmt.Errorf("%w: %s", fsx.ErrExist, name)
		}
		return err
	}
	if err := os.Remove(tmp); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return fsx.SyncDir(dir)
}
