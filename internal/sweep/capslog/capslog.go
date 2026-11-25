package capslog

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"sort"
	"sync"
	"syscall"
	"time"

	"github.com/Neorichi/precinto/internal/fsx"
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

// lockWait bounds how long an append waits for a Compact in progress.
const lockWait = 2 * time.Minute

// maxLogBytes bounds a log read (millions of entries); a larger file is
// refused rather than read into memory (FX-G4-20). A variable only so
// tests can lower it.
var maxLogBytes int64 = 1 << 30

// errTooLarge: the log is larger than maxLogBytes.
var errTooLarge = errors.New("capslog: capsule log too large")

// Open returns the log at path.
func Open(path string) *Log { return &Log{Path: path} }

// Append writes e as one line (fsx.AppendLine, FullSync).
func (l *Log) Append(e Entry) error {
	// Appends hold a shared flock on <path>.lock so that Compact, which
	// takes it exclusively, never renames a new log over a line appended
	// to the old one. A torn last line left by a crash is terminated first
	// (a bare '\n'), so it can never swallow the new entry.
	if l == nil || l.Path == "" {
		return errors.New("capslog: no log path")
	}
	if e.Path == "" {
		return errors.New("capslog: entry without a path")
	}
	if e.V == 0 {
		e.V = Version
	}
	line, err := json.Marshal(e)
	if err != nil {
		return err
	}
	lk, err := l.lock(true)
	if err != nil {
		return err
	}
	defer lk.Unlock()
	if err := l.terminateTornTail(); err != nil {
		return err
	}
	return fsx.AppendLine(l.Path, line)
}

// Lookup returns the live (not deleted) entry for path whose HeaderSHA256
// equals headerSHA256; ErrNotLogged otherwise.
func (l *Log) Lookup(path, headerSHA256 string) (Entry, error) {
	all, err := l.All()
	if err != nil {
		return Entry{}, err
	}
	for i := len(all) - 1; i >= 0; i-- {
		if all[i].Path == path && all[i].HeaderSHA256 == headerSHA256 && headerSHA256 != "" {
			return all[i], nil
		}
	}
	return Entry{}, ErrNotLogged
}

// Unit returns the live entries of a unit, ordered by Gen.
func (l *Log) Unit(unit string) ([]Entry, error) {
	all, err := l.All()
	if err != nil {
		return nil, err
	}
	var out []Entry
	for _, e := range all {
		if e.Unit == unit {
			out = append(out, e)
		}
	}
	sort.SliceStable(out, func(a, b int) bool { return out[a].Gen < out[b].Gen })
	return out, nil
}

// All returns every live entry (deleted ones folded away).
func (l *Log) All() ([]Entry, error) {
	// Lines are folded in file order: a deletion record removes the live
	// entry for its path, an entry repeated for the same path and header
	// (a re-append after a crash) counts once, and a later entry for a
	// path replaces an earlier one. A torn last line (no final newline)
	// and lines that do not decode are ignored: they can never add
	// provenance, only fail to record it, which is the safe direction (an
	// unlogged capsule is never restored, D8). Results are cached per file
	// identity.
	if l == nil || l.Path == "" {
		return nil, errors.New("capslog: no log path")
	}
	data, st, err := readLog(l.Path)
	if err != nil {
		return nil, err
	}
	if entries, ok := cached(l.Path, st); ok {
		return entries, nil
	}
	entries := fold(data)
	store(l.Path, st, entries)
	return copyEntries(entries), nil
}

// MarkDeleted appends a deletion record for path.
func (l *Log) MarkDeleted(path string, at time.Time) error {
	return l.Append(Entry{V: Version, Path: path, Deleted: true, SealedAt: at.UTC()})
}

// Compact rewrites the log without deleted entries (atomic; only under the
// sweep lock).
func (l *Log) Compact() error {
	// It holds the log lock exclusively while it rewrites, so no append
	// can be lost to the rename.
	if l == nil || l.Path == "" {
		return errors.New("capslog: no log path")
	}
	lk, err := l.lock(false)
	if err != nil {
		return err
	}
	defer lk.Unlock()
	data, _, err := readLog(l.Path)
	if err != nil {
		return err
	}
	var buf bytes.Buffer
	for _, e := range fold(data) {
		line, err := json.Marshal(e)
		if err != nil {
			return err
		}
		buf.Write(line)
		buf.WriteByte('\n')
	}
	if err := fsx.WriteFileAtomic(l.Path, buf.Bytes(), 0o600); err != nil {
		return err
	}
	invalidate(l.Path)
	return nil
}

// lock takes the log lock file (<path>.lock, never deleted).
func (l *Log) lock(shared bool) (*fsx.Lock, error) {
	ctx, cancel := context.WithTimeout(context.Background(), lockWait)
	defer cancel()
	lk, err := fsx.WaitLock(ctx, l.Path+".lock", shared)
	if err != nil {
		return nil, fmt.Errorf("capslog: lock: %w", err)
	}
	return lk, nil
}

// terminateTornTail appends a bare newline when the log does not end with
// one (a crash cut the previous append short).
func (l *Log) terminateTornTail() error {
	f, err := os.OpenFile(l.Path, os.O_RDONLY|fsx.ONoFollow|syscall.O_NONBLOCK, 0)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer f.Close()
	st, err := fsx.Fstat(f)
	if err != nil {
		return err
	}
	if !st.IsRegular() {
		return fmt.Errorf("%w: capsule log is not a regular file", fsx.ErrUnsafe)
	}
	if st.Size == 0 {
		return nil
	}
	var last [1]byte
	if _, err := f.ReadAt(last[:], st.Size-1); err != nil {
		return err
	}
	if last[0] == '\n' {
		return nil
	}
	return fsx.AppendLine(l.Path, nil)
}

// readLog reads the whole log without following symlinks or blocking on a
// FIFO (O_RDONLY|O_NOFOLLOW|O_NONBLOCK), requires a regular file and at
// most maxLogBytes; a missing log is empty.
func readLog(path string) ([]byte, fsx.Stat, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|fsx.ONoFollow|syscall.O_NONBLOCK, 0)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fsx.Stat{}, nil
	}
	if err != nil {
		return nil, fsx.Stat{}, err
	}
	defer f.Close()
	st, err := fsx.Fstat(f)
	if err != nil {
		return nil, fsx.Stat{}, err
	}
	if !st.IsRegular() {
		return nil, fsx.Stat{}, fmt.Errorf("%w: capsule log is not a regular file", fsx.ErrUnsafe)
	}
	if st.Size > maxLogBytes {
		return nil, fsx.Stat{}, errTooLarge
	}
	data, err := io.ReadAll(io.LimitReader(f, maxLogBytes+1))
	if err != nil {
		return nil, fsx.Stat{}, err
	}
	if int64(len(data)) > maxLogBytes {
		return nil, fsx.Stat{}, errTooLarge
	}
	return data, st, nil
}

// fold turns log bytes into the live entries, in log order (linear time:
// replaced and deleted entries are tombstoned, then dropped at the end).
func fold(data []byte) []Entry {
	type slot struct {
		e    Entry
		dead bool
	}
	var slots []slot
	pos := map[string]int{} // path → index of its live slot
	for len(data) > 0 {
		i := bytes.IndexByte(data, '\n')
		if i < 0 {
			break // torn last line
		}
		line := bytes.TrimSpace(data[:i])
		data = data[i+1:]
		if len(line) == 0 {
			continue
		}
		var e Entry
		if err := json.Unmarshal(line, &e); err != nil || e.Path == "" {
			continue
		}
		at, live := pos[e.Path]
		switch {
		case e.Deleted:
			if live {
				slots[at].dead = true
				delete(pos, e.Path)
			}
		case live && slots[at].e.HeaderSHA256 == e.HeaderSHA256:
			// The same capsule logged twice (re-append): keep the first.
		default:
			if live {
				slots[at].dead = true // a later entry describes the file now at Path
			}
			pos[e.Path] = len(slots)
			slots = append(slots, slot{e: e})
		}
	}
	out := make([]Entry, 0, len(pos))
	for _, s := range slots {
		if !s.dead {
			out = append(out, s.e)
		}
	}
	return out
}

// The cache keeps the folded entries of a log file for as long as its
// identity (inode, size, mtime, ctime) is unchanged: any append or rewrite
// changes it.
var cache struct {
	sync.Mutex
	m map[string]cachedLog
}

type cachedLog struct {
	st      fsx.Stat
	entries []Entry
}

func cached(path string, st fsx.Stat) ([]Entry, bool) {
	if st.Ino == 0 {
		return nil, false
	}
	cache.Lock()
	defer cache.Unlock()
	c, ok := cache.m[path]
	if !ok || !c.st.Unchanged(st) {
		return nil, false
	}
	return copyEntries(c.entries), true
}

func store(path string, st fsx.Stat, entries []Entry) {
	if st.Ino == 0 {
		return
	}
	cache.Lock()
	defer cache.Unlock()
	if cache.m == nil {
		cache.m = map[string]cachedLog{}
	}
	cache.m[path] = cachedLog{st: st, entries: copyEntries(entries)}
}

func invalidate(path string) {
	cache.Lock()
	defer cache.Unlock()
	delete(cache.m, path)
}

// copyEntries returns a deep copy so callers may modify what they get.
func copyEntries(in []Entry) []Entry {
	out := make([]Entry, len(in))
	for i, e := range in {
		e.RootIDs = append([]string(nil), e.RootIDs...)
		out[i] = e
	}
	return out
}
