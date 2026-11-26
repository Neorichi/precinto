package ledger

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/Neorichi/precinto/internal/fsx"
	"github.com/Neorichi/precinto/internal/platform"
)

const (
	fileExt = ".jsonl"
	// maxLedgerBytes bounds one session ledger. Ledgers hold a few hundred
	// content-free events; anything larger is refused (callers treat the
	// error as "live", never as "no ledger").
	maxLedgerBytes = 64 << 20
	// typeArchived is the first line of a ledger whose head was moved into
	// a capsule by Archive while events kept arriving (S13). It carries
	// only the archived length, so a repeated Archive of the same snapshot
	// (journal recovery re-running SPEC §10.3 step 8) is recognised as done
	// and never cuts events that were not sealed.
	typeArchived Type = "archived"
	// lateAppendRounds bounds how often Archive re-checks the replaced
	// file for events appended while it was being rewritten.
	lateAppendRounds = 8
	// tornLineRetries and tornLineWait let a hook finish a write(2) that
	// Archive observed half-done before the bytes are copied.
	tornLineRetries = 5
	tornLineWait    = 20 * time.Millisecond
)

// errInvalid is wrapped by every argument error.
var errInvalid = errors.New("ledger: invalid argument")

// archivedLine is the marker Archive writes at the head of a rewritten file.
type archivedLine struct {
	V        int       `json:"v"`
	T        time.Time `json:"t"`
	Type     Type      `json:"type"`
	Harness  string    `json:"harness"`
	SID      string    `json:"sid"`
	Archived int64     `json:"archived"`
}

// component validates a harness id or session id used as a file name: one
// plain path component, never ".", ".." or anything with a separator or a
// control character.
func component(what, s string) error {
	if s == "" || s == "." || s == ".." || len(s) > 200 || strings.ContainsAny(s, "/\\") {
		return fmt.Errorf("%w: bad %s %q", errInvalid, what, s)
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("%w: control character in %s", errInvalid, what)
		}
	}
	return nil
}

func (l *Ledger) root() (string, error) {
	if l == nil || l.Dir == "" || !filepath.IsAbs(l.Dir) {
		return "", fmt.Errorf("%w: the ledger directory must be absolute", errInvalid)
	}
	return filepath.Clean(l.Dir), nil
}

func (l *Ledger) sessionPath(harness, sid string) (string, error) {
	root, err := l.root()
	if err != nil {
		return "", err
	}
	if err := component("harness", harness); err != nil {
		return "", err
	}
	if err := component("session id", sid); err != nil {
		return "", err
	}
	return filepath.Join(root, harness, sid+fileExt), nil
}

// appendEvent implements Append.
func (l *Ledger) appendEvent(e Event) error {
	if e.Type == "" || e.Type == typeArchived {
		return fmt.Errorf("%w: bad event type %q", errInvalid, e.Type)
	}
	path, err := l.sessionPath(e.Harness, e.SID)
	if err != nil {
		return err
	}
	for name, p := range map[string]string{
		"cwd": e.Cwd, "project_dir": e.ProjectDir, "transcript": e.Transcript,
		"config_dir": e.ConfigDir, "tmp_dir": e.TmpDir, "path": e.Path,
	} {
		if p != "" && !filepath.IsAbs(p) {
			return fmt.Errorf("%w: %s must be absolute", errInvalid, name)
		}
	}
	for _, r := range e.Roots {
		if r == "" {
			return fmt.Errorf("%w: empty root id", errInvalid)
		}
	}
	if e.V == 0 {
		e.V = Version
	}
	if e.T.IsZero() {
		e.T = time.Now().UTC()
	}
	line, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("ledger: encode event: %w", err)
	}
	if err := mkdirPrivate(filepath.Dir(path)); err != nil {
		return err
	}
	return fsx.AppendLine(path, line)
}

// openNoFollow opens a ledger file for reading without following a final
// symlink and requires a regular file.
func openNoFollow(path string) (*os.File, fsx.Stat, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|fsx.ONoFollow|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, fsx.Stat{}, err
	}
	st, err := fsx.Fstat(f)
	if err != nil {
		f.Close()
		return nil, fsx.Stat{}, err
	}
	if !st.IsRegular() {
		f.Close()
		return nil, fsx.Stat{}, fmt.Errorf("%w: %s is not a regular file", fsx.ErrUnsafe, filepath.Base(path))
	}
	return f, st, nil
}

// readComplete reads f from 0 up to its current size and returns the
// complete lines (up to and including the last '\n').
func readComplete(f *os.File, size int64) ([]byte, error) {
	if size > maxLedgerBytes {
		return nil, fmt.Errorf("ledger: %s is larger than %d bytes", filepath.Base(f.Name()), maxLedgerBytes)
	}
	buf := make([]byte, size)
	n, err := f.ReadAt(buf, 0)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	buf = buf[:n]
	if i := bytes.LastIndexByte(buf, '\n'); i >= 0 {
		return buf[:i+1], nil
	}
	return buf[:0], nil
}

// read returns the complete lines of a session ledger; ErrNotFound if it
// does not exist.
func (l *Ledger) read(harness, sid string) ([]byte, error) {
	path, err := l.sessionPath(harness, sid)
	if err != nil {
		return nil, err
	}
	f, st, err := openNoFollow(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%w: %s/%s", ErrNotFound, harness, sid)
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return readComplete(f, st.Size)
}

// folded is a Session plus the facts ByProc needs: when each process last
// started (or launched) this session.
type folded struct {
	s          Session
	lastStarts map[platform.ProcID]time.Time
}

// firstContact reports a start event with an empty source: the hooks'
// record of the first managed contact of a session that had no ledger yet
// (SPEC §14.3), not a SessionStart.
func firstContact(e Event) bool { return e.Type == TypeStart && e.Source == "" }

// fold applies the fold rules to the events of one session in file order.
// Lines that do not decode, belong to another session, or have an unknown
// type are ignored: they can never make a session look less live. A
// first-contact start (firstContact) is the session's start when it is the
// first start of the file: it gives the process, homes and transcript of a
// session that became managed after its SessionStart.
func fold(harness, sid string, raw []byte) folded {
	f := folded{s: Session{Harness: harness, SID: sid}, lastStarts: map[platform.ProcID]time.Time{}}
	s := &f.s
	lastStart, lastEnd := -1, -1
	endTranscript, transcript := "", ""
	seen := map[string]map[string]bool{}
	add := func(set string, list *[]string, v string) {
		if v == "" {
			return
		}
		if seen[set] == nil {
			seen[set] = map[string]bool{}
		}
		if !seen[set][v] {
			seen[set][v] = true
			*list = append(*list, v)
		}
	}
	procSeen := map[platform.ProcID]bool{}
	i := -1
	for _, line := range bytes.Split(raw, []byte("\n")) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var e Event
		if json.Unmarshal(line, &e) != nil || e.SID != sid || e.Harness != harness {
			continue
		}
		i++
		if e.T.After(s.LastEvent) {
			s.LastEvent = e.T
		}
		if !e.Proc.IsZero() && !procSeen[e.Proc] {
			procSeen[e.Proc] = true
			s.Procs = append(s.Procs, e.Proc)
		}
		for _, r := range e.Roots {
			add("roots", &s.RootIDs, r)
		}
		add("cwds", &s.Cwds, e.Cwd)
		add("config", &s.ConfigDirs, e.ConfigDir)
		add("tmp", &s.TmpDirs, e.TmpDir)
		if e.Transcript != "" {
			transcript = e.Transcript
		}
		if e.HarnessVersion != "" {
			s.Version = e.HarnessVersion
		}
		if e.Entrypoint != "" {
			s.Entrypoint = e.Entrypoint
		}
		if e.Background {
			s.Background = true
		}
		if e.Wrapper {
			s.Wrapper = true
		}
		switch e.Type {
		case TypeLaunch, TypeStart:
			if s.Started.IsZero() {
				s.Started = e.T
			}
			if firstContact(e) && lastStart >= 0 {
				// A first-contact start after the session already started
				// (a hook that found no ledger while an Archive replaced
				// it): its process, homes and transcript are facts (folded
				// above), never a restart. A session that ended with /clear
				// stays ended and warm, and its process keeps owning the
				// newer session (D20).
				break
			}
			if !e.Proc.IsZero() {
				s.CurrentProc = e.Proc
				if e.T.After(f.lastStarts[e.Proc]) || f.lastStarts[e.Proc].IsZero() {
					f.lastStarts[e.Proc] = e.T
				}
			}
			lastStart = i
			if e.Type == TypeStart && e.Source == "compact" {
				s.Compacting = false
			}
		case TypeDir:
			add("dirs", &s.Dirs, e.Path)
		case TypeMarkdown:
			add("md", &s.Markdown, e.Path)
		case TypeCompactBegin:
			s.Compacting = true
			s.CompactAt = e.T
		case TypeCompactEnd:
			s.Compacting = false
		case TypeEnd:
			lastEnd = i
			s.EndReason = e.Reason
			s.EndProc = e.Proc
			s.Compacting = false
			if e.Transcript != "" {
				endTranscript = e.Transcript
			}
		}
		// Only hooks write these events (the wrapper writes launch, and may
		// write taint or dir for --add-dir): any of them means hooks ran.
		switch e.Type {
		case TypeStart, TypeCwd, TypeTouch, TypeMarkdown, TypeCompactBegin, TypeCompactEnd, TypeEnd, TypeHooksSeen:
			s.HooksSeen = true
		}
		if s.Started.IsZero() && i == 0 {
			s.Started = e.T
		}
	}
	s.Ended = lastEnd > lastStart
	if !s.Ended {
		s.EndReason, s.EndProc = "", platform.ProcID{}
	}
	s.Transcript = transcript
	if endTranscript != "" {
		// SessionEnd's transcript_path is trusted over SessionStart's
		// (HOOKS-IO §2.3: a cross-folder resume can report the wrong slug).
		s.Transcript = endTranscript
	}
	return f
}

// get implements Get.
func (l *Ledger) get(harness, sid string) (Session, error) {
	raw, err := l.read(harness, sid)
	if err != nil {
		return Session{}, err
	}
	return fold(harness, sid, raw).s, nil
}

// listFolded folds every session ledger of harness, sorted by start time
// then session id.
func (l *Ledger) listFolded(harness string) ([]folded, error) {
	root, err := l.root()
	if err != nil {
		return nil, err
	}
	if err := component("harness", harness); err != nil {
		return nil, err
	}
	dir := filepath.Join(root, harness)
	entries, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []folded
	for _, de := range entries {
		name := de.Name()
		if !de.Type().IsRegular() || !strings.HasSuffix(name, fileExt) {
			continue // never follow symlinks or descend into directories
		}
		sid := strings.TrimSuffix(name, fileExt)
		if component("session id", sid) != nil {
			continue
		}
		raw, err := l.read(harness, sid)
		if errors.Is(err, ErrNotFound) {
			continue // archived while listing
		}
		if err != nil {
			return nil, err
		}
		out = append(out, fold(harness, sid, raw))
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i].s, out[j].s
		if !a.Started.Equal(b.Started) {
			return a.Started.Before(b.Started)
		}
		return a.SID < b.SID
	})
	return out, nil
}

func (l *Ledger) list(harness string) ([]Session, error) {
	fs, err := l.listFolded(harness)
	if err != nil || len(fs) == 0 {
		return nil, err
	}
	out := make([]Session, len(fs))
	for i, f := range fs {
		out[i] = f.s
	}
	return out, nil
}

// byProc implements ByProc: of the sessions whose current process is id,
// only those id started (or launched) most recently; a process that moved
// on to a newer session no longer owns the older one (D20).
func (l *Ledger) byProc(harness string, id platform.ProcID) ([]Session, error) {
	if id.IsZero() {
		return nil, nil
	}
	fs, err := l.listFolded(harness)
	if err != nil {
		return nil, err
	}
	var newest time.Time
	var cands []folded
	for _, f := range fs {
		if f.s.CurrentProc != id {
			continue
		}
		cands = append(cands, f)
		if t := f.lastStarts[id]; t.After(newest) {
			newest = t
		}
	}
	var out []Session
	for _, f := range cands {
		if f.lastStarts[id].Equal(newest) {
			out = append(out, f.s)
		}
	}
	return out, nil
}

// snapshot implements Snapshot: the complete lines present right now.
func (l *Ledger) snapshot(harness, sid string) ([]byte, int64, error) {
	raw, err := l.read(harness, sid)
	if err != nil {
		return nil, 0, err
	}
	return raw, int64(len(raw)), nil
}

// isArchivedMarker reports whether the first line of data is the marker of
// an Archive of a snapshot of length n.
func isArchivedMarker(data []byte, harness, sid string, n int64) bool {
	line := data
	if i := bytes.IndexByte(data, '\n'); i >= 0 {
		line = data[:i]
	}
	var m archivedLine
	return json.Unmarshal(line, &m) == nil && m.Type == typeArchived &&
		m.Harness == harness && m.SID == sid && m.Archived == n
}

// archive implements Archive (S13, SPEC §10.3 step 8). The bytes [0, n)
// are in a committed capsule; everything after n is kept:
//   - size == n: a tombstone is recorded and the file is unlinked, then
//     bytes a hook appended to the unlinked inode meanwhile are appended to
//     the path again;
//   - size > n: the tail is written to a temporary (behind a marker naming
//     n) and renamed over the file, then late appends to the replaced inode
//     are copied over the same way.
//
// A repeated call for the same snapshot (journal recovery re-running step
// 8) finds the marker or the tombstone and does nothing, so it never cuts
// or removes events that were not sealed. A file shorter than n is left
// alone (never cut).
func (l *Ledger) archive(harness, sid string, n int64) error {
	if n < 0 {
		return fmt.Errorf("%w: negative length", errInvalid)
	}
	path, err := l.sessionPath(harness, sid)
	if err != nil {
		return err
	}
	f, st, err := openNoFollow(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil // already archived
	}
	if err != nil {
		return err
	}
	defer f.Close()
	head, err := readComplete(f, st.Size)
	if err != nil {
		return err
	}
	if isArchivedMarker(head, harness, sid, n) {
		return nil // this snapshot was archived before
	}
	dir := filepath.Dir(path)
	if t, ok, err := findTombstone(dir, sid, n); err != nil {
		return err
	} else if ok && !t.names(st) {
		return nil // the snapshot's file was removed; this is a newer ledger
	}
	if st.Size < n {
		return nil // not the snapshot's file: keep every byte
	}
	if st.Size == n {
		if err := addTombstone(dir, sid, n, st); err != nil {
			return err
		}
		if err := unlinkIfSame(path, st); err != nil {
			return err
		}
		if err := fsx.SyncDir(dir); err != nil {
			return err
		}
		_, err := copyLate(f, n, path)
		return err
	}
	tail, end, err := readFrom(f, n)
	if err != nil {
		return err
	}
	marker, err := json.Marshal(archivedLine{V: Version, T: time.Now().UTC(), Type: typeArchived, Harness: harness, SID: sid, Archived: n})
	if err != nil {
		return err
	}
	content := append(append(marker, '\n'), tail...)
	tmp, err := writeTemp(dir, filepath.Base(path), content)
	if err != nil {
		return err
	}
	cur, err := fsx.Lstat(path)
	if err != nil || !cur.SameFile(st) {
		os.Remove(tmp)
		if err == nil {
			err = fmt.Errorf("ledger: %s/%s was replaced while archiving", harness, sid)
		}
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := fsx.SyncDir(dir); err != nil {
		return err
	}
	_, err = copyLate(f, end, path)
	return err
}

// unlinkIfSame removes path only while it still names the inode of st.
func unlinkIfSame(path string, st fsx.Stat) error {
	cur, err := fsx.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !cur.SameFile(st) {
		return fmt.Errorf("ledger: %s was replaced while archiving", filepath.Base(path))
	}
	return os.Remove(path)
}

// readFrom returns the complete lines of f from offset off on, waiting
// briefly for a write(2) in progress to finish its line, and the offset
// just after the bytes returned.
func readFrom(f *os.File, off int64) ([]byte, int64, error) {
	for try := 0; ; try++ {
		st, err := fsx.Fstat(f)
		if err != nil {
			return nil, off, err
		}
		if st.Size <= off {
			return nil, off, nil
		}
		if st.Size-off > maxLedgerBytes {
			return nil, off, fmt.Errorf("ledger: %s grew past %d bytes", filepath.Base(f.Name()), maxLedgerBytes)
		}
		buf := make([]byte, st.Size-off)
		k, err := f.ReadAt(buf, off)
		if err != nil && !errors.Is(err, io.EOF) {
			return nil, off, err
		}
		buf = buf[:k]
		last := bytes.LastIndexByte(buf, '\n')
		if last == len(buf)-1 || try >= tornLineRetries {
			if last < 0 {
				return nil, off, nil
			}
			return buf[:last+1], off + int64(last) + 1, nil
		}
		time.Sleep(tornLineWait)
	}
}

// copyLate appends to path the complete lines written to the old inode f
// after offset off (events a hook appended while Archive replaced or
// removed the file), until f stops growing. It returns the final offset.
func copyLate(f *os.File, off int64, path string) (int64, error) {
	settled := false
	for round := 0; round < lateAppendRounds; round++ {
		late, end, err := readFrom(f, off)
		if err != nil {
			return off, err
		}
		if len(late) == 0 {
			if settled {
				return off, nil
			}
			// A hook that opened the old inode just before the rename may
			// not have written yet: look once more after a moment.
			settled = true
			time.Sleep(tornLineWait)
			continue
		}
		settled = false
		for _, line := range bytes.SplitAfter(late, []byte("\n")) {
			line = bytes.TrimSuffix(line, []byte("\n"))
			if len(line) == 0 {
				continue
			}
			if err := fsx.AppendLine(path, line); err != nil {
				return off, err
			}
		}
		off = end
	}
	return off, nil
}

// writeTemp writes data to a new 0600 temporary next to base in dir,
// FullSyncs it and returns its path.
func writeTemp(dir, base string, data []byte) (string, error) {
	for i := 0; i < 100; i++ {
		tmp := filepath.Join(dir, fmt.Sprintf(".%s.archive-%d-%d", base, os.Getpid(), i))
		f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|fsx.ONoFollow, 0o600)
		if errors.Is(err, fs.ErrExist) {
			continue
		}
		if err != nil {
			return "", err
		}
		_, werr := f.Write(data)
		if werr == nil {
			werr = fsx.FullSync(f)
		}
		if cerr := f.Close(); werr == nil {
			werr = cerr
		}
		if werr != nil {
			os.Remove(tmp)
			return "", werr
		}
		return tmp, nil
	}
	return "", fmt.Errorf("ledger: no free temporary name in %s", dir)
}

// mkdirPrivate creates dir and its missing parents with mode 0700 and
// requires the final directory to be a real directory (not a symlink)
// owned by the current user.
func mkdirPrivate(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	st, err := fsx.Lstat(dir)
	if err != nil {
		return err
	}
	if !st.IsDir() {
		return fmt.Errorf("%w: %s is not a directory", fsx.ErrUnsafe, dir)
	}
	if int(st.UID) != os.Getuid() {
		return fmt.Errorf("%w: %s is not owned by the current user", fsx.ErrUnsafe, dir)
	}
	return nil
}
