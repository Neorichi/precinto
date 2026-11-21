package fsx

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/precinto/precinto/internal/fsx/failpoint"
)

// Errors. Callers test them with errors.Is.
var (
	// ErrUnsafe: a symlink, foreign owner, group/other-writable directory,
	// non-regular file, path escaping its base, or non-clean relative path.
	ErrUnsafe = errors.New("fsx: unsafe path")
	// ErrChanged: the file's identity (dev, ino, size, mtime, ctime) differs
	// from the expected snapshot.
	ErrChanged = errors.New("fsx: file changed")
	// ErrExist: a no-replace rename or exclusive create found the target.
	ErrExist = errors.New("fsx: target exists")
	// ErrLocked: a non-blocking lock is held by someone else.
	ErrLocked = errors.New("fsx: locked")
	// ErrNoSpace: free space is below the requested amount plus the floor.
	ErrNoSpace = errors.New("fsx: not enough free space")
	// ErrHardlink: the file has more than one link; it is never unlinked.
	ErrHardlink = errors.New("fsx: file has several hard links")
)

// Stat identifies one version of a file. ctime cannot be set from user space,
// so Unchanged means "not written or replaced since the snapshot".
type Stat struct {
	Dev     uint64
	Ino     uint64
	Mode    uint32 // full st_mode (type and permission bits)
	Nlink   uint32
	UID     uint32
	Size    int64
	MtimeNS int64
	CtimeNS int64
}

// Lstat returns the Stat of path without following a final symlink.
// Implemented in the scaffold.
func Lstat(path string) (Stat, error) { return lstatPath(path) }

// Fstat returns the Stat of an open file. Implemented in the scaffold.
func Fstat(f *os.File) (Stat, error) { return fstatFile(f) }

// SameFile reports whether s and o are the same inode (Dev and Ino).
func (s Stat) SameFile(o Stat) bool { return s.Dev == o.Dev && s.Ino == o.Ino }

// Unchanged reports whether Dev, Ino, Size, MtimeNS and CtimeNS are equal.
func (s Stat) Unchanged(o Stat) bool {
	return s.SameFile(o) && s.Size == o.Size && s.MtimeNS == o.MtimeNS && s.CtimeNS == o.CtimeNS
}

// st_mode file-type bits (identical on darwin and linux).
const (
	modeTypeMask = 0o170000
	modeRegular  = 0o100000
	modeDir      = 0o040000
)

// IsRegular reports whether Mode is a regular file.
func (s Stat) IsRegular() bool { return s.Mode&modeTypeMask == modeRegular }

// IsDir reports whether Mode is a directory.
func (s Stat) IsDir() bool { return s.Mode&modeTypeMask == modeDir }

// Perm returns the permission bits (Mode & 0o7777) as an fs.FileMode
// (setuid, setgid and sticky mapped to their fs.FileMode bits).
func (s Stat) Perm() fs.FileMode {
	m := fs.FileMode(s.Mode & 0o777)
	if s.Mode&0o4000 != 0 {
		m |= fs.ModeSetuid
	}
	if s.Mode&0o2000 != 0 {
		m |= fs.ModeSetgid
	}
	if s.Mode&0o1000 != 0 {
		m |= fs.ModeSticky
	}
	return m
}

// EntryType classifies a directory entry without following it.
type EntryType int

// Entry types.
const (
	TypeRegular EntryType = iota
	TypeDir
	TypeSymlink
	TypeOther // FIFO, socket, device: never opened, never followed
)

// Hazard is a reason an entry is reported instead of being sealed or deleted
// (SPEC §10 "seal walk").
type Hazard string

// Hazards.
const (
	HazardNone     Hazard = ""
	HazardSymlink  Hazard = "symlink"
	HazardSpecial  Hazard = "special"  // FIFO, socket, device
	HazardHardlink Hazard = "hardlink" // st_nlink > 1
	HazardForeign  Hazard = "foreign"  // not owned by the current uid
	HazardAccess   Hazard = "access"   // EACCES/EPERM (TCC) while reading
)

// Entry is one lstat'ed directory entry.
type Entry struct {
	Name string
	Type EntryType
	Stat Stat
}

// WalkEntry is one entry visited by Dir.Walk. Rel is relative to the Dir the
// walk started from and uses '/' separators.
type WalkEntry struct {
	Rel    string
	Type   EntryType
	Stat   Stat
	Hazard Hazard
}

// RenameMode selects rename semantics.
type RenameMode int

// Rename modes.
const (
	// NoReplace fails with ErrExist if the target exists (darwin
	// renameatx_np RENAME_EXCL, linux renameat2 RENAME_NOREPLACE, fallback
	// linkat+unlinkat).
	NoReplace RenameMode = iota
	// Replace atomically replaces the target (renameat).
	Replace
)

// Dir is an open directory handle. Every operation is relative to it, walks
// path components with O_NOFOLLOW, and refuses symlinks, foreign-owned or
// group/other-writable directories below it (D12). A Dir is safe for use by
// one goroutine at a time.
type Dir struct {
	fd   int
	path string
	open bool
}

// OpenBase opens a trusted base directory. path must be absolute and already
// resolved (see Realpath); the base itself may be reached through symlinks
// that were resolved once at protect/integrate time (SPEC §11.4), but must be
// owned by the current uid.
func OpenBase(path string) (*Dir, error) { return openBase(path) }

// Path returns the absolute path the Dir was opened at (informational).
func (d *Dir) Path() string {
	if d == nil {
		return ""
	}
	return d.path
}

// Close releases the handle.
func (d *Dir) Close() error { return d.close() }

// OpenDir opens the directory rel below d without following symlinks. With
// create, missing components are created with mode 0700.
func (d *Dir) OpenDir(rel string, create bool) (*Dir, error) {
	return d.openDir(rel, create)
}

// Open opens the regular file rel for reading with
// O_RDONLY|O_NOFOLLOW|O_NONBLOCK, then requires fstat to be a regular file.
func (d *Dir) Open(rel string) (*os.File, Stat, error) { return d.openFile(rel) }

// Lstat returns the Stat of rel without following symlinks anywhere.
func (d *Dir) Lstat(rel string) (Stat, error) { return d.lstat(rel) }

// ReadDir lists the entries of rel (lstat semantics, no following).
func (d *Dir) ReadDir(rel string) ([]Entry, error) { return d.readDir(rel) }

// Walk visits every entry below rel in lexical order without following
// symlinks. Hazardous entries are passed to fn with Hazard set and are never
// descended into. fn returning fs.SkipDir skips a directory.
func (d *Dir) Walk(rel string, fn func(WalkEntry) error) error {
	if fn == nil {
		return errors.New("fsx: Walk needs a visit function")
	}
	return d.walk(rel, fn)
}

// CreateTemp creates a new 0600 file in the directory dirRel (created 0700
// if missing) with O_CREAT|O_EXCL|O_NOFOLLOW and returns it with its name
// relative to d. The last '*' of pattern is replaced by a random string; a
// pattern without '*' is the exact name, created O_EXCL (ErrExist if it
// exists). Unlike os.CreateTemp, a pattern without '*' gets no suffix.
func (d *Dir) CreateTemp(dirRel, pattern string) (*os.File, string, error) {
	return d.createTemp(dirRel, pattern)
}

// AppendLine appends line, plus "\n" if it lacks one, with one
// O_WRONLY|O_APPEND|O_NOFOLLOW write to the regular file rel opened
// component by component below d (created 0600 with O_EXCL when absent;
// the parent directory is then fsynced), then FullSyncs it; refuses
// non-regular files (a FIFO is refused without blocking) and files not
// owned by the user (ErrUnsafe). line must hold no other '\n' and be at
// most MaxLine bytes; an empty line appends only the newline (used to end
// a torn last line). Parent directories are never created (failpoints
// "fsx.write", "fsx.fsync").
func (d *Dir) AppendLine(rel string, line []byte) error { return d.appendLine(rel, line) }

// Rename renames oldRel to newRel (both relative to d) and fsyncs the
// affected directories.
func (d *Dir) Rename(oldRel, newRel string, mode RenameMode) error {
	return d.renameTo(oldRel, d, newRel, mode)
}

// RenameTo renames oldRel in d to newRel in dst (same file system), then
// fsyncs both directories.
func (d *Dir) RenameTo(oldRel string, dst *Dir, newRel string, mode RenameMode) error {
	return d.renameTo(oldRel, dst, newRel, mode)
}

// Link creates a hard link newRel to oldRel (used to hold an inode alive
// during history rotation, SPEC §7.1.4).
func (d *Dir) Link(oldRel, newRel string) error { return d.link(oldRel, newRel) }

// UnlinkIfUnchanged removes rel only if its current lstat is Unchanged
// relative to expect and Nlink == 1; otherwise it returns ErrChanged or
// ErrHardlink and leaves the file alone. The parent directory is fsynced.
func (d *Dir) UnlinkIfUnchanged(rel string, expect Stat) error {
	return d.unlinkIfUnchanged(rel, expect)
}

// Remove removes rel (a file, or an empty directory) unconditionally. Used
// only for precinto-owned temporaries and staging.
func (d *Dir) Remove(rel string) error { return d.remove(rel) }

// RemoveEmptyDirs removes rel and its now-empty parents up to (excluding)
// stopAt; non-empty directories are left alone.
func (d *Dir) RemoveEmptyDirs(rel, stopAt string) error {
	return d.removeEmptyDirs(rel, stopAt)
}

// Chtimes sets the mtime (and atime) of rel without following symlinks.
func (d *Dir) Chtimes(rel string, mtime time.Time) error { return d.chtimes(rel, mtime) }

// Chmod sets permission bits of rel (masked with 0o700) without following.
func (d *Dir) Chmod(rel string, perm fs.FileMode) error { return d.chmod(rel, perm) }

// Sync fsyncs the directory itself.
func (d *Dir) Sync() error { return d.sync() }

// Device returns the st_dev of the directory.
func (d *Dir) Device() (uint64, error) { return d.device() }

// FullSync flushes f to stable storage (F_FULLFSYNC on darwin, falling
// back to fsync on volumes that do not support it; fsync on linux).
// Implemented in the scaffold (failpoint "fsx.fsync").
func FullSync(f *os.File) error {
	if err := failpoint.Hit("fsx.fsync"); err != nil {
		return err
	}
	if err := fullSync(f); err != nil {
		return err
	}
	noteSync(f)
	return nil
}

// SyncDir fsyncs the directory at path. Implemented in the scaffold
// (failpoint "fsx.fsync").
func SyncDir(path string) error {
	if err := failpoint.Hit("fsx.fsync"); err != nil {
		return err
	}
	d, err := openDirNoFollow(path)
	if err != nil {
		return err
	}
	defer d.Close()
	if err := fullSync(d); err != nil {
		return err
	}
	note(failpoint.FSDirSync, path, "", true)
	return nil
}

// MaxLine bounds AppendLine (one write(2) of at most this many bytes plus
// the newline).
const MaxLine = 64 << 10

// WriteFileAtomic writes data to a temporary file next to path (perm masked
// to owner bits, O_CREAT|O_EXCL|O_NOFOLLOW), FullSyncs it, renames it over
// path and fsyncs the directory. It is used for precinto-owned metadata
// (config.toml, receipts, vault.toml, roots.list). The temporary is removed
// on any error. Implemented in the scaffold (failpoints "fsx.write",
// "fsx.fsync", "fsx.rename").
func WriteFileAtomic(path string, data []byte, perm fs.FileMode) error {
	dir, base := filepath.Split(path)
	if base == "" || !filepath.IsAbs(path) {
		return fmt.Errorf("%w: %q", ErrUnsafe, path)
	}
	var f *os.File
	var tmp string
	for i := 0; ; i++ {
		tmp = filepath.Join(dir, "."+base+".tmp-"+strconv.Itoa(os.Getpid())+"-"+strconv.Itoa(i))
		var err error
		f, err = os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|oNoFollow, perm&0o700)
		if err == nil {
			note(failpoint.FSCreate, tmp, "", true)
			break
		}
		if !errors.Is(err, fs.ErrExist) || i >= 100 {
			return err
		}
	}
	fail := func(err error) error {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := failpoint.Hit("fsx.write"); err != nil {
		return fail(err)
	}
	if _, err := f.Write(data); err != nil {
		return fail(err)
	}
	if err := FullSync(f); err != nil {
		return fail(err)
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := failpoint.Hit("fsx.rename"); err != nil {
		os.Remove(tmp)
		return err
	}
	note(failpoint.FSRename, tmp, path, false)
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	note(failpoint.FSRename, tmp, path, true)
	return SyncDir(filepath.Clean(dir))
}

// AppendLine appends line plus '\n' with one write(2) on an
// O_APPEND (created O_EXCL 0600 if missing, then the parent directory is
// fsynced) descriptor opened O_NOFOLLOW|O_NONBLOCK, refuses non-regular
// files, and FullSyncs it. line must not contain '\n' and must be at most
// MaxLine bytes. Implemented in the scaffold (failpoints "fsx.write",
// "fsx.fsync").
func AppendLine(path string, line []byte) error {
	if len(line) > MaxLine || bytes.IndexByte(line, '\n') >= 0 {
		return fmt.Errorf("%w: bad line for AppendLine", ErrUnsafe)
	}
	f, created, err := openAppend(path)
	if err != nil {
		return err
	}
	defer f.Close()
	if created {
		note(failpoint.FSCreate, path, "", true)
	}
	if err := failpoint.Hit("fsx.write"); err != nil {
		return err
	}
	buf := make([]byte, 0, len(line)+1)
	buf = append(append(buf, line...), '\n')
	n, err := f.Write(buf)
	if err != nil {
		return err
	}
	if n != len(buf) {
		return fmt.Errorf("fsx: short append (%d of %d bytes)", n, len(buf))
	}
	if err := FullSync(f); err != nil {
		return err
	}
	if created {
		return SyncDir(filepath.Dir(path))
	}
	return nil
}

// openAppend opens path for appending, creating it exclusively if missing.
func openAppend(path string) (*os.File, bool, error) {
	for i := 0; i < 3; i++ {
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|oNoFollow|oNonblock, 0)
		created := false
		if errors.Is(err, fs.ErrNotExist) {
			f, err = os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE|os.O_EXCL|oNoFollow|oNonblock, 0o600)
			if errors.Is(err, fs.ErrExist) {
				continue // created concurrently: reopen without O_CREATE
			}
			created = true
		}
		if err != nil {
			return nil, false, err
		}
		st, err := Fstat(f)
		if err != nil {
			f.Close()
			return nil, false, err
		}
		if !st.IsRegular() {
			f.Close()
			return nil, false, fmt.Errorf("%w: %s is not a regular file", ErrUnsafe, filepath.Base(path))
		}
		return f, created, nil
	}
	return nil, false, fmt.Errorf("fsx: could not open %s for appending", filepath.Base(path))
}

// MkdirPrivate creates path and missing parents with mode 0700 and checks
// that the final directory is owned by the current uid and not a symlink.
func MkdirPrivate(path string) error { return mkdirPrivate(path) }

// CheckPrivateDir requires path to be a directory (not a symlink) owned by
// the current uid with no group/other permission bits (D6 socket dir rule).
func CheckPrivateDir(path string) error { return checkPrivateDir(path) }

// Realpath resolves symlinks in an existing absolute path once (protect and
// integrate time) and returns the cleaned result.
func Realpath(path string) (string, error) { return realpath(path) }

// Contains reports whether p is root or below root. It compares (dev, ino)
// of p's existing ancestors with root, so it is correct on case- and
// normalization-insensitive volumes; for non-existent tails it falls back to
// a component-wise comparison (case-folded on darwin).
func Contains(root, p string) (bool, error) { return contains(root, p) }

// SameDevice reports whether a and b live on the same file system.
func SameDevice(a, b string) (bool, error) { return sameDevice(a, b) }

// Lock is a held flock(2) lock. Lock files are never deleted (SPEC §10.2).
type Lock struct {
	file *os.File
}

// TryLock takes an exclusive (or shared) non-blocking flock on path,
// creating the file 0600 if needed (O_NOFOLLOW, regular files only);
// ErrLocked if held elsewhere. Implemented in the scaffold.
func TryLock(path string, shared bool) (*Lock, error) {
	f, err := openLockFile(path)
	if err != nil {
		return nil, err
	}
	st, err := Fstat(f)
	if err != nil {
		f.Close()
		return nil, err
	}
	if !st.IsRegular() {
		f.Close()
		return nil, fmt.Errorf("%w: lock file is not a regular file", ErrUnsafe)
	}
	if err := flockNB(f, shared); err != nil {
		f.Close()
		return nil, err
	}
	return &Lock{file: f}, nil
}

// openLockFile opens the lock file at path read-write, creating it 0600
// when it is missing; a file it creates is reported to failpoint observers
// (power-loss recording, internal/fsx/fsxtest).
func openLockFile(path string) (*os.File, error) {
	for i := 0; i < 3; i++ {
		f, err := os.OpenFile(path, os.O_RDWR|oNoFollow|oNonblock, 0)
		if !errors.Is(err, fs.ErrNotExist) {
			return f, err
		}
		f, err = os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL|oNoFollow|oNonblock, 0o600)
		if errors.Is(err, fs.ErrExist) {
			continue // created concurrently: open it without O_CREATE
		}
		if err == nil {
			note(failpoint.FSCreate, path, "", true)
		}
		return f, err
	}
	return nil, fmt.Errorf("fsx: could not open lock file %s", filepath.Base(path))
}

// WaitLock blocks until the lock is acquired or ctx ends (polling with
// back-off from 10 ms to 250 ms). Implemented in the scaffold.
func WaitLock(ctx context.Context, path string, shared bool) (*Lock, error) {
	wait := 10 * time.Millisecond
	for {
		l, err := TryLock(path, shared)
		if !errors.Is(err, ErrLocked) {
			return l, err
		}
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return nil, ctx.Err()
		case <-t.C:
		}
		if wait < 250*time.Millisecond {
			wait *= 2
		}
	}
}

// Unlock releases the lock and closes the descriptor.
func (l *Lock) Unlock() error {
	if l == nil || l.file == nil {
		return nil
	}
	err := unlockFile(l.file)
	if cerr := l.file.Close(); err == nil {
		err = cerr
	}
	l.file = nil
	return err
}

// File returns the locked descriptor (used to make a lease inheritable
// across exec, SPEC §9.3).
func (l *Lock) File() *os.File { return l.file }

// ProbeHeld reports whether another process holds any flock on path. It
// tries LOCK_EX|LOCK_NB and releases immediately, then verifies that the
// path still names the probed inode. A missing file is not held: (false,
// nil) — lease files are created before use and never deleted (SPEC §9.3).
// Any other error, an unsupported file system, or an inode swap during the
// probe reports held=true (R17). It is the one probe implementation for
// leases (live.Probe uses it). Use it only on precinto's own lock and lease
// files: harness writer locks (Codex thread-writer-locks) are checked with
// platform.ProcTable.OpenFilesUnder, never by flocking them (HA17).
func ProbeHeld(path string) (held bool, err error) { return probeHeld(path) }

// Space reports available and total bytes of the file system holding path.
func Space(path string) (avail, total uint64, err error) { return spaceOf(path) }

// Floor is the free-space reserve kept after an operation (D12, D38).
type Floor struct {
	MinBytes    int64   // default 2 GiB
	MinFraction float64 // default 0.05 of the volume
}

// DefaultFloor is max(2 GiB, 5% of the volume).
var DefaultFloor = Floor{MinBytes: 2 << 30, MinFraction: 0.05}

// CheckSpace returns ErrNoSpace unless need bytes fit on path's volume while
// keeping the floor free.
func CheckSpace(path string, need int64, floor Floor) error { return checkSpace(path, need, floor) }

// Staging is a 0700 directory on the same file system as a restore target,
// removed when the operation completes (D12).
type Staging struct {
	Dir  *Dir
	Path string
	ID   string
}

// NewStaging creates <preferred>/<id> if preferred is on the same device as
// target, else <target volume root>/.precinto-staging/<id>.
func NewStaging(preferred, target, id string) (*Staging, error) {
	return newStaging(preferred, target, id)
}

// OpenStaging reopens an existing staging directory during journal recovery.
func OpenStaging(path string) (*Staging, error) { return openStaging(path) }

// Remove deletes the staging directory and everything in it.
func (s *Staging) Remove() error {
	if s == nil {
		return nil
	}
	return removeStaging(s)
}

// Class is the coarse classification of an I/O error used by the error
// table in SPEC §17.
type Class string

// Error classes.
const (
	ClassNone     Class = ""
	ClassNoSpace  Class = "nospace"  // ENOSPC, EDQUOT, EFBIG
	ClassAccess   Class = "access"   // EACCES, EPERM (includes macOS TCC denials)
	ClassMissing  Class = "missing"  // ENOENT, ENOTDIR
	ClassBusy     Class = "busy"     // EBUSY, ETXTBSY, EDEADLK, EAGAIN, ErrLocked
	ClassUnsafe   Class = "unsafe"   // ErrUnsafe, ELOOP, EMLINK
	ClassReadOnly Class = "readonly" // EROFS
	ClassIO       Class = "io"       // EIO and anything else from the kernel
	ClassOther    Class = "other"
)

// Classify maps err to a Class. EPERM/EACCES are never treated as missing.
func Classify(err error) Class { return classify(err) }
