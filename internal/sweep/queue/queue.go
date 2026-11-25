package queue

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
	"github.com/precinto/precinto/internal/platform"
)

// Version is the request format.
const Version = 1

// Request asks for one session (or unit) to be sealed once its writer is
// gone. It holds no content.
type Request struct {
	V         int             `json:"v"`
	ID        string          `json:"id"`
	Harness   string          `json:"harness"`
	SID       string          `json:"sid,omitempty"`
	UnitKey   string          `json:"unit_key,omitempty"`
	Reason    string          `json:"reason"`               // SessionEnd reason | "wrapper-exit" | "lock" | "codex-exit"
	WaitFor   platform.ProcID `json:"wait_for,omitempty"`   // process that must exit first (--wait-pid PID:START)
	Warm      bool            `json:"warm,omitempty"`       // clear/resume: seal when the registry no longer names the sid and it is quiet (HA16)
	ConfigDir string          `json:"config_dir,omitempty"` // harness home realpath (must be registered)
	Cwd       string          `json:"cwd,omitempty"`
	At        time.Time       `json:"at"`
	NotBefore time.Time       `json:"not_before,omitempty"` // retry backoff
	Attempts  int             `json:"attempts,omitempty"`
	Deadline  time.Time       `json:"deadline,omitempty"` // give up and report after (codex: ~6 h, HA17)
}

// requestExt is the suffix of request files; temporaries start with a dot.
const requestExt = ".json"

// maxRequestBytes bounds a request read (requests are a few hundred bytes).
const maxRequestBytes = 64 << 10

// Enqueue writes r atomically (ID assigned if empty) and returns its id.
func Enqueue(dir string, r Request) (string, error) {
	// The request becomes visible at once and completely: it is FullSynced
	// in a hidden temporary and hard-linked to <id>.json, which fails if a
	// request with that id already exists (an id is never silently
	// replaced).
	if err := ensureDir(dir); err != nil {
		return "", err
	}
	if r.ID == "" {
		r.ID = newID()
	}
	if !validID(r.ID) {
		return "", fmt.Errorf("queue: invalid request id %q", r.ID)
	}
	r.V = Version
	if r.At.IsZero() {
		r.At = time.Now().UTC()
	}
	data, err := json.Marshal(r)
	if err != nil {
		return "", err
	}
	if err := createExclusive(dir, r.ID+requestExt, data); err != nil {
		return "", err
	}
	return r.ID, nil
}

// List returns pending requests ordered by At.
func List(dir string) ([]Request, error) {
	// Files that are not requests precinto wrote (bad names, undecodable
	// or oversized content, symlinks) are skipped; a missing directory is
	// an empty queue.
	ents, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []Request
	for _, de := range ents {
		id, ok := strings.CutSuffix(de.Name(), requestExt)
		if !ok || !validID(id) {
			continue
		}
		r, err := readRequest(filepath.Join(dir, de.Name()))
		if err != nil || r.ID != id {
			continue
		}
		out = append(out, r)
	}
	sort.SliceStable(out, func(a, b int) bool {
		if !out[a].At.Equal(out[b].At) {
			return out[a].At.Before(out[b].At)
		}
		return out[a].ID < out[b].ID
	})
	return out, nil
}

// Update rewrites r (attempts, backoff).
func Update(dir string, r Request) error {
	// It refuses (fs.ErrNotExist) to recreate a request another drainer
	// already removed.
	if !validID(r.ID) {
		return fmt.Errorf("queue: invalid request id %q", r.ID)
	}
	path := filepath.Join(dir, r.ID+requestExt)
	st, err := fsx.Lstat(path)
	if err != nil {
		return err
	}
	if !st.IsRegular() {
		return fmt.Errorf("%w: queue entry is not a regular file", fsx.ErrUnsafe)
	}
	r.V = Version
	data, err := json.Marshal(r)
	if err != nil {
		return err
	}
	return fsx.WriteFileAtomic(path, data, 0o600)
}

// Remove deletes a request.
func Remove(dir, id string) error {
	if !validID(id) {
		return fmt.Errorf("queue: invalid request id %q", id)
	}
	err := os.Remove(filepath.Join(dir, id+requestExt))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	return fsx.SyncDir(dir)
}

// readRequest reads one request without following symlinks.
func readRequest(path string) (Request, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|fsx.ONoFollow|syscall.O_NONBLOCK, 0)
	if err != nil {
		return Request{}, err
	}
	defer f.Close()
	st, err := fsx.Fstat(f)
	if err != nil {
		return Request{}, err
	}
	if !st.IsRegular() {
		return Request{}, fmt.Errorf("%w: not a regular file", fsx.ErrUnsafe)
	}
	data, err := io.ReadAll(io.LimitReader(f, maxRequestBytes+1))
	if err != nil {
		return Request{}, err
	}
	if len(data) > maxRequestBytes {
		return Request{}, errors.New("queue: request too large")
	}
	var r Request
	if err := json.Unmarshal(data, &r); err != nil {
		return Request{}, err
	}
	return r, nil
}

// idState keeps ids strictly increasing within a process.
var idState struct {
	sync.Mutex
	last int64
}

// newID returns a sortable unique id: 16 hex digits of nanoseconds, a dash,
// 8 random hex digits.
func newID() string {
	idState.Lock()
	n := time.Now().UnixNano()
	if n <= idState.last {
		n = idState.last + 1
	}
	idState.last = n
	idState.Unlock()
	var rnd [4]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		pid := uint32(os.Getpid())
		rnd = [4]byte{byte(pid >> 24), byte(pid >> 16), byte(pid >> 8), byte(pid)}
	}
	return fmt.Sprintf("%016x-%s", uint64(n), hex.EncodeToString(rnd[:]))
}

// validID accepts ids that are safe file names: 1–64 characters of
// [0-9A-Za-z_-] (newID produces a subset; hooks may pass their own).
func validID(id string) bool {
	if id == "" || len(id) > 64 {
		return false
	}
	for _, c := range id {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

// ensureDir creates dir (0700) if missing and requires a private directory
// owned by the current user that is not a symlink.
func ensureDir(dir string) error {
	if dir == "" || !filepath.IsAbs(dir) {
		return fmt.Errorf("queue: directory %q is not absolute", dir)
	}
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
		return fmt.Errorf("%w: queue directory is not a directory", fsx.ErrUnsafe)
	}
	if int(st.UID) != os.Getuid() || st.Mode&0o077 != 0 {
		return fmt.Errorf("%w: queue directory is not private", fsx.ErrUnsafe)
	}
	return nil
}

// createExclusive writes data to dir/name atomically, failing if the name
// exists (temporary + FullSync + link + directory fsync).
func createExclusive(dir, name string, data []byte) error {
	var f *os.File
	var tmp string
	for i := 0; ; i++ {
		tmp = filepath.Join(dir, "."+name+".tmp-"+strconv.Itoa(os.Getpid())+"-"+strconv.Itoa(i))
		var err error
		f, err = os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|fsx.ONoFollow, 0o600)
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
			return fmt.Errorf("%w: queue request %s", fsx.ErrExist, strings.TrimSuffix(name, requestExt))
		}
		return err
	}
	if err := os.Remove(tmp); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return fsx.SyncDir(dir)
}
