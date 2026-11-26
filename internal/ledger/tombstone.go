package ledger

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"

	"github.com/Neorichi/precinto/internal/fsx"
)

const (
	// tombstoneFile records, per harness directory, the session ledgers that
	// Archive removed. Entries name the session only by a one-way hash of
	// its id (session ids are random UUIDs), so the file holds no id, path
	// or content of a sealed session (S13, D45).
	tombstoneFile = ".archived"
	// maxTombstoneBytes triggers a rewrite that keeps the newest half.
	maxTombstoneBytes = 1 << 20
)

type tombstone struct {
	H   string `json:"h"`   // sidHash
	N   int64  `json:"n"`   // archived snapshot length
	Dev uint64 `json:"dev"` // identity of the removed file
	Ino uint64 `json:"ino"`
	// The removed file's times. Linux reuses a freed inode number at once,
	// so a new ledger of the same session can get the number of the one
	// Archive removed; the times tell the two apart. Zero in tombstones
	// written before they were recorded.
	MtimeNS int64 `json:"mtime,omitempty"`
	CtimeNS int64 `json:"ctime,omitempty"`
}

// names reports whether st is the file t was written for: the same device
// and inode and, when t recorded them, the same modification and change
// times (an inode number alone may already name a newer file).
func (t tombstone) names(st fsx.Stat) bool {
	if t.Dev != st.Dev || t.Ino != st.Ino {
		return false
	}
	if t.MtimeNS == 0 && t.CtimeNS == 0 {
		return true
	}
	return t.MtimeNS == st.MtimeNS && t.CtimeNS == st.CtimeNS
}

func sidHash(sid string) string {
	sum := sha256.Sum256([]byte("precinto/ledger/archived\x00" + sid))
	return hex.EncodeToString(sum[:16])
}

// findTombstone returns the newest tombstone of (sid, n) in dir.
func findTombstone(dir, sid string, n int64) (tombstone, bool, error) {
	data, err := readTombstones(dir)
	if err != nil {
		return tombstone{}, false, err
	}
	h := sidHash(sid)
	var found tombstone
	ok := false
	for _, line := range bytes.Split(data, []byte("\n")) {
		var t tombstone
		if json.Unmarshal(line, &t) == nil && t.H == h && t.N == n {
			found, ok = t, true
		}
	}
	return found, ok, nil
}

func readTombstones(dir string) ([]byte, error) {
	f, err := os.OpenFile(filepath.Join(dir, tombstoneFile), os.O_RDONLY|fsx.ONoFollow|syscall.O_NONBLOCK, 0)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := fsx.Fstat(f)
	if err != nil {
		return nil, err
	}
	if !st.IsRegular() {
		return nil, fsx.ErrUnsafe
	}
	return io.ReadAll(io.LimitReader(f, 2*maxTombstoneBytes))
}

// addTombstone records that the file st of (sid, n) is about to be
// removed; it is durable before the unlink.
func addTombstone(dir, sid string, n int64, st fsx.Stat) error {
	line, err := json.Marshal(tombstone{H: sidHash(sid), N: n, Dev: st.Dev, Ino: st.Ino, MtimeNS: st.MtimeNS, CtimeNS: st.CtimeNS})
	if err != nil {
		return err
	}
	path := filepath.Join(dir, tombstoneFile)
	if cur, err := fsx.Lstat(path); err == nil && cur.Size > maxTombstoneBytes {
		if err := compactTombstones(path); err != nil {
			return err
		}
	}
	return fsx.AppendLine(path, line)
}

// compactTombstones keeps the newest half of the tombstone file.
func compactTombstones(path string) error {
	data, err := readTombstones(filepath.Dir(path))
	if err != nil {
		return err
	}
	lines := bytes.Split(bytes.TrimSuffix(data, []byte("\n")), []byte("\n"))
	keep := lines[len(lines)/2:]
	return fsx.WriteFileAtomic(path, append(bytes.Join(keep, []byte("\n")), '\n'), 0o600)
}
