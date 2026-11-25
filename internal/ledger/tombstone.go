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
	line, err := json.Marshal(tombstone{H: sidHash(sid), N: n, Dev: st.Dev, Ino: st.Ino})
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
