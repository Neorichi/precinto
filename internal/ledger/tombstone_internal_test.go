package ledger

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Neorichi/precinto/internal/fsx"
	"github.com/Neorichi/precinto/internal/platform"
)

// TestTombstoneNamesOneFileNotAnInode (S13): a tombstone names the file it
// was written for by device, inode and times, so a newer file that got the
// same inode number (Linux reuses a freed one at once) is not taken for it.
// Tombstones written before the times were recorded match by inode alone.
func TestTombstoneNamesOneFileNotAnInode(t *testing.T) {
	p := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(p, []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	st, err := fsx.Lstat(p)
	if err != nil {
		t.Fatal(err)
	}
	tb := tombstone{Dev: st.Dev, Ino: st.Ino, MtimeNS: st.MtimeNS, CtimeNS: st.CtimeNS}
	if !tb.names(st) {
		t.Fatal("a tombstone does not name the file it was written for")
	}
	for name, other := range map[string]fsx.Stat{
		"modified at another time": {Dev: st.Dev, Ino: st.Ino, MtimeNS: st.MtimeNS + 1, CtimeNS: st.CtimeNS},
		"changed at another time":  {Dev: st.Dev, Ino: st.Ino, MtimeNS: st.MtimeNS, CtimeNS: st.CtimeNS + 1},
		"another inode":            {Dev: st.Dev, Ino: st.Ino + 1, MtimeNS: st.MtimeNS, CtimeNS: st.CtimeNS},
	} {
		if tb.names(other) {
			t.Errorf("%s: the tombstone names a different file", name)
		}
	}
	old := tombstone{Dev: st.Dev, Ino: st.Ino}
	if !old.names(fsx.Stat{Dev: st.Dev, Ino: st.Ino, MtimeNS: 1, CtimeNS: 2}) {
		t.Error("a tombstone without times no longer matches by device and inode")
	}
}

// TestRepeatedArchiveKeepsALedgerThatReusedTheInode (S13): journal recovery
// repeats an Archive whose file is gone and finds a newer ledger of the
// same session and length at the same path. Even when that ledger has the
// removed file's inode number, which Linux hands out again at once (the
// tombstone is forged here so the test does not depend on the file system),
// the newer ledger survives.
func TestRepeatedArchiveKeepsALedgerThatReusedTheInode(t *testing.T) {
	l := Open(filepath.Join(t.TempDir(), "state", "sessions"))
	const h, sid = "claude-code", "00000000-0000-4000-8000-0000000000aa"
	e := Event{T: time.Unix(1_700_000_000, 0).UTC(), Harness: h, Type: TypeStart, SID: sid,
		Proc: platform.ProcID{PID: 4242, StartUS: 1_700_000_000_000_000}, Roots: []string{"root-acme"}}
	if err := l.Append(e); err != nil {
		t.Fatal(err)
	}
	_, n, err := l.Snapshot(h, sid)
	if err != nil {
		t.Fatal(err)
	}
	path, err := l.sessionPath(h, sid)
	if err != nil {
		t.Fatal(err)
	}
	st, err := fsx.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	// The removed file had this inode number but other times.
	gone := st
	gone.MtimeNS--
	gone.CtimeNS--
	if err := addTombstone(filepath.Dir(path), sid, n, gone); err != nil {
		t.Fatal(err)
	}
	if err := l.Archive(h, sid, n); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Get(h, sid); err != nil {
		t.Fatalf("a repeated Archive removed a newer ledger that reused the inode: %v", err)
	}
	// The same tombstone with the file's own times is an interrupted Archive
	// of this very file: recovery finishes it.
	if err := addTombstone(filepath.Dir(path), sid, n, st); err != nil {
		t.Fatal(err)
	}
	if err := l.Archive(h, sid, n); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("recovery did not finish an interrupted Archive: %v", err)
	}
}
