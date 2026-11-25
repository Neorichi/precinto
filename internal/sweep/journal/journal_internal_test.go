package journal

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/precinto/precinto/internal/fsx"
	"github.com/precinto/precinto/internal/testkit"
)

// TestCreateExclusiveNeverReplaces is the O_EXCL-create rule: a record name
// that exists is never overwritten, and nothing is left behind.
func TestCreateExclusiveNeverReplaces(t *testing.T) {
	dir := t.TempDir()
	name := NewID() + recordExt
	if err := createExclusive(dir, name, []byte(`{"v":1}`)); err != nil {
		t.Fatal(err)
	}
	if err := createExclusive(dir, name, []byte(`{"v":2}`)); !errors.Is(err, fsx.ErrExist) {
		t.Fatalf("second create: %v, want ErrExist", err)
	}
	b, _ := os.ReadFile(filepath.Join(dir, name))
	if string(b) != `{"v":1}` {
		t.Fatalf("record replaced: %q", b)
	}
	ents, _ := os.ReadDir(dir)
	if len(ents) != 1 {
		t.Fatalf("temporaries left: %v", ents)
	}
}

func TestValidID(t *testing.T) {
	if !validID(NewID()) {
		t.Fatal("NewID output rejected")
	}
	for _, bad := range []string{"", "x", "0123456789abcdef-0123456", "0123456789abcdef_01234567", "0123456789ABCDEF-01234567", "../../../../../etc/passwd"} {
		if validID(bad) {
			t.Errorf("validID(%q) = true", bad)
		}
	}
}

// FX-G4-20: a FIFO named like a record is reported by Pending without
// blocking, and the readable records are still returned.
func TestPendingNeverBlocksOnAFIFORecord(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "journal")
	j := Open(dir)
	ok, err := j.Begin(KindSeal, "claude-code", "0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	if err := testkit.Mkfifo(filepath.Join(dir, NewID()+recordExt), 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	var recs []*Record
	go func() { defer close(done); recs, err = j.Pending() }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Pending blocked on a FIFO")
	}
	if !errors.Is(err, fsx.ErrUnsafe) || len(recs) != 1 || recs[0].ID != ok.ID {
		t.Fatalf("Pending = %d records, %v", len(recs), err)
	}
}
