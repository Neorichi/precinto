package journal

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/precinto/precinto/internal/fsx"
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
