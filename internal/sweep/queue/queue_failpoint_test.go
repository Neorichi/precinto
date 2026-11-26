//go:build failpoints

package queue_test

import (
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"

	"github.com/Neorichi/precinto/internal/fsx/failpoint"
	"github.com/Neorichi/precinto/internal/sweep/queue"
)

// TestEnqueueLeavesItsFreedTemporaryNameAlone: once Enqueue has removed its
// temporary, another writer of the process may take the same name at once
// (an Update of the request: fsx.WriteFileAtomic builds it the same way).
// Enqueue must not remove that name again after its directory sync: the
// Update's rename then failed and the retry's backoff was lost, which is
// how TestD131HeldRequestIsTriedOnce failed under WSL 2 (a slow sync).
func TestEnqueueLeavesItsFreedTemporaryNameAlone(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "queue")
	const id = "req-1"
	other := filepath.Join(dir, "."+id+".json.tmp-"+strconv.Itoa(os.Getpid())+"-0")
	var once sync.Once
	taken := false
	stop := failpoint.ObserveFS(func(op failpoint.FSOp) {
		if op.Kind != failpoint.FSDirSync || op.Path != dir {
			return
		}
		once.Do(func() {
			// The other writer takes the freed name (plain os: an observer
			// must not call into fsx).
			f, err := os.OpenFile(other, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
			if err != nil {
				t.Errorf("the temporary name was not free at the directory sync: %v", err)
				return
			}
			f.Close()
			taken = true
		})
	})
	defer stop()
	if _, err := queue.Enqueue(dir, queue.Request{ID: id, Harness: "claude-code", SID: "s1", Reason: "other"}); err != nil {
		t.Fatal(err)
	}
	stop()
	if !taken {
		t.Fatal("no directory sync of the queue was observed")
	}
	if _, err := os.Lstat(other); err != nil {
		t.Fatalf("Enqueue removed the temporary name after it had freed it: %v", err)
	}
}
