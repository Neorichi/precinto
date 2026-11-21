package queue_test

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/precinto/precinto/internal/fsx"
	"github.com/precinto/precinto/internal/platform"
	"github.com/precinto/precinto/internal/sweep/queue"
)

var t0 = time.Date(2026, 11, 21, 9, 0, 0, 0, time.UTC)

func qdir(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "state", "queue")
}

func TestEnqueueListUpdateRemove(t *testing.T) {
	dir := qdir(t)
	r := queue.Request{
		Harness: "claude-code", SID: "00000000-0000-4000-8000-000000000001", Reason: "prompt_input_exit",
		WaitFor: platform.ProcID{PID: 4242, StartUS: 1}, ConfigDir: "/x/claude", At: t0,
	}
	id, err := queue.Enqueue(dir, r)
	if err != nil || id == "" {
		t.Fatalf("enqueue: %q %v", id, err)
	}
	list, err := queue.List(dir)
	if err != nil || len(list) != 1 {
		t.Fatalf("list: %v %v", list, err)
	}
	got := list[0]
	if got.ID != id || got.V != queue.Version || got.SID != r.SID || got.WaitFor != r.WaitFor || !got.At.Equal(t0) {
		t.Fatalf("request %+v", got)
	}
	got.Attempts, got.NotBefore = 2, t0.Add(time.Minute)
	if err := queue.Update(dir, got); err != nil {
		t.Fatal(err)
	}
	list, _ = queue.List(dir)
	if list[0].Attempts != 2 || !list[0].NotBefore.Equal(t0.Add(time.Minute)) {
		t.Fatalf("update lost: %+v", list[0])
	}
	if err := queue.Remove(dir, id); err != nil {
		t.Fatal(err)
	}
	if err := queue.Remove(dir, id); err != nil {
		t.Fatalf("second remove: %v", err)
	}
	if list, _ := queue.List(dir); len(list) != 0 {
		t.Fatalf("after remove: %v", list)
	}
	if err := queue.Update(dir, got); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("update resurrected a removed request: %v", err)
	}
}

func TestEnqueueIsAtomicAndExclusive(t *testing.T) {
	dir := qdir(t)
	id, err := queue.Enqueue(dir, queue.Request{ID: "fixed-id", Harness: "codex", Reason: "codex-exit"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := queue.Enqueue(dir, queue.Request{ID: id, Harness: "codex", Reason: "other"}); !errors.Is(err, fsx.ErrExist) {
		t.Fatalf("duplicate id: %v", err)
	}
	list, _ := queue.List(dir)
	if len(list) != 1 || list[0].Reason != "codex-exit" {
		t.Fatalf("existing request replaced: %+v", list)
	}
	ents, _ := os.ReadDir(dir)
	if len(ents) != 1 {
		t.Fatalf("temporaries left: %v", ents)
	}
	if fi, _ := os.Stat(filepath.Join(dir, id+".json")); fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", fi.Mode().Perm())
	}
	if fi, _ := os.Stat(dir); fi.Mode().Perm() != 0o700 {
		t.Fatalf("dir mode %v", fi.Mode().Perm())
	}
}

func TestListSkipsForeignAndPartialFiles(t *testing.T) {
	dir := qdir(t)
	if _, err := queue.Enqueue(dir, queue.Request{Harness: "claude-code", Reason: "other"}); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(dir, "garbage.json"), []byte("{"), 0o600)
	_ = os.WriteFile(filepath.Join(dir, ".partial.json.tmp-1-0"), []byte(`{"id":"partial"}`), 0o600)
	_ = os.WriteFile(filepath.Join(dir, "other.txt"), []byte("x"), 0o600)
	_ = os.WriteFile(filepath.Join(dir, "mismatch.json"), []byte(`{"id":"different"}`), 0o600)
	_ = os.Symlink("/etc/hosts", filepath.Join(dir, "link.json"))
	list, err := queue.List(dir)
	if err != nil || len(list) != 1 {
		t.Fatalf("list %+v %v", list, err)
	}
}

func TestListOrdersByAt(t *testing.T) {
	dir := qdir(t)
	for _, d := range []time.Duration{3, 1, 2} {
		if _, err := queue.Enqueue(dir, queue.Request{Harness: "claude-code", Reason: "other", At: t0.Add(d * time.Minute)}); err != nil {
			t.Fatal(err)
		}
	}
	list, _ := queue.List(dir)
	for i := 1; i < len(list); i++ {
		if list[i].At.Before(list[i-1].At) {
			t.Fatalf("not ordered by At: %v", list)
		}
	}
}

func TestInvalidIDsAreRefused(t *testing.T) {
	dir := qdir(t)
	for _, id := range []string{"../escape", "a/b", strings.Repeat("x", 65), "dot.dot"} {
		if _, err := queue.Enqueue(dir, queue.Request{ID: id}); err == nil {
			t.Errorf("Enqueue accepted %q", id)
		}
		if err := queue.Remove(dir, id); err == nil {
			t.Errorf("Remove accepted %q", id)
		}
		if err := queue.Update(dir, queue.Request{ID: id}); err == nil {
			t.Errorf("Update accepted %q", id)
		}
	}
	if err := queue.Remove(dir, ""); err == nil {
		t.Error("Remove accepted an empty id")
	}
}

func TestConcurrentEnqueuesGetDistinctIDs(t *testing.T) {
	dir := qdir(t)
	var wg sync.WaitGroup
	var mu sync.Mutex
	ids := map[string]bool{}
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			id, err := queue.Enqueue(dir, queue.Request{Harness: "claude-code", Reason: "other"})
			if err != nil {
				t.Error(err)
				return
			}
			mu.Lock()
			ids[id] = true
			mu.Unlock()
		}()
	}
	wg.Wait()
	if list, _ := queue.List(dir); len(list) != 50 || len(ids) != 50 {
		t.Fatalf("%d requests, %d ids", len(list), len(ids))
	}
}

func TestRelativeDirectoryRefused(t *testing.T) {
	if _, err := queue.Enqueue("state/queue", queue.Request{}); err == nil {
		t.Fatal("relative queue directory accepted")
	}
}

// FX-G4-20: a FIFO named like a request is skipped without blocking.
func TestListNeverBlocksOnAFIFORequest(t *testing.T) {
	t.Parallel()
	dir := filepath.Join(t.TempDir(), "queue")
	id, err := queue.Enqueue(dir, queue.Request{Harness: "claude-code", SID: "s", Reason: "other"})
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(dir, "fifo-request.json"), 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan []queue.Request)
	go func() {
		reqs, _ := queue.List(dir)
		done <- reqs
	}()
	select {
	case reqs := <-done:
		if len(reqs) != 1 || reqs[0].ID != id {
			t.Fatalf("List = %+v", reqs)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("List blocked on a FIFO")
	}
}
