package codextest_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/precinto/precinto/internal/harness/codex/codextest"
)

func TestAppenderWritesCodexRecords(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "sessions", "rollout-x.jsonl")
	os.MkdirAll(filepath.Dir(path), 0o755)
	a := codextest.StartAppender(t, path, 5*time.Millisecond)
	if _, err := os.Stat(path); err != nil {
		t.Fatal("the first record is not written synchronously")
	}
	time.Sleep(30 * time.Millisecond)
	n := a.Stop()
	if n < 2 || a.Stop() != n {
		t.Fatalf("Stop = %d", n)
	}
	data, _ := os.ReadFile(path)
	lines := strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
	if len(lines) != n {
		t.Fatalf("%d lines for %d records", len(lines), n)
	}
	for i, l := range lines {
		var rec struct {
			Timestamp string          `json:"timestamp"`
			Ordinal   int             `json:"ordinal"`
			Type      string          `json:"type"`
			Payload   json.RawMessage `json:"payload"`
		}
		if err := json.Unmarshal([]byte(l), &rec); err != nil || rec.Ordinal != i || rec.Timestamp == "" || len(rec.Payload) == 0 {
			t.Fatalf("record %d = %q (%v)", i, l, err)
		}
		if rec.Type != "event_msg" && rec.Type != "response_item" {
			t.Fatalf("record %d type %q", i, rec.Type)
		}
	}
	// The writer keeps its descriptor: an unlinked rollout keeps growing in
	// the unlinked inode, as Codex's writer does.
	b := codextest.StartAppender(t, path, 5*time.Millisecond)
	os.Remove(path)
	time.Sleep(20 * time.Millisecond)
	if b.Stop() < 2 {
		t.Fatal("the appender stopped writing after the unlink")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("the appender recreated the unlinked rollout")
	}
}

func TestOptionsCwdIsRecorded(t *testing.T) {
	t.Parallel()
	h := codextest.New(t, filepath.Join(t.TempDir(), "home"), codextest.Options{Rollouts: 1, Cwd: "/u/work/acme/"})
	data, _ := os.ReadFile(h.Rollouts(t)[0])
	first := strings.SplitN(string(data), "\n", 2)[0]
	var meta struct {
		Type    string `json:"type"`
		Payload struct {
			Cwd string `json:"cwd"`
		} `json:"payload"`
	}
	if err := json.Unmarshal([]byte(first), &meta); err != nil || meta.Type != "session_meta" || meta.Payload.Cwd != "/u/work/acme" {
		t.Fatalf("session_meta = %q", first)
	}
	if msg := expectFatal(t, func(tb testing.TB) {
		codextest.New(tb, filepath.Join(t.TempDir(), "h2"), codextest.Options{Cwd: "relative"})
	}); msg == "" {
		t.Fatal("a relative cwd was accepted")
	}
}
