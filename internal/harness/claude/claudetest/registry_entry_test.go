package claudetest_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Neorichi/precinto/internal/harness/claude"
	"github.com/Neorichi/precinto/internal/harness/claude/claudetest"
)

func TestWriteRegistryEntryWritesEveryField(t *testing.T) {
	t.Parallel()
	l := claudetest.New(t, t.TempDir())
	started := time.Date(2026, 11, 21, 8, 0, 0, 0, time.UTC)
	mtime := started.Add(time.Minute)
	path := l.WriteRegistryEntry(t, claude.RegistryEntry{
		PID: 77, SessionID: testSID, Cwd: "/u/work/acme", Status: "busy", WaitingFor: "permission",
		Kind: "background", Entrypoint: "sdk-cli", StartedAt: started, Mtime: mtime, Valid: true,
		Path: "/ignored",
	})
	if path != filepath.Join(l.ConfigDir, "sessions", "77.json") {
		t.Fatalf("path %s", path)
	}
	var got map[string]any
	data, _ := os.ReadFile(path)
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	want := map[string]any{"pid": 77.0, "sessionId": testSID, "cwd": "/u/work/acme", "status": "busy",
		"waitingFor": "permission", "kind": "background", "entrypoint": "sdk-cli", "startedAt": float64(started.UnixMilli())}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %v, want %v", k, got[k], v)
		}
	}
	if fi, _ := os.Stat(path); !fi.ModTime().Equal(mtime) {
		t.Errorf("mtime %v, want %v", fi.ModTime(), mtime)
	}
	// Read back through the adapter's reader.
	entries, err := claude.ReadRegistry(l.ConfigDir)
	if err != nil || len(entries) != 1 || !entries[0].Valid || !entries[0].StartedAt.Equal(started) || entries[0].Kind != "background" {
		t.Fatalf("ReadRegistry = %+v %v", entries, err)
	}
	// Optional fields are omitted; Valid=false writes a half-written file.
	bare := l.WriteRegistryEntry(t, claude.RegistryEntry{PID: 78, SessionID: testSID, Valid: true})
	data, _ = os.ReadFile(bare)
	var m map[string]any
	json.Unmarshal(data, &m)
	for _, k := range []string{"startedAt", "status", "waitingFor"} {
		if _, ok := m[k]; ok {
			t.Errorf("%s written although empty", k)
		}
	}
	half := l.WriteRegistryEntry(t, claude.RegistryEntry{PID: 79, SessionID: testSID})
	data, _ = os.ReadFile(half)
	if json.Valid(data) {
		t.Fatal("an invalid entry must be half-written JSON")
	}
	matches, _ := filepath.Glob(filepath.Join(l.ConfigDir, "sessions", "79.*.key"))
	if len(matches) != 1 {
		t.Fatalf("the .key sibling was not written: %v", matches)
	}
	if msg := expectFatal(t, func(tb testing.TB) { l.WriteRegistryEntry(tb, claude.RegistryEntry{PID: 0}) }); msg == "" {
		t.Fatal("pid 0 accepted")
	}
}
