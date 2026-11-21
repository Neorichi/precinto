package claudetest

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/precinto/precinto/internal/harness/claude"
)

// writeRegistry writes $CC/sessions/<pid>.json. A valid entry is replaced
// atomically; an invalid one is the first half of the valid JSON, as a
// reader racing Claude's write sees it (half-written, D18, LIVE-9). The
// <pid>.<64 hex>.key sibling that Claude creates first is written once per
// pid with synthetic, non-secret content.
func writeRegistry(t testing.TB, l *Layout, pid int, sid, cwd, status string, valid bool) string {
	t.Helper()
	if l == nil {
		t.Fatalf("claudetest: nil *Layout")
	}
	cfg := baseDir(t, "ConfigDir", l.ConfigDir)
	if pid <= 0 {
		t.Fatalf("claudetest: WriteRegistry needs a positive pid, got %d", pid)
	}
	dir := filepath.Join(cfg, "sessions")
	mkdirs(t, cfg, dir)
	ensureRegistryKey(t, cfg, dir, pid)
	data := encodeJSON(t, registryFile{
		PID:        pid,
		SessionID:  sid,
		Cwd:        cwd,
		StartedAt:  time.Now().UnixMilli(),
		ProcStart:  "claudetest-procstart-" + strconv.Itoa(pid),
		Kind:       "interactive",
		Entrypoint: "cli",
		Status:     status,
	})
	path := filepath.Join(dir, strconv.Itoa(pid)+".json")
	if !valid {
		// A strict prefix of a JSON object never parses.
		data = data[:len(data)/2]
	}
	writeReplace(t, cfg, path, data)
	return path
}

// registryEntryFile is sessions/<pid>.json as WriteRegistryEntry writes it:
// startedAt is omitted when zero (LIVE-5), status and waitingFor when empty
// (Claude omits status until the first turn).
type registryEntryFile struct {
	PID        int    `json:"pid"`
	SessionID  string `json:"sessionId"`
	Cwd        string `json:"cwd"`
	StartedAt  *int64 `json:"startedAt,omitempty"` // Unix milliseconds
	ProcStart  string `json:"procStart"`
	Kind       string `json:"kind"`
	Entrypoint string `json:"entrypoint"`
	Status     string `json:"status,omitempty"`
	WaitingFor string `json:"waitingFor,omitempty"`
}

// writeRegistryEntry writes $CC/sessions/<pid>.json from every field of e:
// Valid=false writes the first half of the JSON (half-written, LIVE-9); a
// non-zero Mtime is applied to the file. e.Path is ignored: the path is
// always sessions/<e.PID>.json and is returned.
func writeRegistryEntry(t testing.TB, l *Layout, e claude.RegistryEntry) string {
	t.Helper()
	if l == nil {
		t.Fatalf("claudetest: nil *Layout")
	}
	cfg := baseDir(t, "ConfigDir", l.ConfigDir)
	if e.PID <= 0 {
		t.Fatalf("claudetest: WriteRegistryEntry needs a positive pid, got %d", e.PID)
	}
	dir := filepath.Join(cfg, "sessions")
	mkdirs(t, cfg, dir)
	ensureRegistryKey(t, cfg, dir, e.PID)
	rec := registryEntryFile{
		PID:        e.PID,
		SessionID:  e.SessionID,
		Cwd:        e.Cwd,
		ProcStart:  "claudetest-procstart-" + strconv.Itoa(e.PID),
		Kind:       e.Kind,
		Entrypoint: e.Entrypoint,
		Status:     e.Status,
		WaitingFor: e.WaitingFor,
	}
	if !e.StartedAt.IsZero() {
		ms := e.StartedAt.UnixMilli()
		rec.StartedAt = &ms
	}
	data := encodeJSON(t, rec)
	if !e.Valid {
		data = data[:len(data)/2]
	}
	path := filepath.Join(dir, strconv.Itoa(e.PID)+".json")
	writeReplace(t, cfg, path, data)
	setMtime(t, path, e.Mtime)
	return path
}

func ensureRegistryKey(t testing.TB, cfg, dir string, pid int) {
	t.Helper()
	prefix := strconv.Itoa(pid) + "."
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("claudetest: read %s: %v", dir, err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), prefix) && strings.HasSuffix(e.Name(), ".key") {
			return
		}
	}
	const keySize = 108
	content := bytes.Repeat([]byte("claudetest-registry-key-not-a-secret."), 3)[:keySize-1]
	content = append(content, '\n')
	name := prefix + fixtureHex(64, "registry-key", strconv.Itoa(pid)) + ".key"
	createFile(t, cfg, filepath.Join(dir, name), content, time.Time{}, true)
}

// writeHistory appends n history.jsonl lines for (project, sid). Even lines
// paste text: their pastedContents reference paste-cache/<contentHash>.txt,
// named by the hash of the pasted text, so equal pastes share one entry
// across projects as in Claude. Timestamps (Unix ms) increase across calls.
func writeHistory(t testing.TB, l *Layout, project, sid string, n int, marker string) {
	t.Helper()
	if l == nil {
		t.Fatalf("claudetest: nil *Layout")
	}
	cfg := baseDir(t, "ConfigDir", l.ConfigDir)
	checkMarker(t, marker)
	if n < 0 {
		t.Fatalf("claudetest: WriteHistory needs n >= 0, got %d", n)
	}
	if n == 0 {
		return
	}
	path := filepath.Join(cfg, "history.jsonl")
	base := time.Now().UnixMilli()
	if last, ok := lastHistoryTimestamp(path); ok && last >= base {
		base = last + 1
	}
	f := openAppend(t, cfg, path)
	defer f.Close()
	for i := 0; i < n; i++ {
		line := historyLine{
			Display:        withMarker(marker, "claudetest history prompt "+strconv.Itoa(i)),
			PastedContents: map[string]pasteRef{},
			Timestamp:      base + int64(i),
			Project:        project,
			SessionID:      sid,
		}
		if i%2 == 0 {
			text := "claudetest pasted text " + strconv.Itoa(i) + "\n" + withMarker(marker, "pasted body") + "\n"
			hash := fixtureHex(16, "paste", text)
			createFile(t, cfg, filepath.Join(cfg, "paste-cache", hash+".txt"), []byte(text), time.Time{}, true)
			line.PastedContents["1"] = pasteRef{ID: 1, Type: "text", ContentHash: hash}
			line.Display = "[Pasted text #1 +2 lines] " + line.Display
		}
		// One write per line, as Claude appends: concurrent writers never
		// interleave inside a line.
		if _, err := f.Write(encodeLine(t, line)); err != nil {
			t.Fatalf("claudetest: append %s: %v", path, err)
		}
	}
	if err := f.Close(); err != nil {
		t.Fatalf("claudetest: close %s: %v", path, err)
	}
}

// lastHistoryTimestamp returns the timestamp of the last parseable line of
// history.jsonl.
func lastHistoryTimestamp(path string) (int64, bool) {
	f, err := os.Open(path)
	if err != nil {
		return 0, false
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() {
		return 0, false
	}
	off := max(fi.Size()-tailWindow, 0)
	buf := make([]byte, fi.Size()-off)
	n, err := f.ReadAt(buf, off)
	if err != nil && !errors.Is(err, io.EOF) {
		return 0, false
	}
	lines := bytes.Split(buf[:n], []byte("\n"))
	for i := len(lines) - 1; i >= 0; i-- {
		var rec struct {
			Timestamp int64 `json:"timestamp"`
		}
		if json.Unmarshal(lines[i], &rec) == nil && rec.Timestamp > 0 {
			return rec.Timestamp, true
		}
	}
	return 0, false
}

// writeJob writes $CC/jobs/<id>/state.json atomically (a job record is
// rewritten as its state changes).
func writeJob(t testing.TB, l *Layout, id, sid, state string) {
	t.Helper()
	if l == nil {
		t.Fatalf("claudetest: nil *Layout")
	}
	cfg := baseDir(t, "ConfigDir", l.ConfigDir)
	checkComponent(t, "job id", id)
	path := filepath.Join(cfg, "jobs", id, "state.json")
	writeReplace(t, cfg, path, encodeJSON(t, jobFile{ID: id, SessionID: sid, State: state, UpdatedAt: time.Now().UnixMilli()}))
}

// appendFragment appends `lines` records to projects/<P>/<sid>.jsonl the
// way Claude does after the transcript was moved away (E8): O_APPEND with
// O_CREATE, one write per record. The first record's parentUuid is the
// last uuid of the file when it exists and has one, else the last uuid of
// the original transcript of s (recomputed, so the original may be gone).
// Fragment uuids are disjoint from the original's and from earlier
// fragments'.
func appendFragment(t testing.TB, l *Layout, s Session, lines int) string {
	t.Helper()
	w := newSessionWriter(t, l, s)
	if lines < 1 {
		t.Fatalf("claudetest: AppendFragment needs at least one line, got %d", lines)
	}
	path := w.transcriptPath()
	parent := tailFacts(path).UUID
	if parent == "" {
		parent = w.lastUUID()
	}
	nonce := strconv.FormatInt(time.Now().UnixNano(), 10)
	f := openAppend(t, w.cfg, path)
	defer f.Close()
	now := time.Now().UTC()
	for i := 0; i < lines; i++ {
		uuid := fixtureUUID("fragment", s.SID, parent, nonce, strconv.Itoa(i))
		at := now.Add(time.Duration(i) * time.Millisecond)
		p := parent
		var rec convRecord
		if i%2 == 0 {
			rec = w.conv("assistant", &p, uuid, at, assistant(w.messageID("fragment-"+nonce, i), "end_turn",
				textBlock{Type: "text", Text: w.text("claudetest fragment answer %d", i)}), "")
			rec.RequestID = w.requestID("fragment-"+nonce, i)
		} else {
			rec = w.conv("user", &p, uuid, at, userTextMessage{Role: "user", Content: w.text("claudetest fragment prompt %d", i)}, "")
		}
		if _, err := f.Write(encodeLine(t, rec)); err != nil {
			t.Fatalf("claudetest: append %s: %v", path, err)
		}
		parent = uuid
	}
	if err := f.Close(); err != nil {
		t.Fatalf("claudetest: close %s: %v", path, err)
	}
	return path
}
