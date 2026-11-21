package codextest

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Shapes of a Codex 0.154 home (codex-rs: rollout/src/recorder.rs,
// rollout_file_name.rs, message-history, rollout/src/session_index.rs,
// state/src/sqlite.rs, core/src/shell_snapshot.rs). Values are synthetic.
const (
	cliVersion   = "0.154.0"
	originator   = "codex_cli_rs"
	fixtureModel = "gpt-codextest"

	rolloutSpan = 30 * time.Second // wall time of one synthetic session
	rolloutGap  = time.Minute      // between the ends of successive sessions
	lineGap     = 3 * time.Second  // between rollout lines

	sqlitePage = 4096
	shmSize    = 32 << 10
)

// databases are the *_N.sqlite files written as opaque bytes (no SQLite
// driver is linked; precinto never opens Codex databases, SPEC §7.2).
var databases = []string{"state_5.sqlite", "logs_2.sqlite", "thread_history_1.sqlite"}

// walDatabase is the database that gets -wal/-shm siblings with WithWAL.
const walDatabase = "state_5.sqlite"

type thread struct {
	index int
	id    string
	start time.Time // UTC, millisecond precision
	end   time.Time
	rel   string // home-relative rollout path
}

type generator struct {
	t       testing.TB
	home    string
	o       Options
	cwd     string    // recorded session cwd (only recorded, never created)
	last    time.Time // newest activity: now − RolloutAge
	threads []thread
}

func newHome(t testing.TB, dir string, o Options) *Home {
	t.Helper()
	home := homeDir(t, dir)
	checkMarker(t, o.Marker)
	if o.Rollouts < 0 {
		t.Fatalf("codextest: Options.Rollouts=%d is negative", o.Rollouts)
	}
	cwd := filepath.Join(filepath.Dir(home), "codextest-workspace")
	if o.Cwd != "" {
		if !filepath.IsAbs(o.Cwd) {
			t.Fatalf("codextest: Options.Cwd must be absolute (Codex records absolute cwds), got %q", o.Cwd)
		}
		cwd = filepath.Clean(o.Cwd)
	}
	g := &generator{
		t:    t,
		home: home,
		o:    o,
		cwd:  cwd,
		last: time.Now().Add(-o.RolloutAge).UTC().Truncate(time.Millisecond),
	}
	mkdirs(t, home, home, homePerm)
	g.plan()
	for _, th := range g.threads {
		g.writeRollout(th)
	}
	g.writeHistory()
	g.writeSessionIndex()
	g.writeDatabases()
	g.writeShellSnapshot()
	g.writePlaceholders()
	if o.WithLocks {
		g.writeLocks()
	}
	return &Home{Dir: home}
}

// plan names one rollout per session: sessions/YYYY/MM/DD (local date of
// the start) / rollout-<local start>-<thread id>.jsonl, the sessions ending
// rolloutGap apart, the newest at now − RolloutAge.
func (g *generator) plan() {
	n := g.o.Rollouts
	for i := 0; i < n; i++ {
		end := g.last.Add(-time.Duration(n-1-i) * rolloutGap)
		start := end.Add(-rolloutSpan)
		id := threadID(start, g.home, strconv.Itoa(i), g.o.Marker)
		local := start.In(time.Local)
		name := "rollout-" + local.Format("2006-01-02T15-04-05") + "-" + id + ".jsonl"
		rel := filepath.Join("sessions", local.Format("2006"), local.Format("01"), local.Format("02"), name)
		g.threads = append(g.threads, thread{index: i, id: id, start: start, end: end, rel: rel})
	}
}

func (g *generator) text(format string, args ...any) string {
	return withMarker(g.o.Marker, fmt.Sprintf(format, args...))
}

func utcMillis(at time.Time) string { return at.UTC().Format("2006-01-02T15:04:05.000Z") }

// Rollout line shapes: {timestamp, ordinal, type, payload} (RolloutLine;
// ordinals are written for paginated history, the 0.154 default).
type rolloutLine struct {
	Timestamp string `json:"timestamp"`
	Ordinal   int    `json:"ordinal"`
	Type      string `json:"type"`
	Payload   any    `json:"payload"`
}

type sessionMeta struct {
	SessionID        string           `json:"session_id"`
	ID               string           `json:"id"`
	Timestamp        string           `json:"timestamp"`
	Cwd              string           `json:"cwd"`
	Originator       string           `json:"originator"`
	CLIVersion       string           `json:"cli_version"`
	Source           string           `json:"source"`
	ThreadSource     string           `json:"thread_source"`
	ModelProvider    string           `json:"model_provider"`
	BaseInstructions baseInstructions `json:"base_instructions"`
	HistoryMode      string           `json:"history_mode"`
}

type baseInstructions struct {
	Text string `json:"text"`
}

type turnContext struct {
	TurnID         string        `json:"turn_id"`
	Cwd            string        `json:"cwd"`
	ApprovalPolicy string        `json:"approval_policy"`
	SandboxPolicy  sandboxPolicy `json:"sandbox_policy"`
	Model          string        `json:"model"`
}

type sandboxPolicy struct {
	Type string `json:"type"`
}

type messageItem struct {
	Type    string        `json:"type"`
	Role    string        `json:"role"`
	Content []contentItem `json:"content"`
}

type contentItem struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type customToolCall struct {
	Type   string `json:"type"`
	Status string `json:"status"`
	CallID string `json:"call_id"`
	Name   string `json:"name"`
	Input  string `json:"input"`
}

type toolOutput struct {
	Type   string `json:"type"`
	CallID string `json:"call_id"`
	Output string `json:"output"`
}

type functionCall struct {
	Type      string `json:"type"`
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
	CallID    string `json:"call_id"`
}

type eventMessage struct {
	Type    string `json:"type"`
	Message string `json:"message"`
}

type historyEntry struct {
	SessionID string `json:"session_id"`
	TS        int64  `json:"ts"` // Unix seconds
	Text      string `json:"text"`
}

type sessionIndexEntry struct {
	ID         string `json:"id"`
	ThreadName string `json:"thread_name"`
	UpdatedAt  string `json:"updated_at"`
}

func (g *generator) callID(th thread, kind string) string {
	return "call_" + fmt.Sprintf("%x", digest("call", th.id, kind)[:12])
}

// writeRollout writes one session: session_meta, turn_context, the user
// prompt, an apply_patch that adds a Markdown note, a shell call and the
// answer; the marker is in the prompt, the tool inputs and outputs and the
// answer. The file's mtime is the session's end.
func (g *generator) writeRollout(th thread) {
	t := g.t
	t.Helper()
	prompt := g.text("codextest prompt %d", th.index)
	answer := g.text("codextest answer %d", th.index)
	patch := fmt.Sprintf("*** Begin Patch\n*** Add File: docs/notes-%d.md\n+# codextest note %d\n+%s\n*** End Patch\n",
		th.index, th.index, g.text("codextest note body %d", th.index))
	args := string(encodeLine(t, map[string]any{
		"command": []string{"bash", "-lc", "grep -rn '" + g.text("needle") + "' ."},
		"workdir": g.cwd,
	}))
	args = strings.TrimSuffix(args, "\n")
	payloads := []struct {
		typ     string
		payload any
	}{
		{"session_meta", sessionMeta{
			SessionID: th.id, ID: th.id, Timestamp: utcMillis(th.start), Cwd: g.cwd,
			Originator: originator, CLIVersion: cliVersion, Source: "cli", ThreadSource: "user",
			ModelProvider: "openai", BaseInstructions: baseInstructions{Text: "codextest base instructions"},
			HistoryMode: "paginated",
		}},
		{"turn_context", turnContext{
			TurnID: fmt.Sprintf("%x", digest("turn", th.id)[:8]), Cwd: g.cwd, ApprovalPolicy: "on-request",
			SandboxPolicy: sandboxPolicy{Type: "workspace-write"}, Model: fixtureModel,
		}},
		{"response_item", messageItem{Type: "message", Role: "user", Content: []contentItem{{Type: "input_text", Text: prompt}}}},
		{"event_msg", eventMessage{Type: "user_message", Message: prompt}},
		{"response_item", customToolCall{Type: "custom_tool_call", Status: "completed", CallID: g.callID(th, "patch"), Name: "apply_patch", Input: patch}},
		{"response_item", toolOutput{Type: "custom_tool_call_output", CallID: g.callID(th, "patch"),
			Output: fmt.Sprintf("Success. Updated the following files:\nA docs/notes-%d.md\n", th.index)}},
		{"response_item", functionCall{Type: "function_call", Name: "shell", Arguments: args, CallID: g.callID(th, "shell")}},
		{"response_item", toolOutput{Type: "function_call_output", CallID: g.callID(th, "shell"), Output: g.text("codextest shell output") + "\n"}},
		{"response_item", messageItem{Type: "message", Role: "assistant", Content: []contentItem{{Type: "output_text", Text: answer}}}},
		{"event_msg", eventMessage{Type: "agent_message", Message: answer}},
	}
	var data []byte
	for i, p := range payloads {
		data = append(data, encodeLine(t, rolloutLine{
			Timestamp: utcMillis(th.start.Add(time.Duration(i) * lineGap)),
			Ordinal:   i,
			Type:      p.typ,
			Payload:   p.payload,
		})...)
	}
	createFile(t, g.home, filepath.Join(g.home, th.rel), data, filePerm, th.end)
}

// writeHistory writes history.jsonl (0600, as Codex forces): one prompt
// per session.
func (g *generator) writeHistory() {
	t := g.t
	t.Helper()
	if len(g.threads) == 0 {
		return
	}
	var data []byte
	for _, th := range g.threads {
		data = append(data, encodeLine(t, historyEntry{SessionID: th.id, TS: th.start.Unix(), Text: g.text("codextest prompt %d", th.index)})...)
	}
	createFile(t, g.home, filepath.Join(g.home, "history.jsonl"), data, privatePerm, g.last)
}

// writeSessionIndex writes session_index.jsonl: thread names derive from
// content, so they carry the marker.
func (g *generator) writeSessionIndex() {
	t := g.t
	t.Helper()
	if len(g.threads) == 0 {
		return
	}
	var data []byte
	for _, th := range g.threads {
		data = append(data, encodeLine(t, sessionIndexEntry{
			ID: th.id, ThreadName: g.text("codextest thread %d", th.index), UpdatedAt: th.end.UTC().Format(time.RFC3339Nano),
		})...)
	}
	createFile(t, g.home, filepath.Join(g.home, "session_index.jsonl"), data, filePerm, g.last)
}

// writeDatabases writes the *_N.sqlite files as opaque bytes that look like
// SQLite (a database header page, then pages holding the content Codex keeps
// there: titles in state, prompts in logs, items in thread_history), plus
// state_5.sqlite-wal and -shm with WithWAL. The -shm (a wal-index, never
// sealed) holds no content and so no marker.
func (g *generator) writeDatabases() {
	t := g.t
	t.Helper()
	for _, name := range databases {
		var payload []byte
		for _, th := range g.threads {
			var row string
			switch name {
			case "state_5.sqlite":
				row = fmt.Sprintf("threads|%s|%s|%s|cli\n", th.id, filepath.ToSlash(th.rel), g.text("codextest thread %d", th.index))
			case "logs_2.sqlite":
				row = fmt.Sprintf("logs|DEBUG|codex_core::session::handlers|%s|%s\n", th.id, g.text("codextest prompt %d", th.index))
			default:
				row = fmt.Sprintf("thread_items|%s|userMessage|{\"text\":\"%s\"}\n", th.id, g.text("codextest prompt %d", th.index))
			}
			payload = append(payload, row...)
		}
		createFile(t, g.home, filepath.Join(g.home, name), sqliteBytes(payload), filePerm, g.last)
	}
	if !g.o.WithWAL {
		return
	}
	frame := "wal|threads|pending\n"
	if n := len(g.threads); n > 0 {
		th := g.threads[n-1]
		frame = fmt.Sprintf("wal|threads|%s|%s\n", th.id, g.text("codextest pending title %d", th.index))
	}
	createFile(t, g.home, filepath.Join(g.home, walDatabase+"-wal"), walBytes([]byte(frame)), filePerm, g.last)
	createFile(t, g.home, filepath.Join(g.home, walDatabase+"-shm"), make([]byte, shmSize), filePerm, g.last)
}

// sqliteBytes is a database file: a header page and the payload pages.
func sqliteBytes(payload []byte) []byte {
	pages := 1 + max(1, (len(payload)+sqlitePage-1)/sqlitePage)
	b := make([]byte, pages*sqlitePage)
	copy(b, "SQLite format 3\x00")
	binary.BigEndian.PutUint16(b[16:], sqlitePage)
	b[18], b[19] = 2, 2 // WAL journal mode
	b[21], b[22], b[23] = 64, 32, 32
	binary.BigEndian.PutUint32(b[28:], uint32(pages))
	binary.BigEndian.PutUint32(b[44:], 4) // schema format
	binary.BigEndian.PutUint32(b[56:], 1) // UTF-8
	copy(b[sqlitePage:], payload)
	return b
}

// walBytes is a write-ahead log: the WAL header and one frame.
func walBytes(page []byte) []byte {
	b := make([]byte, 32+24+sqlitePage)
	binary.BigEndian.PutUint32(b[0:], 0x377f0682)
	binary.BigEndian.PutUint32(b[4:], 3007000)
	binary.BigEndian.PutUint32(b[8:], sqlitePage)
	binary.BigEndian.PutUint32(b[32:], 2) // frame: page number
	binary.BigEndian.PutUint32(b[36:], 2) // frame: database size after commit
	copy(b[56:], page)
	return b
}

// writeShellSnapshot leaves shell_snapshots/<thread>.<nanos>.sh of the
// newest session, as a session that did not shut down cleanly does.
func (g *generator) writeShellSnapshot() {
	t := g.t
	t.Helper()
	if len(g.threads) == 0 {
		return
	}
	th := g.threads[len(g.threads)-1]
	name := th.id + "." + strconv.FormatInt(th.start.UnixNano(), 10) + ".sh"
	data := "# codextest synthetic shell snapshot (no real environment)\nexport CODEXTEST_FIXTURE='" + g.text("codextest snapshot") + "'\n"
	createFile(t, g.home, filepath.Join(g.home, "shell_snapshots", name), []byte(data), filePerm, g.last)
}

// writePlaceholders writes auth.json and config.toml unless present (they
// are never-touch files; a home seeded by PrepareHome keeps its own). They
// hold no marker: they stay in plaintext when the home is sealed.
func (g *generator) writePlaceholders() {
	t := g.t
	t.Helper()
	auth := "{\n" +
		"  \"OPENAI_API_KEY\": null,\n" +
		"  \"tokens\": {\n" +
		"    \"id_token\": \"codextest-placeholder\",\n" +
		"    \"access_token\": \"codextest-placeholder\",\n" +
		"    \"refresh_token\": \"codextest-placeholder\",\n" +
		"    \"account_id\": \"codextest-account\"\n" +
		"  },\n" +
		"  \"last_refresh\": \"" + time.Now().UTC().Format(time.RFC3339) + "\"\n" +
		"}\n"
	g.createIfAbsent(filepath.Join(g.home, "auth.json"), []byte(auth), privatePerm)
	config := "# codextest placeholder configuration (synthetic, no user data)\n" +
		"model = " + tomlString(fixtureModel) + "\n" +
		"model_reasoning_effort = \"low\"\n" +
		"sqlite_home = " + tomlString(g.home) + "\n" +
		"log_dir = " + tomlString(filepath.Join(g.home, "log")) + "\n" +
		"\n[history]\npersistence = \"save-all\"\n" +
		"\n[projects." + tomlString(g.cwd) + "]\ntrust_level = \"trusted\"\n"
	g.createIfAbsent(filepath.Join(g.home, "config.toml"), []byte(config), filePerm)
}

// writeLocks creates thread-writer-locks/ with .coordination.lock and an
// unheld, empty <thread id>.lock per session (as crashed sessions leave).
func (g *generator) writeLocks() {
	t := g.t
	t.Helper()
	dir := filepath.Join(g.home, lockDirName)
	mkdirs(t, g.home, dir, dirPerm)
	g.createIfAbsent(filepath.Join(dir, coordinationName), nil, filePerm)
	for _, th := range g.threads {
		g.createIfAbsent(filepath.Join(dir, th.id+".lock"), nil, filePerm)
	}
}

func (g *generator) createIfAbsent(path string, data []byte, perm fs.FileMode) {
	t := g.t
	t.Helper()
	checkTarget(t, g.home, path)
	if _, err := os.Lstat(path); err == nil {
		return
	} else if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("codextest: lstat %s: %v", path, err)
	}
	createFile(t, g.home, path, data, perm, time.Time{})
}

// rollouts lists rollout-*.jsonl(.zst) files under sessions/ and
// archived_sessions/ (the names Codex discovers), sorted.
func rollouts(t testing.TB, h *Home) []string {
	t.Helper()
	if h == nil {
		t.Fatalf("codextest: nil *Home")
	}
	home := homeDir(t, h.Dir)
	var out []string
	for _, sub := range []string{"sessions", "archived_sessions"} {
		root := filepath.Join(home, sub)
		if _, err := os.Lstat(root); errors.Is(err, fs.ErrNotExist) {
			continue
		} else if err != nil {
			t.Fatalf("codextest: lstat %s: %v", root, err)
		}
		err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				if p != root && errors.Is(err, fs.ErrNotExist) {
					return nil // vanished while listing (a concurrent seal)
				}
				return err
			}
			if d.Type().IsRegular() && isRolloutName(d.Name()) {
				out = append(out, p)
			}
			return nil
		})
		if err != nil {
			t.Fatalf("codextest: list rollouts under %s: %v", root, err)
		}
	}
	sort.Strings(out)
	return out
}

func isRolloutName(name string) bool {
	return strings.HasPrefix(name, "rollout-") && (strings.HasSuffix(name, ".jsonl") || strings.HasSuffix(name, ".jsonl.zst"))
}
