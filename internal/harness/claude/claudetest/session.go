package claudetest

import (
	"bytes"
	"fmt"
	"io"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// sessionWriter renders one Session into a Layout. Every name and id is a
// deterministic function of the Session, so AppendFragment can recompute
// the original's last uuid after the transcript was moved or sealed, and a
// Session with ModTime set rewritten at the same place produces
// byte-identical files (contents embed the layout's absolute paths).
type sessionWriter struct {
	t     testing.TB
	s     Session
	cfg   string // $CC
	tmp   string // $TMP
	cache string // $CACHE
	slug  string // <P>
	n     int    // transcript records
	end   time.Time
	paths []string
}

func newSessionWriter(t testing.TB, l *Layout, s Session) *sessionWriter {
	t.Helper()
	if l == nil {
		t.Fatalf("claudetest: nil *Layout")
	}
	w := &sessionWriter{t: t, s: s}
	w.cfg = baseDir(t, "ConfigDir", l.ConfigDir)
	w.tmp = baseDir(t, "TmpDir", l.TmpDir)
	w.cache = baseDir(t, "CacheDir", l.CacheDir)
	checkComponent(t, "Session.SID", s.SID)
	if s.Cwd == "" || !filepath.IsAbs(s.Cwd) {
		t.Fatalf("claudetest: Session.Cwd must be an absolute path (Claude records absolute cwds), got %q", s.Cwd)
	}
	w.slug = s.Slug
	if w.slug == "" {
		w.slug = fixtureSlug(s.Cwd)
	}
	checkComponent(t, "Session.Slug", w.slug)
	if s.PlanSlug != "" {
		checkComponent(t, "Session.PlanSlug", s.PlanSlug)
	}
	checkMarker(t, s.Marker)
	if s.Subagents < 0 {
		t.Fatalf("claudetest: Session.Subagents=%d is negative", s.Subagents)
	}
	for i, p := range s.MDWrites {
		if p == "" {
			t.Fatalf("claudetest: Session.MDWrites[%d] is empty", i)
		}
	}
	need := 1 + 2*len(s.MDWrites)
	switch {
	case s.Lines <= 0:
		w.n = max(defaultLines, need)
	case s.Lines < need:
		t.Fatalf("claudetest: Session.Lines=%d cannot hold %d MDWrites (need at least %d records)", s.Lines, len(s.MDWrites), need)
	default:
		w.n = s.Lines
	}
	w.end = s.ModTime
	if w.end.IsZero() {
		w.end = time.Now()
	}
	w.end = w.end.UTC().Truncate(time.Millisecond)
	return w
}

// Paths of the session (SPEC §7.1.1, §11.2 claude-session targets).
func (w *sessionWriter) projectDir() string { return filepath.Join(w.cfg, "projects", w.slug) }
func (w *sessionWriter) transcriptPath() string {
	return filepath.Join(w.projectDir(), w.s.SID+".jsonl")
}
func (w *sessionWriter) sidDir() string     { return filepath.Join(w.projectDir(), w.s.SID) }
func (w *sessionWriter) tmpSidDir() string  { return filepath.Join(w.tmp, w.slug, w.s.SID) }
func (w *sessionWriter) editedPath() string { return filepath.Join(w.s.Cwd, "claudetest-edited.txt") }

func (w *sessionWriter) toolResultPath() string {
	return filepath.Join(w.sidDir(), "tool-results", w.toolID("bash", 0)+".txt")
}

func (w *sessionWriter) backupName() string {
	return fixtureHex(16, "file-history", w.editedPath()) + "@v1"
}

// Identifiers derived from the session id.
func (w *sessionWriter) recordUUID(i int) string {
	return fixtureUUID("record", w.s.SID, strconv.Itoa(i))
}
func (w *sessionWriter) toolID(kind string, n int) string {
	return "toolu_" + fixtureHex(24, "tool", w.s.SID, kind, strconv.Itoa(n))
}
func (w *sessionWriter) messageID(scope string, i int) string {
	return "msg_" + fixtureHex(24, "message", w.s.SID, scope, strconv.Itoa(i))
}
func (w *sessionWriter) requestID(scope string, i int) string {
	return "req_" + fixtureHex(24, "request", w.s.SID, scope, strconv.Itoa(i))
}
func (w *sessionWriter) agentID(k int) string {
	return fixtureHex(8, "agent", w.s.SID, strconv.Itoa(k))
}
func (w *sessionWriter) shellID() string { return "b" + fixtureHex(8, "shell", w.s.SID) }

func (w *sessionWriter) text(format string, args ...any) string {
	return withMarker(w.s.Marker, fmt.Sprintf(format, args...))
}

func (w *sessionWriter) noteContent(j int) string {
	return fmt.Sprintf("# claudetest note %d\n\n%s\n", j, w.text("note body %d", j))
}

// conv builds a conversation record of the main transcript or a subagent.
func (w *sessionWriter) conv(typ string, parent *string, uuid string, at time.Time, msg any, agent string) convRecord {
	return convRecord{
		ParentUUID:  parent,
		IsSidechain: agent != "",
		UserType:    "external",
		Cwd:         w.s.Cwd,
		SessionID:   w.s.SID,
		Version:     claudeVersion,
		GitBranch:   gitBranch,
		AgentID:     agent,
		Slug:        w.s.PlanSlug,
		Type:        typ,
		Message:     msg,
		UUID:        uuid,
		Timestamp:   isoMillis(at),
	}
}

func assistant(id string, stop string, blocks ...any) assistantMessage {
	return assistantMessage{
		ID:         id,
		Type:       "message",
		Role:       "assistant",
		Model:      fixtureModel,
		Content:    blocks,
		StopReason: stop,
		Usage:      usage{InputTokens: 12, OutputTokens: 34},
	}
}

func toolResult(id, content string) userResultMessage {
	return userResultMessage{Role: "user", Content: []toolResultBlock{{ToolUseID: id, Type: "tool_result", Content: content}}}
}

// lastUUID is the uuid of the transcript's last conversation record,
// computed from the script alone (the transcript may be gone).
func (w *sessionWriter) lastUUID() string {
	for i := w.n - 1; i >= 0; i-- {
		if stepAt(i, len(w.s.MDWrites)).kind.hasUUID() {
			return w.recordUUID(i)
		}
	}
	return ""
}

// renderTranscript emits the n records of the main transcript in order,
// each line ending with '\n'.
func (w *sessionWriter) renderTranscript(emit func(line []byte) error) error {
	s := w.s
	start := w.end.Add(-time.Duration(w.n-1) * recordGap)
	var parent *string
	lastPrompt := ""
	for i := 0; i < w.n; i++ {
		st := stepAt(i, len(s.MDWrites))
		at := start.Add(time.Duration(i) * recordGap)
		uuid := ""
		if st.kind.hasUUID() {
			uuid = w.recordUUID(i)
		}
		var rec any
		switch st.kind {
		case stepPrompt:
			lastPrompt = w.text("claudetest prompt %d: please keep working on the notes", st.n)
			rec = w.conv("user", parent, uuid, at, userTextMessage{Role: "user", Content: lastPrompt}, "")
		case stepWrite:
			path := s.MDWrites[st.n]
			c := w.conv("assistant", parent, uuid, at, assistant(w.messageID("main", i), "tool_use",
				textBlock{Type: "text", Text: w.text("writing note %d", st.n)},
				toolUseBlock{Type: "tool_use", ID: w.toolID("write", st.n), Name: "Write",
					Input: writeInput{FilePath: path, Content: w.noteContent(st.n)}}), "")
			c.RequestID = w.requestID("main", i)
			rec = c
		case stepWriteResult:
			path := s.MDWrites[st.n]
			c := w.conv("user", parent, uuid, at, toolResult(w.toolID("write", st.n), "File created successfully at: "+path), "")
			c.ToolUseResult = writeResult{Type: "create", FilePath: path, Content: w.noteContent(st.n), StructuredPatch: []any{}}
			rec = c
		case stepAITitle:
			rec = aiTitleRecord{Type: "ai-title", AITitle: w.text("claudetest session title"), SessionID: s.SID}
		case stepBash:
			c := w.conv("assistant", parent, uuid, at, assistant(w.messageID("main", i), "tool_use",
				toolUseBlock{Type: "tool_use", ID: w.toolID("bash", 0), Name: "Bash",
					Input: bashInput{Command: "grep -rn '" + w.text("needle") + "' .", Description: "Search the workspace"}}), "")
			c.RequestID = w.requestID("main", i)
			rec = c
		case stepBashResult:
			out := fmt.Sprintf("Output too large (4.1KB). Full output saved to: %s\n\nPreview (first 2KB):\n%s", w.toolResultPath(), w.text("claudetest bash output"))
			c := w.conv("user", parent, uuid, at, toolResult(w.toolID("bash", 0), out), "")
			c.ToolUseResult = bashResult{Stdout: w.text("claudetest bash output")}
			rec = c
		case stepSnapshot:
			rec = snapshotRecord{
				Type:      "file-history-snapshot",
				MessageID: w.recordUUID(i + 1),
				Snapshot: snapshotBody{
					MessageID: w.recordUUID(i + 1),
					TrackedFileBackups: map[string]backupRef{
						w.editedPath(): {BackupFileName: w.backupName(), Version: 1, BackupTime: isoMillis(at)},
					},
					Timestamp: isoMillis(at),
				},
			}
		case stepEdit:
			c := w.conv("assistant", parent, uuid, at, assistant(w.messageID("main", i), "tool_use",
				toolUseBlock{Type: "tool_use", ID: w.toolID("edit", 0), Name: "Edit",
					Input: editInput{FilePath: w.editedPath(), OldString: w.text("before"), NewString: w.text("after")}}), "")
			c.RequestID = w.requestID("main", i)
			rec = c
		case stepEditResult:
			c := w.conv("user", parent, uuid, at, toolResult(w.toolID("edit", 0), "The file "+w.editedPath()+" has been updated."), "")
			c.ToolUseResult = editResult{FilePath: w.editedPath(), OldString: w.text("before"), NewString: w.text("after")}
			rec = c
		case stepAnswer:
			c := w.conv("assistant", parent, uuid, at, assistant(w.messageID("main", i), "end_turn",
				textBlock{Type: "text", Text: w.text("claudetest answer %d", st.n)}), "")
			c.RequestID = w.requestID("main", i)
			rec = c
		case stepLastPrompt:
			rec = lastPromptRecord{Type: "last-prompt", LastPrompt: lastPrompt, SessionID: s.SID}
		}
		line, err := marshalLine(rec)
		if err != nil {
			return err
		}
		if err := emit(line); err != nil {
			return err
		}
		if uuid != "" {
			u := uuid
			parent = &u
		}
	}
	return nil
}

// write creates every file of the session and returns their paths in
// creation order, the transcript first.
func (w *sessionWriter) write() []string {
	t, s := w.t, w.s
	t.Helper()
	// The transcript streams to disk; each line is held until the next one
	// is known, so NoNewline can drop the very last '\n'.
	createStream(t, w.cfg, w.transcriptPath(), s.ModTime, func(out io.Writer) error {
		var held []byte
		err := w.renderTranscript(func(line []byte) error {
			if held != nil {
				if _, err := out.Write(held); err != nil {
					return err
				}
			}
			held = line
			return nil
		})
		if err != nil {
			return err
		}
		if s.NoNewline {
			held = bytes.TrimSuffix(held, []byte("\n"))
		}
		_, err = out.Write(held)
		return err
	})
	w.paths = append(w.paths, w.transcriptPath())

	for k := 0; k < s.Subagents; k++ {
		w.writeSubagent(k)
	}

	w.create(w.cfg, w.toolResultPath(), []byte(fmt.Sprintf("%s\n%s\n", w.text("claudetest bash output"), w.text("claudetest bash output, continued"))))
	w.create(w.cfg, filepath.Join(w.cfg, "file-history", s.SID, w.backupName()),
		[]byte("claudetest edited file before the edit\n"+w.text("before")+"\n"))
	w.create(w.cfg, filepath.Join(w.cfg, "session-env", s.SID, "sessionstart-hook-0.sh"),
		[]byte("export CLAUDETEST_SESSION_VALUE='"+w.text("session env")+"'\n"))
	w.create(w.cfg, filepath.Join(w.cfg, "tasks", s.SID, "1.json"), encodeJSON(t, taskFile{
		ID: "1", Subject: w.text("claudetest task"), Description: w.text("claudetest task description"),
		ActiveForm: "Working on the claudetest task", Status: "in_progress", Blocks: []string{}, BlockedBy: []string{},
	}))
	w.create(w.cfg, filepath.Join(w.cfg, "todos", s.SID+"-agent-"+s.SID+".json"), encodeJSON(t, []todoItem{
		{Content: w.text("claudetest todo"), Status: "in_progress", ActiveForm: "Working on the claudetest todo"},
	}))

	// $TMP/<P>/<sid>: the scratchpad, Bash task output and the child-notes
	// directory (CLAUDE_CODE_CHILD_NOTES_DIR) that Claude creates empty.
	w.create(w.tmp, filepath.Join(w.tmpSidDir(), "scratchpad", "notes.txt"), []byte(w.text("claudetest scratchpad notes")+"\n"))
	w.create(w.tmp, filepath.Join(w.tmpSidDir(), "tasks", w.shellID()+".output"), []byte(w.text("claudetest background task output")+"\n"))
	mkdirs(t, w.tmp, filepath.Join(w.tmpSidDir(), "started"))

	// Shared by every session of the project or plan: written once.
	w.createShared(w.cfg, filepath.Join(w.projectDir(), "memory", "MEMORY.md"),
		[]byte("# claudetest memory\n\n- "+w.text("claudetest remembered fact")+"\n"))
	if s.PlanSlug != "" {
		w.createShared(w.cfg, filepath.Join(w.cfg, "plans", s.PlanSlug+".md"),
			[]byte("# claudetest plan\n\n1. "+w.text("claudetest plan step")+"\n"))
		if s.Subagents > 0 {
			w.createShared(w.cfg, filepath.Join(w.cfg, "plans", s.PlanSlug+"-agent-"+w.agentID(0)+".md"),
				[]byte("# claudetest subagent plan\n\n1. "+w.text("claudetest subagent plan step")+"\n"))
		}
	}
	w.writeMCPLog()
	return w.paths
}

func (w *sessionWriter) create(base, path string, data []byte) {
	w.t.Helper()
	createFile(w.t, base, path, data, w.s.ModTime, false)
	w.paths = append(w.paths, path)
}

func (w *sessionWriter) createShared(base, path string, data []byte) bool {
	w.t.Helper()
	if !createFile(w.t, base, path, data, w.s.ModTime, true) {
		return false
	}
	w.paths = append(w.paths, path)
	return true
}

// writeSubagent writes projects/<P>/<sid>/subagents/agent-<id>.jsonl (a
// sidechain with its own uuid chain and sessionId = the parent session)
// and its .meta.json.
func (w *sessionWriter) writeSubagent(k int) {
	t := w.t
	t.Helper()
	id := w.agentID(k)
	scope := "agent-" + id
	start := w.end.Add(-time.Duration(subagentRecords) * time.Second)
	var parent *string
	var lines [][]byte
	for i := 0; i < subagentRecords; i++ {
		at := start.Add(time.Duration(i) * 500 * time.Millisecond)
		uuid := fixtureUUID("subagent", w.s.SID, strconv.Itoa(k), strconv.Itoa(i))
		var rec convRecord
		switch i {
		case 0:
			rec = w.conv("user", parent, uuid, at, userTextMessage{Role: "user", Content: w.text("claudetest subagent %d task", k)}, id)
		case 1:
			rec = w.conv("assistant", parent, uuid, at, assistant(w.messageID(scope, i), "tool_use",
				toolUseBlock{Type: "tool_use", ID: w.toolID(scope, i), Name: "Bash",
					Input: bashInput{Command: "grep -rn '" + w.text("subagent needle") + "' .", Description: "Search for the needle"}}), id)
			rec.RequestID = w.requestID(scope, i)
		case 2:
			rec = w.conv("user", parent, uuid, at, toolResult(w.toolID(scope, 1), w.text("claudetest subagent %d match", k)), id)
		default:
			rec = w.conv("assistant", parent, uuid, at, assistant(w.messageID(scope, i), "end_turn",
				textBlock{Type: "text", Text: w.text("claudetest subagent %d result", k)}), id)
			rec.RequestID = w.requestID(scope, i)
		}
		lines = append(lines, encodeLine(t, rec))
		u := uuid
		parent = &u
	}
	base := filepath.Join(w.sidDir(), "subagents", "agent-"+id)
	w.create(w.cfg, base+".jsonl", bytes.Join(lines, nil))
	w.create(w.cfg, base+".meta.json", encodeJSON(t, subagentMeta{AgentType: "general-purpose", Description: w.text("claudetest subagent %d", k)}))
}

// writeMCPLog writes $CACHE/<P>/mcp-logs-<server>/<ISO time>.jsonl, one
// file per Claude start; a name already taken moves on by a millisecond.
func (w *sessionWriter) writeMCPLog() {
	t := w.t
	t.Helper()
	start := w.end.Add(-time.Duration(w.n-1) * recordGap)
	var data []byte
	for i, l := range []mcpLogLine{
		{Debug: "Starting connection with timeout of 30000ms"},
		{Debug: "Successfully connected to stdio server"},
		{Debug: "Calling MCP tool: claudetest_lookup"},
		{Debug: "Tool claudetest_lookup returned: " + w.text("claudetest mcp output")},
	} {
		l.Timestamp = isoMillis(start.Add(time.Duration(i) * 10 * time.Millisecond))
		l.SessionID = w.s.SID
		l.Cwd = w.s.Cwd
		data = append(data, encodeLine(t, l)...)
	}
	dir := filepath.Join(w.cache, w.slug, "mcp-logs-"+mcpServer)
	for i := 0; i < 1000; i++ {
		at := start.Add(time.Duration(i) * time.Millisecond)
		name := at.Format("2006-01-02T15-04-05") + fmt.Sprintf("-%03dZ.jsonl", at.Nanosecond()/int(time.Millisecond))
		if w.createShared(w.cache, filepath.Join(dir, name), data) {
			return
		}
	}
	t.Fatalf("claudetest: no free MCP log name in %s", dir)
}
