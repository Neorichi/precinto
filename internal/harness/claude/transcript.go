package claude

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/precinto/precinto/internal/fsx"
)

const (
	// maxRecordBytes bounds one JSONL record. Claude spills large tool
	// output to tool-results/, so records are far smaller; a longer line
	// is skipped (ScanTranscript) or makes the stream invalid (ScanLinks).
	maxRecordBytes = 64 << 20
	// maxTitleRunes bounds the title kept for the manifest.
	maxTitleRunes = 200
	// ctxEvery is how many records are read between context checks.
	ctxEvery = 256
)

// lineReader streams JSONL records. Every complete or final line is passed
// to fn without its '\n'; over-long lines are reported with oversize=true
// and no bytes. trailingNL tells whether the stream ended with '\n'.
type lineReader struct {
	r          *bufio.Reader
	buf        []byte
	trailingNL bool
	any        bool
}

func newLineReader(r io.Reader) *lineReader {
	return &lineReader{r: bufio.NewReaderSize(r, 256<<10)}
}

func (lr *lineReader) each(ctx context.Context, fn func(line []byte, oversize bool)) error {
	n := 0
	for {
		if n%ctxEvery == 0 {
			if err := ctx.Err(); err != nil {
				return err
			}
		}
		n++
		lr.buf = lr.buf[:0]
		oversize := false
		var err error
		for {
			var chunk []byte
			chunk, err = lr.r.ReadSlice('\n')
			if len(chunk) > 0 {
				lr.any = true
			}
			if !oversize {
				if len(lr.buf)+len(chunk) > maxRecordBytes {
					oversize = true
					lr.buf = lr.buf[:0]
				} else {
					lr.buf = append(lr.buf, chunk...)
				}
			}
			if errors.Is(err, bufio.ErrBufferFull) {
				continue
			}
			break
		}
		if err != nil && !errors.Is(err, io.EOF) {
			return err
		}
		line := lr.buf
		if len(line) > 0 && line[len(line)-1] == '\n' {
			line = line[:len(line)-1]
			lr.trailingNL = true
		} else if len(line) > 0 || oversize {
			lr.trailingNL = false
		}
		if len(line) > 0 || oversize {
			fn(line, oversize)
		}
		if errors.Is(err, io.EOF) {
			return nil
		}
	}
}

// isObject reports whether a line holds a JSON object.
func isObject(line []byte) bool {
	t := bytes.TrimLeft(line, " \t\r")
	return len(t) > 0 && t[0] == '{'
}

// linkRecord is what ScanLinks decodes of each record.
type linkRecord struct {
	UUID              *string `json:"uuid"`
	ParentUUID        *string `json:"parentUuid"`
	LogicalParentUUID *string `json:"logicalParentUuid"`
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// scanLinks implements ScanLinks. The first record that carries a uuid or
// a parent link gives FirstParent/FirstLogicalParent (metadata records
// without links, such as ai-title, are skipped). Any line that is not a
// JSON object makes Valid false; blank lines are ignored.
func scanLinks(ctx context.Context, r io.Reader) (Links, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	links := Links{UUIDs: map[string]bool{}, Valid: true}
	first := false
	lr := newLineReader(r)
	err := lr.each(ctx, func(line []byte, oversize bool) {
		if oversize {
			links.Valid = false
			return
		}
		if len(bytes.TrimSpace(line)) == 0 {
			return
		}
		var rec linkRecord
		if !isObject(line) || json.Unmarshal(line, &rec) != nil {
			links.Valid = false
			return
		}
		links.Records++
		if u := deref(rec.UUID); u != "" {
			links.UUIDs[u] = true
		}
		if !first && (rec.UUID != nil || rec.ParentUUID != nil || rec.LogicalParentUUID != nil) {
			first = true
			links.FirstParent = deref(rec.ParentUUID)
			links.FirstLogicalParent = deref(rec.LogicalParentUUID)
		}
	})
	if err != nil {
		return Links{}, err
	}
	links.TrailingNL = lr.any && lr.trailingNL
	return links, nil
}

// transcriptRecord is the subset of a transcript record ScanTranscript
// reads: ids, paths and the bounded title sources only.
type transcriptRecord struct {
	Type        string          `json:"type"`
	UUID        string          `json:"uuid"`
	SessionID   string          `json:"sessionId"`
	Cwd         string          `json:"cwd"`
	Slug        string          `json:"slug"`
	Timestamp   string          `json:"timestamp"`
	IsMeta      bool            `json:"isMeta"`
	IsSidechain bool            `json:"isSidechain"`
	CustomTitle string          `json:"customTitle"`
	AITitle     string          `json:"aiTitle"`
	ForkedFrom  json.RawMessage `json:"forkedFrom"`
	Message     *struct {
		Role    string          `json:"role"`
		Content json.RawMessage `json:"content"`
	} `json:"message"`
}

type contentBlock struct {
	Type  string `json:"type"`
	Name  string `json:"name"`
	Text  string `json:"text"`
	Input *struct {
		FilePath     string `json:"file_path"`
		NotebookPath string `json:"notebook_path"`
	} `json:"input"`
}

// mdTools are the tools whose file paths name agent-written Markdown.
var mdTools = map[string]bool{"Write": true, "Edit": true, "MultiEdit": true, "NotebookEdit": true}

// transcriptScan accumulates facts across the records of one transcript.
type transcriptScan struct {
	own         string // the transcript's own session id
	facts       TranscriptFacts
	slugs       []string
	customTitle string
	aiTitle     string
	firstPrompt string
}

// scanTranscript implements ScanTranscript.
func scanTranscript(ctx context.Context, path string) (TranscriptFacts, error) {
	ts, err := scanTranscriptFull(ctx, path)
	if err != nil {
		return TranscriptFacts{}, err
	}
	return ts.facts, nil
}

// scanTranscriptFull scans a transcript and keeps every slug seen (plan
// liveness needs all of them, D46).
func scanTranscriptFull(ctx context.Context, path string) (*transcriptScan, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	f, err := os.OpenFile(path, os.O_RDONLY|fsx.ONoFollow|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := fsx.Fstat(f)
	if err != nil {
		return nil, err
	}
	if !st.IsRegular() {
		return nil, fmt.Errorf("%w: %s is not a regular file", fsx.ErrUnsafe, filepath.Base(path))
	}
	ts := &transcriptScan{}
	if sid, ok := sidOf(strings.TrimSuffix(filepath.Base(path), ".jsonl")); ok && strings.HasSuffix(path, ".jsonl") {
		ts.own = sid
	}
	lr := newLineReader(f)
	err = lr.each(ctx, func(line []byte, oversize bool) {
		if oversize || !isObject(line) {
			return
		}
		ts.record(line)
	})
	if err != nil {
		return nil, err
	}
	ts.facts.TrailingNL = lr.any && lr.trailingNL
	if len(ts.slugs) > 0 {
		ts.facts.Slug = ts.slugs[len(ts.slugs)-1]
	}
	switch {
	case ts.customTitle != "":
		ts.facts.Title = ts.customTitle
	case ts.aiTitle != "":
		ts.facts.Title = ts.aiTitle
	default:
		ts.facts.Title = ts.firstPrompt
	}
	return ts, nil
}

func (ts *transcriptScan) record(line []byte) {
	var rec transcriptRecord
	if json.Unmarshal(line, &rec) != nil {
		return
	}
	f := &ts.facts
	if ts.own == "" && rec.SessionID != "" {
		ts.own = rec.SessionID
	}
	if rec.UUID != "" {
		f.Uuids++
	}
	if rec.Cwd != "" {
		f.Cwds = appendUnique(f.Cwds, rec.Cwd)
	}
	if rec.Slug != "" && safeComponent(rec.Slug) && (len(ts.slugs) == 0 || ts.slugs[len(ts.slugs)-1] != rec.Slug) {
		// Every slug seen, the most recent last (TranscriptFacts.Slug).
		ts.slugs = append(removeValue(ts.slugs, rec.Slug), rec.Slug)
	}
	if rec.Timestamp != "" {
		if t, err := time.Parse(time.RFC3339Nano, rec.Timestamp); err == nil && t.After(f.LastAt) {
			f.LastAt = t.UTC()
		}
	}
	if rec.SessionID != "" && ts.own != "" && !strings.EqualFold(rec.SessionID, ts.own) {
		f.CopiedSIDs = appendUnique(f.CopiedSIDs, rec.SessionID)
	}
	if rec.Type == "fork-context-ref" {
		for _, id := range uuidsIn(line) {
			if !strings.EqualFold(id, ts.own) && !strings.EqualFold(id, rec.UUID) {
				f.ForkRefs = appendUnique(f.ForkRefs, strings.ToLower(id))
			}
		}
	}
	if len(rec.ForkedFrom) > 0 {
		var ff struct {
			SessionID string `json:"sessionId"`
		}
		if json.Unmarshal(rec.ForkedFrom, &ff) == nil && isUUID(ff.SessionID) && !strings.EqualFold(ff.SessionID, ts.own) {
			f.ForkRefs = appendUnique(f.ForkRefs, strings.ToLower(ff.SessionID))
		}
	}
	switch rec.Type {
	case "custom-title":
		if t := boundTitle(rec.CustomTitle); t != "" {
			ts.customTitle = t
		}
	case "ai-title":
		if t := boundTitle(rec.AITitle); t != "" {
			ts.aiTitle = t
		}
	case "user":
		if ts.firstPrompt == "" && !rec.IsMeta && !rec.IsSidechain && rec.Message != nil {
			ts.firstPrompt = promptText(rec.Message.Content)
		}
	case "assistant":
		if rec.Message != nil {
			for _, p := range markdownToolPaths(rec.Message.Content) {
				f.MDPaths = appendUnique(f.MDPaths, p)
			}
		}
	}
}

func removeValue(list []string, v string) []string {
	out := list[:0]
	for _, x := range list {
		if x != v {
			out = append(out, x)
		}
	}
	return out
}

// uuidsIn returns every UUID-shaped JSON string value of a record.
func uuidsIn(line []byte) []string {
	var v any
	if json.Unmarshal(line, &v) != nil {
		return nil
	}
	var out []string
	var walk func(any)
	walk = func(x any) {
		switch t := x.(type) {
		case string:
			if isUUID(t) {
				out = append(out, t)
			}
		case []any:
			for _, e := range t {
				walk(e)
			}
		case map[string]any:
			keys := make([]string, 0, len(t))
			for k := range t {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				walk(t[k])
			}
		}
	}
	walk(v)
	return out
}

// promptText returns the bounded text of a human prompt: a string content,
// or the first text block; tool results and harness-injected wrappers
// (<command-name>, <system-reminder>…) are not prompts.
func promptText(raw json.RawMessage) string {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 {
		return ""
	}
	var text string
	if raw[0] == '"' {
		if json.Unmarshal(raw, &text) != nil {
			return ""
		}
	} else if raw[0] == '[' {
		var blocks []contentBlock
		if json.Unmarshal(raw, &blocks) != nil {
			return ""
		}
		for _, b := range blocks {
			if b.Type == "tool_result" {
				return ""
			}
			if b.Type == "text" && b.Text != "" {
				text = b.Text
				break
			}
		}
	}
	text = strings.TrimSpace(text)
	if strings.HasPrefix(text, "<") {
		return ""
	}
	return boundTitle(text)
}

// markdownToolPaths returns the Markdown file paths of Write, Edit,
// MultiEdit and NotebookEdit tool_use blocks (absolute paths only).
func markdownToolPaths(raw json.RawMessage) []string {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || raw[0] != '[' {
		return nil
	}
	var blocks []contentBlock
	if json.Unmarshal(raw, &blocks) != nil {
		return nil
	}
	var out []string
	for _, b := range blocks {
		if b.Type != "tool_use" || !mdTools[b.Name] || b.Input == nil {
			continue
		}
		for _, p := range []string{b.Input.FilePath, b.Input.NotebookPath} {
			if p != "" && filepath.IsAbs(p) && mdExt(p) {
				out = appendUnique(out, filepath.Clean(p))
			}
		}
	}
	return out
}

// boundTitle collapses whitespace and control characters and keeps at most
// maxTitleRunes runes.
func boundTitle(s string) string {
	var b strings.Builder
	space := false
	n := 0
	for _, r := range s {
		if r == utf8.RuneError || unicode.IsControl(r) || unicode.IsSpace(r) {
			space = b.Len() > 0
			continue
		}
		if space {
			b.WriteByte(' ')
			n++
			space = false
		}
		if n >= maxTitleRunes {
			break
		}
		b.WriteRune(r)
		n++
	}
	return b.String()
}

// historyRecord is what ParseHistoryLine decodes of a history.jsonl line.
type historyRecord struct {
	Project        *string                    `json:"project"`
	SessionID      string                     `json:"sessionId"`
	Timestamp      json.Number                `json:"timestamp"`
	PastedContents map[string]json.RawMessage `json:"pastedContents"`
}

// parseHistoryLine implements ParseHistoryLine: Raw is a copy of the line
// (without its newline); only project, session id, timestamp and the
// paste-cache entry names are decoded. Valid requires a JSON object with a
// non-empty project.
func parseHistoryLine(b []byte) HistoryLine {
	line := bytes.TrimRight(b, "\r\n")
	h := HistoryLine{Raw: append([]byte(nil), line...)}
	if !isObject(line) {
		return h
	}
	var rec historyRecord
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.UseNumber()
	if dec.Decode(&rec) != nil || rec.Project == nil || *rec.Project == "" {
		return h
	}
	h.Project = *rec.Project
	h.SessionID = rec.SessionID
	if rec.Timestamp != "" {
		if ms, err := strconv.ParseFloat(rec.Timestamp.String(), 64); err == nil && ms > 0 && ms < 1e15 {
			h.Timestamp = time.UnixMilli(int64(ms)).UTC()
		}
	}
	keys := make([]string, 0, len(rec.PastedContents))
	for k := range rec.PastedContents {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		var ref struct {
			ContentHash string `json:"contentHash"`
		}
		if json.Unmarshal(rec.PastedContents[k], &ref) == nil && ref.ContentHash != "" && safeComponent(ref.ContentHash+".txt") {
			h.PasteRefs = appendUnique(h.PasteRefs, ref.ContentHash+".txt")
		}
	}
	h.Valid = true
	return h
}
