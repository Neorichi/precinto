package claudetest

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode"
)

// Shapes of the synthetic layout. File and directory names follow Claude
// Code 2.1.329 (SPEC §7.1, HOOKS-IO §2); every value written is synthetic.
const (
	claudeVersion = "2.1.329" // the verified Claude Code version (HOOKS-IO §2)
	fixtureModel  = "claude-claudetest-model"
	gitBranch     = "main"
	mcpServer     = "claudetest" // mcp-logs-<server>

	defaultLines    = 12                    // records of a Session with Lines <= 0
	recordGap       = 2 * time.Second       // wall time between transcript records
	defaultEvery    = 20 * time.Millisecond // Appender interval when every <= 0 (TESTPLAN §4: 10–50 ms)
	maxSlugLen      = 200                   // longer sanitized cwds are cut and suffixed with a hash
	tailWindow      = 256 << 10             // bytes read from the end of a JSONL file to find its last record
	subagentRecords = 4

	dirPerm  fs.FileMode = 0o700
	filePerm fs.FileMode = 0o600
)

// digest hashes a namespaced tuple; every identifier in a fixture is derived
// from it, so layouts never carry random or real ids (S13).
func digest(kind string, parts ...string) []byte {
	h := sha256.New()
	_, _ = io.WriteString(h, "claudetest\x00"+kind)
	for _, p := range parts {
		_, _ = h.Write([]byte{0})
		_, _ = io.WriteString(h, p)
	}
	return h.Sum(nil)
}

// fixtureUUID returns a deterministic fixture UUID for parts, in the
// zero-prefixed form testkit.Hygiene recognises as a fixture
// (00000000-0000-4000-8000-<48 bits of the digest>), so goldens built from
// claudetest output never look like real session ids (S13).
func fixtureUUID(kind string, parts ...string) string {
	b := digest(kind, parts...)
	return fmt.Sprintf("00000000-0000-4000-8000-%x", b[0:6])
}

// fixtureHex returns n (≤ 64) lowercase hex digits derived from parts.
func fixtureHex(n int, kind string, parts ...string) string {
	return hex.EncodeToString(digest(kind, parts...))[:n]
}

// fixtureSlug derives the projects/<P> name of a cwd in Claude's style:
// every character other than [A-Za-z0-9] becomes '-' (one per UTF-16 code
// unit, as Claude's JavaScript does). Over-long results are cut and get a
// hash suffix so they stay unique. precinto itself never computes slugs
// (D19, D45): only fixtures do.
func fixtureSlug(cwd string) string {
	var b strings.Builder
	for _, r := range cwd {
		switch {
		case r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9':
			b.WriteRune(r)
		case r > 0xffff:
			b.WriteString("--")
		default:
			b.WriteByte('-')
		}
	}
	s := b.String()
	if len(s) > maxSlugLen {
		s = s[:maxSlugLen] + "-" + fixtureHex(8, "slug", cwd)
	}
	return s
}

// withMarker prefixes text with the marker (when there is one).
func withMarker(marker, text string) string {
	if marker == "" {
		return text
	}
	return marker + " " + text
}

// checkComponent fails the test unless s is one plain path component, so a
// fixture can never write outside its layout.
func checkComponent(t testing.TB, what, s string) {
	t.Helper()
	if s == "" || s == "." || s == ".." || strings.ContainsAny(s, "/\\\x00") || filepath.Base(s) != s {
		t.Fatalf("claudetest: %s %q is not a single path component", what, s)
	}
}

// checkMarker fails the test when the marker would not appear verbatim in
// every file (JSON, shell and Markdown): leak checks grep raw bytes (I7).
func checkMarker(t testing.TB, marker string) {
	t.Helper()
	for _, r := range marker {
		if r < 0x20 || r == 0x7f || r == '"' || r == '\\' || r == '\'' || r == 0x2028 || r == 0x2029 || r == unicode.ReplacementChar {
			t.Fatalf("claudetest: marker %q contains %q, which would not appear verbatim in JSON or shell fixtures", marker, r)
		}
	}
}

// baseDir validates one directory of a Layout: fixtures are written only
// below absolute bases, never relative to the test's working directory.
func baseDir(t testing.TB, field, dir string) string {
	t.Helper()
	if dir == "" || !filepath.IsAbs(dir) {
		t.Fatalf("claudetest: Layout.%s must be an absolute directory, got %q", field, dir)
	}
	return filepath.Clean(dir)
}

// within reports whether p lies inside base (or is base).
func within(base, p string) bool {
	rel, err := filepath.Rel(base, p)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
}

// checkTarget fails unless target lies inside base and no existing
// component below base is a symlink (fixtures never follow links out of the
// layout).
func checkTarget(t testing.TB, base, target string) {
	t.Helper()
	if !within(base, target) {
		t.Fatalf("claudetest: %s lies outside %s", target, base)
	}
	rel, _ := filepath.Rel(base, target)
	if rel == "." {
		return
	}
	cur := base
	for _, c := range strings.Split(rel, string(filepath.Separator)) {
		cur = filepath.Join(cur, c)
		fi, err := os.Lstat(cur)
		if errors.Is(err, fs.ErrNotExist) {
			return
		}
		if err != nil {
			t.Fatalf("claudetest: lstat %s: %v", cur, err)
		}
		if fi.Mode()&fs.ModeSymlink != 0 {
			t.Fatalf("claudetest: %s is a symlink; fixtures never write through links", cur)
		}
	}
}

// mkdirs creates dir and its missing parents (0700) below base.
func mkdirs(t testing.TB, base, dir string) {
	t.Helper()
	checkTarget(t, base, dir)
	if err := os.MkdirAll(dir, dirPerm); err != nil {
		t.Fatalf("claudetest: mkdir %s: %v", dir, err)
	}
}

// createFile creates path below base with data (0600, parents 0700) and
// sets its mtime when mtime is not zero. With shared=false an existing file
// fails the test (fixtures never clobber); with shared=true it is kept and
// created reports false.
func createFile(t testing.TB, base, path string, data []byte, mtime time.Time, shared bool) (created bool) {
	t.Helper()
	return create(t, base, path, mtime, shared, func(w io.Writer) error {
		_, err := w.Write(data)
		return err
	})
}

// createStream is createFile (never shared) for content produced by fill
// through a buffered writer: transcripts can be large.
func createStream(t testing.TB, base, path string, mtime time.Time, fill func(io.Writer) error) {
	t.Helper()
	create(t, base, path, mtime, false, fill)
}

func create(t testing.TB, base, path string, mtime time.Time, shared bool, fill func(io.Writer) error) bool {
	t.Helper()
	mkdirs(t, base, filepath.Dir(path))
	checkTarget(t, base, path)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, filePerm)
	if shared && errors.Is(err, fs.ErrExist) {
		return false
	}
	if err != nil {
		t.Fatalf("claudetest: create %s: %v", path, err)
	}
	bw := bufio.NewWriterSize(f, 64<<10)
	werr := fill(bw)
	if werr == nil {
		werr = bw.Flush()
	}
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		t.Fatalf("claudetest: write %s: %v", path, werr)
	}
	setMtime(t, path, mtime)
	return true
}

// writeReplace writes path below base through a temporary in the same
// directory and a rename, so concurrent readers see the old or the new
// content, never a torn file.
func writeReplace(t testing.TB, base, path string, data []byte) {
	t.Helper()
	dir := filepath.Dir(path)
	mkdirs(t, base, dir)
	checkTarget(t, base, path)
	f, err := os.CreateTemp(dir, ".claudetest-*.tmp")
	if err != nil {
		t.Fatalf("claudetest: temporary in %s: %v", dir, err)
	}
	tmp := f.Name()
	_, werr := f.Write(data)
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr == nil {
		werr = os.Chmod(tmp, filePerm)
	}
	if werr == nil {
		werr = os.Rename(tmp, path)
	}
	if werr != nil {
		_ = os.Remove(tmp)
		t.Fatalf("claudetest: write %s: %v", path, werr)
	}
}

// openAppend opens path below base for appending, creating it 0600 the way
// Claude's writers do (O_APPEND, no O_EXCL).
func openAppend(t testing.TB, base, path string) *os.File {
	t.Helper()
	mkdirs(t, base, filepath.Dir(path))
	checkTarget(t, base, path)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, filePerm)
	if err != nil {
		t.Fatalf("claudetest: open %s: %v", path, err)
	}
	return f
}

func setMtime(t testing.TB, path string, mtime time.Time) {
	t.Helper()
	if mtime.IsZero() {
		return
	}
	if err := os.Chtimes(path, mtime, mtime); err != nil {
		t.Fatalf("claudetest: chtimes %s: %v", path, err)
	}
}

// marshalLine renders one JSONL record (with its trailing '\n'). HTML
// escaping is off so text appears as Claude's JSON.stringify writes it.
func marshalLine(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// encodeLine is marshalLine for the test goroutine.
func encodeLine(t testing.TB, v any) []byte {
	t.Helper()
	b, err := marshalLine(v)
	if err != nil {
		t.Fatalf("claudetest: encode %T: %v", v, err)
	}
	return b
}

// encodeJSON renders one JSON document without a trailing newline.
func encodeJSON(t testing.TB, v any) []byte {
	t.Helper()
	return bytes.TrimSuffix(encodeLine(t, v), []byte("\n"))
}

// isoMillis formats a time as Claude does (JavaScript toISOString).
func isoMillis(at time.Time) string {
	return at.UTC().Format("2006-01-02T15:04:05.000Z")
}

// chainHead is what Claude's writer keeps in memory about a JSONL file: the
// last conversation record's uuid and the fields it repeats on every record.
type chainHead struct {
	UUID        string `json:"uuid"`
	SessionID   string `json:"sessionId"`
	Cwd         string `json:"cwd"`
	Slug        string `json:"slug"`
	AgentID     string `json:"agentId"`
	IsSidechain bool   `json:"isSidechain"`
}

// tailFacts returns the chain head of path: its last record (within the
// last tailWindow bytes) that carries a uuid. A missing or unreadable file
// yields the zero value.
func tailFacts(path string) chainHead {
	f, err := os.Open(path)
	if err != nil {
		return chainHead{}
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() {
		return chainHead{}
	}
	off := max(fi.Size()-tailWindow, 0)
	buf := make([]byte, fi.Size()-off)
	n, err := f.ReadAt(buf, off)
	if err != nil && !errors.Is(err, io.EOF) {
		return chainHead{}
	}
	lines := bytes.Split(buf[:n], []byte("\n"))
	for i := len(lines) - 1; i >= 0; i-- {
		var h chainHead
		if json.Unmarshal(lines[i], &h) == nil && h.UUID != "" {
			return h
		}
	}
	return chainHead{}
}
