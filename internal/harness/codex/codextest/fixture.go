package codextest

import (
	"bytes"
	"crypto/sha256"
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

// Modes Codex 0.154 produces under a umask of 022 (r1 codex research):
// rollouts and databases 0644 in 0755 directories, history.jsonl and
// auth.json 0600. The home itself is 0700, as PrepareHome creates per-root
// homes (SPEC §7.2).
const (
	homePerm    fs.FileMode = 0o700
	dirPerm     fs.FileMode = 0o755
	filePerm    fs.FileMode = 0o644
	privatePerm fs.FileMode = 0o600
)

// digest hashes a namespaced tuple; fixture ids derive from it (S13).
func digest(kind string, parts ...string) []byte {
	h := sha256.New()
	_, _ = io.WriteString(h, "codextest\x00"+kind)
	for _, p := range parts {
		_, _ = h.Write([]byte{0})
		_, _ = io.WriteString(h, p)
	}
	return h.Sum(nil)
}

// threadID returns a deterministic fixture thread id in the zero-prefixed
// form testkit.Hygiene recognises as a fixture
// (00000000-0000-7000-8000-<48 bits of the digest>). Real Codex thread ids
// are UUIDv7; precinto treats them as opaque UUIDs, so fixtures carry no
// timestamp in the id (the rollout file name and session_meta carry it).
func threadID(start time.Time, parts ...string) string {
	r := digest("thread", append([]string{start.UTC().Format(time.RFC3339Nano)}, parts...)...)
	return fmt.Sprintf("00000000-0000-7000-8000-%x", r[0:6])
}

// isUUID reports canonical 8-4-4-4-12 hex syntax (Codex accepts only
// UUIDs as thread ids, writer_lock.rs).
func isUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, c := range s {
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return false
			}
		default:
			if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
				return false
			}
		}
	}
	return true
}

func withMarker(marker, text string) string {
	if marker == "" {
		return text
	}
	return marker + " " + text
}

// checkMarker fails the test when the marker would not appear verbatim in
// JSON, shell or opaque database fixtures: leak checks grep raw bytes (I7).
func checkMarker(t testing.TB, marker string) {
	t.Helper()
	for _, r := range marker {
		if r < 0x20 || r == 0x7f || r == '"' || r == '\\' || r == '\'' || r == 0x2028 || r == 0x2029 || r == unicode.ReplacementChar {
			t.Fatalf("codextest: marker %q contains %q, which would not appear verbatim in JSON or shell fixtures", marker, r)
		}
	}
}

// homeDir validates Home.Dir: fixtures are written only below an absolute
// directory, never relative to the test's working directory or ~/.codex.
func homeDir(t testing.TB, dir string) string {
	t.Helper()
	if dir == "" || !filepath.IsAbs(dir) {
		t.Fatalf("codextest: the home must be an absolute directory, got %q", dir)
	}
	return filepath.Clean(dir)
}

func within(base, p string) bool {
	rel, err := filepath.Rel(base, p)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
}

// checkTarget fails unless target lies inside base and no existing
// component below base is a symlink.
func checkTarget(t testing.TB, base, target string) {
	t.Helper()
	if !within(base, target) {
		t.Fatalf("codextest: %s lies outside %s", target, base)
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
			t.Fatalf("codextest: lstat %s: %v", cur, err)
		}
		if fi.Mode()&fs.ModeSymlink != 0 {
			t.Fatalf("codextest: %s is a symlink; fixtures never write through links", cur)
		}
	}
}

func mkdirs(t testing.TB, base, dir string, perm fs.FileMode) {
	t.Helper()
	checkTarget(t, base, dir)
	if err := os.MkdirAll(dir, perm); err != nil {
		t.Fatalf("codextest: mkdir %s: %v", dir, err)
	}
}

// createFile creates path below base (parents 0755); an existing file fails
// the test, fixtures never clobber. A non-zero mtime is applied.
func createFile(t testing.TB, base, path string, data []byte, perm fs.FileMode, mtime time.Time) {
	t.Helper()
	mkdirs(t, base, filepath.Dir(path), dirPerm)
	checkTarget(t, base, path)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		t.Fatalf("codextest: create %s: %v", path, err)
	}
	_, werr := f.Write(data)
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		t.Fatalf("codextest: write %s: %v", path, werr)
	}
	if !mtime.IsZero() {
		if err := os.Chtimes(path, mtime, mtime); err != nil {
			t.Fatalf("codextest: chtimes %s: %v", path, err)
		}
	}
}

// encodeLine renders one JSONL record with its '\n' (HTML escaping off, as
// serde_json writes).
func encodeLine(t testing.TB, v any) []byte {
	t.Helper()
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		t.Fatalf("codextest: encode %T: %v", v, err)
	}
	return buf.Bytes()
}

// tomlString quotes s as a TOML basic string.
func tomlString(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '"' || r == '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		case r < 0x20 || r == 0x7f:
			fmt.Fprintf(&b, "\\u%04X", r)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}
