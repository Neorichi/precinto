package testkit

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/precinto/precinto/internal/paths"
)

// Hygiene rules (S13; docs/TESTPLAN.md §1.2, SEC-22). A file fails when its
// content, its name or its symlink target contains:
//
//   - a real-looking path outside the test's temp directory: a home
//     directory (/Users/<name> except /Users/Shared, /home/<name>, /root,
//     /var/root, C:\Users\<name>, /mnt/<drive>/Users/<name>), the macOS
//     per-user temp tree (/var/folders/…) or the real $HOME, also in the
//     Claude project-slug form (-Users-<name>-…, -home-<name>-…);
//     synthetic paths (/u/work/acme, ~/work/acme, /tmp/x) are fine;
//   - an email address, except at the reserved example domains (RFC 2606,
//     RFC 6761: example.com/.net/.org, *.example, *.test, *.invalid,
//     *.localhost);
//   - a token or API key: Anthropic, OpenAI, GitHub, GitLab, Slack, AWS,
//     Google, Stripe, npm and Hugging Face formats, JWTs, PEM/PGP private
//     keys, age secret and plugin identities, and secret-looking
//     assignments (token=…, "api_key": "…", Bearer …) whose value has both
//     letters and digits and no placeholder word;
//   - a UUID that is not a fixture UUID (isFixtureUUID).
//
// Findings are reported as file:line and kind only, never the matched text
// (it may be a secret). The content of an age file (a capsule) is
// ciphertext and only its header is checked; in binary content (a NUL
// byte) an email must also sit in a run of at least 16 printable bytes, so
// random bytes cannot fake one.

// scanWindow is the size of the read window; patterns are bounded by
// scanOverlap bytes, which consecutive windows share.
const (
	scanWindow   = 1 << 20
	scanOverlap  = 4 << 10
	maxFindings  = 50
	ageMagic     = "age-encryption.org/v1\n"
	maxAgeHeader = 1 << 20
)

// boundary is the character class that may precede a path: anything that
// cannot continue a path component.
const boundary = `(?:^|[^A-Za-z0-9._~-])`

type hygieneRule struct {
	kind  string
	re    *regexp.Regexp
	group int                                    // submatch holding the finding
	keep  func(s *hygieneScanner, m []byte) bool // false drops the match
	text  bool                                   // binary content: only in printable runs
}

var hygieneRules = []hygieneRule{
	{kind: "home directory path", re: regexp.MustCompile(boundary + `(/Users/[A-Za-z0-9._-]+)`), group: 1,
		keep: func(s *hygieneScanner, m []byte) bool { return !bytes.Equal(m, []byte("/Users/Shared")) }},
	{kind: "home directory path", re: regexp.MustCompile(boundary + `(/home/[A-Za-z0-9._-]+)`), group: 1},
	{kind: "home directory path", re: regexp.MustCompile(boundary + `(/(?:var/)?root)(?:$|[^A-Za-z0-9._~-])`), group: 1},
	{kind: "home directory path", re: regexp.MustCompile(`/mnt/[a-z]/Users/[A-Za-z0-9._-]+`)},
	{kind: "home directory path", re: regexp.MustCompile(`\b[A-Za-z]:[\\/]+Users[\\/]+([A-Za-z0-9._-]+)`), group: 0,
		keep: func(_ *hygieneScanner, m []byte) bool {
			name := m[bytes.LastIndexAny(m, `\/`)+1:]
			return !bytes.EqualFold(name, []byte("Public")) && !bytes.EqualFold(name, []byte("Default"))
		}},
	{kind: "macOS temp path", re: regexp.MustCompile(boundary + `((?:/private)?/var/folders/)`), group: 1},
	{kind: "home directory path (Claude slug)", re: regexp.MustCompile(boundary + `(-(?:Users|home)-[A-Za-z0-9][A-Za-z0-9-]*)`), group: 1,
		keep: func(s *hygieneScanner, m []byte) bool { return !bytes.HasPrefix(m, []byte("-Users-Shared")) }},

	{kind: "email address", re: regexp.MustCompile(`(?i)(?:^|[^a-z0-9._%+-])([a-z0-9._%+-]+@([a-z0-9-]+(?:\.[a-z0-9-]+)*\.[a-z]{2,24}))`), group: 1,
		keep: keepEmail, text: true},

	{kind: "API key", re: regexp.MustCompile(`\bsk-ant-[A-Za-z0-9_-]{20,}`)},
	{kind: "API key", re: regexp.MustCompile(`(?:^|[^A-Za-z0-9-])(sk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,})`), group: 1,
		keep: func(_ *hygieneScanner, m []byte) bool {
			return lettersAndDigits(m[3:]) && !bytes.HasPrefix(m, []byte("sk-ant-"))
		}},
	{kind: "API token", re: regexp.MustCompile(`\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}`)},
	{kind: "API token", re: regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{22,}`)},
	{kind: "API token", re: regexp.MustCompile(`\bglpat-[A-Za-z0-9_-]{20,}`)},
	{kind: "API token", re: regexp.MustCompile(`\bxox[abposr]-[A-Za-z0-9-]{10,}`)},
	{kind: "API key", re: regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`)},
	{kind: "API key", re: regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{35}`)},
	{kind: "API token", re: regexp.MustCompile(`\bya29\.[0-9A-Za-z_-]{20,}`)},
	{kind: "API key", re: regexp.MustCompile(`\b(?:sk|rk)_live_[0-9A-Za-z]{16,}`)},
	{kind: "API token", re: regexp.MustCompile(`\bnpm_[A-Za-z0-9]{36}\b`)},
	{kind: "API token", re: regexp.MustCompile(`\bhf_[A-Za-z0-9]{30,}`)},
	{kind: "JWT", re: regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`)},
	{kind: "private key", re: regexp.MustCompile(`-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----`)},
	{kind: "age identity", re: regexp.MustCompile(`AGE-SECRET-KEY-1[0-9A-Z]{50,}`)},
	{kind: "age identity", re: regexp.MustCompile(`AGE-PLUGIN-[A-Z0-9]+-1[0-9A-Z]{20,}`)},
	{kind: "secret assignment", re: regexp.MustCompile(`(?i)(?:api[_-]?key|secret[_-]?key|client[_-]?secret|access[_-]?token|auth[_-]?token|refresh[_-]?token|session[_-]?token|password|passwd|secret|token)["']?\s*[:=]\s*["']?([A-Za-z0-9/+_.=~-]{20,})`), group: 1,
		keep: keepSecretValue},
	{kind: "bearer token", re: regexp.MustCompile(`(?i)\bbearer\s+([A-Za-z0-9._~+/-]{20,}=*)`), group: 1,
		keep: keepSecretValue},
	{kind: "basic credentials", re: regexp.MustCompile(`(?i)\bbasic\s+([A-Za-z0-9+/]{20,}={0,2})(?:$|[^A-Za-z0-9+/=])`), group: 1,
		keep: keepSecretValue},

	{kind: "non-fixture UUID", re: regexp.MustCompile(`(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b`),
		keep: func(_ *hygieneScanner, m []byte) bool { return !isFixtureUUID(string(m)) }},
}

// isFixtureUUID reports whether u is recognisably synthetic:
//   - every group is one repeated hex digit (11111111-2222-3333-4444-
//     555555555555, the nil and max UUIDs);
//   - a counter: the first 20 hex digits are zero except the version and
//     variant nibbles (00000000-0000-0000-0000-000000000042,
//     00000000-0000-4000-8000-00000000002a);
//   - one of the RFC 4122 namespace ids (6ba7b810…6ba7b814-9dad-11d1-80b4-
//     00c04fd430c8).
//
// Anything else (in particular a random-looking v4 UUID, even one derived
// deterministically from a hash) cannot be told apart from a real session
// id and is not a fixture.
func isFixtureUUID(u string) bool {
	u = strings.ToLower(u)
	g := strings.Split(u, "-")
	if len(g) != 5 {
		return false
	}
	repeated := true
	for _, part := range g {
		if strings.Count(part, part[:1]) != len(part) {
			repeated = false
			break
		}
	}
	if repeated {
		return true
	}
	if g[0] == "00000000" && g[1] == "0000" && g[2][1:] == "000" && g[3][1:] == "000" {
		return true
	}
	switch u {
	case "6ba7b810-9dad-11d1-80b4-00c04fd430c8", "6ba7b811-9dad-11d1-80b4-00c04fd430c8",
		"6ba7b812-9dad-11d1-80b4-00c04fd430c8", "6ba7b814-9dad-11d1-80b4-00c04fd430c8":
		return true
	}
	return false
}

// reservedEmailDomains are the domains reserved for documentation and
// testing (RFC 2606, RFC 6761).
var reservedEmailDomains = []string{"example.com", "example.net", "example.org"}
var reservedEmailTLDs = []string{".example", ".test", ".invalid", ".localhost"}

var retinaAsset = regexp.MustCompile(`^[0-9]+x\.`)

func keepEmail(_ *hygieneScanner, m []byte) bool {
	at := bytes.LastIndexByte(m, '@')
	domain := strings.ToLower(string(m[at+1:]))
	if retinaAsset.MatchString(domain) { // icon@2x.png
		return false
	}
	for _, d := range reservedEmailDomains {
		if domain == d || strings.HasSuffix(domain, "."+d) {
			return false
		}
	}
	for _, tld := range reservedEmailTLDs {
		if strings.HasSuffix(domain, tld) {
			return false
		}
	}
	return true
}

// placeholderWords mark a value as a fixture rather than a secret.
var placeholderWords = []string{"example", "placeholder", "fixture", "dummy", "fake", "redacted",
	"changeme", "xxxx", "synthetic", "marker", "test", "sample"}

func keepSecretValue(_ *hygieneScanner, v []byte) bool {
	if !lettersAndDigits(v) {
		return false
	}
	low := strings.ToLower(string(v))
	for _, w := range placeholderWords {
		if strings.Contains(low, w) {
			return false
		}
	}
	return true
}

func lettersAndDigits(v []byte) bool {
	var letter, digit bool
	for _, c := range v {
		switch {
		case '0' <= c && c <= '9':
			digit = true
		case ('a' <= c && c <= 'z') || ('A' <= c && c <= 'Z'):
			letter = true
		}
	}
	return letter && digit
}

// hygieneScanner holds what a scan may accept: the temp directories the
// test owns, and the real HOME when the generic rules do not cover it.
type hygieneScanner struct {
	allowRoots []string // temp roots, symlinked and resolved forms
	allowSlugs []string // the same roots in Claude slug form
	realHome   *regexp.Regexp
}

// pathKinds are the rules whose matches are paths (allowed inside a temp
// root).
var pathKinds = map[string]bool{"home directory path": true, "macOS temp path": true, "real HOME path": true}

func newHygieneScanner(t testing.TB) *hygieneScanner {
	t.Helper()
	s := &hygieneScanner{}
	// t.TempDir() is <GOTMPDIR or TMPDIR>/<test><n>/<seq>: the base of
	// every temp dir the test binary's tests get.
	base := filepath.Dir(filepath.Dir(t.TempDir()))
	roots := []string{base}
	if r, err := filepath.EvalSymlinks(base); err == nil {
		roots = append(roots, r)
	}
	for _, r := range append([]string(nil), roots...) {
		switch {
		case strings.HasPrefix(r, "/private/"):
			roots = append(roots, strings.TrimPrefix(r, "/private"))
		case strings.HasPrefix(r, "/var/"), strings.HasPrefix(r, "/tmp/"), r == "/tmp":
			roots = append(roots, "/private"+r)
		}
	}
	for _, r := range roots {
		if r == "/" || r == "" {
			continue
		}
		s.allowRoots = append(s.allowRoots, r)
		s.allowSlugs = append(s.allowSlugs, claudeSlug(r))
	}
	// The real HOME gets a rule of its own only where the generic rules do
	// not already catch it (HOME=/var/lib/ci rather than /Users/<name>).
	if home, err := paths.UserHome(startEnv); err == nil && home != "/" && strings.Count(home, "/") >= 2 && !s.allowed(home) {
		probe := []byte(" " + home + "/x")
		covered := false
		s.scanBytes(probe, len(probe), func(int, string) { covered = true })
		if !covered {
			s.realHome = regexp.MustCompile(boundary + "(" + regexp.QuoteMeta(home) + `)(?:$|[^A-Za-z0-9._~-])`)
		}
	}
	return s
}

// claudeSlug is the projects/<slug> form Claude derives from a path.
func claudeSlug(p string) string {
	b := []byte(p)
	for i, c := range b {
		if !(('a' <= c && c <= 'z') || ('A' <= c && c <= 'Z') || ('0' <= c && c <= '9')) {
			b[i] = '-'
		}
	}
	return string(b)
}

// allowed reports whether path p lies inside a temp root.
func (s *hygieneScanner) allowed(p string) bool {
	for _, r := range s.allowRoots {
		if paths.Within(r, p) {
			return true
		}
	}
	return false
}

func (s *hygieneScanner) allowedSlug(slug string) bool {
	for _, a := range s.allowSlugs {
		if slug == a || strings.HasPrefix(slug, a+"-") {
			return true
		}
	}
	return false
}

// pathRun extends a path match to the whole path-like run starting at i
// (for the temp-root check).
func pathRun(w []byte, i int) string {
	j := i
	for j < len(w) {
		c := w[j]
		if c <= ' ' || c == '"' || c == '\'' || c == '`' || c == '<' || c == '>' || c == '|' || c == ';' || c == 0x7f {
			break
		}
		j++
	}
	return string(w[i:j])
}

// scanBytes checks one window. limit is the offset after which matches
// belong to the next window; report receives the offset and kind of each
// finding.
func (s *hygieneScanner) scanBytes(w []byte, limit int, report func(off int, kind string)) {
	binary := bytes.IndexByte(w, 0) >= 0
	rules := hygieneRules
	if s.realHome != nil {
		rules = append(rules[:len(rules):len(rules)], hygieneRule{kind: "real HOME path", re: s.realHome, group: 1})
	}
	for _, r := range rules {
		for _, m := range r.re.FindAllSubmatchIndex(w, -1) {
			start, end := m[2*r.group], m[2*r.group+1]
			if start < 0 || start >= limit {
				continue
			}
			match := w[start:end]
			if r.keep != nil && !r.keep(s, match) {
				continue
			}
			if r.text && binary && !inPrintableRun(w, start, end, 16) {
				continue
			}
			if pathKinds[r.kind] && s.allowed(pathRun(w, start)) {
				continue
			}
			if r.kind == "home directory path (Claude slug)" && s.allowedSlug(pathRun(w, start)) {
				continue
			}
			report(start, r.kind)
		}
	}
}

// inPrintableRun reports whether w[start:end] lies in a run of at least n
// printable ASCII bytes.
func inPrintableRun(w []byte, start, end, n int) bool {
	printable := func(c byte) bool { return c >= 0x20 && c < 0x7f || c == '\t' || c == '\n' || c == '\r' }
	i, j := start, end
	for i > 0 && printable(w[i-1]) {
		i--
	}
	for j < len(w) && printable(w[j]) {
		j++
	}
	return j-i >= n
}

type hygieneFinding struct {
	rel  string
	line int // 0: in the name or symlink target
	kind string
}

// scanTree walks dir (never following symlinks) and returns every finding,
// plus the errors that kept a file from being checked.
func (s *hygieneScanner) scanTree(dir string) (findings []hygieneFinding, problems []string) {
	seen := map[hygieneFinding]bool{}
	add := func(f hygieneFinding) {
		if !seen[f] {
			seen[f] = true
			findings = append(findings, f)
		}
	}
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		rel, _ := filepath.Rel(dir, p)
		rel = filepath.ToSlash(rel)
		if err != nil {
			problems = append(problems, fmt.Sprintf("%s: %v", rel, err))
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if rel != "." {
			name := []byte(rel)
			s.scanBytes(name, len(name), func(_ int, kind string) { add(hygieneFinding{rel, 0, kind + " in the file name"}) })
		}
		switch {
		case d.Type()&fs.ModeSymlink != 0:
			target, err := os.Readlink(p)
			if err != nil {
				problems = append(problems, fmt.Sprintf("%s: %v", rel, err))
				return nil
			}
			tb := []byte(target)
			s.scanBytes(tb, len(tb), func(_ int, kind string) { add(hygieneFinding{rel, 0, kind + " in the symlink target"}) })
		case d.Type().IsRegular():
			if err := s.scanFile(p, func(line int, kind string) { add(hygieneFinding{rel, line, kind}) }); err != nil {
				problems = append(problems, fmt.Sprintf("%s: %v", rel, err))
			}
		}
		return nil // directories are walked; FIFOs, sockets and devices hold no text
	})
	if err != nil {
		problems = append(problems, err.Error())
	}
	sort.SliceStable(findings, func(i, j int) bool {
		if findings[i].rel != findings[j].rel {
			return findings[i].rel < findings[j].rel
		}
		return findings[i].line < findings[j].line
	})
	return findings, problems
}

// scanFile streams one regular file through scanBytes.
func (s *hygieneScanner) scanFile(p string, report func(line int, kind string)) error {
	f, err := os.Open(p)
	if err != nil {
		return err
	}
	defer f.Close()
	buf := make([]byte, 0, scanWindow+scanOverlap)
	lines := 1 // line number at buf[0]
	first := true
	for {
		n, rerr := io.ReadFull(f, buf[len(buf):cap(buf)])
		buf = buf[:len(buf)+n]
		eof := errors.Is(rerr, io.EOF) || errors.Is(rerr, io.ErrUnexpectedEOF)
		if rerr != nil && !eof {
			return rerr
		}
		if first {
			first = false
			if bytes.HasPrefix(buf, []byte(ageMagic)) {
				// Ciphertext after the header: check the header only.
				end := bytes.Index(buf[:min(len(buf), maxAgeHeader)], []byte("\n--- "))
				if end >= 0 {
					if nl := bytes.IndexByte(buf[end+1:], '\n'); nl >= 0 {
						h := buf[:end+1+nl+1]
						s.scanBytes(h, len(h), func(off int, kind string) { report(1+bytes.Count(h[:off], []byte("\n")), kind) })
						return nil
					}
				}
			}
		}
		limit := len(buf)
		if !eof {
			limit = len(buf) - scanOverlap
		}
		s.scanBytes(buf, limit, func(off int, kind string) {
			report(lines+bytes.Count(buf[:off], []byte("\n")), kind)
		})
		if eof {
			return nil
		}
		lines += bytes.Count(buf[:limit], []byte("\n"))
		buf = append(buf[:0], buf[limit:]...)
	}
}

// hygiene implements Hygiene.
func hygiene(t testing.TB, dir string) {
	t.Helper()
	root, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatalf("testkit.Hygiene: %v", err)
	}
	if fi, err := os.Stat(root); err != nil || !fi.IsDir() {
		t.Fatalf("testkit.Hygiene: %s is not a directory (%v)", dir, err)
	}
	s := newHygieneScanner(t)
	findings, problems := s.scanTree(root)
	for _, p := range problems {
		t.Errorf("testkit.Hygiene: cannot check %s", p)
	}
	for i, f := range findings {
		if i == maxFindings {
			t.Errorf("testkit.Hygiene: %d more findings not listed", len(findings)-maxFindings)
			break
		}
		if f.line == 0 {
			t.Errorf("testkit.Hygiene: %s: %s", f.rel, f.kind)
		} else {
			t.Errorf("testkit.Hygiene: %s:%d: %s", f.rel, f.line, f.kind)
		}
	}
}

// hygieneOfBytes returns the kinds of finding in b (Golden refuses to write
// such content).
func hygieneOfBytes(t testing.TB, b []byte) []string {
	t.Helper()
	s := newHygieneScanner(t)
	var kinds []string
	s.scanBytes(b, len(b), func(off int, kind string) {
		kinds = append(kinds, fmt.Sprintf("line %d: %s", 1+bytes.Count(b[:off], []byte("\n")), kind))
	})
	return kinds
}
