package testkit_test

import (
	"crypto/rand"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/Neorichi/precinto/internal/testkit"
)

// Secret-looking samples are assembled at run time so that no literal in
// this file matches a secret scanner.
func fakeToken(prefix string, n int) string { return prefix + strings.Repeat("a1B2", n/4+1)[:n] }

func writeFiles(t *testing.T, dir string, files map[string]string) {
	t.Helper()
	for name, body := range files {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func hygieneOf(t *testing.T, dir string) *recorder {
	t.Helper()
	return record(t, func(tb testing.TB) { testkit.Hygiene(tb, dir) })
}

// TestHygieneFindings: each sample alone must fail the check, reported
// with its file, line and kind, and never with the matched text.
func TestHygieneFindings(t *testing.T) {
	uuid := "3f1c9a7e-5b2d-4e8f-9a6c-1d2e3f4a5b6c"
	cases := []struct {
		name, body, kind string
	}{
		{"darwin home", `{"cwd": "/Users/alice/work/acme"}`, "home directory path"},
		{"linux home", "path=/home/bob/.claude/projects\n", "home directory path"},
		{"root home", "HOME=/root\n", "home directory path"},
		{"darwin root home", "dir /var/root/x", "home directory path"},
		{"windows home", `C:\\Users\\carol\\AppData`, "home directory path"},
		{"wsl home", "/mnt/c/Users/dave/x", "home directory path"},
		{"file url", "file:///Users/erin/notes.md", "home directory path"},
		{"claude slug", "projects/-Users-frank-work-acme/x.jsonl", "home directory path (Claude slug)"},
		{"claude slug linux", `"slug": "-home-gina-src"`, "home directory path (Claude slug)"},
		{"macos temp", "/var/folders/zz/zyxvpxvq6csfxvn_n0000000000000/T/x", "macOS temp path"},
		{"private macos temp", "/private/var/folders/zz/zyxvpxvq6csfxvn_n0000000000000/T/x", "macOS temp path"},
		{"email", "Author: Jane Doe <jane.doe@corp.io>\n", "email address"},
		{"anthropic key", "key " + fakeToken("sk-"+"ant-api03-", 40), "API key"},
		{"openai key", "OPENAI=" + fakeToken("sk-"+"proj-", 40), "API key"},
		{"github token", fakeToken("gh"+"p_", 36), "API token"},
		{"github pat", fakeToken("github"+"_pat_", 30), "API token"},
		{"gitlab token", fakeToken("gl"+"pat-", 20), "API token"},
		{"slack token", fakeToken("xo"+"xb-", 30), "API token"},
		{"aws key", "AKI" + "A" + strings.Repeat("Q7", 8), "API key"},
		{"google key", fakeToken("AI"+"za", 35), "API key"},
		{"google oauth", fakeToken("ya"+"29.", 30), "API token"},
		{"stripe key", fakeToken("sk"+"_live_", 24), "API key"},
		{"npm token", fakeToken("np"+"m_", 36), "API token"},
		{"hugging face", fakeToken("h"+"f_", 34), "API token"},
		{"jwt", fakeToken("ey"+"J", 20) + "." + fakeToken("ey"+"J", 20) + "." + fakeToken("", 20), "JWT"},
		{"pem key", "-----BEGIN " + "RSA PRIVATE KEY-----\nMII\n", "private key"},
		{"openssh key", "-----BEGIN " + "OPENSSH PRIVATE KEY-----", "private key"},
		{"pgp key", "-----BEGIN " + "PGP PRIVATE KEY BLOCK-----", "private key"},
		{"age identity", "AGE-SECRET-" + "KEY-1" + strings.Repeat("QZ9", 20)[:58], "age identity"},
		{"age plugin identity", "AGE-PLUGIN-" + "SE-1" + strings.Repeat("QZ9", 10), "age identity"},
		{"secret assignment", `{"access_token": "` + fakeToken("", 32) + `"}`, "secret assignment"},
		{"password", "password = " + fakeToken("", 24), "secret assignment"},
		{"bearer", "Authorization: Bearer " + fakeToken("", 40), "bearer token"},
		{"basic", "Authorization: Basic " + fakeToken("", 28) + "==", "basic credentials"},
		{"uuid", `{"sessionId": "` + uuid + `"}`, "non-fixture UUID"},
		{"uuid upper", strings.ToUpper(uuid), "non-fixture UUID"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			writeFiles(t, dir, map[string]string{"a/sample.txt": "first line\n" + c.body + "\n"})
			r := hygieneOf(t, dir)
			out := r.text()
			if r.fatal || !strings.Contains(out, "a/sample.txt:2: "+c.kind) {
				t.Fatalf("Hygiene output %q, want a/sample.txt:2: %s", out, c.kind)
			}
			// The secret itself is never echoed.
			if secret := strings.TrimSpace(c.body); len(secret) > 12 && strings.Contains(out, secret[len(secret)-12:]) {
				t.Errorf("Hygiene echoed the finding: %q", out)
			}
		})
	}
}

// TestHygieneClean: fixtures, synthetic paths and look-alikes pass.
func TestHygieneClean(t *testing.T) {
	tmp := t.TempDir()
	files := map[string]string{
		"fixture-uuids.json": `{"a": "11111111-2222-3333-4444-555555555555", "b": "00000000-0000-0000-0000-000000000000",
			"c": "ffffffff-ffff-ffff-ffff-ffffffffffff", "d": "00000000-0000-4000-8000-00000000002a",
			"e": "00000000-0000-0000-0000-000000000042", "ns": "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
			"f": "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE"}`,
		"paths.txt": "/u/work/acme ~/work/acme /tmp/x /Users/Shared/x /usr/local/bin /home /homes/codex /rootfs/x " +
			"/root-acme --home-dir C:\\Users\\Public my-home-page task-runner-implementation-detail\n",
		"temp.txt":    tmp + "/home/work/acme/notes.md\n" + strings.Replace(tmp, "/", "-", -1) + "\n",
		"emails.txt":  "ops@example.com a@b.example c@d.test e@f.invalid g@x.localhost icon@2x.png\n",
		"hex.txt":     "unit 7c86bcb2589f2f6c00c44229522bb4e1 sha256 " + strings.Repeat("ab", 32) + "\n",
		"marker.txt":  testkit.Marker(t) + " " + testkit.Marker(t) + "\n",
		"prose.md":    "The token budget is 12345678901234567890 tokens; secrets: none. Bearer of good news.\n",
		"placeholder": `{"api_key": "PLACEHOLDER-key-0123456789abcd", "token": "fixture-token-000000000000000000"}` + "\n",
		"sk-words.txt": "risk-assessment-2026-q4-planning-notes and disk-usage-0123456789abcdef " +
			"sk-learn-is-a-python-machine-learning-library\n",
		"age.txt": "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p\n",
		"empty":   "",
	}
	writeFiles(t, tmp, files)
	if r := hygieneOf(t, tmp); r.Failed() {
		t.Errorf("clean files flagged:\n%s", r.text())
	}
}

func TestHygieneNamesAndLinks(t *testing.T) {
	dir := t.TempDir()
	writeFiles(t, dir, map[string]string{"3f1c9a7e-5b2d-4e8f-9a6c-1d2e3f4a5b6c.jsonl": "{}\n"})
	if err := os.Symlink("/Users/alice/secret", filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("relative/target", filepath.Join(dir, "fine-link")); err != nil {
		t.Fatal(err)
	}
	out := hygieneOf(t, dir).text()
	for _, want := range []string{
		"3f1c9a7e-5b2d-4e8f-9a6c-1d2e3f4a5b6c.jsonl: non-fixture UUID in the file name",
		"link: home directory path in the symlink target",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in %q", want, out)
		}
	}
	if strings.Contains(out, "fine-link") {
		t.Errorf("relative link flagged: %q", out)
	}
}

func TestHygieneBinaryAndCiphertext(t *testing.T) {
	random := make([]byte, 256<<10)
	_, _ = rand.Read(random)
	dir := t.TempDir()
	// An age file: only the header is text; whatever follows is ciphertext.
	capsule := append([]byte("age-encryption.org/v1\n-> X25519 c29tZQ\nYm9keQ\n--- bWFj\n"), random...)
	capsule = append(capsule, []byte("/Users/alice jane@corp.io")...)
	// Binary content: an email-looking fragment between NULs is noise, a
	// real one inside text is not.
	noise := []byte("\x00\x01ab@cd.ef\x00\x02")
	text := append([]byte("\x00\x00"), []byte("contact jane.doe@corp.io for access\x00")...)
	for name, b := range map[string][]byte{"g000001.pcap": capsule, "noise.bin": noise, "text.bin": text} {
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	out := hygieneOf(t, dir).text()
	if strings.Contains(out, "g000001.pcap") || strings.Contains(out, "noise.bin") {
		t.Errorf("ciphertext or noise flagged: %q", out)
	}
	if !strings.Contains(out, "text.bin:1: email address") {
		t.Errorf("email in binary text not flagged: %q", out)
	}
	// An age header that itself leaks is still checked.
	leak := []byte("age-encryption.org/v1\n-> X25519 /Users/alice\n--- bWFj\n\x00\x01")
	d2 := t.TempDir()
	if err := os.WriteFile(filepath.Join(d2, "x.pcap"), leak, 0o600); err != nil {
		t.Fatal(err)
	}
	if out := hygieneOf(t, d2).text(); !strings.Contains(out, "x.pcap:2: home directory path") {
		t.Errorf("leaking age header: %q", out)
	}
}

func TestHygieneErrors(t *testing.T) {
	mustFatal(t, "testkit.Hygiene", func(tb testing.TB) { testkit.Hygiene(tb, filepath.Join(t.TempDir(), "missing")) })
	f := filepath.Join(t.TempDir(), "file")
	writeFiles(t, filepath.Dir(f), map[string]string{"file": "x"})
	mustFatal(t, "not a directory", func(tb testing.TB) { testkit.Hygiene(tb, f) })
	if os.Geteuid() != 0 && runtime.GOOS != "windows" {
		dir := t.TempDir()
		writeFiles(t, dir, map[string]string{"secret.txt": "x"})
		if err := os.Chmod(filepath.Join(dir, "secret.txt"), 0o000); err != nil {
			t.Fatal(err)
		}
		if out := hygieneOf(t, dir).text(); !strings.Contains(out, "cannot check secret.txt") {
			t.Errorf("unreadable file not reported: %q", out)
		}
	}
	// Many findings are summarised, not listed one by one.
	dir := t.TempDir()
	many := map[string]string{}
	for i := 0; i < 60; i++ {
		many["f"+strconv.Itoa(i)+".txt"] = "/Users/alice/x\n"
	}
	writeFiles(t, dir, many)
	if out := hygieneOf(t, dir).text(); !strings.Contains(out, "10 more findings not listed") {
		t.Errorf("findings not capped: %d lines", strings.Count(out, "\n"))
	}
	// A symlinked directory is checked through its target.
	target := t.TempDir()
	writeFiles(t, target, map[string]string{"x.txt": "/Users/alice/x\n"})
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if out := hygieneOf(t, link).text(); !strings.Contains(out, "x.txt:1: home directory path") {
		t.Errorf("symlinked dir: %q", out)
	}
}

// TestHygieneRepositoryTestdata runs the check over testkit's own
// testdata/, as CI does for every package (S13).
func TestHygieneRepositoryTestdata(t *testing.T) {
	testkit.Hygiene(t, "testdata")
}
