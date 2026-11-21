package integration_test

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/precinto/precinto/internal/testkit"
)

// The subcommands of SPEC §16.1 with their usage lines, as the binary
// prints them (--help, exit 0); an unknown flag is exit 2 (SPEC §16.2).
// These paths touch no other package, so they run in every worktree.
func TestBinaryUsageAndExitCodes(t *testing.T) {
	exe := needBinary(t)
	h := newHome(t)
	r := precinto(t, exe, h, h.Root, nil, "")
	if r.code != 2 || !strings.Contains(r.stderr, "usage: precinto <command>") {
		t.Fatalf("no args: %+v", r)
	}
	r = precinto(t, exe, h, h.Root, nil, "", "--help")
	if r.code != 0 {
		t.Fatalf("--help: %+v", r)
	}
	visible := []string{"init", "factor", "vault", "protect", "unprotect", "status", "unlock", "lock", "seal",
		"sweep", "restore", "resume", "run", "ls", "open", "cat", "resolve", "forget", "prune", "codex",
		"agent", "service", "shell-init", "integrate", "doctor", "recover", "version"}
	for _, c := range visible {
		if !strings.Contains(r.stdout, "\n  "+c+" ") {
			t.Errorf("--help lacks %s", c)
		}
	}
	for _, c := range visible {
		if c == "version" {
			continue
		}
		r := precinto(t, exe, h, h.Root, nil, "", c, "--help")
		if r.code != 0 || !strings.HasPrefix(r.stdout, "usage: precinto "+c) {
			t.Errorf("%s --help: %+v", c, r)
		}
		r = precinto(t, exe, h, h.Root, nil, "", c, "--definitely-not-a-flag")
		if r.code != 2 {
			t.Errorf("%s with a bad flag: exit %d (%s)", c, r.code, r.stderr)
		}
	}
	if r := precinto(t, exe, h, h.Root, nil, "", "frobnicate"); r.code != 2 {
		t.Errorf("unknown command: %+v", r)
	}
	// D49: deferred commands exit 2 with a notice.
	for _, c := range []string{"canary", "scrub", "rekey", "import"} {
		r := precinto(t, exe, h, h.Root, nil, "", c)
		if r.code != 2 || !strings.Contains(r.stderr, "planned for a later version") {
			t.Errorf("%s: %+v", c, r)
		}
	}
	if r := precinto(t, exe, h, h.Root, nil, "", "version"); r.code != 0 || !strings.HasPrefix(r.stdout, "precinto ") {
		t.Errorf("version: %+v", r)
	}
}

// S17: cat prints plaintext only to a terminal or --to FILE; with stdout
// a pipe it is refused before anything is read. recover --key-file needs
// --insecure-key-file (SEC-21).
func TestBinaryRefusalsBeforeAnyWork(t *testing.T) {
	exe := needBinary(t)
	h := newHome(t)
	if r := precinto(t, exe, h, h.Root, nil, "", "cat", "x.md.precinto"); r.code != 2 || !strings.Contains(r.stderr, "only to a terminal") {
		t.Errorf("cat to a pipe: %+v", r)
	}
	if r := precinto(t, exe, h, h.Root, nil, "", "recover", "--key-file", filepath.Join(h.Dir, "k")); r.code != 2 || !strings.Contains(r.stderr, "--insecure-key-file") {
		t.Errorf("recover --key-file: %+v", r)
	}
	if r := precinto(t, exe, h, h.Root, nil, "", "seal", "--dormant", "gemini"); r.code != 2 {
		t.Errorf("seal --dormant without --experimental: %+v", r)
	}
}

// service install writes the LaunchAgent into the fake HOME; a testing
// binary never runs launchctl (it is skipped inside the binary). linux:
// deferred, exit 2 (D49).
func TestBinaryServiceInFakeHome(t *testing.T) {
	exe := needBinary(t)
	h := newHome(t)
	// The pinned link the plist names (integrate writes it in real use).
	if err := os.MkdirAll(filepath.Dir(h.Layout.BinLink), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(exe, h.Layout.BinLink); err != nil {
		t.Fatal(err)
	}
	r := precinto(t, exe, h, h.Root, nil, "", "service", "install")
	if runtime.GOOS != "darwin" {
		if r.code != 2 || !strings.Contains(r.stderr, "not available on linux") {
			t.Fatalf("linux: %+v", r)
		}
		return
	}
	if r.code != 0 {
		t.Fatalf("install: %+v", r)
	}
	plist := filepath.Join(h.HomeDir, "Library", "LaunchAgents", "com.github.precinto.sweep.plist")
	b, err := os.ReadFile(plist)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"<string>" + h.Layout.BinLink + "</string>", "<string>sweep</string>", "<string>--quiet</string>", "<string>" + h.Base + "</string>"} {
		if !strings.Contains(string(b), want) {
			t.Errorf("plist lacks %q", want)
		}
	}
	if r := precinto(t, exe, h, h.Root, nil, "", "service", "status"); r.code != 0 || !strings.Contains(r.stdout, "installed") {
		t.Errorf("status: %+v", r)
	}
	if r := precinto(t, exe, h, h.Root, nil, "", "service", "uninstall"); r.code != 0 {
		t.Errorf("uninstall: %+v", r)
	}
	if _, err := os.Stat(plist); !os.IsNotExist(err) {
		t.Error("plist left behind")
	}
}

// TESTPLAN §10: every testdata/ directory of the repository passes
// testkit.Hygiene (no real paths, emails, tokens or non-fixture UUIDs).
func TestTestdataHygiene(t *testing.T) {
	root := moduleRoot(t)
	n := 0
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			return nil
		}
		if strings.HasPrefix(d.Name(), ".") && p != root {
			return fs.SkipDir
		}
		if d.Name() == "testdata" {
			n++
			testkit.Hygiene(t, p)
			return fs.SkipDir
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if n == 0 {
		t.Fatal("no testdata directory found (wrong root?)")
	}
}

// D41, D78: plugins/codex/ is byte-identical across releases (Codex's
// trust hash covers every file of the plugin root). Its SHA-256 list is
// recorded in testdata/codex-plugin.sha256 ("<hex>  <path relative to
// plugins/codex>" per line, "#" comments): any drift fails, so a change to
// the root is a deliberate edit of the list in the same change until E2E-9
// freezes the root (D61), and impossible after that.
func TestCodexPluginByteStable(t *testing.T) {
	root := moduleRoot(t)
	list := filepath.Join("testdata", "codex-plugin.sha256")
	f, err := os.Open(list)
	if err != nil {
		t.Fatalf("the recorded SHA-256 list of plugins/codex/ (D78): %v", err)
	}
	defer f.Close()
	want := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		sum, rel, ok := strings.Cut(line, "  ")
		if !ok {
			t.Fatalf("bad line %q", line)
		}
		want[rel] = sum
	}
	got := map[string]string{}
	base := filepath.Join(root, "plugins", "codex")
	err = filepath.WalkDir(base, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(base, p)
		s := sha256.Sum256(b)
		got[filepath.ToSlash(rel)] = hex.EncodeToString(s[:])
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for rel, sum := range want {
		if got[rel] != sum {
			t.Errorf("plugins/codex/%s changed (or is missing): the Codex trust hash would break (D41)", rel)
		}
	}
	for rel := range got {
		if _, ok := want[rel]; !ok {
			t.Errorf("plugins/codex/%s is new: the Codex trust hash would break (D41)", rel)
		}
	}
}
