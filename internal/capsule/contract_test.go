package capsule_test

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/precinto/precinto/internal/capsule"
	"github.com/precinto/precinto/internal/fsx"
)

// TmpName is a pure function of the final name: callers journal it before
// Seal (D58a).
func TestTmpNameGolden(t *testing.T) {
	for name, want := range map[string]string{
		"g000007.pcap":  ".g000007.pcap.tmp",
		"g1234567.pcap": ".g1234567.pcap.tmp",
	} {
		if got := capsule.TmpName(name); got != want {
			t.Errorf("TmpName(%q) = %q, want %q", name, got, want)
		}
	}
}

// A temporary left over by a crash makes Seal fail with ErrExist and stay
// in place for journal recovery; Seal writes nothing else.
func TestSealRefusesALeftoverTemporary(t *testing.T) {
	u := newUnit(t)
	u.write("s.jsonl", []byte("x\n"))
	left := filepath.Join(u.outP, capsule.TmpName("g000001.pcap"))
	if err := os.WriteFile(left, []byte("partial"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := seal(t, u, newKeys(t), "g000001.pcap", u.inputs("s.jsonl"), nil, nil)
	if !errors.Is(err, fsx.ErrExist) {
		t.Fatalf("Seal = %v, want fsx.ErrExist", err)
	}
	if b, err := os.ReadFile(left); err != nil || string(b) != "partial" {
		t.Fatalf("leftover temporary changed: %q %v", b, err)
	}
	if n := u.outNames(); len(n) != 1 {
		t.Fatalf("capsule directory %v", n)
	}
	u.assertPlaintext()
}

// SealRequest.Dirs: empty directories and codex-home blob files are
// recorded as given, without tar members; anything else is refused.
func TestSealMemberlessEntries(t *testing.T) {
	u := newUnit(t)
	k := newKeys(t)
	u.write("auth.json", []byte("{}"))
	blob := capsule.Entry{Base: capsule.BaseCodexHome, Rel: "sessions/2026/rollout.jsonl", Mode: 0o644, MtimeNS: 1700000000000000000,
		Size: 12345, SHA256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", Blob: "fedcba9876543210fedcba9876543210", Group: "g1"}
	dir := capsule.Entry{Base: capsule.BaseCodexHome, Rel: "memories", Dir: true, Mode: 0o700}
	in := []capsule.Input{u.input("auth.json")}
	in[0].Base = capsule.BaseCodexHome
	s, err := seal(t, u, k, "g000001.pcap", in, []capsule.Entry{blob, dir}, nil)
	if err != nil {
		t.Fatal(err)
	}
	files := s.Manifest.Files
	if len(files) != 3 || files[0].Name != "f/000001" {
		t.Fatalf("manifest %+v", files)
	}
	if b := files[1]; b.Name != "" || b.Dir || b.Blob != blob.Blob || b.Size != blob.Size || b.SHA256 != blob.SHA256 ||
		b.Rel != blob.Rel || b.Mode != 0o644 || b.MtimeNS != blob.MtimeNS || b.Group != "g1" {
		t.Errorf("blob entry %+v", b)
	}
	if d := files[2]; !d.Dir || d.Name != "" || d.Blob != "" || d.Size != 0 || d.SHA256 != "" {
		t.Errorf("directory entry %+v", d)
	}
	// The round trip keeps both without staging anything for them.
	st := newStaging(t, u.root)
	f, _, err := u.out.Open(s.Name)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	m, staged, err := capsule.Extract(context.Background(), f, capsule.ExtractOptions{FileKey: fileKey(t, u.out, s.Name, k.vault), Staging: st, Limits: capsule.Limits{MaxTotal: 1 << 20}, Check: allowAll})
	if err != nil {
		t.Fatal(err)
	}
	if len(staged) != 1 || len(m.Files) != 3 || m.Files[1].Blob != blob.Blob || !m.Files[2].Dir {
		t.Fatalf("extracted %d staged, manifest %+v", len(staged), m.Files)
	}

	for name, bad := range map[string]capsule.Entry{
		"neither":          {Base: capsule.BaseCodexHome, Rel: "x", Mode: 0o600},
		"directory+blob":   {Base: capsule.BaseCodexHome, Rel: "x", Dir: true, Blob: blob.Blob, SHA256: blob.SHA256},
		"directory+size":   {Base: capsule.BaseCodexHome, Rel: "x", Dir: true, Size: 3},
		"blob without sha": {Base: capsule.BaseCodexHome, Rel: "x", Blob: blob.Blob},
		"short blob key":   {Base: capsule.BaseCodexHome, Rel: "x", Blob: "abc", SHA256: blob.SHA256},
	} {
		u := newUnit(t)
		u.write("a", []byte("a"))
		if _, err := seal(t, u, k, "g000001.pcap", u.inputs("a"), []capsule.Entry{bad}, nil); !errors.Is(err, capsule.ErrFormat) {
			t.Errorf("%s: Seal = %v, want ErrFormat", name, err)
		}
		if n := u.outNames(); len(n) != 0 {
			t.Errorf("%s: left %v", name, n)
		}
	}
}

// Input.Open is read instead of Dir/Rel for any input, not only rescues:
// a still-linked file handed over open seals its descriptor's bytes.
func TestSealOpenOnALinkedInput(t *testing.T) {
	u := newUnit(t)
	k := newKeys(t)
	u.write("history.jsonl", []byte("kept line\n"))
	f, err := os.Open(filepath.Join(u.root, "history.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	st, err := fsx.Fstat(f)
	if err != nil {
		t.Fatal(err)
	}
	s, err := seal(t, u, k, "g000001.pcap", []capsule.Input{{Base: capsule.BaseClaudeConfig, Dir: u.base, Rel: "history.jsonl", Snap: st, Open: f}}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if e := s.Manifest.Files[0]; e.Rel != "history.jsonl" || e.Size != int64(len("kept line\n")) {
		t.Fatalf("entry %+v", e)
	}
	u.assertPlaintext()
}

func TestReadSalt(t *testing.T) {
	dir, err := fsx.Realpath(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "name.salt")
	if salt, ok, err := capsule.ReadSalt(p); ok || salt != nil || err != nil {
		t.Fatalf("missing salt: %x %v %v", salt, ok, err)
	}
	if ents, _ := os.ReadDir(dir); len(ents) != 0 {
		t.Fatalf("ReadSalt created %v", ents)
	}
	if _, ok, err := capsule.ReadSalt(filepath.Join(dir, "missing-dir", "name.salt")); ok || err != nil {
		t.Fatalf("missing state directory: %v %v", ok, err)
	}
	loaded, err := capsule.LoadSalt(p)
	if err != nil {
		t.Fatal(err)
	}
	salt, ok, err := capsule.ReadSalt(p)
	if !ok || err != nil || !bytes.Equal(salt, loaded) {
		t.Fatalf("ReadSalt = %x %v %v, LoadSalt %x", salt, ok, err, loaded)
	}
	link := filepath.Join(dir, "link.salt")
	if err := os.Symlink(p, link); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := capsule.ReadSalt(link); ok || !errors.Is(err, fsx.ErrUnsafe) {
		t.Errorf("symlinked salt: %v %v", ok, err)
	}
	fifo := filepath.Join(dir, "fifo.salt")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := capsule.ReadSalt(fifo); ok || !errors.Is(err, fsx.ErrUnsafe) {
		t.Errorf("FIFO salt: %v %v", ok, err)
	}
	// The sealers' LoadSalt refuses the FIFO too, at once, and never
	// replaces it with a fresh salt (every unit key depends on it).
	done := make(chan error, 1)
	go func() { _, err := capsule.LoadSalt(fifo); done <- err }()
	select {
	case err := <-done:
		if !errors.Is(err, fsx.ErrUnsafe) {
			t.Errorf("LoadSalt of a FIFO: %v, want ErrUnsafe", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("LoadSalt blocked on a FIFO")
	}
	if fi, err := os.Lstat(fifo); err != nil || fi.Mode()&os.ModeNamedPipe == 0 {
		t.Errorf("the FIFO was replaced: %v %v", fi, err)
	}
	short := filepath.Join(dir, "short.salt")
	if err := os.WriteFile(short, []byte("short"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := capsule.ReadSalt(short); ok || err == nil {
		t.Errorf("short salt: %v %v", ok, err)
	}
	if _, _, err := capsule.ReadSalt("relative/name.salt"); !errors.Is(err, capsule.ErrUnsafe) {
		t.Errorf("relative path: %v", err)
	}
}

// Limits.MaxTotal ≤ 0 refuses any capsule with plaintext bytes (CC-03),
// and only those: empty files and directories need no budget.
func TestExtractBudgetAtOrBelowZero(t *testing.T) {
	k := newKeys(t)
	extract := func(u *unit, name string, max int64) error {
		t.Helper()
		f, _, err := u.out.Open(name)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		_, _, err = capsule.Extract(context.Background(), f, capsule.ExtractOptions{
			FileKey: fileKey(t, u.out, name, k.vault), Staging: newStaging(t, u.root), Limits: capsule.Limits{MaxTotal: max}, Check: allowAll,
		})
		return err
	}
	full := newUnit(t)
	full.write("a", []byte("x"))
	if _, err := seal(t, full, k, "g000001.pcap", full.inputs("a"), nil, nil); err != nil {
		t.Fatal(err)
	}
	empty := newUnit(t)
	empty.write("empty.json", nil)
	dirs := []capsule.Entry{{Base: capsule.BaseClaudeConfig, Rel: "file-history/x", Dir: true, Mode: 0o700}}
	if _, err := seal(t, empty, k, "g000001.pcap", empty.inputs("empty.json"), dirs, nil); err != nil {
		t.Fatal(err)
	}
	for _, max := range []int64{0, -1, -1 << 40} {
		if err := extract(full, "g000001.pcap", max); !errors.Is(err, capsule.ErrTooLarge) {
			t.Errorf("MaxTotal %d, 1 byte of plaintext: %v, want ErrTooLarge", max, err)
		}
		if err := extract(empty, "g000001.pcap", max); err != nil {
			t.Errorf("MaxTotal %d, no plaintext bytes: %v", max, err)
		}
	}
}
