package agent

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/awnumar/memguard"

	"github.com/Neorichi/precinto/internal/paths"
	"github.com/Neorichi/precinto/internal/platform"
	"github.com/Neorichi/precinto/internal/platform/fakeplatform"
)

// TestAssuanExchange drives the pinentry response parser with scripted
// streams (no pinentry program is run).
func TestAssuanExchange(t *testing.T) {
	a := &assuan{r: strings.NewReader("OK Pleased to meet you\n# comment\nS PASSWORD_FROM_CACHE\nD p%25ss%0Aword\nOK\n")}
	if b, err := a.expectOK(); err != nil || b.Size() != 0 {
		t.Fatalf("greeting = %v %v", b, err)
	}
	b, err := a.expectOK()
	if err != nil || string(b.Bytes()) != "p%ss\nword" {
		t.Fatalf("pin = %q %v", b.Bytes(), err)
	}
	b.Destroy()
	a = &assuan{r: strings.NewReader("ERR 83886179 Operation cancelled <Pinentry>\n")}
	if _, err := a.expectOK(); !errors.Is(err, errPinentryCancelled) {
		t.Fatalf("cancel = %v", err)
	}
	a = &assuan{r: strings.NewReader("D unterminated")}
	if _, err := a.expectOK(); err == nil {
		t.Fatal("truncated stream accepted")
	}
	if got := assuanEscape("50% off\r\nnow"); got != "50%25 off%0D%0Anow" {
		t.Fatalf("escape = %q", got)
	}
	if u := assuanUnescape([]byte("%zz%4")); string(u.Bytes()) != "%zz%4" {
		t.Fatalf("bad escapes must stay literal: %q", u.Bytes())
	}
	for i := range a.line {
		if a.line[i] != 0 {
			a.wipe()
			break
		}
	}
	a.wipe()
	for _, c := range a.line {
		if c != 0 {
			t.Fatal("line buffer not wiped")
		}
	}
}

// CC-15: a Pinentry seam set by the caller (agenttest's stub) is kept
// whatever process table is used, the real one included; only a nil seam
// with the kernel's table selects the real pinentry, and a fake table
// without a seam never runs a program. (The real pinentry is never called
// here.)
func TestPinentrySeamIsKept(t *testing.T) {
	stubErr := errors.New("stub")
	stub := func(context.Context, string, string) (*memguard.LockedBuffer, error) { return nil, stubErr }
	for _, procs := range []platform.ProcTable{platform.System(), fakeplatform.NewProcs()} {
		o := withDefaults(Options{Procs: procs, Pinentry: stub, Harden: func() error { return nil }})
		if _, err := o.Pinentry(context.Background(), "d", "p"); !errors.Is(err, stubErr) {
			t.Fatalf("%T: the caller's Pinentry was replaced", procs)
		}
	}
	o := withDefaults(Options{Procs: fakeplatform.NewProcs(), Harden: func() error { return nil }})
	if _, err := o.Pinentry(context.Background(), "d", "p"); !errors.Is(err, errNoPinentry) {
		t.Fatalf("fake table without a seam: %v (never a real dialog in tests)", err)
	}
	if o := withDefaults(Options{Procs: platform.System(), Harden: func() error { return nil }}); o.Pinentry == nil {
		t.Fatal("no default pinentry with the real process table")
	}
}

// D97 (SEC-F2): the default wiring never runs a pinentry from a directory
// the user can write, wherever it sits on the inherited PATH: the planted
// program is never executed and nothing else qualifies here.
func TestPinentryIgnoresUntrustedPATH(t *testing.T) {
	evilDir := t.TempDir()
	log := filepath.Join(evilDir, "seen.log")
	script := "#!/bin/sh\necho ran >> \"" + log + "\"\necho OK\nwhile IFS= read -r line; do case $line in GETPIN) echo \"D x\"; echo OK ;; BYE) echo OK; exit 0 ;; *) echo OK ;; esac; done\n"
	for _, n := range pinentryNames {
		if err := os.WriteFile(filepath.Join(evilDir, n), []byte(script), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	o := withDefaults(Options{Env: paths.FromMap(map[string]string{"PATH": evilDir, "HOME": evilDir}), Procs: platform.System(),
		Harden: func() error { return nil }})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if sec, err := o.Pinentry(ctx, "precinto: test", "precinto passphrase:"); !errors.Is(err, errNoPinentry) {
		if sec != nil {
			sec.Destroy()
		}
		t.Fatalf("pinentry from a user-writable directory: %v", err)
	}
	if b, _ := os.ReadFile(log); len(b) != 0 {
		t.Fatal("the planted pinentry ran")
	}
	if _, err := findPinentry(paths.FromMap(map[string]string{"PATH": evilDir})); !errors.Is(err, errNoPinentry) {
		t.Fatalf("findPinentry = %v", err)
	}
}

// D97: what counts as a trusted executable.
func TestTrustedExecutable(t *testing.T) {
	if _, ok := trustedExecutable("/bin/sh"); !ok {
		t.Skip("/bin/sh is not root-owned here")
	}
	dir := t.TempDir()
	p := filepath.Join(dir, "pinentry")
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, ok := trustedExecutable(p); ok {
		t.Fatal("a user-owned file in a user-owned directory is trusted")
	}
	link := filepath.Join(dir, "sh")
	if err := os.Symlink("/bin/sh", link); err != nil {
		t.Fatal(err)
	}
	if _, ok := trustedExecutable(link); ok {
		t.Fatal("a root binary behind a link the user can replace is trusted")
	}
	if pinentryEnv(paths.FromMap(map[string]string{"PATH": "/evil:/usr/bin", "HOME": "/u"}), "/usr/local/bin/pinentry")[0] != "PATH=/usr/local/bin" {
		t.Fatal("pinentry's PATH is not limited to its own directory")
	}
}
