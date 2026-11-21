package testkit

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/precinto/precinto/internal/paths"
)

func TestNormalizeTags(t *testing.T) {
	for _, c := range []struct {
		in   []string
		want string
	}{
		{nil, "testing"},
		{[]string{"testing"}, "testing"},
		{[]string{"failpoints"}, "testing,failpoints"},
		{[]string{"failpoints", "testing"}, "testing,failpoints"},
		{[]string{"testing,failpoints"}, "testing,failpoints"},
		{[]string{" testing , failpoints ", ""}, "testing,failpoints"},
	} {
		got, err := normalizeTags(c.in)
		if err != nil || strings.Join(got, ",") != c.want {
			t.Errorf("normalizeTags(%q) = %q, %v; want %q", c.in, got, err, c.want)
		}
	}
	for _, bad := range [][]string{{"race"}, {"testing", "netgo"}, {"testing failpoints"}} {
		if got, err := normalizeTags(bad); err == nil {
			t.Errorf("normalizeTags(%q) = %q, want an error", bad, got)
		}
	}
}

func TestBuildEnv(t *testing.T) {
	e := paths.FromMap(map[string]string{
		"PATH": "/usr/bin", "HOME": "/u", "GOFLAGS": "-mod=mod", "GOCACHE": "/c", "GOROOT": "/r",
		"GOTOOLCHAIN": "auto", "CGO_ENABLED": "0", "GOOS": "plan9", "GOARCH": "mips",
		"CLAUDECODE": "1", "PRECINTO_HOME": "/b", "CODEX_HOME": "/x", "ANTHROPIC_API_KEY": "k", "SSH_AUTH_SOCK": "/s",
	})
	got := buildEnv(e)
	for _, want := range []string{"PATH=/usr/bin", "HOME=/u", "GOFLAGS=-mod=mod", "GOCACHE=/c", "GOROOT=/r",
		"GOTOOLCHAIN=auto", "CGO_ENABLED=0", "GOOS=" + runtime.GOOS, "GOARCH=" + runtime.GOARCH} {
		if !slices.Contains(got, want) {
			t.Errorf("build env lacks %s: %q", want, got)
		}
	}
	for _, kv := range got {
		k, _, _ := strings.Cut(kv, "=")
		switch k {
		case "CLAUDECODE", "PRECINTO_HOME", "CODEX_HOME", "ANTHROPIC_API_KEY", "SSH_AUTH_SOCK":
			t.Errorf("build env passes %s", k)
		}
		if (k == "GOOS" && kv != "GOOS="+runtime.GOOS) || (k == "GOARCH" && kv != "GOARCH="+runtime.GOARCH) {
			t.Errorf("build env: %s", kv)
		}
	}
}

func TestModuleRoot(t *testing.T) {
	root, err := moduleRoot()
	if err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(filepath.Join(root, "go.mod")); err != nil || modulePath(b) != module {
		t.Errorf("module root %s: %v", root, err)
	}
	for in, want := range map[string]string{
		"module github.com/precinto/precinto\n\ngo 1.26.0\n": module,
		"// c\nmodule \"example.test/x\" // why\n":           "example.test/x",
		"modules x\n": "",
		"go 1.26\n":   "",
	} {
		if got := modulePath([]byte(in)); got != want {
			t.Errorf("modulePath(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestBuildBinaryOnce builds the helper program under testdata/: once per
// tag set, into this process's locked directory.
func TestBuildBinaryOnce(t *testing.T) {
	const probe = "./internal/testkit/testdata/buildprobe"
	run := func(bin string) string {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, bin)
		cmd.Env = []string{}
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("%s: %v", bin, err)
		}
		return strings.TrimSpace(string(out))
	}
	plain := buildBinary(t, probe, nil)
	buildsMu.Lock()
	n := buildCount
	buildsMu.Unlock()
	if again := buildBinary(t, probe, []string{"testing"}); again != plain {
		t.Errorf("second build of the same tag set: %s, want %s", again, plain)
	}
	buildsMu.Lock()
	if buildCount != n {
		t.Errorf("the same tag set was built again (%d builds, want %d)", buildCount, n)
	}
	buildsMu.Unlock()
	both := buildBinary(t, probe, []string{"testing", "failpoints"})
	if both == plain {
		t.Fatal("two tag sets share a binary")
	}
	if got := run(plain); got != "testing" {
		t.Errorf("default build has tags %q, want testing", got)
	}
	if got := run(both); got != "testing,failpoints" {
		t.Errorf("failpoints build has tags %q", got)
	}
	// One locked directory per process below the start-up TMPDIR.
	dir := filepath.Dir(filepath.Dir(plain))
	if !strings.HasPrefix(filepath.Base(dir), binDirPrefix) || filepath.Dir(filepath.Dir(both)) != dir {
		t.Errorf("binaries in %s and %s", plain, both)
	}
	if base, err := filepath.EvalSymlinks(tempBase()); err != nil || filepath.Dir(dir) != base {
		t.Errorf("binary directory %s is not in %s (%v)", dir, tempBase(), err)
	}
	f, err := os.OpenFile(filepath.Join(dir, binLockName), os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := tryLock(f); err != errLocked {
		t.Errorf("the directory lock is not held: %v", err)
	}
	// A build failure is reported, not retried, and is fatal.
	r := &fatalRecorder{TB: t}
	done := make(chan struct{})
	go func() {
		defer close(done)
		buildBinary(r, "./internal/testkit/testdata/missing", nil)
	}()
	<-done
	if !r.fatal || !strings.Contains(r.msg, "go build -tags testing ./internal/testkit/testdata/missing") {
		t.Errorf("failed build: fatal=%v %q", r.fatal, r.msg)
	}
	mustFatalInternal(t, "unsupported build tag", func(tb testing.TB) { buildBinary(tb, probe, []string{"race"}) })
}

// TestSweepBinDirs: only directories of exited test processes are removed.
func TestSweepBinDirs(t *testing.T) {
	base := t.TempDir()
	mk := func(name string, lock bool) string {
		d := filepath.Join(base, name)
		if err := os.MkdirAll(filepath.Join(d, "testing"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(d, "testing", "precinto"), []byte("bin"), 0o700); err != nil {
			t.Fatal(err)
		}
		if lock {
			if err := os.WriteFile(filepath.Join(d, binLockName), nil, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		return d
	}
	dead := mk(binDirPrefix+"dead", true)
	alive := mk(binDirPrefix+"alive", true)
	noLock := mk(binDirPrefix+"nolock", false)
	freshHalf := mk(binTempPrefix+"fresh", false)
	oldHalf := mk(binTempPrefix+"old", false)
	other := mk("unrelated-dir", true)
	old := time.Now().Add(-2 * staleTempAge)
	if err := os.Chtimes(oldHalf, old, old); err != nil {
		t.Fatal(err)
	}
	target := mk("target", true)
	if err := os.Symlink(target, filepath.Join(base, binDirPrefix+"link")); err != nil {
		t.Fatal(err)
	}
	holder, err := os.OpenFile(filepath.Join(alive, binLockName), os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Close()
	if err := tryLock(holder); err != nil {
		t.Fatal(err)
	}
	sweepBinDirs(base, time.Now())
	for d, wantGone := range map[string]bool{dead: true, oldHalf: true, alive: false, noLock: false, freshHalf: false, other: false, target: false} {
		_, err := os.Lstat(d)
		if gone := os.IsNotExist(err); gone != wantGone {
			t.Errorf("%s: removed=%v, want %v", filepath.Base(d), gone, wantGone)
		}
	}
	if _, err := os.Stat(filepath.Join(target, "testing", "precinto")); err != nil {
		t.Errorf("sweep followed a symlink: %v", err)
	}
	// A fresh directory made by makeBinDir is locked and survives sweeps.
	d, lock, err := makeBinDir(base)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	sweepBinDirs(base, time.Now())
	if _, err := os.Stat(d); err != nil {
		t.Errorf("a live directory was swept: %v", err)
	}
	if !strings.HasPrefix(filepath.Base(d), binDirPrefix) {
		t.Errorf("makeBinDir = %s", d)
	}
}

type fatalRecorder struct {
	testing.TB
	fatal bool
	msg   string
}

func (r *fatalRecorder) Helper() {}
func (r *fatalRecorder) Fatalf(format string, args ...any) {
	r.fatal = true
	r.msg = strings.TrimSpace(fmt.Sprintf(format, args...))
	runtime.Goexit()
}

func mustFatalInternal(t *testing.T, want string, f func(tb testing.TB)) {
	t.Helper()
	r := &fatalRecorder{TB: t}
	done := make(chan struct{})
	go func() {
		defer close(done)
		f(r)
	}()
	<-done
	if !r.fatal || !strings.Contains(r.msg, want) {
		t.Errorf("want a fatal failure containing %q, got %v %q", want, r.fatal, r.msg)
	}
}

// removeChildEnv runs TestRemoveBinaries as its child.
const removeChildEnv = "TESTKIT_REMOVE_BINARIES_CHILD"

// TestRemoveBinaries: RemoveBinaries deletes the process's binary
// directory and makes later builds fail instead of handing out a path into
// it. It ends BuildBinary for the whole process, so it runs in a child
// process (with a lifeline and a bounded wait, TESTPLAN §1.8).
func TestRemoveBinaries(t *testing.T) {
	if os.Getenv(removeChildEnv) == "1" {
		go func() { // the lifeline: the parent test went away
			_, _ = io.Copy(io.Discard, os.Stdin)
			os.Exit(70)
		}()
		bin := buildBinary(t, "./internal/testkit/testdata/buildprobe", nil)
		dir, err := processBinDir()
		if err != nil || !strings.HasPrefix(bin, dir+string(filepath.Separator)) {
			t.Fatalf("binary %s outside the process directory %s (%v)", bin, dir, err)
		}
		RemoveBinaries()
		if _, err := os.Lstat(dir); !os.IsNotExist(err) {
			t.Fatalf("%s still exists after RemoveBinaries: %v", dir, err)
		}
		if _, err := processBinDir(); !errors.Is(err, errRemoved) {
			t.Fatalf("processBinDir after RemoveBinaries = %v, want errRemoved", err)
		}
		buildsMu.Lock()
		n := len(builds)
		buildsMu.Unlock()
		if n != 0 {
			t.Fatalf("%d cached builds still name the removed directory", n)
		}
		return
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, self, "-test.run=^TestRemoveBinaries$", "-test.count=1", "-test.v")
	cmd.Env = append(startEnv.Environ(), removeChildEnv+"=1")
	life, lifeline, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer lifeline.Close()
	cmd.Stdin = life
	cmd.WaitDelay = 10 * time.Second
	out, err := cmd.CombinedOutput()
	life.Close()
	if err != nil || !strings.Contains(string(out), "--- PASS: TestRemoveBinaries") {
		t.Fatalf("child: %v\n%s", err, out)
	}
}
