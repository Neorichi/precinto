package testkit

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Neorichi/precinto/internal/paths"
)

// BuildBinary builds into <TMPDIR>/precinto-testbin-<random>/<tags>/, one
// directory per test process. The directory holds owner.lock, flock'ed for
// the life of the process (the descriptor is never closed), so that the
// next test process can tell an abandoned directory from one in use: before
// creating its own it removes every precinto-testbin-* directory of the
// same uid whose lock it can take. A directory is renamed to its final name
// only once its lock is held, so a sweeper never sees one half made.
const (
	module        = "github.com/Neorichi/precinto"
	binDirPrefix  = "precinto-testbin-"
	binTempPrefix = ".precinto-testbin-new-"
	binLockName   = "owner.lock"
	buildTimeout  = 10 * time.Minute
	staleTempAge  = time.Hour
)

// buildTags are the only tags BuildBinary accepts, in canonical order.
var buildTags = []string{"testing", "failpoints"}

type buildResult struct {
	once sync.Once
	path string
	err  error
}

var (
	buildsMu sync.Mutex
	builds   = map[string]*buildResult{}

	binDirOnce sync.Once
	binDir     string
	binDirErr  error
	binDirLock *os.File // held until the process exits

	buildCount int // builds run, for the self-tests (guarded by buildsMu)
)

// normalizeTags returns the canonical tag list for BuildBinary: "testing"
// always (a binary that ignored PRECINTO_HOME would use the real base),
// then "failpoints" when asked for. Arguments may hold several
// comma-separated tags; anything else is refused.
func normalizeTags(tags []string) ([]string, error) {
	want := map[string]bool{"testing": true}
	for _, arg := range tags {
		for _, tag := range strings.Split(arg, ",") {
			tag = strings.TrimSpace(tag)
			switch tag {
			case "":
			case "testing", "failpoints":
				want[tag] = true
			default:
				return nil, fmt.Errorf("unsupported build tag %q (only testing and failpoints)", tag)
			}
		}
	}
	var out []string
	for _, tag := range buildTags {
		if want[tag] {
			out = append(out, tag)
		}
	}
	return out, nil
}

// buildBinary implements BuildBinary for any main package of the module
// (pkg is a ./-relative package path); the self-tests build a helper under
// testdata/.
func buildBinary(t testing.TB, pkg string, tags []string) string {
	t.Helper()
	tagList, err := normalizeTags(tags)
	if err != nil {
		t.Fatalf("testkit.BuildBinary: %v", err)
	}
	key := pkg + " " + strings.Join(tagList, ",")
	buildsMu.Lock()
	r := builds[key]
	if r == nil {
		r = &buildResult{}
		builds[key] = r
	}
	buildsMu.Unlock()
	r.once.Do(func() { r.path, r.err = runBuild(pkg, tagList) })
	if r.err != nil {
		t.Fatalf("testkit.BuildBinary: %v", r.err)
	}
	return r.path
}

func runBuild(pkg string, tags []string) (string, error) {
	root, err := moduleRoot()
	if err != nil {
		return "", err
	}
	dir, err := processBinDir()
	if err != nil {
		return "", err
	}
	name := filepath.Base(filepath.FromSlash(pkg))
	sub := filepath.Join(dir, strings.Join(tags, "-"))
	if pkg != "./cmd/precinto" {
		sub = filepath.Join(dir, claudeSlug(strings.TrimPrefix(pkg, "./"))+"-"+strings.Join(tags, "-"))
	}
	if err := os.MkdirAll(sub, 0o700); err != nil {
		return "", err
	}
	out := filepath.Join(sub, name)
	gotool, err := goTool()
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(context.Background(), buildTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, gotool, "build", "-tags", strings.Join(tags, ","), "-buildvcs=false", "-o", out, pkg)
	cmd.Dir = root
	cmd.Env = buildEnv(startEnv)
	var output bytes.Buffer
	cmd.Stdout, cmd.Stderr = &output, &output
	buildsMu.Lock()
	buildCount++
	buildsMu.Unlock()
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("go build -tags %s %s: %v\n%s", strings.Join(tags, ","), pkg, err, output.Bytes())
	}
	return out, nil
}

// buildEnv is the explicit environment of `go build`: the Go and C
// toolchain configuration of the test process at start-up (GOFLAGS
// included), with GOOS/GOARCH pinned to the host so the binary runs here.
// Nothing else (agent markers, PRECINTO_*, harness variables) is passed.
func buildEnv(e paths.Env) []string {
	keep := map[string]bool{
		"PATH": true, "HOME": true, "USER": true, "LOGNAME": true, "TMPDIR": true,
		"XDG_CACHE_HOME": true, "XDG_CONFIG_HOME": true, "CC": true, "CXX": true, "AR": true,
		"PKG_CONFIG": true, "SDKROOT": true, "DEVELOPER_DIR": true, "SSL_CERT_FILE": true, "SSL_CERT_DIR": true,
		"HTTP_PROXY": true, "HTTPS_PROXY": true, "NO_PROXY": true, "http_proxy": true, "https_proxy": true, "no_proxy": true,
	}
	var env []string
	for _, kv := range e.Environ() {
		k, _, _ := strings.Cut(kv, "=")
		if k == "GOOS" || k == "GOARCH" {
			continue
		}
		if keep[k] || strings.HasPrefix(k, "GO") || strings.HasPrefix(k, "CGO_") {
			env = append(env, kv)
		}
	}
	return append(env, "GOOS="+runtime.GOOS, "GOARCH="+runtime.GOARCH)
}

// goTool returns the go command of the toolchain running the tests (go test
// sets GOROOT for the test binary), else the first go on PATH.
func goTool() (string, error) {
	if r := startEnv.Get("GOROOT"); filepath.IsAbs(r) {
		p := filepath.Join(r, "bin", "go")
		if fi, err := os.Stat(p); err == nil && fi.Mode().IsRegular() && fi.Mode().Perm()&0o111 != 0 {
			return p, nil
		}
	}
	p, err := paths.LookPath(startEnv, "go")
	if err != nil {
		return "", fmt.Errorf("no go command: %w", err)
	}
	return p, nil
}

// moduleRoot finds the directory of the precinto go.mod, from the working
// directory (go test runs in the package directory) or from this file.
func moduleRoot() (string, error) {
	if wd, err := os.Getwd(); err == nil {
		if r, ok := findModule(wd); ok {
			return r, nil
		}
	}
	if _, file, _, ok := runtime.Caller(0); ok && filepath.IsAbs(file) {
		if r, ok := findModule(filepath.Dir(file)); ok {
			return r, nil
		}
	}
	return "", errors.New("cannot find the " + module + " module root (run the test from inside the repository)")
}

func findModule(dir string) (string, bool) {
	for d := dir; ; d = filepath.Dir(d) {
		if b, err := os.ReadFile(filepath.Join(d, "go.mod")); err == nil && modulePath(b) == module {
			return d, true
		}
		if filepath.Dir(d) == d {
			return "", false
		}
	}
}

// modulePath returns the module path a go.mod declares.
func modulePath(gomod []byte) string {
	for _, line := range strings.Split(string(gomod), "\n") {
		line = strings.TrimSpace(line)
		if rest, ok := strings.CutPrefix(line, "module"); ok && (rest == "" || rest[0] == ' ' || rest[0] == '\t') {
			if i := strings.Index(rest, "//"); i >= 0 {
				rest = rest[:i]
			}
			return strings.Trim(strings.TrimSpace(rest), `"`)
		}
	}
	return ""
}

// tempBase is where test binaries go: the process's TMPDIR at start-up, or
// /tmp.
func tempBase() string {
	if d := startEnv.Get("TMPDIR"); filepath.IsAbs(d) {
		return filepath.Clean(d)
	}
	return "/tmp"
}

// processBinDir creates (once) this process's binary directory.
func processBinDir() (string, error) {
	binDirOnce.Do(func() { binDir, binDirLock, binDirErr = makeBinDir(tempBase()) })
	return binDir, binDirErr
}

// makeBinDir sweeps abandoned directories in base, then creates a locked one.
func makeBinDir(base string) (string, *os.File, error) {
	sweepBinDirs(base, time.Now())
	tmp, err := os.MkdirTemp(base, binTempPrefix)
	if err != nil {
		return "", nil, err
	}
	lock, err := os.OpenFile(filepath.Join(tmp, binLockName), os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err == nil {
		if err = tryLock(lock); err != nil {
			lock.Close()
		}
	}
	if err != nil {
		os.RemoveAll(tmp)
		return "", nil, fmt.Errorf("lock %s: %w", tmp, err)
	}
	final := filepath.Join(base, binDirPrefix+strings.TrimPrefix(filepath.Base(tmp), binTempPrefix))
	if err := os.Rename(tmp, final); err != nil {
		lock.Close()
		os.RemoveAll(tmp)
		return "", nil, err
	}
	real, err := filepath.EvalSymlinks(final)
	if err != nil {
		lock.Close()
		return "", nil, err
	}
	return real, lock, nil
}

// sweepBinDirs removes the binary directories of test processes that have
// exited: entries of base named precinto-testbin-*, real directories owned
// by this uid, whose owner.lock can be locked. Half-made directories
// (.precinto-testbin-new-*) are removed once older than staleTempAge. Errors
// are ignored: a directory that cannot be judged is left alone.
func sweepBinDirs(base string, now time.Time) {
	entries, err := os.ReadDir(base)
	if err != nil {
		return
	}
	for _, e := range entries {
		name := e.Name()
		final, half := strings.HasPrefix(name, binDirPrefix), strings.HasPrefix(name, binTempPrefix)
		if !final && !half {
			continue
		}
		d := filepath.Join(base, name)
		fi, err := os.Lstat(d)
		if err != nil || !fi.IsDir() || !ownedByMe(fi) {
			continue
		}
		if half {
			if now.Sub(fi.ModTime()) > staleTempAge {
				os.RemoveAll(d)
			}
			continue
		}
		lock, err := os.OpenFile(filepath.Join(d, binLockName), os.O_RDWR|oNoFollow, 0)
		if err != nil {
			continue
		}
		if lfi, err := lock.Stat(); err != nil || !lfi.Mode().IsRegular() {
			lock.Close()
			continue
		}
		if tryLock(lock) == nil {
			// Abandoned. Removing the directory while holding its lock
			// keeps a concurrent sweeper from judging it again.
			os.RemoveAll(d)
		}
		lock.Close()
	}
}

// errLocked is returned by tryLock when another descriptor holds the lock.
var errLocked = errors.New("locked")

// errRemoved is BuildBinary's error after RemoveBinaries.
var errRemoved = errors.New("the test binaries of this process were removed (RemoveBinaries)")

// removeBinaries implements RemoveBinaries: it removes this process's
// binary directory while still holding its lock (so no concurrent sweeper
// judges it), then releases the lock. Later builds in this process fail.
func removeBinaries() {
	binDirOnce.Do(func() { binDirErr = errRemoved }) // nothing built yet: never create one
	buildsMu.Lock()
	defer buildsMu.Unlock()
	builds = map[string]*buildResult{} // no cached path into the removed directory
	if binDir != "" {
		_ = os.RemoveAll(binDir)
		binDir = ""
	}
	if binDirLock != nil {
		_ = binDirLock.Close()
		binDirLock = nil
	}
	binDirErr = errRemoved
}
