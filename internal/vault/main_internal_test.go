package vault

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/precinto/precinto/internal/paths"
)

// The fake age plugin (testdata/fakeplugin) is built once per test binary
// into a private temporary directory, removed by TestMain.

var (
	pluginOnce sync.Once
	pluginBin  string
	pluginErr  error
	pluginDir  string
)

// TestMain also fails the package when a helper process outlives the tests
// (TESTPLAN §1 rule 8): every age plugin the vault code starts must have
// been reaped, so no child of this process may remain (reapLeakedHelpers).
func TestMain(m *testing.M) {
	code := m.Run()
	if leaked := reapLeakedHelpers(); leaked > 0 && code == 0 {
		code = 1
	}
	if pluginDir != "" {
		os.RemoveAll(pluginDir)
	}
	os.Exit(code)
}

// buildEnv is the explicit environment of `go build`: the toolchain
// configuration of the test process, nothing else.
func buildEnv(e paths.Env) []string {
	keep := map[string]bool{"PATH": true, "HOME": true, "USER": true, "TMPDIR": true, "XDG_CACHE_HOME": true, "SDKROOT": true, "DEVELOPER_DIR": true}
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
	return append(env, "GOOS="+runtime.GOOS, "GOARCH="+runtime.GOARCH, "CGO_ENABLED=0")
}

func goTool(e paths.Env) (string, error) {
	if r := e.Get("GOROOT"); filepath.IsAbs(r) {
		p := filepath.Join(r, "bin", "go")
		if fi, err := os.Stat(p); err == nil && fi.Mode().IsRegular() {
			return p, nil
		}
	}
	return paths.LookPath(e, "go")
}

// fakePluginBinary returns the built fake plugin (shared by all tests).
func fakePluginBinary(t testing.TB) string {
	t.Helper()
	pluginOnce.Do(func() {
		env := paths.FromOS()
		gotool, err := goTool(env)
		if err != nil {
			pluginErr = err
			return
		}
		pluginDir, err = os.MkdirTemp("", "precinto-fakeplugin-")
		if err != nil {
			pluginErr = err
			return
		}
		out := filepath.Join(pluginDir, "fakeplugin")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		cmd := exec.CommandContext(ctx, gotool, "build", "-buildvcs=false", "-o", out, "./testdata/fakeplugin")
		cmd.Env = buildEnv(env)
		var log bytes.Buffer
		cmd.Stdout, cmd.Stderr = &log, &log
		if err := cmd.Run(); err != nil {
			pluginErr = fmt.Errorf("go build fakeplugin: %v\n%s", err, log.Bytes())
			return
		}
		pluginBin = out
	})
	if pluginErr != nil {
		t.Fatal(pluginErr)
	}
	return pluginBin
}

// installPlugin copies the fake plugin to <fresh dir>/age-plugin-<name>
// and returns its resolved absolute path.
func installPlugin(t testing.TB, name string) string {
	t.Helper()
	src := fakePluginBinary(t)
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(dir, "age-plugin-"+name)
	in, err := os.Open(src)
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o755)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(out, in); err != nil {
		t.Fatal(err)
	}
	if err := out.Close(); err != nil {
		t.Fatal(err)
	}
	return dst
}

// keygen asks a fake plugin for its recipient.
func keygen(t testing.TB, path string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, "--keygen")
	cmd.Env = []string{"PATH=" + filepath.Dir(path)}
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	return strings.TrimSpace(string(out))
}

// Exported for the external test package (this file is test-only).
var (
	InstallPluginForTest = installPlugin
	KeygenForTest        = keygen
)

// SetFastScryptForTest switches the test-binary allowance of low scrypt
// work factors, so tests can check the production floor (D3).
func SetFastScryptForTest(on bool) (restore func()) {
	old := fastScrypt
	fastScrypt = on
	return func() { fastScrypt = old }
}
