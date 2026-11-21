//go:build crossgroup

package integration_test

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/precinto/precinto/internal/config"
	"github.com/precinto/precinto/internal/testkit"
)

var (
	prodOnce sync.Once
	prodPath string
	prodErr  string
)

// productionBinary builds cmd/precinto WITHOUT the testing tag (the
// release flavour, SEC-12). testkit.BuildBinary always adds -tags testing
// (D62), so this test builds its own.
func productionBinary(t *testing.T) string {
	t.Helper()
	if testing.Short() {
		t.Skip("builds a production binary (slow)")
	}
	prodOnce.Do(func() {
		dir, err := os.MkdirTemp("", "precinto-prod-")
		if err != nil {
			prodErr = err.Error()
			return
		}
		out := filepath.Join(dir, "precinto")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		cmd := exec.CommandContext(ctx, goTool(t), "build", "-trimpath", "-o", out, "./cmd/precinto")
		cmd.Dir = moduleRoot(t)
		cmd.Env = append(goEnv(), "CGO_ENABLED=0")
		if b, err := cmd.CombinedOutput(); err != nil {
			prodErr = err.Error() + "\n" + string(b)
			return
		}
		prodPath = out
	})
	if prodErr != "" {
		t.Fatalf("production build: %s", prodErr)
	}
	return prodPath
}

// SEC-12 (D6, D56): a production build ignores PRECINTO_HOME and
// PRECINTO_RUNTIME_DIR (with or without an agent marker); PRECINTO_DEV=1
// enables them only outside agent contexts; PRECINTO_BIN does not exist.
// Everything runs in a throwaway HOME (short: the default socket path must
// stay under 104 bytes), never against the real one.
func TestSEC12ProductionBuildIgnoresOverrides(t *testing.T) {
	exe := productionBinary(t)
	home := testkit.ShortTempDir(t)
	xdgData := filepath.Join(home, "xdg-data")
	var base string
	if runtime.GOOS == "darwin" {
		base = filepath.Join(home, "Library", "Application Support", "precinto")
	} else {
		base = filepath.Join(xdgData, "precinto")
	}
	real := filepath.Join(home, "work", "real")
	decoy := filepath.Join(home, "work", "decoy")
	other := filepath.Join(home, "decoy-base")
	for _, d := range []string{base, real, decoy, other} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	writeConfig(t, filepath.Join(base, "config.toml"), "root-real", real)
	writeConfig(t, filepath.Join(other, "config.toml"), "root-decoy", decoy)
	runDir := testkit.ShortTempDir(t)

	run := func(extra map[string]string) []string {
		t.Helper()
		env := []string{"HOME=" + home, "PATH=/usr/bin:/bin:/usr/sbin:/sbin", "XDG_DATA_HOME=" + xdgData,
			"PRECINTO_HOME=" + other, "PRECINTO_RUNTIME_DIR=" + runDir, "PRECINTO_BIN=/nonexistent/precinto"}
		for k, v := range extra {
			env = append(env, k+"="+v)
		}
		ctx, cancel := context.WithTimeout(context.Background(), binTimeout)
		defer cancel()
		cmd := exec.CommandContext(ctx, exe, "status", "--json")
		cmd.Env = env
		cmd.Dir = home
		cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("status %v: %v\n%s", extra, err, out)
		}
		var s struct {
			Folders []struct {
				ID string `json:"id"`
			} `json:"folders"`
		}
		if err := json.Unmarshal(out, &s); err != nil {
			t.Fatalf("status JSON: %v\n%s", err, out)
		}
		var ids []string
		for _, f := range s.Folders {
			ids = append(ids, f.ID)
		}
		return ids
	}
	check := func(name string, extra map[string]string, want string) {
		t.Helper()
		ids := run(extra)
		if len(ids) != 1 || ids[0] != want {
			t.Errorf("%s: folders %v, want [%s]", name, ids, want)
		}
	}
	check("overrides set", nil, "root-real")
	check("agent marker", map[string]string{"CLAUDECODE": "1"}, "root-real")
	check("dev in an agent context", map[string]string{"PRECINTO_DEV": "1", "CLAUDECODE": "1"}, "root-real")
	check("dev under codex", map[string]string{"PRECINTO_DEV": "1", "CODEX_THREAD_ID": "00000000-0000-7000-8000-000000000001"}, "root-real")
	// Nothing was created under the ignored overrides.
	for _, d := range []string{runDir, other} {
		es, _ := os.ReadDir(d)
		for _, e := range es {
			if e.Name() != "config.toml" {
				t.Errorf("the ignored override %s was used: %s", d, e.Name())
			}
		}
	}
	check("dev outside agents", map[string]string{"PRECINTO_DEV": "1"}, "root-decoy")
}

func writeConfig(t *testing.T, path, id, root string) {
	t.Helper()
	c := config.Default()
	c.Roots = []config.Root{{ID: id, Path: root, MD: config.MDLedger, Harnesses: []string{"claude-code"}, ProtectedAt: testkit.Epoch}}
	if err := config.Save(path, c); err != nil {
		t.Fatal(err)
	}
}
