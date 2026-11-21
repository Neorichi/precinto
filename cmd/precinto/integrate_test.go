package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/precinto/precinto/internal/harness"
)

// integrate claude-code: version check (≥ 2.1.295, D22), <base>/bin/precinto
// link (D6), home and binary registered, plugin installed through the
// harness's own plugin CLI — all in the fake HOME, the harness CLI faked.
func TestIntegrateClaude(t *testing.T) {
	e := newEnv(t)
	bin := fakePluginDir(t, e, "claude")
	exe := filepath.Join(e.h.Dir, "precinto-bin")
	if err := os.WriteFile(exe, []byte("x"), 0o700); err != nil {
		t.Fatal(err)
	}
	e.execOut["--version"] = []byte("2.1.329 (Claude Code)\n")
	a := e.app()
	a.sys.executable = func() (string, error) { return exe, nil }
	if code := a.run([]string{"integrate", "claude-code"}); code != exitOK {
		t.Fatalf("exit %d (%s)", code, e.stderr())
	}
	var argv []string
	for _, x := range e.execs {
		argv = append(argv, strings.Join(x.Argv[1:], " "))
		for _, kv := range x.Env {
			if strings.HasPrefix(kv, "PRECINTO_") {
				t.Fatalf("harness CLI got %s", kv)
			}
		}
	}
	want := "--version|plugin marketplace add precinto/precinto|plugin install precinto@precinto"
	if strings.Join(argv, "|") != want {
		t.Fatalf("commands %q, want %q", strings.Join(argv, "|"), want)
	}
	link, err := os.Readlink(e.h.Layout.BinLink)
	if err != nil || link != exe {
		t.Fatalf("bin link %q %v", link, err)
	}
	c := e.loadConfig()
	if c.Harness["claude-code"].Bin != filepath.Join(bin, "claude") {
		t.Fatalf("bin %q", c.Harness["claude-code"].Bin)
	}
}

func TestIntegrateRefusesOldClaude(t *testing.T) {
	e := newEnv(t)
	fakePluginDir(t, e, "claude")
	e.execOut["--version"] = []byte("2.1.200 (Claude Code)\n")
	if code := e.run("integrate", "claude-code"); code != exitError {
		t.Fatalf("exit %d", code)
	}
	if len(e.execs) != 1 {
		t.Fatal("installed into an old Claude")
	}
	if _, err := os.Lstat(e.h.Layout.BinLink); !os.IsNotExist(err) {
		t.Fatal("bin link written for a refused integration")
	}
	// An unreadable version refuses too (fail closed).
	e = newEnv(t)
	fakePluginDir(t, e, "claude")
	e.execOut["--version"] = []byte("dev build\n")
	if code := e.run("integrate", "claude-code"); code != exitError {
		t.Fatalf("unreadable version: exit %d", code)
	}
}

// --print changes nothing.
func TestIntegratePrint(t *testing.T) {
	e := newEnv(t)
	fakePluginDir(t, e, "codex")
	e.execOut["--version"] = []byte("codex-cli 0.154.0\n")
	if code := e.run("integrate", "codex", "--print"); code != exitOK {
		t.Fatalf("exit %d (%s)", code, e.stderr())
	}
	if !strings.Contains(e.stdout(), "plugin install precinto@precinto") || len(e.execs) != 1 {
		t.Fatalf("stdout %q execs %d", e.stdout(), len(e.execs))
	}
	if _, err := os.Lstat(e.h.Layout.BinLink); !os.IsNotExist(err) {
		t.Fatal("--print wrote the bin link")
	}
}

// Experimental harnesses and hosts need --experimental (D33).
func TestIntegrateExperimental(t *testing.T) {
	e := newEnv(t)
	e.eng.invs[harness.ID("gemini")] = harness.Inventory{ID: "gemini", Status: "experimental"}
	if code := e.run("integrate", "gemini"); code != exitUsage {
		t.Fatalf("exit %d", code)
	}
	if code := e.run("integrate", "gemini", "--experimental"); code != exitOK {
		t.Fatalf("exit %d (%s)", code, e.stderr())
	}
	if h := e.loadConfig().Harness["gemini"]; !h.Enabled || !h.Experimental {
		t.Fatalf("gemini %+v", h)
	}
	e = newEnv(t)
	if code := e.run("integrate", "cursor"); code != exitUsage {
		t.Fatalf("cursor: exit %d", code)
	}
	if code := e.run("integrate", "cursor", "--experimental"); code != exitOK || !strings.Contains(e.stdout(), "experimental") {
		t.Fatalf("cursor: exit %d %q", code, e.stdout())
	}
	if code := e.run("integrate", "nosuch", "--experimental"); code != exitUsage {
		t.Fatalf("unknown: exit %d", code)
	}
}

func TestVersionCompare(t *testing.T) {
	cases := []struct {
		a, b string
		less bool
	}{
		{"2.1.294", "2.1.295", true}, {"2.1.295", "2.1.295", false}, {"2.1.329", "2.1.295", false},
		{"0.154.0", "0.154.0", false}, {"0.153.9", "0.154.0", true}, {"x", "1.0.0", true}, {"10.0.0", "9.9.9", false},
	}
	for _, c := range cases {
		if got := versionLess(c.a, c.b); got != c.less {
			t.Errorf("versionLess(%s, %s) = %v", c.a, c.b, got)
		}
	}
}
