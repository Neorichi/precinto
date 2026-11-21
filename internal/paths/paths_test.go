package paths_test

import (
	"errors"
	"os/exec"
	"runtime"
	"strings"
	"testing"

	"github.com/precinto/precinto/internal/paths"
)

func TestEnvSnapshot(t *testing.T) {
	e := paths.FromEnviron([]string{"A=1", "B=x=y", "noequals", "A=2", "=bad"})
	if e.Get("A") != "2" || e.Get("B") != "x=y" {
		t.Fatalf("FromEnviron: A=%q B=%q", e.Get("A"), e.Get("B"))
	}
	if _, ok := e.Lookup("noequals"); ok {
		t.Fatal("entry without '=' kept")
	}
	e2 := e.With("C", "3").Without("A")
	if _, ok := e.Lookup("C"); ok {
		t.Fatal("With mutated the original")
	}
	if got := strings.Join(e2.Environ(), ","); got != "B=x=y,C=3" {
		t.Fatalf("Environ = %q", got)
	}
	m := map[string]string{"K": "v"}
	e3 := paths.FromMap(m)
	m["K"] = "changed"
	if e3.Get("K") != "v" {
		t.Fatal("FromMap aliases the caller's map")
	}
}

func TestWithin(t *testing.T) {
	for _, c := range []struct {
		root, p string
		want    bool
	}{
		{"/u/work/acme", "/u/work/acme", true},
		{"/u/work/acme", "/u/work/acme/docs/x.md", true},
		{"/u/work/acme", "/u/work/acme-other/x.md", false}, // never a string prefix
		{"/u/work/acme", "/u/work", false},
		{"/u/work/acme", "/u/work/acme/../beta", false},
		{"/u/work/acme", "work/acme", false},
		{"/", "/anything", true},
	} {
		if got := paths.Within(c.root, c.p); got != c.want {
			t.Errorf("Within(%q, %q) = %v, want %v", c.root, c.p, got, c.want)
		}
	}
	if got := paths.Within("/u/Work/Acme", "/u/work/acme/x"); got != (runtime.GOOS == "darwin") {
		t.Errorf("case folding = %v on %s", got, runtime.GOOS)
	}
}

func TestCleanAndTilde(t *testing.T) {
	if c, ok := paths.Clean("/a/b/"); ok || c != "/a/b" {
		t.Errorf("Clean(/a/b/) = %q, %v", c, ok)
	}
	if _, ok := paths.Clean("/a/b"); !ok {
		t.Error("Clean(/a/b) not clean")
	}
	if _, ok := paths.Clean("a/b"); ok {
		t.Error("relative path reported clean")
	}
	if got := paths.Tilde("/u", "/u/work/acme"); got != "~/work/acme" {
		t.Errorf("Tilde = %q", got)
	}
	if got := paths.Tilde("/u", "/u"); got != "~" {
		t.Errorf("Tilde(home) = %q", got)
	}
	if got := paths.Tilde("/u", "/usr/x"); got != "/usr/x" {
		t.Errorf("Tilde outside home = %q", got)
	}
}

func TestLayoutAt(t *testing.T) {
	l, err := paths.LayoutAt("/b", "/r")
	if err != nil {
		t.Fatal(err)
	}
	if l.Socket != "/r/agent.sock" || l.CapsuleLog != "/b/state/capsules.log" || l.PolicyPinned != "/b/state/policy.pinned" {
		t.Fatalf("layout: %+v", l)
	}
	if l.HookDedupeDir != "/b/state/hookdedupe" || l.NotesIndex != "/b/state/notes.json" {
		t.Fatalf("hook and notes state: %q %q", l.HookDedupeDir, l.NotesIndex)
	}
	if got := l.UnitCapsuleDir("claude-code", "k"); got != "/b/capsules/claude-code/k" {
		t.Errorf("UnitCapsuleDir = %q", got)
	}
	if got := l.CodexHome("root-acme"); got != "/b/homes/codex/root-acme" {
		t.Errorf("CodexHome = %q", got)
	}
	if got := l.LockFile("sweep"); got != "/b/state/locks/sweep.lock" {
		t.Errorf("LockFile = %q", got)
	}
	if _, err := paths.LayoutAt("/b", "/"+strings.Repeat("x", 100)); !errors.Is(err, paths.ErrSocketPath) {
		t.Errorf("long socket path: err = %v", err)
	}
	if _, err := paths.LayoutAt("relative", "/r"); err == nil {
		t.Error("relative base accepted")
	}
}

func TestDefaultBase(t *testing.T) {
	e := paths.FromMap(map[string]string{"HOME": "/u", "XDG_DATA_HOME": "/x"})
	got, err := paths.DefaultBase(e)
	if err != nil {
		t.Skip("unsupported OS:", err)
	}
	want := map[string]string{"darwin": "/u/Library/Application Support/precinto", "linux": "/x/precinto"}[runtime.GOOS]
	if got != want {
		t.Errorf("DefaultBase = %q, want %q", got, want)
	}
	if _, err := paths.DefaultBase(paths.FromMap(map[string]string{"HOME": "rel"})); err == nil {
		t.Error("relative HOME accepted")
	}
}

func TestLookPath(t *testing.T) {
	e := paths.FromMap(map[string]string{"PATH": "relative:/bin:/usr/bin"})
	got, err := paths.LookPath(e, "sh")
	if err != nil || (got != "/bin/sh" && got != "/usr/bin/sh") {
		t.Fatalf("LookPath(sh) = %q, %v", got, err)
	}
	if _, err := paths.LookPath(e, "precinto-no-such-tool"); err == nil {
		t.Error("missing tool found")
	}
	if _, err := paths.LookPath(e, "./sh"); err == nil {
		t.Error("relative path with a slash accepted")
	}
}

// UX-16: a command that is not in PATH (or an absolute path that is not
// an executable) is exec.ErrNotFound, which `precinto run` maps to the
// shell's 127, with an unchanged message.
func TestLookPathNotFoundIsErrNotFound(t *testing.T) {
	e := paths.FromMap(map[string]string{"PATH": "/bin:/usr/bin"})
	for _, name := range []string{"precinto-no-such-tool", "/nonexistent/precinto-no-such-tool"} {
		_, err := paths.LookPath(e, name)
		if !errors.Is(err, exec.ErrNotFound) {
			t.Errorf("LookPath(%s) = %v, want exec.ErrNotFound", name, err)
		}
		if err != nil && !strings.HasPrefix(err.Error(), "paths: "+name) {
			t.Errorf("LookPath(%s) message %q", name, err)
		}
	}
}

// HookLayout never honours PRECINTO_* in any build (hook mode, D6/D56).
func TestHookLayoutIgnoresOverrides(t *testing.T) {
	e := paths.FromMap(map[string]string{
		"HOME": "/u", paths.EnvHome: "/b", paths.EnvRuntimeDir: "/r", paths.EnvDev: "1",
		paths.EnvTestAncestryStop: "1:2", paths.EnvXDGDataHome: "/x", paths.EnvXDGRuntimeDir: "/run/user/7",
	})
	got, err := paths.HookLayout(e)
	if err != nil {
		t.Fatal(err)
	}
	want, err := paths.HookLayout(paths.FromMap(map[string]string{"HOME": "/u", paths.EnvXDGDataHome: "/x", paths.EnvXDGRuntimeDir: "/run/user/7"}))
	if err != nil {
		t.Fatal(err)
	}
	if got != want || got.Base == "/b" || got.RunDir == "/r" {
		t.Fatalf("HookLayout honoured an override: %+v", got)
	}
	base, _ := paths.DefaultBase(e)
	if got.Base != base {
		t.Fatalf("HookLayout base %q, want the default %q", got.Base, base)
	}
	long := paths.FromMap(map[string]string{"HOME": "/" + strings.Repeat("h", 120)})
	if _, err := paths.HookLayout(long); !errors.Is(err, paths.ErrSocketPath) {
		t.Fatalf("long socket path: %v, want ErrSocketPath", err)
	}
	if _, err := paths.HookLayout(paths.FromMap(nil)); err == nil {
		t.Fatal("HookLayout without HOME succeeded")
	}
}

func TestProductNames(t *testing.T) {
	if paths.ServiceLabel != "com.github.precinto.sweep" || paths.ClaudePluginID != "precinto@precinto" {
		t.Fatalf("names %q %q (owner-revisable, OD-05: change docs and doctor together)", paths.ServiceLabel, paths.ClaudePluginID)
	}
}
