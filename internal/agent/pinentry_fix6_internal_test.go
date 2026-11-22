package agent

import (
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"testing"

	"github.com/precinto/precinto/internal/paths"
	"github.com/precinto/precinto/internal/platform"
	"github.com/precinto/precinto/internal/platform/fakeplatform"
)

// D139 (S6-5, SEC-45): the pinentry gets a dialog endpoint only in the form
// that names the user's own local session; an endpoint an autostarting
// client chose (an X proxy display, a socket or a bus of its own) is
// dropped, and the dialog then has nowhere to go: the unlock needs a
// terminal.
func TestPinentryDialogEndpoints(t *testing.T) {
	base, err := os.MkdirTemp("/tmp", "pe") // short: socket paths stay below 104 bytes
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	oldRun, oldX, oldTrusted := runUserDir, x11Dir, trusted
	t.Cleanup(func() { runUserDir, x11Dir, trusted = oldRun, oldX, oldTrusted })
	runUserDir, x11Dir = filepath.Join(base, "run"), filepath.Join(base, "x11")
	trusted = func(string) bool { return true } // the temporary tree stands for root-owned /run/user
	rt := filepath.Join(runUserDir, strconv.Itoa(os.Getuid()))
	for _, d := range []string{rt, x11Dir} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, sock := range []string{filepath.Join(rt, "wayland-0"), filepath.Join(x11Dir, "X0")} {
		l, err := net.Listen("unix", sock)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = l.Close() })
	}
	session := map[string]string{
		"HOME": "/home/u", "PATH": "/usr/bin:/bin", paths.EnvXDGRuntimeDir: rt,
		"DISPLAY": ":0", "WAYLAND_DISPLAY": "wayland-0", "DBUS_SESSION_BUS_ADDRESS": "unix:path=" + filepath.Join(rt, "bus"),
	}
	envOf := func(edit map[string]string) []string {
		m := map[string]string{}
		for k, v := range session {
			m[k] = v
		}
		for k, v := range edit {
			if v == "" {
				delete(m, k)
			} else {
				m[k] = v
			}
		}
		return pinentryEnv(paths.FromMap(m), "/usr/bin/pinentry-gnome3")
	}
	want := []string{"PATH=/usr/bin", "HOME=/home/u", paths.EnvXDGRuntimeDir + "=" + rt,
		"DBUS_SESSION_BUS_ADDRESS=unix:path=" + filepath.Join(rt, "bus"), "WAYLAND_DISPLAY=wayland-0", "DISPLAY=:0"}
	if got := envOf(nil); !slices.Equal(got, want) {
		t.Fatalf("the user's own session: %q, want %q", got, want)
	}
	for _, tc := range []struct {
		edit map[string]string
		gone []string
	}{
		// The probe's environment: an X proxy display, a socket and a bus of
		// the agent's own, its own runtime directory.
		{map[string]string{"DISPLAY": ":9", "WAYLAND_DISPLAY": "agent-0", "DBUS_SESSION_BUS_ADDRESS": "unix:path=/tmp/agent-bus",
			paths.EnvXDGRuntimeDir: "/tmp/agent-runtime"},
			[]string{"DISPLAY", "WAYLAND_DISPLAY", "DBUS_SESSION_BUS_ADDRESS", paths.EnvXDGRuntimeDir}},
		{map[string]string{"DISPLAY": "evil.example:0"}, []string{"DISPLAY"}},
		{map[string]string{"DISPLAY": ":0.x"}, []string{"DISPLAY"}},
		{map[string]string{"WAYLAND_DISPLAY": filepath.Join(rt, "wayland-0")}, []string{"WAYLAND_DISPLAY"}},
		{map[string]string{"WAYLAND_DISPLAY": "wayland-1"}, []string{"WAYLAND_DISPLAY"}}, // no such socket
		{map[string]string{"DBUS_SESSION_BUS_ADDRESS": "unix:path=" + filepath.Join(base, "bus")}, []string{"DBUS_SESSION_BUS_ADDRESS"}},
		{map[string]string{paths.EnvXDGRuntimeDir: ""}, []string{paths.EnvXDGRuntimeDir, "DBUS_SESSION_BUS_ADDRESS", "WAYLAND_DISPLAY"}},
	} {
		got := envOf(tc.edit)
		for _, k := range tc.gone {
			for _, kv := range got {
				if len(kv) > len(k) && kv[:len(k)+1] == k+"=" {
					t.Errorf("%v: pinentry gets %s", tc.edit, kv)
				}
			}
		}
	}
	// A runtime directory others can enter is not the user's own.
	if err := os.Chmod(rt, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, kv := range envOf(nil) {
		if kv == paths.EnvXDGRuntimeDir+"="+rt || kv == "WAYLAND_DISPLAY=wayland-0" {
			t.Errorf("runtime directory 0755: pinentry gets %s", kv)
		}
	}
}

// A pinentry other than pinentry-mac without a trusted display cannot show
// its dialog: the daemon does not count it as a factor that prompts
// without a terminal (D27, D139).
func TestPinentryCanDraw(t *testing.T) {
	if !pinentryCanDraw("/usr/local/bin/pinentry-mac", nil) {
		t.Error("pinentry-mac needs no display")
	}
	if pinentryCanDraw("/usr/bin/pinentry-gnome3", []string{"XDG_RUNTIME_DIR=/run/user/1000"}) {
		t.Error("pinentry-gnome3 without a display counted as able to draw")
	}
	for _, kv := range []string{"DISPLAY=:0", "WAYLAND_DISPLAY=wayland-0"} {
		if !pinentryCanDraw("/usr/bin/pinentry-qt", []string{kv}) {
			t.Errorf("%s: pinentry-qt cannot draw", kv)
		}
	}
}

// D139 (S6-5, SEC-45): `precinto agent` run from an agent's shell (an
// agent marker in its environment, or an AI agent among its ancestors)
// starts a daemon whose environment holds no dialog endpoint, so its
// pinentry has no display of the agent's choosing; one started from a
// terminal no agent runs keeps them. Ancestry that cannot be read counts
// as an agent context; in a -tags testing build the walk ends at the D64
// stop, as everywhere else.
func TestStartEnvLeavesOutDialogEndpointsInAnAgentContext(t *testing.T) {
	display := map[string]string{"HOME": "/home/u", "PATH": "/usr/bin", "DISPLAY": ":9", "WAYLAND_DISPLAY": "wayland-9",
		"DBUS_SESSION_BUS_ADDRESS": "unix:path=/run/user/1000/bus", paths.EnvXDGRuntimeDir: "/run/user/1000"}
	with := func(extra map[string]string) paths.Env {
		m := map[string]string{}
		for k, v := range display {
			m[k] = v
		}
		for k, v := range extra {
			m[k] = v
		}
		return paths.FromMap(m)
	}
	const self = 4242
	_, stopHonoured := paths.TestAncestryStop(paths.FromMap(map[string]string{paths.EnvTestAncestryStop: "300:3"}))
	table := func(parentExe string) *fakeplatform.Procs {
		p := fakeplatform.NewProcs()
		p.Add(platform.ProcInfo{ID: platform.ProcID{PID: 100, StartUS: 1}, PPID: 1, Exe: "/usr/bin/login"})
		p.Add(platform.ProcInfo{ID: platform.ProcID{PID: 200, StartUS: 2}, PPID: 100, Exe: parentExe, Argv: []string{parentExe}})
		p.Add(platform.ProcInfo{ID: platform.ProcID{PID: 300, StartUS: 3}, PPID: 200, Exe: "/bin/zsh", Argv: []string{"-zsh"}})
		p.Add(platform.ProcInfo{ID: platform.ProcID{PID: self, StartUS: 4}, PPID: 300, Exe: "/usr/local/bin/precinto",
			Argv: []string{"precinto", "agent"}})
		return p
	}
	for _, tc := range []struct {
		name  string
		env   paths.Env
		procs platform.ProcTable
		kept  bool
	}{
		{"a terminal no agent runs", with(nil), table("/Applications/Terminal.app/Contents/MacOS/Terminal"), true},
		{"an agent marker", with(map[string]string{"CLAUDECODE": "1"}), table("/Applications/Terminal.app/Contents/MacOS/Terminal"), false},
		{"Claude among the ancestors", with(nil), table("/Users/u/.local/share/claude/versions/2.1.330"), false},
		{"Codex among the ancestors", with(nil), table("/opt/homebrew/bin/codex"), false},
		{"ancestry unreadable", with(nil), fakeplatform.NewProcs(), false},
		{"no process table", with(nil), nil, false},
		// Only a -tags testing build honours the stop (D64).
		{"Claude above the D64 stop", with(map[string]string{paths.EnvTestAncestryStop: "300:3"}),
			table("/Users/u/.local/share/claude/versions/2.1.330"), stopHonoured},
	} {
		got := StartEnv(tc.env, tc.procs, self)
		for _, k := range dialogKeys {
			if _, ok := got.Lookup(k); ok != tc.kept {
				t.Errorf("%s: %s kept %v, want %v", tc.name, k, ok, tc.kept)
			}
		}
		if got.Get("HOME") != "/home/u" || got.Get(paths.EnvXDGRuntimeDir) != "/run/user/1000" {
			t.Errorf("%s: other variables changed: %q", tc.name, got.Environ())
		}
	}
}
