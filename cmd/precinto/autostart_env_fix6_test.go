package main

import (
	"slices"
	"strings"
	"testing"

	"github.com/Neorichi/precinto/internal/paths"
	"github.com/Neorichi/precinto/internal/platform"
)

// D139 (S6-5, SEC-45; CROSS from group a): a daemon the CLI autostarts
// gets the dialog endpoints its pinentry uses only from a terminal no
// agent runs; from an agent context they are left out.
func TestAutostartEnvDialogEndpoints(t *testing.T) {
	for _, agentCtx := range []bool{false, true} {
		e := newEnv(t)
		e.agentCtx = agentCtx
		a := e.app()
		a.env = paths.FromMap(map[string]string{"HOME": "/u", "PATH": "/usr/bin", "DISPLAY": ":0",
			"WAYLAND_DISPLAY": "wayland-0", "DBUS_SESSION_BUS_ADDRESS": "unix:path=/run/user/501/bus"})
		got := a.autostartEnv()
		for _, k := range dialogKeys {
			has := slices.ContainsFunc(got, func(kv string) bool { return strings.HasPrefix(kv, k+"=") })
			if has == agentCtx {
				t.Errorf("agent context %v: %s passed %v (%q)", agentCtx, k, has, got)
			}
		}
		if !slices.Contains(got, "HOME=/u") {
			t.Errorf("agent context %v: %q", agentCtx, got)
		}
	}
}

// D139 (S6-5, SEC-45; CROSS from group a): `precinto agent` (and `agent
// --restart`) run from an agent's shell starts a daemon whose environment
// holds no dialog endpoint, whatever the shell set; run from a terminal no
// agent runs, the daemon keeps them for its pinentry.
func TestAgentCommandDialogEndpoints(t *testing.T) {
	for _, tc := range []struct {
		name   string
		marker bool
		kept   bool
	}{
		{"from a terminal", false, true},
		{"from an agent's shell", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			e.dialErr = nil
			// The fake table knows this process (a.sys.self) with no
			// harness above it: only the marker decides.
			e.h.Procs.Add(platform.ProcInfo{ID: platform.ProcID{PID: 4242, StartUS: 7}, PPID: 1, Exe: "/opt/precinto/bin/precinto"})
			a := e.app()
			env := map[string]string{"HOME": e.h.HomeDir, "PATH": "/usr/bin", "DISPLAY": ":9", "WAYLAND_DISPLAY": "wayland-9",
				"DBUS_SESSION_BUS_ADDRESS": "unix:path=/run/user/501/bus", "XDG_RUNTIME_DIR": "/run/user/501"}
			if tc.marker {
				env["CLAUDECODE"] = "1"
			}
			a.env = paths.FromMap(env)
			if code := a.run([]string{"agent"}); code != exitOK || len(e.agentOpts) != 1 {
				t.Fatalf("agent: exit %d, %d runs (%s)", code, len(e.agentOpts), e.stderr())
			}
			got := e.agentOpts[0].Env
			for _, k := range dialogKeys {
				if _, ok := got.Lookup(k); ok != tc.kept {
					t.Errorf("%s kept %v, want %v", k, ok, tc.kept)
				}
			}
			if got.Get("HOME") != e.h.HomeDir {
				t.Errorf("env %q", got.Environ())
			}
		})
	}
}
