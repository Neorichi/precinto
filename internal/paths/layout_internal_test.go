package paths

import "testing"

// TestNewLayoutPerOS covers both OS layouts and both build flavours on any
// host, through the unexported helpers NewLayout and OverridesAllowed use.
func TestNewLayoutPerOS(t *testing.T) {
	for _, c := range []struct {
		name      string
		goos      string
		env       map[string]string
		overrides bool
		base, run string
	}{
		{"darwin", "darwin", map[string]string{"HOME": "/u", EnvXDGRuntimeDir: "/run/user/7"}, false,
			"/u/Library/Application Support/precinto", "/u/Library/Application Support/precinto/run"},
		{"linux defaults", "linux", map[string]string{"HOME": "/u"}, false,
			"/u/.local/share/precinto", "/u/.local/share/precinto/run"},
		{"linux xdg", "linux", map[string]string{"HOME": "/u", EnvXDGDataHome: "/x", EnvXDGRuntimeDir: "/run/user/7"}, false,
			"/x/precinto", "/run/user/7/precinto"},
		{"linux xdg cleaned", "linux", map[string]string{"HOME": "/u", EnvXDGRuntimeDir: "/run/user/7/"}, false,
			"/u/.local/share/precinto", "/run/user/7/precinto"},
		{"linux relative xdg ignored", "linux", map[string]string{"HOME": "/u", EnvXDGDataHome: "x", EnvXDGRuntimeDir: "run"}, false,
			"/u/.local/share/precinto", "/u/.local/share/precinto/run"},
		{"linux xdg runtime root ignored", "linux", map[string]string{"HOME": "/u", EnvXDGRuntimeDir: "/"}, false,
			"/u/.local/share/precinto", "/u/.local/share/precinto/run"},
		{"overrides ignored", "linux", map[string]string{"HOME": "/u", EnvHome: "/b", EnvRuntimeDir: "/r"}, false,
			"/u/.local/share/precinto", "/u/.local/share/precinto/run"},
		{"overrides honoured", "linux", map[string]string{"HOME": "/u", EnvHome: "/b", EnvRuntimeDir: "/r"}, true,
			"/b", "/r"},
		{"linux base override keeps the socket away from XDG_RUNTIME_DIR", "linux",
			map[string]string{"HOME": "/u", EnvHome: "/b", EnvXDGRuntimeDir: "/run/user/7"}, true, "/b", "/b/run"},
		{"darwin run override", "darwin", map[string]string{"HOME": "/u", EnvRuntimeDir: "/r"}, true,
			"/u/Library/Application Support/precinto", "/r"},
	} {
		t.Run(c.name, func(t *testing.T) {
			l, err := newLayout(FromMap(c.env), c.goos, c.overrides)
			if err != nil {
				t.Fatal(err)
			}
			if l.Base != c.base || l.RunDir != c.run {
				t.Errorf("base %q run %q, want %q %q", l.Base, l.RunDir, c.base, c.run)
			}
			want, err := LayoutAt(c.base, c.run)
			if err != nil || l != want {
				t.Errorf("layout differs from LayoutAt: %+v (%v)", l, err)
			}
		})
	}
	if _, err := newLayout(FromMap(map[string]string{"HOME": "/u"}), "plan9", false); err == nil {
		t.Error("unsupported OS accepted")
	}
	// With the base overridden the OS default (and HOME) is never consulted.
	if l, err := newLayout(FromMap(map[string]string{EnvHome: "/b"}), "plan9", true); err != nil || l.Base != "/b" {
		t.Errorf("base override on an unsupported OS: %+v %v", l, err)
	}
}

func TestOverridesAllowedPerBuild(t *testing.T) {
	for _, c := range []struct {
		env  map[string]string
		prod bool
	}{
		{map[string]string{}, false},
		{map[string]string{EnvDev: "1"}, true},
		{map[string]string{EnvDev: "0"}, false},
		{map[string]string{EnvDev: "1", EnvClaudeCode: "1"}, false},
		{map[string]string{EnvDev: "1", "CODEX_SESSION_ID": "s"}, false},
		{map[string]string{EnvDev: "1", "KIMI_SESSION": "k"}, false},
	} {
		e := FromMap(c.env)
		if !overridesAllowed(e, true) {
			t.Errorf("testing build refuses overrides for %v", c.env)
		}
		if got := overridesAllowed(e, false); got != c.prod {
			t.Errorf("production build: overridesAllowed(%v) = %v, want %v", c.env, got, c.prod)
		}
	}
}

func TestIsAgentMarker(t *testing.T) {
	for name, want := range map[string]bool{
		"CLAUDECODE": true, "CODEX_THREAD_ID": true, "PLUGIN_ROOT": true, "KIMI_X": true,
		"KIMI_": false, "KIMI": false, "CODEX_HOME": false, "CLAUDE_CONFIG_DIR": false, "claudecode": false,
	} {
		if got := isAgentMarker(name); got != want {
			t.Errorf("isAgentMarker(%q) = %v, want %v", name, got, want)
		}
	}
	seen := map[string]bool{}
	for _, n := range agentMarkerNames {
		if seen[n] {
			t.Errorf("duplicate marker %s", n)
		}
		seen[n] = true
	}
}
