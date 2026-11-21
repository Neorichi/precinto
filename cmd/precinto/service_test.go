package main

import (
	"context"
	"encoding/xml"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// service install writes the LaunchAgent into the (fake) HOME and loads it
// through the launchctl seam (never the real tool in tests).
func TestServiceInstallDarwin(t *testing.T) {
	e := newEnv(t)
	if code := e.run("service", "install"); code != exitOK {
		t.Fatalf("exit %d (%s)", code, e.stderr())
	}
	plist := filepath.Join(e.h.HomeDir, "Library", "LaunchAgents", serviceLabel+".plist")
	b, err := os.ReadFile(plist)
	if err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(plist); fi.Mode().Perm() != 0o600 {
		t.Fatalf("plist mode %v", fi.Mode().Perm())
	}
	s := string(b)
	for _, want := range []string{
		"<string>/opt/precinto/bin/precinto</string>\n\t\t<string>sweep</string>\n\t\t<string>--quiet</string>",
		"<key>StartInterval</key>\n\t<integer>600</integer>",
		"<key>ProcessType</key>\n\t<string>Background</string>",
		"<key>HOME</key>\n\t\t<string>" + e.h.HomeDir + "</string>",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("plist lacks %q:\n%s", want, s)
		}
	}
	if err := xmlWellFormed(b); err != nil {
		t.Fatalf("plist is not well-formed XML: %v", err)
	}
	want := [][]string{
		{"bootout", "gui/501/" + serviceLabel},
		{"bootstrap", "gui/501", plist},
	}
	if len(e.launchctl) != 2 || strings.Join(e.launchctl[0], " ") != strings.Join(want[0], " ") || strings.Join(e.launchctl[1], " ") != strings.Join(want[1], " ") {
		t.Fatalf("launchctl calls %v, want %v", e.launchctl, want)
	}

	if code := e.run("service", "status"); code != exitOK || !strings.Contains(e.stdout(), "installed") {
		t.Fatalf("status exit %d: %q", code, e.stdout())
	}
	if code := e.run("service", "uninstall"); code != exitOK {
		t.Fatalf("uninstall exit %d", code)
	}
	if _, err := os.Stat(plist); !os.IsNotExist(err) {
		t.Fatal("plist left behind")
	}
	if last := e.launchctl[len(e.launchctl)-1]; last[0] != "bootout" {
		t.Fatalf("uninstall did not boot out: %v", last)
	}
}

func xmlWellFormed(b []byte) error {
	d := xml.NewDecoder(strings.NewReader(string(b)))
	d.Strict = true
	for {
		if _, err := d.Token(); err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
	}
}

// D49: on linux the systemd user unit is deferred: exit 2 with a notice,
// nothing written, launchctl never called.
func TestServiceLinuxDeferred(t *testing.T) {
	for _, sub := range []string{"install", "uninstall", "status"} {
		e := newEnv(t)
		e.goos = "linux"
		if code := e.run("service", sub); code != exitUsage {
			t.Fatalf("%s: exit %d, want 2", sub, code)
		}
		if !strings.Contains(e.stderr(), "not available on linux") {
			t.Fatalf("%s: stderr %q", sub, e.stderr())
		}
		if len(e.launchctl) != 0 {
			t.Fatalf("%s: launchctl called", sub)
		}
	}
}

func TestRenderPlistEscapes(t *testing.T) {
	b := renderPlist("/tmp/a&b<c>/precinto", map[string]string{"HOME": "/h&x"})
	if !strings.Contains(string(b), "/tmp/a&amp;b&lt;c&gt;/precinto") || !strings.Contains(string(b), "/h&amp;x") {
		t.Fatalf("%s", b)
	}
	if err := xmlWellFormed(b); err != nil {
		t.Fatal(err)
	}
}

// A testing build never runs the real launchctl (defense in depth); a
// production build runs /bin/launchctl with an explicit minimal
// environment. Nothing is executed here: the runner is a fake.
func TestLaunchctlRunner(t *testing.T) {
	var got []execSpec
	run := func(_ context.Context, c execSpec) ([]byte, error) { got = append(got, c); return nil, nil }
	if err := launchctlVia(t.Context(), []string{"print", "gui/501"}, true, run); err != nil || len(got) != 0 {
		t.Fatalf("testing build ran launchctl: %v %v", got, err)
	}
	if err := launchctlVia(t.Context(), []string{"print", "gui/501"}, false, run); err != nil || len(got) != 1 {
		t.Fatalf("production build: %v %v", got, err)
	}
	if got[0].Argv[0] != "/bin/launchctl" || len(got[0].Env) != 1 || !strings.HasPrefix(got[0].Env[0], "PATH=") {
		t.Fatalf("spec %+v", got[0])
	}
}
