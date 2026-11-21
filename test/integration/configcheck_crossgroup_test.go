//go:build crossgroup

package integration_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/precinto/precinto/internal/config"
	"github.com/precinto/precinto/internal/paths"
)

// UX-09, SEC-43: a config.toml that does not load never makes `status
// --check` pass, through the real binary, engine and vault store. A
// locked md=all folder keeps an unencrypted note (no agent runs, so
// nothing seals it): --check exits 3 with a good config.toml and still 3
// with a broken one, because the folder is scanned with the settings
// confirmed last; without the note it exits 1, never 0; and without the
// confirmed settings the folder still comes from its vault.
func TestFlowStatusCheckWithBrokenConfig(t *testing.T) {
	exe := needBinary(t)
	h := newHome(t)
	h.Cfg.Roots[0].MD = config.MDAll
	fastPolicy(t, h)
	initVaults(t, exe, h)
	stop := startDaemon(t, exe, childEnv(h, nil).Environ(), h.Layout.Socket)
	p := startPTY(t, exe, h, h.HomeDir, nil, "protect", h.Root)
	p.expect("passphrase")
	p.send(testPassphrase + "\r")
	if code := p.wait(); code != 0 {
		t.Fatalf("protect exit %d: %q", code, p.output())
	}
	stop() // every folder is locked without the agent, and nothing seals
	note := filepath.Join(h.Root, "notes.md")
	if err := os.WriteFile(note, []byte("# a note\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	check := func(stage string, want int) result {
		t.Helper()
		r := precinto(t, exe, h, h.HomeDir, nil, "", "status", "--check")
		if r.code != want {
			t.Fatalf("%s: status --check exit %d, want %d\nstdout:\n%s\nstderr: %s", stage, r.code, want, r.stdout, r.stderr)
		}
		return r
	}
	check("good config.toml, a note", 3)

	good, err := os.ReadFile(h.Layout.ConfigFile)
	if err != nil {
		t.Fatal(err)
	}
	minFree := regexp.MustCompile(`(?m)^(\s*)min_free = .*$`)
	if !minFree.Match(good) {
		t.Fatalf("no min_free line in config.toml:\n%s", good)
	}
	if err := os.WriteFile(h.Layout.ConfigFile, minFree.ReplaceAll(good, []byte(`${1}min_free = "2GB"`)), 0o600); err != nil {
		t.Fatal(err)
	}
	r := check("broken config.toml, a note", 3)
	for _, w := range []string{"found with the settings confirmed last (config.toml does not load)", "policy.min_free", "\n  unsealed  "} {
		if !strings.Contains(r.stdout, w) {
			t.Errorf("broken config.toml, a note: status lacks %q:\n%s", w, r.stdout)
		}
	}

	if err := os.Remove(note); err != nil {
		t.Fatal(err)
	}
	r = check("broken config.toml, no note", 1)
	if !strings.Contains(r.stderr, "status --check cannot tell whether every locked folder is sealed") || !strings.Contains(r.stdout, "unencrypted: none found with the settings confirmed last") {
		t.Errorf("broken config.toml, no note:\nstdout:\n%s\nstderr: %s", r.stdout, r.stderr)
	}

	// Without the confirmed settings the folder comes from its vault.
	if err := os.Remove(h.Layout.PolicyPinned); err != nil {
		t.Fatal(err)
	}
	r = check("broken config.toml, no pin", 1)
	if folder := paths.Tilde(h.HomeDir, h.Root); !strings.Contains(r.stdout, "\n  "+folder+"  locked") || strings.Contains(r.stdout, "none (protect one") {
		t.Errorf("no pin: status does not list %s:\n%s", folder, r.stdout)
	}
}
