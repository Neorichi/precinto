//go:build crossgroup

package integration_test

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/precinto/precinto/internal/config"
	"github.com/precinto/precinto/internal/testkit"
)

// protectedWithNote is a fake home with the fixture folder protected (md =
// all, a genuine pin holding it), its agent stopped, and an unencrypted
// note in the folder, which is locked.
func protectedWithNote(t *testing.T) (exe string, h *testkit.Home, note string) {
	t.Helper()
	exe = needBinary(t)
	h = newHome(t)
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
	stop()
	pin, ok, err := config.LoadPinned(h.Layout.PolicyPinned)
	if err != nil || !ok {
		t.Fatalf("no pin after protect: %v", err)
	}
	if _, in := pin.Config.RootByID(h.Cfg.Roots[0].ID); !in {
		t.Fatal("the pin does not hold the folder")
	}
	note = filepath.Join(h.Root, "notes.md")
	if err := os.WriteFile(note, []byte("# a note "+testkit.Marker(t)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return exe, h, note
}

func plaintext(note string) bool {
	b, err := os.ReadFile(note)
	return err == nil && strings.Contains(string(b), "# a note")
}

// D142, D143 (SEC-49, S6-2, S6-3): a folder removed from config.toml stays
// protected until the removal is confirmed (D48): the agent enforces the
// confirmed settings, and so does every process that seals. status
// --check never passes while that locked folder holds plaintext; the lock
// worker `sweep --lock --root DIR` seals its note; and a background home
// registration (a sweep meeting a Claude home config.toml does not list)
// keeps the folder in roots.list for the POSIX shim.
func TestSealersSealFoldersWhoseRemovalWaits(t *testing.T) {
	exe, h, note := protectedWithNote(t)
	cfg, err := config.Load(h.Layout.ConfigFile)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Roots = nil // the folder removed from config.toml: pending
	if err := config.Save(h.Layout.ConfigFile, cfg); err != nil {
		t.Fatal(err)
	}
	startDaemon(t, exe, childEnv(h, nil).Environ(), h.Layout.Socket)
	if list, _ := config.ReadRootsList(h.Layout.RootsList); !slices.Contains(list, h.Root) {
		t.Fatalf("the agent dropped the folder from roots.list: %q", list)
	}
	st := precinto(t, exe, h, h.HomeDir, nil, "", "status")
	if !strings.Contains(st.stdout, "~/work/acme") {
		t.Errorf("status does not list the folder whose removal waits:\n%s", st.stdout)
	}
	if r := precinto(t, exe, h, h.HomeDir, nil, "", "status", "--check"); r.code != 3 {
		t.Errorf("status --check: exit %d, want 3 (a locked folder holds plaintext)\n%s%s", r.code, r.stdout, r.stderr)
	}
	// D143: a background registration keeps the folder in roots.list.
	other := filepath.Join(h.Dir, "claude-other")
	if err := os.Mkdir(other, 0o700); err != nil {
		t.Fatal(err)
	}
	r := precinto(t, exe, h, filepath.Dir(h.Root), map[string]string{"CLAUDE_CONFIG_DIR": other}, "", "seal", "--harness", "claude-code", "--session", "00000000-0000-4000-8000-0000000000ff")
	c, err := config.Load(h.Layout.ConfigFile)
	if err != nil {
		t.Fatal(err)
	}
	registered := false
	for _, home := range c.Harness["claude-code"].Homes {
		registered = registered || strings.HasSuffix(home.Dir, "claude-other")
	}
	if !registered {
		t.Fatalf("the seal registered no home (exit %d %s): the registration was not exercised", r.code, r.stderr)
	}
	if list, _ := config.ReadRootsList(h.Layout.RootsList); !slices.Contains(list, h.Root) {
		t.Errorf("a home registration dropped the enforced folder from roots.list: %q", list)
	}
	// The agent's lock worker for the folder (--wait: the agent's own
	// start-up sweep may hold the sweep lock).
	r = precinto(t, exe, h, h.HomeDir, nil, "", "sweep", "--lock", "--wait", "--root", h.Root, "--quiet")
	if r.code != 0 {
		t.Fatalf("sweep --lock --root: exit %d %s", r.code, r.stderr)
	}
	if plaintext(note) {
		t.Fatal("the lock sweep left the note of the locked folder in plaintext")
	}
}

// D142 (SEC-49, S6-2, U6-2): a config.toml that does not load never stops
// a seal: the lock worker seals the locked folder with the settings that
// stand in for the file (the confirmed ones, D121) and reports the error
// after.
func TestBrokenConfigNeverStopsTheLockSeal(t *testing.T) {
	exe, h, note := protectedWithNote(t)
	good, err := os.ReadFile(h.Layout.ConfigFile)
	if err != nil {
		t.Fatal(err)
	}
	broken := strings.Replace(string(good), "[policy]", "[policy]\nidle_sfot = \"15m\"", 1)
	if broken == string(good) {
		t.Fatalf("no [policy] table in config.toml:\n%s", good)
	}
	if err := os.WriteFile(h.Layout.ConfigFile, []byte(broken), 0o600); err != nil {
		t.Fatal(err)
	}
	r := precinto(t, exe, h, h.HomeDir, nil, "", "sweep", "--lock", "--wait", "--root", h.Root, "--quiet")
	if r.code != 0 {
		t.Fatalf("sweep --lock --root with a broken config.toml: exit %d %s", r.code, r.stderr)
	}
	if plaintext(note) {
		t.Fatal("a config.toml that does not load stopped the lock seal: the note stays plaintext")
	}
	if !strings.Contains(r.stderr, "idle_sfot") {
		t.Errorf("the config error is not reported: %q", r.stderr)
	}
}
