package config_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/precinto/precinto/internal/config"
)

func write(t *testing.T, s string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(p, []byte(s), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadDefaultsAndMerge(t *testing.T) {
	c, err := config.Load(filepath.Join(t.TempDir(), "missing.toml"))
	if err != nil || c.Policy.IdleSoft.D() != 15*time.Minute {
		t.Fatalf("missing file: %v %v", c.Policy.IdleSoft, err)
	}
	p := write(t, `
version = 1
[policy]
idle_soft = "30m"
[[roots]]
id = "root-acme"
path = "/u/work/acme"
[harness.claude-code]
homes = [{ dir = "/u/.claude" }]
`)
	c, err = config.Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if c.Policy.IdleSoft.D() != 30*time.Minute || c.Policy.MaxUnlock.D() != 8*time.Hour {
		t.Errorf("policy merge: %v %v", c.Policy.IdleSoft.D(), c.Policy.MaxUnlock.D())
	}
	if h := c.Harness["claude-code"]; !h.Enabled || h.MinVersion != "2.1.295" || len(h.Homes) != 1 {
		t.Errorf("harness defaults lost: %+v", h)
	}
	if !c.Harness["codex"].Enabled {
		t.Error("codex default lost")
	}
}

func TestLoadRejects(t *testing.T) {
	for name, body := range map[string]string{
		"typo":          "version = 1\n[policy]\nidle_sotf = \"1m\"\n",
		"relative root": "version = 1\n[[roots]]\nid = \"a\"\npath = \"work\"\n",
		"dup id":        "version = 1\n[[roots]]\nid = \"a\"\npath = \"/x\"\n[[roots]]\nid = \"a\"\npath = \"/y\"\n",
		"enum":          "version = 1\n[policy]\non_enter = \"always\"\n",
		"cap":           "version = 1\n[policy]\nmax_unlock = \"48h\"\n",
		"zero idle":     "version = 1\n[policy]\nidle_soft = \"0\"\n",
		"negative":      "version = 1\n[policy]\nbusy_grace = \"-1m\"\n",
		"version":       "version = 2\n",
	} {
		if _, err := config.Load(write(t, body)); !errors.Is(err, config.ErrInvalid) {
			t.Errorf("%s: err = %v, want ErrInvalid", name, err)
		}
	}
}

func TestRootsAndDurations(t *testing.T) {
	c := config.Default()
	c.Roots = []config.Root{{ID: "outer", Path: "/u/work"}, {ID: "inner", Path: "/u/work/acme"}}
	if r, ok := c.RootFor("/u/work/acme/x.md"); !ok || r.ID != "inner" {
		t.Errorf("RootFor deepest = %v %v", r.ID, ok)
	}
	if rs := c.RootsFor("/u/work/acme/x", "/u/work/other"); len(rs) != 2 || rs[0].ID != "inner" {
		t.Errorf("RootsFor = %+v", rs)
	}
	if rs := c.Overlapping("/u"); len(rs) != 2 {
		t.Errorf("Overlapping = %+v", rs)
	}
	if got := c.EffectiveOnEnter(c.Roots[0]); got != config.OnEnterPrompt {
		t.Errorf("EffectiveOnEnter = %q", got)
	}
	for d, want := range map[time.Duration]string{0: "0", 90 * time.Second: "90s", 15 * time.Minute: "15m", 8 * time.Hour: "8h", 1500 * time.Millisecond: "1.5s"} {
		b, _ := config.Duration(d).MarshalText()
		var back config.Duration
		if string(b) != want || back.UnmarshalText(b) != nil || back.D() != d {
			t.Errorf("Duration %v → %q → %v", d, b, back.D())
		}
	}
}

func TestSaveRootsListPinned(t *testing.T) {
	dir := t.TempDir()
	c := config.Default()
	c.Roots = []config.Root{{ID: "b", Path: "/u/b"}, {ID: "a", Path: "/u/a"}}
	if err := config.Save(filepath.Join(dir, "config.toml"), c); err != nil {
		t.Fatal(err)
	}
	back, err := config.Load(filepath.Join(dir, "config.toml"))
	if err != nil || len(back.Roots) != 2 {
		t.Fatalf("round trip: %v %+v", err, back.Roots)
	}
	if err := config.WriteRootsList(filepath.Join(dir, "roots.list"), c); err != nil {
		t.Fatal(err)
	}
	rl, err := config.ReadRootsList(filepath.Join(dir, "roots.list"))
	if err != nil || strings.Join(rl, ",") != "/u/b,/u/a" {
		t.Fatalf("roots.list = %q %v", rl, err)
	}
	swapped := c
	swapped.Roots = []config.Root{c.Roots[1], c.Roots[0]}
	if string(config.Canonical(c)) != string(config.Canonical(swapped)) {
		t.Error("Canonical depends on root order")
	}
	pin := config.Pinned{ConfirmedAt: time.Unix(0, 0).UTC(), Config: c, MACs: map[string]string{"a": "00"}}
	pp := filepath.Join(dir, "policy.pinned")
	if err := config.SavePinned(pp, pin); err != nil {
		t.Fatal(err)
	}
	got, ok, err := config.LoadPinned(pp)
	if err != nil || !ok || got.MACs["a"] != "00" || len(got.Config.Roots) != 2 {
		t.Fatalf("pinned round trip: %v %v %+v", ok, err, got)
	}
	if fi, _ := os.Stat(pp); fi.Mode().Perm() != 0o600 {
		t.Errorf("pinned mode %v", fi.Mode().Perm())
	}
}

// D63: quiet_window "0" keeps the 120 s default; any other value below
// 10 s is refused (every sealing process waits once for the window, so it
// must be long enough to see a writer pause).
func TestQuietWindowFloor(t *testing.T) {
	for v, ok := range map[string]bool{"0": true, "10s": true, "2m": true, "9s": false, "1s": false, "500ms": false, "-1m": false} {
		_, err := config.Load(write(t, "version = 1\n[policy]\nquiet_window = \""+v+"\"\n"))
		if ok && err != nil {
			t.Errorf("quiet_window = %q refused: %v", v, err)
		}
		if !ok && !errors.Is(err, config.ErrInvalid) {
			t.Errorf("quiet_window = %q: err = %v, want ErrInvalid", v, err)
		}
	}
	c := config.Default()
	c.Policy.QuietWindow = config.Duration(5 * time.Second)
	if err := config.Save(filepath.Join(t.TempDir(), "config.toml"), c); !errors.Is(err, config.ErrInvalid) {
		t.Errorf("Save with quiet_window 5s: %v, want ErrInvalid", err)
	}
	if config.Default().Policy.QuietWindow.D() != 120*time.Second {
		t.Errorf("default quiet_window %v", config.Default().Policy.QuietWindow.D())
	}
}

// D63: "0" means the 120 s default in the protection order too, so a merge
// never prefers a longer window over it and 2m → 0 is no weakening.
func TestQuietWindowZeroMeansDefault(t *testing.T) {
	zero, long := config.Default(), config.Default()
	zero.Policy.QuietWindow = 0
	long.Policy.QuietWindow = config.Duration(5 * time.Minute)
	if got := config.Strictest(zero, long).Policy.QuietWindow; got != 0 {
		t.Errorf("Strictest(0, 5m) = %v, want 0 (= 120 s)", got.D())
	}
	if got := config.Strictest(long, zero).Policy.QuietWindow; got != 0 {
		t.Errorf("Strictest(5m, 0) = %v, want 0 (= 120 s)", got.D())
	}
	short := config.Default()
	short.Policy.QuietWindow = config.Duration(30 * time.Second)
	if got := config.Strictest(zero, short).Policy.QuietWindow.D(); got != 30*time.Second {
		t.Errorf("Strictest(0, 30s) = %v, want 30s", got)
	}
	for _, c := range []struct {
		from, to  config.Duration
		weakening bool
	}{
		{config.Duration(2 * time.Minute), 0, false},
		{0, config.Duration(2 * time.Minute), false},
		{0, config.Duration(5 * time.Minute), true},
		{0, config.Duration(30 * time.Second), false},
	} {
		a, b := config.Default(), config.Default()
		a.Policy.QuietWindow, b.Policy.QuietWindow = c.from, c.to
		cs := config.Diff(a, b)
		if len(cs) != 1 || cs[0].Key != "policy.quiet_window" || cs[0].Weakening != c.weakening {
			t.Errorf("Diff quiet_window %v → %v = %+v, want weakening=%v", c.from.D(), c.to.D(), cs, c.weakening)
		}
	}
}
