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

// UX-09: a config.toml that does not load names the file, the line and
// the key, and keeps the reason with its hint (a decimal size, a duration
// without a unit), so the user can fix it without guessing.
func TestLoadErrorSaysWhereAndWhy(t *testing.T) {
	for name, c := range map[string]struct {
		body string
		want []string
	}{
		"decimal size":  {"version = 1\n[policy]\nidle_soft = \"15m\"\nmin_free = \"2GB\"\n", []string{"config.toml", "line 4", "policy.min_free", `"2GiB"`}},
		"unitless time": {"version = 1\n[policy]\nidle_soft = \"15\"\n", []string{"config.toml", "line 3", "policy.idle_soft", `"15m"`}},
		"syntax":        {"version = 1\n[policy]\nidle_soft = 15m\n", []string{"config.toml", "line 3"}},
		"unknown key":   {"version = 1\n[policy]\nidle_sotf = \"1m\"\n", []string{"config.toml line 3, policy.idle_sotf: unknown key (did you mean idle_soft?)"}},
		"far key":       {"version = 1\n[policy]\n\n# a comment\nzzz_top = 1\n", []string{"config.toml line 5, policy.zzz_top: unknown key (check its spelling)"}},
		"root key":      {"version = 1\n[[roots]]\nid = \"a\"\npath = \"/u/a\"\n[[roots]]\nid = \"b\"\npath = \"/u/b\"\nmdd = \"all\"\n", []string{"config.toml line 8, roots.mdd: unknown key (did you mean md?)"}},
		"harness key":   {"version = 1\n[harness.\"claude-code\"]\nbinn = \"/x\"\n", []string{"config.toml line 3, harness.claude-code.binn: unknown key (did you mean bin?)"}},
		"dotted key":    {"version = 1\npolicy.idle_sotf = \"1m\"\n", []string{"config.toml line 2, policy.idle_sotf: unknown key (did you mean idle_soft?)"}},
		"unknown table": {"version = 1\n[polcy]\nidle_soft = \"1m\"\n", []string{"config.toml line 2, polcy: unknown key (did you mean policy?)"}},
		"enum":          {"version = 1\n[policy]\non_enter = \"always\"\n", []string{"config.toml line 3: policy.on_enter must be prompt, notify or off"}},
		"zero time":     {"version = 1\n[policy]\nmin_free = \"1GiB\"\nidle_soft = \"0s\"\n", []string{"config.toml line 4: policy.idle_soft must be positive"}},
		"root enum": {"version = 1\n[[roots]]\nid = \"a\"\npath = \"/u/a\"\nmd = \"all\"\n[[roots]]\nid = \"b\"\npath = \"/u/b\"\nmd = \"some\"\n",
			[]string{"config.toml line 9: root b md must be ledger, all or off"}},
		"counter": {"version = 1\n[policy]\nprompt_rate_per_minute = -1\n", []string{"config.toml line 3: policy counters must not be negative"}},
	} {
		_, err := config.Load(write(t, c.body))
		if !errors.Is(err, config.ErrInvalid) {
			t.Errorf("%s: err = %v, want ErrInvalid", name, err)
			continue
		}
		for _, w := range c.want {
			if !strings.Contains(err.Error(), w) {
				t.Errorf("%s: %q does not say %q", name, err, w)
			}
		}
		if strings.Count(err.Error(), "invalid configuration") != 1 || strings.Contains(err.Error(), "\n") {
			t.Errorf("%s: %q is not one plain line", name, err)
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

// D76: policy.min_free is a size string (binary units), at least 512 MiB;
// "0" keeps the 2 GiB default, decimal units and other junk are refused.
func TestMinFree(t *testing.T) {
	for v, want := range map[string]int64{
		`"512MiB"`: 512 << 20, `"2GiB"`: 2 << 30, `"3 GiB"`: 3 << 30, `"1tib"`: 1 << 40,
		`"524288KiB"`: 512 << 20, `"536870912"`: 512 << 20, `"536870912B"`: 512 << 20,
		`536870912`: 512 << 20, `"0"`: 2 << 30,
	} {
		c, err := config.Load(write(t, "version = 1\n[policy]\nmin_free = "+v+"\n"))
		if err != nil {
			t.Errorf("min_free = %s refused: %v", v, err)
			continue
		}
		if got := c.Policy.MinFreeBytes(); got != want {
			t.Errorf("min_free = %s: %d bytes, want %d", v, got, want)
		}
		if f := c.Policy.Floor(); f.MinBytes != want || f.MinFraction != 0 {
			t.Errorf("min_free = %s: floor %+v", v, f)
		}
	}
	for _, v := range []string{`"511MiB"`, `"1GB"`, `"2G"`, `"1.5GiB"`, `"-1GiB"`, `"GiB"`, `""`, `"2GiB "`, `"2  GiB"`,
		`"99999999999TiB"`, `"12345678901234567890"`, `-1`} {
		if _, err := config.Load(write(t, "version = 1\n[policy]\nmin_free = "+v+"\n")); !errors.Is(err, config.ErrInvalid) {
			t.Errorf("min_free = %s: err = %v, want ErrInvalid", v, err)
		}
	}
	// Absent: the default.
	c, err := config.Load(write(t, "version = 1\n"))
	if err != nil || c.Policy.MinFree != config.DefaultMinFree {
		t.Fatalf("default min_free = %v (%v)", c.Policy.MinFree, err)
	}
	// Text round trip with the largest exact unit.
	for v, want := range map[config.Size]string{0: "0", 512 << 20: "512MiB", 2 << 30: "2GiB", 1536 << 20: "1536MiB", 1 << 40: "1TiB", 1000: "1000B", 3 << 10: "3KiB"} {
		b, _ := v.MarshalText()
		var back config.Size
		if string(b) != want || back.UnmarshalText(b) != nil || back != v {
			t.Errorf("Size %d → %q → %d", v, b, back)
		}
	}
	// Save writes it as text and Load reads it back.
	dir := t.TempDir()
	c = config.Default()
	c.Policy.MinFree = 768 << 20
	if err := config.Save(filepath.Join(dir, "config.toml"), c); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(dir, "config.toml"))
	if !strings.Contains(string(b), `min_free = "768MiB"`) {
		t.Errorf("saved config lacks min_free: %s", b)
	}
	if back, err := config.Load(filepath.Join(dir, "config.toml")); err != nil || back.Policy.MinFree != 768<<20 {
		t.Errorf("min_free round trip: %v %v", back.Policy.MinFree, err)
	}
	// Validate refuses a value below the minimum set in code too.
	c.Policy.MinFree = 1 << 20
	if err := c.Validate(); !errors.Is(err, config.ErrInvalid) {
		t.Errorf("Validate(min_free 1MiB) = %v", err)
	}
}

// D76: a policy.pinned written before min_free existed has no MinFree in
// its canonical JSON; decoded, the key is 0 (the 2 GiB default) and the
// canonical encoding, which the pin's MACs cover, is unchanged.
func TestMinFreeCanonicalCompatibility(t *testing.T) {
	c := config.Default()
	c.Policy.MinFree = 0
	if strings.Contains(string(config.Canonical(c)), "MinFree") {
		t.Fatalf("a zero min_free is part of the canonical encoding: %s", config.Canonical(c))
	}
	c.Policy.MinFree = 4 << 30
	if !strings.Contains(string(config.Canonical(c)), `"MinFree":"4GiB"`) {
		t.Fatalf("a set min_free is not covered by the canonical encoding: %s", config.Canonical(c))
	}
	// A pin without the key: same canonical bytes after a round trip.
	old := config.Default()
	old.Policy.MinFree = 0
	dir := t.TempDir()
	pp := filepath.Join(dir, "policy.pinned")
	if err := config.SavePinned(pp, config.Pinned{ConfirmedAt: time.Unix(0, 0).UTC(), Config: old, MACs: map[string]string{}}); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(pp)
	if strings.Contains(string(b), "MinFree") {
		t.Fatalf("pin written with a zero min_free names it: %s", b)
	}
	got, ok, err := config.LoadPinned(pp)
	if err != nil || !ok || got.Config.Policy.MinFree != 0 || got.Config.Policy.MinFreeBytes() != 2<<30 {
		t.Fatalf("pin without min_free: %v %v %+v", ok, err, got.Config.Policy.MinFree)
	}
	if string(config.Canonical(got.Config)) != string(config.Canonical(old)) {
		t.Error("canonical encoding changed across the pin round trip")
	}
	// Strictest of config.toml (2 GiB written out) and such a pin is the
	// same 2 GiB floor.
	if s := config.Strictest(config.Default(), got.Config); s.Policy.MinFreeBytes() != 2<<30 {
		t.Errorf("Strictest floor %d", s.Policy.MinFreeBytes())
	}
}

// D130: unlock prompts cannot be turned off. config.toml with a rate of 0
// does not load (with its line, key and reason, like every D121 error),
// and a rate below 1 never wins a strictest merge or counts as a
// strengthening: no wait would end it, so precinto could never unlock.
func TestPromptRateCannotTurnUnlockPromptsOff(t *testing.T) {
	_, err := config.Load(write(t, "version = 1\n[policy]\nidle_soft = \"15m\"\nprompt_rate_per_minute = 0\n"))
	if !errors.Is(err, config.ErrInvalid) {
		t.Fatalf("prompt_rate_per_minute = 0 loads: %v", err)
	}
	want := "config.toml line 4: policy.prompt_rate_per_minute must be at least 1 (unlock prompts cannot be turned off: precinto could never unlock the folder again)"
	if !strings.Contains(err.Error(), want) {
		t.Errorf("error %q does not say %q", err, want)
	}
	if _, err := config.Load(write(t, "version = 1\n[policy]\nprompt_rate_per_minute = 1\n")); err != nil {
		t.Errorf("a rate of 1 does not load: %v", err)
	}
	off := config.Default()
	off.Policy.PromptRatePerMinute = 0
	if got := config.Strictest(config.Default(), off).Policy.PromptRatePerMinute; got != 3 {
		t.Errorf("Strictest(3, 0) = %d, want 3: a rate of 0 is invalid, never the strictest", got)
	}
	if got := config.Strictest(off, config.Default()).Policy.PromptRatePerMinute; got != 3 {
		t.Errorf("Strictest(0, 3) = %d, want 3", got)
	}
	cs := config.Diff(config.Default(), off)
	if len(cs) != 1 || !cs[0].Weakening {
		t.Errorf("3 → 0 is %+v, want one weakening change", cs)
	}
}
