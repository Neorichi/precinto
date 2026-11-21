package config_test

import (
	"encoding/hex"
	"math/rand/v2"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/precinto/precinto/internal/config"
)

func dur(d time.Duration) config.Duration { return config.Duration(d) }

// sample is a valid configuration with one root and both built-in harnesses.
func sample() config.Config {
	c := config.Default()
	c.Roots = []config.Root{{
		ID: "root-acme", Path: "/u/work/acme", MD: config.MDLedger, MDExclude: []string{"drafts/**"},
		Harnesses: []string{"claude-code", "codex"}, ProtectedAt: time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC),
	}}
	cc := c.Harness["claude-code"]
	cc.Homes = []config.Home{{Dir: "/u/.claude", Tmp: "/private/tmp/claude-501", Cache: "/u/Library/Caches/claude-cli-nodejs", Default: true}}
	c.Harness["claude-code"] = cc
	return c
}

// clone deep-copies a configuration through Strictest's no-alias guarantee.
func clone(c config.Config) config.Config {
	out := c
	out.Roots = nil
	for _, r := range c.Roots {
		r.MDExclude = slices.Clone(r.MDExclude)
		r.Harnesses = slices.Clone(r.Harnesses)
		out.Roots = append(out.Roots, r)
	}
	if c.Harness != nil {
		out.Harness = map[string]config.Harness{}
		for id, h := range c.Harness {
			h.Homes = slices.Clone(h.Homes)
			out.Harness[id] = h
		}
	}
	return out
}

func findChange(cs []config.Change, key string) (config.Change, bool) {
	for _, c := range cs {
		if c.Key == key {
			return c, true
		}
	}
	return config.Change{}, false
}

func TestDiffIdentical(t *testing.T) {
	if cs := config.Diff(config.Default(), config.Default()); len(cs) != 0 {
		t.Errorf("Diff(Default, Default) = %+v", cs)
	}
	s := sample()
	if cs := config.Diff(s, clone(s)); len(cs) != 0 {
		t.Errorf("Diff(sample, sample) = %+v", cs)
	}
	// Order of roots, homes and list entries is not a change.
	r := clone(s)
	r.Roots = append(r.Roots, config.Root{ID: "b", Path: "/u/b"})
	r2 := clone(r)
	r2.Roots[0], r2.Roots[1] = r2.Roots[1], r2.Roots[0]
	r2.Roots[1].Harnesses = []string{"codex", "claude-code"}
	if cs := config.Diff(r, r2); len(cs) != 0 {
		t.Errorf("reordering = %+v", cs)
	}
}

func TestDiffPolicy(t *testing.T) {
	for _, c := range []struct {
		key       string
		edit      func(p *config.Policy)
		old, new  string
		weakening bool
	}{
		{"idle_soft", func(p *config.Policy) { p.IdleSoft = dur(30 * time.Minute) }, "15m", "30m", true},
		{"idle_soft", func(p *config.Policy) { p.IdleSoft = dur(5 * time.Minute) }, "15m", "5m", false},
		{"idle_hard", func(p *config.Policy) { p.IdleHard = 0 }, "1h", "0", true}, // "0" never
		{"idle_hard", func(p *config.Policy) { p.IdleHard = dur(30 * time.Minute) }, "1h", "30m", false},
		{"max_unlock", func(p *config.Policy) { p.MaxUnlock = dur(12 * time.Hour) }, "8h", "12h", true},
		{"max_unlock", func(p *config.Policy) { p.MaxUnlock = dur(time.Hour) }, "8h", "1h", false},
		{"lock_on_screen_lock", func(p *config.Policy) { p.LockOnScreenLock = false }, "true", "false", true},
		{"screen_lock_hard_after", func(p *config.Policy) { p.ScreenLockHardAfter = 0 }, "15m", "0", true},
		{"screen_lock_hard_after", func(p *config.Policy) { p.ScreenLockHardAfter = dur(5 * time.Minute) }, "15m", "5m", false},
		{"busy_grace", func(p *config.Policy) { p.BusyGrace = dur(time.Hour) }, "30m", "1h", true},
		{"busy_grace", func(p *config.Policy) { p.BusyGrace = 0 }, "30m", "0", true},
		{"busy_grace", func(p *config.Policy) { p.BusyGrace = dur(10 * time.Minute) }, "30m", "10m", false},
		{"busy_timeout", func(p *config.Policy) { p.BusyTimeout = dur(20 * time.Minute) }, "10m", "20m", true},
		{"quiet_window", func(p *config.Policy) { p.QuietWindow = dur(10 * time.Minute) }, "2m", "10m", true},
		{"quiet_window", func(p *config.Policy) { p.QuietWindow = dur(90 * time.Second) }, "2m", "90s", false},
		{"hold_cap", func(p *config.Policy) { p.HoldCap = dur(48 * time.Hour) }, "24h", "48h", true},
		{"restore_recent", func(p *config.Policy) { p.RestoreRecent = 10 }, "5", "10", true},
		{"restore_recent", func(p *config.Policy) { p.RestoreRecent = 0 }, "5", "0", false},
		{"restore_max_bytes", func(p *config.Policy) { p.RestoreMaxBytes = 2 << 30 }, "1073741824", "2147483648", true},
		{"restore_history", func(p *config.Policy) { p.RestoreHistory = false }, "true", "false", false},
		{"per_root_auth", func(p *config.Policy) { p.PerRootAuth = false }, "true", "false", true},
		{"unlock_on_prompt", func(p *config.Policy) { p.UnlockOnPrompt = true }, "false", "true", true},
		{"on_enter", func(p *config.Policy) { p.OnEnter = config.OnEnterNotify }, "prompt", "notify", true},
		{"on_enter", func(p *config.Policy) { p.OnEnter = config.OnEnterOff }, "prompt", "off", true},
		{"md_seal_on", func(p *config.Policy) { p.MDSealOn = config.MDSealOnEnd }, "lock", "end", true},
		{"clear_terminal_on_end", func(p *config.Policy) { p.ClearTerminalOnEnd = false }, "true", "false", true},
		{"clear_scrollback_on_lock", func(p *config.Policy) { p.ClearScrollbackLock = false }, "true", "false", true},
		{"prompt_rate_per_minute", func(p *config.Policy) { p.PromptRatePerMinute = 10 }, "3", "10", true},
		{"prompt_rate_per_minute", func(p *config.Policy) { p.PromptRatePerMinute = 1 }, "3", "1", false},
		{"prompt_backoff", func(p *config.Policy) { p.PromptBackoff = 0 }, "30s", "0", true},
		{"prompt_backoff", func(p *config.Policy) { p.PromptBackoff = dur(time.Minute) }, "30s", "1m", false},
		{"hook_prompt_cooldown", func(p *config.Policy) { p.HookPromptCooldown = dur(time.Minute) }, "10m", "1m", true},
		{"hook_prompt_cooldown", func(p *config.Policy) { p.HookPromptCooldown = dur(time.Hour) }, "10m", "1h", false},
	} {
		old := config.Default()
		n := config.Default()
		c.edit(&n.Policy)
		cs := config.Diff(old, n)
		if len(cs) != 1 {
			t.Errorf("%s → %s: %d changes %+v", c.key, c.new, len(cs), cs)
			continue
		}
		want := config.Change{Key: "policy." + c.key, Old: c.old, New: c.new, Weakening: c.weakening}
		if cs[0] != want {
			t.Errorf("Diff = %+v, want %+v", cs[0], want)
		}
		// The reverse edit has the opposite classification.
		back := config.Diff(n, old)
		if len(back) != 1 || back[0].Weakening == c.weakening {
			t.Errorf("%s reverse: %+v", c.key, back)
		}
	}
	// restore_history: turning merge-back on is the weakening direction.
	off := config.Default()
	off.Policy.RestoreHistory = false
	if cs := config.Diff(off, config.Default()); len(cs) != 1 || !cs[0].Weakening {
		t.Errorf("restore_history on: %+v", cs)
	}
	// Invalid values are the weakest.
	bad := config.Default()
	bad.Policy.IdleSoft = 0
	bad.Policy.BusyGrace = dur(-time.Minute)
	for _, ch := range config.Diff(config.Default(), bad) {
		if !ch.Weakening {
			t.Errorf("invalid value not weakening: %+v", ch)
		}
	}
}

func TestDiffRoots(t *testing.T) {
	base := sample()
	edit := func(f func(c *config.Config)) config.Config {
		c := clone(base)
		f(&c)
		return c
	}
	for _, c := range []struct {
		name      string
		new       config.Config
		key       string
		weakening bool
	}{
		{"root removed", edit(func(c *config.Config) { c.Roots = nil }), "roots[root-acme]", true},
		{"root added", edit(func(c *config.Config) { c.Roots = append(c.Roots, config.Root{ID: "b", Path: "/u/b"}) }), "roots[b]", false},
		{"path moved", edit(func(c *config.Config) { c.Roots[0].Path = "/u/empty" }), "roots[root-acme].path", true},
		{"md narrowed", edit(func(c *config.Config) { c.Roots[0].MD = config.MDOff }), "roots[root-acme].md", true},
		{"md widened", edit(func(c *config.Config) { c.Roots[0].MD = config.MDAll }), "roots[root-acme].md", false},
		{"md same meaning", edit(func(c *config.Config) { c.Roots[0].MD = "" }), "roots[root-acme].md", false},
		{"exclude added", edit(func(c *config.Config) { c.Roots[0].MDExclude = append(c.Roots[0].MDExclude, "**") }), "roots[root-acme].md_exclude", true},
		{"exclude removed", edit(func(c *config.Config) { c.Roots[0].MDExclude = nil }), "roots[root-acme].md_exclude", false},
		{"include_tracked on", edit(func(c *config.Config) { c.Roots[0].IncludeTracked = true }), "roots[root-acme].include_tracked", false},
		{"on_enter relaxed", edit(func(c *config.Config) { c.Roots[0].OnEnter = config.OnEnterOff }), "roots[root-acme].on_enter", true},
		{"on_enter same as policy", edit(func(c *config.Config) { c.Roots[0].OnEnter = config.OnEnterPrompt }), "roots[root-acme].on_enter", false},
		{"harness dropped", edit(func(c *config.Config) { c.Roots[0].Harnesses = []string{"claude-code"} }), "roots[root-acme].harnesses", true},
		{"harnesses default", edit(func(c *config.Config) { c.Roots[0].Harnesses = nil }), "roots[root-acme].harnesses", false},
		{"claude_settings on", edit(func(c *config.Config) { c.Roots[0].ClaudeSettings = true }), "roots[root-acme].claude_settings", false},
		{"protected_at", edit(func(c *config.Config) { c.Roots[0].ProtectedAt = time.Time{} }), "roots[root-acme].protected_at", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			cs := config.Diff(base, c.new)
			ch, ok := findChange(cs, c.key)
			if !ok || ch.Weakening != c.weakening {
				t.Fatalf("Diff = %+v, want %s weakening=%v", cs, c.key, c.weakening)
			}
			if c.name == "root removed" && ch.Old != "/u/work/acme" {
				t.Errorf("removed root reported as %+v", ch)
			}
		})
	}
	// Turning include_tracked/claude_settings off weakens.
	on := edit(func(c *config.Config) { c.Roots[0].IncludeTracked, c.Roots[0].ClaudeSettings = true, true })
	for _, ch := range config.Diff(on, base) {
		if !ch.Weakening {
			t.Errorf("turning off %s not weakening", ch.Key)
		}
	}
	// A root override is judged on its effective value: relaxing the policy
	// while the root pins "prompt" does not weaken the root.
	pinned := edit(func(c *config.Config) { c.Policy.OnEnter = config.OnEnterOff; c.Roots[0].OnEnter = "" })
	pinnedRoot := edit(func(c *config.Config) {
		c.Policy.OnEnter = config.OnEnterOff
		c.Roots[0].OnEnter = config.OnEnterPrompt
	})
	if ch, ok := findChange(config.Diff(pinned, pinnedRoot), "roots[root-acme].on_enter"); !ok || ch.Weakening {
		t.Errorf("root pins prompt: %+v", ch)
	}
	if ch, ok := findChange(config.Diff(pinnedRoot, pinned), "roots[root-acme].on_enter"); !ok || !ch.Weakening {
		t.Errorf("root override dropped: %+v", ch)
	}
}

func TestDiffHarness(t *testing.T) {
	base := sample()
	edit := func(f func(c *config.Config)) config.Config {
		c := clone(base)
		f(&c)
		return c
	}
	cc := func(c *config.Config, f func(h *config.Harness)) {
		h := c.Harness["claude-code"]
		f(&h)
		c.Harness["claude-code"] = h
	}
	for _, c := range []struct {
		name      string
		new       config.Config
		key       string
		weakening bool
	}{
		{"harness removed", edit(func(c *config.Config) { delete(c.Harness, "codex") }), "harness.codex", true},
		{"harness added", edit(func(c *config.Config) { c.Harness["gemini"] = config.Harness{Experimental: true} }), "harness.gemini", false},
		{"disabled", edit(func(c *config.Config) { cc(c, func(h *config.Harness) { h.Enabled = false }) }), "harness.claude-code.enabled", true},
		{"experimental on", edit(func(c *config.Config) { cc(c, func(h *config.Harness) { h.Experimental = true }) }), "harness.claude-code.experimental", false},
		{"bin set", edit(func(c *config.Config) { cc(c, func(h *config.Harness) { h.Bin = "/opt/claude" }) }), "harness.claude-code.bin", false},
		{"min_version lowered", edit(func(c *config.Config) { cc(c, func(h *config.Harness) { h.MinVersion = "2.1.200" }) }), "harness.claude-code.min_version", true},
		{"min_version raised", edit(func(c *config.Config) { cc(c, func(h *config.Harness) { h.MinVersion = "2.1.329" }) }), "harness.claude-code.min_version", false},
		{"min_version dropped", edit(func(c *config.Config) { cc(c, func(h *config.Harness) { h.MinVersion = "" }) }), "harness.claude-code.min_version", true},
		{"home removed", edit(func(c *config.Config) { cc(c, func(h *config.Harness) { h.Homes = nil }) }), "harness.claude-code.homes[/u/.claude]", true},
		{"home added", edit(func(c *config.Config) {
			cc(c, func(h *config.Harness) { h.Homes = append(h.Homes, config.Home{Dir: "/u/alt-claude"}) })
		}), "harness.claude-code.homes[/u/alt-claude]", false},
		{"home tmp moved", edit(func(c *config.Config) { cc(c, func(h *config.Harness) { h.Homes[0].Tmp = "/u/tmp" }) }), "harness.claude-code.homes[/u/.claude].tmp", true},
		{"home seen", edit(func(c *config.Config) { cc(c, func(h *config.Harness) { h.Homes[0].SeenAt = time.Unix(1, 0) }) }), "harness.claude-code.homes[/u/.claude].seen_at", false},
		{"home default", edit(func(c *config.Config) { cc(c, func(h *config.Harness) { h.Homes[0].Default = false }) }), "harness.claude-code.homes[/u/.claude].default", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			cs := config.Diff(base, c.new)
			ch, ok := findChange(cs, c.key)
			if !ok || ch.Weakening != c.weakening || len(cs) != 1 {
				t.Fatalf("Diff = %+v, want only %s weakening=%v", cs, c.key, c.weakening)
			}
		})
	}
	// Replacing or clearing a configured executable waits for confirmation.
	withBin := edit(func(c *config.Config) { cc(c, func(h *config.Harness) { h.Bin = "/opt/claude" }) })
	other := edit(func(c *config.Config) { cc(c, func(h *config.Harness) { h.Bin = "/tmp/claude" }) })
	for _, n := range []config.Config{other, base} {
		if ch, ok := findChange(config.Diff(withBin, n), "harness.claude-code.bin"); !ok || !ch.Weakening {
			t.Errorf("bin replaced: %+v", ch)
		}
	}
	// Re-enabling and leaving experimental mode.
	disabled := edit(func(c *config.Config) { cc(c, func(h *config.Harness) { h.Enabled = false; h.Experimental = true }) })
	for _, ch := range config.Diff(disabled, base) {
		if ch.Key == "harness.claude-code.enabled" && ch.Weakening {
			t.Errorf("enabling weakens: %+v", ch)
		}
		if ch.Key == "harness.claude-code.experimental" && !ch.Weakening {
			t.Errorf("leaving experimental does not weaken: %+v", ch)
		}
	}
}

func TestDiffVersionAndKeys(t *testing.T) {
	n := config.Default()
	n.Version = 2
	cs := config.Diff(config.Default(), n)
	if len(cs) != 1 || cs[0].Key != "version" || !cs[0].Weakening || cs[0].Old != "1" || cs[0].New != "2" {
		t.Errorf("version change: %+v", cs)
	}
	// Changes come in a stable order: version, policy, roots, harnesses.
	a, b := sample(), clone(sample())
	b.Version = 2
	b.Policy.IdleSoft = dur(time.Hour)
	b.Roots = nil
	delete(b.Harness, "codex")
	var keys []string
	for _, c := range config.Diff(a, b) {
		keys = append(keys, c.Key)
	}
	if strings.Join(keys, " ") != "version policy.idle_soft roots[root-acme] harness.codex" {
		t.Errorf("order = %q", keys)
	}
}

func TestStrictestPolicy(t *testing.T) {
	type pick struct {
		name string
		a, b func(p *config.Policy)
		want func(p config.Policy) bool
	}
	for _, c := range []pick{
		{"idle_soft lower", func(p *config.Policy) { p.IdleSoft = dur(30 * time.Minute) }, func(p *config.Policy) { p.IdleSoft = dur(5 * time.Minute) },
			func(p config.Policy) bool { return p.IdleSoft == dur(5*time.Minute) }},
		{"invalid idle_soft loses", func(p *config.Policy) { p.IdleSoft = 0 }, func(p *config.Policy) {},
			func(p config.Policy) bool { return p.IdleSoft == dur(15*time.Minute) }},
		{"idle_hard never loses", func(p *config.Policy) { p.IdleHard = 0 }, func(p *config.Policy) { p.IdleHard = dur(2 * time.Hour) },
			func(p config.Policy) bool { return p.IdleHard == dur(2*time.Hour) }},
		{"busy_grace lower", func(p *config.Policy) { p.BusyGrace = dur(5 * time.Minute) }, func(p *config.Policy) {},
			func(p config.Policy) bool { return p.BusyGrace == dur(5*time.Minute) }},
		{"busy_grace never loses", func(p *config.Policy) { p.BusyGrace = 0 }, func(p *config.Policy) {},
			func(p config.Policy) bool { return p.BusyGrace == dur(30*time.Minute) }},
		{"negative loses to never", func(p *config.Policy) { p.ScreenLockHardAfter = dur(-time.Minute) }, func(p *config.Policy) { p.ScreenLockHardAfter = 0 },
			func(p config.Policy) bool { return p.ScreenLockHardAfter == 0 }},
		{"max_unlock clamped", func(p *config.Policy) { p.MaxUnlock = dur(48 * time.Hour) }, func(p *config.Policy) { p.MaxUnlock = dur(72 * time.Hour) },
			func(p config.Policy) bool { return p.MaxUnlock.D() == config.MaxUnlockCap }},
		{"restore_recent zero", func(p *config.Policy) { p.RestoreRecent = 0 }, func(p *config.Policy) {},
			func(p config.Policy) bool { return p.RestoreRecent == 0 }},
		{"negative counter loses", func(p *config.Policy) { p.RestoreMaxBytes = -1 }, func(p *config.Policy) {},
			func(p config.Policy) bool { return p.RestoreMaxBytes == 1<<30 }},
		{"prompt rate lower", func(p *config.Policy) { p.PromptRatePerMinute = 10 }, func(p *config.Policy) { p.PromptRatePerMinute = 1 },
			func(p config.Policy) bool { return p.PromptRatePerMinute == 1 }},
		{"backoff longer", func(p *config.Policy) { p.PromptBackoff = 0 }, func(p *config.Policy) { p.PromptBackoff = dur(time.Minute) },
			func(p config.Policy) bool { return p.PromptBackoff == dur(time.Minute) }},
		{"cooldown longer", func(p *config.Policy) { p.HookPromptCooldown = dur(time.Hour) }, func(p *config.Policy) {},
			func(p config.Policy) bool { return p.HookPromptCooldown == dur(time.Hour) }},
		{"bools", func(p *config.Policy) {
			p.LockOnScreenLock, p.PerRootAuth, p.ClearTerminalOnEnd, p.ClearScrollbackLock = false, false, false, false
			p.RestoreHistory, p.UnlockOnPrompt = true, true
		}, func(p *config.Policy) { p.RestoreHistory = false },
			func(p config.Policy) bool {
				return p.LockOnScreenLock && p.PerRootAuth && p.ClearTerminalOnEnd && p.ClearScrollbackLock && !p.RestoreHistory && !p.UnlockOnPrompt
			}},
		{"on_enter", func(p *config.Policy) { p.OnEnter = config.OnEnterOff }, func(p *config.Policy) { p.OnEnter = config.OnEnterNotify },
			func(p config.Policy) bool { return p.OnEnter == config.OnEnterNotify }},
		{"unknown enum loses", func(p *config.Policy) { p.OnEnter = "always" }, func(p *config.Policy) { p.OnEnter = config.OnEnterOff },
			func(p config.Policy) bool { return p.OnEnter == config.OnEnterOff }},
		{"md_seal_on", func(p *config.Policy) { p.MDSealOn = config.MDSealOnEnd }, func(p *config.Policy) {},
			func(p config.Policy) bool { return p.MDSealOn == config.MDSealOnLock }},
	} {
		a, b := config.Default(), config.Default()
		c.a(&a.Policy)
		c.b(&b.Policy)
		for _, order := range [][2]config.Config{{a, b}, {b, a}} {
			if got := config.Strictest(order[0], order[1]); !c.want(got.Policy) {
				t.Errorf("%s: Strictest policy = %+v", c.name, got.Policy)
			}
		}
	}
	if got := config.Strictest(config.Default(), config.Default()); len(config.Diff(config.Default(), got)) != 0 {
		t.Errorf("Strictest(Default, Default) differs: %+v", config.Diff(config.Default(), got))
	}
}

func TestStrictestRoots(t *testing.T) {
	a := sample()
	b := clone(sample())
	b.Roots[0].MD = config.MDAll
	b.Roots[0].MDExclude = []string{"drafts/**", "tmp/**"}
	b.Roots[0].IncludeTracked = true
	b.Roots[0].Harnesses = []string{"claude-code", "gemini"}
	b.Roots[0].ProtectedAt = time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	b.Roots = append(b.Roots, config.Root{ID: "beta", Path: "/u/work/beta", OnEnter: config.OnEnterOff})
	a.Roots = append(a.Roots, config.Root{ID: "gamma", Path: "/u/work/gamma"})
	got := config.Strictest(a, b)
	if err := got.Validate(); err != nil {
		t.Fatalf("Strictest of valid configs without conflicts is invalid: %v", err)
	}
	var ids []string
	for _, r := range got.Roots {
		ids = append(ids, r.ID)
	}
	if strings.Join(ids, ",") != "root-acme,gamma,beta" {
		t.Fatalf("roots = %q (union, first appearance order)", ids)
	}
	r := got.Roots[0]
	if r.MD != config.MDAll || !slices.Equal(r.MDExclude, []string{"drafts/**"}) || !r.IncludeTracked ||
		!slices.Equal(r.Harnesses, []string{"claude-code", "codex", "gemini"}) || !r.ProtectedAt.Equal(b.Roots[0].ProtectedAt) {
		t.Errorf("merged root = %+v", r)
	}
	if got.Roots[2].OnEnter != config.OnEnterOff {
		t.Errorf("a root only one side has keeps its fields: %+v", got.Roots[2])
	}
	// on_enter: the stricter effective value.
	x, y := sample(), clone(sample())
	x.Roots[0].OnEnter = config.OnEnterOff
	y.Policy.OnEnter = config.OnEnterNotify
	if s := config.Strictest(x, y); s.Roots[0].OnEnter != config.OnEnterNotify || s.Policy.OnEnter != config.OnEnterPrompt {
		t.Errorf("on_enter: root %q policy %q", s.Roots[0].OnEnter, s.Policy.OnEnter)
	}
	if s := config.Strictest(sample(), sample()); s.Roots[0].OnEnter != "" {
		t.Errorf("inheriting roots keep inheriting: %q", s.Roots[0].OnEnter)
	}
	// No aliasing.
	got.Roots[0].MDExclude[0] = "changed"
	got.Roots[0].Harnesses[0] = "changed"
	if a.Roots[0].MDExclude[0] != "drafts/**" || b.Roots[0].Harnesses[0] != "claude-code" {
		t.Error("Strictest aliases its inputs")
	}
}

// TestStrictestRootConflicts: a moved path or a reassigned id never drops the
// protection of either folder.
func TestStrictestRootConflicts(t *testing.T) {
	pinned := sample()
	moved := clone(sample())
	moved.Roots[0].Path = "/u/empty"
	got := config.Strictest(moved, pinned)
	var paths []string
	for _, r := range got.Roots {
		if r.ID == "root-acme" {
			paths = append(paths, r.Path)
		}
	}
	if !slices.Equal(paths, []string{"/u/empty", "/u/work/acme"}) {
		t.Errorf("moved root: %+v", got.Roots)
	}
	if r, ok := got.RootFor("/u/work/acme/notes.md"); !ok || r.ID != "root-acme" {
		t.Errorf("old folder unprotected: %+v %v", r, ok)
	}
	reassigned := clone(sample())
	reassigned.Roots[0].ID = "attacker"
	got = config.Strictest(reassigned, pinned)
	if rs := got.RootsFor("/u/work/acme/x"); len(rs) != 2 {
		t.Errorf("reassigned id: %+v", rs)
	}
	for _, s := range []config.Config{config.Strictest(moved, pinned), config.Strictest(reassigned, pinned)} {
		if err := s.Validate(); err == nil {
			t.Error("conflicting roots validated (expected duplicate id or path)")
		}
	}
}

func TestStrictestHarness(t *testing.T) {
	a, b := sample(), clone(sample())
	ha := a.Harness["claude-code"]
	ha.Enabled, ha.MinVersion, ha.Bin = false, "2.1.329", "/opt/a/claude"
	a.Harness["claude-code"] = ha
	hb := b.Harness["claude-code"]
	hb.Experimental, hb.MinVersion, hb.Bin = true, "2.1.300", "/opt/b/claude"
	hb.Homes = append(hb.Homes, config.Home{Dir: "/u/alt"})
	hb.Homes[0].SeenAt = time.Unix(100, 0)
	b.Harness["claude-code"] = hb
	delete(b.Harness, "codex")
	b.Harness["gemini"] = config.Harness{Experimental: true}
	got := config.Strictest(a, b)
	h := got.Harness["claude-code"]
	if !h.Enabled || !h.Experimental || h.MinVersion != "2.1.329" || h.Bin != "/opt/b/claude" || len(h.Homes) != 2 || !h.Homes[0].SeenAt.Equal(time.Unix(100, 0)) {
		t.Errorf("merged harness = %+v", h)
	}
	if _, ok := got.Harness["codex"]; !ok {
		t.Error("harness removed by one side dropped")
	}
	if _, ok := got.Harness["gemini"]; !ok {
		t.Error("harness added by one side dropped")
	}
	// bin: the second argument's when set, else the first's.
	hb.Bin = ""
	b.Harness["claude-code"] = hb
	if got := config.Strictest(a, b); got.Harness["claude-code"].Bin != "/opt/a/claude" {
		t.Errorf("bin = %q", got.Harness["claude-code"].Bin)
	}
	if got := config.Strictest(config.Config{}, config.Config{}); got.Harness != nil || got.Roots != nil {
		t.Errorf("empty inputs: %+v", got)
	}
	// Homes differing only in tmp are both kept (both are visited).
	c1, c2 := sample(), clone(sample())
	h2 := c2.Harness["claude-code"]
	h2.Homes[0].Tmp = "/u/tmp"
	c2.Harness["claude-code"] = h2
	if got := config.Strictest(c1, c2); len(got.Harness["claude-code"].Homes) != 2 {
		t.Errorf("home variants: %+v", got.Harness["claude-code"].Homes)
	}
}

// TestStrictestNeverWeaker is the property tying Diff and Strictest together:
// the merge is never weaker than either input, merging a config with itself
// changes nothing, and the merge does not depend on the argument order
// (bin aside, which has no protection order).
func TestStrictestNeverWeaker(t *testing.T) {
	rng := rand.New(rand.NewPCG(1, 2))
	for i := 0; i < 3000; i++ {
		a, b := randomConfig(rng), randomConfig(rng)
		s := config.Strictest(a, b)
		for _, in := range []config.Config{a, b} {
			for _, c := range config.Diff(in, s) {
				if c.Weakening && !strings.HasSuffix(c.Key, ".bin") {
					t.Fatalf("Strictest weaker than an input on %s (%q → %q)\na=%+v\nb=%+v", c.Key, c.Old, c.New, a, b)
				}
			}
		}
		// Idempotent, except that invalid shapes are normalised: entries
		// sharing a root id are merged field by field, duplicate homes are
		// folded, and max_unlock is clamped to its cap. Normalising is never
		// weakening.
		aa := config.Diff(a, config.Strictest(a, a))
		for _, c := range aa {
			if c.Weakening {
				t.Fatalf("Strictest(a, a) weaker than a: %+v\na=%+v", c, a)
			}
		}
		if uniqueIDs(a) && uniqueHomes(a) && a.Policy.MaxUnlock.D() <= config.MaxUnlockCap && len(aa) != 0 {
			t.Fatalf("Strictest(a, a) differs from a: %+v\na=%+v", aa, a)
		}
		if cs := config.Diff(a, clone(a)); len(cs) != 0 {
			t.Fatalf("Diff(a, a) = %+v", cs)
		}
		ba := config.Strictest(b, a)
		for _, c := range config.Diff(s, ba) {
			if c.Weakening && !strings.HasSuffix(c.Key, ".bin") {
				t.Fatalf("Strictest depends on order: %+v\na=%+v\nb=%+v", c, a, b)
			}
		}
	}
}

func uniqueIDs(c config.Config) bool {
	seen := map[string]bool{}
	for _, r := range c.Roots {
		if seen[r.ID] {
			return false
		}
		seen[r.ID] = true
	}
	return true
}

func uniqueHomes(c config.Config) bool {
	for _, h := range c.Harness {
		seen := map[config.Home]bool{}
		for _, home := range h.Homes {
			k := config.Home{Dir: home.Dir, Tmp: home.Tmp, Cache: home.Cache}
			if seen[k] {
				return false
			}
			seen[k] = true
		}
	}
	return true
}

func randomConfig(rng *rand.Rand) config.Config {
	pickD := func(vs ...time.Duration) config.Duration { return config.Duration(vs[rng.IntN(len(vs))]) }
	pickS := func(vs ...string) string { return vs[rng.IntN(len(vs))] }
	pickB := func() bool { return rng.IntN(2) == 0 }
	c := config.Config{Version: 1}
	if rng.IntN(10) == 0 {
		c.Version = rng.IntN(3)
	}
	p := &c.Policy
	p.IdleSoft = pickD(0, -time.Minute, time.Minute, 15*time.Minute, time.Hour)
	p.IdleHard = pickD(0, -time.Minute, 30*time.Minute, time.Hour)
	p.MaxUnlock = pickD(0, time.Hour, 8*time.Hour, 48*time.Hour)
	p.LockOnScreenLock = pickB()
	p.ScreenLockHardAfter = pickD(0, 5*time.Minute, 15*time.Minute)
	p.BusyGrace = pickD(0, -time.Second, 10*time.Minute, 30*time.Minute)
	p.BusyTimeout = pickD(0, 10*time.Minute, 20*time.Minute)
	p.QuietWindow = pickD(0, time.Minute, 2*time.Minute)
	p.HoldCap = pickD(0, 24*time.Hour, 48*time.Hour)
	p.RestoreRecent = rng.IntN(4) - 1
	p.RestoreMaxBytes = int64(rng.IntN(4)-1) << 30
	p.RestoreHistory = pickB()
	p.PerRootAuth = pickB()
	p.UnlockOnPrompt = pickB()
	p.OnEnter = pickS("prompt", "notify", "off", "", "bogus")
	p.MDSealOn = pickS("lock", "end", "")
	p.ClearTerminalOnEnd = pickB()
	p.ClearScrollbackLock = pickB()
	p.PromptRatePerMinute = rng.IntN(5) - 1
	p.PromptBackoff = pickD(0, -time.Second, 30*time.Second, time.Minute)
	p.HookPromptCooldown = pickD(0, 10*time.Minute, time.Hour)
	for n := rng.IntN(4); n > 0; n-- {
		r := config.Root{
			ID:             pickS("r1", "r2", "r3"),
			Path:           pickS("/u/a", "/u/b", "/u/a/c"),
			MD:             pickS("", "ledger", "all", "off", "bogus"),
			IncludeTracked: pickB(),
			OnEnter:        pickS("", "prompt", "notify", "off"),
			ClaudeSettings: pickB(),
		}
		for _, g := range []string{"x/**", "y/**", "z/**"} {
			if pickB() {
				r.MDExclude = append(r.MDExclude, g)
			}
		}
		for _, h := range []string{"claude-code", "codex", "gemini"} {
			if rng.IntN(3) == 0 {
				r.Harnesses = append(r.Harnesses, h)
			}
		}
		if pickB() {
			r.ProtectedAt = time.Unix(int64(rng.IntN(3))*1000, 0).UTC()
		}
		c.Roots = append(c.Roots, r)
	}
	if rng.IntN(5) > 0 {
		c.Harness = map[string]config.Harness{}
		for _, id := range []string{"claude-code", "codex", "gemini"} {
			if rng.IntN(3) == 0 {
				continue
			}
			h := config.Harness{
				Enabled: pickB(), Experimental: pickB(),
				MinVersion: pickS("", "2.1.295", "2.1.329", "0.154.0", "1.0.0-beta", "garbage"),
			}
			for n := rng.IntN(3); n > 0; n-- {
				h.Homes = append(h.Homes, config.Home{
					Dir: pickS("/u/.claude", "/u/alt"), Tmp: pickS("", "/tmp/c"), Cache: pickS("", "/u/cache"),
					SeenAt: time.Unix(int64(rng.IntN(3)), 0).UTC(), Default: pickB(),
				})
			}
			c.Harness[id] = h
		}
	}
	return c
}

func TestNewRootID(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 1000; i++ {
		id := config.NewRootID()
		if len(id) != 32 || strings.ToLower(id) != id {
			t.Fatalf("NewRootID = %q", id)
		}
		if _, err := hex.DecodeString(id); err != nil {
			t.Fatalf("NewRootID = %q: %v", id, err)
		}
		if seen[id] {
			t.Fatalf("NewRootID repeated %q", id)
		}
		seen[id] = true
	}
	c := config.Default()
	c.Roots = []config.Root{{ID: config.NewRootID(), Path: "/u/a"}, {ID: config.NewRootID(), Path: "/u/b"}}
	if err := c.Validate(); err != nil {
		t.Errorf("config with fresh ids invalid: %v", err)
	}
}

func TestRootByID(t *testing.T) {
	c := sample()
	if r, ok := c.RootByID("root-acme"); !ok || r.Path != "/u/work/acme" {
		t.Errorf("RootByID = %+v %v", r, ok)
	}
	if _, ok := c.RootByID("missing"); ok {
		t.Error("RootByID found a missing id")
	}
}
