package config

import (
	"cmp"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Protection order of every configuration key, shared by Diff (a change is
// weakening when the new value is less strict than the old one) and
// Strictest (the stricter value wins), so the two can never disagree (D48).
//
// Conventions where the contract leaves room (strictest reading):
//   - Durations that must be positive (idle_soft, max_unlock, busy_timeout,
//     hold_cap): smaller is stricter; a value <= 0 is invalid and is the
//     weakest (it never wins a merge).
//   - quiet_window: smaller is stricter (sealing starts sooner); 0 means
//     the 120 s default and compares as 120 s; any other value below 10 s
//     is invalid (D63) and the weakest.
//   - Timers ending sessions or turns (idle_hard, screen_lock_hard_after,
//     busy_grace): smaller is stricter; "0" means "never" (Duration doc,
//     SPEC §12.2 for idle_hard), so it is the weakest valid value; negative
//     values are invalid and weaker still.
//   - Delays after a cancelled prompt (prompt_backoff, hook_prompt_cooldown):
//     longer is stricter; 0 is no delay; negative values are invalid.
//   - min_free (D76): larger is stricter (more of the volume stays free);
//     0 means the 2 GiB default and compares as 2 GiB; any other value
//     below 512 MiB is invalid and the weakest.
//   - Counters (restore_recent, restore_max_bytes, prompt_rate_per_minute):
//     smaller is stricter and 0 means none (the contract gives 0 no other
//     meaning); negative values are invalid and the weakest.
//   - Booleans: lock_on_screen_lock, per_root_auth, clear_terminal_on_end,
//     clear_scrollback_on_lock, include_tracked, claude_settings, enabled and
//     experimental are stricter when true; restore_history and
//     unlock_on_prompt when false.
//   - Enums: on_enter prompt > notify > off; md_seal_on lock > end; a root's
//     md all > ledger (also "") > off. Unknown values are the weakest.
//   - min_version: higher is stricter; "" (no minimum) is the weakest; a
//     value that does not parse is the strictest (an unknown requirement
//     cannot be met).

// cmpFunc orders two values by protection: > 0 when a is stricter than b,
// 0 when they protect equally, < 0 when a is weaker.
type cmpFunc[T any] func(a, b T) int

func cmpPositiveLower(a, b Duration) int {
	av, bv := a > 0, b > 0
	switch {
	case av && bv:
		return cmp.Compare(b, a)
	case av:
		return 1
	case bv:
		return -1
	}
	return 0
}

// cmpQuietWindow orders quiet_window values by the window they mean.
func cmpQuietWindow(a, b Duration) int {
	mean := func(d Duration) (Duration, bool) {
		switch {
		case d == 0:
			return Duration(defaultQuietWindow), true
		case d < Duration(minQuietWindow):
			return 0, false
		}
		return d, true
	}
	av, aok := mean(a)
	bv, bok := mean(b)
	switch {
	case aok && bok:
		return cmp.Compare(bv, av)
	case aok:
		return 1
	case bok:
		return -1
	}
	return 0
}

// cmpMinFree orders min_free values by the floor they mean (D76).
func cmpMinFree(a, b Size) int {
	mean := func(s Size) (Size, bool) {
		switch {
		case s == 0:
			return DefaultMinFree, true
		case s < MinMinFree:
			return 0, false
		}
		return s, true
	}
	av, aok := mean(a)
	bv, bok := mean(b)
	switch {
	case aok && bok:
		return cmp.Compare(av, bv)
	case aok:
		return 1
	case bok:
		return -1
	}
	return 0
}

func cmpTimerZeroNever(a, b Duration) int {
	rank := func(d Duration) int {
		switch {
		case d < 0:
			return 0
		case d == 0:
			return 1
		}
		return 2
	}
	if ra, rb := rank(a), rank(b); ra != rb || ra < 2 {
		return cmp.Compare(ra, rb)
	}
	return cmp.Compare(b, a)
}

func cmpDelayHigher(a, b Duration) int {
	switch {
	case a < 0 && b < 0:
		return 0
	case a < 0:
		return -1
	case b < 0:
		return 1
	}
	return cmp.Compare(a, b)
}

func cmpCountLower[T int | int64](a, b T) int {
	switch {
	case a < 0 && b < 0:
		return 0
	case a < 0:
		return -1
	case b < 0:
		return 1
	}
	return cmp.Compare(b, a)
}

func cmpTrue(a, b bool) int { return cmp.Compare(b2i(a), b2i(b)) }

func cmpFalse(a, b bool) int { return cmp.Compare(b2i(b), b2i(a)) }

func b2i(v bool) int {
	if v {
		return 1
	}
	return 0
}

// cmpRank orders enum values by their rank (unknown values rank 0).
func cmpRank(ranks map[string]int) cmpFunc[string] {
	return func(a, b string) int { return cmp.Compare(ranks[a], ranks[b]) }
}

var (
	onEnterRank  = map[string]int{OnEnterPrompt: 3, OnEnterNotify: 2, OnEnterOff: 1}
	mdSealOnRank = map[string]int{MDSealOnLock: 2, MDSealOnEnd: 1}
	mdRank       = map[string]int{MDAll: 3, MDLedger: 2, "": 2, MDOff: 1}
)

// stricter returns the stricter of a and b, a on a tie.
func stricter[T any](c cmpFunc[T], a, b T) T {
	if c(b, a) > 0 {
		return b
	}
	return a
}

// policyRule is one [policy] key.
type policyRule interface {
	name() string
	diff(old, new *Policy) (Change, bool)
	merge(dst, a, b *Policy)
}

type fieldRule[T comparable] struct {
	key  string
	ptr  func(*Policy) *T
	cmp  cmpFunc[T]
	text func(T) string
}

func (r fieldRule[T]) name() string { return r.key }

func (r fieldRule[T]) diff(old, new *Policy) (Change, bool) {
	o, n := *r.ptr(old), *r.ptr(new)
	if o == n {
		return Change{}, false
	}
	return Change{Key: "policy." + r.key, Old: r.text(o), New: r.text(n), Weakening: r.cmp(n, o) < 0}, true
}

func (r fieldRule[T]) merge(dst, a, b *Policy) { *r.ptr(dst) = stricter(r.cmp, *r.ptr(a), *r.ptr(b)) }

func durationText(d Duration) string {
	b, _ := d.MarshalText() // never fails
	return string(b)
}

func sizeText(s Size) string {
	b, _ := s.MarshalText() // never fails
	return string(b)
}

func boolText(v bool) string      { return strconv.FormatBool(v) }
func intText(v int) string        { return strconv.Itoa(v) }
func int64Text(v int64) string    { return strconv.FormatInt(v, 10) }
func stringText(v string) string  { return v }
func timeText(v time.Time) string { return v.UTC().Format(time.RFC3339Nano) }

// policyRules lists every Policy field (an internal test checks the list
// against the struct's TOML tags).
var policyRules = []policyRule{
	fieldRule[Duration]{"idle_soft", func(p *Policy) *Duration { return &p.IdleSoft }, cmpPositiveLower, durationText},
	fieldRule[Duration]{"idle_hard", func(p *Policy) *Duration { return &p.IdleHard }, cmpTimerZeroNever, durationText},
	fieldRule[Duration]{"max_unlock", func(p *Policy) *Duration { return &p.MaxUnlock }, cmpPositiveLower, durationText},
	fieldRule[bool]{"lock_on_screen_lock", func(p *Policy) *bool { return &p.LockOnScreenLock }, cmpTrue, boolText},
	fieldRule[Duration]{"screen_lock_hard_after", func(p *Policy) *Duration { return &p.ScreenLockHardAfter }, cmpTimerZeroNever, durationText},
	fieldRule[Duration]{"busy_grace", func(p *Policy) *Duration { return &p.BusyGrace }, cmpTimerZeroNever, durationText},
	fieldRule[Duration]{"busy_timeout", func(p *Policy) *Duration { return &p.BusyTimeout }, cmpPositiveLower, durationText},
	fieldRule[Duration]{"quiet_window", func(p *Policy) *Duration { return &p.QuietWindow }, cmpQuietWindow, durationText},
	fieldRule[Duration]{"hold_cap", func(p *Policy) *Duration { return &p.HoldCap }, cmpPositiveLower, durationText},
	fieldRule[int]{"restore_recent", func(p *Policy) *int { return &p.RestoreRecent }, cmpCountLower[int], intText},
	fieldRule[int64]{"restore_max_bytes", func(p *Policy) *int64 { return &p.RestoreMaxBytes }, cmpCountLower[int64], int64Text},
	fieldRule[Size]{"min_free", func(p *Policy) *Size { return &p.MinFree }, cmpMinFree, sizeText},
	fieldRule[bool]{"restore_history", func(p *Policy) *bool { return &p.RestoreHistory }, cmpFalse, boolText},
	fieldRule[bool]{"per_root_auth", func(p *Policy) *bool { return &p.PerRootAuth }, cmpTrue, boolText},
	fieldRule[bool]{"unlock_on_prompt", func(p *Policy) *bool { return &p.UnlockOnPrompt }, cmpFalse, boolText},
	fieldRule[string]{"on_enter", func(p *Policy) *string { return &p.OnEnter }, cmpRank(onEnterRank), stringText},
	fieldRule[string]{"md_seal_on", func(p *Policy) *string { return &p.MDSealOn }, cmpRank(mdSealOnRank), stringText},
	fieldRule[bool]{"clear_terminal_on_end", func(p *Policy) *bool { return &p.ClearTerminalOnEnd }, cmpTrue, boolText},
	fieldRule[bool]{"clear_scrollback_on_lock", func(p *Policy) *bool { return &p.ClearScrollbackLock }, cmpTrue, boolText},
	fieldRule[int]{"prompt_rate_per_minute", func(p *Policy) *int { return &p.PromptRatePerMinute }, cmpCountLower[int], intText},
	fieldRule[Duration]{"prompt_backoff", func(p *Policy) *Duration { return &p.PromptBackoff }, cmpDelayHigher, durationText},
	fieldRule[Duration]{"hook_prompt_cooldown", func(p *Policy) *Duration { return &p.HookPromptCooldown }, cmpDelayHigher, durationText},
}

// defaultHarnesses are the harnesses of a root whose list is empty.
var defaultHarnesses = []string{"claude-code", "codex"}

// effectiveHarnesses returns the harnesses a root manages.
func effectiveHarnesses(hs []string) []string {
	if len(hs) == 0 {
		return defaultHarnesses
	}
	return hs
}

// cmpVersion orders min_version values: "" lowest, then dotted numeric
// versions (a "-pre" suffix sorts below the release, "+build" is ignored),
// then values that do not parse (highest: the strictest requirement).
func cmpVersion(a, b string) int {
	ra, na, pa := parseVersion(a)
	rb, nb, pb := parseVersion(b)
	if ra != rb {
		return cmp.Compare(ra, rb)
	}
	if ra != 1 {
		return 0
	}
	if c := slices.Compare(padTo(na, len(nb)), padTo(nb, len(na))); c != 0 {
		return c
	}
	// Same numbers: a release outranks its pre-release.
	return cmp.Compare(b2i(!pa), b2i(!pb))
}

// parseVersion returns the rank of v (0 empty, 1 parsed, 2 unparseable),
// its numeric components and whether it carries a pre-release suffix.
func parseVersion(v string) (rank int, nums []uint64, pre bool) {
	if v == "" {
		return 0, nil, false
	}
	core := strings.TrimPrefix(v, "v")
	if i := strings.IndexByte(core, '+'); i >= 0 {
		core = core[:i]
	}
	if i := strings.IndexByte(core, '-'); i >= 0 {
		core, pre = core[:i], true
	}
	for _, part := range strings.Split(core, ".") {
		if part == "" || strings.TrimLeft(part, "0123456789") != "" {
			return 2, nil, false
		}
		n, err := strconv.ParseUint(part, 10, 64)
		if err != nil {
			return 2, nil, false
		}
		nums = append(nums, n)
	}
	return 1, nums, pre
}

func padTo(v []uint64, n int) []uint64 {
	for len(v) < n {
		v = append(v, 0)
	}
	return v
}
