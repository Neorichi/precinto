package agent

import (
	"context"
	"time"

	"github.com/Neorichi/precinto/internal/config"
	"github.com/Neorichi/precinto/internal/harness"
	"github.com/Neorichi/precinto/internal/platform"
)

// clampTTL implements ClampTTL. A policy without a positive max_unlock
// (config.Validate refuses it) falls back to the default 8 h, never to
// "unlimited".
func clampTTL(p config.Policy, ttl time.Duration) time.Duration {
	max := p.MaxUnlock.D()
	if max <= 0 {
		max = config.Default().Policy.MaxUnlock.D()
	}
	if max > config.MaxUnlockCap {
		max = config.MaxUnlockCap
	}
	if ttl <= 0 || ttl > max {
		return max
	}
	return ttl
}

// killGrace implements KillGrace with harness.KillGrace (one formula for
// the daemon and the wrapper, SPEC §12.7).
func killGrace(budget time.Duration) time.Duration {
	if budget < 0 {
		budget = 0
	}
	return harness.KillGrace(budget)
}

// The RateLimiter's unexported state (agent.go declares the type):
//
//	perMinute     prompts allowed per vault per minute (0: none, D62)
//	backoff       no prompt for a vault this long after a cancel
//	cooldown      no hook-raised prompt for a vault this long after a
//	              cancel in a hook (hook_prompt_cooldown)
//	prompts       monotonic times of the prompts of the last minute
//	lastCancel    monotonic time of the vault's last cancel
//	lastHookCxl   monotonic time of the vault's last cancel in a hook
//	flights       in-flight unlocks (single-flight per vault)

// flight is one in-flight unlock of a vault; followers wait for done and
// share err.
type flight struct {
	done chan struct{}
	err  error
}

func newRateLimiter(p config.Policy, c platform.Clock) *RateLimiter {
	if c == nil {
		c = platform.SystemClock()
	}
	return &RateLimiter{
		perMinute:   p.PromptRatePerMinute,
		backoff:     p.PromptBackoff.D(),
		cooldown:    p.HookPromptCooldown.D(),
		clock:       c,
		prompts:     map[string][]time.Duration{},
		lastCancel:  map[string]time.Duration{},
		lastHookCxl: map[string]time.Duration{},
		flights:     map[string]*flight{},
	}
}

// limitWhy is the rule that refused a prompt (the text the user sees
// depends on it, UX-08).
type limitWhy uint8

const (
	limitBackoff limitWhy = iota // a recent cancel or wrong secret (backoff, hook cooldown)
	limitRate                    // the per-minute limit
	limitOff                     // no prompts at all: prompt_rate_per_minute = 0 (D62), no wait ends it
)

// check reports whether a prompt may be raised now and, if not, how long
// to wait and why. record consumes a slot when allowed.
func (r *RateLimiter) check(vault string, fromHook, record bool) (bool, time.Duration, limitWhy) {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.clock.Mono()
	kept := r.prompts[vault][:0]
	for _, t := range r.prompts[vault] {
		if now-t < time.Minute {
			kept = append(kept, t)
		}
	}
	r.prompts[vault] = kept
	if r.perMinute <= 0 {
		return false, time.Minute, limitOff
	}
	if t, ok := r.lastCancel[vault]; ok && now-t < r.backoff {
		return false, r.backoff - (now - t), limitBackoff
	}
	if t, ok := r.lastHookCxl[vault]; fromHook && ok && now-t < r.cooldown {
		return false, r.cooldown - (now - t), limitBackoff
	}
	if len(kept) >= r.perMinute {
		return false, kept[0] + time.Minute - now, limitRate
	}
	if record {
		r.prompts[vault] = append(kept, now)
	}
	return true, 0, 0
}

// perMinuteLimit is the per-minute prompt limit (C2.toomany's {n}).
func (r *RateLimiter) perMinuteLimit() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.perMinute
}

func (r *RateLimiter) cancelled(vault string, fromHook bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.clock.Mono()
	r.lastCancel[vault] = now
	if fromHook {
		r.lastHookCxl[vault] = now
	}
}

// join enters the single flight of vault: the leader runs the unlock and
// calls finish; followers get the leader's flight to wait on.
func (r *RateLimiter) join(vault string) (*flight, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if f, ok := r.flights[vault]; ok {
		return f, false
	}
	f := &flight{done: make(chan struct{})}
	r.flights[vault] = f
	return f, true
}

// inFlight reports whether an unlock of vault is in progress (status shows
// "unlocking", CC-32).
func (r *RateLimiter) inFlight(vault string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, ok := r.flights[vault]
	return ok
}

// finish ends the leader's flight with err.
func (r *RateLimiter) finish(vault string, f *flight, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.flights[vault] == f {
		delete(r.flights, vault)
	}
	f.err = err
	close(f.done)
}

// wait blocks until f ends or ctx is done.
func (f *flight) wait(ctx context.Context) error {
	select {
	case <-f.done:
		return f.err
	case <-ctx.Done():
		return ctx.Err()
	}
}
