package agent

import (
	"context"
	"time"

	"github.com/precinto/precinto/internal/config"
	"github.com/precinto/precinto/internal/platform"
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

// killGrace implements KillGrace: max(8 s, budget + 6 s), capped at 70 s.
func killGrace(budget time.Duration) time.Duration {
	if budget < 0 {
		budget = 0
	}
	g := budget + 6*time.Second
	if g < 8*time.Second {
		g = 8 * time.Second
	}
	if g > 70*time.Second {
		g = 70 * time.Second
	}
	return g
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

// check reports whether a prompt may be raised now and, if not, how long
// to wait. record consumes a slot when allowed.
func (r *RateLimiter) check(vault string, fromHook, record bool) (bool, time.Duration) {
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
		return false, time.Minute
	}
	if t, ok := r.lastCancel[vault]; ok && now-t < r.backoff {
		return false, r.backoff - (now - t)
	}
	if t, ok := r.lastHookCxl[vault]; fromHook && ok && now-t < r.cooldown {
		return false, r.cooldown - (now - t)
	}
	if len(kept) >= r.perMinute {
		return false, kept[0] + time.Minute - now
	}
	if record {
		r.prompts[vault] = append(kept, now)
	}
	return true, 0
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
