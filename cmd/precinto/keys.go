package main

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/precinto/precinto/internal/ipc"
	"github.com/precinto/precinto/internal/sweep"
)

// keySource implements sweep.KeySource over the daemon's keys operation
// (D39): file keys only, never identities, for logged capsules of unlocked
// folders. One connection is dialled lazily and serialized (an ipc.Client
// is not safe for concurrent requests). Every key set handed out is
// remembered so that destroy can wipe them all at once on a lock event
// (REST-8: within 2 s of the event).
type keySource struct {
	dial func(ctx context.Context) (daemonClient, error)

	callMu sync.Mutex // serializes daemon requests (one connection)
	client daemonClient

	setsMu    sync.Mutex // never held across a daemon request
	sets      []sweep.FileKeys
	destroyed bool
}

var _ sweep.KeySource = (*keySource)(nil)

// keyDeniedError reports a key release that the daemon refused. It matches
// sweep.ErrKeyDenied (exit 3) and keeps the daemon's codes for the exit
// mapping (a provenance refusal stays exit 5).
type keyDeniedError struct {
	codes []ipc.Code
	cause error
}

func (e *keyDeniedError) Error() string {
	if e.cause != nil {
		return sweep.ErrKeyDenied.Error() + ": " + e.cause.Error()
	}
	if len(e.codes) > 0 {
		return fmt.Sprintf("%s (%s)", sweep.ErrKeyDenied, e.codes[0])
	}
	return sweep.ErrKeyDenied.Error()
}

func (e *keyDeniedError) Is(target error) bool { return target == sweep.ErrKeyDenied }

func (e *keyDeniedError) Unwrap() error { return e.cause }

// exitCode is the most severe exit code among the denial codes.
func (e *keyDeniedError) exitCode() int {
	code := exitLocked
	for _, c := range e.codes {
		if x := (&ipc.Error{Code: c}).ExitCode(); x > code {
			code = x
		}
	}
	return code
}

// FileKeys asks the daemon for the file keys of paths (relative to
// CapsulesDir) with purpose (ipc.Purpose*). When some capsules are denied
// the granted keys are returned and sweep treats the missing ones as
// denied; when every capsule is denied the error matches sweep.ErrKeyDenied.
func (k *keySource) FileKeys(ctx context.Context, capsules []string, purpose string) (sweep.FileKeys, error) {
	if k.isDestroyed() {
		return nil, &keyDeniedError{codes: []ipc.Code{ipc.CodeLocked}}
	}
	k.callMu.Lock()
	defer k.callMu.Unlock()
	if k.client == nil {
		c, err := k.dial(ctx)
		if err != nil {
			return nil, &keyDeniedError{cause: err}
		}
		k.client = c
	}
	refs := make([]ipc.CapsuleRef, len(capsules))
	for i, p := range capsules {
		refs[i] = ipc.CapsuleRef{Path: p}
	}
	keys, resp, err := k.client.releaseKeys(ctx, ipc.KeysReq{Capsules: refs, Purpose: purpose})
	if err != nil {
		if keys != nil {
			keys.Destroy()
		}
		var ie *ipc.Error
		if errors.As(err, &ie) {
			return nil, &keyDeniedError{codes: []ipc.Code{ie.Code}, cause: err}
		}
		// A transport failure: the next request dials again.
		_ = k.client.Close()
		k.client = nil
		return nil, &keyDeniedError{cause: err}
	}
	if len(capsules) > 0 && len(resp.Granted) == 0 {
		if keys != nil {
			keys.Destroy()
		}
		return nil, &keyDeniedError{codes: deniedCodes(resp.Denied)}
	}
	if keys == nil {
		return nil, &keyDeniedError{codes: deniedCodes(resp.Denied)}
	}
	k.setsMu.Lock()
	defer k.setsMu.Unlock()
	if k.destroyed {
		// A lock arrived while the request was in flight.
		keys.Destroy()
		return nil, &keyDeniedError{codes: []ipc.Code{ipc.CodeLocked}}
	}
	k.sets = append(k.sets, keys)
	return keys, nil
}

func (k *keySource) isDestroyed() bool {
	k.setsMu.Lock()
	defer k.setsMu.Unlock()
	return k.destroyed
}

// deniedCodes returns the distinct codes of a denied map, sorted.
func deniedCodes(m map[string]ipc.Code) []ipc.Code {
	seen := map[ipc.Code]bool{}
	var out []ipc.Code
	for _, c := range m {
		if !seen[c] {
			seen[c] = true
			out = append(out, c)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	if len(out) == 0 {
		out = []ipc.Code{ipc.CodeLocked}
	}
	return out
}

// destroy wipes every key set handed out and refuses further releases (a
// lock event, or the end of the operation). It never waits for a request
// in flight (REST-8: keys are destroyed at once).
func (k *keySource) destroy() {
	k.setsMu.Lock()
	defer k.setsMu.Unlock()
	k.destroyed = true
	for _, s := range k.sets {
		s.Destroy()
	}
	k.sets = nil
}

// close destroys the keys and closes the connection.
func (k *keySource) close() {
	k.destroy()
	k.callMu.Lock()
	defer k.callMu.Unlock()
	if k.client != nil {
		_ = k.client.Close()
		k.client = nil
	}
}

// keys returns a key source over a daemon connection without autostart
// (nothing is unlocked when the daemon is not running).
func (a *app) keys() *keySource {
	return &keySource{dial: func(ctx context.Context) (daemonClient, error) { return a.dial(ctx, false) }}
}

// grants implements sweep.Grants over the daemon status. Any failure (no
// daemon, a status error) is returned as is: sweep then treats every folder
// as locked (R4).
func (a *app) grants() sweep.Grants {
	return func(ctx context.Context) (map[string]bool, error) {
		c, err := a.dial(ctx, false)
		if err != nil {
			return nil, err
		}
		defer c.Close()
		st, err := c.Status(ctx)
		if err != nil {
			return nil, err
		}
		return unlockedVaults(st), nil
	}
}

// unlockedVaults returns the vault ids the daemon reports unlocked.
func unlockedVaults(st ipc.StatusResp) map[string]bool {
	m := map[string]bool{}
	for _, v := range st.Vaults {
		if v.State == "unlocked" {
			m[v.VaultID] = true
		}
	}
	return m
}

// watchLocks returns a channel closed as soon as any of rootIDs (every
// folder when empty) locks, or the subscription is lost (treated as a lock,
// SPEC §15.3), and a stop function. onLock runs once, right when the channel
// closes (the caller destroys its file keys there, REST-8). If the
// subscription cannot be started the channel is closed at once: without it
// a lock could not be noticed, so the operation must not hold keys.
func (a *app) watchLocks(ctx context.Context, rootIDs []string, onLock func()) (<-chan struct{}, func()) {
	abort := make(chan struct{})
	var once sync.Once
	fire := func() {
		once.Do(func() {
			if onLock != nil {
				onLock()
			}
			close(abort)
		})
	}
	ctx, cancel := context.WithCancel(ctx)
	c, err := a.dial(ctx, false)
	if err != nil {
		cancel()
		fire()
		return abort, func() {}
	}
	events, err := c.Subscribe(ctx, ipc.SubscribeReq{RootIDs: rootIDs})
	if err != nil {
		cancel()
		_ = c.Close()
		fire()
		return abort, func() {}
	}
	watched := map[string]bool{}
	for _, id := range rootIDs {
		watched[id] = true
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-ctx.Done():
				return
			case ev, ok := <-events:
				if !ok {
					if ctx.Err() == nil {
						fire()
					}
					return
				}
				if ev.Kind == ipc.EventLocked && (len(watched) == 0 || len(ev.RootIDs) == 0 || anyWatched(watched, ev.RootIDs)) {
					fire()
					return
				}
			}
		}
	}()
	stop := func() {
		cancel()
		_ = c.Close()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
		}
	}
	return abort, stop
}

func anyWatched(watched map[string]bool, ids []string) bool {
	for _, id := range ids {
		if watched[id] {
			return true
		}
	}
	return false
}
