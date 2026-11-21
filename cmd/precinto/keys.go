package main

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/awnumar/memguard"

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
// CapsulesDir) with purpose (ipc.Purpose*), in requests of at most
// ipc.MaxKeysPerRequest capsules (CC-17). When some capsules are denied the
// granted keys are returned and sweep treats the missing ones as denied;
// when every capsule is denied the error matches sweep.ErrKeyDenied. A
// refusal of any batch (an ipc error) fails the whole call and destroys
// the keys the earlier batches released.
func (k *keySource) FileKeys(ctx context.Context, capsules []string, purpose string) (sweep.FileKeys, error) {
	if k.isDestroyed() {
		return nil, &keyDeniedError{codes: []ipc.Code{ipc.CodeLocked}}
	}
	if len(capsules) == 0 {
		return multiKeys(nil), nil // nothing to release
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
	var got multiKeys
	granted := 0
	denied := map[string]ipc.Code{}
	for start := 0; start < len(capsules); start += ipc.MaxKeysPerRequest {
		end := min(start+ipc.MaxKeysPerRequest, len(capsules))
		refs := make([]ipc.CapsuleRef, 0, end-start)
		for _, p := range capsules[start:end] {
			refs = append(refs, ipc.CapsuleRef{Path: p})
		}
		keys, resp, err := k.client.releaseKeys(ctx, ipc.KeysReq{Capsules: refs, Purpose: purpose})
		if err != nil {
			if keys != nil {
				keys.Destroy()
			}
			got.Destroy()
			var ie *ipc.Error
			if errors.As(err, &ie) {
				return nil, &keyDeniedError{codes: []ipc.Code{ie.Code}, cause: err}
			}
			// A transport failure: the next request dials again.
			_ = k.client.Close()
			k.client = nil
			return nil, &keyDeniedError{cause: err}
		}
		for p, c := range resp.Denied {
			denied[p] = c
		}
		if keys != nil {
			if len(resp.Granted) == 0 {
				keys.Destroy()
			} else if !k.keep(keys) {
				// A lock arrived while the request was in flight: destroy
				// wiped the earlier batches already.
				keys.Destroy()
				return nil, &keyDeniedError{codes: []ipc.Code{ipc.CodeLocked}}
			} else {
				got = append(got, keys)
				granted += len(resp.Granted)
			}
		}
	}
	if granted == 0 || len(got) == 0 {
		got.Destroy()
		return nil, &keyDeniedError{codes: deniedCodes(denied)}
	}
	if len(got) == 1 {
		return got[0], nil
	}
	return got, nil
}

// keep remembers a released key set for destroy; false (and nothing kept)
// once the source was destroyed.
func (k *keySource) keep(keys sweep.FileKeys) bool {
	k.setsMu.Lock()
	defer k.setsMu.Unlock()
	if k.destroyed {
		return false
	}
	k.sets = append(k.sets, keys)
	return true
}

// multiKeys is the key sets of one FileKeys call that needed several
// requests; each set is also remembered by the source, so destroy wipes
// them however the caller holds them.
type multiKeys []sweep.FileKeys

func (m multiKeys) Key(path string) (*memguard.LockedBuffer, bool) {
	for _, s := range m {
		if b, ok := s.Key(path); ok {
			return b, true
		}
	}
	return nil, false
}

func (m multiKeys) Destroy() {
	for _, s := range m {
		s.Destroy()
	}
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
//
// A subscription starts with one locked or unlocked event per folder, its
// state at that moment (D71): that first event is not a lock during the
// operation. A folder locked at the start is refused by the key request
// itself (exit 3, C3); only a later locked event aborts.
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
		seen := map[string]bool{} // folders whose initial state arrived (D71)
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
				if lockedDuring(ev, watched, seen) {
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

// lockedDuring reports whether ev locks a watched folder after its initial
// state event, recording the folders whose state ev reports in seen. An
// event naming no folder applies to every folder and is never an initial
// state.
func lockedDuring(ev ipc.Event, watched, seen map[string]bool) bool {
	if ev.Kind != ipc.EventLocked && ev.Kind != ipc.EventUnlocked {
		return false
	}
	if len(ev.RootIDs) == 0 {
		return ev.Kind == ipc.EventLocked
	}
	locked := false
	for _, id := range ev.RootIDs {
		if len(watched) > 0 && !watched[id] {
			continue
		}
		first := !seen[id]
		seen[id] = true
		if ev.Kind == ipc.EventLocked && !first {
			locked = true
		}
	}
	return locked
}
