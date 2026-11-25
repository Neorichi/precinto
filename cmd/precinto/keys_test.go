package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/awnumar/memguard"

	"github.com/Neorichi/precinto/internal/ipc"
	"github.com/Neorichi/precinto/internal/paths"
	"github.com/Neorichi/precinto/internal/sweep"
)

func TestKeySourceGrantedAndDestroy(t *testing.T) {
	e := newEnv(t)
	var sets []*fakeKeys
	e.daemon.keysFunc = func(r ipc.KeysReq) (sweep.FileKeys, ipc.KeysResp, error) {
		k := &fakeKeys{}
		for _, c := range r.Capsules {
			k.paths = append(k.paths, c.Path)
		}
		sets = append(sets, k)
		return k, ipc.KeysResp{Granted: []ipc.KeyGrant{{Path: r.Capsules[0].Path, VaultID: "root-acme"}}}, nil
	}
	a := e.app()
	ks := a.keys()
	ctx := context.Background()
	for i := 0; i < 2; i++ {
		got, err := ks.FileKeys(ctx, []string{"claude-code/u/g000001.pcap"}, ipc.PurposeRestore)
		if err != nil || got == nil {
			t.Fatalf("FileKeys: %v", err)
		}
	}
	if len(e.dials) != 1 {
		t.Fatalf("dialled %d times, want one shared connection", len(e.dials))
	}
	if e.dials[0].Autostart {
		t.Fatal("key release must not autostart (nothing is unlocked without a daemon)")
	}
	if r := e.daemon.keys[0]; r.Purpose != ipc.PurposeRestore || r.Capsules[0].Path != "claude-code/u/g000001.pcap" {
		t.Fatalf("request %+v", r)
	}
	ks.destroy()
	for i, s := range sets {
		if !s.isDestroyed() {
			t.Fatalf("set %d not destroyed", i)
		}
	}
	if _, err := ks.FileKeys(ctx, []string{"x"}, ipc.PurposeRestore); !errors.Is(err, sweep.ErrKeyDenied) {
		t.Fatalf("after destroy: %v", err)
	}
	ks.close()
	if e.daemon.closed != 1 {
		t.Fatalf("closed %d", e.daemon.closed)
	}
}

func TestKeySourceDenied(t *testing.T) {
	e := newEnv(t)
	e.daemon.keysFunc = func(r ipc.KeysReq) (sweep.FileKeys, ipc.KeysResp, error) {
		return nil, ipc.KeysResp{Denied: map[string]ipc.Code{"a": ipc.CodeLocked, "b": ipc.CodeNotLogged}}, nil
	}
	ks := e.app().keys()
	_, err := ks.FileKeys(context.Background(), []string{"a", "b"}, ipc.PurposeCat)
	if !errors.Is(err, sweep.ErrKeyDenied) {
		t.Fatalf("err %v", err)
	}
	if exitFor(err) != exitVerify {
		t.Fatalf("a not_logged denial must stay exit 5, got %d", exitFor(err))
	}

	e = newEnv(t) // the daemon refuses the whole request
	e.daemon.keysFunc = func(r ipc.KeysReq) (sweep.FileKeys, ipc.KeysResp, error) {
		return nil, ipc.KeysResp{}, &ipc.Error{Code: ipc.CodeAgentContext}
	}
	_, err = e.app().keys().FileKeys(context.Background(), []string{"a"}, ipc.PurposeOpen)
	if !errors.Is(err, sweep.ErrKeyDenied) || exitFor(err) != exitLocked {
		t.Fatalf("err %v exit %d", err, exitFor(err))
	}

	e = newEnv(t) // no daemon
	e.dialErr = ipc.ErrNoDaemon
	_, err = e.app().keys().FileKeys(context.Background(), []string{"a"}, ipc.PurposeRestore)
	if !errors.Is(err, sweep.ErrKeyDenied) || exitFor(err) != exitLocked {
		t.Fatalf("err %v exit %d", err, exitFor(err))
	}
}

// Partly denied: the granted keys come back; sweep treats the rest as
// denied (they have no key in the set).
func TestKeySourcePartlyDenied(t *testing.T) {
	e := newEnv(t)
	k := &fakeKeys{}
	e.daemon.keysFunc = func(r ipc.KeysReq) (sweep.FileKeys, ipc.KeysResp, error) {
		return k, ipc.KeysResp{Granted: []ipc.KeyGrant{{Path: "a"}}, Denied: map[string]ipc.Code{"b": ipc.CodeLocked}}, nil
	}
	got, err := e.app().keys().FileKeys(context.Background(), []string{"a", "b"}, ipc.PurposeRestore)
	if err != nil || got != sweep.FileKeys(k) {
		t.Fatalf("got %v err %v", got, err)
	}
}

func TestGrants(t *testing.T) {
	e := newEnv(t)
	e.daemon.status = ipc.StatusResp{Vaults: []ipc.VaultStatus{{VaultID: "root-acme", State: "unlocked"}, {VaultID: "root-b", State: "locked"}}}
	m, err := e.app().grants()(context.Background())
	if err != nil || !m["root-acme"] || m["root-b"] {
		t.Fatalf("grants %v err %v", m, err)
	}
	e = newEnv(t)
	e.dialErr = ipc.ErrNoDaemon
	if _, err := e.app().grants()(context.Background()); err == nil {
		t.Fatal("no daemon must be an error (sweep then treats every folder as locked)")
	}
}

// watchLocks closes its channel (and destroys keys) on a lock of a watched
// folder, and at once when no subscription can be made. The first event of
// each subscribed folder is its state when the subscription starts (D71),
// not a lock during the operation: a folder locked then is refused by the
// key request. Watching every folder there is no such event (D153).
func TestWatchLocks(t *testing.T) {
	e := newEnv(t)
	e.daemon.events = make(chan ipc.Event, 4)
	a := e.app()
	fired := make(chan struct{})
	abort, stop := a.watchLocks(context.Background(), []string{"root-acme"}, func() { close(fired) })
	defer stop()
	e.daemon.events <- ipc.Event{Kind: ipc.EventUnlocked, RootIDs: []string{"root-acme"}} // initial state
	e.daemon.events <- ipc.Event{Kind: ipc.EventLocked, RootIDs: []string{"root-beta"}}   // not watched
	e.daemon.events <- ipc.Event{Kind: ipc.EventLocked, RootIDs: []string{"root-acme"}}
	select {
	case <-abort:
	case <-time.After(2 * time.Second):
		t.Fatal("abort not closed within 2 s of the lock (REST-8)")
	}
	<-fired

	// Locked when the subscription starts: no abort; a later lock aborts.
	e = newEnv(t)
	e.daemon.events = make(chan ipc.Event, 4)
	abort, stop = e.app().watchLocks(context.Background(), []string{"root-acme"}, nil)
	defer stop()
	e.daemon.events <- ipc.Event{Kind: ipc.EventLocked, RootIDs: []string{"root-acme"}} // initial state
	select {
	case <-abort:
		t.Fatal("the initial locked state of the folder aborted the operation (D71)")
	case <-time.After(200 * time.Millisecond):
	}
	e.daemon.events <- ipc.Event{Kind: ipc.EventUnlocked, RootIDs: []string{"root-acme"}}
	e.daemon.events <- ipc.Event{Kind: ipc.EventLocked, RootIDs: []string{"root-acme"}}
	select {
	case <-abort:
	case <-time.After(2 * time.Second):
		t.Fatal("a lock after the initial state did not abort")
	}

	// Watching every folder (open, restore --session outside a folder): no
	// folder gets an initial state event (D71 sends them only for the
	// folders named), so the first locked event of a folder is a lock
	// during the operation (D153); an unlocked one is not.
	e = newEnv(t)
	e.daemon.events = make(chan ipc.Event, 2)
	abort, stop = e.app().watchLocks(context.Background(), nil, nil)
	defer stop()
	e.daemon.events <- ipc.Event{Kind: ipc.EventUnlocked, RootIDs: []string{"root-beta"}}
	select {
	case <-abort:
		t.Fatal("an unlocked event aborted the operation")
	case <-time.After(200 * time.Millisecond):
	}
	e.daemon.events <- ipc.Event{Kind: ipc.EventLocked, RootIDs: []string{"root-acme"}}
	select {
	case <-abort:
	case <-time.After(2 * time.Second):
		t.Fatal("the first lock of a folder while watching every folder did not abort (REST-8)")
	}

	// A lock event naming no folder locks every folder.
	e = newEnv(t)
	e.daemon.events = make(chan ipc.Event, 1)
	abort, stop = e.app().watchLocks(context.Background(), nil, nil)
	defer stop()
	e.daemon.events <- ipc.Event{Kind: ipc.EventLocked}
	select {
	case <-abort:
	case <-time.After(2 * time.Second):
		t.Fatal("a lock of every folder did not abort")
	}

	e = newEnv(t)
	e.dialErr = ipc.ErrNoDaemon
	abort, stop = e.app().watchLocks(context.Background(), nil, nil)
	defer stop()
	select {
	case <-abort:
	default:
		t.Fatal("without a subscription the operation must not hold keys")
	}
}

// The daemon environment is an allowlist: agent markers and loader
// variables never pass; layout overrides only when honoured (D6).
func TestDaemonEnvAllowlist(t *testing.T) {
	e := paths.FromMap(map[string]string{
		"HOME": "/h", "PATH": "/usr/bin", "CLAUDECODE": "1", "DYLD_INSERT_LIBRARIES": "/x.dylib",
		"LD_PRELOAD": "/x.so", "CLAUDE_CONFIG_DIR": "/c", "PRECINTO_HOME": "/p",
	})
	got := map[string]bool{}
	for _, kv := range daemonEnv(e) {
		got[kv] = true
	}
	for _, bad := range []string{"CLAUDECODE=1", "DYLD_INSERT_LIBRARIES=/x.dylib", "LD_PRELOAD=/x.so", "CLAUDE_CONFIG_DIR=/c"} {
		if got[bad] {
			t.Errorf("%s passed to the daemon", bad)
		}
	}
	if !got["HOME=/h"] || !got["PATH=/usr/bin"] {
		t.Errorf("missing HOME/PATH: %v", got)
	}
	if got["PRECINTO_HOME=/p"] != paths.OverridesAllowed(e) {
		t.Errorf("PRECINTO_HOME passed=%v, overrides allowed=%v", got["PRECINTO_HOME=/p"], paths.OverridesAllowed(e))
	}
	// D64: the test ancestry stop passes only in -tags testing builds.
	stop := paths.EnvTestAncestryStop + "=123:456"
	passed := false
	for _, kv := range daemonEnv(e.With(paths.EnvTestAncestryStop, "123:456")) {
		passed = passed || kv == stop
	}
	if passed != paths.TestingBuild() {
		t.Errorf("%s passed=%v in a testing build=%v", stop, passed, paths.TestingBuild())
	}
}

func TestHarnessEnvDropsPrecintoAndLoader(t *testing.T) {
	e := paths.FromMap(map[string]string{"HOME": "/h", "PRECINTO_HOME": "/p", "DYLD_X": "1", "LD_Y": "1", "CLAUDE_CONFIG_DIR": "/c"})
	got := harnessEnv(e)
	want := []string{"CLAUDE_CONFIG_DIR=/c", "HOME=/h"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("got %v", got)
	}
}

// A lock during a key request in flight destroys the keys at once: the
// request's keys are wiped when it returns (REST-8).
func TestKeySourceDestroyDuringRequest(t *testing.T) {
	e := newEnv(t)
	release, started := make(chan struct{}), make(chan struct{})
	k := &fakeKeys{}
	e.daemon.keysFunc = func(r ipc.KeysReq) (sweep.FileKeys, ipc.KeysResp, error) {
		close(started)
		<-release
		return k, ipc.KeysResp{Granted: []ipc.KeyGrant{{Path: "a"}}}, nil
	}
	ks := e.app().keys()
	done := make(chan error, 1)
	go func() {
		_, err := ks.FileKeys(context.Background(), []string{"a"}, ipc.PurposeRestore)
		done <- err
	}()
	<-started // the request is in flight
	destroyed := make(chan struct{})
	go func() { ks.destroy(); close(destroyed) }()
	select {
	case <-destroyed:
	case <-time.After(2 * time.Second):
		t.Fatal("destroy waited for the request in flight")
	}
	close(release)
	if err := <-done; !errors.Is(err, sweep.ErrKeyDenied) {
		t.Fatalf("err %v", err)
	}
	if !k.isDestroyed() {
		t.Fatal("keys of the request in flight survived the lock")
	}
}

// A transport failure drops the connection; the next request dials again.
func TestKeySourceRedialsAfterTransportError(t *testing.T) {
	e := newEnv(t)
	calls := 0
	e.daemon.keysFunc = func(r ipc.KeysReq) (sweep.FileKeys, ipc.KeysResp, error) {
		calls++
		if calls == 1 {
			return nil, ipc.KeysResp{}, errors.New("broken pipe")
		}
		return &fakeKeys{}, ipc.KeysResp{Granted: []ipc.KeyGrant{{Path: "a"}}}, nil
	}
	ks := e.app().keys()
	if _, err := ks.FileKeys(context.Background(), []string{"a"}, ipc.PurposeRestore); err == nil {
		t.Fatal("transport error swallowed")
	}
	if _, err := ks.FileKeys(context.Background(), []string{"a"}, ipc.PurposeRestore); err != nil {
		t.Fatalf("second request: %v", err)
	}
	if len(e.dials) != 2 {
		t.Fatalf("dials %d, want a redial", len(e.dials))
	}
}

// CC-17: a key request names at most ipc.MaxKeysPerRequest capsules; the
// adapter splits a longer list, merges the granted sets and destroys every
// batch at a lock.
func TestKeySourceBatches(t *testing.T) {
	e := newEnv(t)
	var sets []*pathKeys
	e.daemon.keysFunc = func(r ipc.KeysReq) (sweep.FileKeys, ipc.KeysResp, error) {
		k := &pathKeys{paths: map[string]bool{}}
		var resp ipc.KeysResp
		for _, c := range r.Capsules {
			k.paths[c.Path] = true
			resp.Granted = append(resp.Granted, ipc.KeyGrant{Path: c.Path, VaultID: "root-acme"})
		}
		sets = append(sets, k)
		return k, resp, nil
	}
	ks := e.app().keys()
	var paths []string
	for i := 0; i < 2*ipc.MaxKeysPerRequest+3; i++ {
		paths = append(paths, fmt.Sprintf("codex/%032x/g%06d.pcap", i, 1))
	}
	got, err := ks.FileKeys(context.Background(), paths, ipc.PurposeRestore)
	if err != nil {
		t.Fatal(err)
	}
	if len(e.daemon.keys) != 3 {
		t.Fatalf("%d requests for %d capsules, want 3", len(e.daemon.keys), len(paths))
	}
	for i, r := range e.daemon.keys {
		if len(r.Capsules) > ipc.MaxKeysPerRequest {
			t.Fatalf("request %d names %d capsules", i, len(r.Capsules))
		}
	}
	for _, p := range []string{paths[0], paths[ipc.MaxKeysPerRequest], paths[len(paths)-1]} {
		if _, ok := got.Key(p); !ok {
			t.Errorf("no key for %s in the merged set", p)
		}
	}
	ks.destroy()
	for i, s := range sets {
		if !s.destroyed {
			t.Errorf("batch %d survived the lock", i)
		}
	}

	// A refusal of a later batch fails the call and wipes the earlier ones.
	e = newEnv(t)
	sets = nil
	n := 0
	e.daemon.keysFunc = func(r ipc.KeysReq) (sweep.FileKeys, ipc.KeysResp, error) {
		n++
		if n == 2 {
			return nil, ipc.KeysResp{}, &ipc.Error{Code: ipc.CodeAgentContext, Msg: "refused"}
		}
		k := &pathKeys{paths: map[string]bool{}}
		sets = append(sets, k)
		return k, ipc.KeysResp{Granted: []ipc.KeyGrant{{Path: r.Capsules[0].Path}}}, nil
	}
	ks = e.app().keys()
	if _, err := ks.FileKeys(context.Background(), paths, ipc.PurposeRestore); !errors.Is(err, sweep.ErrKeyDenied) || exitFor(err) != exitLocked {
		t.Fatalf("refused batch: %v (exit %d)", err, exitFor(err))
	}
	if len(sets) != 1 || !sets[0].destroyed {
		t.Fatal("the first batch's keys survived a refused second batch")
	}
}

// CC-11: unlock and key requests carry the client's own agent markers (a
// self-restricting claim); without markers nothing is added.
func TestAgentMarkersInRequests(t *testing.T) {
	e := newEnv(t)
	e.h.Env = e.h.Env.With("CLAUDECODE", "1").With("CLAUDE_CODE_ENTRYPOINT", "cli")
	e.daemon.keysFunc = func(r ipc.KeysReq) (sweep.FileKeys, ipc.KeysResp, error) {
		return &fakeKeys{}, ipc.KeysResp{Granted: []ipc.KeyGrant{{Path: "a"}}}, nil
	}
	if code := e.run("unlock"); code != exitOK {
		t.Fatalf("unlock: exit %d (%s)", code, e.stderr())
	}
	ks := e.app().keys()
	if _, err := ks.FileKeys(context.Background(), []string{"a"}, ipc.PurposeRestore); err != nil {
		t.Fatal(err)
	}
	want := paths.AgentMarkers(e.h.Env)
	if len(want) != 2 {
		t.Fatalf("markers %v", want)
	}
	if got := e.daemon.unlocks[0].AgentMarkers; strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("unlock markers %v, want %v", got, want)
	}
	if got := e.daemon.keys[0].AgentMarkers; strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("keys markers %v, want %v", got, want)
	}
	// The wrapper's own unlock (from the overlay) goes through the same
	// client: backend.Daemon.
	b := newBackend(e.app(), e.eng)
	d, err := b.Daemon(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.Unlock(context.Background(), ipc.UnlockReq{RootIDs: []string{"root-acme"}}, headlessUI{}); err != nil {
		t.Fatal(err)
	}
	if got := e.daemon.unlocks[1].AgentMarkers; strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("wrapper unlock markers %v", got)
	}

	e = newEnv(t)
	if code := e.run("unlock"); code != exitOK {
		t.Fatalf("unlock: exit %d", code)
	}
	if got := e.daemon.unlocks[0].AgentMarkers; len(got) != 0 {
		t.Errorf("markers %v without any in the environment", got)
	}
}

// pathKeys is a released key set that knows its paths.
type pathKeys struct {
	paths     map[string]bool
	destroyed bool
}

func (k *pathKeys) Key(p string) (*memguard.LockedBuffer, bool) {
	if k.destroyed || !k.paths[p] {
		return nil, false
	}
	return memguard.NewBuffer(32), true
}

func (k *pathKeys) Destroy() { k.destroyed = true }
