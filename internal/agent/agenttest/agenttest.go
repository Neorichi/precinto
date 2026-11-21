package agenttest

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/awnumar/memguard"

	"github.com/precinto/precinto/internal/agent"
	"github.com/precinto/precinto/internal/ipc"
	"github.com/precinto/precinto/internal/paths"
	"github.com/precinto/precinto/internal/platform"
	"github.com/precinto/precinto/internal/platform/fakeplatform"
)

// Agent is a running in-process daemon.
type Agent struct {
	Layout paths.Layout
	Clock  *fakeplatform.Clock
	Procs  *fakeplatform.Procs

	stop    func()
	done    chan error
	once    sync.Once
	mu      sync.Mutex
	screen  platform.ScreenState
	spawned [][]string
	nextPID int
}

// tick is the polling period of the in-process daemon: deadlines follow the
// fake clock, but a test that advances it sees the effect within a few ms.
const tick = 10 * time.Millisecond

// errNoPinentry is the agenttest pinentry: it never runs a program.
var errNoPinentry = errors.New("agenttest: pinentry is not available in tests")

// Start runs agent.Run on l in a goroutine and waits until it listens. It
// sets every agent.Options seam: Harden is a no-op (the go test binary is
// never hardened), Spawn records worker argv without executing anything
// (see Spawned), Screen returns the state set with SetScreen (unlocked,
// HID idle unknown by default), and Pinentry is a stub that always fails,
// so no pinentry program can run from a test whatever process table is
// used (the daemon reports vault.ErrNoUI, ipc.CodeNoUI).
func Start(t testing.TB, l paths.Layout, clock *fakeplatform.Clock, procs *fakeplatform.Procs) *Agent {
	t.Helper()
	if clock == nil {
		clock = fakeplatform.NewClock(time.Date(2026, 11, 21, 9, 0, 0, 0, time.UTC))
	}
	if procs == nil {
		procs = fakeplatform.NewProcs()
	}
	if err := l.EnsureDirs(); err != nil {
		t.Fatalf("agenttest: %v", err)
	}
	a := &Agent{Layout: l, Clock: clock, Procs: procs, done: make(chan error, 1),
		screen: platform.ScreenState{LockKnown: true}, nextPID: 900000}
	ctx, cancel := context.WithCancel(context.Background())
	a.stop = cancel
	o := agent.Options{
		Layout:  l,
		Env:     paths.FromMap(map[string]string{"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", paths.EnvHome: l.Base, paths.EnvRuntimeDir: l.RunDir}),
		Exe:     filepath.Join(l.Base, "bin", "precinto"), // never executed: Spawn only records
		Version: "agenttest",
		Clock:   clock,
		Procs:   procs,
		// The daemon never exits on idle under test: Stop ends it.
		IdleExit: 100 * 365 * 24 * time.Hour,
		Tick:     tick,
		Spawn:    a.spawn,
		Screen:   a.readScreen,
		Harden:   func() error { return nil },
		Pinentry: func(context.Context, string, string) (*memguard.LockedBuffer, error) {
			return nil, errNoPinentry
		},
	}
	go func() { a.done <- agent.Run(ctx, o) }()
	t.Cleanup(a.Stop)
	deadline := time.Now().Add(10 * time.Second)
	for {
		select {
		case err := <-a.done:
			a.done <- err
			t.Fatalf("agenttest: agent stopped while starting: %v", err)
		default:
		}
		if st, err := os.Lstat(l.Socket); err == nil && st.Mode()&os.ModeSocket != 0 {
			if c, err := a.dial(); err == nil {
				c.Close()
				return a
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("agenttest: agent did not start listening")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func (a *Agent) dial() (*ipc.Client, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return ipc.Dial(ctx, ipc.DialOptions{Layout: a.Layout, Client: "test", Timeout: 5 * time.Second, Insecure: true})
}

// Client is a non-fatal dial for fake backends and other goroutines: it
// never calls t.Fatalf, so it is safe after the test ended (it then fails
// with an error). The caller closes the client.
func (a *Agent) Client(ctx context.Context) (*ipc.Client, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return ipc.Dial(ctx, ipc.DialOptions{Layout: a.Layout, Client: "test", Timeout: 5 * time.Second, Insecure: true})
}

// UnlockForTest unlocks rootIDs with the recovery factor, answering the
// relayed secret prompt with recoveryKey (test-only; vaulttest
// Fixture.Recovery.String()). It fails the test on any error, so call it
// from the test goroutine.
func (a *Agent) UnlockForTest(t testing.TB, rootIDs []string, recoveryKey string) {
	t.Helper()
	c, err := a.Client(context.Background())
	if err != nil {
		t.Fatalf("agenttest: dial: %v", err)
	}
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	// The deadline is wall time, like a real client's: the daemon bounds
	// prompts with the real clock, whatever the fake clock says.
	req := ipc.UnlockReq{RootIDs: rootIDs, Factor: "recovery", TTY: true, Confirmed: len(rootIDs) > 1, Deadline: time.Now().Add(time.Minute)}
	if _, err := c.Unlock(ctx, req, recoveryAnswer{key: recoveryKey}); err != nil {
		t.Fatalf("agenttest: unlock %v: %v", rootIDs, err)
	}
}

// recoveryAnswer answers the relayed prompts of a recovery unlock.
type recoveryAnswer struct{ key string }

func (recoveryAnswer) Display(string) error { return nil }
func (r recoveryAnswer) Secret(string) (*memguard.LockedBuffer, error) {
	return memguard.NewBufferFromBytes([]byte(r.key)), nil
}
func (recoveryAnswer) Confirm(string, string, string) (bool, error) { return true, nil }

// Dial returns a client connected to the agent. It calls t.Fatalf on
// failure, so call it from the test goroutine only; other goroutines (fake
// backends) use Client.
func (a *Agent) Dial(t testing.TB) *ipc.Client {
	t.Helper()
	c, err := a.dial()
	if err != nil {
		t.Fatalf("agenttest: dial: %v", err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

// Spawned returns the argv of every worker the agent asked to spawn, in
// order. Workers name the folder by its absolute path (--root takes a path
// only): `<Exe> sweep --lock --root <abs path>`, `<Exe> restore --root <abs
// path> --recent N --md --history --background`.
func (a *Agent) Spawned() [][]string {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([][]string, len(a.spawned))
	for i, argv := range a.spawned {
		out[i] = append([]string(nil), argv...)
	}
	return out
}

// SetScreen sets what the agent's next console poll observes.
func (a *Agent) SetScreen(s platform.ScreenState) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.screen = s
}

// Stop stops the agent and waits for it.
func (a *Agent) Stop() {
	a.once.Do(func() {
		a.stop()
		select {
		case <-a.done:
		case <-time.After(10 * time.Second):
		}
	})
}

// spawn records a worker and returns a made-up identity (never in Procs:
// nothing runs).
func (a *Agent) spawn(argv []string, _ platform.SpawnOptions) (platform.ProcID, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.spawned = append(a.spawned, append([]string(nil), argv...))
	a.nextPID++
	return platform.ProcID{PID: a.nextPID, StartUS: a.Clock.Now().UnixMicro()}, nil
}

func (a *Agent) readScreen(ctx context.Context) (platform.ScreenState, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	s := a.screen
	s.At = a.Clock.Now()
	return s, ctx.Err()
}
