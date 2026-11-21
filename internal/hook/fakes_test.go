package hook_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"sync"

	"github.com/precinto/precinto/internal/hook"
	"github.com/precinto/precinto/internal/ipc"
	"github.com/precinto/precinto/internal/ledger"
	"github.com/precinto/precinto/internal/sweep/queue"
)

// fakeLedger is an in-memory hook.Ledger with a minimal fold of the rules
// the hook relies on (taint, cwds, compaction, wrapper, hooks seen).
type fakeLedger struct {
	mu       sync.Mutex
	events   map[string][]ledger.Event
	appended []ledger.Event
	getErr   error
	hang     <-chan struct{}
	panicGet bool
}

func newFakeLedger(existing []ledger.Event) *fakeLedger {
	f := &fakeLedger{events: map[string][]ledger.Event{}}
	for _, e := range existing {
		k := e.Harness + "/" + e.SID
		f.events[k] = append(f.events[k], e)
	}
	return f
}

func (f *fakeLedger) Append(e ledger.Event) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.appended = append(f.appended, e)
	k := e.Harness + "/" + e.SID
	f.events[k] = append(f.events[k], e)
	return nil
}

func (f *fakeLedger) Get(harness, sid string) (ledger.Session, error) {
	if f.hang != nil {
		<-f.hang
	}
	if f.panicGet {
		panic("fake ledger: Get")
	}
	if f.getErr != nil {
		return ledger.Session{}, f.getErr
	}
	f.mu.Lock()
	evs := slices.Clone(f.events[harness+"/"+sid])
	f.mu.Unlock()
	if len(evs) == 0 {
		return ledger.Session{}, ledger.ErrNotFound
	}
	return foldLedger(harness, sid, evs), nil
}

func (f *fakeLedger) Appended() []ledger.Event {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.appended)
}

func foldLedger(harness, sid string, evs []ledger.Event) ledger.Session {
	s := ledger.Session{Harness: harness, SID: sid}
	for _, e := range evs {
		switch e.Type {
		case ledger.TypeLaunch:
			s.Wrapper = s.Wrapper || e.Wrapper
			s.CurrentProc = e.Proc
		case ledger.TypeStart:
			s.CurrentProc = e.Proc
			if e.Cwd != "" {
				s.Cwds = append(s.Cwds, e.Cwd)
			}
		case ledger.TypeTaint:
			for _, r := range e.Roots {
				if !slices.Contains(s.RootIDs, r) {
					s.RootIDs = append(s.RootIDs, r)
				}
			}
		case ledger.TypeCwd:
			s.Cwds = append(s.Cwds, e.Cwd)
		case ledger.TypeDir:
			s.Dirs = append(s.Dirs, e.Path)
		case ledger.TypeMarkdown:
			s.Markdown = append(s.Markdown, e.Path)
		case ledger.TypeCompactBegin:
			s.Compacting = true
		case ledger.TypeCompactEnd:
			s.Compacting = false
		case ledger.TypeEnd:
			s.Ended, s.EndReason, s.Compacting = true, e.Reason, false
		case ledger.TypeHooksSeen:
			s.HooksSeen = true
		}
	}
	return s
}

// daemonSpec scripts the fake daemon of a golden case; a nil spec is an
// unreachable daemon.
type daemonSpec struct {
	// DialError: "untrusted" (ipc.ErrUntrustedServer), "timeout" (no answer
	// within the gate budget: ipc.ErrNoDaemon wrapping the deadline, as
	// ipc.Dial reports it), "version" (a daemon speaking another protocol,
	// CodeVersion), anything else ipc.ErrNoDaemon.
	DialError   string          `json:"dial_error,omitempty"`
	Gate        *ipc.GateResp   `json:"gate,omitempty"`
	Regate      *ipc.GateResp   `json:"regate,omitempty"`
	GateError   string          `json:"gate_error,omitempty"` // an ipc.Code
	Hang        bool            `json:"hang,omitempty"`
	Panic       bool            `json:"panic,omitempty"`
	Unlock      *ipc.UnlockResp `json:"unlock,omitempty"`
	UnlockError string          `json:"unlock_error,omitempty"` // an ipc.Code
}

// call is one recorded daemon request.
type call struct {
	Op  string          `json:"op"`
	Req json.RawMessage `json:"req"`
}

// recorder collects daemon calls, queue requests and spawned workers.
type recorder struct {
	mu     sync.Mutex
	calls  []call
	queue  []queue.Request
	spawns [][]string
}

func (r *recorder) record(op string, req any) {
	b, err := json.Marshal(req)
	if err != nil {
		panic(err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, call{Op: op, Req: b})
}

func (r *recorder) Calls() []call {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.calls)
}

func (r *recorder) Queue() []queue.Request {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.queue)
}

func (r *recorder) Spawns() [][]string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.spawns)
}

func (r *recorder) enqueue(q queue.Request) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.queue = append(r.queue, q)
	return "req-1", nil
}

func (r *recorder) spawn(argv []string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.spawns = append(r.spawns, slices.Clone(argv))
	return nil
}

// dialer returns the Dial function of a fake daemon following spec.
func (r *recorder) dialer(spec *daemonSpec, gates *int) func(context.Context) (hook.Daemon, error) {
	return func(ctx context.Context) (hook.Daemon, error) {
		if spec == nil {
			return nil, ipc.ErrNoDaemon
		}
		switch spec.DialError {
		case "":
		case "untrusted":
			return nil, ipc.ErrUntrustedServer
		case "timeout":
			return nil, fmt.Errorf("%w (%v)", ipc.ErrNoDaemon, context.DeadlineExceeded)
		case "version":
			return nil, &ipc.Error{Code: ipc.CodeVersion, Msg: "fake: another protocol version"}
		default:
			return nil, ipc.ErrNoDaemon
		}
		return &fakeDaemon{spec: spec, rec: r, gates: gates}, nil
	}
}

type fakeDaemon struct {
	spec  *daemonSpec
	rec   *recorder
	gates *int // gate calls across connections (the unlock path re-gates)
}

func (d *fakeDaemon) Gate(ctx context.Context, r ipc.GateReq) (ipc.GateResp, error) {
	d.rec.record("gate", r)
	if d.spec.Panic {
		panic("fake daemon: Gate")
	}
	if d.spec.Hang {
		<-ctx.Done()
		return ipc.GateResp{}, ctx.Err()
	}
	if d.spec.GateError != "" {
		return ipc.GateResp{}, &ipc.Error{Code: ipc.Code(d.spec.GateError), Msg: "fake"}
	}
	*d.gates++
	if *d.gates > 1 && d.spec.Regate != nil {
		return *d.spec.Regate, nil
	}
	if d.spec.Gate == nil {
		return ipc.GateResp{}, &ipc.Error{Code: ipc.CodeInternal, Msg: "fake: no gate answer"}
	}
	return *d.spec.Gate, nil
}

func (d *fakeDaemon) Activity(ctx context.Context, r ipc.ActivityReq) error {
	d.rec.record("activity", r)
	return nil
}

func (d *fakeDaemon) Register(ctx context.Context, r ipc.RegisterReq) error {
	d.rec.record("register", r)
	return nil
}

func (d *fakeDaemon) Unlock(ctx context.Context, r ipc.UnlockReq, ui ipc.UIHandler) (ipc.UnlockResp, error) {
	d.rec.record("unlock", r)
	if d.spec.UnlockError != "" {
		return ipc.UnlockResp{}, &ipc.Error{Code: ipc.Code(d.spec.UnlockError), Msg: "fake"}
	}
	if d.spec.Unlock == nil {
		return ipc.UnlockResp{}, &ipc.Error{Code: ipc.CodeNoUI, Msg: "fake: no unlock answer"}
	}
	return *d.spec.Unlock, nil
}

func (d *fakeDaemon) Close() error { return nil }

// fakeApplyPatchPaths mirrors the contract of codex.ApplyPatchPaths (G3):
// the paths of the "*** Add File:", "*** Update File:" and "*** Move to:"
// headers, resolved against cwd.
func fakeApplyPatchPaths(patch []byte, cwd string) []string {
	var out []string
	for _, line := range strings.Split(string(patch), "\n") {
		for _, h := range []string{"*** Add File: ", "*** Update File: ", "*** Move to: "} {
			if rest, ok := strings.CutPrefix(line, h); ok {
				p := strings.TrimSpace(rest)
				if !filepath.IsAbs(p) {
					p = filepath.Join(cwd, p)
				}
				out = append(out, filepath.Clean(p))
			}
		}
	}
	return out
}

var errFakeLedger = errors.New("fake ledger: unreadable")
