package wrapper

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/precinto/precinto/internal/ipc"
)

// ctlConn is the wrapper's request connection to the daemon (register,
// activity, unlock, unregister). ipc.Client is not safe for concurrent
// requests, so requests are serialised; the subscription uses a connection
// of its own. A transport failure drops the connection and the next request
// dials again (the daemon may have restarted).
type ctlConn struct {
	mu sync.Mutex
	b  Backend
	d  Daemon
}

func (c *ctlConn) do(ctx context.Context, f func(Daemon) error) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.d == nil {
		d, err := c.b.Daemon(ctx)
		if err != nil {
			return err
		}
		if d == nil {
			return ipc.ErrNoDaemon
		}
		c.d = d
	}
	err := f(c.d)
	var ie *ipc.Error
	if err != nil && !errors.As(err, &ie) {
		_ = c.d.Close()
		c.d = nil
	}
	return err
}

func (c *ctlConn) close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.d != nil {
		_ = c.d.Close()
		c.d = nil
	}
}

// subMsg is what the subscription manager hands to the event loop.
type subMsg struct {
	ev          ipc.Event
	isEvent     bool
	lost        bool // no event for heartbeatTimeout, or the stream closed
	reconnected bool // subscribed again after a loss (still locked)
}

// dialSub opens a subscription on a fresh connection.
func (r *runner) dialSub(ctx context.Context) (Daemon, <-chan ipc.Event, error) {
	d, err := r.b.Daemon(ctx)
	if err != nil {
		return nil, nil, err
	}
	if d == nil {
		return nil, nil, ipc.ErrNoDaemon
	}
	ch, err := d.Subscribe(ctx, ipc.SubscribeReq{RootIDs: r.rootIDs, SID: r.sid, Wrapper: true})
	if err != nil {
		_ = d.Close()
		return nil, nil, err
	}
	return d, ch, nil
}

// watchSub forwards subscription events to r.events and implements SPEC
// §15.3: 2 s without an event (heartbeats come every second) or a closed
// stream is a loss, reported once; the wrapper then redials with back-off
// and stays locked until an "unlocked" event.
func (r *runner) watchSub(ctx context.Context, d Daemon, ch <-chan ipc.Event) {
	for {
		r.pumpSub(ctx, ch)
		_ = d.Close()
		if ctx.Err() != nil {
			return
		}
		r.sendMsg(ctx, subMsg{lost: true})
		delay := reconnectBackoff
		for {
			t := time.NewTimer(delay)
			select {
			case <-t.C:
			case <-ctx.Done():
				t.Stop()
				return
			}
			nd, nch, err := r.dialSub(ctx)
			if err == nil {
				d, ch = nd, nch
				r.sendMsg(ctx, subMsg{reconnected: true})
				break
			}
			if delay *= 2; delay > reconnectMax {
				delay = reconnectMax
			}
		}
	}
}

func (r *runner) pumpSub(ctx context.Context, ch <-chan ipc.Event) {
	t := time.NewTimer(heartbeatTimeout)
	defer t.Stop()
	for {
		select {
		case ev, ok := <-ch:
			if !ok {
				return
			}
			if !t.Stop() {
				select {
				case <-t.C:
				default:
				}
			}
			t.Reset(heartbeatTimeout)
			if ev.Kind != ipc.EventHeartbeat {
				r.sendMsg(ctx, subMsg{ev: ev, isEvent: true})
			}
		case <-t.C:
			return
		case <-ctx.Done():
			return
		}
	}
}

func (r *runner) sendMsg(ctx context.Context, m subMsg) {
	select {
	case r.events <- m:
	case <-ctx.Done():
	}
}

// activity rate-limits human-input reports (SPEC §15.1 step 7): an Enter
// is sent at once (D37 compares it with the next prompt within 3 s), other
// keys at most once per inputEvery. OnHuman runs on the input goroutine and
// never blocks.
type activity struct {
	mu    sync.Mutex
	input bool
	enter bool
	kick  chan struct{}
}

func newActivity() *activity { return &activity{kick: make(chan struct{}, 1)} }

func (a *activity) human(enter bool) {
	a.mu.Lock()
	if enter {
		a.enter = true
	} else {
		a.input = true
	}
	a.mu.Unlock()
	select {
	case a.kick <- struct{}{}:
	default:
	}
}

// take returns and clears the pending kind ("" when none or when input is
// not due yet; then wait is how long until it is).
func (a *activity) take(lastInput time.Time) (kind ipc.ActivityKind, wait time.Duration) {
	a.mu.Lock()
	defer a.mu.Unlock()
	switch {
	case a.enter:
		a.enter, a.input = false, false
		return ipc.ActEnter, 0
	case a.input:
		if d := inputEvery - time.Since(lastInput); d > 0 {
			return "", d
		}
		a.input = false
		return ipc.ActInput, 0
	}
	return "", 0
}

func (r *runner) activityLoop(ctx context.Context) {
	var last time.Time
	var timerC <-chan time.Time
	for {
		select {
		case <-r.act.kick:
		case <-timerC:
			timerC = nil
		case <-ctx.Done():
			return
		}
		kind, wait := r.act.take(last)
		if kind == "" {
			if wait > 0 && timerC == nil {
				timerC = time.After(wait)
			}
			continue
		}
		last = time.Now()
		r.sendActivity(ctx, kind)
	}
}

func (r *runner) sendActivity(ctx context.Context, kind ipc.ActivityKind) {
	c, cancel := context.WithTimeout(ctx, activityTimeout)
	defer cancel()
	req := ipc.ActivityReq{Harness: string(r.plan.Harness), SID: r.sid, Kind: kind, At: time.Now()}
	_ = r.ctl.do(c, func(d Daemon) error { return d.Activity(c, req) })
}

// register announces the child and this wrapper to the daemon (SPEC §15.1
// step 6; D54: wrapper = true with the wrapper's own pid).
func (r *runner) register(ctx context.Context) {
	req := ipc.RegisterReq{
		Harness:    string(r.plan.Harness),
		SID:        r.sid,
		PID:        r.pid,
		Cwd:        r.cwd,
		RootIDs:    r.rootIDs,
		Wrapper:    true,
		WrapperPID: selfPID(),
		TTY:        r.tty,
		ConfigDir:  r.configDir,
		TermITerm:  r.iterm,
	}
	for attempt := 0; attempt < 2; attempt++ {
		c, cancel := context.WithTimeout(ctx, requestTimeout)
		err := r.ctl.do(c, func(d Daemon) error { return d.Register(c, req) })
		cancel()
		var ie *ipc.Error
		if err == nil || errors.As(err, &ie) || ctx.Err() != nil {
			return
		}
	}
}

func (r *runner) unregister(ctx context.Context) {
	req := ipc.UnregisterReq{Harness: string(r.plan.Harness), SID: r.sid, PID: r.pid}
	c, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	_ = r.ctl.do(c, func(d Daemon) error { return d.Unregister(c, req) })
}
