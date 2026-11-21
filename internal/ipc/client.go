package ipc

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/awnumar/memguard"

	"github.com/precinto/precinto/internal/fsx"
	"github.com/precinto/precinto/internal/paths"
	"github.com/precinto/precinto/internal/platform"
)

// helloVersion is the client version sent in Hello.
const helloVersion = "1"

// dial implements Dial.
func dial(ctx context.Context, o DialOptions) (*Client, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if o.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, o.Timeout)
		defer cancel()
	}
	c, err := dialOnce(ctx, o)
	if err == nil || !errors.Is(err, ErrNoDaemon) || !o.Autostart {
		return c, err
	}
	if err := autostart(o); err != nil {
		return nil, fmt.Errorf("%w (autostart: %v)", ErrNoDaemon, err)
	}
	wait := 10 * time.Millisecond
	for {
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return nil, fmt.Errorf("%w (autostarted daemon did not answer in time)", ErrNoDaemon)
		case <-t.C:
		}
		c, err := dialOnce(ctx, o)
		if err == nil || !errors.Is(err, ErrNoDaemon) {
			return c, err
		}
		if wait < 200*time.Millisecond {
			wait *= 2
		}
	}
}

// autostart starts `<Exe> agent` detached unless a daemon holds
// run/agent.lock (it is then starting up and will answer shortly). Two
// clients may race to spawn; Listen's lock lets exactly one daemon serve
// (CONC-2).
func autostart(o DialOptions) error {
	if !filepath.IsAbs(o.Exe) {
		return errors.New("ipc: autostart needs the absolute path of the precinto binary")
	}
	if err := checkPrivateDir(o.Layout.RunDir); err != nil && !errors.Is(err, errNotExist) {
		return err
	}
	if lk, err := fsx.TryLock(o.Layout.AgentLock, false); err == nil {
		_ = lk.Unlock()
	} else if errors.Is(err, fsx.ErrLocked) {
		return nil
	}
	logPath := ""
	if o.Layout.LogFile != "" {
		if st, err := os.Lstat(filepath.Dir(o.Layout.LogFile)); err == nil && st.IsDir() {
			logPath = o.Layout.LogFile
		}
	}
	_, err := platform.Spawn([]string{o.Exe, "agent"}, platform.SpawnOptions{Dir: "/", Env: o.Env, LogPath: logPath})
	return err
}

// dialOnce authenticates the daemon (D6) and performs Hello. Nothing is
// written to the socket before the run directory, the socket owner and the
// server's executable have been checked.
func dialOnce(ctx context.Context, o DialOptions) (*Client, error) {
	switch err := checkPrivateDir(o.Layout.RunDir); {
	case errors.Is(err, errNotExist):
		return nil, ErrNoDaemon
	case err != nil:
		return nil, fmt.Errorf("%w (%v)", ErrUntrustedServer, err)
	}
	switch err := checkSocket(o.Layout.Socket); {
	case errors.Is(err, errNotExist):
		return nil, ErrNoDaemon
	case err != nil:
		return nil, fmt.Errorf("%w (%v)", ErrUntrustedServer, err)
	}
	var d net.Dialer
	nc, err := d.DialContext(ctx, "unix", o.Layout.Socket)
	if err != nil {
		if errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.ENOENT) {
			return nil, ErrNoDaemon // a stale socket: nobody listens
		}
		if ctx.Err() != nil {
			return nil, fmt.Errorf("%w (%v)", ErrNoDaemon, ctx.Err())
		}
		return nil, fmt.Errorf("ipc: connect: %w", err)
	}
	uc, ok := nc.(*net.UnixConn)
	if !ok {
		nc.Close()
		return nil, errors.New("ipc: not a unix connection")
	}
	peer, err := platform.PeerOf(uc)
	if err != nil {
		uc.Close()
		return nil, fmt.Errorf("%w (server credentials unavailable)", ErrUntrustedServer)
	}
	if peer.UID != os.Getuid() {
		uc.Close()
		return nil, fmt.Errorf("%w (server runs as another user)", ErrUntrustedServer)
	}
	if !(o.Insecure && paths.TestingBuild()) && !serverTrusted(peer.PID, o.Layout.AgentLock) {
		uc.Close()
		return nil, ErrUntrustedServer
	}
	c := &Client{opts: o, w: newWire(uc, 0), subs: map[*wire]struct{}{}}
	resp, err := c.simple(ctx, Request{Op: OpHello, Hello: &Hello{Client: o.Client, Version: helloVersion}})
	if err != nil {
		c.close()
		return nil, err
	}
	if resp.Hello == nil || resp.Hello.Protocol != Version {
		c.close()
		return nil, &Error{Code: CodeVersion, Msg: "precinto agent speaks another protocol version; run precinto agent --restart"}
	}
	c.hello = *resp.Hello
	return c, nil
}

// close implements Client.Close: the request connection and every
// subscription stream.
func (c *Client) close() error {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	w := c.w
	c.w = nil
	c.closed = true
	subs := c.subs
	c.subs = nil
	c.mu.Unlock()
	for s := range subs {
		_ = s.close()
	}
	if w != nil {
		return w.close()
	}
	return nil
}

// simple performs a request without secrets or relayed UI.
func (c *Client) simple(ctx context.Context, req Request) (Response, error) {
	resp, sec, err := c.do(ctx, req, nil, nil)
	destroyAll(sec)
	return resp, err
}

// guard applies ctx to the connection: its deadline, and cancellation by
// expiring every pending read or write at once. The returned function
// restores the connection.
func guard(ctx context.Context, conn net.Conn) func() {
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Unix(1, 0)) })
	return func() {
		stop()
		_ = conn.SetDeadline(time.Time{})
	}
}

// do sends req (with secrets) and returns the final response and its
// secrets, answering relayed UI requests with ui on the way. Any transport
// or protocol failure closes the connection: its state is unknown.
func (c *Client) do(ctx context.Context, req Request, secrets []*memguard.LockedBuffer, ui UIHandler) (Response, []*memguard.LockedBuffer, error) {
	if c == nil {
		return Response{}, nil, errClosed
	}
	if ctx == nil {
		ctx = context.Background()
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.w == nil {
		return Response{}, nil, errClosed
	}
	if err := ctx.Err(); err != nil {
		return Response{}, nil, err
	}
	c.nextID++
	req.V, req.ID, req.Secrets = Version, c.nextID, len(secrets)
	w := c.w
	restore := guard(ctx, w.c)
	defer restore()
	fail := func(err error) (Response, []*memguard.LockedBuffer, error) {
		_ = w.close()
		c.w = nil
		return Response{}, nil, ctxErr(ctx, err)
	}
	if err := w.write(req, secrets); err != nil {
		return fail(err)
	}
	for {
		var resp Response
		if err := w.readJSON(&resp); err != nil {
			return fail(err)
		}
		if resp.V != Version || resp.ID != req.ID {
			return fail(errProtocol("response does not match the request"))
		}
		sec, err := w.readSecrets(resp.Secrets)
		if err != nil {
			return fail(err)
		}
		if resp.UI != nil {
			destroyAll(sec)
			if err := c.answerUI(w, req.ID, resp.UI, ui); err != nil {
				return fail(err)
			}
			continue
		}
		if !resp.OK {
			destroyAll(sec)
			if resp.Err == nil {
				return resp, nil, &Error{Code: CodeInternal, Msg: "the precinto agent refused the request"}
			}
			return resp, nil, resp.Err
		}
		return resp, sec, nil
	}
}

// answerUI relays one UIRequest to ui. Display and wait need no reply;
// secret and confirm are answered with a UIReply (a secret in one 'S'
// frame). Without a handler every question is answered "cancelled".
func (c *Client) answerUI(w *wire, id uint64, u *UIRequest, ui UIHandler) error {
	switch u.Kind {
	case UIDisplay, UIWait:
		if ui != nil && u.Prompt != "" {
			_ = ui.Display(u.Prompt)
		}
		return nil
	case UISecret:
		var sec *memguard.LockedBuffer
		var err error
		if ui != nil {
			sec, err = ui.Secret(u.Prompt)
		}
		reply := Request{V: Version, ID: id, Op: OpUIReply, UIReply: &UIReply{Seq: u.Seq}}
		var secrets []*memguard.LockedBuffer
		if ui != nil && err == nil && sec != nil && sec.IsAlive() {
			reply.UIReply.OK, reply.UIReply.HasSecret = true, true
			secrets = []*memguard.LockedBuffer{sec}
		}
		reply.Secrets = len(secrets)
		werr := w.write(reply, secrets)
		if sec != nil {
			sec.Destroy()
		}
		return werr
	case UIConfirm:
		choice, err := false, error(nil)
		if ui != nil {
			choice, err = ui.Confirm(u.Prompt, u.Yes, u.No)
		}
		reply := Request{V: Version, ID: id, Op: OpUIReply, UIReply: &UIReply{Seq: u.Seq}}
		if ui != nil && err == nil {
			reply.UIReply.OK, reply.UIReply.Choice = true, choice
		}
		return w.write(reply, nil)
	}
	return errProtocol("unknown UI request kind")
}

// ctxErr reports ctx's error for a transport failure caused by it: the
// connection deadline is ctx's deadline, so a timeout may surface a moment
// before ctx itself is done.
func ctxErr(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if _, ok := ctx.Deadline(); ok && errors.Is(err, os.ErrDeadlineExceeded) {
		t := time.NewTimer(100 * time.Millisecond)
		defer t.Stop()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
		}
	}
	return err
}

// keys implements Client.Keys.
func (c *Client) keys(ctx context.Context, r KeysReq) (*KeySet, KeysResp, error) {
	resp, sec, err := c.do(ctx, Request{Op: OpKeys, Keys: &r}, nil, nil)
	if err != nil {
		return nil, KeysResp{}, err
	}
	if resp.Keys == nil || len(resp.Keys.Granted) != len(sec) {
		destroyAll(sec)
		c.mu.Lock()
		if c.w != nil {
			_ = c.w.close()
			c.w = nil
		}
		c.mu.Unlock()
		return nil, KeysResp{}, errProtocol("key count does not match the grants")
	}
	ks := &KeySet{keys: make(map[string]*memguard.LockedBuffer, len(sec))}
	for i, g := range resp.Keys.Granted {
		if old, dup := ks.keys[g.Path]; dup {
			old.Destroy()
		}
		ks.keys[g.Path] = sec[i]
	}
	return ks, *resp.Keys, nil
}

// vaultRepair implements Client.VaultRepair.
func (c *Client) vaultRepair(ctx context.Context, r VaultRepairReq, recovery *memguard.LockedBuffer, ui UIHandler) (VaultRepairResp, error) {
	var secrets []*memguard.LockedBuffer
	if r.UseRecovery {
		if recovery == nil || !recovery.IsAlive() {
			return VaultRepairResp{}, &Error{Code: CodeBadRequest, Msg: "vault repair --recovery needs the recovery key"}
		}
		secrets = []*memguard.LockedBuffer{recovery}
	}
	resp, sec, err := c.do(ctx, Request{Op: OpVaultRepair, VaultRepair: &r}, secrets, ui)
	destroyAll(sec)
	if err != nil {
		return VaultRepairResp{}, err
	}
	if resp.Repair == nil {
		return VaultRepairResp{}, errProtocol("repair response without result")
	}
	return *resp.Repair, nil
}

// subscribe implements Client.Subscribe on a connection of its own (the
// stream occupies it; the Client keeps serving requests). The channel is
// closed when the stream ends: ctx done, Close, or the daemon gone.
func (c *Client) subscribe(ctx context.Context, r SubscribeReq) (<-chan Event, error) {
	if c == nil {
		return nil, errClosed
	}
	if ctx == nil {
		ctx = context.Background()
	}
	c.mu.Lock()
	closed := c.closed
	o := c.opts
	c.mu.Unlock()
	if closed {
		return nil, errClosed
	}
	o.Autostart = false
	dctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	sc, err := dialOnce(dctx, o)
	cancel()
	if err != nil {
		return nil, err
	}
	if _, err := sc.simple(ctx, Request{Op: OpSubscribe, Subscribe: &r}); err != nil {
		sc.close()
		return nil, err
	}
	sc.mu.Lock()
	w := sc.w
	sc.w = nil // the stream owns the connection now
	sc.mu.Unlock()
	if w == nil {
		return nil, errClosed
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		w.close()
		return nil, errClosed
	}
	c.subs[w] = struct{}{}
	c.mu.Unlock()

	out := make(chan Event, 64)
	stop := context.AfterFunc(ctx, func() { _ = w.close() })
	go func() {
		defer close(out)
		defer stop()
		defer func() {
			_ = w.close()
			c.mu.Lock()
			delete(c.subs, w)
			c.mu.Unlock()
		}()
		for {
			var ev Response
			if err := w.readJSON(&ev); err != nil {
				return
			}
			sec, err := w.readSecrets(ev.Secrets)
			destroyAll(sec)
			if err != nil || ev.Event == nil {
				return
			}
			select {
			case out <- *ev.Event:
			case <-ctx.Done():
				return
			}
		}
	}()
	return out, nil
}
