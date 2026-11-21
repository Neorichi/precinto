package ipc_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/awnumar/memguard"

	"github.com/precinto/precinto/internal/fsx"
	"github.com/precinto/precinto/internal/ipc"
	"github.com/precinto/precinto/internal/paths"
	"github.com/precinto/precinto/internal/testkit"
)

// layout returns a throwaway layout with a short run directory.
func layout(t *testing.T) paths.Layout {
	t.Helper()
	run := filepath.Join(testkit.ShortTempDir(t), "run")
	l, err := paths.LayoutAt(t.TempDir(), run)
	if err != nil {
		t.Fatal(err)
	}
	return l
}

// handler answers one non-hello request; returning false closes the
// connection.
type handler func(c *ipc.Conn, req ipc.Request, sec []*memguard.LockedBuffer) bool

// server is an in-process listener answering hello itself.
type server struct {
	ln    *ipc.Listener
	wg    sync.WaitGroup
	mu    sync.Mutex
	peers []bool // PeerSameExecutable of each accepted connection
}

func startServer(t *testing.T, l paths.Layout, h handler) *server {
	t.Helper()
	ln, err := ipc.Listen(l)
	if err != nil {
		t.Fatal(err)
	}
	s := &server{ln: ln}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			s.mu.Lock()
			s.peers = append(s.peers, c.PeerSameExecutable())
			s.mu.Unlock()
			s.wg.Add(1)
			go func() {
				defer s.wg.Done()
				defer c.Close()
				for {
					req, sec, err := c.ReadRequest()
					if err != nil {
						var e *ipc.Error
						if errors.As(err, &e) {
							_ = c.WriteResponse(ipc.Response{ID: req.ID, Err: e})
						}
						return
					}
					if req.Op == ipc.OpHello {
						_ = c.WriteResponse(ipc.Response{ID: req.ID, OK: true, Hello: &ipc.HelloResp{Version: "test", PID: os.Getpid(), Protocol: ipc.Version}})
						continue
					}
					ok := h(c, req, sec)
					for _, b := range sec {
						b.Destroy()
					}
					if !ok {
						return
					}
				}
			}()
		}
	}()
	t.Cleanup(func() { ln.Close(); s.wg.Wait() })
	return s
}

func dialT(t *testing.T, l paths.Layout) *ipc.Client {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := ipc.Dial(ctx, ipc.DialOptions{Layout: l, Client: "cli", Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func TestListenDialStatus(t *testing.T) {
	l := layout(t)
	startServer(t, l, func(c *ipc.Conn, req ipc.Request, _ []*memguard.LockedBuffer) bool {
		switch req.Op {
		case ipc.OpStatus:
			_ = c.WriteResponse(ipc.Response{ID: req.ID, OK: true, Status: &ipc.StatusResp{Version: "test", PID: os.Getpid()}})
		case ipc.OpLock:
			_ = c.WriteResponse(ipc.Response{ID: req.ID, Err: &ipc.Error{Code: ipc.CodeLocked, Msg: "locked"}})
		default:
			_ = c.WriteResponse(ipc.Response{ID: req.ID, OK: true})
		}
		return true
	})
	st, err := os.Lstat(l.Socket)
	if err != nil || st.Mode()&os.ModeSocket == 0 || st.Mode().Perm() != 0o600 {
		t.Fatalf("socket = %v %v (want a 0600 socket)", st, err)
	}
	if st, err := os.Stat(l.RunDir); err != nil || st.Mode().Perm() != 0o700 {
		t.Fatalf("run dir = %v %v", st, err)
	}
	c := dialT(t, l)
	s, err := c.Status(context.Background())
	if err != nil || s.PID != os.Getpid() {
		t.Fatalf("Status = %+v, %v", s, err)
	}
	_, err = c.Lock(context.Background(), ipc.LockReq{All: true})
	var e *ipc.Error
	if !errors.As(err, &e) || e.Code != ipc.CodeLocked || e.ExitCode() != 3 {
		t.Fatalf("Lock error = %v", err)
	}
	if err := c.Activity(context.Background(), ipc.ActivityReq{SID: "s", Kind: ipc.ActStop}); err != nil {
		t.Fatal(err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Status(context.Background()); err == nil {
		t.Fatal("request after Close succeeded")
	}
}

func TestTwoListenersOneWins(t *testing.T) {
	l := layout(t)
	var wins, locked int
	var mu sync.Mutex
	var wg sync.WaitGroup
	var lns []*ipc.Listener
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ln, err := ipc.Listen(l)
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				wins++
				lns = append(lns, ln)
			case errors.Is(err, fsx.ErrLocked):
				locked++
			default:
				t.Errorf("Listen: %v", err)
			}
		}()
	}
	wg.Wait()
	if wins != 1 || locked != 7 {
		t.Fatalf("wins=%d locked=%d (CONC-2: exactly one daemon serves)", wins, locked)
	}
	for _, ln := range lns {
		ln.Close()
	}
	if _, err := os.Lstat(l.Socket); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("socket left after Close: %v", err)
	}
	ln, err := ipc.Listen(l)
	if err != nil {
		t.Fatalf("Listen after Close: %v", err)
	}
	ln.Close()
}

func TestStaleSocket(t *testing.T) {
	l := layout(t)
	if err := os.Mkdir(l.RunDir, 0o700); err != nil {
		t.Fatal(err)
	}
	stale, err := net.ListenUnix("unix", &net.UnixAddr{Name: l.Socket, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	stale.SetUnlinkOnClose(false)
	stale.Close() // the file stays: a daemon that died
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := ipc.Dial(ctx, ipc.DialOptions{Layout: l}); !errors.Is(err, ipc.ErrNoDaemon) {
		t.Fatalf("Dial(stale) = %v, want ErrNoDaemon", err)
	}
	startServer(t, l, func(c *ipc.Conn, req ipc.Request, _ []*memguard.LockedBuffer) bool { return false })
	dialT(t, l)
}

func TestListenRefusesNonSocket(t *testing.T) {
	l := layout(t)
	if err := os.Mkdir(l.RunDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(l.Socket, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if ln, err := ipc.Listen(l); err == nil {
		ln.Close()
		t.Fatal("Listen replaced a regular file")
	}
	if b, _ := os.ReadFile(l.Socket); string(b) != "x" {
		t.Fatal("the regular file was touched")
	}
}

func TestRunDirChecks(t *testing.T) {
	ctx := context.Background()
	l := layout(t)
	if _, err := ipc.Dial(ctx, ipc.DialOptions{Layout: l}); !errors.Is(err, ipc.ErrNoDaemon) {
		t.Fatalf("missing run dir = %v", err)
	}
	if err := os.Mkdir(l.RunDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := ipc.Dial(ctx, ipc.DialOptions{Layout: l}); !errors.Is(err, ipc.ErrUntrustedServer) {
		t.Fatalf("0755 run dir = %v, want ErrUntrustedServer", err)
	}
	if ln, err := ipc.Listen(l); err == nil {
		ln.Close()
		t.Fatal("Listen accepted a 0755 run dir")
	}
	// A symlinked run directory is refused too.
	l2 := layout(t)
	target := filepath.Join(filepath.Dir(l2.RunDir), "real")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, l2.RunDir); err != nil {
		t.Fatal(err)
	}
	if _, err := ipc.Dial(ctx, ipc.DialOptions{Layout: l2}); !errors.Is(err, ipc.ErrUntrustedServer) {
		t.Fatalf("symlinked run dir = %v", err)
	}
	if ln, err := ipc.Listen(l2); err == nil {
		ln.Close()
		t.Fatal("Listen accepted a symlinked run dir")
	}
}

// TestSecretsTravelOnlyInSecretFrames reads the raw wire of a Keys answer:
// the JSON frame names the grants, the keys follow as 'S' frames and never
// appear in JSON (D6, I7).
func TestSecretsTravelOnlyInSecretFrames(t *testing.T) {
	l := layout(t)
	k1 := []byte("0123456789abcdef")
	k2 := []byte("fedcba9876543210")
	startServer(t, l, func(c *ipc.Conn, req ipc.Request, _ []*memguard.LockedBuffer) bool {
		b1 := memguard.NewBufferFromBytes(append([]byte(nil), k1...))
		b2 := memguard.NewBufferFromBytes(append([]byte(nil), k2...))
		defer b1.Destroy()
		defer b2.Destroy()
		_ = c.WriteResponse(ipc.Response{ID: req.ID, OK: true, Keys: &ipc.KeysResp{
			Granted: []ipc.KeyGrant{{Path: "claude-code/u/g000001.pcap", VaultID: "root-acme"}, {Path: "md/u/g000002.pcap", VaultID: "root-acme"}},
			Denied:  map[string]ipc.Code{"md/x/g000001.pcap": ipc.CodeNotLogged},
		}}, b1, b2)
		return true
	})
	// Raw client.
	conn, err := net.Dial("unix", l.Socket)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := ipc.WriteFrame(conn, ipc.FrameJSON, []byte(`{"v":1,"id":1,"op":"keys","keys":{"capsules":[],"purpose":"restore"}}`)); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	k, p, err := ipc.ReadFrame(conn, nil)
	if err != nil || k != ipc.FrameJSON {
		t.Fatalf("first frame %c %v", k, err)
	}
	if !bytes.Contains(p, []byte(`"secrets":2`)) || bytes.Contains(p, k1) || bytes.Contains(p, k2) {
		t.Fatalf("control frame = %s", p)
	}
	for _, want := range [][]byte{k1, k2} {
		k, p, err := ipc.ReadFrame(conn, nil)
		if err != nil || k != ipc.FrameSecret || !bytes.Equal(p, want) {
			t.Fatalf("secret frame = %c %q %v", k, p, err)
		}
	}
	// Through the client: the keys land in a KeySet.
	c := dialT(t, l)
	ks, resp, err := c.Keys(context.Background(), ipc.KeysReq{Purpose: ipc.PurposeRestore})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Granted) != 2 || resp.Denied["md/x/g000001.pcap"] != ipc.CodeNotLogged {
		t.Fatalf("resp = %+v", resp)
	}
	b, ok := ks.Key("md/u/g000002.pcap")
	if !ok || !bytes.Equal(b.Bytes(), k2) {
		t.Fatal("key not in the KeySet")
	}
	ks.Destroy()
	if _, ok := ks.Key("md/u/g000002.pcap"); ok || b.IsAlive() {
		t.Fatal("Destroy left a key")
	}
}

// scriptedUI is a test ipc.UIHandler.
type scriptedUI struct {
	displayed []string
	secret    string
	confirm   bool
	cancel    bool
}

func (u *scriptedUI) Display(m string) error { u.displayed = append(u.displayed, m); return nil }
func (u *scriptedUI) Secret(string) (*memguard.LockedBuffer, error) {
	if u.cancel {
		return nil, errors.New("cancelled")
	}
	return memguard.NewBufferFromBytes([]byte(u.secret)), nil
}
func (u *scriptedUI) Confirm(p, yes, no string) (bool, error) { return u.confirm, nil }

func TestUnlockRelaysUI(t *testing.T) {
	l := layout(t)
	got := make(chan string, 4)
	startServer(t, l, func(c *ipc.Conn, req ipc.Request, _ []*memguard.LockedBuffer) bool {
		if req.Op != ipc.OpUnlock {
			return false
		}
		_ = c.WriteResponse(ipc.Response{ID: req.ID, UI: &ipc.UIRequest{Seq: 1, Kind: ipc.UIDisplay, Prompt: "touch"}})
		_ = c.WriteResponse(ipc.Response{ID: req.ID, UI: &ipc.UIRequest{Seq: 2, Kind: ipc.UISecret, Prompt: "pass"}})
		r, sec, err := c.ReadRequest()
		if err != nil || r.Op != ipc.OpUIReply || r.UIReply.Seq != 2 {
			got <- "bad reply"
			return false
		}
		if r.UIReply.OK && len(sec) == 1 {
			got <- "secret:" + string(sec[0].Bytes())
		} else {
			got <- "cancelled"
		}
		for _, b := range sec {
			b.Destroy()
		}
		_ = c.WriteResponse(ipc.Response{ID: req.ID, UI: &ipc.UIRequest{Seq: 3, Kind: ipc.UIConfirm, Prompt: "ok?", Yes: "repair", No: "no"}})
		r, _, err = c.ReadRequest()
		if err != nil || r.UIReply == nil || r.UIReply.Seq != 3 {
			got <- "bad confirm"
			return false
		}
		got <- "confirm:" + strconv.FormatBool(r.UIReply.Choice)
		_ = c.WriteResponse(ipc.Response{ID: req.ID, OK: true, Unlock: &ipc.UnlockResp{Unlocked: []string{"root-acme"}}})
		return true
	})
	c := dialT(t, l)
	ui := &scriptedUI{secret: "correct horse", confirm: true}
	resp, err := c.Unlock(context.Background(), ipc.UnlockReq{RootIDs: []string{"root-acme"}, TTY: true}, ui)
	if err != nil || len(resp.Unlocked) != 1 {
		t.Fatalf("Unlock = %+v, %v", resp, err)
	}
	if a, b := <-got, <-got; a != "secret:correct horse" || b != "confirm:true" {
		t.Fatalf("server saw %q %q", a, b)
	}
	if len(ui.displayed) != 1 || ui.displayed[0] != "touch" {
		t.Fatalf("displayed = %q", ui.displayed)
	}
	// Without a handler every question is answered "cancelled".
	_, err = c.Unlock(context.Background(), ipc.UnlockReq{RootIDs: []string{"root-acme"}}, nil)
	if a := <-got; a != "cancelled" || err != nil {
		t.Fatalf("nil UI: server saw %q, err %v", a, err)
	}
	<-got
}

func TestContextCancelsRequest(t *testing.T) {
	l := layout(t)
	release := make(chan struct{})
	startServer(t, l, func(c *ipc.Conn, req ipc.Request, _ []*memguard.LockedBuffer) bool {
		<-release // never answers in time
		return false
	})
	defer close(release)
	c := dialT(t, l)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := c.Status(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Status = %v", err)
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("cancellation was not prompt")
	}
	if _, err := c.Status(context.Background()); err == nil {
		t.Fatal("a connection in an unknown state was reused")
	}
}

func TestSubscribeStream(t *testing.T) {
	l := layout(t)
	stop := make(chan struct{})
	startServer(t, l, func(c *ipc.Conn, req ipc.Request, _ []*memguard.LockedBuffer) bool {
		if req.Op != ipc.OpSubscribe {
			_ = c.WriteResponse(ipc.Response{ID: req.ID, OK: true})
			return true
		}
		_ = c.WriteResponse(ipc.Response{ID: req.ID, OK: true})
		for _, k := range []ipc.EventKind{ipc.EventLocked, ipc.EventHeartbeat, ipc.EventUnlocked} {
			_ = c.WriteResponse(ipc.Response{ID: req.ID, OK: true, Event: &ipc.Event{Kind: k, RootIDs: []string{"root-acme"}}})
		}
		<-stop
		return false // the daemon goes away
	})
	c := dialT(t, l)
	ch, err := c.Subscribe(context.Background(), ipc.SubscribeReq{RootIDs: []string{"root-acme"}, Wrapper: true})
	if err != nil {
		t.Fatal(err)
	}
	var kinds []ipc.EventKind
	for i := 0; i < 3; i++ {
		select {
		case ev := <-ch:
			kinds = append(kinds, ev.Kind)
		case <-time.After(5 * time.Second):
			t.Fatal("event not received")
		}
	}
	if kinds[0] != ipc.EventLocked || kinds[2] != ipc.EventUnlocked {
		t.Fatalf("events = %v", kinds)
	}
	// The request connection still works while the stream is open.
	if err := c.Activity(context.Background(), ipc.ActivityReq{Kind: ipc.ActStop}); err != nil {
		t.Fatal(err)
	}
	close(stop)
	select {
	case _, ok := <-ch:
		if ok {
			t.Fatal("unexpected event")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("channel not closed when the daemon went away (SPEC §15.3)")
	}
}

func TestMalformedRequestRefused(t *testing.T) {
	l := layout(t)
	startServer(t, l, func(c *ipc.Conn, req ipc.Request, _ []*memguard.LockedBuffer) bool { return false })
	conn, err := net.Dial("unix", l.Socket)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	// Op gate carrying another op's payload.
	if err := ipc.WriteFrame(conn, ipc.FrameJSON, []byte(`{"v":1,"id":7,"op":"gate","lock":{"all":true}}`)); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, p, err := ipc.ReadFrame(conn, nil)
	if err != nil || !strings.Contains(string(p), `"bad_request"`) {
		t.Fatalf("response = %s %v", p, err)
	}
	// An unknown field is a protocol error: the connection is closed.
	conn2, err := net.Dial("unix", l.Socket)
	if err != nil {
		t.Fatal(err)
	}
	defer conn2.Close()
	_ = ipc.WriteFrame(conn2, ipc.FrameJSON, []byte(`{"v":1,"id":1,"op":"status","origin":"human"}`))
	_ = conn2.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, _, err := ipc.ReadFrame(conn2, nil); !errors.Is(err, io.EOF) {
		t.Fatalf("unknown field: %v, want the connection closed", err)
	}
	// A secret frame in place of a control frame is refused, unread.
	conn3, err := net.Dial("unix", l.Socket)
	if err != nil {
		t.Fatal(err)
	}
	defer conn3.Close()
	_ = ipc.WriteFrame(conn3, ipc.FrameSecret, []byte("AGE-SECRET-KEY-1FIXTURE"))
	_ = conn3.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, _, err := ipc.ReadFrame(conn3, nil); !errors.Is(err, io.EOF) {
		t.Fatalf("stray secret frame: %v", err)
	}
}

// helperCopy copies the test binary: a different file (dev+inode) running
// the same code, i.e. "another executable" for D6.
func helperCopy(t *testing.T) string {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "helper.test")
	if err := os.WriteFile(p, b, 0o700); err != nil {
		t.Fatal(err)
	}
	return p
}

// helper is a child process the test started: the test binary (or a copy)
// in helper mode. It carries a lifeline (its stdin, a pipe the test holds)
// and exits as soon as the pipe closes, so it never outlives the test even
// when the test binary dies; t.Cleanup also kills and reaps it.
type helper struct {
	cmd   *exec.Cmd
	life  *os.File      // write end of the lifeline
	lines chan string   // the helper's stdout, line by line
	done  chan struct{} // closed once the helper was reaped
	err   error         // its exit status (after done)
}

func runHelper(t *testing.T, exe string, args ...string) *helper {
	t.Helper()
	cmd := exec.Command(exe, append([]string{"-test.run=^TestIPCHelper$", "-test.count=1", "--"}, args...)...)
	cmd.Env = []string{"HOME=/nonexistent"}
	lifeR, lifeW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stdin = lifeR
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	lifeR.Close()
	h := &helper{cmd: cmd, life: lifeW, lines: make(chan string, 16), done: make(chan struct{})}
	go func() {
		b := make([]byte, 0, 256)
		buf := make([]byte, 256)
		for {
			n, err := out.Read(buf)
			b = append(b, buf[:n]...)
			for {
				i := bytes.IndexByte(b, '\n')
				if i < 0 {
					break
				}
				select {
				case h.lines <- string(b[:i]):
				default:
				}
				b = b[i+1:]
			}
			if err != nil {
				break
			}
		}
		h.err = cmd.Wait()
		close(h.done)
	}()
	t.Cleanup(func() {
		h.life.Close() // the helper exits on its own
		select {
		case <-h.done:
		case <-time.After(5 * time.Second):
			_ = cmd.Process.Kill() // our own child only
			<-h.done
		}
	})
	return h
}

// waitReady waits until the helper printed "ready" (it is listening).
func (h *helper) waitReady(t *testing.T) {
	t.Helper()
	timeout := time.After(20 * time.Second)
	for {
		select {
		case l := <-h.lines:
			if l == "ready" {
				return
			}
		case <-h.done:
			t.Fatalf("helper exited before it was ready: %v", h.err)
		case <-timeout:
			t.Fatal("helper never got ready")
		}
	}
}

// wait waits for the helper to exit by itself and returns its status.
func (h *helper) wait(t *testing.T) error {
	t.Helper()
	select {
	case <-h.done:
		return h.err
	case <-time.After(20 * time.Second):
		t.Fatal("helper did not exit")
		return nil
	}
}

// TestSocketSquat is SEC-11: another binary bound at agent.sock is refused
// before the client writes a single byte.
func TestSocketSquat(t *testing.T) {
	l := layout(t)
	if err := os.Mkdir(l.RunDir, 0o700); err != nil {
		t.Fatal(err)
	}
	result := filepath.Join(t.TempDir(), "received")
	h := runHelper(t, helperCopy(t), "listen", l.Socket, result)
	h.waitReady(t) // listening, not only bound: never an "agent is not running" race
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := ipc.Dial(ctx, ipc.DialOptions{Layout: l, Client: "cli"})
	if !errors.Is(err, ipc.ErrUntrustedServer) {
		t.Fatalf("Dial(squatter) = %v, want ErrUntrustedServer", err)
	}
	if err := h.wait(t); err != nil {
		t.Fatalf("helper: %v", err)
	}
	b, err := os.ReadFile(result)
	if err != nil || string(b) != "0" {
		t.Fatalf("squatter received %q bytes (%v): the client must send nothing", b, err)
	}
}

// TestPeerSameExecutable: the in-process peer runs this binary, a copy of it
// does not (keys, unlock and wrapper activity require it, D6/D54).
func TestPeerSameExecutable(t *testing.T) {
	l := layout(t)
	s := startServer(t, l, func(c *ipc.Conn, req ipc.Request, _ []*memguard.LockedBuffer) bool {
		_ = c.WriteResponse(ipc.Response{ID: req.ID, OK: true})
		return true
	})
	dialT(t, l)
	h := runHelper(t, helperCopy(t), "dial", l.Socket)
	if err := h.wait(t); err != nil {
		t.Fatalf("helper: %v", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.peers) != 2 || !s.peers[0] || s.peers[1] {
		t.Fatalf("PeerSameExecutable per connection = %v, want [true false]", s.peers)
	}
}

// TestIPCHelper is the body of helper processes (a no-op test otherwise).
// Every mode exits when its lifeline (stdin) closes.
func TestIPCHelper(t *testing.T) {
	args := helperArgs()
	if args == nil {
		return
	}
	go func() {
		_, _ = io.Copy(io.Discard, os.Stdin)
		os.Exit(70) // the test went away
	}()
	if extra, ok := helperModes[args[0]]; ok {
		extra(args[1:])
		os.Exit(0)
	}
	switch args[0] {
	case "listen": // listen <socket> <result>: count bytes a client sends
		ln, err := net.Listen("unix", args[1])
		if err != nil {
			os.Exit(2)
		}
		fmt.Println("ready")
		c, err := ln.Accept()
		if err != nil {
			os.Exit(3)
		}
		_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, _ := io.Copy(io.Discard, c)
		_ = os.WriteFile(args[2], []byte(strconv.FormatInt(n, 10)), 0o600)
		os.Exit(0)
	case "dial": // dial <socket>: speak hello with raw frames
		c, err := net.Dial("unix", args[1])
		if err != nil {
			os.Exit(2)
		}
		_ = ipc.WriteFrame(c, ipc.FrameJSON, []byte(`{"v":1,"id":1,"op":"hello","hello":{"client":"x","version":"1"}}`))
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		var hdr [4]byte
		if _, err := io.ReadFull(c, hdr[:]); err != nil || binary.BigEndian.Uint32(hdr[:]) == 0 {
			os.Exit(3)
		}
		os.Exit(0)
	}
	os.Exit(9)
}

// helperModes are OS-specific helper modes (auth_linux_test.go), keyed by
// name; each returns when done.
var helperModes = map[string]func(args []string){}

func helperArgs() []string {
	for i, a := range os.Args {
		if a == "--" && i+1 < len(os.Args) {
			return os.Args[i+1:]
		}
	}
	return nil
}
