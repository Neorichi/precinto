package ipc

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/awnumar/memguard"

	"github.com/precinto/precinto/internal/fsx"
	"github.com/precinto/precinto/internal/paths"
	"github.com/precinto/precinto/internal/platform"
)

// serverWriteTimeout bounds every write of the daemon to one client: a
// client that stops reading (a stuck subscriber) is dropped, never waited
// for.
const serverWriteTimeout = 5 * time.Second

// listen implements Listen.
func listen(l paths.Layout) (*Listener, error) {
	if l.RunDir == "" || l.Socket == "" || l.AgentLock == "" {
		return nil, errors.New("ipc: listen: incomplete layout")
	}
	if err := ensureRunDir(l.RunDir); err != nil {
		return nil, err
	}
	lk, err := fsx.TryLock(l.AgentLock, false)
	if err != nil {
		return nil, fmt.Errorf("ipc: listen: %w", err) // fsx.ErrLocked: another daemon runs (D6)
	}
	ln, err := bindPrivate(l.RunDir, l.Socket)
	if err != nil {
		_ = lk.Unlock()
		return nil, err
	}
	return &Listener{lock: lk, ln: ln, socket: l.Socket}, nil
}

// ensureRunDir creates the run directory (0700) when missing, then
// requires it to be private (D6).
func ensureRunDir(dir string) error {
	if err := checkPrivateDir(dir); err == nil {
		return nil
	} else if !errors.Is(err, errNotExist) {
		return err
	}
	if err := os.Mkdir(dir, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
		return fmt.Errorf("ipc: run directory: %w", err)
	}
	if err := checkPrivateDir(dir); err != nil {
		return err
	}
	return nil
}

// bindPrivate binds a listening socket that appears at socket with mode
// 0600 only: it is bound under a temporary name in the private directory,
// chmodded, then renamed over the final name. This has the effect of
// binding under umask 0177 without touching the process-wide umask (other
// goroutines create files concurrently). The caller holds run/agent.lock,
// so any socket found at the final name is stale and is replaced.
func bindPrivate(dir, socket string) (*net.UnixListener, error) {
	if st, err := os.Lstat(socket); err == nil {
		if st.Mode()&fs.ModeSocket == 0 {
			return nil, fmt.Errorf("ipc: listen: a file that is not a socket occupies the socket path")
		}
		if err := os.Remove(socket); err != nil {
			return nil, fmt.Errorf("ipc: listen: remove stale socket: %w", err)
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("ipc: listen: %w", err)
	}
	var rnd [4]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return nil, fmt.Errorf("ipc: listen: %w", err)
	}
	tmp := filepath.Join(dir, ".s"+hex.EncodeToString(rnd[:]))
	if len(tmp) >= paths.MaxSocketPath {
		return nil, paths.ErrSocketPath
	}
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: tmp, Net: "unix"})
	if err != nil {
		return nil, fmt.Errorf("ipc: listen: %w", err)
	}
	ln.SetUnlinkOnClose(false)
	if err := os.Chmod(tmp, 0o600); err != nil {
		ln.Close()
		_ = os.Remove(tmp)
		return nil, fmt.Errorf("ipc: listen: %w", err)
	}
	if err := os.Rename(tmp, socket); err != nil {
		ln.Close()
		_ = os.Remove(tmp)
		return nil, fmt.Errorf("ipc: listen: %w", err)
	}
	return ln, nil
}

// accept implements Listener.Accept: connections whose peer credentials
// cannot be read or belong to another uid are closed and skipped.
func (l *Listener) accept() (*Conn, error) {
	for {
		uc, err := l.ln.AcceptUnix()
		if err != nil {
			return nil, err
		}
		peer, err := platform.PeerOf(uc)
		if err != nil || peer.UID != os.Getuid() {
			uc.Close()
			continue
		}
		return &Conn{peer: peer, w: newWire(uc, serverWriteTimeout)}, nil
	}
}

// close implements Listener.Close: unlink the socket while still holding
// the lock (so no newer daemon's socket is ever removed), then release it.
func (l *Listener) close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil
	}
	l.closed = true
	err := l.ln.Close()
	if rerr := os.Remove(l.socket); rerr != nil && !errors.Is(rerr, fs.ErrNotExist) && err == nil {
		err = rerr
	}
	if uerr := l.lock.Unlock(); uerr != nil && err == nil {
		err = uerr
	}
	return err
}

// peerSameExecutable re-verifies on every call that the peer process is
// still the incarnation measured at accept time and runs this binary.
func (c *Conn) peerSameExecutable() bool {
	if c == nil || c.peer.Proc.ID.IsZero() {
		return false
	}
	if c.peer.PID == os.Getpid() {
		return true
	}
	if !platform.System().Alive(c.peer.Proc.ID) {
		return false
	}
	return sameExe(c.peer.PID)
}

// readRequest implements Conn.ReadRequest. A request with a bad version,
// secret count or payload is a protocol error: the connection must be
// closed (its framing can no longer be trusted).
func (c *Conn) readRequest() (Request, []*memguard.LockedBuffer, error) {
	var req Request
	if err := c.w.readJSON(&req); err != nil {
		return Request{}, nil, err
	}
	if req.V != Version {
		return req, nil, &Error{Code: CodeVersion, Msg: "this precinto speaks another protocol version; run precinto agent --restart"}
	}
	sec, err := c.w.readSecrets(req.Secrets)
	if err != nil {
		return Request{}, nil, err
	}
	if !payloadMatches(req) {
		destroyAll(sec)
		return req, nil, &Error{Code: CodeBadRequest, Msg: "malformed request"}
	}
	return req, sec, nil
}

// payloadMatches reports whether exactly the payload of req.Op is set.
func payloadMatches(r Request) bool {
	set := map[Op]bool{
		OpHello:       r.Hello != nil,
		OpGate:        r.Gate != nil,
		OpActivity:    r.Activity != nil,
		OpRegister:    r.Register != nil,
		OpUnregister:  r.Unregister != nil,
		OpUnlock:      r.Unlock != nil,
		OpUIReply:     r.UIReply != nil,
		OpLock:        r.Lock != nil,
		OpKeys:        r.Keys != nil,
		OpSubscribe:   r.Subscribe != nil,
		OpVaultCreate: r.VaultCreate != nil,
		OpFactorAdd:   r.FactorAdd != nil,
		OpVaultRepair: r.VaultRepair != nil,
		OpPolicy:      r.Policy != nil,
	}
	n := 0
	for _, v := range set {
		if v {
			n++
		}
	}
	switch r.Op {
	case OpStatus, OpShutdown:
		return n == 0
	}
	has, known := set[r.Op]
	return known && has && n == 1
}

// writeResponse implements Conn.WriteResponse.
func (c *Conn) writeResponse(r Response, secrets []*memguard.LockedBuffer) error {
	r.V, r.Secrets = Version, len(secrets)
	return c.w.write(r, secrets)
}

// key implements KeySet.Key.
func (k *KeySet) key(path string) (*memguard.LockedBuffer, bool) {
	if k == nil {
		return nil, false
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	b, ok := k.keys[path]
	if !ok || b == nil || !b.IsAlive() {
		return nil, false
	}
	return b, true
}

// destroy implements KeySet.Destroy (idempotent).
func (k *KeySet) destroy() {
	if k == nil {
		return
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	for _, b := range k.keys {
		if b != nil {
			b.Destroy()
		}
	}
	k.keys = nil
}
