package ipc

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/awnumar/memguard"
)

// maxSecrets bounds the secret frames that may follow one JSON frame (one
// file key per capsule of a Keys response; clients batch larger restores).
const maxSecrets = 1024

// Protocol errors. They never carry content: frames are not echoed.
var (
	errFrameSize = errors.New("ipc: frame length out of bounds")
	errFrameKind = errors.New("ipc: unknown frame kind")
	errClosed    = errors.New("ipc: connection closed")
)

// errProtocol reports a peer that broke the protocol.
func errProtocol(what string) error { return fmt.Errorf("ipc: protocol error: %s", what) }

// writeFrame implements WriteFrame. The header and the payload are written
// separately so a secret payload is never copied into another buffer.
func writeFrame(w io.Writer, kind FrameKind, payload []byte) error {
	if kind != FrameJSON && kind != FrameSecret {
		return errFrameKind
	}
	if len(payload)+1 > MaxFrame {
		return errFrameSize
	}
	var hdr [5]byte
	binary.BigEndian.PutUint32(hdr[:4], uint32(len(payload)+1))
	hdr[4] = byte(kind)
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	if len(payload) == 0 {
		return nil
	}
	_, err := w.Write(payload)
	return err
}

// readHeader reads a frame header and returns the kind and payload length.
func readHeader(r io.Reader) (FrameKind, int, error) {
	var hdr [5]byte
	if _, err := io.ReadFull(r, hdr[:4]); err != nil {
		return 0, 0, err
	}
	n := binary.BigEndian.Uint32(hdr[:4])
	if n == 0 || n > MaxFrame {
		return 0, 0, errFrameSize
	}
	if _, err := io.ReadFull(r, hdr[4:]); err != nil {
		return 0, 0, unexpectedEOF(err)
	}
	k := FrameKind(hdr[4])
	if k != FrameJSON && k != FrameSecret {
		return 0, 0, errFrameKind
	}
	return k, int(n) - 1, nil
}

func unexpectedEOF(err error) error {
	if errors.Is(err, io.EOF) {
		return io.ErrUnexpectedEOF
	}
	return err
}

// readFrame implements ReadFrame. The payload aliases buf when it fits,
// else a new buffer; callers wipe the returned payload of a secret frame.
func readFrame(r io.Reader, buf []byte) (FrameKind, []byte, error) {
	k, n, err := readHeader(r)
	if err != nil {
		return 0, nil, err
	}
	if cap(buf) >= n {
		buf = buf[:n]
	} else {
		buf = make([]byte, n)
	}
	if _, err := io.ReadFull(r, buf); err != nil {
		wipe(buf)
		return 0, nil, unexpectedEOF(err)
	}
	return k, buf, nil
}

// wipe zeroes b.
func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// destroyAll destroys every buffer of bs.
func destroyAll(bs []*memguard.LockedBuffer) {
	for _, b := range bs {
		if b != nil {
			b.Destroy()
		}
	}
}

// wire is one framed connection: JSON control frames, each followed by the
// secret frames it announces. Secret payloads are read straight into
// locked buffers and written straight from them (never via JSON or another
// heap buffer).
type wire struct {
	c            net.Conn
	wmu          sync.Mutex // serializes whole messages (responses and pushed events)
	writeTimeout time.Duration
	closeOnce    sync.Once
}

func newWire(c net.Conn, writeTimeout time.Duration) *wire {
	return &wire{c: c, writeTimeout: writeTimeout}
}

// write sends v as one JSON frame followed by one secret frame per buffer.
func (w *wire) write(v any, secrets []*memguard.LockedBuffer) error {
	if len(secrets) > maxSecrets {
		return errProtocol("too many secret frames")
	}
	for _, s := range secrets {
		if s == nil || !s.IsAlive() {
			return errProtocol("destroyed secret")
		}
	}
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("ipc: encode: %w", err)
	}
	if len(b)+1 > MaxFrame {
		return errFrameSize
	}
	w.wmu.Lock()
	defer w.wmu.Unlock()
	if w.writeTimeout > 0 {
		_ = w.c.SetWriteDeadline(time.Now().Add(w.writeTimeout))
		defer w.c.SetWriteDeadline(time.Time{})
	}
	if err := writeFrame(w.c, FrameJSON, b); err != nil {
		return err
	}
	for _, s := range secrets {
		if err := writeFrame(w.c, FrameSecret, s.Bytes()); err != nil {
			return err
		}
	}
	return nil
}

// readJSON reads one JSON frame into v, strictly: unknown fields and
// trailing data are protocol errors. A secret frame where a control frame
// is expected is discarded unread into a locked buffer and refused.
func (w *wire) readJSON(v any) error {
	k, n, err := readHeader(w.c)
	if err != nil {
		return err
	}
	if k == FrameSecret {
		b := memguard.NewBuffer(n)
		_, err := io.ReadFull(w.c, b.Bytes())
		b.Destroy()
		if err != nil {
			return unexpectedEOF(err)
		}
		return errProtocol("secret frame without a control frame")
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(w.c, buf); err != nil {
		return unexpectedEOF(err)
	}
	dec := json.NewDecoder(bytes.NewReader(buf))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return errProtocol("malformed control frame")
	}
	if dec.More() {
		return errProtocol("trailing data in control frame")
	}
	return nil
}

// readSecrets reads n secret frames into locked buffers.
func (w *wire) readSecrets(n int) ([]*memguard.LockedBuffer, error) {
	if n < 0 || n > maxSecrets {
		return nil, errProtocol("bad secret count")
	}
	out := make([]*memguard.LockedBuffer, 0, n)
	for i := 0; i < n; i++ {
		k, size, err := readHeader(w.c)
		if err != nil {
			destroyAll(out)
			return nil, unexpectedEOF(err)
		}
		if k != FrameSecret {
			destroyAll(out)
			return nil, errProtocol("control frame where a secret was announced")
		}
		b := memguard.NewBuffer(size)
		if size > 0 {
			if _, err := io.ReadFull(w.c, b.Bytes()); err != nil {
				b.Destroy()
				destroyAll(out)
				return nil, unexpectedEOF(err)
			}
		}
		out = append(out, b)
	}
	return out, nil
}

func (w *wire) close() error {
	var err error
	w.closeOnce.Do(func() { err = w.c.Close() })
	return err
}
