package ipc_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"

	"github.com/precinto/precinto/internal/ipc"
)

func TestFrameRoundTrip(t *testing.T) {
	var b bytes.Buffer
	if err := ipc.WriteFrame(&b, ipc.FrameJSON, []byte(`{"a":1}`)); err != nil {
		t.Fatal(err)
	}
	if err := ipc.WriteFrame(&b, ipc.FrameSecret, []byte{1, 2, 3}); err != nil {
		t.Fatal(err)
	}
	if err := ipc.WriteFrame(&b, ipc.FrameSecret, nil); err != nil {
		t.Fatal(err)
	}
	raw := b.Bytes()
	if binary.BigEndian.Uint32(raw[:4]) != 8 || raw[4] != 'J' {
		t.Fatalf("header = % x (length counts kind+payload)", raw[:5])
	}
	buf := make([]byte, 2)
	k, p, err := ipc.ReadFrame(&b, buf)
	if err != nil || k != ipc.FrameJSON || string(p) != `{"a":1}` {
		t.Fatalf("frame 1 = %c %q %v", k, p, err)
	}
	k, p, err = ipc.ReadFrame(&b, buf)
	if err != nil || k != ipc.FrameSecret || !bytes.Equal(p, []byte{1, 2, 3}) {
		t.Fatalf("frame 2 = %c %v %v", k, p, err)
	}
	k, p, err = ipc.ReadFrame(&b, buf)
	if err != nil || k != ipc.FrameSecret || len(p) != 0 {
		t.Fatalf("frame 3 = %c %v %v", k, p, err)
	}
	if _, _, err := ipc.ReadFrame(&b, buf); !errors.Is(err, io.EOF) {
		t.Fatalf("end = %v", err)
	}
}

func TestFrameLimits(t *testing.T) {
	var b bytes.Buffer
	if err := ipc.WriteFrame(&b, ipc.FrameJSON, make([]byte, ipc.MaxFrame)); err == nil {
		t.Fatal("frame above MaxFrame written")
	}
	if err := ipc.WriteFrame(&b, ipc.FrameJSON, make([]byte, ipc.MaxFrame-1)); err != nil {
		t.Fatalf("largest frame refused: %v", err)
	}
	if err := ipc.WriteFrame(&b, 'X', nil); err == nil {
		t.Fatal("unknown kind written")
	}
	hdr := func(n uint32, kind byte) []byte {
		h := make([]byte, 5)
		binary.BigEndian.PutUint32(h, n)
		h[4] = kind
		return h
	}
	for name, in := range map[string][]byte{
		"zero length":  hdr(0, 'J'),
		"too long":     hdr(ipc.MaxFrame+1, 'J'),
		"unknown kind": append(hdr(2, 'X'), 'a'),
		"truncated":    append(hdr(10, 'S'), 1, 2),
		"short header": {0, 0},
	} {
		if _, _, err := ipc.ReadFrame(bytes.NewReader(in), nil); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if _, _, err := ipc.ReadFrame(bytes.NewReader(hdr(10, 'S')[:5]), nil); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Errorf("payload missing = %v", err)
	}
}

func TestExitCodes(t *testing.T) {
	for code, want := range map[ipc.Code]int{
		ipc.CodeLocked: 3, ipc.CodeUnauthorized: 3, ipc.CodeAgentContext: 3, ipc.CodeCancelled: 3,
		ipc.CodeNoUI: 3, ipc.CodeRateLimited: 3, ipc.CodeBadSecret: 3, ipc.CodeLive: 4, ipc.CodeVerify: 5, ipc.CodeNotLogged: 5,
		ipc.CodeBadRequest: 2, ipc.CodeVersion: 1, ipc.CodeInternal: 1, "other": 1,
	} {
		e := &ipc.Error{Code: code, Msg: "m"}
		if got := e.ExitCode(); got != want {
			t.Errorf("%s → %d, want %d", code, got, want)
		}
		if e.Error() != string(code)+": m" {
			t.Errorf("Error() = %q", e.Error())
		}
	}
}

func TestKeySetNil(t *testing.T) {
	var k *ipc.KeySet
	if _, ok := k.Key("x"); ok {
		t.Fatal("nil KeySet returned a key")
	}
	k.Destroy()
	(&ipc.KeySet{}).Destroy()
}
