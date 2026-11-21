//go:build darwin || linux

package wrapper

import (
	"syscall"
	"testing"
)

// TestDecodeWait pins the wait-status bits, in particular a SIGSTOP stop,
// which darwin's syscall.WaitStatus.Stopped reports as false.
func TestDecodeWait(t *testing.T) {
	cases := []struct {
		status uint32
		want   waitResult
		ok     bool
	}{
		{0x0000, waitResult{exited: true, code: 0}, true},
		{0x0700, waitResult{exited: true, code: 7}, true},
		{0x000f, waitResult{exited: true, code: 128 + 15}, true}, // SIGTERM
		{0x0089, waitResult{exited: true, code: 128 + 9}, true},  // SIGKILL with core bit
		{uint32(syscall.SIGSTOP)<<8 | 0x7f, waitResult{stopped: true, stopSign: syscall.SIGSTOP}, true},
		{uint32(syscall.SIGTSTP)<<8 | 0x7f, waitResult{stopped: true, stopSign: syscall.SIGTSTP}, true},
		{0xffff, waitResult{}, false}, // linux "continued"
	}
	for _, tc := range cases {
		got, ok := decodeWait(tc.status)
		if ok != tc.ok || got != tc.want {
			t.Errorf("decodeWait(%#x) = %+v, %v; want %+v, %v", tc.status, got, ok, tc.want, tc.ok)
		}
	}
}
