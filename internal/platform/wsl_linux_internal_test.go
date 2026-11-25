//go:build linux

package platform

import (
	"context"
	"testing"

	"github.com/Neorichi/precinto/internal/paths"
)

// D156: inside WSL logind does not see the Windows desktop: the screen
// lock and the HID idle are unknown, whatever loginctl would say; and the
// distribution's virtual disk says nothing about BitLocker: unknown.
func TestScreenAndDiskUnknownUnderWSL(t *testing.T) {
	fakeWSL(t, paths.WSL{Version: 2, MountRoot: "/mnt/"})
	s, err := sysReadScreen(context.Background())
	if err != nil || s.LockKnown || s.IdleKnown || s.Locked || s.At.IsZero() {
		t.Fatalf("ReadScreen under WSL = %+v, %v; want unknown", s, err)
	}
	on, known, err := diskEncryption(context.Background())
	if on || known || err != nil {
		t.Fatalf("DiskEncryption under WSL = %v, %v, %v; want unknown", on, known, err)
	}
}
