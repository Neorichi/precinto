//go:build testing

package ipc_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/precinto/precinto/internal/ipc"
)

// TestInsecureHonouredInTestingBuilds: with -tags testing, Insecure skips
// the executable check (and only that: the hello is then sent).
func TestInsecureHonouredInTestingBuilds(t *testing.T) {
	l := layout(t)
	if err := os.Mkdir(l.RunDir, 0o700); err != nil {
		t.Fatal(err)
	}
	result := filepath.Join(t.TempDir(), "received")
	h := runHelper(t, helperCopy(t), "listen", l.Socket, result)
	h.waitReady(t)
	// The squatter hangs up after the first bytes, so the dial ends as
	// soon as hello was sent; the generous bound only covers a loaded
	// machine (it once hung for ten minutes on a 500 ms one).
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_, err := ipc.Dial(ctx, ipc.DialOptions{Layout: l, Insecure: true, Timeout: 30 * time.Second})
	if err == nil || errors.Is(err, ipc.ErrUntrustedServer) {
		t.Fatalf("Dial(Insecure) in a testing build = %v (the squatter does not answer hello)", err)
	}
	if err := h.wait(t); err != nil {
		t.Fatalf("helper: %v", err)
	}
	if b, _ := os.ReadFile(result); string(b) == "0" || len(b) == 0 {
		t.Fatalf("hello not sent although Insecure was honoured (the squatter read %q bytes)", b)
	}
}
