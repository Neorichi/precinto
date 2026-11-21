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
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	_, err := ipc.Dial(ctx, ipc.DialOptions{Layout: l, Insecure: true})
	if err == nil || errors.Is(err, ipc.ErrUntrustedServer) {
		t.Fatalf("Dial(Insecure) in a testing build = %v (the squatter does not answer hello)", err)
	}
	_ = h.wait(t)
	if b, _ := os.ReadFile(result); string(b) == "0" {
		t.Fatal("hello not sent although Insecure was honoured")
	}
}
