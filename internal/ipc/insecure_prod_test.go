//go:build !testing

package ipc_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Neorichi/precinto/internal/ipc"
)

// TestInsecureIgnoredInProductionBuilds: DialOptions.Insecure has no
// effect without -tags testing (D6).
func TestInsecureIgnoredInProductionBuilds(t *testing.T) {
	l := layout(t)
	if err := os.Mkdir(l.RunDir, 0o700); err != nil {
		t.Fatal(err)
	}
	result := filepath.Join(t.TempDir(), "received")
	h := runHelper(t, helperCopy(t), "listen", l.Socket, result)
	h.waitReady(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := ipc.Dial(ctx, ipc.DialOptions{Layout: l, Insecure: true}); !errors.Is(err, ipc.ErrUntrustedServer) {
		t.Fatalf("Dial(Insecure) in a production build = %v, want ErrUntrustedServer", err)
	}
	_ = h.wait(t)
}
