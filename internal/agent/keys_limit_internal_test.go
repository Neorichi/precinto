//go:build darwin || linux

package agent

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/precinto/precinto/internal/ipc"
)

// CC-17: a keys request names at most ipc.MaxKeysPerRequest capsules; a
// bigger one is refused as bad_request before anything is looked up.
func TestKeysRequestBound(t *testing.T) {
	x := startTD(t)
	c := x.dial()
	ctx := context.Background()
	refs := func(n int) []ipc.CapsuleRef {
		out := make([]ipc.CapsuleRef, n)
		for i := range out {
			out[i] = ipc.CapsuleRef{Path: fmt.Sprintf("md/%032x/g000001.pcap", i)}
		}
		return out
	}
	if _, _, err := c.Keys(ctx, ipc.KeysReq{Capsules: refs(ipc.MaxKeysPerRequest + 1), Purpose: ipc.PurposeRestore}); ipcCode(err) != ipc.CodeBadRequest {
		t.Fatalf("%d capsules = %v, want bad_request", ipc.MaxKeysPerRequest+1, err)
	}
	ks, resp, err := c.Keys(ctx, ipc.KeysReq{Capsules: refs(ipc.MaxKeysPerRequest), Purpose: ipc.PurposeRestore})
	if err != nil {
		t.Fatalf("%d capsules = %v", ipc.MaxKeysPerRequest, err)
	}
	ks.Destroy()
	if len(resp.Denied) != ipc.MaxKeysPerRequest {
		t.Fatalf("denied %d of %d unlogged capsules", len(resp.Denied), ipc.MaxKeysPerRequest)
	}
}

// CC-17: the daemon raises RLIMIT_MEMLOCK's soft limit to the hard one at
// start. Tested in a re-executed child, which first lowers its own soft
// limit; the test process's limits are never touched.
func TestRaiseMemlockInAChild(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe, "-test.run=^TestMemlockHelper$", "-test.count=1", "--", "memlock-child")
	cmd.Env = []string{"HOME=/nonexistent"}
	cmd.WaitDelay = time.Second
	out, err := cmd.Output() // reaps the child; the context kills it on a hang
	if err != nil {
		t.Fatalf("child: %v (%s)", err, out)
	}
	line := ""
	for _, l := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(l, "memlock ") {
			line = l
		}
	}
	if line == "memlock skip" {
		t.Skip("RLIMIT_MEMLOCK has a zero hard limit here")
	}
	var lowered, soft, hard uint64
	if _, err := fmt.Sscanf(line, "memlock lowered=%d soft=%d hard=%d", &lowered, &soft, &hard); err != nil {
		t.Fatalf("child said %q: %v", out, err)
	}
	if lowered >= hard || soft != hard {
		t.Fatalf("memlock lowered to %d, then soft %d, hard %d: not raised to the hard limit", lowered, soft, hard)
	}
}

// TestMemlockHelper is the body of the child of TestRaiseMemlockInAChild
// (a no-op test otherwise).
func TestMemlockHelper(t *testing.T) {
	if len(os.Args) < 2 || os.Args[len(os.Args)-1] != "memlock-child" {
		return
	}
	var r syscall.Rlimit
	if err := syscall.Getrlimit(rlimitMemlock, &r); err != nil {
		fmt.Println("memlock error", err)
		os.Exit(1)
	}
	if r.Max == 0 {
		fmt.Println("memlock skip")
		os.Exit(0)
	}
	low := r.Max / 2
	if low > 32<<10 {
		low = 32 << 10
	}
	r.Cur = low
	if err := syscall.Setrlimit(rlimitMemlock, &r); err != nil {
		fmt.Println("memlock error", err)
		os.Exit(1)
	}
	if err := raiseMemlock(); err != nil {
		fmt.Println("memlock error", err)
		os.Exit(1)
	}
	if err := syscall.Getrlimit(rlimitMemlock, &r); err != nil {
		fmt.Println("memlock error", err)
		os.Exit(1)
	}
	fmt.Println("memlock lowered=" + strconv.FormatUint(low, 10) + " soft=" + strconv.FormatUint(r.Cur, 10) + " hard=" + strconv.FormatUint(r.Max, 10))
	os.Exit(0)
}
