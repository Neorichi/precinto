//go:build darwin || linux

package wrapper_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/Neorichi/precinto/internal/config"
	"github.com/Neorichi/precinto/internal/harness"
	"github.com/Neorichi/precinto/internal/wrapper"
)

// Environment of the test binary's own subprocesses.
const (
	// helperEnv selects the wrapper-process mode of the test binary: tests
	// that stop the whole wrapper (job control) or need it to be a
	// terminal's foreground process group run it as a subprocess.
	helperEnv = "PRECINTO_WRAPPER_TEST_HELPER"
	// tokenEnv, lifelineEnv and helpersEnv configure a probe run of the
	// test binary (TestHelpersDieWithTheirTest): its token, the fd of its
	// own lifeline, and the directory of the helper binaries to reuse.
	tokenEnv    = "PRECINTO_WRAPPER_TEST_TOKEN"
	lifelineEnv = "PRECINTO_WRAPPER_TEST_LIFELINE"
	helpersEnv  = "PRECINTO_WRAPPER_TEST_HELPERS"
)

// exitLifeline is how every helper exits when its lifeline ends or its hard
// lifetime runs out; helperMaxLife is that lifetime.
const (
	exitLifeline  = 70
	helperMaxLife = 2 * time.Minute
)

// testToken is carried in the argv of every helper process this test
// binary starts (and of their own helpers), so the processes left with it
// are this binary's and nobody else's.
var testToken string

// testHeartbeat is the subscription heartbeat timeout of the tests (the
// fake daemon beats every 50 ms; crossgroup_test.go raises it for the real
// daemon, which beats every second).
var testHeartbeat = time.Second

func TestMain(m *testing.M) {
	// Short subscription timings for every test (set once: goroutines of a
	// finished Run may still read them).
	wrapper.SetTimings(testHeartbeat, 50*time.Millisecond, 20*time.Millisecond)
	if mode := startEnv.Get(helperEnv); mode != "" {
		os.Exit(helperMain(mode, os.Args[1:]))
	}
	testToken = startEnv.Get(tokenEnv)
	if testToken == "" {
		testToken = newToken()
	}
	if fd := startEnv.Get(lifelineEnv); fd != "" {
		// A probe run is a helper of its parent test: same lifeline and
		// hard lifetime.
		watchLifeline(inheritedFile(fd, "lifeline"))
		time.AfterFunc(helperMaxLife, func() { os.Exit(exitLifeline) })
	}
	code := m.Run()
	if helpersDir != "" && !helpersShared {
		_ = os.RemoveAll(helpersDir)
	}
	// A helper still running now outlived its test, its cleanup and its
	// lifeline (TESTPLAN §1 rule 8): kill it and fail the package.
	if left := sweepToken(testToken, 3*time.Second); len(left) > 0 {
		fmt.Fprintf(os.Stderr, "FAIL: %d helper process(es) outlived their test and were killed:\n", len(left))
		for _, p := range left {
			fmt.Fprintf(os.Stderr, "  pid %d %s\n", p.ID.PID, filepath.Base(p.Exe))
		}
		if code == 0 {
			code = 1
		}
	}
	os.Exit(code)
}

func newToken() string {
	var b [16]byte
	_, _ = rand.Read(b[:]) // never fails (Go ≥ 1.24)
	return "precinto-wrapper-test-" + hex.EncodeToString(b[:])
}

// inheritedFile wraps an inherited descriptor once (an *os.File closes its
// descriptor when it is garbage-collected).
func inheritedFile(fd, name string) *os.File {
	n, err := strconv.Atoi(fd)
	if err != nil || n < 3 {
		return nil
	}
	return os.NewFile(uintptr(n), name)
}

// watchLifeline exits the process once f, the read end of a lifeline,
// reaches EOF (nobody writes to it).
func watchLifeline(f *os.File) {
	if f == nil {
		return
	}
	go func() {
		buf := make([]byte, 16)
		for {
			if _, err := f.Read(buf); err != nil {
				os.Exit(exitLifeline)
			}
		}
	}()
}

// helperMain is the wrapper process: "proxy CHILD ARGS…" runs StartProxy on
// stdin; "run [-no-pty] CHILD ARGS…" runs wrapper.Run with a fake backend
// for an unmanaged launch (no daemon). Before them it takes -lifeline FD
// (it exits with 70 when the test's lifeline ends, and its child gets the
// lifeline as fd 3) and -test-token T. It exits with the child's code, and
// after helperMaxLife with 70.
func helperMain(mode string, args []string) int {
	var life *os.File
	noPTY := false
flags:
	for len(args) > 0 {
		switch {
		case args[0] == "-lifeline" && len(args) > 1:
			life = inheritedFile(args[1], "lifeline")
			args = args[2:]
		case args[0] == "-test-token" && len(args) > 1:
			args = args[2:]
		case args[0] == "-no-pty" && mode == "run":
			noPTY, args = true, args[1:]
		default:
			break flags
		}
	}
	watchLifeline(life)
	time.AfterFunc(helperMaxLife, func() { os.Exit(exitLifeline) })
	if len(args) == 0 {
		return 64
	}
	switch mode {
	case "proxy":
		cmd := exec.Command(args[0], args[1:]...)
		cmd.Env = []string{"TERM=xterm-256color"}
		if life != nil {
			cmd.ExtraFiles = []*os.File{life}
		}
		p, err := wrapper.StartProxy(cmd, os.Stdin, wrapper.ProxyOptions{})
		if err != nil {
			fmt.Fprintln(os.Stderr, "helper: start:", err)
			return 70
		}
		code, _ := p.Wait()
		return code
	case "run":
		plan := harness.LaunchPlan{Harness: "generic", Mode: harness.LaunchInteractive, Argv: args}
		b := newFakeBackend(plan)
		b.takeLifeline(life)
		code, err := wrapper.Run(context.Background(), wrapper.Options{
			Harness: "generic",
			Argv:    args,
			Env:     startEnv.Without(helperEnv),
			NoPTY:   noPTY,
			Stdin:   os.Stdin,
			Stdout:  os.Stdout,
			Stderr:  os.Stderr,
			Policy:  config.Default().Policy,
			Backend: b,
		})
		if err != nil {
			fmt.Fprintln(os.Stderr, "helper: run:", err)
		}
		return code
	}
	return 64
}
