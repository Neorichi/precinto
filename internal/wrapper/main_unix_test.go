//go:build darwin || linux

package wrapper_test

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/precinto/precinto/internal/config"
	"github.com/precinto/precinto/internal/harness"
	"github.com/precinto/precinto/internal/wrapper"
)

// helperEnv selects the wrapper-process mode of the test binary: tests
// that stop the whole wrapper (job control) or need it to be a terminal's
// foreground process group run it as a subprocess of its own.
const helperEnv = "PRECINTO_WRAPPER_TEST_HELPER"

func TestMain(m *testing.M) {
	// Short subscription timings for every test (set once: goroutines of a
	// finished Run may still read them).
	wrapper.SetTimings(time.Second, 50*time.Millisecond, 20*time.Millisecond)
	if mode := startEnv.Get(helperEnv); mode != "" {
		os.Exit(helperMain(mode, os.Args[1:]))
	}
	code := m.Run()
	if helpersDir != "" {
		_ = os.RemoveAll(helpersDir)
	}
	os.Exit(code)
}

// helperMain is the wrapper process: "proxy CHILD ARGS…" runs StartProxy on
// stdin; "run [-no-pty] CHILD ARGS…" runs wrapper.Run with a fake backend
// for an unmanaged launch (no daemon). It exits with the child's code.
func helperMain(mode string, args []string) int {
	switch mode {
	case "proxy":
		if len(args) == 0 {
			return 64
		}
		cmd := exec.Command(args[0], args[1:]...)
		cmd.Env = []string{"TERM=xterm-256color"}
		p, err := wrapper.StartProxy(cmd, os.Stdin, wrapper.ProxyOptions{})
		if err != nil {
			fmt.Fprintln(os.Stderr, "helper: start:", err)
			return 70
		}
		code, _ := p.Wait()
		return code
	case "run":
		noPTY := false
		if len(args) > 0 && args[0] == "-no-pty" {
			noPTY, args = true, args[1:]
		}
		if len(args) == 0 {
			return 64
		}
		plan := harness.LaunchPlan{Harness: "generic", Mode: harness.LaunchInteractive, Argv: args}
		b := newFakeBackend(plan)
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
