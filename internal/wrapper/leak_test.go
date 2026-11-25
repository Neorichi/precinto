//go:build darwin || linux

package wrapper_test

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/Neorichi/precinto/internal/wrapper"
)

// probeEnv makes a probe run of this test binary start helpers and fail at
// once, in the way it names (TestHelpersDieWithTheirTest).
const probeEnv = "PRECINTO_WRAPPER_TEST_PROBE"

// TestHelpersDieWithTheirTest is TESTPLAN §1 rule 8 for this package: a
// test that fails right after starting its helpers (a PTY child that
// ignores SIGTERM with a grandchild in a process group of its own, a
// sleeper in the test's session, a wrapper process with its own PTY child)
// leaves no process carrying its token, whether it fails, panics, or its
// process exits without running any cleanup (then only the lifelines end
// them).
func TestHelpersDieWithTheirTest(t *testing.T) {
	if testing.Short() {
		t.Skip("runs the test binary")
	}
	helpers(t) // built once; the probe runs reuse the binaries
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"fatal", "panic", "exit"} {
		t.Run(mode, func(t *testing.T) {
			token := newToken()
			// The probe carries this binary's token too (as a test
			// argument), and a lifeline of this test like any helper.
			cmd := exec.Command(self, "-test.run=^TestLeakProbe$", "-test.count=1", "probe-of="+testToken)
			// The probe's own temporary directories (t.TempDir) go below
			// this test's: a probe that exits without its cleanup leaves
			// nothing in the system's TMPDIR (TESTPLAN §1.8).
			cmd.Env = append(childEnv(t).With("TMPDIR", t.TempDir()).Environ(), probeEnv+"="+mode, tokenEnv+"="+token,
				lifelineEnv+"=3", helpersEnv+"="+helpersDir)
			cmd.ExtraFiles = []*os.File{newLifeline(t).r}
			goR, goW, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer goW.Close()
			cmd.Stdin = goR
			out := &syncBuffer{}
			cmd.Stdout, cmd.Stderr = out, out
			probe := startHelper(t, cmd)
			goR.Close()
			// Its helpers run and carry its token: the check below is not
			// vacuous. Then the probe may fail.
			deadline := time.Now().Add(waitTimeout)
			for !strings.Contains(out.String(), "PROBE-STARTED") {
				if time.Now().After(deadline) {
					t.Fatalf("the probe did not start its helpers:\n%s", tail(out.String(), 2000))
				}
				time.Sleep(10 * time.Millisecond)
			}
			if n := len(withToken(token)); n < probeHelpers {
				t.Fatalf("%d running process(es) carry the probe's token, want its %d helpers", n, probeHelpers)
			}
			if _, err := goW.Write([]byte("fail\n")); err != nil {
				t.Fatal(err)
			}
			if code := probe.wait(t); code == 0 {
				t.Fatalf("the probe passed although it fails on purpose:\n%s", tail(out.String(), 2000))
			}
			if left := sweepToken(token, waitTimeout); len(left) > 0 {
				t.Fatalf("%d helper process(es) outlived a test that ended by %s (killed now)", len(left), mode)
			}
		})
	}
}

// probeHelpers is how many helper processes TestLeakProbe starts: the PTY
// child and its grandchild, the sleeper, the wrapper process and its child.
const probeHelpers = 5

// TestLeakProbe starts helpers, waits for a line on stdin and fails; only
// TestHelpersDieWithTheirTest runs it (probeEnv).
func TestLeakProbe(t *testing.T) {
	mode := startEnv.Get(probeEnv)
	if mode == "" {
		t.Skip("run by TestHelpersDieWithTheirTest")
	}
	bins := helpers(t)
	r := startRig(t, wrapper.ProxyOptions{}, nil, "-ignore-term")
	m := r.term.mark()
	r.term.typeKeys("G")
	r.term.waitFor("GRANDCHILD pid=", m)
	testSibling(t, bins, newProbe(t))
	tp := newTerm(t, 100, 30)
	cmd := helperCmd(t, tp, "proxy", bins.child("-ignore-term")...)
	asSessionLeader(cmd)
	startHelper(t, cmd)
	tp.waitForRe(readyRe, 0)
	fmt.Println("PROBE-STARTED")
	_, _ = bufio.NewReader(os.Stdin).ReadString('\n') // the parent saw the helpers
	switch mode {
	case "panic":
		panic("probe: failing right after starting helpers")
	case "exit":
		// No cleanup and no TestMain sweep run: only the lifelines are left.
		os.Exit(3)
	}
	t.Fatal("probe: failing right after starting helpers")
}
