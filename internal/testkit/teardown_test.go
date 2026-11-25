package testkit_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/precinto/precinto/internal/paths"
	"github.com/precinto/precinto/internal/testkit"
)

// D129: StopInstallation ends the agent of a test's installation with
// `precinto agent --stop` and the workers it spawned, and leaves nothing
// of that installation running; the check after it reports what still
// runs and names the installation's folders, which it never signals.
func TestStopInstallationEndsTheAgentAndItsWorkers(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the precinto binary (slow)")
	}
	bin := testkit.BuildBinary(t, "testing")
	h := testkit.NewHome(t)
	env := h.Env.Environ()
	// The agent as an autostart runs it: detached, in a session of its own
	// (it spawns its start-up sweep worker the same way).
	agent := exec.Command(bin, "agent")
	agent.Env, agent.Dir = env, "/"
	agent.SysProcAttr = testkit.NewSession()
	if err := agent.Start(); err != nil {
		t.Fatal(err)
	}
	exited := make(chan struct{})
	go func() { _ = agent.Wait(); close(exited) }()
	t.Cleanup(func() {
		select {
		case <-exited:
		default:
			_ = agent.Process.Kill() // started by this test
			<-exited
		}
	})
	deadline := time.Now().Add(15 * time.Second)
	for {
		if _, err := os.Stat(h.Layout.Socket); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the agent did not listen")
		}
		time.Sleep(50 * time.Millisecond)
	}
	if left := testkit.Leftovers(bin); len(left) == 0 {
		t.Fatal("no process of the installation runs: nothing to stop")
	}
	if r := record(t, func(tb testing.TB) { testkit.StopInstallation(tb, bin, env, h.Dir) }); r.Failed() {
		t.Fatalf("StopInstallation failed a clean installation: %s", r.text())
	}
	select {
	case <-exited:
	case <-time.After(5 * time.Second):
		t.Fatal("the agent still runs after StopInstallation")
	}
	if left := testkit.Leftovers(bin, h.Dir); len(left) > 0 {
		t.Fatalf("left running: %v", left)
	}

	// A process of the test that names the installation's folders and is
	// still running fails the check; it is never signalled.
	stray := filepath.Join(h.Dir, "stray.log")
	if err := os.WriteFile(stray, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	tail := exec.Command("/usr/bin/tail", "-f", stray)
	tail.Env = []string{}
	if err := tail.Start(); err != nil {
		t.Fatal(err)
	}
	tailDone := make(chan struct{})
	go func() { _ = tail.Wait(); close(tailDone) }()
	defer func() { _ = tail.Process.Kill(); <-tailDone }() // started by this test
	r := record(t, func(tb testing.TB) { testkit.StopInstallation(tb, bin, env, h.Dir) })
	if !r.Failed() || !strings.Contains(r.text(), "still run") || !strings.Contains(r.text(), "tail") {
		t.Fatalf("a process naming the installation's folder was not reported: %q", r.text())
	}
	select {
	case <-tailDone:
		t.Fatal("StopInstallation signalled a process that does not run the test's binary")
	default:
	}
}

// StopInstallation never reaches the user's own agent: an environment
// without a throwaway HOME or PRECINTO_HOME is refused before anything
// runs.
func TestStopInstallationRefusesTheRealInstallation(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "never-run")
	for name, env := range map[string][]string{
		"no HOME":   nil,
		"real HOME": {"HOME=" + paths.FromOS().Get("HOME")},
	} {
		r := record(t, func(tb testing.TB) { testkit.StopInstallation(tb, bin, env) })
		if !strings.Contains(r.text(), "refusing to stop an agent") {
			t.Errorf("%s: %q", name, r.text())
		}
	}
}
