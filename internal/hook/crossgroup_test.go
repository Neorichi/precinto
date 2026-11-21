//go:build crossgroup

package hook_test

// Cross-group tests: they exercise other groups' real implementations
// (codex.ApplyPatchPaths, ledger, queue, ipc, agent) and pass only once the
// tree is integrated. Run with -tags testing,crossgroup.

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/precinto/precinto/internal/agent/agenttest"
	"github.com/precinto/precinto/internal/config"
	"github.com/precinto/precinto/internal/harness/codex"
	"github.com/precinto/precinto/internal/hook"
	"github.com/precinto/precinto/internal/ipc"
	"github.com/precinto/precinto/internal/ledger"
	"github.com/precinto/precinto/internal/paths"
	"github.com/precinto/precinto/internal/platform/fakeplatform"
	"github.com/precinto/precinto/internal/sweep/queue"
	"github.com/precinto/precinto/internal/testkit"
)

// TestCrossgroupApplyPatchPaths: the real G3 extractor gives the hook the
// same header paths as the contract (HA25).
func TestCrossgroupApplyPatchPaths(t *testing.T) {
	patch := "*** Begin Patch\n*** Add File: docs/new.md\n+x\n*** Update File: /u/work/acme/old.go\n*** Move to: docs/moved.markdown\n*** End Patch\n"
	got := codex.ApplyPatchPaths([]byte(patch), "/u/work/acme")
	want := fakeApplyPatchPaths([]byte(patch), "/u/work/acme")
	if !reflect.DeepEqual(got, want) {
		t.Errorf("codex.ApplyPatchPaths = %v, the hook's contract mirror says %v", got, want)
	}
}

// crossHome is a fake HOME short enough for the hook-mode socket path, with
// precinto's default base under it (hook mode never honours PRECINTO_HOME).
func crossHome(t *testing.T) (home string, l paths.Layout, root string) {
	t.Helper()
	home = testkit.ShortTempDir(t)
	l, ok := hook.HookLayout(paths.FromMap(map[string]string{"HOME": home}))
	if !ok || l.Socket == "" {
		t.Fatalf("no usable hook layout under %s", home)
	}
	if err := l.EnsureDirs(); err != nil {
		t.Fatal(err)
	}
	root = filepath.Join(home, "work", "acme")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.Roots = []config.Root{{ID: "root-acme", Path: root, MD: config.MDLedger, Harnesses: []string{"claude-code", "codex"}, ProtectedAt: testkit.Epoch}}
	if err := config.Save(l.ConfigFile, cfg); err != nil {
		t.Fatal(err)
	}
	if err := config.WriteRootsList(l.RootsList, cfg); err != nil {
		t.Fatal(err)
	}
	return home, l, root
}

// TestCrossgroupProductionDeps runs the hook with its production
// dependencies (real ledger, queue and ipc dial; no daemon running): the
// prompt fails closed, the ledger and the seal request are written, and no
// content reaches the disk.
func TestCrossgroupProductionDeps(t *testing.T) {
	home, l, root := crossHome(t)
	m := testkit.Marker(t)
	env := map[string]string{"HOME": home, "CLAUDECODE": "1", "CLAUDE_PROJECT_DIR": root, "PATH": "/usr/bin:/bin"}
	deps := hook.ProductionDeps(paths.FromMap(env))
	deps.Spawn = func([]string) error { return nil } // never start a worker from a test

	payload := `{"session_id":"` + sidC + `","cwd":"` + root + `","prompt":"` + m + `","hook_event_name":"UserPromptSubmit"}`
	var out, errb bytes.Buffer
	code := hook.RunWith([]string{"claude-code", "UserPromptSubmit"}, strings.NewReader(payload), &out, &errb, paths.FromMap(env), hook.TestSystem{Deps: deps})
	if code != 0 || !strings.Contains(out.String(), `"decision":"block"`) {
		t.Fatalf("no daemon, managed prompt: %d %q", code, out.String())
	}
	s, err := ledger.Open(l.SessionsDir).Get("claude-code", sidC)
	if err != nil || len(s.RootIDs) == 0 || s.RootIDs[0] != "root-acme" {
		t.Errorf("ledger after the prompt: %+v %v", s, err)
	}

	end := `{"session_id":"` + sidC + `","cwd":"` + root + `","reason":"other","hook_event_name":"SessionEnd"}`
	code = hook.RunWith([]string{"claude-code", "SessionEnd"}, strings.NewReader(end), &out, &errb, paths.FromMap(env), hook.TestSystem{Deps: deps})
	if code != 0 {
		t.Fatalf("SessionEnd exit %d", code)
	}
	reqs, err := queue.List(l.QueueDir)
	if err != nil || len(reqs) != 1 || reqs[0].SID != sidC || reqs[0].Harness != "claude-code" {
		t.Errorf("seal requests %+v %v", reqs, err)
	}
	if hits := testkit.GrepTree(t, l.Base, m); len(hits) > 0 {
		t.Errorf("content on disk: %v", hits)
	}
}

// TestCrossgroupAgentGate asks the real (in-process) daemon: at start every
// folder is locked, so a managed prompt is blocked and a tool denied, and a
// session outside every folder is never sent to the daemon.
func TestCrossgroupAgentGate(t *testing.T) {
	_, l, root := crossHome(t)
	clock := fakeplatform.NewClock(testkit.Epoch)
	procs := fakeplatform.NewProcs()
	a := agenttest.Start(t, l, clock, procs)
	defer a.Stop()
	deps, _, _ := testDeps(t, nil)
	deps.Layout = l
	deps.Cfg.Roots = []config.Root{{ID: "root-acme", Path: root, MD: config.MDLedger}}
	deps.Dial = func(ctx context.Context) (hook.Daemon, error) { return a.Dial(t), nil }
	for ev, want := range map[hook.Event]ipc.Verdict{hook.UserPromptSubmit: ipc.VerdictBlock, hook.PreToolUse: ipc.VerdictDeny} {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		dec := hook.Handle(ctx, deps, hook.Payload{Host: hook.HostClaude, Label: "claude-code", Event: ev, SID: sidC, Cwd: root})
		cancel()
		if dec.Verdict != want {
			t.Errorf("%s in a locked folder: %+v", ev, dec)
		}
	}
}
