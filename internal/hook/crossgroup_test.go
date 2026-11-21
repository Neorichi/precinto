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
	"github.com/precinto/precinto/internal/ui"
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
	l, err := paths.HookLayout(paths.FromMap(map[string]string{"HOME": home}))
	if err != nil {
		t.Fatalf("no usable hook layout under %s: %v", home, err)
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
	deps.Dial = agentDial(a)
	for ev, want := range map[hook.Event]ipc.Verdict{hook.UserPromptSubmit: ipc.VerdictBlock, hook.PreToolUse: ipc.VerdictDeny} {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		dec := hook.Handle(ctx, deps, hook.Payload{Host: hook.HostClaude, Label: "claude-code", Event: ev, SID: sidC, Cwd: root})
		cancel()
		if dec.Verdict != want {
			t.Errorf("%s in a locked folder: %+v", ev, dec)
		}
	}
}

// agentDial is a hook Dial to the in-process agent that never calls
// t.Fatalf (agenttest Client, CC-53): the hook may dial from its own
// goroutine.
func agentDial(a *agenttest.Agent) func(context.Context) (hook.Daemon, error) {
	return func(ctx context.Context) (hook.Daemon, error) {
		c, err := a.Client(ctx)
		if err != nil {
			return nil, err
		}
		return c, nil
	}
}

// TestCrossgroupCodexWrongHome (D31, D72): in a folder whose harnesses
// list codex, the real daemon blocks a Codex session whose CODEX_HOME is
// not the folder's per-root home with C3.codexhome, as the hook forwards
// it; the same session in its per-root home gets the locked-folder answer
// instead.
func TestCrossgroupCodexWrongHome(t *testing.T) {
	home, l, root := crossHome(t) // root-acme lists claude-code and codex
	a := agenttest.Start(t, l, fakeplatform.NewClock(testkit.Epoch), fakeplatform.NewProcs())
	defer a.Stop()
	deps, _, _ := testDeps(t, nil)
	deps.Layout = l
	deps.Cfg.Roots = []config.Root{{ID: "root-acme", Path: root, MD: config.MDLedger, Harnesses: []string{"claude-code", "codex"}}}
	deps.Dial = agentDial(a)
	wrong := ui.Format(ui.MsgCodexWrongHome, ui.Vars{Folder: root}) // the agenttest daemon has no HOME: full paths
	gate := func(ev hook.Event, codexHome string) hook.Decision {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return hook.Handle(ctx, deps, hook.Payload{Host: hook.HostCodex, Label: "codex", Event: ev, SID: sidX,
			TurnID: "00000000-0000-7000-8000-0000000000b1", Cwd: root, CodexHome: codexHome})
	}
	userHome := filepath.Join(home, ".codex")
	if d := gate(hook.UserPromptSubmit, userHome); d.Verdict != ipc.VerdictBlock || d.UserMessage != wrong {
		t.Errorf("prompt from the user's own Codex home: %+v, want C3.codexhome %q", d, wrong)
	}
	if d := gate(hook.PreToolUse, userHome); d.Verdict != ipc.VerdictDeny || d.ModelMessage != wrong {
		t.Errorf("tool from the user's own Codex home: %+v, want C3.codexhome", d)
	}
	if d := gate(hook.UserPromptSubmit, ""); d.Verdict != ipc.VerdictBlock || d.UserMessage != wrong {
		t.Errorf("prompt without CODEX_HOME (~/.codex): %+v, want C3.codexhome", d)
	}
	// In its per-root home the session is only gated by the lock (every
	// folder is locked when the daemon starts).
	if d := gate(hook.UserPromptSubmit, l.CodexHome("root-acme")); d.Verdict != ipc.VerdictBlock || d.UserMessage == wrong || d.UserMessage == "" {
		t.Errorf("prompt from the per-root home in a locked folder: %+v, want the locked-folder block", d)
	}
}
