package hook_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/precinto/precinto/internal/config"
	"github.com/precinto/precinto/internal/hook"
	"github.com/precinto/precinto/internal/ipc"
	"github.com/precinto/precinto/internal/ledger"
	"github.com/precinto/precinto/internal/paths"
	"github.com/precinto/precinto/internal/sweep/queue"
	"github.com/precinto/precinto/internal/testkit"
)

// fileLedger writes every appended event as a JSON line below the layout,
// so that the leak check greps what a real ledger would hold on disk.
type fileLedger struct {
	*fakeLedger
	dir string
}

func (f fileLedger) Append(e ledger.Event) error {
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	p := filepath.Join(f.dir, e.Harness, e.SID+".jsonl")
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	fh, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer fh.Close()
	if _, err := fh.Write(append(b, '\n')); err != nil {
		return err
	}
	return f.fakeLedger.Append(e)
}

// TestHookStdinNeverLogged (SEC-25, I7): payloads with a marker in every
// content field, through every event and host, including malformed JSON,
// leave no marker on disk, in the answer or in any daemon request.
func TestHookStdinNeverLogged(t *testing.T) {
	restore := hook.SetApplyPatchPaths(fakeApplyPatchPaths)
	defer restore()
	m := testkit.Marker(t)
	content := map[string]any{
		"prompt": m, "custom_instructions": m, "compact_summary": m, "last_assistant_message": m,
		"message": m, "error_details": m, "tool_response": map[string]any{"content": m, "stdout": m},
		"tool_input": map[string]any{"file_path": "/u/work/acme/n.md", "content": m, "old_string": m, "new_string": m,
			"command": "*** Begin Patch\n*** Add File: n.md\n+" + m + "\n*** End Patch\n"},
	}
	events := []string{"SessionStart", "UserPromptSubmit", "PreToolUse", "PermissionRequest", "PostToolUse", "PreCompact",
		"PostCompact", "Stop", "StopFailure", "Interrupt", "Notification", "CwdChanged", "DirectoryAdded", "SessionEnd",
		"beforeSubmitPrompt", "preToolUse"}
	labels := map[string]map[string]string{
		"claude-code": {"HOME": "/u", "CLAUDECODE": "1", "CLAUDE_PROJECT_DIR": "/u/work/acme", "ANTHROPIC_API_KEY": m},
		"codex":       {"HOME": "/u", "PLUGIN_ROOT": "/p", "PWD": "/u/work/acme", "OPENAI_API_KEY": m},
		"cursor":      {"HOME": "/u", "CURSOR_VERSION": "2", "PWD": "/u/work/acme"},
		"copilot":     {"HOME": "/u", "COPILOT_CLI": "1", "PWD": "/u/work/acme"},
	}
	verdicts := []*daemonSpec{
		nil,
		{Gate: &ipc.GateResp{Verdict: ipc.VerdictAllow, State: "unlocked", RootIDs: []string{"root-acme"}}},
		{Gate: &ipc.GateResp{Verdict: ipc.VerdictBlock, State: "locked", RootIDs: []string{"root-acme"}, Reason: "idle"}},
	}
	for label, env := range labels {
		for _, ev := range events {
			for vi, spec := range verdicts {
				for _, malformed := range []bool{false, true} {
					payload := map[string]any{"session_id": sidC, "conversation_id": sidC, "turn_id": "t1", "cwd": "/u/work/acme",
						"hook_event_name": ev, "tool_name": "apply_patch", "directory": "/u/work/acme", "new_cwd": "/u/work/acme/x"}
					for k, v := range content {
						payload[k] = v
					}
					raw := mustJSON(t, payload)
					if malformed {
						raw = append(raw[:len(raw)-1], []byte(`, "tail": `+m)...)
					}
					deps, _, rec := testDeps(t, spec)
					led := fileLedger{fakeLedger: newFakeLedger(nil), dir: deps.Layout.SessionsDir}
					deps.Ledger = led
					deps.Enqueue = func(r queue.Request) (string, error) {
						b, _ := json.Marshal(r)
						return "q", os.WriteFile(filepath.Join(deps.Layout.QueueDir, "q.json"), b, 0o600)
					}
					var out, errb bytes.Buffer
					hook.RunWith([]string{label, ev}, bytes.NewReader(raw), &out, &errb, paths.FromMap(env), hook.TestSystem{Deps: deps})
					where := label + "/" + ev
					if strings.Contains(out.String(), m) || strings.Contains(errb.String(), m) {
						t.Errorf("%s (daemon %d, malformed %v): marker in the answer", where, vi, malformed)
					}
					for _, c := range rec.Calls() {
						if bytes.Contains(c.Req, []byte(m)) {
							t.Errorf("%s: marker in daemon request %s", where, c.Op)
						}
					}
					if hits := testkit.GrepTree(t, deps.Layout.Base, m); len(hits) > 0 {
						t.Errorf("%s (daemon %d, malformed %v): marker on disk: %v", where, vi, malformed, hits)
					}
				}
			}
		}
	}
}

// TestHookLayoutIgnoresOverrides (SEC-12, SEC-31 hook side): PRECINTO_HOME,
// PRECINTO_RUNTIME_DIR and PRECINTO_DEV in a hook's environment (Claude's
// settings env reaches hooks) have no effect, in this -tags testing build
// too.
func TestHookLayoutIgnoresOverrides(t *testing.T) {
	home := testkit.ShortTempDir(t)
	env := paths.FromMap(map[string]string{
		"HOME": home, "PRECINTO_HOME": "/tmp/attacker-base", "PRECINTO_RUNTIME_DIR": "/tmp/attacker-run", "PRECINTO_DEV": "1",
		"XDG_RUNTIME_DIR": "/tmp/attacker-xdg",
	})
	l, ok := hook.HookLayout(env)
	if !ok {
		t.Fatal("no layout")
	}
	base, err := paths.DefaultBase(env)
	if err != nil {
		t.Fatal(err)
	}
	if l.Base != base || strings.Contains(l.Base, "attacker") || strings.Contains(l.RunDir, "attacker-base") || strings.Contains(l.RunDir, "attacker-run") {
		t.Errorf("hook layout %s / %s honours an override", l.Base, l.RunDir)
	}
	// A HOME too long for the socket keeps the files and drops the daemon.
	long := "/" + strings.Repeat("h", 80)
	l, ok = hook.HookLayout(paths.FromMap(map[string]string{"HOME": long}))
	if !ok || l.Socket != "" || !strings.HasPrefix(l.RootsList, long) {
		t.Errorf("long HOME: %v %+v", ok, l)
	}
	// No HOME: no layout.
	if _, ok := hook.HookLayout(paths.FromMap(map[string]string{"HOME": "relative"})); ok {
		t.Error("relative HOME gave a layout")
	}
}

// TestEffectiveConfig: the hook enforces config.toml, the pinned policy and
// roots.list together (the stricter set, D48, SPEC §12.8).
func TestEffectiveConfig(t *testing.T) {
	home := testkit.ShortTempDir(t)
	l, ok := hook.HookLayout(paths.FromMap(map[string]string{"HOME": home}))
	if !ok {
		t.Fatal("no layout")
	}
	if err := l.EnsureDirs(); err != nil {
		t.Fatal(err)
	}
	mk := func(rel string) string {
		p := filepath.Join(home, rel)
		if err := os.MkdirAll(p, 0o700); err != nil {
			t.Fatal(err)
		}
		return p
	}
	acme, beta, gamma := mk("work/acme"), mk("work/beta"), mk("work/gamma")

	// Nothing on disk: the defaults, no root.
	if c := hook.EffectiveConfig(l); len(c.Roots) != 0 || c.Policy.UnlockOnPrompt {
		t.Errorf("empty base: %+v", c.Roots)
	}
	cfg := config.Default()
	cfg.Roots = []config.Root{{ID: "root-acme", Path: acme, MD: config.MDLedger, Harnesses: []string{"claude-code"}}}
	if err := config.Save(l.ConfigFile, cfg); err != nil {
		t.Fatal(err)
	}
	pinned := config.Default()
	pinned.Roots = []config.Root{{ID: "root-beta", Path: beta, MD: config.MDLedger, Harnesses: []string{"claude-code"}}}
	if err := config.SavePinned(l.PolicyPinned, config.Pinned{Config: pinned, ConfirmedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(l.RootsList, []byte(acme+"\n"+gamma+"\nrelative\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c := hook.EffectiveConfig(l)
	for _, p := range []string{acme, beta, gamma} {
		if _, ok := c.RootFor(filepath.Join(p, "x")); !ok {
			t.Errorf("%s is not protected in %+v", p, c.Roots)
		}
	}
	if r, _ := c.RootFor(gamma); r.ID != "" {
		t.Errorf("a roots.list-only folder got an id: %+v", r)
	}
	// An invalid config.toml loses no folder that roots.list names.
	if err := os.WriteFile(l.ConfigFile, []byte("unknown_key = 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c = hook.EffectiveConfig(l)
	for _, p := range []string{acme, gamma} {
		if _, ok := c.RootFor(p); !ok {
			t.Errorf("invalid config: %s not protected", p)
		}
	}
}

// TestWorkerEnv: spawned workers and an autostarted daemon get an
// allowlisted environment: no PRECINTO_* override, no loader variable, no
// agent marker, no secret.
func TestWorkerEnv(t *testing.T) {
	env := paths.FromMap(map[string]string{
		"HOME": "/u", "PATH": "/usr/bin:/bin", "LANG": "C", "TMPDIR": "/tmp/x",
		"PRECINTO_HOME": "/x", "PRECINTO_RUNTIME_DIR": "/y", "PRECINTO_DEV": "1", "PRECINTO_ACTIVE": "1",
		"DYLD_INSERT_LIBRARIES": "/z.dylib", "LD_PRELOAD": "/z.so", "CLAUDECODE": "1", "CLAUDE_PID": "1",
		"ANTHROPIC_API_KEY": "k", "CODEX_HOME": "/c",
	})
	got := strings.Join(hook.WorkerEnv(env), "\n")
	for _, bad := range []string{"PRECINTO_", "DYLD_", "LD_PRELOAD", "CLAUDECODE", "CLAUDE_PID", "ANTHROPIC", "CODEX_HOME"} {
		if strings.Contains(got, bad) {
			t.Errorf("worker env carries %s:\n%s", bad, got)
		}
	}
	for _, good := range []string{"HOME=/u", "PATH=/usr/bin:/bin", "LANG=C", "TMPDIR=/tmp/x"} {
		if !strings.Contains(got, good) {
			t.Errorf("worker env lacks %s", good)
		}
	}
}

// TestDedupe: a non-gate event of an experimental host that reaches
// precinto through two hooks files acts once; gate events always decide.
func TestDedupe(t *testing.T) {
	deps, led, rec := testDeps(t, &daemonSpec{Gate: &ipc.GateResp{Verdict: ipc.VerdictDeny, State: "locked", RootIDs: []string{"root-acme"}}})
	env := map[string]string{"HOME": "/u", "CURSOR_VERSION": "2"}
	payload := `{"conversation_id":"c1","hook_event_name":"afterFileEdit","workspace_roots":["/u/work/acme"],"file_path":"/u/work/acme/n.md"}`
	for _, label := range []string{"cursor", "claude-code"} {
		if code, out, _ := runMain(t, []string{label, "afterFileEdit"}, strings.NewReader(payload), env, hook.TestSystem{Deps: deps}); code != 0 || out != "" {
			t.Fatalf("%s: %d %q", label, code, out)
		}
	}
	var md int
	for _, e := range led.Appended() {
		if e.Type == ledger.TypeMarkdown {
			md++
		}
	}
	if md != 1 {
		t.Errorf("markdown recorded %d times, want once", md)
	}
	gate := `{"conversation_id":"c1","hook_event_name":"preToolUse","workspace_roots":["/u/work/acme"],"tool_name":"edit","tool_input":{"file_path":"/u/work/acme/n.md"}}`
	for _, label := range []string{"cursor", "claude-code"} {
		if code, out, _ := runMain(t, []string{label, "preToolUse"}, strings.NewReader(gate), env, hook.TestSystem{Deps: deps}); code != 0 || !strings.Contains(out, `"permission":"deny"`) {
			t.Errorf("%s gate: %d %q", label, code, out)
		}
	}
	gates := 0
	for _, c := range rec.Calls() {
		if c.Op == "gate" {
			gates++
		}
	}
	if gates != 2 {
		t.Errorf("gate asked %d times, want once per invocation", gates)
	}
	// Markers are content-free names under state/hookdedupe.
	entries, err := os.ReadDir(filepath.Join(deps.Layout.StateDir, "hookdedupe"))
	if err != nil || len(entries) == 0 {
		t.Fatalf("dedupe markers: %v %v", entries, err)
	}
	for _, e := range entries {
		if len(e.Name()) != 32 || strings.ContainsAny(e.Name(), "/.") {
			t.Errorf("marker name %q", e.Name())
		}
	}
}

// TestSpawnedWorkerArgs: the SessionEnd worker and the opportunistic sweep
// are exactly `seal --queue` and `sweep --quiet` (SPEC §10.1, §10.6).
func TestSpawnedWorkerArgs(t *testing.T) {
	deps, _, rec := testDeps(t, nil)
	env := map[string]string{"HOME": "/u", "CLAUDECODE": "1"}
	runMain(t, []string{"claude-code", "SessionStart"}, strings.NewReader(`{"session_id":"s","cwd":"/u/play","source":"resume"}`), env, hook.TestSystem{Deps: deps})
	runMain(t, []string{"claude-code", "SessionEnd"}, strings.NewReader(`{"session_id":"s","cwd":"/u/work/acme","reason":"other"}`), env, hook.TestSystem{Deps: deps})
	got := rec.Spawns()
	if len(got) != 2 || strings.Join(got[0], " ") != "sweep --quiet" || strings.Join(got[1], " ") != "seal --queue" {
		t.Errorf("spawned %v", got)
	}
	// No opportunistic sweep while a sweep holds the lock.
	deps2, _, rec2 := testDeps(t, nil)
	lockPath := deps2.Layout.LockFile("sweep")
	held, err := lockHeld(lockPath)
	if err != nil {
		t.Skipf("flock unavailable: %v", err)
	}
	defer held()
	runMain(t, []string{"claude-code", "SessionStart"}, strings.NewReader(`{"session_id":"s","cwd":"/u/play","source":"startup"}`), env, hook.TestSystem{Deps: deps2})
	if s := rec2.Spawns(); len(s) != 0 && runtime.GOOS != "windows" {
		t.Errorf("sweep spawned while the sweep lock is held: %v", s)
	}
}
