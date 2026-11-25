//go:build crossgroup

package main

// Session-lifecycle regressions over the real engine (sweep, the Claude
// adapter, live, ledger), the real vault store (vaulttest) and, where a
// key or a lock state is needed, the in-process daemon (agenttest), in a
// testkit fake HOME. Fakes of the engine cannot show these bugs: they are
// in how the CLI, the backend and the adapter work together.

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Neorichi/precinto/internal/agent/agenttest"
	"github.com/Neorichi/precinto/internal/capsule"
	"github.com/Neorichi/precinto/internal/config"
	"github.com/Neorichi/precinto/internal/fsx"
	"github.com/Neorichi/precinto/internal/harness"
	"github.com/Neorichi/precinto/internal/harness/claude/claudetest"
	"github.com/Neorichi/precinto/internal/ledger"
	"github.com/Neorichi/precinto/internal/platform"
	"github.com/Neorichi/precinto/internal/sweep"
	"github.com/Neorichi/precinto/internal/sweep/capslog"
	"github.com/Neorichi/precinto/internal/testkit"
	"github.com/Neorichi/precinto/internal/ui"
	"github.com/Neorichi/precinto/internal/vault/vaulttest"
)

// lifecycleRoot is the protected folder of every testkit home.
const lifecycleRoot = "root-acme"

// lifecycleApp is realApp whose worker spawns are only recorded: a spawn
// would otherwise run the go test binary itself.
func lifecycleApp(t *testing.T, h *testkit.Home) (*app, *env, *[][]string) {
	t.Helper()
	a, e := realApp(t, h)
	var mu sync.Mutex
	spawned := &[][]string{}
	a.sys.spawn = func(argv []string, _ platform.SpawnOptions) (platform.ProcID, error) {
		mu.Lock()
		defer mu.Unlock()
		*spawned = append(*spawned, append([]string(nil), argv...))
		return platform.ProcID{PID: 999999, StartUS: 1}, nil
	}
	return a, e, spawned
}

// loggedUnits returns the capsule-log entries of kind.
func loggedUnits(t *testing.T, h *testkit.Home, kind capsule.Kind) []capslog.Entry {
	t.Helper()
	all, err := capslog.Open(h.Layout.CapsuleLog).All()
	if err != nil {
		t.Fatal(err)
	}
	var out []capslog.Entry
	for _, en := range all {
		if en.Kind == string(kind) {
			out = append(out, en)
		}
	}
	return out
}

// gone reports whether p no longer exists.
func gone(p string) bool {
	_, err := os.Lstat(p)
	return os.IsNotExist(err)
}

// needSealRoom fails the test at once when the volume of h (below
// GOTMPDIR, or TMPDIR) cannot take a seal while keeping the home's
// free-space floor free (policy.min_free, 2 GiB by default, D76): the
// production engine refuses such a seal as specified, and the test would
// fail as "disk full" instead of naming its environment.
func needSealRoom(t *testing.T, h *testkit.Home) {
	t.Helper()
	if err := fsx.CheckSpace(h.Dir, 1<<20, floorPolicy(h.Cfg, h.Layout).Floor()); err != nil {
		t.Fatalf("the test's temporary directory cannot take a seal while keeping policy.min_free free; run with GOTMPDIR or TMPDIR on a volume with more free space: %v", err)
	}
}

// UX-01, D106: `precinto seal --adopt` seals a session that only its
// transcript ties to the folder (from before protection, or without
// hooks): the dry run lists it, the seal removes the plaintext and logs a
// capsule. Before the fix the scope never asked the adapter to adopt, so
// both said "nothing to seal".
func TestCrossgroupSealAdoptSealsAnAdoptedSession(t *testing.T) {
	h := realHome(t)
	needSealRoom(t, h)
	vaulttest.New(t, h.Layout.Base, lifecycleRoot)
	l := claudetest.New(t, h.Dir)
	paths := l.WriteSession(t, claudetest.Session{SID: "00000000-0000-4000-8000-0000000000a1", Cwd: h.Root,
		Marker: testkit.Marker(t), ModTime: h.Clock.Now().Add(-time.Hour)})
	transcript := paths[0]
	a, e, _ := lifecycleApp(t, h)

	if code := a.run([]string{"seal", "--adopt", "--dry-run"}); code != exitOK {
		t.Fatalf("seal --adopt --dry-run: exit %d (%s)", code, e.stderr())
	}
	// The session and the project unit its transcript ties to the folder;
	// a dry run seals nothing, so it says what a seal would do (D150).
	if out := e.stdout(); strings.Contains(out, "nothing to seal") || strings.Contains(out, "precinto: sealed ") || !strings.Contains(out, "precinto: would seal ") {
		t.Fatalf("seal --adopt --dry-run printed %q, want the adopted session as what a seal would do", out)
	}
	if gone(transcript) {
		t.Fatal("the dry run removed the transcript")
	}
	e.out.Reset()
	if code := a.run([]string{"seal", "--adopt"}); code != exitOK {
		t.Fatalf("seal --adopt: exit %d (%s)", code, e.stderr())
	}
	if out := e.stdout(); !strings.Contains(out, "precinto: sealed ") {
		t.Fatalf("seal --adopt printed %q", out)
	}
	if !gone(transcript) {
		t.Fatal("seal --adopt left the adopted transcript in plaintext")
	}
	if n := len(loggedUnits(t, h, capsule.KindClaudeSession)); n != 1 {
		t.Fatalf("%d session capsules logged, want 1", n)
	}
}

// UX-03, D109: protect and integrate ran while the Claude home did not
// exist yet, so config.toml registers none; a session sealed later from
// the default home registers it first, so the capsule has a restore target
// and restoring it after an unlock works (before the fix the restore
// refused it with exit 5, the tamper class).
func TestCrossgroupSealRegistersTheHomeItSealsFrom(t *testing.T) {
	h := realHome(t)
	needSealRoom(t, h)
	cc := h.Cfg.Harness["claude-code"]
	cc.Homes = nil
	h.Cfg.Harness["claude-code"] = cc
	if err := config.Save(h.Layout.ConfigFile, h.Cfg); err != nil {
		t.Fatal(err)
	}
	fx := vaulttest.New(t, h.Layout.Base, lifecycleRoot)
	const sid = "00000000-0000-4000-8000-0000000000a2"
	l := claudetest.New(t, h.Dir)
	paths := l.WriteSession(t, claudetest.Session{SID: sid, Cwd: h.Root, Marker: testkit.Marker(t),
		ModTime: h.Clock.Now().Add(-time.Hour)})
	transcript := paths[0]
	want, err := os.ReadFile(transcript)
	if err != nil {
		t.Fatal(err)
	}
	led := ledger.Open(h.Layout.SessionsDir)
	if err := led.Append(ledger.Event{Type: ledger.TypeTaint, Harness: "claude-code", SID: sid, Roots: []string{lifecycleRoot},
		Cwd: h.Root, ConfigDir: h.ClaudeConfig, TmpDir: h.ClaudeTmp}); err != nil {
		t.Fatal(err)
	}
	ag := agenttest.Start(t, h.Layout, h.Clock, h.Procs)
	defer ag.Stop()
	a, e, _ := lifecycleApp(t, h)
	if code := a.run([]string{"seal", "--session", sid}); code != exitOK {
		t.Fatalf("seal: exit %d (%s)", code, e.stderr())
	}
	if !gone(transcript) {
		t.Fatal("the session was not sealed")
	}
	cfg, err := config.Load(h.Layout.ConfigFile)
	if err != nil {
		t.Fatal(err)
	}
	registered := false
	for _, hm := range cfg.Harness["claude-code"].Homes {
		registered = registered || hm.Dir == h.ClaudeConfig
	}
	if !registered {
		t.Fatalf("the home the session was sealed from is not registered: %+v", cfg.Harness["claude-code"].Homes)
	}

	ag.UnlockForTest(t, []string{lifecycleRoot}, fx.Recovery.String())
	a, e, _ = lifecycleApp(t, h)
	code := a.run([]string{"restore", "--session", sid})
	if code != exitOK {
		t.Fatalf("restore: exit %d, stdout %q stderr %q", code, e.stdout(), e.stderr())
	}
	got, err := os.ReadFile(transcript)
	if err != nil || string(got) != string(want) {
		t.Fatalf("restored transcript differs (%v)", err)
	}
}

// UX-03, D109: a capsule of a home config does not register is refused
// with exit 1 and the catalog line that names the fix, never exit 5 and
// the internal error chain.
func TestCrossgroupRestoreFromAnUnregisteredHomeExitsOne(t *testing.T) {
	h := realHome(t)
	needSealRoom(t, h)
	fx := vaulttest.New(t, h.Layout.Base, lifecycleRoot)
	const sid = "00000000-0000-4000-8000-0000000000a3"
	l := claudetest.New(t, h.Dir)
	l.WriteSession(t, claudetest.Session{SID: sid, Cwd: h.Root, Marker: testkit.Marker(t), ModTime: h.Clock.Now().Add(-time.Hour)})
	if err := ledger.Open(h.Layout.SessionsDir).Append(ledger.Event{Type: ledger.TypeTaint, Harness: "claude-code", SID: sid,
		Roots: []string{lifecycleRoot}, Cwd: h.Root, ConfigDir: h.ClaudeConfig, TmpDir: h.ClaudeTmp}); err != nil {
		t.Fatal(err)
	}
	ag := agenttest.Start(t, h.Layout, h.Clock, h.Procs)
	defer ag.Stop()
	a, e, _ := lifecycleApp(t, h)
	if code := a.run([]string{"seal", "--session", sid}); code != exitOK {
		t.Fatalf("seal: exit %d (%s)", code, e.stderr())
	}
	// The home is forgotten afterwards (hand-edited config.toml): the
	// capsule has no restore target any more.
	cfg, err := config.Load(h.Layout.ConfigFile)
	if err != nil {
		t.Fatal(err)
	}
	cc := cfg.Harness["claude-code"]
	cc.Homes = nil
	cfg.Harness["claude-code"] = cc
	if err := config.Save(h.Layout.ConfigFile, cfg); err != nil {
		t.Fatal(err)
	}
	ag.UnlockForTest(t, []string{lifecycleRoot}, fx.Recovery.String())
	a, e, _ = lifecycleApp(t, h)
	code := a.run([]string{"restore"})
	if code != exitError {
		t.Fatalf("restore: exit %d, want 1 (stdout %q stderr %q)", code, e.stdout(), e.stderr())
	}
	if got, want := e.stderr(), ui.Format(ui.MsgHomeUnregistered, ui.Vars{N: 1})+"\n"; got != want {
		t.Fatalf("stderr %q, want %q", got, want)
	}
	if got := e.stdout(); strings.Contains(got, "nothing to restore") {
		t.Fatalf("stdout %q says nothing to restore next to E.unregistered", got)
	}
}

// fakeClaude writes a stand-in for the claude executable (tests only): it
// writes one synthetic transcript for the session id it is given with
// --session-id (a fixed one otherwise, like a Claude that chose its own),
// the way Claude lays it out, runs no hook, and exits 3. It refuses to run
// without the fake home's CLAUDE_CONFIG_DIR.
func fakeClaude(t *testing.T, dir string) string {
	t.Helper()
	p := filepath.Join(dir, "bin", "claude")
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	script := `#!/bin/sh
[ -n "$CLAUDE_CONFIG_DIR" ] || exit 99
sid=00000000-0000-4000-8000-0000000000f9
while [ $# -gt 0 ]; do
  case "$1" in
    --session-id) sid=$2; shift 2 ;;
    *) shift ;;
  esac
done
dir="$CLAUDE_CONFIG_DIR/projects/$(printf '%s' "$PWD" | tr '/.' '--')"
mkdir -p "$dir" || exit 98
printf '{"type":"user","sessionId":"%s","cwd":"%s","uuid":"00000000-0000-4000-8000-000000000001","parentUuid":null,"message":{"role":"user","content":"%s"}}\n' "$sid" "$PWD" "$FAKE_CLAUDE_MARKER" > "$dir/$sid.jsonl" || exit 97
chmod 600 "$dir/$sid.jsonl"
if [ -n "$FAKE_CLAUDE_CLEAR_TO" ]; then
  # /clear: a new session, named only in Claude's live-session registry.
  next=$FAKE_CLAUDE_CLEAR_TO
  mkdir -p "$CLAUDE_CONFIG_DIR/sessions" || exit 96
  printf '{"pid":%s,"sessionId":"%s","cwd":"%s","startedAt":%s000,"kind":"interactive","entrypoint":"cli"}' "$$" "$next" "$PWD" "$(date +%s)" > "$CLAUDE_CONFIG_DIR/sessions/$$.json"
  printf '{"type":"user","sessionId":"%s","cwd":"%s","uuid":"00000000-0000-4000-8000-000000000002","parentUuid":null,"message":{"role":"user","content":"%s"}}\n' "$next" "$PWD" "$FAKE_CLAUDE_MARKER" > "$dir/$next.jsonl" || exit 95
  chmod 600 "$dir/$next.jsonl"
  sleep 1
  rm -f "$CLAUDE_CONFIG_DIR/sessions/$$.json" # Claude removes it before it exits
fi
exit 3
`
	if err := os.WriteFile(p, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return p
}

// UX-02, D107, D108: a wrapped Claude session in a protected folder whose
// hooks never run (no plugin, --bare, disableAllHooks) is still sealed
// when it exits: the wrapper knows its session id before exec and records
// it as the child's. The exit lines say "sealed" because the seal summary
// shows it, and C9.claude no longer claims it by itself. Before the fix the
// transcript stayed plaintext while C9.claude said "the session is sealed
// now".
func TestCrossgroupHooklessWrappedSessionIsSealed(t *testing.T) {
	h := realHome(t)
	needSealRoom(t, h)
	fx := vaulttest.New(t, h.Layout.Base, lifecycleRoot)
	ag := agenttest.Start(t, h.Layout, h.Clock, h.Procs)
	defer ag.Stop()
	ag.UnlockForTest(t, []string{lifecycleRoot}, fx.Recovery.String())
	exe := fakeClaude(t, h.Dir)
	marker := testkit.Marker(t)
	h.Env = h.Env.With("FAKE_CLAUDE_MARKER", marker)
	a, e, _ := lifecycleApp(t, h)
	stdin, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer stdin.Close()
	stdout, err := os.Create(filepath.Join(h.Dir, "child-stdout"))
	if err != nil {
		t.Fatal(err)
	}
	defer stdout.Close()
	a.sys.stdinFile, a.sys.stdoutFile = stdin, stdout

	code := a.run([]string{"run", "--no-pty", "--", exe, "-p", "hello"})
	if code != 3 {
		t.Fatalf("run: exit %d, want the child's 3 (stderr %q)", code, e.stderr())
	}
	sessions, err := ledger.Open(h.Layout.SessionsDir).List("claude-code")
	if err != nil {
		t.Fatal(err)
	}
	entries := loggedUnits(t, h, capsule.KindClaudeSession)
	if len(entries) != 1 {
		t.Fatalf("%d session capsules logged (ledger %+v; stderr %q), want the wrapped session's", len(entries), sessions, e.stderr())
	}
	matches, _ := filepath.Glob(filepath.Join(h.ClaudeConfig, "projects", "*", "*.jsonl"))
	if len(matches) != 0 {
		t.Fatalf("transcripts left in plaintext after the exit: %v", matches)
	}
	if hits := testkit.GrepTree(t, h.Dir, marker, "capsules"); len(hits) > 0 {
		t.Fatalf("the session's marker is still in plaintext (I7): %v", hits)
	}
	got := e.stderr()
	if !strings.Contains(got, ui.Format(ui.MsgClaudeNoHooks, ui.Vars{})) {
		t.Errorf("stderr %q lacks C9.claude", got)
	}
	if strings.Contains(got, "sealed now") || !strings.Contains(got, "precinto: sealed this session (") {
		t.Errorf("stderr %q: the seal must be reported by its C6 line only", got)
	}

	// --dry-run never registers or seals anything, and a sweep of the
	// folder finds nothing of the session left (no adopted leftovers).
	e.out.Reset()
	if code := a.run([]string{"sweep", "--dry-run"}); code != exitOK {
		t.Fatalf("sweep --dry-run: exit %d", code)
	}
	rep, err := mustEngine(t, a).Sweep(context.Background(), sweep.Options{DryRun: true, Reason: "sweep", Scope: harness.Scope{Adopt: true}})
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range rep.Units {
		if u.Kind == capsule.KindClaudeSession {
			t.Errorf("a session unit is still on disk after the exit: %+v", u)
		}
	}
}

// UX-02, D107: a session the wrapped child switched to without hooks
// (/clear, /resume, a fork) is known only from Claude's live-session
// registry entry of the child; the wrapper follows it while the child runs
// and seals that session too after the exit.
func TestCrossgroupHooklessClearedSessionIsSealed(t *testing.T) {
	old := watchEvery
	watchEvery = 50 * time.Millisecond
	t.Cleanup(func() { watchEvery = old })
	h := realHome(t)
	needSealRoom(t, h)
	fx := vaulttest.New(t, h.Layout.Base, lifecycleRoot)
	ag := agenttest.Start(t, h.Layout, h.Clock, h.Procs)
	defer ag.Stop()
	ag.UnlockForTest(t, []string{lifecycleRoot}, fx.Recovery.String())
	exe := fakeClaude(t, h.Dir)
	const cleared = "00000000-0000-4000-8000-0000000000c2"
	h.Env = h.Env.With("FAKE_CLAUDE_MARKER", testkit.Marker(t)).With("FAKE_CLAUDE_CLEAR_TO", cleared)
	a, e, _ := lifecycleApp(t, h)
	stdin, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer stdin.Close()
	stdout, err := os.Create(filepath.Join(h.Dir, "child-stdout"))
	if err != nil {
		t.Fatal(err)
	}
	defer stdout.Close()
	a.sys.stdinFile, a.sys.stdoutFile = stdin, stdout
	if code := a.run([]string{"run", "--no-pty", "--", exe, "-p", "hello"}); code != 3 {
		t.Fatalf("run: exit %d (stderr %q)", code, e.stderr())
	}
	s, err := ledger.Open(h.Layout.SessionsDir).Get("claude-code", cleared)
	if err != nil && !errors.Is(err, ledger.ErrNotFound) {
		t.Fatal(err)
	}
	matches, _ := filepath.Glob(filepath.Join(h.ClaudeConfig, "projects", "*", "*.jsonl"))
	if len(matches) != 0 {
		t.Fatalf("transcripts left in plaintext after the exit: %v (ledger of the cleared session %+v, stderr %q)", matches, s, e.stderr())
	}
	if n := len(loggedUnits(t, h, capsule.KindClaudeSession)); n != 2 {
		t.Fatalf("%d session capsules logged, want the fresh and the cleared session", n)
	}
}

// D107: the seal after exit of a fresh launch is not narrowed to the
// session precinto chose for it. A session the child switched to that only
// its hooks recorded (Claude's live-session registry was not read before
// the exit) is the child's too and is sealed with it, and the summary
// names it as the session the child ran last. Before this fix the scope
// named the chosen session only, so the hook-recorded one stayed in
// plaintext.
func TestCrossgroupSealAfterExitTakesEverySessionOfTheChild(t *testing.T) {
	h := realHome(t)
	needSealRoom(t, h)
	vaulttest.New(t, h.Layout.Base, lifecycleRoot)
	exe := fakeClaude(t, h.Dir)
	a, e, _ := lifecycleApp(t, h)
	eng := mustEngine(t, a)
	ctx := context.Background()
	plan, err := eng.PlanLaunch(ctx, harness.ClaudeCode, h.Root, []string{exe}, h.Env)
	if err != nil {
		t.Fatal(err)
	}
	if plan.SessionID == "" || len(plan.SealScope.SIDs) != 0 {
		t.Fatalf("plan session id %q seal scope %+v", plan.SessionID, plan.SealScope)
	}
	b := newBackend(a, eng)
	// The child has exited (not in the process table): nothing waits.
	child := platform.ProcID{PID: 424242, StartUS: h.Clock.Now().Add(-time.Hour).UnixMicro()}
	if err := b.RecordLaunch(ctx, plan, child); err != nil {
		t.Fatal(err)
	}
	const cleared = "00000000-0000-4000-8000-0000000000c3"
	marker := testkit.Marker(t)
	l := claudetest.New(t, h.Dir)
	var transcripts []string
	for _, sid := range []string{plan.SessionID, cleared} {
		ps := l.WriteSession(t, claudetest.Session{SID: sid, Cwd: h.Root, Marker: marker, ModTime: h.Clock.Now().Add(-time.Hour)})
		transcripts = append(transcripts, ps[0])
	}
	// What the hooks of the child write for a /clear: SessionEnd(clear) of
	// the first session, SessionStart(clear) and the taint of the next.
	led := ledger.Open(h.Layout.SessionsDir)
	for _, ev := range []ledger.Event{
		{Type: ledger.TypeEnd, Harness: "claude-code", SID: plan.SessionID, Proc: child, Reason: "clear"},
		{Type: ledger.TypeStart, Harness: "claude-code", SID: cleared, Proc: child, Source: "clear", Cwd: h.Root,
			ConfigDir: h.ClaudeConfig, TmpDir: h.ClaudeTmp},
		{Type: ledger.TypeTaint, Harness: "claude-code", SID: cleared, Proc: child, Roots: []string{lifecycleRoot}},
	} {
		if err := led.Append(ev); err != nil {
			t.Fatal(err)
		}
	}
	sum, err := b.SealAfterExit(ctx, plan, child)
	if err != nil || sum.Failed != "" || sum.Deferred {
		t.Fatalf("seal after exit: summary %+v err %v (stderr %q)", sum, err, e.stderr())
	}
	for _, p := range transcripts {
		if !gone(p) {
			t.Fatalf("%s stayed in plaintext after the exit (summary %+v)", filepath.Base(p), sum)
		}
	}
	if n := len(loggedUnits(t, h, capsule.KindClaudeSession)); n != 2 {
		t.Fatalf("%d session capsules logged, want both sessions of the child", n)
	}
	if sum.SID != cleared {
		t.Fatalf("summary names %q, want the session the child ran last (%s)", sum.SID, cleared)
	}
}

// mustEngine is the app's production engine.
func mustEngine(t *testing.T, a *app) engine {
	t.Helper()
	eng, err := a.engine(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	return eng
}
