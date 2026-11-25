package hook_test

import (
	"bytes"
	"io"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Neorichi/precinto/internal/config"
	"github.com/Neorichi/precinto/internal/hook"
	"github.com/Neorichi/precinto/internal/ipc"
	"github.com/Neorichi/precinto/internal/paths"
	"github.com/Neorichi/precinto/internal/platform"
	"github.com/Neorichi/precinto/internal/platform/fakeplatform"
	"github.com/Neorichi/precinto/internal/testkit"
)

// testDeps returns fake dependencies with one root, /u/work/acme.
func testDeps(t *testing.T, daemon *daemonSpec) (hook.Deps, *fakeLedger, *recorder) {
	t.Helper()
	cfg := config.Default()
	cfg.Roots = []config.Root{{ID: "root-acme", Path: "/u/work/acme", MD: config.MDLedger}}
	short := testkit.ShortTempDir(t)
	l, err := paths.LayoutAt(short, filepath.Join(short, "run"))
	if err != nil {
		t.Fatal(err)
	}
	if err := l.EnsureDirs(); err != nil {
		t.Fatal(err)
	}
	led := newFakeLedger(nil)
	rec := &recorder{}
	gates := 0
	return hook.Deps{
		Cfg: cfg, Layout: l, Env: paths.FromMap(map[string]string{"HOME": "/u"}),
		Ledger: led, Procs: fakeplatform.NewProcs(),
		Identify: func(int) (platform.ProcID, error) { return platform.ProcID{}, platform.ErrNoProcess },
		Now:      func() time.Time { return testkit.Epoch },
		Dial:     rec.dialer(daemon, &gates), DialUnlock: rec.dialer(daemon, &gates),
		Enqueue: rec.enqueue, Spawn: rec.spawn,
	}, led, rec
}

// countingReader records whether anything read the payload.
type countingReader struct {
	r     io.Reader
	reads atomic.Int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	c.reads.Add(1)
	return c.r.Read(p)
}

// blockingReader never returns (a harness that never closes stdin).
type blockingReader struct{ done chan struct{} }

func (b blockingReader) Read([]byte) (int, error) {
	<-b.done
	return 0, io.EOF
}

func runMain(t *testing.T, args []string, stdin io.Reader, env map[string]string, ts hook.TestSystem) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := hook.RunWith(args, stdin, &out, &errb, paths.FromMap(env), ts)
	return code, out.String(), errb.String()
}

func TestMainArgs(t *testing.T) {
	deps, _, _ := testDeps(t, nil)
	for _, args := range [][]string{nil, {"claude-code"}, {"claude-code", "UserPromptSubmit", "extra"}, {"", "UserPromptSubmit"}, {"claude-code", ""}} {
		if code, out, errs := runMain(t, args, strings.NewReader("{}"), nil, hook.TestSystem{Deps: deps}); code != hook.ExitFailure || out != "" || errs != "" {
			t.Errorf("args %q: %d %q %q, want ExitFailure and silence", args, code, out, errs)
		}
	}
	// The leading subcommand name is accepted.
	payload := `{"session_id":"s","cwd":"/u/play"}`
	if code, out, _ := runMain(t, []string{"hook", "claude-code", "UserPromptSubmit"}, strings.NewReader(payload), map[string]string{"HOME": "/u"}, hook.TestSystem{Deps: deps}); code != 0 || out != "" {
		t.Errorf("hook claude-code UserPromptSubmit outside a root: %d %q", code, out)
	}
	// An event precinto does not know never blocks.
	if code, out, _ := runMain(t, []string{"claude-code", "FileChanged"}, strings.NewReader(`{"session_id":"s","cwd":"/u/work/acme"}`), map[string]string{"HOME": "/u"}, hook.TestSystem{Deps: deps}); code != 0 || out != "" {
		t.Errorf("unknown event: %d %q", code, out)
	}
}

// TestMainHardenFailure: an unhardened process never reads the payload;
// the environment's folders decide.
func TestMainHardenFailure(t *testing.T) {
	deps, led, rec := testDeps(t, &daemonSpec{Gate: &ipc.GateResp{Verdict: ipc.VerdictAllow, State: "unlocked"}})
	fail := func() error { return platform.ErrRoot }
	for _, tc := range []struct {
		wd   string
		want int
		out  bool
	}{{"/u/work/acme/src", 0, true}, {"/u/play", 0, false}} {
		stdin := &countingReader{r: strings.NewReader(`{"session_id":"s","cwd":"/u/work/acme"}`)}
		ts := hook.TestSystem{Deps: deps, Harden: fail, Getwd: func() (string, error) { return tc.wd, nil }}
		code, out, _ := runMain(t, []string{"claude-code", "PreToolUse"}, stdin, map[string]string{"HOME": "/u"}, ts)
		if code != tc.want || (out != "") != tc.out {
			t.Errorf("cwd %s: %d %q", tc.wd, code, out)
		}
		if stdin.reads.Load() != 0 {
			t.Errorf("cwd %s: the payload was read by an unhardened process", tc.wd)
		}
	}
	if len(led.Appended()) != 0 || len(rec.Calls()) != 0 {
		t.Errorf("side effects without hardening: %v %v", led.Appended(), rec.Calls())
	}
}

// TestMainStdinNeverCloses: the answer comes before the deadline.
func TestMainStdinNeverCloses(t *testing.T) {
	deps, _, _ := testDeps(t, nil)
	done := make(chan struct{})
	defer close(done)
	for _, tc := range []struct {
		env  map[string]string
		args []string
		exit int
		out  bool
	}{
		{map[string]string{"HOME": "/u", "CLAUDE_PROJECT_DIR": "/u/work/acme"}, []string{"claude-code", "UserPromptSubmit"}, 0, true},
		{map[string]string{"HOME": "/u", "PWD": "/u/work/acme", "PLUGIN_ROOT": "/p"}, []string{"codex", "PreToolUse"}, hook.ExitBlockCode2, false},
		{map[string]string{"HOME": "/u", "CLAUDE_PROJECT_DIR": "/u/play"}, []string{"claude-code", "UserPromptSubmit"}, 0, false},
	} {
		start := time.Now()
		code, out, errs := runMain(t, tc.args, blockingReader{done}, tc.env, hook.TestSystem{Deps: deps, Deadline: 100 * time.Millisecond})
		if elapsed := time.Since(start); elapsed > 2*time.Second {
			t.Errorf("%v: answered after %v", tc.args, elapsed)
		}
		if code != tc.exit || (out != "") != tc.out {
			t.Errorf("%v %v: %d %q %q", tc.args, tc.env, code, out, errs)
		}
		if tc.exit == hook.ExitBlockCode2 && errs == "" {
			t.Errorf("%v: no Codex reason on stderr", tc.args)
		}
	}
}

func TestMainOversizedPayload(t *testing.T) {
	if testing.Short() {
		t.Skip("reads 64 MiB")
	}
	deps, _, _ := testDeps(t, nil)
	big := io.LimitReader(zeroReader{}, hook.MaxPayload+10)
	code, out, _ := runMain(t, []string{"claude-code", "UserPromptSubmit"}, big, map[string]string{"HOME": "/u", "CLAUDE_PROJECT_DIR": "/u/work/acme"}, hook.TestSystem{Deps: deps})
	if code != 0 || !strings.Contains(out, `"decision":"block"`) {
		t.Errorf("oversized inside a root: %d %q", code, out)
	}
	big = io.LimitReader(zeroReader{}, hook.MaxPayload+10)
	if code, out, _ := runMain(t, []string{"claude-code", "UserPromptSubmit"}, big, map[string]string{"HOME": "/u", "CLAUDE_PROJECT_DIR": "/u/play"}, hook.TestSystem{Deps: deps}); code != 0 || out != "" {
		t.Errorf("oversized outside: %d %q", code, out)
	}
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = ' '
	}
	return len(p), nil
}

// TestMainDepsPanic: when not even the configuration can be built, gate
// events exit 1 so that the shim's roots.list rule decides.
func TestMainDepsPanic(t *testing.T) {
	var out, errb bytes.Buffer
	if code := hook.RunWithDepsPanic([]string{"claude-code", "PreToolUse"}, strings.NewReader("{}"), &out, &errb, paths.FromMap(nil)); code != hook.ExitFailure || out.Len() != 0 || errb.Len() != 0 {
		t.Errorf("gate: %d %q %q", code, out.String(), errb.String())
	}
	if code := hook.RunWithDepsPanic([]string{"claude-code", "SessionEnd"}, strings.NewReader("{}"), &out, &errb, paths.FromMap(nil)); code != 0 || out.Len() != 0 {
		t.Errorf("non-gate: %d %q", code, out.String())
	}
}

// TestMainPanicInLedger: a panic before handle classified the session
// still fails closed when Main's own view says managed, and fails open
// otherwise.
func TestMainPanicInLedger(t *testing.T) {
	deps, led, _ := testDeps(t, nil)
	led.panicGet = true
	env := map[string]string{"HOME": "/u", "CLAUDECODE": "1"}
	code, out, _ := runMain(t, []string{"claude-code", "PermissionRequest"}, strings.NewReader(`{"session_id":"s","cwd":"/u/work/acme"}`), env, hook.TestSystem{Deps: deps})
	if code != 0 || !strings.Contains(out, `"behavior":"deny"`) {
		t.Errorf("managed: %d %q", code, out)
	}
	code, out, _ = runMain(t, []string{"claude-code", "PermissionRequest"}, strings.NewReader(`{"session_id":"s","cwd":"/u/play"}`), env, hook.TestSystem{Deps: deps})
	if code != 0 || out != "" {
		t.Errorf("unmanaged: %d %q", code, out)
	}
}

// TestMainExistingLedgerIsManaged: a session whose ledger file exists is
// treated as managed when handle cannot finish (a stalled ledger read).
func TestMainExistingLedgerIsManaged(t *testing.T) {
	deps, led, _ := testDeps(t, nil)
	hang := make(chan struct{})
	defer close(hang)
	led.hang = hang
	dir := filepath.Join(deps.Layout.SessionsDir, "claude-code")
	if err := mkdirAll(dir); err != nil {
		t.Fatal(err)
	}
	if err := writeFile(filepath.Join(dir, sidC+".jsonl"), "{}\n"); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{"HOME": "/u", "CLAUDECODE": "1"}
	payload := `{"session_id":"` + sidC + `","cwd":"/u/play"}`
	code, out, _ := runMain(t, []string{"claude-code", "PreCompact"}, strings.NewReader(payload), env, hook.TestSystem{Deps: deps, Deadline: 100 * time.Millisecond})
	if code != 0 || !strings.Contains(out, `"decision":"block"`) {
		t.Errorf("tainted elsewhere, ledger stalled: %d %q", code, out)
	}
	// A session id that is not a file name is never used as one.
	payload = `{"session_id":"../../x","cwd":"/u/play"}`
	if code, out, _ := runMain(t, []string{"claude-code", "PreCompact"}, strings.NewReader(payload), env, hook.TestSystem{Deps: deps, Deadline: 100 * time.Millisecond}); code != 0 || out != "" {
		t.Errorf("unsafe sid: %d %q", code, out)
	}
}

// TestHandleNilDeps: missing dependencies degrade to fail closed for a
// managed gate, never to a panic.
func TestHandleNilDeps(t *testing.T) {
	cfg := config.Default()
	cfg.Roots = []config.Root{{ID: "root-acme", Path: "/u/work/acme"}}
	d := hook.Deps{Cfg: cfg}
	for _, ev := range []hook.Event{hook.UserPromptSubmit, hook.PreToolUse, hook.PermissionRequest, hook.PreCompact} {
		dec := hook.Handle(t.Context(), d, hook.Payload{Host: hook.HostClaude, Label: "claude-code", Event: ev, SID: "s", Cwd: "/u/work/acme"})
		if dec.Verdict == ipc.VerdictAllow {
			t.Errorf("%s: allowed without a daemon", ev)
		}
	}
	for _, ev := range []hook.Event{hook.SessionStart, hook.PostToolUse, hook.SessionEnd, hook.Stop} {
		if dec := hook.Handle(t.Context(), d, hook.Payload{Host: hook.HostClaude, Label: "claude-code", Event: ev, SID: "s", Cwd: "/u/work/acme"}); dec.Verdict != ipc.VerdictAllow {
			t.Errorf("%s: %+v", ev, dec)
		}
	}
}

// TestHandleSocketSquat (SEC-11, hook side): a daemon that fails
// authentication is no daemon: the gate blocks.
func TestHandleSocketSquat(t *testing.T) {
	deps, _, _ := testDeps(t, &daemonSpec{DialError: "untrusted"})
	dec := hook.Handle(t.Context(), deps, hook.Payload{Host: hook.HostClaude, Label: "claude-code", Event: hook.UserPromptSubmit, SID: "s", Cwd: "/u/work/acme"})
	if dec.Verdict != ipc.VerdictBlock {
		t.Errorf("untrusted daemon: %+v", dec)
	}
}
