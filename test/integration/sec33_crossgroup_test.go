//go:build crossgroup

package integration_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/awnumar/memguard"

	"github.com/precinto/precinto/internal/ipc"
	"github.com/precinto/precinto/internal/paths"
	"github.com/precinto/precinto/internal/testkit"
	"github.com/precinto/precinto/internal/ui"
)

// SEC-33 (D64, D6, D59): PRECINTO_TEST_ANCESTRY_STOP is a testing-build
// feature only. A fake `claude` (testdata/fakeharness in run mode) runs
// precinto as its child, the way an agent's tool call does, with the stop
// set to the fake claude's own PID:START.
func TestSEC33TestAncestryStop(t *testing.T) {
	exe := needBinary(t)
	prod := productionBinary(t)
	claude := buildHelper(t, "testdata/fakeharness", "claude")
	t.Run("production", func(t *testing.T) { sec33Production(t, prod, claude) })
	t.Run("testing", func(t *testing.T) { sec33Testing(t, exe, claude) })
}

// Texts of the refusals (the catalog, never literal copies).
var (
	refuseInitText  = ui.Format(ui.MsgInitRefuseAgent, ui.Vars{})
	refuseAgentText = "from inside an AI agent session" // C12.agent, whatever the folder
	choosePassText  = promptNewPassphrase               // B.passphrase.new
)

// sec33Production: a production build reads the stop neither in the CLI
// nor in the daemon: under the fake claude, init is refused (B.refuse) and
// unlock --root of a folder the session is not in is refused (C12.agent).
// The production daemon gives a testing-build peer (this test process,
// dialled with Insecure) nothing, and a testing client refuses the
// production daemon (ErrUntrustedServer) before sending anything.
func sec33Production(t *testing.T, prod, claude string) {
	home := testkit.ShortTempDir(t)
	runDir := testkit.ShortTempDir(t)
	env := []string{
		"HOME=" + home, "PATH=" + systemPathForTests, "TERM=xterm-256color",
		"XDG_DATA_HOME=" + filepath.Join(home, "xdg-data"), "XDG_RUNTIME_DIR=" + runDir,
	}
	// The production layout of this HOME (HookLayout never honours
	// overrides, like a production build).
	l, err := paths.HookLayout(paths.FromEnviron(env))
	if err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(home, "work", "other")
	for _, d := range []string{l.Base, other} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	writeConfig(t, l.ConfigFile, "root-other", other)
	run := append(append([]string(nil), env...), "FAKE_HARNESS_RUN="+prod, "FAKE_HARNESS_STOP_SELF=1")

	// init under the fake claude, the stop naming it: refused.
	p := startPTYEnv(t, claude, run, home, "init", "--factor", "passphrase")
	if p.expectAny(refuseInitText, choosePassText) != 0 {
		t.Fatalf("a production build honoured the test ancestry stop: init proceeded: %q", p.output())
	}
	if code := p.wait(); code != 3 {
		t.Fatalf("production init under claude: exit %d, want 3: %q", code, p.output())
	}

	// unlock --root of another folder through a production daemon whose
	// own environment names the fake claude as the stop as well.
	p = startPTYEnv(t, claude, append(append([]string(nil), run...), "FAKE_HARNESS_HANDSHAKE=1"), home, "unlock", "--root", other)
	stop := p.expectProcID()
	startDaemon(t, prod, append(append([]string(nil), env...), paths.EnvTestAncestryStop+"="+stop), l.Socket)
	p.send("\r")
	p.expect(refuseAgentText)
	if code := p.wait(); code != 3 {
		t.Fatalf("production unlock --root under claude: exit %d, want 3: %q", code, p.output())
	}

	// A testing-build peer dialled with Insecure: every key, unlock and
	// vault operation is refused (D6: only the same executable).
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	c, err := ipc.Dial(ctx, ipc.DialOptions{Layout: l, Client: "cli", Timeout: 5 * time.Second, Insecure: true})
	if err != nil {
		t.Fatalf("insecure dial of the production daemon: %v", err)
	}
	defer c.Close()
	unauthorized := func(op string, err error) {
		t.Helper()
		var ie *ipc.Error
		if !errors.As(err, &ie) || ie.Code != ipc.CodeUnauthorized {
			t.Errorf("%s from a testing-build peer: %v, want %s", op, err, ipc.CodeUnauthorized)
		}
	}
	ks, _, err := c.Keys(ctx, ipc.KeysReq{Capsules: []ipc.CapsuleRef{{Path: "claude-code/0123456789abcdef0123456789abcdef/g000001.pcap"}}, Purpose: ipc.PurposeRestore})
	if ks != nil {
		ks.Destroy()
		t.Error("keys released to a testing-build peer")
	}
	unauthorized("keys", err)
	_, err = c.Unlock(ctx, ipc.UnlockReq{RootIDs: []string{"root-other"}, TTY: true, Confirmed: true}, refuseUI{})
	unauthorized("unlock", err)
	unauthorized("vault_create", c.VaultCreate(ctx, ipc.VaultCreateReq{RootID: "root-other", RootPath: other}, refuseUI{}))
	unauthorized("factor_add", c.FactorAdd(ctx, ipc.FactorAddReq{Kind: "passphrase"}, refuseUI{}))
	_, err = c.VaultRepair(ctx, ipc.VaultRepairReq{VaultID: "root-other"}, nil, refuseUI{})
	unauthorized("vault_repair", err)
	_, err = c.Policy(ctx, ipc.PolicyReq{Confirm: true})
	unauthorized("policy", err)

	// A testing client (this process, without Insecure) refuses the
	// production daemon before sending anything.
	if c2, err := ipc.Dial(ctx, ipc.DialOptions{Layout: l, Client: "cli", Timeout: 5 * time.Second}); !errors.Is(err, ipc.ErrUntrustedServer) {
		if c2 != nil {
			c2.Close()
		}
		t.Fatalf("testing client dialling a production daemon: %v, want ErrUntrustedServer", err)
	}
}

// sec33Testing: a testing build honours the stop only above the process it
// names; env markers and the no-controlling-terminal rule still apply, and
// the daemon's peer check follows the stop of its own environment.
func sec33Testing(t *testing.T, exe, claude string) {
	h := testkit.NewHome(t)
	fastPolicy(t, h)
	base := childEnv(h, map[string]string{"FAKE_HARNESS_RUN": exe}).With("TERM", "xterm-256color")
	// The stop names the fake claude: it and everything above are ignored.
	atClaude := base.With("FAKE_HARNESS_STOP_SELF", "1")
	rec := filepath.Join(h.Dir, "recovery.txt")
	initArgs := []string{"init", "--factor", "passphrase", "--recovery-out", rec}

	refusedInit := func(name string, env paths.Env) {
		t.Helper()
		p := startPTYEnv(t, claude, env.Environ(), h.HomeDir, initArgs...)
		if p.expectAny(refuseInitText, choosePassText) != 0 {
			t.Fatalf("%s: init proceeded under the fake claude: %q", name, p.output())
		}
		if code := p.wait(); code != 3 {
			t.Fatalf("%s: exit %d, want 3: %q", name, code, p.output())
		}
	}
	// An env marker refuses with the stop set.
	refusedInit("CLAUDECODE=1", atClaude.With("CLAUDECODE", "1"))
	// The stop above the fake claude (testkit's: this test process): the
	// fake claude below it is found.
	refusedInit("stop above claude", base)
	// No controlling terminal refuses with the stop set (D59).
	if r := runEnv(t, claude, atClaude.Environ(), h.HomeDir, "", initArgs...); r.code != 3 || !strings.Contains(r.stderr, refuseInitText) {
		t.Fatalf("init without a terminal under the stop: %+v", r)
	}
	if _, err := os.Stat(rec); !os.IsNotExist(err) {
		t.Fatalf("a refused init wrote the recovery key: %v", err)
	}

	// The stop at the fake claude, on a terminal: init proceeds.
	p := startPTYEnv(t, claude, atClaude.Environ(), h.HomeDir, initArgs...)
	p.expect(choosePassText)
	p.send(testPassphrase + "\r")
	p.expect(promptAgainPassphrase)
	p.send(testPassphrase + "\r")
	if runtime.GOOS == "darwin" {
		p.expect(promptService)
		p.send("n\r")
	}
	if code := p.wait(); code != 0 {
		t.Fatalf("init under the fake claude with the stop at it: exit %d: %q", code, p.output())
	}

	// A daemon whose stop is this test process: protect creates the
	// folder's vault (on this test's own terminal, no fake claude), lock.
	stopAgent := startDaemon(t, exe, childEnv(h, nil).Environ(), h.Layout.Socket)
	p = startPTY(t, exe, h, h.HomeDir, nil, "protect", h.Root)
	p.expect("passphrase")
	p.send(testPassphrase + "\r")
	if code := p.wait(); code != 0 {
		t.Fatalf("protect exit %d: %q", code, p.output())
	}
	if r := precinto(t, exe, h, h.HomeDir, nil, "", "lock"); r.code != 0 {
		t.Fatalf("lock: %+v", r)
	}
	// The fake claude (cwd outside the folder) asks to unlock the folder:
	// below the daemon's stop, it is an agent context (C12.agent, D28).
	p = startPTYEnv(t, claude, atClaude.Environ(), h.HomeDir, "unlock", "--root", h.Root)
	p.expect(refuseAgentText)
	if code := p.wait(); code != 3 {
		t.Fatalf("unlock --root under claude below the daemon's stop: exit %d: %q", code, p.output())
	}
	stopAgent()

	// A daemon whose stop is the fake claude itself: the same request is a
	// human's on a terminal and unlocks with the passphrase.
	p = startPTYEnv(t, claude, atClaude.With("FAKE_HARNESS_HANDSHAKE", "1").Environ(), h.HomeDir, "unlock", "--root", h.Root)
	claudeID := p.expectProcID()
	startDaemon(t, exe, childEnv(h, map[string]string{paths.EnvTestAncestryStop: claudeID}).Environ(), h.Layout.Socket)
	p.send("\r")
	p.expect("passphrase")
	p.send(testPassphrase + "\r")
	if code := p.wait(); code != 0 || !strings.Contains(p.output(), "unlocked") {
		t.Fatalf("unlock --root under claude with the daemon's stop at it: exit %d: %q", code, p.output())
	}
}

// systemPathForTests is the PATH of throwaway homes outside testkit
// (system directories only: no installed precinto, harness or plugin).
const systemPathForTests = "/usr/bin:/bin:/usr/sbin:/sbin"

// refuseUI answers no relayed prompt (a peer that is never asked).
type refuseUI struct{}

func (refuseUI) Display(string) error { return nil }

func (refuseUI) Secret(string) (*memguard.LockedBuffer, error) {
	return nil, errors.New("refuseUI: no secret")
}

func (refuseUI) Confirm(string, string, string) (bool, error) { return false, nil }
