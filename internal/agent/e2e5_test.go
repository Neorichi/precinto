//go:build darwin || linux

package agent_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/creack/pty"

	"github.com/Neorichi/precinto/internal/config"
	"github.com/Neorichi/precinto/internal/ipc"
	"github.com/Neorichi/precinto/internal/paths"
	"github.com/Neorichi/precinto/internal/platform"
	"github.com/Neorichi/precinto/internal/testkit"
	"github.com/Neorichi/precinto/internal/vault/vaulttest"
)

// TestE2E5UnwrappedClaudeEndedAtHardLock is the unwrapped part of E2E-5
// (TESTPLAN §9; D52, D57; opt-in, PRECINTO_E2E=1, never run in
// automation): a real, unwrapped `claude` started from an interactive shell
// in a throwaway CLAUDE_CONFIG_DIR inside an unlocked protected folder;
// `precinto lock --end` (hard lock) ends it with ProcID-verified signals,
// the terminal is scrubbed and C5 is printed on it, and the login shell and
// another job of that terminal survive (precinto never signals a session or
// process group it did not create, D57).
//
// It needs a logged-in claude on PATH (the existing login keychain item is
// reused through CLAUDE_SECURESTORAGE_CONFIG_DIR=""; no transcript of the
// user is read) and runs `--model haiku`. Every process it starts dies with
// it: the shell and its jobs with the pseudo-terminal the test holds, the
// daemon through a lifeline pipe.
func TestE2E5UnwrappedClaudeEndedAtHardLock(t *testing.T) {
	if os.Getenv("PRECINTO_E2E") != "1" {
		t.Skip("opt-in E2E: set PRECINTO_E2E=1 (runs a real claude)")
	}
	if !paths.TestingBuild() {
		t.Skip("needs -tags testing (the test dials the testing daemon with Insecure)")
	}
	claudeBin, err := exec.LookPath("claude")
	if err != nil {
		t.Skip("no claude on PATH")
	}
	h := testkit.NewHome(t)
	fx := vaulttest.New(t, h.Layout.Base, "root-acme")
	// The daemon reads Claude's registry from the registered home (D52).
	cfg := h.Cfg
	cc := cfg.Harness["claude-code"]
	cc.Homes = append(cc.Homes, config.Home{Dir: h.ClaudeConfig, Tmp: h.ClaudeTmp, Default: true})
	cfg.Harness["claude-code"] = cc
	if err := config.Save(h.Layout.ConfigFile, cfg); err != nil {
		t.Fatal(err)
	}
	// Skip Claude's first-run screens in the throwaway config dir.
	seed, _ := json.Marshal(map[string]any{"hasCompletedOnboarding": true,
		"projects": map[string]any{h.Root: map[string]any{"hasTrustDialogAccepted": true}}})
	if err := os.WriteFile(filepath.Join(h.ClaudeConfig, ".claude.json"), seed, 0o600); err != nil {
		t.Fatal(err)
	}
	bin := testkit.BuildBinary(t, "testing")
	env := append(h.Env.Environ(), "CLAUDE_SECURESTORAGE_CONFIG_DIR=", "PATH="+filepath.Dir(claudeBin)+":/usr/bin:/bin:/usr/sbin:/sbin")

	// The daemon, ended by its lifeline: the shell kills its own child (a
	// pid it has not reaped cannot be reused) when the test's pipe closes.
	lifeR, lifeW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	daemon := exec.Command("/bin/sh", "-c", `"$0" agent --foreground & pid=$!; read _; kill "$pid"; wait "$pid"`, bin)
	daemon.Env, daemon.Stdin, daemon.Dir = env, lifeR, "/"
	if err := daemon.Start(); err != nil {
		t.Fatal(err)
	}
	lifeR.Close()
	t.Cleanup(func() {
		lifeW.Close()
		done := make(chan struct{})
		go func() { _ = daemon.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(15 * time.Second):
			_ = daemon.Process.Kill() // our own child
			<-done
		}
	})
	dial := func() *ipc.Client {
		t.Helper()
		deadline := time.Now().Add(20 * time.Second)
		for {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			c, err := ipc.Dial(ctx, ipc.DialOptions{Layout: h.Layout, Client: "test", Timeout: 2 * time.Second, Insecure: true})
			cancel()
			if err == nil {
				return c
			}
			if time.Now().After(deadline) {
				t.Fatalf("daemon not reachable: %v", err)
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
	c := dial()
	defer c.Close()

	// An interactive login shell on a pseudo-terminal the test holds: when
	// the test ends, the terminal hangs up and the shell and its jobs go.
	shell := exec.Command("/bin/sh", "-i")
	shell.Env, shell.Dir = env, h.Root
	tty, err := pty.Start(shell)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var screen bytes.Buffer
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := tty.Read(buf)
			mu.Lock()
			screen.Write(buf[:n])
			mu.Unlock()
			if err != nil {
				return
			}
		}
	}()
	output := func() string { mu.Lock(); defer mu.Unlock(); return screen.String() }
	t.Cleanup(func() {
		// The shell's descendants are our own; kill them by verified
		// identity, then hang up the terminal.
		if id, err := platform.Identify(shell.Process.Pid); err == nil {
			if desc, err := platform.Descendants(platform.System(), id); err == nil {
				for _, d := range desc {
					_ = platform.Signal(d.ID, syscall.SIGKILL)
				}
			}
		}
		tty.Close()
		_ = shell.Process.Kill()
		_ = shell.Wait()
	})
	waitFor := func(what string, d time.Duration, cond func() bool) {
		t.Helper()
		deadline := time.Now().Add(d)
		for !cond() {
			if time.Now().After(deadline) {
				t.Fatalf("timed out waiting for %s; terminal:\n%q", what, output())
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
	shellID, err := platform.Identify(shell.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}

	// Unlock the folder on the terminal with the recovery factor.
	mark := len(output())
	if _, err := tty.WriteString("'" + bin + "' unlock --root '" + h.Root + "' --factor recovery\n"); err != nil {
		t.Fatal(err)
	}
	waitFor("the secret prompt", 20*time.Second, func() bool {
		return strings.Contains(output()[mark:], "(Ctrl-C") || strings.Contains(strings.ToLower(output()[mark:]), "recovery")
	})
	if _, err := tty.WriteString(fx.Recovery.String() + "\n"); err != nil {
		t.Fatal(err)
	}
	unlocked := func() bool {
		st, err := c.Status(context.Background())
		if err != nil {
			return false
		}
		for _, v := range st.Vaults {
			if v.VaultID == "root-acme" {
				return v.State == "unlocked"
			}
		}
		return false
	}
	waitFor("the folder unlocked", 30*time.Second, unlocked)

	// Another job of this terminal, then the unwrapped claude.
	if _, err := tty.WriteString("sleep 600 &\n'" + claudeBin + "' --model haiku\n"); err != nil {
		t.Fatal(err)
	}
	var claude platform.ProcInfo
	waitFor("claude running", 60*time.Second, func() bool {
		desc, err := platform.Descendants(platform.System(), shellID)
		if err != nil {
			return false
		}
		for _, d := range desc {
			if strings.Contains(d.Exe, "claude") || (len(d.Argv) > 1 && strings.HasSuffix(d.Argv[1], "/claude")) {
				claude = d
				return true
			}
		}
		return false
	})
	waitFor("claude's registry entry", 60*time.Second, func() bool {
		ents, _ := os.ReadDir(filepath.Join(h.ClaudeConfig, "sessions"))
		return len(ents) > 0
	})
	var job platform.ProcInfo
	if desc, err := platform.Descendants(platform.System(), shellID); err == nil {
		for _, d := range desc {
			if filepath.Base(d.Exe) == "sleep" {
				job = d
			}
		}
	}
	time.Sleep(12 * time.Second) // past the hook-presence window (§14.4)

	// Hard lock.
	mark = len(output())
	lock := exec.Command(bin, "lock", "--end")
	lock.Env, lock.Dir = env, "/"
	if out, err := lock.CombinedOutput(); err != nil {
		t.Fatalf("precinto lock --end: %v\n%s", err, out)
	}
	waitFor("claude ended", 90*time.Second, func() bool { return !platform.System().Alive(claude.ID) })
	waitFor("C5 on the terminal", 30*time.Second, func() bool {
		o := output()[mark:]
		return strings.Contains(o, "precinto: locked ") && strings.Contains(o, "and ended 1 session")
	})
	if !strings.Contains(output()[mark:], "\x1b[?1049l") {
		t.Fatalf("terminal not scrubbed; output after the lock:\n%q", output()[mark:])
	}
	if !platform.System().Alive(shellID) {
		t.Fatal("the login shell was signalled (D57)")
	}
	if !job.ID.IsZero() && !platform.System().Alive(job.ID) {
		t.Fatal("another job of the terminal was signalled (D57)")
	}
	mark = len(output())
	if _, err := tty.WriteString("echo still-$((40+2))\n"); err != nil {
		t.Fatal(err)
	}
	waitFor("the shell answers", 10*time.Second, func() bool { return strings.Contains(output()[mark:], "still-42") })
}
