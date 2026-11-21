package main

import (
	"strings"
	"testing"
)

func TestNoArgumentsIsUsage(t *testing.T) {
	e := newEnv(t)
	if code := e.run(); code != exitUsage {
		t.Fatalf("exit %d, want %d", code, exitUsage)
	}
	if !strings.Contains(e.stderr(), "usage: precinto <command>") {
		t.Fatalf("stderr %q lacks the usage line", e.stderr())
	}
}

func TestHelpListsVisibleCommands(t *testing.T) {
	for _, arg := range []string{"--help", "-h", "help"} {
		e := newEnv(t)
		if code := e.run(arg); code != exitOK {
			t.Fatalf("%s: exit %d", arg, code)
		}
		out := e.stdout()
		for _, c := range commands {
			listed := strings.Contains(out, "\n  "+c.name+" ")
			if listed == c.hidden {
				t.Errorf("%s: command %s listed=%v, hidden=%v", arg, c.name, listed, c.hidden)
			}
		}
	}
}

func TestUnknownCommand(t *testing.T) {
	e := newEnv(t)
	if code := e.run("frobnicate"); code != exitUsage {
		t.Fatalf("exit %d, want %d", code, exitUsage)
	}
	if !strings.Contains(e.stderr(), `unknown command "frobnicate"`) {
		t.Fatalf("stderr %q", e.stderr())
	}
}

// Every subcommand of SPEC §16.1 answers --help with its usage on stdout
// and exit 0, and refuses an unknown flag with exit 2, before touching any
// other package.
func TestEverySubcommandHelpAndBadFlag(t *testing.T) {
	for _, c := range commands {
		if c.name == "hook" || c.name == "version" || c.name == "help" || c.run == nil {
			continue
		}
		if isDeferred(c) {
			continue
		}
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t)
			if code := e.run(c.name, "--help"); code != exitOK {
				t.Fatalf("--help: exit %d (stderr %q)", code, e.stderr())
			}
			want := c
			if strings.HasPrefix(c.summary, "alias of ") {
				want, _ = lookup(strings.Fields(strings.TrimPrefix(c.summary, "alias of "))[0])
			}
			if !strings.HasPrefix(e.stdout(), "usage: precinto "+want.usage) {
				t.Fatalf("--help printed %q", e.stdout())
			}
			e2 := newEnv(t)
			if code := e2.run(c.name, "--no-such-flag"); code != exitUsage {
				t.Fatalf("bad flag: exit %d, want %d", code, exitUsage)
			}
			if !strings.Contains(e2.stderr(), "usage: precinto "+want.name) {
				t.Fatalf("bad flag stderr %q", e2.stderr())
			}
			if e2.hardened != 0 || len(e2.dials) != 0 || len(e2.engExp) != 0 {
				t.Fatalf("a usage error touched the system (harden %d, dials %d, engine %d)", e2.hardened, len(e2.dials), len(e2.engExp))
			}
		})
	}
}

func isDeferred(c command) bool { return strings.Contains(c.summary, "deferred beyond v0.2") }

// D49: canary, scrub, rekey and import exit 2 with a notice.
func TestDeferredCommandsExitUsage(t *testing.T) {
	for _, name := range []string{"canary", "scrub", "rekey", "import"} {
		e := newEnv(t)
		if code := e.run(name, "x"); code != exitUsage {
			t.Errorf("%s: exit %d, want %d", name, code, exitUsage)
		}
		if !strings.Contains(e.stderr(), "planned for a later version") {
			t.Errorf("%s: stderr %q lacks the notice", name, e.stderr())
		}
	}
}

func TestVersion(t *testing.T) {
	for _, args := range [][]string{{"version"}, {"--version"}, {"-v"}} {
		e := newEnv(t)
		if code := e.run(args...); code != exitOK {
			t.Fatalf("%v: exit %d", args, code)
		}
		if !strings.HasPrefix(e.stdout(), "precinto ") {
			t.Fatalf("%v: %q", args, e.stdout())
		}
	}
}

func TestHelpCommand(t *testing.T) {
	e := newEnv(t)
	if code := e.run("help", "lock"); code != exitOK {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(e.stdout(), "usage: precinto lock") {
		t.Fatalf("stdout %q", e.stdout())
	}
	e = newEnv(t)
	if code := e.run("help", "nope"); code != exitUsage {
		t.Fatalf("exit %d", code)
	}
}

// The hook entry point goes straight to hook.Main: nothing else runs (no
// config, no hardening by the CLI, no daemon), and its exit code is the
// hook's (D43).
func TestHookDelegatesAtOnce(t *testing.T) {
	e := newEnv(t)
	code := e.run("hook", "claude-code", "UserPromptSubmit")
	if code != 10 {
		t.Fatalf("exit %d, want the hook's 10", code)
	}
	if len(e.hooked) != 1 || strings.Join(e.hooked[0], " ") != "claude-code UserPromptSubmit" {
		t.Fatalf("hook args %v", e.hooked)
	}
	if e.hardened != 0 || len(e.dials) != 0 || len(e.engExp) != 0 {
		t.Fatal("the hook fast path touched more than hook.Main")
	}
}

func TestCommandTableMatchesSpec(t *testing.T) {
	// SPEC §16.1 commands, in order of the spec.
	want := []string{"init", "factor", "vault", "protect", "unprotect", "status", "unlock", "lock", "seal",
		"sweep", "restore", "resume", "run", "ls", "open", "cat", "resolve", "merge", "forget", "prune",
		"codex", "agent", "service", "shell-init", "integrate", "doctor", "recover", "version", "hook", "shell-hook",
		"canary", "scrub", "rekey", "import"}
	for _, n := range want {
		if _, ok := lookup(n); !ok {
			t.Errorf("command %s missing", n)
		}
	}
}
