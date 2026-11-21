package main

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/precinto/precinto/internal/fsx/failpoint"
	"github.com/precinto/precinto/internal/paths"
)

// Exit codes (SPEC §16.2).
const (
	exitOK       = 0
	exitError    = 1
	exitUsage    = 2
	exitLocked   = 3
	exitLive     = 4
	exitVerify   = 5
	exitNotReady = exitError
)

// version is set with -ldflags "-X main.version=…" by release builds;
// `go install` builds read debug.ReadBuildInfo instead.
var version = "0.1.0-dev"

// stdio bundles the standard streams so handlers stay testable.
type stdio struct {
	in       io.Reader
	out, err io.Writer
}

// command is one subcommand.
type command struct {
	name    string
	usage   string
	summary string
	run     func(args []string, s stdio) int
	hidden  bool // internal entry points (hook, shell-hook) and deferred commands
}

// commands is the dispatch table. Handlers live in commands.go.
var commands = []command{
	{"init", "init [--factor se|passphrase|plugin:<recipient>]… [--recovery-out FILE] [--show-recovery]", "create the vault, factors and recovery key (own terminal only, D7)", cmdInit, false},
	{"factor", "factor list|add|remove|test [ARGS]", "manage unlock factors", cmdFactor, false},
	{"vault", "vault repair --root DIR | --global [--recovery]", "repair a vault whose settings were changed outside precinto (own terminal only, D53)", cmdVault, false},
	{"protect", "protect DIR [--md ledger|all|off] [--on-enter prompt|notify|off] [--harness LIST] [--claude-settings]", "protect a folder (creates its vault, seals what is there)", cmdProtect, false},
	{"unprotect", "unprotect DIR", "restore everything of a folder and stop protecting it (asks to confirm)", cmdUnprotect, false},
	{"status", "status [--json] [--check]", "show folders, sessions, unencrypted files and attention items", cmdStatus, false},
	{"unlock", "unlock [--root DIR | --all | --global] [--for DUR] [--factor NAME] [--extend]", "unlock folders with user presence", cmdUnlock, false},
	{"lock", "lock [--root DIR | --all] [--end] [--force] [--let-finish]", "lock folders (default: all); --end also ends sessions", cmdLock, false},
	{"seal", "seal [--harness H] [--session ID] [--root DIR] [--wait-pid PID:START] [--queue] [--adopt] [--dry-run] [--dormant H --experimental]", "seal now (never needs a key)", cmdSeal, false},
	{"sweep", "sweep [--root DIR] [--lock] [--wait] [--dry-run] [--quiet]", "seal every non-live unit of locked folders", cmdSweep, false},
	{"restore", "restore [--root DIR] [--session ID] [--recent N] [--all] [--md] [--history] [--global] [--background]", "restore sealed units of unlocked folders", cmdRestore, false},
	{"resume", "resume [ID | --last | --pick] [--harness claude-code]", "restore one session and exec the harness to resume it", cmdResume, false},
	{"run", "run [--harness H] [--no-pty] -- CMD [ARGS…]", "run a harness with unlock-before-launch, lock screen and seal-on-exit", cmdRun, false},
	{"ls", "ls [--root DIR] [--conflicts] [--json]", "list sealed units", cmdLs, false},
	{"open", "open FILE.md.precinto…", "restore sealed notes in place", cmdOpen, false},
	{"cat", "cat FILE.md.precinto [--raw] [--to FILE]", "print a sealed note (terminal-sanitized)", cmdCat, false},
	{"resolve", "resolve FILE [--keep capsule|plaintext]", "resolve a note or file conflict", cmdResolve, false},
	{"merge", "merge FILE [--keep capsule|plaintext]", "alias of resolve (D11)", cmdResolve, true},
	{"forget", "forget FILE|UNIT", "delete the sealed copies of a unit (asks to confirm)", cmdForget, false},
	{"prune", "prune [--unit KEY] [--keep N] [--diverged] [--dry-run]", "delete superseded generations (manual only, asks to confirm; D15, D59)", cmdPrune, false},
	{"codex", "codex reconcile --root DIR --prefer capsule|plaintext | codex sync-config --root DIR", "per-root Codex homes: reconcile a diverged home, re-seed config", cmdCodex, false},
	{"agent", "agent [--foreground] [--restart]", "run the per-user daemon", cmdAgent, false},
	{"service", "service install|uninstall|status", "background re-seal LaunchAgent (darwin; the linux unit is deferred, D49)", cmdService, false},
	{"shell-init", "shell-init zsh|bash|fish [--install]", "print (or install) the shell integration", cmdShellInit, false},
	{"integrate", "integrate HARNESS [--print] [--experimental]", "install or print the harness plugin/hooks", cmdIntegrate, false},
	{"doctor", "doctor [--leaks] [HARNESS]", "read-only health and leak checks", cmdDoctor, false},
	{"recover", "recover --verify | recover [--key-file FILE --insecure-key-file]", "use or test the offline recovery key", cmdRecover, false},
	{"version", "version", "print the version", cmdVersion, false},
	{"hook", "hook HARNESS EVENT", "harness hook entry point (reads the payload on stdin)", cmdHook, true},
	{"shell-hook", "shell-hook --shell S --pwd DIR [--prev DIR] [--skip KEY] [--first]", "folder-entry hook entry point", cmdShellHook, true},
	{"canary", "canary HARNESS", "deferred beyond v0.2 (D49)", cmdDeferred, true},
	{"scrub", "scrub claude-json", "deferred beyond v0.2 (D49)", cmdDeferred, true},
	{"rekey", "rekey [--recovery]", "deferred beyond v0.2 (D49)", cmdDeferred, true},
	{"import", "import FILE", "deferred beyond v0.2 (D49)", cmdDeferred, true},
}

func main() {
	armFailpoints()
	os.Exit(run(os.Args[1:], stdio{in: os.Stdin, out: os.Stdout, err: os.Stderr}))
}

// armFailpoints arms fault injection from PRECINTO_CRASHPOINT in binaries
// built with -tags failpoints (docs/TESTPLAN.md §4). Only internal/paths
// reads the environment; every other build ignores the variable.
func armFailpoints() {
	if !failpoint.Enabled() {
		return
	}
	if spec := paths.FromOS().Get(paths.EnvCrashpoint); spec != "" {
		failpoint.Set(spec)
	}
}

// run dispatches args to a subcommand and returns the exit code.
func run(args []string, s stdio) int {
	if len(args) == 0 {
		usage(s.err)
		return exitUsage
	}
	name := args[0]
	switch name {
	case "-h", "--help", "help":
		usage(s.out)
		return exitOK
	case "-v", "--version":
		return cmdVersion(nil, s)
	}
	for _, c := range commands {
		if c.name == name {
			return c.run(args[1:], s)
		}
	}
	fmt.Fprintf(s.err, "precinto: unknown command %q\n", name)
	usage(s.err)
	return exitUsage
}

func usage(w io.Writer) {
	fmt.Fprintln(w, "usage: precinto <command> [flags]")
	fmt.Fprintln(w)
	names := make([]string, 0, len(commands))
	byName := map[string]command{}
	for _, c := range commands {
		if c.hidden {
			continue
		}
		names = append(names, c.name)
		byName[c.name] = c
	}
	sort.Strings(names)
	for _, n := range names {
		fmt.Fprintf(w, "  %-11s %s\n", n, byName[n].summary)
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Run `precinto <command> --help` for flags. Spec: docs/SPEC.md.")
}

// notImplemented is returned by stubs until G7 wires the command.
func notImplemented(name string, s stdio) int {
	fmt.Fprintf(s.err, "precinto: %s is not implemented yet\n", strings.TrimSpace(name))
	return exitNotReady
}
