package main

import "fmt"

// Subcommand handlers. Each returns an exit code; until implemented they
// report "not implemented" (exit 1). G7 implements them by wiring the
// internal packages as described in docs/API.md §G7.

func cmdInit(args []string, s stdio) int      { return notImplemented("init", s) }
func cmdFactor(args []string, s stdio) int    { return notImplemented("factor", s) }
func cmdVault(args []string, s stdio) int     { return notImplemented("vault", s) }
func cmdProtect(args []string, s stdio) int   { return notImplemented("protect", s) }
func cmdUnprotect(args []string, s stdio) int { return notImplemented("unprotect", s) }
func cmdStatus(args []string, s stdio) int    { return notImplemented("status", s) }
func cmdUnlock(args []string, s stdio) int    { return notImplemented("unlock", s) }
func cmdLock(args []string, s stdio) int      { return notImplemented("lock", s) }
func cmdSeal(args []string, s stdio) int      { return notImplemented("seal", s) }
func cmdSweep(args []string, s stdio) int     { return notImplemented("sweep", s) }
func cmdRestore(args []string, s stdio) int   { return notImplemented("restore", s) }
func cmdResume(args []string, s stdio) int    { return notImplemented("resume", s) }
func cmdRun(args []string, s stdio) int       { return notImplemented("run", s) }
func cmdLs(args []string, s stdio) int        { return notImplemented("ls", s) }
func cmdOpen(args []string, s stdio) int      { return notImplemented("open", s) }
func cmdCat(args []string, s stdio) int       { return notImplemented("cat", s) }
func cmdResolve(args []string, s stdio) int   { return notImplemented("resolve", s) }
func cmdForget(args []string, s stdio) int    { return notImplemented("forget", s) }
func cmdPrune(args []string, s stdio) int     { return notImplemented("prune", s) }
func cmdCodex(args []string, s stdio) int     { return notImplemented("codex", s) }
func cmdAgent(args []string, s stdio) int     { return notImplemented("agent", s) }
func cmdService(args []string, s stdio) int   { return notImplemented("service", s) }
func cmdShellInit(args []string, s stdio) int { return notImplemented("shell-init", s) }
func cmdIntegrate(args []string, s stdio) int { return notImplemented("integrate", s) }
func cmdDoctor(args []string, s stdio) int    { return notImplemented("doctor", s) }
func cmdRecover(args []string, s stdio) int   { return notImplemented("recover", s) }
func cmdShellHook(args []string, s stdio) int { return notImplemented("shell-hook", s) }

// cmdHook must stay fast and fail closed; it delegates to hook.Main
// (G5). Until wired it exits 1, which Claude treats as a failure and blocks
// gate events via onFailure:"block".
func cmdHook(args []string, s stdio) int { return notImplemented("hook", s) }

// cmdDeferred reports commands deferred beyond v0.2 (D49).
func cmdDeferred(args []string, s stdio) int {
	fmt.Fprintln(s.err, "precinto: this command is planned for a later version (see docs/DECISIONS.md D49)")
	return exitUsage
}

// cmdVersion prints the version.
func cmdVersion(args []string, s stdio) int {
	fmt.Fprintf(s.out, "precinto %s\n", version)
	return exitOK
}

// Exit-code constants referenced by future handlers; kept here so the
// table in docs/API.md §G7 stays in one place.
var _ = []int{exitOK, exitError, exitUsage, exitLocked, exitLive, exitVerify}
