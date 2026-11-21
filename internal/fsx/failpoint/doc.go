// Package failpoint provides named fault-injection points for crash and
// errno-injection tests (docs/TESTPLAN.md "crash-injection").
//
// Owner: G1 (crypto core). Imports: stdlib only.
//
// Production builds compile every point to a no-op. Builds with
// `-tags failpoints` are armed in-process with Set/Reset; binaries are armed
// by cmd/precinto, which reads PRECINTO_CRASHPOINT through internal/paths
// (paths.EnvCrashpoint; only paths reads the environment) and calls Set
// before dispatching. The spec syntax is:
//
//	PRECINTO_CRASHPOINT=<name>[:<n>]            SIGKILL self at the n-th hit (default 1)
//	PRECINTO_CRASHPOINT=<name>=errno:<E>[:<n>]  return syscall errno E at the n-th hit
//
// Point names are "<component>.<step>" and come from the registry in
// docs/TESTPLAN.md §4, which also says which package hits each name; a name
// is hit in exactly one place (capsule.Seal hits only "capsule.*", sweep
// only its own "seal.*"/"restore.*"/"history.*"/"codex.*" names), so the
// ":<n>" hit counts are meaningful. Every destructive step listed in SPEC
// §10/§11 has a point. Implemented in the scaffold.
package failpoint
