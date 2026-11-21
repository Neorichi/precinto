// Package shellinit renders the zsh, bash and fish integration printed by
// `precinto shell-init <shell>` and implements the decision behind the
// folder-entry hook `precinto shell-hook` (SPEC §15.5; D29; UX19).
//
// Owner: G5 (hooks & packaging). Imports: stdlib, internal/config,
// internal/paths, internal/ipc, internal/ui.
//
// The snippets define wrapper functions for enabled harnesses that run
// `command precinto run --harness H -- H "$@"` (guarded by PRECINTO_ACTIVE
// to avoid recursion), and a chpwd/precmd (zsh), PROMPT_COMMAND (bash) or
// --on-variable PWD (fish) hook that runs only in interactive top-level
// shells, is skipped when VSCODE_RESOLVING_ENVIRONMENT is set, fires only on
// outside→inside transitions (or the first prompt of a shell started
// inside), asks at most once per shell per lock epoch, and never reads the
// TTY in the fast path (daemon query ≤ 150 ms).
package shellinit
