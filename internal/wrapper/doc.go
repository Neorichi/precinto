// Package wrapper implements `precinto run [--harness H] [--no-pty] -- CMD
// [ARGS…]` (SPEC §15): launch planning through the harness adapter, unlock
// in this terminal, launch lease, synchronous restore of the targeted units
// before exec and background restore of the rest, the PTY proxy (raw mode,
// SIGWINCH, job control), the lock overlay with output kept in a bounded
// scrollback and replayed on unlock (D30), input gating with
// terminal-generated sequences filtered from human activity (UX15),
// termination on "end" events, TTY reset, and seal-after-exit.
//
// Owner: G6 (wrapper). Imports: stdlib, github.com/creack/pty,
// golang.org/x/term, internal/harness, internal/ipc, internal/live,
// internal/config, internal/paths, internal/platform, internal/fsx,
// internal/ui.
//
// The wrapper never imports internal/sweep, internal/vault or
// internal/agent: it orchestrates through the Backend interface that
// cmd/precinto implements ("restore-before-launch orchestration via
// interfaces").
package wrapper
