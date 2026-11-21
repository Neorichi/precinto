// Package hook implements `precinto hook <harness> <event>` (SPEC §14,
// docs/HOOKS-IO.md): real-host detection that defaults to the argv label
// (HA21, D56), per-harness payload
// decoders that keep only content-free facts, the decision logic (ledger
// taint, gate query with a 150 ms budget, fail-closed for managed sessions,
// GUI-only unlock on human prompts, D22/D26/D27/D37), per-harness/per-event
// output encoders, its own deadline below the harness timeout, panic
// recovery, and the detached seal request at SessionEnd.
//
// Owner: G5 (hooks & packaging). Imports: stdlib, internal/ipc,
// internal/ledger, internal/config, internal/paths, internal/platform,
// internal/fsx, internal/ui, internal/harness, internal/sweep/queue.
//
// Never write hook stdin, prompts, tool input/output, summaries or
// environment values anywhere (logs, ledger, errors) — including on parse
// errors (S11, S13). The allow path prints nothing on stdout. Hook mode
// never honours PRECINTO_* overrides: hooks always run in an agent context
// (D6). Every dependency is behind Deps (fakeable Daemon and Ledger,
// injected Identify, Enqueue and Spawn), so golden tests need no other
// group's implementation.
package hook
