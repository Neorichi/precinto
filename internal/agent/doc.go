// Package agent is the per-user daemon `precinto agent` (SPEC §12, §13):
// the only holder of unwrapped identities (Keyring, D4), the folder/session
// lock state machine (D23–D26), triggers (idle timers, max_unlock,
// screen lock, HID idle, sleep/wake jumps), the gate (answered from an
// atomically swapped in-memory snapshot, never waiting on I/O), relayed
// unlock UI (D4, D27), per-capsule key release (D39), policy pinning (D48),
// session registry and termination (S14, R11, R20), roots.list and the
// verified recipient copies, and the work queue (it spawns
// `precinto sweep|seal|restore` workers; it never seals or restores
// in-process).
//
// Owner: G2 (daemon). Imports: stdlib, github.com/awnumar/memguard,
// internal/ipc, internal/vault, internal/capsule, internal/sweep/capslog,
// internal/sweep/queue, internal/sweep/journal, internal/config,
// internal/paths, internal/platform, internal/fsx, internal/ledger,
// internal/harness, internal/harness/claude, internal/ui, inventories
// (harness process matching, CC-12).
//
// Machine is pure (no I/O, no goroutines, injected clock) so it can be
// tested exhaustively with internal/platform/fakeplatform. Run's side
// effects that a test cannot allow (hardening the process, spawning
// workers from Exe, polling the real console, running pinentry) go
// through Options seams that internal/agent/agenttest replaces.
//
// Trust rules: the daemon re-measures every pid a client sends (SPEC
// §9.1), computes prompt origins itself (D54), and acts on signals only
// for ProcID-verified processes it registered or found by its own scan
// (D57).
package agent
