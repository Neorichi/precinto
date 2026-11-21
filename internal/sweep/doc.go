// Package sweep orchestrates sealing and restoring (SPEC §8, §10, §11):
// planning per unit, keyless two-pass sealing through internal/capsule,
// generations that are never overwritten (D9), lineage from restore receipts
// (D10, D42), the provenance log (D8), journaled crash-safe phases (I9),
// deletion of originals with identity and liveness re-checks, unit-atomic
// restore through staging with the placement table (D11, D12), history
// rotation and merge (D21, D36), the Markdown policy (D16, D17), Codex
// per-root home snapshots (D31), the seal queue and the sweep lock.
//
// Owner: G4 (orchestration). Imports: stdlib, github.com/awnumar/memguard,
// internal/capsule, internal/vault, internal/harness (+ claude, codex,
// generic), internal/live, internal/ledger, internal/config,
// internal/paths, internal/fsx, internal/fsx/failpoint, internal/platform,
// internal/sweep/journal, internal/sweep/capslog, internal/sweep/queue.
//
// sweep never holds an identity: restore obtains per-capsule file keys
// through KeySource (production: the daemon, D39). sweep never imports
// internal/ipc; cmd/precinto adapts ipc to KeySource and Grants.
package sweep
