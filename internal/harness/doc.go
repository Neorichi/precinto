// Package harness defines what a harness adapter must provide (SPEC §7):
// registered homes, the inventory of plaintext units (fail-closed),
// harness-specific liveness evidence, allowed restore targets per kind
// (derived from trusted context, never from manifests, D8), per-file
// placement policies (D11), and the launch plan the wrapper executes
// (restore-before-launch, injected settings, environment, PTY mode).
// It also defines the data-driven inventory TOML schema (D33, HA20).
//
// Owner: G3 (harness adapters). Imports: stdlib,
// github.com/BurntSushi/toml, internal/capsule, internal/config,
// internal/paths, internal/fsx, internal/platform, internal/ledger,
// internal/live.
//
// Adapters never seal, restore, or delete: internal/sweep does, using the
// units, targets and policies adapters return.
package harness
