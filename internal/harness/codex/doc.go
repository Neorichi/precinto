// Package codex is the Codex adapter with per-root homes (D31, SPEC §7.2):
// `precinto run codex` inside a protected root runs Codex with
// CODEX_HOME=<base>/homes/codex/<root-id>, seeded from ~/.codex; the home is
// sealed as one snapshot generation (manifest + blobs, SQLite groups kept
// together, -shm never sealed) and restored all-or-nothing before launch.
//
// Owner: G3 (harness adapters). Imports: stdlib, internal/harness and
// everything it may import, inventories.
//
// Never open Codex SQLite databases (no SQLite driver is linked); treat them
// as opaque file groups.
package codex
