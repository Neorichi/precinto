// Package live is the liveness engine: it decides whether any process can
// still write a unit, from the union of evidence measured by precinto itself
// (SPEC §9; D18, D19, D20, D25; R4, R8, R9, R16, R17, S14):
//
//   - ledger processes (ProcID equality, zombies are dead),
//   - launch leases (shared flocks held by wrappers),
//   - harness-specific evidence supplied by adapters (Claude registry and job
//     records, Codex writer locks, open-file holders),
//   - a stability window measured on the monotonic clock.
//
// Any doubt (read error, unknown schema, half-written registry, lock probe
// failure) means live. Units held live only by weak evidence (name or mtime
// only) for longer than policy.hold_cap are reported in status (S14).
//
// Owner: G3 (harness adapters). Imports: stdlib, internal/platform,
// internal/fsx, internal/paths, internal/config, internal/ledger.
package live
