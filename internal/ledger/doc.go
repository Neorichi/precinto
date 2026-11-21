// Package ledger records content-free facts about managed sessions: which
// harness process (ProcID measured by precinto) owns which session, the
// directories and paths that made the session managed ("taint", sticky),
// Markdown paths written, compaction in flight, the harness homes used, and
// session end reasons (SPEC §7.0, §9; D18, D19, D20; S6, HA10, IM4).
//
// Owner: G3 (harness adapters). Imports: stdlib, internal/paths,
// internal/fsx, internal/platform, internal/config.
//
// The ledger never stores prompts, tool input/output, assistant text or
// environment values. A session's ledger file is created only at its first
// managed event, and is moved into the session capsule when the unit is
// sealed (S13).
package ledger
