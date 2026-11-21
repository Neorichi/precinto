// Package codextest writes synthetic Codex homes (rollouts with marker
// text, *_N.sqlite files with -wal/-shm siblings as opaque bytes,
// history.jsonl, session_index.jsonl, thread-writer-locks, shell snapshots,
// auth.json and config.toml placeholders) for tests. Never touches ~/.codex.
//
// Owner: G3 (harness adapters). Imports: stdlib. Test-only.
package codextest
