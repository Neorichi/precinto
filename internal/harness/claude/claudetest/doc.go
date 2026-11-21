// Package claudetest writes synthetic Claude Code layouts (transcripts with
// marker text, subagents, tool-results, file-history, session-env, tmp
// scratchpads, registry and job files, history.jsonl, paste-cache, memory)
// under a fake CLAUDE_CONFIG_DIR / CLAUDE_CODE_TMPDIR. Never copies real
// user data (SPEC §20, S13).
//
// Owner: G3 (harness adapters). Imports: stdlib, internal/harness/claude
// (RegistryEntry), internal/platform.
// Test-only.
package claudetest
