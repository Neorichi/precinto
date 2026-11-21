// Package claude is the Claude Code adapter (capsule mode, SPEC §7.1):
// session units by session id (fail-closed), project units (auto memory,
// legacy sessions-index.json, MCP logs), plan units by slug (D46), history
// lines per root (D36), global stores, registry and job readers for
// liveness, transcript scanning for Markdown paths, titles and fork
// references, and the launch plan (resume parsing, --settings injection D32,
// retention clamp D14).
//
// Owner: G3 (harness adapters). Imports: stdlib, internal/harness and
// everything it may import, inventories.
//
// Never re-implement Claude's slug: locate transcripts by session id across
// every projects/* directory (D19); map slugs to cwds with the project index.
package claude
