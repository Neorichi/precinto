// Package precinto carries precinto's harness plugins and their
// marketplace manifests (SPEC §21) inside the binary, so that `precinto
// integrate` installs them from bytes precinto controls, written under
// precinto's own directory, and never from a network marketplace (D116).
//
// Owner: G5 (hooks & packaging). Imports: stdlib only.
//
// The files are embedded at their repository paths: the Claude Code
// marketplace (.claude-plugin/marketplace.json → plugin/), the Codex one
// (.agents/plugins/marketplace.json → plugins/codex/, byte-stable, D41,
// D78) and every file of both plugin roots. Directories are named one by
// one so that a stray dot file of a checkout (.DS_Store) is never
// embedded; a test keeps the list equal to the repository's files.
package precinto

import "embed"

// Plugins holds the marketplace manifests and the plugin files, at their
// repository paths.
//
//go:embed .claude-plugin/marketplace.json .agents/plugins/marketplace.json
//go:embed plugin/.claude-plugin plugin/.cursor-plugin plugin/.github plugin/hooks plugin/scripts plugin/commands plugin/skills
//go:embed plugins/codex/.codex-plugin plugins/codex/hooks plugins/codex/scripts
var Plugins embed.FS
