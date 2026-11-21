// Package inventories embeds the data-driven harness inventories
// (inventories/*.toml, schema 1; SPEC §7.3, D33, HA20).
//
// Owner: G3 (harness adapters). Imports: stdlib only.
//
// claude-code.toml and codex.toml carry process matching, passthrough and
// direct-mode argv lists and resume flags for the built-in adapters; every
// other file ships with status = "experimental" and is used only with
// --experimental (wrapper-only, no hooks).
package inventories
