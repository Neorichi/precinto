// Package testkit builds throwaway environments for tests of every group
// (docs/TESTPLAN.md §2 "fake HOME conventions"): a temp HOME with
// PRECINTO_HOME, a short PRECINTO_RUNTIME_DIR (sun_path < 104 bytes),
// CLAUDE_CONFIG_DIR, CLAUDE_CODE_TMPDIR, CODEX_HOME and XDG_* all under
// t.TempDir(), a config with one protected root, golden-file helpers and
// the testdata hygiene check.
//
// Owner: G7 (CLI). Imports: stdlib, internal/paths, internal/config,
// internal/platform, internal/platform/fakeplatform. Test-only.
package testkit
