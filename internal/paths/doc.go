// Package paths resolves every precinto-owned location and is the only
// package that reads the process environment (SPEC §6, D6).
//
// Owner: G7 (CLI). Imports: stdlib, internal/fsx.
//
// Production builds ignore PRECINTO_HOME and PRECINTO_RUNTIME_DIR unless
// the binary was built with `-tags testing`, or PRECINTO_DEV=1 is set and
// no agent marker is present (D6). The hook shim never reads PRECINTO_*
// variables. Unit tests do not need the tag: they build a Layout
// explicitly with LayoutAt.
//
// The scaffold implements the leaf helpers every group needs from day one
// (Env, UserHome, DefaultBase, LayoutAt, Within, Clean, Tilde and the
// Layout path helpers); NewLayout, AgentMarkers, OverridesAllowed and
// EnsureDirs are G7's.
package paths
