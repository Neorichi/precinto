// Package config is the schema of <base>/config.toml: protected roots (with
// stable ids), lock policy, registered harness homes, and the helpers that
// map paths to roots and detect protection-weakening edits (SPEC §6, §12.2,
// §12.9; D22, D29, D38, D48).
//
// Owner: G7 (CLI). Imports: stdlib, github.com/BurntSushi/toml,
// internal/paths, internal/fsx.
//
// Default() is normative: it encodes the defaults of SPEC §12.2. The
// scaffold also implements the helpers every group needs from day one —
// Duration text encoding, Load (defaults merged, unknown keys rejected),
// Save, Validate, RootFor/RootsFor/RootByID/Overlapping/EffectiveOnEnter,
// roots.list I/O, Canonical and the policy.pinned file (D55). Diff,
// Strictest and NewRootID are G7's.
package config
