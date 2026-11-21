// Package capsule implements capsule format v1: keyless two-pass sealing to
// public age recipients with an ephemeral round-trip verification, header
// stanza checks, manifest-only decryption with a file key, and bounded,
// validating extraction into a staging directory (SPEC §5, §10, §11; D2, D5,
// D8, D13, D45).
//
// Owner: G1 (crypto core). Imports: stdlib, filippo.io/age,
// github.com/klauspost/compress/zstd, internal/fsx, internal/fsx/failpoint.
//
// capsule never deletes plaintext and never decides liveness or placement:
// internal/sweep does. capsule never logs file contents or manifest titles.
// UnitKey, GenName and ParseGenName are implemented in the scaffold.
package capsule
