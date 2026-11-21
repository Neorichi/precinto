// Package capslog is the capsule provenance log state/capsules.log: one
// JSON line per committed capsule. Restore and key release accept only
// logged capsules; anything else is quarantined (SPEC §11.1; D8, D39).
//
// Owner: G4 (orchestration). Imports: stdlib, internal/fsx.
//
// The log holds no content and no plaintext paths: units are named by
// HMAC-derived unit keys (D45). It is read by internal/agent for key
// release, so it must stay a leaf package.
package capslog
