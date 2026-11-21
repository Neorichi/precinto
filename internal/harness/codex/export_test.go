package codex

import "testing"

// GoldenTrust exposes the pinned Codex 0.154 trust hashes of precinto's
// hooks ("<event label>:<group>:<handler>" → hash) to the external tests.
func GoldenTrust(t *testing.T) map[string]string { return goldenTrust(t) }

// AuthRecordName is the per-root home's auth.json sync record (D100).
const AuthRecordName = authRecordName
