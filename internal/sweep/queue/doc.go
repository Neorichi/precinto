// Package queue holds pending seal requests (state/queue/<id>.json) written
// by hooks and wrappers and drained by the sweep-lock holder or a
// daemon-spawned worker (SPEC §10.6; R19, HA16, HA17).
//
// Owner: G4 (orchestration). Imports: stdlib, internal/fsx,
// internal/platform.
package queue
