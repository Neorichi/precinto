// Package journal persists one record per in-flight destructive operation
// so that a crash at any step can be rolled back or rolled forward without
// any key (SPEC §10.5, §11.5; I9; R5).
//
// Owner: G4 (orchestration). Imports: stdlib, internal/fsx,
// internal/fsx/failpoint.
//
// Records are created O_CREAT|O_EXCL, fsynced with their directory, hold no
// content (paths are base-relative, unit keys are HMACs), and are deleted
// at PhaseDone. Every phase is a completed milestone: a record is advanced
// to a phase only after that step has finished and is durable, and
// everything recovery needs to undo or finish the next step (for a seal:
// the temporary and the final capsule name) is recorded before that step
// starts (D58).
package journal
