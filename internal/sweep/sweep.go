package sweep

import (
	"context"
	"errors"
	"time"

	"github.com/awnumar/memguard"

	"github.com/precinto/precinto/internal/capsule"
	"github.com/precinto/precinto/internal/config"
	"github.com/precinto/precinto/internal/fsx"
	"github.com/precinto/precinto/internal/harness"
	"github.com/precinto/precinto/internal/live"
	"github.com/precinto/precinto/internal/platform"
	"github.com/precinto/precinto/internal/sweep/capslog"
	"github.com/precinto/precinto/internal/sweep/journal"
	"github.com/precinto/precinto/internal/vault"
)

// Errors (mapped to exit codes by cmd/precinto).
var (
	ErrLive         = errors.New("sweep: unit is live")                     // exit 4
	ErrBusy         = errors.New("sweep: another sweep holds the lock")     // exit 0 after touching sweep.requested
	ErrConflict     = errors.New("sweep: plaintext conflicts with capsule") // exit 4 for codex launches (R12)
	ErrNoSpace      = errors.New("sweep: not enough free space")            // ENOSPC policy, SPEC §17
	ErrNotLogged    = capslog.ErrNotLogged                                  // exit 5 (no provenance: quarantined, never restored)
	ErrKeyDenied    = errors.New("sweep: file key denied")                  // exit 3
	ErrTripwire     = vault.ErrRecipientsChanged                            // exit 5 (fix: precinto vault repair, D53)
	ErrInaccessible = errors.New("sweep: unit inaccessible (EACCES/EPERM)") // exit 1, reported
	ErrNotMarker    = errors.New("sweep: not a precinto note marker")       // exit 2 (cat/open of a non-marker)
)

// FileKeys is a set of released per-capsule file keys (*ipc.KeySet
// implements it, asserted in cmd/precinto).
type FileKeys interface {
	// Key returns the file key of a capsule path relative to CapsulesDir.
	Key(path string) (*memguard.LockedBuffer, bool)
	// Destroy wipes every key; called on completion and on any lock event.
	Destroy()
}

// KeySource obtains file keys (production: ipc.Client.Keys through
// cmd/precinto; tests: a vaulttest identity). Callers pass at most 256
// paths per FileKeys call (ipc.MaxKeysPerRequest) and destroy the keys as
// soon as their capsules are decrypted.
type KeySource interface {
	FileKeys(ctx context.Context, paths []string, purpose string) (FileKeys, error)
}

// Grants reports which root ids are unlocked right now. An error means
// "treat every root as locked" (R4).
type Grants func(ctx context.Context) (unlocked map[string]bool, err error)

// Env carries every dependency of an operation.
type Env struct {
	Cfg      config.Config
	Harness  harness.Env
	Adapters []harness.Adapter
	Vaults   *vault.Store
	Log      *capslog.Log
	Journal  *journal.Journal
	Live     *live.Engine
	Procs    platform.ProcTable
	Clock    platform.Clock
	Grants   Grants
	// Protected reports the root ids protected right now, as a run started
	// now would take them (cmd/precinto: config.toml on disk merged with
	// the confirmed settings and the folders a running agent reports,
	// D142). ok false says nothing: every root of the run stays protected
	// (seal on doubt). nil: config.toml on disk alone decides (D133, D151).
	Protected func(ctx context.Context) (ids map[string]bool, ok bool)
	Floor     fsx.Floor
	Sealer    string // "precinto <version>"
	// Parallel bounds concurrent unit seals (default 2; units > 1 GiB run alone, R19).
	Parallel int
	// Sleep waits d or until ctx ends; nil = a real timer. It is used for
	// the D63 quiet-window wait (and every other wait of a run: rescue
	// grace, history tail quiet, writer polling). Tests with a fake clock
	// pass one that advances it.
	Sleep func(ctx context.Context, d time.Duration) error
}

// Options controls a seal/sweep run.
type Options struct {
	Scope    harness.Scope
	DryRun   bool
	Quiet    bool
	Wait     bool             // wait for the sweep lock instead of returning ErrBusy
	WaitFor  *platform.ProcID // --wait-pid PID:START: wait for exit, then re-check full liveness (R8)
	Reason   string           // "sweep" | "session-end" | "wrapper-exit" | "lock" | "manual"
	Adopt    bool             // also seal transcripts found outside the ledger that reference a root (S6)
	Lock     bool             // sealing on behalf of a lock (status reason "lock")
	Dormant  string           // generic inventories: seal this harness once (D33)
	Deadline time.Time
	// OnQuietWait, when set, is called once, just before the run's single
	// quiet-window wait (D63), with the wait's length, so a command run
	// from a terminal can say why it pauses (D113). It never runs for a
	// run that does not wait.
	OnQuietWait func(d time.Duration)

	// queuedAt is set on the jobs of queued requests: the newest request
	// time of the unit. A unit a restore placed after it (a restore's
	// receipt, not a kept one) is left in place when its folder is
	// unlocked or no longer protected, because the session the request
	// names ended before that restore (U6-3, D133); in a locked folder it
	// is sealed, as a sweep would.
	queuedAt time.Time
	// lockedOnly is set on a sweep's own jobs (its units and notes): they
	// are sealed only while their folders are locked and still protected,
	// checked again under the unit lock (R4, folders.go).
	lockedOnly bool
	// queued is set on the jobs of queued requests: nothing is sealed for
	// them in a folder no longer protected (folders.go).
	queued bool
}

// detailRestoredSince is the result of a queued seal whose unit a later
// restore placed in a folder that is open now (D133): the request is
// done, the plaintext stays.
const detailRestoredSince = "restored after the request: left in place"

// restoredSince reports whether a queued job's unit was restored after the
// request it serves (D133): its receipt is a restore's (not kept by a
// seal) and newer than the request.
func restoredSince(o Options, rd receiptDisk, hasRc bool) bool {
	return !o.queuedAt.IsZero() && hasRc && !rd.Kept && rd.RestoredAt.After(o.queuedAt)
}

// Outcome of one unit.
type Outcome string

// Outcomes.
const (
	OutSealed       Outcome = "sealed"
	OutUnchanged    Outcome = "unchanged" // plaintext equal to the receipt: deleted, no new generation (D10)
	OutLive         Outcome = "live"
	OutWarm         Outcome = "warm"
	OutLeased       Outcome = "leased"
	OutRestored     Outcome = "restored"
	OutMerged       Outcome = "merged"        // JSONL linked fragment merged (D11)
	OutConflict     Outcome = "conflict"      // kept both versions
	OutSkipped      Outcome = "skipped"       // budget, free space, not in scope
	OutInaccessible Outcome = "inaccessible"  // EACCES/EPERM/TCC: never treated as missing
	OutRemoveFailed Outcome = "remove-failed" // committed, but plaintext could not be unlinked
	OutQuarantined  Outcome = "quarantined"
	OutPruned       Outcome = "pruned"    // Prune deleted (or, with DryRun, would delete) Files capsules of the unit
	OutForgotten    Outcome = "forgotten" // Forget deleted Files capsules of the unit
	OutFailed       Outcome = "failed"
)

// UnitResult is the result for one unit (content-free).
type UnitResult struct {
	Harness  string
	Kind     capsule.Kind
	Unit     string // unit key
	Outcome  Outcome
	Gen      uint64
	Lineage  capsule.Lineage
	Files    int   // seal/restore: plaintext files; prune/forget: capsules deleted
	Bytes    int64 // seal/restore: plaintext bytes; prune/forget: capsule bytes deleted
	Evidence []live.Evidence
	Hazards  []harness.Hazard
	Class    fsx.Class // error class for failures
	Detail   string
}

// Report aggregates a run.
type Report struct {
	Started  time.Time
	Finished time.Time
	Units    []UnitResult
}

// RestoreRequest selects what to restore.
type RestoreRequest struct {
	Units  []harness.UnitRef
	Select []harness.Selector // resolved against the capsule log (and manifests when needed)
	// BeforePlace is called with a unit key before any of its plaintext is
	// placed (the wrapper adds it to its launch lease, SPEC §9.3).
	BeforePlace func(unit string) error
	Budget      int64 // bytes; 0 = policy.restore_max_bytes
	MtimeNow    bool  // Units only: explicit resume of a session older than cleanupPeriodDays−2 (D14); a selector's units follow its own MtimeNow (D102)
	Purpose     string
	StopOnErr   bool
	// Abort is closed by the caller on any lock event (R6, D58): file keys
	// are destroyed at once; a unit not yet staged is rolled back (staging
	// removed, nothing placed); a unit already staged or placing is rolled
	// forward from staging (no key needed) so it is never left half placed;
	// then the restore stops.
	Abort <-chan struct{}
}

// CodexPrefer selects the side kept in place by ReconcileCodex.
type CodexPrefer string

// Reconcile preferences.
const (
	PreferCapsule   CodexPrefer = "capsule"
	PreferPlaintext CodexPrefer = "plaintext"
)

// PruneOptions selects generations to delete (D15: manual only).
type PruneOptions struct {
	Unit      string // unit key; "" = all units
	KeepLast  int    // default 3 (D9)
	Diverged  bool   // also prune diverged generations (requires explicit flag)
	OlderThan time.Duration
	DryRun    bool
}

// Generation is one logged generation of a unit.
type Generation struct {
	Gen      uint64
	Parent   uint64
	Lineage  capsule.Lineage
	Path     string
	Size     int64
	SealedAt time.Time
}

// ReceiptFile is one restored file (D10).
type ReceiptFile struct {
	Base    capsule.BaseID `json:"base"`
	Rel     string         `json:"rel"`
	Snap    fsx.Stat       `json:"snap"`
	SHA256  string         `json:"sha256"`
	Size    int64          `json:"size"`
	FromGen uint64         `json:"from_gen"`
	// Absent: a file of the generations behind this plaintext that is not
	// present as plaintext (a seal deleted it while other files stayed, or
	// a restore skipped it or could not place it). Generation FromGen holds
	// it; Snap is zero. A re-seal that still lacks it is partial, so the
	// generation stays in the restore chain (D85).
	Absent bool `json:"absent,omitempty"`
}

// Receipt is state/receipts/<unit>.json: the plaintext of a unit that
// precinto knows the origin of (D10, D58). Restore writes it (identity and
// SHA-256 of each placed file, Gen = the restored generation). After a seal
// commits, the sealer rewrites it to the new generation for every file
// still present as plaintext (remove-failed, changed after hashing, rescue
// sources), with identity and SHA-256 as sealed, and deletes it only when
// no listed file remains; a remove-failed unit therefore re-seals as
// "unchanged" without a new generation.
type Receipt struct {
	V          int           `json:"v"`
	Unit       string        `json:"unit"`
	Gen        uint64        `json:"gen"`
	RestoredAt time.Time     `json:"restored_at"`
	Files      []ReceiptFile `json:"files"`
	// Kept marks a receipt the seal of Gen rewrote for files it left as
	// plaintext (SPEC §10.3 step 8); a restore's receipt never has it.
	// Plaintext still equal to a kept receipt is "remove-failed"; equal to
	// a restore's, it waits for the next sweep of its locked folder (D110).
	Kept bool `json:"kept,omitempty"`
}

// UnitInfo is one sealed or plaintext unit for `precinto ls` and status.
type UnitInfo struct {
	Harness      string
	Kind         capsule.Kind
	Unit         string
	RootIDs      []string
	Gens         []Generation
	Plaintext    bool   // files currently on disk
	Reason       string // why plaintext remains: running|restored|deferred|history_pending|inaccessible|remove-failed|conflict|hold-capped (live only by weak evidence in a locked folder, SPEC §9.5)|adopted (found only by its transcripts' cwd: sweeps leave it to seal --adopt, D113)|disk_full (sealing it now would go below policy.min_free, D111)
	Bytes        int64
	LastActivity time.Time
	Title        string // only when keys were supplied and the caller is authorized
	Conflicts    int
	Quarantined  bool
}

// ListOptions filters List.
type ListOptions struct {
	RootIDs   []string
	Conflicts bool
	Keys      KeySource // optional: decrypt manifests for titles (fresh presence rules apply, D28)
}

// Plaintext summarizes unencrypted files on disk per root and reason, for
// `precinto status` and `status --check` (UX22).
type Plaintext struct {
	RootID   string
	Files    int
	Bytes    int64
	ByReason map[string]int
}
