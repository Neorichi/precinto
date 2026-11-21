package sweep

import (
	"context"
	"errors"
	"io"
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
// cmd/precinto; tests: a vaulttest identity).
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
	Floor    fsx.Floor
	Sealer   string // "precinto <version>"
	// Parallel bounds concurrent unit seals (default 2; units > 1 GiB run alone, R19).
	Parallel int
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
	Files    int
	Bytes    int64
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

// Count returns the number of units with outcome o.
func (r *Report) Count(o Outcome) int { panic("unimplemented: sweep.Report.Count") }

// Err summarizes failures as one error (nil if none).
func (r *Report) Err() error { panic("unimplemented: sweep.Report.Err") }

// Sweep is `precinto sweep`: take state/locks/sweep.lock (TryLock; if busy,
// touch sweep.requested and return ErrBusy unless o.Wait), Recover, drain
// the queue, scan every adapter's homes, seal every non-live,
// non-leased unit whose roots are locked (units restored under a current
// grant are left alone, R4), rotate global stores, apply the Markdown
// policy, then rescan once if sweep.requested was touched meanwhile.
func Sweep(ctx context.Context, e Env, o Options) (*Report, error) {
	panic("unimplemented: sweep.Sweep")
}

// Seal seals the given units now (seal command, wrapper exit, queue
// worker), honouring liveness and leases; it never needs a key.
func Seal(ctx context.Context, e Env, units []harness.Unit, o Options) (*Report, error) {
	panic("unimplemented: sweep.Seal")
}

// DrainQueue processes state/queue requests whose wait conditions hold.
func DrainQueue(ctx context.Context, e Env, o Options) (*Report, error) {
	panic("unimplemented: sweep.DrainQueue")
}

// Recover finishes or rolls back every pending journal record without any
// key (SPEC §10.5). Each phase is the last completed milestone: prepared or
// tmp_written → remove the temporary; if the capsule named by
// Record.Capsule exists and is logged continue as committed, if it exists
// unlogged (a crash between rename and log append) remove it; keep
// plaintext;
// committed/unlinking → require the capsule to exist and be logged, then
// resume identity-checked unlinks (otherwise treat as tmp_written);
// staged/placing → roll forward; held/sealed/rewritten → finish the
// history protocol from the hold link and the journaled offsets. It runs
// before any Quarantine, so precinto's own crash leftovers are never
// reported as forgeries.
func Recover(ctx context.Context, e Env) (*Report, error) { panic("unimplemented: sweep.Recover") }

// RestoreRequest selects what to restore.
type RestoreRequest struct {
	Units  []harness.UnitRef
	Select []harness.Selector // resolved against the capsule log (and manifests when needed)
	// BeforePlace is called with a unit key before any of its plaintext is
	// placed (the wrapper adds it to its launch lease, SPEC §9.3).
	BeforePlace func(unit string) error
	Budget      int64 // bytes; 0 = policy.restore_max_bytes
	MtimeNow    bool  // explicit resume of a session older than cleanupPeriodDays−2 (D14)
	Purpose     string
	StopOnErr   bool
	// Abort is closed by the caller on any lock event (R6, D58): file keys
	// are destroyed at once; a unit not yet staged is rolled back (staging
	// removed, nothing placed); a unit already staged or placing is rolled
	// forward from staging (no key needed) so it is never left half placed;
	// then the restore stops.
	Abort <-chan struct{}
}

// Restore restores units unit-atomically through staging (SPEC §11.5): for
// each unit, provenance check against the capsule log (D8), file keys from
// keys (D39), free-space check, Extract with adapter target rules, placement
// table (D11), receipts (D10). Newest-first within Budget.
func Restore(ctx context.Context, e Env, keys KeySource, r RestoreRequest) (*Report, error) {
	panic("unimplemented: sweep.Restore")
}

// RotateHistory extracts protected-root lines of Claude's history.jsonl
// into per-root history generations with the hold-link protocol (D21, D36,
// SPEC §7.1.4). Only when no Claude process is running anywhere.
func RotateHistory(ctx context.Context, e Env) (*Report, error) {
	panic("unimplemented: sweep.RotateHistory")
}

// MergeHistory appends a root's sealed history lines that are not already
// present byte-for-byte (idempotent), restoring referenced paste-cache
// entries (SPEC §7.1.4).
func MergeHistory(ctx context.Context, e Env, keys KeySource, rootID string) (*Report, error) {
	panic("unimplemented: sweep.MergeHistory")
}

// SealMarkdown applies a root's Markdown policy (SPEC §8): candidates from
// the ledger, transcripts and (md=all) a scan; excludes; git-tracked check
// via a hardened git invocation; no seal while a session that wrote the note
// is live or busy (D17); store capsule + in-tree marker (D16).
func SealMarkdown(ctx context.Context, e Env, root config.Root, o Options) (*Report, error) {
	panic("unimplemented: sweep.SealMarkdown")
}

// RestoreMarkdown restores a root's sealed notes at unlock: marker location
// minus suffix when a valid marker exists, else the authenticated original
// relpath (D16; SPEC §8.5).
func RestoreMarkdown(ctx context.Context, e Env, keys KeySource, root config.Root) (*Report, error) {
	panic("unimplemented: sweep.RestoreMarkdown")
}

// CodexPrefer selects the side kept in place by ReconcileCodex.
type CodexPrefer string

// Reconcile preferences.
const (
	PreferCapsule   CodexPrefer = "capsule"
	PreferPlaintext CodexPrefer = "plaintext"
)

// ReconcileCodex resolves a per-root Codex home whose plaintext diverged
// from its newest snapshot (R12): the other side is kept as a retained
// generation; nothing is deleted.
func ReconcileCodex(ctx context.Context, e Env, keys KeySource, rootID string, prefer CodexPrefer) (*Report, error) {
	panic("unimplemented: sweep.ReconcileCodex")
}

// Resolve keeps one side of a Markdown or file conflict (`precinto
// resolve`), sealing the other as a retained generation.
func Resolve(ctx context.Context, e Env, keys KeySource, path string, keep string) (*Report, error) {
	panic("unimplemented: sweep.Resolve")
}

// PruneOptions selects generations to delete (D15: manual only).
type PruneOptions struct {
	Unit      string // unit key; "" = all units
	KeepLast  int    // default 3 (D9)
	Diverged  bool   // also prune diverged generations (requires explicit flag)
	OlderThan time.Duration
	DryRun    bool
}

// Prune deletes generations fully subsumed by a successor chain, keeping
// KeepLast and every generation needed by a layered restore (D9, D42). The
// CLI calls it only after typed confirmation on a TTY (except DryRun) and
// never from an agent context (D59).
func Prune(ctx context.Context, e Env, o PruneOptions) (*Report, error) {
	panic("unimplemented: sweep.Prune")
}

// Forget deletes every generation of a unit after typed confirmation on a
// TTY by the caller (`precinto forget`; refused from agent contexts, D59),
// logging deletion records (I12).
func Forget(ctx context.Context, e Env, unit string) (*Report, error) {
	panic("unimplemented: sweep.Forget")
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

// Generations returns the logged generations of a unit, oldest first.
func Generations(e Env, unit string) ([]Generation, error) { panic("unimplemented: sweep.Generations") }

// NextGen reserves the next generation number of a unit: a counter in
// state/gens/<unit> persisted with FullSync before use, never a timestamp
// (D9, R16). Numbers are never reused; a crash can leave gaps (a reserved
// generation whose capsule recovery removed), and nothing may assume
// consecutive numbers (lineage uses logged Parent links, D58).
func NextGen(e Env, unit string) (uint64, error) { panic("unimplemented: sweep.NextGen") }

// ReceiptFile is one restored file (D10).
type ReceiptFile struct {
	Base    capsule.BaseID `json:"base"`
	Rel     string         `json:"rel"`
	Snap    fsx.Stat       `json:"snap"`
	SHA256  string         `json:"sha256"`
	Size    int64          `json:"size"`
	FromGen uint64         `json:"from_gen"`
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
}

// LoadReceipt reads the receipt of a unit (ok=false if none).
func LoadReceipt(e Env, unit string) (Receipt, bool, error) {
	panic("unimplemented: sweep.LoadReceipt")
}

// UnitInfo is one sealed or plaintext unit for `precinto ls` and status.
type UnitInfo struct {
	Harness      string
	Kind         capsule.Kind
	Unit         string
	RootIDs      []string
	Gens         []Generation
	Plaintext    bool   // files currently on disk
	Reason       string // why plaintext remains: running|restored|deferred|history_pending|inaccessible|remove-failed|conflict
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

// List returns units from the capsule log and the on-disk scan.
func List(ctx context.Context, e Env, o ListOptions) ([]UnitInfo, error) {
	panic("unimplemented: sweep.List")
}

// Plaintext summarizes unencrypted files on disk per root and reason, for
// `precinto status` and `status --check` (UX22).
type Plaintext struct {
	RootID   string
	Files    int
	Bytes    int64
	ByReason map[string]int
}

// PlaintextSummary scans without sealing.
func PlaintextSummary(ctx context.Context, e Env) ([]Plaintext, error) {
	panic("unimplemented: sweep.PlaintextSummary")
}

// Quarantine moves capsules that are not in the provenance log to
// <base>/quarantine and reports them (S3, D8). It runs only after Recover
// has processed every journal record and never touches a capsule named by
// a pending journal record.
func Quarantine(ctx context.Context, e Env) (*Report, error) {
	panic("unimplemented: sweep.Quarantine")
}

// MarkerText returns the exact bytes of the in-tree marker of a sealed note
// (SPEC §8.4): two lines, the second naming the unit key. ui.MsgNoteMarker
// mirrors it (plus this final newline); a cmd/precinto test asserts both
// are identical. Implemented in the scaffold.
func MarkerText(unitKey string) []byte {
	return []byte("This note is sealed by precinto. Run `precinto unlock` in this folder to open it.\nid: " + unitKey + "\n")
}

// ParseMarker reads a *.md.precinto marker (at most 4 KiB, opened
// O_NOFOLLOW, regular file) and returns the unit key it names, or
// ErrNotMarker. Callers still require the unit to be logged (§11.1).
func ParseMarker(path string) (unitKey string, err error) {
	panic("unimplemented: sweep.ParseMarker")
}

// CatNote decrypts the newest generation of the logged note a marker names
// and writes its bytes to w (`precinto cat`; the CLI sanitizes for a TTY,
// S17). Keys come from keys with purpose "cat" (fresh presence from agent
// contexts, D28).
func CatNote(ctx context.Context, e Env, keys KeySource, marker string, w io.Writer) error {
	panic("unimplemented: sweep.CatNote")
}

// OpenNotes restores the notes named by markers in place (`precinto
// open`): RestoreMarkdown restricted to those units, purpose "open".
func OpenNotes(ctx context.Context, e Env, keys KeySource, markers []string) (*Report, error) {
	panic("unimplemented: sweep.OpenNotes")
}
