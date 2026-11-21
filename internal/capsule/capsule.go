package capsule

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"filippo.io/age"

	"github.com/precinto/precinto/internal/fsx"
)

// Format constants (SPEC §5).
const (
	Magic            = "PRECINTO-CAPSULE-1\n"
	FormatVersion    = 1
	ManifestName     = "MANIFEST.json"
	MaxManifestBytes = 16 << 20 // reject larger manifests
	MaxEntries       = 1 << 20  // reject more tar members
	MaxZstdWindow    = 64 << 20 // zstd.WithDecoderMaxWindow
	MaxZstdMemory    = 1 << 30  // zstd.WithDecoderMaxMemory
	FileExt          = ".pcap"
	// HeaderStanzas is the exact number of X25519 stanzas every capsule
	// header carries: vault, recovery, ephemeral verify (D2, D5).
	HeaderStanzas = 3
)

// Errors.
var (
	// ErrChanged: a source changed between the hash pass and the copy pass
	// (D13). Callers treat the unit as live (exit 4) and keep plaintext.
	ErrChanged = errors.New("capsule: source changed while sealing")
	// ErrVerify: the ephemeral round trip did not reproduce the manifest and
	// every hash exactly (exit 5, plaintext kept).
	ErrVerify = errors.New("capsule: verification failed")
	// ErrHeader: the written header does not carry exactly HeaderStanzas
	// X25519 stanzas (D5; exit 5, plaintext kept).
	ErrHeader = errors.New("capsule: unexpected header stanzas")
	// ErrRecipients: the recipient set handed to Seal is not exactly
	// {vault, recovery} of the X25519 family (D2, D5).
	ErrRecipients = errors.New("capsule: bad recipient set")
	// ErrFormat: magic, tar layout, member order, type flags, sizes or
	// limits violated while reading (bombs, PAX overrides, links, sparse).
	ErrFormat = errors.New("capsule: malformed capsule")
	// ErrUnsafe: an entry's base or relative path is not allowed or not
	// local/clean.
	ErrUnsafe = errors.New("capsule: unsafe entry")
	// ErrTooLarge: an entry or the total exceeds the manifest or the budget.
	ErrTooLarge = errors.New("capsule: capsule too large")
)

// Kind identifies the unit type a capsule holds (SPEC §7, §8).
type Kind string

// Kinds.
const (
	KindClaudeSession Kind = "claude-session" // one Claude session (sid-prefixed files, fail-closed)
	KindClaudeProject Kind = "claude-project" // auto memory, legacy sessions-index.json, MCP logs
	KindClaudePlan    Kind = "claude-plan"    // plans/<slug>*.md (D46)
	KindClaudeHistory Kind = "claude-history" // history.jsonl lines + paste-cache of one root (D36)
	KindGlobalStore   Kind = "global-store"   // unattributable global stores, global vault (D1, D36)
	KindCodexHome     Kind = "codex-home"     // per-root CODEX_HOME snapshot manifest (D31, D42)
	KindCodexBlob     Kind = "codex-blob"     // one file or one SQLite group referenced by a snapshot
	KindMarkdown      Kind = "md"             // one agent-written note (D16)
	KindGeneric       Kind = "generic"        // experimental inventories (D33)
)

// BaseID names the trusted directory an entry is relative to. The restoring
// client resolves BaseIDs from registered homes and config, never from the
// manifest (D8).
type BaseID string

// Bases.
const (
	BaseClaudeConfig BaseID = "claude_config" // $CLAUDE_CONFIG_DIR or ~/.claude
	BaseClaudeTmp    BaseID = "claude_tmp"    // CLAUDE_CODE_TMPDIR or /private/tmp/claude-<uid>
	BaseClaudeCache  BaseID = "claude_cache"  // ~/Library/Caches/claude-cli-nodejs
	BaseCodexHome    BaseID = "codex_home"    // <base>/homes/codex/<root-id>
	BaseRoot         BaseID = "root"          // the protected root (Markdown)
	BaseGeneric      BaseID = "generic"       // prefix: experimental inventories use "generic:<base-name>" (D33)
)

// Lineage of a generation relative to its parent (D9, D10, D42).
type Lineage string

// Lineages.
const (
	LineageFresh     Lineage = "fresh"     // no restore receipt: first seal, or plaintext that appeared without a restore
	LineageSuccessor Lineage = "successor" // every parent file present, each unchanged or append-only grown
	LineagePartial   Lineage = "partial"   // some parent files missing; present ones unchanged or appended
	LineageDiverged  Lineage = "diverged"  // a parent file changed in a non-append way
)

// Entry is one manifest file record. JSON keys are snake_case.
type Entry struct {
	Name    string `json:"name,omitempty"` // tar member "f/000001" (consecutive, manifest order); "" for Dir or Blob entries
	Base    BaseID `json:"base"`
	Rel     string `json:"rel"`            // filepath.IsLocal and Clean
	Path    string `json:"path,omitempty"` // absolute path at seal time: audit only, never used for writing
	Dir     bool   `json:"dir,omitempty"`  // empty directory record (no tar member)
	Mode    uint32 `json:"mode"`           // original permission bits; restored as Mode & 0o700
	MtimeNS int64  `json:"mtime_ns"`
	Size    int64  `json:"size"`
	SHA256  string `json:"sha256,omitempty"`
	Blob    string `json:"blob,omitempty"`   // codex-home: blob capsule unit key holding this file
	Group   string `json:"group,omitempty"`  // SQLite group id: db + -wal + -journal sealed/restored together
	Append  bool   `json:"append,omitempty"` // adapter marked the file append-only (JSONL lineage)
}

// Manifest is MANIFEST.json, the first tar member (SPEC §5).
type Manifest struct {
	Format         int       `json:"format"`
	Kind           Kind      `json:"kind"`
	Harness        string    `json:"harness"`
	HarnessVersion string    `json:"harness_version,omitempty"`
	UnitKey        string    `json:"unit_key"` // store directory name (D45)
	UnitID         string    `json:"unit_id"`  // sid, slug, relpath…: inside ciphertext only
	VaultID        string    `json:"vault_id"` // vault whose recipient sealed it (D1)
	RootIDs        []string  `json:"root_ids"` // every managed root; key release needs all of them unlocked
	RootPath       string    `json:"root_path,omitempty"`
	ProjectDir     string    `json:"project_dir,omitempty"`
	Gen            uint64    `json:"gen"`
	Parent         uint64    `json:"parent"`
	Lineage        Lineage   `json:"lineage"`
	CreatedAt      time.Time `json:"created_at"`
	Sealer         string    `json:"sealer"`         // "precinto 0.1.0"
	RecipientsFpr  string    `json:"recipients_fpr"` // D5
	Title          string    `json:"title,omitempty"`
	LastActivity   time.Time `json:"last_activity,omitempty"`
	Ledger         []byte    `json:"ledger,omitempty"` // the unit's ledger lines, moved into the capsule (S13)
	Files          []Entry   `json:"files"`
}

// Input is one regular file to capture. Snap is the identity observed by the
// planner; Seal re-verifies it in both passes.
type Input struct {
	Base   BaseID
	Dir    *fsx.Dir // handle of the resolved base
	Rel    string
	Path   string // absolute, for the audit-only Entry.Path
	Snap   fsx.Stat
	Append bool
	Group  string
	// Open, if set, is read instead of opening Dir/Rel: rescue of bytes
	// appended to an already-unlinked inode (SPEC §10.3 step 7). Snap must
	// be its current fstat.
	Open *os.File
}

// Phase is a sealing milestone reported to the caller's callback.
type Phase string

// Phases, in order. OnPhase is called right after each milestone has
// completed (never before). Returning an error before PhaseCommitted aborts
// and removes the temporary; an error at PhaseCommitted leaves the renamed
// file for the caller's journal recovery (which removes an unlogged
// capsule, D58). capsule itself evaluates only "capsule.*" failpoints; the
// caller's journal phases ("seal.*") are evaluated by the caller
// (docs/TESTPLAN.md §4 failpoint registry).
const (
	PhaseHashed     Phase = "hashed"      // pass 1 done; manifest built
	PhaseTmpWritten Phase = "tmp_written" // pass 2 streamed and FullSynced
	PhaseVerified   Phase = "verified"    // ephemeral round trip + header check passed
	PhaseCommitted  Phase = "committed"   // no-replace rename + dir fsync done (not yet logged: the caller logs)
)

// SealRequest describes one capsule to write.
type SealRequest struct {
	Manifest   Manifest        // Files is filled by Seal from Inputs and Dirs
	Inputs     []Input         // regular files, in tar order
	Dirs       []Entry         // empty directories to record
	Recipients []age.Recipient // exactly {vault, recovery} X25519; Seal adds an ephemeral one
	Out        *fsx.Dir        // capsule unit directory
	Name       string          // final file name, e.g. "g000007.pcap"; committed with NoReplace
	OnPhase    func(Phase, *Sealed) error
}

// Sealed is a committed, verified capsule whose plaintext still exists.
type Sealed struct {
	Name         string
	Path         string
	SHA256       string // of the whole ciphertext file
	HeaderSHA256 string // of the age header (provenance key, D8/D39)
	Size         int64
	Manifest     Manifest
	Snaps        []fsx.Stat // per Input, as hashed in pass 1
}

// Seal performs SPEC §10.3 step 4 only: pass 1 (open O_NOFOLLOW, fstat ==
// Snap, sha256) builds the manifest; pass 2 streams magic+zstd(tar) into an
// age writer on a temporary in Out, re-hashing each file and requiring
// identical identity and bytes (ErrChanged otherwise); FullSync; decrypt
// the temporary with the in-memory ephemeral identity and compare manifest
// and hashes (ErrVerify); CheckHeader (ErrHeader); rename NoReplace to
// Name; fsync Out. Journaling, the capsule-log append, receipts and
// deletion of plaintext are the caller's (internal/sweep) steps. The
// ephemeral identity is never serialized. Seal never deletes plaintext.
func Seal(ctx context.Context, r SealRequest) (*Sealed, error) { panic("unimplemented: capsule.Seal") }

// CheckHeader parses the age header of r and requires exactly want X25519
// stanzas and no other stanza types.
func CheckHeader(r io.Reader, want int) error { panic("unimplemented: capsule.CheckHeader") }

// ReadHeader returns the detached age header of the capsule file name in dir
// (age.ExtractHeader), opening it with O_NOFOLLOW, plus its SHA-256.
func ReadHeader(dir *fsx.Dir, name string) (header []byte, headerSHA256 string, err error) {
	panic("unimplemented: capsule.ReadHeader")
}

// HashFile returns the SHA-256 and size of a capsule file.
func HashFile(dir *fsx.Dir, name string) (sha256 string, size int64, err error) {
	panic("unimplemented: capsule.HashFile")
}

// OpenManifest decrypts only up to the first tar member using fileKey
// (age.NewInjectedFileKeyIdentity) and returns the manifest.
func OpenManifest(r io.Reader, fileKey []byte) (Manifest, error) {
	panic("unimplemented: capsule.OpenManifest")
}

// Limits bounds extraction (SPEC §5 rule 3, §11.5).
type Limits struct {
	MaxTotal int64 // reject if the manifest sum exceeds it (free space − floor)
	MaxFiles int   // default MaxEntries
}

// Staged is one file written into staging by Extract.
type Staged struct {
	Entry     Entry
	StagedRel string   // name inside the staging directory
	Stat      fsx.Stat // of the staged file
}

// ExtractOptions configures Extract.
type ExtractOptions struct {
	FileKey []byte
	Staging *fsx.Staging
	Limits  Limits
	// Check validates every entry (allowed base and rel for this kind and
	// unit, computed from trusted context, D8) before anything is written.
	Check func(Entry) error
}

// Extract decrypts the capsule r and writes every regular entry into
// staging with mode 0600 (Entry.Mode & 0o700 applied at placement), after
// validating the whole manifest with Check. It accepts only TypeReg members
// named MANIFEST.json then f/000001… in order with sizes equal to the
// manifest, rejects PAX path overrides, links, sparse entries, trailing
// members, oversize manifests and totals above Limits, verifies every
// SHA-256, and fsyncs staging. All-or-nothing: on error staging is left for
// the caller to remove.
func Extract(ctx context.Context, r io.Reader, o ExtractOptions) (Manifest, []Staged, error) {
	panic("unimplemented: capsule.Extract")
}

// GenName returns the capsule file name of generation n ("g%06d.pcap";
// numbers above 999999 use more digits).
func GenName(n uint64) string { return fmt.Sprintf("g%06d%s", n, FileExt) }

// ParseGenName parses a generation file name; it accepts only names that
// GenName produces (no sign, no extra leading zeros beyond six digits,
// generation ≥ 1).
func ParseGenName(name string) (uint64, bool) {
	digits, ok := strings.CutPrefix(name, "g")
	if !ok {
		return 0, false
	}
	digits, ok = strings.CutSuffix(digits, FileExt)
	if !ok || len(digits) < 6 {
		return 0, false
	}
	for _, c := range digits {
		if c < '0' || c > '9' {
			return 0, false
		}
	}
	n, err := strconv.ParseUint(digits, 10, 64)
	if err != nil || n == 0 || GenName(n) != name {
		return 0, false
	}
	return n, true
}

// UnitKey derives a unit key: lowercase hex of the first 16 bytes of
// HMAC-SHA256(salt, join(parts, 0x1f)). Parts per kind are fixed by SPEC
// §6.2 (D45); use harness.UnitKeyFor rather than building parts by hand.
// Implemented in the scaffold (test vectors in docs/TESTPLAN.md §8, D45).
func UnitKey(salt []byte, parts ...string) string {
	m := hmac.New(sha256.New, salt)
	m.Write([]byte(strings.Join(parts, "\x1f")))
	return hex.EncodeToString(m.Sum(nil)[:16])
}

// LoadSalt reads <state>/name.salt, creating 32 random bytes (0600) if
// missing.
func LoadSalt(path string) ([]byte, error) { panic("unimplemented: capsule.LoadSalt") }

// RecipientsFingerprint is SHA-256 over the canonical recipient set
// (sorted recipient strings joined by '\n', prefixed by the family) (D5).
func RecipientsFingerprint(family string, recipients []string) string {
	panic("unimplemented: capsule.RecipientsFingerprint")
}
