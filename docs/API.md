# precinto — Go API contract (v0.2)

This is the frozen exported API that eight groups implement in parallel. The second half of this file is **generated** from the scaffold (`go run ./internal/archtest/apidoc -splice docs/API.md`; `make api-check` fails on drift), so the code and this document cannot disagree. Semantics are normative together with `docs/SPEC.md`; wire formats with `docs/HOOKS-IO.md`; tests with `docs/TESTPLAN.md`; file ownership with `docs/OWNERSHIP.md`.

Module `github.com/precinto/precinto` · `go 1.26.0` (the go command rejects a bare `go 1.26` as untidy) · `toolchain go1.26.11` · `CGO_ENABLED=0` must build · dependencies are pinned in `go.mod`/`go.sum` (owned by G7; implementers never add dependencies) · darwin first, linux builds (D34).

## 1. Rules of the contract
1. **Exported identifiers are frozen.** Implementers fill function bodies (currently `panic("unimplemented: <pkg>.<Func>")`; the leaf helpers listed in docs/OWNERSHIP.md §4 are already implemented, with tests), may add unexported code and new files in their own directories, and may change unexported fields of their own types. They MUST NOT change exported signatures, exported struct fields, constants or another group's files. If a change is needed, implement an adapter in your own package and report the request to the lead (docs/OWNERSHIP.md §3).
2. **Imports** follow the allowlist in `internal/archtest/allowlist.go` (rendered per package below). Lower layers never import higher ones; test-only helper packages are never imported by production code; only `internal/paths` reads the process environment. `go test ./internal/archtest` enforces all three.
3. **Errors** are sentinel values checked with `errors.Is`, or `*ipc.Error` with a `Code`. `cmd/precinto` maps them to exit codes (§5). Error strings never contain plaintext content; user-facing text comes from `internal/ui`.
4. **Secrets** (identities, passphrases, PINs, file keys, recovery keys) are `*memguard.LockedBuffer` or `*memguard.Enclave` — never `string`, never JSON.
5. **No content in metadata**: ledgers, journals, receipts, queue entries, the capsule log, logs and errors hold paths, ids and stats only (I7).
6. **Context**: every blocking operation takes a `context.Context` and returns promptly when it ends (locks cancel restores, R8).

## 2. Groups
| Group | Directories (disjoint) | Packages |
|---|---|---|
| **G1 crypto core** | `internal/fsx/`, `internal/capsule/`, `internal/vault/` | `fsx`, `fsx/failpoint`, `capsule`, `vault`, `vault/vaulttest` |
| **G2 daemon** | `internal/agent/`, `internal/ipc/`, `internal/platform/` | `agent`, `agent/agenttest`, `ipc`, `platform` (darwin/linux files), `platform/fakeplatform` |
| **G3 harness adapters** | `internal/harness/`, `internal/ledger/`, `internal/live/`, `inventories/` | `harness`, `harness/claude`, `harness/claude/claudetest`, `harness/codex`, `harness/codex/codextest`, `harness/generic`, `ledger`, `live`, `inventories` (embedded `*.toml`) |
| **G4 orchestration** | `internal/sweep/` | `sweep`, `sweep/journal`, `sweep/capslog`, `sweep/queue` |
| **G5 hooks & packaging** | `internal/hook/`, `internal/shellinit/`, `plugin/`, `plugins/codex/`, `.claude-plugin/`, `.agents/plugins/` | `hook`, `shellinit`; plugin manifests, hooks files, POSIX shim, commands, skill |
| **G6 wrapper** | `internal/wrapper/` | `wrapper` |
| **G7 CLI** | `cmd/precinto/`, `internal/config/`, `internal/paths/`, `internal/doctor/`, `internal/ui/`, `internal/testkit/`, `internal/archtest/` (contract: lead only), `Makefile`, `go.mod`, `go.sum`, `test/integration/`, `test/e2e/flows/` | `cmd/precinto`, `config`, `paths`, `doctor`, `ui`, `testkit`, `archtest`, `archtest/apidoc` |
| **G8 docs** | `README.md`, `README.es.md`, `docs/THREAT_MODEL.md`, `docs/HARNESSES.md`, `docs/COMPACTION.md`, `SECURITY.md`, `CONTRIBUTING.md`, `TRADEMARKS.md` | – |

## 3. Layers (import direction: down only)
```
10  cmd/precinto, archtest/apidoc
 9  doctor
 8  hook, shellinit, wrapper, agenttest
 7  sweep, agent, claudetest, codextest
 6  harness/claude, harness/codex, harness/generic
 5  harness
 4  live
 3  ledger, ipc, vaulttest, testkit
 2  config, capsule, vault, ui, sweep/journal, sweep/queue, fakeplatform
 1  paths, platform, sweep/capslog, fsx/fsxtest (test-only)
 0  fsx, fsx/failpoint, inventories, archtest
```
`internal/agent` never imports `internal/sweep` (it spawns `precinto sweep|seal|restore` workers) and may import `inventories` (embedded data: `harness.LoadInventories(inventories.FS)` once at start for `register` and the D52 scan); `internal/sweep` never imports `internal/ipc`; `internal/wrapper` never imports `internal/sweep`, `internal/vault` or `internal/agent`.

## 4. Cross-group seams (who implements what)
| Interface (owner) | Implemented by | Purpose |
|---|---|---|
| `harness.Adapter` (G3) | `harness/claude`, `harness/codex`, `harness/generic` (G3) | inventory, liveness evidence, targets (authenticated unit ids only, SPEC §11.2), launch plans |
| `platform.ProcTable`, `platform.Clock` (G2) | `platform.System()`, `platform.SystemClock()`; `*fakeplatform.Procs`, `*fakeplatform.Clock` (asserted in `fakeplatform`) | process identity, cwd, open-file holders and time everywhere |
| `vault.UI` (G1) | the daemon (G2) bridging `ipc.UIHandler` of the requesting client; `vaulttest.UI` | relayed presence prompts (D4) |
| `ipc.UIHandler` (G2) | `*ui.TTY` directly (G7; `Display`, `Secret`, `Confirm`), wrapper (G6), headless hook handler (G5) | client side of relayed prompts |
| `sweep.FileKeys` (G4) | `*ipc.KeySet` directly (G2; `Key`, `Destroy`) | released per-capsule file keys |
| `sweep.KeySource`, `sweep.Grants` (G4) | `cmd/precinto` adapters over `ipc.Client.Keys`/`Status` (G7); `vaulttest` identity in tests | file keys without importing ipc (D39) |
| `hook.Daemon`, `hook.Ledger` (G5) | `*ipc.Client` (G2), `*ledger.Ledger` (G3); fakes in hook tests | gate/activity/register/unlock; ledger facts |
| `wrapper.Backend`, `wrapper.Daemon`, `wrapper.Lease` (G6) | `cmd/precinto` (G7) over `harness`, `sweep`, `live`, `ledger`, `ipc`; `*ipc.Client`; `*live.Held` | restore-before-launch orchestration via interfaces; G6 tests fake all three |
| `live.Engine` (G3) | used by `sweep` (G4) and `doctor` (G7) | liveness decisions |
| `sweep.Env.Sleep` (G4) | nil in production (real sleep); tests pass a function that advances the fake clock | the one D63 quiet-window wait per run |
| `agenttest.Agent.Client` (G2) | fake backends and other goroutines (non-fatal dial; `Dial` calls `t.Fatalf` and is for the test goroutine only) | background dials in tests |

Every "implemented directly" row is a compile-time assertion in `cmd/precinto/seams.go` (or `fakeplatform`), so a signature drift fails `go build`.

## 5. Errors → exit codes (`cmd/precinto`, SPEC §16.2)
| Error | Exit |
|---|---|
| nil | 0 |
| usage errors; `ipc.CodeBadRequest` | 2 |
| `sweep.ErrNotMarker` (cat/open of a non-marker) | 2 |
| `ipc.CodeLocked`, `CodeUnauthorized`, `CodeAgentContext`, `CodeCancelled`, `CodeNoUI`, `CodeRateLimited`, `CodeBadSecret`; `sweep.ErrKeyDenied`; `vault.ErrCancelled`, `vault.ErrBadSecret`, `vault.ErrNoUI`, `vault.ErrLocked`, `vault.ErrNeedRecovery`; `ui.ErrCancelled`; `platform.ErrRoot` | 3 |
| `sweep.ErrLive`, `capsule.ErrChanged`, `sweep.ErrConflict` (codex launch) | 4 |
| `capsule.ErrVerify`, `capsule.ErrHeader`, `capsule.ErrRecipients`, `capsule.ErrFormat`, `capsule.ErrUnsafe`, `capsule.ErrTooLarge`, `fsx.ErrUnsafe` from restore/extract, `harness.ErrUnitKey` from restore (unit id does not match its key), `vault.ErrMACMismatch`, `vault.ErrRecipientsChanged` (`sweep.ErrTripwire`), `vault.ErrWrongIdentity`, `vault.ErrPluginPin`, `capslog.ErrNotLogged` (`sweep.ErrNotLogged`: quarantined, no provenance), `ipc.CodeVerify`, `ipc.CodeNotLogged` | 5 |
| anything else (`ipc.ErrUntrustedServer`, `ipc.ErrNoDaemon`, `sweep.ErrInaccessible`, `sweep.ErrNoSpace`, `harness.ErrUnregistered` from restore: a capsule of a home config does not register is a configuration gap, never 5 (D109), I/O) | 1 |
| `sweep.ErrBusy` from `precinto sweep` | 0 (another sweep will rescan) |
| `wrapper.ExitNotStarted` from `wrapper.Run` (the launch never started) | map the returned error with this table (an executable that cannot run: 127, or 126 when it is not executable); once the child started, `run` returns the child's own code |
| `precinto doctor` | `doctor.Worst`: 1 when any finding fails, else 0 |
| hook mode | see `hook.ExitOK`/`ExitBlockCode2`/`ExitFailure` (D43) |

## 6. On-disk and wire formats and their owners
| Format | Owner package | Spec |
|---|---|---|
| capsule v1 (`*.pcap`), unit keys, `name.salt` | `capsule` (G1) | SPEC §5, §6.2 |
| `vault.toml`, `identity.<factor>.age`, `factors/se.identity`, `state/verified/*` | `vault` (G1) | §4 |
| lock files, staging dirs, atomic writes | `fsx` (G1) | §10.2, §11.4 |
| socket frames and protocol structs | `ipc` (G2) | §13 |
| `state/sessions/**.jsonl`, `state/projects/*.json` | `ledger` (G3) | §14.3 |
| `state/leases/*.lease` | `live` (G3) | §9.3 |
| `inventories/*.toml` (schema 1) | `harness` (G3) | §7.3 |
| `state/capsules.log` | `sweep/capslog` (G4) | §11.1 |
| `state/journal/*.json` | `sweep/journal` (G4) | §10.5 |
| `state/queue/*.json` | `sweep/queue` (G4) | §10.6 |
| `state/gens/*`, `state/receipts/*.json` (written by restore and rewritten after each seal commit), `*.md.precinto` markers (`sweep.MarkerText`) | `sweep` (G4) | §8.4, §10.3, §10.4, §11.5 |
| `config.toml`, `roots.list`, `state/policy.pinned` | `config` (G7; MACs computed by the daemon with `vault.Keyring.MAC`) | §6, §12.2, §12.8 (D55) |
| hooks files, shim | `plugin/`, `plugins/codex/` (G5) | HOOKS-IO |
| `status --json` v1 (attention codes `ipc.Attn*`, shared with `doctor.Check*`) | `cmd/precinto` (G7) with `ipc.StatusResp` and `sweep.PlaintextSummary` | §16.4 |

## 7. CLI wiring (G7)
| Subcommand | Wires |
|---|---|
| `init`, `factor` | `ui.AgentContext` refusal, `vault.Store.Init`, `ipc` `factor_add` (`PresencePolicy`/`NoPresenceAck` for plugin factors), `ui.TTY.ShowSecretScreen`, B.remote passphrase offer in tmux/SSH (D60), `service install` offer; `factor test NAME`: `ipc.Client.Unlock` with `UnlockReq.Test`; `factor repin NAME`: typed confirmation, `vault.Store.RepinPlugin` (D75) |
| `vault repair` | TTY + `ui.AgentContext` refusal, `ipc.Client.VaultRepair` (recovery key read with `ui.TTY.Secret` for `--recovery`), diff + `ui.MsgVaultRepairConfirm` typed confirmation (D53) |
| `protect`, `unprotect` | `config` (overlap check, new root id, `WriteRootsList`), `ipc` `vault_create`, `sweep.Sweep` scoped to the root, `.git/info/exclude`; `unprotect`: typed confirmation, refused in agent contexts (D59) |
| `status` | `ipc.Client.Status` + `sweep.PlaintextSummary` + `doctor` codes; `--json` v1; `--check` exit 3 |
| `unlock`, `lock` | `ipc.Client.Unlock`/`Lock` with a TTY `ipc.UIHandler`; typed confirmation for `--all` (D40) |
| `seal`, `sweep`, `restore`, `resume`, `ls`, `open`, `cat`, `resolve`, `forget`, `prune`, `codex` | `sweep` with `sweep.Env` built from `config`, `paths`, `ledger`, `live`, `harness` adapters, `vault.Store`, `capslog`, `journal`; KeySource/Grants over `ipc`; `cat`/`open` via `sweep.ParseMarker`, `CatNote`, `OpenNotes`; `forget`/`prune` (not `--dry-run`): typed confirmation (`ui.MsgConfirmTyped`), refused in agent contexts and without a controlling terminal (D59); `codex sync-config` via `codex.PrepareHome` with `ForceConfig` |
| `run` | `wrapper.Run` with a `wrapper.Backend` over `harness`, `sweep`, `live`, `ipc`; `wrapper.ExitNotStarted` maps the returned error with §5 |
| `hook` | `hook.Main` (fast path; no autostart) |
| `shell-init`, `shell-hook` | `shellinit.Script`, `shellinit.OnEnter`; `shell-hook` prints `shellinit.EnterResult.Lines()` and nothing else (D69) |
| `agent`, `service` | `agent.Run`; darwin LaunchAgent running `precinto sweep --quiet` (linux unit deferred, D49: exit 2 with a notice) |
| `integrate` | harness plugin CLIs (`claude plugin …`, `codex plugin …`), `<base>/bin/precinto` link |
| `doctor` | `doctor.Run`, printed with `doctor.Render` (`--json`), exit from `doctor.Worst` |
| `recover` | `vault.ParseRecoveryKey`, `vault.VerifyRecovery`; `--verify` records `vault.Store.MarkRecoveryVerified` |
| `canary`, `scrub`, `rekey`, `import` | deferred beyond v0.2 (D49): exit 2 with a notice |
| every build with `-tags failpoints` | `main` reads `paths.EnvCrashpoint` through `internal/paths` and calls `failpoint.Set` before dispatching (TESTPLAN §4) |

## 8. Generated package contract
Each package lists its owner, layer, allowed imports, test expectations and its exported API (doc comments are normative one-line-or-more semantics).

<!-- BEGIN GENERATED: go run ./internal/archtest/apidoc -splice docs/API.md -->

## G1 crypto core

### `internal/fsx/failpoint`

- Owner: **G1 crypto core** · layer 0 · production
- May import (module): none
- May import (third party): stdlib only
- Tests: unit: arming/disarming, nth-hit counting, errno specs, bad specs panic, crash point SIGKILLs a child process (failpoint_on_test.go); compiled out without -tags failpoints (failpoint_off_test.go)

> Package failpoint provides named fault-injection points for crash and
> errno-injection tests (docs/TESTPLAN.md "crash-injection").
>
> Production builds compile every point to a no-op. Builds with
> `-tags failpoints` are armed in-process with Set/Reset; binaries are armed
> by cmd/precinto, which reads PRECINTO_CRASHPOINT through internal/paths
> (paths.EnvCrashpoint; only paths reads the environment) and calls Set
> before dispatching. The spec syntax is:
>
> 	PRECINTO_CRASHPOINT=<name>[:<n>]            SIGKILL self at the n-th hit (default 1)
> 	PRECINTO_CRASHPOINT=<name>=errno:<E>[:<n>]  return syscall errno E at the n-th hit
>
> Point names are "<component>.<step>" and come from the registry in
> docs/TESTPLAN.md §4, which also says which package hits each name; a name
> is hit in exactly one place (capsule.Seal hits only "capsule.*", sweep
> only its own "seal.*"/"restore.*"/"history.*"/"codex.*" names), so the
> ":<n>" hit counts are meaningful. Every destructive step listed in SPEC
> §10/§11 has a point. Implemented in the scaffold.

```go
// Enabled reports whether this binary was built with -tags failpoints.
func Enabled() bool

// Hit evaluates the point name. It returns nil unless a fault is armed for
// name; an armed crash fault never returns (the process SIGKILLs itself), an
// armed errno fault returns that errno (as a syscall.Errno wrapped in
// *os.SyscallError-compatible form). Always a no-op without -tags failpoints.
// Point names come from the registry in docs/TESTPLAN.md §4.
func Hit(name string) error

// Hits returns how many times name was evaluated since the last Reset
// (failpoints builds only; 0 otherwise).
func Hits(name string) int

// NoteFS reports op to the observers registered with ObserveFS. It is a
// no-op without -tags failpoints or without observers.
func NoteFS(op FSOp)

// ObserveFS registers fn to receive every FSOp reported by NoteFS until
// the returned stop is called. fn runs synchronously in the reporting
// goroutine, possibly concurrently with itself, and must not call back
// into internal/fsx. Only valid with -tags failpoints; otherwise it panics
// so tests cannot silently pass.
func ObserveFS(fn func(FSOp)) (stop func())

// Reset disarms every fault and clears hit counters.
func Reset()

// Set arms faults in-process from a spec with the PRECINTO_CRASHPOINT
// syntax; several specs may be separated by commas:
//
// 	<name>[:<n>]              SIGKILL self at the n-th hit (default 1)
// 	<name>=errno:<E>[:<n>]    return errno E (ENOSPC, EDQUOT, EFBIG, EACCES,
// 	                          EPERM, EIO, EROFS, ENOENT, EAGAIN, EBUSY)
//
// Only valid with -tags failpoints; otherwise it panics so tests cannot
// silently pass. A malformed spec panics too. Implemented in the scaffold.
func Set(spec string)

// FSOp is one mutating file-system operation that internal/fsx reports in
// failpoints builds, so that test helpers (internal/fsx/fsxtest) can build
// power-loss images (docs/TESTPLAN.md §4). Paths are absolute. Rename,
// link, unlink and rmdir are reported twice: with Done=false right before
// the operation (Path and Target still hold their old state) and with
// Done=true once it succeeded; the other kinds only with Done=true.
type FSOp struct {
	Kind   FSOpKind
	Path   string
	Target string   // rename and link: the new name
	Done   bool     // false: about to run; true: completed
	File   *os.File // FSFsync: the synced file (read it only with ReadAt/Stat)
}

// FSOpKind names a mutating file-system operation reported by NoteFS.
type FSOpKind string

// Reported operations (internal/fsx, failpoints builds only).
const (
	FSCreate  FSOpKind = "create"  // a file was created (O_EXCL, or a lock file)
	FSMkdir   FSOpKind = "mkdir"   // a directory was created
	FSRename  FSOpKind = "rename"  // Path renamed to Target (Target replaced if it existed)
	FSLink    FSOpKind = "link"    // Target created as a hard link of Path
	FSUnlink  FSOpKind = "unlink"  // a non-directory was removed
	FSRmdir   FSOpKind = "rmdir"   // an empty directory was removed
	FSFsync   FSOpKind = "fsync"   // File's data and size are durable (FullSync)
	FSDirSync FSOpKind = "dirsync" // the entries of the directory Path are durable
)
```

### `internal/fsx`

- Owner: **G1 crypto core** · layer 0 · production
- May import (module): `internal/fsx/failpoint`
- May import (third party): stdlib, `golang.org/x/sys/unix`
- Tests: unit: no-follow walking (symlink parents, swapped components), RenameNoReplace, UnlinkIfUnchanged (inode swap, same size+mtime), hazards (FIFO, socket, nlink>1), staging on same device, free-space floor, Classify table; race test flipping a parent to a symlink 10k times (TESTPLAN SEC-6); scaffold-implemented leaf helpers (Lstat, AppendLine, WriteFileAtomic, TryLock/WaitLock) have tests in fsx_leaf_test.go

> Package fsx is precinto's only path to the file system for plaintext and
> capsule data: directory-handle (openat) walking that never follows
> symlinks, atomic writes, no-replace renames, unlink-if-unchanged, staging
> directories on the target volume, permission and owner checks, free-space
> checks, flock-based locks and errno classification (SPEC §10–§12, §17;
> D12, D13; invariants I2, I3, I8, I9, I13).
>
> Rules every implementation MUST follow:
>   - Below a trusted base, every component is opened with
>     O_NOFOLLOW|O_DIRECTORY relative to its parent fd (darwin may add
>     O_NOFOLLOW_ANY; linux may use openat2 RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS).
>     os.Root alone is not sufficient (it follows in-root symlinks).
>   - Every existing directory below a base must be owned by the current uid
>     and must not be group- or other-writable, else ErrUnsafe — except, on
>     linux, a group-writable, not other-writable directory of the user's
>     private group (the user's primary group, named like the user, with no
>     other member in /etc/group; anything undeterminable is unsafe, D67).
>   - Files are created O_CREAT|O_EXCL|O_NOFOLLOW with mode 0600; directories
>     0700. Restored modes are masked with 0700 (I8).
>   - Durability: File.Sync uses F_FULLFSYNC on darwin; every rename or
>     unlink that commits a state change is followed by a directory fsync.
>   - Every syscall that mutates state calls failpoint.Hit first.
>
> The scaffold implements the leaf helpers every group needs from day one
> (Lstat, Fstat, the Stat predicates, FullSync, SyncDir, WriteFileAtomic,
> AppendLine, TryLock, WaitLock, Lock.Unlock/File) in fsx.go, sys_unix.go
> and the per-OS files; everything else is G1's.

```go
// MaxLine bounds AppendLine (one write(2) of at most this many bytes plus
// the newline).
const MaxLine = 64 << 10

// MaxRecord bounds Dir.AppendRecord.
const MaxRecord = 64 << 20

// Errors. Callers test them with errors.Is.
var (
	// ErrUnsafe: a symlink, foreign owner, group/other-writable directory
	// (a linux user-private group's group-writable directory excepted, D67),
	// non-regular file, path escaping its base, or non-clean relative path.
	ErrUnsafe = errors.New("fsx: unsafe path")
	// ErrChanged: the file's identity (dev, ino, size, mtime, ctime) differs
	// from the expected snapshot.
	ErrChanged = errors.New("fsx: file changed")
	// ErrExist: a no-replace rename or exclusive create found the target.
	ErrExist = errors.New("fsx: target exists")
	// ErrLocked: a non-blocking lock is held by someone else.
	ErrLocked = errors.New("fsx: locked")
	// ErrNoSpace: free space is below the requested amount plus the floor.
	ErrNoSpace = errors.New("fsx: not enough free space")
	// ErrHardlink: the file has more than one link; it is never unlinked.
	ErrHardlink = errors.New("fsx: file has several hard links")
)

// DefaultFloor is a fixed 2 GiB (D76). Callers pass the effective
// policy.min_free instead (config.Policy.Floor); a fraction of the volume
// is no longer part of the default, because 5 % of a large, nearly full
// disk refused every seal while gigabytes were free.
var DefaultFloor = Floor{MinBytes: 2 << 30}

// AppendLine appends line plus '\n' with one write(2) on an
// O_APPEND (created O_EXCL 0600 if missing, then the parent directory is
// fsynced) descriptor opened O_NOFOLLOW|O_NONBLOCK, refuses non-regular
// files, and FullSyncs it. line must not contain '\n' and must be at most
// MaxLine bytes. Implemented in the scaffold (failpoints "fsx.write",
// "fsx.fsync").
func AppendLine(path string, line []byte) error

// CheckPrivateDir requires path to be a directory (not a symlink) owned by
// the current uid with no group/other permission bits (D6 socket dir rule).
func CheckPrivateDir(path string) error

// CheckSpace returns ErrNoSpace unless need bytes fit on path's volume while
// keeping the floor free.
func CheckSpace(path string, need int64, floor Floor) error

// Contains reports whether p is root or below root. It compares (dev, ino)
// of p's existing ancestors with root, so it is correct on case- and
// normalization-insensitive volumes; for non-existent tails it falls back to
// a component-wise comparison (case-folded on darwin).
func Contains(root, p string) (bool, error)

// FullSync flushes f to stable storage (F_FULLFSYNC on darwin, falling
// back to fsync on volumes that do not support it; fsync on linux).
// Implemented in the scaffold (failpoint "fsx.fsync").
func FullSync(f *os.File) error

// MkdirPrivate creates path and missing parents with mode 0700 and checks
// that the final directory is owned by the current uid and not a symlink.
func MkdirPrivate(path string) error

// ProbeHeld reports whether another process holds any flock on path. It
// tries LOCK_EX|LOCK_NB and releases immediately, then verifies that the
// path still names the probed inode. A missing file is not held: (false,
// nil) — lease files are created before use and never deleted (SPEC §9.3).
// Any other error, an unsupported file system, or an inode swap during the
// probe reports held=true (R17). It is the one probe implementation for
// leases (live.Probe uses it). Use it only on precinto's own lock and lease
// files: harness writer locks (Codex thread-writer-locks) are checked with
// platform.ProcTable.OpenFilesUnder, never by flocking them (HA17).
func ProbeHeld(path string) (held bool, err error)

// Realpath resolves symlinks in an existing absolute path once (protect and
// integrate time) and returns the cleaned result.
func Realpath(path string) (string, error)

// SameDevice reports whether a and b live on the same file system.
func SameDevice(a, b string) (bool, error)

// Space reports available and total bytes of the file system holding path.
func Space(path string) (avail, total uint64, err error)

// SyncDir fsyncs the directory at path. Implemented in the scaffold
// (failpoint "fsx.fsync").
func SyncDir(path string) error

// WriteFileAtomic writes data to a temporary file next to path (perm masked
// to owner bits, O_CREAT|O_EXCL|O_NOFOLLOW), FullSyncs it, renames it over
// path and fsyncs the directory. It is used for precinto-owned metadata
// (config.toml, receipts, vault.toml, roots.list). The temporary is removed
// on any error. Implemented in the scaffold (failpoints "fsx.write",
// "fsx.fsync", "fsx.rename").
func WriteFileAtomic(path string, data []byte, perm fs.FileMode) error

// Class is the coarse classification of an I/O error used by the error
// table in SPEC §17.
type Class string

// Error classes.
const (
	ClassNone     Class = ""
	ClassNoSpace  Class = "nospace"  // ENOSPC, EDQUOT, EFBIG
	ClassAccess   Class = "access"   // EACCES, EPERM (includes macOS TCC denials)
	ClassMissing  Class = "missing"  // ENOENT, ENOTDIR
	ClassBusy     Class = "busy"     // EBUSY, ETXTBSY, EDEADLK, EAGAIN, ErrLocked
	ClassUnsafe   Class = "unsafe"   // ErrUnsafe, ELOOP, EMLINK
	ClassReadOnly Class = "readonly" // EROFS
	ClassIO       Class = "io"       // EIO and anything else from the kernel
	ClassOther    Class = "other"
)

// Classify maps err to a Class. EPERM/EACCES are never treated as missing.
func Classify(err error) Class

// Dir is an open directory handle. Every operation is relative to it, walks
// path components with O_NOFOLLOW, and refuses symlinks, foreign-owned or
// group/other-writable directories below it (D12; on linux a group-writable,
// not other-writable directory of the user's private group is accepted,
// D67). A Dir is safe for use by one goroutine at a time.
type Dir struct {
	// contains filtered or unexported fields
}

// OpenBase opens a trusted base directory. path must be absolute and already
// resolved (see Realpath); the base itself may be reached through symlinks
// that were resolved once at protect/integrate time (SPEC §11.4), but must be
// owned by the current uid.
func OpenBase(path string) (*Dir, error)

// AppendLine appends line, plus "\n" if it lacks one, with one
// O_WRONLY|O_APPEND|O_NOFOLLOW write to the regular file rel opened
// component by component below d (created 0600 with O_EXCL when absent;
// the parent directory is then fsynced), then FullSyncs it; refuses
// non-regular files (a FIFO is refused without blocking) and files not
// owned by the user (ErrUnsafe). line must hold no other '\n' and be at
// most MaxLine bytes; an empty line appends only the newline (used to end
// a torn last line). Parent directories are never created (failpoints
// "fsx.write", "fsx.fsync").
func (d *Dir) AppendLine(rel string, line []byte) error

// AppendRecord is AppendLine for one record of up to MaxRecord bytes (a
// long history line, D90): the same single O_APPEND write, opened and
// synced the same way.
func (d *Dir) AppendRecord(rel string, line []byte) error

// Chmod sets permission bits of rel (masked with 0o700) without following.
func (d *Dir) Chmod(rel string, perm fs.FileMode) error

// Chtimes sets the mtime (and atime) of rel without following symlinks.
func (d *Dir) Chtimes(rel string, mtime time.Time) error

// Close releases the handle.
func (d *Dir) Close() error

// CreateTemp creates a new 0600 file in the directory dirRel (created 0700
// if missing) with O_CREAT|O_EXCL|O_NOFOLLOW and returns it with its name
// relative to d. The last '*' of pattern is replaced by a random string; a
// pattern without '*' is the exact name, created O_EXCL (ErrExist if it
// exists). Unlike os.CreateTemp, a pattern without '*' gets no suffix.
func (d *Dir) CreateTemp(dirRel, pattern string) (*os.File, string, error)

// Device returns the st_dev of the directory.
func (d *Dir) Device() (uint64, error)

// Link creates a hard link newRel to oldRel (used to hold an inode alive
// during history rotation, SPEC §7.1.4).
func (d *Dir) Link(oldRel, newRel string) error

// Lstat returns the Stat of rel without following symlinks anywhere.
func (d *Dir) Lstat(rel string) (Stat, error)

// Open opens the regular file rel for reading with
// O_RDONLY|O_NOFOLLOW|O_NONBLOCK, then requires fstat to be a regular file.
func (d *Dir) Open(rel string) (*os.File, Stat, error)

// OpenDir opens the directory rel below d without following symlinks. With
// create, missing components are created with mode 0700.
func (d *Dir) OpenDir(rel string, create bool) (*Dir, error)

// Path returns the absolute path the Dir was opened at (informational).
func (d *Dir) Path() string

// ReadDir lists the entries of rel (lstat semantics, no following).
func (d *Dir) ReadDir(rel string) ([]Entry, error)

// Remove removes rel (a file, or an empty directory) unconditionally. Used
// only for precinto-owned temporaries and staging.
func (d *Dir) Remove(rel string) error

// RemoveEmptyDirs removes rel and its now-empty parents up to (excluding)
// stopAt; non-empty directories are left alone.
func (d *Dir) RemoveEmptyDirs(rel, stopAt string) error

// Rename renames oldRel to newRel (both relative to d) and fsyncs the
// affected directories.
func (d *Dir) Rename(oldRel, newRel string, mode RenameMode) error

// RenameTo renames oldRel in d to newRel in dst (same file system), then
// fsyncs both directories.
func (d *Dir) RenameTo(oldRel string, dst *Dir, newRel string, mode RenameMode) error

// Sync fsyncs the directory itself.
func (d *Dir) Sync() error

// UnlinkIfUnchanged removes rel only if its current lstat is Unchanged
// relative to expect and Nlink == 1; otherwise it returns ErrChanged or
// ErrHardlink and leaves the file alone. The parent directory is fsynced.
func (d *Dir) UnlinkIfUnchanged(rel string, expect Stat) error

// Walk visits every entry below rel in lexical order without following
// symlinks. Hazardous entries are passed to fn with Hazard set and are never
// descended into. fn returning fs.SkipDir skips a directory.
func (d *Dir) Walk(rel string, fn func(WalkEntry) error) error

// Entry is one lstat'ed directory entry.
type Entry struct {
	Name string
	Type EntryType
	Stat Stat
}

// EntryType classifies a directory entry without following it.
type EntryType int

// Entry types.
const (
	TypeRegular EntryType = iota
	TypeDir
	TypeSymlink
	TypeOther // FIFO, socket, device: never opened, never followed
)

// Floor is the free-space reserve kept after an operation (D12, D38,
// D76): max(MinBytes, MinFraction × the volume's size).
type Floor struct {
	MinBytes    int64   // default 2 GiB (policy.min_free, D76)
	MinFraction float64 // default 0: the floor is a fixed size (D76)
}

// Hazard is a reason an entry is reported instead of being sealed or deleted
// (SPEC §10 "seal walk").
type Hazard string

// Hazards.
const (
	HazardNone     Hazard = ""
	HazardSymlink  Hazard = "symlink"
	HazardSpecial  Hazard = "special"  // FIFO, socket, device
	HazardHardlink Hazard = "hardlink" // st_nlink > 1
	HazardForeign  Hazard = "foreign"  // not owned by the current uid
	HazardAccess   Hazard = "access"   // EACCES/EPERM (TCC) while reading
)

// Lock is a held flock(2) lock. Lock files are never deleted (SPEC §10.2).
type Lock struct {
	// contains filtered or unexported fields
}

// TryLock takes an exclusive (or shared) non-blocking flock on path,
// creating the file 0600 if needed (O_NOFOLLOW, regular files only);
// ErrLocked if held elsewhere. Implemented in the scaffold.
func TryLock(path string, shared bool) (*Lock, error)

// WaitLock blocks until the lock is acquired or ctx ends (polling with
// back-off from 10 ms to 250 ms). Implemented in the scaffold.
func WaitLock(ctx context.Context, path string, shared bool) (*Lock, error)

// File returns the locked descriptor (used to make a lease inheritable
// across exec, SPEC §9.3).
func (l *Lock) File() *os.File

// Unlock releases the lock and closes the descriptor.
func (l *Lock) Unlock() error

// RenameMode selects rename semantics.
type RenameMode int

// Rename modes.
const (
	// NoReplace fails with ErrExist if the target exists (darwin
	// renameatx_np RENAME_EXCL, linux renameat2 RENAME_NOREPLACE, fallback
	// linkat+unlinkat).
	NoReplace RenameMode = iota
	// Replace atomically replaces the target (renameat).
	Replace
)

// Staging is a 0700 directory on the same file system as a restore target,
// removed when the operation completes (D12).
type Staging struct {
	Dir  *Dir
	Path string
	ID   string
}

// NewStaging creates <preferred>/<id> if preferred is on the same device as
// target, else <target volume root>/.precinto-staging/<id>.
func NewStaging(preferred, target, id string) (*Staging, error)

// OpenStaging reopens an existing staging directory during journal recovery.
func OpenStaging(path string) (*Staging, error)

// Remove deletes the staging directory and everything in it.
func (s *Staging) Remove() error

// Stat identifies one version of a file. ctime cannot be set from user space,
// so Unchanged means "not written or replaced since the snapshot".
type Stat struct {
	Dev     uint64
	Ino     uint64
	Mode    uint32 // full st_mode (type and permission bits)
	Nlink   uint32
	UID     uint32
	Size    int64
	MtimeNS int64
	CtimeNS int64
}

// Fstat returns the Stat of an open file. Implemented in the scaffold.
func Fstat(f *os.File) (Stat, error)

// Lstat returns the Stat of path without following a final symlink.
// Implemented in the scaffold.
func Lstat(path string) (Stat, error)

// IsDir reports whether Mode is a directory.
func (s Stat) IsDir() bool

// IsRegular reports whether Mode is a regular file.
func (s Stat) IsRegular() bool

// Perm returns the permission bits (Mode & 0o7777) as an fs.FileMode
// (setuid, setgid and sticky mapped to their fs.FileMode bits).
func (s Stat) Perm() fs.FileMode

// SameFile reports whether s and o are the same inode (Dev and Ino).
func (s Stat) SameFile(o Stat) bool

// Unchanged reports whether Dev, Ino, Size, MtimeNS and CtimeNS are equal.
func (s Stat) Unchanged(o Stat) bool

// WalkEntry is one entry visited by Dir.Walk. Rel is relative to the Dir the
// walk started from and uses '/' separators.
type WalkEntry struct {
	Rel    string
	Type   EntryType
	Stat   Stat
	Hazard Hazard
}
```

### `internal/fsx/fsxtest`

- Owner: **G1 crypto core** · layer 1 · test-only helper (production packages must not import it)
- May import (module): `internal/fsx`, `internal/fsx/failpoint`
- May import (third party): stdlib only
- Tests: self-tests (-tags failpoints): an unsynced rename, create, unlink or write is absent from the strict image and present in the full one, synced operations and everything they depend on are present in every image, identical images are merged

> Package fsxtest records the mutating file-system operations of
> internal/fsx and builds power-loss images from them (docs/TESTPLAN.md §4,
> power-loss mode). It works only in -tags failpoints builds, where fsx
> reports every create, mkdir, rename, link, unlink, rmdir, file FullSync
> and directory fsync through failpoint.NoteFS.
>
> The model: an entry created, renamed, linked or removed in a directory is
> durable once that directory (for a rename or link: the new name's
> directory) was fsynced after it; file data is durable as of the file's
> last FullSync. Images undo non-durable name operations (a random subset
> closed under their dependencies, newest first) and revert non-durable
> data to its last synced content (empty for a file created during the
> recording and never synced). Writes are seen only through FullSync, so
> files that existed before Record and were never synced during it keep
> their current content. A rename out of the imaged directory cannot be
> undone and counts as persisted.

```go
// Recording is the operation log of one test (Record).
type Recording struct {
	// contains filtered or unexported fields
}

// Record starts logging every mutating fsx operation of the process until
// the test ends. It skips the test in builds without -tags failpoints.
func Record(t testing.TB) *Recording

// Images builds up to n power-loss images of dir (n ≥ 2: the first keeps
// only what is durable, the second everything; the rest are random subsets
// of the non-durable operations, deterministic per test name). Each image
// is a directory tree under t.TempDir() with dir's layout, returned by
// path; journals inside hold absolute paths, so callers copy an image over
// dir before running recovery on it. dir must be the absolute path the
// code under test used (or its realpath). Hard links are not preserved:
// every path of an image is a file of its own (a hold link and its
// original are two equal files), so recovery checks run on an image must
// not rely on link counts.
func (r *Recording) Images(t testing.TB, dir string, n int) []string
```

### `internal/capsule`

- Owner: **G1 crypto core** · layer 2 · production
- May import (module): `internal/fsx`, `internal/fsx/failpoint`
- May import (third party): stdlib, `filippo.io/age`, `github.com/klauspost/compress/zstd`
- Tests: unit: round trip, tamper/truncation, wrong recipient, ErrChanged between passes, ErrHeader with 2/4 stanzas, bombs/PAX/links/sparse/size mismatch/1e6 entries rejected with bounded memory, mode mask, OnPhase after each milestone, UnitKey vectors and GenName/ParseGenName (names_test.go)

> Package capsule implements capsule format v1: keyless two-pass sealing to
> public age recipients with an ephemeral round-trip verification, header
> stanza checks, manifest-only decryption with a file key, and bounded,
> validating extraction into a staging directory (SPEC §5, §10, §11; D2, D5,
> D8, D13, D45).
>
> capsule never deletes plaintext and never decides liveness or placement:
> internal/sweep does. capsule never logs file contents or manifest titles.
> UnitKey, GenName and ParseGenName are implemented in the scaffold.

```go
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

// CheckHeader parses the age header of r and requires exactly want X25519
// stanzas and no other stanza types.
func CheckHeader(r io.Reader, want int) error

// Extract decrypts the capsule r and writes every regular entry into
// staging with mode 0600 (Entry.Mode & 0o700 applied at placement), after
// validating the whole manifest with Check. It accepts only TypeReg members
// named MANIFEST.json then f/000001… in order with sizes equal to the
// manifest, rejects PAX path overrides, links, sparse entries, trailing
// members, oversize manifests and totals above Limits, verifies every
// SHA-256, and fsyncs staging. All-or-nothing: on error staging is left for
// the caller to remove.
func Extract(ctx context.Context, r io.Reader, o ExtractOptions) (Manifest, []Staged, error)

// GenName returns the capsule file name of generation n ("g%06d.pcap";
// numbers above 999999 use more digits).
func GenName(n uint64) string

// HashFile returns the SHA-256 and size of a capsule file.
func HashFile(dir *fsx.Dir, name string) (sha256 string, size int64, err error)

// LoadSalt reads <state>/name.salt, creating 32 random bytes (0600) if
// missing. Sealers use it; read-only callers use ReadSalt.
func LoadSalt(path string) ([]byte, error)

// ParseGenName parses a generation file name; it accepts only names that
// GenName produces (no sign, no extra leading zeros beyond six digits,
// generation ≥ 1).
func ParseGenName(name string) (uint64, bool)

// ReadHeader returns the detached age header of the capsule file name in dir
// (age.ExtractHeader), opening it with O_NOFOLLOW, plus its SHA-256.
func ReadHeader(dir *fsx.Dir, name string) (header []byte, headerSHA256 string, err error)

// ReadSalt reads state/name.salt without creating it; ok=false when it does
// not exist (then no unit key exists yet). Read-only callers (doctor,
// status) use it, sealers keep LoadSalt. A symlink, FIFO or other
// non-regular file at path, or a salt of the wrong size, is an error.
func ReadSalt(path string) (salt []byte, ok bool, err error)

// RecipientsFingerprint is SHA-256 over the canonical recipient set
// (sorted recipient strings joined by '\n', prefixed by the family) (D5).
func RecipientsFingerprint(family string, recipients []string) string

// TmpName returns the temporary Seal writes in SealRequest.Out for the
// final name: "." + name + ".tmp", created O_EXCL (Seal fails with
// fsx.ErrExist when it is left over, and leaves it) and removed on every
// error return. It is a pure function of the final name so that callers
// journal it before Seal (D58a, journal.Record.Tmp).
func TmpName(name string) string

// UnitKey derives a unit key: lowercase hex of the first 16 bytes of
// HMAC-SHA256(salt, join(parts, 0x1f)). Parts per kind are fixed by SPEC
// §6.2 (D45); use harness.UnitKeyFor rather than building parts by hand.
// Implemented in the scaffold (test vectors in docs/TESTPLAN.md §8, D45).
func UnitKey(salt []byte, parts ...string) string

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

// ExtractOptions configures Extract.
type ExtractOptions struct {
	FileKey []byte
	Staging *fsx.Staging
	Limits  Limits
	// Check validates every entry (allowed base and rel for this kind and
	// unit, computed from trusted context, D8) before anything is written.
	Check func(Entry) error
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
	// Open, if set, is read instead of opening Dir/Rel, for any input whose
	// bytes sit in an already-unlinked inode (rescue, SPEC §10.3 step 7;
	// extracted history lines). Snap must be its current fstat; Dir/Rel
	// still name the entry.
	Open *os.File
}

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

// Limits bounds extraction (SPEC §5 rule 3, §11.5).
type Limits struct {
	// MaxTotal rejects a manifest whose sum of file sizes exceeds it; ≤ 0
	// refuses any non-empty capsule (ErrTooLarge). Callers always pass the
	// real budget (free space − floor).
	MaxTotal int64
	MaxFiles int // default MaxEntries
}

// Lineage of a generation relative to its parent (D9, D10, D42).
type Lineage string

// Lineages.
const (
	LineageFresh     Lineage = "fresh"     // no restore receipt: first seal, or plaintext that appeared without a restore
	LineageSuccessor Lineage = "successor" // every parent file present, each unchanged or append-only grown
	LineagePartial   Lineage = "partial"   // some parent files missing; present ones unchanged or appended
	LineageDiverged  Lineage = "diverged"  // a parent file changed in a non-append way
)

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
	ProjectDir     string    `json:"project_dir,omitempty"` // copied from harness.Unit.ProjectDir (D73)
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

// OpenManifest decrypts only up to the first tar member using fileKey
// (age.NewInjectedFileKeyIdentity) and returns the manifest.
func OpenManifest(r io.Reader, fileKey []byte) (Manifest, error)

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
	Manifest Manifest // Files is filled by Seal from Inputs and Dirs
	Inputs   []Input  // regular files, in tar order
	// Dirs are member-less entries recorded as given: empty directories
	// (Dir=true) and, for codex-home snapshot manifests, files whose bytes
	// live in a blob capsule (Blob set, Size/SHA256 as recorded). Seal
	// rejects an entry that is neither (ErrFormat).
	Dirs       []Entry
	Recipients []age.Recipient // exactly {vault, recovery} X25519; Seal adds an ephemeral one
	// Out is the capsule unit directory; Seal writes only Out/TmpName(Name)
	// and commits it to Out/Name with a no-replace rename.
	Out     *fsx.Dir
	Name    string // final file name, e.g. "g000007.pcap"; committed with NoReplace
	OnPhase func(Phase, *Sealed) error
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
func Seal(ctx context.Context, r SealRequest) (*Sealed, error)

// Staged is one file written into staging by Extract.
type Staged struct {
	Entry     Entry
	StagedRel string   // name inside the staging directory
	Stat      fsx.Stat // of the staged file
}
```

### `internal/vault`

- Owner: **G1 crypto core** · layer 2 · production
- May import (module): `internal/fsx`, `internal/fsx/failpoint`
- May import (third party): stdlib, `filippo.io/age`, `filippo.io/age/plugin`, `filippo.io/age/tag`, `github.com/awnumar/memguard`, `github.com/BurntSushi/toml`
- Tests: unit: passphrase factor wrap/unwrap, X25519 test plugin, MAC mismatch refuses, tripwire on recipients edit, Repair (recipient rewrite, ErrNeedRecovery, verified copy), Keyring.MAC per info string, last-factor refusal, plugin pin mismatch (se included), Keyring FileKey/Drop; E2E (opt-in): age-plugin-se

> Package vault manages per-root vaults (D1): one X25519 identity per
> protected root plus the `global` vault, each wrapped once per enrolled
> factor (Secure Enclave via age-plugin-se, other age plugins, scrypt
> passphrase, offline recovery key), the authenticated recipient set with its
> tripwire copy (D5), daemon-side unwrap with relayed UI (D4), and the
> Keyring that holds unlocked identities in memguard enclaves.
>
> Secrets are never Go strings: identities, passphrases, file keys and the
> recovery key live in *memguard.LockedBuffer. The transient heap copy made
> while age parses an identity during one DecryptHeader call is a documented
> residual (SPEC §19). Plugin binaries — age-plugin-se included — are
> pinned by absolute path and SHA-256 and run with PATH limited to the
> pinned directory (S2). After a MAC or tripwire failure, Store.Repair
> rewrites the recipient set from an identity the daemon unwrapped at the
> user's request (`precinto vault repair`, D53).

```go
// HKDF info strings of the MAC keys derived from a vault identity
// (Keyring.MAC).
const (
	InfoRecipients = "precinto/recipients/v1" // recipients_mac (D5)
	InfoPolicy     = "precinto/policy/v1"     // state/policy.pinned MACs (D55)
)

// Family is the cryptographic family of a vault. v0.1 supports only X25519
// (D2); a mismatching family makes the sealer refuse.
const Family = "x25519"

// FormatVersion is the vault.toml format.
const FormatVersion = 1

// GlobalID is the vault for global-store units not attributable to a root
// (D1, D36).
const GlobalID = "global"

// Errors.
var (
	ErrNoUI              = errors.New("vault: no interactive UI available for this factor")
	ErrCancelled         = errors.New("vault: cancelled by the user")
	ErrWrongIdentity     = errors.New("vault: identity does not match the vault recipient")
	ErrMACMismatch       = errors.New("vault: recipient set MAC mismatch")               // D5: refuse grant, alert
	ErrRecipientsChanged = errors.New("vault: recipients differ from the verified copy") // D5 tripwire: exit 5
	ErrLastFactor        = errors.New("vault: refusing to remove the last interactive factor")
	ErrPluginPin         = errors.New("vault: plugin binary does not match its pinned hash")
	ErrWeakPassphrase    = errors.New("vault: passphrase below the strength policy")
	ErrNotFound          = errors.New("vault: no such vault")
	ErrLocked            = errors.New("vault: vault is locked")
	ErrNeedRecovery      = errors.New("vault: the recovery recipient differs from the verified copy; repair needs the recovery key") // D53
	// ErrBadSecret: a wrong passphrase or recovery key (exit 3). It counts
	// toward the D27 prompt rate limit like a cancel and is never a tamper
	// alert (never ErrWrongIdentity).
	ErrBadSecret = errors.New("vault: incorrect passphrase or recovery key")
)

// CalibrateScrypt returns the scrypt logN that takes about target on this
// machine, clamped to [19, 22] (D3: 2^20 default).
func CalibrateScrypt(target time.Duration) int

// Diceware generates a passphrase of words from the embedded 7776-word
// list (7 words ≈ 90 bits; S9). The list file (wordlist.txt) is swappable
// without a code change (OD-01).
func Diceware(words int) (*memguard.LockedBuffer, error)

// EstimateBits estimates the entropy of a user-chosen passphrase; the
// policy requires ≥ 80 bits and ≥ 12 characters (D3, S9).
func EstimateBits(p *memguard.LockedBuffer) float64

// FormatRecoveryKey groups a recovery key for display (groups of 6, UX5).
func FormatRecoveryKey(b *memguard.LockedBuffer) (*memguard.LockedBuffer, error)

// ParseRecoveryKey reads a recovery identity (AGE-SECRET-KEY-1…, optionally
// grouped with spaces or dashes) from a locked buffer.
func ParseRecoveryKey(b *memguard.LockedBuffer) (age.Identity, error)

// PluginTarget returns what RepinPlugin would pin for f now: the path its
// enrolled path resolves to (D80), checked like RepinPlugin checks it.
func PluginTarget(f Factor) (string, error)

// VerifyRecovery checks that the recovery identity unwraps header (a fresh
// capsule header), for `precinto recover --verify` (D7).
func VerifyRecovery(recovery *memguard.LockedBuffer, header []byte) error

// Factor is one [[factors]] entry of vault.toml: one wrapped copy of the
// vault identity in identity.<name>.age.
type Factor struct {
	Name           string     `toml:"name"` // file suffix: identity.<name>.age
	Kind           FactorKind `toml:"kind"`
	Recipient      string     `toml:"recipient"`       // what the identity file is encrypted to ("" for passphrase)
	IdentityStub   string     `toml:"identity_stub"`   // AGE-PLUGIN-…-1 handle (not secret; needed to unwrap)
	PluginPath     string     `toml:"plugin_path"`     // pinned absolute path of age-plugin-<name>, symlinks resolved (every plugin-backed factor, se included); the only path ever run
	PluginLink     string     `toml:"plugin_link"`     // the absolute path the factor was enrolled with, before resolving (e.g. /opt/homebrew/bin/age-plugin-se); RepinPlugin resolves it again (D80)
	PluginSHA256   string     `toml:"plugin_sha256"`   // pinned hash, checked before every use (ErrPluginPin)
	ScryptLogN     int        `toml:"scrypt_log_n"`    // passphrase only
	PresencePolicy string     `toml:"presence_policy"` // e.g. "any-biometry-or-passcode", "touch-always"
	GUI            bool       `toml:"gui"`             // can prompt without a TTY (D27)
	AddedAt        time.Time  `toml:"added_at"`
}

// FactorKind is how a vault identity is wrapped (SPEC §4.3).
type FactorKind string

// Factor kinds.
const (
	FactorSE         FactorKind = "se"         // age-plugin-se, access control any-biometry-or-passcode (D3)
	FactorPlugin     FactorKind = "plugin"     // any other age plugin (YubiKey, TPM)
	FactorPassphrase FactorKind = "passphrase" // scrypt, logN calibrated to ~1 s, min logN 19 (D3)
	FactorRecovery   FactorKind = "recovery"   // offline X25519 recovery key (D7)
)

// FactorSpec describes a factor to enroll.
type FactorSpec struct {
	Kind            FactorKind
	Name            string // default: kind, or plugin name
	Recipient       string // se/plugin: from keygen output, never from `recipients` (S10)
	IdentityStub    string // se/plugin handle
	PluginPath      string // absolute; hashed and pinned
	SEAccessControl string // se only: default "any-biometry-or-passcode"; biometry-only and "none" rejected
	// PresencePolicy is for plugin factors: "touch-always" | "touch-cached" |
	// "pin-always" | "pin-once" | "tpm-pin"; "" requires NoPresenceAck
	// (S10); se keeps SEAccessControl. Recorded as Factor.PresencePolicy.
	PresencePolicy string
	// Passphrase is consumed (destroyed) by AddFactor and Init: pass a
	// fresh copy per call (Create takes no FactorSpec: it asks through
	// the UI).
	Passphrase    *memguard.LockedBuffer
	ScryptLogN    int  // 0 = calibrate
	NoPresenceAck bool // accept a plugin factor without a known presence policy (S10)
}

// InitOptions configures Init.
type InitOptions struct {
	Factors []FactorSpec
	UI      UI
	Now     func() time.Time
	// Confirm, when set, receives the new recovery identity before
	// anything is written (the caller shows or writes it and has the user
	// confirm it, D7); an error from it ends Init with nothing created, so
	// init can run again with a new key (UX-07). The buffer stays the
	// caller's to read only: Init returns it on success.
	Confirm func(recovery *memguard.LockedBuffer) error
}

// Keyring holds unlocked identities, one memguard enclave per vault id (D4).
// Only the daemon creates a Keyring.
type Keyring struct {
	// contains filtered or unexported fields
}

// NewKeyring returns an empty keyring.
func NewKeyring() *Keyring

// Drop wipes vault id.
func (k *Keyring) Drop(id string)

// DropAll wipes every identity.
func (k *Keyring) DropAll()

// FileKey opens vault id's enclave, parses the identity, unwraps the
// detached age header with age.DecryptHeader, and returns the 16-byte file
// key in a locked buffer. The parsed identity is dropped before returning.
func (k *Keyring) FileKey(id string, header []byte) (*memguard.LockedBuffer, error)

// Has reports whether vault id is unlocked.
func (k *Keyring) Has(id string) bool

// IDs returns the unlocked vault ids.
func (k *Keyring) IDs() []string

// MAC returns hex HMAC-SHA256(HKDF-SHA256(identity of vault id, info),
// data) without exposing the identity (info: InfoRecipients, InfoPolicy).
// ErrLocked if the vault is not unlocked.
func (k *Keyring) MAC(id, info string, data []byte) (string, error)

// Put takes ownership of identity (the buffer is destroyed) for vault id.
func (k *Keyring) Put(id string, identity *memguard.LockedBuffer) error

// WithIdentity runs fn with a parsed identity of vault id (vault creation,
// factor enrollment, MAC computation). fn must not retain it.
func (k *Keyring) WithIdentity(id string, fn func(age.Identity, *memguard.LockedBuffer) error) error

// WithIdentityBuffer runs fn with the locked identity of vault id (factor
// enrollment by the daemon, which cannot import age); fn must not retain,
// copy or log it. The buffer is destroyed when fn returns. ErrLocked if the
// vault is not unlocked.
func (k *Keyring) WithIdentityBuffer(id string, fn func(identity *memguard.LockedBuffer) error) error

// Meta is vaults/<id>/vault.toml.
type Meta struct {
	Format             int       `toml:"format"`
	ID                 string    `toml:"id"` // root id or "global"
	RootPath           string    `toml:"root_path"`
	CreatedAt          time.Time `toml:"created_at"`
	Family             string    `toml:"family"`
	Recipient          string    `toml:"recipient"`          // age1… X25519 vault recipient
	RecoveryRecipient  string    `toml:"recovery_recipient"` // shared by all vaults of an install
	RecipientsMAC      string    `toml:"recipients_mac"`     // hex HMAC(HKDF(identity,"precinto/recipients/v1"), canonical set) (D5)
	Factors            []Factor  `toml:"factors"`
	LastAudit          time.Time `toml:"last_audit"`           // capsules sealed after this are audited at unlock (D5)
	RecoveryVerifiedAt time.Time `toml:"recovery_verified_at"` // `recover --verify` success (D7)
}

// RepairOptions configures Store.Repair (D53).
type RepairOptions struct {
	// Identity is the vault identity the daemon just unwrapped with a
	// factor, or from identity.recovery.age with the recovery key.
	Identity *memguard.LockedBuffer
	// Recovery is the recovery identity typed by the user (optional). When
	// nil, the recovery recipient is kept only if it equals the one in the
	// verified copy; otherwise Repair returns ErrNeedRecovery.
	Recovery *memguard.LockedBuffer
	Now      func() time.Time
}

// RepairResult reports what Repair rewrote.
type RepairResult struct {
	RecipientChanged bool
	RecoveryChanged  bool
	LastAudit        time.Time // the previous last_audit: capsules sealed after it are audited as possibly exposed
}

// Store is the set of vaults under <base>/vaults plus the tripwire copies
// under <base>/state/verified.
type Store struct {
	VaultsDir   string
	VerifiedDir string
	FactorsDir  string
}

// OpenStore returns the store rooted at the given directories.
func OpenStore(vaultsDir, verifiedDir, factorsDir string) *Store

// Create creates the vault id (a new root, D1): generates an X25519
// identity, wraps it to every enrolled factor and to the recovery
// recipient, writes vault.toml with the recipients MAC and the verified
// copy, and returns the identity (the daemon keeps it as an unlocked grant).
func (s *Store) Create(ctx context.Context, id, rootPath string, ui UI) (*memguard.LockedBuffer, error)

// Init creates the install-wide recovery identity and the global vault
// wrapped to every factor, and returns the recovery identity once, in a
// locked buffer, for the caller to show or write per D7 (with
// InitOptions.Confirm, before the vault exists).
func (s *Store) Init(ctx context.Context, o InitOptions) (*memguard.LockedBuffer, error)

// Initialized reports whether init has run (recovery recipient and global
// vault exist).
func (s *Store) Initialized() (bool, error)

// List returns every vault id.
func (s *Store) List() ([]string, error)

// MarkAudited sets last_audit of vault id after the daemon audited every
// capsule sealed since the previous last_audit (D5). It never moves
// last_audit backwards (an older at is a no-op) and refuses an at later
// than now; vault.toml is rewritten atomically under the vault's lock
// file, outside the recipients MAC. Readers treat a last_audit later than
// now as zero (audit everything).
func (s *Store) MarkAudited(id string, at time.Time) error

// MarkRecoveryVerified records recovery_verified_at = at in every
// vault.toml after `precinto recover --verify` succeeded (SPEC §4.7). Like
// MarkAudited it never moves the time backwards and refuses the future.
func (s *Store) MarkRecoveryVerified(at time.Time) error

// Open loads vaults/<id>/vault.toml.
func (s *Store) Open(id string) (*Vault, error)

// Recipients returns the sealing recipients {vault, recovery} of id and the
// recipients fingerprint, without any secret. It returns
// ErrRecipientsChanged if vault.toml differs from the verified copy (D5).
func (s *Store) Recipients(id string) ([]age.Recipient, string, error)

// Remove deletes vaults/<id> and its verified copy. Unused in v0.2:
// unprotect keeps the vault and every capsule (D74).
func (s *Store) Remove(id string) error

// Repair rewrites vault.toml of v after a MAC or tripwire failure (D53):
// recipient := Identity.Recipient(), recovery_recipient := the recovery
// identity's recipient (or the verified one), family x25519, a fresh
// recipients_mac computed with Identity, and the verified copy. It never
// touches identity files or capsules. The daemon calls it only after
// checking that Identity opens the header of at least one capsule of this
// vault logged before LastAudit (when any exists) and after the user's
// typed confirmation on a TTY; the caller then audits capsules sealed
// since LastAudit and reports foreign fingerprints as exposed.
func (s *Store) Repair(v *Vault, o RepairOptions) (RepairResult, error)

// RepinPlugin re-pins factor name in every vault to the binary its
// enrolled path resolves to now (Factor.PluginLink; the pinned PluginPath
// for a factor enrolled before it existed), D75, D80: after a Homebrew
// upgrade the link points into a new Cellar version and the old one is
// gone. The resolved binary must be named like the pinned one
// (age-plugin-<name>) and be a regular file owned by root or the user and
// not group- or other-writable (else ErrUnsafe). Every vault gets the new
// PluginPath and SHA-256; a vault that failed is reported in the joined
// error and a later RepinPlugin completes the others (vaults that already
// pin the new binary are left as they are). It returns the previous and the
// new SHA-256; the caller showed both hashes and both paths (PluginTarget)
// and obtained the typed word on a TTY. ErrNotFound when no vault has the
// factor.
func (s *Store) RepinPlugin(name string) (oldSHA, newSHA string, err error)

// Verify checks that identity matches the vault recipient and that the
// recipients MAC is valid, then (re)writes the verified copy (D5).
func (s *Store) Verify(v *Vault, identity *memguard.LockedBuffer) error

// UI is the presence/secret channel for one unwrap. In the daemon it relays
// to the requesting client's TTY, or to pinentry when the client has none
// (D4, D27). Secret answers arrive in locked buffers.
type UI interface {
	// Display shows an informational line (plugin DisplayMessage, "Touch your YubiKey").
	Display(msg string) error
	// Secret asks for a secret value (passphrase, PIN); ErrNoUI if impossible.
	Secret(prompt string) (*memguard.LockedBuffer, error)
	// Confirm asks a yes/no question; ErrNoUI if impossible.
	Confirm(prompt, yes, no string) (bool, error)
	// Interactive reports whether Secret/Confirm can reach a human.
	Interactive() bool
	// GUI reports whether a GUI dialog (Secure Enclave, pinentry-mac) can appear.
	GUI() bool
}

// Vault is one opened vault directory.
type Vault struct {
	Dir  string
	Meta Meta
}

// AddFactor wraps identity to a new factor and updates vault.toml
// atomically (requires the vault unlocked).
func (v *Vault) AddFactor(ctx context.Context, identity *memguard.LockedBuffer, spec FactorSpec, ui UI) error

// RemoveFactor removes a factor file; ErrLastFactor if it is the last
// non-recovery factor. Backed-up copies stay valid (SPEC §19).
func (v *Vault) RemoveFactor(name string) error

// Unwrap performs exactly one user-presence unwrap of the vault identity
// with the named factor ("" picks the best factor usable with ui: SE or GUI
// plugin when !ui.Interactive(), D27). Plugins run from their pinned path.
func (v *Vault) Unwrap(ctx context.Context, factor string, ui UI) (*memguard.LockedBuffer, error)

// UsableFactors returns the factors that can prompt in a context with the
// given capabilities (tty, gui).
func (v *Vault) UsableFactors(tty, gui bool) []Factor
```

### `internal/vault/vaulttest`

- Owner: **G1 crypto core** · layer 3 · test-only helper (production packages must not import it)
- May import (module): `internal/vault`
- May import (third party): stdlib, `filippo.io/age`, `github.com/awnumar/memguard`
- Tests: used by G2/G4/G7 tests

> Package vaulttest builds throwaway vaults with a known X25519 test
> identity (no Secure Enclave, no plugins) for tests of every group.

```go
// LockedBuffer copies s into a locked buffer (test convenience).
func LockedBuffer(t testing.TB, s string) *memguard.LockedBuffer

// Fixture is an initialized store with one root vault.
type Fixture struct {
	Store    *vault.Store
	RootID   string
	Identity *age.X25519Identity // the root vault identity (test only)
	Recovery *age.X25519Identity // the recovery identity (test only)
	Keyring  *vault.Keyring      // already holding RootID and vault.GlobalID
}

// New creates a store under dir (vaults/, state/verified/, factors/) with a
// passphrase-only factor (scrypt logN 10 for speed), the global vault and a
// root vault rootID, all unlocked in Keyring.
func New(t testing.TB, dir, rootID string) *Fixture

// TamperRecipient replaces the vault recipient of vaultID in its vault.toml
// (or, with recovery, the recovery recipient) with a fresh foreign X25519
// recipient, as a one-shot writer would (SEC-9, SEC-26), and returns it.
// Only the top-level key is edited, byte for byte, so the recipients MAC
// and the verified copy no longer match.
func (f *Fixture) TamperRecipient(t testing.TB, vaultID string, recovery bool) string

// UI is a scripted vault.UI.
type UI struct {
	Secrets     []string // answers to Secret, in order
	Confirms    []bool   // answers to Confirm, in order
	Displayed   []string // recorded Display messages
	Interactive bool
	GUIOK       bool
}

// AsUI returns u as a vault.UI.
func (u *UI) AsUI() vault.UI
```

## G2 daemon

### `internal/platform`

- Owner: **G2 daemon** · layer 1 · production
- May import (module): `internal/paths`, `internal/fsx`
- May import (third party): stdlib, `golang.org/x/sys/unix`
- Tests: unit+integration (real child processes): ProcID equality and reuse, zombie as exited, WaitExit, Signal re-verification, Ancestors, Descendants (PPID walk, never by session id, reused pids excluded; walk_test.go), SignalGroup only on a Setsid child's session, Cwd and OpenFilesUnder, SameExecutable, PeerOf over a socketpair, ReadScreen parsing fixtures (ioreg/loginctl output), WatchJumps with a fake clock

> Package platform wraps every OS-specific facility precinto needs, cgo-free:
> process identity measured by precinto itself (pid + kernel start time),
> process-table scans by executable, open-file holders, race-free waits and
> signals, peer credentials on Unix sockets, screen-lock / HID-idle / sleep
> triggers, UI-context detection, process hardening and terminal scrubbing
> (SPEC §9, §12.5, §13, §15; D6, D18, D24, D27, D34).
>
> Files: platform.go (exported API, shared types), *_darwin.go, *_linux.go
> (implementations), *_other.go (unsupported stubs so `go vet` builds).
> darwin: sysctl kern.proc.pid (kp_proc.p_starttime, p_stat), kern.procargs2
> (exe path), proc_info(2) (proc_pidpath, PROC_PIDVNODEPATHINFO,
> PROC_PIDLISTFDS + PROC_PIDFDVNODEPATHINFO) through syscall(2) for
> executables, working directories and open-file holders, with `lsof` only
> when proc_info is unavailable (ENOSYS); inspection-protected processes
> (EPERM) are skipped like lsof does. kqueue EVFILT_PROC NOTE_EXIT,
> getsockopt LOCAL_PEERCRED / LOCAL_PEERPID, PT_DENY_ATTACH,
> `/usr/sbin/ioreg` polling (IOConsoleLocked, HIDIdleTime), `tmutil`
> queries (read-only). linux: /proc/<pid>/stat field 22 (µs since boot,
> D66) + /proc/sys/kernel/random/boot_id, /proc/<pid>/exe, pidfd_open /
> pidfd_send_signal, SO_PEERCRED, PR_SET_DUMPABLE, `loginctl show-session`
> (LockedHint, IdleSinceHint).
>
> ProcID.IsZero, Ancestors and Descendants are implemented in the scaffold
> (pure walks over a ProcTable); everything OS-specific is G2's.

```go
// Errors.
var (
	ErrNoProcess   = errors.New("platform: no such process")
	ErrNotSame     = errors.New("platform: process identity changed")
	ErrUnsupported = errors.New("platform: unsupported on this OS")
	ErrRoot        = errors.New("platform: refusing to run as root")
	ErrUnsafeEnv   = errors.New("platform: unsafe loader environment (DYLD_*/LD_*)")
)

// BackupExcluded is a read-only Time Machine query: `tmutil
// destinationinfo`, then `tmutil isexcluded path`, with an explicit minimal
// environment and a 10 s timeout per run. known=false off darwin or when
// no backup destination is configured (nothing is backed up; err is nil
// then), or when the answer could not be read (err says why).
func BackupExcluded(ctx context.Context, path string) (excluded, known bool, err error)

// CheckLoaderEnv returns ErrUnsafeEnv if environ contains DYLD_* or LD_*
// variables; the daemon refuses to start (or re-execs with a clean env).
func CheckLoaderEnv(environ []string) error

// CloudSynced reports whether path is inside a known cloud-synced location
// (~/Library/Mobile Documents, ~/Library/CloudStorage, iCloud Desktop &
// Documents, Dropbox, OneDrive).
func CloudSynced(path string) bool

// DiskEncryption reports FileVault (darwin `fdesetup status`) or an
// encrypted home (linux, best effort); known=false if undeterminable.
func DiskEncryption(ctx context.Context) (on, known bool, err error)

// ExcludeFromBackup adds a sticky Time Machine exclusion (`tmutil
// addexclusion`, no root needed); no-op on linux.
func ExcludeFromBackup(ctx context.Context, path string) error

// Executable returns the absolute path and Stat-like identity of the running
// binary (os.Executable resolved once at startup).
func Executable() (path string, dev, ino uint64, err error)

// Harden must be the first call of every subcommand that may hold secrets or
// plaintext (agent, unlock, hook, run, seal, sweep, restore, open, cat,
// recover): refuse uid 0, setrlimit(RLIMIT_CORE, 0), PT_DENY_ATTACH (darwin)
// or prctl(PR_SET_DUMPABLE, 0) (linux) (SPEC §4.6, S15).
func Harden() error

// SameExecutable reports whether pid runs the same file (dev+inode) as the
// current binary (D6 mutual authentication).
func SameExecutable(pid int) (bool, error)

// ScrubTTY opens tty with O_WRONLY|O_NOCTTY (only if owned by the current
// uid) and writes the reset sequence of SPEC §15.4, then runs `stty sane`
// on it (darwin -f, linux -F).
func ScrubTTY(tty string, o ScrubOptions) error

// Signal sends sig to id after re-verifying (pid, start time) immediately
// before kill(2) (linux: pidfd_send_signal). ErrNotSame if the process
// changed (S14).
func Signal(id ProcID, sig syscall.Signal) error

// SignalGroup signals the remaining processes whose session id is
// leader.PID. It refuses (ErrNotSame) when a process with that pid exists
// with another start time (the session id was reused), refuses sid ≤ 1 and
// the caller's own session, and never signals the caller. Only for
// sessions precinto created itself — the wrapper's PTY child or a
// direct-mode child started with Setsid, both session leaders — never for
// an unwrapped harness, whose session is the user's terminal session (its
// login shell and every other job of that tab) (R11, D57). Members are
// re-verified one by one like Signal.
func SignalGroup(leader ProcID, sig syscall.Signal) error

// SpotlightIndexed reports whether Spotlight indexes path (`mdfind -onlyin
// <path> -count 'kMDItemFSName == *.md'` > 0); known=false off darwin.
func SpotlightIndexed(ctx context.Context, path string) (indexed, known bool, err error)

// StartTime returns the wall-clock start of id for comparisons with
// harness timestamps (D18 registry startedAt, hook windows): darwin's
// StartUS as is; on linux the current btime is added to a ProcID measured
// on this boot (one with a BootID; a ProcID without one, such as a test
// fake, is taken as wall time). It is the zero time when btime cannot be
// read. See D66.
func StartTime(id ProcID) time.Time

// WaitExit blocks until id has exited (zombie counts as exited) or ctx ends;
// darwin kqueue EVFILT_PROC/NOTE_EXIT, linux pidfd poll, fallback polling.
func WaitExit(ctx context.Context, id ProcID) error

// WatchJumps ticks every interval and sends a Jump whenever wall time moved
// more than threshold beyond monotonic time (D24 sleep/wake ⇒ lock at wake).
func WatchJumps(ctx context.Context, c Clock, every, threshold time.Duration, out chan<- Jump)

// Clock is wall time plus a monotonic reading. Deadlines are evaluated
// against both (R16, IM15): a deadline expires if either clock says so.
type Clock interface {
	// Now returns wall-clock time with the monotonic reading stripped.
	Now() time.Time
	// Mono returns a monotonic duration since an arbitrary fixed origin.
	Mono() time.Duration
}

// SystemClock returns the real clock.
func SystemClock() Clock

// Holder is a process with an open descriptor on a path.
type Holder struct {
	Proc ProcInfo
	Path string
}

// Jump is a detected wall-vs-monotonic discontinuity (sleep/wake or clock
// step).
type Jump struct {
	Wall time.Duration // wall-clock delta between ticks
	Mono time.Duration // monotonic delta between ticks
	At   time.Time
}

// Peer holds the verified credentials of a Unix-socket peer.
type Peer struct {
	UID  int
	PID  int
	Proc ProcInfo // resolved at accept time; Proc.ID guards PID reuse
}

// PeerOf returns the peer credentials of c (darwin LOCAL_PEERCRED +
// LOCAL_PEERPID; linux SO_PEERCRED).
func PeerOf(c *net.UnixConn) (Peer, error)

// ProcID is one process incarnation as measured by precinto: pid plus the
// kernel start time, with BootID guarding reboots on linux. ProcIDs are
// compared by equality only; never computed as now−elapsed and never taken
// from a harness (R9, S14). Use StartTime to compare a start with a wall
// clock time (D66).
type ProcID struct {
	PID int `json:"pid"`
	// StartUS is the kernel start time in µs: wall time on darwin
	// (p_starttime), µs since boot on linux (/proc/<pid>/stat field 22 ×
	// 10^6/CLK_TCK), so a wall-clock step never changes a measured
	// identity; compared by equality only.
	StartUS int64  `json:"start_us"`
	BootID  string `json:"boot_id,omitempty"` // linux only
}

// Identify measures the ProcID of a live pid.
func Identify(pid int) (ProcID, error)

// ParseProcID parses "PID:START".
func ParseProcID(s string) (ProcID, error)

// Self returns the identity of the current process.
func Self() ProcID

// Spawn starts argv detached (Setsid, stdin /dev/null) and does not wait.
// argv[0] must be absolute.
func Spawn(argv []string, o SpawnOptions) (ProcID, error)

// IsZero reports whether id is unset. Implemented in the scaffold.
func (id ProcID) IsZero() bool

// String formats "PID:START" (the --wait-pid syntax).
func (id ProcID) String() string

// ProcInfo is a snapshot of one process.
type ProcInfo struct {
	ID    ProcID
	PPID  int
	UID   int
	PGID  int
	SID   int       // session id (setsid)
	State ProcState // zombie counts as exited
	Exe   string    // absolute executable path (kern.procargs2 / /proc/<pid>/exe); "" if unknown
	Comm  string    // kernel short name; for Claude Code this is its version string: never match on it
	Argv  []string  // best effort; may be empty
	TTY   string    // controlling terminal device path, "" if none
}

// Ancestors returns up to max ancestors of pid, nearest first, by walking
// PPIDs with t.Lookup; the walk stops at pid 0/1, at a lookup error or at a
// loop. An error is returned only if pid itself cannot be looked up.
// Implemented in the scaffold.
func Ancestors(t ProcTable, pid int, max int) ([]ProcInfo, error)

// Descendants returns every live descendant of root found by walking PPIDs
// in one t.List() snapshot (a child must have started no earlier than its
// parent, so a reused pid is never adopted), each re-verified with t.Alive.
// It is how precinto finds the helpers of an unwrapped harness it ends
// (D57): never by session or process-group id. Call it before signalling
// root: once root exits its children are reparented and no longer found.
// Implemented in the scaffold.
func Descendants(t ProcTable, root ProcID) ([]ProcInfo, error)

// ProcState is the scheduler state of a process.
type ProcState string

// Process states.
const (
	StateRunning ProcState = "running"
	StateStopped ProcState = "stopped"
	StateZombie  ProcState = "zombie" // counts as exited everywhere (R8)
	StateUnknown ProcState = "unknown"
)

// ProcTable is the process-table view used by liveness, hooks and the
// daemon; tests substitute internal/platform/fakeplatform. Every
// process-derived liveness fact (E6, E7, D47, D52) goes through it so it
// can be faked.
type ProcTable interface {
	// Lookup returns the current process with pid, or ErrNoProcess.
	Lookup(pid int) (ProcInfo, error)
	// Alive reports whether id still exists with the same start time and is
	// not a zombie.
	Alive(id ProcID) bool
	// List returns every process of the current uid.
	List() ([]ProcInfo, error)
	// Cwd returns the current working directory of id ("" with nil error
	// if it cannot be determined; callers treat unknown as "may be
	// inside"); ErrNotSame if id is gone or changed (darwin proc_pidinfo
	// PROC_PIDVNODEPATHINFO or lsof -d cwd; linux /proc/<pid>/cwd).
	Cwd(id ProcID) (string, error)
	// OpenFilesUnder returns processes holding open descriptors on files
	// below any of dirs (darwin: lsof +D/-F; linux: /proc/*/fd). An error
	// means the caller must treat the paths as live (HA9, R11).
	OpenFilesUnder(ctx context.Context, dirs []string) ([]Holder, error)
}

// System returns the real process table.
func System() ProcTable

// ScreenState is one observation of the console.
type ScreenState struct {
	Locked    bool
	LockKnown bool          // false if the state cannot be determined (headless, SSH)
	HIDIdle   time.Duration // time since the last keyboard/mouse event
	IdleKnown bool
	At        time.Time
}

// ReadScreen polls the console once (darwin: `/usr/sbin/ioreg -n Root -d1`
// IOConsoleLocked and IOHIDSystem HIDIdleTime, ~25 ms; linux: loginctl
// LockedHint and IdleSinceHint).
func ReadScreen(ctx context.Context) (ScreenState, error)

// ScrubOptions controls TTY scrubbing after a harness has exited.
type ScrubOptions struct {
	ITerm  bool   // also send OSC 1337;ClearScrollback
	Clear  bool   // clear screen and scrollback (policy clear_terminal_on_end)
	Banner string // printed after the reset, one line
}

// SpawnOptions configures a detached child.
type SpawnOptions struct {
	Dir     string
	Env     []string // full environment (allowlisted by the caller)
	LogPath string   // stdout/stderr destination; "" means /dev/null
}

// UIContext describes where an unlock prompt could appear (D27).
type UIContext struct {
	TTY  bool // the requester owns a terminal (stdin and stdout are TTYs)
	GUI  bool // a GUI dialog can appear (darwin Aqua session with graphic access)
	Tmux bool // $TMUX or $STY set
	SSH  bool // $SSH_CONNECTION/$SSH_TTY set
}

// DetectUIContext inspects e and the current process (D27): SE dialogs are
// impossible in SSH and detached tmux/screen sessions.
func DetectUIContext(e paths.Env, stdin, stdout *os.File) UIContext
```

### `internal/platform/fakeplatform`

- Owner: **G2 daemon** · layer 2 · test-only helper (production packages must not import it)
- May import (module): `internal/platform`
- May import (third party): stdlib only
- Tests: self-tests of the fakes

> Package fakeplatform provides deterministic fakes of platform.ProcTable and
> platform.Clock for liveness, state-machine and crash tests
> (docs/TESTPLAN.md "fakes").

```go
// Operations accepted by SetErr.
const (
	OpLookup         = "Lookup"
	OpList           = "List"
	OpCwd            = "Cwd"
	OpOpenFilesUnder = "OpenFilesUnder"
)

// Clock is a settable clock with independent wall and monotonic readings.
// A clock from NewClock is frozen: it moves only when the test moves it. A
// clock from NewRealClock follows the real clock and adds what the test
// moved it by.
type Clock struct {
	// contains filtered or unexported fields
}

// NewClock starts at wall with monotonic reading 0.
func NewClock(wall time.Time) *Clock

// NewRealClock returns a Clock that follows the real clock: Now is the
// system wall time plus everything Advance, Sleep and StepWall added, and
// Mono the real time elapsed since NewRealClock plus everything Advance
// added; Now is in UTC. Without StepWall it is never behind the real clock,
// so the code under test never sees a time the kernel stamped during the
// test (a file mtime the test did not set, a real process's start time) as
// "in the future", and Advance makes the waits a test skips (a quiet
// window) pass at once.
//
// Use it where the code under test compares the clock with such kernel
// times; state-machine tests whose every time input is fake keep a frozen
// NewClock(testkit.Epoch). A deadline sent to another process (an ipc
// deadline) is real time whatever the clock (TESTPLAN §1.4, D77).
func NewRealClock() *Clock

// Advance moves both readings forward by d.
func (c *Clock) Advance(d time.Duration)

// Mono implements platform.Clock.
func (c *Clock) Mono() time.Duration

// Now implements platform.Clock.
func (c *Clock) Now() time.Time

// Sleep simulates system sleep: wall advances by d, monotonic does not.
func (c *Clock) Sleep(d time.Duration)

// StepWall moves only the wall clock (NTP step; may be negative).
func (c *Clock) StepWall(d time.Duration)

// Procs is a mutable fake process table.
type Procs struct {
	// contains filtered or unexported fields
}

// NewProcs returns an empty table.
func NewProcs() *Procs

// Add inserts or replaces a process (state running unless set).
func (p *Procs) Add(info platform.ProcInfo)

// Alive implements platform.ProcTable.
func (p *Procs) Alive(id platform.ProcID) bool

// Cwd implements platform.ProcTable.
func (p *Procs) Cwd(id platform.ProcID) (string, error)

// Exit marks pid as exited (removed) or, with zombie, as a zombie.
func (p *Procs) Exit(pid int, zombie bool)

// List implements platform.ProcTable.
func (p *Procs) List() ([]platform.ProcInfo, error)

// Lookup implements platform.ProcTable.
func (p *Procs) Lookup(pid int) (platform.ProcInfo, error)

// OpenFilesUnder implements platform.ProcTable.
func (p *Procs) OpenFilesUnder(ctx context.Context, dirs []string) ([]platform.Holder, error)

// Reuse replaces pid with a new incarnation that has a different start time.
func (p *Procs) Reuse(pid int, startUS int64, exe string)

// SetCwd sets the working directory Cwd reports for pid ("" = unknown).
func (p *Procs) SetCwd(pid int, cwd string)

// SetErr makes every later call of op (OpLookup, OpList, OpCwd or
// OpOpenFilesUnder) fail with an error wrapping err, until SetErr(op, nil).
// It models an unreadable process table, a TCC denial or a missing lsof, so
// tests can check that callers read such failures as "live" (HA9, R11). Any
// other op panics: a misspelt op would silently inject nothing.
func (p *Procs) SetErr(op string, err error)

// SetOpenFiles sets the absolute paths pid holds open (OpenFilesUnder).
func (p *Procs) SetOpenFiles(pid int, paths ...string)
```

### `internal/ipc`

- Owner: **G2 daemon** · layer 3 · production
- May import (module): `internal/paths`, `internal/fsx`, `internal/platform`
- May import (third party): stdlib, `github.com/awnumar/memguard`, `golang.org/x/sys/unix`
- Tests: unit: framing limits, secret frames never JSON, ExitCode table; integration: socket squat and wrong executable rejected before any secret is sent (TESTPLAN SEC-11), stale socket handling, two concurrent Listen (one wins), PeerSameExecutable gate on every op that requires it

> Package ipc is the daemon protocol: length-prefixed frames (JSON control
> frames, binary secret frames), the request/response structs, the
> mutually-authenticated client, and the server-side listener used by
> internal/agent (SPEC §13; D4, D6, D39).
>
> Wire format: every frame is
>
> 	uint32 big-endian length (of kind+payload) | 1 byte kind | payload
>
> with kind 'J' (a JSON Request or Response) or 'S' (a secret blob that
> belongs to the preceding JSON frame, which states how many follow). Frames
> are at most MaxFrame bytes. Secrets (passphrases, PINs, per-capsule file
> keys) only ever travel in 'S' frames, are read into caller-owned buffers
> that are wiped, and are never JSON strings (D6). No operation returns an
> identity; Keys returns per-capsule file keys only to a verified precinto
> peer for logged capsules of unlocked vaults (D39).
>
> Client authentication of the server (D6): before sending anything, the
> client checks that RunDir is a directory owned by the uid with mode 0700
> and no symlink, connects, reads the server's peer credentials, and
> requires the server pid's executable to be the same file (dev+inode) as
> its own. The server checks the peer uid on every connection and requires
> a peer that runs the same executable (Conn.PeerSameExecutable) for keys,
> unlock, vault_create, factor_add, vault_repair and policy confirmation,
> for registrations with Wrapper=true, and for Input/Enter activity (whose
> peer must also be the session's registered wrapper, D54) (SPEC §13.2,
> §13.3).
>
> On linux (D65) every hardened precinto process is non-dumpable, so its
> /proc/<pid>/exe cannot be read and the executable check is best effort
> in both directions. The client requires of a hardened daemon the peer
> uid (SO_PEERCRED), that the peer pid holds the exclusive flock on
> run/agent.lock (/proc/locks, matched by inode) and the client's own
> kernel name (comm); the daemon requires of a hardened client the peer
> uid and the same comm (clients hold no lock), and re-verifies the peer
> incarnation for keys and unlock. This stops accidents and naive
> squatters, not a same-uid process that kills the daemon and takes the
> lock under a binary named like precinto (SPEC §19); darwin keeps the full
> executable check both ways.
>
> The daemon never trusts identity facts from a client: requests carry
> pids, which the daemon measures itself (SPEC §9.1), and prompt origins,
> which only the daemon computes (D54).

```go
// Protocol constants.
const (
	Version  = 1
	MaxFrame = 1 << 20

	// GateBudget is the total time a hook may spend dialing and asking the
	// daemon (SPEC §14.2). On expiry the hook fails closed for managed
	// sessions.
	GateBudget = 150 * time.Millisecond
)

// Key-release purposes (KeysReq.Purpose). The agent-context rules of D28
// and D59 depend on them.
const (
	PurposeRestore    = "restore"     // targeted restores: wrapper launch, the daemon's post-unlock restore worker, restore --root/--session
	PurposeRestoreAll = "restore-all" // precinto restore --all
	PurposeOpen       = "open"        // precinto open
	PurposeCat        = "cat"         // precinto cat (TTY or --to FILE)
	PurposeList       = "list"        // ls titles
)

// Attention codes: one kebab-case vocabulary shared by `status` and
// `doctor` (internal/doctor reuses these constants as check codes).
const (
	AttnUnsealed        = "unsealed"          // plaintext of a locked folder, with reasons (§17)
	AttnHoldCapped      = "hold-capped"       // weak liveness holds beyond hold_cap (S14)
	AttnHistoryPending  = "history-pending"   // protected lines still in history.jsonl (§19)
	AttnPendingPolicy   = "pending-policy"    // weakening config edits awaiting confirmation (D48)
	AttnPolicyTampered  = "policy-tampered"   // state/policy.pinned failed its MAC (D55)
	AttnQuarantine      = "quarantine"        // capsules without provenance (D8)
	AttnRecoveryTested  = "recovery-tested"   // recovery key never tested (D7)
	AttnUnhardenedBuild = "unhardened-build"  // not signed with hardened runtime (S15)
	AttnCodexHooksTrust = "codex-hooks-trust" // Codex has not trusted precinto's hooks (UX10)
	AttnCodexWrongHome  = "codex-wrong-home"  // Codex wrote a protected folder's history to the user's home (HA1)
	AttnConflict        = "conflict"          // kept-both copies awaiting precinto resolve (D11)
	AttnUngatedSession  = "ungated-session"   // a session in a folder runs without a working gate (D52)
	AttnVaultTampered   = "vault-tampered"    // recipients MAC/tripwire failed: sealing paused; fix: precinto vault repair (D53)
	AttnExposed         = "exposed-capsules"  // capsules sealed to a foreign recipient set (D5 audit)
)

// MaxKeysPerRequest bounds a keys request: it names at most this many
// capsules (bad_request otherwise). Clients batch and destroy each file key
// as soon as its capsule is decrypted, so locked memory stays small.
const MaxKeysPerRequest = 256

// ErrNoDaemon is returned by Dial when no daemon listens and autostart is
// off or failed.
var ErrNoDaemon = errors.New("ipc: precinto agent is not running")

// ErrUntrustedServer is returned by Dial when the socket directory or the
// server executable fails mutual authentication (D6).
var ErrUntrustedServer = errors.New("ipc: daemon identity mismatch; run precinto agent --restart")

// WriteFrame writes one frame.
func WriteFrame(w io.Writer, kind FrameKind, payload []byte) error

// ActivityKind is a session activity signal.
type ActivityKind string

// Activity kinds. Only two kinds move the idle clock (D23, D54): Input and
// Enter, accepted only from a peer that runs the same executable and whose
// measured ProcID equals the session's registered wrapper (others are
// dropped); and Prompt, only when the origin the daemon itself computed at
// gate time for (sid, prompt/turn id) was OriginHuman.
const (
	ActInput        ActivityKind = "input"        // wrapper: human keystrokes (filtered, rate-limited)
	ActEnter        ActivityKind = "enter"        // wrapper: an Enter keystroke reached the PTY (D37)
	ActPrompt       ActivityKind = "prompt"       // UserPromptSubmit allowed; matched to the gate's recorded origin
	ActTool         ActivityKind = "tool"         // Pre/PostToolUse
	ActStop         ActivityKind = "stop"         // Stop: turn ended
	ActStopFailure  ActivityKind = "stop_failure" // StopFailure
	ActInterrupt    ActivityKind = "interrupt"    // Codex Interrupt
	ActIdlePrompt   ActivityKind = "idle_prompt"  // Notification(idle_prompt): clears busy, no idle reset (HA7)
	ActPermission   ActivityKind = "permission"   // waiting on a permission/elicitation: counts as idle
	ActCompactBegin ActivityKind = "compact_begin"
	ActCompactEnd   ActivityKind = "compact_end"
	ActSessionEnd   ActivityKind = "session_end"
)

// ActivityReq reports activity; fire-and-forget is allowed. It carries no
// origin: the daemon uses only the origin it computed itself at gate time
// (D54), and accepts Input/Enter only from the verified wrapper peer.
type ActivityReq struct {
	Harness  string       `json:"harness"`
	SID      string       `json:"sid"`
	Kind     ActivityKind `json:"kind"`
	PromptID string       `json:"prompt_id,omitempty"`
	TurnID   string       `json:"turn_id,omitempty"`
	At       time.Time    `json:"at"` // the client's time of the activity, informational: the daemon times activity with its own clock (D54, D77)
}

// Attention is one "needs attention" item (UX22).
type Attention struct {
	Code    string `json:"code"` // one of the Attn* constants
	Folder  string `json:"folder,omitempty"`
	Count   int    `json:"count,omitempty"`
	PID     int    `json:"pid,omitempty"`
	Detail  string `json:"detail,omitempty"`
	Fix     string `json:"fix,omitempty"`     // the command that fixes it, e.g. "precinto vault repair --root ~/work/acme"
	Harness string `json:"harness,omitempty"` // {harness} of C9.ungated
}

// CapsuleRef names one capsule for key release.
type CapsuleRef struct {
	Path string `json:"path"` // relative to CapsulesDir
}

// Client is a connection to the daemon. Not safe for concurrent requests.
type Client struct {
	// contains filtered or unexported fields
}

// Dial authenticates the daemon (D6) and performs Hello. With Autostart it
// starts the daemon under run/agent.lock when absent and waits for it.
func Dial(ctx context.Context, o DialOptions) (*Client, error)

// Activity reports activity.
func (c *Client) Activity(ctx context.Context, r ActivityReq) error

// Close closes the connection.
func (c *Client) Close() error

// FactorAdd enrolls a factor in every vault.
func (c *Client) FactorAdd(ctx context.Context, r FactorAddReq, ui UIHandler) error

// Gate asks for a gate decision (answered from an in-memory snapshot).
func (c *Client) Gate(ctx context.Context, r GateReq) (GateResp, error)

// Keys requests file keys; denied capsules are listed in the response.
func (c *Client) Keys(ctx context.Context, r KeysReq) (*KeySet, KeysResp, error)

// Lock locks folders (and optionally ends sessions).
func (c *Client) Lock(ctx context.Context, r LockReq) (LockResp, error)

// Policy lists or confirms pending weakening changes.
func (c *Client) Policy(ctx context.Context, r PolicyReq) (PolicyResp, error)

// Register announces a harness process.
func (c *Client) Register(ctx context.Context, r RegisterReq) error

// Shutdown asks the daemon to wipe keys and exit.
func (c *Client) Shutdown(ctx context.Context) error

// Status returns the daemon status.
func (c *Client) Status(ctx context.Context) (StatusResp, error)

// Subscribe streams events; the channel closes on disconnect, which
// wrappers treat as a lock (SPEC §15.3). The stream starts with one locked
// or unlocked event per subscribed folder (D71).
func (c *Client) Subscribe(ctx context.Context, r SubscribeReq) (<-chan Event, error)

// Unlock requests an unlock and relays UI prompts to ui until the final
// response.
func (c *Client) Unlock(ctx context.Context, r UnlockReq, ui UIHandler) (UnlockResp, error)

// Unregister removes a wrapper registration.
func (c *Client) Unregister(ctx context.Context, r UnregisterReq) error

// VaultCreate creates the per-root vault (UI may be relayed for
// passphrase factors).
func (c *Client) VaultCreate(ctx context.Context, r VaultCreateReq, ui UIHandler) error

// VaultRepair repairs a tampered vault (D53). recovery, when r.UseRecovery
// is set, is sent in one 'S' frame and destroyed by the caller afterwards;
// factor prompts are relayed to ui.
func (c *Client) VaultRepair(ctx context.Context, r VaultRepairReq, recovery *memguard.LockedBuffer, ui UIHandler) (VaultRepairResp, error)

// Code is a machine-readable error code; ExitCode maps it to SPEC §16.2.
type Code string

// Error codes.
const (
	CodeLocked       Code = "locked"        // exit 3
	CodeUnauthorized Code = "unauthorized"  // exit 3
	CodeAgentContext Code = "agent_context" // exit 3 (D28)
	CodeCancelled    Code = "cancelled"     // exit 3
	CodeBadSecret    Code = "bad_secret"    // exit 3: wrong passphrase or recovery key (vault.ErrBadSecret, C2.badsecret)
	CodeNoUI         Code = "no_ui"         // exit 3 (D27)
	CodeRateLimited  Code = "rate_limited"  // exit 3 (D27)
	CodeLive         Code = "live"          // exit 4
	CodeVerify       Code = "verify"        // exit 5 (MAC mismatch, recipients changed, repair check failed)
	CodeBadRequest   Code = "bad_request"   // exit 2
	CodeVersion      Code = "version"       // exit 1
	CodeNotLogged    Code = "not_logged"    // exit 5 (provenance, D8)
	CodeInternal     Code = "internal"      // exit 1
)

// Conn is one accepted connection.
type Conn struct {
	// contains filtered or unexported fields
}

// Close closes the connection.
func (c *Conn) Close() error

// Peer returns the verified peer credentials.
func (c *Conn) Peer() platform.Peer

// PeerSameExecutable reports whether the peer runs this binary (dev+inode,
// D6). Required for keys, unlock, vault_create, factor_add, vault_repair,
// policy confirmation, wrapper registrations and Input/Enter activity
// (SPEC §13.2, D39, D54).
func (c *Conn) PeerSameExecutable() bool

// ReadRequest reads the next JSON request and its secret frames into
// locked buffers.
func (c *Conn) ReadRequest() (Request, []*memguard.LockedBuffer, error)

// WriteResponse writes a response followed by its secret frames (each
// buffer is written then left for the caller to destroy).
func (c *Conn) WriteResponse(r Response, secrets ...*memguard.LockedBuffer) error

// DialOptions configures Dial.
type DialOptions struct {
	Layout    paths.Layout
	Client    string        // Hello.Client
	Timeout   time.Duration // total dial+hello budget (hooks: GateBudget)
	Autostart bool          // start `<Exe> agent` detached if absent (never for the hook fast path)
	Exe       string        // absolute path of the precinto binary for autostart
	Env       []string      // allowlisted environment for the autostarted daemon
	// Insecure skips the executable identity check; only honoured in
	// -tags testing builds (tests that run the agent in-process).
	Insecure bool
}

// Error is the error object of a Response.
type Error struct {
	Code Code   `json:"code"`
	Msg  string `json:"msg"` // user-facing, from the ui catalog; never OS error text
}

// Error implements error.
func (e *Error) Error() string

// ExitCode maps the error to the CLI exit codes of SPEC §16.2.
func (e *Error) ExitCode() int

// Event is pushed on a subscription.
type Event struct {
	Kind     EventKind `json:"kind"`
	RootIDs  []string  `json:"root_ids,omitempty"`
	SIDs     []string  `json:"sids,omitempty"`
	Reason   string    `json:"reason,omitempty"` // ui.Reason
	Message  string    `json:"message,omitempty"`
	At       time.Time `json:"at"`
	Deadline time.Time `json:"deadline,omitempty"`
	Busy     bool      `json:"busy,omitempty"`
	// Factors are the folder's enrolled factor kinds in unlock order ("se",
	// "plugin", "passphrase"; never "recovery"), on locked, unlocked and
	// expiring events (ui.FactorName names one for {factor}).
	Factors []string `json:"factors,omitempty"`
}

// EventKind is a lock event pushed to subscribers.
type EventKind string

// Event kinds.
const (
	EventLocked   EventKind = "locked"
	EventUnlocked EventKind = "unlocked"
	// EventEnd is sent only on the subscriptions of wrappers whose session
	// the daemon ends (registration wrapper ProcID = subscribing peer), with
	// SIDs when known (D71): end these sessions now (hard lock).
	EventEnd       EventKind = "end"
	EventExpiring  EventKind = "expiring"
	EventHeartbeat EventKind = "heartbeat" // every 1 s; 2 s without one ⇒ wrapper locks locally
)

// FactorAddReq enrolls a factor in every vault (all must be unlocked).
type FactorAddReq struct {
	Kind         string `json:"kind"`
	Recipient    string `json:"recipient,omitempty"`
	IdentityStub string `json:"identity_stub,omitempty"`
	PluginPath   string `json:"plugin_path,omitempty"`
	// PresencePolicy is a plugin factor's presence policy ("touch-always",
	// "touch-cached", "pin-always", "pin-once", "tpm-pin"); "" requires
	// NoPresenceAck (S10, vault.FactorSpec).
	PresencePolicy string `json:"presence_policy,omitempty"`
	NoPresenceAck  bool   `json:"no_presence_ack,omitempty"`
}

// FrameKind tags a frame.
type FrameKind byte

// Frame kinds.
const (
	FrameJSON   FrameKind = 'J'
	FrameSecret FrameKind = 'S'
)

// ReadFrame reads one frame into buf (grown up to MaxFrame) and returns the
// payload slice aliasing buf; callers wipe buf after secret frames.
func ReadFrame(r io.Reader, buf []byte) (FrameKind, []byte, error)

// GateReq asks whether a hook event may proceed. The daemon computes the
// root set itself from the ledger and the facts below; Roots is advisory
// (HA10). The daemon never trusts a ProcID from a client: it measures PID
// itself (SPEC §9.1).
type GateReq struct {
	Harness    string   `json:"harness"` // label from argv
	Host       string   `json:"host"`    // detected real host (HA21, D56)
	Event      string   `json:"event"`   // harness event name
	SID        string   `json:"sid"`
	PromptID   string   `json:"prompt_id,omitempty"`
	TurnID     string   `json:"turn_id,omitempty"`
	Cwd        string   `json:"cwd"`
	ProjectDir string   `json:"project_dir,omitempty"` // CLAUDE_PROJECT_DIR
	Paths      []string `json:"paths,omitempty"`       // absolute tool paths / added dirs
	Roots      []string `json:"roots,omitempty"`       // root ids the hook computed
	ToolName   string   `json:"tool_name,omitempty"`
	Trigger    string   `json:"trigger,omitempty"` // PreCompact manual|auto
	PID        int      `json:"pid,omitempty"`     // harness pid (CLAUDE_PID, or the nearest codex ancestor); measured again by the daemon
	CodexHome  string   `json:"codex_home,omitempty"`
}

// GateResp is the daemon's decision; texts come from the ui catalog and are
// built from verified data (D27).
type GateResp struct {
	Verdict        Verdict      `json:"verdict"`
	Reason         string       `json:"reason,omitempty"` // ui.Reason code
	UserMessage    string       `json:"user_message,omitempty"`
	ModelMessage   string       `json:"model_message,omitempty"` // PreToolUse deny text addressed to the model
	State          string       `json:"state"`                   // "unlocked" | "locked" | "paused"
	RootIDs        []string     `json:"root_ids,omitempty"`
	Origin         PromptOrigin `json:"origin,omitempty"`          // computed by the daemon and recorded for (sid, prompt id) (D54)
	UnlockEligible bool         `json:"unlock_eligible,omitempty"` // a hook may attempt a GUI unlock now (D27, D37)
}

// Hello opens every connection.
type Hello struct {
	Client  string `json:"client"` // "hook" | "cli" | "wrapper" | "sweep" | "shell"
	Version string `json:"version"`
}

// HelloResp answers Hello.
type HelloResp struct {
	Version  string    `json:"version"`
	PID      int       `json:"pid"`
	Started  time.Time `json:"started"`
	Protocol int       `json:"protocol"`
}

// KeyGrant describes one released key; the key itself follows in an 'S'
// frame, in Granted order.
type KeyGrant struct {
	Path    string `json:"path"`
	VaultID string `json:"vault_id"`
}

// KeySet holds released file keys in locked buffers. It implements
// sweep.FileKeys directly (asserted in cmd/precinto).
type KeySet struct {
	// contains filtered or unexported fields
}

// Destroy wipes every key (also called on any lock event).
func (k *KeySet) Destroy()

// Key returns the file key of a capsule path relative to CapsulesDir.
func (k *KeySet) Key(path string) (*memguard.LockedBuffer, bool)

// KeysReq asks for per-capsule file keys (D39).
type KeysReq struct {
	Capsules []CapsuleRef `json:"capsules"` // at most MaxKeysPerRequest
	Purpose  string       `json:"purpose"`  // one of the Purpose* constants
	// AgentMarkers are the client's own paths.AgentMarkers: a
	// self-restricting claim. The daemon unions it with the ancestry and
	// no-controlling-terminal rules it measures itself and never treats an
	// empty list as proof of a human (D28, D59).
	AgentMarkers []string `json:"agent_markers,omitempty"`
}

// KeysResp answers Keys.
type KeysResp struct {
	Granted []KeyGrant      `json:"granted"`
	Denied  map[string]Code `json:"denied,omitempty"`
}

// Listener is the daemon side: it owns run/agent.lock for its lifetime.
type Listener struct {
	// contains filtered or unexported fields
}

// Listen verifies RunDir (fsx.CheckPrivateDir), takes an exclusive flock on
// AgentLock (ErrLocked if another daemon runs), unlinks a stale socket only
// while holding it, and binds under umask 0177 (socket mode 0600).
func Listen(l paths.Layout) (*Listener, error)

// Accept waits for a connection and verifies the peer uid.
func (l *Listener) Accept() (*Conn, error)

// Close unlinks the socket (still holding the lock) and releases the lock.
func (l *Listener) Close() error

// LockReq locks folders.
type LockReq struct {
	RootIDs   []string `json:"root_ids,omitempty"`
	All       bool     `json:"all,omitempty"` // default scope of `precinto lock` (UX16)
	End       bool     `json:"end,omitempty"` // also end sessions (alias --hard)
	Force     bool     `json:"force,omitempty"`
	LetFinish bool     `json:"let_finish,omitempty"`
}

// LockResp reports the result; a lock always completes (I15).
type LockResp struct {
	Locked   []string `json:"locked"`
	Ended    []string `json:"ended,omitempty"`    // session ids
	Unsealed []string `json:"unsealed,omitempty"` // unit keys still plaintext, with reasons in status
}

// Op names a request.
type Op string

// Operations (SPEC §13.3).
const (
	OpHello       Op = "hello"
	OpStatus      Op = "status"
	OpGate        Op = "gate"
	OpActivity    Op = "activity"
	OpRegister    Op = "register"
	OpUnregister  Op = "unregister"
	OpUnlock      Op = "unlock"
	OpUIReply     Op = "ui_reply" // client → daemon answer to a UIRequest during Unlock
	OpLock        Op = "lock"
	OpKeys        Op = "keys"
	OpSubscribe   Op = "subscribe"
	OpVaultCreate Op = "vault_create"
	OpFactorAdd   Op = "factor_add"
	OpVaultRepair Op = "vault_repair" // rewrite a tampered recipient set after a TTY unwrap (D53)
	OpPolicy      Op = "policy"       // confirm pending weakening changes (D48)
	OpShutdown    Op = "shutdown"
)

// PolicyReq confirms or lists pending weakening config changes (D48).
type PolicyReq struct {
	Confirm bool `json:"confirm"`
}

// PolicyResp lists pending changes.
type PolicyResp struct {
	Pending []string `json:"pending"`
}

// PromptOrigin classifies a UserPromptSubmit (D23, D26, D37, D54). Only the
// daemon computes it (wrapper Enter timestamps, system HID idle); a
// client never supplies one.
type PromptOrigin string

// Prompt origins.
const (
	OriginHuman     PromptOrigin = "human"
	OriginAutomated PromptOrigin = "automated"
	OriginUnknown   PromptOrigin = "unknown" // HID idle unreadable: never moves the idle clock, never raises a dialog (D54)
)

// RegisterReq announces a live harness process. The daemon measures the
// ProcID itself from PID and verifies the executable against the harness
// inventory before accepting (S14). Wrapper=true is accepted only from a
// peer that runs the same executable and whose measured ProcID is
// WrapperPID (the wrapper registers itself); otherwise the registration is
// recorded as unwrapped and Input/Enter activity for it is dropped (D54).
type RegisterReq struct {
	Harness    string   `json:"harness"`
	SID        string   `json:"sid,omitempty"` // empty for a wrapper launch before the sid is known
	PID        int      `json:"pid"`
	Cwd        string   `json:"cwd"`
	ProjectDir string   `json:"project_dir,omitempty"`
	RootIDs    []string `json:"root_ids,omitempty"`
	Wrapper    bool     `json:"wrapper"`
	WrapperPID int      `json:"wrapper_pid,omitempty"` // must equal the peer's own pid
	TTY        string   `json:"tty,omitempty"`         // the session's terminal (hook-dialog OSC 9 notice, D60; TTY scrub)
	ConfigDir  string   `json:"config_dir,omitempty"`
	Version    string   `json:"version,omitempty"`
	Background bool     `json:"background,omitempty"`
	TermITerm  bool     `json:"term_iterm,omitempty"`
}

// Request is one JSON control frame from a client. Exactly one payload
// pointer matching Op is set. Secrets frames that follow are counted by
// Secrets.
type Request struct {
	V           int             `json:"v"`
	ID          uint64          `json:"id"`
	Op          Op              `json:"op"`
	Secrets     int             `json:"secrets,omitempty"`
	Hello       *Hello          `json:"hello,omitempty"`
	Gate        *GateReq        `json:"gate,omitempty"`
	Activity    *ActivityReq    `json:"activity,omitempty"`
	Register    *RegisterReq    `json:"register,omitempty"`
	Unregister  *UnregisterReq  `json:"unregister,omitempty"`
	Unlock      *UnlockReq      `json:"unlock,omitempty"`
	UIReply     *UIReply        `json:"ui_reply,omitempty"`
	Lock        *LockReq        `json:"lock,omitempty"`
	Keys        *KeysReq        `json:"keys,omitempty"`
	Subscribe   *SubscribeReq   `json:"subscribe,omitempty"`
	VaultCreate *VaultCreateReq `json:"vault_create,omitempty"`
	FactorAdd   *FactorAddReq   `json:"factor_add,omitempty"`
	VaultRepair *VaultRepairReq `json:"vault_repair,omitempty"`
	Policy      *PolicyReq      `json:"policy,omitempty"`
}

// Response is one JSON control frame from the daemon. During Unlock the
// daemon may send Responses carrying UI (a prompt to relay) before the final
// one; Subscribe streams Responses carrying Event.
type Response struct {
	V       int              `json:"v"`
	ID      uint64           `json:"id"`
	OK      bool             `json:"ok"`
	Err     *Error           `json:"err,omitempty"`
	Secrets int              `json:"secrets,omitempty"`
	Hello   *HelloResp       `json:"hello,omitempty"`
	Status  *StatusResp      `json:"status,omitempty"`
	Gate    *GateResp        `json:"gate,omitempty"`
	Unlock  *UnlockResp      `json:"unlock,omitempty"`
	Lock    *LockResp        `json:"lock,omitempty"`
	Keys    *KeysResp        `json:"keys,omitempty"`
	UI      *UIRequest       `json:"ui,omitempty"`
	Event   *Event           `json:"event,omitempty"`
	Repair  *VaultRepairResp `json:"repair,omitempty"`
	Policy  *PolicyResp      `json:"policy,omitempty"`
}

// SessionStatus is one live or paused session in status.
type SessionStatus struct {
	Harness    string          `json:"harness"`
	SID        string          `json:"sid"`
	Proc       platform.ProcID `json:"proc"`
	RootIDs    []string        `json:"root_ids"`
	State      string          `json:"state"` // "running" | "paused" | "ending"
	Busy       bool            `json:"busy"`
	Wrapper    bool            `json:"wrapper"`
	Background bool            `json:"background"`
	HooksSeen  bool            `json:"hooks_seen"`
	Registered bool            `json:"registered"` // false: found by the process-table scan only (D52, D57)
	TTY        string          `json:"tty,omitempty"`
	Version    string          `json:"version,omitempty"` // harness version from register (SPEC §16.4 AGENTS line)
}

// StatusResp is the daemon side of `precinto status` (the CLI adds on-disk
// facts; schema v1 in SPEC §16.4).
type StatusResp struct {
	Version       string          `json:"version"`
	PID           int             `json:"pid"`
	Started       time.Time       `json:"started"`
	Vaults        []VaultStatus   `json:"vaults"`
	Sessions      []SessionStatus `json:"sessions"`
	Attention     []Attention     `json:"attention"`
	ScreenWatch   bool            `json:"screen_watch"`
	LastSweep     time.Time       `json:"last_sweep,omitempty"`
	PendingPolicy []string        `json:"pending_policy,omitempty"`
}

// SubscribeReq subscribes to events for roots and/or a session.
type SubscribeReq struct {
	RootIDs []string `json:"root_ids"`
	SID     string   `json:"sid,omitempty"`
	Wrapper bool     `json:"wrapper"`
}

// UIHandler is the client side of relayed UI during Unlock.
type UIHandler interface {
	Display(msg string) error
	Secret(prompt string) (*memguard.LockedBuffer, error)
	Confirm(prompt, yes, no string) (bool, error)
}

// UIKind is a relayed prompt kind.
type UIKind string

// UI kinds.
const (
	UIDisplay UIKind = "display"
	UISecret  UIKind = "secret"
	UIConfirm UIKind = "confirm"
	UIWait    UIKind = "wait"
)

// UIReply answers a UIRequest; a secret answer follows in one 'S' frame.
type UIReply struct {
	Seq       int  `json:"seq"`
	OK        bool `json:"ok"` // false = cancelled
	Choice    bool `json:"choice,omitempty"`
	HasSecret bool `json:"has_secret,omitempty"`
}

// UIRequest is a prompt the daemon relays to the client during Unlock.
type UIRequest struct {
	Seq    int    `json:"seq"`
	Kind   UIKind `json:"kind"`
	Prompt string `json:"prompt"`
	Yes    string `json:"yes,omitempty"`
	No     string `json:"no,omitempty"`
}

// UnlockReq asks the daemon to unwrap vault identities with user presence.
// The daemon runs the factor (age plugin or scrypt) itself and relays UI
// through UIRequest frames to this connection (D4).
type UnlockReq struct {
	RootIDs     []string      `json:"root_ids,omitempty"`
	All         bool          `json:"all,omitempty"`    // every root (one prompt per root, D40)
	Global      bool          `json:"global,omitempty"` // the global vault (D1)
	Factor      string        `json:"factor,omitempty"`
	TTL         time.Duration `json:"ttl,omitempty"` // clamped to min(max_unlock, 24h) (S8)
	Extend      bool          `json:"extend,omitempty"`
	TTY         bool          `json:"tty"`       // the client can prompt on a terminal
	Confirmed   bool          `json:"confirmed"` // the client obtained typed confirmation for multi-root
	FromHook    bool          `json:"from_hook,omitempty"`
	SID         string        `json:"sid,omitempty"`          // hook: the session requesting it
	Deadline    time.Time     `json:"deadline"`               // real time (the client's time.Now): the daemon bounds the unlock with it on its own clock; never from a test clock (D77)
	ConfirmDiff bool          `json:"confirm_diff,omitempty"` // also confirm pending policy changes (D48)
	// AgentMarkers are the client's own paths.AgentMarkers: a
	// self-restricting claim. The daemon unions it with the ancestry and
	// no-controlling-terminal rules it measures itself and never treats an
	// empty list as proof of a human (D28, D59).
	AgentMarkers []string `json:"agent_markers,omitempty"`
	// Test is a factor test (precinto factor test): unwrap with Factor and
	// verify, then drop; no grant, no restore worker, no policy re-pin.
	Test bool `json:"test,omitempty"`
}

// UnlockResp lists what was unlocked.
type UnlockResp struct {
	Unlocked []string  `json:"unlocked"` // vault ids
	Until    time.Time `json:"until"`    // absolute deadline
	Pending  []string  `json:"pending,omitempty"`
}

// UnregisterReq removes a wrapper registration after the child exited.
type UnregisterReq struct {
	Harness string `json:"harness"`
	SID     string `json:"sid,omitempty"`
	PID     int    `json:"pid"`
}

// VaultCreateReq creates the per-root vault at protect time (D1).
type VaultCreateReq struct {
	RootID   string `json:"root_id"`
	RootPath string `json:"root_path"`
}

// VaultRepairReq asks the daemon to repair a vault whose recipient set
// failed the MAC or tripwire check (`precinto vault repair`, D53). Only from
// a same-executable peer with a TTY, never from an agent context. With
// UseRecovery the recovery identity follows in one 'S' frame (typed by the
// user); otherwise the daemon unwraps with a factor through relayed UI.
type VaultRepairReq struct {
	VaultID     string `json:"vault_id"` // root id or "global"
	UseRecovery bool   `json:"use_recovery,omitempty"`
	// Confirmed false is a dry run: unwrap (presence), genuineness check,
	// diff in VaultRepairResp, nothing written; the identity stays bound to
	// that connection for at most 120 s and any lock wipes it. true writes
	// (and unwraps again only on another connection or after that).
	Confirmed bool `json:"confirmed"`
}

// VaultRepairResp reports a repair.
type VaultRepairResp struct {
	RecipientChanged bool     `json:"recipient_changed"`
	RecoveryChanged  bool     `json:"recovery_changed"`
	Exposed          []string `json:"exposed,omitempty"` // capsule paths sealed since last_audit to a foreign recipient set
}

// VaultStatus is one folder (vault) in status.
type VaultStatus struct {
	VaultID      string    `json:"vault_id"`
	RootPath     string    `json:"root_path,omitempty"`
	State        string    `json:"state"` // "locked" | "unlocking" (a single-flight unlock is in progress) | "unlocked"
	Reason       string    `json:"reason,omitempty"`
	Since        time.Time `json:"since"`
	IdleDeadline time.Time `json:"idle_deadline,omitempty"`
	AbsDeadline  time.Time `json:"abs_deadline,omitempty"`
	LastHuman    time.Time `json:"last_human,omitempty"`
	// Factors are the folder's enrolled factor kinds in unlock order ("se",
	// "plugin", "passphrase"; never "recovery").
	Factors []string `json:"factors,omitempty"`
}

// Verdict is a gate decision.
type Verdict string

// Verdicts.
const (
	VerdictAllow Verdict = "allow"
	VerdictBlock Verdict = "block" // prompt / compaction blocked
	VerdictDeny  Verdict = "deny"  // tool or permission denied
)
```

### `internal/agent`

- Owner: **G2 daemon** · layer 7 · production
- May import (module): `internal/ipc`, `internal/vault`, `internal/capsule`, `internal/sweep/capslog`, `internal/sweep/queue`, `internal/sweep/journal`, `internal/config`, `internal/paths`, `internal/platform`, `internal/fsx`, `internal/ledger`, `internal/harness`, `internal/harness/claude`, `internal/ui`, `inventories`
- May import (third party): stdlib, `github.com/awnumar/memguard`
- Tests: unit: Machine exhaustively with a fake clock (idle only on verified human input: wrapper Input/Enter with FromWrapper, Prompt with a recorded human origin; unknown origin never; busy grace, screen-lock hard-after, max_unlock, sleep jump, background exemption, automated prompts never prompt, ungated scan sessions); integration with agenttest: gate fail-closed, activity from a non-wrapper peer dropped, key release scope and provenance, TTL clamp, policy pinning across a daemon restart, vault repair, rate limits, single-flight unlock

> Package agent is the per-user daemon `precinto agent` (SPEC §12, §13):
> the only holder of unwrapped identities (Keyring, D4), the folder/session
> lock state machine (D23–D26), triggers (idle timers, max_unlock,
> screen lock, HID idle, sleep/wake jumps), the gate (answered from an
> atomically swapped in-memory snapshot, never waiting on I/O), relayed
> unlock UI (D4, D27), per-capsule key release (D39), policy pinning (D48),
> session registry and termination (S14, R11, R20), roots.list and the
> verified recipient copies, and the work queue (it spawns
> `precinto sweep|seal|restore` workers; it never seals or restores
> in-process).
>
> Machine is pure (no I/O, no goroutines, injected clock) so it can be
> tested exhaustively with internal/platform/fakeplatform. Run's side
> effects that a test cannot allow (hardening the process, spawning
> workers from Exe, polling the real console, running pinentry) go
> through Options seams that internal/agent/agenttest replaces.
>
> Trust rules: the daemon re-measures every pid a client sends (SPEC
> §9.1), computes prompt origins itself (D54), and acts on signals only
> for ProcID-verified processes it registered or found by its own scan
> (D57).

```go
// Authorize applies the agent-context rules (D28, D59). A peer is in an
// agent context when an ancestor's executable is a known harness or its
// environment carries agent markers; walking stops at the daemon itself, so
// workers the daemon spawned are never agent contexts. For such peers:
// unlocking any root other than the roots of the session it runs in is
// refused (CodeAgentContext, C12.agent, no dialog); key releases of any
// purpose need fresh presence even when the root is unlocked; factor_add,
// vault_repair and policy confirmation are refused. A peer without a
// controlling TTY (setsid, double fork) that is not a daemon worker is
// treated the same way for the explicit content-revealing purposes
// ipc.PurposeRestoreAll, PurposeOpen, PurposeCat and PurposeList (D59).
// purpose is ipc.KeysReq.Purpose for OpKeys, "" otherwise. A nil result
// means allowed (possibly after the presence prompt the caller raises).
func Authorize(peer platform.Peer, ancestry []platform.ProcInfo, op ipc.Op, purpose string, rootIDs []string, sessionRoots []string) *ipc.Error

// ClampTTL returns min(ttl, policy.max_unlock, 24h); ttl<=0 means max_unlock (S8).
func ClampTTL(p config.Policy, ttl time.Duration) time.Duration

// GateFromSnapshot answers a gate query from a published snapshot (what
// the connection handlers use).
func GateFromSnapshot(s *Snapshot, p config.Policy, q GateQuery) ipc.GateResp

// KillGrace returns the SIGTERM→SIGKILL delay for a harness given its
// SessionEnd budget (R20): harness.KillGrace.
func KillGrace(sessionEndBudget time.Duration) time.Duration

// Run is `precinto agent`: Options.Harden (platform.Harden and
// CheckLoaderEnv); ipc.Listen (holding run/agent.lock); treat every vault
// as locked; load the effective policy as the stricter of config.toml and
// state/policy.pinned (D55); spawn one recovery+full sweep worker;
// bootstrap sessions from the ledger and the harness registries; then serve
// requests and triggers until ctx ends or the idle-exit rule fires.
func Run(ctx context.Context, o Options) error

// Action is one effect.
type Action struct {
	Kind     ActionKind
	Vault    string
	RootIDs  []string
	Sessions []SessionInfo
	Event    ipc.Event
	Reason   string // ui.Reason
	// Grace is the SIGTERM→SIGKILL delay for ActEndSessions:
	// max(8s, SessionEnd budget + 6s), capped at 70s (R20).
	Grace time.Duration
}

// ActionKind is an effect the daemon must perform after Apply.
type ActionKind string

// Actions.
const (
	ActWipeKey        ActionKind = "wipe_key"         // Keyring.Drop(Vault) — immediate, never deferred (I15)
	ActPublish        ActionKind = "publish"          // send Event to subscribers
	ActSealRoots      ActionKind = "seal_roots"       // spawn `precinto sweep --lock --root …`
	ActEndSessions    ActionKind = "end_sessions"     // wrapped: EventEnd (the wrapper ends its own PTY/Setsid child); unwrapped Claude (registered or scan-found, D52): ProcID-verified SIGTERM→SIGKILL of the process and its ProcID-verified descendants found by PPID walk, never by session id (D57); background/supervised sessions are never included (D25)
	ActScrubTTY       ActionKind = "scrub_tty"        // after a verified exit (UX13)
	ActRestoreRoots   ActionKind = "restore_roots"    // spawn `precinto restore --background --root …` after unlock (UX12)
	ActNotifyExpiring ActionKind = "notify_expiring"  // 10 min before max_unlock (C8)
	ActWriteRootsList ActionKind = "write_roots_list" // D22
	ActAuditCapsules  ActionKind = "audit_capsules"   // after unlock: recipients_fpr audit since LastAudit (D5)
)

// GateEvent is a normalized gate event.
type GateEvent string

// Gate events.
const (
	GatePrompt     GateEvent = "prompt"     // UserPromptSubmit / beforeSubmitPrompt
	GateTool       GateEvent = "tool"       // PreToolUse
	GateCompact    GateEvent = "compact"    // PreCompact
	GatePermission GateEvent = "permission" // PermissionRequest
	GateStart      GateEvent = "start"      // SessionStart (never blocks; returns context text)
)

// GateQuery is a gate request after root resolution.
type GateQuery struct {
	Event       GateEvent
	SID         string
	RootIDs     []string         // resolved by the daemon: ledger taint ∪ project dir ∪ cwd ∪ paths (HA10)
	Origin      ipc.PromptOrigin // computed by the daemon (wrapper Enter ≤ 3 s before, else HID idle ≤ 5 s), D37
	FromWrapper bool
	Trigger     string // compaction trigger
}

// Input is one event fed to the machine. Connection handlers fill it only
// with facts the daemon verified itself.
type Input struct {
	Kind     InputKind
	Vaults   []string
	All      bool
	SID      string
	PromptID string // prompt_id (Claude) or turn_id (Codex): pairs a Prompt activity with its InGateOrigin
	Session  *SessionInfo
	Activity ipc.ActivityKind
	Origin   ipc.PromptOrigin // InGateOrigin only: computed by the daemon, never taken from a client
	// FromWrapper is set by the connection handler only when the peer passed
	// ipc.Conn.PeerSameExecutable and its measured ProcID equals the
	// session's registered WrapperPID; Input/Enter activity without it is
	// ignored (D54).
	FromWrapper bool
	Busy        bool
	End         bool
	Force       bool
	LetFinish   bool
	TTL         time.Duration
	Extend      bool
	Policy      *config.Policy
	Jump        platform.Jump
}

// InputKind is a state-machine input.
type InputKind string

// Inputs.
const (
	InUnlock         InputKind = "unlock"      // a vault was unwrapped (Vault, TTL, Extend)
	InLock           InputKind = "lock"        // manual lock (Vaults/All, End, Force, LetFinish)
	InActivity       InputKind = "activity"    // ipc.ActivityReq: Input/Enter move the idle clock only with FromWrapper; Prompt only if the recorded origin of (SID, PromptID) is human (D54)
	InGateOrigin     InputKind = "gate_origin" // the origin the daemon computed when answering a prompt gate for (SID, PromptID), enqueued before the gate response is written; consumed by the matching Prompt activity, expires after busy_timeout (D54)
	InRegister       InputKind = "register"    // a harness process registered (Session)
	InUnregister     InputKind = "unregister"  // the process exited
	InUngated        InputKind = "ungated"     // the process-table scan found an unregistered harness process in a root with no hook event or registration within the hook-presence window (Session, D52, D57)
	InBusy           InputKind = "busy"        // registry/hook busy observation (Busy)
	InScreenLocked   InputKind = "screen_locked"
	InScreenUnlocked InputKind = "screen_unlocked" // advisory only: never unlocks (D24, I6)
	InHIDActivity    InputKind = "hid_activity"    // system HID idle reset observed (D37 evidence only)
	InJump           InputKind = "jump"            // wall/monotonic jump ⇒ sleep/wake ⇒ lock (D24)
	InTick           InputKind = "tick"
	InPolicy         InputKind = "policy" // new effective policy (D48)
)

// Machine is the pure lock state machine. Not safe for concurrent use; the
// daemon serializes inputs and publishes Snapshots.
type Machine struct {
	// contains filtered or unexported fields
}

// NewMachine builds a machine with every vault locked.
func NewMachine(p config.Policy, c platform.Clock) *Machine

// Apply consumes one input and returns the actions to perform, in order.
// Rules (SPEC §12): lock transitions are immediate; only verified human
// input moves the idle clock — wrapper Input/Enter with FromWrapper, and
// Prompt activity whose recorded gate origin is human; unknown and
// automated origins never do (D23, D54); busy sessions finish their turn
// up to busy_grace (D24, UX2); background sessions are never signalled
// (D25); automated prompts never raise unlock dialogs (D26); no OS event
// unlocks (I6).
func (m *Machine) Apply(in Input) []Action

// Gate decides a query against the current state.
func (m *Machine) Gate(q GateQuery) ipc.GateResp

// NextDeadline is the earliest time Apply(InTick) must run.
func (m *Machine) NextDeadline() (time.Time, bool)

// Snapshot returns the current state.
func (m *Machine) Snapshot() Snapshot

// Options configures Run.
type Options struct {
	Layout     paths.Layout
	Env        paths.Env
	Exe        string // absolute path of this binary (workers are spawned from it)
	Version    string
	Foreground bool
	Clock      platform.Clock
	Procs      platform.ProcTable
	// IdleExit: exit after this long with no unlocked vault, no subscriber,
	// an empty queue and no pending journal (default 10m, R19).
	IdleExit time.Duration
	// Tick is the trigger polling period (default 3s: screen lock, HID idle,
	// registry busy state, deadlines).
	Tick time.Duration

	// Test seams (internal/agent/agenttest sets them; nil selects the real
	// implementation). Spawn starts `<Exe> sweep|seal|restore` workers
	// (default platform.Spawn); a worker names its folder by the absolute
	// path: `<Exe> sweep --lock --root <abs path>`, `<Exe> restore --root
	// <abs path> --recent N --md --history --background` (the CLI's --root
	// takes a path only). Screen polls the console (default
	// platform.ReadScreen); Harden runs platform.Harden and
	// CheckLoaderEnv (agenttest passes a no-op so the go test binary is
	// never hardened or re-executed); Pinentry runs pinentry for hook-raised
	// unlocks of passphrase/plugin factors (default: the pinentry binary
	// found next to the user's PATH, D4).
	Spawn    func(argv []string, o platform.SpawnOptions) (platform.ProcID, error)
	Screen   func(ctx context.Context) (platform.ScreenState, error)
	Harden   func() error
	Pinentry func(ctx context.Context, desc, prompt string) (*memguard.LockedBuffer, error)
}

// RateLimiter enforces at most n unlock prompts per minute, a backoff after
// a cancel, and a per-root hook cooldown (D27). Unlock is single-flight per
// vault: concurrent requesters share the result.
type RateLimiter struct {
	// contains filtered or unexported fields
}

// NewRateLimiter returns a limiter from policy.
func NewRateLimiter(p config.Policy, c platform.Clock) *RateLimiter

// Allow reports whether a prompt for vault may be raised now (fromHook
// applies the hook cooldown after a cancel).
func (r *RateLimiter) Allow(vault string, fromHook bool) (bool, time.Duration)

// Cancelled records a cancel for vault.
func (r *RateLimiter) Cancelled(vault string, fromHook bool)

// SessionInfo is what the machine knows about a live session.
type SessionInfo struct {
	Harness    string
	SID        string
	Proc       platform.ProcID
	RootIDs    []string        // vault ids of its managed roots
	Wrapper    bool            // registration verified as coming from the wrapper itself (D54)
	WrapperPID platform.ProcID // the wrapper process (measured by the daemon)
	Background bool            // supervised: never terminated by signals (D25)
	TTY        string
	HooksSeen  bool
	Registered bool // false: found only by the process-table scan (D52, D57)
}

// SessionSnapshot is one session's state.
type SessionSnapshot struct {
	Info        SessionInfo
	State       SessionState
	Busy        bool
	BusyAtLock  bool      // was mid-turn when its root locked: tools allowed until Stop or busy_grace (UX2)
	LockedAt    time.Time // when the session became paused
	CompactBusy bool
}

// SessionState is the state of one live session.
type SessionState string

// Session states.
const (
	SessionRunning SessionState = "running" // all its roots unlocked
	SessionPaused  SessionState = "paused"  // some root locked: gated (and overlaid if wrapped)
	SessionEnding  SessionState = "ending"  // termination requested
)

// Snapshot is an immutable copy of the machine state used to answer gates
// without locks or I/O.
type Snapshot struct {
	At       time.Time
	Vaults   map[string]VaultSnapshot
	Sessions map[string]SessionSnapshot // by SID
}

// VaultSnapshot is one vault's state.
type VaultSnapshot struct {
	State        VaultState
	Reason       string
	Since        time.Time
	IdleDeadline time.Time
	AbsDeadline  time.Time
	LastHuman    time.Time
}

// VaultState is the key state of one vault (UX16: two independent state
// machines, vault key state and session state).
type VaultState string

// Vault states.
const (
	VaultLocked   VaultState = "locked"
	VaultUnlocked VaultState = "unlocked"
)
```

### `internal/agent/agenttest`

- Owner: **G2 daemon** · layer 8 · test-only helper (production packages must not import it)
- May import (module): `internal/agent`, `internal/ipc`, `internal/paths`, `internal/platform`, `internal/platform/fakeplatform`, `internal/config`
- May import (third party): stdlib, `github.com/awnumar/memguard`
- Tests: used by G2/G5/G6/G7 tests

> Package agenttest runs a real agent in-process on a throwaway layout with
> a fake clock and process table, for gate, unlock, key-release and lock
> tests of every group (docs/TESTPLAN.md).

```go
// Agent is a running in-process daemon.
type Agent struct {
	Layout paths.Layout
	Clock  *fakeplatform.Clock
	Procs  *fakeplatform.Procs
	// contains filtered or unexported fields
}

// Start runs agent.Run on l in a goroutine and waits until it listens. It
// sets every agent.Options seam: Harden is a no-op (the go test binary is
// never hardened), Spawn records worker argv without executing anything
// (see Spawned), Screen returns the state set with SetScreen (unlocked,
// HID idle unknown by default), and Pinentry is a stub that always fails,
// so no pinentry program can run from a test whatever process table is
// used (the daemon reports vault.ErrNoUI, ipc.CodeNoUI). A nil clock is
// fakeplatform.NewRealClock (a daemon whose caller chose no clock never
// disagrees with real time, D77); a nil procs is an empty table. The
// daemon's state machine runs on clock; the deadlines of requests it
// serves are real time, like a real daemon's (UnlockForTest).
func Start(t testing.TB, l paths.Layout, clock *fakeplatform.Clock, procs *fakeplatform.Procs) *Agent

// Client is a non-fatal dial for fake backends and other goroutines: it
// never calls t.Fatalf, so it is safe after the test ended (it then fails
// with an error). The caller closes the client.
func (a *Agent) Client(ctx context.Context) (*ipc.Client, error)

// Dial returns a client connected to the agent. It calls t.Fatalf on
// failure, so call it from the test goroutine only; other goroutines (fake
// backends) use Client.
func (a *Agent) Dial(t testing.TB) *ipc.Client

// SetScreen sets what the agent's next console poll observes.
func (a *Agent) SetScreen(s platform.ScreenState)

// Spawned returns the argv of every worker the agent asked to spawn, in
// order. Workers name the folder by its absolute path (--root takes a path
// only): `<Exe> sweep --lock --root <abs path>`, `<Exe> restore --root <abs
// path> --recent N --md --history --background`.
func (a *Agent) Spawned() [][]string

// Stop stops the agent and waits for it.
func (a *Agent) Stop()

// UnlockForTest unlocks rootIDs with the recovery factor, answering the
// relayed secret prompt with recoveryKey (test-only; vaulttest
// Fixture.Recovery.String()). It fails the test on any error, so call it
// from the test goroutine.
func (a *Agent) UnlockForTest(t testing.TB, rootIDs []string, recoveryKey string)
```

## G3 harness adapters

### `internal/ledger`

- Owner: **G3 harness adapters** · layer 3 · production
- May import (module): `internal/paths`, `internal/fsx`, `internal/platform`, `internal/config`
- May import (third party): stdlib only
- Tests: unit: fold rules (taint sticky, warm, ByProc after /clear, compaction cleared by Stop/StopFailure/end), Snapshot + Archive keeps events appended after the snapshot, Taint root resolution, content-free lines (hygiene)

> Package ledger records content-free facts about managed sessions: which
> harness process (ProcID measured by precinto) owns which session, the
> directories and paths that made the session managed ("taint", sticky),
> Markdown paths written, compaction in flight, the harness homes used, and
> session end reasons (SPEC §7.0, §9; D18, D19, D20; S6, HA10, IM4).
>
> The ledger never stores prompts, tool input/output, assistant text or
> environment values. A session's ledger file is created only at its first
> managed event, and is moved into the session capsule when the unit is
> sealed (S13).

```go
// Version is the ledger line format.
const Version = 1

// ErrNotFound means no ledger exists for the session.
var ErrNotFound = errors.New("ledger: no such session")

// Taint computes the roots a set of directories and paths touch: every root
// of c containing any of them (deepest first). Hooks pass start cwd,
// CLAUDE_PROJECT_DIR, payload cwd, added dirs and tool paths (HA10).
// Implemented in the scaffold as c.RootsFor.
func Taint(c config.Config, dirsAndPaths ...string) []config.Root

// Event is one JSON line of state/sessions/<harness>/<sid>.jsonl.
type Event struct {
	V              int             `json:"v"`
	T              time.Time       `json:"t"`
	Type           Type            `json:"type"`
	Harness        string          `json:"harness"`
	Host           string          `json:"host,omitempty"` // real host when a Claude-format hook runs elsewhere (HA21)
	SID            string          `json:"sid"`
	Proc           platform.ProcID `json:"proc,omitempty"` // harness process, measured by precinto's own hook/wrapper process: liveness evidence only, never a reason to signal or release keys (SPEC §9.1)
	Wrapper        bool            `json:"wrapper,omitempty"`
	Cwd            string          `json:"cwd,omitempty"`
	ProjectDir     string          `json:"project_dir,omitempty"`
	Transcript     string          `json:"transcript,omitempty"` // as reported (SessionEnd's value is trusted over SessionStart's)
	ConfigDir      string          `json:"config_dir,omitempty"` // CLAUDE_CONFIG_DIR / CODEX_HOME realpath
	TmpDir         string          `json:"tmp_dir,omitempty"`    // payload scratchpad_dir's base, CLAUDE_CODE_TMPDIR
	Source         string          `json:"source,omitempty"`     // SessionStart source
	Reason         string          `json:"reason,omitempty"`     // SessionEnd reason
	Path           string          `json:"path,omitempty"`       // touch/md/dir path (absolute)
	Roots          []string        `json:"roots,omitempty"`      // root ids (taint)
	HarnessVersion string          `json:"harness_version,omitempty"`
	Entrypoint     string          `json:"entrypoint,omitempty"` // cli|sdk-cli|...
	Background     bool            `json:"background,omitempty"` // supervised/background session (D25)
	LeaseKey       string          `json:"lease_key,omitempty"`
}

// Index is the project index state/projects/<harness>.json.
type Index struct {
	Path string
}

// OpenIndex returns the index file of harness under dir.
func OpenIndex(dir, harness string) *Index

// All returns every project.
func (x *Index) All() ([]Project, error)

// Lookup returns the project of (configDir, slug).
func (x *Index) Lookup(configDir, slug string) (Project, bool, error)

// Put merges p into the index atomically.
func (x *Index) Put(p Project) error

// Ledger is the directory state/sessions.
type Ledger struct {
	Dir string
}

// Open returns the ledger rooted at dir.
func Open(dir string) *Ledger

// Append writes e (V and T filled if zero) with fsx.AppendLine. It creates
// the session file on the first event.
func (l *Ledger) Append(e Event) error

// Archive is called after the generation holding a Snapshot of length n is
// committed (S13, SPEC §10.3 step 8): it removes the session file if it
// still has length n; if events were appended after the snapshot it
// atomically keeps only the bytes after n (they go into the next
// generation), so no event is lost.
func (l *Ledger) Archive(harness, sid string, n int64) error

// ByProc returns the sessions whose CurrentProc is id (D20: a process that
// moved to another session no longer owns the old one).
func (l *Ledger) ByProc(harness string, id platform.ProcID) ([]Session, error)

// Get folds the ledger of one session.
func (l *Ledger) Get(harness, sid string) (Session, error)

// List folds every session ledger of harness.
func (l *Ledger) List(harness string) ([]Session, error)

// Snapshot returns the raw ledger bytes of a session and their length n,
// read once without modifying the file, for capsule.Manifest.Ledger before
// the seal (SPEC §10.3 step 4).
func (l *Ledger) Snapshot(harness, sid string) (raw []byte, n int64, err error)

// Project maps a harness project directory (Claude slug) to the cwds seen
// in it and their roots (IM12). Slugs are never computed by precinto.
type Project struct {
	Harness   string   `json:"harness"`
	ConfigDir string   `json:"config_dir"`
	Slug      string   `json:"slug"` // actual directory name under projects/
	Cwds      []string `json:"cwds"`
	RootIDs   []string `json:"root_ids"`
	MemoryDir string   `json:"memory_dir,omitempty"` // auto-memory dir used by sessions of this project (HA14)
}

// Session is the folded view of one session's events.
type Session struct {
	Harness     string
	SID         string
	Procs       []platform.ProcID // every process that ran the session, oldest first
	CurrentProc platform.ProcID   // last process with a start/launch event
	RootIDs     []string          // sticky managed roots (taint), first = primary
	Cwds        []string
	Dirs        []string
	Markdown    []string // absolute paths of agent-written Markdown
	ConfigDirs  []string
	TmpDirs     []string
	Transcript  string
	Started     time.Time
	LastEvent   time.Time
	Ended       bool
	EndReason   string // clear|resume|logout|prompt_input_exit|other
	EndProc     platform.ProcID
	Compacting  bool
	CompactAt   time.Time
	Wrapper     bool
	HooksSeen   bool
	Background  bool
	Version     string
	Entrypoint  string
}

// Managed reports whether the session has at least one managed root.
func (s Session) Managed() bool

// Warm reports whether the session is non-current for a process that may
// still be alive: its latest end has reason clear|resume, or that process
// has a newer start (D20). Such a unit becomes sealable once stable.
func (s Session) Warm() bool

// Type is the kind of a ledger event.
type Type string

// Event types.
const (
	TypeLaunch       Type = "launch"        // wrapper, before exec (carries the lease and homes)
	TypeStart        Type = "start"         // SessionStart (source)
	TypeTaint        Type = "taint"         // the session became managed by Roots (sticky)
	TypeCwd          Type = "cwd"           // CwdChanged / payload cwd changed
	TypeDir          Type = "dir"           // DirectoryAdded / --add-dir
	TypeTouch        Type = "touch"         // a tool path inside a root
	TypeMarkdown     Type = "md"            // an agent wrote a Markdown file (Path)
	TypeCompactBegin Type = "compact_begin" // PreCompact allowed
	TypeCompactEnd   Type = "compact_end"   // PostCompact / SessionStart(compact) / Stop / StopFailure / end
	TypeEnd          Type = "end"           // SessionEnd (Reason); the process may still be alive (R8)
	TypeHooksSeen    Type = "hooks_seen"    // first hook event of a wrapped session (hook health, UX10)
)
```

### `internal/live`

- Owner: **G3 harness adapters** · layer 4 · production
- May import (module): `internal/platform`, `internal/fsx`, `internal/paths`, `internal/config`, `internal/ledger`
- May import (third party): stdlib only
- Tests: unit with fakes: LIVE-1–LIVE-10 of the crash matrix (registry gone + end + pid alive, launch window via lease, PID reuse, zombie, unknown procStart, wall jump, warm, half-written registry), lease inode swap, hold caps, cwd evidence through ProcTable.Cwd (D47)

> Package live is the liveness engine: it decides whether any process can
> still write a unit, from the union of evidence measured by precinto itself
> (SPEC §9; D18, D19, D20, D25; R4, R8, R9, R16, R17, S14):
>
>   - ledger processes (ProcID equality, zombies are dead),
>   - launch leases (shared flocks held by wrappers),
>   - harness-specific evidence supplied by adapters (Claude registry and job
>     records, Codex writer locks, open-file holders),
>   - a stability window measured on the monotonic clock.
>
> Any doubt (read error, unknown schema, half-written registry, lock probe
> failure) means live. Units held live only by weak evidence (name or mtime
> only) for longer than policy.hold_cap are reported in status (S14).

```go
// ErrLeaseHeld is returned by sealers that find a lease.
var ErrLeaseHeld = errors.New("live: unit is leased by a running launch")

// Engine combines evidence. It is safe for concurrent use.
type Engine struct {
	Procs     platform.ProcTable
	Clock     platform.Clock
	LeasesDir string
	Observer  *Observer     // nil: no unit is ever stable
	Quiet     time.Duration // policy.quiet_window; ≤ 0 means 120 s, never immediate
	HoldCap   time.Duration // policy.hold_cap
}

// Decide evaluates s plus adapter-supplied evidence. It adds ledger-proc,
// lease and stability evidence itself. Weak evidence (capped by HoldCap,
// S14) is: a harness process by name, a future mtime, a change of file
// times only, a first observation (ReasonUnobserved), a restore within the
// quiet window, and a registry naming a non-harness pid. A nil Observer
// means not stable.
func (e *Engine) Decide(ctx context.Context, s Subject, extra []Evidence) (Verdict, error)

// StillQuiet re-checks, immediately before an unlink, that s shows no new
// evidence and its files keep their snapshot identity (SPEC §10.3 step 6).
func (e *Engine) StillQuiet(ctx context.Context, s Subject, snaps map[string]fsx.Stat) (bool, error)

// Evidence is one reason a unit may still be written.
type Evidence struct {
	Reason Reason
	Proc   platform.ProcID // zero if not process-based
	Path   string          // file or lock involved, if any
	Detail string          // short, content-free
	// Weak marks evidence based only on a process name or file times; such
	// holds are capped and reported after policy.hold_cap (S14).
	Weak bool
}

// Held is a set of leases held by this process (shared flocks on
// state/leases/<key>.lease plus a JSON description).
type Held struct {
	// contains filtered or unexported fields
}

// Acquire takes shared leases for every key (creating lease files 0600) and
// records proc. Leases on the same key by several wrappers coexist. The
// shared flock is taken with a bounded wait (2 s), so a concurrent probe's
// momentary LOCK_EX|LOCK_NB never fails a launch.
func Acquire(dir string, keys []string, l Lease) (*Held, error)

// Add takes shared leases on more keys (units resolved after the launch
// started, e.g. by a restore Selector) before their plaintext is placed,
// with Acquire's bounded wait.
func (h *Held) Add(keys ...string) error

// Inheritable returns the locked descriptors so a wrapper that execs the
// harness directly (--no-pty exec mode) can clear FD_CLOEXEC and keep the
// lease for the harness's lifetime.
func (h *Held) Inheritable() []*os.File

// Release drops every lease.
func (h *Held) Release() error

// SetChild records the harness child pid in the lease descriptions.
func (h *Held) SetChild(child platform.ProcID) error

// Lease describes a launch lease (written by the wrapper before restoring,
// held until its child has been reaped, R4).
type Lease struct {
	Key   string          `json:"key"` // unit key, or the codex home key
	Proc  platform.ProcID `json:"proc"`
	Root  string          `json:"root"` // root id
	Child platform.ProcID `json:"child,omitempty"`
	At    time.Time       `json:"at"`
}

// Probe reports whether any process holds a lease on key, and the lease
// descriptions found while it is held. It is fsx.ProbeHeld on the lease
// file: a missing file was never leased; an inode swap during the probe or
// any probe error reports held=true.
func Probe(dir, key string) (held bool, leases []Lease, err error)

// Observer tracks file identities across observations on the monotonic
// clock: a unit is stable when every file's (dev, ino, size, mtime, ctime)
// and every directory listing were identical in two observations at least Q
// apart (R16). Every sealing process starts without observations (sweeps,
// seals and the queue worker are separate processes, SPEC §13.1): a sweep
// decides once, waits Q once and decides again (D63).
type Observer struct {
	// contains filtered or unexported fields
}

// NewObserver returns an observer using c.
func NewObserver(c platform.Clock) *Observer

// Forget drops the history of key.
func (o *Observer) Forget(key string)

// Observe records the current identities of paths under key and reports
// whether they have been stable for at least q.
func (o *Observer) Observe(key string, paths []string, q time.Duration) (stable bool, err error)

// Reason names one piece of liveness evidence.
type Reason string

// Evidence reasons.
const (
	ReasonLedgerProc Reason = "ledger-proc"  // a ledger process of the session is alive (same start time)
	ReasonRegistry   Reason = "registry"     // harness registry names the unit with a live pid (D18)
	ReasonRegistryIO Reason = "registry-err" // registry unreadable/half-written/unknown schema (R8)
	ReasonLease      Reason = "lease"        // a launch lease is held (R4)
	ReasonJob        Reason = "job"          // a background/supervised job references the unit (D25, R11)
	ReasonWriterLock Reason = "writer-lock"  // a harness writer lock is held (R17)
	ReasonOpenFD     Reason = "open-fd"      // a process holds a descriptor below the unit (HA9)
	ReasonProcess    Reason = "process"      // a harness process is running (global/project units, D21)
	ReasonUnstable   Reason = "unstable"     // files changed within the stability window (R16)
	// ReasonUnobserved: first observation, the unit was not yet seen across
	// a full quiet window (weak); a caller without earlier observations
	// waits Quiet once and decides again (D63).
	ReasonUnobserved Reason = "unobserved"
	ReasonFutureTime Reason = "future-mtime" // mtime in the future: treated as live (R16)
	ReasonWarm       Reason = "warm"         // non-current session of a live process, not yet stable (D20)
	ReasonForkParent Reason = "fork-parent"  // a live session references this transcript (R21)
	ReasonPlanSlug   Reason = "plan-slug"    // a live session references this plan slug (D46)
	ReasonUnknown    Reason = "unknown"      // evidence could not be evaluated: live by default
)

// Subject is what the engine evaluates.
type Subject struct {
	Key        string            // unit key
	Paths      []string          // absolute files and directories of the unit
	Procs      []platform.ProcID // ledger processes that own the unit (current session owners only, D20)
	LeaseKeys  []string          // lease names to probe (unit key, codex home key)
	RestoredAt time.Time         // receipt time, if restored under the current grant
	// WriterExited is set when the wrapper reaped the only known writer and no
	// other evidence exists: the stability window may be skipped (R20).
	WriterExited bool
}

// Verdict is the engine's decision for one unit.
type Verdict struct {
	Live      bool
	Warm      bool // non-current session of a live process (D20): sealable once stable; status shows "sealing after /clear"
	Evidence  []Evidence
	HeldSince time.Time // first time this unit was seen live (for hold caps)
	Capped    bool      // held by weak evidence longer than hold_cap: report it
}
```

### `inventories`

- Owner: **G3 harness adapters** · layer 0 · production
- May import (module): none
- May import (third party): stdlib only
- Tests: every *.toml decodes strictly (no undecoded keys) into harness.Inventory

> Package inventories embeds the data-driven harness inventories
> (inventories/*.toml, schema 1; SPEC §7.3, D33, HA20).
>
> claude-code.toml and codex.toml carry process matching, passthrough and
> direct-mode argv lists and resume flags for the built-in adapters; every
> other file ships with status = "experimental" and is used only with
> --experimental (wrapper-only, no hooks).

```go
// FS holds every *.toml inventory.
var FS embed.FS
```

### `internal/harness`

- Owner: **G3 harness adapters** · layer 5 · production
- May import (module): `internal/capsule`, `internal/config`, `internal/paths`, `internal/fsx`, `internal/platform`, `internal/ledger`, `internal/live`
- May import (third party): stdlib, `github.com/BurntSushi/toml`
- Tests: unit: registry, inventory parsing/validation, MatchProcess, Classify passthrough/direct, UnitKeyFor vectors and refusals (unitkey_test.go)

> Package harness defines what a harness adapter must provide (SPEC §7):
> registered homes, the inventory of plaintext units (fail-closed),
> harness-specific liveness evidence, allowed restore targets per kind
> (derived from trusted context, never from manifests, D8), per-file
> placement policies (D11), and the launch plan the wrapper executes
> (restore-before-launch, injected settings, environment, PTY mode).
> It also defines the data-driven inventory TOML schema (D33, HA20).
>
> Adapters never seal, restore, or delete: internal/sweep does, using the
> units, targets and policies adapters return.

```go
// Errors.
var (
	ErrUnknownHarness = errors.New("harness: unknown harness")
	ErrNotManaged     = errors.New("harness: path is not inside a protected root")
	ErrUnregistered   = errors.New("harness: home is not registered")
	ErrWrongHome      = errors.New("harness: session does not use the folder's sealed home") // codex D31
	ErrUnitKey        = errors.New("harness: unit key parts missing or malformed")
)

// KillGrace is the SIGTERM→SIGKILL grace for a harness whose SessionEnd
// hooks take up to sessionEnd: max(8 s, sessionEnd+6 s), capped at 70 s
// (SPEC §12.7).
func KillGrace(sessionEnd time.Duration) time.Duration

// Register adds an adapter (called from cmd/precinto wiring).
func Register(a Adapter)

// UnitKeyFor derives the unit key of a unit from the parts table of SPEC
// §6.2 (D45), so every group computes keys identically (implemented in the
// scaffold). unitID is the kind's own id: sid (claude-session), project
// directory name as found on disk (claude-project), slug (claude-plan),
// store name (global-store), random blob id (codex-blob), root-relative
// slash-separated path (md), partition id (generic). For claude-history
// and codex-home the root is the unit: unitID must be empty or equal
// rootID. homeID is Home.ID; rootID a config root id. Non-final parts must
// not contain 0x1f.
func UnitKeyFor(salt []byte, k capsule.Kind, h ID, homeID, rootID, unitID string) (string, error)

// Adapter is implemented by each harness package.
type Adapter interface {
	// ID returns the harness id.
	ID() ID
	// Homes returns every registered home of this harness (config + ledger
	// + defaults); codex returns one home per protected root (D31).
	Homes(ctx context.Context, e Env) ([]Home, error)
	// Scan lists plaintext units in scope, fail-closed (unknown files that
	// carry a session id belong to that session unit, I10).
	Scan(ctx context.Context, e Env, s Scope) ([]Unit, error)
	// Probe returns harness-specific liveness evidence for u (registry, job
	// records, writer locks, open-file holders, harness processes). Errors
	// mean "treat as live".
	Probe(ctx context.Context, e Env, u Unit) ([]live.Evidence, error)
	// Targets returns restore rules for a logged capsule of kind/unit.
	// unitID is manifest.UnitID, which the caller (internal/sweep) has
	// already authenticated: UnitKeyFor(salt, ref.Kind, ref.Harness, the
	// registered home id or config root id, unitID) equals ref.Key, the
	// unit key of the capsule-log entry; otherwise the capsule is rejected
	// (exit 5) before Targets is called and before any write (SPEC §11.2).
	Targets(ctx context.Context, e Env, ref UnitRef, unitID string) (TargetRules, error)
	// PlanLaunch parses argv (argv[0] is the harness name) for cwd.
	PlanLaunch(ctx context.Context, e Env, cwd string, argv []string) (LaunchPlan, error)
	// MarkdownPaths returns absolute Markdown paths an agent wrote, derived
	// from the unit's own files (transcript tool inputs, apply_patch headers)
	// to complement the hook ledger (S6). Only paths are retained.
	MarkdownPaths(ctx context.Context, e Env, u Unit) ([]string, error)
	// Describe returns content-free metadata for a unit (title is returned
	// only to be written inside the capsule).
	Describe(ctx context.Context, e Env, u Unit) (title string, last time.Time, err error)
}

// All lists registered adapters in registration order.
func All() []Adapter

// Get returns the adapter for id.
func Get(id ID) (Adapter, bool)

// BaseSpec is one base directory of an inventory.
type BaseSpec struct {
	Name    string `toml:"name"`
	Default string `toml:"default"` // "~/.gemini", "$XDG_DATA_HOME/opencode"
	Env     string `toml:"env"`     // relocation variable
}

// Env is everything an adapter may read. Homes come from config and the
// ledger, never from the caller's environment alone (R22).
type Env struct {
	Cfg    config.Config
	Layout paths.Layout
	Ledger *ledger.Ledger
	Index  func(harness string) *ledger.Index
	Live   *live.Engine
	Procs  platform.ProcTable
	Clock  platform.Clock
	Salt   []byte
	Host   paths.Env // the invoking process environment (wrapper: the child's)
}

// File is one planned file of a unit (snapshot taken at scan time).
type File struct {
	Base      capsule.BaseID
	Rel       string
	Snap      fsx.Stat
	Placement Placement
	Append    bool   // append-only (lineage by prefix hash, D10)
	Group     string // SQLite group id
	Last      bool   // place after every other file (Claude <sid>.jsonl, R6)
}

// GenMode is how generations of a kind are restored (D42).
type GenMode string

// Generation modes.
const (
	GenLayered  GenMode = "layered"  // restore the union through non-successor links
	GenSnapshot GenMode = "snapshot" // restore exactly the newest snapshot (codex home)
)

// Hazard is an entry found while scanning that is never sealed or deleted
// (symlink, FIFO, socket, device, hard link, unreadable): it is reported.
type Hazard struct {
	Base   capsule.BaseID
	Rel    string
	Hazard fsx.Hazard
}

// Home is one resolved harness home. Bases maps every BaseID the harness
// uses to an absolute, realpath'd directory (SPEC §7.0, R22).
type Home struct {
	Harness ID
	ID      string // stable short id of the home (hash of its realpath): part of unit keys
	Bases   map[capsule.BaseID]string
	Default bool
	RootID  string // codex per-root homes: the owning root (D31); "" otherwise
}

// HookCheck configures the hook-presence check.
type HookCheck struct {
	Event   string
	Within  time.Duration
	OnInput bool // Codex: measured from the first Enter (SessionStart runs at the first turn)
}

// ID is a harness identifier.
type ID string

// Built-in harnesses (v0.1 scope, D41/D49).
const (
	ClaudeCode ID = "claude-code"
	Codex      ID = "codex"
)

// Inventory is a data-driven harness description, inventories/<id>.toml
// (schema 1, D33, HA20). Built-in adapters also read theirs for process
// matching and passthrough lists.
type Inventory struct {
	Schema           int          `toml:"schema"`
	ID               string       `toml:"id"`
	Name             string       `toml:"name"`
	Status           string       `toml:"status"`            // "verified" | "experimental"
	VerifiedVersions string       `toml:"verified_versions"` // semver range verified; informational for experimental inventories (doctor warns outside it)
	Mode             string       `toml:"mode"`              // "capsule" (claude) | "home" (codex, generic)
	Bases            []BaseSpec   `toml:"bases"`
	Content          []string     `toml:"content"`       // globs relative to a base ("<base>:<glob>")
	NeverTouch       []string     `toml:"never_touch"`   // deny-list (codex, HA24)
	Exclude          []string     `toml:"exclude"`       // e.g. Antigravity paths under ~/.gemini
	Process          ProcessMatch `toml:"process"`       // how to recognise harness processes
	Locks            []LockSpec   `toml:"locks"`         // writer locks
	OpenFDCheck      bool         `toml:"open_fd_check"` // require no open fds before sealing
	Partition        string       `toml:"partition"`     // "home" | "project-slug" | "project-dir"
	SlugGlob         string       `toml:"slug_glob"`
	StopCmd          []string     `toml:"stop_cmd"`
	Passthrough      [][]string   `toml:"passthrough"` // argv prefixes that skip gate and restore (UX14)
	Direct           [][]string   `toml:"direct"`      // argv prefixes that run gated without a PTY
	Resume           ResumeSpec   `toml:"resume"`
	Notes            []string     `toml:"notes"`
}

// LoadInventories parses every *.toml in fsys.
func LoadInventories(fsys fs.FS) ([]Inventory, error)

// LoadInventory parses inventories/<name>.toml from fsys and validates it.
func LoadInventory(fsys fs.FS, name string) (Inventory, error)

// Classify returns the launch mode of argv (argv[0] excluded) per the
// passthrough/direct lists, and whether stdin/stdout are terminals.
func (inv Inventory) Classify(args []string, stdinTTY, stdoutTTY bool) LaunchMode

// MatchProcess reports whether p is a process of inv.
func (inv Inventory) MatchProcess(p platform.ProcInfo) bool

// LaunchMode is how the wrapper runs the child (UX14).
type LaunchMode string

// Launch modes.
const (
	LaunchInteractive LaunchMode = "interactive" // PTY proxy with overlay
	LaunchDirect      LaunchMode = "direct"      // gated and sealed, no PTY (-p, exec, pipes)
	LaunchPassthrough LaunchMode = "passthrough" // no gate, no restore (update, login, --version…)
)

// LaunchPlan is what the wrapper executes for one harness invocation.
type LaunchPlan struct {
	Harness    ID
	Mode       LaunchMode
	Roots      []config.Root
	Resume     Resume
	Sync       []Selector // restore before exec, synchronously, in order
	Background []Selector // restore after exec, newest first, within budget (D38)
	Lease      []string   // lease keys known up front (e.g. the codex home key); restored units are added as they are placed
	Argv       []string   // final argv (argv[0] absolute), e.g. with --settings injected (D32)
	Env        []string   // environment additions (CODEX_HOME, CODEX_SQLITE_HOME, TMPDIR, CLAUDE_CODE_ENABLE_AWAY_SUMMARY=0…)
	// Notices are ui.MsgID values (harness packages cannot import
	// internal/ui), printed before exec; the wrapper renders them with
	// ui.Format and MsgVars.
	Notices []string
	// Confirm is a ui.MsgID asked on the TTY before launching (e.g.
	// C7.twice, C7.purge, C9.bare, C10.consent), "" if none: yes runs Argv
	// as planned (e.g. with --fork-session for C7.twice), no aborts the
	// launch with ui.ErrCancelled (exit 3).
	Confirm string
	// MsgVars are the {placeholder} values for Notices and Confirm, keyed
	// without braces ("sid", "pid", "folder").
	MsgVars map[string]string
	// QuitKeys are sent through the PTY before SIGTERM when precinto ends
	// the session (codex: Ctrl-C twice); nil = none.
	QuitKeys []byte
	// KillGrace is the SIGTERM→SIGKILL grace for this harness (KillGrace).
	KillGrace time.Duration
	// Prepare runs after unlock and before restore (codex per-root home
	// creation and seeding, D31).
	Prepare func(ctx context.Context) error
	// Finish runs after the child exited and before sealing (codex auth.json
	// sync back, D31).
	Finish func(ctx context.Context, exitCode int) error
	// SealScope selects the units to seal after exit (resolved again by
	// scanning). Adapters always set SIDs when the resume target is known;
	// the backend adds Procs=[child].
	SealScope Scope
	// SessionID is the id of the new session a fresh launch starts, when
	// the adapter knows it before exec (Claude: the --session-id it passes,
	// or the user's own, D107); "" otherwise. The backend records it as the
	// child's (RecordLaunch). It does not narrow SealScope: the seal after
	// exit still takes every session the child owns.
	SessionID string
	// HookCheck says how to verify hook health (UX10): event expected and
	// within how long after start.
	HookCheck HookCheck
}

// LockSpec is one writer-lock convention.
type LockSpec struct {
	Glob string `toml:"glob"`
	Kind string `toml:"kind"` // "flock" | "json-pid"
}

// Placement is the restore/merge policy of one file (SPEC §11.3, D11).
type Placement string

// Placements.
const (
	PlaceExact       Placement = "exact"        // equal hash ⇒ no-op; otherwise conflict copy, never overwrite
	PlaceJSONLAppend Placement = "jsonl-append" // Claude transcripts/subagents: prefix/link/uuid rules
	PlaceLineUnion   Placement = "line-union"   // history.jsonl, session_index.jsonl: add missing lines
	PlaceSQLiteGroup Placement = "sqlite-group" // db + -wal + -journal as one unit; -shm never restored
	PlaceMarkdown    Placement = "md"           // note: exact, plus marker handling (D16)
)

// ProcessMatch identifies harness processes (never by Claude's p_comm).
type ProcessMatch struct {
	ExeBasenames []string `toml:"exe_basenames"`
	ExePaths     []string `toml:"exe_paths"`  // globs
	ArgvRegex    []string `toml:"argv_regex"` // node/python CLIs
}

// Resume is the parsed resume target.
type Resume struct {
	Kind  ResumeKind
	Value string
	Fork  bool
}

// ResumeKind classifies resume arguments (HA23, IM13).
type ResumeKind string

// Resume kinds.
const (
	ResumeNone     ResumeKind = ""
	ResumeSID      ResumeKind = "sid"      // --resume <uuid>
	ResumePath     ResumeKind = "path"     // --resume /abs/<uuid>.jsonl
	ResumeName     ResumeKind = "name"     // --resume <title or search term>
	ResumePicker   ResumeKind = "picker"   // --resume / -r without a value
	ResumeContinue ResumeKind = "continue" // -c / --continue / codex resume --last
	ResumeJob      ResumeKind = "job"      // claude attach|respawn <job-id>
)

// ResumeSpec describes resume flags (wrapper parsing).
type ResumeSpec struct {
	Flags      []string `toml:"flags"`      // "--resume", "-r"
	Continue   []string `toml:"continue"`   // "--continue", "-c"
	Fork       []string `toml:"fork"`       // "--fork-session"
	Subcommand []string `toml:"subcommand"` // codex: "resume", "fork"
}

// Scope limits a scan.
type Scope struct {
	RootIDs []string // empty = every root
	SIDs    []string // specific sessions
	// Kinds: empty = every kind except KindGeneric, which is scanned only
	// when listed (seal --dormant, D33).
	Kinds  []capsule.Kind
	Global bool // include global stores
	// Adopt also adopts sessions found only by transcript cwd (seal
	// --adopt, md="all" sweeps; S6).
	Adopt bool
	// Procs keeps only sessions whose ledger current owner is one of these
	// processes (the wrapper's seal after exit of a fresh session); units
	// that are not sessions are left out. Adapters without session units
	// (codex homes, generic partitions) ignore it.
	Procs []platform.ProcID
}

// Selector picks sealed units to restore. internal/sweep resolves it
// against the capsule log and, for ProjectDir/Title, the manifests (which
// needs file keys); adapters only compute what they know (D38, D14).
type Selector struct {
	Kind       capsule.Kind
	RootID     string
	Keys       []string      // exact unit keys (e.g. resume by sid, computed with capsule.UnitKey)
	ProjectDir string        // the realpath'd launch cwd; matches Manifest.ProjectDir exactly (-c / --continue, D73)
	Title      string        // only units whose manifest title contains it (--resume <name>)
	Recent     int           // newest N by last activity; 0 = every match
	Newest     bool          // only the single newest match
	MaxAge     time.Duration // skip units whose last activity is older (D14: cleanupPeriodDays − 2 days); 0 = no limit
	MtimeNow   bool          // explicit resume of an old session: clamp mtimes to now − 1 day (D14)
	MaxBytes   int64         // budget for this selector; 0 = policy.restore_max_bytes
	// SkipEntrypoints drops units whose ledger (in the manifest) records
	// one of these entrypoints for the session's start, e.g. the sdk-*
	// entrypoints Claude's interactive --continue skips (D102); a unit
	// that records none is kept.
	SkipEntrypoints []string
}

// TargetRules says where a capsule of a kind may restore, computed from
// trusted context (registered homes, config roots) and the manifest's unit
// id once it is authenticated against the logged unit key (D8, S3).
type TargetRules struct {
	Bases map[capsule.BaseID]string
	// Allow reports whether (base, rel) is a permitted target for this kind
	// and unit; it must reject anything outside the per-kind table of SPEC
	// §11.2, compare case-insensitively on darwin, and require Clean(rel).
	Allow func(base capsule.BaseID, rel string) bool
	// Policy returns the placement of an entry.
	Policy func(e capsule.Entry) Placement
	Mode   GenMode
	// Last reports entries placed after every other entry (Claude
	// <sid>.jsonl, REST-3); nil = no ordering constraint.
	Last func(e capsule.Entry) bool
	// Skip names bases that exist but are unsafe now (Claude $TMP not
	// 0700/owned, S7), with the reason: their entries are skipped and
	// reported, never written, and the rest of the unit restores. An entry
	// whose base is in neither Bases nor Skip still rejects the capsule
	// (exit 5).
	Skip map[capsule.BaseID]string
}

// Unit is one sealable group of plaintext files.
type Unit struct {
	Harness ID
	Kind    capsule.Kind
	Key     string // unit key (capsule.UnitKey)
	UnitID  string // sid, slug, relpath… (private; never logged)
	VaultID string // sealing vault (D1, D36)
	RootIDs []string
	Home    Home
	Files   []File
	Dirs    []File // empty directories to record
	Hazards []Hazard
	// Prune lists "<base id>:<rel>" entries (e.g. "claude_tmp:<P>/<sid>"),
	// deepest first, of directories to remove when empty after sealing;
	// never a base root and never projects/<P>. One format, no bare rel.
	Prune        []string
	Mode         GenMode
	Procs        []platform.ProcID // ledger owners (current), for live.Subject
	Paths        []string          // absolute files/dirs for stability and fd checks
	LeaseKeys    []string
	Title        string // custom-title > ai-title > first prompt; stored only inside ciphertext
	LastActivity time.Time
	Adopted      bool   // found by transcript cwd or the project index, not by the ledger, and never restored by precinto (S6; a ledger-less unit with a receipt is precinto's own and re-sealed)
	Note         string // content-free scan note
	// ProjectDir is, for claude-session units, the session's start cwd,
	// realpath'd (the ledger start event, else the transcript's first cwd);
	// for claude-project units the cwd the project index maps to <P> when
	// unique, else "". Copied into capsule.Manifest.ProjectDir (D73).
	ProjectDir string
}

// Ref returns the reference of u.
func (u Unit) Ref() UnitRef

// UnitRef names a unit without its files (restore requests, leases).
type UnitRef struct {
	Harness ID
	Kind    capsule.Kind
	Key     string
	VaultID string
	RootIDs []string
	HomeID  string
}
```

### `internal/harness/claude`

- Owner: **G3 harness adapters** · layer 6 · production
- May import (module): `internal/capsule`, `internal/config`, `internal/paths`, `internal/fsx`, `internal/platform`, `internal/ledger`, `internal/live`, `internal/harness`, `inventories`
- May import (third party): stdlib only
- Tests: unit with claudetest: fail-closed sid inventory (unknown files sealed, deny-list honoured), registry parsing incl. malformed, jobs, history line parsing, ScanTranscript facts, ScanLinks (uuid set, first parent, trailing newline), ParseResume table, SettingsJSON, Targets per kind (SPEC §11.2 table)

> Package claude is the Claude Code adapter (capsule mode, SPEC §7.1):
> session units by session id (fail-closed), project units (auto memory,
> legacy sessions-index.json, MCP logs), plan units by slug (D46), history
> lines per root (D36), global stores, registry and job readers for
> liveness, transcript scanning for Markdown paths, titles and fork
> references, and the launch plan (resume parsing, --settings injection D32,
> retention clamp D14).
>
> Never re-implement Claude's slug: locate transcripts by session id across
> every projects/* directory (D19); map slugs to cwds with the project index.

```go
// CleanupPeriodDays returns Claude's effective cleanupPeriodDays from the
// user settings of configDir (default 30) for the retention rules of D14.
func CleanupPeriodDays(configDir string) (int, error)

// New returns the adapter.
func New() harness.Adapter

// ParseResume classifies Claude resume flags (argv excludes argv[0]).
func ParseResume(args []string) harness.Resume

// SettingsJSON returns the inline JSON passed with --settings for managed
// launches (D32, HA12): idleCompaction=false, awaySummaryEnabled=false,
// precomputeCompactionEnabled=false.
func SettingsJSON(p config.Policy) string

// HistoryLine is the content-free view of one history.jsonl line; Raw is
// kept only in memory while rotating and is sealed, never logged.
type HistoryLine struct {
	Raw       []byte
	Project   string
	SessionID string
	Timestamp time.Time
	PasteRefs []string // paste-cache entry names referenced by pastedContents
	Valid     bool
}

// ParseHistoryLine parses one line without retaining anything but the
// fields above.
func ParseHistoryLine(b []byte) HistoryLine

// Job is a background/supervised session record ($CC/jobs/<id>/state.json).
type Job struct {
	ID        string
	SessionID string
	State     string // running|stopped|...
	Valid     bool   // false: unknown schema ⇒ live
}

// ReadJobs reads job records of a config dir (D25, R11).
func ReadJobs(configDir string) ([]Job, error)

// Links are the JSONL linkage facts the placement table needs (SPEC §11.3,
// D11): the uuid of every record, the first record's parentUuid and
// logicalParentUuid, and whether the stream ends with '\n'. They hold ids
// only, never content.
type Links struct {
	UUIDs              map[string]bool
	FirstParent        string
	FirstLogicalParent string
	Records            int
	TrailingNL         bool
	Valid              bool // false: a line did not parse (callers treat the pair as a conflict)
}

// ScanLinks streams a Claude transcript or subagent JSONL (the staged
// capsule version C or the existing file F) and returns its Links, so
// internal/sweep never parses Claude records itself.
func ScanLinks(ctx context.Context, r io.Reader) (Links, error)

// RegistryEntry is one ~/.claude/sessions/<pid>.json (Claude's live-session
// registry). Fields are read best-effort; Valid=false means the file was
// unreadable, half-written or of an unknown schema (treat its pid's
// sessions as live, R8, D18).
type RegistryEntry struct {
	Path       string
	PID        int
	SessionID  string
	Cwd        string
	Status     string // "busy" | "idle" | ""
	WaitingFor string // non-empty: permission/elicitation pending (counts as idle, HA7)
	Kind       string // "interactive" | background kinds
	Entrypoint string // "cli" | "sdk-cli" | ...
	StartedAt  time.Time
	Mtime      time.Time
	Valid      bool
}

// ReadRegistry reads every registry file of a config dir.
func ReadRegistry(configDir string) ([]RegistryEntry, error)

// Busy reports whether an entry says the session is mid-turn (status busy
// and WaitingFor empty, HA7).
func (r RegistryEntry) Busy() bool

// TranscriptFacts are paths and ids found in a transcript (never content).
type TranscriptFacts struct {
	Cwds       []string // every distinct `cwd` key
	Slug       string   // plan slug (`slug` key)
	MDPaths    []string // Write/Edit/MultiEdit/NotebookEdit tool_use file paths ending in .md/.mdx/.markdown
	ForkRefs   []string // parent session ids from fork-context-ref lines (R21)
	CopiedSIDs []string // other sessionIds present in copied lines
	Title      string   // last custom-title, else last ai-title, else first prompt (bounded)
	LastAt     time.Time
	Uuids      int  // number of records with a uuid (merge checks)
	TrailingNL bool // the file ends with '\n'
}

// ScanTranscript streams a transcript and extracts TranscriptFacts.
func ScanTranscript(ctx context.Context, path string) (TranscriptFacts, error)
```

### `internal/harness/codex`

- Owner: **G3 harness adapters** · layer 6 · production
- May import (module): `internal/capsule`, `internal/config`, `internal/paths`, `internal/fsx`, `internal/platform`, `internal/ledger`, `internal/live`, `internal/harness`, `inventories`
- May import (third party): stdlib only
- Tests: unit with codextest: Classify deny-list, SQLite grouping, PrepareHome (sqlite_home stripped, links, ForceConfig keeps trust entries), SyncAuthBack, ApplyPatchPaths (Add/Update/Move, relative), HooksTrusted fixture

> Package codex is the Codex adapter with per-root homes (D31, SPEC §7.2):
> `precinto run codex` inside a protected root runs Codex with
> CODEX_HOME=<base>/homes/codex/<root-id>, seeded from ~/.codex; the home is
> sealed as one snapshot generation (manifest + blobs, SQLite groups kept
> together, -shm never sealed) and restored all-or-nothing before launch.
>
> Never open Codex SQLite databases (no SQLite driver is linked); treat them
> as opaque file groups.

```go
// Errors of HooksTrusted for the states that are known but not "trusted".
var (
	// ErrHooksModified: trust entries exist for precinto's hooks but hold
	// the hash of other declarations (another version of hooks/codex.json,
	// or another normalization by Codex): Codex skips the hooks until the
	// user reviews them in /hooks again (D98).
	ErrHooksModified = errors.New("codex: precinto's hooks are trusted for other hook declarations")
	// ErrPluginMissing: the home's config.toml enables no precinto plugin,
	// or the plugin is not installed in the home's plugins/cache: Codex
	// loads no precinto hook there, so /hooks cannot list them (D99).
	ErrPluginMissing = errors.New("codex: the home does not load precinto's Codex plugin")
)

// ApplyPatchPaths extracts "*** Add File:", "*** Update File:" and
// "*** Move to:" paths from an apply_patch command, resolved against cwd
// (HA25). Only paths are returned.
func ApplyPatchPaths(patch []byte, cwd string) []string

// GroupOf returns the SQLite group id of a home-relative path ("" if none).
func GroupOf(rel string) string

// HooksTrusted reports, read-only, whether Codex 0.154 runs precinto's
// hooks in home (UX10): config.toml enables a precinto plugin installed in
// home's plugins/cache, and has a [hooks.state."…"] entry for every hook of
// plugins/codex/hooks/codex.json whose trusted_hash equals the hash Codex
// computes for that hook's declaration and that is not disabled (D98).
// When the state is known but not trusted, err tells why: ErrPluginMissing
// (no such plugin) or ErrHooksModified (trusted for other declarations:
// Codex 0.154 skips them until reviewed again); nil means some hook is not
// trusted yet. known is false (with trusted false) when config.toml cannot
// be read or parsed — a read failure is also returned in err — and when
// entries with other hashes were written by a Codex newer than 0.154
// (they carry trusted_content_hash: that Codex may hash another way).
func HooksTrusted(home string) (trusted bool, known bool, err error)

// LaunchEnv returns the environment additions for a managed launch:
// CODEX_HOME, CODEX_SQLITE_HOME (= home) and TMPDIR (= <home>/precinto-tmp,
// so hook-output spills are sealed with the home, D44).
func LaunchEnv(rootHome string) []string

// New returns the adapter.
func New() harness.Adapter

// PrepareHome creates RootHome 0700 if missing and seeds it: copies
// config.toml once (or again with ForceConfig), removing sqlite_home and
// log_dir keys, and at every call adds the [marketplaces.*] and
// [plugins.*] tables of the user's config.toml that RootHome's lacks
// (D99); synchronizes auth.json from UserHome when newer, never into a
// home that logged out, removing the other copy of logged-out credentials,
// and only with a UserHome that exists (D100); and symlinks plugins/ and
// skills/ to UserHome, moving a real directory Codex created there to
// <RootHome>.displaced/ first (never deleted, D99). It never touches
// content files.
func PrepareHome(ctx context.Context, s Seed) error

// SyncAuthBack copies RootHome/auth.json to UserHome/auth.json atomically
// when it is newer and differs (token refresh), after the child exited; a
// logout on either side is never undone (D100).
func SyncAuthBack(ctx context.Context, s Seed) error

// UserHome resolves the user's own Codex home (CODEX_HOME or ~/.codex) from e.
func UserHome(e paths.Env) (string, error)

// WrongHomeRollouts counts the rollouts under userHome/sessions (and
// userHome/archived_sessions) whose first line is a session_meta record
// (its `type` is checked) with payload.cwd inside a protected root of c:
// sessions started without the wrapper, written outside the sealed
// per-root home and never sealed (codex-wrong-home, C9.codexoutside, D31).
// It reads at most 64 KiB of that line and keeps only cwd, decoding token
// by token so no other value is kept; counts are per root id. Compressed
// (.jsonl.zst) or unreadable rollouts (a first line that is not JSON, or
// whose cwd lies beyond the bound) are counted under "" (could not be
// checked); a readable first line of another record type is not a
// session and is not counted. A missing home counts nothing.
func WrongHomeRollouts(ctx context.Context, userHome string, c config.Config) (map[string]int, error)

// Class is how a file below a per-root home is treated.
type Class string

// Classes.
const (
	ClassContent    Class = "content"     // sealed (everything not in never_touch: fail-closed, HA24)
	ClassNeverTouch Class = "never-touch" // auth.json, config.toml, plugins/, skills/, caches, locks…
	ClassSQLiteMain Class = "sqlite-main" // *_<N>.sqlite: group leader
	ClassSQLiteSide Class = "sqlite-side" // -wal / -journal: sealed and restored with the main file
	ClassSHM        Class = "shm"         // -shm: never sealed, never restored, moved to quarantine on restore
)

// Classify returns the class of a home-relative path.
func Classify(rel string) Class

// Seed describes how a per-root home is created and refreshed (D31, D44).
type Seed struct {
	UserHome string // ~/.codex (or the user's CODEX_HOME outside roots)
	RootHome string // <base>/homes/codex/<root-id>
	// ForceConfig re-copies config.toml even when the home already has one
	// (`precinto codex sync-config`); hooks trust entries of the per-root
	// home are kept.
	ForceConfig bool
}
```

### `internal/harness/generic`

- Owner: **G3 harness adapters** · layer 6 · production
- May import (module): `internal/capsule`, `internal/config`, `internal/paths`, `internal/fsx`, `internal/platform`, `internal/ledger`, `internal/live`, `internal/harness`, `inventories`
- May import (third party): stdlib only
- Tests: unit: experimental gating (--experimental and seal --dormant only), refusal while a matching process runs, a lock is held, the open-file check fails or a -wal/-shm exists

> Package generic implements experimental home-mode adapters from
> data-driven inventories (D33, HA20): wrapper-only (no hooks), relocation
> through each harness's env var where available, liveness by wrapper lease
> + open-file holders + lock specs + stability window. Per SPEC §7.3 an
> adapter seals only with `--experimental` through `precinto seal --dormant
> <id>`, and only when no matching process runs, no lock is held, the
> open-file check passes and no -wal/-shm file exists; there is no
> automatic restore in v0.2. verified_versions is informational for
> experimental inventories (doctor warns when the installed version is
> outside it); it never enables sealing by itself.

```go
// Adapters loads every inventory from fsys that is not built in
// (claude-code, codex) and returns adapters; experimental inventories are
// returned only when experimental is true.
func Adapters(fsys fs.FS, experimental bool) ([]harness.Adapter, error)

// New returns an adapter for one inventory.
func New(inv harness.Inventory) harness.Adapter
```

### `internal/harness/claude/claudetest`

- Owner: **G3 harness adapters** · layer 7 · test-only helper (production packages must not import it)
- May import (module): `internal/harness/claude`, `internal/platform`, `internal/fsx`
- May import (third party): stdlib only
- Tests: used by G3/G4/G5/G6/G7 tests

> Package claudetest writes synthetic Claude Code layouts (transcripts with
> marker text, subagents, tool-results, file-history, session-env, tmp
> scratchpads, registry and job files, history.jsonl, paste-cache, memory)
> under a fake CLAUDE_CONFIG_DIR / CLAUDE_CODE_TMPDIR. Never copies real
> user data (SPEC §20, S13).

```go
// Appender simulates Claude's writer: open, append one record, close, every
// interval; recreates the file if it is missing. Stop ends it.
type Appender struct {
	// contains filtered or unexported fields
}

// StartAppender starts an appender on path.
func StartAppender(t testing.TB, path string, every time.Duration) *Appender

// Stop stops the appender and returns the number of records written.
func (a *Appender) Stop() int

// Layout is a fake Claude installation.
type Layout struct {
	ConfigDir string
	TmpDir    string
	CacheDir  string
}

// New creates the directory skeleton under dir.
func New(t testing.TB, dir string) *Layout

// AppendFragment simulates Claude recreating <sid>.jsonl after a move (E8):
// lines whose first parentUuid points into the original.
func (l *Layout) AppendFragment(t testing.TB, s Session, lines int) string

// WriteHistory appends history.jsonl lines for (project, sid).
func (l *Layout) WriteHistory(t testing.TB, project, sid string, n int, marker string)

// WriteJob writes jobs/<id>/state.json for a background session.
func (l *Layout) WriteJob(t testing.TB, id, sid, state string)

// WriteRegistry writes sessions/<pid>.json (valid=false writes a truncated file).
func (l *Layout) WriteRegistry(t testing.TB, pid int, sid, cwd, status string, valid bool) string

// WriteRegistryEntry writes sessions/<pid>.json with every field of e and returns its path.
func (l *Layout) WriteRegistryEntry(t testing.TB, e claude.RegistryEntry) string

// WriteSession writes the session files and returns every path created.
func (l *Layout) WriteSession(t testing.TB, s Session) []string

// Session describes a synthetic session.
type Session struct {
	SID       string
	Cwd       string
	Slug      string // projects/<Slug>; "" = derive a fixture slug
	Lines     int    // transcript records
	Subagents int
	Marker    string // unique marker text embedded in prompts/tool inputs
	NoNewline bool   // omit the trailing newline (crash simulation)
	MDWrites  []string
	PlanSlug  string
	ModTime   time.Time
}
```

### `internal/harness/codex/codextest`

- Owner: **G3 harness adapters** · layer 7 · test-only helper (production packages must not import it)
- May import (module): `internal/harness/codex`, `internal/fsx`
- May import (third party): stdlib only
- Tests: used by G3/G4/G7 tests

> Package codextest writes synthetic Codex homes (rollouts with marker
> text, *_N.sqlite files with -wal/-shm siblings as opaque bytes,
> history.jsonl, session_index.jsonl, thread-writer-locks, shell snapshots,
> auth.json and config.toml placeholders) for tests. Never touches ~/.codex.

```go
// Appender simulates Codex's rollout writer: it keeps the rollout open with
// O_APPEND and appends one Codex-shaped record every interval; Stop ends it.
type Appender struct {
	// contains filtered or unexported fields
}

// StartAppender starts an appender on path.
func StartAppender(t testing.TB, path string, every time.Duration) *Appender

// Stop stops the appender and returns the number of records written.
func (a *Appender) Stop() int

// Home is a fake Codex home.
type Home struct {
	Dir string
}

// New writes a synthetic home under dir.
func New(t testing.TB, dir string, o Options) *Home

// HoldWriterLock flocks thread-writer-locks/<id>.lock until release is called.
func (h *Home) HoldWriterLock(t testing.TB, id string) (release func())

// Rollouts lists rollout paths.
func (h *Home) Rollouts(t testing.TB) []string

// Options shapes a synthetic home.
type Options struct {
	Rollouts   int
	Marker     string
	WithWAL    bool // write state_5.sqlite-wal next to state_5.sqlite
	WithLocks  bool // create thread-writer-locks/<id>.lock files (unheld)
	RolloutAge time.Duration
	Cwd        string // cwd recorded in session_meta; "" = <parent of the home>/codextest-workspace
}
```

## G4 orchestration

### `internal/sweep/journal`

- Owner: **G4 orchestration** · layer 2 · production
- May import (module): `internal/fsx`, `internal/fsx/failpoint`
- May import (third party): stdlib only
- Tests: unit: O_EXCL create, phases persisted only after their step (failpoints), Capsule name recorded at prepared, history Offset/Pending/NewBase round trip, Pending ordering, Done removal

> Package journal persists one record per in-flight destructive operation
> so that a crash at any step can be rolled back or rolled forward without
> any key (SPEC §10.5, §11.5; I9; R5).
>
> Records are created O_CREAT|O_EXCL, fsynced with their directory, hold no
> content (paths are base-relative, unit keys are HMACs), and are deleted
> at PhaseDone. Every phase is a completed milestone: a record is advanced
> to a phase only after that step has finished and is durable, and
> everything recovery needs to undo or finish the next step (for a seal:
> the temporary and the final capsule name) is recorded before that step
> starts (D58).

```go
// Version is the record format.
const Version = 1

// ErrConflict is returned when another record already covers the unit.
var ErrConflict = errors.New("journal: operation already in flight for this unit")

// NewID returns a sortable unique operation id.
func NewID() string

// File is one source or target recorded in a journal (no content).
type File struct {
	Base string `json:"base"` // base id (capsule.BaseID)
	// Dir is the absolute, realpath'd base directory, for keyless recovery
	// (recovery runs without the adapters).
	Dir  string   `json:"dir"`
	Rel  string   `json:"rel"`
	Snap fsx.Stat `json:"snap"`
	Done bool     `json:"done,omitempty"` // unlinked / placed
}

// Journal is the directory state/journal.
type Journal struct {
	Dir string
}

// Open returns the journal rooted at dir.
func Open(dir string) *Journal

// Advance sets r.Phase = p and persists it. Call it AFTER the step named by
// p has completed and is durable (phases are milestones, D58).
func (j *Journal) Advance(r *Record, p Phase) error

// Begin creates and persists a new record at PhasePrepared.
func (j *Journal) Begin(kind Kind, harness, unit string) (*Record, error)

// Done removes the record (fsync of the directory).
func (j *Journal) Done(r *Record) error

// Pending lists unfinished records, oldest first.
func (j *Journal) Pending() ([]*Record, error)

// Save persists r as is (FullSync of the record and its directory); used
// for progress within a phase (Files[i].Done, Offset, Pending).
func (j *Journal) Save(r *Record) error

// Kind is the operation type.
type Kind string

// Operation kinds.
const (
	KindSeal          Kind = "seal"           // SPEC §10.3
	KindRestore       Kind = "restore"        // SPEC §11.5
	KindCodexSnapshot Kind = "codex-snapshot" // SPEC §7.2
	KindCodexRestore  Kind = "codex-restore"
	KindHistoryRotate Kind = "history-rotate" // SPEC §7.1.4
	KindHistoryMerge  Kind = "history-merge"
	KindMarkdown      Kind = "md"
	KindPrune         Kind = "prune"
)

// Phase is a completed, durable milestone: a record is advanced to a phase
// only after the step that phase names has finished and is durable, so
// recovery always acts on the last milestone reached (D58).
type Phase string

// Phases (each operation uses the subset listed in SPEC §10.3/§11.5/§7.1.4).
const (
	PhasePrepared   Phase = "prepared"    // sources snapshotted, generation reserved, Tmp and final Capsule name recorded
	PhaseTmpWritten Phase = "tmp_written" // capsule temporary written and FullSynced (not yet renamed or logged)
	PhaseCommitted  Phase = "committed"   // generation renamed no-replace, directory fsynced AND appended to the capsule log
	PhaseUnlinking  Phase = "unlinking"   // deleting originals (identity-checked); Files[i].Done marks progress
	PhaseRescue     Phase = "rescue"      // a late tail is being sealed into a rescue generation
	PhaseStaged     Phase = "staged"      // restore: unit decrypted into staging and verified
	PhasePlacing    Phase = "placing"     // restore: no-replace renames in progress; Files[i].Done marks progress
	PhaseHeld       Phase = "held"        // history: hold link created (HoldSize = S0)
	PhaseSealed     Phase = "sealed"      // history: extracted lines of [0, Pending) committed as generations
	PhaseRewritten  Phase = "rewritten"   // history: filtered file renamed in; Offset = S1, NewBase set
	PhaseDone       Phase = "done"
)

// Record is state/journal/<id>.json.
type Record struct {
	V        int       `json:"v"`
	ID       string    `json:"id"` // ULID-like, sortable
	Kind     Kind      `json:"kind"`
	Unit     string    `json:"unit"` // unit key
	Harness  string    `json:"harness"`
	Phase    Phase     `json:"phase"`
	PID      int       `json:"pid"`
	Started  time.Time `json:"started"`
	Updated  time.Time `json:"updated"`
	Tmp      string    `json:"tmp,omitempty"`     // capsule temp name (relative to the unit capsule dir)
	Capsule  string    `json:"capsule,omitempty"` // final capsule name (g<N>.pcap), recorded at PhasePrepared, BEFORE the rename
	Gen      uint64    `json:"gen,omitempty"`
	Files    []File    `json:"files,omitempty"`
	Staging  string    `json:"staging,omitempty"` // absolute staging dir
	Hold     string    `json:"hold,omitempty"`    // history hold link name
	HoldSize int64     `json:"hold_size,omitempty"`
	// History rotation offsets in the hold inode (SPEC §7.1.4): Offset is
	// the end of the bytes fully processed (kept lines in the new file and
	// extracted lines sealed); Pending is the end of the range being
	// processed (> Offset while an iteration is in flight); NewBase is the
	// size of the rewritten history.jsonl right after the rename (tail
	// appends skip kept lines already present after it, so a re-run never
	// appends a line twice).
	Offset  int64 `json:"offset,omitempty"`
	Pending int64 `json:"pending,omitempty"`
	NewBase int64 `json:"new_base,omitempty"`
	// LedgerSID and LedgerN name the ledger snapshot sealed into the
	// capsule (S13): after a committed seal, recovery archives that many
	// bytes of the session's ledger (ledger.Archive).
	LedgerSID string   `json:"ledger_sid,omitempty"`
	LedgerN   int64    `json:"ledger_n,omitempty"`
	Notes     []string `json:"notes,omitempty"` // content-free diagnostics
}
```

### `internal/sweep/capslog`

- Owner: **G4 orchestration** · layer 1 · production
- May import (module): `internal/fsx`
- May import (third party): stdlib only
- Tests: unit: append/lookup by header hash, deleted folding, torn last line ignored, Compact

> Package capslog is the capsule provenance log state/capsules.log: one
> JSON line per committed capsule. Restore and key release accept only
> logged capsules; anything else is quarantined (SPEC §11.1; D8, D39).
>
> The log holds no content and no plaintext paths: units are named by
> HMAC-derived unit keys (D45). It is read by internal/agent for key
> release, so it must stay a leaf package.

```go
// Version is the line format.
const Version = 1

// ErrNotLogged means the capsule has no matching log entry (exit 5).
var ErrNotLogged = errors.New("capslog: capsule not in the provenance log")

// Entry is one log line.
type Entry struct {
	V             int       `json:"v"`
	Path          string    `json:"path"`          // relative to CapsulesDir, e.g. "claude-code/<unit>/g000003.pcap"
	SHA256        string    `json:"sha256"`        // whole ciphertext
	HeaderSHA256  string    `json:"header_sha256"` // age header: provenance key for key release (D39)
	Size          int64     `json:"size"`
	Kind          string    `json:"kind"`
	Harness       string    `json:"harness"`
	Unit          string    `json:"unit"`     // unit key
	VaultID       string    `json:"vault_id"` // sealing vault
	RootIDs       []string  `json:"root_ids"` // all must be unlocked for key release
	Gen           uint64    `json:"gen"`
	Parent        uint64    `json:"parent"`
	Lineage       string    `json:"lineage"`
	Snapshot      bool      `json:"snapshot,omitempty"` // codex-home: restore newest only (D42)
	Blob          bool      `json:"blob,omitempty"`
	SealedAt      time.Time `json:"sealed_at"`
	RecipientsFpr string    `json:"recipients_fpr"`
	Files         int       `json:"files"`
	Bytes         int64     `json:"bytes"` // plaintext total (restore free-space planning)
	LastActivity  time.Time `json:"last_activity,omitempty"`
	// Deleted marks a later "forget"/"prune" record for Path (append-only log).
	Deleted bool `json:"deleted,omitempty"`
}

// Log is the provenance log file.
type Log struct {
	Path string
}

// Open returns the log at path.
func Open(path string) *Log

// All returns every live entry (deleted ones folded away).
func (l *Log) All() ([]Entry, error)

// Append writes e as one line (fsx.AppendLine, FullSync).
func (l *Log) Append(e Entry) error

// Compact rewrites the log without deleted entries (atomic; only under the
// sweep lock).
func (l *Log) Compact() error

// Lookup returns the live (not deleted) entry for path whose HeaderSHA256
// equals headerSHA256; ErrNotLogged otherwise.
func (l *Log) Lookup(path, headerSHA256 string) (Entry, error)

// MarkDeleted appends a deletion record for path.
func (l *Log) MarkDeleted(path string, at time.Time) error

// Unit returns the live entries of a unit, ordered by Gen.
func (l *Log) Unit(unit string) ([]Entry, error)
```

### `internal/sweep/queue`

- Owner: **G4 orchestration** · layer 2 · production
- May import (module): `internal/fsx`, `internal/platform`
- May import (third party): stdlib only
- Tests: unit: enqueue/list/update/remove, atomicity

> Package queue holds pending seal requests (state/queue/<id>.json) written
> by hooks and wrappers and drained by the sweep-lock holder or a
> daemon-spawned worker (SPEC §10.6; R19, HA16, HA17).

```go
// Version is the request format.
const Version = 1

// Enqueue writes r atomically (ID assigned if empty) and returns its id.
func Enqueue(dir string, r Request) (string, error)

// Remove deletes a request.
func Remove(dir, id string) error

// Update rewrites r (attempts, backoff).
func Update(dir string, r Request) error

// Request asks for one session (or unit) to be sealed once its writer is
// gone. It holds no content.
type Request struct {
	V         int             `json:"v"`
	ID        string          `json:"id"`
	Harness   string          `json:"harness"`
	SID       string          `json:"sid,omitempty"`
	UnitKey   string          `json:"unit_key,omitempty"`
	Reason    string          `json:"reason"`               // SessionEnd reason | "wrapper-exit" | "lock" | "codex-exit"
	WaitFor   platform.ProcID `json:"wait_for,omitempty"`   // process that must exit first (--wait-pid PID:START)
	Warm      bool            `json:"warm,omitempty"`       // clear/resume: seal when the registry no longer names the sid and it is quiet (HA16)
	ConfigDir string          `json:"config_dir,omitempty"` // harness home realpath (must be registered)
	Cwd       string          `json:"cwd,omitempty"`
	At        time.Time       `json:"at"`
	NotBefore time.Time       `json:"not_before,omitempty"` // retry backoff
	Attempts  int             `json:"attempts,omitempty"`
	Deadline  time.Time       `json:"deadline,omitempty"` // give up and report after (codex: ~6 h, HA17)
}

// List returns pending requests ordered by At.
func List(dir string) ([]Request, error)
```

### `internal/sweep`

- Owner: **G4 orchestration** · layer 7 · production
- May import (module): `internal/capsule`, `internal/vault`, `internal/harness`, `internal/harness/claude`, `internal/harness/codex`, `internal/harness/generic`, `internal/live`, `internal/ledger`, `internal/config`, `internal/paths`, `internal/fsx`, `internal/fsx/failpoint`, `internal/platform`, `internal/sweep/journal`, `internal/sweep/capslog`, `internal/sweep/queue`, `inventories`
- May import (third party): stdlib, `github.com/awnumar/memguard`
- Tests: unit+crash-injection: the full matrix SEAL-*, REST-*, HIST-*, CODX-*, NOTE-*, CONC-*, PERF-* (docs/TESTPLAN.md §4) with -tags failpoints; placement table golden tests; lineage/generation tests incl. receipts rewritten after commit; provenance (forged capsules quarantined, crash leftovers never quarantined); manifest unit id authenticated against the logged unit key (SEC-2)

> Package sweep orchestrates sealing and restoring (SPEC §8, §10, §11):
> planning per unit, keyless two-pass sealing through internal/capsule,
> generations that are never overwritten (D9), lineage from restore receipts
> (D10, D42), the provenance log (D8), journaled crash-safe phases (I9),
> deletion of originals with identity and liveness re-checks, unit-atomic
> restore through staging with the placement table (D11, D12), history
> rotation and merge (D21, D36), the Markdown policy (D16, D17), Codex
> per-root home snapshots (D31), the seal queue and the sweep lock.
>
> sweep never holds an identity: restore obtains per-capsule file keys
> through KeySource (production: the daemon, D39). sweep never imports
> internal/ipc; cmd/precinto adapts ipc to KeySource and Grants.

```go
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

// CatNote decrypts the newest generation of the logged note a marker names
// and writes its bytes to w (`precinto cat`; the CLI sanitizes for a TTY,
// S17). Keys come from keys with purpose "cat" (fresh presence from agent
// contexts, D28).
func CatNote(ctx context.Context, e Env, keys KeySource, marker string, w io.Writer) error

// MarkerText returns the exact bytes of the in-tree marker of a sealed note
// (SPEC §8.4): two lines, the second naming the unit key. ui.MsgNoteMarker
// mirrors it (plus this final newline); a cmd/precinto test asserts both
// are identical. Implemented in the scaffold.
func MarkerText(unitKey string) []byte

// NextGen reserves the next generation number of a unit: a counter in
// state/gens/<unit> persisted with FullSync before use, never a timestamp
// (D9, R16). Numbers are never reused; a crash can leave gaps (a reserved
// generation whose capsule recovery removed), and nothing may assume
// consecutive numbers (lineage uses logged Parent links, D58).
func NextGen(e Env, unit string) (uint64, error)

// ParseMarker reads a *.md.precinto marker (at most 4 KiB, opened
// O_NOFOLLOW, regular file) and returns the unit key it names, or
// ErrNotMarker. Callers still require the unit to be logged (§11.1).
func ParseMarker(path string) (unitKey string, err error)

// CodexPrefer selects the side kept in place by ReconcileCodex.
type CodexPrefer string

// Reconcile preferences.
const (
	PreferCapsule   CodexPrefer = "capsule"
	PreferPlaintext CodexPrefer = "plaintext"
)

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
	// Sleep waits d or until ctx ends; nil = a real timer. It is used for
	// the D63 quiet-window wait (and every other wait of a run: rescue
	// grace, history tail quiet, writer polling). Tests with a fake clock
	// pass one that advances it.
	Sleep func(ctx context.Context, d time.Duration) error
}

// FileKeys is a set of released per-capsule file keys (*ipc.KeySet
// implements it, asserted in cmd/precinto).
type FileKeys interface {
	// Key returns the file key of a capsule path relative to CapsulesDir.
	Key(path string) (*memguard.LockedBuffer, bool)
	// Destroy wipes every key; called on completion and on any lock event.
	Destroy()
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
func Generations(e Env, unit string) ([]Generation, error)

// Grants reports which root ids are unlocked right now. An error means
// "treat every root as locked" (R4).
type Grants func(ctx context.Context) (unlocked map[string]bool, err error)

// KeySource obtains file keys (production: ipc.Client.Keys through
// cmd/precinto; tests: a vaulttest identity). Callers pass at most 256
// paths per FileKeys call (ipc.MaxKeysPerRequest) and destroy the keys as
// soon as their capsules are decrypted.
type KeySource interface {
	FileKeys(ctx context.Context, paths []string, purpose string) (FileKeys, error)
}

// ListOptions filters List.
type ListOptions struct {
	RootIDs   []string
	Conflicts bool
	Keys      KeySource // optional: decrypt manifests for titles (fresh presence rules apply, D28)
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

// Plaintext summarizes unencrypted files on disk per root and reason, for
// `precinto status` and `status --check` (UX22).
type Plaintext struct {
	RootID   string
	Files    int
	Bytes    int64
	ByReason map[string]int
}

// PlaintextSummary scans without sealing.
func PlaintextSummary(ctx context.Context, e Env) ([]Plaintext, error)

// PruneOptions selects generations to delete (D15: manual only).
type PruneOptions struct {
	Unit      string // unit key; "" = all units
	KeepLast  int    // default 3 (D9)
	Diverged  bool   // also prune diverged generations (requires explicit flag)
	OlderThan time.Duration
	DryRun    bool
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

// LoadReceipt reads the receipt of a unit (ok=false if none).
func LoadReceipt(e Env, unit string) (Receipt, bool, error)

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

// Report aggregates a run.
type Report struct {
	Started  time.Time
	Finished time.Time
	Units    []UnitResult
}

// DrainQueue processes state/queue requests whose wait conditions hold.
func DrainQueue(ctx context.Context, e Env, o Options) (*Report, error)

// Forget deletes every generation of a unit after typed confirmation on a
// TTY by the caller (`precinto forget`; refused from agent contexts, D59),
// logging deletion records (I12).
func Forget(ctx context.Context, e Env, unit string) (*Report, error)

// MergeHistory appends a root's sealed history lines that are not already
// present byte-for-byte (idempotent), restoring referenced paste-cache
// entries (SPEC §7.1.4).
func MergeHistory(ctx context.Context, e Env, keys KeySource, rootID string) (*Report, error)

// OpenNotes restores the notes named by markers in place (`precinto
// open`): RestoreMarkdown restricted to those units, purpose "open".
func OpenNotes(ctx context.Context, e Env, keys KeySource, markers []string) (*Report, error)

// Prune deletes generations fully subsumed by a successor chain, keeping
// KeepLast and every generation needed by a layered restore (D9, D42). The
// CLI calls it only after typed confirmation on a TTY (except DryRun) and
// never from an agent context (D59).
func Prune(ctx context.Context, e Env, o PruneOptions) (*Report, error)

// Quarantine moves capsules that are not in the provenance log to
// <base>/quarantine and reports them (S3, D8). It runs only after Recover
// has processed every journal record and never touches a capsule named by
// a pending journal record.
func Quarantine(ctx context.Context, e Env) (*Report, error)

// ReconcileCodex resolves a per-root Codex home whose plaintext diverged
// from its newest snapshot (R12): the other side is kept as a retained
// generation; nothing is deleted.
func ReconcileCodex(ctx context.Context, e Env, keys KeySource, rootID string, prefer CodexPrefer) (*Report, error)

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
func Recover(ctx context.Context, e Env) (*Report, error)

// Resolve keeps one side of a Markdown or file conflict (`precinto
// resolve`), sealing the other as a retained generation.
func Resolve(ctx context.Context, e Env, keys KeySource, path string, keep string) (*Report, error)

// Restore restores units unit-atomically through staging (SPEC §11.5): for
// each unit, provenance check against the capsule log (D8), file keys from
// keys (D39), free-space check, Extract with adapter target rules, placement
// table (D11), receipts (D10). Newest-first within Budget.
func Restore(ctx context.Context, e Env, keys KeySource, r RestoreRequest) (*Report, error)

// RestoreMarkdown restores a root's sealed notes at unlock: marker location
// minus suffix when a valid marker exists, else the authenticated original
// relpath (D16; SPEC §8.5).
func RestoreMarkdown(ctx context.Context, e Env, keys KeySource, root config.Root) (*Report, error)

// RotateHistory extracts protected-root lines of Claude's history.jsonl
// into per-root history generations with the hold-link protocol (D21, D36,
// SPEC §7.1.4). Only when no Claude process is running anywhere.
func RotateHistory(ctx context.Context, e Env) (*Report, error)

// Seal seals the given units now (seal command, wrapper exit, queue
// worker), honouring liveness and leases; it never needs a key.
func Seal(ctx context.Context, e Env, units []harness.Unit, o Options) (*Report, error)

// SealMarkdown applies a root's Markdown policy (SPEC §8): candidates from
// the ledger, transcripts and (md=all) a scan; excludes; git-tracked check
// via a hardened git invocation; no seal while a session that wrote the note
// is live or busy (D17); store capsule + in-tree marker (D16).
func SealMarkdown(ctx context.Context, e Env, root config.Root, o Options) (*Report, error)

// Sweep is `precinto sweep`: take state/locks/sweep.lock (TryLock; if busy,
// touch sweep.requested and return ErrBusy unless o.Wait), Recover, drain
// the queue, scan every adapter's homes, seal every non-live,
// non-leased unit whose roots are locked (units restored under a current
// grant are left alone, R4), rotate global stores, apply the Markdown
// policy, then rescan once if sweep.requested was touched meanwhile.
func Sweep(ctx context.Context, e Env, o Options) (*Report, error)

// Count returns the number of units with outcome o.
func (r *Report) Count(o Outcome) int

// Err summarizes failures as one error (nil if none). Live, warm and
// leased units are failures (ErrLive, exit 4) only for an explicit Seal of
// named units (their Detail carries the live code); sweeps report them as
// outcomes and exit 0.
func (r *Report) Err() error

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

// List returns units from the capsule log and the on-disk scan.
func List(ctx context.Context, e Env, o ListOptions) ([]UnitInfo, error)

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
```

## G5 hooks & packaging

### `github.com/precinto/precinto` (module root)

- Owner: **G5 hooks & packaging** · layer 0 · production
- May import (module): none
- May import (third party): stdlib only
- Tests: the embedded files equal the repository's two marketplace manifests and plugin roots byte for byte, nothing more, nothing less (plugins_test.go)

> Package precinto carries precinto's harness plugins and their
> marketplace manifests (SPEC §21) inside the binary, so that `precinto
> integrate` installs them from bytes precinto controls, written under
> precinto's own directory, and never from a network marketplace (D116).
>
> The files are embedded at their repository paths: the Claude Code
> marketplace (.claude-plugin/marketplace.json → plugin/), the Codex one
> (.agents/plugins/marketplace.json → plugins/codex/, byte-stable, D41,
> D78) and every file of both plugin roots. Directories are named one by
> one so that a stray dot file of a checkout (.DS_Store) is never
> embedded; a test keeps the list equal to the repository's files.

```go
// Plugins holds the marketplace manifests and the plugin files, at their
// repository paths.
var Plugins embed.FS
```

### `internal/hook`

- Owner: **G5 hooks & packaging** · layer 8 · production
- May import (module): `internal/ipc`, `internal/ledger`, `internal/config`, `internal/paths`, `internal/platform`, `internal/fsx`, `internal/ui`, `internal/harness`, `internal/harness/codex`, `internal/sweep/queue`
- May import (third party): stdlib, `github.com/awnumar/memguard`
- Tests: golden: synthetic payloads per host/version/event → exact stdout/stderr/exit (HOOKS-IO.md), Codex outputs decoded with deny_unknown_fields structs; unit: host detection (label default, every gate event without CLAUDE_PID, Codex SessionStart/SessionEnd without turn_id), fail-closed on every error path, deadline, panic recovery; shim tests (shellcheck, exit-code table, PRECINTO_* ignored, failed run inside/outside roots)

> Package hook implements `precinto hook <harness> <event>` (SPEC §14,
> docs/HOOKS-IO.md): real-host detection that defaults to the argv label
> (HA21, D56), per-harness payload
> decoders that keep only content-free facts, the decision logic (ledger
> taint, gate query with a 150 ms budget, fail-closed for managed sessions,
> GUI-only unlock on human prompts, D22/D26/D27/D37), per-harness/per-event
> output encoders, its own deadline below the harness timeout, panic
> recovery, and the detached seal request at SessionEnd.
>
> Never write hook stdin, prompts, tool input/output, summaries or
> environment values anywhere (logs, ledger, errors) — including on parse
> errors (S11, S13). The allow path prints nothing on stdout. Hook mode
> never honours PRECINTO_* overrides: hooks always run in an agent context
> (D6). Every dependency is behind Deps (fakeable Daemon and Ledger,
> injected Identify, Enqueue and Spawn), so golden tests need no other
> group's implementation.

```go
// Exit codes of the binary in hook mode (D43, D56). The POSIX shim passes
// stdout through on ExitOK, maps ExitBlockCode2 to 2, and treats any other
// exit (ExitFailure, a Go runtime exit 2, a signal) like a missing binary:
// it discards stdout and, for gate events whose $PWD or
// $CLAUDE_PROJECT_DIR lies inside a root of roots.list, prints the host's
// static block (text ui.MsgShimFailed); otherwise it exits 0.
const (
	ExitOK         = 0
	ExitBlockCode2 = 10 // intended "exit 2" block (Codex UserPromptSubmit, PreToolUse, PermissionRequest)
	ExitFailure    = 1  // internal failure (never used deliberately for a managed gate event: FailClosed instead)
)

// MaxPayload bounds stdin; larger payloads are treated as a decode failure
// (fail closed for managed gate events).
const MaxPayload = 64 << 20

// IsGate reports whether ev can block on host (prompt, tool, compaction or
// permission gate).
func IsGate(host Host, ev Event) bool

// Main is the whole `precinto hook <label> <event>` command: platform
// hardening, deadline from Timings, panic recovery (fail closed for managed
// gate events, exit 0 otherwise), Decode, Handle, Encode. It returns the
// process exit code.
func Main(args []string, stdin io.Reader, stdout, stderr io.Writer, env paths.Env) int

// Daemon is the subset of the ipc client the hook uses (fakeable;
// *ipc.Client implements it, asserted in cmd/precinto).
type Daemon interface {
	Gate(ctx context.Context, r ipc.GateReq) (ipc.GateResp, error)
	Activity(ctx context.Context, r ipc.ActivityReq) error
	Register(ctx context.Context, r ipc.RegisterReq) error
	Unlock(ctx context.Context, r ipc.UnlockReq, ui ipc.UIHandler) (ipc.UnlockResp, error)
	Close() error
}

// Decision is what the hook answers.
type Decision struct {
	Verdict      ipc.Verdict // allow | block | deny
	UserMessage  string      // shown to the user (block reason, PreCompact stderr)
	ModelMessage string      // PreToolUse deny reason addressed to the model
	Context      string      // SessionStart additionalContext (locked folder notice)
}

// Handle runs the decision logic for one decoded payload: ledger taint and
// facts, gate for managed sessions (fail closed when the daemon is
// unreachable), optional GUI unlock for human prompts, activity, and the
// SessionEnd seal request. It never blocks SessionStart and never prompts
// from it.
func Handle(ctx context.Context, d Deps, p Payload) Decision

// Deps are the hook's dependencies; every field is fakeable so golden tests
// need no other group's implementation.
type Deps struct {
	Cfg    config.Config
	Layout paths.Layout
	Env    paths.Env
	Ledger Ledger
	Procs  platform.ProcTable
	// Identify measures the ProcID of the harness pid (platform.Identify).
	Identify func(pid int) (platform.ProcID, error)
	Now      func() time.Time
	// Dial connects without autostart within ipc.GateBudget.
	Dial func(ctx context.Context) (Daemon, error)
	// DialUnlock connects with autostart for the slow unlock path only
	// (IM7).
	DialUnlock func(ctx context.Context) (Daemon, error)
	// Enqueue writes a seal request (SessionEnd) and Spawn starts the
	// detached `precinto seal --queue` worker (Setsid, stdio /dev/null).
	// Spawn's argv is the arguments after the precinto executable (e.g.
	// ["seal","--queue"]); the production implementation prepends
	// platform.Executable() and spawns detached with an allowlisted env and
	// cwd /.
	Enqueue func(r queue.Request) (string, error)
	Spawn   func(argv []string) error
}

// Event is a hook event name in Claude's PascalCase spelling; decoders map
// other hosts' names (camelCase) onto it.
type Event string

// Events.
const (
	SessionStart      Event = "SessionStart"
	UserPromptSubmit  Event = "UserPromptSubmit"
	PreToolUse        Event = "PreToolUse"
	PermissionRequest Event = "PermissionRequest"
	PostToolUse       Event = "PostToolUse"
	PreCompact        Event = "PreCompact"
	PostCompact       Event = "PostCompact"
	Stop              Event = "Stop"
	StopFailure       Event = "StopFailure"
	Interrupt         Event = "Interrupt"
	Notification      Event = "Notification"
	CwdChanged        Event = "CwdChanged"
	DirectoryAdded    Event = "DirectoryAdded"
	SessionEnd        Event = "SessionEnd"
)

// Host is the harness that actually invoked the hook (HA21).
type Host string

// Hosts.
const (
	HostClaude  Host = "claude-code"
	HostCodex   Host = "codex"
	HostCursor  Host = "cursor"  // experimental (D41)
	HostCopilot Host = "copilot" // experimental (D41)
	HostDroid   Host = "droid"   // Claude-compatible payloads, Droid tool names
	HostUnknown Host = "unknown" // neither markers nor the argv label name a host: gate events inside a root exit ExitFailure (the shim then blocks), others exit 0
)

// DetectHost identifies the real host (HA21, D56; docs/HOOKS-IO.md §0.7),
// first match wins: other-host markers (CURSOR_VERSION/CURSOR_PLUGIN_ROOT ⇒
// cursor; COPILOT_* or camelCase event names ⇒ copilot;
// DROID_PLUGIN_ROOT/FACTORY_PROJECT_DIR ⇒ droid); Codex markers (turn_id in
// the payload, or PLUGIN_ROOT set with label "codex" or with neither
// CLAUDE_PID nor CLAUDECODE); Claude markers (CLAUDE_PID, CLAUDECODE=1,
// CLAUDE_PROJECT_DIR); otherwise the argv label itself, which names the
// hooks file that invoked it. HostUnknown only for an unrecognised label
// with no markers. A missing marker never makes a gate fail open.
func DetectHost(label string, env paths.Env, raw []byte) Host

// Ledger is the subset of the ledger the hook uses (fakeable;
// *ledger.Ledger implements it).
type Ledger interface {
	Append(e ledger.Event) error
	Get(harness, sid string) (ledger.Session, error)
}

// Output is the rendered answer.
type Output struct {
	Stdout []byte
	Stderr []byte
	Exit   int
}

// Encode renders d for host/event exactly as docs/HOOKS-IO.md specifies
// (Claude: decision JSON on stdout with exit 0; Codex UserPromptSubmit,
// PreToolUse and PermissionRequest: fixed stderr reason with
// ExitBlockCode2; Codex PreCompact: {"continue":false,"stopReason":…};
// Codex SessionStart: nothing in v0.2; allow: empty stdout, exit 0). It
// never emits keys a host does not accept (Codex deny_unknown_fields).
func Encode(host Host, ev Event, d Decision) Output

// FailClosed returns the static block/deny output of a gate event in a
// managed session when precinto could not decide (decode error, deadline,
// panic) (I5), in the format of host (the detected host, which defaults to
// the argv label, D56). Its prompt text is C3.failed; the gate's own
// unreachable-daemon answer says C3.agentdown instead (CC-38).
func FailClosed(host Host, ev Event, folder string) Output

// Payload is the normalized, content-free view of one invocation. Raw
// prompts, tool input/output and summaries are never retained.
type Payload struct {
	Host           Host
	Label          string // harness label from argv
	Event          Event
	SID            string
	PromptID       string
	TurnID         string
	TranscriptPath string
	Cwd            string
	ProjectDir     string // CLAUDE_PROJECT_DIR
	ConfigDir      string // derived from transcript_path / CLAUDE_CONFIG_DIR / CODEX_HOME
	ScratchpadDir  string
	Source         string // SessionStart source
	Reason         string // SessionEnd reason
	Trigger        string // PreCompact trigger
	ToolName       string
	Notification   string   // notification_type (idle_prompt…)
	Paths          []string // absolute paths from tool_input (file_path, notebook_path, path), apply_patch headers
	MarkdownPaths  []string // subset of Paths written by Write/Edit/MultiEdit/NotebookEdit/apply_patch ending .md/.mdx/.markdown
	OldCwd, NewCwd string
	AddedDirs      []string
	HarnessPID     int             // CLAUDE_PID, or nearest ancestor whose executable is codex (HA17)
	HarnessProc    platform.ProcID // measured by precinto
	HarnessVersion string
	Entrypoint     string // CLAUDE_CODE_ENTRYPOINT
	CodexHome      string // CODEX_HOME seen by the hook (D31 check)
	AgentID        string // subagent context
}

// Decode reads at most MaxPayload bytes of raw (already read from stdin)
// and the environment into a Payload.
func Decode(host Host, label string, ev Event, raw []byte, env paths.Env, procs platform.ProcTable) (Payload, error)

// Timing is the harness timeout declared in the hooks file and the hook's
// own deadline, which must end strictly before it (D22).
type Timing struct {
	HarnessTimeout time.Duration
	Deadline       time.Duration // print a decision and exit before this
	UnlockWait     time.Duration // max time waiting for a GUI unlock (UserPromptSubmit only)
}

// Timings returns the normative timing for host/event (docs/HOOKS-IO.md §1).
func Timings(host Host, ev Event) Timing
```

### `internal/shellinit`

- Owner: **G5 hooks & packaging** · layer 8 · production
- May import (module): `internal/config`, `internal/paths`, `internal/ipc`, `internal/ui`
- May import (third party): stdlib only
- Tests: golden scripts per shell; zsh/bash syntax check (zsh -n, bash -n); OnEnter transitions, skip epochs, single-flight

> Package shellinit renders the zsh, bash and fish integration printed by
> `precinto shell-init <shell>` and implements the decision behind the
> folder-entry hook `precinto shell-hook` (SPEC §15.5; D29; UX19).
>
> The snippets define wrapper functions for enabled harnesses that run
> `command precinto run --harness H -- H "$@"` (guarded by PRECINTO_ACTIVE
> to avoid recursion), and a chpwd/precmd (zsh), PROMPT_COMMAND (bash) or
> --on-variable PWD (fish) hook that runs only in interactive top-level
> shells, is skipped when VSCODE_RESOLVING_ENVIRONMENT is set, fires only on
> outside→inside transitions (or the first prompt of a shell started
> inside), asks at most once per shell per lock epoch, and never reads the
> TTY in the fast path (daemon query ≤ 150 ms).

```go
// Shells.
const (
	Zsh  = "zsh"
	Bash = "bash"
	Fish = "fish"
)

// Install appends InstallLine to the rc file once (idempotent), only after
// the caller obtained consent.
func Install(shell, home string) error

// InstallLine returns the rc-file line (`eval "$(precinto shell-init zsh)"`).
func InstallLine(shell string) string

// RCFile returns the rc file for shell under home (~/.zshrc, ~/.bashrc,
// ~/.config/fish/config.fish).
func RCFile(shell, home string) string

// Script returns the integration snippet for o.Shell.
func Script(o Options) (string, error)

// EnterAction is what the folder-entry hook should do.
type EnterAction string

// Enter actions.
const (
	EnterNothing EnterAction = ""
	EnterNotify  EnterAction = "notify" // print ui.MsgEnterNotify
	EnterPrompt  EnterAction = "prompt" // print ui.MsgEnterPrompt (or .plain) and unlock on Enter
	EnterBusy    EnterAction = "busy"   // another terminal is unlocking (ui.MsgEnterElsewhere)
)

// EnterRequest is one shell-hook invocation.
type EnterRequest struct {
	PWD      string
	PrevPWD  string
	Shell    string
	SkipKey  string // _PRECINTO_SKIP=<root-id>:<epoch> from the shell
	FirstRun bool   // first prompt of a new shell
	Home     string // the user's HOME, for ~-shortened folders
	// GUI reports whether a GUI dialog can appear for this terminal
	// (platform.DetectUIContext): C1.prompt names the Mac password only
	// then (ui.FactorName).
	GUI bool
}

// EnterResult is the decision of one shell-hook invocation; `precinto
// shell-hook` prints Lines() and nothing else (D69).
type EnterResult struct {
	Action  EnterAction
	RootID  string
	Path    string // absolute folder path, for precinto unlock --root
	Folder  string
	Epoch   uint64 // lock epoch, so a skip is remembered until the next lock
	Message string
}

// OnEnter decides the action for r using config and a ≤150 ms daemon
// status query; it never prompts and never autostarts the daemon.
func OnEnter(ctx context.Context, c config.Config, l paths.Layout, r EnterRequest) (EnterResult, error)

// Lines renders r as key=value lines action=, root=, epoch=, path=,
// folder=, message=, one per line, values stripped of C0/C1 controls (a
// newline or tab becomes a space), empty for EnterNothing. The scripts
// parse them without eval: a folder name never becomes shell code (D69).
func (r EnterResult) Lines() string

// Options configures Script.
type Options struct {
	Shell     string
	Harnesses []string // e.g. ["claude", "codex"] (executable names)
	Exe       string   // absolute precinto path written into the functions
}
```

## G6 wrapper

### `internal/wrapper`

- Owner: **G6 wrapper** · layer 8 · production
- May import (module): `internal/harness`, `internal/ipc`, `internal/live`, `internal/config`, `internal/paths`, `internal/platform`, `internal/fsx`, `internal/ui`
- May import (third party): stdlib, `github.com/creack/pty`, `golang.org/x/term`, `github.com/awnumar/memguard`
- Tests: unit: Scrollback bounds, safe boundaries and Wrapped, Modes tracking/restore, HumanInput filter table; integration with a fake Backend and fake Daemon and a scripted TUI child (testdata/ main package) on a PTY: lock overlay, replay of pre-lock output, input dropped while locked, end event termination of the child's own session only, direct-mode Setsid, job control, exit code propagation

> Package wrapper implements `precinto run [--harness H] [--no-pty] -- CMD
> [ARGS…]` (SPEC §15): launch planning through the harness adapter, unlock
> in this terminal, launch lease, synchronous restore of the targeted units
> before exec and background restore of the rest, the PTY proxy (raw mode,
> SIGWINCH, job control), the lock overlay with output kept in a bounded
> scrollback and replayed on unlock (D30), input gating with
> terminal-generated sequences filtered from human activity (UX15),
> termination on "end" events, TTY reset, and seal-after-exit.
>
> The wrapper never imports internal/sweep, internal/vault or
> internal/agent: it orchestrates through the Backend interface that
> cmd/precinto implements ("restore-before-launch orchestration via
> interfaces").

```go
// ExitNotStarted is Run's code when the child never started; err says why
// and cmd/precinto maps it with the API §5 table (e.g. sweep.ErrConflict →
// 4, ipc codes → 3). Otherwise Run returns the child's own code.
const ExitNotStarted = -1

// HumanInput reports whether b contains human keystrokes after removing
// sequences terminals send on their own (focus CSI I/O, mouse CSI M and
// CSI < … M/m, cursor reports CSI … R, DA replies CSI ? … c, kitty replies
// CSI ? … u, OSC replies) and whether it contains Enter (UX15, D37).
func HumanInput(b []byte) (human, enter bool)

// ResetSequence is the full terminal reset of SPEC §15.4 (optionally with
// clear screen + scrollback and iTerm2 ClearScrollback).
func ResetSequence(clear, iterm bool) []byte

// Run is `precinto run` (SPEC §15.1): Plan; a passthrough mode runs the
// child in the wrapper's own process group (not exec: no gate, no restore,
// SIGTERM forwarded, its exit code returned); an unmanaged launch (no
// folder) runs without unlock, daemon or registration. Otherwise: confirm
// (plan.Confirm), EnsureUnlocked, subscribe at once and wait for the
// folders' initial state (D71) — any lock, end or subscription loss from
// then until exec refuses the launch with ExitNotStarted and an exit-3
// C1.notify error — then plan.Prepare, AcquireLease, RestoreSync, start the
// child (PTY when stdin and stdout are terminals and the mode is
// interactive, else direct: started with Setsid so it is the leader of its
// own session, with SIGINT, SIGQUIT, SIGTERM and SIGHUP forwarded to it,
// D57), RecordLaunch, register as the wrapper, forward activity, handle
// lock/unlock/end events, RestoreBackground, wait, reset the terminal,
// plan.Finish, release the lease, SealAfterExit, print one summary line.
// Returns the child's exit code, or ExitNotStarted when the child never
// started (err says why).
func Run(ctx context.Context, o Options) (int, error)

// Backend is everything the wrapper needs from the rest of precinto.
// cmd/precinto implements it with internal/harness, internal/sweep,
// internal/live, internal/ledger and internal/ipc.
type Backend interface {
	// Plan asks the harness adapter for the launch plan.
	Plan(ctx context.Context, h harness.ID, cwd string, argv []string) (harness.LaunchPlan, error)
	// EnsureUnlocked unlocks the plan's roots in this terminal if needed
	// (TTY prompts or a relayed Secure Enclave dialog). ui is the terminal.
	EnsureUnlocked(ctx context.Context, roots []config.Root, ui ipc.UIHandler) error
	// AcquireLease takes the launch lease before any restore (SPEC §9.3).
	AcquireLease(ctx context.Context, plan harness.LaunchPlan) (Lease, error)
	// RestoreSync restores plan.Sync before exec; abort is closed on lock.
	RestoreSync(ctx context.Context, plan harness.LaunchPlan, abort <-chan struct{}) (RestoreSummary, error)
	// RestoreBackground restores plan.Background after exec (best effort).
	RestoreBackground(ctx context.Context, plan harness.LaunchPlan, abort <-chan struct{})
	// Daemon returns a new connection on every call (autostarted); the
	// wrapper keeps one for the subscription stream and one for requests
	// (register, activity, unlock-from-overlay), and dials again after a
	// loss.
	Daemon(ctx context.Context) (Daemon, error)
	// RecordLaunch writes the ledger "launch" event for a launch whose
	// session id is known before exec (resume targets, and fresh launches
	// whose id the plan chose, D107), carrying the lease keys and harness
	// homes; a no-op when the sid is not known yet.
	RecordLaunch(ctx context.Context, plan harness.LaunchPlan, child platform.ProcID) error
	// WatchSessions follows, until ctx ends, which sessions the child runs
	// (Claude names them in its live-session registry while it runs) and
	// records each one it has not recorded yet like RecordLaunch, so a
	// session no hook reported is the child's too and is sealed after exit
	// (D107). Run calls it for managed launches only, from the start of the
	// child until it was reaped, and waits for it to return before
	// SealAfterExit.
	WatchSessions(ctx context.Context, plan harness.LaunchPlan, child platform.ProcID)
	// SealAfterExit seals the session's units after the child was reaped
	// (writer known exited, R20), or queues them if still live.
	SealAfterExit(ctx context.Context, plan harness.LaunchPlan, child platform.ProcID) (SealSummary, error)
	// HooksSeen reports whether a hook event arrived for the child (UX10).
	// Run asks it before SealAfterExit: sealing a session moves its ledger,
	// hooks_seen included, into the capsule (S13, D108).
	HooksSeen(ctx context.Context, plan harness.LaunchPlan, child platform.ProcID) (bool, error)
}

// Daemon is the subset of the ipc client the wrapper uses (fakeable;
// *ipc.Client implements it, asserted in cmd/precinto). G6 tests use a fake
// and never need a real daemon.
type Daemon interface {
	Register(ctx context.Context, r ipc.RegisterReq) error
	Unregister(ctx context.Context, r ipc.UnregisterReq) error
	Subscribe(ctx context.Context, r ipc.SubscribeReq) (<-chan ipc.Event, error)
	Activity(ctx context.Context, r ipc.ActivityReq) error
	Unlock(ctx context.Context, r ipc.UnlockReq, ui ipc.UIHandler) (ipc.UnlockResp, error)
	Close() error
}

// Lease is a held launch lease (live.Held behind an interface; *live.Held
// implements it, asserted in cmd/precinto).
type Lease interface {
	Add(keys ...string) error
	SetChild(child platform.ProcID) error
	Inheritable() []*os.File
	Release() error
}

// Modes tracks DEC private modes and keyboard protocol state set by the
// child, including while locked.
type Modes struct {
	// contains filtered or unexported fields
}

// NewModes returns an empty tracker.
func NewModes() *Modes

// Feed parses child output for CSI ? Pm h/l, CSI > … u / CSI < u (kitty).
func (m *Modes) Feed(b []byte)

// Reset returns the sequence that turns every tracked mode off (TTY reset
// at exit and before the lock overlay).
func (m *Modes) Reset() []byte

// Restore returns the sequence re-establishing the tracked modes.
func (m *Modes) Restore() []byte

// Options configures Run.
type Options struct {
	Harness harness.ID
	Argv    []string // argv[0] is the harness executable name or path
	Cwd     string
	Env     paths.Env
	NoPTY   bool
	Stdin   *os.File
	Stdout  *os.File
	Stderr  io.Writer
	Policy  config.Policy
	Backend Backend
}

// Overlay is the lock screen content (SPEC §16.3 C4).
type Overlay struct {
	Folder string
	Reason string // ui.Reason text
	Factor string // "Mac password", "passphrase", "YubiKey"
	Busy   bool   // show the busy line
	// Harness is {harness} of C4.busy: the inventory display name
	// ("Claude Code", "Codex").
	Harness string
}

// Proxy runs a child on a PTY bound to the user's terminal.
type Proxy struct {
	// contains filtered or unexported fields
}

// StartProxy starts cmd on a new PTY, puts tty in raw mode, propagates
// SIGWINCH, and forwards I/O until Wait returns.
func StartProxy(cmd *exec.Cmd, tty *os.File, o ProxyOptions) (*Proxy, error)

// Child returns the child's ProcID.
func (p *Proxy) Child() platform.ProcID

// Lock stops forwarding input (keys are dropped, not queued), keeps
// recording child output in the scrollback ring (which holds output since
// the child started, not only since the lock) while tracking terminal
// modes, clears the screen (and scrollback when configured), and draws the
// overlay on a fresh alternate screen: when the child uses the alternate
// screen, Lock leaves it and clears the main screen first, and Unlock
// restores the child's (D30, IM16, SPEC §15.2).
func (p *Proxy) Lock(o Overlay) error

// Locked reports whether the overlay is shown.
func (p *Proxy) Locked() bool

// OverlayKeys returns keys pressed on the overlay: Enter (unlock) and
// Ctrl-D (end session); everything else is dropped and is never activity.
func (p *Proxy) OverlayKeys() <-chan byte

// Terminate ends the child: optional quit keys, SIGTERM, wait Grace,
// SIGKILL, then SIGKILL of the child's remaining session
// (platform.SignalGroup with the child's pid: the PTY child is the leader
// of a session the wrapper created, never the user's terminal session;
// R11, D57).
func (p *Proxy) Terminate(o TerminateOptions) error

// Unlock clears the overlay and the screen, replays the ring from its safe
// boundary (Scrollback.Bytes) so inline-mode TUIs such as Claude's default
// mode get their finished messages back, restores tracked modes (1049,
// 1000–1006, 2004, 1004, 25, kitty flags) and forces a repaint by resizing
// to cols−1 then cols 50 ms apart (a same-size SIGWINCH does not repaint
// Node/ratatui TUIs). When the ring wrapped, only its tail is replayed
// before the repaint (output older than the ring is not shown again, SPEC
// §19).
func (p *Proxy) Unlock() error

// Wait waits for the child, handles job control (on a stop, restore the
// outer terminal and stop the wrapper itself; on SIGCONT re-enter raw mode,
// continue the child and repaint, UX14) and returns its exit code.
func (p *Proxy) Wait() (int, error)

// ProxyOptions configures the PTY proxy.
type ProxyOptions struct {
	ScrollbackBytes int  // ring of ALL child output since start, replayed at unlock (default 8 MiB, D30, D60)
	ITerm           bool // TERM_PROGRAM=iTerm.app: add OSC 1337;ClearScrollback
	ClearScrollback bool // policy.clear_scrollback_on_lock (D30)
	// OnHuman is called (rate-limited by the caller) for filtered human
	// input; enter reports an Enter keystroke (D37).
	OnHuman func(enter bool)
}

// RestoreSummary is the content-free result of a restore step.
type RestoreSummary struct {
	Units     int
	Files     int
	Bytes     int64
	Conflicts int
	Skipped   int
	Notices   []string // ui catalog lines (e.g. MsgResumeOld)
}

// Scrollback is a bounded ring buffer of all raw child output since the
// child started (D30, D60). It holds terminal output of the session in
// wrapper memory only and is wiped at exit.
type Scrollback struct {
	// contains filtered or unexported fields
}

// NewScrollback returns a buffer of max bytes.
func NewScrollback(max int) *Scrollback

// Bytes returns the buffered output for replay. Before the ring wraps it
// is every byte since start; after, it starts at a safe boundary — the
// first line start after the oldest kept byte, never inside an escape
// sequence or UTF-8 rune — preceded by an SGR reset.
func (s *Scrollback) Bytes() []byte

// Wipe zeroes the buffer.
func (s *Scrollback) Wipe()

// Wrapped reports whether output was dropped (the replay is only the tail).
func (s *Scrollback) Wrapped() bool

// Write appends output, dropping the oldest bytes beyond the bound.
func (s *Scrollback) Write(b []byte) (int, error)

// SealSummary is the content-free result of seal-after-exit. Files and
// Bytes count what was sealed (or dropped as unchanged) now; the wrapper
// says "sealed" only when Files > 0 (D108). SID is the session the exit
// lines name and C5 resumes: the one the child ran last that the seal
// found files of, else the launch's target; "" when no such session is
// known (C5 then suggests continuing the folder's latest session, D107).
type SealSummary struct {
	SID      string
	Files    int
	Bytes    int64
	Deferred bool   // still live: queued (MsgSealDeferred)
	Failed   string // error class (MsgSealFailed)
}

// TerminateOptions configures Terminate.
type TerminateOptions struct {
	QuitKeys []byte        // sent through the PTY first (Codex: Ctrl-C twice, R20/HA19)
	KeysWait time.Duration // wait after QuitKeys (3s)
	Grace    time.Duration // SIGTERM→SIGKILL delay (harness.KillGrace; LaunchPlan.KillGrace)
}
```

## G7 CLI

### `internal/paths`

- Owner: **G7 CLI** · layer 1 · production
- May import (module): `internal/fsx`
- May import (third party): stdlib only
- Tests: unit: layouts per OS, override rules with/without -tags testing and PRECINTO_DEV + agent markers (D6), socket length limit, Within component-wise and case-folded, LookPath ignores relative PATH entries (scaffold helpers tested in paths_test.go)

> Package paths resolves every precinto-owned location and is the only
> package that reads the process environment (SPEC §6, D6).
>
> Production builds ignore PRECINTO_HOME and PRECINTO_RUNTIME_DIR unless
> the binary was built with `-tags testing`, or PRECINTO_DEV=1 is set and
> no agent marker is present (D6). The hook shim never reads PRECINTO_*
> variables. Unit tests do not need the tag: they build a Layout
> explicitly with LayoutAt.
>
> The scaffold implements the leaf helpers every group needs from day one
> (Env, UserHome, DefaultBase, LayoutAt, Within, Clean, Tilde and the
> Layout path helpers); NewLayout, AgentMarkers, OverridesAllowed and
> EnsureDirs are G7's.

```go
// Environment variables precinto reads. Harness variables are read only to
// resolve harness homes in the harness's own context (SPEC §7.0). There is
// no PRECINTO_BIN: the hook shim never reads PRECINTO_* variables, because
// hooks always run in an agent context (D6, HOOKS-IO §5).
const (
	EnvHome       = "PRECINTO_HOME"        // base dir override (testing tag / PRECINTO_DEV only)
	EnvRuntimeDir = "PRECINTO_RUNTIME_DIR" // socket dir override (testing tag / PRECINTO_DEV only)
	EnvDev        = "PRECINTO_DEV"         // "1" enables overrides outside agent contexts
	EnvActive     = "PRECINTO_ACTIVE"      // set by the wrapper in the child; prevents recursion
	EnvE2E        = "PRECINTO_E2E"         // "1" enables opt-in E2E tests
	// EnvCrashpoint arms fault injection in binaries built with -tags
	// failpoints: cmd/precinto reads it here and calls failpoint.Set before
	// dispatching (docs/TESTPLAN.md §4). Ignored by every other build.
	EnvCrashpoint = "PRECINTO_CRASHPOINT"
	// EnvTestAncestryStop ("PID:START") ends the harness-ancestry walk of
	// ui.AgentContext and of the daemon's peer checks at that process, in
	// -tags testing builds only (D64); read it with TestAncestryStop.
	// Production builds never read it; hook mode and the shim ignore it.
	EnvTestAncestryStop = "PRECINTO_TEST_ANCESTRY_STOP"

	EnvClaudeConfigDir   = "CLAUDE_CONFIG_DIR"
	EnvClaudeTmpDir      = "CLAUDE_CODE_TMPDIR"
	EnvClaudeProjectName = "CLAUDE_CODE_PROJECT_DIR_NAME"
	EnvClaudePID         = "CLAUDE_PID"
	EnvClaudeProjectDir  = "CLAUDE_PROJECT_DIR"
	EnvClaudeCode        = "CLAUDECODE"         // "1" in Claude Code hooks and tools (host marker, D56)
	EnvClaudePluginRoot  = "CLAUDE_PLUGIN_ROOT" // Claude; Codex sets it too, as an alias of PLUGIN_ROOT
	EnvPluginRoot        = "PLUGIN_ROOT"        // Codex hooks (host marker without CLAUDE_PID, D56)
	EnvCodexHome         = "CODEX_HOME"
	EnvCodexSQLiteHome   = "CODEX_SQLITE_HOME"
	EnvXDGDataHome       = "XDG_DATA_HOME"
	EnvXDGRuntimeDir     = "XDG_RUNTIME_DIR"
)

// Names fixed by the product (owner-revisable, OD-05).
const (
	// ServiceLabel is the LaunchAgent label; its plist is
	// ~/Library/LaunchAgents/<label>.plist.
	ServiceLabel = "com.github.precinto.sweep"
	// ClaudePluginID is the Claude Code plugin id: plugin precinto of the
	// marketplace precinto (SPEC §21).
	ClaudePluginID = "precinto@precinto"
)

// MaxSocketPath is the exclusive upper bound on the socket path length
// (darwin sun_path is 104 bytes; linux allows 108, precinto uses the
// stricter bound everywhere).
const MaxSocketPath = 104

// ErrSocketPath is returned when the socket path would be too long.
var ErrSocketPath = errors.New("paths: socket path too long (use a shorter PRECINTO_RUNTIME_DIR)")

// AgentMarkers returns the names of environment variables that indicate an
// AI-agent context (CLAUDECODE, CLAUDE_CODE_ENTRYPOINT, CLAUDE_CODE_SESSION_ID,
// CLAUDE_PID, CODEX_THREAD_ID-like markers, KIMI_*, GEMINI_SESSION_ID,
// PRECINTO_ACTIVE). Process ancestry and a missing controlling TTY are
// checked separately by ui.AgentContext and the daemon (D7, D28, D59).
func AgentMarkers(e Env) []string

// Clean returns filepath.Clean of an absolute path and reports whether the
// input was already clean and absolute.
func Clean(p string) (string, bool)

// DefaultBase returns the OS default base directory for e (ignores
// overrides): darwin $HOME/Library/Application Support/precinto; linux
// ${XDG_DATA_HOME:-$HOME/.local/share}/precinto (a relative XDG_DATA_HOME is
// ignored, as the XDG spec requires).
func DefaultBase(e Env) (string, error)

// LookPath finds an executable regular file named name in the PATH of e
// (exec.LookPath reads the process environment, which only this package
// may do). A name containing '/' must be absolute and is checked as is.
// Prefer absolute system paths (/usr/sbin/lsof, /usr/sbin/ioreg) where
// they are fixed. A name that is not found is an error matching
// exec.ErrNotFound (`precinto run` exits 127 for it, UX-16). Implemented
// in the scaffold.
func LookPath(e Env, name string) (string, error)

// OverridesAllowed reports whether PRECINTO_HOME/PRECINTO_RUNTIME_DIR may be
// honoured: built with -tags testing, or PRECINTO_DEV=1 and AgentMarkers(e)
// is empty (D6). Hook mode never honours them (hooks run in agent
// contexts).
func OverridesAllowed(e Env) bool

// TestAncestryStop returns the PID:START value of EnvTestAncestryStop in a
// -tags testing build (ok=false when unset or malformed); ("", false) in
// every other build, which never reads the variable (the reading code is
// only in build_testing.go, D64). Callers end the harness-ancestry walk at
// the process whose measured ProcID equals it: that process and its
// ancestors are ignored, everything below is checked, and env markers and
// the no-controlling-terminal rule still apply.
func TestAncestryStop(e Env) (string, bool)

// TestingBuild reports whether the binary was built with -tags testing.
func TestingBuild() bool

// Tilde shortens p for display ("~/work/acme"); p is returned unchanged
// when it is not within home.
func Tilde(home, p string) string

// UserHome returns $HOME, which must be absolute (precinto trusts HOME;
// see SPEC §19).
func UserHome(e Env) (string, error)

// Within reports whether p equals root or lies below it, comparing cleaned
// absolute paths component by component (never by string prefix), with
// ASCII case folding on darwin. Relative paths are never within anything.
// Prefer fsx.Contains when both paths exist (it also handles Unicode
// normalization and case-insensitive volumes through (dev, ino)).
func Within(root, p string) bool

// Env is an immutable snapshot of the environment. No package other than
// paths calls os.Getenv/os.Environ (enforced by internal/archtest).
type Env struct {
	// contains filtered or unexported fields
}

// FromEnviron builds an Env from KEY=VALUE pairs; entries without '=' are
// ignored and a later duplicate wins (os/exec semantics).
func FromEnviron(kv []string) Env

// FromMap builds an Env from a map (tests, hook payload environments).
func FromMap(m map[string]string) Env

// FromOS snapshots the current process environment.
func FromOS() Env

// Environ returns KEY=VALUE pairs in sorted order (child processes).
func (e Env) Environ() []string

// Get returns the value of key or "".
func (e Env) Get(key string) string

// Lookup returns the value of key and whether it is set.
func (e Env) Lookup(key string) (string, bool)

// With returns a copy of e with key set to value.
func (e Env) With(key, value string) Env

// Without returns a copy of e without the given keys.
func (e Env) Without(keys ...string) Env

// Layout is every precinto-owned path. Directories are 0700, files 0600.
type Layout struct {
	Base string // ~/Library/Application Support/precinto | ${XDG_DATA_HOME:-~/.local/share}/precinto

	ConfigFile string // <base>/config.toml
	RootsList  string // <base>/roots.list (D22; read by the POSIX shim)
	BinLink    string // <base>/bin/precinto (pinned binary symlink written by integrate, D6)
	// Marketplace is <base>/marketplace: precinto's plugins and their two
	// marketplace manifests, written byte for byte from the binary by
	// integrate, which adds it to the harness as a local marketplace
	// (D116). Not created by EnsureDirs.
	Marketplace string

	VaultsDir     string // <base>/vaults/<vault-id>/ (D1)
	FactorsDir    string // <base>/factors/ (non-secret factor stubs, e.g. se.identity)
	CapsulesDir   string // <base>/capsules/<harness>/<unit-key>/g<N>.pcap (D9, D45)
	HomesDir      string // <base>/homes/codex/<root-id>/ (D31)
	StagingDir    string // <base>/staging/<op-id>/ (D12)
	QuarantineDir string // <base>/quarantine/<op-id>/ (unlogged capsules, displaced -wal files)

	StateDir       string // <base>/state
	NameSalt       string // state/name.salt (D45)
	CapsuleLog     string // state/capsules.log (D8)
	VerifiedDir    string // state/verified/<vault-id>.recipients (D5)
	GensDir        string // state/gens/<unit-key> (D9)
	ReceiptsDir    string // state/receipts/<unit-key>.json (D10)
	LeasesDir      string // state/leases/<unit-key>.lease (SPEC §9.3)
	SessionsDir    string // state/sessions/<harness>/<sid>.jsonl (ledger)
	ProjectsDir    string // state/projects/<harness>.json (project index)
	JournalDir     string // state/journal/<op-id>.json (I9)
	QueueDir       string // state/queue/<req-id>.json
	LocksDir       string // state/locks/*.lock (never deleted)
	PolicyPinned   string // state/policy.pinned: policy confirmed at the last TTY unlock, with per-vault MACs (D48, D55)
	HookDedupeDir  string // state/hookdedupe (HA21 duplicate suppression, content-free hashed names)
	NotesIndex     string // state/notes.json (pending-notes index: absolute note paths per root, no content)
	SweepRequested string // state/sweep.requested
	SweepLast      string // state/sweep.last (heartbeat for status)

	LogsDir string // <base>/logs
	LogFile string // logs/precinto.log (no content, HMAC'd paths only)

	RunDir    string // <base>/run (darwin) | $XDG_RUNTIME_DIR/precinto (linux) | PRECINTO_RUNTIME_DIR
	Socket    string // RunDir/agent.sock (len < 104 bytes)
	AgentLock string // RunDir/agent.lock (held by the daemon for its lifetime, D6)
}

// HookLayout returns the default base and run dir for e, never honouring
// PRECINTO_* overrides (hook mode, D6/D56), in every build; it fails like
// NewLayout when the socket path is too long (ErrSocketPath).
func HookLayout(e Env) (Layout, error)

// LayoutAt derives a Layout for an explicit base and run directory (tests,
// and the daemon after it has resolved its own layout). Both must be
// absolute and clean; the socket path must be shorter than MaxSocketPath.
// It touches nothing on disk.
func LayoutAt(base, runDir string) (Layout, error)

// NewLayout derives the Layout for e, honouring overrides only when
// OverridesAllowed(e). It fails if the socket path is 104 bytes or longer.
func NewLayout(e Env) (Layout, error)

// CodexHome returns <base>/homes/codex/<rootID> (D31).
func (l Layout) CodexHome(rootID string) string

// EnsureDirs creates every Layout directory with mode 0700 and fails on
// symlinks or foreign owners (fsx.CheckPrivateDir).
func (l Layout) EnsureDirs() error

// LockFile returns <base>/state/locks/<name>.lock for a lock name such as
// "sweep", "global-claude-code", "root-<id>", "unit-<key>", "unlock-<id>".
func (l Layout) LockFile(name string) string

// UnitCapsuleDir returns <base>/capsules/<harness>/<unitKey>.
func (l Layout) UnitCapsuleDir(harness, unitKey string) string

// VaultDir returns <base>/vaults/<vaultID>.
func (l Layout) VaultDir(vaultID string) string
```

### `internal/config`

- Owner: **G7 CLI** · layer 2 · production
- May import (module): `internal/paths`, `internal/fsx`
- May import (third party): stdlib, `github.com/BurntSushi/toml`
- Tests: unit: defaults equal SPEC §12.2, Load merge and unknown-key rejection, round trip, Validate, RootFor deepest match, Diff weakening classification (D48), Strictest, roots.list, Canonical/Pinned round trip (D55) (scaffold helpers tested in config_test.go)

> Package config is the schema of <base>/config.toml: protected roots (with
> stable ids), lock policy, registered harness homes, and the helpers that
> map paths to roots and detect protection-weakening edits (SPEC §6, §12.2,
> §12.9; D22, D29, D38, D48).
>
> Default() is normative: it encodes the defaults of SPEC §12.2. The
> scaffold also implements the helpers every group needs from day one —
> Duration text encoding, Load (defaults merged, unknown keys rejected),
> Save, Validate, RootFor/RootsFor/RootByID/Overlapping/EffectiveOnEnter,
> roots.list I/O, Canonical and the policy.pinned file (D55). Diff,
> Strictest and NewRootID are G7's.

```go
// MD policies for a root (SPEC §8).
const (
	MDLedger = "ledger" // default: Markdown the ledger or transcript shows an agent wrote
	MDAll    = "all"    // every *.md/*.mdx/*.markdown under the root (minus excludes)
	MDOff    = "off"
)

// OnEnter policies (D29).
const (
	OnEnterPrompt = "prompt"
	OnEnterNotify = "notify"
	OnEnterOff    = "off"
)

// MDSealOn values (SPEC §8.4).
const (
	MDSealOnLock = "lock" // seal notes at lock (and by sweeps while locked)
	MDSealOnEnd  = "end"  // seal notes only when the sessions that wrote them end
)

// MaxFileBytes bounds config.toml, roots.list and state/policy.pinned.
const MaxFileBytes = 1 << 20

// MaxUnlockCap is the hard cap on policy.max_unlock and on any unlock TTL.
const MaxUnlockCap = 24 * time.Hour

// PinnedGlobalVault is the vault id of the global stores (vault.GlobalID),
// the one MAC key of a pin that is not a root of its settings.
const PinnedGlobalVault = "global"

// PinnedVersion is the state/policy.pinned format version.
const PinnedVersion = 1

// SchemaVersion is the config.toml format version.
const SchemaVersion = 1

// Errors.
var (
	ErrInvalid = errors.New("config: invalid configuration")
	ErrOverlap = errors.New("config: root overlaps an existing root")
)

// DefaultMDExclude are the globs never sealed by the Markdown policy
// (SPEC §8.2), in addition to git-tracked files.
var DefaultMDExclude = []string{
	"README.md", "CHANGELOG.md", "LICENSE.md", "CONTRIBUTING.md", "SECURITY.md",
	"CLAUDE.md", "AGENTS.md", "GEMINI.md", "**/SKILL.md",
	".git/**", ".claude/**", ".codex/**", ".cursor/**", ".agents/**", ".gemini/**", ".github/**",
	"node_modules/**", "vendor/**", ".venv/**",
}

// ErrForgedPin is a decodable pin of a shape precinto never writes (D91).
var ErrForgedPin = errors.New("config: policy.pinned has a forged shape")

// Canonical returns the deterministic encoding of c that policy MACs cover:
// JSON with roots sorted by id and homes by directory (map keys are sorted
// by encoding/json). Implemented in the scaffold.
func Canonical(c Config) []byte

// NewRootID returns a fresh random root id (32 hex characters).
func NewRootID() string

// ReadRootsList reads a roots.list file (missing file: no roots); lines
// that are not absolute clean paths are ignored. The file is opened like
// Load's (regular, owned by the user, ≤ MaxFileBytes, else fsx.ErrUnsafe).
func ReadRootsList(path string) ([]string, error)

// Save validates c and writes it atomically with mode 0600. Implemented in
// the scaffold.
func Save(path string, c Config) error

// SavePinned writes p atomically with mode 0600. Implemented in the
// scaffold.
func SavePinned(path string, p Pinned) error

// WriteRootsList writes the absolute root paths of c, one per line, to path
// atomically with mode 0600 (D22; read by the POSIX shim). Implemented in
// the scaffold.
func WriteRootsList(path string, c Config) error

// Change is one difference between two configurations.
type Change struct {
	Key       string // dotted key, e.g. "policy.idle_soft", "roots[<id>]"
	Old, New  string
	Weakening bool // removes or narrows protection (D48)
}

// Diff lists changes from old to new. A change is weakening if it removes a
// root or harness, raises a timer, disables a trigger, narrows md, or turns
// on a less strict option (D48).
func Diff(old, new Config) []Change

// Config is the whole file.
type Config struct {
	Version int                `toml:"version"`
	Policy  Policy             `toml:"policy"`
	Roots   []Root             `toml:"roots"`
	Harness map[string]Harness `toml:"harness"`
}

// Default returns the normative defaults of SPEC §12.2.
func Default() Config

// Load parses path and validates it. A missing file yields Default().
// Keys absent from the file keep their defaults (a [harness.<id>] table
// without `enabled`/`min_version` keeps the built-in values); unknown keys
// are rejected (ErrInvalid), so a typo never silently weakens policy. The
// file is opened O_RDONLY|O_NOFOLLOW|O_NONBLOCK and must be a regular file
// owned by the user of at most MaxFileBytes; anything else (a symlink,
// FIFO, directory, foreign or oversized file) is an error wrapping
// fsx.ErrUnsafe, never a hang.
func Load(path string) (Config, error)

// Strictest merges a and b taking, per key, the more protective value; used
// by hooks with the daemon's pinned policy (D48).
func Strictest(a, b Config) Config

// WithRoots returns c with every root of add whose id and path c does not
// have yet, in order, when the root has an id and a path Validate accepts
// (absolute, clean, not "/") without a control character (C0, DEL or C1):
// folders that another source records — the confirmed settings of
// state/policy.pinned, a vault's vault.toml root_path — added to settings
// that lack them (D121, D142, D145). Those sources are never validated as
// a configuration, so a root they hold that could not be saved is left
// out. Nothing in the result aliases c or add.
func WithRoots(c Config, add ...Root) Config

// EffectiveOnEnter returns the root override or the policy value.
func (c Config) EffectiveOnEnter(r Root) string

// Overlapping returns existing roots that contain or are contained by dir.
func (c Config) Overlapping(dir string) []Root

// RootByID returns the root with id.
func (c Config) RootByID(id string) (Root, bool)

// RootFor returns the deepest root containing p (component-wise, see
// paths.Within).
func (c Config) RootFor(p string) (Root, bool)

// RootsFor returns the distinct roots containing any of ps, deepest first
// (ties by id, so the order is deterministic). On darwin a root whose
// path holds non-ASCII bytes is also matched by identity (D93): APFS
// ignores Unicode normalization, getcwd returns a name as stored (often
// NFD, as Finder creates it) while Claude Code reports its cwd in NFC, so
// both spellings of one folder must match.
func (c Config) RootsFor(ps ...string) []Root

// Validate rejects relative or unclean root paths, duplicate ids or paths,
// unknown enum values, negative or zero durations where a positive one is
// required, and durations above their caps. Implemented in the scaffold.
func (c Config) Validate() error

// Duration is a time.Duration encoded in TOML as a string accepted by
// time.ParseDuration; "0" means "never" where the key allows it.
type Duration time.Duration

// D returns the value as a time.Duration.
func (d Duration) D() time.Duration

// MarshalText implements encoding.TextMarshaler with the shortest exact
// unit ("0", "90s", "15m", "8h"); other values use time.Duration.String.
func (d Duration) MarshalText() ([]byte, error)

// UnmarshalText implements encoding.TextUnmarshaler: "0" or any value
// accepted by time.ParseDuration; negative values are rejected.
func (d *Duration) UnmarshalText(b []byte) error

// Harness is a [harness.<id>] table.
type Harness struct {
	Enabled      bool   `toml:"enabled"`
	Experimental bool   `toml:"experimental"` // generic inventories (D33)
	Homes        []Home `toml:"homes"`
	Bin          string `toml:"bin"`         // absolute path of the harness executable used by the wrapper
	MinVersion   string `toml:"min_version"` // refuse integration below this version
}

// Home is a registered harness home (R22): sweeps visit every registered
// home, and restore requests naming an unregistered home are rejected.
type Home struct {
	Dir     string    `toml:"dir"`     // realpath of the config dir / home
	Tmp     string    `toml:"tmp"`     // claude: realpath of CLAUDE_CODE_TMPDIR or /private/tmp/claude-<uid>
	Cache   string    `toml:"cache"`   // claude: ~/Library/Caches/claude-cli-nodejs or $XDG_CACHE_HOME/...
	SeenAt  time.Time `toml:"seen_at"` // last time a hook or the wrapper reported it
	Default bool      `toml:"default"` // the harness default location
}

// Pinned is state/policy.pinned (D48, D55): the configuration the user
// confirmed at the last TTY unlock, and one MAC per vault unlocked at that
// moment, MACs[vault id] = hex HMAC-SHA256(HKDF-SHA256(vault identity,
// vault.InfoPolicy), Canonical(Config)) (computed by the daemon with
// vault.Keyring.MAC). At start the daemon enforces Strictest(config.toml,
// Pinned.Config); when a vault listed in MACs is unlocked it verifies that
// MAC, and a missing or bad MAC is an attention item (policy-tampered) after
// which the daemon also takes Default() into the strictest merge until the
// next TTY confirmation rewrites the file.
type Pinned struct {
	Version     int               `json:"v"`
	ConfirmedAt time.Time         `json:"confirmed_at"`
	Config      Config            `json:"config"`
	MACs        map[string]string `json:"macs"`
}

// LoadPinned reads state/policy.pinned (ok=false if it does not exist). It
// does not verify MACs (the daemon does, with the vault keys); a file that
// does not decode is an error (the daemon reports policy-tampered). It is
// opened like Load's file: a FIFO or symlink planted at the path is an
// error wrapping fsx.ErrUnsafe (policy-tampered), never a hang.
func LoadPinned(path string) (p Pinned, ok bool, err error)

// CheckShape reports why a decodable pin is forged (D91): every pin
// precinto writes once a root vault exists carries at least one MAC, each
// 64 hex characters, keyed by "global" or a root of the pinned settings,
// naming a vault that exists (vaultExists: vaults/<id>/vault.toml). The
// daemon and doctor apply the same rule; MAC values are checked by the
// daemon with the vault keys at unlock.
//
// A pin whose settings name folders also carries a MAC keyed by one of
// those folders (D145): a "global" MAC is checked only by `unlock
// --global` and `recover`, so it alone never authenticates settings that
// name folders (the daemon's writePin refuses to write such a pin). And
// the pinned policy keeps unlock prompts on (prompt_rate_per_minute at
// least 1, D130), as every configuration precinto saves does.
func (p Pinned) CheckShape(vaultExists func(id string) bool) error

// Policy is the [policy] table. TOML keys are the snake_case tags.
type Policy struct {
	IdleSoft            Duration `toml:"idle_soft"`                  // 15m: lock after this much human idle (D23)
	IdleHard            Duration `toml:"idle_hard"`                  // 60m: end paused sessions; "0" never
	MaxUnlock           Duration `toml:"max_unlock"`                 // 8h: absolute grant lifetime ⇒ lock (D24), capped at 24h
	LockOnScreenLock    bool     `toml:"lock_on_screen_lock"`        // true (D24)
	ScreenLockHardAfter Duration `toml:"screen_lock_hard_after"`     // 15m of continuous screen lock ⇒ end idle sessions (D24)
	BusyGrace           Duration `toml:"busy_grace"`                 // 30m: busy turns may finish after a lock (D24)
	BusyTimeout         Duration `toml:"busy_timeout"`               // 10m without hook activity and registry not busy ⇒ not busy (D23)
	QuietWindow         Duration `toml:"quiet_window"`               // 120s stability window for unknown writers (SPEC §9.4)
	HoldCap             Duration `toml:"hold_cap"`                   // 24h: weak-evidence liveness holds are reported after this (S14)
	RestoreRecent       int      `toml:"restore_recent"`             // 5 (D38)
	RestoreMaxBytes     int64    `toml:"restore_max_bytes"`          // 1 GiB (D38)
	MinFree             Size     `toml:"min_free" json:",omitempty"` // 2GiB free-space floor of seals and restores, at least 512MiB (D76; 0 = default, omitted from Canonical)
	RestoreHistory      bool     `toml:"restore_history"`            // true: merge sealed history lines back at unlock
	PerRootAuth         bool     `toml:"per_root_auth"`              // true: each root needs its own presence prompt (D1, D40)
	UnlockOnPrompt      bool     `toml:"unlock_on_prompt"`           // false until the hook-dialog E2E passes (D60); human prompts only (D26, D27, D37)
	OnEnter             string   `toml:"on_enter"`                   // "prompt" (D29)
	MDSealOn            string   `toml:"md_seal_on"`                 // "lock"
	ClearTerminalOnEnd  bool     `toml:"clear_terminal_on_end"`      // true: scrub the TTY when sessions are ended
	ClearScrollbackLock bool     `toml:"clear_scrollback_on_lock"`   // true: wrapper clears scrollback at lock (D30)
	PromptRatePerMinute int      `toml:"prompt_rate_per_minute"`     // 3 (D27)
	PromptBackoff       Duration `toml:"prompt_backoff"`             // 30s after a cancel (D27)
	HookPromptCooldown  Duration `toml:"hook_prompt_cooldown"`       // 10m: no hook-raised dialog for a root after a cancel
}

// Floor returns the free-space floor of the policy for sweep.Env (D76): a
// fixed MinFreeBytes, never a fraction of the volume.
func (p Policy) Floor() fsx.Floor

// MinFreeBytes returns the effective policy.min_free in bytes: the value,
// or DefaultMinFree when it is 0 (unset, e.g. a policy.pinned written
// before the key existed).
func (p Policy) MinFreeBytes() int64

// Root is one [[roots]] entry: a protected folder (never an in-repo marker).
type Root struct {
	ID             string    `toml:"id"`              // stable random id (vault id, D1)
	Path           string    `toml:"path"`            // absolute, clean, realpath'd at protect time
	MD             string    `toml:"md"`              // ledger|all|off
	MDExclude      []string  `toml:"md_exclude"`      // extra globs added to the default excludes
	IncludeTracked bool      `toml:"include_tracked"` // seal git-tracked Markdown too (default false)
	OnEnter        string    `toml:"on_enter"`        // overrides policy.on_enter when set
	Harnesses      []string  `toml:"harnesses"`       // default ["claude-code","codex"]
	ClaudeSettings bool      `toml:"claude_settings"` // protect --claude-settings was used (D32)
	ProtectedAt    time.Time `toml:"protected_at"`
}

// Size is a byte count encoded in TOML as a string: an integer with a
// binary unit ("512MiB", "2GiB", "1TiB"; "KiB" and "B" too, the unit's
// case ignored, one optional space) or a bare number of bytes; "0" means
// the key's default. Decimal units ("2GB") are rejected, so a size never
// silently means something else; negative, fractional and overflowing
// values are rejected too.
type Size int64

// Free-space floor (policy.min_free, D76): the bytes every seal, restore
// and staging write leaves free on its volume. 0 means the default; any
// other value below the minimum is refused by Validate.
const (
	DefaultMinFree Size = 2 << 30
	MinMinFree     Size = 512 << 20
)

// Bytes returns the value in bytes.
func (s Size) Bytes() int64

// MarshalText implements encoding.TextMarshaler with the largest binary
// unit that represents the value exactly ("0", "512MiB", "2GiB", "100B").
func (s Size) MarshalText() ([]byte, error)

// UnmarshalText implements encoding.TextUnmarshaler.
func (s *Size) UnmarshalText(b []byte) error
```

### `internal/ui`

- Owner: **G7 CLI** · layer 2 · production
- May import (module): `internal/paths`, `internal/platform`
- May import (third party): stdlib, `golang.org/x/term`, `github.com/awnumar/memguard`
- Tests: unit: catalog comments identical to the Format table, every MsgID renders with no unfilled placeholders and no forbidden words (root, grant, soft, hard; the --root flag excepted), MsgShimFailed safe to embed in sh and JSON (catalog_test.go), SanitizeTerminal, AgentContext with fake ancestry and without a controlling terminal

> Package ui holds the terminal interaction primitives (secret prompts into
> locked buffers, confirmations, the alternate-screen recovery-key display),
> agent-context detection (D7, D28) and the normative message catalog of
> SPEC §16.3 (user-facing words: "folder", "locked", "paused", "ended and
> sealed"; never "root", "grant", "soft" or "hard").
>
> Messages never contain prompt text, session titles or file content.
> The scaffold implements Format, ReasonText, HumanBytes and Writer.Line
> over a catalog table that a unit test keeps identical to the normative
> comments of the MsgID constants; TTY prompts and AgentContext are G7's.

```go
// ErrCancelled is returned when the user cancels a prompt.
var ErrCancelled = errorString("ui: cancelled")

// AgentContext reports whether the current process runs inside an AI agent
// session: any paths.AgentMarkers, or an ancestor whose executable is a
// known harness (claude, codex, droid, cursor-agent, copilot, gemini, kimi,
// opencode), or no controlling terminal (D59). The returned string names
// the evidence (D7, D28). An ancestor whose lookup fails for any reason
// other than having exited (platform.ErrNoProcess) is an agent context
// ("process ancestry unavailable"); an exited ancestor ends the walk (the
// no-controlling-terminal rule covers reparented processes). In -tags
// testing builds only, the walk also ends at the process named by
// paths.TestAncestryStop (D64): it and its ancestors are ignored,
// everything below is checked, and markers and the no-controlling-terminal
// rule still apply.
func AgentContext(e paths.Env, t platform.ProcTable) (bool, string)

// FactorName names the first usable unlock factor of kinds (a folder's
// enrolled factor kinds in unlock order, ipc.VaultStatus.Factors) for
// {factor}: "Mac password" for "se" when a GUI dialog can appear (gui,
// from platform.DetectUIContext), "security key" for "plugin", "precinto
// passphrase" for "passphrase"; "" when none is usable (then callers use
// the .plain variant of the message). "recovery" is never named.
func FactorName(kinds []string, gui bool) string

// Format renders a catalog message: every {placeholder} of the text is
// replaced from v ({idle} and {limit} as "15 min" / "8 h", {until} as
// 15:04 in v.Until's location, {size} with HumanBytes). An unknown id
// renders as the id itself so a missing entry is visible. An empty v.SID
// drops its slot: "({sid} · " renders as "(" and "session {sid} " as
// "this session " (a Codex session has no id the wrapper knows, D128).
// Implemented in the scaffold.
func Format(id MsgID, v Vars) string

// HumanBytes renders sizes with decimal units: 512 B, 12 kB, 12 MB, 1.2 GB.
// Implemented in the scaffold.
func HumanBytes(n int64) string

// Interactive reports whether both stdin and stdout are terminals.
func Interactive(stdin, stdout *os.File) bool

// ReasonText renders a Reason with its parameter d, the idle time for
// ReasonIdle ("idle 15 min") or the limit for ReasonLimit ("8 h limit
// reached"). Implemented in the scaffold.
func ReasonText(r Reason, d time.Duration) string

// SanitizeTerminal strips C0/C1 control characters except '\n' and '\t'
// (escape-sequence injection defence for `precinto cat` to a TTY, S17).
func SanitizeTerminal(b []byte) []byte

// ShellWord renders the path p as one shell word for a command a message
// tells the user to run (a fix, C6.none): the ~-shortened form (paths.Tilde
// of home) when it needs no quoting, else the absolute path in single
// quotes. Control characters are dropped (a folder name can carry terminal
// escapes, S17) and newlines and tabs become spaces, so the command stays
// on its line.
func ShellWord(home, p string) string

// MsgID identifies a catalog message (SPEC §16.3; text from the UX review).
type MsgID string

// Catalog. The comment gives the normative English text with
// {placeholders} (\n is a line break); Format renders the same text from
// an unexported table that a unit test keeps identical to these comments.
// Two texts are also frozen outside this package and asserted
// byte-identical by tests: MsgNoteMarker (sweep.MarkerText writes it,
// plus a final newline) and MsgShimFailed (the static block text of the
// byte-frozen POSIX shims, D41).
const (
	MsgEnterNotify        MsgID = "C1.notify"          // precinto: {folder} is locked. It unlocks when you start claude or codex here, or run: precinto unlock
	MsgEnterPrompt        MsgID = "C1.prompt"          // precinto: {folder} is locked. Unlock now with your {factor}? [Enter = yes · any other key = skip]
	MsgEnterPromptPlain   MsgID = "C1.prompt.plain"    // precinto: {folder} is locked. Unlock now? [Enter = yes · any other key = skip]
	MsgEnterElsewhere     MsgID = "C1.elsewhere"       // precinto: {folder} is being unlocked in another terminal.
	MsgUnlockSE           MsgID = "C2.se"              // precinto: unlock {folder} for {harness} ({tty}). Enter your Mac password in the system dialog. (Ctrl-C to cancel)
	MsgUnlockHook         MsgID = "C2.hook"            // precinto: {harness} in {folder} asks to unlock it. Approve the system dialog, or cancel it to keep the folder locked.
	MsgUnlockPassphrase   MsgID = "C2.passphrase"      // precinto passphrase for {folder} (Ctrl-C to cancel):
	MsgUnlockTouch        MsgID = "C2.touch"           // Touch your YubiKey...
	MsgUnlockOK           MsgID = "C2.ok"              // precinto: {folder} unlocked. Restoring up to {n} recent sessions in the background. Locks after {idle} idle, at {until} at the latest.
	MsgUnlockOKGlobal     MsgID = "C2.okglobal"        // precinto: the global vault unlocked. Locks after {idle} idle, at {until} at the latest. Restore what belongs to no folder with: precinto restore --global
	MsgUnlockCancelled    MsgID = "C2.cancelled"       // precinto: unlock cancelled. {folder} stays locked.
	MsgUnlockBadSecret    MsgID = "C2.badsecret"       // precinto: that passphrase or recovery key is not right. {folder} stays locked.
	MsgUnlockNoGUI        MsgID = "C2.nogui"           // precinto: the Mac password dialog can't appear inside tmux or over SSH. Run precinto unlock in a local terminal tab; every terminal unlocks at once.
	MsgUnlockNeedTTY      MsgID = "C2.needtty"         // precinto: unlocking {folder} with your {factor} needs a terminal. Run precinto unlock in a terminal; every terminal unlocks at once.
	MsgUnlockNeedTTYPlain MsgID = "C2.needtty.plain"   // precinto: unlocking {folder} needs a terminal. Run precinto unlock in a terminal; every terminal unlocks at once.
	MsgUnlockWait         MsgID = "C2.wait"            // precinto: {folder} stays locked for now: after a cancelled or mistyped unlock, precinto waits before it asks again. Try again in {wait}: precinto unlock
	MsgUnlockTooMany      MsgID = "C2.toomany"         // precinto: {folder} stays locked for now: precinto asks for it at most {n} times a minute. Try again in {wait}: precinto unlock
	MsgUnlockPromptsOff   MsgID = "C2.promptsoff"      // precinto: {folder} stays locked: unlock prompts are turned off (policy.prompt_rate_per_minute is 0 in the settings in force). Set it to 1 or more in config.toml, then run precinto unlock.
	MsgUnlockRetry        MsgID = "C2.retry"           // precinto: you can try again in {wait}: precinto unlock
	MsgUnlockPassFallback MsgID = "C2.passfallback"    // Using your precinto passphrase instead.
	MsgUnlockConfirmAll   MsgID = "C2.confirmall"      // precinto: unlock {n} folders ({folder} …)? Each asks for presence once. Type "unlock" to confirm:
	MsgPromptBlocked      MsgID = "C3.blocked"         // precinto: {folder} is locked ({reason}). Your message was not sent; press ↑ to get it back after unlocking. To unlock, run precinto unlock in any terminal.
	MsgPromptUnlockCxl    MsgID = "C3.cancelled"       // precinto: unlock cancelled. Your message was not sent (press ↑ to get it back).
	MsgAgentDown          MsgID = "C3.agentdown"       // precinto: the precinto agent isn't running, so {folder} stays locked. Run precinto unlock in a terminal.
	MsgGateFailed         MsgID = "C3.failed"          // precinto: precinto could not check {folder}, so it stays locked. Run precinto unlock in a terminal, then precinto doctor if this repeats.
	MsgToolStop           MsgID = "C3.stop"            // precinto: {folder} is locked
	MsgMovedFolder        MsgID = "C3.moved"           // precinto: this session moved into {other}, which is locked. Run precinto unlock --root {other}.
	MsgToolDenied         MsgID = "C3.tooldenied"      // precinto: the user's project {folder} is locked. Do not retry this tool or use other tools. End your turn now with one short sentence asking the user to run "precinto unlock".
	MsgCompactPaused      MsgID = "C3.compact"         // precinto: compaction is paused while {folder} is locked.
	MsgStartLockedModel   MsgID = "C3.start.model"     // precinto: this project is locked. If precinto denies a tool, stop and ask the user to run "precinto unlock".
	MsgStartLockedUser    MsgID = "C3.start.user"      // precinto: {folder} is locked. Your first message will ask you to unlock.
	MsgCodexWrongHome     MsgID = "C3.codexhome"       // precinto: Codex in {folder} must be started with precinto run codex (or the shell integration) so its history stays in the folder's sealed home.
	MsgOverlayTitle       MsgID = "C4.title"           // Locked by precinto
	MsgOverlayLine        MsgID = "C4.line"            // {folder} · {reason}
	MsgOverlayPaused      MsgID = "C4.paused"          // Your session is paused, not closed. It continues where it was.
	MsgOverlayKeys        MsgID = "C4.keys"            // Enter   unlock ({factor})          Ctrl-D   end session and seal it
	MsgOverlayKeysPlain   MsgID = "C4.keys.plain"      // Enter   unlock          Ctrl-D   end session and seal it
	MsgOverlayBusy        MsgID = "C4.busy"            // {harness} is finishing its current step. New messages wait until you unlock.
	MsgOverlayEnding      MsgID = "C4.ending"          // Ending session...
	MsgEnded              MsgID = "C5.ended"           // precinto: locked {folder} ({reason}) and ended {n} session(s). Resume with: {resume}
	MsgSealedOK           MsgID = "C6.ok"              // precinto: sealed this session ({sid} · {files} files · {size}). {folder} stays unlocked until {idle} idle.
	MsgSealedLocked       MsgID = "C6.sealed"          // precinto: sealed this session ({sid} · {files} files · {size}).
	MsgSealNone           MsgID = "C6.none"            // precinto: no file of this session was found to seal. If it saved a conversation, seal it with: {command}
	MsgSealDeferred       MsgID = "C6.deferred"        // precinto: sealing this session as soon as {harness} finishes writing (usually under 2 min).
	MsgSealFailed         MsgID = "C6.failed"          // precinto: WARNING: couldn't seal session {sid} ({cause}). Its files are still readable on disk. Run precinto doctor.
	MsgResumeOlder        MsgID = "C7.older"           // precinto: Claude's list shows your {n} most recent sessions in this folder. Older ones: precinto resume --pick
	MsgResumeMiss         MsgID = "C7.miss"            // precinto: session {sid} is sealed. Resume it with: claude --resume {sid}
	MsgResumeTwice        MsgID = "C7.twice"           // Session {sid} is already open in another terminal (pid {pid}). Opening it twice can lose messages. Open a copy instead (--fork-session)? [Y/n]
	MsgResumeOld          MsgID = "C7.old"             // precinto: Claude deletes sessions older than {days} days when it starts (cleanupPeriodDays). This session was restored with today's date so Claude keeps it; the sealed copy is safe either way.
	MsgPurgeForget        MsgID = "C7.purge"           // precinto: claude purge deletes Claude's own copies of these sessions. precinto keeps its sealed copies (precinto forget deletes them). Run claude purge? [y/N]
	MsgExpiry             MsgID = "C8.expiry"          // precinto: {folder} locks in 10 min ({limit} limit). Run precinto unlock --extend to keep working without interruption.
	MsgCodexUntrusted     MsgID = "C9.codex"           // precinto: Codex hasn't trusted precinto's hooks yet, so it won't pause prompts when this folder locks. Your history is still sealed when Codex exits. In Codex run /hooks and trust "precinto". Start anyway? [Y/n]
	MsgCodexModified      MsgID = "C9.codexmodified"   // precinto: the trust Codex keeps for precinto's hooks doesn't match the hooks precinto ships: they changed since you trusted them, or this Codex version records trust differently. If /hooks in Codex shows them as changed, Codex skips them and won't pause prompts when this folder locks: trust "precinto" again there. Your history is still sealed when Codex exits. Start anyway? [Y/n]
	MsgCodexNoPlugin      MsgID = "C9.codexplugin"     // precinto: this folder's Codex doesn't have precinto's plugin enabled, so it won't pause prompts when the folder locks. Your history is still sealed when Codex exits. Run precinto integrate codex (if it is installed already: precinto codex sync-config --root {folder}). Start anyway? [Y/n]
	MsgClaudeNoHooks      MsgID = "C9.claude"          // precinto: Claude's precinto hooks didn't run in this session (plugin not installed or disabled, --bare or disableAllHooks), so its prompts can't be paused when the folder locks. Check why with: precinto doctor claude-code
	MsgBareWarning        MsgID = "C9.bare"            // precinto: --bare turns off precinto's hooks. This session will be sealed when it ends but won't pause when the folder locks. Continue? [y/N]
	MsgUngatedSession     MsgID = "C9.ungated"         // precinto: {harness} (pid {pid}) runs in {folder} without precinto's hooks, so it can't be paused when the folder locks. Quit it, or start it with: precinto run {harness}
	MsgCodexOutside       MsgID = "C9.codexoutside"    // precinto: {n} Codex conversation(s) from {folder} were saved in your own Codex history, which precinto doesn't seal. Start Codex there with: precinto run codex
	MsgSettingsKept       MsgID = "C9.settings"        // precinto: you passed your own --settings, so precinto did not add its settings that stop Claude compacting or summarizing while you are away. Add idleCompaction: false and awaySummaryEnabled: false to them.
	MsgCodexConsent       MsgID = "C10.consent"        // precinto keeps a separate, sealed Codex history for each protected folder. Codex started in a protected folder through precinto uses that folder's history; elsewhere Codex is unchanged. Protect Codex in {folder}? [Y/n]
	MsgNoteConflict       MsgID = "C11.conflict"       // precinto: {file} changed while it was sealed. Kept both: {file} and {conflict}. Keep one with: precinto resolve {file}
	MsgNoteRestored       MsgID = "C11.restored"       // precinto: restored {file} from the vault (its .md.precinto file had been deleted). To delete it for good: precinto forget {file}
	MsgCodexConflict      MsgID = "C11.codex"          // precinto: Codex ran while its history was sealed: {n} new conversation(s) kept separately. Run: precinto doctor codex
	MsgNoteMarker         MsgID = "C11.marker"         // This note is sealed by precinto. Run `precinto unlock` in this folder to open it.\nid: {unit}
	MsgRefuseAgent        MsgID = "C12.agent"          // precinto: refusing to {action} {folder} from inside an AI agent session. Run precinto {command} yourself in a terminal.
	MsgRefuseCodexLive    MsgID = "C12.codexlive"      // precinto: Codex is already running (pid {pid}) and its history is sealed. Quit it first.
	MsgConfirmTyped       MsgID = "C12.typed"          // precinto: {action} can't be undone. Type "{command}" to confirm:
	MsgPolicyPending      MsgID = "C13.policy"         // precinto: config.toml changes that weaken protection are waiting for your confirmation ({n}). Review them at your next unlock in a terminal.
	MsgPolicyTampered     MsgID = "C13.tampered"       // precinto: the saved copy of the settings you confirmed was changed outside precinto. Until you confirm them again at your next unlock in a terminal, precinto applies the strictest settings.
	MsgPolicyConfirm      MsgID = "C13.confirm"        // Confirm these changes? [y/N]
	MsgPolicyReview       MsgID = "C13.review"         // precinto: these config.toml changes weaken protection and wait for your confirmation ({n}):
	MsgPolicySigner       MsgID = "C13.signer"         // precinto: confirming needs {folder} unlocked: precinto signs the settings you confirm with its key. Unlock it now? [Y/n]
	MsgVaultTampered      MsgID = "C14.tampered"       // precinto: WARNING: {folder}'s vault file was changed outside precinto, so precinto stopped encrypting there and its files stay readable on disk. Check it, then run: precinto vault repair --root {folder}
	MsgVaultRepairConfirm MsgID = "C14.confirm"        // precinto: reset {folder}'s vault to the key you just unlocked? Capsules sealed since the change will be listed as exposed. Type "repair" to confirm:
	MsgVaultRepaired      MsgID = "C14.repaired"       // precinto: repaired {folder}'s vault; encryption resumes now. {n} capsule(s) sealed while it was changed may be readable by whoever changed it: see precinto status.
	MsgVaultNotGenuine    MsgID = "C14.notgenuine"     // precinto: the key you unlocked does not open {folder}'s older capsules, so its key files may have been replaced too. Nothing was changed. Use your recovery key: precinto vault repair --root {folder} --recovery
	MsgInitRefuseAgent    MsgID = "B.refuse"           // precinto init must be run by you in your own terminal, not by an AI agent: the recovery key would end up in the agent's transcript and be sent to the model provider.
	MsgInitNeedSE         MsgID = "B.needse"           // Unlocking with your Mac password needs age-plugin-se: brew install age-plugin-se, then run precinto init again. (Or use a passphrase only: precinto init --factor passphrase.)
	MsgInitRemote         MsgID = "B.remote"           // precinto: you're in tmux, screen or SSH, where the Mac password dialog can't appear. Add a passphrase as a second way to unlock? [Y/n]
	MsgPassphraseNew      MsgID = "B.passphrase.new"   // Choose a precinto passphrase (at least 12 characters), or press Enter to get a generated one:
	MsgPassphraseAgain    MsgID = "B.passphrase.again" // Type the passphrase again:
	MsgPassphraseWeak     MsgID = "B.passphrase.weak"  // that passphrase is too weak (at least 12 characters and about 80 bits are needed). Try again.
	MsgPassphraseDiff     MsgID = "B.passphrase.diff"  // the two passphrases differ. Try again.
	MsgPassphraseGen      MsgID = "B.passphrase.gen"   // Your new precinto passphrase. Type it exactly as shown, hyphens included:
	MsgRecoveryHeader     MsgID = "B.recovery.header"  // Your precinto recovery key. It opens every sealed folder if you lose your other ways to unlock.\nWrite it down and keep it offline. It is shown only once.
	MsgTypeBack           MsgID = "B.typeback"         // Type its last {n} characters to continue:
	MsgTypeBackWrong      MsgID = "B.typeback.wrong"   // Those are not its last {n} characters. Type them again:
	MsgRecoveryAgain      MsgID = "B.recovery.again"   // The recovery key is shown only now. Show it again? [Y/n]
	MsgRecoveryLost       MsgID = "B.recovery.lost"    // WARNING: the recovery key was not confirmed and cannot be shown again. Keep your other ways to unlock safe.
	MsgRecoveryWritten    MsgID = "B.recovery.written" // recovery key written to {file}. Move it offline (it opens every sealed folder).
	MsgRecoveryPrompt     MsgID = "B.recovery.prompt"  // precinto recovery key:
	MsgRecoveryWrongKey   MsgID = "B.recovery.wrong"   // precinto: that is not the recovery key of this precinto installation; nothing was changed. Check the key you wrote down and try again.
	MsgServiceOffer       MsgID = "B.service"          // Seal in the background every 10 minutes (installs a LaunchAgent)? [Y/n]
	MsgNotProtected       MsgID = "E.notprotected"     // {folder} is not inside a protected folder. Protect it with: precinto protect DIR
	MsgNotInitialized     MsgID = "E.notinit"          // precinto is not set up yet. Run: precinto init
	MsgAgentDownAll       MsgID = "E.agentdown"        // the precinto agent isn't running, so every folder is locked. Unlock with: precinto unlock
	MsgNeedTerminal       MsgID = "E.needtty"          // {command} needs your own terminal (stdin and stdout must be a terminal). Run it yourself in a terminal.
	MsgHomeUnregistered   MsgID = "E.unregistered"     // precinto: {n} sealed unit(s) come from a Claude config folder (~/.claude or CLAUDE_CONFIG_DIR) that precinto has not registered, so they stay sealed. Register it with: precinto integrate claude-code
	MsgShimFailed         MsgID = "D.shim"             // precinto: precinto could not run, so this protected folder stays locked. Reinstall precinto, then run: precinto doctor
)

// Reason is why a folder is locked, as shown to users (SPEC §16.3 C3).
type Reason string

// Lock reasons.
const (
	ReasonIdle   Reason = "idle"   // "idle N min"
	ReasonScreen Reason = "screen" // "screen locked"
	ReasonLimit  Reason = "limit"  // "8 h limit reached"
	ReasonManual Reason = "manual" // "locked by you"
	ReasonSleep  Reason = "sleep"  // "computer slept"
	ReasonStart  Reason = "start"  // never unlocked since the agent started
	ReasonAgent  Reason = "agent"  // "the precinto agent stopped responding"
)

// TTY is an opened controlling terminal (/dev/tty), used for prompts that
// must not go through redirected stdio. *TTY implements ipc.UIHandler
// (Display, Secret, Confirm), asserted in cmd/precinto, so the CLI relays
// daemon prompts without an adapter.
type TTY struct {
	// contains filtered or unexported fields
}

// OpenTTY opens /dev/tty; it fails in hooks (no controlling terminal).
func OpenTTY() (*TTY, error)

// Close releases the terminal.
func (t *TTY) Close() error

// Confirm asks a question answered by typing yes or no (the words of the
// relayed request, ipc.UIHandler); anything else counts as no.
func (t *TTY) Confirm(prompt, yes, no string) (bool, error)

// Display shows one informational line (ipc.UIHandler).
func (t *TTY) Display(msg string) error

// Printf writes to the terminal.
func (t *TTY) Printf(format string, args ...any)

// ReadLine reads one visible line (typed-back confirmations such as
// MsgConfirmTyped and MsgUnlockConfirmAll).
func (t *TTY) ReadLine(prompt string) (string, error)

// Secret prompts and reads a secret with echo off directly into a locked
// buffer; Ctrl-C returns ErrCancelled (ipc.UIHandler).
func (t *TTY) Secret(prompt string) (*memguard.LockedBuffer, error)

// ShowSecretScreen shows lines on the alternate screen (the secret in
// groups of 6), requires the user to type back its last confirmLast
// characters (4, D7), then clears screen and scrollback (ESC[2J ESC[3J,
// iTerm2 ClearScrollback) and leaves the alternate screen. The buffer is not
// retained.
func (t *TTY) ShowSecretScreen(header []string, secret *memguard.LockedBuffer, confirmLast int) error

// YesNo asks a [y/N] or [Y/n] question.
func (t *TTY) YesNo(prompt string, def bool) (bool, error)

// Vars fills catalog placeholders.
type Vars struct {
	Folder   string // {folder}: display path (paths.Tilde)
	Other    string // {other}
	Reason   Reason // {reason}: ReasonText(Reason, Idle or Limit)
	Idle     time.Duration
	Harness  string // {harness}
	TTY      string // {tty}
	Factor   string // {factor}
	N        int    // {n}
	Until    time.Time
	Limit    time.Duration
	Wait     time.Duration // {wait}: time left before precinto asks again ("30 s", "1 min")
	SID      string        // {sid}: short sid (first 8 characters are shown)
	PID      int           // {pid}
	Files    int           // {files}
	Bytes    int64         // {size}: HumanBytes
	Cause    string        // {cause}: short error class, never an OS error string
	Resume   string        // {resume}: resume command
	Days     int           // {days}
	File     string        // {file}
	Conflict string        // {conflict}
	Action   string        // {action}
	Command  string        // {command}
	Unit     string        // {unit}: unit key (note markers)
}

// Writer prints status/summary lines to w with the "precinto: " prefix.
type Writer struct {
	W io.Writer
}

// Line prints one message followed by a newline, adding the "precinto: "
// prefix when the text lacks it. Implemented in the scaffold.
func (w Writer) Line(id MsgID, v Vars)
```

### `internal/doctor`

- Owner: **G7 CLI** · layer 9 · production
- May import (module): `internal/config`, `internal/paths`, `internal/platform`, `internal/fsx`, `internal/vault`, `internal/capsule`, `internal/sweep/capslog`, `internal/sweep/queue`, `internal/sweep/journal`, `internal/ledger`, `internal/live`, `internal/harness`, `internal/harness/claude`, `internal/harness/codex`, `internal/harness/generic`, `internal/ipc`, `internal/ui`, `internal/sweep`, `inventories`
- May import (third party): stdlib only
- Tests: unit: each check against fixtures (claude-settings-env, codex-wrong-home reading only the session_meta cwd); read-only (no writes under a canary tree)

> Package doctor implements `precinto doctor [--leaks] [HARNESS]`: read-only
> health and leak checks with one-line fixes (SPEC §16.1, §19). It never
> changes anything; fixes are separate commands that ask for consent.

```go
// Check codes (stable; used by tests and `status`). Codes that also appear
// as status attention items reuse the ipc.Attn* constants, so `status` and
// `doctor` speak one kebab-case vocabulary.
const (
	// CheckConfig: config.toml does not load (its key, line and reason);
	// commands that read it stop until it is fixed (UX-09).
	CheckConfig            = "config"
	CheckDiskEncryption    = "disk-encryption" // FileVault / encrypted home (S18)
	CheckUnhardenedBuild   = ipc.AttnUnhardenedBuild
	CheckLoaderEnv         = "loader-env"          // DYLD_*/LD_* present
	CheckBaseSynced        = "base-synced"         // <base> inside a cloud-synced folder (S9)
	CheckBackups           = "backups"             // Time Machine covers harness plaintext dirs (S18)
	CheckSpotlight         = "spotlight"           // protected folders indexed (S17, UX21)
	CheckCloudRoot         = "cloud-root"          // protected folder is cloud-synced (S17)
	CheckClaudeVersion     = "claude-version"      // ≥ 2.1.295 for onFailure (D22)
	CheckClaudePlugin      = "claude-plugin"       // plugin installed and enabled
	CheckClaudeHooksOff    = "claude-hooks-off"    // disableAllHooks / plugin hooks removed in <root>/.claude/settings*.json (S6, S16)
	CheckClaudeSettings    = "claude-settings"     // drift from what protect --claude-settings wrote
	CheckClaudeSettingsEnv = "claude-settings-env" // PRECINTO_*, HOME, XDG_*, PATH, DYLD_* or LD_* keys in the "env" of any Claude settings file (user, <root>/.claude/settings*.json): they reach every hook process (S2, D56)
	CheckClaudeRetention   = "claude-retention"    // cleanupPeriodDays advice (D14)
	CheckClaudeLegacy      = "claude-legacy"       // lastSessionFirstPrompt, sessions-index.json, session-memory/ (critic)
	CheckCodexVersion      = "codex-version"       // pinned 0.154 range
	CheckCodexHooksTrust   = ipc.AttnCodexHooksTrust
	CheckCodexShellNoise   = "codex-shell-noise"    // `$SHELL -lc true` prints to stdout (HA6)
	CheckCodexWrongHome    = ipc.AttnCodexWrongHome // rollouts in the user's own Codex home whose session_meta cwd lies inside a root (reads only that field of each rollout's first line, ≤ 64 KiB): written outside the sealed per-root home and never sealed (D31, HA1); fix: precinto run codex
	CheckCodexOutsideRuns  = "codex-outside-runs"   // rollouts in a per-root home without a lease (R12)
	CheckRecoveryTested    = ipc.AttnRecoveryTested
	CheckPassphraseFactor  = "passphrase-factor" // offline-attackable (D3)
	CheckServiceRunning    = "service-running"   // background re-seal heartbeat (UX23)
	CheckServiceTCC        = "service-tcc"       // LaunchAgent cannot read a root (R15)
	CheckTerminalResidue   = "terminal-residue"  // iTerm2/Terminal.app restoration, tmux-resurrect…
	CheckQuarantine        = ipc.AttnQuarantine
	CheckUnsealed          = ipc.AttnUnsealed
	CheckHoldCapped        = ipc.AttnHoldCapped
	CheckResidue           = "residue" // shell-snapshots, usage-data, bash-edit-diff, hook_outputs (IM14)
	CheckPendingPolicy     = ipc.AttnPendingPolicy
	CheckPolicyTampered    = ipc.AttnPolicyTampered
	// CheckUnprotectedFolders: the confirmed settings name no folder, and
	// folders whose vault is kept are protected by nothing (D145). Such
	// settings are checked only by `precinto unlock --global`; also a
	// status item.
	CheckUnprotectedFolders = "unprotected-folders"
	CheckHistoryPending     = ipc.AttnHistoryPending
	CheckVaultTampered      = ipc.AttnVaultTampered
	CheckExposed            = ipc.AttnExposed
	CheckUngatedSession     = ipc.AttnUngatedSession
	CheckConflict           = ipc.AttnConflict
	// CheckPermissions: precinto's own directories and Claude's temp folder
	// are not private (owner, mode, symlinks; S7, D6).
	CheckPermissions = "permissions"
	// CheckAgentSocket: the run directory or socket is unusable or unsafe
	// (length, owner, mode, a non-socket; D6).
	CheckAgentSocket = "agent-socket"
	// CheckInterrupted: journal leftovers, abandoned restore staging and
	// history hold links of interrupted operations (D12, D58).
	CheckInterrupted = "interrupted"
	// CheckPluginPin: a pinned plugin binary no longer matches its SHA-256;
	// fix: precinto factor repin NAME (D75).
	CheckPluginPin = "plugin-pin"
	// CheckExperimentalVersion: an installed harness version outside an
	// experimental inventory's verified_versions (SPEC §7.3).
	CheckExperimentalVersion = "experimental-version"
)

// Codes lists every check code in display order.
func Codes() []string

// Render writes fs for `precinto doctor`: one line per finding
// ("FAIL  code  message", the fix on the next line) and a summary line, or
// with asJSON the v1 document {"v":1,"worst":sev,"findings":[{"code",
// "severity","message","fix"}]}. Both sanitize every text again (a finding
// may come from the agent).
func Render(w io.Writer, fs []Finding, asJSON bool) error

// Finding is one result.
type Finding struct {
	Code     string   `json:"code"`
	Severity Severity `json:"severity"`
	Message  string   `json:"message"`       // one line, content-free
	Fix      string   `json:"fix,omitempty"` // command or setting that fixes it
}

// Run executes every applicable check.
func Run(ctx context.Context, o Options) ([]Finding, error)

// Options configures Run.
type Options struct {
	Cfg     config.Config
	Layout  paths.Layout
	Env     paths.Env
	Procs   platform.ProcTable
	Leaks   bool   // also scan residue locations (slow)
	Harness string // limit to one harness
	// ConfigErr is why config.toml did not load (config.Load), nil when it
	// did: the config check fails with it, and the other checks run with
	// Cfg, the settings confirmed last or the defaults (UX-09).
	ConfigErr error
}

// Severity of a finding.
type Severity string

// Severities.
const (
	OK   Severity = "ok"
	Info Severity = "info"
	Warn Severity = "warn"
	Fail Severity = "fail"
)

// Worst returns the most severe severity among fs (OK when empty). The CLI
// exits 1 when it is Fail, 0 otherwise (SPEC §16.2; 2 is usage).
func Worst(fs []Finding) Severity
```

### `internal/testkit`

- Owner: **G7 CLI** · layer 3 · test-only helper (production packages must not import it)
- May import (module): `internal/paths`, `internal/config`, `internal/platform`, `internal/platform/fakeplatform`
- May import (third party): stdlib only
- Tests: self-tests

> Package testkit builds throwaway environments for tests of every group
> (docs/TESTPLAN.md §2 "fake HOME conventions"): a temp HOME with
> PRECINTO_HOME, a short PRECINTO_RUNTIME_DIR (sun_path < 104 bytes),
> CLAUDE_CONFIG_DIR, CLAUDE_CODE_TMPDIR, CODEX_HOME and XDG_* all under
> t.TempDir(), a config with one protected root, golden-file helpers and
> the testdata hygiene check.

```go
// Epoch is the fixed wall time frozen fake clocks start at. Fixture times
// derive from the clock of the code under test (Epoch for h.Clock), never
// from a copy of the date; code that compares its clock with times the
// kernel stamps or another process checks runs on
// fakeplatform.NewRealClock instead (TESTPLAN §1.4, D77), so no test
// depends on today's date.
var Epoch = time.Date(2026, 11, 21, 9, 0, 0, 0, time.UTC)

// BuildBinary builds cmd/precinto with -tags testing(,failpoints) once per
// test binary and returns its path (integration and crash tests). The
// binaries live in a directory of this test process below TMPDIR; the
// package's TestMain removes it with RemoveBinaries.
func BuildBinary(t testing.TB, tags ...string) string

// Golden compares got with testdata/<name> (rewritten with -update).
func Golden(t testing.TB, name string, got []byte)

// GrepTree reports files under dir containing marker (content leak check).
func GrepTree(t testing.TB, dir, marker string, exclude ...string) []string

// Hygiene fails if any file below dir contains $HOME-like paths, emails,
// tokens, or UUIDs that are not fixtures (S13).
func Hygiene(t testing.TB, dir string)

// Leftovers describes ("pid name args…") the live processes, other than
// this one, that run bin or name a path below dirs in their arguments: what
// a test's installation left running.
func Leftovers(bin string, dirs ...string) []string

// Marker returns a unique marker string for leak greps.
func Marker(t testing.TB) string

// RemoveBinaries deletes the directory of the binaries BuildBinary built
// in this process, so a test run leaves nothing in TMPDIR (TESTPLAN §1.8).
// A package that builds binaries calls it from TestMain after m.Run, when
// no test and no process the tests started still runs them; a later
// BuildBinary in the same process fails. Without it the next test process
// that builds removes the directory, as an abandoned one.
func RemoveBinaries()

// Settle waits, at most timeout, until no process other than the test
// holds a file open below dirs: the daemons and binaries a test started,
// and the workers a daemon spawned (their log descriptor stays open while
// they live), write into the fake home until they exit, so a fake home is
// removed only after them (TESTPLAN §1.8). A process still writing then
// is a leak: Settle reports it with t.Errorf and kills it when it runs one
// of exes (binaries the test built, the only processes Settle ever
// signals). Call it after stopping a daemon the test started.
func Settle(t testing.TB, timeout time.Duration, exes []string, dirs ...string)

// ShortTempDir returns a fresh directory with a short absolute path (macOS
// t.TempDir paths exceed the 104-byte socket limit), removed when the test
// ends; a process the test started that still writes there is waited for
// first (Settle), and reported when it outlives the wait.
func ShortTempDir(t testing.TB) string

// StopInstallation ends what a test's installation of the testing build
// left running, before its fake home is removed, and fails the test when
// something outlives it (TESTPLAN §1.8, D129): `bin agent --stop` with env
// (the installation's environment: HOME, PRECINTO_HOME,
// PRECINTO_RUNTIME_DIR…) stops its agent, whose keys are wiped, and waits
// until it no longer answers; every other process that runs bin — the
// workers the agent spawned (sweep, seal --queue, restore), a stray CLI —
// gets a moment to end by itself, then SIGTERM; one that needs SIGKILL
// fails the test, and so does any process still running bin or naming a
// path below dirs in its arguments afterwards. Only processes running bin
// (a binary the test built) are ever signalled. Register it with t.Cleanup
// right after creating the fake home, so it runs after the cleanups of the
// sessions the test started and before the home is removed.
func StopInstallation(t testing.TB, bin string, env []string, dirs ...string)

// Home is a throwaway environment.
type Home struct {
	Dir          string // t.TempDir()
	HomeDir      string // Dir/home (HOME)
	Base         string // PRECINTO_HOME
	RunDir       string // short dir under /tmp (PRECINTO_RUNTIME_DIR)
	ClaudeConfig string // CLAUDE_CONFIG_DIR
	ClaudeTmp    string // CLAUDE_CODE_TMPDIR
	ClaudeCache  string // XDG/Library cache for claude-cli-nodejs
	CodexUser    string // the user's CODEX_HOME (never ~/.codex)
	Root         string // a protected root (HomeDir/work/acme)
	Env          paths.Env
	Layout       paths.Layout
	Cfg          config.Config
	Clock        *fakeplatform.Clock
	Procs        *fakeplatform.Procs
}

// NewHome creates the directories, writes config.toml with Root protected
// (id "root-acme"), and registers cleanup. It does not touch the process
// environment; call Setenv for tests that exec the binary.
func NewHome(t testing.TB) *Home

// Protect adds another root and returns it.
func (h *Home) Protect(t testing.TB, rel string) config.Root

// Setenv sets every variable of h.Env on the test process (t.Setenv).
func (h *Home) Setenv(t testing.TB)
```

### `internal/archtest`

- Owner: **G7 CLI** · layer 0 · production
- May import (module): none
- May import (third party): stdlib only
- Tests: this test

> Package archtest enforces the package contract of docs/API.md: owners,
> the import allowlist (no cycles, lower layers never import higher ones),
> test-only helper packages, and the rule that only internal/paths reads the
> process environment. `go test ./internal/archtest` fails on violations.

```go
// Group identifiers (docs/OWNERSHIP.md).
const (
	G1 = "G1 crypto core"
	G2 = "G2 daemon"
	G3 = "G3 harness adapters"
	G4 = "G4 orchestration"
	G5 = "G5 hooks & packaging"
	G6 = "G6 wrapper"
	G7 = "G7 CLI"
)

// Module is the module path.
const Module = "github.com/precinto/precinto"

// Packages is the whole contract, in layer order.
// (Value elided here: it is rendered as the per-package headers of docs/API.md.)
var Packages []Package

// ContractPath is ImportPath's inverse for a path of the module (ok is
// false for any other import path).
func ContractPath(importPath string) (string, bool)

// ImportPath returns the import path of the contract path rel ("." is the
// module root package).
func ImportPath(rel string) string

// Package describes one package of the contract.
type Package struct {
	Path     string   // relative to Module
	Owner    string   // group
	Layer    int      // lower layers never import higher ones
	TestOnly bool     // helper for tests: production packages must not import it
	Internal []string // allowed module-internal imports (relative paths)
	External []string // allowed third-party import paths (stdlib is always allowed)
	Tests    string   // test expectations (rendered into docs/API.md)
}
```

### `internal/archtest/apidoc`

- Owner: **G7 CLI** · layer 10 · production
- May import (module): `internal/archtest`
- May import (third party): stdlib only
- Tests: none (generator for docs/API.md)

> Command apidoc renders the exported Go API of every package listed in
> archtest.Packages as Markdown, grouped by owner: the generated part of
> docs/API.md, between the BEGIN/END GENERATED markers. From the
> repository root:
>
> 	go run ./internal/archtest/apidoc                  # print to stdout
> 	go run ./internal/archtest/apidoc -splice docs/API.md  # rewrite between markers
> 	go run ./internal/archtest/apidoc -check docs/API.md   # exit 1 if out of date

```go
// (no exported identifiers)
```

### `cmd/precinto`

- Owner: **G7 CLI** · layer 10 · production
- May import (module): `.`, `internal/fsx`, `internal/fsx/failpoint`, `internal/paths`, `internal/platform`, `internal/config`, `internal/capsule`, `internal/vault`, `internal/ui`, `internal/sweep/journal`, `internal/sweep/capslog`, `internal/sweep/queue`, `internal/ledger`, `internal/ipc`, `internal/live`, `inventories`, `internal/harness`, `internal/harness/claude`, `internal/harness/codex`, `internal/harness/generic`, `internal/sweep`, `internal/agent`, `internal/hook`, `internal/shellinit`, `internal/wrapper`, `internal/doctor`
- May import (third party): stdlib, `filippo.io/age`, `github.com/awnumar/memguard`, `golang.org/x/term`
- Tests: unit: seam assertions compile (seams.go), marker text mirrors ui C11.marker; integration (test/integration, -tags testing): every subcommand's flags, exit codes and messages against testkit homes; E2E (PRECINTO_E2E=1): real claude/codex flows

> Command precinto is the single binary: CLI, hook handler, wrapper, sweeper
> and daemon (SPEC §16).

```go
// (no exported identifiers)
```

<!-- END GENERATED -->
