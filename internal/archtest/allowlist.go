package archtest

import "strings"

// Module is the module path.
const Module = "github.com/Neorichi/precinto"

// ImportPath returns the import path of the contract path rel ("." is the
// module root package).
func ImportPath(rel string) string {
	if rel == root {
		return Module
	}
	return Module + "/" + rel
}

// ContractPath is ImportPath's inverse for a path of the module (ok is
// false for any other import path).
func ContractPath(importPath string) (string, bool) {
	if importPath == Module {
		return root, true
	}
	rel, ok := strings.CutPrefix(importPath, Module+"/")
	return rel, ok
}

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

const (
	age     = "filippo.io/age"
	agePlug = "filippo.io/age/plugin"
	ageTag  = "filippo.io/age/tag"
	toml    = "github.com/BurntSushi/toml"
	memg    = "github.com/awnumar/memguard"
	ptyPkg  = "github.com/creack/pty"
	zstd    = "github.com/klauspost/compress/zstd"
	unix    = "golang.org/x/sys/unix"
	term    = "golang.org/x/term"
)

var (
	root      = "." // the module root package: the embedded plugins (D116)
	fsx       = "internal/fsx"
	failpoint = "internal/fsx/failpoint"
	fsxtest   = "internal/fsx/fsxtest"
	paths     = "internal/paths"
	platform  = "internal/platform"
	fakeplat  = "internal/platform/fakeplatform"
	config    = "internal/config"
	capsule   = "internal/capsule"
	vault     = "internal/vault"
	vaulttest = "internal/vault/vaulttest"
	ui        = "internal/ui"
	journal   = "internal/sweep/journal"
	capslog   = "internal/sweep/capslog"
	queue     = "internal/sweep/queue"
	ledger    = "internal/ledger"
	ipc       = "internal/ipc"
	live      = "internal/live"
	invs      = "inventories"
	harness   = "internal/harness"
	claude    = "internal/harness/claude"
	claudet   = "internal/harness/claude/claudetest"
	codex     = "internal/harness/codex"
	codext    = "internal/harness/codex/codextest"
	generic   = "internal/harness/generic"
	sweep     = "internal/sweep"
	agent     = "internal/agent"
	agentt    = "internal/agent/agenttest"
	hook      = "internal/hook"
	shellinit = "internal/shellinit"
	wrapper   = "internal/wrapper"
	doctor    = "internal/doctor"
	testkit   = "internal/testkit"
	archtest  = "internal/archtest"
	apidoc    = "internal/archtest/apidoc"
	cmd       = "cmd/precinto"
)

func with(base []string, extra ...string) []string {
	out := append([]string{}, base...)
	return append(out, extra...)
}

var harnessDeps = []string{capsule, config, paths, fsx, platform, ledger, live}

// Packages is the whole contract, in layer order.
var Packages = []Package{
	{Path: failpoint, Owner: G1, Layer: 0,
		Tests: "unit: arming/disarming, nth-hit counting, errno specs, bad specs panic, crash point SIGKILLs a child process (failpoint_on_test.go); compiled out without -tags failpoints (failpoint_off_test.go)"},
	{Path: fsx, Owner: G1, Layer: 0, Internal: []string{failpoint}, External: []string{unix},
		Tests: "unit: no-follow walking (symlink parents, swapped components), RenameNoReplace, UnlinkIfUnchanged (inode swap, same size+mtime), hazards (FIFO, socket, nlink>1), staging on same device, free-space floor, Classify table; race test flipping a parent to a symlink 10k times (TESTPLAN SEC-6); scaffold-implemented leaf helpers (Lstat, AppendLine, WriteFileAtomic, TryLock/WaitLock) have tests in fsx_leaf_test.go"},
	{Path: fsxtest, Owner: G1, Layer: 1, TestOnly: true, Internal: []string{fsx, failpoint},
		Tests: "self-tests (-tags failpoints): an unsynced rename, create, unlink or write is absent from the strict image and present in the full one, synced operations and everything they depend on are present in every image, identical images are merged"},
	{Path: paths, Owner: G7, Layer: 1, Internal: []string{fsx},
		Tests: "unit: layouts per OS, override rules with/without -tags testing and PRECINTO_DEV + agent markers (D6), socket length limit, Within component-wise and case-folded, LookPath ignores relative PATH entries (scaffold helpers tested in paths_test.go)"},
	{Path: platform, Owner: G2, Layer: 1, Internal: []string{paths, fsx}, External: []string{unix},
		Tests: "unit+integration (real child processes): ProcID equality and reuse, zombie as exited, WaitExit, Signal re-verification, Ancestors, Descendants (PPID walk, never by session id, reused pids excluded; walk_test.go), SignalGroup only on a Setsid child's session, Cwd and OpenFilesUnder, SameExecutable, PeerOf over a socketpair, ReadScreen parsing fixtures (ioreg/loginctl output), WatchJumps with a fake clock"},
	{Path: fakeplat, Owner: G2, Layer: 2, TestOnly: true, Internal: []string{platform},
		Tests: "self-tests of the fakes"},
	{Path: config, Owner: G7, Layer: 2, Internal: []string{paths, fsx}, External: []string{toml},
		Tests: "unit: defaults equal SPEC §12.2, Load merge and unknown-key rejection, round trip, Validate, RootFor deepest match, Diff weakening classification (D48), Strictest, roots.list, Canonical/Pinned round trip (D55) (scaffold helpers tested in config_test.go)"},
	{Path: capsule, Owner: G1, Layer: 2, Internal: []string{fsx, failpoint}, External: []string{age, zstd},
		Tests: "unit: round trip, tamper/truncation, wrong recipient, ErrChanged between passes, ErrHeader with 2/4 stanzas, bombs/PAX/links/sparse/size mismatch/1e6 entries rejected with bounded memory, mode mask, OnPhase after each milestone, UnitKey vectors and GenName/ParseGenName (names_test.go)"},
	{Path: vault, Owner: G1, Layer: 2, Internal: []string{fsx, failpoint}, External: []string{age, agePlug, ageTag, memg, toml},
		Tests: "unit: passphrase factor wrap/unwrap, X25519 test plugin, MAC mismatch refuses, tripwire on recipients edit, Repair (recipient rewrite, ErrNeedRecovery, verified copy), Keyring.MAC per info string, last-factor refusal, plugin pin mismatch (se included), Keyring FileKey/Drop; E2E (opt-in): age-plugin-se"},
	{Path: vaulttest, Owner: G1, Layer: 3, TestOnly: true, Internal: []string{vault}, External: []string{age, memg},
		Tests: "used by G2/G4/G7 tests"},
	{Path: ui, Owner: G7, Layer: 2, Internal: []string{paths, platform}, External: []string{term, memg},
		Tests: "unit: catalog comments identical to the Format table, every MsgID renders with no unfilled placeholders and no forbidden words (root, grant, soft, hard; the --root flag excepted), MsgShimFailed safe to embed in sh and JSON (catalog_test.go), SanitizeTerminal, AgentContext with fake ancestry and without a controlling terminal"},
	{Path: journal, Owner: G4, Layer: 2, Internal: []string{fsx, failpoint},
		Tests: "unit: O_EXCL create, phases persisted only after their step (failpoints), Capsule name recorded at prepared, history Offset/Pending/NewBase round trip, Pending ordering, Done removal"},
	{Path: capslog, Owner: G4, Layer: 1, Internal: []string{fsx},
		Tests: "unit: append/lookup by header hash, deleted folding, torn last line ignored, Compact"},
	{Path: queue, Owner: G4, Layer: 2, Internal: []string{fsx, platform},
		Tests: "unit: enqueue/list/update/remove, atomicity"},
	{Path: ledger, Owner: G3, Layer: 3, Internal: []string{paths, fsx, platform, config},
		Tests: "unit: fold rules (taint sticky, warm, ByProc after /clear, compaction cleared by Stop/StopFailure/end), Snapshot + Archive keeps events appended after the snapshot, Taint root resolution, content-free lines (hygiene)"},
	{Path: ipc, Owner: G2, Layer: 3, Internal: []string{paths, fsx, platform}, External: []string{memg, unix},
		Tests: "unit: framing limits, secret frames never JSON, ExitCode table; integration: socket squat and wrong executable rejected before any secret is sent (TESTPLAN SEC-11), stale socket handling, two concurrent Listen (one wins), PeerSameExecutable gate on every op that requires it"},
	{Path: live, Owner: G3, Layer: 4, Internal: []string{platform, fsx, paths, config, ledger},
		Tests: "unit with fakes: LIVE-1–LIVE-10 of the crash matrix (registry gone + end + pid alive, launch window via lease, PID reuse, zombie, unknown procStart, wall jump, warm, half-written registry), lease inode swap, hold caps, cwd evidence through ProcTable.Cwd (D47)"},
	{Path: invs, Owner: G3, Layer: 0,
		Tests: "every *.toml decodes strictly (no undecoded keys) into harness.Inventory"},
	{Path: root, Owner: G5, Layer: 0,
		Tests: "the embedded files equal the repository's two marketplace manifests and plugin roots byte for byte, nothing more, nothing less (plugins_test.go)"},
	{Path: harness, Owner: G3, Layer: 5, Internal: harnessDeps, External: []string{toml},
		Tests: "unit: registry, inventory parsing/validation, MatchProcess, Classify passthrough/direct, UnitKeyFor vectors and refusals (unitkey_test.go)"},
	{Path: claude, Owner: G3, Layer: 6, Internal: with(harnessDeps, harness, invs),
		Tests: "unit with claudetest: fail-closed sid inventory (unknown files sealed, deny-list honoured), registry parsing incl. malformed, jobs, history line parsing, ScanTranscript facts, ScanLinks (uuid set, first parent, trailing newline), ParseResume table, SettingsJSON, Targets per kind (SPEC §11.2 table)"},
	{Path: codex, Owner: G3, Layer: 6, Internal: with(harnessDeps, harness, invs),
		Tests: "unit with codextest: Classify deny-list, SQLite grouping, PrepareHome (sqlite_home stripped, links, ForceConfig keeps trust entries), SyncAuthBack, ApplyPatchPaths (Add/Update/Move, relative), HooksTrusted fixture"},
	{Path: generic, Owner: G3, Layer: 6, Internal: with(harnessDeps, harness, invs),
		Tests: "unit: experimental gating (--experimental and seal --dormant only), refusal while a matching process runs, a lock is held, the open-file check fails or a -wal/-shm exists"},
	{Path: claudet, Owner: G3, Layer: 7, TestOnly: true, Internal: []string{claude, platform, fsx},
		Tests: "used by G3/G4/G5/G6/G7 tests"},
	{Path: codext, Owner: G3, Layer: 7, TestOnly: true, Internal: []string{codex, fsx},
		Tests: "used by G3/G4/G7 tests"},
	{Path: sweep, Owner: G4, Layer: 7, Internal: []string{capsule, vault, harness, claude, codex, generic, live, ledger, config, paths, fsx, failpoint, platform, journal, capslog, queue, invs}, External: []string{memg},
		Tests: "unit+crash-injection: the full matrix SEAL-*, REST-*, HIST-*, CODX-*, NOTE-*, CONC-*, PERF-* (docs/TESTPLAN.md §4) with -tags failpoints; placement table golden tests; lineage/generation tests incl. receipts rewritten after commit; provenance (forged capsules quarantined, crash leftovers never quarantined); manifest unit id authenticated against the logged unit key (SEC-2)"},
	{Path: agent, Owner: G2, Layer: 7, Internal: []string{ipc, vault, capsule, capslog, queue, journal, config, paths, platform, fsx, ledger, harness, claude, ui, invs}, External: []string{memg},
		Tests: "unit: Machine exhaustively with a fake clock (idle only on verified human input: wrapper Input/Enter with FromWrapper, Prompt with a recorded human origin; unknown origin never; busy grace, screen-lock hard-after, max_unlock, sleep jump, background exemption, automated prompts never prompt, ungated scan sessions); integration with agenttest: gate fail-closed, activity from a non-wrapper peer dropped, key release scope and provenance, TTL clamp, policy pinning across a daemon restart, vault repair, rate limits, single-flight unlock"},
	{Path: agentt, Owner: G2, Layer: 8, TestOnly: true, Internal: []string{agent, ipc, paths, platform, fakeplat, config}, External: []string{memg},
		Tests: "used by G2/G5/G6/G7 tests"},
	{Path: hook, Owner: G5, Layer: 8, Internal: []string{ipc, ledger, config, paths, platform, fsx, ui, harness, codex, queue}, External: []string{memg},
		Tests: "golden: synthetic payloads per host/version/event → exact stdout/stderr/exit (HOOKS-IO.md), Codex outputs decoded with deny_unknown_fields structs; unit: host detection (label default, every gate event without CLAUDE_PID, Codex SessionStart/SessionEnd without turn_id), fail-closed on every error path, deadline, panic recovery; shim tests (shellcheck, exit-code table, PRECINTO_* ignored, failed run inside/outside roots)"},
	{Path: shellinit, Owner: G5, Layer: 8, Internal: []string{config, paths, ipc, ui},
		Tests: "golden scripts per shell; zsh/bash syntax check (zsh -n, bash -n); OnEnter transitions, skip epochs, single-flight"},
	{Path: wrapper, Owner: G6, Layer: 8, Internal: []string{harness, ipc, live, config, paths, platform, fsx, ui}, External: []string{ptyPkg, term, memg},
		Tests: "unit: Scrollback bounds, safe boundaries and Wrapped, Modes tracking/restore, HumanInput filter table; integration with a fake Backend and fake Daemon and a scripted TUI child (testdata/ main package) on a PTY: lock overlay, replay of pre-lock output, input dropped while locked, end event termination of the child's own session only, direct-mode Setsid, job control, exit code propagation"},
	{Path: doctor, Owner: G7, Layer: 9, Internal: []string{config, paths, platform, fsx, vault, capsule, capslog, queue, journal, ledger, live, harness, claude, codex, generic, ipc, ui, sweep, invs},
		Tests: "unit: each check against fixtures (claude-settings-env, codex-wrong-home reading only the session_meta cwd); read-only (no writes under a canary tree)"},
	{Path: testkit, Owner: G7, Layer: 3, TestOnly: true, Internal: []string{paths, config, platform, fakeplat},
		Tests: "self-tests"},
	{Path: archtest, Owner: G7, Layer: 0,
		Tests: "this test"},
	{Path: apidoc, Owner: G7, Layer: 10, Internal: []string{archtest},
		Tests: "none (generator for docs/API.md)"},
	{Path: cmd, Owner: G7, Layer: 10,
		Internal: []string{root, fsx, failpoint, paths, platform, config, capsule, vault, ui, journal, capslog, queue, ledger, ipc, live, invs, harness, claude, codex, generic, sweep, agent, hook, shellinit, wrapper, doctor},
		External: []string{age, memg, term},
		Tests:    "unit: seam assertions compile (seams.go), marker text mirrors ui C11.marker; integration (test/integration, -tags testing): every subcommand's flags, exit codes and messages against testkit homes; E2E (PRECINTO_E2E=1): real claude/codex flows"},
}
