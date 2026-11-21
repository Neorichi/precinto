# precinto — Ownership (v0.2)

Eight groups implement precinto in parallel against the frozen contract in `docs/API.md`. Directories are disjoint: each file has exactly one owner. "Lead" means the lead/architect (contract owner).

## 1. Rules
1. **Own directory only.** Implementers may add unexported code, new files and new test files in their own directories, and change unexported fields of their own types. Helper programs for tests (a scripted TUI child, fake harness executables, fake daemons) are `main` packages under the owner's `testdata/` directory, which `internal/archtest` skips; any other new package needs a lead contract change. Helper programs take a lifeline (an inherited pipe or stdin) and exit when it closes, and every test kills and reaps every process it starts, including their sessions and descendants (TESTPLAN §1).
2. **Never edit another group's files**, and never change an exported identifier (signature, struct field, constant, variable, type) — not even in your own package — without a lead-approved contract change.
3. **Need something else? Adapt locally and report.** If another package lacks a function or behaves differently from the contract, implement an adapter or helper inside your own package (unexported), keep your tests green against the contract, and report the request to the lead with: package, identifier, proposed signature, why, and the adapter you used meanwhile. The lead updates the scaffold, `internal/archtest/allowlist.go` and `docs/API.md` (`make api-doc`) in one change.
4. **No new dependencies.** `go.mod`/`go.sum` are pinned (G7 owns them; changes need the lead). Every allowed third-party import is already pinned by a `deps.go` blank import in the package that may use it.
5. **Imports follow `internal/archtest/allowlist.go`.** `go test ./internal/archtest` must pass at every commit. Only `internal/paths` reads the environment.
6. **Shared generated or normative files are lead-only**: `docs/SPEC.md`, `docs/API.md` (generated part via `make api-doc` only), `docs/HOOKS-IO.md`, `docs/TESTPLAN.md` (including its failpoint registry), `docs/DECISIONS.md`, `docs/OWNERSHIP.md`, `internal/archtest/allowlist.go`, `LICENSE`, `NOTICE`, `.gitignore`. Shared vocabularies are contract too and change only through the lead: `capsule.Kind` and `capsule.BaseID` values, the unit-key parts of SPEC §6.2 (`harness.UnitKeyFor`), `ipc.Attn*` codes, `doctor.Check*` codes, `ui.MsgID` values, failpoint names.
7. **Commits are made by the lead.** Groups hand over working trees; nobody pushes.
8. Before handing over: `make fmt-check vet arch api-check`, `go build ./...`, `CGO_ENABLED=0 go build ./...`, `GOOS=linux go build ./...`, and your package tests (`make test`, plus `make test-crash` for G1/G3/G4).

## 2. Files and directories
| Path | Group | Notes |
|---|---|---|
| `internal/fsx/` (`doc.go`, `fsx.go`, `deps.go`, `sys_unix.go`, `sys_darwin.go`, `sys_linux.go`, `sys_other.go`) | **G1** | safe file ops: dir-fd O_NOFOLLOW walking, atomic writes, no-replace renames, staging, perms, free space, locks (leaf helpers implemented in the scaffold) |
| `internal/fsx/failpoint/` | **G1** | fault injection (`-tags failpoints`) |
| `internal/fsx/fsxtest/` | **G1** | test-only power-loss recorder and image builder (`-tags failpoints`; `fsxtest.Record`, TESTPLAN §4) |
| `internal/capsule/` | **G1** | capsule v1, two-pass seal + ephemeral verify, extract, unit keys |
| `internal/vault/` | **G1** | per-root vaults, factors, MAC/tripwire, Keyring |
| `internal/vault/vaulttest/` | **G1** | test helper |
| `internal/platform/` (`platform.go`, `doc.go`, `deps.go`, `proc_*.go`, `peer_*.go`, `screen_*.go`, `harden_*.go`, `unsupported_other.go`) | **G2** | darwin/linux process identity, peers, triggers, hardening |
| `internal/platform/fakeplatform/` | **G2** | fake process table and clock |
| `internal/ipc/` | **G2** | frames, protocol, authenticated client, listener |
| `internal/agent/` | **G2** | daemon, state machine, key release |
| `internal/agent/agenttest/` | **G2** | in-process agent for tests |
| `internal/harness/` (`doc.go`, `harness.go`, `deps.go`) | **G3** | adapter interface, registry, inventory schema |
| `internal/harness/claude/`, `internal/harness/claude/claudetest/` | **G3** | Claude adapter and synthetic layouts |
| `internal/harness/codex/`, `internal/harness/codex/codextest/` | **G3** | Codex per-root homes and synthetic homes |
| `internal/harness/generic/` | **G3** | experimental inventories |
| `inventories/` (`embed.go`, `*.toml`) | **G3** | embedded inventories |
| `internal/ledger/` | **G3** | content-free ledger, taint, project index |
| `internal/live/` | **G3** | liveness engine, observer, leases |
| `internal/sweep/` (`doc.go`, `sweep.go`, new files) | **G4** | seal/restore planner and executor, generations, lineage, receipts, history rotation/merge, Markdown policy, Codex snapshots, prune/forget, quarantine |
| `internal/sweep/journal/` | **G4** | operation journal |
| `internal/sweep/capslog/` | **G4** | provenance log |
| `internal/sweep/queue/` | **G4** | seal queue |
| `internal/hook/` (+ `testdata/`) | **G5** | decoders, encoders, decision logic, golden fixtures |
| `internal/shellinit/` | **G5** | zsh/bash/fish integration, folder-entry decision |
| `plugin/` (to create: `.claude-plugin/plugin.json`, `.cursor-plugin/plugin.json`, `.github/plugin/plugin.json`, `hooks/hooks.json`, `hooks/cursor.json`, `hooks/copilot.json`, `scripts/precinto-hook`, `commands/lock.md`, `commands/status.md`, `skills/precinto/SKILL.md`) | **G5** | exact hooks files in HOOKS-IO §2.2; no unlock command |
| `plugins/codex/` (to create: `.codex-plugin/plugin.json`, `hooks/codex.json`, `scripts/precinto-hook`) | **G5** | byte-stable across releases (D41); HOOKS-IO §3.2 |
| `.claude-plugin/marketplace.json`, `.agents/plugins/marketplace.json` (to create) | **G5** | marketplaces (SPEC §21) |
| `test/e2e/hooks/` (to create) | **G5** | opt-in E2E with real `claude` |
| `internal/wrapper/` | **G6** | PTY proxy, lock screen, scrollback replay, input gating, signals, run orchestration via `Backend` |
| `test/e2e/wrapper/` (to create) | **G6** | opt-in E2E of the lock screen and resume |
| `cmd/precinto/` | **G7** | subcommands and wiring (implements `wrapper.Backend`, `sweep.KeySource`/`Grants`; `seams.go` asserts at compile time that `*ipc.Client`, `*ipc.KeySet`, `*ui.TTY`, `*live.Held` and `*ledger.Ledger` satisfy the interfaces other groups consume); arms failpoints from `PRECINTO_CRASHPOINT` |
| `internal/config/` | **G7** | `config.toml`, `roots.list`, policy diff |
| `internal/paths/` | **G7** | env snapshot, layout, testing overrides (D6) |
| `internal/doctor/` | **G7** | read-only checks |
| `internal/ui/` | **G7** | TTY prompts, agent-context detection, message catalog |
| `internal/testkit/` | **G7** | fake HOME and test helpers |
| `internal/archtest/imports_test.go`, `internal/archtest/apidoc/` | **G7** | contract enforcement and API doc generator (`allowlist.go` is lead-only) |
| `Makefile`, `go.mod`, `go.sum` | **G7** | lead approval for dependency or target changes |
| `test/integration/` (to create), `test/e2e/flows/` (to create) | **G7** | cross-package flows |
| `.github/` (to create), `.goreleaser.yaml` (later) | **G7** | CI per TESTPLAN §10 |
| `README.md`, `README.es.md` (to create) | **G8** | user docs (English and Spanish) |
| `docs/THREAT_MODEL.md`, `docs/HARNESSES.md`, `docs/COMPACTION.md` (to create) | **G8** | threat model (SPEC §2, §19), per-harness guide, compaction behaviour |
| `SECURITY.md`, `CONTRIBUTING.md` (DCO), `TRADEMARKS.md` (to create) | **G8** | |
| `docs/SPEC.md`, `docs/API.md`, `docs/HOOKS-IO.md`, `docs/TESTPLAN.md`, `docs/DECISIONS.md`, `docs/OWNERSHIP.md`, `internal/archtest/allowlist.go`, `LICENSE`, `NOTICE`, `.gitignore` | **Lead** | contract files |

## 3. Change requests
Send to the lead: `{group, file or package, exported identifier, current, proposed, reason, local adapter used, tests affected}`. Typical outcomes: approved (the lead changes scaffold + allowlist + API.md and notifies every affected group), approved as an unexported helper in your package, or rejected with the existing alternative. Spec ambiguities go the same way; until answered, implement the strictest reading (fail closed, keep plaintext, never delete). A new failpoint name, `capsule.Kind`, `capsule.BaseID`, attention code or message ID is a change request too.

## 4. Dependencies between groups (what can start when)
- Everyone can start at once: the scaffold compiles, every type is complete, and fakes exist (`fakeplatform`, `vaulttest`, `claudetest`, `codextest`, `agenttest`, `testkit`) as stubs to implement first.
- **Already implemented in the scaffold** (with tests), so nobody waits for them: `paths` (Env snapshot, `UserHome`, `DefaultBase`, `LayoutAt`, Layout path helpers, `Within`, `Clean`, `Tilde`, `LookPath`), `config` (`Default`, Duration text, `Load`, `Save`, `Validate`, `RootFor`/`RootsFor`/`RootByID`/`Overlapping`/`EffectiveOnEnter`, roots.list I/O, `Canonical`, `LoadPinned`/`SavePinned`), `ui` (`Format`, `ReasonText`, `HumanBytes`, `Writer.Line` over the catalog), `fsx` (`Lstat`, `Fstat`, Stat predicates, `FullSync`, `SyncDir`, `WriteFileAtomic`, `AppendLine`, `TryLock`, `WaitLock`, `Lock`), `fsx/failpoint` (all of it), `capsule` (`UnitKey`, `GenName`, `ParseGenName`), `platform` (`ProcID.IsZero`, `Ancestors`, `Descendants`), `harness.UnitKeyFor`, `ledger.Taint`, `sweep.MarkerText`, `ipc.Error`. Owners keep these behaviours (and their tests) when they extend the packages.
- First deliverables, in this order, unblock the most tests: G7 `paths.NewLayout`/`AgentMarkers`/`testkit.NewHome`; G2 `fakeplatform`; G1 the rest of `fsx` and `vaulttest`; G3 `claudetest`/`codextest`; G2 `agenttest` (it uses the `agent.Options` seams `Spawn`, `Screen`, `Harden`, `Pinentry`, so it never hardens or re-executes the test binary).
- G3 liveness evidence that depends on processes (cwd for D47/E7, open files for E6) goes through `platform.ProcTable.Cwd`/`OpenFilesUnder`, which `fakeplatform.Procs` fakes (`SetCwd`, `SetOpenFiles`).
- G4 tests depend on G1 (`capsule`, `fsx`) and G3 (`harness` adapters, `live`, `claude.ScanLinks`); until those land, G4 tests its planner and placement table with in-package fakes of `harness.Adapter` and `sweep.KeySource`. Unit keys always come from `harness.UnitKeyFor`.
- G5 golden tests depend only on `hook` itself: every dependency is in `hook.Deps` (fake `hook.Daemon`, fake `hook.Ledger`, `fakeplatform.Procs`, `Identify`, `Enqueue`, `Spawn`), and texts come from the scaffold's `ui.Format`.
- G6 tests use a fake `wrapper.Backend` whose `Daemon` returns a fake `wrapper.Daemon` (no real ipc server needed) and a scripted TUI child under `internal/wrapper/testdata/`.
- G7 wires everything last; its integration tests run when the pieces exist. G7 carries the most first-day work; the lead may move `doctor` or `testkit` to another group if it becomes the bottleneck (open question for the owner).
