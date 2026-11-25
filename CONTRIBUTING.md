# Contributing to Precinto

Thank you for helping. Precinto handles some of the most sensitive files on a developer's machine, so the bar for changes is high: behaviour follows a written specification, every change brings its tests, and no test ever touches real user data.

The repository is not public yet. Until it is, this guide applies to invited contributors; once it is published, it applies to everyone. Security problems are not reported through pull requests or issues: see [SECURITY.md](SECURITY.md).

## Contents

- [Before you start](#before-you-start)
- [Build and test](#build-and-test)
- [Continuous integration](#continuous-integration)
- [How the code is organized](#how-the-code-is-organized)
- [Style](#style)
- [Tests and fixtures: never real user data](#tests-and-fixtures-never-real-user-data)
- [Developer Certificate of Origin](#developer-certificate-of-origin)
- [Pull requests](#pull-requests)
- [License](#license)

## Before you start

Four documents form the contract that the code implements:

| Document | What it fixes |
|---|---|
| [docs/SPEC.md](docs/SPEC.md) | behaviour: units, sealing, restore, the lock model, the daemon, hooks, the CLI, error handling, invariants |
| [docs/API.md](docs/API.md) | the exported Go API of every package; its second half is generated from the code |
| [docs/HOOKS-IO.md](docs/HOOKS-IO.md) | the exact hook inputs and outputs for each harness |
| [docs/TESTPLAN.md](docs/TESTPLAN.md) | which tests exist, who owns them, and the fake-home conventions |

[docs/DECISIONS.md](docs/DECISIONS.md) records why things are the way they are, and [docs/OWNERSHIP.md](docs/OWNERSHIP.md) assigns every file to an area. If code and specification disagree, fix one of them in the same change. When the specification is ambiguous, implement the strictest reading (fail closed, keep plaintext, never delete) and raise the question in your pull request.

## Build and test

You need Go 1.21 or newer and `make`. `go.mod` pins `toolchain go1.26.11`; with the default `GOTOOLCHAIN=auto` the go command downloads that toolchain the first time (network access to the Go module proxy is needed once). The Makefile uses the first working `go` on your `PATH`; override it with `make GO=/path/to/go`. Builds must work with `CGO_ENABLED=0`, which the Makefile sets.

| Command | What it does |
|---|---|
| `make build` | release-style binary `bin/precinto` (CGO disabled, `-trimpath`) |
| `make build-testing` | `bin/precinto-testing`, built with `-tags testing`, which honours `PRECINTO_HOME` and `PRECINTO_RUNTIME_DIR` for integration tests; never point it at real data |
| `make build-linux` | cross-compiles for linux/amd64 and linux/arm64 |
| `make build-windows` | cross-compiles for windows/amd64 and windows/arm64; the Windows binary refuses everything, because on Windows Precinto runs as its Linux build inside WSL 2 ([D155](docs/DECISIONS.md#added-for-windows-through-wsl-2-2026-11-25)) |
| `make test` | unit and integration tests, `-tags testing`; no network, no real harness data |
| `make test-race` | the same tests under the race detector |
| `make test-crash` | the crash-injection matrix of [TESTPLAN §4](docs/TESTPLAN.md#4-crash-injection-matrix), `-tags testing,failpoints`; `make test-crash CRASH_COUNT=5` runs it five times in a row, as the weekly crash run does |
| `make crossgroup` | the tests that need every area's real code (`-tags testing,crossgroup`), bounded at 8 minutes and printing every goroutine's stack on a hang |
| `make crossgroup-crash` | the crash rows that need every area's real code (`-tags testing,failpoints,crossgroup`), over `internal/fsx`, `internal/capsule`, `internal/sweep` and `internal/live`, bounded and traced like `make crossgroup`; no file excludes the crossgroup tag, so it also runs every `make test-crash` test |
| `make test-integration` | the cross-package flows of `test/integration` against the testing binary |
| `make test-e2e` | opt-in end-to-end tests against real harnesses in throwaway homes (`PRECINTO_E2E=1`) |
| `make vet` | `go vet` for the default and `testing,failpoints` tag sets, on darwin and on linux |
| `make vet-crossgroup` | checks that the crossgroup tests compile on darwin and on linux, with and without `failpoints` |
| `make vet-windows` | `go vet` for `GOOS=windows` with the default, `testing`, `testing,failpoints`, `testing,crossgroup` and `testing,failpoints,crossgroup` tag sets |
| `make fmt`, `make fmt-check` | run `gofmt -w`, or only check formatting |
| `make arch` | the architecture contract (`internal/archtest`): import allowlist, layers, test-only helpers, environment access |
| `make api-check`, `make api-doc` | check, or regenerate, the generated part of `docs/API.md` |
| `make hygiene` | the fixture hygiene check over every `testdata/` directory |
| `make codex-plugin-check` | checks that `plugins/codex/` still matches its recorded SHA-256 list; a change to the folder updates `test/integration/testdata/codex-plugin.sha256` in the same change |
| `make lint` | `fmt-check`, `vet`, `vet-crossgroup`, `arch` and `api-check`, plus the linters (`make linters`): `staticcheck` over the darwin, linux and windows builds, `govulncheck`, and `shellcheck` of the hook shims, each skipped when it is not installed, except a missing `shellcheck` in CI, which fails; `make -k lint` runs every check even when one fails |
| `make ci` | most of what CI runs on every change: `lint`, `build-windows`, `vet-windows`, `build`, `build-linux`, `build-testing`, `test`, `hygiene` and `codex-plugin-check`; CI also runs `test-race`, `crossgroup` and `crossgroup-crash`, and never the end-to-end tests |
| `make clean` | removes `bin/` |

Before you send a change, run:

```sh
make fmt-check vet arch api-check
go build ./... && CGO_ENABLED=0 go build ./... && GOOS=linux go build ./...
make build-windows vet-windows   # if you touched OS-specific files or build tags
make test
make test-crash        # if you touched internal/fsx, internal/capsule, internal/sweep or internal/live
make crossgroup        # if your change affects code another area calls
```

`make test-e2e` runs real harnesses (for example `claude -p` with a throwaway config directory and a small model) and uses your harness login, so it may consume API usage. Codex is never run against a real home in these tests. Run it only when your change needs it.

## Continuous integration

Every change runs on Linux only, and macOS, WSL 2 and the repeated crash matrix run on a schedule ([D158](docs/DECISIONS.md#added-for-continuous-integration-2026-11-25)). The owner chose this layout while the repository was private and its Actions minutes were counted (a macOS minute cost about ten Linux minutes, a Windows minute about 1.7); a public repository runs on GitHub-hosted runners at no cost, so the layout may widen:

| Workflow | Runs | What it checks |
|---|---|---|
| `ci.yml` | every push to `main`, every pull request | on ubuntu: `make -k lint` (staticcheck checks the darwin, linux and windows builds), `make build-windows vet-windows`, `make build build-testing build-linux`, `make test`, `make test-race`, `make hygiene`, `make codex-plugin-check`, `make crossgroup`, `make crossgroup-crash`, and the plugin validation when `claude` is on the runner (it is not, so that step skips) |
| `secrets.yml` | every push to any branch or tag, every pull request | the [secret scan](#secret-scan) |
| `macos.yml` | the 1st and the 15th of each month, 05:37 UTC | the same gates on macOS, without the Windows build and vet |
| `wsl2.yml` | Wednesdays, 04:41 UTC | `make test`, `make crossgroup` and `make crossgroup-crash` inside WSL 2 (Ubuntu 24.04 on a Windows runner), the way Precinto runs on Windows ([docs/WINDOWS.md](docs/WINDOWS.md)) |
| `crash.yml` | Mondays, 03:23 UTC | the crash-injection matrix five times in a row (`make test-crash CRASH_COUNT=5`), to find rows that fail only now and then |

Since the Linux runner vets and lints the darwin and Windows files and builds for Windows on every change, most OS-specific mistakes fail there; what only a real macOS or WSL 2 system shows turns up in the next scheduled run. End-to-end tests never run in CI, and no workflow holds secrets. [TESTPLAN §10](docs/TESTPLAN.md#10-ci-gates-g7-owns-the-workflows) lists every step.

### Running the macOS or WSL 2 job by hand

Every workflow can also be started by hand, which needs write access to the repository. Scheduled runs use the workflows as they are on `main`, so once a change lands there that touches the WSL code (the `wsl*.go` files, the Windows drive and Windows program checks, the boot-time floor: D155 to D157), macOS-specific code or one of the workflows, start the run instead of waiting for the schedule:

```sh
gh workflow run wsl2.yml --ref main
gh workflow run macos.yml --ref main
gh workflow run crash.yml --ref main   # after a change to a crash row
gh run list --workflow wsl2.yml        # follow the run
```

What no runner can show (a laptop that sleeps, Win+L, Windows Terminal, a YubiKey through usbipd-win) is on the manual list of [TESTPLAN §11](docs/TESTPLAN.md#11-windows-through-wsl-2-d155d157).

### Secret scan

`secrets.yml` runs gitleaks over the history of every branch and tag and over the working tree, on every push and every pull request. A finding fails the run, and the log shows where it is, never the secret itself (`--redact`). `.gitleaks.toml` adds rules for Anthropic tokens and Precinto recovery keys, and it is the only place for exceptions:

- A synthetic fixture that a rule flags gets its own `[[allowlists]]` entry naming the rule (`targetRules`), the files (`paths`) and the exact value (`regexes`), with `condition = "AND"`, so the same file still reports any other value and the same value is still reported anywhere else. Never widen an existing entry, and never add a broader pattern.
- Do not write `gitleaks:allow` comments: CI ignores them (`--ignore-gitleaks-allow`), so the finding still fails the scan.
- Do not add a `.gitleaksignore` file: CI fails as soon as one exists.
- Never commit a real secret, not even to remove it in the next commit: the history scan finds it in any commit of any branch. If one was pushed, revoke it first.

To run the scan before you push, from the repository root (gitleaks 8.25.0 or later; CI uses 8.30.1), with the options CI uses; the history scan also reads the diffs of merge commits (`-m`), so a secret added while resolving a conflict is found too:

```sh
gitleaks git . --config .gitleaks.toml --ignore-gitleaks-allow --log-opts="--full-history --all --diff-filter=tuxdb -m" --redact --verbose
gitleaks dir . --config .gitleaks.toml --ignore-gitleaks-allow --redact
```

### Pinned tools

Every workflow pins its actions by commit SHA, `secrets.yml` pins gitleaks 8.30.1 by version and SHA-256, and `ci.yml` and `macos.yml` pin the Go linters by version: `staticcheck` v0.8.2 and `govulncheck` v1.9.0. A new release lands by changing those lines in a reviewed change. `make lint` uses whichever versions are on your `PATH`, so install the same ones to get the same findings:

```sh
go install honnef.co/go/tools/cmd/staticcheck@v0.8.2
go install golang.org/x/vuln/cmd/govulncheck@v1.9.0
```

`make linters` runs staticcheck once over six builds (`STATICCHECK_MATRIX` in the Makefile: darwin, linux and windows, each with the default tags and with `testing,failpoints,crossgroup`), so it reports code as unused only when no build uses it. CI also installs `shellcheck` and `fish` (`.github/scripts/install-shells.sh`); with `CI` set, a missing one fails the linters and the shell tests instead of skipping them.

## How the code is organized

Every file belongs to exactly one area, and areas never share directories; the full table is in [docs/OWNERSHIP.md](docs/OWNERSHIP.md). For outside contributors it boils down to this:

| Area | Directories | What lives there |
|---|---|---|
| Crypto core | `internal/fsx/`, `internal/capsule/`, `internal/vault/` | safe file operations, the capsule format, vaults and factors |
| Daemon | `internal/agent/`, `internal/ipc/`, `internal/platform/` | the daemon and its lock state machine, the socket protocol, macOS and Linux specifics |
| Harness adapters | `internal/harness/`, `internal/ledger/`, `internal/live/`, `inventories/` | what each harness writes, the content-free ledger, liveness |
| Orchestration | `internal/sweep/` | seal and restore, generations, lineage, the journal, the capsule log, the seal queue |
| Hooks and packaging | `internal/hook/`, `internal/shellinit/`, `plugin/`, `plugins/codex/`, `.claude-plugin/`, `.agents/plugins/`, `plugins.go`, `test/e2e/hooks/` | hook decisions, shell integration, the plugins and the POSIX shim; `plugins.go` embeds the plugins in the binary for `precinto integrate`, and a file added to a plugin folder joins its `//go:embed` list (a test compares both) |
| Wrapper | `internal/wrapper/`, `test/e2e/wrapper/` | the PTY proxy, the lock screen, launch orchestration |
| CLI and tooling | `cmd/precinto/`, `internal/config/`, `internal/paths/`, `internal/doctor/`, `internal/ui/`, `internal/testkit/`, `internal/archtest/`, `Makefile`, `go.mod`, `go.sum`, `test/integration/`, `test/e2e/flows/`, `.github/`, `.gitleaks.toml` | commands, configuration, environment, the message catalog, the test kit, CI |
| Documentation | `README.md`, `README.es.md`, `docs/THREAT_MODEL.md`, `docs/HARNESSES.md`, `docs/COMPACTION.md`, `docs/WINDOWS.md`, `SECURITY.md`, `CONTRIBUTING.md`, `TRADEMARKS.md` | user and contributor documentation |
| Contract (maintainers only) | `docs/SPEC.md`, `docs/API.md`, `docs/HOOKS-IO.md`, `docs/TESTPLAN.md`, `docs/DECISIONS.md`, `docs/OWNERSHIP.md`, `internal/archtest/allowlist.go`, `LICENSE`, `NOTICE`, `.gitignore` | changed only through a contract change |

The rules that follow from it:

1. **Keep a change inside one area** when you can. Unexported code, new files and new tests in that area are fine.
2. **Exported identifiers are a frozen contract.** Do not change an exported signature, struct field, constant, variable or type, not even in the package you are working on, without a contract change. The same goes for shared vocabularies: capsule kinds and base ids, the unit-key parts, attention codes, doctor check codes, message ids and failpoint names.
3. **Need something from another area?** Write an unexported adapter in your own package, keep your tests green against the current contract, and describe the request in your pull request: package, identifier, current and proposed signature, why, and the adapter you used meanwhile. The maintainers then update the scaffold, `internal/archtest/allowlist.go` and `docs/API.md` (`make api-doc`) in one change.
4. **Imports follow `internal/archtest/allowlist.go`.** Lower layers never import higher ones, production code never imports test helpers, and only `internal/paths` reads the process environment; every file that builds an `exec.Cmd` sets its `Env`. `go test ./internal/archtest` enforces this at every commit.
5. **No new dependencies.** `go.mod` and `go.sum` are pinned; every allowed third-party import is already pinned by a blank import in the package that may use it.
6. **Behaviour comes with tests**, in the same change, in the test layer that [docs/TESTPLAN.md](docs/TESTPLAN.md) assigns.
7. **Helper programs for tests** (a scripted terminal program, a fake harness, a fake daemon) are `main` packages under the owning area's `testdata/`, and they take a lifeline (see [Tests and fixtures](#tests-and-fixtures-never-real-user-data)); any other new package needs a contract change.

## Style

- `gofmt`, `go vet` clean for every tag set on darwin, linux and windows, `staticcheck` and `govulncheck` clean.
- Errors are sentinel values checked with `errors.Is`, or `*ipc.Error` with a code; `cmd/precinto` maps them to exit codes. Error strings never contain file content, prompts or environment values.
- User-visible text comes from the message catalog in `internal/ui`: every text that hooks, the wrapper, the shell integration and the daemon show, every prompt another component or a test waits for, and every refusal. The only exceptions are the CLI's usage errors and command summaries, in `cmd/precinto/text.go`, and doctor's findings, in `internal/doctor/text.go`, which follow the same rules, each checked by its owner's tests. Messages name the folder and the next command, never include prompt text, titles or file content, and do not use the words "root", "grant", "soft" or "hard" (except in the flag `--root`): on screen Precinto says "folder", "locked", "paused" and "ended and sealed".
- Secrets (identities, passphrases, PINs, file keys, recovery keys) live in memguard locked buffers or enclaves, never in a `string` and never in JSON. Do not use `memguard.CatchInterrupt` or `memguard.CatchSignal`.
- No content in metadata: ledgers, journals, receipts, queue entries, the capsule log, logs and errors hold paths, ids and statistics only.
- Every blocking operation takes a `context.Context` and returns promptly when it is cancelled.
- Shell code is POSIX `sh` and passes `shellcheck -s sh`.
- Documentation is Markdown that renders on GitHub: in tables, write a literal `|` as `\|`, also inside code spans.

## Tests and fixtures: never real user data

- **Never read or write real user data**: not `~/.claude`, `~/.claude.json`, `~/.codex`, Precinto's real directory, the keychain, or any real project. Every path in a test comes from `testkit.NewHome` or `t.TempDir()`, and `HOME` is overridden too.
- **Synthetic content only.** Payloads, transcripts, rollouts and notes are generated by `claudetest` and `codextest` with marker strings from `testkit.Marker`. Golden files never contain real prompts, paths, emails, tokens or non-fixture UUIDs; `testkit.Hygiene` checks every `testdata/` directory in CI. Fixture UUIDs use the zero-prefixed form `00000000-0000-<v>000-8000-<12 hex>` that the hygiene check recognises.
- **Leak checks by marker.** Security and end-to-end tests search the whole fake home (except `capsules/`) for markers after each scenario; any hit fails.
- **Deterministic time and processes.** State-machine and liveness tests use `fakeplatform.Clock` and `fakeplatform.Procs`. Real child processes are used only where kernel behaviour is the subject, and a test never signals a process it did not start.
- **Helpers never outlive their test.** A helper process carries a lifeline (an inherited pipe or stdin) and a hard lifetime, and exits when the lifeline closes; every wait on a process is bounded (`exec.CommandContext`, plus `WaitDelay` when you capture its output). Every test kills and reaps every process it starts, including their sessions and descendants, and a package fails when a helper outlives it. A fake home is removed only after the daemons and workers started in it have exited (`testkit.Settle`; `newHome` in `test/integration`; the end-to-end worlds call `testkit.StopInstallation`, which runs `precinto agent --stop` with the home's environment, stops the workers of the test's binary and fails the test when a process of that installation is still running), and a package that builds binaries removes them in its `TestMain` (`testkit.RemoveBinaries`), so a test run leaves nothing behind in the temporary directory.
- **One time frame per boundary.** A clock frozen at `testkit.Epoch` is only for code whose every time input is fake, and fixture times derive from that clock. Code that compares its clock with times the kernel stamps (the mtimes of files a test creates) uses `fakeplatform.NewRealClock()`. A deadline sent to the daemon is real time, whatever clock the test injected. No test may depend on how far today's date is from `testkit.Epoch`.
- **Running the suite inside an agent session.** `testkit.NewHome` sets `PRECINTO_TEST_ANCESTRY_STOP` to the test process, so in `-tags testing` builds Precinto's agent detection ignores the test process and its ancestors (your Claude Code or Codex session) and still checks every process the test starts; environment markers and the no-terminal rule still apply, and production builds never read the variable.
- **No real side effects.** Outside the opt-in end-to-end suite, tests never show an unlock dialog, lock the screen, ask for a password or Touch ID, touch the keychain or install a service.
- **External test packages** (`package foo_test`) by default; internal tests only for unexported helpers. Unit tests must not need build tags.
- **Hooks never take a binary from the environment.** To make a real harness run the testing build, give the harness a throwaway `HOME` whose `precinto` link points at `testkit.BuildBinary(t, "testing")`; `PRECINTO_BIN` and `PRECINTO_DEV` must have no effect. Hook mode ignores every `PRECINTO_*` variable, even in testing builds, so a test that runs `precinto hook` gives it a `testkit.ShortTempDir` as `HOME`.
- Only `internal/testkit` defines the `-update` flag for golden files.

## Developer Certificate of Origin

Precinto accepts contributions under the [Developer Certificate of Origin](https://developercertificate.org/) (DCO) version 1.1. By adding a `Signed-off-by` line to a commit, you certify the following:

```text
Developer's Certificate of Origin 1.1

By making a contribution to this project, I certify that:

(a) The contribution was created in whole or in part by me and I
    have the right to submit it under the open source license
    indicated in the file; or

(b) The contribution is based upon previous work that, to the best
    of my knowledge, is covered under an appropriate open source
    license and I have the right under that license to submit that
    work with modifications, whether created in whole or in part
    by me, under the same open source license (unless I am
    permitted to submit under a different license), as indicated
    in the file; or

(c) The contribution was provided directly to me by some other
    person who certified (a), (b) or (c) and I have not modified
    it.

(d) I understand and agree that this project and the contribution
    are public and that a record of the contribution (including all
    personal information I submit with it, including my sign-off) is
    maintained indefinitely and may be redistributed consistent with
    this project or the open source license(s) involved.
```

### The Signed-off-by rule

- **Every commit** in a pull request must end with a sign-off line:

  ```text
  Signed-off-by: Your Name <you@example.com>
  ```

- Use the same name and email as the commit's author. `git commit -s` (or `--signoff`) adds the line for you.
- Forgot it? Add it to the last commit with `git commit --amend --signoff`, or to every commit of your branch with `git rebase --signoff <base>`, then update your pull request.
- You sign off only for yourself. If your change includes work by someone else, that person must have certified it as well (clause (c)).
- Commits without a valid sign-off cannot be merged.

## Pull requests

- Keep each pull request small and focused on one area.
- Say what behaviour changes and which part of the specification it implements or amends, and list the tests you added.
- Include any contract change request (see [How the code is organized](#how-the-code-is-organized)) and any open question about the specification.
- Make sure the checks in [Build and test](#build-and-test) pass.
- The maintainers review and merge; nobody pushes directly to the default branch.

## License

Precinto is licensed under the [Apache License 2.0](LICENSE). As section 5 of that license says, a contribution you submit is licensed under the same terms, and your sign-off certifies that you have the right to submit it. Third-party notices are in [NOTICE](NOTICE).
