# precinto — Hook I/O contract

Normative wire details for `precinto hook <harness> <event>` (SPEC §14) and the plugin files that invoke it. Owner of the implementation: G5 (`internal/hook`, `plugin/`, `plugins/codex/`). Sources: Claude Code 2.1.329 docs and binary strings, Codex `rust-v0.154.0` source (`codex-rs/hooks`, `codex-rs/config/src/hook_config.rs`), r2 research for other hosts.

Status per host: **Claude Code** verified (2.1.329, min 2.1.295); **Codex** verified from source (0.154.0; re-verify for ≥ 0.155: hook spawning changed in 0.155 and 0.158, `SessionStart` source `fork` arrived in 0.155) — the hooks file of §3.2 is UNVERIFIED against a real Codex until the opt-in E2E of TESTPLAN §9 (E2E-9) passes under sh, bash, zsh and fish, and `plugins/codex/` is not frozen before that (D61); **Droid, Cursor, Copilot** UNVERIFIED drafts — shipped experimental (D41), enabled only by `precinto integrate <host> --experimental` after G5's golden and E2E checks.

## 0. Rules for every host
1. **Allow = exit 0 with empty stdout.** Plain stdout becomes model context (SessionStart, UserPromptSubmit) or summarizer instructions (Claude PreCompact). Never print anything on allow.
2. **Never read, retain or log content.** Fields read are listed per host; `prompt`, `tool_input.content`, `old_string`, `new_string`, `tool_response`, `last_assistant_message`, `compact_summary`, `custom_instructions` and environment values are never retained, logged or echoed, including on parse errors (S11, S13).
3. **Fail closed for managed sessions** (I5): daemon unreachable within 150 ms, payload over 64 MiB or undecodable, own deadline reached, panic ⇒ the event's block/deny output below; a missing or failed binary ⇒ the shim's static block inside a `roots.list` root (§5). Unmanaged sessions fail open (exit 0, empty stdout). The prompt text says why: daemon unreachable or untrusted (`ipc.ErrNoDaemon`, `ipc.ErrUntrustedServer`) ⇒ C3.agentdown; decode error, deadline, panic, a failing gate query or an unknown verdict ⇒ C3.failed (`hook.FailClosed` is the static C3.failed answer).
4. **Block texts** come from the `internal/ui` catalog (C3.*) and never contain OS error strings (HA5). `<folder>` is the `~`-shortened root path.
5. **Exit-code contract (D43, D56).** The binary exits `0` (allow, or a JSON block that needs exit 0), `10` (intended "exit 2" block, Codex), or `1` (internal failure). The shim passes stdout through and exits 0 on `0`, exits 2 on `10`, and handles anything else (1, a Go runtime exit 2, a signal) like a missing binary: stdout discarded, then the `roots.list` rule of §5 step 3. The binary never exits 1 on purpose for a managed gate event: it prints `hook.FailClosed` output instead.
6. **Deadlines.** The hook prints its decision before its own deadline, strictly below the harness timeout (§1), so the harness timeout never fires.
7. **Host detection (HA21, D56, D92; `hook.DetectHost`).** First match wins. Claude Code and Codex pass the user's whole environment to hooks, so other hosts' variables are often only inherited: they never override Claude's or Codex's markers.
   1. Codex: the argv label `codex` (`plugins/codex/hooks/codex.json`, loaded only by Codex) or `turn_id` in the payload ⇒ codex;
   2. the labels `cursor` and `copilot` ⇒ those hosts;
   3. a camelCase event name (only Copilot and Cursor generate them) ⇒ cursor when `CURSOR_VERSION`/`CURSOR_PLUGIN_ROOT` is set, else copilot;
   4. Claude markers: `CLAUDE_PID`, `CLAUDECODE=1` or `CLAUDE_PROJECT_DIR` (with a PascalCase payload) ⇒ claude-code, whatever `COPILOT_*`, `CURSOR_*`, `DROID_*` or `FACTORY_*` variables are set;
   5. `PLUGIN_ROOT` set and neither `CLAUDE_PID` nor `CLAUDECODE` ⇒ codex (Claude sets only `CLAUDE_PLUGIN_ROOT`);
   6. other hosts' variables, by exact name only (no `COPILOT_` prefix): `CURSOR_VERSION`/`CURSOR_PLUGIN_ROOT` ⇒ cursor; `DROID_PLUGIN_ROOT`/`FACTORY_PROJECT_DIR` ⇒ droid;
   7. otherwise the argv label, which names the hooks file that invoked the hook (`claude-code` from `plugin/hooks/hooks.json`, `codex`, `cursor`, `copilot`).

   A missing marker therefore never makes a gate fail open: `CLAUDE_PID` was observed only on SessionStart, UserPromptSubmit, PostToolUse, Stop and SessionEnd (never on PreToolUse, PreCompact or PermissionRequest), and Codex SessionStart/SessionEnd payloads have no `turn_id`. Only an unrecognised label with no marker is "unknown": its gate events whose cwd or `CLAUDE_PROJECT_DIR` lies inside a root exit 1 (the shim then applies §5 step 3), everything else exits 0. A Claude-format hook firing inside another host answers in that host's format or exits 0. HA21 de-duplication (`state/hookdedupe/`) applies only to non-gate events of Cursor and Copilot, keyed by (host, session, event, prompt id, tool name, paths, source, reason); gate events are never suppressed.

## 1. Timing (normative; `hook.Timings`)

| Host | Event | Declared timeout | Hook deadline | Unlock wait |
|---|---|---|---|---|
| claude-code | UserPromptSubmit | 90 s, `onFailure: block` | 85 s | ≤ 60 s (GUI factor, human prompt) |
| claude-code | PreToolUse, PermissionRequest, PreCompact | 10 s, `onFailure: block` | 7 s | – |
| claude-code | SessionStart, PostToolUse | 10 s | 5 s | – |
| claude-code | CwdChanged, DirectoryAdded | 5 s | 3 s | – |
| claude-code | Stop, StopFailure, Notification, PostCompact | `async: true` | 5 s | – |
| claude-code | SessionEnd | shared 1.5 s budget (plugin timeouts do not raise it) | 1 s | – |
| codex | UserPromptSubmit | 90 s (no `onFailure`: unverified key, D61) | 85 s | ≤ 60 s |
| codex | PreToolUse, PermissionRequest, PreCompact | 10 s | 7 s | – |
| codex | SessionStart, PostToolUse | 10 s | 5 s | – |
| codex | Interrupt | 3 s (max 3) | 2 s | – |
| codex | SessionEnd | 3 s (max 3; login-shell startup counts) | 2 s | – |
| codex | Stop, PostCompact | `async: true` | 5 s | – |

Async events have no enforced harness timeout; the hook's own 5 s deadline bounds them.

## 2. Claude Code (verified 2.1.329; minimum 2.1.295 for `onFailure`)

### 2.1 Invocation
Shell form (Claude runs `sh -c`); every command is `sh "${CLAUDE_PLUGIN_ROOT}/scripts/precinto-hook" claude-code <Event>`. Hooks are direct children of `claude`, in their own process group, with no controlling terminal (`/dev/tty` unavailable).

### 2.2 `plugin/hooks/hooks.json` (exact)
```json
{
  "description": "precinto: gate and seal agent sessions in protected folders",
  "hooks": {
    "SessionStart": [{ "matcher": "startup|resume|clear|compact|fork", "hooks": [{ "type": "command", "command": "sh \"${CLAUDE_PLUGIN_ROOT}/scripts/precinto-hook\" claude-code SessionStart", "timeout": 10 }] }],
    "UserPromptSubmit": [{ "hooks": [{ "type": "command", "command": "sh \"${CLAUDE_PLUGIN_ROOT}/scripts/precinto-hook\" claude-code UserPromptSubmit", "timeout": 90, "onFailure": "block" }] }],
    "PreToolUse": [{ "matcher": "*", "hooks": [{ "type": "command", "command": "sh \"${CLAUDE_PLUGIN_ROOT}/scripts/precinto-hook\" claude-code PreToolUse", "timeout": 10, "onFailure": "block" }] }],
    "PermissionRequest": [{ "matcher": "*", "hooks": [{ "type": "command", "command": "sh \"${CLAUDE_PLUGIN_ROOT}/scripts/precinto-hook\" claude-code PermissionRequest", "timeout": 10, "onFailure": "block" }] }],
    "PostToolUse": [{ "matcher": "Write|Edit|MultiEdit|NotebookEdit", "hooks": [{ "type": "command", "command": "sh \"${CLAUDE_PLUGIN_ROOT}/scripts/precinto-hook\" claude-code PostToolUse", "timeout": 10 }] }],
    "PreCompact": [{ "matcher": "manual|auto", "hooks": [{ "type": "command", "command": "sh \"${CLAUDE_PLUGIN_ROOT}/scripts/precinto-hook\" claude-code PreCompact", "timeout": 10, "onFailure": "block" }] }],
    "PostCompact": [{ "matcher": "manual|auto", "hooks": [{ "type": "command", "command": "sh \"${CLAUDE_PLUGIN_ROOT}/scripts/precinto-hook\" claude-code PostCompact", "async": true }] }],
    "Stop": [{ "hooks": [{ "type": "command", "command": "sh \"${CLAUDE_PLUGIN_ROOT}/scripts/precinto-hook\" claude-code Stop", "async": true }] }],
    "StopFailure": [{ "hooks": [{ "type": "command", "command": "sh \"${CLAUDE_PLUGIN_ROOT}/scripts/precinto-hook\" claude-code StopFailure", "async": true }] }],
    "Notification": [{ "matcher": "idle_prompt", "hooks": [{ "type": "command", "command": "sh \"${CLAUDE_PLUGIN_ROOT}/scripts/precinto-hook\" claude-code Notification", "async": true }] }],
    "CwdChanged": [{ "hooks": [{ "type": "command", "command": "sh \"${CLAUDE_PLUGIN_ROOT}/scripts/precinto-hook\" claude-code CwdChanged", "timeout": 5 }] }],
    "DirectoryAdded": [{ "hooks": [{ "type": "command", "command": "sh \"${CLAUDE_PLUGIN_ROOT}/scripts/precinto-hook\" claude-code DirectoryAdded", "timeout": 5 }] }],
    "SessionEnd": [{ "hooks": [{ "type": "command", "command": "sh \"${CLAUDE_PLUGIN_ROOT}/scripts/precinto-hook\" claude-code SessionEnd" }] }]
  }
}
```
Notes: `MultiEdit` is absent from the docs but present in the 2.1.329 binary's file-edit tool list; keep it. Do not add a `modules` key (Claude mods) to any file Codex can read. The plugin manifest has no `engines` key: the minimum Claude version is enforced by `integrate` and `doctor` (§6). CI: `claude plugin validate --strict ./plugin`.

### 2.3 Input read (everything else is ignored)
- Common stdin: `session_id`, `prompt_id` (absent before the first input), `transcript_path` (may not exist yet; on SessionStart of a cross-folder resume it can name the wrong slug — trust SessionEnd's value or locate by sid), `cwd` (current directory; follows `cd`), `scratchpad_dir` (≥ 2.1.257), `hook_event_name`, `agent_id`/`agent_type` (subagents), `permission_mode`.
- Per event: SessionStart `source` (`startup|resume|clear|compact|fork`); SessionEnd `reason` (`clear|resume|logout|prompt_input_exit|other`); PreCompact `trigger` (`manual|auto`; `auto` includes idle compaction); Pre/PostToolUse `tool_name` and only the path keys of `tool_input` (`file_path`, `notebook_path`, `path`); Notification `notification_type`; CwdChanged `old_cwd`/`new_cwd`; DirectoryAdded `directory` (plus `source`).
- Environment: `CLAUDE_PID` (harness pid; fallback: the nearest ancestor that is not a shell; the daemon re-measures it), `CLAUDE_PROJECT_DIR` (start directory; not updated in worktrees), `CLAUDE_CODE_SESSION_ID`, `CLAUDE_CODE_ENTRYPOINT` (`cli|sdk-cli`), `CLAUDE_CONFIG_DIR`, `CLAUDE_CODE_EXECPATH` (version from its basename), `CLAUDE_PLUGIN_ROOT`. `CLAUDE_ENV_FILE` and `CLAUDE_CODE_MESSAGING_*` are never read.

### 2.4 Output (exact)
| Event | Block / deny (stdout, exit 0) | Notes |
|---|---|---|
| UserPromptSubmit | `{"decision":"block","reason":"<C3.blocked>","hookSpecificOutput":{"hookEventName":"UserPromptSubmit","suppressOriginalPrompt":true}}` | `hookSpecificOutput` requires `hookEventName`; `suppressOriginalPrompt` keeps the typed text off the block message (it may still reach transcript and history, SPEC §19). Fires also for `/loop`, scheduled tasks, background-subagent reports, cross-session messages. |
| PreToolUse | `{"continue":false,"stopReason":"<C3.stop>","hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"<C3.tooldenied>"}}` | `permissionDecisionReason` is non-empty and addressed to the model; `continue:false` alone does not block a tool, the deny does. |
| PermissionRequest | `{"hookSpecificOutput":{"hookEventName":"PermissionRequest","decision":{"behavior":"deny","message":"<C3.tooldenied>"}}}` | exit 2 is not honoured here; verify `message` in the golden/E2E test. |
| PreCompact | `{"decision":"block","reason":"<C3.compact>"}` | blocked proactive compaction is skipped; blocked reactive compaction fails the request (a flag-gated 2.1.329 path may run it anyway, SPEC §19). |
| SessionStart (folder locked) | `{"hookSpecificOutput":{"hookEventName":"SessionStart","additionalContext":"<C3.start.model>"}}` | never blocks; exit 2 would only show stderr to the user. |
| PostToolUse, PostCompact, Stop, StopFailure, Notification, CwdChanged, DirectoryAdded, SessionEnd | nothing | never exit 2 (PostToolUse would feed stderr to the model; Stop would prevent stopping). |

### 2.5 Exit codes and failures
- Exit 0: stdout parsed as JSON; JSON failing the schema is a non-blocking error (the action proceeds) unless `onFailure: "block"`.
- Exit 2: blocking with stderr as reason — EXCEPT a plugin UserPromptSubmit hook with empty stdout whose stderr mentions a missing file ("No such file or directory"), which Claude treats as non-blocking. precinto never relies on exit 2 for Claude.
- Other exit codes, timeouts, unstartable commands, invalid output: non-blocking unless `onFailure: "block"` (≥ 2.1.295), which turns them into a block for gate events. The shim never lets a failed binary reach Claude as exit 1: it applies the `roots.list` rule (§5), so a crash blocks inside protected folders and nowhere else.
- SessionEnd: all SessionEnd hooks share a 1.5 s budget (raised only by `CLAUDE_CODE_SESSIONEND_HOOKS_TIMEOUT_MS` in the launching environment, or settings-level timeouts, not plugin timeouts); then SIGTERM to the hook's process group, SIGKILL ≈ 1.5 s later. The hook enqueues a seal request and starts a detached worker (Setsid, double-fork, stdio `/dev/null`), returning in < 100 ms. The registry file `sessions/<pid>.json` is already deleted when SessionEnd runs.
- Background sessions (`--bg`, agent view) are restarted by their supervisor when signalled; precinto never signals them (D25).

## 3. Codex (verified 0.154.0)

### 3.1 Invocation
- Manifest `plugins/codex/.codex-plugin/plugin.json` → `"hooks": "./hooks/codex.json"` (a manifest `hooks` entry replaces the default file). The plugin root holds only the manifest, `hooks/codex.json` and `scripts/precinto-hook`, and is byte-identical across releases (trust hash, D41).
- Codex runs `$SHELL -lc "<command>"` (fallback `/bin/sh`) with the environment cleared and replaced by the session snapshot plus `PLUGIN_ROOT`/`PLUGIN_DATA` (aliases `CLAUDE_PLUGIN_ROOT`/`CLAUDE_PLUGIN_DATA`); cwd = session cwd; `process_group(0)` (the controlling TTY is still attached: never read it). A login profile that prints to stdout corrupts JSON outputs — `doctor` checks that `$SHELL -lc true` prints nothing (HA6). Because `$SHELL` may be fish, which rejects `${VAR}`, commands use `"$PLUGIN_ROOT/…"` without braces (valid in sh, bash, zsh and fish) [D61].
- Handler keys in 0.154: `type`, `command`, `commandWindows`, `timeout` (s), `async`, `statusMessage`, `additionalContextLimit`. Whether 0.154 tolerates an unknown handler key (such as `onFailure`) is UNVERIFIED — the HA6 reading of `HookHandlerConfig` and the IM6 reading disagree and no real Codex has loaded such a file — so `codex.json` uses only `type`, `command`, `timeout` and `async`; `onFailure` is added only if E2E-9 proves it is accepted (D61). Codex 0.154 has no `onFailure` semantics anyway: a timed-out hook fails open (SPEC §19). The top level of the file (`description`, `hooks`) rejects unknown keys. No `args`: shell form only.
- Hooks run only after the user trusts them in `/hooks` (trust stored as `[hooks.state."<path>:<Event>:<g>:<h>"] trusted_hash` in the `config.toml` of the `CODEX_HOME` in use — for precinto, the per-root home, seeded from the user's config).

### 3.2 `plugins/codex/hooks/codex.json` (exact)
```json
{
  "description": "precinto: gate and seal Codex sessions in protected folders",
  "hooks": {
    "SessionStart": [{ "matcher": "*", "hooks": [{ "type": "command", "command": "sh \"$PLUGIN_ROOT/scripts/precinto-hook\" codex SessionStart", "timeout": 10 }] }],
    "UserPromptSubmit": [{ "hooks": [{ "type": "command", "command": "sh \"$PLUGIN_ROOT/scripts/precinto-hook\" codex UserPromptSubmit", "timeout": 90 }] }],
    "PreToolUse": [{ "matcher": "*", "hooks": [{ "type": "command", "command": "sh \"$PLUGIN_ROOT/scripts/precinto-hook\" codex PreToolUse", "timeout": 10 }] }],
    "PermissionRequest": [{ "matcher": "*", "hooks": [{ "type": "command", "command": "sh \"$PLUGIN_ROOT/scripts/precinto-hook\" codex PermissionRequest", "timeout": 10 }] }],
    "PostToolUse": [{ "matcher": "apply_patch|Edit|Write", "hooks": [{ "type": "command", "command": "sh \"$PLUGIN_ROOT/scripts/precinto-hook\" codex PostToolUse", "timeout": 10 }] }],
    "PreCompact": [{ "matcher": "*", "hooks": [{ "type": "command", "command": "sh \"$PLUGIN_ROOT/scripts/precinto-hook\" codex PreCompact", "timeout": 10 }] }],
    "PostCompact": [{ "matcher": "*", "hooks": [{ "type": "command", "command": "sh \"$PLUGIN_ROOT/scripts/precinto-hook\" codex PostCompact", "async": true }] }],
    "Stop": [{ "hooks": [{ "type": "command", "command": "sh \"$PLUGIN_ROOT/scripts/precinto-hook\" codex Stop", "async": true }] }],
    "Interrupt": [{ "hooks": [{ "type": "command", "command": "sh \"$PLUGIN_ROOT/scripts/precinto-hook\" codex Interrupt", "timeout": 3 }] }],
    "SessionEnd": [{ "hooks": [{ "type": "command", "command": "sh \"$PLUGIN_ROOT/scripts/precinto-hook\" codex SessionEnd", "timeout": 3 }] }]
  }
}
```
Golden test: decode with a Go mirror of `HooksFile` that disallows unknown top-level keys **and** unknown handler keys (only `type`, `command`, `timeout`, `async`, `matcher` are used). Before `plugins/codex/` is frozen, E2E-9 (TESTPLAN §9) loads this exact file into real Codex 0.154 with a synthetic `CODEX_HOME` (`-c hooks.*` with `--dangerously-bypass-hook-trust`) under `SHELL` = sh, bash, zsh and fish and asserts that a UserPromptSubmit block fires (D61).

### 3.3 Input read
Common: `session_id` (= root thread UUID in the rollout name), `transcript_path` (live rollout; null for ephemeral), `cwd`, `hook_event_name`. Per event: SessionStart `source` (`startup|resume|clear|compact`; runs at the **first turn**, after resumed history is loaded); UserPromptSubmit `turn_id`; PreToolUse/PostToolUse `turn_id`, `tool_name`, and for `apply_patch` only the `*** Add File:`, `*** Update File:`, `*** Move to:` header paths of `tool_input.command`, resolved against `cwd` (HA25); PreCompact `turn_id`, `trigger`; Interrupt `turn_id`; SessionEnd `reason` (always `other`). Environment: `CODEX_HOME` (from the session snapshot; checked against the folder's per-root home, D31), `PLUGIN_ROOT`. There is no pid variable: the harness pid is the nearest ancestor whose executable basename is `codex` (HA17); if that process is `codex app-server`, the home is marked daemon-held (the session registers as background: never signalled, live while it runs). Host markers (§0.7): `PLUGIN_ROOT` is present on every event, `turn_id` is absent on SessionStart and SessionEnd; with neither, the label `codex` decides, so SessionEnd still enqueues its seal request.

### 3.4 Output (exact)
| Event | Block / deny | Notes |
|---|---|---|
| UserPromptSubmit | stdout empty; stderr `<C3.blocked>`; binary exit 10 → shim exit 2 | immune to login-profile noise. JSON alternative `{"decision":"block","reason":"<non-empty>"}` (exit 0) breaks if the profile prints first. An empty reason is invalid (the prompt proceeds). |
| PreToolUse | stdout empty; stderr `<C3.tooldenied>`; exit 10 → 2 | `continue:false`, `stopReason`, `suppressOutput` or `ask` make the JSON output invalid (the tool proceeds). Hosted tools (WebSearch) are not hooked. |
| PermissionRequest | stdout empty; stderr `<C3.tooldenied>`; exit 10 → 2 | becomes `Deny{message}`. |
| PreCompact | stdout exactly `{"continue":false,"stopReason":"<C3.compact>"}`, exit 0 | the only way to block; aborts the turn (TurnAborted). Any non-zero exit is a failure and compaction proceeds; no `decision` key is accepted. |
| SessionStart | nothing (`{"hookSpecificOutput":{"hookEventName":"SessionStart","additionalContext":"…"}}` allowed but not used in v0.2) | cannot block. |
| PostToolUse, PostCompact, Stop, Interrupt, SessionEnd | nothing | never exit 2: PostToolUse would feed stderr to the model; a synchronous Stop would turn stderr into a continuation prompt. |

Every output struct denies unknown fields: never emit a key not listed above.

### 3.5 Exit codes and failures
Exit 0: stdout parsed (it must start with `{` after leading whitespace, else UserPromptSubmit/SessionStart treat it as plain-text context — fail open). Exit 2 with non-empty stderr: block (UserPromptSubmit, PreToolUse, PermissionRequest). Other codes and timeouts: `Failed`, the action proceeds (no `onFailure` in 0.154; SPEC §19). A crashed or killed binary is caught by the shim (§5 step 3): inside a protected folder it still exits 2 with D.shim (or prints the PreCompact JSON). On timeout Codex kills the hook's process group; detached helpers must `setsid` and redirect stdio. SessionEnd runs before the final rollout flush and writer-lock release: the worker waits for `thread-writer-locks/<session_id>.lock` to be unheld (open-file check, never flock) and the codex pid to exit. SessionEnd is not run on SIGTERM/crash (the 0.154 TUI has no SIGTERM handler).

## 4. Other hosts (UNVERIFIED drafts; experimental)

| Host | Files | Prompt gate | Tool gate | Compaction | Failure mode | Notes |
|---|---|---|---|---|---|---|
| Factory Droid | shares `plugin/hooks/hooks.json` (installs Claude plugins) | UserPromptSubmit like Claude | PreToolUse deny like Claude | PreCompact blocks manual only | supports `onFailure: block` | env `DROID_PLUGIN_ROOT`; tool names differ (`Execute` for Bash); cloud session sync on by default |
| Cursor | `plugin/.cursor-plugin/plugin.json` → `hooks/cursor.json` (flat `{version:1, hooks:{event:[{command, timeout, failClosed}]}}`, camelCase) | `beforeSubmitPrompt` → `{"continue":false,"user_message":"<C3.blocked>"}` | `preToolUse`/`beforeShellExecution`/`beforeReadFile` deny (exact JSON to verify) | `preCompact` observe-only | fails open unless `failClosed: true` | `CURSOR_PLUGIN_ROOT`; imports Claude hooks from `.claude/settings*.json` (double firing) |
| Copilot CLI | `plugin/.github/plugin/plugin.json` → `hooks/copilot.json` (`version:1`, `bash`, `timeoutSec`) | none (`userPromptSubmitted` cannot block) ⇒ wrapper only | `preToolUse` `{"permissionDecision":"deny","permissionDecisionReason":"…"}` (fails closed on crash/exit 2) | `preCompact` observe-only | timeouts always fail open | no plugin-root variable: call `precinto` from `PATH` |
| Gemini, Kimi, Qwen, OpenCode, Crush, Goose, Auggie, Continue, Aider | none in v0.2 | wrapper only | – | – | – | inventories only (D33) |

Cursor, Copilot and Droid are gate-only: their SessionEnd (or equivalent) enqueues no seal request; their sessions are sealed by sweeps. `precinto integrate cursor|copilot` requires `--experimental` and prints what it cannot gate.

## 5. Shim contract (`plugin/scripts/precinto-hook`, `plugins/codex/scripts/precinto-hook`; identical bytes)
POSIX `sh`, `shellcheck`-clean, invoked as `sh <shim> <harness> <event>` with the payload on stdin. The shim never reads any `PRECINTO_*` variable: hooks always run in an agent context, and Claude's settings `env` (agent-writable in `<root>/.claude/settings.local.json`) reaches hook processes (D6, D56).
1. Resolve the binary, first match wins: `<base>/bin/precinto` (symlink written by `precinto integrate`; `<base>` per SPEC §6.1 for the OS, from `$HOME` or `$XDG_DATA_HOME`), then `precinto` on `PATH`, then `/opt/homebrew/bin/precinto`, `/usr/local/bin/precinto`, `$HOME/go/bin/precinto`. Tests and E2E runs point `<base>/bin/precinto` at the `-tags testing` build by running the harness with a throwaway `HOME` (darwin; plus `XDG_DATA_HOME` on linux), or load a test-only plugin directory whose shim is generated by the test; nothing in the shipped shim selects a binary from the environment.
2. Run it in one fork with stdin passed through and stdout and stderr captured, the call itself silenced: `run() { out=$(exec "$bin" hook "$1" "$2" 2>&1); rc=$?; }; run "$1" "$2" 2>/dev/null` (job-control messages such as "Killed: 9" never reach the harness). On `rc = 0` pass through only empty output (exit 0) or one `{…}` JSON object (`printf '%s' "$out"`, exit 0); anything else is a failed run (step 3). On `rc = 10` print the captured reason on stderr and exit 2 (an empty reason is a failed run). Any other `rc` (1, a Go runtime exit 2, 128+signal) is a failed run: discard `$out` and continue with step 3.
3. Missing or failed binary: for gate events (`UserPromptSubmit`, `PreToolUse`, `PermissionRequest`, `PreCompact`; Cursor's `beforeSubmitPrompt`, `preToolUse`, `beforeShellExecution`, `beforeMCPExecution`, `beforeReadFile`), compare `$PWD` and `$CLAUDE_PROJECT_DIR` with the lines of `<base>/roots.list` (path-boundary match, not string prefix); inside a root print that harness's static block with the text D.shim (`ui.MsgShimFailed`, frozen with the shim bytes) — Claude: the §2.4 JSON, exit 0; Codex UserPromptSubmit/PreToolUse/PermissionRequest: D.shim on stderr, exit 2; Codex PreCompact: `{"continue":false,"stopReason":"<D.shim>"}`, exit 0; Cursor and Copilot: their deny JSON, exit 0; any other label answers the Claude JSON for Claude event names, else D.shim on stderr, exit 2 — otherwise exit 0 silently. Non-gate events exit 0.
4. Never print OS error text; never read stdin when the binary is missing (discard it).
5. Keep it to one fork for the binary (the command substitution): Codex runs the shim through a login shell on every hook.

Shim tests (G5): `shellcheck -s sh`; a table of binary exit → shim exit and output (0 with output, 10, 1, a simulated Go exit 2, SIGKILL) inside and outside a `roots.list` root for each gate event; `PRECINTO_BIN`/`PRECINTO_DEV` set in the environment have no effect; a test asserts D.shim in both shims equals `ui.MsgShimFailed` byte for byte.

## 6. Minimum versions and checks
- Claude Code ≥ 2.1.295 (`onFailure`); verified 2.1.329. `integrate` and `doctor` refuse older versions.
- Codex 0.154.x verified from source; `doctor` warns on other versions until re-verified; Codex hooks are optional (the wrapper and per-root home work without them). `plugins/codex/` is frozen only after E2E-9 passes (D61).
- `doctor` flags `PRECINTO_*`, `HOME`, `XDG_*`, `PATH`, `DYLD_*` and `LD_*` keys in the `env` of every Claude settings file it can see (user settings and `<root>/.claude/settings*.json`): they reach every hook process (`claude-settings-env`, D56).
- `status` shows per harness "hooks OK, seen N min ago" or the reason they are not running (untrusted, plugin disabled, `--bare`, `disableAllHooks`) (UX10).
