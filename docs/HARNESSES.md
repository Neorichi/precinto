# Harness guide

A *harness* is the agent CLI you work with: Claude Code, Codex and others. This guide explains, for each harness precinto supports, what precinto seals, how its hooks and its wrapper fit in, and what to watch out for. The normative details are in [SPEC.md §7](SPEC.md#7-units-and-harness-adapters), [§14](SPEC.md#14-hooks-d22--wire-details-in-docshooks-iomd), [§15](SPEC.md#15-wrapper-and-shell-integration) and [HOOKS-IO.md](HOOKS-IO.md). precinto is pre-release (specification v0.2), so everything here is subject to change.

## Contents

- [Summary](#summary)
- [Claude Code](#claude-code)
- [Codex CLI](#codex-cli)
- [Experimental harnesses](#experimental-harnesses)

## Summary

| Harness | Level | Versions | What precinto seals | Hooks | Restore before launch |
|---|---|---|---|---|---|
| Claude Code | supported | verified on 2.1.329; 2.1.295 or later required | sessions, project memory, plans, prompt-history lines, global stores | yes, fail closed | yes |
| Codex CLI | supported | 0.154.x, verified from source | one Codex home per protected folder that manages Codex, through the wrapper only | optional, after you trust them in Codex (possibly once per folder); fail open on timeout | yes |
| Factory Droid, Cursor, GitHub Copilot CLI | experimental, unverified | – | no history store in v0.2 (hooks only) | drafts, with `--experimental` | no |
| Gemini CLI, Kimi Code, Qwen Code, OpenCode | experimental | – | stores from a data-driven inventory, sealed manually into the `global` vault | none | no (restore by hand with `precinto restore --global`) |

Every harness can be connected in two ways:

- **Hooks** gate prompts, tools, permission dialogs and compaction while a folder is locked, record which files a session touches, and queue the session for sealing when it ends. They ship in a plugin that `precinto integrate HARNESS` installs through the harness's own plugin commands (`--print` shows the steps instead of running them). `integrate` also writes `<base>/bin/precinto`, a link to the binary, which is the first place the hooks look for it; run it again if you move the binary. (`<base>` is precinto's directory: `~/Library/Application Support/precinto` on macOS, `${XDG_DATA_HOME:-~/.local/share}/precinto` on Linux.)
- **The wrapper**, `precinto run [--harness H] [--no-pty] -- CMD [ARGS]`, or the shell functions from `precinto shell-init`, which call it for you unless you are already inside a session it started. It unlocks before launch, restores what the session needs, shows the lock screen, ends the session when it is time, and seals it on exit. Under its pseudo-terminal, a harness's own Ctrl-Z suspend does nothing: the harness's process group is orphaned, so the kernel discards the stop signal.

`precinto status` shows the hook health of each harness ("hooks OK, seen N min ago", or why they are not running: untrusted, plugin disabled, `--bare`, `disableAllHooks`). `precinto doctor HARNESS` runs the read-only checks for one harness.

## Claude Code

### Support level

Verified on Claude Code 2.1.329. precinto needs 2.1.295 or later, the first version whose hooks can fail closed (`onFailure: "block"`); `precinto integrate` and `precinto doctor` refuse older versions.

### Where Claude Code keeps its data

| Name | Location |
|---|---|
| config directory (`$CC`) | `CLAUDE_CONFIG_DIR`, or `~/.claude` |
| temp directory (`$TMP`) | the base of the session's scratchpad directory, else `CLAUDE_CODE_TMPDIR`, else `/private/tmp/claude-<uid>` (macOS) or `/tmp/claude-<uid>` (Linux). It must belong to you with mode 0700, or precinto refuses to restore there and `doctor` warns. |
| cache directory | `~/Library/Caches/claude-cli-nodejs` (macOS), `${XDG_CACHE_HOME:-~/.cache}/claude-cli-nodejs` (Linux) |

precinto learns these locations in Claude Code's own environment, from the hooks and the wrapper, and adds every new one it sees to its list of homes; a second config directory (another `CLAUDE_CONFIG_DIR`) is covered as soon as it is seen. Below, `<P>` is Claude Code's project directory name for a folder and `<sid>` is a session id.

### What is sealed

| Unit | Files | Can be sealed when |
|---|---|---|
| Session | `$CC/projects/<P>/<sid>.jsonl` and its siblings (`*.compact.tmp.*`, `*.superseded-*`, `*.orphaned-*`, `.precompact.json.tmp.*`); everything under `$CC/projects/<P>/<sid>/` (subagent transcripts, tool results, workflow journals, `precompact.json`); every other file under `$CC` (up to four levels deep) and under `$TMP/<P>/` whose path has a component equal to the session id, or whose name starts with `<sid>.` or `<sid>-` (file history, session environment, uploads, todos, tasks, debug logs, image cache…); `$CC/jobs/<id>/` for the jobs that name the session | the session has ended, or is no longer the current session of its process (after `/clear` or `/resume`), and nothing writes its files |
| Project | `$CC/projects/<P>/memory/` (auto memory), the legacy `projects/<P>/sessions-index.json`, other non-session files directly in `projects/<P>/`, and `<cache>/<P>/` (MCP logs) | no Claude Code process has its working directory in the folder or in the git repository that contains it, and none has a working directory precinto cannot determine |
| Plan | `$CC/plans/<slug>.md` and `$CC/plans/<slug>-*.md`, with the slug taken from the session transcripts | no live session refers to that slug |
| History | the lines of `$CC/history.jsonl` whose project is inside the folder, plus the paste-cache entries that only those lines refer to | at rotation, which runs only when no Claude Code process runs anywhere |
| Global stores (`global` vault) | `$CC/usage-data/`, `$CC/feedback/drafts/` | no Claude Code process runs; they are restored only by `precinto restore --global` after `precinto unlock --global` |

Sweeps seal only units of locked folders; a session that ends is sealed whatever its folder's state. Transcripts are found by session id in every project directory, never by a remembered path, so a session resumed from another folder, or a temporary file left by a crash, is still found. A file that carries a session id but is unknown to precinto is sealed with that session rather than ignored (fail closed): that is how files added by future Claude Code versions are covered. Plans that Claude Code writes inside the project (`plansDirectory`) are Markdown in the folder and follow precinto's Markdown policy instead.

### What is never sealed

`settings*.json`, `plugins/`, `skills/`, `commands/`, `agents/`, `sessions/` (the registry of running sessions), credentials, `keybindings.json`, `ide/`, `CLAUDE.md` and `shell-snapshots/`. Stale shell snapshots (environment dumps that crashes leave behind, older than a day and not open) are deleted by sweeps while no Claude Code process runs; they are never sealed. The legacy `lastSessionFirstPrompt` entries in `~/.claude.json` are reported by `doctor`; cleaning them is deferred to a later version.

### Which sessions precinto manages

A session becomes *managed*, for the rest of its life, as soon as its start directory, `CLAUDE_PROJECT_DIR`, its current directory, a directory added to it, or any path a tool touches lies inside a protected folder. Sessions that never touch a protected folder are left alone and leave nothing in precinto's ledger. A session started outside every protected folder runs without precinto's wrapper; if it later touches a protected folder, the hooks gate it from then on, but it has no lock screen. Sessions that ran before the folder was protected, or without hooks, are recognised from the working directories recorded in their transcripts ("adopted"): `precinto status` lists them and `precinto seal --adopt` seals them.

### Hooks

`precinto integrate claude-code` installs the plugin. Every hook runs `sh "${CLAUDE_PLUGIN_ROOT}/scripts/precinto-hook" claude-code <Event>`, a small POSIX shim that finds the binary and runs `precinto hook`.

| Event | Timeout | What precinto does |
|---|---|---|
| SessionStart | 10 s | records the session and registers it with the daemon; in a locked folder, tells the model that the project is locked; never blocks |
| UserPromptSubmit | 90 s, fail closed | while locked, blocks the prompt (also for `/loop`, scheduled tasks, background-subagent reports and messages from other sessions); the block message leaves out your text, which you get back with ↑ after unlocking; with `unlock_on_prompt` on, a prompt you typed can raise the unlock dialog instead; human prompts count as activity |
| PreToolUse | 10 s, fail closed | records paths inside protected folders; while locked, denies the tool and tells the model to stop and ask you to run `precinto unlock` |
| PermissionRequest | 10 s, fail closed | denies while locked |
| PreCompact | 10 s, fail closed | blocks compaction while locked, otherwise marks it in progress (see [COMPACTION.md](COMPACTION.md)) |
| PostToolUse (`Write`, `Edit`, `MultiEdit`, `NotebookEdit`) | 10 s | records the Markdown files the agent wrote inside protected folders |
| PostCompact | asynchronous | marks the compaction finished |
| Stop, StopFailure | asynchronous | the turn ended: clears "busy", never extends the unlock |
| Notification (`idle_prompt`) | asynchronous | the session is waiting for you |
| CwdChanged, DirectoryAdded | 5 s | records new directories |
| SessionEnd | the shared 1.5 s budget | queues a seal request, starts a detached worker and returns at once |

The hook answers in under 50 ms and prints nothing when it allows. For a managed session every failure blocks: the daemon unreachable within 150 ms, a payload it cannot decode, its own deadline, a panic. If the binary is missing or crashes, the shim blocks gate events only when the working directory or `CLAUDE_PROJECT_DIR` is inside a protected folder, with "precinto could not run, so this protected folder stays locked. Reinstall precinto, then run: precinto doctor"; elsewhere it stays silent. The shim never reads `PRECINTO_*` variables, so a project's settings cannot redirect it.

The plugin also ships `lock` and `status` commands, and a skill that tells the model what a precinto block means and that it must never run `unlock`, `restore`, `cat`, `open` or `recover`, nor ask for secrets in the chat. There is deliberately no `unlock` command: it would be a way around the gate.

### Wrapper

`precinto run claude [ARGS]` (or `claude` with the shell integration), in a protected folder:

1. unlocks the folder in this terminal if it is locked;
2. restores what the launch needs before Claude Code starts. Resuming needs the transcript before Claude Code looks for it, which happens before any hook runs:

   | You run | precinto restores first |
   |---|---|
   | `claude --resume <uuid>` or `-r <uuid>` | that session, wherever its capsule is |
   | `claude --resume <path>.jsonl` | the session named by the file |
   | `claude --resume <name>` | the sessions of the folder's project, within the restore budget |
   | `claude --resume` or `-r` alone (the picker) | the project unit and the recent sessions |
   | `claude --continue` or `-c` | the newest session of this folder that Claude Code's `--continue` can pick (not one started by `claude -p` or the Agent SDK; a session started in Claude Code and later continued with `claude -p -c` still counts), then the project unit, then the folder's other recent sessions it can pick with their own times, because Claude Code also skips sessions whose first prompt was `/loop` and precinto cannot see that; with `-p`, the newest session of any kind; with `restore_recent = 0`, no other recent session |
   | any of these with `--fork-session` | the same as without it |
   | `claude attach <job>`, `claude respawn <job>` | the session of that job |

   precinto reads the options as Claude Code does, so `-pc` is `-p -c` and `-r<id>` is `-r <id>` (but `-r=<id>` resumes the name `=<id>`, as in Claude Code, where only a long option such as `--resume=<id>` splits at `=`). The project unit and the other recent sessions are restored beside the launch's target: one that another Claude Code is using (the project unit while another Claude Code runs in the folder, a session open in another terminal) is left as it is, and the launch goes on (still sealed, it then starts without it); only the session the launch resumes or continues must be free.

3. adds, unless you passed your own `--settings` (then it prints a notice and adds nothing), `--settings '{"idleCompaction":false,"awaySummaryEnabled":false,"precomputeCompactionEnabled":false}'` and `CLAUDE_CODE_ENABLE_AWAY_SUMMARY=0`, so that Claude Code does not summarize the session in the background while you are away (see [COMPACTION.md](COMPACTION.md)). For a session it starts fresh (no `--resume`, `--continue` or `--fork-session`, also when bundled as in `-pc` or `-r<id>`), it also passes `--session-id <uuid>` with an id it chose (yours when you pass your own `--session-id`), so it knows which session to seal even when its hooks do not run; it passes none where Claude Code would refuse it (`--environment` or `--pool`, a background or cloud session…) or where an option is one it cannot read, and then the hooks record the session. `precinto protect DIR --claude-settings` also merges the three settings into the folder's `.claude/settings.local.json` (Claude Code's local settings file, not meant to be committed), so that sessions started without precinto get them too; it keeps every other key there, and `precinto unprotect` removes the keys whose values precinto wrote. That is the only case in which precinto writes Claude Code settings into your project;
4. starts Claude Code: through a pseudo-terminal when stdin and stdout are terminals, so that it can draw the lock screen; directly (still gated and sealed) for `-p` or `--print`, `--output-format` and pipes. Commands that do not open a session here, such as `update` (or `upgrade`), `doctor`, `mcp`, `plugin` (or `plugins`), `install`, `setup-token`, `daemon` (also after `--dangerously-skip-permissions` or `--allow-dangerously-skip-permissions`, the only flags Claude Code accepts ahead of it), Remote Control (`remote-control` or `rc` first; Claude Code refuses precinto's `--settings` ahead of it), `--version` or `--help`, run straight away with no gate and no restore (the list lives in `inventories/claude-code.toml`); `claude config` is not a Claude Code command (it starts a session whose first prompt is "config"), so precinto manages it like any session;
5. on exit, resets the terminal, seals the session (or queues it) and prints at most one line saying what was sealed; if the folder locked meanwhile and precinto had restored other sessions into it, it starts a sweep of the folder.

It also asks before running `--bare` in a protected folder (`--bare` turns off precinto's hooks: the session is still sealed when it ends, but it does not pause when the folder locks), offers to open a copy with `--fork-session` when the session is already open in another terminal, and asks before `claude purge` runs (default no): yes runs it, and it deletes only Claude's own copies, because precinto keeps its sealed copies until you run `precinto forget` (D79). If no SessionStart hook arrives within 10 s, precinto marks the session as running without hooks and tells you when it exits (sessions in protected folders only).

Automatic restores skip sessions whose last activity is older than Claude Code's `cleanupPeriodDays` minus two days. An explicit resume restores them with their modification time set to one day ago, so that Claude Code's cleanup keeps them; the manifest keeps the original time. Capsules are never deleted at restore, so a restored file that Claude Code deletes later is not lost.

### Locking and ending

While its folder is locked, a managed session is paused as described in the [README](../README.md#two-levels-of-lock). When paused sessions are ended:

- a **wrapped** session is ended by its wrapper, which terminates its own child and that child's session, resets the terminal and prints how to resume;
- an **unwrapped** session gets SIGTERM once precinto has verified the process identity (pid and start time), then a wait of at least 8 s (longer when Claude Code's SessionEnd budget is longer, at most 70 s), then SIGKILL, and then SIGKILL of its verified descendants. precinto never signals by session or process group, because an unwrapped `claude` shares your terminal's session and your shell must survive. A compaction in progress gets up to 5 minutes unless you use `--force`. Afterwards precinto cleans the terminal if it belongs to you;
- **background** sessions (`--bg`, agent view, daemon backend) are never signalled, because their supervisor would restart them: they stay paused and `status` flags them.

An unwrapped session with no working hooks (plugin disabled, `--bare`, `disableAllHooks`) cannot be paused: an interactive one is ended at lock, and any other is only reported in `status` (`ungated-session`).

### Caveats

- A prompt blocked while locked may still be written to the transcript and to `history.jsonl`. The transcript copy is sealed with the session; the history line waits for the next rotation, which needs every Claude Code process to be closed. `status` counts the pending lines.
- In IDE terminals, desktop apps and `command claude`, a lock only stops the model; the conversation stays visible.
- Auto memory is shared by every session and worktree of a git repository, so it is sealed only when no Claude Code process works in that repository. `protect` warns when the repository root lies outside the folder, because the memory is then shared with unprotected sessions.
- Claude Code 2.1.329 has a flag-gated path that runs a reactive compaction despite precinto's block.
- `env` keys in Claude Code settings reach every hook. precinto ignores `PRECINTO_*` keys there, and `doctor` reports `PRECINTO_*`, `HOME`, `XDG_*`, `PATH`, `DYLD_*` and `LD_*` keys in your user settings and in the `.claude/settings*.json` files of each protected folder and of its subdirectories, up to four levels down, skipping `.git`, `node_modules` and `vendor` (`claude-settings-env`).
- `unlock_on_prompt` ships off; it is planned to turn on once its end-to-end test passes on the pinned Claude Code version.
- A large session is re-encrypted in full whenever it changes.
- The Claude desktop app's and Cowork's stores are outside precinto's inventory.

## Codex CLI

### Support level

Codex 0.154.x, verified from the Codex source. `doctor` warns on other versions until they are re-verified: Codex changed the way it starts hooks in 0.155 and again in 0.158. The hooks file (`plugins/codex/hooks/codex.json`) has not yet been loaded by a real Codex; it is frozen only after an opt-in end-to-end test passes under sh, bash, zsh and fish, so it may still change.

### A sealed Codex home per protected folder

precinto manages Codex **only inside protected folders, and only through the wrapper**. `precinto run codex` (or `codex` with the shell integration) in a protected folder runs Codex with:

| Variable | Value |
|---|---|
| `CODEX_HOME`, `CODEX_SQLITE_HOME` | `<base>/homes/codex/<folder-id>/`, a home just for this folder |
| `TMPDIR` | `<home>/precinto-tmp`, so that hook output Codex spills to disk stays inside the sealed home |

A protected folder manages Codex only when its entry in `config.toml` lists `codex` among its harnesses, and precinto asks before it adds it: `precinto protect` asks when Codex is installed, and `precinto run codex` asks only in a folder that does not manage Codex yet. Yes adds `codex` to the folder (a stricter setting, so it applies at once); no starts nothing (exit 3). Outside protected folders, and for commands that open no session (such as `codex login` and `codex logout`), Codex runs unchanged on your own Codex home (`~/.codex`, or your `CODEX_HOME`), which precinto never seals or modifies, except for `auth.json`: a newer copy is synchronized back to it, and after a logout its copy of the logged-out credentials is removed (see below).

The folder's home is seeded from yours: `config.toml` is copied once (without `sqlite_home` and `log_dir`), and at every launch the plugin and marketplace tables you add later (for example with `precinto integrate codex`) are added to the folder's copy, without changing anything it already has; `auth.json` is copied in when yours is newer and copied back after Codex exits when it changed; and `plugins/` and `skills/` are links to yours. If Codex created its own `plugins/` or `skills/` directory in the folder's home while you had none, precinto moves it next to that home, into `<home>.displaced/` (never deleted; `doctor` tells you), and links yours. `precinto codex sync-config --root DIR` copies your configuration again, keeping the folder's hook trust.

A logout is never undone. Once both homes held the same `auth.json`, a home whose copy disappears (`codex logout` in your own home, or Codex's `/logout` in a folder's session) gets nothing copied back, and the other home's copy of those credentials is removed too; a newer login in the other home is kept, and the copies are synchronized again once both homes have one. When you log in for the first time inside a protected folder, the credentials are copied back into `~/.codex` only: precinto never writes them into another `CODEX_HOME` that has no `auth.json` (such as a scratch one), so wiping or reusing such a home never logs you out anywhere; a `CODEX_HOME` that has a login of its own is synchronized like `~/.codex`. precinto keeps the SHA-256 of the last synchronized copy in the folder's home (`.precinto-auth`), one entry for each Codex home you used with that folder (`CODEX_HOME`), to tell a logout from a first login. A Codex home that is not there at a launch (an unmounted `CODEX_HOME`, a renamed `~/.codex`) is not a logout: nothing is copied or removed. Conversations you had in that folder before, in your own Codex home, stay there: they are not moved, not sealed, and do not appear in the folder's home; `status` and `doctor` count them.

### What is sealed

Everything in the folder's home except `auth.json`, `config.toml`, `hooks.json`, `plugins/`, `skills/`, `cache/`, `packages/`, `models_cache.json`, `installation_id`, `version.json`, `.tmp/`, `tmp/`, `thread-writer-locks/`, `app-server-control/`, `log/`, `rollout-maintenance.lock`, precinto's `.precinto-auth` and every `*-shm` file. This is a list of exclusions, not of inclusions: a file that a new Codex version adds is sealed too, and `doctor` reports new top-level entries.

- **Snapshots.** Each seal writes one snapshot generation listing every file (size, time, mode, hash) and the encrypted blobs it uses. A blob holds one file, or one SQLite database together with its `-wal` and `-journal` files, read in a single pass; `-shm` files are never sealed. An unchanged file reuses its blob. precinto never opens Codex's databases.
- **Restore.** Before Codex starts, precinto places exactly the newest snapshot that is not `diverged`, all or nothing, through a staging directory. Stray `-wal`, `-shm` or `-journal` files next to a database being placed are moved to quarantine, never deleted.
- **Divergence.** If the home holds content that the newest snapshot did not place (for example because Codex ran against it some other way), `precinto run codex` refuses (exit 4), seals that content as a separate `diverged` generation and deletes nothing. A `diverged` generation is never restored as the folder's home: until you reconcile, restore refuses too (exit 4). `precinto codex reconcile --root DIR --prefer capsule|plaintext` chooses which side to use and keeps the other one as a generation too. New conversations whose names do not collide may be merged automatically; databases never are. A stray `-wal` or `-journal` file without its database is not divergence: it goes to quarantine when the database is placed.
- **Liveness.** The home counts as in use while any process has a file open under it, while a launch lease is held, or while its files are still changing.

### Hooks (optional)

`precinto integrate codex` installs the plugin from its own directory, `plugins/codex/`, whose bytes do not change between releases: newer Codex versions hash every file of a plugin for hook trust, so a changed file would turn the hooks off until you trust them again. Codex runs plugin hooks only while the plugin is enabled and installed in the Codex home in use, and only after you trust them; precinto never writes that trust for you: run `/hooks` in Codex and trust precinto. The trust is stored in the configuration of the Codex home in use, which for a protected folder is the folder's own home. In Codex 0.154 a trust entry names precinto's plugin and hook, never a path, and holds a hash of the hook's declaration (its event, matcher, command and timeout), not of the files, so trust you gave in your own Codex home before a folder's home was created is copied with your configuration and stays valid there. After that, trust precinto once in the folder (start Codex there through precinto, then `/hooks`), or run `precinto codex sync-config --root DIR`, which copies your configuration again and keeps the folder's own trust. Until the hooks are trusted, `precinto run codex` warns you and asks whether to start anyway: history is still sealed when Codex exits, but prompts are not paused while the folder is locked. It also tells you, instead, when the folder's home does not load precinto's plugin (run `precinto integrate codex`, or `precinto codex sync-config --root DIR` if it is installed), and when the trust Codex keeps holds other hashes than precinto's hooks have: Codex 0.154 then skips them until you trust them again in `/hooks`, while a newer Codex may record trust differently, so the question asks you to look at `/hooks` (when those entries were written by a Codex newer than 0.154, which also records the plugin's contents, precinto cannot tell and asks nothing). `doctor` checks the same, for each folder's home and for your own, and for a Codex outside the versions precinto was verified with it says it cannot tell instead of warning.

Codex runs each hook through `$SHELL -lc`, so the commands are written `sh "$PLUGIN_ROOT/scripts/precinto-hook" codex <Event>`, without braces, which also works in fish. A login profile that prints anything would corrupt the JSON output; once a folder has its own Codex home, `doctor` checks that `$SHELL -lc true` prints nothing (it runs your login profile only then).

| Event | Timeout | What precinto does |
|---|---|---|
| SessionStart | 10 s | records the session; prints nothing in v0.2 |
| UserPromptSubmit | 90 s | while locked, blocks the prompt (reason on stderr, exit 2) |
| PreToolUse, PermissionRequest | 10 s | deny while locked |
| PostToolUse (`apply_patch`, `Edit`, `Write`) | 10 s | records Markdown files from the `*** Add File:`, `*** Update File:` and `*** Move to:` headers of patches |
| PreCompact | 10 s | while locked, blocks compaction with `{"continue":false,…}`, which aborts the turn |
| PostCompact, Stop | asynchronous | marks the compaction or the turn finished |
| Interrupt | 3 s | the turn was interrupted |
| SessionEnd | 3 s | queues a seal request; the worker waits until Codex has released its writer lock and exited |

In a protected folder that manages Codex, the gate also blocks a Codex session whose `CODEX_HOME` is not that folder's home, telling you to start Codex with `precinto run codex` or the shell integration. In a folder that does not manage Codex, it does not.

### Ending

Codex 0.154 installs no SIGTERM handler, so the wrapper first sends Codex's own quit keys through the terminal (Ctrl-C twice, then a 3 s wait), then SIGTERM, then SIGKILL, and finally resets the terminal.

### Caveats

- Codex 0.154 has no fail-closed option for hooks: if precinto's hook times out, the action proceeds. A crashed precinto binary is still caught by the shim inside protected folders. Untrusted hooks do not run at all.
- Codex started without precinto (an IDE, `command codex`) in a protected folder writes to your own Codex home, which precinto never seals. It is blocked only if precinto's hooks are trusted in your own Codex home, and only in a folder that manages Codex; `doctor` and `status` count such conversations (`codex-wrong-home`). To count them, precinto reads only the working directory recorded in the first line of each conversation file (at most 64 KiB), never content.
- A shared `codex app-server` is not supported in protected folders. A session started under one is a background session for precinto: it is never ended, and the folder's Codex home stays in use while it runs.
- Databases are sealed as opaque groups: free pages inside them are sealed too, but not scrubbed.
- Codex does not tell hooks its process id; precinto takes the nearest ancestor process whose executable is named `codex`.

## Experimental harnesses

Experimental support is off unless you ask for it with `--experimental`. It is unverified and may change or disappear.

### Hook hosts: Factory Droid, Cursor, GitHub Copilot CLI

These hosts can load hooks from the same `plugin/` directory as Claude Code, through their own manifests. Their hook files are unverified drafts: `precinto integrate <host> --experimental` enables them only after precinto's own golden and end-to-end checks, and prints what it cannot gate. precinto has no inventory of these hosts' session stores in v0.2, so it can gate them but does not seal their history; with `md = "all"`, every Markdown file in a protected folder is still sealed, whoever wrote it.

| Host | Hook files | Prompt gate | Tool gate | Compaction | Failure mode |
|---|---|---|---|---|---|
| Factory Droid | shares Claude Code's `plugin/hooks/hooks.json` | like Claude Code | like Claude Code | blocks manual compaction only | supports fail closed |
| Cursor | `plugin/.cursor-plugin/plugin.json`, `plugin/hooks/cursor.json` | `beforeSubmitPrompt` | `preToolUse`, `beforeShellExecution`, `beforeReadFile` (exact output still to be verified) | observed only | fails open unless `failClosed: true` |
| GitHub Copilot CLI | `plugin/.github/plugin/plugin.json`, `plugin/hooks/copilot.json` | **none**: prompts cannot be blocked, so only the wrapper helps | `preToolUse` deny | observed only | timeouts always fail open |

More notes: Droid uses different tool names (`Execute` for shell commands) and syncs sessions to its cloud by default. Cursor also imports Claude Code hooks from `.claude/settings*.json`, so a hook may fire twice; precinto drops a repeated non-gate event (same host, session, event, prompt, tool and paths) and never suppresses a gate event. Copilot CLI gives hooks no plugin-directory variable, so its hooks call `precinto` from `PATH`. When a Claude-format hook runs inside another host, precinto answers in that host's format or not at all.

### Inventory-only harnesses: Gemini CLI, Kimi Code, Qwen Code, OpenCode

These harnesses have no precinto hooks in v0.2. precinto describes their stores in data-driven inventories (`inventories/*.toml`, embedded in the binary): base directories and the environment variables that relocate them, content globs, exclusions, how to recognise their processes (by executable path and arguments, never by kernel process name), their lock files, and whether to check for open files. The values shipped in v0.2 are placeholders still to be verified.

- **Wrapper only.** `precinto run --harness <id> -- <command>` gives them the unlock before launch and the lock screen; without hooks, nothing pauses an unwrapped session.
- **Manual sealing.** `precinto seal --dormant <id> --experimental` seals one of these harnesses, and only when no matching process runs, no lock file is held, no file is open and no SQLite `-wal` or `-shm` file exists.
- **No automatic restore** in v0.2. Their stores belong to no folder, so their units are sealed into the `global` vault. Restore them yourself: `precinto unlock --global`, then `precinto restore --global --harness <id>` (without `--harness`, every global store is restored, Claude Code's included). Restore writes only into a home that precinto has registered for that harness in `config.toml`.
- `verified_versions` in an experimental inventory is informational: `doctor` warns when the installed version is outside it, but it never enables or blocks sealing.

Other agent CLIs have no precinto hooks and no shipped inventory in v0.2. Native adapters for Gemini, Kimi, Qwen, OpenCode, Cursor and Copilot are on the roadmap.
