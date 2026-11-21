# precinto

English · [Español](README.es.md)

> **precinto** (Spanish): a seal that keeps something closed, so that it is opened only when, and by whom, it should be.

precinto is a KeePass-style vault for AI coding-agent sessions. You choose the folders that matter. When one of them locks (because you stopped typing, the screen locked, or you asked), precinto seals the conversations, summaries, memories, plans, tool outputs and agent-written notes of its sessions into [age](https://age-encryption.org)-encrypted capsules. Coming back asks for your presence (Touch ID or your Mac password, a hardware key, or a passphrase), and everything is restored byte for byte where it was.

> **Status: pre-release, specification v0.2, under active development.** The commands on this page describe the v0.2 specification and are being implemented right now: some may be missing or change. macOS first, Linux partial, no Windows. The repository is not public yet, and every design decision is still a default waiting for the project owner's confirmation, so details are subject to change.

## Contents

- [The problem](#the-problem)
- [How it works](#how-it-works)
- [Status](#status)
- [Install from source](#install-from-source)
- [Quick start](#quick-start)
- [Everyday commands](#everyday-commands)
- [Configuration](#configuration)
- [Supported harnesses](#supported-harnesses)
- [What precinto does not protect against](#what-precinto-does-not-protect-against)
- [FAQ](#faq)
- [Documentation](#documentation)
- [License](#license)

## The problem

Coding agents (precinto calls them *harnesses*: Claude Code, Codex and the like) keep everything you and they say as plaintext on disk:

- full conversation transcripts, including the files the agent read, command output and anything you pasted;
- derived data: compaction summaries, auto memory, plans, checkpoints of edited files, tool results, todo lists, debug logs;
- your prompt history, in a separate file;
- Markdown notes and plans that the agent writes into your project.

These files stay in your home directory for weeks, protected only by file permissions, so any program running as you can read them: an infostealer run once, a package's install script, another agent searching your home directory, a backup or a synced folder.

precinto keeps those files encrypted whenever nobody is using them, and asks for you before they come back.

## How it works

### Protected folders, one vault each

You protect a folder with `precinto protect DIR`. Each protected folder gets its own vault: an X25519 identity, wrapped once for each way you can unlock it (your *factors*). Unlocking a folder unwraps only that folder's key, like keeping one KeePass database per folder, so an agent working in one folder cannot obtain another folder's key without you. A separate `global` vault holds the few harness stores that belong to no folder.

### Capsules

precinto groups the files a harness writes into *units*: one Claude Code session with its subagents and tool results, a project's auto memory, a plan, one folder's lines of the prompt history, a folder's Codex home, one Markdown note. Sealing a unit writes a *capsule*: a single age file holding a manifest and the exact bytes of every file. Each capsule is encrypted to three keys: the folder's vault, your recovery key, and a one-time key that precinto uses to decrypt and check the capsule before it deletes any plaintext.

- Capsules live in precinto's own directory (`~/Library/Application Support/precinto` on macOS; `$XDG_DATA_HOME/precinto`, by default `~/.local/share/precinto`, on Linux), never inside the harness's files or your project. A sealed note leaves only a small text marker, `NAME.md.precinto`, where it was.
- A capsule is never overwritten. Every re-seal adds a new *generation*, and old generations go away only when you delete them yourself (`precinto prune`, `precinto forget`).
- Only capsules that precinto sealed itself, recorded in its capsule log, are ever restored, and only into the places their kind of unit allows.
- **Sealing never needs a key.** Anything precinto runs in the background (a sweep, the end of a session, a lock) can seal. Only restoring needs you.

### Two levels of lock

| Level | What happens |
|---|---|
| **Locked** (soft lock) | The folder's key is wiped from memory at once and its sessions are *paused*: precinto's hooks block new prompts (automated ones too), deny tools and permission dialogs, and pause compaction. A session started through precinto also gets a lock screen that hides the conversation and drops your keystrokes; Enter unlocks, Ctrl-D ends the session and seals it. Files that no process can still write are sealed. |
| **Ended and sealed** (hard lock) | Later, paused sessions are *ended*: precinto stops the harness gracefully, cleans the terminal and seals everything the session wrote. This is the step that turns a live session into ciphertext. |

On screen precinto only says *locked*, *paused* and *ended and sealed*. A turn that is running when the folder locks may finish (for up to 30 minutes after the lock), except after `precinto lock`, which gates everything at once unless you add `--let-finish`. Background sessions (Claude Code `--bg` and agent view) are never ended: they stay paused and `precinto status` flags them.

### What locks a folder

| When | What happens | Setting |
|---|---|---|
| 15 min without your input in the folder | the folder locks | `idle_soft` |
| 60 min without your input | paused sessions are ended and sealed | `idle_hard` |
| the screen locks | every folder locks at once; after 15 min of continuous screen lock, idle sessions are ended (busy ones after 30 min) | `lock_on_screen_lock`, `screen_lock_hard_after`, `busy_grace` |
| the computer sleeps | every folder is locked when it wakes | – |
| 8 h after an unlock | the folder locks however active you are; a notice comes 10 min before, and `precinto unlock --extend` asks for you again | `max_unlock` (at most 24 h) |
| `precinto lock` | every folder locks now (or one, with `--root DIR`); `--end` also ends the sessions | – |
| the precinto daemon starts | every vault starts locked | – |

"Input" means human input: keystrokes in a session started through precinto, or a prompt that precinto judges you typed. Loops, scheduled tasks and other automated prompts never keep a folder unlocked. Nothing the operating system does ever unlocks a folder.

### Hooks and the wrapper

precinto connects to a harness in two ways:

- **Hooks**, from a plugin installed with `precinto integrate`. Before each prompt, tool call, permission dialog and compaction, the harness asks precinto, which answers from the daemon's state in milliseconds. For sessions in protected folders every failure blocks (fail closed); elsewhere precinto stays out of the way. The hooks also record which files a session touched, and queue the session for sealing when it ends.
- **The wrapper**, `precinto run` (or the `claude` and `codex` shell functions that `precinto shell-init` installs). It asks for an unlock before the harness starts, restores the session you are resuming before the harness looks for it, draws the lock screen, ends the session cleanly when it is time, and seals it on exit. The shell integration also offers to unlock when you `cd` into a locked folder.

Hooks are a gate, not a security boundary: a harness can be started with hooks turned off. What protects your data is encryption at rest, keys that only the daemon holds, and sweeps that need no key. See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

### The daemon

`precinto agent` is a per-user background process that starts on demand. It is the only process that unwraps vault keys. It keeps them in locked memory, never writes them to disk, and hands out only per-capsule file keys, only to the same precinto executable, only for capsules in its log, and only while every folder of that capsule is unlocked.

## Status

- **Pre-release, specification v0.2** (it supersedes v0.1). The specification, the Go API contract and the test plan are written; the code is being implemented against them now. Expect missing commands and breaking changes.
- **macOS first.** Secure Enclave factor through `age-plugin-se`, screen-lock, idle and sleep triggers, and an optional background re-seal service (a LaunchAgent).
- **Linux partial.** It builds and runs with a passphrase factor (or an age plugin such as a YubiKey); screen lock and idle come from `loginctl`. There is no background service yet (`precinto service install` is macOS-only in v0.2), and machines without logind rely on idle timers and the 8-hour limit.
- **No Windows** (WSL behaves like Linux).
- **Not public yet.** There is no public repository, release or download. The Go module path `github.com/precinto/precinto` is a placeholder.
- **Decisions are defaults.** Every entry in [docs/DECISIONS.md](docs/DECISIONS.md) is a safe default waiting for the project owner's confirmation, and may change.

## Install from source

You need a checkout of the repository and:

- Go 1.21 or newer, `make` and `git`. `go.mod` pins `toolchain go1.26.11`, so with the default `GOTOOLCHAIN=auto` the go command downloads and uses Go 1.26.11 the first time you build (this needs network access to the Go module proxy).
- On macOS, for the default factor: `age-plugin-se` (`brew install age-plugin-se`; check its own macOS requirements). Optional: `pinentry-mac`, to unlock with a passphrase or a plugin factor from inside a harness. precinto runs a pinentry only from a location that only root can change (`/usr/bin`, MacPorts' `/opt/local/bin`, GPG Suite), never from Homebrew's prefix, which is writable by you and so by any program running as you; with Homebrew's `pinentry-mac` alone, unlock with a passphrase in a terminal.
- On Linux, optional: `pinentry-gnome3` (from your distribution's packages), and `age-plugin-yubikey` for a YubiKey factor.

```sh
cd precinto                    # your checkout
make build                     # builds bin/precinto (CGO disabled, -trimpath)
sudo install -m 0755 bin/precinto /usr/local/bin/precinto   # or any directory on your PATH
precinto version
```

`make` picks the first working `go` on your `PATH`; use `make GO=/path/to/go` to choose another. There are no prebuilt or signed release archives. `go install` and a Homebrew formula that builds from source are planned for when the repository is public (subject to change). A build from source is not signed or notarized, so on macOS `precinto doctor` reports it as an unhardened build; that is expected.

After you replace the binary, run `precinto agent --restart`: clients refuse to talk to a daemon that runs a different executable.

## Quick start

Run these commands yourself, in your own terminal, not inside an agent session: precinto refuses to show your recovery key or change your factors where an agent could read them.

```sh
precinto init                       # 1. vaults, unlock factor and recovery key (once)
precinto protect ~/work/acme        # 2. protect a folder
precinto shell-init zsh --install   # 3. shell integration (or bash, fish)
precinto integrate claude-code      # 4. install the hooks
precinto integrate codex

cd ~/work/acme                      # 5. work as usual
claude                              #    goes through precinto thanks to step 3
precinto run codex                  #    the explicit form, without the shell integration

precinto status                     # 6. what is locked, running or still unencrypted
precinto lock                       #    lock every folder now
precinto lock --end                 #    ...and also end and seal their sessions
precinto unlock                     #    unlock the folder you are in
precinto unlock --root ~/work/acme  #    or name it
```

1. **`precinto init`** creates your vaults and factors. On macOS the default factor is a Secure Enclave key made with `age-plugin-se`: it unlocks with Touch ID, or with your Mac password when no Touch ID is paired. On Linux it asks for a passphrase (at least 12 characters; it can suggest a 7-word one). Inside tmux, screen or SSH, where the macOS dialog cannot appear, it offers a passphrase as a second factor. Then it shows your recovery key once, on a cleared screen, and asks you to type back its last 4 characters (`--recovery-out FILE` writes it to a file instead). On macOS it also offers the background re-seal service. Test the recovery key with `precinto recover --verify`.
2. **`precinto protect DIR`** creates the folder's vault and registers it. Options: `--md ledger|all|off` (which Markdown files to seal: by default only those an agent wrote), `--on-enter prompt|notify|off`, `--harness LIST` (the harnesses precinto manages in the folder, by default `claude-code,codex`) and `--claude-settings` (see [What does precinto change in my projects?](#what-does-precinto-change-in-my-projects)). When Codex is installed, it also asks whether precinto should keep a separate, sealed Codex history for the folder. If you say no, the folder does not manage Codex: `precinto run codex` there asks the same question again and starts Codex only after a yes. `protect` offers to add `*.md.precinto` to the repository's local `.git/info/exclude`, which is never committed. Claude Code sessions you ran in that folder before protecting it show up in `precinto status`; seal them with `precinto seal --adopt`. Codex conversations from before stay in your own Codex home, which precinto does not seal.
3. **`precinto shell-init zsh|bash|fish`** prints shell functions for your harnesses and a hook that offers to unlock when you `cd` into a locked folder (Enter unlocks, any other key skips). The hook asks at most once per lock in each shell, and never in a subshell or inside a session that precinto started. `--install` asks first, then adds exactly one line to your shell's rc file, once: `eval "$(precinto shell-init zsh)"` to `~/.zshrc`, `eval "$(precinto shell-init bash)"` to `~/.bashrc`, or `precinto shell-init fish | source` to `~/.config/fish/config.fish`. You can add the same line yourself instead. On macOS, Terminal starts bash as a login shell, which reads `~/.bashrc` only if your `~/.bash_profile` sources it.
4. **`precinto integrate HARNESS`** installs precinto's plugin through the harness's own plugin commands (`--print` shows the steps instead). It refuses Claude Code older than 2.1.295. Codex runs plugin hooks only after you trust them: start Codex in the protected folder through precinto, run `/hooks` and trust precinto. precinto never trusts them for you. Codex keeps that trust in the Codex home it uses, which for a protected folder is the folder's own home, so you may have to trust precinto once in each protected folder: whether trust you gave in your own Codex home carries over has not been verified yet. Codex hooks are optional; without them Codex history is still sealed when Codex exits, but prompts are not paused while the folder is locked.
5. **`precinto run HARNESS [ARGS]`** (or the shell function) checks that the folder is unlocked, asking for you if needed, restores what the session needs, starts the harness, and seals the session when it exits. Sessions that never touch a protected folder are left alone.
6. **`status`, `lock`, `unlock`**: see [Everyday commands](#everyday-commands). `precinto unlock` with no flag unlocks the folder you are in. Outside every protected folder, in a terminal, it unlocks the only locked folder, or lists the locked folders and asks you to pick one by number (or all of them, after you type `unlock`). Without a terminal it can unlock only the folder of the current directory. After an unlock, precinto restores the folder's five most recent sessions, its notes and its prompt history in the background.

## Everyday commands

| Command | What it does |
|---|---|
| `precinto status [--json] [--check]` | folders and their state, sessions, files still unencrypted and why, hook health, and what needs attention (each item names the command that fixes it). `--check` exits 3 if a locked folder still has unencrypted files. |
| `precinto unlock [--root DIR \| --all \| --global] [--for DUR] [--factor NAME] [--extend]` | unlock with your presence: the folder you are in or the one you name; outside every folder, the only locked one or one you pick. `--all` asks once per folder after a typed confirmation; `--global` unlocks the `global` vault. Unlocking a folder unlocks it in every terminal. |
| `precinto lock [--root DIR \| --all] [--end] [--force] [--let-finish]` | lock now (every folder by default). `--end` also ends sessions; `--force` does not wait for a compaction in progress. |
| `precinto run [--harness H] [--no-pty] -- CMD [ARGS]` | run a harness through precinto |
| `precinto resume [ID \| --last \| --pick]` | restore a Claude Code session and resume it |
| `precinto restore [--root DIR] [--session ID] [--recent N] [--all] [--md] [--history]` | restore by hand; with no selection flag it restores what an unlock restores |
| `precinto restore --global [--harness H]` | after `precinto unlock --global`: restore what belongs to no folder (Claude Code's global stores, the units of experimental harnesses) |
| `precinto seal [--adopt] [--dry-run]` | seal now; never needs a key |
| `precinto ls [--root DIR] [--conflicts]` | list sealed units and notes |
| `precinto open FILE.md.precinto`, `precinto cat FILE.md.precinto` | restore a sealed note in place, or print it |
| `precinto resolve FILE [--keep capsule\|plaintext]` | settle a conflict between a sealed and a current version |
| `precinto prune`, `precinto forget FILE\|UNIT` | delete old generations, or the sealed copies of a unit, after a typed confirmation |
| `precinto doctor [--leaks] [HARNESS]` | read-only health checks; `--leaks` looks for copies outside precinto's reach |
| `precinto service install\|uninstall\|status` | macOS: background re-seal every 10 minutes (it never holds keys) |
| `precinto factor list\|add\|remove\|test\|repin`, `precinto recover --verify` | manage factors (`repin` accepts an upgraded age plugin, see [the FAQ](#what-if-unlock-fails-after-i-upgrade-an-age-plugin)); test the recovery key |

## Configuration

Settings live in `config.toml` in precinto's directory. The `[policy]` table holds the timers and switches described above, for example:

```toml
[policy]
idle_soft = "15m"              # lock after this much idle time
idle_hard = "60m"              # end paused sessions ("0" = never)
max_unlock = "8h"              # absolute limit of an unlock (at most 24h)
lock_on_screen_lock = true
screen_lock_hard_after = "15m"
on_enter = "prompt"            # offer to unlock when you cd into a locked folder
unlock_on_prompt = false       # let a prompt typed in a locked session raise the unlock dialog
min_free = "2GiB"              # free space precinto always leaves on the disk when it seals or restores
```

`min_free` takes a size such as `"512MiB"` or `"4GiB"` (binary units; at least `512MiB`). When sealing a session would leave less free space than that, precinto keeps the session as it is and reports "disk full" instead of filling the disk; the same floor applies to restores.

Edits that **weaken** protection (removing a folder or a harness, raising a timer, disabling a trigger, sealing fewer notes, relaxing the unlock prompts, lowering `min_free`) wait until your next unlock in a terminal shows you the change and you confirm it. Stricter edits apply at once. This keeps another program running as you, or an agent, from quietly turning protection down. After precinto's background agent restarts, the first unlock of a folder that your saved settings were not yet signed for may list your customized settings and ask you to confirm them once. `unlock_on_prompt` ships off and is planned to turn on once its end-to-end test passes on the pinned Claude Code version.

## Supported harnesses

| Harness | Support | How precinto connects |
|---|---|---|
| Claude Code | **Supported.** Verified on 2.1.329; 2.1.295 or later required | plugin hooks (`precinto integrate claude-code`) plus the wrapper |
| Codex CLI | **Supported**, 0.154.x (verified from source; other versions get a warning until re-verified) | the wrapper gives each protected folder that manages Codex (precinto asks once per folder) its own sealed Codex home; hooks are optional and need your trust in Codex, possibly once per folder |
| Factory Droid, Cursor, GitHub Copilot CLI | **Experimental**, unverified | hooks from the same plugin, enabled only with `precinto integrate <host> --experimental` |
| Gemini CLI, Kimi Code, Qwen Code, OpenCode | **Experimental** | wrapper only, with a data-driven inventory; sealing is manual (`precinto seal --dormant <id> --experimental`) into the `global` vault, and nothing is restored automatically: run `precinto restore --global --harness <id>` after `precinto unlock --global` |

What is sealed for each harness, how the hooks and the wrapper fit in, and the known caveats: [docs/HARNESSES.md](docs/HARNESSES.md).

## What precinto does not protect against

precinto shortens the time your sessions sit on disk as plaintext. It does not make a running session secret. In particular:

- **Malware that keeps running as you.** It can read whatever is unlocked or in use, and it can capture a folder's key the next time you unlock that folder. Separate vaults limit it to the folders you unlock.
- **Sessions in use.** The files of a running session and of an unlocked folder are plaintext on disk and in memory, readable by any program running as you.
- **Copies elsewhere.** What model providers keep, a harness's cloud sync, and copies made before you protected a folder or outside precinto's inventory: Spotlight's index, Time Machine snapshots and backups taken while unlocked, terminal scrollback and session restoration (iTerm2, Terminal.app, tmux-resurrect), the clipboard and Handoff, notification history, editor histories, git objects, the Claude desktop app's stores, MCP servers' own stores. `precinto doctor --leaks` reports what it can find.
- **Deleted plaintext on SSDs.** Old blocks can survive after a file is sealed and deleted. Turn on FileVault, or disk encryption on Linux.
- **Prompts typed while locked.** They are not sent to the model, but the harness may still write them into the transcript and its prompt history. The transcript copy is sealed with the session; the history line waits for the next history rotation, which needs every Claude Code process to be closed. Do not type secrets into a locked session.
- **Sessions started without the wrapper.** In IDE terminals, desktop apps or `command claude`, a lock only stops the model: the conversation stays visible and local commands such as `/export` or `/copy` still work. If such a session has no working hooks either (plugin disabled, `--bare`, `disableAllHooks`), an interactive Claude Code session is ended at lock and any other one is only reported.
- **Hooks that fail open.** Codex 0.154 lets an action proceed when a hook times out, and runs no hook you have not trusted. Claude Code 2.1.329 has a flag-gated path that can run a compaction despite precinto's block. Copilot CLI cannot block prompts. If the precinto binary crashes, its shim blocks only in sessions whose working directory or project directory is inside a protected folder.
- **Codex started without precinto** in a protected folder writes to your own Codex home, which precinto never seals; `status` and `doctor` count those conversations. If you trusted precinto's hooks in your own Codex home, they block such a session in a folder that manages Codex.
- **Metadata.** Folder paths, how many sessions there are, capsule sizes and times can be read without a key. Titles and content cannot.
- **A determined program running as you.** Agent detection and typed confirmations stop accidents and prompt-injected agents, not a program that fakes a terminal. precinto also trusts your `$HOME`, your shell's `PATH` and its own binary. On Linux, precinto can check its daemon only by user, lock-file holder and process name, so such a program could stand in for the daemon.

Also in v0.2: a large session is re-encrypted in full every time it changes; prompt-history lines are sealed only when no Claude Code process runs anywhere, and project memory only when none works in that folder's repository. The full list, with the reasons, is in [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

## FAQ

### Does precinto encrypt my files while I work?

No. While a folder is unlocked, or while a session can still write its files, they stay plaintext, exactly where the harness expects them. precinto never seals, moves or deletes a file that a process may still be writing: harnesses append to their transcripts, and a transcript moved away under a running session loses history. Files are sealed once the folder is locked and nothing writes them any more, and at the latest when the session ends.

### What happens when the agent compacts the conversation?

Compaction appends a summary to the same transcript, so the summary is sealed together with the session. While a folder is locked, precinto pauses compaction (a turn that was already running may finish). When precinto starts Claude Code in a protected folder, it also turns off the summaries Claude Code writes in the background while you are away (idle compaction, the away summary and precomputed compaction), because they would add new plaintext to a session that cannot be sealed yet. What really protects a compacted conversation is ending the session. Details: [docs/COMPACTION.md](docs/COMPACTION.md).

### How do I resume a sealed session?

Resume as you always do, through precinto: with the shell integration, `claude --resume ID`, `claude --continue` and the `claude --resume` picker just work, because precinto restores the transcript before Claude Code starts (Claude Code looks for it before any hook runs). After an unlock, the folder's five most recent sessions come back in the background, so Claude Code's own picker lists them; for older ones use `precinto resume --pick`, `precinto resume ID` or `precinto resume --last`. For Codex, the folder's whole Codex home is restored before Codex starts, so `codex resume` works through precinto too.

If you start a harness without precinto and the session is sealed, the harness will not find it; precinto then tells you how to resume it. Automatic restores skip Claude Code sessions that are close to Claude Code's own `cleanupPeriodDays` limit; when you resume one explicitly, precinto restores it with a recent date so that Claude Code does not delete it when it starts. The sealed copy is kept either way.

### Can I run several sessions at the same time?

Yes. All sessions in a folder share its lock: one unlock opens the folder in every terminal, and a lock pauses all of them. Each session is sealed when it ends.

- Opening a session that is already running in another terminal: precinto offers to open a copy with `--fork-session` instead, because two processes writing one transcript can lose messages.
- A session that works in two protected folders is paused while either of them is locked, and needs both unlocked to be restored.
- Claude Code's auto memory is shared by every session of a git repository, so precinto seals it only when no Claude Code process is working in that folder or its repository.
- Folders inside folders: `protect` asks before accepting one, and the deepest protected folder wins.
- Several folders: each has its own vault and asks for you separately; `precinto unlock --all` asks once per folder.

### What is the recovery key, and what if I lose it?

`precinto init` creates one recovery key per installation. Every capsule is also encrypted to it, and every folder's key is also wrapped to it, so with it you can get your data back after losing a factor: a forgotten passphrase, a lost YubiKey, or a Secure Enclave key that stayed on an old Mac. It also means that **whoever has the recovery key can decrypt all your capsules**: keep it offline.

- precinto shows it only to a person at a real terminal, never inside an agent session (it would end up in a transcript and be sent to the model provider): once, on a cleared screen, asking you to type back its last 4 characters. `--recovery-out FILE` writes it to a file instead, but not inside a protected folder, a harness's data directory or a synced folder.
- Check it with `precinto recover --verify`; until you do, `precinto status` says "recovery key: never tested".
- `precinto recover` unlocks every folder with it, so that you can enroll a replacement factor with `precinto factor add`; `precinto vault repair --recovery` uses it after a vault file was tampered with.
- If you lose the recovery key while your normal factor still works, nothing is lost, but v0.2 cannot issue a new one (`rekey` is planned for a later version).

### What if unlock fails after I upgrade an age plugin?

precinto pins every age plugin it runs (`age-plugin-se`, `age-plugin-yubikey` and others) by path and SHA-256, so that a binary someone replaced never handles your vault keys. After an upgrade the hash no longer matches: unlocking with that factor fails (exit 5), and `precinto doctor` reports `plugin-pin`. If you expected the upgrade, re-pin the plugin yourself, in your own terminal: `precinto factor repin se`, or the factor's name from `precinto factor list`. precinto remembers the path you enrolled the plugin with, such as Homebrew's `/opt/homebrew/bin/age-plugin-se`, so after `brew upgrade` repin follows it to the new version. It shows that path, the pinned binary and its SHA-256, the binary the path leads to now and its SHA-256, and the file's owner and modification time, asks you to type `repin`, and then updates the pin in every vault. Check that the new binary is the one you installed (for Homebrew, a `Cellar/age-plugin-se/<version>` path): a program running as you could re-point that link, and only you can tell. repin accepts only a regular file with the plugin's name, owned by you or by root, that nobody else can write, and it is refused inside an agent session. If you did not expect the change, do not re-pin: `precinto recover` can still unlock your folders with the recovery key.

### Can an agent unlock the folder or read sealed files?

Not on its own. precinto's plugin has no unlock command, and its skill tells the model never to run unlock, restore, cat, open or recover. For a command that comes from inside an agent session, precinto refuses to unlock any folder except the session's own, and for that one it can only raise an unlock dialog on your screen (Secure Enclave or pinentry), which you must approve. Restoring, opening or printing sealed content asks for you again even when the folder is unlocked. `init`, factor changes, the recovery key, `vault repair`, `prune`, `forget` and `unprotect` are refused. These checks stop accidents and prompt-injected agents, not malware running as you.

### What if precinto, its daemon or my computer crashes?

Every seal and restore is journaled and crash-safe: a crash or a power cut at any step loses no data, and the next sweep finishes or undoes whatever was in flight. Because sealing needs no key, leftovers are sealed even when nothing is unlocked. If the daemon is not running, the hooks keep sessions in protected folders locked instead of letting them through; `precinto unlock` starts the daemon again.

### What does precinto change in my projects?

Very little. Capsules live in precinto's own directory. A sealed note leaves a `NAME.md.precinto` marker (plain text, no ciphertext); losing a marker loses nothing, and the note still comes back at unlock. precinto adds `*.md.precinto` to a repository's local `.git/info/exclude` only if you accept when you protect the folder. It writes Claude Code settings into a project only if you ask with `protect --claude-settings`: it then merges its three settings (no idle compaction, no away summary, no precomputed compaction) into the folder's `.claude/settings.local.json`, Claude Code's local settings file that is not meant to be committed, and keeps every other key there; `unprotect` removes those keys again, unless you changed their values. Git-tracked files and instruction files (`README.md`, `CLAUDE.md`, `AGENTS.md` and others) are never sealed.

### How do I stop protecting a folder?

`precinto unprotect DIR`, in your own terminal. It restores everything of the folder first, so the folder must be unlocked, and it asks you to type a confirmation. Then it removes the folder from precinto's configuration, together with the Claude Code settings that `--claude-settings` wrote, but it deletes nothing: the folder's vault and every capsule stay in precinto's directory. If you protect the same folder again later, precinto reuses that vault, so the old capsules can be restored again. precinto never deletes capsules on its own: only `prune` and `forget` do, after listing what they will delete and asking for a typed confirmation.

### Why does `precinto doctor` warn about folders under Documents, Downloads or Desktop?

macOS privacy controls can stop the background service from reading those folders. Their sessions are then sealed by precinto processes started from your terminal, or reported as inaccessible; they are never treated as missing.

## Documentation

| Document | Contents |
|---|---|
| [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) | assets, adversaries, trust boundaries, scope and residual risks |
| [docs/HARNESSES.md](docs/HARNESSES.md) | what is sealed per harness, hooks, wrapper and caveats |
| [docs/COMPACTION.md](docs/COMPACTION.md) | compaction and background summaries, locked and unlocked |
| [docs/SPEC.md](docs/SPEC.md) | the normative specification (v0.2) |
| [docs/DECISIONS.md](docs/DECISIONS.md) | design decisions and their status |
| [docs/HOOKS-IO.md](docs/HOOKS-IO.md) | exact hook inputs and outputs per harness |
| [docs/API.md](docs/API.md), [docs/TESTPLAN.md](docs/TESTPLAN.md) | the Go contract and the test plan, for contributors |
| [SECURITY.md](SECURITY.md) | how to report a vulnerability |
| [CONTRIBUTING.md](CONTRIBUTING.md) | building, testing, code layout and the DCO sign-off |
| [TRADEMARKS.md](TRADEMARKS.md) | use of the name precinto and of third-party names |

## License

precinto is licensed under the [Apache License 2.0](LICENSE); see also [NOTICE](NOTICE) for third-party software. Contributions are accepted under the Developer Certificate of Origin ([CONTRIBUTING.md](CONTRIBUTING.md)). precinto is an independent project, not affiliated with or endorsed by any harness vendor ([TRADEMARKS.md](TRADEMARKS.md)).
