# precinto threat model

Status: pre-release, specification v0.2. This document expands [SPEC.md §2](SPEC.md#2-threat-model-summary--full-version-in-docsthreat_modelmd) and [§19](SPEC.md#19-known-limitations). The specification is normative: if the two disagree, the specification wins and this file gets fixed. Decisions cited as `Dn` are listed in [DECISIONS.md](DECISIONS.md); all of them are defaults waiting for the project owner's confirmation, so they are subject to change. To report a problem with any of this, see [SECURITY.md](../SECURITY.md).

## Contents

1. [Security goal](#1-security-goal)
2. [Assets](#2-assets)
3. [Adversaries](#3-adversaries)
4. [Trust boundaries](#4-trust-boundaries)
5. [Scope](#5-scope)
6. [Cryptography and integrity](#6-cryptography-and-integrity)
7. [Residual risks](#7-residual-risks)
8. [What you can do](#8-what-you-can-do)
9. [Invariants](#9-invariants)

## 1. Security goal

precinto bounds how long the data of coding-agent sessions sits on disk as plaintext, and requires a fresh act of user presence to bring it back.

- **Bounded plaintext dwell** (G1). Every file of a unit that precinto manages is sealed into a verified capsule once no process can still write it and its folder is locked. Its plaintext exists only while a process can write it, while its folder is unlocked, after a crash until the next sweep, or while `precinto status` lists it as unsealable with a reason.
- **Presence to unlock** (G2, G3). Unlocking needs the Secure Enclave (Touch ID or the Mac password, through `age-plugin-se`), another age plugin (for example a YubiKey touch), or a passphrase; an offline recovery key is the fallback. Starting a harness in a locked folder, or resuming a sealed session, asks for an unlock first. Sealing never needs a secret.
- **Never lose data** (G7). A capsule generation is never overwritten. A generation is deleted only by an explicit `prune` or `forget` that keeps every file still needed, and plaintext that disappears is never treated as a deletion.

The security boundary is **encryption at rest, plus key custody in the daemon, plus sweeps that need no key**. Hooks are not part of it (§4.3). A vault is only as strong as the weakest factor enrolled in it.

## 2. Assets

| Asset | Where it lives | How precinto protects it |
|---|---|---|
| Session transcripts and derived data: messages, tool input and output, compaction summaries, subagent transcripts, file checkpoints, todo lists, plans, auto memory, debug logs, uploads, MCP logs | the harness's data directories (for Claude Code: its config, temp and cache directories) | sealed per unit (session, project, plan) once the folder is locked and nothing writes the files |
| Prompt history | Claude Code's `history.jsonl` and paste cache | the lines of a protected folder move into that folder's history capsules at the next rotation |
| Codex history and databases of a protected folder | the folder's own Codex home, inside precinto's directory | sealed as snapshot generations |
| Markdown that agents write in a protected folder | the folder itself | sealed into precinto's store; a text marker without ciphertext stays behind |
| Vault identities: one X25519 key per protected folder, plus the `global` vault | `vaults/<id>/identity.<factor>.age`, wrapped once per factor | unwrapped only by the daemon, after fresh presence; kept in locked memory; never written to disk unencrypted; never sent to a client |
| Recovery key | with the user, offline | shown only to a person at a terminal; it can decrypt every capsule of the installation |
| Per-capsule file keys | in a client, during a restore | released one by one by the daemon under the rules of §4.2; kept in locked buffers and destroyed at the next lock |
| Integrity state: `vault.toml` (recipients and their MAC), the tripwire copies, the capsule log, the pinned policy, `config.toml`, `roots.list`, the journal and the receipts | precinto's directory | MACs keyed from the vault identity, a tripwire, a provenance log, policy pinning, a crash journal |
| Metadata | precinto's directory | **not protected**: folder paths, unit counts, capsule sizes and seal times, unit keys, ledgers of sessions not sealed yet (paths, never content), receipts of restored units, logs (ids, counts and reasons only, no paths). Session titles exist only inside capsules. |

precinto's directory is `~/Library/Application Support/precinto` on macOS and `${XDG_DATA_HOME:-~/.local/share}/precinto` on Linux; its directories are 0700 and its files 0600.

## 3. Adversaries

| Adversary or event | Protected? | How, or why not |
|---|---|---|
| Point-in-time reader of the home directory: an infostealer run once, another agent searching `~` | **Yes**, for sealed units | capsules are age ciphertext; identities exist only in the daemon's memory; unlocking needs presence |
| One-shot writer: a rogue package edits `vault.toml`, or plants capsules or markers | **Detected** | the recipient MAC and the tripwire make the sealer refuse (exit 5) until `precinto vault repair` [D53]; capsules missing from the log are quarantined [D8]; restore targets come from trusted context and authenticated unit ids |
| Persistent malware running as the user | **No** | it obtains a folder's key at that folder's next unlock; per-folder identities limit it to the folders the user unlocks [D1] |
| Backups, sync, copied disk images | **Yes**, for sealed units | they hold ciphertext; FileVault (or disk encryption on Linux) is needed against remnants of deleted plaintext |
| A person at the idle, unlocked machine | **Partly** | wrapped sessions: the lock screen hides output and drops input [D30]; unwrapped sessions: only the model is stopped, the terminal stays readable |
| Sandboxed or prompt-injected agent | **Mostly** | it cannot read other folders' plaintext without presence [D28]; it cannot make a restore write outside its unit |
| Live session files and process memory | **No** | their dwell is bounded by the idle and screen-lock policy |
| Provider-side retention | **No** | out of scope |

### 3.1 Point-in-time reader

A program that reads the disk once (an infostealer, a curious agent, a script) finds ciphertext for every sealed unit, the metadata of §2, and the plaintext of whatever is in use or unlocked at that moment. It finds no usable key: vault identities are stored only wrapped (by the Secure Enclave, by an age plugin, or with scrypt for a passphrase), the Secure Enclave stub on disk is useless on another machine, and precinto never stores the recovery key unless the user chose `--recovery-out FILE`.

### 3.2 One-shot writer

A program that runs once and modifies files (for example a malicious install script) can try three things:

- **Add its own recipient** to a folder's `vault.toml`, so that future capsules are also encrypted to it. The sealer compares the recipients with the copy the daemon wrote after the last successful verification (the tripwire) and refuses to seal when they differ or when that copy is missing; every unlock also checks that the identity matches the stored recipient and verifies a MAC keyed from the identity. Either failure raises `vault-tampered`, and sealing stops for that folder (its plaintext is kept, nothing is lost) until `precinto vault repair --root DIR`, which needs a terminal and is refused to agents, rebuilds the recipients from the unlocked identity. Capsules sealed while the file was altered are listed as exposed; re-encrypting them needs `rekey`, which is deferred [D49].
- **Plant capsules or markers.** Only capsules recorded in the capsule log, with a matching path and header hash, are restored or get a key released. Others are moved to quarantine and listed by `status` and `doctor`; markers naming unknown units are ignored.
- **Weaken the policy** in `config.toml` (remove a folder, raise a timer, disable a trigger). The daemon enforces the stricter of `config.toml` and the policy confirmed at the last terminal unlock, which it first pins when the first folder is protected and keeps with one MAC per vault [D68]; weakening edits stay pending until the user confirms them at an interactive unlock (§4.2).

### 3.3 Persistent malware running as the user

precinto cannot defend an account against code that keeps running as the same user. Such code can read plaintext while it is in use, watch the next unlock, replace files in user-writable places, or drive a pseudo-terminal. What precinto does is limit the damage: each folder has its own key, so the malware obtains only the folders the user unlocks while it runs [D1]; age plugin binaries are pinned by absolute path and SHA-256, and a changed binary is refused until the user re-pins it with `precinto factor repin NAME`, which follows the path the factor was enrolled with (a Homebrew link) to the binary it leads to now, shows both binaries and both hashes and needs the typed word `repin` at a terminal [D75, D80]; precinto refuses to run as root, disables core dumps and debugger attachment, and the daemon refuses injected loader variables (§6).

### 3.4 A person at the machine

When a folder locks, a session started through precinto's wrapper gets a lock screen: the screen and scrollback are cleared, the conversation is hidden, and keystrokes are dropped, not queued. An unwrapped session (an IDE terminal, a desktop app, `command claude`) gets only the model gate: the conversation stays on screen and local commands such as `/export` or `/copy` still work. A session that has no working hooks and no wrapper cannot be paused at all: an interactive Claude Code session is ended at lock, and any other is only reported (`ungated-session`) [D52, D57]. With the default policy, locking the screen locks every folder at once.

### 3.5 Sandboxed or prompt-injected agent

An agent runs as the user, so precinto treats requests that come from it (detected through environment markers or a harness process among its ancestors) with extra rules [D28, D59]:

- revealing content (`restore`, `cat`, `open`, `ls` titles) needs fresh presence even when the folder is unlocked: one dialog per folder (Secure Enclave or pinentry, after a notice in the session's terminal), and capsules of folders other than the session's are refused;
- unlocking the folder of the session it runs in needs a dialog on the user's screen (Secure Enclave or pinentry), and unlocking any other folder is refused without a dialog;
- `init`, factor changes (`factor repin` included), the recovery key, `vault repair`, `prune`, `forget` and `unprotect` are refused;
- a caller without a controlling terminal that is not one of the daemon's own workers counts as an agent for `restore --all`, `open`, `cat` and `ls` titles, and can unlock only the folder of its working directory or of its session; a client that claims to have no terminal while it has one is refused.

An agent also cannot steer a restore. The capsule log and the store carry only HMAC'd unit keys; the real unit id (session id, slug, relative path) exists only inside the ciphertext. At restore the client takes the unit id from the decrypted manifest, accepts it only if it hashes to the logged unit key, computes the allowed targets from the registered harness home and the folder, and rejects the whole capsule (exit 5, nothing written) if any entry falls outside them. Comparisons are component-wise, case-insensitive on macOS, and also checked against the inodes of protected directories such as `.git`, so tricks like `.GIT/hooks` do not pass.

These rules stop accidents and prompt-injected agents. They are not a boundary against a determined same-user process (§7).

## 4. Trust boundaries

### 4.1 Components

| Component | Holds | Trusted to |
|---|---|---|
| Daemon (`precinto agent`) | vault identities while unlocked (memguard enclaves), grants with an idle and an absolute deadline, the effective policy | check presence and recipients, release file keys only under the rules of §4.2, wipe every key at once at each lock, never seal or restore in its own process |
| Clients: the wrapper, the CLI, restore workers | per-capsule file keys during a restore, and the plaintext they place | restore only logged capsules into computed targets; destroy keys within 2 s of a lock |
| Sealer and sweeps | public recipients only | seal only units of locked folders that nothing writes, and verify each capsule before deleting any plaintext |
| Hooks and the POSIX shim | no secrets | answer gate events quickly, fail closed for managed sessions, never log payloads |
| The harness | its own sessions | precinto reads only a few fields of hook payloads (ids, paths, event names) and never stores prompt, tool or summary content |
| Factors | wraps of the vault identities | provide presence: the Secure Enclave through `age-plugin-se` with `any-biometry-or-passcode` (biometry-only and `none` are refused); an age plugin with a known presence policy (YubiKey touch, TPM PIN) or an explicit `--no-presence-ack`; a passphrase of at least 12 characters and at least 80 estimated bits, stretched with scrypt; the recovery key |

### 4.2 Crossing points

- **Unlock.** Always fresh presence, single-flight per vault (concurrent requests share one prompt), rate-limited (3 per minute, 30 s back-off after a cancel). A hook has no terminal, so it can only raise a graphical dialog (Secure Enclave or pinentry), never a terminal prompt, and only for a prompt of the same session that the daemon judged typed by a person within the last 60 s; inside tmux, screen or SSH the Secure Enclave dialog is not offered. Before a dialog the user learns who is asking: a terminal requester prints the reason, and for a hook-raised dialog the daemon first sends a notification to the session's terminal. Unlock durations are capped at `min(max_unlock, 24 h)`. No operating-system event ever unlocks.
- **Daemon socket.** A Unix socket in a 0700, owner-checked directory, bound under a 0177 umask. The daemon checks the peer's uid on every connection and, for key release, unlock, vault creation, factor changes, vault repair, policy confirmation and wrapper activity, that the peer runs the same executable (same device and inode). The client checks the server's executable the same way before it sends anything. On Linux a hardened precinto process cannot be inspected (it is not dumpable), so both checks are best effort there: the client checks instead that the daemon has the user's uid, holds the lock on `run/agent.lock` and has the expected process name, and the daemon checks that a hardened client has the user's uid and the expected process name (§7) [D65]. Secrets travel only in binary frames into locked buffers, never as JSON strings.
- **Key release** [D39]. For each requested capsule the daemon opens it under `capsules/` without following symlinks, looks up its path and header SHA-256 in the capsule log, requires every folder of the capsule to be unlocked, applies the agent-context rules for the purpose, and returns one file key. An identity never leaves the daemon.
- **Restore** [D12]. It runs in the client, in the harness's own environment. precinto checks free space, decrypts the whole unit into a 0700 staging directory on the same file system, and validates every entry before placing anything. It then places files through directory descriptors with `O_NOFOLLOW`, checking the owner and permissions of every existing parent; files are created 0600 (0700 if owner-executable) and directories 0700. Existing files are replaced only as the placement table allows; anything else is kept side by side and reported as a conflict, and nothing is ever merged into a live unit.
- **Hook gate.** The harness runs the shim, the shim runs `precinto hook`, and the hook asks the daemon. If the daemon is unreachable within 150 ms, the payload cannot be decoded, the hook's own deadline passes or it panics, a managed session is blocked. If the binary is missing or crashes, the shim blocks gate events whose working directory or `CLAUDE_PROJECT_DIR` is inside a folder listed in `roots.list`.
- **Configuration** [D48, D55, D68]. Edits that weaken protection stay pending until an interactive unlock shows the difference and the user confirms it; stricter edits apply at once. The confirmed policy is first pinned when the first folder is protected, and is kept with a MAC per vault; from then on, if that copy is missing or altered, the daemon raises `policy-tampered` and also applies the built-in defaults, whichever is stricter, until the next confirmation. A terminal unlock re-pins it without asking only when `config.toml` weakens nothing.

### 4.3 What is not a boundary

- **Hooks.** A harness can run without them (`--bare`, `disableAllHooks`, a disabled plugin, Codex hooks the user has not trusted), some engines fail open (Codex on timeouts, Copilot CLI for prompts), and some harness paths bypass them (a flag-gated reactive compaction path in Claude Code 2.1.329, background summaries that no hook covers). Hooks turn a lock into a pause; encryption is what protects the data.
- **The wrapper's lock screen.** It hides the conversation from a person; any process can still read the files of a running session.
- **Agent detection and typed confirmations.** Reparenting (`setsid`, double fork) and `env -i` defeat ancestry checks, and a process that allocates its own pseudo-terminal (`script`, `expect`) can type confirmations [D59].
- **File permissions.** Harness files are already 0600 or 0644; every process of the user passes those checks.

### 4.4 What precinto trusts

- The kernel, the boundary between user accounts, and the hardware: the Secure Enclave, and FileVault for remnants on disk.
- `filippo.io/age` v1.3.x, and the age plugins pinned by path and hash.
- The precinto binary itself, `$HOME`, and the `PATH` of the user's shell. Pinning reduces, but does not remove, tampering by the same user. Claude Code's settings `env`, which an agent can write in `<folder>/.claude/settings.local.json`, reaches every hook process: precinto ignores any `PRECINTO_*` variable there, but an injected `HOME` or `PATH` changes where the shim and the hook look for precinto's directory, so `doctor` reports such keys (`claude-settings-env`) [D56].
- The harness binaries: they run as the user and hold the plaintext of their own running sessions anyway.

## 5. Scope

### In scope

- Programs that read the home directory at one point in time, and copies of it: backups, sync, disk images.
- One-shot tampering with precinto's files: recipients, capsules, markers, configuration.
- A person at an unattended machine whose folders have locked.
- Agents, sandboxed or prompt-injected, that try to read other folders, reveal sealed content without the user, or make a restore write somewhere else.
- Crashes and power loss: no step may lose data (I9), and a lock always completes even when sealing fails (I15).

### Out of scope

- Malware that keeps running as the user, and anything with administrator (root) or kernel access.
- A running session's files and the process memory of the harness.
- Copies kept by model providers or by a harness's cloud sync.
- Copies made before a folder was protected, or outside precinto's inventory (§7, "Residue").
- Attacks on age, on the Secure Enclave or on the operating system itself.

### Non-goals for v0.2

- Protecting a **live** session (its files and process memory) from malware running as the same user.
- Copies kept by model providers, harness cloud sync, terminal residue already written, Spotlight and Time Machine copies made before enrollment, git objects (`doctor` reports them; precinto does not fix them).
- Windows (WSL works as Linux), transparent FUSE or FSKit mounts, post-quantum capsules [D2].

## 6. Cryptography and integrity

- **Library and family.** `filippo.io/age` v1.3.x only, with no custom primitives. Every vault, recovery and ephemeral identity is X25519 [D2]. Post-quantum capsules are not in v0.2: the factor wraps (Secure Enclave, YubiKey) are classical, so post-quantum capsules would not stop a quantum attacker anyway; they are on the roadmap once factor wraps can be post-quantum.
- **Capsule format.** `age("PRECINTO-CAPSULE-1\n" || zstd(tar))`, where the tar holds `MANIFEST.json` and then the files in manifest order, regular files only. The header carries exactly three X25519 stanzas: the vault, the recovery key and a one-time verification key. After writing, the sealer parses the header and refuses any other count or type (exit 5, plaintext kept) [D5].
- **Order of sealing** [D13, D58]. precinto records each file's identity (device, inode, size, times) and hashes it; streams a second pass that re-opens each file, requires the same identity and re-hashes it; forces the data to disk; decrypts the temporary capsule with the in-memory one-time key and compares the manifest and every hash; checks the header; renames the capsule into place without replacing anything; appends it to the capsule log; and only then deletes each plaintext file whose identity is unchanged and that nothing writes. Files that grew within the next second are sealed again as a successor ("rescue") generation.
- **Authenticated recipients** [D5]. Each `vault.toml` stores the recipients and an HMAC over them keyed from the vault identity; the daemon keeps a tripwire copy after each successful verification; every manifest carries a fingerprint of the recipient set, and after each unlock the daemon audits the capsules sealed since the last audit and reports any with a foreign fingerprint as exposed.
- **Names without content** [D45]. Unit keys are an HMAC of the unit's parts under a per-installation salt, truncated to 128 bits; capsule paths and the capsule log contain only unit keys and generation numbers from fsynced counters.
- **Decoding limits.** Manifests up to 16 MiB, at most 1,048,576 entries, a zstd window up to 64 MiB and decoder memory up to 1 GiB, and a total no larger than the restore budget and the free space; no symlinks, devices, FIFOs, hard links, PAX path overrides or sparse entries. Restored files get owner permission bits only; setuid, setgid and sticky bits are dropped.
- **Process hardening.** Every command that may hold secrets or plaintext refuses to run as root, sets `RLIMIT_CORE=0` and denies debugger attachment (`PT_DENY_ATTACH` on macOS, `PR_SET_DUMPABLE=0` on Linux). The daemon refuses to start with `DYLD_*` or `LD_*` variables (or re-executes itself with a clean environment), and is autostarted with an allowlisted environment. macOS release builds are meant to be Developer-ID signed, hardened and notarized (a pending decision, D35); `doctor` flags unhardened builds.
- **Crash safety** [D58]. Every operation is journaled, written to a temporary, renamed without replacing and fsynced; recovery needs no key and runs before every sweep, seal and restore. Quarantine runs only after recovery, so precinto's own crash leftovers are never reported as forgeries.

## 7. Residual risks

| Risk | Why it remains | What reduces it |
|---|---|---|
| **Live data** | Plaintext of running sessions and of unlocked folders is readable by any process of the user; persistent malware captures a folder's key at its next unlock. | short `idle_soft` and `idle_hard`; `precinto lock --end` when leaving |
| **Deleted plaintext on SSDs** | Blocks of deleted files can survive on the disk. | FileVault, or an encrypted home on Linux |
| **Blocked prompts reach disk** | A prompt blocked while locked may still be written to the transcript and to `history.jsonl`. The transcript copy is sealed with the session; the history line waits for the next rotation, which needs no Claude Code process running anywhere. `status` counts pending lines. | never type secrets into a locked session |
| **Soft lock without the wrapper is a model gate** | IDE terminals, desktop apps and `command claude` keep the conversation visible; local commands (`/export`, `/copy`, scrollback) work. Unwrapped sessions without working hooks cannot be paused: interactive Claude Code sessions are ended at lock, every other one is only reported [D52, D57]. | use the shell integration or `precinto run` |
| **Lock-screen replay is bounded** | The wrapper keeps the last 8 MiB of terminal output in its memory to redraw it after unlock; older output is not shown again once the lock cleared screen and scrollback (it is still in the session) [D60]. | – |
| **Hooks fail open where the host does** | Codex 0.154 has no fail-closed option: a timed-out hook lets the action proceed (a crashed binary is still caught by the shim inside protected folders), and untrusted Codex hooks do not run at all. Codex keeps hook trust in the Codex home in use; in Codex 0.154 its keys and hashes do not depend on the path (a hash of each hook's declaration, HOOKS-IO §3.1), so trust given in the user's own Codex home carries over to a folder's home created, or `sync-config`'d, afterwards; otherwise it is given once in that folder. Claude Code 2.1.329 has a flag-gated path that runs reactive compaction despite a PreCompact block. Copilot CLI cannot block prompts; Cursor, Copilot CLI and Droid support is experimental. | keep hooks trusted and healthy in every protected folder (`precinto status` shows hook health); rely on ending sessions |
| **A crashing binary fails open outside listed folders** | When the binary dies, the shim can only compare `$PWD` and `$CLAUDE_PROJECT_DIR` with `roots.list`; a session managed only through a tool path or an added directory outside those folders is not blocked by that run [D56]. | start sessions inside the protected folder |
| **Delayed history and memory** | History rotation waits until no Claude Code process runs anywhere; project memory waits until none works in the folder's repository. | `precinto lock --end --all` ends sessions so that rotation can run |
| **Heap copies during unwrap** | age parses identities on the Go heap during each unwrap; hardening mitigates this but does not eliminate it. | – |
| **Plugin pinning hashes, then runs by path** | There is no `fexecve`: between the hash check and the exec of an age plugin, a process running as the user could swap the binary. This stays within the same-user model (§3.3). | install age plugins where only an administrator can write; re-pin (`precinto factor repin NAME`) only after an upgrade you expected |
| **Re-pinning trusts the human** | `factor repin` follows the factor's enrolled path, such as Homebrew's `/opt/homebrew/bin/age-plugin-se`, to whatever binary of the same name it leads to now. A process running as the user that re-points that link (Homebrew's links and Cellar are the user's) makes its binary look like an upgrade; repin shows the enrolled path, the old and the new binary and both hashes, and only the user can tell them apart (§3.3) [D80]. | check that the new binary is the version you installed (for Homebrew, a `Cellar/age-plugin-se/<version>` path) before typing `repin` |
| **Rescue grace** | If the sealer crashes during the short rescue grace after a seal, bytes that a still-running writer appended to a file already deleted can be lost; recovery seals whatever remains on disk. | – |
| **Process identity on Linux is best effort, both ways** | Hardened precinto processes are not dumpable, so on Linux the client checks the daemon's uid, the holder of `run/agent.lock` and the process name instead of its executable, and the daemon checks a hardened client's uid and process name instead of its executable. A process running as the user that kills the daemon and binds the socket in its place, or that runs under precinto's process name, is not stopped (persistent same-user malware, §3.3); macOS keeps the full executable check both ways [D65]. | – |
| **A session managed later has no lock screen** | A launch outside every protected folder runs unmanaged. If that session later touches a protected folder, the hooks gate it from then on, but it has no lock screen. | start sessions inside the protected folder |
| **Trust in `$HOME`, `PATH` and the binary** | Pinned binary links and plugin hashes reduce, but do not remove, same-user tampering; Claude Code settings `env` can inject `HOME` or `PATH` into hooks [D56]. | install the binary where only an administrator can write; act on `claude-settings-env` findings |
| **Agent detection and typed confirmations** | Reparenting and `env -i` defeat ancestry checks; a process with its own pseudo-terminal can type confirmations [D59]. | – (they stop accidents, not malware) |
| **Metadata** | Folder paths, unit counts, capsule sizes and times, and the ledgers of unsealed sessions are plaintext. Session titles are only inside capsules. | – |
| **Residue outside the inventory** | Terminal state (iTerm2 restoration, Terminal.app, tmux-resurrect), the Spotlight index, Time Machine snapshots and backups made while unlocked, clipboard and Handoff, git objects, Claude desktop and Cowork stores, MCP server stores, Notification Center, editor histories. | `precinto doctor --leaks`; exclude protected folders from Spotlight and cloud sync (`doctor` warns) |
| **Codex specifics** | Codex outside protected folders, and in protected folders that do not manage Codex (the user declined it), is unmanaged [D72]; a shared `codex app-server` is not supported in protected folders; databases are sealed as opaque groups (free pages inside them are sealed too, not scrubbed). Codex started without the wrapper in a protected folder writes to the user's own Codex home, which precinto never seals; it is gated only if precinto's hooks are trusted there, and `doctor` and `status` count those conversations (`codex-wrong-home`) [D31]. | always start Codex with `precinto run codex` or the shell function |
| **Large sessions** | A changed session is re-encrypted in full; there are no incremental Claude Code capsules in v0.2. | – |
| **Prompt-origin heuristic** | Whether a prompt was typed by a human is inferred [D37]: it can misjudge a prompt typed while the system idle time is large (remote input) or an automated prompt right after a keystroke. Where the idle time cannot be read (headless Linux), unwrapped prompts never extend an unlock [D54]. | – |
| **Vault repair trusts the unlocked identity** | `vault repair` checks that the unlocked identity opens older capsules of the folder, but a writer who replaced the identity files of a folder with no older capsules cannot be told apart; capsules sealed while `vault.toml` was changed are reported as exposed, not re-encrypted (`rekey` is deferred) [D53]. | `precinto vault repair --recovery` when in doubt |
| **macOS privacy controls (TCC)** | A LaunchAgent sweep may not read folders under `~/Documents`, `~/Downloads` or `~/Desktop`; those units are sealed by precinto processes started from a terminal, or reported as inaccessible. `precinto service install` checks access with the terminal's permissions, so it can only warn. | `precinto status` shows what the background service could not read; grant the service access, or keep projects elsewhere |
| **Bash-created Markdown** | Notes written by shell commands rather than file tools are sealed only with `md = "all"`. | `precinto protect DIR --md all` |
| **Passphrase factor** | A passphrase is offline-attackable once someone copies the wrapped identity; `doctor` warns about it. | prefer the Secure Enclave or a hardware key |
| **Background sessions** | Claude Code background and supervised sessions (`--bg`, agent view) are never ended, because their supervisor would restart them; they stay paused and flagged [D25]. | end them from Claude Code itself |

## 8. What you can do

- Turn on FileVault on macOS, or disk encryption on Linux.
- Start harnesses through precinto (`precinto shell-init`, `precinto run`) rather than unwrapped, and keep the hooks installed and trusted (for Codex, check the trust in each protected folder); `precinto status` shows their health.
- Use `precinto lock --end` when you leave, and keep `idle_hard` and `screen_lock_hard_after` short: ending sessions is what turns them into ciphertext.
- Never type secrets into a locked session, and never paste them into a prompt.
- Prefer the Secure Enclave or a hardware key over a passphrase.
- Verify the recovery key with `precinto recover --verify`, and keep it offline.
- Install the precinto binary in a directory that only an administrator can write.
- Re-pin an age plugin (`precinto factor repin NAME`) only after an upgrade you made yourself, and only when the new binary it shows is the one you installed.
- Keep protected folders out of Spotlight and cloud sync, and run `precinto doctor --leaks` now and then.
- Run `precinto status --check` in scripts: it exits 3 when a locked folder still has unencrypted files.

## 9. Invariants

The tests enforce these properties ([SPEC.md §18](SPEC.md#18-invariants-tests-must-enforce-see-testplanmd-for-the-mapping); mapping in [TESTPLAN.md §7](TESTPLAN.md#7-invariants--tests)):

| # | Property |
|---|---|
| I1 | A file of a live unit is never sealed, moved or deleted. |
| I2 | Restore writes exact bytes at the computed path, as regular files, with the original mtime and owner-only permissions, unless the placement table applies. |
| I3 | Plaintext is deleted only after its generation is committed and verified and the file is unchanged since it was hashed. |
| I4 | Capsules live only in precinto's store; the working tree holds only text markers. |
| I5 | Gate hooks block on every error path for managed sessions; unmanaged paths fail open. |
| I6 | A lock never waits for a dialog, a seal or a restore; an unlock always needs fresh presence; no system event unlocks. |
| I7 | Identities never touch disk unencrypted and never leave the daemon; no content, prompt, tool data or environment value appears in logs, ledgers, journals, receipts, the queue or errors. |
| I8 | Restore targets come from trusted context: no traversal, no symlinks below a base, files 0600 (0700 if executable), directories 0700. |
| I9 | Every operation is idempotent and crash-safe; a crash or power loss at any step loses no data. |
| I10 | Unknown files that carry a session id are sealed with that session, never ignored. |
| I11 | A generation is never overwritten, unrelated plaintext never replaces a capsule, and a generation is deleted only by `prune` or `forget`, keeping every file still needed. |
| I12 | Plaintext that disappears never deletes, replaces or shrinks a capsule. |
| I13 | Restore replaces an existing file only as the placement table allows, and never merges into a live unit. |
| I14 | Only capsules recorded in the capsule log are restored or have keys released. |
| I15 | A lock always completes: keys are wiped and gates engaged even when sealing fails, and unsealed units are reported. |
| I16 | The sealer refuses when the recipient set is not the verified one, or the header does not carry exactly the expected stanzas. |
