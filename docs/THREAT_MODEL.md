# Precinto threat model

Status: pre-release, specification v0.2. This document expands [SPEC.md §2](SPEC.md#2-threat-model-summary--full-version-in-docsthreat_modelmd) and [§19](SPEC.md#19-known-limitations). The specification is normative: if the two disagree, the specification wins and this file gets fixed. Decisions cited as `Dn` are listed in [DECISIONS.md](DECISIONS.md); most of them are defaults waiting for the project owner's confirmation, so they are subject to change (those marked `owner`, such as D155, are confirmed). To report a problem with any of this, see [SECURITY.md](../SECURITY.md).

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

Precinto bounds how long the data of coding-agent sessions sits on disk as plaintext, and requires a fresh act of user presence to bring it back.

- **Bounded plaintext dwell** (G1). Every file of a unit that Precinto manages is sealed into a verified capsule once no process can still write it and its folder is locked. Its plaintext exists only while a process can write it, while its folder is unlocked, after a crash until the next sweep, or while `precinto status` lists it as unsealable with a reason.
- **Presence to unlock** (G2, G3). Unlocking needs the Secure Enclave (Touch ID or the Mac password, through `age-plugin-se`), another age plugin (for example a YubiKey touch), or a passphrase; an offline recovery key is the fallback. Starting a harness in a locked folder, or resuming a sealed session, asks for an unlock first. Sealing never needs a secret.
- **Never lose data** (G7). A capsule generation is never overwritten. A generation is deleted only by an explicit `prune` or `forget` that keeps every file still needed, and plaintext that disappears is never treated as a deletion.

The security boundary is **encryption at rest, plus key custody in the daemon, plus sweeps that need no key**. Hooks are not part of it (§4.3). A vault is only as strong as the weakest factor enrolled in it.

## 2. Assets

| Asset | Where it lives | How Precinto protects it |
|---|---|---|
| Session transcripts and derived data: messages, tool input and output, compaction summaries, subagent transcripts, file checkpoints, todo lists, plans, auto memory, debug logs, uploads, MCP logs | the harness's data directories (for Claude Code: its config, temp and cache directories) | sealed per unit (session, project, plan) once the folder is locked and nothing writes the files |
| Prompt history | Claude Code's `history.jsonl` and paste cache | the lines of a protected folder move into that folder's history capsules at the next rotation |
| Codex history and databases of a protected folder | the folder's own Codex home, inside Precinto's directory | sealed as snapshot generations |
| Markdown that agents write in a protected folder | the folder itself | sealed into Precinto's store; a text marker without ciphertext stays behind |
| Vault identities: one X25519 key per protected folder, plus the `global` vault | `vaults/<id>/identity.<factor>.age`, wrapped once per factor | unwrapped only by the daemon, after fresh presence; kept in locked memory; never written to disk unencrypted; never sent to a client |
| Recovery key | with the user, offline | shown only to a person at a terminal; it can decrypt every capsule of the installation |
| Per-capsule file keys | in a client, during a restore | released one by one by the daemon under the rules of §4.2; kept in locked buffers and destroyed at the next lock |
| Integrity state: `vault.toml` (recipients and their MAC), the tripwire copies, the capsule log, the pinned policy, `config.toml`, `roots.list`, the journal and the receipts | Precinto's directory | MACs keyed from the vault identity, a tripwire, a provenance log, policy pinning, a crash journal |
| Metadata | Precinto's directory | **not protected**: folder paths, unit counts, capsule sizes and seal times, unit keys, ledgers of sessions not sealed yet (paths, never content), receipts of restored units, logs (ids, counts and reasons only, no paths). Session titles exist only inside capsules. |

Precinto's directory is `~/Library/Application Support/precinto` on macOS and `${XDG_DATA_HOME:-~/.local/share}/precinto` on Linux; its directories are 0700 and its files 0600.

On Windows, Precinto runs as its Linux build inside a WSL 2 distribution [D155], and every asset above lives inside that distribution: Precinto's directory, the protected folders and the harness homes must be on the distribution's own Linux file system, never on a Windows drive mounted into it (`/mnt/c` and the like), which Precinto refuses [D156]. That file system is itself a virtual disk file (`.vhdx`) on a Windows drive, and the distribution's swap is another one (by default `swap.vhdx` in the Windows temporary folder): Windows programs, backups and copies of that drive see both as ordinary files (§3.6, §7).

## 3. Adversaries

| Adversary or event | Protected? | How, or why not |
|---|---|---|
| Point-in-time reader of the home directory: an infostealer run once, another agent searching `~` | **Yes**, for sealed units | capsules are age ciphertext; identities exist only in the daemon's memory; unlocking needs presence |
| One-shot writer: a rogue package edits `vault.toml`, or plants capsules or markers | **Detected** | the recipient MAC and the tripwire make the sealer refuse (exit 5) until `precinto vault repair` [D53]; capsules missing from the log are quarantined [D8]; restore targets come from trusted context and authenticated unit ids |
| Persistent malware running as the user | **No** | it obtains a folder's key at that folder's next unlock; per-folder identities limit it to the folders the user unlocks [D1] |
| Windows programs of the same Windows account, under WSL 2 | **No** for unlocked folders; **yes** for sealed units of locked folders | any of them can become root in the distribution and read the keys of the folders unlocked at that moment from the daemon's memory; Precinto refuses Windows drives and Windows programs where it finds them, because it cannot see them (§3.6) [D155, D156] |
| Backups, sync, copied disk images | **Yes**, for sealed units | they hold ciphertext; FileVault (or disk encryption on Linux; under WSL 2, BitLocker or Device Encryption of the Windows drive that holds the distribution's virtual disk) is needed against remnants of deleted plaintext |
| A person at the idle, unlocked machine | **Partly** | wrapped sessions: the lock screen hides output and drops input [D30]; unwrapped sessions: only the model is stopped, the terminal stays readable |
| Sandboxed or prompt-injected agent | **Mostly** | it cannot read other folders' plaintext without presence [D28]; it cannot make a restore write outside its unit; under WSL 2 an agent that can run programs can become root and read the keys of unlocked folders: at once while Windows interoperability is on, and otherwise at the next sign-in or WSL start, through a file it leaves on a mounted Windows drive for Windows or WSL to run (§3.6) |
| Live session files and process memory | **No** | their dwell is bounded by the idle and screen-lock policy |
| Provider-side retention | **No** | out of scope |

### 3.1 Point-in-time reader

A program that reads the disk once (an infostealer, a curious agent, a script) finds ciphertext for every sealed unit, the metadata of §2, and the plaintext of whatever is in use or unlocked at that moment. It finds no usable key: vault identities are stored only wrapped (by the Secure Enclave, by an age plugin, or with scrypt for a passphrase), the Secure Enclave stub on disk is useless on another machine, and Precinto never stores the recovery key unless the user chose `--recovery-out FILE`.

### 3.2 One-shot writer

A program that runs once and modifies files (for example a malicious install script) can try three things:

- **Add its own recipient** to a folder's `vault.toml`, so that future capsules are also encrypted to it. The sealer compares the recipients with the copy the daemon wrote after the last successful verification (the tripwire) and refuses to seal when they differ or when that copy is missing; every unlock also checks that the identity matches the stored recipient and verifies a MAC keyed from the identity. Either failure raises `vault-tampered`, and sealing stops for that folder (its plaintext is kept, nothing is lost) until `precinto vault repair --root DIR`, which needs a terminal and is refused to agents, rebuilds the recipients from the unlocked identity. Capsules sealed while the file was altered are listed as exposed; re-encrypting them needs `rekey`, which is deferred [D49].
- **Plant capsules or markers.** Only capsules recorded in the capsule log, with a matching path and header hash, are restored or get a key released. Others are moved to quarantine and listed by `status` and `doctor`; markers naming unknown units are ignored.
- **Weaken the policy** in `config.toml` (remove a folder, raise a timer, disable a trigger). The daemon enforces the stricter of `config.toml` and the policy confirmed at the last terminal unlock, which it first pins when the first folder is protected and keeps with one MAC per vault [D68]; weakening edits stay pending until the user confirms them at an interactive unlock (§4.2). Until then every process that seals, `status --check` and `roots.list` follow the confirmed policy too, so a folder removed from `config.toml` stays sealed and gated, and a `config.toml` that does not load stops no seal [D142, D143]. A forged pin must carry the MAC of a folder it names (a `global` MAC alone is checked only by `unlock --global`), and while the daemon finds the pin tampered every folder a vault records stays protected and shows in the review; a pin that names no folder is surfaced by `status` and `doctor` while folders whose vault is kept are protected by nothing [D145]. A folder the user stopped protecting (its vault kept, D74) is sealed by nothing, a broken `config.toml` included [D142].

### 3.3 Persistent malware running as the user

Precinto cannot defend an account against code that keeps running as the same user. Such code can read plaintext while it is in use, watch the next unlock, replace files in user-writable places, or drive a pseudo-terminal. What Precinto does is limit the damage: each folder has its own key, so the malware obtains only the folders the user unlocks while it runs [D1]; age plugin binaries are pinned by absolute path and SHA-256, and a changed binary is refused until the user re-pins it with `precinto factor repin NAME`, which follows the path the factor was enrolled with (a Homebrew link) to the binary it leads to now, shows both binaries and both hashes and needs the typed word `repin` at a terminal [D75, D80]; Precinto refuses to run as root, disables core dumps and debugger attachment, and the daemon refuses injected loader variables (§6).

### 3.4 A person at the machine

When a folder locks, a session started through Precinto's wrapper gets a lock screen: the screen and scrollback are cleared, the conversation is hidden, and keystrokes are dropped, not queued. An unwrapped session (an IDE terminal, a desktop app, `command claude`) gets only the model gate: the conversation stays on screen and local commands such as `/export` or `/copy` still work. A session that has no working hooks and no wrapper cannot be paused at all: an interactive Claude Code session is ended at lock, and any other is only reported (`ungated-session`) [D52, D57]. With the default policy, locking the screen locks every folder at once; under WSL 2 it does not, because Precinto cannot see the Windows lock screen (§3.6).

### 3.5 Sandboxed or prompt-injected agent

An agent runs as the user, so Precinto treats requests that come from it (detected through environment markers or a harness process among its ancestors) with extra rules [D28, D59]:

- revealing content (`restore`, `cat`, `open`, `ls` titles) needs fresh presence even when the folder is unlocked: one dialog per folder (Secure Enclave or pinentry, after a notice in the session's terminal), and capsules of folders other than the session's are refused;
- unlocking the folder of the session it runs in needs a dialog on the user's screen (Secure Enclave or pinentry), and unlocking any other folder is refused without a dialog;
- `init`, factor changes (`factor repin` included), the recovery key, `vault repair`, `prune`, `forget` and `unprotect` are refused;
- a caller without a controlling terminal that is not one of the daemon's own workers counts as an agent for `restore --all`, `open`, `cat` and `ls` titles, and can unlock only the folder of its working directory or of its session; a client that claims to have no terminal while it has one is refused.

An agent also cannot steer a restore. The capsule log and the store carry only HMAC'd unit keys; the real unit id (session id, slug, relative path) exists only inside the ciphertext. At restore the client takes the unit id from the decrypted manifest, accepts it only if it hashes to the logged unit key, computes the allowed targets from the registered harness home and the folder, and rejects the whole capsule (exit 5, nothing written) if any entry falls outside them. Comparisons are component-wise, case-insensitive on macOS, and also checked against the inodes of protected directories such as `.git`, so tricks like `.GIT/hooks` do not pass.

Under WSL 2 with Windows interoperability on, which is WSL's default, an agent that can run programs can also run `wsl.exe` to become root in the distribution and read the keys of every folder unlocked at that moment; with interoperability off it can still get there later, through a file it leaves on a mounted Windows drive for Windows or WSL to run (§3.6).

These rules stop accidents and prompt-injected agents. They are not a boundary against a determined same-user process (§7).

### 3.6 Windows programs of the same account (WSL 2)

On Windows, Precinto runs inside a WSL 2 distribution [D155], and there the boundary is the Windows account, not the Linux user:

- **Any Windows process of the account can become root in the distribution.** `wsl -u root` opens a root shell in it without a password (Microsoft documents it as the way to reset a forgotten Linux password), and while Windows interoperability is on, a program inside the distribution, an agent included, can do the same by running `wsl.exe`. Process hardening does not stop root: it can read the keys of the folders unlocked at that moment from the daemon's memory, and with a folder's key every capsule of that folder, besides the plaintext of unlocked folders and running sessions. Locked folders stay protected: their keys exist only wrapped, and a program that keeps running obtains a folder's key only when that folder is next unlocked, as with persistent malware (§3.3). Turning interoperability off (`enabled=false` under `[interop]` in `/etc/wsl.conf`, then `wsl --shutdown`) closes the direct path from inside the distribution, at the cost of starting Windows programs from it (`code .`, `explorer.exe`, `clip.exe`, Git Credential Manager from Git for Windows); it does not close it from Windows. Nor does it close the slower path from inside: while the Windows drives are mounted (`[automount]`, on by default), a program in the distribution writes there with the user's Windows rights, so it can leave a file that Windows or WSL later runs as the user (a script in the Startup folder, a `kernel=` line in `%UserProfile%\.wslconfig` that names a kernel of its own) and reach root at the next sign-in or WSL start, as persistent malware does (§3.3); `enabled=false` under `[automount]` takes the drives away too. `doctor` warns while interoperability is on (`wsl-interop`).
- **Windows programs are invisible to Precinto.** Its liveness checks see only the processes of the distribution, so a Windows program (Claude Code or Codex for Windows, Claude Desktop, a Windows editor or IDE agent) can write files without Precinto knowing they are in use, and cannot be paused or ended. That is why, under WSL, Precinto refuses to protect a folder, use a harness home, keep its own directory or write the recovery key on a Windows drive, refuses to run a harness that would run as a Windows program, and treats a location or an executable it cannot check as refused [D156]. What it cannot find, it cannot refuse: a Windows program that opens a protected folder through `\\wsl.localhost`, or a script that starts a Windows program from its body.
- **The terminal is a Windows program.** The window that shows a session (Windows Terminal, the console host, an editor) belongs to the Windows account: any Windows process of the user can read what it shows and type into it.
- **No Windows lock screen and no Windows idle time.** Precinto cannot see the Windows lock screen or the Windows keyboard and mouse: locking Windows (Win+L) locks no folder, `screen_lock_hard_after` never applies, an unwrapped prompt never extends an unlock, and a hook never raises an unlock dialog. Folders are unlocked in a terminal, and lock on their idle timers, at `max_unlock`, at a detected sleep or with `precinto lock`.

## 4. Trust boundaries

### 4.1 Components

| Component | Holds | Trusted to |
|---|---|---|
| Daemon (`precinto agent`) | vault identities while unlocked (memguard enclaves), grants with an idle and an absolute deadline, the effective policy | check presence and recipients, release file keys only under the rules of §4.2, wipe every key at once at each lock, never seal or restore in its own process |
| Clients: the wrapper, the CLI, restore workers | per-capsule file keys during a restore, and the plaintext they place | restore only logged capsules into computed targets; destroy keys within 2 s of a lock |
| Sealer and sweeps | public recipients only | seal only units of locked folders that nothing writes, and verify each capsule before deleting any plaintext |
| Hooks and the POSIX shim | no secrets | answer gate events quickly, fail closed for managed sessions, never log payloads |
| The harness | its own sessions | Precinto reads only a few fields of hook payloads (ids, paths, event names) and never stores prompt, tool or summary content |
| Factors | wraps of the vault identities | provide presence: the Secure Enclave through `age-plugin-se` with `any-biometry-or-passcode` (biometry-only and `none` are refused); an age plugin with a known presence policy (YubiKey touch, TPM PIN) or an explicit `--no-presence-ack`; a passphrase of at least 12 characters and at least 80 estimated bits, stretched with scrypt; the recovery key |

### 4.2 Crossing points

- **Unlock.** Always fresh presence, single-flight per vault (concurrent requests share one prompt), rate-limited (3 per minute, 30 s back-off after a cancel). A hook has no terminal, so it can only raise a graphical dialog (Secure Enclave or pinentry), never a terminal prompt, and only for a prompt of the same session that the daemon judged typed by a person within the last 60 s; inside tmux, screen or SSH the Secure Enclave dialog is not offered, and under WSL 2, where the screen state is unknown, a hook raises no dialog at all (§3.6). Before a dialog the user learns who is asking: a terminal requester prints the reason, and for a hook-raised dialog the daemon first sends a notification to the session's terminal. Unlock durations are capped at `min(max_unlock, 24 h)`. No operating-system event ever unlocks.
- **Daemon socket.** A Unix socket in a 0700, owner-checked directory, bound under a 0177 umask. The daemon checks the peer's uid on every connection and, for key release, unlock, vault creation, factor changes, vault repair, policy confirmation and wrapper activity, that the peer runs the same executable (same device and inode). The client checks the server's executable the same way before it sends anything. On Linux a hardened Precinto process cannot be inspected (it is not dumpable), so both checks are best effort there: the client checks instead that the daemon has the user's uid, holds the lock on `run/agent.lock` and has the expected process name, and the daemon checks that a hardened client has the user's uid and the expected process name (§7) [D65]. Secrets travel only in binary frames into locked buffers, never as JSON strings.
- **Key release** [D39]. For each requested capsule the daemon opens it under `capsules/` without following symlinks, looks up its path and header SHA-256 in the capsule log, requires every folder of the capsule to be unlocked, applies the agent-context rules for the purpose, and returns one file key. An identity never leaves the daemon.
- **Restore** [D12]. It runs in the client, in the harness's own environment. Precinto checks free space, decrypts the whole unit into a 0700 staging directory on the same file system, and validates every entry before placing anything. It then places files through directory descriptors with `O_NOFOLLOW`, checking the owner and permissions of every existing parent; files are created 0600 (0700 if owner-executable) and directories 0700. Existing files are replaced only as the placement table allows; anything else is kept side by side and reported as a conflict, and nothing is ever merged into a live unit.
- **Hook gate.** The harness runs the shim, the shim runs `precinto hook`, and the hook asks the daemon. If the daemon is unreachable within 150 ms, the payload cannot be decoded, the hook's own deadline passes or it panics, a managed session is blocked. If the binary is missing or crashes, the shim blocks gate events whose working directory or `CLAUDE_PROJECT_DIR` is inside a folder listed in `roots.list`.
- **Configuration** [D48, D55, D68]. Edits that weaken protection stay pending until an interactive unlock shows the difference and the user confirms it; stricter edits apply at once. The confirmed policy is first pinned when the first folder is protected, and is kept with a MAC per vault; from then on, if that copy is missing or altered, the daemon raises `policy-tampered` and also applies the built-in defaults, whichever is stricter, until the next confirmation. A terminal unlock re-pins it without asking only when `config.toml` weakens nothing. A confirmation is signed with the key of a folder that stays protected, or of the global vault when none does [D145]; a `prompt_rate_per_minute` of 0, which would end unlocking for good, does not load and makes a pin forged [D130].

### 4.3 What is not a boundary

- **Hooks.** A harness can run without them (`--bare`, `disableAllHooks`, a disabled plugin, Codex hooks the user has not trusted), some engines fail open (Codex on timeouts, Copilot CLI for prompts), and some harness paths bypass them (a flag-gated reactive compaction path in Claude Code 2.1.329, background summaries that no hook covers). Hooks turn a lock into a pause; encryption is what protects the data.
- **The wrapper's lock screen.** It hides the conversation from a person; any process can still read the files of a running session.
- **Agent detection and typed confirmations.** Reparenting (`setsid`, double fork) and `env -i` defeat ancestry checks, and a process that allocates its own pseudo-terminal (`script`, `expect`) can type confirmations [D59].
- **File permissions.** Harness files are already 0600 or 0644; every process of the user passes those checks.
- **The Linux user inside a WSL 2 distribution.** The Windows account owns the distribution: its Windows programs become root there at will (§3.6) [D155].

### 4.4 What Precinto trusts

- The kernel, the boundary between user accounts, and the hardware: the Secure Enclave, and FileVault for remnants on disk.
- Under WSL 2: Windows, the WSL virtual machine and the Windows account with every program it runs, which is the boundary there (§3.6); BitLocker or Device Encryption of the Windows drive that holds the distribution's virtual disk, for remnants on disk; and the kernel's mount table, which tells Precinto whether a location is on a Windows drive [D155, D156].
- `filippo.io/age` v1.3.x, and the age plugins pinned by path and hash.
- The `precinto` binary itself, `$HOME`, and the `PATH` of the user's shell. Pinning reduces, but does not remove, tampering by the same user. Claude Code's settings `env`, which an agent can write in `<folder>/.claude/settings.local.json`, reaches every hook process: Precinto ignores any `PRECINTO_*` variable there, but an injected `HOME` or `PATH` changes where the shim and the hook look for Precinto's directory, so `doctor` reports such keys (`claude-settings-env`) [D56].
- The harness binaries: they run as the user and hold the plaintext of their own running sessions anyway.

## 5. Scope

### In scope

- Programs that read the home directory at one point in time, and copies of it: backups, sync, disk images.
- One-shot tampering with Precinto's files: recipients, capsules, markers, configuration.
- A person at an unattended machine whose folders have locked.
- Agents, sandboxed or prompt-injected, that try to read other folders, reveal sealed content without the user, or make a restore write somewhere else.
- Crashes and power loss: no step may lose data (I9), and a lock always completes even when sealing fails (I15).

### Out of scope

- Malware that keeps running as the user, and anything with administrator (root) or kernel access; under WSL 2 that includes every Windows program of the user's account, which can become root in the distribution (§3.6).
- Windows programs that reach protected data unseen: Claude Code or Codex for Windows, Claude Desktop, Windows editors and IDE agents, Windows tools opening a protected folder through `\\wsl.localhost`. Precinto refuses them only where it finds them (§3.6) [D156].
- A running session's files and the process memory of the harness.
- Copies kept by model providers or by a harness's cloud sync.
- Copies made before a folder was protected, or outside Precinto's inventory (§7, "Residue").
- Attacks on age, on the Secure Enclave or on the operating system itself.

### Non-goals for v0.2

- Protecting a **live** session (its files and process memory) from malware running as the same user.
- Copies kept by model providers, harness cloud sync, terminal residue already written, Spotlight and Time Machine copies made before enrollment, git objects (`doctor` reports them; Precinto does not fix them).
- Native Windows: the Windows build refuses everything, and Windows is supported only through WSL 2, with the assumptions of §3.6 [D155]. Transparent FUSE or FSKit mounts, post-quantum capsules [D2].

## 6. Cryptography and integrity

- **Library and family.** `filippo.io/age` v1.3.x only, with no custom primitives. Every vault, recovery and ephemeral identity is X25519 [D2]. Post-quantum capsules are not in v0.2: the factor wraps (Secure Enclave, YubiKey) are classical, so post-quantum capsules would not stop a quantum attacker anyway; they are on the roadmap once factor wraps can be post-quantum.
- **Capsule format.** `age("PRECINTO-CAPSULE-1\n" || zstd(tar))`, where the tar holds `MANIFEST.json` and then the files in manifest order, regular files only. The header carries exactly three X25519 stanzas: the vault, the recovery key and a one-time verification key. After writing, the sealer parses the header and refuses any other count or type (exit 5, plaintext kept) [D5].
- **Order of sealing** [D13, D58]. Precinto records each file's identity (device, inode, size, times) and hashes it; streams a second pass that re-opens each file, requires the same identity and re-hashes it; forces the data to disk; decrypts the temporary capsule with the in-memory one-time key and compares the manifest and every hash; checks the header; renames the capsule into place without replacing anything; appends it to the capsule log; and only then deletes each plaintext file whose identity is unchanged and that nothing writes. Files that grew within the next second are sealed again as a successor ("rescue") generation.
- **Authenticated recipients** [D5]. Each `vault.toml` stores the recipients and an HMAC over them keyed from the vault identity; the daemon keeps a tripwire copy after each successful verification; every manifest carries a fingerprint of the recipient set, and after each unlock the daemon audits the capsules sealed since the last audit and reports any with a foreign fingerprint as exposed.
- **Names without content** [D45]. Unit keys are an HMAC of the unit's parts under a per-installation salt, truncated to 128 bits; capsule paths and the capsule log contain only unit keys and generation numbers from fsynced counters.
- **Decoding limits.** Manifests up to 16 MiB, at most 1,048,576 entries, a zstd window up to 64 MiB and decoder memory up to 1 GiB, and a total no larger than the restore budget and the free space; no symlinks, devices, FIFOs, hard links, PAX path overrides or sparse entries. Restored files get owner permission bits only; setuid, setgid and sticky bits are dropped.
- **Process hardening.** Every command that may hold secrets or plaintext refuses to run as root, sets `RLIMIT_CORE=0` and denies debugger attachment (`PT_DENY_ATTACH` on macOS, `PR_SET_DUMPABLE=0` on Linux). The daemon refuses to start with `DYLD_*` or `LD_*` variables (or re-executes itself with a clean environment), and is autostarted with an allowlisted environment. macOS release builds are meant to be Developer-ID signed, hardened and notarized (a pending decision, D35); `doctor` flags unhardened builds.
- **Crash safety** [D58]. Every operation is journaled, written to a temporary, renamed without replacing and fsynced; recovery needs no key and runs before every sweep, seal and restore. Quarantine runs only after recovery, so Precinto's own crash leftovers are never reported as forgeries.

## 7. Residual risks

| Risk | Why it remains | What reduces it |
|---|---|---|
| **Live data** | Plaintext of running sessions and of unlocked folders is readable by any process of the user; persistent malware captures a folder's key at its next unlock. | short `idle_soft` and `idle_hard`; `precinto lock --end` when leaving |
| **Deleted plaintext on SSDs** | Blocks of deleted files can survive on the disk. | FileVault, or an encrypted home on Linux; under WSL 2, BitLocker or Device Encryption of the Windows drive that holds the distribution's virtual disk |
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
| **Process identity on Linux is best effort, both ways** | Hardened Precinto processes are not dumpable, so on Linux the client checks the daemon's uid, the holder of `run/agent.lock` and the process name instead of its executable, and the daemon checks a hardened client's uid and process name instead of its executable. A process running as the user that kills the daemon and binds the socket in its place, or that runs under Precinto's process name, is not stopped (persistent same-user malware, §3.3); macOS keeps the full executable check both ways [D65]. | – |
| **A session managed later has no lock screen** | A launch outside every protected folder runs unmanaged. If that session later touches a protected folder, the hooks gate it from then on, but it has no lock screen. | start sessions inside the protected folder |
| **Trust in `$HOME`, `PATH` and the binary** | Pinned binary links and plugin hashes reduce, but do not remove, same-user tampering; Claude Code settings `env` can inject `HOME` or `PATH` into hooks [D56]. | install the binary where only an administrator can write; act on `claude-settings-env` findings |
| **Agent detection and typed confirmations** | Reparenting and `env -i` defeat ancestry checks; a process with its own pseudo-terminal can type confirmations [D59]. | – (they stop accidents, not malware) |
| **Metadata** | Folder paths, unit counts, capsule sizes and times, and the ledgers of unsealed sessions are plaintext. Session titles are only inside capsules. | – |
| **Residue outside the inventory** | Terminal state (iTerm2 restoration, Terminal.app, tmux-resurrect), the Spotlight index, Time Machine snapshots and backups made while unlocked, clipboard and Handoff, git objects, Claude desktop and Cowork stores, MCP server stores, Notification Center, editor histories; under WSL 2 also the Windows side: the scrollback of the Windows terminal, the copy of each pane's text that Windows Terminal (1.21 and later) saves on the Windows drive when it restores the previous session (*Open windows from a previous session*), and the Windows clipboard. | `precinto doctor --leaks`; exclude protected folders from Spotlight and cloud sync (`doctor` warns) |
| **Codex specifics** | Codex outside protected folders, and in protected folders that do not manage Codex (the user declined it), is unmanaged [D72]; a shared `codex app-server` is not supported in protected folders; databases are sealed as opaque groups (free pages inside them are sealed too, not scrubbed). Codex started without the wrapper in a protected folder writes to the user's own Codex home, which Precinto never seals; it is gated only if Precinto's hooks are trusted there, and `doctor` and `status` count those conversations (`codex-wrong-home`) [D31]. | always start Codex with `precinto run codex` or the shell function |
| **One temporary folder per Claude Code home** | A home has one temporary folder, fixed when Precinto registers the home; on Linux it follows the `TMPDIR`, `TMP` or `TEMP` of the process that registers or scans it. A session started with another `CLAUDE_CODE_TMPDIR`, or on Linux another `TMPDIR`, `TMP` or `TEMP` (an IDE may set one), writes its temporary files where Precinto neither seals nor restores them [D156]. | start Claude Code with the same temporary-folder settings everywhere, best from a terminal through Precinto |
| **Large sessions** | A changed session is re-encrypted in full; there are no incremental Claude Code capsules in v0.2. | – |
| **Prompt-origin heuristic** | Whether a prompt was typed by a human is inferred [D37]: it can misjudge a prompt typed while the system idle time is large (remote input) or an automated prompt right after a keystroke. Where the idle time cannot be read (headless Linux, WSL), unwrapped prompts never extend an unlock [D54]. | – |
| **Vault repair trusts the unlocked identity** | `vault repair` checks that the unlocked identity opens older capsules of the folder, but a writer who replaced the identity files of a folder with no older capsules cannot be told apart; capsules sealed while `vault.toml` was changed are reported as exposed, not re-encrypted (`rekey` is deferred) [D53]. | `precinto vault repair --recovery` when in doubt |
| **macOS privacy controls (TCC)** | A LaunchAgent sweep may not read folders under `~/Documents`, `~/Downloads` or `~/Desktop`; those units are sealed by Precinto processes started from a terminal, or reported as inaccessible. `precinto service install` checks access with the terminal's permissions, so it can only warn. | `precinto status` shows what the background service could not read; grant the service access, or keep projects elsewhere |
| **Bash-created Markdown** | Notes written by shell commands rather than file tools are sealed only with `md = "all"`. | `precinto protect DIR --md all` |
| **Passphrase factor** | A passphrase is offline-attackable once someone copies the wrapped identity; `doctor` warns about it. | prefer the Secure Enclave or a hardware key |
| **A forged pin that names no folder** | A pin whose settings name no folder may carry only a `global` MAC, which only `unlock --global` and `recover` check; with a `config.toml` that names no folder either, such a pin drops every folder from enforcement until then [D145]. | `precinto status` (`unprotected-folders`) and `precinto doctor` name the folders whose vault is kept but that nothing protects, with `precinto unlock --global` as the fix, which reports the tampering; a folder unlock's review names them before a confirmation could drop them for good |
| **Background sessions** | Claude Code background and supervised sessions (`--bg`, agent view) are never ended, because their supervisor would restart them; they stay paused and flagged [D25]. | end them from Claude Code itself |
| **WSL 2: the Windows account is the boundary** | Any Windows process of the user becomes root in the distribution with `wsl -u root`, and while Windows interoperability is on (WSL's default) so can a program inside it, an agent included, through `wsl.exe`; with interoperability off, such a program can still leave a file on a mounted Windows drive that Windows or WSL runs later as the user, and so become root at the next sign-in or WSL start. Root reads the keys of the folders unlocked at that moment from the daemon's memory, and with them every capsule of those folders. Any Windows process of the user can also read the terminal window that shows a session and type into it (§3.6) [D155]. | lock folders when you step away and keep unlocks short; turn interoperability off in `/etc/wsl.conf` if you can do without starting Windows programs from the distribution (`doctor` warns: `wsl-interop`), and the automatic mounting of the Windows drives (`[automount]`) if you can do without them too |
| **WSL 2: Windows programs are invisible** | Precinto's liveness checks see Linux processes only. It refuses the Windows drives and Windows programs it finds, but cannot see a Windows program that opens a protected folder through `\\wsl.localhost`, a script whose body starts a Windows program, or a Windows drive mounted below a Claude Code home, which the scans of that home do not check yet [D156]. | install and run the harnesses inside the distribution; keep Windows tools away from protected folders; act on `windows-drive` and `windows-harness-data` findings (`precinto doctor --leaks`) |
| **WSL 2: the disks are Windows files** | The distribution's file system is a virtual disk file on a Windows drive, and its swap is another (`swap.vhdx` in the Windows temporary folder by default): Windows backups, sync and copies of that drive take them whole, with remnants of deleted plaintext and swapped-out memory, a harness's conversation included; Windows' hibernation file holds a copy of memory too. Linux cannot tell whether that drive is encrypted, so `doctor` reports disk encryption as unknown. | BitLocker or Device Encryption on that drive |
| **WSL 2: no Windows lock screen, no idle time** | Locking Windows (Win+L) locks no folder, `screen_lock_hard_after` never applies, unwrapped prompts never extend an unlock, and hooks raise no unlock dialog. A sleep locks folders only once WSL sets the clock of the distribution forward at resume. WSL stops the distribution about 15 s after its last terminal closes (`instanceIdleTimeout`), and the agent with it: the keys are wiped, but what was unlocked stays plaintext until Precinto runs again, since there is no background service on Linux [D155]. | `precinto lock` (or `precinto lock --end`) before you step away; a short `idle_soft`; `instanceIdleTimeout=-1` under `[general]` in `.wslconfig` keeps the distribution, and the agent, running |
| **WSL 2: a sleep no Precinto process saw** | After Windows sleeps, the boot time Linux reports moves forward by the length of the sleep, and Precinto undoes that with the earliest boot time its agent recorded [D157]. When no agent ran before the sleep (every folder locked), a Claude Code session without working hooks that started before it is held live only while its files keep changing (the quiet window), as before D157. | keep Claude Code's hooks working in protected folders |

## 8. What you can do

- Turn on FileVault on macOS, or disk encryption on Linux; on Windows, BitLocker or Device Encryption for the drive that holds WSL's virtual disks.
- On Windows, keep Precinto, Claude Code, Codex, the protected folders and the harness homes inside one WSL 2 distribution, on its Linux file system, and work from its terminal; never run the harnesses from Windows on protected folders ([WINDOWS.md](WINDOWS.md)). Lock folders yourself before you leave, since locking Windows does not lock them, and consider turning Windows interoperability off in `/etc/wsl.conf`, and the automatic mounting of the Windows drives with it.
- Start harnesses through Precinto (`precinto shell-init`, `precinto run`) rather than unwrapped, and keep the hooks installed and trusted (for Codex, check the trust in each protected folder); `precinto status` shows their health.
- Use `precinto lock --end` when you leave, and keep `idle_hard` and `screen_lock_hard_after` short: ending sessions is what turns them into ciphertext.
- Never type secrets into a locked session, and never paste them into a prompt.
- Prefer the Secure Enclave or a hardware key over a passphrase.
- Verify the recovery key with `precinto recover --verify`, and keep it offline.
- Install the `precinto` binary in a directory that only an administrator can write.
- Re-pin an age plugin (`precinto factor repin NAME`) only after an upgrade you made yourself, and only when the new binary it shows is the one you installed.
- Keep protected folders out of Spotlight and cloud sync, and run `precinto doctor --leaks` now and then.
- Run `precinto status --check` in scripts: it exits 3 when a locked folder still has unencrypted files, and 1 when it cannot tell (config.toml does not load, or a locked folder could not be scanned), so treat any non-zero exit as a failure.

## 9. Invariants

The tests enforce these properties ([SPEC.md §18](SPEC.md#18-invariants-tests-must-enforce-see-testplanmd-for-the-mapping); mapping in [TESTPLAN.md §7](TESTPLAN.md#7-invariants--tests)):

| # | Property |
|---|---|
| I1 | A file of a live unit is never sealed, moved or deleted. |
| I2 | Restore writes exact bytes at the computed path, as regular files, with the original mtime and owner-only permissions, unless the placement table applies. |
| I3 | Plaintext is deleted only after its generation is committed and verified and the file is unchanged since it was hashed. |
| I4 | Capsules live only in Precinto's store; the working tree holds only text markers. |
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
