# precinto — Specification v0.2

> **precinto** (Spanish: *a seal that keeps something closed so that it is opened only when, and by whom, it should be*).
> A KeePass-style vault for AI coding-agent sessions: transcripts, derived data (compaction summaries, memories, checkpoints, tool outputs) and agent-written Markdown are **sealed at rest**; returning to a protected folder **asks for an unlock**; idle folders **lock**, and sessions left alone **end and are sealed**. One repo, many harnesses.

Status: DRAFT v0.2 (2026-11-21). Supersedes v0.1. It applies every decision of `docs/DECISIONS.md` (D1–D81; D36–D52 were added with this version, D53–D61 in its verification fix pass, D62–D75 in the wave-3 integration and D76–D81 in the final integration) and every critical/high finding of the v0.1 review. This document is the contract between modules; `docs/API.md` is the Go contract, `docs/HOOKS-IO.md` the hook wire contract, `docs/TESTPLAN.md` the test contract. If code and spec disagree, fix one of them in the same change.

Conventions. MUST/MUST NOT/SHOULD/MAY are used as in RFC 2119. `[Dn]` marks a binding decision. Parenthesised tags such as (R4), (S3), (UX2), (HA10), (IM8) name findings of the v0.1 review (private workspace) for traceability. "Folder" is the user-facing word for a protected root; user-facing text never says root, grant, soft or hard (§16.3).

---

## 1. Goals and non-goals

### Goals
- **G1 – Bounded plaintext dwell for inventoried files.** Every file of a managed unit (§3) is sealed into a verified capsule once no process can still write it and its folder is locked. Plaintext of a managed unit exists only (a) while a process can write it, (b) while its folder is unlocked, (c) after a crash, until the next sweep, or (d) when listed in `status` as unsealable with a reason (§17). Residual copies outside the inventory are listed in §19.
- **G2 – User presence to unlock.** Secure Enclave via `age-plugin-se` (Mac password while no Touch ID is paired), other age plugins, or a passphrase; an offline recovery key. Sealing never needs a secret.
- **G3 – Unlock before launch.** Starting a harness in a locked folder, or resuming a sealed session, asks for an unlock first (wrapper pre-launch gate); entering a locked folder in an interactive shell asks too [D29].
- **G4 – Auto-lock.** Folders lock after human idle, on screen lock, at wake from sleep, at the absolute limit, or on request; paused sessions end after longer idle or a long screen lock (§12).
- **G5 – Robustness.** Compaction, resume, fork, subagents, background sessions, crashes (SIGKILL, power loss), concurrent sessions and harness upgrades that add files (fail-closed inventories).
- **G6 – Portable.** Native hooks for Claude Code and Codex; a wrapper and data-driven inventories for other harnesses (experimental) [D33].
- **G7 – Never lose data.** A capsule generation is never overwritten; a generation is deleted only by an explicit `prune`/`forget` that keeps every file still needed (§10.4); disappearance of plaintext is never treated as a deletion (I12).

### Non-goals (v0.2)
- Protecting a **live** session (its files and process memory) from malware running as the same user.
- Copies kept by model providers, harness cloud sync, terminal residue already written, Spotlight/Time Machine copies made before enrollment, git objects (reported by `doctor`, not fixed).
- Windows (WSL works as Linux). Transparent FUSE/FSKit mounts. Post-quantum capsules [D2].

---

## 2. Threat model (summary — full version in `docs/THREAT_MODEL.md`)

| Adversary / event | Protected? | How |
|---|---|---|
| Point-in-time reader of the home directory (infostealer run once, another agent grepping `~`) | **Yes** for sealed units | capsules are age ciphertext; identities only in daemon memory; unlock needs presence |
| One-shot writer (rogue package edits `vault.toml`, plants capsules or markers) | **Detected** | recipients MAC + tripwire refuse sealing (exit 5) [D5] until `precinto vault repair` [D53]; unlogged capsules are quarantined [D8]; restore targets derive from trusted context and authenticated unit ids (§11.2) |
| Persistent same-UID malware | **No** | it obtains a root's key at that root's next unlock; per-root identities limit it to roots the user unlocks [D1] |
| Backups, sync, copied disk images | **Yes** for sealed units | ciphertext; FileVault required for deleted-plaintext remnants (§19) |
| A person at the idle, unlocked machine | **Partly** | wrapped sessions: lock screen hides output and swallows input [D30]; unwrapped sessions: model gate only — the TUI stays readable (§19) |
| Sandboxed or prompt-injected agent | **Mostly** | cannot read other roots' plaintext without presence [D28]; cannot make restore write outside its unit (§11.2) |
| Live session files / process memory | **No** | dwell bounded by idle/screen-lock policy |
| Provider-side retention | **No** | out of scope |

Hooks are **not** a security boundary (`--bare`, `disableAllHooks`, untrusted Codex hooks, fail-open engines). The boundary is: *encryption at rest + key custody in the daemon + keyless sweeps*. Vault strength equals the weakest enrolled factor.

---

## 3. Glossary

- **Harness** – an agent CLI/IDE (`claude-code`, `codex`, …); `harness.ID`.
- **Folder / protected root** – a directory registered in `config.toml` with a stable random id (never an in-repo marker). Roots may not overlap unless the user confirms; the deepest root wins.
- **Vault** – one X25519 identity plus its wrapped copies; one per root, plus the `global` vault [D1].
- **Vault recipient / recovery recipient** – public halves used for sealing; the recovery recipient is shared by all vaults of an install.
- **Factor** – a way to unwrap a vault identity: `se`, `plugin`, `passphrase`, `recovery` (§4.3).
- **Home** – a harness data directory set (Claude: config dir + tmp dir + cache; Codex: a per-root `CODEX_HOME`), realpath'd and registered in config (§7.0).
- **Unit** – a set of plaintext files sealed and restored together: Claude session, project, plan, history, global store; Codex home snapshot; one Markdown note.
- **Unit key** – HMAC-derived opaque name of a unit; the only identifier in plaintext metadata [D45].
- **Managed** – a session is managed once any of its directories or tool paths lies inside a root ("taint", sticky) [HA10].
- **Capsule** – one age-encrypted file holding a unit generation (§5).
- **Generation** – an immutable capsule of a unit, numbered by a persisted counter; never overwritten [D9].
- **Lineage** – how a generation relates to its parent: fresh, successor, partial, diverged [D10, D42].
- **Receipt** – record of plaintext whose origin precinto knows — placed by a restore, or left behind by a seal (identity + SHA-256 per file); basis of lineage [D10, D58].
- **Capsule log** – provenance log of every capsule precinto sealed; only logged capsules restore [D8].
- **Grant** – an unlocked vault held by the daemon with an idle and an absolute deadline.
- **Live** – some process can still write a file of the unit (§9). **Lease** – a wrapper's claim on units it restored for a launch.
- **Busy** – a session mid-turn (registry busy, or hook-derived) [D23].
- **Paused / ended** – a session whose folder is locked is paused (gated); ending terminates and seals it (§12).
- **Seal / restore** – encrypt+verify, then delete plaintext / decrypt, then place exact bytes with the placement table.
- **Sweep** – keyless scan that seals every non-live unit of locked folders.
- **Quarantine** – holding area for capsules without provenance.

---

## 4. Keys and cryptography

### 4.1 Library and family
- `filippo.io/age` v1.3.x only; no custom primitives. Family is **X25519** for every vault, recovery and ephemeral identity [D2]. A recipient set of any other family makes the sealer refuse (exit 5).
- Every capsule header carries **exactly three X25519 stanzas**: vault recipient, recovery recipient, ephemeral verify recipient. After writing, the sealer parses the header and refuses (exit 5, plaintext kept) on any other count or type [D5].

### 4.2 Vaults [D1]
- `vaults/<root-id>/` per protected root, created at `protect` by the daemon; `vaults/global/` for global-store units that cannot be attributed to a root (`usage-data/`, `feedback/drafts/`) [D36].
- Unlocking a folder unwraps only that folder's identity. Units are sealed to the vault of their **primary** root (the root containing the session's start cwd, else the first tainted root); the manifest and capsule log list every managed root, and key release requires all of them unlocked (§13.5).
- History lines extracted from Claude's `history.jsonl` belong to the deepest root containing their `project` and are sealed to that root's vault [D36].

### 4.3 Factors [D3]
Each vault identity is wrapped once per factor in `vaults/<id>/identity.<factor>.age` (scrypt stanzas alone in their file).
- `se` (default on macOS): `age-plugin-se keygen --access-control any-biometry-or-passcode`. Biometry-only and `none` access controls MUST be refused. The recipient is taken from keygen output (`age1tag1…` P-256 tag recipient, wrapped natively by age ≥ 1.3); the `AGE-PLUGIN-SE-1…` identity stub (not secret, required to unwrap) is stored in `<base>/factors/se.identity` (0600). When `init` runs inside tmux/screen or over SSH (`$TMUX`, `$STY`, `$SSH_CONNECTION`), where the Secure Enclave dialog cannot appear, it offers a passphrase factor as well (B.remote, default yes) [D60].
- `plugin`: any `age1<name>1…` recipient. A plugin factor requires a known presence policy (YubiKey touch `always`/`cached`, TPM PIN) or `--no-presence-ack` (S10): `init --factor plugin:<recipient>` and `factor add plugin:<recipient>` take `--identity-stub FILE` and `--presence touch-always|touch-cached|pin-always|pin-once|tpm-pin` or `--no-presence-ack` (recorded as `vault.Factor.PresencePolicy`; `se` keeps its access control).
- Every factor backed by a plugin binary — `se` (`age-plugin-se`) as well as `plugin` — pins that binary by absolute path and SHA-256 in `vault.toml` and runs it with `PATH` limited to its directory; a hash mismatch refuses (`vault.ErrPluginPin`, exit 5) (S2).
- `passphrase` (default on Linux, optional on macOS): ≥ 12 characters and ≥ 80 estimated bits; `init` offers a 7-word diceware passphrase; scrypt logN calibrated to ≈ 1 s, minimum 19, default 20. Read only from a TTY or pinentry into locked buffers; never from argv or environment. `doctor` warns it is offline-attackable.
- `recovery`: an X25519 identity generated at `init`; its recipient is in every capsule; each vault identity is also wrapped to it (`identity.recovery.age`) so a lost factor can be replaced. Shown only to a human (§4.7). It is listed in `vault.toml`, is never removed and is offered only to a requester with a TTY.
- One passphrase per install: every vault identity is wrapped with it, so `vault_create` asks for it on a TTY or through pinentry and creates nothing when no UI can (`vault.ErrNoUI`). The scrypt floor (logN ≥ 19) applies to every build; test binaries and `-tags testing` builds may use logN ≥ 10 (`vaulttest`).
- A plugin binary that changed (an upgrade) is re-pinned with `precinto factor repin NAME` (TTY only, refused in agent contexts) [D75, D80]. The vault records the path the factor was enrolled with before symlinks are resolved (`vault.Factor.PluginLink`, e.g. `/opt/homebrew/bin/age-plugin-se`) next to the resolved binary it pins and runs (`PluginPath`); repin resolves the enrolled path again (`vault.PluginTarget`), shows the enrolled path, the pinned binary and SHA-256, the current binary and SHA-256, owner and mtime, asks for the typed word `repin` (C12.typed) and rewrites path and hash in every vault (`vault.Store.RepinPlugin`; a vault that failed is reported and the next repin completes it). The current binary must keep the pinned binary's name and be a regular file owned by root or the user and not group/other-writable. A link re-pointed to another binary of the same name looks like an upgrade: the human reading both paths and hashes decides (§19). doctor reports a mismatch as `plugin-pin`.

### 4.4 Authenticated recipient set [D5]
- `vault.toml` stores `recipient`, `recovery_recipient`, `family` and `recipients_mac = HMAC-SHA256(HKDF-SHA256(identity, info="precinto/recipients/v1"), canonical)`, where `canonical = family "\n" sorted(recipients) joined by "\n"`; written while the identity is in the daemon.
- Every unlock MUST verify `identity.Recipient() == recipient` and the MAC; on mismatch the daemon refuses the grant, raises the attention item `vault-tampered` (C14.tampered, naming `precinto vault repair --root DIR`) and lists capsules sealed since the last audit.
- After a successful verification the daemon writes `state/verified/<vault-id>.recipients`. The sealer MUST refuse (exit 5, plaintext kept) if `vault.toml` recipients differ from that copy (tripwire), and when the verified copy is missing; the refusal raises the same attention item. Once a verified copy exists only vault repair moves it; Verify rewrites a missing copy only behind a valid MAC.
- Every manifest carries `recipients_fpr = SHA-256(canonical)`. After unlock the daemon audits capsules sealed since `last_audit` (header unwrap + manifest) and reports any foreign fingerprint as exposed (`exposed-capsules`). `last_audit` only moves forward (`vault.Store.MarkAudited`, outside the MAC); a `last_audit` later than now counts as zero (audit everything).
- **Repair** [D53]. `precinto vault repair --root DIR | --global [--recovery]` is the only way back to sealing after a MAC or tripwire failure. It needs a TTY and is refused in agent contexts (C12.agent). The daemon (op `vault_repair`) unwraps the identity with a factor through relayed UI — or, with `--recovery`, from `identity.recovery.age` with the recovery identity the user types (sent in one 'S' frame) — and requires it to open the header of at least one capsule of this vault logged before `last_audit` when any exists; otherwise it changes nothing and shows C14.notgenuine (the identity files may have been replaced too). The client first sends `Confirmed=false` (dry run: unwrap, genuineness check, diff; nothing written), shows the recipient diff and obtains typed confirmation (C14.confirm), then sends `Confirmed=true` on the same connection without a second presence prompt. The daemon then rewrites `recipient` from the identity, `recovery_recipient` from the recovery identity (without `--recovery` it is kept only if it equals the verified copy, else `vault.ErrNeedRecovery`), `family`, the MAC and the verified copy (`vault.Store.Repair`), and lists every capsule sealed since the old `last_audit` with a foreign `recipients_fpr` as exposed (C14.repaired). Repair never touches identity files or capsules; exposed capsules stay as they are (re-encryption needs `rekey`, deferred [D49]).

### 4.5 Key custody [D4, D39]
- Only the daemon unwraps identities. It runs the age plugin or scrypt itself; plugin `ClientUI` messages and passphrase/PIN requests are relayed to the requesting client's TTY, or to pinentry when the client has none.
- Identities live in memguard enclaves; each operation opens the enclave, parses the identity, performs `age.DecryptHeader`, and drops it. The transient heap copy is a documented residual (§19). Identities never leave the daemon and never touch disk unencrypted.
- Restore runs in the client (wrapper/CLI/worker), in the harness's environment. The daemon releases **per-capsule file keys** — never identities — only to a peer that runs the same precinto executable, only for capsules found in the capsule log, only when every root of the capsule is unlocked, and subject to agent-context rules [D28, D39]. Clients hold file keys in locked buffers and destroy them on completion and on any lock event.
- The pinentry the daemon runs for a terminal-less passphrase prompt must be a root-owned executable, not group/other-writable, reached through root-only directories (its own and its target's), found in PATH order; it runs with `PATH` limited to its directory. A pinentry in a user-writable directory (Homebrew's prefix included) is never run [D97].

### 4.6 Process hardening (S15)
- Every subcommand that may hold secrets or plaintext (`agent`, `init`, `factor`, `vault repair`, `protect`, `unprotect`, `unlock`, `hook`, `run`, `seal`, `sweep`, `restore`, `open`, `cat`, `recover`) MUST first call `platform.Harden` [D95]: refuse uid 0, `RLIMIT_CORE=0`, `PT_DENY_ATTACH` (darwin) or `PR_SET_DUMPABLE=0` (linux).
- The daemon MUST refuse to start (or re-exec with a clean environment) when `DYLD_*`/`LD_*` variables are present; autostart passes an allowlisted environment.
- Release builds for macOS SHOULD be Developer-ID signed with hardened runtime and notarized (owner decision, D35); `doctor` flags unhardened builds.

### 4.7 Recovery key [D7]
- `init` MUST refuse to show or write the recovery key unless stdin and stdout are TTYs and no agent context is detected (env markers or a harness ancestor, §12.8).
- Shown on the alternate screen in groups of 6; the user types back the last 4 characters [D7], as the screen says under the key (B.typeback; a wrong answer replaces that line with B.typeback.wrong and asks again); then screen and scrollback are cleared (`ESC[2J ESC[3J`, iTerm2 `OSC 1337;ClearScrollback`). The key is shown, or written with `--recovery-out`, before anything exists (`vault.InitOptions.Confirm`): an init stopped at its screen (Ctrl-C, then no to seeing it again) creates nothing and exits 3, so `init` can run again with a new key; a cancelled `--show-recovery` screen after the file was written does not stop init [D119]. Alternative: `--recovery-out FILE` (0600, O_EXCL; refused inside roots, harness homes and synced folders). `--show-recovery` also shows the key on the alternate screen when `--recovery-out` is given; without `--recovery-out` it is always shown.
- `precinto recover --verify` checks the key unwraps a fresh capsule header and records `recovery_verified_at` in every `vault.toml` (`vault.Store.MarkRecoveryVerified`); `status` shows "recovery key: never tested" until then, and the date after. `recover` without `--verify` unlocks every folder and the global vault with the recovery factor (one relayed secret per vault, answered from the key typed once) so that `factor add` can enroll a replacement. `recover` reads the key from the TTY or stdin; a plaintext key file requires `--insecure-key-file`. `vault repair --recovery` uses the key to unwrap `identity.recovery.age` and to re-derive the recovery recipient [D53]. `rekey` is deferred [D49].

---

## 5. Capsule format v1

```
file  = age( "PRECINTO-CAPSULE-1\n" || zstd( tar ) )     ; recipients: vault, recovery, ephemeral (X25519)
tar   = "MANIFEST.json", "f/000001", "f/000002", …        ; TypeReg members only, manifest order
```

`MANIFEST.json` (JSON, snake_case keys; Go type `capsule.Manifest`):
`format`, `kind`, `harness`, `harness_version`, `unit_key`, `unit_id` (sid, slug, relpath — inside ciphertext only), `vault_id`, `root_ids[]`, `root_path`, `project_dir` (claude-session: the session's start cwd, realpath'd; claude-project: the cwd the project index maps to `<P>` when unique; copied from `harness.Unit.ProjectDir`, D73), `gen`, `parent`, `lineage`, `created_at`, `sealer`, `recipients_fpr`, `title` (custom-title > ai-title > first prompt), `last_activity`, `ledger` (the unit's ledger lines, S13), `files[]` with `{name, base, rel, path (audit only), dir, mode, mtime_ns, size, sha256, blob, group, append}`.

Rules (writers MUST produce, readers MUST enforce):
1. Regular files only. Empty directories are entries with `dir: true` and no member. No symlinks, devices, FIFOs, hard-link semantics.
2. Members appear exactly as `MANIFEST.json` then `f/000001…` consecutive, in manifest order, with sizes equal to the manifest; no trailing members; no PAX path overrides, links or sparse entries.
3. Limits: manifest ≤ 16 MiB; ≤ 1,048,576 entries; zstd decoder window ≤ 64 MiB, memory ≤ 1 GiB, concurrency 1; total plaintext ≤ the restore budget and the free space minus the floor.
4. `base` is one of `claude_config`, `claude_tmp`, `claude_cache`, `codex_home`, `root`, `generic:<name>`; `rel` is local and clean (`filepath.IsLocal`, `Clean(rel)==rel`). `path` is informational only and MUST NOT be used for writing [D8].
5. Restored permission bits = recorded owner bits only: files 0600 (0700 if owner-exec), directories 0700; setuid/setgid/sticky dropped (I8). Example: a recorded 04777 file is restored 0700, a 04666 file 0600 (`fsx.Dir.Chmod`).
6. A manifest can be read without full decryption: the daemon releases the file key, and the client decrypts only the first members (`capsule.OpenManifest`).

---

## 6. Storage layout and naming

### 6.1 Layout
Base `<base>` = `~/Library/Application Support/precinto` (darwin) or `${XDG_DATA_HOME:-~/.local/share}/precinto` (linux). `PRECINTO_HOME`/`PRECINTO_RUNTIME_DIR` are honoured only by builds with `-tags testing`, or with `PRECINTO_DEV=1` outside agent contexts; hook mode and the shim never honour `PRECINTO_*` overrides (hooks always run in an agent context; `paths.HookLayout`) [D6, D56]. Only `-tags testing` builds read `PRECINTO_TEST_ANCESTRY_STOP=PID:START`, which ends the agent-context ancestry walk at the test process (`testkit.NewHome` sets it) [D64].

```
<base>/                                   0700
  config.toml                             roots (ids), policy, registered harness homes
  roots.list                              absolute root paths, one per line (read by the shim) [D22]
  bin/precinto                            symlink to the pinned binary (written by integrate) [D6]
  marketplace/                            the plugins and both marketplace manifests, written byte for byte from the binary by integrate (dirs 0700, files 0600, shims 0700); the harness adds it as a local marketplace [D116]
  factors/se.identity                     AGE-PLUGIN-SE-1… stub (not secret); a reference copy: unwrap uses the stub recorded in vault.toml
  vaults/<vault-id>/vault.toml            recipients, MAC, factors [D1, D5]
  vaults/<vault-id>/identity.<factor>.age wrapped identity per factor
  capsules/<harness>/<unit-key>/g<N>.pcap generations [D9, D45]
  capsules/md/<unit-key>/g<N>.pcap        notes [D16]
  capsules/codex/<unit-key>/g<N>.pcap     codex home snapshot manifests; …/blobs/<blob-key>.pcap
  homes/codex/<root-id>/                  per-root CODEX_HOME [D31]
  staging/<op-id>/                        restore staging (same volume, else <volume>/.precinto-staging) [D12]
  quarantine/<op-id>/                     unlogged capsules; displaced -wal/-shm/-journal files
  state/name.salt                         32 random bytes for unit keys [D45]
  state/capsules.log                      provenance log [D8]
  state/verified/<vault-id>.recipients    tripwire copy [D5]
  state/gens/<unit-key>                   generation counter (fsynced) [D9]
  state/gens/<home-unit>.refs.json        Codex generation → blob unit keys
  state/receipts/<unit-key>.json          restore receipts [D10]
  state/leases/<unit-key>.lease           launch leases (flock) [§9.3]
  state/sessions/<harness>/<sid>.jsonl    content-free ledger
  state/projects/<harness>.json           project index: slug → cwds, roots, memory dir
  state/journal/<op-id>.json              in-flight operations [I9]
  state/queue/<req-id>.json               pending seal requests
  state/locks/*.lock                      flock files — never deleted
  state/policy.pinned                     policy confirmed at the last TTY unlock + per-vault MACs [D48, D55]
  state/sweep.requested, state/sweep.last sweep coordination and heartbeat
  state/hookdedupe/                       HA21 duplicate-suppression markers (hashed, content-free names; pruned after 10 min)
  state/notes.json                        pending-notes index: absolute note paths per root, no content (filled before plaintext goes, cleared when a note is sealed or vanishes)
  logs/precinto.log                       ids, counts and reasons only; no content and no paths
  run/agent.sock, run/agent.lock          darwin; linux: $XDG_RUNTIME_DIR/precinto/ [D6]
```
Directories 0700, files 0600, socket 0600 (bound under umask 0177), socket path < 104 bytes.

### 6.2 Unit keys [D45]
`unit_key = hex(HMAC-SHA256(name_salt, join(parts, 0x1f))[:16])` (32 hex chars), where parts are:

| Kind | Parts |
|---|---|
| `claude-session` | `claude-code`, `session`, home id, sid |
| `claude-project` | `claude-code`, `project`, home id, project directory name as found on disk |
| `claude-plan` | `claude-code`, `plan`, home id, slug [D46] |
| `claude-history` | `claude-code`, `history`, home id, root id [D36] |
| `global-store` | harness, `global`, home id, store name |
| `codex-home` | `codex`, `home`, root id [D31] |
| `codex-blob` | `codex`, `blob`, root id, random blob id |
| `md` | `md`, root id, relpath (root-relative, `/`-separated) |
| `generic` | harness, `generic`, home id, partition id [D33] |

Home id = first 16 hex of SHA-256 of the home's realpath. Every group derives keys with `harness.UnitKeyFor(salt, kind, harness, home id, root id, unit id)`, which encodes this table (non-final parts never contain 0x1f). Claude's slug is never computed by precinto (IM12, HA15). Generation files are `g%06d.pcap`, committed with no-replace renames; the counter in `state/gens/` is fsynced before use, never derived from the wall clock (R16) and never reused; numbers may have gaps after crash recovery, and lineage follows the logged `parent` links, never number arithmetic [D58].

### 6.3 Plaintext metadata
Visible without keys: root paths (`config.toml`, `roots.list`), unit counts, capsule sizes and seal times, unit keys, ledgers of sessions not yet sealed (paths, never content), receipts of restored units, logs (ids, counts and reasons; no paths). Ledgers move into the capsule when a unit is sealed (S13). Ledger events recorded after a unit's last generation stay in its ledger file until the next generation (an unchanged re-seal archives nothing). See §19.

---

## 7. Units and harness adapters

An adapter (`harness.Adapter`, docs/API.md §G3) provides: registered homes, a fail-closed inventory of units, harness-specific liveness evidence, restore target rules per kind, per-file placement policies, Markdown paths derived from transcripts, and the launch plan. Adapters never seal, restore or delete; `internal/sweep` does.

### 7.0 Homes and environment
- Harness homes are resolved **in the harness's own context**: from the hook environment (which is the harness's) and from the wrapper's child environment. Hooks record the home in the session ledger; seals, sweeps and queue workers (before they seal anything, not in a dry run), `integrate` and `protect` register newly seen homes that exist, realpath'd once, in `config.toml` `[harness.<id>].homes` (adding a home strengthens protection and applies at once, D48; config.toml is read again under `state/locks/config.lock`, the flock every edit of `config.toml` and `roots.list` holds, so an edit another process saved meanwhile is kept [D114]) [D109] (R22, IM2).
- Sweeps visit every registered home; restore requests naming an unregistered home MUST be rejected: nothing is written, the unit fails with its own code (`unregistered`) and `restore` exits 1 with E.unregistered — a configuration gap, never the verification class (exit 5) [D109]. The daemon never derives harness homes from its own environment.
- Claude: `$CC` = `CLAUDE_CONFIG_DIR` or `~/.claude`; `$TMP` = the base of the payload `scratchpad_dir`, else `CLAUDE_CODE_TMPDIR`, else `/private/tmp/claude-<uid>` (darwin) / `/tmp/claude-<uid>` (linux); `$CACHE` = `~/Library/Caches/claude-cli-nodejs` (darwin) / `${XDG_CACHE_HOME:-~/.cache}/claude-cli-nodejs`. `CLAUDE_CODE_PROJECT_DIR_NAME` is recorded when set. `$TMP` MUST be owned by the user with mode 0700, else precinto refuses to restore there and `doctor` warns (S7).
- Codex: per-root homes only (§7.2) [D31].

### 7.1 Claude Code (`claude-code`) — capsule mode

#### 7.1.1 Session unit (fail-closed) (I10, HA13, IM14)
- Transcripts are located by session id across every `$CC/projects/*/` directory, including `*.compact.tmp.*`, `*.superseded-*`, `*.orphaned-*` and `.precompact.json.tmp.*` siblings — never by cached path or inode [D19].
- The unit is every regular file under `$CC/projects/<P>/<sid>/` at any depth (subagent transcripts, tool results and workflow journals sit 5–7 components below `$CC`); every other regular file under `$CC` and `$TMP/<P>/` where a component equal to the sid, or starting with `<sid>.` or `<sid>-`, within the first four components below `$CC` (positions 2–4 below `$TMP`, under `<P>`) takes that entry's whole subtree at any depth; plus `$CC/jobs/<id>/**` for jobs whose state names the sid. Deny-list (never sealed): `settings*.json`, `plugins/`, `skills/`, `commands/`, `agents/`, `sessions/` (registry and `.key` files), credentials, `keybindings.json`, `ide/`, `CLAUDE.md`, `shell-snapshots/`.
- Files that no ledger, index entry or transcript ties to a root are unmanaged and left alone. History units come only from rotation (§7.1.4), never from Scan.
- Placement: `projects/<P>/<sid>.jsonl` and `<sid>/subagents/**/*.jsonl` are append-only JSONL (`jsonl-append`), `<sid>.jsonl` is placed last (`harness.TargetRules.Last`); everything else `exact`.
- A session is managed iff its ledger has a taint (§14.3), or — when hooks never ran — any `cwd` key of its transcript lies inside a root (adoption, S6). `seal --adopt` (whose scan adopts, D106) and `md = "all"` sweeps also seal adopted sessions; `status` reports them (reason `adopted`; status and `doctor` name `precinto seal --adopt --root DIR`, the folder as one shell word, D113).
- Non-current transcripts of a live process (after `/clear` or `/resume`: SessionEnd reason `clear|resume`, a newer ledger start for the same pid, or a registry `sessionId` that differs) are sealable once stable [D20].
- Stale `$CC/shell-snapshots/*.sh` (environment dumps left by crashes) older than one day and not open are deleted by sweeps while no Claude process runs; they are never sealed.

#### 7.1.2 Project unit [D47]
- Contents: `projects/<P>/memory/**` (auto memory, keyed by the memory directory actually used — shared per git repository, HA14), legacy `projects/<P>/sessions-index.json`, other non-session files directly in `projects/<P>/`, and `$CACHE/<P>/**` (MCP logs).
- Live while any Claude process (process-table scan by executable, never by `p_comm`) has a cwd inside the root, inside the git repository containing the root, or an unknown cwd. Memory files are not append-only: restore never overwrites (placement `exact`).
- `protect` warns when the repository root of a root lies outside it (memory shared with unprotected sessions).

#### 7.1.3 Plan unit [D46]
`$CC/plans/<slug>.md` and `<slug>-*.md`, where the slug is read from the transcripts' `slug` key. Live while any live session references the slug. Plans written inside the project (`plansDirectory`) fall under the Markdown policy (§8).

#### 7.1.4 Global stores [D21, D36]
- **Rotation of `$CC/history.jsonl`** runs only when no Claude process runs anywhere (process-table scan by executable ∪ registry ∪ leases). Lines whose `project` lies inside a root move to that root's `claude-history` unit; paste-cache entries referenced only by extracted lines move with them. Protocol (R7, D58), journaled (`journal.Record` fields `hold_size`, `pending`, `offset`, `new_base`); every offset is in the hold inode:
  1. Record (dev, ino, size S0) of `history.jsonl`; journal `prepared`.
  2. Hard-link it to `$CC/.precinto-hold-<op>`; journal `held` (`hold_size = S0`).
  3. Tail reconcile before the rename (D21): let S1 be the hold inode's size now (S1 ≥ S0). Filter `[0, S1)` once and commit one history generation per affected root with the extracted lines (successor of that root's newest history generation); journal `sealed` (`pending = S1`). Every extracted line of `[0, S1)` is sealed before anything is removed from `history.jsonl`.
  4. Write the kept lines of `[0, S1)` to a temporary (0600) and rename it over `history.jsonl`; journal `rewritten` (`offset = S1`, `new_base` = the new file's size).
  5. Tail loop on the hold inode (late appends through descriptors opened before the rename): read `[offset, EOF)`; if empty for 500 ms, stop. Otherwise journal `pending = EOF`, seal the extracted lines of that range as a successor generation, append its kept lines to `history.jsonl` with `O_APPEND` skipping lines already present byte-for-byte after `new_base` (line-union, so a re-run never appends a line twice), then journal `offset = pending`; repeat.
  6. Delete extracted paste-cache files (identity-checked) and the hold link; journal done.
  Recovery (keyless): `prepared` ⇒ remove a hold link that names the recorded inode, nothing else changed; `held` ⇒ redo from step 3 (a history generation committed but not journaled only duplicates lines, which merge-back's line-union absorbs); `sealed` ⇒ if `history.jsonl` is still the hold inode redo step 4, else the rename happened: journal `rewritten` with `offset = pending` and `new_base` = the length of the kept lines of `[0, pending)`; `rewritten` ⇒ resume step 5 from `offset` (re-processing `[offset, pending)` idempotently). `lock --end --all` ends sessions so that rotation can run.
  Lines and paste-cache entries already sealed into a logged generation of the root's history unit (keyed hashes in `state/gens/<unit-key>.lines.json`, valid only while every generation they rely on is logged) are not sealed again; they still leave `history.jsonl`, and a range with nothing new commits no generation [D89]. The rotation checks `policy.min_free` before step 2 (twice the extracted bytes plus their paste-cache entries on the capsule volume, the kept bytes on the home's volume) and before each tail range: below it nothing starts (no hold link, no record) and the unit reports `no-space` (`history_pending`). Kept lines longer than 64 KiB are appended with one `O_APPEND` write (`fsx.Dir.AppendRecord`), never skipped [D90].
- **Merge-back** at unlock (`policy.restore_history`): append the root's sealed lines not already present byte-for-byte, in timestamp order (idempotent; lines over 64 KiB too, in one write); restore their paste-cache entries; history generations stay logged. Below the floor (1.1 × the generations' bytes) nothing is staged or appended [D90].
- **Global vault** units (`usage-data/`, `feedback/drafts/`): sealed when no Claude process runs; restored only by `restore --global` after `unlock --global` [D36].
- Legacy `lastSessionFirstPrompt` and the old per-project history arrays in `~/.claude.json` (and its backups) for projects inside protected folders are reported by `doctor` (`claude-legacy`, counts only); scrubbing is deferred [D49].

#### 7.1.5 Launch, resume and retention
- Resume needs the transcript before `claude` starts (SessionStart is too late), so the wrapper restores before exec.
- Resume targets (HA23, IM13): `--resume <uuid>`/`-r <uuid>` → that sid wherever its capsule is; `--resume <path>.jsonl` → sid from the basename; `--resume <name>` → sessions of the cwd's project within budget; bare `-r`/`--resume` (picker) → project unit + recent sessions [D38]; `-c`/`--continue` → the newest session for the cwd whose ledger does not record its creation by an SDK entrypoint (the entrypoint of its start line with source `startup` or `clear` is `sdk-cli`, `sdk-ts` or `sdk-py`: Claude's interactive `--continue` reads the transcript's first entrypoint and skips those, and sessions whose first prompt was `/loop`; a unit whose newest generation records no creation — created in an earlier generation, continued by `claude -p -c`, forked or managed late — is kept), clamped like an explicit resume (which keeps it the newest), then the project unit, then the cwd's other recent sessions not created by an SDK entrypoint (`restore_recent`, within retention, after the project unit so that under the wrapper's stop-on-error their failure never stops it, with their own mtimes — a request's `MtimeNow` clamps explicit units only — so Claude orders them by their own times and the one it picks after a `/loop` session, which precinto cannot tell, is there), all before exec; `-p`/`--print` with `-c` → the newest session of any entrypoint [D102]; `restore_recent = 0` adds no recent selector (before exec or in the background) to any launch (the selectors' project dir is the realpath'd launch cwd and matches the manifest's `project_dir` exactly, D73); `--fork-session` → same restore; `attach|respawn <job>` → sid from the job record.
- Settings injection [D32]: managed launches add `--settings '{"idleCompaction":false,"awaySummaryEnabled":false,"precomputeCompactionEnabled":false}'` and `CLAUDE_CODE_ENABLE_AWAY_SUMMARY=0`; PlanLaunch adds them (the adapter, never the wrapper); when the user passed `--settings` precinto prints C9.settings and adds nothing. precinto writes into user repositories only with `protect --claude-settings`.
- Session id of a fresh launch [D107]: a managed launch that starts a new session (no resume, no fork) passes `--session-id <uuid>` (a new random version-4 UUID, right after precinto's `--settings`; the user's own `--session-id` is kept and used instead) and names it in `LaunchPlan.SessionID`, so the wrapper records it as the child's before exec and seals it after exit without hooks. The seal scope names no session: like a fork's, it is every session the child owns (`Scope.Procs`), so a session the child switches to (`/clear`, `/resume`) is sealed too, whether the hooks or the registry watch recorded it. No id is chosen for subcommands that start no session here (`agents`, `attach`, `auth`, `daemon`, `logs`, `rm`, `stop`, … and the passthrough verbs) nor with `--bg`/`--background`, `--exec`, `--desktop`, `--cloud`/`--remote`, `--environment`, `--teleport`, `--from-pr`, `--init-only`, `--no-session-persistence`.
- Retention [D14]: automatic restores skip sessions whose last activity is older than `cleanupPeriodDays − 2` days; an explicit resume restores them with mtime clamped to `now − 1 day` (the manifest keeps the original; an unchanged re-seal keeps the old generation) and prints C7.old. Capsules are never deleted at restore; a restored file deleted by Claude's sweep is not lost (I12).
- A session already open in another terminal (registry) → ask to open a copy with `--fork-session` (C7.twice). A SessionEnd whose transcript is missing while a capsule exists is a resume miss: the next prompt and `status` show C7.miss.
- `claude purge [path]` through the wrapper asks C7.purge first [D79]: yes runs `claude purge`, which deletes Claude's own copies only — precinto keeps every capsule (only `forget` and `prune`, with their typed confirmation, delete capsules, §11.7); no, the default, starts nothing (exit 3).

#### 7.1.6 Compaction and background writers
- Compaction appends to the same transcript; no special file handling. PreCompact is gated while locked (`auto` includes idle compaction). The `<sid>/precompact.json` sidecar belongs to the session unit.
- In-flight compaction: PreCompact allowed → `compact_begin`; cleared by PostCompact, SessionStart(`compact`), Stop, StopFailure, SessionEnd, the next prompt, registry idle, or process death (R20). Ending a session waits for it at most 5 min unless `--force`.
- Background/supervised sessions (`--bg`, agent view, daemon backend) are exempt from ending, stay gated, and are flagged in `status` [D25].

### 7.2 Codex per-root homes (`codex`) [D31, D44]
- **Managed only inside roots, only through the wrapper.** A folder manages Codex when `config.Root.Harnesses` lists `codex` [D72]: protect asks C10.consent when Codex is installed; `precinto run codex` asks it only when the folder does not list codex yet, and yes adds it (a strengthening edit, D48); no starts nothing (exit 3). `precinto run codex` (or the shell function) in root R runs Codex with `CODEX_HOME=<base>/homes/codex/<R>`, `CODEX_SQLITE_HOME=<same>` and `TMPDIR=<home>/precinto-tmp` (hook-output spills stay inside the sealed home). Outside roots Codex is unmanaged; the user's `~/.codex` is never sealed or modified except for `auth.json` (sync-back, and removal of logged-out credentials, D100).
- **Seeding** (`codex.PrepareHome`): create the home 0700; copy `config.toml` once from the user's home, removing `sqlite_home` and `log_dir`, and at every launch append the user's `[marketplaces.<name>]` and `[plugins."<id>"]` tables (in the table form Codex writes) whose entity the per-root config does not define in any form, verbatim, never changing a per-root value or trust entry (a per-root `plugins`/`marketplaces` defined as one inline table, or a user config that does not parse, adds nothing and fails nothing) [D99]; copy `auth.json` in when the user's copy is newer; symlink `plugins/` and `skills/` to the user's home — a real directory there (Codex made it while the user had none) is moved to `<home>.displaced/<name>-<UTC time>` (0700, never deleted; `doctor` reports it) and replaced by the link [D99]. `precinto codex sync-config --root DIR` re-seeds config explicitly (`Seed.ForceConfig`, keeping the per-root hook trust entries). After the child exits, `auth.json` is copied back atomically when newer and different. A logout is never undone [D100]: `<home>/.precinto-auth` records, for each user home the per-root home was synchronized with, the SHA-256 of the `auth.json` both held after their last synchronization (a launch with another `CODEX_HOME` adds its own entry and never erases or stands for another's); when one side's copy is missing while that pair has an entry, nothing is copied into that side, the other side's copy is removed when it still holds exactly the recorded credentials (a newer login is kept, and syncing resumes once both sides hold a copy), and the entry goes; without an entry (first sync of the pair) the side that has none gets a copy, as before. `auth.json` is synchronized only with a user home that exists: one that is not there (an unmounted `CODEX_HOME`, a renamed `~/.codex`) is no logout, and nothing is copied or removed.
- **Content set** = everything in the home except the never-touch list (`auth.json`, `config.toml`, `hooks.json`, `plugins/`, `skills/`, `cache/`, `packages/`, `models_cache.json`, `installation_id`, `version.json`, `.tmp/`, `tmp/`, `thread-writer-locks/`, `app-server-control/`, `log/`, `rollout-maintenance.lock`, `*-shm`, `.precinto-auth`) — fail-closed (HA24); `doctor` reports new top-level entries.
- **Snapshot generations** (R3, D42): a seal writes one `codex-home` manifest generation listing every content file `{rel, size, mtime, mode, sha256, blob, group}` and the blobs it references; each blob holds one file or one **SQLite group** (`*.sqlite` + `-wal` + `-journal`, read in one pass after liveness is confirmed). `-shm` is never sealed. A blob is reused when the receipt shows the file unchanged. Commit = rename of the manifest generation + directory fsync; plaintext is deleted only after commit. Precinto never opens Codex databases.
- **Restore** places exactly the newest snapshot, all-or-nothing through staging, before launch. Existing `-wal`/`-shm`/`-journal` files next to a database being placed are moved to quarantine, never deleted.
- **Divergence** (R12): content plaintext present without a receipt from the newest snapshot ⇒ `run codex` refuses (exit 4, C11.codex), seals the diverging plaintext as a separate `diverged` generation and deletes nothing; `precinto codex reconcile --root DIR --prefer capsule|plaintext` re-commits the preferred side as a successor and keeps the other side as a retained generation. New rollouts whose names do not collide MAY merge automatically; databases never do. The diverged generation sealed at a refused launch is never authoritative: restore uses the newest non-diverged snapshot and refuses (exit 4) while a newer diverged one exists. A stray `-wal`/`-journal` without its database is not divergence: it moves to quarantine when the database is placed. A home restored from the authoritative snapshot (its receipt names it) that Codex then changed in place — every session does: SQLite writes and checkpoints, appended rollouts — seals as that snapshot's `successor` (`partial` when receipt files are missing), never `diverged` [D86].
- **Passthrough and outside launches**: passthrough commands (`login`, `logout`, …) inside a root and every launch outside a root run on the user's own home, unmanaged. A session whose nearest codex ancestor is `codex app-server` registers as background (daemon-held: never signalled, live while it runs).
- **Liveness**: any process with an open descriptor under the home (writer and maintenance locks are checked through open descriptors, never by flocking them, HA17), a launch lease, or instability (§9).
- **Hooks** (optional, need Codex hook trust): gates per HOOKS-IO §3; Codex 0.154 runs them only when the home's `config.toml` enables a precinto plugin installed in its `plugins/cache` and every hook's `trusted_hash` equals the hash of its current declaration (HOOKS-IO §3.1). `codex.HooksTrusted` checks exactly that against the hashes of the shipped `codex.json` (pinned in `test/integration/testdata/codex-trust.sha256`): `precinto run codex` asks C9.codexplugin when the home, as Prepare will leave it, loads no precinto plugin, C9.codexmodified when trust entries hold other hashes (Codex 0.154 skips those hooks until reviewed; the question is conditional, since the launch does not know the Codex version), C9.codex when some hook is untrusted, and `doctor` reports the same states, a "modified" one as a warning only for a verified Codex version (or one it cannot tell) and as information for a Codex outside the verified versions; entries with other hashes that carry `trusted_content_hash`, which only Codex newer than 0.154 writes, are "unknown": nothing is asked [D98, D99]; the gate blocks a Codex session in a protected root that lists codex whose `CODEX_HOME` is not that root's home (C3.codexhome) [D72]; `doctor` flags homes used without a lease (`codex-outside-runs` = rollouts in a per-root home not covered by its codex-home receipt, with no launch lease, no open descriptor under the home and no queued Codex seal, while the folder is locked).
- **Unwrapped Codex** (IDE, `command codex`) in a protected folder writes to the user's own home (`~/.codex` or `CODEX_HOME`), which precinto never seals; it is gated only if precinto's hooks are trusted there. `doctor` and `status` count such rollouts (`codex-wrong-home`, C9.codexoutside): precinto reads only the `type` and `payload.cwd` fields of each rollout's first (`session_meta`) line, bounded to 64 KiB, never content (`codex.WrongHomeRollouts`; compressed or unreadable rollouts count as not checked); the fix is `precinto run codex` (§19).
- **Ending**: the wrapper sends Codex's quit keys through the PTY (Ctrl-C twice, wait 3 s), then SIGTERM, then SIGKILL, then resets the terminal (Codex 0.154 installs no SIGTERM handler, HA19).

### 7.3 Data-driven adapters (experimental) [D33]
`inventories/*.toml` (schema 1; `harness.Inventory`): bases with relocation env vars, content globs, never-touch/exclude globs, process matching by executable and argv regex (never by kernel name), lock specs (`flock` | `json-pid`), `open_fd_check`, partitioning, stop command, passthrough/direct argv lists, resume flags. Every non-built-in inventory ships `status = "experimental"`, is wrapper-only (no hooks), requires `--experimental`, and seals only through `precinto seal --dormant <id>` when no matching process runs, no lock is held, open-file checks pass and no `-wal`/`-shm` exists; no automatic restore in v0.2. Generic units are sealed to the global vault (their stores name no folder) and are restored only explicitly: `precinto restore --global [--harness H]` after `unlock --global`; restore requires a home registered in config. `verified_versions` is informational for experimental inventories (`doctor` warns when the installed version is outside it); it never enables or blocks sealing.

---

## 8. Markdown policy [D16, D17]

### 8.1 Candidates (per root)
- `md = "ledger"` (default): paths an agent wrote, from the hook ledger (PostToolUse `Write|Edit|MultiEdit|NotebookEdit`; Codex `apply_patch` `*** Add File:`, `*** Update File:`, `*** Move to:` resolved against the payload cwd) **and** from the session's own transcript at seal time (S6). Extensions `.md`, `.mdx`, `.markdown`.
- `md = "all"`: every such file under the root. `md = "off"`. Every note a restore placed is a candidate too, at the path its receipt records (conflict copies excepted): at its relpath it re-seals as unchanged; at a moved marker's location it is dropped as unchanged under the unit it was restored from, and once edited there it is sealed as a note of its new path [D83].

### 8.2 Never sealed
Git-tracked files (unless `include_tracked = true`); the default excludes (`README.md`, `CHANGELOG.md`, `LICENSE.md`, `CONTRIBUTING.md`, `SECURITY.md`, `CLAUDE.md`, `AGENTS.md`, `GEMINI.md`, `**/SKILL.md`, `.git/**`, `.claude/**`, `.codex/**`, `.cursor/**`, `.agents/**`, `.gemini/**`, `.github/**`, `node_modules/**`, `vendor/**`, `.venv/**`) plus `md_exclude`; symlinks and hard-linked files; files changed within the quiet window. The git check runs `git -c core.fsmonitor=false -c core.hooksPath=/dev/null ls-files -z --cached` with `GIT_CONFIG_NOSYSTEM=1`, `GIT_CONFIG_GLOBAL=/dev/null` and a minimal environment, once per repository per sweep, never on the hook path; any error means "tracked, never seal" (S21, IM22).

### 8.3 When
A note listed in a live session's ledger is live (I1) and is sealed when that session ends, or at the next sweep while the folder is locked. Notes are never sealed while any session in the root is busy [D17]: "busy" means busy at seal time, so notes of a root with a busy session are deferred; `busy_grace` is enforced by the daemon ending sessions (§12.6). `md_seal_on = "end"` seals notes only when their sessions end.

### 8.4 Seal
The capsule goes to the store (`capsules/md/<unit-key>/`). Then a text marker `<name>.md.precinto` (0600, O_EXCL, no ciphertext, no title) is written next to the note:
```
This note is sealed by precinto. Run `precinto unlock` in this folder to open it.
id: <unit-key>
```
Then the plaintext is deleted (identity-checked). `protect` offers (consent, default yes) to add `*.md.precinto` to `.git/info/exclude` of each repository under the root (local, never committed; the only repository file precinto writes besides markers and `--claude-settings`, D32). Losing a marker loses nothing.

### 8.5 Restore (at unlock)
For each logged `md` unit of the root: target = the location of a marker carrying that unit key, minus `.precinto`, when it lies inside the root and passes §11.2; otherwise the original relpath from the manifest, authenticated by the unit key (`HMAC(salt, md ‖ root ‖ relpath)` must equal the logged key) — then C11.restored is shown [D51]. A marker counts for a note only when it names the note's own file name; the marker at the authenticated relpath wins; two valid markers elsewhere are ambiguous and the note returns to its relpath; foreign markers are never removed. Existing different plaintext at the target ⇒ conflict copy `<name>.conflict-<YYYYMMDD-HHMM>.md` and C11.conflict; `precinto resolve`. The marker is removed after placement.

### 8.6 Notes
Re-seal follows lineage (§10.4): unchanged ⇒ delete plaintext, no new generation; descendant of the restored generation ⇒ successor; plaintext with no receipt ⇒ a fresh generation kept alongside, reported as a conflict (UX7). `doctor` warns when Spotlight indexes a root or a root is cloud-synced (S17). Bash-created notes are caught only with `md = "all"`.

---

## 9. Liveness [D18–D21, D25]

### 9.1 Process identity (R9, S14)
`ProcID = (pid, kernel start time in µs, boot id)` measured by precinto (darwin `kern.proc.pid` `p_starttime`, wall-clock µs; linux `/proc/<pid>/stat` field 22, µs since boot, + `boot_id`), compared by equality only, never computed as now − elapsed; a wall-clock step never changes a measured identity [D66]. Comparisons with harness wall times (registry `startedAt`) use `platform.StartTime`. The daemon never accepts a ProcID from a client: `register` and `gate` carry pids, which the daemon measures itself (and, for `register`, verifies the executable against the harness inventory). ProcIDs that precinto's own hook and wrapper processes measure and write to the ledger are liveness evidence only — a false entry can keep a unit live, never cause a signal or a key release. A zombie counts as exited. Claude's registry `procStart` is never parsed.

### 9.2 Evidence
A unit is **live** if any of the following holds (any read error, unknown schema or failed probe also means live):

| # | Evidence | Applies to |
|---|---|---|
| E1 | A ledger process whose current session is this unit is alive (an `end` record does not make it dead, R8; a process that moved to a newer session no longer owns the old one, D20) | sessions |
| E2 | A Claude registry file names the sid with a live pid whose start ≤ `startedAt` + 2 s (fallback: file mtime ≥ start); a malformed registry with a live pid makes that pid's cwd sessions live [D18] | Claude sessions |
| E3 | A launch lease on the unit is held (§9.3) | all |
| E4 | A Claude job record references the sid and is not verifiably stopped, or has an unknown schema [D25] | Claude sessions |
| E5 | Instability: a file's (dev, ino, size, mtime, ctime) or a directory listing changed between two observations ≥ `quiet_window` apart on the monotonic clock, or an mtime lies in the future (R16) | all |
| E6 | A process holds an open descriptor below the unit's directories (Codex home, Claude `$TMP/<P>/<sid>` tasks, generic) (HA9, R11) | all with directories |
| E7 | A harness process runs: anywhere (global stores, D21); with cwd in the root, its repository, or unknown (project units, D47) | global, project |
| E8 | A live session references this transcript (fork-context-ref, copied sessionId) or this plan slug (R21, D46) | sessions, plans |

E5 is skipped when the wrapper reaped the only known writer and no other evidence exists (R20).

### 9.3 Launch leases (R4)
Before restoring, the wrapper takes shared flocks on `state/leases/<unit-key>.lease` for every unit it restores (synchronous and background; units resolved from restore selectors are added before any of their plaintext is placed) and writes `{pid, start, root, child}`; it holds them until the child is reaped (in exec mode the descriptors are inherited). Sealers probe with a non-blocking exclusive flock and verify the path still names the probed inode; held or mismatched ⇒ live (`fsx.ProbeHeld`, the one probe; a missing lease file is not held). Lease files are never deleted. Each holder appends one JSON description line; a new holder that finds no other holder truncates them; Probe reports descriptions only while the lease is held. The lease descriptors are inherited by the child in PTY and direct mode too, so the lease outlives a wrapper that dies first. Acquire waits up to 2 s for the shared flock, so a prober's momentary exclusive try never fails a launch; read-only callers (doctor, status) may probe.

### 9.4 Stability observer [D63]
Stability is proven inside each sealing process: sweeps, seals and the queue worker start with no observations, so a unit seen for the first time is `unobserved` (weak). After its first decision pass a sweep or seal waits once for `quiet_window` (bounded by its context, its deadline and the sweep lock it holds; pending notes and history are primed before that pass) and decides those units again; files that kept their identity across both looks are stable. No wait when the only known writer was reaped (R20). `quiet_window` ≤ 0 means 120 s; `config.Validate` refuses values below 10 s. Run from a terminal (stdout a TTY, not `--quiet`), `seal` and `sweep` print one line just before that wait (`sweep.Options.OnQuietWait`), and their summary lists held units by kind and a short reason, indented under its line [D113].

### 9.5 Hold caps (S14)
A unit held live only by weak evidence (E5 mtime-only, E7 name-only, `unobserved`) while its folder is locked is listed in the sweep report and `PlaintextSummary` with the reason `hold-capped`, shown by `status` and `doctor`. The `hold_cap` (24 h) for unlocked folders needs a persistent observer and is deferred [D63].

### 9.6 Background sessions [D25]
Detected from registry kind/entrypoint and job records. They are never signalled, stay gated while locked, are live while their job record says running or is unreadable, and are flagged in `status`.

---

## 10. Sealing

### 10.1 Who seals
Sweeps seal only units whose folders are locked (units restored under a current grant stay until lock, R4); sessions are sealed when they end whatever the folder state. Keyless sweeps and seal workers only: the SessionEnd queue worker, wrapper exit, lock (the daemon spawns `precinto sweep --lock --root R`), the periodic service (darwin: `service install`, a LaunchAgent that runs only `precinto sweep --quiet`; the linux systemd unit is deferred [D49], so linux relies on the other triggers), and an opportunistic sweep spawned by SessionStart (sources `startup|resume` only, when `state/sweep.last` is older than 10 min and the sweep lock is free) (IM18). The SessionStart opportunistic sweep runs for any session, managed or not, when at least one folder is protected. Global stores are sealed by sweeps whenever the global vault is not unlocked. An explicit `precinto seal --root R` (without `--session`) seals every non-live unit of R whatever the folder state; sweeps seal only locked folders; the wrapper's seal after exit is scoped to its own sessions (`harness.Scope.Procs`, never the whole folder). Every process that seals takes its folders from config.toml merged strictest with the confirmed settings of `state/policy.pinned` (the defaults without a pin), the set the hooks gate with, plus, while the pin is missing or forged and a root vault exists, the folders vaults record, plus every folder a running agent reports in its status (it enforces the recorded folders too once a MAC failed at an unlock): a folder whose removal waits for its confirmation is still sealed; a config.toml that does not load never stops a seal (the stand-in settings of §16.1 are used and the error is reported after). A `--root DIR` (also the lock worker's) resolves against those folders only, so a retired vault's folder (D74) is "not inside a protected folder" and is never sealed, config.toml broken or not [D142].

### 10.2 Concurrency (R19)
- `state/locks/sweep.lock` is taken non-blocking; if busy, the caller touches `state/sweep.requested` and exits 0; the holder rescans once before exiting.
- Lock order is harness-global → root → unit, never acquired upward. Lock files are never deleted.
- At most two unit seals run in parallel; units over 1 GiB run alone.

### 10.3 Algorithm (per unit) [D13, D58, I3, I9]
Journal phases are completed milestones: a record is advanced to a phase only after the step it names has finished and is durable, and everything recovery needs to undo or finish the next step is journaled before that step starts (`journal.Advance` after the step; `journal.Save` for progress within a phase).
1. Take the unit lock; re-evaluate liveness (§9) and leases; check the recipients tripwire (§4.4); check free space for the capsule (plaintext size + floor, §17).
2. Plan: lstat walk of the unit (hazards — symlinks, FIFOs, sockets, devices, nlink > 1, unreadable — are reported and never followed or deleted); lineage (§10.4) against the receipt.
3. Unchanged (every file's SHA-256 equals the receipt) ⇒ no new generation: journal `prepared` and then `committed`, both naming the receipt's generation (already logged), and go to step 6. Otherwise reserve the next generation N (fsynced counter), take a ledger snapshot for the manifest (`ledger.Snapshot`, length n), and journal `prepared` with every snapshot (dev, ino, size, mtime_ns, ctime_ns), the temporary name and the final name `g<N>.pcap` — before anything is written.
4. Seal (`capsule.Seal`, this step only): pass 1 opens each file `O_RDONLY|O_NOFOLLOW|O_NONBLOCK`, requires fstat = snapshot and hashes it; pass 2 streams magic+zstd(tar) through age into the temporary, re-opening each file, requiring identical identity and re-hashing (mismatch ⇒ abort as live, exit 4); FullSync (`F_FULLFSYNC` on darwin); journal `tmp_written` (from `OnPhase(PhaseTmpWritten)`); decrypt the temporary with the in-memory ephemeral identity and compare manifest and every hash (exit 5 on mismatch); check header stanzas (§4.1); rename no-replace to `g<N>.pcap`; fsync the directory.
5. Append the capsule log entry (FullSync); then journal `committed` (rename and log entry both durable).
6. Delete originals: for each file re-check liveness (`live.Engine.StillQuiet`), unlink only if lstat still equals the snapshot and nlink = 1, keeping the descriptor open; fsync parent directories; remove emptied directories listed by the adapter; journal `unlinking` and save per-file progress.
7. After ≥ 1 s, fstat each kept descriptor: if a file grew, seal its current content through the descriptor as a successor ("rescue") generation, journaling `rescue` with that generation's temporary and final names before writing it.
8. Receipt and ledger: rewrite the receipt to the newest generation of this run (N, or the rescue generation) for every file still present as plaintext — remove-failed, changed after hashing, rescue sources — with identity and SHA-256 as sealed (marked `kept`, so status tells it from a restore's receipt, D110), and delete the receipt only when none remains, so a remove-failed unit later re-seals as unchanged without a new generation (R15). While the receipt stays, the files this seal deleted are kept in it as absent (generation N, no identity), with the absent entries of the previous receipt [D85]. `ledger.Archive(…, n)` then removes the ledger file, or keeps only the events appended after the snapshot (they go into the next generation, S13). Journal done.

### 10.4 Generations and lineage [D9, D10, D42]
- Receipts (§11.5, and step 8 above) record the identity and SHA-256 of each plaintext file whose origin precinto knows: placed by a restore, or left behind by a seal. At re-seal each file is classified against its receipt: unchanged; append-only successor (size ≥ receipt size and the first receipt-size bytes hash to the receipt value); new; changed (anything else); missing.
- Generation lineage: `fresh` (no receipt); `successor` (every receipt file present, each unchanged or append-only grown, or — for an exact-placement file precinto placed — rewritten in place, which supersedes it [D87]); `partial` (some receipt files missing, absent entries included [D85], the rest unchanged, appended or superseding); `diverged` (some other file changed, an absent file came back with other bytes, or plaintext appeared without a receipt while generations exist). Codex snapshots: see §7.2 [D86].
- A generation is never overwritten. Missing plaintext is never a deletion (I12).
- Layered kinds (all Claude kinds, `md`, generic) restore the newest generation plus, through non-successor links, files of older generations absent from newer ones. When two generations hold different versions of a path, the placement table (§11.3) decides with the newer version in the role of the existing file F and the older in the role of the capsule C (a linked JSONL fragment merges into C+F; a superset wins); if it reports a conflict, the newer version goes to the path and the older to `<name>.precinto-g<k><ext>` (reported) — except at an exact-placement path whose newer version a non-diverged generation holds: it supersedes the older one, no copy [D87]. Snapshot kinds (`codex-home`) restore exactly the newest snapshot.
- Retention: keep the last 3 generations, every generation needed by a layered restore of the newest, and every diverged generation until the user prunes [D9]. `claude-history` generations are never pruned (each holds lines no other generation holds, D89); only `forget` deletes them. Deletion only by `precinto prune`/`forget` [D15].

### 10.5 Crash recovery (keyless) [D58]
Run first by every sweep, seal and restore, and by the daemon at start (as a spawned worker). Quarantine (§11.1) runs only after recovery has processed every record and never touches a capsule named by a pending record, so precinto's own crash leftovers are never reported as forgeries. It moves a capsule of a unit directory only under that unit's lock (skipped while the lock is held), after reading the pending records and the log again: a seal committed by another process meanwhile stays [D82]. A seal unlinks plaintext only while its committed generation is still in the store.

| Last milestone | Recovery |
|---|---|
| `prepared`, `tmp_written` | delete the temporary; if the recorded `g<N>.pcap` is present and logged (a crash after the log append, before the milestone), continue as `committed`; if it is present and not logged (a crash between rename and log append), delete it — it cannot be re-verified because the ephemeral key is gone; plaintext untouched; seal again later under a new number (gaps are allowed) |
| `committed`, `unlinking` | require the recorded capsule to exist and to be logged (otherwise handle as `tmp_written`); resume identity-checked unlinks; files that changed stay for the next generation; finish step 8 |
| `rescue` | handle the rescue capsule as `tmp_written`, then seal what remains on disk in the next sweep |
| `staged` | roll forward: place remaining files (re-evaluating every target) |
| `placing` | roll forward from the first file not marked done |
| `held`, `sealed`, `rewritten` | resume the history protocol from the hold link and the journaled offsets (§7.1.4) |

### 10.6 Seal queue
SessionEnd enqueues `{harness, sid, reason, wait_for = PID:START, warm}` in `state/queue/` and spawns a detached `precinto seal --queue` worker (Setsid, stdio `/dev/null`). Reasons `clear|resume`: seal when the registry for that pid no longer names the sid and the unit is stable (HA16). Codex: the worker re-probes the unit (the adapter's open-descriptor and writer-lock evidence plus `wait_for`) with back-off until it is not live or ~6 h passed; there is no separate Codex poller (HA17). The daemon and the sweep-lock holder drain the queue; the daemon never exits while the queue or journal is non-empty. The wrapper queues the units it finds still held after exit one request per unit key, with the sid only when its seal scope names exactly one session [D107].

---

## 11. Provenance and restore

### 11.1 Provenance [D8, D39]
- Every committed capsule is appended to `state/capsules.log`: `{path, sha256, header_sha256, size, kind, harness, unit, vault_id, root_ids, gen, parent, lineage, sealed_at, recipients_fpr, files, bytes, last_activity}`.
- Restore and key release accept only capsules whose path and header SHA-256 match a live (not deleted) log entry. The header hash is a sufficient provenance key: a different payload under a copied header fails age authentication.
- Capsules without provenance are moved to `<base>/quarantine/` (after crash recovery, §10.5), listed by `status`/`doctor` (`quarantine`), never restored automatically; `precinto import` (TTY confirmation, shows targets) is deferred [D49]. Markers naming unlogged units are ignored.

### 11.2 Allowed targets (computed from trusted context) [D8] (S3)
The capsule log and the store path carry only the unit **key**; the unit **id** (sid, slug, project directory name, store name, blob id, relpath, partition id) exists only inside the ciphertext. For every kind the client therefore takes `unit_id` from the decrypted manifest and accepts it only if `harness.UnitKeyFor(salt, kind, harness, home id of the registered home, root id from config, unit_id)` equals the unit key of the log entry (§6.2); manifest `kind`, `vault_id`, `root_ids` and `unit_key` MUST also equal the log entry. Only then does it compute targets from (kind, harness, registered home, root from config, authenticated unit id) and require every manifest entry to fall inside them. Any mismatch rejects the whole capsule (exit 5) before any write; `harness.Adapter.Targets` receives only authenticated unit ids.

| Kind | Allowed `base:rel` |
|---|---|
| `claude-session` | `claude_config:projects/<P>/<sid>.jsonl` and its siblings (§7.1.1), `projects/<P>/<sid>/**`, `file-history/<sid>/**`, `session-env/<sid>/**`, `uploads/<sid>/**`, `dev-mods/<sid>/**`, `tasks/<sid>*`, `todos/<sid>*`, `debug/<sid>*`, `image-cache/<sid>/**`, `jobs/<id>/**` for one clean job-id component (the ledger records no job ids; placement never replaces an existing file), and every other path the §7.1.1 inventory seals for that sid, minus the deny-list, which is also checked by (dev, ino) of the first component; `claude_tmp:<P>/<sid>/**` — `<P>` must exist under `projects/` or be in the project index for that home (the index records `<P>` whenever a session is sealed and is never pruned while capsules reference it, so a deleted `projects/<P>` is recreated 0700); `<sid>` is the unit id and matches the UUID syntax |
| `claude-project` | `claude_config:projects/<P>/memory/**`, `projects/<P>/sessions-index.json`, non-sid files in `projects/<P>/`; `claude_cache:<P>/**` |
| `claude-plan` | `claude_config:plans/<slug>.md`, `plans/<slug>-*.md` |
| `claude-history` | `claude_config:history.jsonl` (line union only), `paste-cache/<entry>` for entries the lines reference |
| `global-store` | `claude_config:usage-data/**`, `feedback/drafts/**` |
| `codex-home`, `codex-blob` | `codex_home:<content-set path>` of that root's home only |
| `md` | `root:` exactly the target of §8.5; extension `.md`/`.mdx`/`.markdown`; not git-tracked; not under `.git/`, `.claude/`, `.codex/`, `.cursor/`, `.agents/`, `.vscode/`, `node_modules/` |

Comparisons are component-wise, case-insensitive on darwin, and are repeated against the (dev, ino) of existing deny-listed directories, so `.GIT/hooks` or an NFD `.git` cannot pass.

### 11.3 Placement table [D11] (R2, IM1)
Used for every file restored, and when applying older generations:

| Situation | Action |
|---|---|
| Target absent | no-replace rename from staging; on EEXIST re-evaluate |
| Existing file with equal SHA-256 | no-op (recorded in the receipt) |
| `jsonl-append`, existing F starts with capsule bytes C | keep F |
| `jsonl-append`, C starts with F (stale prefix) | replace F with C after re-checking F's identity |
| `jsonl-append`, F's first record's `parentUuid`/`logicalParentUuid` is a uuid of C and their uuids are disjoint ("classic fragment"; link facts from `claude.ScanLinks`, so `sweep` never parses Claude records) | write C + `"\n"` if C lacks a trailing newline + F to a temporary; swap it in only if F is unchanged and the unit is not live |
| `line-union` (history.jsonl) | append missing lines with `O_APPEND`; never rewrite |
| `sqlite-group` | place the whole group or nothing; an existing group without receipt is a conflict (§7.2); stray `-shm`/`-wal`/`-journal` moved to quarantine |
| Anything else | conflict: write the capsule version to `<name>.precinto-restored` (notes: `<name>.conflict-<ts>.md`), leave the existing file untouched, report it (`ls --conflicts`; `precinto merge`/`resolve` resolves, D11; `resolve --keep capsule` retains the other side as a diverged generation and seals the chosen one as the newest generation, outside the retained line [D88]) |
| The unit became live | abort the unit (exit 4); never merge into a live unit. Liveness is asked by the authenticated unit id and home recorded in the plan; decided before the first file whenever a target exists (a live unit is rolled back, nothing placed); a unit that turns live later keeps its record and staging for recovery's roll-forward, with no receipt yet [D84] |

### 11.4 Bases and file operations [D12] (S7)
Bases are realpath'd once at protect/integrate time and stored in config; below a base every component is opened relative to its parent descriptor with `O_NOFOLLOW|O_DIRECTORY`; every existing parent must be owned by the user and not group/other-writable — except a group-writable, not other-writable directory whose group is the user's primary group when that group is named like the user and `/etc/group` lists no other member (a user-private group, D67; anything undeterminable is unsafe); files are created `O_CREAT|O_EXCL|O_NOFOLLOW` 0600 and committed with renames relative to directory descriptors, followed by a directory fsync.

### 11.5 Restore algorithm (unit-atomic) [D12] (R6)
1. Under the unit lock: provenance check (§11.1); file keys from the daemon (§13.5).
2. Free space: need ≥ 1.1 × plaintext bytes + floor (`policy.min_free`, a fixed 2 GiB by default, §12.2 [D76]) on the target volume; otherwise skip the unit (lowest priority first) and report.
3. Decrypt the whole unit into a 0700 staging directory on the target's file system, validating every entry against §11.2 and §5 before writing anything; fsync; journal `staged` with the planned placements.
4. Place files per §11.3 (`<sid>.jsonl` last); create directories 0700; set mtimes (D14 clamp for explicit old resumes); journal per-file progress (`placing`).
5. Write the receipt `state/receipts/<unit-key>.json` (kind, harness, the absolute bases and, for `codex-home`, the rel → blob map; per file: base, rel, identity after placement, SHA-256, size, generation); remove staging; done.
A merged file (C+F) gets a receipt for C only, so its next seal is an append-only successor that seals F. Entries the restore leaves out (an unsafe base) or cannot place (a conflict without a copy name) are recorded in the receipt as absent [D85]. Entries of a base that exists but is unsafe now (`$TMP` not 0700/owned, S7; `harness.TargetRules.Skip`) are skipped and reported; the rest of the unit restores; the capsule keeps them.
A lock during a restore (R6, D58): the client destroys every file key at once (within 2 s of the event); a unit not yet staged is rolled back (staging removed, nothing placed); a unit that is `staged` or `placing` is rolled forward from staging, which needs no key, so no unit is ever left half placed; then the restore stops before the next unit.

### 11.6 What is restored when
- `precinto run`/`resume`: synchronously the targeted units (resume target, project unit, Codex home), then exec; then in the background the recent sessions newest first within `restore_recent = 5` and `restore_max_bytes = 1 GiB` [D38].
- After an unlock from any entry point, the daemon spawns a background `precinto restore --root R --recent N --md --history --background` worker, N = `restore_recent` (UX12).
- `precinto restore` restores explicitly; `--all` (key purpose `restore-all`) needs fresh presence from agent contexts and from peers without a controlling terminal [D28, D59]. With no selection flag it restores what an unlock restores (`restore_recent` sessions within `cleanupPeriodDays − 2`, the project unit, notes, and history when `restore_history`); `--recent 0` restores no session.

### 11.7 Retention [D14, D15, D59]
Capsules are kept until `prune`/`forget`; harness deletions (`claude purge`, `codex delete`, retention sweeps) are not mirrored. `prune` (except `--dry-run`) and `forget` list what they will delete, require typed confirmation on a TTY (C12.typed) and are refused in agent contexts and from processes without a controlling terminal (C12.agent); they log deletion records. `unprotect` deletes nothing [D74]: it restores everything of the folder, removes it from config.toml and roots.list, and keeps `vaults/<id>/` and every capsule; it keeps its typed confirmation and the agent refusal. protect of a path whose retired vault still exists (vault.toml `root_path` equal after realpath) reuses that id, so old capsules restore again.

---

## 12. Lock model

### 12.1 Two state machines (UX16)
- **Vault key state** per vault: `locked` | `unlocked` (idle deadline, absolute deadline). Every trigger leads to `locked` with the key wiped. No OS event ever unlocks (I6).
- **Session state** per live session: `running` (all its managed roots unlocked) | `paused` (some root locked: gated, overlaid when wrapped) | `ending`. User-facing words: "locked", "paused", "ended and sealed" [D50].

### 12.2 Defaults (`config.toml [policy]`)
| Key | Default | Notes |
|---|---|---|
| `idle_soft` | `15m` | human idle ⇒ lock |
| `idle_hard` | `60m` | ⇒ end paused sessions; `"0"` never; same origin as `idle_soft` |
| `max_unlock` | `8h` | absolute ⇒ lock [D24]; cap 24 h |
| `lock_on_screen_lock` | `true` | [D24] |
| `screen_lock_hard_after` | `15m` | continuous screen lock ⇒ end idle paused sessions [D24] |
| `busy_grace` | `30m` | busy turns may finish after a lock [D24] |
| `busy_timeout` | `10m` | no hook activity and registry not busy ⇒ not busy [D23] |
| `quiet_window` | `120s` | stability window (§9.4); one wait per sealing process [D63]; ≤ 0 means 120 s; values below 10 s are refused |
| `hold_cap` | `24h` | weak liveness holds reported (§9.5; deferred for unlocked folders, D63) |
| `restore_recent`, `restore_max_bytes` | `5`, `1 GiB` | [D38] |
| `min_free` | `"2GiB"` | free space every seal, restore and staging write leaves on its volume (§11.5, §17); a size with binary units (`"512MiB"`), at least `512MiB`, `0` = default; raising it applies at once, lowering it waits for a confirmed TTY unlock (D48) [D76] |
| `restore_history` | `true` | §7.1.4 |
| `per_root_auth` | `true` | false: `unlock` without `--root` unlocks every folder (one prompt each, D40) and folders share one idle clock |
| `unlock_on_prompt` | `false` | human prompts only [D26, D37]; flips to `true` once the hook-dialog E2E passes on the pinned Claude version (TESTPLAN E2E-8) [D60] |
| `on_enter` | `"prompt"` | [D29] |
| `md_seal_on` | `"lock"` | §8.3 |
| `clear_terminal_on_end`, `clear_scrollback_on_lock` | `true`, `true` | §12.7, [D30] |
| `prompt_rate_per_minute`, `prompt_backoff`, `hook_prompt_cooldown` | `3`, `30s`, `10m` | [D27]; `prompt_rate_per_minute` is at least 1: unlock prompts cannot be turned off (a lower value does not load, never wins a merge, and makes a pin forged) [D130] |

### 12.3 Idle clock [D23, D37, D54]
- Idle = now − last **human input** for the folder. Human input is: wrapper key and paste bytes after removing sequences terminals send on their own (focus, mouse, cursor reports, device attributes, kitty and OSC replies) (UX15); and UserPromptSubmit whose origin, computed by the daemon, is `human`.
- Prompt origin [D37] is computed only by the daemon, when it answers the UserPromptSubmit gate: wrapped session ⇒ `human` iff the verified wrapper reported an Enter keystroke reaching the PTY ≤ 3 s before the gate, else `automated`; unwrapped session ⇒ `human` iff the system HID idle at gate time is ≤ 5 s, `automated` if larger, `unknown` if HID idle cannot be read. The daemon records the origin for (sid, prompt id or turn id); a later `activity prompt` for that pair moves the idle clock only if the recorded origin was `human` (the record is consumed once and expires after `busy_timeout`). `unknown` and `automated` never move the idle clock and never raise an unlock dialog.
- Authentication of activity [D54]: `ipc.ActivityReq` carries no origin, and the daemon never trusts one from a client. `input` and `enter` are accepted only from a peer that runs the same executable (`ipc.Conn.PeerSameExecutable`) and whose measured ProcID equals the session's registered wrapper ProcID; anything else is dropped. A `register` with `wrapper = true` is accepted only from that wrapper itself (`wrapper_pid` = the peer's own pid); otherwise the session is registered as unwrapped.
- Stop, StopFailure, Interrupt and `Notification(idle_prompt)` clear busy and never move the idle clock. Input on the lock screen is never activity.
- Deadlines are evaluated against both wall and monotonic clocks; either expiring fires (IM15).

### 12.4 Busy [D23] (HA7)
Claude: registry `status == "busy"` and `waitingFor` empty (authoritative when present); otherwise hook-derived (prompt → Stop/StopFailure with matching prompt id), expiring after `busy_timeout`. Codex: UserPromptSubmit → Stop/Interrupt. Waiting on a permission or elicitation dialog counts as idle.

### 12.5 Triggers
| Trigger | Effect |
|---|---|
| `idle_soft` of human idle | lock the folder |
| `idle_hard` | end paused sessions (not background) |
| `max_unlock` | lock [D24]; 10 min before, notify (C8); `unlock --extend` takes fresh presence |
| Screen lock | lock every folder now; end idle paused sessions after `screen_lock_hard_after` of continuous screen lock; busy sessions after max(`screen_lock_hard_after`, `busy_grace`), never when either is 0 [D24, D62] |
| Sleep/wake (wall − monotonic jump > 30 s) | lock at detection (keys wiped at wake) [D24] |
| `precinto lock` | lock all folders (or `--root`) [D50]; gate everything immediately unless `--let-finish`; `--end` also ends sessions |
| Daemon start | every vault locked |
| Wrapper loses its subscription (2 s without heartbeat) | the wrapper shows its lock screen locally |

Screen-lock state comes from polling: darwin: screen locked = `IOConsoleLocked`, or the user's on-console session has `CGSSessionScreenIsLocked`, or every session of the user is off-console (fast user switching); `HIDIdleTime` every 3 s. linux: `loginctl` `LockedHint`; `IdleSinceHint` is trusted only while `IdleHint=yes`, else the origin is unknown. Headless Linux without logind: only idle timers and `max_unlock`; there HID idle is unreadable, so unwrapped prompts have origin `unknown` and never move the idle clock — only wrapper keystrokes keep a folder unlocked [D54].

### 12.6 Gating per session at lock time (UX2) [D24, D26]
| Session at lock time | Prompts (incl. automated) | Tools | Compaction | Permission dialogs |
|---|---|---|---|---|
| idle | block | deny | block | deny |
| busy | block | allow until Stop or `busy_grace` after the lock, then deny | allow in-turn until Stop | allow until Stop |
| any, manual lock without `--let-finish` | block | deny | block | deny |

Automated prompts are blocked like human ones and never raise an unlock dialog [D26].

**Ungated sessions** [D52, D57] (S4, S19) — no precinto hook event observed, or a host that cannot gate prompts — cannot be paused. Wrapped, they get the lock screen. Unwrapped ones never register and emit no hooks, so the daemon finds them itself: at every lock, and every `Tick` while a folder is locked, it scans the process table for processes whose executable matches a harness inventory (`MatchProcess`, never `p_comm`), whose cwd (`ProcTable.Cwd`) lies inside a locked root, and for whose ProcID no hook event or registration arrived within the hook-presence window (§14.4) since the process started. Matches feed the machine as `InUngated`:
- an interactive Claude session — its registry entry `sessions/<pid>.json` is readable, names that pid with a matching start, has kind interactive and entrypoint `cli`, and no job record marks it background — is **ended at lock** (§12.7 step 4);
- every other match (Codex, generic, unreadable or missing registry, unknown cwd, background/supervised) is **reported** in `status` (`ungated-session`, C9.ungated) and never signalled.

### 12.7 Lock procedure (R18) (I15)
1. Change state and wipe the vault key **immediately** — never deferred by UI, seals or restores; in-flight restores abort; clients destroy file keys on the event.
2. Publish the event (wrappers show the lock screen).
3. Spawn a keyless seal of the folder's non-live units.
4. Ending sessions [D57]: background sessions are exempt and never signalled [D25]; wrapped sessions get an `end` event and the wrapper terminates its own child — the PTY child, or the direct-mode child started with `Setsid` — and then that child's session (`platform.SignalGroup`: a session precinto created, never the user's); unwrapped Claude (registered, or found by the scan of §12.6): ProcID-verified SIGTERM, wait `max(8 s, SessionEnd budget + 6 s)` capped at 70 s, ProcID-verified SIGKILL, then SIGKILL of its ProcID-verified descendants found by walking PPIDs (`platform.Descendants`), never by session or process-group id — an unwrapped `claude` shares the user's terminal session (R11); wait for in-flight compaction ≤ 5 min unless `--force`; after a verified exit, scrub the controlling TTY when owned by the user (§15.4) and print C5.
5. Seal after exit (writer known exited ⇒ no quiet window when no other evidence).
A lock always completes, even if sealing fails; `status` lists unsealed units with reasons. Only processes the daemon measured at `register` (executable verified) or found itself in the §12.6 scan can be signalled; sessions bootstrapped from the ledger or known only from gates never are. `register`'s background flag is accepted only from same-executable peers, exempts the session from ending only, keeps it gated, and is flagged in `status`.

### 12.8 Unlock [D4, D27, D28, D37, D40]
- Always fresh user presence. Unlock is single-flight per vault: concurrent requesters wait for and share the result.
- Factor × context [D27]:

| Requester | Usable factors |
|---|---|
| Local terminal (wrapper, CLI, shell hook) with a GUI session | se, plugin, passphrase |
| tmux/screen detached, SSH (`$TMUX`, `$STY`, `$SSH_CONNECTION`, no graphic access) | passphrase, plugin with TTY PIN; no se (C2.nogui) |
| Harness hook (no TTY) | se with graphic access; plugin or passphrase through pinentry (`pinentry-mac`, `pinentry-gnome3`) when installed [D4]; never an osascript or TTY prompt |

- Hook-initiated unlock (UserPromptSubmit only): `unlock_on_prompt`, origin `human`, the folder locked, a GUI factor usable, the screen not locked, within the rate limits (3 per minute, 30 s back-off after a cancel, 10 min per-folder cooldown after a cancel in a hook), at most `UnlockWait` (60 s). Otherwise block with C3.blocked ("run precinto unlock").
- Before any dialog the user learns who asks [D60]: a requester with a TTY prints C2.se; a hook-raised dialog has no TTY, so the daemon first sends `OSC 9 ; <C2.hook> ST` (a desktop notification in terminals that support it, ignored by others) to the session's terminal — the TTY recorded at `register`, else the controlling terminal of the harness process, opened `O_WRONLY|O_NOCTTY` only if owned by the user — and then raises the dialog. pinentry and passphrase prompt texts are built by the daemon from verified data (peer executable, cwd, folder); the Secure Enclave dialog text belongs to age-plugin-se and cannot carry precinto's reason.
- Agent context [D28, D59] (env markers or a harness ancestor of the peer; the ancestry walk stops at the daemon, so its own workers never qualify): content-revealing operations (`restore`, `cat`, `open`, `ls` titles) need a fresh presence prompt even when the folder is unlocked; unlocking the folder of the session the agent runs in uses a GUI factor; unlocking any other folder is refused with C12.agent without a dialog; `init`, factor, recovery and `vault repair` operations and the destructive commands of §11.7 are refused (exit 3). A peer without a controlling terminal that is not a daemon worker (setsid, double fork, `env -i` defeat ancestry checks) is treated as an agent context for the explicit content-revealing purposes `restore-all`, `open`, `cat` and `list` (`ipc.Purpose*`) and for the refusals of §11.7; targeted restores (wrapper launch, the post-unlock restore worker) keep working without a terminal.
- A hook-raised unlock is tied to the human-origin gate the daemon answered for the same sid within `UnlockWait`. A peer without a controlling terminal (not a daemon worker) unlocking anything but its cwd's or session's folder gets C12.agent; a client claiming `tty=false` while it has one gets `no_ui`. Fresh presence for an agent-context key release is one terminal-less unwrap per vault (SE dialog or pinentry, after the OSC 9 notice); capsules of folders outside the session's are refused. The CLI passes the key purpose and its own `AgentMarkers` (`ipc.UnlockReq`/`KeysReq`; a self-restricting claim the daemon unions with what it measures, never proof of a human) and the daemon decides; the CLI calls `ui.AgentContext` only for the refusals of §11.7 and init/factor/recover/vault repair.
- In `-tags testing` builds the ancestry walk of `ui.AgentContext` and of the daemon's peer checks stops at the process named by `PRECINTO_TEST_ANCESTRY_STOP` (it and its ancestors are ignored; markers and the no-controlling-terminal rule still apply); production builds never read it [D64].
- Multi-folder: `unlock --all` lists the folders, requires typed confirmation on a TTY, then prompts once per folder [D40]. Without a TTY only the folder containing the requester's cwd can be unlocked. `precinto unlock` with no flag outside every folder, on a TTY: one locked folder → unlocks it; several → lists them and asks for a number (or all, with C2.confirmall).
- TTL is clamped to `min(max_unlock, 24 h)` (S8).
- A prompt refused by the rate limits [D27] is catalog text with the time left: C2.wait after a cancel or a wrong secret (the back-off, or the hook cooldown), C2.toomany for the per-minute limit, C2.promptsoff when `prompt_rate_per_minute` is 0 (prompts are off: it names the setting and what to change, never a wait; a defensive fallback only, since `prompt_rate_per_minute` must be at least 1 [D130]); after a cancelled or mistyped terminal unlock the CLI adds C2.retry with `prompt_backoff`. An unlock no prompt can serve (`no_ui`) is C2.nogui for a folder with a Secure Enclave factor, else C2.needtty (its passphrase or security key needs a terminal) [D120, D124].
- C2.ok quotes the policy in force (§12.8 policy pinning: `config.Strictest(config.toml, pin)`), never an unconfirmed weakening edit, and comes after the terminal review of pending edits (C13.review, then C13.confirm), with config.toml's values once they are confirmed; its count is an upper bound ("up to {n}") [D123]. The global vault's line is C2.okglobal: nothing is restored after a global unlock, and it names `precinto restore --global` [D150]. A confirmation is signed by a vault of the settings it confirms (one of their folders, or the global vault when they name none): when none is unlocked, the CLI asks to unlock one (C13.signer) on the connection that confirms; a cancelled or mistyped signer unlock is C2.cancelled or C2.badsecret naming the folder or "the global vault". The review names folders, never `roots[<id>]`. While the confirmed settings name no folder, the review of a folder's terminal unlock also names the folders whose vault is kept but that config.toml does not protect ("~/work/beta: no longer protected"), even when the agent lists nothing [D145]. `unprotect` reviews and confirms its own removal that way; only a confirmed removal (or one the agent holds nothing back for) prints "is no longer protected", otherwise it says the folder stays protected until a terminal unlock confirms the change and exits 3; an agent's refusal is printed as its own line. `unlock` names the folders the agent enforces, a folder whose removal waits included [D146].
- After unlock: MAC verification and tripwire copy (§4.4), capsule audit, background restore (§11.6).
- Policy pinning [D48, D55]: the daemon enforces the policy confirmed at the last TTY unlock and persists it in `state/policy.pinned` (`config.Pinned`: the confirmed configuration plus, for each vault unlocked at confirmation, `HMAC-SHA256(HKDF-SHA256(identity, "precinto/policy/v1"), config.Canonical(config))`). Edits that weaken protection (a root or harness removed, a timer raised, a trigger disabled, md narrowed, `unlock_on_prompt`/`on_enter` relaxed) stay pending until an interactive unlock shows the diff and the user confirms; strengthening edits apply at once. At start — including after an idle exit — the daemon enforces `config.Strictest(config.toml, pinned)`; when a vault listed in the pinned file is unlocked it verifies that vault's MAC, and a missing or bad MAC raises `policy-tampered` (C13.tampered), after which the compiled-in defaults also join the strictest merge until the next TTY confirmation rewrites the file. Hooks use the stricter of `config.toml` and `roots.list`. The first pin is written when the daemon creates the first root vault (`vault_create`), pinning the policy it enforces then (`Strictest(config.toml, defaults)`) with that vault's MAC [D68]; before any root vault exists a missing pin is the normal first-run state (no `policy-tampered`), afterwards it is tampering. A TTY unlock by a non-agent peer with a controlling terminal re-pins automatically only when `Diff(enforced, config.toml)` has nothing weakening; otherwise it shows the diff and needs `ConfirmDiff`; a forged pin is never re-pinned without confirmation. Once a root vault exists a pin that decodes is forged when it carries no MAC, a malformed one, one keyed by neither `global` nor a root of its settings, or one for a vault that does not exist, when its settings name folders but none of its MACs is keyed by one of them (a `global` MAC alone, checked only by `unlock --global`), or when its `prompt_rate_per_minute` is below 1 (`config.Pinned.CheckShape`, also doctor's rule) [D145, D130]. While the policy is tampered every folder a root vault records (`vault.toml` root_path) joins what the daemon enforces, until a confirmation [D145]. A pin of settings that name no folder carries only a `global` MAC, which only `unlock --global` and `recover` check: while one is confirmed, `status` (attention `unprotected-folders`) and `doctor` name the folders whose vault is kept but that nothing protects, with `precinto unlock --global` as the fix, and a folder's terminal unlock lists them in its review [D145]. A pin no listed vault's MAC verified in this daemon's lifetime (and not written by it) is re-pinned only with confirmation, the unlock then listing what config.toml weakens relative to the defaults; MACs cover `global` and the settings' roots only, a pin is never written without one nor with only a `global` MAC for settings that name folders, and re-pinning unchanged settings keeps the earlier MACs of vaults locked now [D91, D145].

### 12.9 Nested and multiple roots (UX18)
`protect` refuses a directory inside or containing a root unless the user confirms; the deepest root wins (sessions by start cwd, notes by path). A session tainted by several roots is gated while any of them is locked, and its capsules need all of them unlocked to restore. Unlocking a folder unlocks it in every terminal.

---

## 13. Agent daemon and protocol

### 13.1 Lifecycle
- Single per-user process, autostarted detached (Setsid, stdio → log, allowlisted env) by `unlock`, `run`, `resume`, `protect` and the hook unlock path — never by the hook fast path. It holds `run/agent.lock` (flock) for its lifetime and unlinks a stale socket only while holding it [D6].
- At start: every vault locked; the effective policy is the stricter of `config.toml` and `state/policy.pinned` (§12.8, D55); a recovery + full sweep worker is spawned; sessions are bootstrapped from the ledger and harness registries.
- Exits after 10 min with no unlocked vault, no subscriber, an empty queue and no pending journal (R19). `precinto agent --stop` stops it at once (its keys are wiped, so every folder locks; exit 0 when none runs; like `lock`, not refused in an agent context) [D129]; `precinto agent --restart` stops it and starts the new one detached through the autostart path, then returns (`--foreground`: in that terminal) [D141].
- The daemon never seals or restores in-process; it spawns `precinto sweep|seal|restore` workers from its own executable. Workers get the folder's absolute path (`--root DIR`; `--root` never takes an id): `sweep --lock --root DIR`, `restore --root DIR --recent N --md --history --background`.
- `service install` (darwin) installs a LaunchAgent that runs only `precinto sweep --quiet` every 10 minutes (background priority); it never holds keys. `init` offers it (default yes); `status` shows its heartbeat (`state/sweep.last`); `service install` checks it can read every root (TCC, §17) — that check runs in the terminal's context and can only warn; the LaunchAgent's own access shows in `status` through the heartbeat's inaccessible count. On linux the systemd user unit is deferred [D49]: `service install` exits 2 with a notice.

### 13.2 Socket and authentication [D6]
- `<base>/run/agent.sock` (darwin) or `$XDG_RUNTIME_DIR/precinto/agent.sock` (linux); directory 0700, owner-checked, no symlink; socket bound under umask 0177; path < 104 bytes (tests use a short `PRECINTO_RUNTIME_DIR`).
- The server checks the peer uid on every connection, and that the peer runs the same executable (dev+inode, `ipc.Conn.PeerSameExecutable`) for `keys`, `unlock`, `vault_create`, `factor_add`, `vault_repair` and `policy` confirmation, for `register` with `wrapper = true`, and for `activity` of kinds `input`/`enter` (whose peer must also be the session's registered wrapper, §12.3). On linux a hardened client is not dumpable either, so the server compares its `comm` with its own instead of the executable, after the uid check — best effort as well (§19) [D65].
- The client, before sending anything, checks the directory and requires the server pid's executable to be the same file as its own; on mismatch: "daemon identity mismatch; run precinto agent --restart". On linux a hardened daemon is not dumpable, so its `/proc/<pid>/exe` cannot be read: the client verifies the peer uid (`SO_PEERCRED`), that the peer pid holds the flock on `run/agent.lock` (`/proc/locks`, matched by inode) and its `comm` — best effort, which stops accidents and naive squatters but not a same-uid process that kills the daemon and binds the socket (§19) [D65].
- Frames: `uint32 length | kind ('J' JSON, 'S' secret) | payload`, ≤ 1 MiB. Secrets (passphrases, PINs, file keys) travel only in 'S' frames into locked buffers, never as JSON strings.

### 13.3 Operations (`ipc.Op`)
| Op | Request | Response | Authorization |
|---|---|---|---|
| `hello` | client kind, version | daemon version, pid, protocol | uid |
| `status` | – | vaults, sessions, attention, pending policy | uid |
| `gate` | harness, host, event, sid, prompt/turn id, cwd, project dir, paths, harness pid | verdict, reason, user/model messages, state, origin (computed and recorded by the daemon), unlock eligibility | uid; answered from an in-memory snapshot, never waits on disk or network I/O; to prove a human origin it may take one HID-idle sample bounded by 60 ms when the cached 3 s sample extrapolated cannot prove ≤ 5 s, otherwise the origin is unknown; the pid is re-measured asynchronously |
| `activity` | sid, kind, prompt/turn id (no origin) | ok (fire-and-forget) | uid; `input`/`enter` only from a same-executable peer whose ProcID is the session's registered wrapper (else dropped); `prompt` moves the idle clock only if the origin recorded at gate time was `human` [D54] |
| `register` / `unregister` | harness, sid, pid (daemon measures ProcID), cwd, roots, wrapper, wrapper pid, tty, config dir | ok | executable verified against the inventory; `wrapper = true` only from a same-executable peer whose pid is `wrapper_pid` |
| `unlock` | roots / all / global, factor, ttl, extend, tty, confirmed, deadline | unlocked vaults, deadline; relays `UIRequest`s | same executable; agent-context rules; rate limits |
| `lock` | roots / all, end, force, let_finish | locked, ended, unsealed | uid |
| `keys` | capsule paths, purpose (`ipc.Purpose*`) | grants + one 'S' frame per file key; denied map | same executable; logged; all roots unlocked; agent-context rules by purpose [D28, D59] |
| `subscribe` | roots, sid, wrapper | stream of events: first one `locked` or `unlocked` per subscribed folder, then `locked`, `unlocked`, `end` (only on the subscriptions of wrappers whose session the daemon ends, with SIDs when known [D71]), `expiring`, `heartbeat` each 1 s | uid |
| `vault_create` | root id, root path | ok (the new identity stays unlocked) | same executable |
| `factor_add` | factor spec | ok (needs every vault unlocked) | same executable; never from agent context |
| `vault_repair` | vault id, use recovery (+ one 'S' frame), confirmed (false = dry run: unwrap, genuineness check, diff, nothing written; then true on the same connection without a second presence prompt) | recipient/recovery changed, exposed capsules | same executable; TTY; never from agent context [D53] |
| `policy` | confirm | pending changes | same executable; TTY unlock flow; never from agent context |
| `shutdown` | – | ok (wipes keys) | uid |

### 13.4 Gate
The daemon computes the session's root set as ledger taint ∪ roots(project dir) ∪ roots(payload cwd) ∪ roots(paths) (HA10) and answers from the published snapshot; texts come from the message catalog. A Codex session in a root that manages Codex (its `harnesses` list names `codex`; an empty list means both built-ins) whose `CODEX_HOME` is not that root's home is blocked with C3.codexhome [D31, D72]; in a root that does not manage Codex the gate answers by lock state alone.

### 13.5 Key release [D39]
For each requested capsule: open it `O_NOFOLLOW` under `capsules/`; read the header; look up `(path, header_sha256)` in the capsule log; require every logged root unlocked; apply agent-context rules for the purpose; `Keyring.FileKey(vault, header)`; return the key in an 'S' frame. The daemon SHOULD also decrypt the manifest head and check its vault and unit against the log entry.

### 13.6 Errors
`ipc.Error{code, msg}`; codes map to exit codes (§16.2): `locked`, `unauthorized`, `agent_context`, `cancelled`, `no_ui`, `rate_limited`, `bad_secret` (wrong passphrase or recovery key; counts toward the prompt rate limit like a cancel, never a tamper alert) → 3; `live` → 4; `verify` (MAC, tripwire, repair check), `not_logged` → 5; `bad_request` → 2; others → 1.

---

## 14. Hooks [D22] — wire details in `docs/HOOKS-IO.md`

### 14.1 Rules
- `precinto hook <harness> <event>` reads the payload on stdin (≤ 64 MiB) and answers on the fast path in < 50 ms. It MUST NOT write stdin, prompts, tool I/O, summaries or environment values anywhere, including on errors (S11, S13). The allow path prints nothing.
- Gate events are declared with explicit timeouts and `onFailure: "block"` (Claude ≥ 2.1.295): UserPromptSubmit 90 s; PreToolUse, PreCompact, PermissionRequest 10 s. The hook enforces its own deadline below the timeout (UserPromptSubmit: unlock wait ≤ 60 s, decision by 85 s; others by 7 s) and always ends with a valid decision.
- For managed sessions every error path blocks/denies: daemon unreachable within 150 ms, decode failure, deadline, panic (recovered), missing or failed binary (shim: static block inside a `roots.list` root) (I5). Unmanaged paths fail open. The prompt text is C3.agentdown when the daemon is unreachable or untrusted, C3.failed for every other cause (HOOKS-IO §0.3).
- Exit-code contract [D43, D56]: Claude blocks with JSON on stdout and exit 0; Codex UserPromptSubmit, PreToolUse and PermissionRequest block with a fixed stderr reason and the binary's exit code 10, which the shim maps to 2; Codex PreCompact blocks with `{"continue":false,"stopReason":…}` and exit 0. The shim passes stdout through only on exit 0; any other exit of the binary (1, a Go runtime exit 2, a signal) is handled like a missing binary: stdout discarded, static block (D.shim) for gate events whose `$PWD` or `$CLAUDE_PROJECT_DIR` lies inside a root of `roots.list`, exit 0 otherwise. Block reasons never contain OS error text.
- Real-host detection [D56] (HOOKS-IO §0.7): other hosts' markers first, then Codex markers, then Claude markers; with no marker the host is the argv label, i.e. the hooks file that invoked the hook. A missing marker never makes a gate fail open; only an unrecognised label with no markers is "unknown", and its gate events inside a root fail closed. A Claude-format hook running inside Cursor, Copilot or Droid answers in that host's format or exits 0, de-duplicated per (host, session, event, prompt id) (HA21).
- Hook mode never honours `PRECINTO_*` overrides (hooks always run in an agent context; Claude settings `env` reaches them) [D6, D56].
- Host detection never lets another host's inherited variables override Claude's or Codex's markers: the `codex` label or `turn_id` ⇒ Codex, Claude's markers with a PascalCase payload ⇒ Claude, other hosts' variables only break ties, by exact name (HOOKS-IO §0.7) [D92]. Root matching treats both Unicode normalizations of a non-ASCII root as the same folder (identity of the existing ancestors, darwin) and `roots.list` carries the stored spelling for the shim [D93].

### 14.2 Actions per event
| Event | Action |
|---|---|
| SessionStart (all sources) | ledger facts (taint if managed); `register` if the daemon runs; in a locked folder, or when the daemon is unreachable for a managed session, Claude returns additionalContext (C3.start.model) — Codex outputs nothing in v0.2 (HOOKS-IO §3.4); `source=compact` ⇒ compaction ended; spawn an opportunistic sweep (§10.1). Never blocks, never prompts. |
| UserPromptSubmit | managed ⇒ `gate` (origin per D37); locked ⇒ optional GUI unlock (§12.8) else block with C3.blocked and `suppressOriginalPrompt`; allowed ⇒ `activity prompt` |
| PreToolUse | ledger touch for paths in roots (taint); managed and locked (per §12.6) ⇒ deny with C3.tooldenied (model text) and C3.stop (stopReason) |
| PermissionRequest | locked ⇒ deny |
| PostToolUse (Claude matcher `Write\|Edit\|MultiEdit\|NotebookEdit`; Codex `apply_patch\|Edit\|Write`) | ledger `md` for Markdown paths in roots; `activity tool` |
| PreCompact | locked ⇒ block with C3.compact as the reason (HOOKS-IO §2.4, §3.4); else `compact_begin` |
| PostCompact | `compact_end` |
| Stop, StopFailure (async), Interrupt (Codex) | `activity stop` (clears busy, never resets idle) |
| Notification(`idle_prompt`) (async) | `activity idle_prompt` |
| CwdChanged, DirectoryAdded | ledger cwd/dir (taint) |
| SessionEnd | ledger end; enqueue a seal request and spawn the detached worker (claude-code and codex only: other hosts are gate-only); return immediately |

### 14.3 Taint (S6, HA10)
A session becomes managed — sticky for its lifetime — when its start cwd, `CLAUDE_PROJECT_DIR`, payload cwd, an added directory, or any tool path lies inside a root. The ledger file is created at the first managed event; unmanaged sessions leave no ledger. The first managed contact of a session with no ledger appends a start event with an empty source. Hook roots are config.toml ∪ the pinned policy ∪ roots.list (`config.Strictest`); a folder listed only in roots.list gates (fails closed) but gets no taint (no id).

### 14.4 Hook presence (UX10)
The wrapper registers each session before exec; HooksSeen is tracked for every plan with a hook check; if no hook event arrives (Claude: SessionStart within 10 s; Codex: UserPromptSubmit within 5 s of the first Enter) the session is marked ungated and, for a managed claude-code session only (an unmanaged one leaves no ledger, so its hooks are never seen), C9.claude is printed at exit — it makes no claim about the seal, the C6 line does; the wrapper reads hook presence before the seal after exit, because sealing a session moves its ledger, `hooks_seen` included, into the capsule (S13) [D108]; `status` shows hook health per harness. The same windows define "no hook event" for the daemon's scan of unregistered processes (§12.6). `doctor` checks Codex trust entries read-only, against the hashes of the shipped hook declarations, and that the home loads precinto's plugin [D98, D99].

---

## 15. Wrapper and shell integration

### 15.1 `precinto run [--harness H] [--no-pty] -- CMD [ARGS…]`
0. The CLI keeps CMD as named: a relative path is made absolute against the working directory, and a bare name that is not the harness's own (its id, the file name of `[harness.<id>].bin`, or a name its inventory recognises; `--harness` names the harness of another command) is resolved through PATH, so the adapter never swaps it for `[harness.<id>].bin`; a command that is not installed exits 127 unstarted [D125, D126].
1. Plan (adapter): mode, roots, resume target, units to restore, argv/env additions, confirmation prompts.
2. Passthrough mode (`update`, `login`, `--version`, … from the inventory; for Claude also `daemon`, alone or after only `--dangerously-skip-permissions`/`--allow-dangerously-skip-permissions`, because Claude runs that subcommand only when no other flag comes ahead of it, so an injected `--settings` would start a session instead [D101]) ⇒ no gate, no restore (UX14): the child runs in the wrapper's process group (not exec), with `PRECINTO_ACTIVE=1` and the plan's env, SIGTERM forwarded, and its exit code returned. Unmanaged launches (no folder) skip unlock, daemon, registration and D32; a session managed later by touch gets no lock screen (hooks still gate it; §19).
3. Confirm if required (`--bare` in a protected folder: C9.bare; `claude purge`).
4. Unlock the plan's folders in this terminal if locked (§12.8), then subscribe right away, before Prepare, the lease and the restore: a lock or subscription loss before exec refuses the launch (exit 3, C1.notify).
5. `Prepare` (Codex home seeding); take the launch lease (§9.3); restore synchronous units (§11.6).
6. Start the child with `PRECINTO_ACTIVE=1`: PTY proxy when stdin and stdout are terminals and the mode is interactive (the PTY child leads a new session); otherwise direct (still gated and sealed: `-p`, `--output-format`, `codex exec`, pipes), started with `Setsid` so it leads its own session too, with SIGINT, SIGQUIT, SIGTERM and SIGHUP forwarded by the wrapper [D57]. Record the launch (`Backend.RecordLaunch`: ledger `launch` event when the sid is known — a resume target, or the id PlanLaunch chose for a fresh launch, D107), follow while the child runs the sessions its own entry of Claude's live-session registry names (`Backend.WatchSessions`: each new one gets a launch event of the child, and a resume's seal scope, which names its target, takes them and the ledger's newest sessions of the child too, D107), register itself as the wrapper (`wrapper = true`, `wrapper_pid` = its own pid, the session TTY), start background restore.
7. While running: filtered human input → `activity input`/`enter` (rate-limited; accepted by the daemon only from this verified wrapper peer, D54); lock → lock screen; unlock → replay; `end` → terminate (Codex quit keys first, then SIGTERM/SIGKILL of the child and of the child's own session), reset the terminal, print C5.
8. Job control: when the child stops, restore the outer terminal and stop the wrapper; on SIGCONT re-enter raw mode, continue the child, repaint.
9. On exit: reset the terminal (cleared only when precinto ended the session), `Finish` (Codex `auth.json` sync-back), release the lease, read hook presence (§14.4), seal (or queue) the session — when restores placed units under the lease and a folder of the plan is locked now, spawn a keyless `precinto sweep --root DIR --quiet` [D110] — and print at most one C6 line, which says "sealed" only when the seal summary counts sealed files [D108]: C6.ok while the folder stays unlocked, C6.sealed when precinto ended the session (after C5) or a folder is locked at exit, C6.deferred, C6.failed, or C6.none (naming `precinto seal --adopt --root DIR`, the folder as one shell word) when nothing was found and Claude's hooks did not run. No C6 line is printed for an unmanaged launch, nor when the hooks ran and the seal found nothing (a session that wrote nothing, or one its SessionEnd hook already queued, §10.6). The session the C6 line names, and C5's `claude --resume` hint, is the newest of the child's sessions — the ledger's newest before the seal (D20), then those the wrapper recorded — that the seal found a unit of, so after `/clear` it is the session the child ran last; without one it is the launch's resume target, else C5 suggests `claude --continue` [D107]. Return the child's exit code. A launch that never started returns `wrapper.ExitNotStarted` with the reason, which the CLI maps with §16.2; when it is refused after its pre-exec restore placed units (a lock, a lost subscription, a command that cannot start), the release of its lease spawns the same `precinto sweep --root DIR --quiet` for the plan's folders locked by then [D147].

### 15.2 Lock screen [D30, D60] (UX3, IM16)
From the child's start the wrapper records **all** child output in a bounded ring (`ScrollbackBytes`, 8 MiB, wrapper memory only, wiped at exit) while tracking terminal modes — not only output produced while locked, because the lock clears screen and scrollback and an inline-mode TUI (Claude's default mode) never repaints finished messages.
On lock: stop forwarding input (keys are dropped, not queued); keep recording output; clear screen and, with `clear_scrollback_on_lock`, scrollback; draw the overlay (C4) on the alternate screen unless the child already uses it. Keys on the overlay: Enter unlocks in this terminal, Ctrl-D ends the session and seals it. C4.line shows the folder and the lock reason ("~/work/acme · locked by you") [D112]; while the session ends, C4.ending makes no claim about the seal, which the C6 line after exit reports [D108].
On unlock: clear the overlay and the screen, replay the ring from its safe boundary (`Scrollback.Bytes`: every byte since start, or after the ring wrapped the first line start after the oldest kept byte, preceded by an SGR reset), restore tracked modes (1049/1047/47, 1000–1006, 2004, 1004, 25, kitty flags), and force a repaint by resizing to cols−1 then cols 50 ms apart. The expected screen after unlock is the pre-lock screen plus whatever the child printed while locked; when the ring wrapped (`Scrollback.Wrapped`), only its tail is replayed before the repaint, and older output is not shown again (it remains in the session; §19). Full-screen TUIs redraw from the repaint alone.
When the child uses the alternate screen, lock leaves it, clears the main screen and scrollback and draws the overlay on a fresh alternate screen; unlock restores the child's alternate screen. The replay filter drops queries and side effects (DA, DSR/CPR, kitty query/push/pop, DECRQM, XTVERSION, window ops, media copy, OSC colour queries, clipboard, notifications, iTerm2 commands, DCS, APC, BEL, ENQ); kitty flags are restored once from the tracked modes.

### 15.3 Subscription loss
2 s without a heartbeat ⇒ the wrapper shows its lock screen locally (reason: the precinto agent stopped responding) and reconnects with back-off; it unlocks only on an `unlocked` event — every subscription starts with one `locked` or `unlocked` event per subscribed folder, so a reconnect to an unlocked folder needs no new presence prompt. The wrapper ends its child on any `end` event naming one of its folders, even while its own sid is still unknown [D71].

### 15.4 Terminal reset sequence (UX13)
`ESC[?1049l ESC[?1000l ESC[?1002l ESC[?1003l ESC[?1006l ESC[?2004l ESC[?1004l ESC[<99u ESC[>4;0m ESC[?25h ESC[r ESC[0m`, then with `clear_terminal_on_end` `ESC[H ESC[2J ESC[3J` (+ `OSC 1337;ClearScrollback ST` on iTerm2), then `stty sane` (darwin `-f`, linux `-F`), then the banner. The wrapper also restores its saved termios. The daemon applies the same sequence to the controlling TTY of an unwrapped harness after a verified exit, opening it `O_WRONLY|O_NOCTTY` only if owned by the user.

### 15.5 Shell integration [D29] (UX19)
`precinto shell-init zsh|bash|fish` prints: wrapper functions for enabled harnesses (`claude`, `codex`, …) calling `command precinto run --harness H -- H "$@"` unless `PRECINTO_ACTIVE` is set; and a folder-entry hook (zsh `chpwd`+`precmd`, bash `PROMPT_COMMAND`, fish `--on-variable PWD` plus a first run) that runs `precinto shell-hook` only in interactive top-level shells, never when `VSCODE_RESOLVING_ENVIRONMENT` is set, only on outside→inside transitions or the first prompt of a shell started inside, at most once per shell per lock epoch (`_PRECINTO_SKIP=<root>:<epoch>`), with a ≤ 150 ms daemon query that never reads the TTY. With `on_enter = "prompt"`: print C1.prompt (naming the folder's first usable factor, `ui.FactorName`; C1.prompt.plain when none is known); Enter unlocks (single-flight across terminals: others print C1.elsewhere), any other key or Ctrl-C skips. `notify` prints C1.notify. Top-level = not a subshell and not inside a precinto-wrapped harness (`PRECINTO_ACTIVE`); `SHLVL` is not used. `--install` appends exactly `shellinit.InstallLine` (`eval "$(precinto shell-init zsh|bash)"` or `precinto shell-init fish | source`) to the rc file once, only after consent.
Protocol [D69]: `precinto shell-hook` prints `shellinit.EnterResult.Lines()` and nothing else — `key=value` lines `action`, `root`, `epoch`, `path`, `folder`, `message`, values stripped of control characters — and never prompts. The scripts parse them without `eval`, print the message, set `_PRECINTO_SKIP="$root:$epoch"`, and for `action=prompt` read one key only when stdin and stdout are terminals; on Enter they run `command precinto unlock --root "$path"`.

---

## 16. CLI

### 16.1 Commands
```
precinto init [--factor se|passphrase|plugin:<recipient>]… [--identity-stub FILE] [--presence POLICY | --no-presence-ack] [--recovery-out FILE] [--show-recovery]
precinto factor list | add NAME [--identity-stub FILE] [--presence POLICY | --no-presence-ack] | remove NAME | test NAME | repin NAME
precinto vault repair --root DIR | --global [--recovery]   # TTY only, never from an agent (D53)
precinto protect DIR [--md ledger|all|off] [--on-enter prompt|notify|off] [--harness LIST] [--claude-settings]
precinto unprotect DIR                          # restores everything of the folder first (needs unlock; typed confirmation, D59); keeps the vault and capsules (D74)
precinto status [--json] [--check]
precinto unlock [--root DIR | --all | --global] [--for DUR] [--factor NAME] [--extend]
precinto lock   [--root DIR | --all] [--end | --hard] [--force] [--let-finish]     # default scope: all [D50]; never depends on config.toml without --root [D121]
precinto seal   [--harness H] [--session ID] [--root DIR] [--wait-pid PID:START] [--queue] [--adopt] [--dry-run] [--dormant H --experimental]
precinto sweep  [--root DIR] [--lock] [--wait] [--dry-run] [--quiet]
precinto restore [--root DIR] [--session ID] [--recent N] [--all] [--md] [--history] [--global] [--background]
precinto resume [ID | --last | --pick] [--harness claude-code]
precinto run    [--harness H] [--no-pty] -- CMD [ARGS…]
precinto ls     [--root DIR] [--conflicts] [--json]
precinto open FILE.md.precinto… | precinto cat FILE.md.precinto [--raw] [--to FILE]
precinto resolve FILE [--keep capsule|plaintext]        # alias: precinto merge (D11)
precinto forget FILE|UNIT                       # typed confirmation (D59)
precinto prune  [--unit KEY] [--keep N] [--diverged] [--dry-run]   # typed confirmation unless --dry-run (D59)
precinto codex reconcile --root DIR --prefer capsule|plaintext | precinto codex sync-config --root DIR
precinto agent  [--foreground] [--restart] | precinto agent --stop
precinto service install|uninstall|status      # darwin LaunchAgent; linux deferred (D49)
precinto shell-init zsh|bash|fish [--install]
precinto integrate HARNESS [--print] [--experimental]
precinto doctor [--leaks] [--json] [HARNESS]
precinto recover --verify | precinto recover [--key-file FILE --insecure-key-file]
precinto version
precinto hook HARNESS EVENT | precinto shell-hook …    # internal entry points
```
Deferred [D49]: `canary`, `scrub`, `rekey`, `import` (exit 2 with a notice). `seal` never needs a key. `cat` writes plaintext only to a TTY (sanitized of C0/C1 controls except `\n`/`\t`; `--raw` overrides) or `--to FILE` (S17); `cat --to`, `open` and `restore --all` count a caller without a controlling terminal as an agent context [D59]. `init`, `factor`, `recover`, `vault repair`, `prune`, `forget` and `unprotect` are refused in agent contexts (C12.agent / B.refuse); the last three, `vault repair`, `factor repin` and `unlock --all` require typed confirmation on a TTY (C12.typed, C14.confirm, C2.confirmall).
- `factor remove` runs in the CLI (no key needed) after a y/N confirmation, refused in agent contexts; the recovery factor and the last interactive factor cannot be removed. `factor test NAME` unwraps with that factor and verifies, then drops it (`ipc.UnlockReq.Test`: no grant, no restore worker, no policy re-pin). `factor repin NAME` re-pins a plugin binary (§4.3, D75).
- `cat` without a TTY and without `--to`: exit 2, nothing done.
- `protect --claude-settings` merges precinto's keys into `DIR/.claude/settings.local.json` (never committed), keeping every other key; `unprotect` removes the keys whose values precinto wrote. `unprotect` keeps `vaults/<id>/` and every capsule (D74).
- `lock` with no daemon running exits 0 ("every folder is locked": a daemon starts locked).
- `seal --dry-run` and `sweep --dry-run` say what a seal would do ("would seal N unit(s) …; nothing was sealed"), never "sealed" [D150].
- config.toml edits (protect, unprotect, integrate, the Codex consent, a seal's home registration) apply their own change to config.toml as it is on disk under the config lock, and write roots.list with the folders of the confirmed settings too [D143, D144]. `status` lists and scans config.toml's folders, the confirmed settings' and the agent's; `unlock` and `lock --root` name folders from config.toml and the confirmed settings; `seal` and `sweep` (`--root` included) take the agent's folders as well [D142, D146].
- `restore` with no selection flag restores what an unlock restores (§11.6); `restore --global [--harness H]` restores global and generic units after `unlock --global` (§7.3).
- `recover --verify` records `recovery_verified_at` (§4.7); a key that is not the installation's is B.recovery.wrong (exit 3), never an unlock message [D127].
- A `config.toml` that does not load names the file, the line where precinto finds the key, the key and the reason (`config.Load`: e.g. `config.toml line 4, policy.min_free: size "2GB" (use e.g. "512MiB" or "2GiB")`; an unknown key `config.toml line 3, policy.idle_sotf: unknown key (did you mean idle_soft?)`, or "check its spelling" when no key is near; a value Validate refuses `config.toml line 3: policy.idle_soft must be positive`). `lock` without `--root` still locks every folder and reports the error, and `seal`, `sweep` and the agent's lock workers still seal, with the stand-in settings below, reporting the error after the seal; restores and edits refuse [D142]. Settings stand in for the file: the confirmed settings (`state/policy.pinned`), else the defaults, with the folders the agent enforces as §10.1 finds them — the confirmed settings' folders, every folder whose vault records its path (`vault.toml` `root_path`) only while the pin is missing or forged, and the folders a running agent reports — so a retired vault's folder (D74) is never among them [D142]; a path config.toml could not hold (a control character) is left out, and every path the CLI prints is escaped [D149]. `status` shows the `config` attention item, scans the folders with an engine built from the stand-in settings, says how the counts were found ("found with the settings confirmed last") and marks them incomplete; `doctor` reports its `config` finding, runs the other checks with the stand-in settings and never calls a folder check ok then (it is info, "checked without config.toml") [D121].
- `run`: a harness that is not installed (not in PATH, also when found while the launch is planned) is exit 127 with one line naming it; a command named with `--harness` is the command run, never replaced by the configured `[harness.<id>].bin` (a bare name is looked up in PATH, a relative path made absolute), unless it is the harness's own name: its id, the file name of `[harness.<id>].bin`, or a name its inventory recognises (`exe_basenames`, `argv_regex`), which the adapter resolves to the configured binary [D125, D126].
- Help: every flag a command takes is in its usage line, flags show their value names, and no user-facing text (summaries, flag help, the CLI's texts, doctor's findings) carries an internal decision id [D127].
- `doctor` runs `$SHELL -lc true` only when a per-root Codex home exists (HA6); it scans `.claude/settings*.json` of the folder and of its subdirectories up to depth 4 (skipping `.git`, `node_modules`, `vendor`). `doctor --json` prints the findings as JSON (`doctor.Render`).

### 16.2 Exit codes
0 ok, 1 error, 2 usage, 3 locked/unauthorized/cancelled/agent context/wrong passphrase or recovery key (`bad_secret`), 4 live (refused to touch live data, or a Codex conflict), 5 verification failed (MAC, tripwire, header, provenance). `precinto run` returns the child's code once the child started; a launch refused before start maps its reason with this table (126/127 when the executable cannot run). `doctor`: 0 with no failing finding, 1 when any finding fails (warnings do not change it), 2 usage (`doctor.Worst`). `sweep` exits 0 when units are live; `seal` of named units that are live exits 4. A restore that meets a capsule of a Claude home config does not register exits 1 with E.unregistered [D109]; units the free-space floor refused exit 1 with one line naming the space needed and `min_free` [D111].

### 16.3 Messages
All user-visible text comes from the catalog in `internal/ui` (IDs `C1…C14`, `B`, `D`); the normative English text of each message is the comment of its `ui.MsgID` constant (docs/API.md, `internal/ui`), and `ui.Format` renders it from a table a unit test keeps identical to those comments. Two texts are also frozen outside `ui`, because their writers cannot depend on it at run time, and tests assert they are byte-identical to the catalog: the note marker (C11.marker, written by `sweep.MarkerText`) and the shims' static block (D.shim, embedded in the byte-frozen shims, D41). Rules: name the folder and the next command; never include prompt text, titles or file content; text addressed to the model is imperative and identical across harnesses. Scope [D70]: the catalog holds every text shown by hooks, the wrapper, shell integration and the daemon (relayed prompts, OSC 9 notices), every prompt another component or a test waits for (`B.passphrase.*`, `B.recovery.*`, `B.service`, and `C13.confirm`, the confirmation unlock and protect ask after listing pending policy edits), and every refusal (C12, `B.refuse`, `E.*`). The CLI's usage errors and command summaries live in `cmd/precinto/text.go` and doctor's findings in `internal/doctor/text.go` under the same rules (never root/grant/soft/hard outside `--root`), each enforced by its owner's test.

### 16.4 `status`
Human output: vault line (factors, recovery tested), agent line (pid, background re-seal, screen-lock watch), FOLDERS (state, idle and absolute deadlines, sessions running/working/paused/restored/sealed/ungated, unencrypted files and bytes by reason: running, restored, notes, history pending, deferred, inaccessible, remove-failed (plaintext a committed seal kept; a restore's plaintext waiting for a sweep of its locked folder is deferred, D110), hold-capped, adopted (sessions only `seal --adopt` seals, D113), disk full (sealing would go below `min_free`, D111)), AGENTS (version, hook health, wrapper installed), NEEDS ATTENTION. Attention items and `doctor` findings share one kebab-case code vocabulary (`ipc.Attn*`, reused by `doctor.Check*`: `unsealed`, `hold-capped`, `history-pending`, `pending-policy`, `policy-tampered`, `quarantine`, `recovery-tested`, `unhardened-build`, `codex-hooks-trust`, `codex-wrong-home`, `conflict`, `ungated-session`, `vault-tampered`, `exposed-capsules`; doctor-only: `config`, `permissions`, `agent-socket`, `interrupted`, `plugin-pin`, `experimental-version`, `unprotected-folders`, …), each with the fixing command. `config` is also a status item while config.toml does not load [D121], and `unprotected-folders` while the confirmed settings name no folder and folders whose vault is kept are protected by nothing (it never fails `--check`) [D145]. `--json` emits schema v1 (`{"v":1, "vault", "agent", "folders"[], "harnesses"[], "attention"[]}`). `--check` exits 3 when any folder that is not unlocked (every folder when the daemon is down) has unencrypted files, and 1 when it cannot tell: config.toml does not load (the folders are still scanned with the stand-in settings, so plaintext they find is still 3), or a folder that is not unlocked could not be scanned (its line says "unencrypted: unknown"). Such counts carry `"incomplete": true` in the JSON [D121]. `status` shows attention items from the daemon and the CLI's on-disk checks; slow or OS-tool checks (`unhardened-build`, backups, `codex-hooks-trust`, `plugin-pin`) appear in `doctor` only. AGENTS shows the harness version reported at register (`ipc.SessionStatus.Version`: the wrapper reads it from the harness's install path — the native installer's `versions/<X.Y.Z>`, Homebrew's `Cellar/<name>/<X.Y.Z>` — the hook from the harness's environment; precinto never runs the harness to ask); C9.ungated names the command the user types (`ipc.Attention.Harness`: `claude` for claude-code, `codex`), as `precinto run {harness}` does.

---

## 17. Error handling (R15)

| Condition | Seal | Restore | Report |
|---|---|---|---|
| `ENOSPC`, `EDQUOT`, `EFBIG` | abort, delete the temporary, keep plaintext, retry after ≥ 60 s (queue back-off) — never spin | skip the unit (lowest priority first), never place partially | status "disk full" (`PlaintextSummary` reason `disk_full`, D111); C6.failed; `seal`/`sweep` print one line naming the space needed and `min_free`, never "nothing to seal" (nor `restore` "nothing to restore" when units failed) |
| Free space below `policy.min_free` after the operation (`fsx.CheckSpace`, checked before anything is written) [D76] | as `ENOSPC`: nothing written, plaintext kept (history rotation: nothing started, D90) | skip the unit before staging (merge-back: nothing appended) | as `ENOSPC` |
| `EACCES`, `EPERM` on read/readdir/open (incl. macOS TCC for `~/Documents`, `~/Downloads`, `~/Desktop`) | mark the unit **inaccessible**, skip it; never treat it as missing | skip the unit | status/doctor with the TCC fix (run sweeps from the terminal session, or grant the service access) |
| `EACCES`/`EPERM` on unlink after commit | journal `remove-failed`, keep the generation and the plaintext; the receipt is rewritten to that generation, so the next sweep finds the file unchanged (no new generation) and only retries the unlink (§10.3 step 8) | a later restore is a no-op (equal hash) | status/doctor; `seal`/`sweep` print one line counting such units [D111] |
| `EROFS` | as `EACCES` for writes | skip | doctor |
| `EIO` | abort, keep plaintext | abort the unit, roll back staging | doctor |
| File vanished or changed between passes (`ENOENT`, `ErrChanged`) | abort the unit as live (exit 4), retry later | – | – |
| Symlink, FIFO, socket, device, hard link (`ELOOP`, hazards) | never followed, opened or deleted; the rest of the unit is sealed; hazard reported | entry rejected (exit 5) | status lists hazards |
| iCloud dataless or unreadable placeholder | inaccessible (never trigger a download): `fsx.Walk` reports dataless files and directories as `HazardAccess` and `Dir.Open` refuses them with `EACCES`, so nothing above fsx can trigger a download | skip | doctor |
| Lock contention (`EDEADLK`, `EAGAIN`, busy flock) | retry with back-off | retry with back-off | – |
| Verification (`ErrVerify`, `ErrHeader`, `ErrRecipients`, `ErrTooLarge`, plugin pin, wrong identity, tripwire, MAC, unit id not matching its key) | exit 5, plaintext kept, alert | exit 5, nothing written | attention item (`vault-tampered` names `precinto vault repair`, D53) |
| Daemon unreachable | sweeps treat every folder as locked but honour leases and stability | client cannot obtain keys (exit 3) | hooks fail closed for managed sessions |

A lock always completes (keys wiped, gates engaged) whatever sealing does (I15). Locks never wait for UI, seals or restores.

---

## 18. Invariants (tests MUST enforce; see TESTPLAN.md for the mapping)
- **I1** Never seal, move or delete a file of a live unit.
- **I2** Restore exact bytes at the computed target path as regular files (no symlinks), with original mtime (except the D14 clamp) and mode masked to owner bits, unless the placement table (§11.3) applies.
- **I3** Never delete plaintext before its generation is committed and verified (ephemeral round trip, header check) and the file's identity is unchanged since hashing.
- **I4** Capsules live only in `<base>/capsules`; the working tree holds only text markers (D16).
- **I5** Gate hooks block/deny on every error path for managed sessions (daemon unreachable, decode error, deadline, panic, missing binary); unmanaged paths fail open.
- **I6** Lock never blocks on UI, seals or restores; unlock always needs fresh user presence; no OS event unlocks.
- **I7** Identities never touch disk unencrypted and never leave the daemon; no plaintext content, prompt, tool I/O or environment value in logs, ledgers, journals, receipts, queue or errors.
- **I8** Restore targets derive from trusted context; no traversal, no symlink components below a base; files 0600 (0700 if owner-exec), directories 0700.
- **I9** Every operation is idempotent and crash-safe (journal + temporary + no-replace rename + fsync); a crash or power loss at any step loses no data.
- **I10** Unknown files that carry a session id are sealed with that session (fail closed), never ignored.
- **I11** A capsule generation is never overwritten; unrelated plaintext never replaces a capsule; a generation is deleted only by `prune`/`forget` keeping every file still needed.
- **I12** Disappearance of restored plaintext never deletes, replaces or shrinks a capsule.
- **I13** Restore never replaces an existing file except as listed in the placement table, and never merges into a live unit.
- **I14** Only capsules with provenance (capsule log) are restored or have keys released.
- **I15** A lock always completes: keys wiped and gates engaged even when sealing fails; unsealed units are reported.
- **I16** The sealer refuses when the recipient set is not the verified one or the header does not carry exactly the expected stanzas.

---

## 19. Known limitations
- **Live data.** Plaintext of running sessions and of unlocked folders is readable by any process of the user; FileVault (or an encrypted home on Linux) is required for deleted-plaintext remnants on SSDs. Persistent same-user malware captures a folder's key at its next unlock.
- **Blocked prompts reach disk.** A prompt blocked while locked may still be written to the transcript and `history.jsonl`; the transcript copy is sealed with the session, the history line waits for the next rotation (which needs no Claude process running anywhere). `status` counts pending lines. Do not type secrets into a locked session.
- **Soft lock without the wrapper is a model gate only.** IDE terminals, desktop apps and `command claude` keep the conversation visible and local commands (`/export`, `/copy`, scrollback) work; only the wrapper hides the screen. Unwrapped sessions without working hooks cannot be paused at all: interactive Claude ones are ended at lock, every other one is only reported (`ungated-session`) [D52, D57].
- **Lock-screen replay is bounded.** The wrapper keeps the last 8 MiB of the session's terminal output in its memory to redraw it after unlock; output older than that is not shown again after the lock cleared screen and scrollback (it remains in the session) [D60].
- **Hooks fail open where the host does.** Codex 0.154 has no `onFailure`: a timed-out precinto hook lets the action proceed (a crashed binary is still caught by the shim inside protected folders); untrusted Codex hooks do not run at all. Claude 2.1.329 has a flag-gated path that runs reactive compaction despite a PreCompact block. Copilot cannot block prompts; Cursor/Copilot/Droid support is experimental.
- **A crashing binary fails open outside listed folders.** When the binary dies (Go runtime fatal error, SIGKILL) the shim can only compare `$PWD` and `$CLAUDE_PROJECT_DIR` with `roots.list`; a session managed only through a tool path or an added directory outside those folders is not blocked by that run [D56].
- **History rotation and project memory are delayed** while Claude runs anywhere (history) or in the folder's repository (memory).
- **Unwrap heap copies.** age parses identities on the Go heap during each unwrap; mitigated by hardening, not eliminated.
- **Plugin pinning hashes, then runs by path.** There is no `fexecve`: a check-then-exec window remains, within the same-user model (§2).
- **Rescue grace.** A sealer crash during the rescue grace (§10.3 step 7) can lose bytes a still-running writer appended to an already-unlinked file; §10.5 seals what remains on disk.
- **Ctrl-Z under the PTY wrapper.** A TUI's own Ctrl-Z suspend does nothing: its process group is orphaned and the kernel discards SIGTSTP.
- **Process identity on linux is best effort, both ways.** Hardened precinto processes are not dumpable, so the client checks a daemon's uid, that it holds `run/agent.lock` and its process name instead of its executable, and the daemon checks a hardened client's uid and process name; a same-user process that kills the daemon and binds the socket, or that runs under precinto's name, is not stopped (persistent same-user malware, §2) [D65].
- **Re-pinning trusts the human.** `factor repin` follows the factor's enrolled path (a Homebrew link) to whatever binary of the same name it leads to now; a link re-pointed by a same-user process looks like an upgrade, so repin shows both paths and hashes and the user must recognise the new binary before typing `repin` [D80].
- **A session managed later gets no lock screen.** A launch outside every folder runs unmanaged and unwrapped by precinto; if it later touches a protected folder its hooks gate it, but it has no lock screen.
- **Trust in `$HOME`, `PATH` of the user's shell and the precinto binary itself.** Pinned binary links and plugin hashes reduce, but do not remove, same-user tampering. Claude's settings `env` (agent-writable in `<root>/.claude/settings.local.json`) reaches every hook process: precinto ignores `PRECINTO_*` there, but an injected `HOME` or `PATH` changes where the shim and the hook look for `<base>`; `doctor` reports such keys (`claude-settings-env`) [D56].
- **Agent detection and typed confirmations are not a boundary against a determined same-user process.** Ancestry checks are defeated by reparenting (`setsid`, double fork) and `env -i`, which is why a peer without a controlling terminal counts as an agent context for content-revealing operations; a process that allocates its own pseudo-terminal (`script`, `expect`) can still type confirmations. These checks stop accidental and prompt-injected use of precinto's commands, not malware (§2) [D59].
- **Metadata.** Root paths, unit counts, capsule sizes and times, and ledgers of unsealed sessions are plaintext (§6.3). Session titles are only inside capsules.
- **Residue outside the inventory**: terminal state (iTerm2 restoration, Terminal.app, tmux-resurrect), Spotlight index, Time Machine snapshots and backups made while unlocked, clipboard/Handoff, git objects, Claude desktop/Cowork stores, MCP server stores, Notification Center, editor histories. `doctor --leaks` reports what it can find.
- **Codex** outside protected folders is unmanaged; a shared `codex app-server` daemon is not supported in protected folders; Codex databases are sealed as opaque groups (free-page residue inside them is sealed too, but not scrubbed). A Codex session started without the wrapper (IDE, `command codex`) in a protected folder writes its rollouts to the user's own `~/.codex`, which precinto never seals; it is gated only when precinto's hooks are trusted there, and `doctor`/`status` count such rollouts (`codex-wrong-home`) [D31].
- **Large sessions** are re-encrypted fully when changed (no incremental Claude capsules in v0.2).
- **Prompt-origin heuristic** (D37) can misclassify a prompt typed while the HID idle is large (remote input) or an automated prompt right after a keystroke. Where HID idle is unreadable (headless Linux) unwrapped prompts never extend an unlock [D54].
- **Vault repair trusts the unlocked identity.** `vault repair` checks that the unwrapped identity opens older capsules of the folder, but a one-shot writer that replaced the identity files of a folder with no older capsules cannot be told apart; capsules sealed while `vault.toml` was changed are reported as exposed and are not re-encrypted (`rekey` is deferred) [D53].
- **TCC**: a LaunchAgent sweep may not read folders under `~/Documents`/`~/Downloads`; those units are sealed by the terminal-launched daemon's workers or reported as inaccessible.
- **Bash-created Markdown** is sealed only with `md = "all"`.
- **Unicode spellings in the shim.** precinto has no Unicode normalization tables: the binary matches both normalizations of a non-ASCII folder by identity (D93), and `roots.list` carries the spelling the file system stores, but when the binary itself is missing a root recorded in NFD is not matched by the shim against Claude's NFC `CLAUDE_PROJECT_DIR`.
- **pinentry must be root-owned.** The daemon never runs a pinentry from a user-writable directory (D97): with only Homebrew's `pinentry-mac`, passphrase prompts need a terminal.
- **A pin waits for a listed folder.** After a daemon restart, a TTY unlock of a folder the pinned policy does not list yet cannot re-pin it without confirmation (D91); it is refreshed at the next unlock of a listed folder, or confirmed.
- **A forged pin that names no folder.** A pin of settings that name no folder may carry only a `global` MAC, which only `unlock --global` and `recover` check: such a forged pin, next to a config.toml that names no folder either, drops every folder from enforcement until then. It is surfaced, not prevented: `status` (`unprotected-folders`) and `doctor` name the folders whose vault is kept but that nothing protects, and a folder unlock's review names them before a confirmation could drop them for good [D145].
- **A marketplace swap is two renames.** fsx has no atomic exchange, so a crash between the two renames that replace `<base>/marketplace` (not an error: every error from the first rename on puts the previous tree back) leaves Claude Code without precinto's plugin until the next `integrate`, which puts the old tree back (doctor reports it as `interrupted`) [D148].

---

## 20. Testing (summary — normative plan in `docs/TESTPLAN.md`)
Unit tests per package (docs/API.md lists expectations); integration tests with throwaway homes (`PRECINTO_HOME`, `PRECINTO_RUNTIME_DIR`, `CLAUDE_CONFIG_DIR`, `CLAUDE_CODE_TMPDIR`, `CODEX_HOME` under `t.TempDir()`, binary built with `-tags testing`); crash injection with `-tags failpoints` (armed by `cmd/precinto` from `PRECINTO_CRASHPOINT` through `internal/paths`) at every journal phase plus a power-loss mode; security tests (forged capsules, manifest authority, bombs, symlink races, socket squat, env hijack, scope, recipient tamper); opt-in E2E (`PRECINTO_E2E=1`) against real `claude -p --plugin-dir` and a synthetic Codex home. Golden hook tests use synthetic payloads only; CI rejects testdata with real paths, emails or tokens. Times that cross a process or ipc boundary are real time and clocks compared with kernel times follow the system clock [D77]; every test outlives the processes it starts and leaves nothing in TMPDIR [D81]. CI gates: `gofmt`, `go vet` (all tag sets, darwin and linux), `internal/archtest`, `apidoc -check`, `staticcheck`, `govulncheck`, `claude plugin validate --strict ./plugin`, `shellcheck` on the shims.

---

## 21. Packaging and distribution [D35, D41]
```
.claude-plugin/marketplace.json      → { name, owner, plugins: [{ name: "precinto", source: "./plugin" }] }   (Claude, Droid, Copilot)
.agents/plugins/marketplace.json     → { …, plugins: [{ name: "precinto", source: "./plugins/codex" }] }     (Codex reads it first)
plugin/.claude-plugin/plugin.json    (Claude, Droid)          plugin/hooks/hooks.json
plugin/.cursor-plugin/plugin.json    (Cursor, experimental)   plugin/hooks/cursor.json
plugin/.github/plugin/plugin.json    (Copilot, experimental)  plugin/hooks/copilot.json
plugin/scripts/precinto-hook         POSIX shim (HOOKS-IO §5)
plugin/commands/{lock,status}.md     no unlock command (it would be a gate bypass) (S20)
plugin/skills/precinto/SKILL.md      tells the model what a precinto block means; never run unlock/restore/cat/open/recover; never ask for secrets in chat
plugins/codex/.codex-plugin/plugin.json   plugins/codex/hooks/codex.json   plugins/codex/scripts/precinto-hook   (byte-stable: frozen version, frozen only after the Codex E2E of TESTPLAN §9 passes) [D41, D61]
inventories/*.toml                   data-driven harness definitions (embedded)
```
- Plugin folders hold no binaries or state; the Codex plugin root is byte-identical across releases (HA18): Codex 0.154's trust hash covers only each hook's normalized declaration, which therefore must not change either, and newer Codex versions also hash every file of the plugin root [D104]. Its SHA-256 list is recorded in `test/integration/testdata/codex-plugin.sha256` and checked on every change (`make codex-plugin-check`): until the root is frozen a change updates the list in the same change, after it never [D78].
- Every hook command uses shell form: `sh "${CLAUDE_PLUGIN_ROOT}/scripts/precinto-hook" claude-code <event>` for Claude; Codex: `sh "$PLUGIN_ROOT/scripts/precinto-hook" codex <event>` without braces, because Codex runs `$SHELL -lc` and fish rejects `${VAR}` [D61] (Codex ignores `args`).
- Binary: `go install` or a Homebrew formula building from source (CGO disabled, `-trimpath`, reproducible); release archives wait for the owner's signing/notarization decision [D35]. The binary embeds both marketplace manifests and plugin roots (the module root package, `precinto.Plugins`), byte for byte the repository's [D116].
- `precinto integrate <harness>` refuses Claude < 2.1.295 (naming `<harness> update`), writes the embedded tree to `<base>/marketplace` (exactly those files; left untouched when it already matches, else rebuilt next to it and renamed into place), then runs the harness's own plugin CLI against that local folder: `claude plugin marketplace add <base>/marketplace` and `claude plugin install precinto@precinto`, or `codex plugin marketplace add …` and `codex plugin add precinto@precinto` [D94]. No network marketplace is involved. Only after both succeed does it write `<base>/bin/precinto`, enable the harness with its binary and register the Claude home, resolved after the plugin commands, which create it on a first run [D117], in config.toml as it is on disk then [D144]; a failure changes none of them and prints the commands, shell-quoted. Claude Code loads the plugin in place from `<base>/marketplace`, so from the first rename of a swap on any failure puts the previous tree back (a rename can report a failed directory fsync after it happened), and an integrate stopped between the two renames is repaired by the next (the hidden `.marketplace.old-*` tree is put back first; doctor reports it as `interrupted`). One integrate swaps at a time (`state/locks/marketplace.lock`), so hidden trees found at its start are an interrupted integrate's: half-built `.marketplace.new-*` trees and replaced ones are removed [D148]. `--print` prints them and writes nothing. It never pre-writes Codex trust hashes.
- License Apache-2.0 + NOTICE; contributions under DCO. The repository stays private until the owner decides to publish it [D35].

---

## 22. Roadmap (post v0.2)
Incremental capsules for large Claude units (blob reuse, appended-tail segments); post-quantum capsules once factor wraps are PQ; bundled multi-folder unlock; `import`, `rekey`, `canary`, `scrub`; a Claude mod for a lock band and prompt placeholder; native adapters for Gemini, Kimi, Qwen, OpenCode, Cursor, Copilot; signed `.app` helper for LocalAuthentication from a LaunchAgent; cgo-free IOKit sleep pre-notification; Linux systemd unit and logind D-Bus triggers; Windows; usage ledger compatible with `ccusage`; encrypted search over sealed history.
