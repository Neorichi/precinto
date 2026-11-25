# Compaction and background summaries

When a conversation outgrows the model's context window, the harness summarizes its older part: this is *compaction*. This page explains what compaction means for a protected folder while it is unlocked and while it is locked, which background summaries Precinto turns off and why, and why ending the session (the hard lock) is what really protects a compacted conversation.

The normative rules are in [SPEC.md §7.1.5](SPEC.md#715-launch-resume-and-retention), [§7.1.6](SPEC.md#716-compaction-and-background-writers), [§12.6](SPEC.md#126-gating-per-session-at-lock-time-ux2-d24-d26) and [HOOKS-IO.md](HOOKS-IO.md). Precinto is pre-release (specification v0.2); details are subject to change. Harness behaviour described here was checked on Claude Code 2.1.329 and Codex 0.154 and may change in other versions.

## Contents

- [What compaction leaves on disk](#what-compaction-leaves-on-disk)
- [Background summaries that Precinto turns off](#background-summaries-that-precinto-turns-off)
- [While the folder is unlocked](#while-the-folder-is-unlocked)
- [While the folder is locked](#while-the-folder-is-locked)
- [Why ending the session is the real protection](#why-ending-the-session-is-the-real-protection)
- [After you unlock](#after-you-unlock)
- [Summary](#summary)

## What compaction leaves on disk

Compaction does not delete anything. Claude Code and Codex append the summary to the **same** transcript (Codex calls it a rollout) and keep the earlier conversation in the file. A summary is new derived plaintext: it condenses your conversation, but it is still your conversation.

Precinto treats compaction like any other write: the summary is part of the session's files and is sealed with them. There is no special handling of the transcript ([SPEC.md §7.1.6](SPEC.md#716-compaction-and-background-writers)). A few extra files can appear around a Claude Code compaction, and Precinto covers them all as part of the session unit:

| File | What it is | How Precinto handles it |
|---|---|---|
| `projects/<P>/<sid>/precompact.json` | a summary Claude Code prepares ahead of time (precomputed compaction) | belongs to the session unit and is sealed with it |
| `*.compact.tmp.*` next to a transcript | a temporary file Claude Code can leave next to a transcript while it rewrites it | found by session id and sealed with the session; restored to the same place |
| `.precompact.json.tmp.*` | the same, for the precomputed summary | found by session id and sealed with the session |
| `*.superseded-*`, `*.orphaned-*` | older copies Claude Code sets aside | found by session id and sealed with the session |

Precinto locates transcripts by session id in every project directory, including these siblings, never by a remembered path or inode ([D19](DECISIONS.md)). A temporary file that a crash or a kill left in the middle of a compaction is therefore sealed with its session instead of being left behind as plaintext: unknown files that carry a session id are always sealed with that session (invariant I10). If Claude Code later deletes one of these files on its own, that is never treated as a deletion of the capsule (I12).

## Background summaries that Precinto turns off

Claude Code can summarize a session while you are not typing:

| Claude Code setting | What it does | Is there a hook? |
|---|---|---|
| `idleCompaction` | compacts an idle session in the background | yes: it runs the PreCompact hook with trigger `auto` |
| `awaySummaryEnabled` | writes a short recap of the session into the transcript and shows it on screen when you come back | no hook covers it |
| `precomputeCompactionEnabled` (undocumented) | prepares a summary in advance, in the `precompact.json` sidecar | not verified |

These summaries are written while you are away, into a session that is still running and therefore cannot be sealed yet; the recap is also painted on the screen. So when Precinto starts Claude Code in a protected folder (through `precinto run claude` or the `claude` shell function), it adds [D32]:

```sh
--settings '{"idleCompaction":false,"awaySummaryEnabled":false,"precomputeCompactionEnabled":false}'
CLAUDE_CODE_ENABLE_AWAY_SUMMARY=0      # in the environment of the launch
```

- If you pass your own `--settings`, Precinto adds nothing and prints a notice. Add the three keys to your own settings to keep those summaries off.
- `precinto protect DIR --claude-settings` also merges the three settings into the folder's `.claude/settings.local.json` (Claude Code's local settings file, not meant to be committed), so that they also apply to sessions started without Precinto. Every other key in that file is kept, and `precinto unprotect` removes the keys whose values Precinto wrote. This is the only case in which Precinto writes Claude Code settings into your project.
- Manual and automatic compaction stay on: sessions need them to keep working, and they are gated while the folder is locked (next sections).
- The trade-off: with idle compaction off, nothing is summarized while you are away, so the first request after a long break still carries the whole context.

Codex 0.154 compacts only inside a turn (the manual `/compact`, or automatically before or during a turn); it has no idle compaction, so Precinto changes no Codex setting.

## While the folder is unlocked

Compaction runs normally.

- **PreCompact** allows it and marks a compaction *in progress* (`compact_begin`). The allow path prints nothing: in Claude Code, anything a PreCompact hook prints becomes instructions for the summarizer. Precinto never reads the summarizer instructions (`custom_instructions`) or the summary itself (`compact_summary`).
- The in-progress mark is cleared by PostCompact, by a SessionStart with source `compact`, by Stop or StopFailure, by SessionEnd, by the next prompt, when Claude Code's session registry shows the session idle, or when the process exits.
- **Ending a session waits for a compaction in progress**, for at most 5 minutes, so that the harness can finish writing the summary before it is stopped. `precinto lock --end --force` does not wait.
- The transcript, the summary and the sidecar stay plaintext, exactly where the harness expects them: the harness, and the model through its own tools, may need to read the full transcript while the session runs.

## While the folder is locked

What a session may still do after its folder locks depends on what it was doing at that moment ([SPEC.md §12.6](SPEC.md#126-gating-per-session-at-lock-time-ux2-d24-d26)):

| Session at lock time | Prompts (automated ones too) | Tools | Compaction | Permission dialogs |
|---|---|---|---|---|
| idle | blocked | denied | **blocked** | denied |
| busy (in the middle of a turn) | blocked | allowed until the turn stops, or until `busy_grace` (30 min) after the lock; then denied | **allowed inside the running turn, until it stops** | allowed until the turn stops |
| any, after `precinto lock` without `--let-finish` | blocked | denied | **blocked** | denied |

Blocked compaction looks like this per harness:

- **Claude Code.** The hook answers `{"decision":"block","reason":"precinto: compaction is paused while <folder> is locked."}`. A blocked *proactive* compaction (manual `/compact`, automatic, idle) is skipped. A blocked *reactive* compaction, the kind that runs when a request is already too large to send, makes that request fail. Trigger `auto` includes idle compaction, so idle compaction is blocked while locked even if the setting was left on. Caveat: Claude Code 2.1.329 has a flag-gated path that runs a reactive compaction despite the block ([SPEC.md §19](SPEC.md#19-known-limitations)).
- **Codex 0.154.** The hook prints `{"continue":false,"stopReason":"precinto: compaction is paused while <folder> is locked."}`, which aborts the turn; it is the only way to block a Codex compaction. Codex has no fail-closed option for hooks: if Precinto's hook times out, the compaction proceeds. If the `precinto` binary crashes, the shim still blocks inside protected folders. Codex runs hooks only after you trust them.

What a lock does **not** stop: the harness process keeps running, with its transcript and memory in plaintext. Anything it still writes (the work of a turn that was allowed to finish, the recap if that setting is on, any feature that no hook covers) lands on disk as plaintext, in a file Precinto cannot seal while the process lives.

## Why ending the session is the real protection

1. **A running session's files are live.** Precinto never seals, moves or deletes a file that a process can still write (invariant I1). Claude Code appends to its transcript, and if the file were moved away under it, it would write a new fragment that loses the earlier history when resumed. So every summary, sidecar and temporary file of a running session stays plaintext until the session ends, whether its folder is locked or not.
2. **A soft lock is enforced by hooks, and hooks are not a security boundary.** They can be turned off (`--bare`, `disableAllHooks`, a disabled plugin, an untrusted Codex hook), they can fail open (Codex timeouts), and some harness paths bypass them (the flag-gated reactive compaction, the away summary).
3. **Ending the session closes the gap.** When the session ends its process exits, and Precinto seals everything in the session unit (transcript, summaries, `precompact.json`, temporary siblings, subagent transcripts, tool results) into a capsule that it verifies before deleting the plaintext.

So the timers that end paused sessions are what bounds how long a compacted conversation stays readable: `idle_hard` (60 minutes without your input by default), `screen_lock_hard_after` (15 minutes of continuous screen lock), or `precinto lock --end` when you walk away. Keep them short if this matters to you.

Background sessions (Claude Code `--bg`, agent view) are an exception: Precinto never ends them, because their supervisor would restart them [D25]. They stay paused and flagged in `precinto status`, and their files stay plaintext until you end them from Claude Code.

## After you unlock

- Precinto restores the exact bytes, so the harness finds its transcript as it left it, summaries included, and resumes normally.
- If the harness wrote a new fragment of a transcript while the older part was sealed (the fragment's first record points into the sealed part, and their records do not overlap), the restore joins the sealed part and the fragment instead of overwriting either one [D11]. Any other mismatch is kept side by side as a conflict and reported (`precinto ls --conflicts`, `precinto resolve`).

## Summary

| | Folder unlocked | Locked, session idle | Locked, turn running | Session ended |
|---|---|---|---|---|
| Manual `/compact` and automatic compaction | run | blocked | allowed until the turn stops (blocked at once after `precinto lock` without `--let-finish`) | – |
| Claude Code idle compaction | turned off in sessions Precinto starts | blocked (trigger `auto`) | – | – |
| Claude Code away summary | turned off in sessions Precinto starts | turned off in sessions Precinto starts; no hook can stop it otherwise | same as idle | – |
| Claude Code precomputed summary | turned off in sessions Precinto starts | same | same | – |
| The transcript and its summaries | plaintext | plaintext (the session is live) | plaintext (live) | **sealed** |
