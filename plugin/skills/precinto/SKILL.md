---
name: precinto
description: What to do when precinto blocks a prompt, denies a tool or pauses compaction (a message that starts with "precinto:"), or when a file ends in .md.precinto.
---

# precinto

precinto keeps the transcripts of AI coding sessions and the notes agents write encrypted on disk while the user's protected folder is locked. While a folder is locked its sessions are paused: prompts are blocked, tools are denied and compaction waits until the user unlocks it with their Mac password, a security key or a passphrase. Unlocking needs the user's presence, so only the user can do it.

## When precinto blocks or denies

A message that starts with `precinto:`, for example "precinto: the user's project ~/work/acme is locked", means the folder is locked. Then:

1. Stop. Do not retry the tool, and do not reach the same files another way: no other tool, path, shell command, copy or backup.
2. End your turn with one short sentence asking the user to run `precinto unlock` in their own terminal.

When precinto says it "could not run", the folder also stays locked: ask the user to run `precinto doctor` in their terminal.

## Never

- Never run `precinto unlock`, `precinto restore`, `precinto cat`, `precinto open`, `precinto recover`, `precinto vault`, `precinto factor`, `precinto init`, `precinto prune`, `precinto forget` or `precinto unprotect`. These need the user, in their own terminal; precinto refuses them from an agent session.
- Never ask the user to type a password, passphrase, PIN or recovery key in the chat. precinto asks for those itself, in a system dialog or in the user's terminal, never through you.
- Never edit, move or delete `*.md.precinto` files. Each one marks a note that precinto sealed; the note comes back when the user unlocks the folder.
- Never change precinto's configuration, its `roots.list`, or the harness settings and hooks to get around a lock.

`precinto status` and `precinto lock` are safe to run when the user asks for them.
