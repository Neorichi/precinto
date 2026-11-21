---
description: Show which precinto folders are locked and what is still unencrypted
allowed-tools: Bash(precinto status)
---

Show the user the state of their precinto-protected folders.

Run exactly this command once with the Bash tool:

```
precinto status
```

Show its output to the user unchanged, in a code block. Do not run any other precinto command. When a line names a command that fixes something, tell the user to run it in their own terminal; never run `precinto unlock`, `precinto restore`, `precinto cat`, `precinto open`, `precinto recover` or `precinto vault` yourself.
