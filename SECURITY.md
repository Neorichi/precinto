# Security policy

Precinto exists to protect sensitive data, so security reports come before any other work. Thank you for helping.

## Supported versions

Precinto is pre-release (specification v0.2) and has no stable release yet. Only the current state of the default development branch receives security fixes. Once there are releases, this table will say which of them are supported.

| Version | Supported |
|---|---|
| default branch (v0.2 pre-release) | yes |
| anything older | no |

## Reporting a vulnerability

**Please do not report vulnerabilities in public**: not in issues, discussions, pull requests, commit messages, chats or social media.

- **Once the repository is published**, report through the private vulnerability reporting of the platform that hosts it (a private security advisory). Only you and the maintainers can see that report.
- **Until then** the repository is private and only invited people can read it. If you are one of them, report the issue privately to the maintainers through the same private channel you were invited through, and never in a shared or public place.

Please include:

- the version or commit (`precinto version`), your operating system and its version (on Windows, also the output of `wsl --version` and the distribution), and the harness and its version (for example Claude Code 2.1.329 or Codex 0.154.0);
- what you expected and what happened instead;
- the smallest reproduction you can make, **with synthetic data only**: a throwaway `HOME`, a test folder, made-up prompts. Never send real transcripts, prompts, capsules of real data, recovery keys, passphrases, tokens or credentials. If something like that reaches us by accident, we delete it;
- the impact as you understand it, and whether you plan to publish.

## Scope

**Platforms**: macOS, Linux, and Windows through WSL 2, where Precinto runs as its Linux build inside a WSL 2 distribution and the Windows account is the trust boundary ([docs/THREAT_MODEL.md §3.6](docs/THREAT_MODEL.md#36-windows-programs-of-the-same-account-wsl-2)). Native Windows is out of scope: `precinto.exe` builds, but every platform primitive refuses there, so it fails closed.

**In scope**: anything that breaks a guarantee described in [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) or an invariant of [docs/SPEC.md §18](docs/SPEC.md#18-invariants-tests-must-enforce-see-testplanmd-for-the-mapping). For example:

- reading the plaintext of a sealed unit, or obtaining a vault identity or a file key, without a fresh unlock;
- obtaining the key or the plaintext of a folder other than the ones that are unlocked;
- the daemon releasing keys to a different executable, to a capsule missing from the capsule log, or for a folder that is locked;
- a restore that writes outside the allowed targets of its unit, follows a symlink, or replaces a file it should not;
- Precinto deleting or losing data: plaintext deleted before its capsule was verified, a generation overwritten, data lost after a crash or power loss;
- a gate hook that fails open for a session in a protected folder where the specification says it must fail closed;
- secrets or content (identities, passphrases, recovery keys, prompts, tool output, environment values) written to logs, ledgers, journals, receipts, the queue or error messages;
- recipient tampering, planted capsules or policy downgrades that go undetected;
- a way for an agent session to run `init`, factor or recovery operations, `vault repair` or destructive commands, or to reveal sealed content without presence, other than the documented limitations.

**Out of scope**, unless you find a way to make them worse than documented:

- the limitations listed in [docs/SPEC.md §19](docs/SPEC.md#19-known-limitations) and in the residual risks of [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md#7-residual-risks), such as what persistent malware running as you can do after you unlock a folder, sessions that run without hooks, or metadata that is visible by design;
- vulnerabilities in a harness, in age or its plugins, or in the operating system: please report them to their maintainers, and tell us too if Precinto's use of them is affected;
- attacks that need administrator (root) or kernel access, including root in a WSL 2 distribution, which every Windows program of your account can get;
- social engineering of maintainers or users.

When in doubt, report it: we would rather triage a report than miss one.

## Disclosure timeline

These are targets. Like every policy of this pre-release project, they are subject to change before the first public release.

| Step | Target |
|---|---|
| acknowledge your report | within 7 days |
| first assessment (confirmed or not, severity) | within 14 days |
| fix or mitigation | within 90 days of the report, sooner for severe issues |
| public disclosure | coordinated with you: by default when the fix ships, or 90 days after the report, whichever comes first; we can agree on a different date |

We will keep you informed while we work on it, and credit you in the advisory if you wish.

## How Precinto is built to be secure

- Threat model: [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).
- Specification, including cryptography, key custody and error handling: [docs/SPEC.md](docs/SPEC.md).
- Security tests: [docs/TESTPLAN.md §5](docs/TESTPLAN.md#5-security-tests).
