// Package vault manages per-root vaults (D1): one X25519 identity per
// protected root plus the `global` vault, each wrapped once per enrolled
// factor (Secure Enclave via age-plugin-se, other age plugins, scrypt
// passphrase, offline recovery key), the authenticated recipient set with its
// tripwire copy (D5), daemon-side unwrap with relayed UI (D4), and the
// Keyring that holds unlocked identities in memguard enclaves.
//
// Owner: G1 (crypto core). Imports: stdlib, filippo.io/age,
// filippo.io/age/plugin, filippo.io/age/tag, github.com/awnumar/memguard,
// github.com/BurntSushi/toml, internal/fsx, internal/fsx/failpoint.
//
// Secrets are never Go strings: identities, passphrases, file keys and the
// recovery key live in *memguard.LockedBuffer. The transient heap copy made
// while age parses an identity during one DecryptHeader call is a documented
// residual (SPEC §19). Plugin binaries — age-plugin-se included — are
// pinned by absolute path and SHA-256 and run with PATH limited to the
// pinned directory (S2). After a MAC or tripwire failure, Store.Repair
// rewrites the recipient set from an identity the daemon unwrapped at the
// user's request (`precinto vault repair`, D53).
package vault
