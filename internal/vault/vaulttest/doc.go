// Package vaulttest builds throwaway vaults with a known X25519 test
// identity (no Secure Enclave, no plugins) for tests of every group.
//
// Owner: G1 (crypto core). Imports: stdlib, filippo.io/age,
// github.com/awnumar/memguard, internal/vault. Test-only.
package vaulttest
