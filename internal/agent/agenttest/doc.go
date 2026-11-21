// Package agenttest runs a real agent in-process on a throwaway layout with
// a fake clock and process table, for gate, unlock, key-release and lock
// tests of every group (docs/TESTPLAN.md).
//
// Owner: G2 (daemon). Imports: stdlib, internal/agent, internal/ipc,
// internal/paths, internal/platform, internal/platform/fakeplatform.
// Test-only; requires -tags testing (ipc.DialOptions.Insecure).
package agenttest
