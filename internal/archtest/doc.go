// Package archtest enforces the package contract of docs/API.md: owners,
// the import allowlist (no cycles, lower layers never import higher ones),
// test-only helper packages, and the rule that only internal/paths reads the
// process environment. `go test ./internal/archtest` fails on violations.
//
// Owner: G7 (CLI). Imports: stdlib only. Changing this file changes the
// contract: only the lead may edit it (docs/OWNERSHIP.md).
package archtest
