// Package doctor implements `precinto doctor [--leaks] [HARNESS]`: read-only
// health and leak checks with one-line fixes (SPEC §16.1, §19). It never
// changes anything; fixes are separate commands that ask for consent.
//
// Owner: G7 (CLI). Imports: everything below cmd/precinto except
// internal/agent, internal/wrapper and internal/hook.
package doctor
