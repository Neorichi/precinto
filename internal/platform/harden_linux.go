//go:build linux

package platform

// linux hardening (RLIMIT_CORE, ptrace/dumpable, uid checks) is implemented here by G2.
const hardenImpl = "linux"
