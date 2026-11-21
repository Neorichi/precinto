//go:build darwin

package platform

// darwin hardening (RLIMIT_CORE, ptrace/dumpable, uid checks) is implemented here by G2.
const hardenImpl = "darwin"
