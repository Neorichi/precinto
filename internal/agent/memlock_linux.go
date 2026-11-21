//go:build linux && !(mips || mipsle || mips64 || mips64le)

package agent

// rlimitMemlock is RLIMIT_MEMLOCK of the generic linux ABI (the standard
// syscall package does not name it).
const rlimitMemlock = 8
