//go:build linux && (mips || mipsle || mips64 || mips64le)

package agent

// rlimitMemlock is RLIMIT_MEMLOCK of the linux MIPS ABI.
const rlimitMemlock = 9
