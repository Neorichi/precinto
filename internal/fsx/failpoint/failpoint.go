package failpoint

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
)

// fault is one armed fault.
type fault struct {
	at    int           // fire at this hit (1-based)
	errno syscall.Errno // 0: crash (SIGKILL self)
}

var (
	mu     sync.Mutex
	armed  = map[string]fault{}
	counts = map[string]int{}
)

// errnos are the injectable errors (SPEC §17).
var errnos = map[string]syscall.Errno{
	"ENOSPC": syscall.ENOSPC,
	"EDQUOT": syscall.EDQUOT,
	"EFBIG":  syscall.EFBIG,
	"EACCES": syscall.EACCES,
	"EPERM":  syscall.EPERM,
	"EIO":    syscall.EIO,
	"EROFS":  syscall.EROFS,
	"ENOENT": syscall.ENOENT,
	"EAGAIN": syscall.EAGAIN,
	"EBUSY":  syscall.EBUSY,
}

// Hit evaluates the point name. It returns nil unless a fault is armed for
// name; an armed crash fault never returns (the process SIGKILLs itself), an
// armed errno fault returns that errno (as a syscall.Errno wrapped in
// *os.SyscallError-compatible form). Always a no-op without -tags failpoints.
// Point names come from the registry in docs/TESTPLAN.md §4.
func Hit(name string) error {
	if !enabled {
		return nil
	}
	mu.Lock()
	counts[name]++
	n := counts[name]
	f, ok := armed[name]
	mu.Unlock()
	if !ok || n != f.at {
		return nil
	}
	if f.errno != 0 {
		return &os.SyscallError{Syscall: "failpoint " + name, Err: f.errno}
	}
	crash()
	return nil
}

// crash kills the current process without running deferred functions or
// flushing buffers, like a power cut for the process.
func crash() {
	if p, err := os.FindProcess(os.Getpid()); err == nil {
		_ = p.Kill()
	}
	select {} // Kill may be asynchronous: never return to the caller
}

// Enabled reports whether this binary was built with -tags failpoints.
func Enabled() bool { return enabled }

// Set arms faults in-process from a spec with the PRECINTO_CRASHPOINT
// syntax; several specs may be separated by commas:
//
//	<name>[:<n>]              SIGKILL self at the n-th hit (default 1)
//	<name>=errno:<E>[:<n>]    return errno E (ENOSPC, EDQUOT, EFBIG, EACCES,
//	                          EPERM, EIO, EROFS, ENOENT, EAGAIN, EBUSY)
//
// Only valid with -tags failpoints; otherwise it panics so tests cannot
// silently pass. A malformed spec panics too. Implemented in the scaffold.
func Set(spec string) {
	if !enabled {
		panic("failpoint.Set: binary built without -tags failpoints")
	}
	parsed := map[string]fault{}
	for _, one := range strings.Split(spec, ",") {
		one = strings.TrimSpace(one)
		if one == "" {
			continue
		}
		name, rest, isErrno := strings.Cut(one, "=")
		f := fault{at: 1}
		if isErrno {
			e, ok := strings.CutPrefix(rest, "errno:")
			if !ok {
				panic(fmt.Sprintf("failpoint.Set: bad spec %q", one))
			}
			code, nth, hasN := strings.Cut(e, ":")
			errno, ok := errnos[code]
			if !ok {
				panic(fmt.Sprintf("failpoint.Set: unknown errno %q", code))
			}
			f.errno = errno
			if hasN {
				f.at = parseNth(one, nth)
			}
		} else if n, nth, hasN := strings.Cut(name, ":"); hasN {
			name = n
			f.at = parseNth(one, nth)
		}
		if name == "" {
			panic(fmt.Sprintf("failpoint.Set: bad spec %q", one))
		}
		parsed[name] = f
	}
	mu.Lock()
	defer mu.Unlock()
	for k, v := range parsed {
		armed[k] = v
	}
}

func parseNth(spec, s string) int {
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 {
		panic(fmt.Sprintf("failpoint.Set: bad hit count in %q", spec))
	}
	return n
}

// Reset disarms every fault and clears hit counters.
func Reset() {
	mu.Lock()
	defer mu.Unlock()
	armed = map[string]fault{}
	counts = map[string]int{}
}

// Hits returns how many times name was evaluated since the last Reset
// (failpoints builds only; 0 otherwise).
func Hits(name string) int {
	mu.Lock()
	defer mu.Unlock()
	return counts[name]
}
