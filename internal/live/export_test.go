package live

import "github.com/precinto/precinto/internal/fsx"

// SetProbeHook runs f between Probe's lock and its inode check (CODX-6:
// the lock file is unlinked and recreated during the probe). Tests that use
// it must not run in parallel.
func SetProbeHook(f func(path string)) (restore func()) {
	old := probeHook
	probeHook = f
	return func() { probeHook = old }
}

// SetTryLock replaces how lease files are locked (ENOTSUP and other
// file-system failures). Tests that use it must not run in parallel.
func SetTryLock(f func(path string, shared bool) (*fsx.Lock, error)) (restore func()) {
	old := tryLock
	tryLock = f
	return func() { tryLock = old }
}
