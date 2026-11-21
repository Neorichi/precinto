package live

import "github.com/precinto/precinto/internal/fsx"

// SetProbeHeld replaces how lease files are probed (fsx.ProbeHeld): ENOTSUP
// and swapped-file answers. Tests that use it must not run in parallel.
func SetProbeHeld(f func(path string) (bool, error)) (restore func()) {
	old := probeHeld
	probeHeld = f
	return func() { probeHeld = old }
}

// SetTryLock replaces how lease files are locked (ENOTSUP and other
// file-system failures). Tests that use it must not run in parallel.
func SetTryLock(f func(path string, shared bool) (*fsx.Lock, error)) (restore func()) {
	old := tryLock
	tryLock = f
	return func() { tryLock = old }
}
