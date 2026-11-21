//go:build !darwin && !linux

package platform

// Unsupported platforms (D34): every OS-specific function returns
// ErrUnsupported once implemented; this file keeps `go vet` building.
const (
	procImpl   = "unsupported"
	peerImpl   = "unsupported"
	screenImpl = "unsupported"
	hardenImpl = "unsupported"
)
