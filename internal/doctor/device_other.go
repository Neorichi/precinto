//go:build !darwin && !linux

package doctor

import "errors"

// deviceOf: other platforms are unsupported (D34), so volumeRoot cannot
// tell the volume and returns "", as when fsx stages nowhere. The text
// names no decision id (UX-18).
func deviceOf(string) (uint64, error) {
	return 0, errors.New("doctor: device numbers are not supported on this OS")
}
