//go:build !darwin && !linux

package vault

// reapLeakedHelpers: unsupported platforms (D34) have no leak check.
func reapLeakedHelpers() int { return 0 }
