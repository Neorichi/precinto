//go:build !darwin && !linux && !windows

package fsx

// oNoFollow: other platforms are unsupported (D34); the package still
// compiles.
const oNoFollow = 0
