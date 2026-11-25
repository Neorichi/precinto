//go:build !darwin && !linux

package ipc

import "io/fs"

// ownedByMe: other platforms are unsupported (D34); no owner can be proven
// here, so the run directory and the socket are refused (fail closed).
func ownedByMe(fs.FileInfo) bool { return false }
