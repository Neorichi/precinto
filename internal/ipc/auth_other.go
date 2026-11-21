//go:build !linux

package ipc

// sameExeFallback: outside linux a hardened process still exposes its
// executable to same-uid peers (darwin proc_pidpath), so a permission
// error means the identity cannot be proven: not the same (fail closed).
func sameExeFallback(int) bool { return false }
