//go:build !darwin && !linux

package agent

// raiseMemlock: only darwin and linux are supported (D34).
func raiseMemlock() error { return nil }
