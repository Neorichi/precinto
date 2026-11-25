//go:build !linux

package paths

// Outside linux there is no WSL (D155): DetectWSL is the zero WSL and
// CheckDrive returns before it would use the probe.

func detectWSL() WSL { return WSL{} }

var driveProbe = probe{}
