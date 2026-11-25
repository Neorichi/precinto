//go:build testing

package platform

// SetBootTimeForTest makes linux read the boot time from fn instead of
// /proc/stat btime until restore is called (StartTime, EarliestStartTime
// and NoteBootTime read it; nil fn reads /proc/stat again): crossgroup
// tests move it forward by hours, as a WSL 2 host sleep does (D157). Only
// -tags testing builds have it; darwin measures process starts in wall
// time and reads no boot time.
func SetBootTimeForTest(fn func() (int64, error)) (restore func()) { return setBootTime(fn) }
