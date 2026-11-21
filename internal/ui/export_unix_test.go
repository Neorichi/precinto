//go:build darwin || linux

package ui

import "time"

// WaitReadable is the select(2) wait prompts use; the test pty driver reads
// the master side with it so that no read ever blocks a test.
func WaitReadable(fd int, timeout time.Duration) (bool, error) { return selectRead(fd, timeout) }
