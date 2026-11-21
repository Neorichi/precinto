//go:build darwin || linux

package fsx

import "testing"

// NoPrivateGroupsForTest turns the D67 user-private group exception off for
// the rest of the test, so a test that expects a group-writable directory to
// be refused behaves the same on every host (a linux host may have a real
// user-private group).
func NoPrivateGroupsForTest(t testing.TB) {
	t.Helper()
	old := privateGroups
	privateGroups = false
	t.Cleanup(func() { privateGroups = old })
}
