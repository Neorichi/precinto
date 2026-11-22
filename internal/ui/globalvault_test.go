package ui

import (
	"strings"
	"testing"
)

// D152: the global vault is no folder a --root could name, so the C14
// commands of a message about it take --global; a folder's keep --root.
func TestFormatGlobalVaultCommands(t *testing.T) {
	for _, tc := range []struct {
		id   MsgID
		want string
	}{
		{MsgVaultTampered, "precinto vault repair --global"},
		{MsgVaultNotGenuine, "precinto vault repair --global --recovery"},
	} {
		got := Format(tc.id, Vars{Folder: "global", Global: true})
		if !strings.Contains(got, tc.want) || strings.Contains(got, "--root") {
			t.Errorf("%s for the global vault: %q, want %q and no --root", tc.id, got, tc.want)
		}
		folder := Format(tc.id, Vars{Folder: "~/work/acme"})
		if !strings.Contains(folder, "precinto vault repair --root ~/work/acme") {
			t.Errorf("%s for a folder: %q", tc.id, folder)
		}
	}
}
