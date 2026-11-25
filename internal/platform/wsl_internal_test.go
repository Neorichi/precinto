package platform

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Neorichi/precinto/internal/paths"
)

// fakeWSL makes detectWSL answer w for the test.
func fakeWSL(t *testing.T, w paths.WSL) {
	t.Helper()
	old := detectWSL
	detectWSL = func() paths.WSL { return w }
	t.Cleanup(func() { detectWSL = old })
}

// D156: under WSL the Users folder of a Windows drive counts as synced
// (OneDrive, Known Folder Move), as given and through a symlink; outside
// WSL nothing changes.
func TestCloudSyncedUnderWSL(t *testing.T) {
	wsl := paths.WSL{Version: 2, MountRoot: "/mnt/"}
	for p, want := range map[string]bool{
		"/mnt/c/Users/Public/recovery.txt": true,
		"/mnt/d/users/someone/OneDrive":    true,
		"/mnt/c/Windows/Temp/x":            false,
		"/home/u/notes":                    false,
		"relative/Users/x":                 false,
	} {
		if got := wslSynced(wsl, p); got != want {
			t.Errorf("wslSynced(%q) = %v, want %v", p, got, want)
		}
		if wslSynced(paths.WSL{}, p) {
			t.Errorf("outside WSL %q counts as synced", p)
		}
	}
	// A link into a Users folder (a fake drive root below a temp dir).
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	users := filepath.Join(dir, "drives", "c", "Users", "Public")
	if err := os.MkdirAll(users, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "keys")
	if err := os.Symlink(users, link); err != nil {
		t.Fatal(err)
	}
	fake := paths.WSL{Version: 2, MountRoot: filepath.Join(dir, "drives") + "/"}
	if !wslSynced(fake, link) {
		t.Error("a symlink into a Users folder is not synced")
	}
	fakeWSL(t, fake)
	if !cloudSynced(link) || !cloudSynced(filepath.Join(users, "key.txt")) {
		t.Error("CloudSynced misses a Users folder under WSL")
	}
	fakeWSL(t, paths.WSL{})
	if cloudSynced(filepath.Join(users, "key.txt")) {
		t.Error("CloudSynced flags a Users folder outside WSL")
	}
}
