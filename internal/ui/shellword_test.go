package ui_test

import (
	"testing"

	"github.com/precinto/precinto/internal/ui"
)

// D113: a folder in a command a message tells the user to run is one shell
// word that names the folder: the ~ form when it is safe, else the
// absolute path single-quoted (quotes inside escaped), never a control
// character.
func TestShellWord(t *testing.T) {
	const home = "/Users/u"
	for _, tc := range []struct{ p, want string }{
		{"/Users/u/work/acme", "~/work/acme"},
		{"/srv/repo-1.2_x", "/srv/repo-1.2_x"},
		{"/Users/u/My Work/acme", "'/Users/u/My Work/acme'"},
		{"/Users/u/it's", `'/Users/u/it'\''s'`},
		{"/Users/u/a\x1b[31mb", "'/Users/u/a[31mb'"},
		{"/Users/u/a\nb", "'/Users/u/a b'"},
		{"/Users/u/~x", "~/~x"},
		{"/tmp/$(rm)", "'/tmp/$(rm)'"},
	} {
		if got := ui.ShellWord(home, tc.p); got != tc.want {
			t.Errorf("ShellWord(%q) = %q, want %q", tc.p, got, tc.want)
		}
	}
}
