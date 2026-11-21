package vault

import (
	"errors"
	"testing"

	"github.com/precinto/precinto/internal/fsx"
)

// The D75 rule for a binary to re-pin: a regular file owned by root or the
// user, writable by nobody else. A foreign owner cannot be created without
// root, so the rule is checked on crafted stats.
func TestCheckRepinStat(t *testing.T) {
	const me = 501
	for _, c := range []struct {
		name string
		st   fsx.Stat
		ok   bool
	}{
		{"mine, 0755", fsx.Stat{Mode: 0o100755, UID: me}, true},
		{"root's, 0755", fsx.Stat{Mode: 0o100755, UID: 0}, true},
		{"mine, 0700", fsx.Stat{Mode: 0o100700, UID: me}, true},
		{"another user's", fsx.Stat{Mode: 0o100755, UID: 4242}, false},
		{"group-writable", fsx.Stat{Mode: 0o100775, UID: me}, false},
		{"other-writable", fsx.Stat{Mode: 0o100757, UID: 0}, false},
		{"symlink", fsx.Stat{Mode: 0o120755, UID: me}, false},
		{"directory", fsx.Stat{Mode: 0o040755, UID: me}, false},
		{"FIFO", fsx.Stat{Mode: 0o010644, UID: me}, false},
	} {
		err := checkRepinStat("/opt/bin/age-plugin-x", c.st, me)
		if (err == nil) != c.ok || err != nil && !errors.Is(err, fsx.ErrUnsafe) {
			t.Errorf("%s: %v, want ok=%v", c.name, err, c.ok)
		}
	}
}
