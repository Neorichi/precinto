//go:build darwin || linux

package fsx

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// D67 tests. The account databases are a seam (accountFiles): every test
// here reads fake passwd and group files from t.TempDir(), never the
// host's. privateGroups is switched on for the test so that the linux path
// also runs on darwin, where production keeps it off.

func resetUPGCache() {
	upgCache.mu.Lock()
	upgCache.key, upgCache.gid, upgCache.ok = "", 0, false
	upgCache.mu.Unlock()
}

// fakeAccounts points the D67 check at fresh fake databases (written to new
// files each call, so the cache key always changes) and enables it.
func fakeAccounts(t *testing.T, passwd, group string) (passwdPath, groupPath string) {
	t.Helper()
	dir := t.TempDir()
	passwdPath, groupPath = filepath.Join(dir, "passwd"), filepath.Join(dir, "group")
	if err := os.WriteFile(passwdPath, []byte(passwd), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(groupPath, []byte(group), 0o644); err != nil {
		t.Fatal(err)
	}
	oldFiles, oldOn := accountFiles, privateGroups
	accountFiles.passwd, accountFiles.group = passwdPath, groupPath
	privateGroups = true
	resetUPGCache()
	t.Cleanup(func() {
		accountFiles, privateGroups = oldFiles, oldOn
		resetUPGCache()
	})
	return passwdPath, groupPath
}

// The exception is linux-only: darwin primary groups (staff) are shared.
func TestPrivateGroupsOnlyOnLinux(t *testing.T) {
	if want := runtime.GOOS == "linux"; privateGroups != want {
		t.Fatalf("privateGroups = %v on %s", privateGroups, runtime.GOOS)
	}
	if accountFiles.passwd != "/etc/passwd" || accountFiles.group != "/etc/group" {
		t.Fatalf("account databases %+v", accountFiles)
	}
}

func TestPrivateGroupOfTable(t *testing.T) {
	const alice = "alice:x:1000:1000:Alice:/home/alice:/bin/bash\n"
	const others = "root:x:0:0:root:/root:/bin/bash\nbob:x:1001:1001::/home/bob:/bin/sh\n"
	const groups = "root:x:0:\nsudo:x:27:alice,bob\nbob:x:1001:\n"
	for _, c := range []struct {
		name          string
		passwd, group string
		ok            bool
	}{
		{"user-private group", others + alice, groups + "alice:x:1000:\n", true},
		{"lists only the user", others + alice, groups + "alice:x:1000:alice\n", true},
		{"comments, blanks and CRLF", "# users\n\n  " + alice + "\r\n" + others, "# groups\r\nalice:x:1000:\r\n" + groups, true},
		{"another member", others + alice, groups + "alice:x:1000:bob\n", false},
		{"another member among blanks", others + alice, groups + "alice:x:1000: alice , bob \n", false},
		{"named unlike the user", others + alice, groups + "staff:x:1000:\n", false},
		{"group missing (NSS only)", others + alice, groups, false},
		{"gid listed twice", others + alice, groups + "alice:x:1000:\nalice2:x:1000:\n", false},
		{"another account's primary group", others + alice + "carol:x:1002:1000::/home/carol:/bin/sh\n", groups + "alice:x:1000:\n", false},
		{"two names for the uid", others + alice + "toor:x:1000:1000::/:/bin/sh\n", groups + "alice:x:1000:\n", false},
		{"user missing (NSS only)", others, groups + "alice:x:1000:\n", false},
		{"NIS compat passwd", others + alice + "+::::::\n", groups + "alice:x:1000:\n", false},
		{"NIS compat group", others + alice, groups + "alice:x:1000:\n+:::\n", false},
		{"NIS exclusion", others + alice + "-bob::::::\n", groups + "alice:x:1000:\n", false},
		{"malformed passwd record", others + alice + "broken:x:1003\n", groups + "alice:x:1000:\n", false},
		{"malformed group record", others + alice, groups + "alice:x:1000:\nbroken:x\n", false},
		{"non-numeric gid", "alice:x:1000:abc::/home/alice:/bin/bash\n", "alice:x:1000:\n", false},
		{"gid out of range", "alice:x:1000:4294967296::/home/alice:/bin/bash\n", "alice:x:1000:\n", false},
		{"empty databases", "", "", false},
	} {
		gid, ok := privateGroupOf(1000, []byte(c.passwd), []byte(c.group))
		if ok != c.ok || ok && gid != 1000 {
			t.Errorf("%s: privateGroupOf = %d %v, want ok=%v", c.name, gid, ok, c.ok)
		}
	}
}

// upgUnit is a base with a group-writable directory g (group = the
// effective gid) holding one file.
func upgUnit(t *testing.T, mode os.FileMode) (*Dir, string) {
	t.Helper()
	root, err := Realpath(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	g := filepath.Join(root, "g")
	if err := os.Mkdir(g, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(g, "file"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	// darwin gives a new directory its parent's group: make it the egid.
	if err := os.Chown(g, -1, os.Getegid()); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(g, mode); err != nil {
		t.Fatal(err)
	}
	d, err := OpenBase(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	return d, g
}

func me() (string, string) {
	return fmt.Sprintf("tester:x:%d:%d::/nonexistent:/bin/false\n", os.Geteuid(), os.Getegid()),
		fmt.Sprintf("tester:x:%d:\n", os.Getegid())
}

// opensAndWalks reports whether g/file opens and g is walked as safe.
func opensAndWalks(t *testing.T, d *Dir) (opened bool, hazard Hazard) {
	t.Helper()
	f, _, err := d.Open("g/file")
	switch {
	case err == nil:
		f.Close()
		opened = true
	case !errors.Is(err, ErrUnsafe):
		t.Fatalf("Open: %v", err)
	}
	hazard = "unvisited"
	if err := d.Walk("", func(e WalkEntry) error {
		if e.Rel == "g" {
			hazard = e.Hazard
		}
		return nil
	}); err != nil {
		t.Fatalf("Walk: %v", err)
	}
	return opened, hazard
}

func TestUserPrivateGroupDirectories(t *testing.T) {
	passwd, group := me()

	t.Run("off (darwin)", func(t *testing.T) {
		d, _ := upgUnit(t, 0o775)
		fakeAccounts(t, passwd, group)
		privateGroups = false
		if opened, hz := opensAndWalks(t, d); opened || hz != HazardForeign {
			t.Fatalf("with the exception off: opened=%v hazard=%q", opened, hz)
		}
	})

	for _, mode := range []os.FileMode{0o775, 0o770, 0o2775} {
		t.Run(fmt.Sprintf("upg %04o", mode), func(t *testing.T) {
			d, _ := upgUnit(t, mode)
			fakeAccounts(t, passwd, group)
			if opened, hz := opensAndWalks(t, d); !opened || hz != HazardNone {
				t.Fatalf("user-private group: opened=%v hazard=%q", opened, hz)
			}
			f, _, err := d.CreateTemp("g", ".t-*")
			if err != nil {
				t.Fatalf("CreateTemp below a user-private group directory: %v", err)
			}
			f.Close()
		})
	}

	t.Run("other-writable", func(t *testing.T) {
		d, _ := upgUnit(t, 0o777)
		fakeAccounts(t, passwd, group)
		if opened, hz := opensAndWalks(t, d); opened || hz != HazardForeign {
			t.Fatalf("0777: opened=%v hazard=%q", opened, hz)
		}
	})

	for name, db := range map[string][2]string{
		"another member":   {passwd, fmt.Sprintf("tester:x:%d:intruder\n", os.Getegid())},
		"named otherwise":  {passwd, fmt.Sprintf("staff:x:%d:\n", os.Getegid())},
		"group missing":    {passwd, "other:x:4242:\n"},
		"user missing":     {"other:x:4242:4242::/:/bin/false\n", group},
		"shared primary":   {passwd + fmt.Sprintf("other:x:4242:%d::/:/bin/false\n", os.Getegid()), group},
		"NIS compat group": {passwd, group + "+:::\n"},
	} {
		t.Run(name, func(t *testing.T) {
			d, _ := upgUnit(t, 0o775)
			fakeAccounts(t, db[0], db[1])
			if opened, hz := opensAndWalks(t, d); opened || hz != HazardForeign {
				t.Fatalf("opened=%v hazard=%q, want refused", opened, hz)
			}
		})
	}

	t.Run("untrusted databases", func(t *testing.T) {
		d, _ := upgUnit(t, 0o775)
		pw, gr := fakeAccounts(t, passwd, group)
		if opened, _ := opensAndWalks(t, d); !opened {
			t.Fatal("baseline refused")
		}
		// A database anyone else may write is not evidence.
		if err := os.Chmod(gr, 0o664); err != nil {
			t.Fatal(err)
		}
		if opened, _ := opensAndWalks(t, d); opened {
			t.Error("group-writable group database trusted")
		}
		if err := os.Chmod(gr, 0o644); err != nil {
			t.Fatal(err)
		}
		// A symlinked, missing or FIFO database is undeterminable.
		real := pw + ".real"
		if err := os.Rename(pw, real); err != nil {
			t.Fatal(err)
		}
		if opened, _ := opensAndWalks(t, d); opened {
			t.Error("missing passwd database trusted")
		}
		if err := os.Symlink(real, pw); err != nil {
			t.Fatal(err)
		}
		if opened, _ := opensAndWalks(t, d); opened {
			t.Error("symlinked passwd database trusted")
		}
		if err := os.Remove(pw); err != nil {
			t.Fatal(err)
		}
		if err := syscall.Mkfifo(pw, 0o644); err != nil {
			t.Fatal(err)
		}
		done := make(chan bool, 1)
		go func() { opened, _ := opensAndWalks(t, d); done <- opened }()
		select {
		case opened := <-done:
			if opened {
				t.Error("FIFO passwd database trusted")
			}
		case <-time.After(2 * time.Second):
			t.Fatal("a FIFO account database blocked the check")
		}
	})

	t.Run("database changes are seen", func(t *testing.T) {
		d, _ := upgUnit(t, 0o775)
		_, gr := fakeAccounts(t, passwd, group)
		if opened, _ := opensAndWalks(t, d); !opened {
			t.Fatal("baseline refused")
		}
		// root adds a member: the next check reads the new database.
		tmp := gr + ".new"
		if err := os.WriteFile(tmp, []byte(fmt.Sprintf("tester:x:%d:intruder\n", os.Getegid())), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(tmp, gr); err != nil {
			t.Fatal(err)
		}
		if opened, hz := opensAndWalks(t, d); opened || hz != HazardForeign {
			t.Fatalf("after a member was added: opened=%v hazard=%q", opened, hz)
		}
	})

	t.Run("group other than the effective gid", func(t *testing.T) {
		groups, err := os.Getgroups()
		if err != nil {
			t.Fatal(err)
		}
		other := -1
		for _, g := range groups {
			if g != os.Getegid() {
				other = g
				break
			}
		}
		if other < 0 {
			t.Skip("the test user belongs to no second group")
		}
		d, g := upgUnit(t, 0o775)
		if err := os.Chown(g, -1, other); err != nil {
			t.Skipf("chgrp: %v", err)
		}
		if err := os.Chmod(g, 0o775); err != nil { // chown may clear bits
			t.Fatal(err)
		}
		// Even a database naming that group the user's private one does
		// not help: the exception needs the process's own effective gid.
		fakeAccounts(t, fmt.Sprintf("tester:x:%d:%d::/nonexistent:/bin/false\n", os.Geteuid(), other),
			fmt.Sprintf("tester:x:%d:\n", other))
		if opened, hz := opensAndWalks(t, d); opened || hz != HazardForeign {
			t.Fatalf("group %d (egid %d): opened=%v hazard=%q", other, os.Getegid(), opened, hz)
		}
	})
}

// The account databases are opened like every other untrusted file: a
// FIFO fails at once, a directory is not a regular file, size is bounded.
func TestReadAccountFileRefusesNonRegular(t *testing.T) {
	dir := t.TempDir()
	if _, err := readAccountFile(dir); !errors.Is(err, ErrUnsafe) {
		t.Errorf("directory: %v", err)
	}
	if _, err := readAccountFile(filepath.Join(dir, "missing")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("missing: %v", err)
	}
	big := filepath.Join(dir, "big")
	f, err := os.Create(big)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(maxAccountFile + 1); err != nil {
		t.Fatal(err)
	}
	f.Close()
	if err := os.Chmod(big, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readAccountFile(big); !errors.Is(err, ErrUnsafe) {
		t.Errorf("oversized: %v", err)
	}
	fifo := filepath.Join(dir, "fifo")
	if err := unix.Mkfifo(fifo, 0o644); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := readAccountFile(fifo); done <- err }()
	select {
	case err := <-done:
		if !errors.Is(err, ErrUnsafe) {
			t.Errorf("FIFO: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("readAccountFile blocked on a FIFO")
	}
}
