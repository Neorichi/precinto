package codex_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/precinto/precinto/internal/harness/codex"
)

// authHomes is a user home with auth.json and a per-root home seeded from
// it once (the first sync records the credentials both hold).
func authHomes(t *testing.T) (seed codex.Seed, userAuth, rootAuth string) {
	t.Helper()
	dir := t.TempDir()
	seed = codex.Seed{UserHome: filepath.Join(dir, "codex-user"), RootHome: filepath.Join(dir, "base", "homes", "codex", "root-acme")}
	if err := os.MkdirAll(seed.UserHome, 0o700); err != nil {
		t.Fatal(err)
	}
	userAuth, rootAuth = filepath.Join(seed.UserHome, "auth.json"), filepath.Join(seed.RootHome, "auth.json")
	writeAuth(t, userAuth, `{"tokens":"codextest-login-1"}`, time.Now().Add(-time.Hour))
	if err := codex.PrepareHome(context.Background(), seed); err != nil {
		t.Fatal(err)
	}
	if got := readAuth(t, rootAuth); got != `{"tokens":"codextest-login-1"}` {
		t.Fatalf("first launch did not copy auth.json in: %q", got)
	}
	return seed, userAuth, rootAuth
}

func writeAuth(t *testing.T, path, data string, mt time.Time) {
	t.Helper()
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, mt, mt); err != nil {
		t.Fatal(err)
	}
}

// readAuth returns the file's content, or "" when it is missing.
func readAuth(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return ""
	}
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// D100 (M6): `codex logout` in the user's own home (auth.json removed) is
// never undone: the next exit of a folder's Codex does not write the
// folder's copy back, and the folder's copy of those credentials goes too.
func TestAuthSyncKeepsAUserLogout(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	for _, next := range []string{"SyncAuthBack", "PrepareHome"} {
		seed, userAuth, rootAuth := authHomes(t)
		if err := os.Remove(userAuth); err != nil { // codex logout
			t.Fatal(err)
		}
		var err error
		if next == "SyncAuthBack" {
			err = codex.SyncAuthBack(ctx, seed)
		} else {
			err = codex.PrepareHome(ctx, seed)
		}
		if err != nil {
			t.Fatal(err)
		}
		if got := readAuth(t, userAuth); got != "" {
			t.Errorf("%s: the user's logout was undone: auth.json is back", next)
		}
		if got := readAuth(t, rootAuth); got != "" {
			t.Errorf("%s: the folder's copy of the logged-out credentials was kept", next)
		}
		// Both sides are logged out; a new login in the user's home is
		// copied in at the next launch, as any first login.
		writeAuth(t, userAuth, `{"tokens":"codextest-login-2"}`, time.Now())
		if err := codex.PrepareHome(ctx, seed); err != nil {
			t.Fatal(err)
		}
		if got := readAuth(t, rootAuth); got != `{"tokens":"codextest-login-2"}` {
			t.Errorf("%s: a new login after the logout was not synchronized: %q", next, got)
		}
	}
}

// D100 (M6): a logout inside a folder's Codex (Codex's /logout removes the
// per-root auth.json) is never undone at the next launch, and the user's
// own copy of those credentials goes too; a newer login in the user's home
// (other credentials) is kept, and syncing resumes once it is copied in.
func TestAuthSyncKeepsAFolderLogout(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	seed, userAuth, rootAuth := authHomes(t)
	if err := os.Remove(rootAuth); err != nil { // /logout in the folder
		t.Fatal(err)
	}
	if err := codex.PrepareHome(ctx, seed); err != nil {
		t.Fatal(err)
	}
	if got := readAuth(t, rootAuth); got != "" {
		t.Fatalf("the folder's logout was undone at the next launch: %q", got)
	}
	if got := readAuth(t, userAuth); got != "" {
		t.Fatalf("the user's copy of the logged-out credentials was kept: %q", got)
	}

	// The same logout, but the user's home logged in again meanwhile:
	// those credentials are kept and not copied into the folder until the
	// folder has a copy of its own again.
	seed, userAuth, rootAuth = authHomes(t)
	if err := os.Remove(rootAuth); err != nil {
		t.Fatal(err)
	}
	writeAuth(t, userAuth, `{"tokens":"codextest-login-2"}`, time.Now())
	for _, op := range []func(context.Context, codex.Seed) error{codex.SyncAuthBack, codex.PrepareHome} {
		if err := op(ctx, seed); err != nil {
			t.Fatal(err)
		}
	}
	if got := readAuth(t, userAuth); got != `{"tokens":"codextest-login-2"}` {
		t.Fatalf("a newer login in the user's home was touched: %q", got)
	}
	if got := readAuth(t, rootAuth); got != "" {
		t.Fatalf("credentials were copied into a folder that logged out: %q", got)
	}
	// The folder logs in again (Codex's own login inside the session):
	// both sides hold credentials, the newer wins as before.
	writeAuth(t, rootAuth, `{"tokens":"codextest-login-3"}`, time.Now().Add(time.Minute))
	if err := codex.SyncAuthBack(ctx, seed); err != nil {
		t.Fatal(err)
	}
	if got := readAuth(t, userAuth); got != `{"tokens":"codextest-login-3"}` {
		t.Fatalf("syncing did not resume once both homes held credentials: %q", got)
	}
}

// D100: without a record (a home seeded by an earlier precinto, or a first
// login inside the folder) auth.json is copied to the side that has none,
// as before; the record is never-touch, 0600, and never sealed.
func TestAuthSyncFirstLoginAndRecord(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	dir := t.TempDir()
	seed := codex.Seed{UserHome: filepath.Join(dir, "u"), RootHome: filepath.Join(dir, "h")}
	os.MkdirAll(seed.UserHome, 0o700)
	if err := codex.PrepareHome(ctx, seed); err != nil {
		t.Fatal(err)
	}
	rootAuth, userAuth := filepath.Join(seed.RootHome, "auth.json"), filepath.Join(seed.UserHome, "auth.json")
	record := filepath.Join(seed.RootHome, codex.AuthRecordName)
	if _, err := os.Lstat(record); !os.IsNotExist(err) {
		t.Fatalf("a record without credentials: %v", err)
	}
	writeAuth(t, rootAuth, `{"tokens":"codextest-folder-login"}`, time.Now())
	if err := codex.SyncAuthBack(ctx, seed); err != nil {
		t.Fatal(err)
	}
	if got := readAuth(t, userAuth); got != `{"tokens":"codextest-folder-login"}` {
		t.Fatalf("a first login inside the folder did not reach the user's home: %q", got)
	}
	fi, err := os.Lstat(record)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("record %v %v", fi, err)
	}
	if c := codex.Classify(codex.AuthRecordName); c != codex.ClassNeverTouch {
		t.Fatalf("the auth record is %s, want never-touch (never sealed)", c)
	}
	// A record that cannot be decoded blocks copies into a missing side
	// and removes nothing.
	os.WriteFile(record, []byte("garbage"), 0o600)
	os.Remove(rootAuth)
	if err := codex.PrepareHome(ctx, seed); err != nil {
		t.Fatal(err)
	}
	if readAuth(t, rootAuth) != "" || readAuth(t, userAuth) == "" {
		t.Fatal("an unreadable record copied or removed credentials")
	}
}

// D100: the record names the user home it was synchronized with, so a
// launch with another CODEX_HOME (which has no auth.json) is no logout:
// the folder keeps its credentials.
func TestAuthSyncAnotherUserHomeIsNoLogout(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	seed, _, rootAuth := authHomes(t)
	other := codex.Seed{UserHome: filepath.Join(t.TempDir(), "other-codex"), RootHome: seed.RootHome}
	if err := os.MkdirAll(other.UserHome, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := codex.PrepareHome(ctx, other); err != nil {
		t.Fatal(err)
	}
	if got := readAuth(t, rootAuth); got != `{"tokens":"codextest-login-1"}` {
		t.Fatalf("a launch with another user home removed the folder's credentials: %q", got)
	}
}

// D100 (M6): the record keeps one entry per user home. A folder session
// with another CODEX_HOME (U2, which then gets a copy as its first login)
// does not erase the first home's entry, so `codex logout` in the user's
// own home (U1) is still recognised afterwards: neither SyncAuthBack nor
// PrepareHome writes the credentials back into U1.
func TestAuthSyncKeepsALogoutAfterAnotherUserHome(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	for _, next := range []string{"SyncAuthBack", "PrepareHome"} {
		seed, userAuth, rootAuth := authHomes(t)
		other := codex.Seed{UserHome: filepath.Join(t.TempDir(), "other-codex"), RootHome: seed.RootHome}
		if err := os.MkdirAll(other.UserHome, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := codex.PrepareHome(ctx, other); err != nil {
			t.Fatal(err)
		}
		if err := codex.SyncAuthBack(ctx, other); err != nil {
			t.Fatal(err)
		}
		otherAuth := filepath.Join(other.UserHome, "auth.json")
		if got := readAuth(t, otherAuth); got != `{"tokens":"codextest-login-1"}` {
			t.Fatalf("the other user home's first sync: %q", got)
		}
		if err := os.Remove(userAuth); err != nil { // codex logout in U1
			t.Fatal(err)
		}
		ops := []func(context.Context, codex.Seed) error{codex.SyncAuthBack, codex.PrepareHome}
		if next == "PrepareHome" {
			ops[0], ops[1] = ops[1], ops[0]
		}
		for _, op := range append(ops, codex.SyncAuthBack, codex.PrepareHome) {
			if err := op(ctx, seed); err != nil {
				t.Fatal(err)
			}
			if got := readAuth(t, userAuth); got != "" {
				t.Fatalf("%s first: the logout of the user's own home was undone after a session with another CODEX_HOME", next)
			}
		}
		if got := readAuth(t, rootAuth); got != "" {
			t.Errorf("%s first: the folder's copy of the logged-out credentials was kept", next)
		}
	}
}

// D100: a user home that is not there at a launch (an unmounted
// CODEX_HOME, a renamed ~/.codex) is no logout: PrepareHome keeps the
// folder's auth.json and the record, and syncing resumes when it is back.
func TestAuthSyncMissingUserHomeIsNoLogout(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	seed, userAuth, rootAuth := authHomes(t)
	away := seed.UserHome + ".away"
	if err := os.Rename(seed.UserHome, away); err != nil {
		t.Fatal(err)
	}
	for _, op := range []func(context.Context, codex.Seed) error{codex.PrepareHome, codex.SyncAuthBack} {
		if err := op(ctx, seed); err != nil {
			t.Fatal(err)
		}
	}
	if got := readAuth(t, rootAuth); got != `{"tokens":"codextest-login-1"}` {
		t.Fatalf("a missing user home removed the folder's credentials: %q", got)
	}
	if _, err := os.Lstat(seed.UserHome); !os.IsNotExist(err) {
		t.Fatalf("the missing user home was created: %v", err)
	}
	if err := os.Rename(away, seed.UserHome); err != nil {
		t.Fatal(err)
	}
	// Back, then logged out: the entry kept across the absence still
	// tells the logout from a first login.
	if err := os.Remove(userAuth); err != nil {
		t.Fatal(err)
	}
	if err := codex.SyncAuthBack(ctx, seed); err != nil {
		t.Fatal(err)
	}
	if readAuth(t, userAuth) != "" || readAuth(t, rootAuth) != "" {
		t.Fatal("the logout after the user home came back was undone")
	}
}
