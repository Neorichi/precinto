package codex_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/precinto/precinto/internal/harness/codex"
	"github.com/precinto/precinto/internal/paths"
)

// recordHomes returns the user homes the per-root home's auth record has
// an entry for.
func recordHomes(t *testing.T, rootHome string) map[string]string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(rootHome, codex.AuthRecordName))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	var r struct {
		Homes map[string]string `json:"homes"`
	}
	if err := json.Unmarshal(b, &r); err != nil {
		t.Fatal(err)
	}
	return r.Homes
}

// D140 (S6-6, M6, SEC-46): precinto writes the folder's credentials into no
// CODEX_HOME other than the default ~/.codex. A scratch CODEX_HOME without
// an auth.json gets none and no entry, so wiping it later (or using it
// again, refreshed or not) can never count as a logout: neither the
// folder's copy nor the credentials of the home the user logged in with
// are removed.
func TestAuthSyncCreatesNoCopyInAnotherCodexHome(t *testing.T) {
	ctx := context.Background()
	seed, userAuth, rootAuth := authHomes(t) // U1 logged in and seeded the folder's home
	scratch := codex.Seed{UserHome: filepath.Join(filepath.Dir(seed.UserHome), "codex-scratch"), RootHome: seed.RootHome}
	if err := os.MkdirAll(scratch.UserHome, 0o700); err != nil {
		t.Fatal(err)
	}
	scratchAuth := filepath.Join(scratch.UserHome, "auth.json")
	run := func(s codex.Seed) {
		t.Helper()
		for _, op := range []func(context.Context, codex.Seed) error{codex.PrepareHome, codex.SyncAuthBack} {
			if err := op(ctx, s); err != nil {
				t.Fatal(err)
			}
		}
	}
	run(scratch)
	if got := readAuth(t, scratchAuth); got != "" {
		t.Fatalf("the folder's credentials were written into another CODEX_HOME: %q", got)
	}
	if _, ok := recordHomes(t, seed.RootHome)[scratch.UserHome]; ok {
		t.Fatal("an entry was recorded for a CODEX_HOME that got no copy")
	}
	// The folder's Codex refreshes the token: it still goes to the homes
	// that hold credentials, never into the scratch home.
	writeAuth(t, rootAuth, `{"tokens":"codextest-login-1-refreshed"}`, time.Now().Add(time.Minute))
	run(scratch)
	run(seed)
	if got := readAuth(t, scratchAuth); got != "" {
		t.Fatalf("a refreshed token was written into another CODEX_HOME: %q", got)
	}
	if readAuth(t, userAuth) != `{"tokens":"codextest-login-1-refreshed"}` {
		t.Fatalf("the refreshed token did not reach the user's own home: %q", readAuth(t, userAuth))
	}
	// Wiped and used again: still no logout anywhere.
	if err := os.RemoveAll(scratch.UserHome); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(scratch.UserHome, 0o700); err != nil {
		t.Fatal(err)
	}
	run(scratch)
	time.Sleep(10 * time.Millisecond)
	run(seed)
	if readAuth(t, userAuth) != `{"tokens":"codextest-login-1-refreshed"}` || readAuth(t, rootAuth) != `{"tokens":"codextest-login-1-refreshed"}` {
		t.Fatalf("a scratch CODEX_HOME logged the account out: ~/.codex %q, folder %q", readAuth(t, userAuth), readAuth(t, rootAuth))
	}
	// The default ~/.codex without an auth.json still gets the folder's
	// credentials (a first login inside the folder, D100).
	def := codex.Seed{UserHome: filepath.Join(filepath.Dir(seed.UserHome), "dot-codex"), UserDefault: true, RootHome: seed.RootHome}
	if err := os.MkdirAll(def.UserHome, 0o700); err != nil {
		t.Fatal(err)
	}
	run(def)
	if got := readAuth(t, filepath.Join(def.UserHome, "auth.json")); got != `{"tokens":"codextest-login-1-refreshed"}` {
		t.Fatalf("the default home did not get the folder's credentials: %q", got)
	}
}

// D140: the launch plan marks the user home as the default one only when
// CODEX_HOME is unset or names ~/.codex; its exit then writes a first login
// made inside the folder into ~/.codex, and into no other CODEX_HOME.
func TestPlanLaunchWritesCredentialsBackOnlyToTheDefaultHome(t *testing.T) {
	for _, tc := range []struct {
		name      string
		codexHome func(f *fx) string // "" : unset
		copied    bool
	}{
		{"CODEX_HOME unset", func(*fx) string { return "" }, true},
		{"CODEX_HOME naming ~/.codex", func(f *fx) string { return filepath.Join(f.h.HomeDir, ".codex") }, true},
		{"another CODEX_HOME", func(f *fx) string { return filepath.Join(f.h.Dir, "codex-other") }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFx(t)
			bin := filepath.Join(f.h.Dir, "bin", "codex")
			if err := os.MkdirAll(filepath.Dir(bin), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(bin, []byte("#!/bin/sh\n"), 0o700); err != nil {
				t.Fatal(err)
			}
			hc := f.e.Cfg.Harness["codex"]
			hc.Bin = bin
			f.e.Cfg.Harness["codex"] = hc
			env := map[string]string{"HOME": f.h.HomeDir, "PATH": "/usr/bin:/bin"}
			user := filepath.Join(f.h.HomeDir, ".codex")
			if v := tc.codexHome(f); v != "" {
				env[paths.EnvCodexHome] = v
				user = v
			}
			if err := os.MkdirAll(user, 0o700); err != nil { // a user home without auth.json
				t.Fatal(err)
			}
			f.e.Host = paths.FromMap(env)
			ctx := context.Background()
			plan, err := f.a.PlanLaunch(ctx, f.e, f.h.Root, []string{"codex"})
			if err != nil {
				t.Fatal(err)
			}
			if err := plan.Prepare(ctx); err != nil {
				t.Fatal(err)
			}
			writeAuth(t, filepath.Join(f.home, "auth.json"), `{"tokens":"codextest-folder-login"}`, time.Now()) // codex login in the folder
			if err := plan.Finish(ctx, 0); err != nil {
				t.Fatal(err)
			}
			got := readAuth(t, filepath.Join(user, "auth.json"))
			if (got != "") != tc.copied {
				t.Fatalf("user home %s after the exit: %q, want copied=%v", user, got, tc.copied)
			}
		})
	}
}
