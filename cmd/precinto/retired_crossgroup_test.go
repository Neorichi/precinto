//go:build crossgroup

package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/precinto/precinto/internal/agent/agenttest"
	"github.com/precinto/precinto/internal/config"
	"github.com/precinto/precinto/internal/harness/claude/claudetest"
	"github.com/precinto/precinto/internal/ledger"
	"github.com/precinto/precinto/internal/testkit"
	"github.com/precinto/precinto/internal/vault/vaulttest"
)

// D142, D145 (R1), with the real agent and engine: unprotect keeps a
// folder's vault and the path its vault.toml records (D74). Such a
// retired folder is no folder the agent enforces, so no sweep seals its
// sessions — with config.toml intact, and with a config.toml that does
// not load, whose stand-in settings are the confirmed settings' folders
// and the agent's, never every folder a vault records.
func TestCrossgroupBrokenConfigLeavesARetiredFolderAlone(t *testing.T) {
	for _, broken := range []bool{false, true} {
		name := "config.toml loads"
		if broken {
			name = "config.toml does not load"
		}
		t.Run(name, func(t *testing.T) {
			h := realHome(t)
			fx := vaulttest.New(t, h.Layout.Base, lifecycleRoot)
			old := filepath.Join(h.HomeDir, "work", "old")
			if err := os.MkdirAll(old, 0o700); err != nil {
				t.Fatal(err)
			}
			// The vault of a folder unprotected earlier (D74), created with
			// the fixture's passphrase factor (vaulttest's test constant).
			const fixturePassphrase = "vaulttest:Q8#zN4!pW7^rT2&mK"
			ui := &vaulttest.UI{Secrets: []string{fixturePassphrase, fixturePassphrase}, Interactive: true}
			id, err := fx.Store.Create(context.Background(), "root-old", old, ui.AsUI())
			if err != nil {
				t.Fatal(err)
			}
			id.Destroy()
			good, err := config.Load(h.Layout.ConfigFile)
			if err != nil {
				t.Fatal(err)
			}
			if _, in := good.RootByID("root-old"); in {
				t.Fatal("config.toml lists the retired folder")
			}
			// The settings confirmed at that unprotect, signed by the folder
			// that stays (a shape precinto writes).
			if err := os.MkdirAll(filepath.Dir(h.Layout.PolicyPinned), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := config.SavePinned(h.Layout.PolicyPinned, config.Pinned{Config: good, MACs: map[string]string{lifecycleRoot: strings.Repeat("ab", 32)}}); err != nil {
				t.Fatal(err)
			}
			// A session the ledger ties to the retired folder, restored by
			// the unprotect: plaintext, as the user expects.
			const sid = "00000000-0000-4000-8000-0000000000c7"
			l := claudetest.New(t, h.Dir)
			ps := l.WriteSession(t, claudetest.Session{SID: sid, Cwd: old, Marker: testkit.Marker(t), ModTime: h.Clock.Now().Add(-time.Hour)})
			if err := ledger.Open(h.Layout.SessionsDir).Append(ledger.Event{Type: ledger.TypeTaint, Harness: "claude-code", SID: sid,
				Roots: []string{"root-old"}, Cwd: old, ConfigDir: h.ClaudeConfig, TmpDir: h.ClaudeTmp}); err != nil {
				t.Fatal(err)
			}
			ag := agenttest.Start(t, h.Layout, h.Clock, h.Procs)
			defer ag.Stop()
			if broken {
				b, err := os.ReadFile(h.Layout.ConfigFile)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(h.Layout.ConfigFile, append(b, []byte("\nbogus_key = 1\n")...), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			for _, args := range [][]string{{"sweep"}, {"sweep", "--lock", "--root", old, "--quiet"}} {
				a, e, _ := lifecycleApp(t, h)
				code := a.run(args)
				if gone(ps[0]) {
					t.Fatalf("%v sealed the session of a folder the user stopped protecting (exit %d, stderr %q)", args, code, e.stderr())
				}
			}
		})
	}
}
