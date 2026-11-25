//go:build testing && failpoints

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Neorichi/precinto/internal/fsx/failpoint"
)

// D148 (S6-7, D6-4): when the second rename of a marketplace swap fails
// (EIO), integrate exits 1 and puts the previous tree back, so Claude Code,
// which loads precinto's plugin in place from <base>/marketplace, keeps
// its hooks; no hidden tree is left.
func TestIntegrateFailedSwapKeepsThePreviousPlugin(t *testing.T) {
	e := newEnv(t)
	fakePluginDir(t, e, "claude")
	e.execOut["--version"] = []byte("2.1.329 (Claude Code)\n")
	if code := e.integrate("claude-code"); code != exitOK {
		t.Fatalf("exit %d (%s)", code, e.stderr())
	}
	dir := e.h.Layout.Marketplace
	hooks := filepath.Join(dir, "plugin", "hooks", "hooks.json")
	// The tree on disk differs from this binary's (an upgrade), so the
	// next integrate rebuilds and swaps it.
	stray := filepath.Join(dir, "plugin", "README.old")
	if err := os.WriteFile(stray, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	failpoint.Reset()
	defer failpoint.Reset()
	failpoint.Set("fsx.rename=errno:EIO:2") // the second rename: new tree -> marketplace
	e.execs = nil
	if code := e.integrate("claude-code"); code != exitError {
		t.Fatalf("a failed swap: exit %d, want %d (%s)", code, exitError, e.stderr())
	}
	if _, err := os.Stat(hooks); err != nil {
		t.Fatalf("a failed swap left <base>/marketplace without its plugin: %v", err)
	}
	if _, err := os.Stat(stray); err != nil {
		t.Fatalf("the tree in place is not the previous one: %v", err)
	}
	es, err := os.ReadDir(e.h.Layout.Base)
	if err != nil {
		t.Fatal(err)
	}
	for _, x := range es {
		if strings.HasPrefix(x.Name(), ".marketplace") {
			t.Errorf("left %s in the base", x.Name())
		}
	}
}

// D148 (S6-7, D6-4): a rename reports a failed directory fsync after the
// rename itself happened. When that is the first rename of a swap (the
// live tree to its hidden name), integrate still puts the previous tree
// back before it returns: Claude Code keeps precinto's plugin, and no
// hidden tree is left.
func TestIntegrateFsyncErrorAfterTheFirstRenamePutsThePluginBack(t *testing.T) {
	e := newEnv(t)
	fakePluginDir(t, e, "claude")
	e.execOut["--version"] = []byte("2.1.329 (Claude Code)\n")
	if code := e.integrate("claude-code"); code != exitOK {
		t.Fatalf("exit %d (%s)", code, e.stderr())
	}
	dir := e.h.Layout.Marketplace
	hooks := filepath.Join(dir, "plugin", "hooks", "hooks.json")
	stray := filepath.Join(dir, "plugin", "README.old")
	if err := os.WriteFile(stray, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	failpoint.Reset()
	defer failpoint.Reset()
	armed := false
	stop := failpoint.ObserveFS(func(op failpoint.FSOp) {
		if !armed && op.Kind == failpoint.FSRename && op.Done && op.Path == dir && strings.HasPrefix(filepath.Base(op.Target), ".marketplace.old-") {
			// The directory fsync right after this rename fails.
			armed = true
			failpoint.Set(fmt.Sprintf("fsx.fsync=errno:EIO:%d", failpoint.Hits("fsx.fsync")+1))
		}
	})
	defer stop()
	e.execs = nil
	if code := e.integrate("claude-code"); code != exitError {
		t.Fatalf("a failed swap: exit %d, want %d (%s)", code, exitError, e.stderr())
	}
	if !armed {
		t.Fatal("the first rename of the swap was not seen")
	}
	if _, err := os.Stat(hooks); err != nil {
		t.Fatalf("a failed swap left <base>/marketplace without its plugin: %v", err)
	}
	if _, err := os.Stat(stray); err != nil {
		t.Fatalf("the tree in place is not the previous one: %v", err)
	}
	es, err := os.ReadDir(e.h.Layout.Base)
	if err != nil {
		t.Fatal(err)
	}
	for _, x := range es {
		if strings.HasPrefix(x.Name(), ".marketplace") {
			t.Errorf("left %s in the base", x.Name())
		}
	}
}
