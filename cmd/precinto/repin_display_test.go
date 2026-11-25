package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Neorichi/precinto/internal/vault"
)

// D96 (SEC-F3): a re-pointed plugin link whose target's path carries
// terminal controls is refused, and no raw control reaches the terminal:
// the repin lines cannot be repainted.
func TestRepinDisplayHasNoControls(t *testing.T) {
	e := newEnv(t)
	fake := "\x1b[2K\rprecinto:   current SHA-256  " + strings.Repeat("a", 64) + "\n\x1b[8m"
	dir := filepath.Join(e.h.Dir, "c", fake, "Cellar", "age-plugin-se", "0.2.3", "bin")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	evil := filepath.Join(dir, "age-plugin-se")
	if err := os.WriteFile(evil, []byte("evil plugin\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	linkDir := filepath.Join(e.h.Dir, "brewbin")
	if err := os.MkdirAll(linkDir, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(linkDir, "age-plugin-se")
	if err := os.Symlink(evil, link); err != nil {
		t.Fatal(err)
	}
	m := e.vaults.metas[vault.GlobalID]
	m.Factors[0].PluginLink = link
	m.Factors[0].PluginPath = filepath.Join(e.h.Dir, "old", "age-plugin-se")
	m.Factors[0].PluginSHA256 = strings.Repeat("a", 64)
	e.vaults.metas[vault.GlobalID] = m
	e.tty.lines = []string{"no"}
	if code := e.run("factor", "repin", "se"); code == exitOK {
		t.Fatal("repin accepted a binary path with terminal controls")
	}
	out := e.stderr() + e.stdout()
	if strings.ContainsAny(out, "\x1b\r") || strings.Count(out, "current SHA-256") > 0 {
		t.Fatalf("raw controls or injected lines reached the terminal: %q", out)
	}
}

func TestShownValueEscapes(t *testing.T) {
	for in, want := range map[string]string{
		"/opt/homebrew/bin/age-plugin-se": "/opt/homebrew/bin/age-plugin-se",
		"~/Dise\u00f1o/bin":               "~/Dise\u00f1o/bin",
		"/x/\x1b[2K\r/y":                  `"/x/\x1b[2K\r/y"`,
		"/x/\u202e/y":                     `"/x/\u202e/y"`,
		"/x/\u200b/y":                     `"/x/\u200b/y"`,
	} {
		if got := shownValue(in); got != want {
			t.Errorf("shownValue(%q) = %s, want %s", in, got, want)
		}
	}
}
