package wrapper

import (
	"os"
	"path/filepath"
	"testing"
)

// CC-49: the wrapper's register carries the harness version its install
// path records (native installer, Homebrew), resolved through symlinks;
// nothing when the path names none. The harness is never run.
func TestHarnessVersion(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	file := func(rel string) string {
		p := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("#!/bin/sh\n"), 0o700); err != nil {
			t.Fatal(err)
		}
		return p
	}
	native := file("share/claude/versions/2.1.329")
	link := filepath.Join(dir, "bin", "claude")
	if err := os.MkdirAll(filepath.Dir(link), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(native, link); err != nil {
		t.Fatal(err)
	}
	cellar := file("Cellar/codex/0.154.0/bin/codex")
	npm := file("lib/node_modules/@openai/codex/bin/codex.js")
	deep := file("9.9.9/a/b/c/d/codex")
	for argv0, want := range map[string]string{
		link:                                "2.1.329", // the native installer's symlink
		native:                              "2.1.329",
		cellar:                              "0.154.0",
		npm:                                 "",
		deep:                                "", // more than four levels up
		"claude":                            "", // not absolute
		filepath.Join(dir, "missing/1.2.3"): "",
	} {
		if got := harnessVersion([]string{argv0, "--resume", "x"}); got != want {
			t.Errorf("harnessVersion(%s) = %q, want %q", argv0, got, want)
		}
	}
	if harnessVersion(nil) != "" {
		t.Error("no argv: a version")
	}
	for v, ok := range map[string]bool{"2.1.329": true, "0.154.0": true, "1.0": true, "1": false, ".1": false, "1.": false, "1..2": false, "1.2a": false, "": false} {
		if dottedVersion(v) != ok {
			t.Errorf("dottedVersion(%q) = %v", v, !ok)
		}
	}
}
