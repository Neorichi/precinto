package precinto_test

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/Neorichi/precinto"
)

// repoFiles lists the files precinto ships as plugins, at their repository
// paths: both marketplace manifests and every file of the two plugin roots
// (a Finder .DS_Store of a developer's checkout is not one of them).
func repoFiles(t *testing.T) []string {
	t.Helper()
	files := []string{".claude-plugin/marketplace.json", ".agents/plugins/marketplace.json"}
	for _, root := range []string{"plugin", "plugins/codex"} {
		err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || d.Name() == ".DS_Store" {
				return nil
			}
			if !d.Type().IsRegular() {
				t.Errorf("%s is not a regular file", p)
				return nil
			}
			files = append(files, filepath.ToSlash(p))
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	sort.Strings(files)
	return files
}

// D116: the binary carries exactly the plugin files of the repository, byte
// for byte: a file added to a plugin root without being embedded (or the
// reverse) fails here, so `precinto integrate` never installs a plugin
// that differs from the one in the repository.
func TestPluginsAreTheRepositoryFiles(t *testing.T) {
	var embedded []string
	err := fs.WalkDir(precinto.Plugins, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			embedded = append(embedded, p)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(embedded)
	want := repoFiles(t)
	if strings.Join(embedded, "\n") != strings.Join(want, "\n") {
		t.Fatalf("embedded files:\n%s\nrepository files:\n%s", strings.Join(embedded, "\n"), strings.Join(want, "\n"))
	}
	for _, p := range want {
		disk, err := os.ReadFile(filepath.FromSlash(p))
		if err != nil {
			t.Fatal(err)
		}
		emb, err := fs.ReadFile(precinto.Plugins, p)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(disk, emb) {
			t.Errorf("%s: the embedded bytes differ from the repository's", p)
		}
	}
	// Both marketplaces, both plugin roots.
	for _, p := range []string{".claude-plugin/marketplace.json", ".agents/plugins/marketplace.json",
		"plugin/.claude-plugin/plugin.json", "plugin/hooks/hooks.json", "plugin/scripts/precinto-hook",
		"plugins/codex/.codex-plugin/plugin.json", "plugins/codex/hooks/codex.json", "plugins/codex/scripts/precinto-hook"} {
		if _, err := fs.Stat(precinto.Plugins, p); err != nil {
			t.Errorf("%s is not embedded: %v", p, err)
		}
	}
}
