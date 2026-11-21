package archtest

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// repoRoot walks up from the test's working directory to go.mod.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found")
		}
		dir = parent
	}
}

type pkgFiles struct {
	rel   string
	files []string // non-test .go files
}

// collect returns every directory containing non-test Go files.
func collect(t *testing.T, root string) map[string]*pkgFiles {
	t.Helper()
	out := map[string]*pkgFiles{}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			name := d.Name()
			if p != root && (strings.HasPrefix(name, ".") || name == "testdata" || name == "docs") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return nil
		}
		rel, _ := filepath.Rel(root, filepath.Dir(p))
		rel = filepath.ToSlash(rel)
		if out[rel] == nil {
			out[rel] = &pkgFiles{rel: rel}
		}
		out[rel].files = append(out[rel].files, p)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func isStdlib(path string) bool {
	first, _, _ := strings.Cut(path, "/")
	return !strings.Contains(first, ".")
}

func TestEveryPackageHasAContract(t *testing.T) {
	root := repoRoot(t)
	contract := map[string]Package{}
	for _, p := range Packages {
		if _, dup := contract[p.Path]; dup {
			t.Errorf("duplicate contract entry %s", p.Path)
		}
		contract[p.Path] = p
	}
	for rel := range collect(t, root) {
		if _, ok := contract[rel]; !ok {
			t.Errorf("package %s has no entry in archtest.Packages (owner, layer, allowed imports)", rel)
		}
	}
}

func TestImportAllowlist(t *testing.T) {
	root := repoRoot(t)
	contract := map[string]Package{}
	for _, p := range Packages {
		contract[p.Path] = p
	}
	fset := token.NewFileSet()
	for rel, pf := range collect(t, root) {
		pkg, ok := contract[rel]
		if !ok {
			continue // reported by TestEveryPackageHasAContract
		}
		allowed := map[string]bool{}
		for _, a := range pkg.Internal {
			allowed[Module+"/"+a] = true
		}
		for _, a := range pkg.External {
			allowed[a] = true
		}
		for _, f := range pf.files {
			af, err := parser.ParseFile(fset, f, nil, parser.ImportsOnly)
			if err != nil {
				t.Fatalf("%s: %v", f, err)
			}
			for _, imp := range af.Imports {
				path := strings.Trim(imp.Path.Value, `"`)
				if isStdlib(path) {
					continue
				}
				if !allowed[path] {
					t.Errorf("%s imports %s, which is not in its allowlist (docs/API.md)", rel, path)
					continue
				}
				if strings.HasPrefix(path, Module+"/") {
					dep := contract[strings.TrimPrefix(path, Module+"/")]
					if dep.TestOnly && !pkg.TestOnly {
						t.Errorf("%s (production) imports test-only %s", rel, dep.Path)
					}
					if dep.Layer > pkg.Layer {
						t.Errorf("%s (layer %d) imports higher layer %s (layer %d)", rel, pkg.Layer, dep.Path, dep.Layer)
					}
				}
			}
		}
	}
}

// envReaders are the functions that read the process environment, per
// import path: only internal/paths may call them (D6).
var envReaders = map[string]map[string]bool{
	"os": {"Getenv": true, "LookupEnv": true, "Environ": true, "ExpandEnv": true,
		"UserHomeDir": true, "UserCacheDir": true, "UserConfigDir": true, "TempDir": true},
	"syscall":               {"Getenv": true, "Environ": true},
	"golang.org/x/sys/unix": {"Getenv": true, "Environ": true},
	"os/exec":               {"LookPath": true}, // reads $PATH: use paths.LookPath
}

// TestOnlyPathsReadsEnv enforces that only internal/paths reads the process
// environment (D6): os.Getenv/LookupEnv/Environ/ExpandEnv/UserHomeDir/
// UserCacheDir/UserConfigDir/TempDir, syscall and x/sys/unix
// Getenv/Environ, and exec.LookPath, under any import alias; dot imports of
// those packages are refused. It also requires every file that builds an
// exec.Cmd (exec.Command, exec.CommandContext) to assign an explicit Env
// (an exec.Cmd with a nil Env inherits the whole environment).
func TestOnlyPathsReadsEnv(t *testing.T) {
	root := repoRoot(t)
	fset := token.NewFileSet()
	var bad []string
	for rel, pf := range collect(t, root) {
		if rel == "internal/paths" {
			continue
		}
		for _, f := range pf.files {
			af, err := parser.ParseFile(fset, f, nil, 0)
			if err != nil {
				t.Fatalf("%s: %v", f, err)
			}
			local := map[string]string{} // local name → import path
			for _, imp := range af.Imports {
				path := strings.Trim(imp.Path.Value, `"`)
				if _, watched := envReaders[path]; !watched {
					continue
				}
				name := path[strings.LastIndex(path, "/")+1:]
				if imp.Name != nil {
					name = imp.Name.Name
				}
				if name == "." {
					bad = append(bad, fset.Position(imp.Pos()).String()+": dot import of "+path)
					continue
				}
				local[name] = path
			}
			builds, setsEnv := false, false
			var buildPos token.Pos
			ast.Inspect(af, func(n ast.Node) bool {
				switch n := n.(type) {
				case *ast.SelectorExpr:
					x, ok := n.X.(*ast.Ident)
					if !ok {
						return true
					}
					path, ok := local[x.Name]
					if !ok {
						return true
					}
					if envReaders[path][n.Sel.Name] {
						bad = append(bad, fset.Position(n.Pos()).String()+": "+path+"."+n.Sel.Name)
					}
					if path == "os/exec" && (n.Sel.Name == "Command" || n.Sel.Name == "CommandContext") && !builds {
						builds, buildPos = true, n.Pos()
					}
				case *ast.AssignStmt:
					for _, l := range n.Lhs {
						if sel, ok := l.(*ast.SelectorExpr); ok && sel.Sel.Name == "Env" {
							setsEnv = true
						}
					}
				case *ast.KeyValueExpr:
					if k, ok := n.Key.(*ast.Ident); ok && k.Name == "Env" {
						setsEnv = true
					}
				}
				return true
			})
			if builds && !setsEnv {
				bad = append(bad, fset.Position(buildPos).String()+": exec.Cmd without an explicit Env")
			}
		}
	}
	sort.Strings(bad)
	for _, b := range bad {
		t.Errorf("%s: read the environment through internal/paths (D6)", b)
	}
}
