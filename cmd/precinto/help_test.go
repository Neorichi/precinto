package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// decisionID matches the internal references of the design documents
// (D49, S15, HA6, UX-12, CC-08, …): user-facing text never carries them
// (UX-18); users act on words and commands, not on DECISIONS.md.
var decisionID = regexp.MustCompile(`\b(?:D|S|HA|IM|UX|CC|DC|R|I|SEC|OD|FX)-?[0-9]{1,3}\b`)

// goPlaceholder is the value name the flag package invents when a flag's
// help has no backquoted name.
var goPlaceholder = regexp.MustCompile(`(?m)^  --[a-z-]+ (?:string|value|int|uint|int64|uint64|float|duration)$`)

// helpOf returns `precinto <name> --help`.
func helpOf(t *testing.T, name string) string {
	t.Helper()
	e := newEnv(t)
	if code := e.run(name, "--help"); code != exitOK {
		t.Fatalf("%s --help: exit %d (%s)", name, code, e.stderr())
	}
	return e.stdout()
}

// UX-18: every visible command's help is in sync with its flags: the
// usage line names every flag the command takes, the flag list shows real
// value names, and no text carries an internal decision id.
func TestHelpMatchesTheFlags(t *testing.T) {
	e := newEnv(t)
	e.run("--help")
	if id := decisionID.FindString(e.stdout()); id != "" {
		t.Errorf("precinto --help shows %s:\n%s", id, e.stdout())
	}
	flagLine := regexp.MustCompile(`(?m)^  --([a-z-]+)`)
	for _, c := range commands {
		if c.hidden || c.name == "version" {
			continue
		}
		help := helpOf(t, c.name)
		if id := decisionID.FindString(help); id != "" {
			t.Errorf("%s --help shows %s:\n%s", c.name, id, help)
		}
		if m := goPlaceholder.FindString(help); m != "" {
			t.Errorf("%s --help shows a Go placeholder %q", c.name, m)
		}
		for _, m := range flagLine.FindAllStringSubmatch(help, -1) {
			if !strings.Contains(c.usage, "--"+m[1]) {
				t.Errorf("%s: --%s is a flag but not in the usage line %q", c.name, m[1], c.usage)
			}
		}
	}
}

// UX-18: the CLI's own texts (text.go) and the command table (main.go)
// carry no internal decision id either.
func TestCLITextsHaveNoDecisionIDs(t *testing.T) {
	for _, file := range []string{"text.go", "main.go"} {
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, file, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			s, err := strconv.Unquote(lit.Value)
			if err == nil && decisionID.MatchString(s) {
				t.Errorf("%s: %q shows %s", fset.Position(lit.Pos()), s, decisionID.FindString(s))
			}
			return true
		})
	}
}

// UX-18: every precinto command line in the READMEs uses flags the
// command has, and vault repair always names its vault (--root DIR or
// --global, as its usage requires).
func TestReadmeCommandsUseRealFlags(t *testing.T) {
	cmdRE := regexp.MustCompile("precinto ([a-z-]+)((?: [^`|\\n]*)?)")
	flags := map[string]map[string]bool{}
	known := func(cmd string) map[string]bool {
		if m, ok := flags[cmd]; ok {
			return m
		}
		m := map[string]bool{}
		for _, f := range regexp.MustCompile(`(?m)^  --([a-z-]+)`).FindAllStringSubmatch(helpOf(t, cmd), -1) {
			m[f[1]] = true
		}
		flags[cmd] = m
		return m
	}
	for _, readme := range []string{"README.md", "README.es.md"} {
		b, err := os.ReadFile(filepath.Join("..", "..", readme))
		if err != nil {
			t.Fatal(err)
		}
		n := 0
		for _, span := range regexp.MustCompile("`[^`\\n]*`|(?s)```.*?```").FindAllString(string(b), -1) {
			for _, m := range cmdRE.FindAllStringSubmatch(span, -1) {
				c, ok := lookup(m[1])
				if !ok || c.hidden {
					continue
				}
				n++
				args := m[2]
				if i := strings.Index(args, "#"); i >= 0 {
					args = args[:i]
				}
				for _, w := range strings.Fields(args) {
					if w == "--" || !strings.HasPrefix(w, "--") {
						continue // the end of precinto's flags, or no flag
					}
					name := strings.TrimRight(strings.SplitN(strings.TrimPrefix(w, "--"), "=", 2)[0], ".,;:)")
					if !known(m[1])[name] {
						t.Errorf("%s: `precinto %s%s` uses --%s, which %s does not have", readme, m[1], m[2], name, m[1])
					}
				}
				if m[1] == "vault" && strings.Contains(args, "repair") && !strings.Contains(args, "--root") && !strings.Contains(args, "--global") {
					t.Errorf("%s: `precinto vault%s` names no vault (--root DIR or --global)", readme, m[2])
				}
			}
		}
		if n < 40 {
			t.Fatalf("%s: only %d commands found; the parse is wrong", readme, n)
		}
	}
}
