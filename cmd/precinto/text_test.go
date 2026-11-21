package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
	"strings"
	"testing"
)

// The CLI's own texts follow the catalog rules of SPEC §16.3: never
// "root", "grant", "soft" or "hard" (the --root flag excepted).
func TestLocalTextsAvoidForbiddenWords(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "text.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	ast.Inspect(f, func(node ast.Node) bool {
		lit, ok := node.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		s, err := strconv.Unquote(lit.Value)
		if err != nil {
			t.Fatal(err)
		}
		n++
		clean := strings.ReplaceAll(s, "--root", "")
		for _, w := range []string{"root", "grant", "soft", "hard"} {
			if strings.Contains(strings.ToLower(clean), w) {
				t.Errorf("%s: text %q uses the forbidden word %q", fset.Position(lit.Pos()), s, w)
			}
		}
		return true
	})
	if n < 50 {
		t.Fatalf("only %d texts found; the parse is wrong", n)
	}
}
