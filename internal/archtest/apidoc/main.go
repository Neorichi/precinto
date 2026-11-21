package main

import (
	"bytes"
	"flag"
	"fmt"
	"go/ast"
	"go/doc"
	"go/parser"
	"go/printer"
	"go/token"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/precinto/precinto/internal/archtest"
)

// Markers delimiting the generated part of docs/API.md.
const (
	beginMarker = "<!-- BEGIN GENERATED: go run ./internal/archtest/apidoc -splice docs/API.md -->"
	endMarker   = "<!-- END GENERATED -->"
)

// out receives the rendering (stdout, or a buffer for -splice/-check).
var out io.Writer = os.Stdout

func main() {
	splice := flag.String("splice", "", "rewrite the generated part of this file")
	check := flag.String("check", "", "exit 1 if the generated part of this file is out of date")
	flag.Parse()
	var buf bytes.Buffer
	if *splice != "" || *check != "" {
		out = &buf
	}
	groups := []string{archtest.G1, archtest.G2, archtest.G3, archtest.G4, archtest.G5, archtest.G6, archtest.G7}
	for _, g := range groups {
		fmt.Fprintf(out, "\n## %s\n", g)
		for _, p := range archtest.Packages {
			if p.Owner != g {
				continue
			}
			if err := renderPackage(p); err != nil {
				fmt.Fprintln(os.Stderr, "apidoc:", p.Path, err)
				os.Exit(1)
			}
		}
	}
	target := *splice
	if target == "" {
		target = *check
	}
	if target == "" {
		return
	}
	old, err := os.ReadFile(target)
	if err != nil {
		fmt.Fprintln(os.Stderr, "apidoc:", err)
		os.Exit(1)
	}
	text := string(old)
	i := strings.Index(text, beginMarker)
	j := strings.Index(text, endMarker)
	if i < 0 || j < i {
		fmt.Fprintln(os.Stderr, "apidoc: markers not found in", target)
		os.Exit(1)
	}
	updated := text[:i+len(beginMarker)] + "\n" + buf.String() + "\n" + text[j:]
	if *check != "" {
		if updated != text {
			fmt.Fprintln(os.Stderr, "apidoc:", target, "is out of date; run: go run ./internal/archtest/apidoc -splice", target)
			os.Exit(1)
		}
		return
	}
	if err := os.WriteFile(target, []byte(updated), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "apidoc:", err)
		os.Exit(1)
	}
}

func renderPackage(p archtest.Package) error {
	if p.Path == "." {
		fmt.Fprintf(out, "\n### `%s` (module root)\n\n", archtest.Module)
	} else {
		fmt.Fprintf(out, "\n### `%s`\n\n", p.Path)
	}
	kind := "production"
	if p.TestOnly {
		kind = "test-only helper (production packages must not import it)"
	}
	fmt.Fprintf(out, "- Owner: **%s** · layer %d · %s\n", p.Owner, p.Layer, kind)
	internal := "none"
	if len(p.Internal) > 0 {
		internal = "`" + strings.Join(p.Internal, "`, `") + "`"
	}
	fmt.Fprintf(out, "- May import (module): %s\n", internal)
	external := "stdlib only"
	if len(p.External) > 0 {
		external = "stdlib, `" + strings.Join(p.External, "`, `") + "`"
	}
	fmt.Fprintf(out, "- May import (third party): %s\n", external)
	fmt.Fprintf(out, "- Tests: %s\n", p.Tests)

	fset := token.NewFileSet()
	dir := filepath.FromSlash(p.Path)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	var files []*ast.File
	var names []string
	for _, e := range entries {
		n := e.Name()
		if e.IsDir() || !strings.HasSuffix(n, ".go") || strings.HasSuffix(n, "_test.go") {
			continue
		}
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		f, err := parser.ParseFile(fset, filepath.Join(dir, n), nil, parser.ParseComments)
		if err != nil {
			return err
		}
		// Keep one representative OS file: implementations differ, the
		// exported API lives in the shared files. The skipped OS files must
		// not export anything, or it would be missing from docs/API.md.
		if strings.Contains(n, "_linux") || strings.Contains(n, "_other") {
			if name := firstExported(f); name != "" {
				return fmt.Errorf("%s declares exported %s; declare exported identifiers in a shared file", n, name)
			}
			continue
		}
		files = append(files, f)
	}
	dp, err := doc.NewFromFiles(fset, files, archtest.ImportPath(p.Path))
	if err != nil {
		return err
	}
	if txt := strings.TrimSpace(dp.Doc); txt != "" {
		// Drop the "Owner: … Imports: …" paragraph (rendered above).
		var paras []string
		for _, para := range strings.Split(txt, "\n\n") {
			if strings.HasPrefix(strings.TrimSpace(para), "Owner:") {
				continue
			}
			paras = append(paras, para)
		}
		fmt.Fprintln(out)
		for i, para := range paras {
			if i > 0 {
				fmt.Fprintln(out, ">")
			}
			for _, line := range strings.Split(para, "\n") {
				fmt.Fprintln(out, ">", line)
			}
		}
	}
	var b bytes.Buffer
	emit := func(node any, docText string) {
		if docText != "" {
			for _, line := range strings.Split(strings.TrimRight(docText, "\n"), "\n") {
				if line == "" {
					b.WriteString("//\n")
				} else {
					b.WriteString("// " + line + "\n")
				}
			}
		}
		cfg := printer.Config{Mode: printer.UseSpaces | printer.TabIndent, Tabwidth: 8}
		_ = cfg.Fprint(&b, fset, node)
		b.WriteString("\n\n")
	}
	funcDecl := func(f *doc.Func) {
		d := *f.Decl
		d.Body = nil
		d.Doc = nil
		emit(&d, f.Doc)
	}
	genDecl := func(g *ast.GenDecl, docText string) {
		c := *g
		c.Doc = nil
		if c.Tok == token.VAR {
			// Elide long composite-literal values (e.g. archtest.Packages,
			// whose content is rendered as the per-package headers).
			var specs []ast.Spec
			for _, sp := range c.Specs {
				vs, ok := sp.(*ast.ValueSpec)
				if !ok || len(vs.Values) != 1 {
					specs = append(specs, sp)
					continue
				}
				cl, ok := vs.Values[0].(*ast.CompositeLit)
				if !ok || fset.Position(cl.End()).Line-fset.Position(cl.Pos()).Line < 40 {
					specs = append(specs, sp)
					continue
				}
				elided := *vs
				elided.Type = cl.Type
				elided.Values = nil
				elided.Comment = nil
				specs = append(specs, &elided)
				docText += "(Value elided here: it is rendered as the per-package headers of docs/API.md.)\n"
			}
			c.Specs = specs
		}
		emit(&c, docText)
	}
	for _, c := range dp.Consts {
		genDecl(c.Decl, c.Doc)
	}
	for _, v := range dp.Vars {
		genDecl(v.Decl, v.Doc)
	}
	for _, f := range dp.Funcs {
		funcDecl(f)
	}
	for _, t := range dp.Types {
		genDecl(t.Decl, t.Doc)
		for _, c := range t.Consts {
			genDecl(c.Decl, c.Doc)
		}
		for _, v := range t.Vars {
			genDecl(v.Decl, v.Doc)
		}
		for _, f := range t.Funcs {
			funcDecl(f)
		}
		for _, m := range t.Methods {
			funcDecl(m)
		}
	}
	rendered := strings.TrimRight(b.String(), "\n")
	if rendered == "" {
		rendered = "// (no exported identifiers)"
	}
	fmt.Fprintf(out, "\n```go\n%s\n```\n", rendered)
	return nil
}

// firstExported returns the first exported top-level identifier of f
// (functions, methods, types, constants, variables), or "".
func firstExported(f *ast.File) string {
	for _, d := range f.Decls {
		switch d := d.(type) {
		case *ast.FuncDecl:
			if d.Name.IsExported() {
				return d.Name.Name
			}
		case *ast.GenDecl:
			for _, sp := range d.Specs {
				switch sp := sp.(type) {
				case *ast.TypeSpec:
					if sp.Name.IsExported() {
						return sp.Name.Name
					}
				case *ast.ValueSpec:
					for _, n := range sp.Names {
						if n.IsExported() {
							return n.Name
						}
					}
				}
			}
		}
	}
	return ""
}
