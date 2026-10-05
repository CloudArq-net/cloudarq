package arch

import (
	"bytes"
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"slices"
	"strings"
	"testing"
)

// callerCopies are the two places the strip that takes a person out of a
// refusal's message lives, each with the package it is compiled in: the
// engine's, which reads bundles already written, and the collector's,
// which writes them. The engine's module may not import the collector's,
// and the collector could import the engine only by a published version,
// so the one file is kept twice.
var callerCopies = []struct{ path, pkg string }{
	{"../../internal/report/caller.go", "report"},
	{"../../internal/collect/aws/caller.go", "aws"},
}

// TestTheTwoStripsAreOneFile holds the copies to one text. Below the
// package clause they are the same bytes. Above it, neither carries a
// build constraint that could leave it out of a build. And each compiles
// alone, as a package of its one file, so neither reads a name another
// file of its package declares: the same text cannot mean two things in
// its two packages.
func TestTheTwoStripsAreOneFile(t *testing.T) {
	var bodies [][]byte
	for _, c := range callerCopies {
		raw, err := os.ReadFile(c.path)
		if err != nil {
			t.Fatal(err)
		}
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, c.path, raw, parser.ParseComments)
		if err != nil {
			t.Fatal(err)
		}
		if file.Name.Name != c.pkg {
			t.Fatalf("%s is in package %s, not %s", c.path, file.Name.Name, c.pkg)
		}
		for _, line := range strings.Split(string(raw[:fset.Position(file.Package).Offset]), "\n") {
			if strings.HasPrefix(line, "//go:build") || strings.HasPrefix(line, "// +build") {
				t.Errorf("%s: %s could leave this copy out of a build", c.path, line)
			}
		}
		if !slices.ContainsFunc(file.Decls, func(d ast.Decl) bool {
			f, ok := d.(*ast.FuncDecl)
			return ok && f.Recv == nil && f.Name.Name == "withoutPeople"
		}) {
			t.Errorf("%s declares no function withoutPeople", c.path)
		}
		config := types.Config{Importer: importer.ForCompiler(fset, "source", nil)}
		if _, err := config.Check(c.pkg, fset, []*ast.File{file}, nil); err != nil {
			t.Errorf("%s does not compile alone: %v", c.path, err)
		}
		clause := fset.Position(file.Name.End()).Offset
		newline := bytes.IndexByte(raw[clause:], '\n')
		if newline < 0 {
			t.Fatalf("%s holds nothing below its package clause", c.path)
		}
		bodies = append(bodies, raw[clause+newline+1:])
	}
	if !bytes.Equal(bodies[0], bodies[1]) {
		engine, collector := strings.Split(string(bodies[0]), "\n"), strings.Split(string(bodies[1]), "\n")
		line := 0
		for line < min(len(engine), len(collector)) && engine[line] == collector[line] {
			line++
		}
		t.Fatalf("the copies differ at line %d below their package clauses:\n%s: %+q\n%s: %+q", line+1,
			callerCopies[0].path, lineAt(engine, line), callerCopies[1].path, lineAt(collector, line))
	}
	t.Logf("%s and %s are the same %d bytes below their package clauses", callerCopies[0].path, callerCopies[1].path, len(bodies[0]))
}

func lineAt(lines []string, i int) string {
	if i < len(lines) {
		return lines[i]
	}
	return "(the file has ended)"
}
