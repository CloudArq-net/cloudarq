package arch

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"unicode"
)

// unicodeTables names, for each standard package that carries or reads the
// toolchain's Unicode tables, what reads them: the case mappings and
// properties, and what says which characters are printable, graphic or a
// letter. Those tables are the Unicode version of the toolchain that
// compiled the engine, and they moved between Go 1.24.13 (Unicode 15.0.0)
// and Go 1.27.1 (Unicode 17.0.0): for the case of 116 code points, U+FB05
// among them, and for whether 10,615 are printable, U+A7CB among them. An
// answer read from them is one answer per compiler, and the command line
// and the WebAssembly engine are built by different ones. Quoting a string
// with strconv.Quote, or fmt's %q, escapes what the tables call
// unprintable and keeps the rest as written, so it reads them too;
// strconv.QuoteToASCII and %+q escape everything beyond ASCII and read
// none.
//
// Every member of package unicode is a table or reads one, but for the
// few in unicodeTableFree.
var unicodeTables = map[string][]string{
	"strings": {"EqualFold", "ToLower", "ToUpper", "ToTitle", "Title", "ToLowerSpecial", "ToUpperSpecial", "ToTitleSpecial"},
	"bytes":   {"EqualFold", "ToLower", "ToUpper", "ToTitle", "Title", "ToLowerSpecial", "ToUpperSpecial", "ToTitleSpecial"},
	"strconv": {"Quote", "QuoteRune", "QuoteToGraphic", "QuoteRuneToGraphic", "AppendQuote", "AppendQuoteRune",
		"AppendQuoteToGraphic", "AppendQuoteRuneToGraphic", "IsPrint", "IsGraphic"},
}

// unicodeTableFree are the members of package unicode that read no table
// whose contents moved: its bounds, IsControl, which reads Latin-1 alone,
// and IsSpace, which reads White_Space, the one table TestWhiteSpaceIsPinned
// holds to the code points it has on every toolchain the gates run.
var unicodeTableFree = []string{"MaxRune", "ReplacementChar", "MaxASCII", "MaxLatin1", "IsControl", "IsSpace"}

// whiteSpace is Unicode's White_Space property, which unicode.IsSpace, and
// through it strings.TrimSpace and strings.Fields, read: the same 25 code
// points in Unicode 15.0.0 and 17.0.0, from U+0009 to U+3000.
var whiteSpace = []rune{
	0x0009, 0x000A, 0x000B, 0x000C, 0x000D, 0x0020, 0x0085, 0x00A0, 0x1680,
	0x2000, 0x2001, 0x2002, 0x2003, 0x2004, 0x2005, 0x2006, 0x2007, 0x2008, 0x2009, 0x200A,
	0x2028, 0x2029, 0x202F, 0x205F, 0x3000,
}

// TestWhiteSpaceIsPinned: the engine reads White_Space through the
// standard library, which is safe only while every toolchain that builds
// it carries the same table. A toolchain whose table differs fails here,
// before an answer can differ.
func TestWhiteSpaceIsPinned(t *testing.T) {
	var got []rune
	for r := rune(0); r <= unicode.MaxRune; r++ {
		if unicode.IsSpace(r) {
			got = append(got, r)
		}
	}
	if !slices.Equal(got, whiteSpace) {
		t.Fatalf("Unicode %s's White_Space is %U; the engine was proven on %U", unicode.Version, got, whiteSpace)
	}
	t.Logf("Unicode %s: %d code points of White_Space, as pinned", unicode.Version, len(got))
}

// TestNoStandardUnicodeTableDecidesAnAnswer holds every Go file of the
// module, tests aside, to one rule: nothing names a Unicode table of the
// standard library, nor quotes through one. What a letter may fold to is
// read from internal/parse/casefold, whose tables are generated from a
// pinned CaseFolding.txt, ASCII case is folded by hand, and a string is
// quoted in ASCII. A use for anything else is still a use this test cannot
// tell from one that decides an answer, so there is none, but for the
// tool named in harmless. The files are found by walking the module,
// not by go list, which leaves out a package whose every file is for
// another platform, as the WebAssembly engine's is.
func TestNoStandardUnicodeTableDecidesAnAnswer(t *testing.T) {
	gomod, err := exec.Command("go", "env", "GOMOD").Output()
	if err != nil || strings.TrimSpace(string(gomod)) == "" {
		t.Fatalf("go env GOMOD: %q, %v", gomod, err)
	}
	root := filepath.Dir(strings.TrimSpace(string(gomod)))
	examined, excused := 0, 0
	fset := token.NewFileSet()
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		switch {
		case err != nil:
			return err
		case d.IsDir() && path != root && (d.Name() == "node_modules" || d.Name() == "testdata" || strings.HasPrefix(d.Name(), ".") || strings.HasPrefix(d.Name(), "_")):
			return filepath.SkipDir
		case d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go"):
			return nil
		}
		file, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		examined++
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		for _, use := range tableUses(file) {
			if harmless[filepath.ToSlash(rel)] == use.name {
				excused++
				continue
			}
			t.Errorf("%s: %s reads the toolchain's Unicode tables; read internal/parse/casefold, fold ASCII by hand, or quote with strconv.QuoteToASCII or %%+q", fset.Position(use.pos), use.name)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	if examined == 0 {
		t.Fatalf("examined 0 files under %s; this test is proving nothing", root)
	}
	if excused != len(harmless) {
		t.Errorf("%d of the %d uses harmless names were met; a use named there and gone should leave the list", excused, len(harmless))
	}
	t.Logf("examined %d files; %d use excused", examined, excused)
}

// harmless are the uses the rule excuses, by file and use, each for a
// reason that no answer can carry it: the native twin under
// web/wasm/native renders the engine's answers natively to compare them
// with the WebAssembly build's, and its own usage error, naming a command
// it does not know, is no answer either build gives.
var harmless = map[string]string{
	"web/wasm/native/main.go": "fmt %q",
}

// tableUse is a use of a Unicode table: a selector that names one, or a
// format verb that quotes through one, as written, and where.
type tableUse struct {
	pos  token.Pos
	name string
}

// tableUses finds every selector in file that names a member of
// unicodeTables, or of package unicode, through the name the file imports
// its package under, called or not: strings.Map(unicode.ToLower, s) reads
// the table as surely as a call does. It finds as well every constant
// format string handed to a function of package fmt that holds %q without
// the + flag, or %U with the # flag, which print what the tables call
// printable as itself.
func tableUses(file *ast.File) []tableUse {
	imported := map[string]string{}
	for _, spec := range file.Imports {
		path, err := strconv.Unquote(spec.Path.Value)
		if err != nil || unicodeTables[path] == nil && path != "unicode" && path != "fmt" {
			continue
		}
		local := path
		if spec.Name != nil {
			local = spec.Name.Name
		}
		imported[local] = path
	}
	var uses []tableUse
	ast.Inspect(file, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.SelectorExpr:
			pkg, ok := n.X.(*ast.Ident)
			if !ok {
				return true
			}
			switch path := imported[pkg.Name]; {
			case path == "unicode" && !slices.Contains(unicodeTableFree, n.Sel.Name),
				slices.Contains(unicodeTables[path], n.Sel.Name):
				uses = append(uses, tableUse{n.Pos(), pkg.Name + "." + n.Sel.Name})
			}
		case *ast.CallExpr:
			sel, ok := n.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if pkg, ok := sel.X.(*ast.Ident); !ok || imported[pkg.Name] != "fmt" {
				return true
			}
			for _, arg := range n.Args {
				if lit, ok := arg.(*ast.BasicLit); ok && lit.Kind == token.STRING {
					if format, err := strconv.Unquote(lit.Value); err == nil && quotesThroughTables(format) {
						uses = append(uses, tableUse{lit.Pos(), "fmt %q"})
					}
				}
			}
		}
		return true
	})
	return uses
}

// quotesThroughTables reports whether a format string holds a verb that
// prints what the Unicode tables call printable as itself: %q without the
// + flag, which asks for ASCII, and %U with the # flag, which adds the
// character when it is printable.
func quotesThroughTables(format string) bool {
	for i := 0; i < len(format); i++ {
		if format[i] != '%' {
			continue
		}
		plus, sharp := false, false
		j := i + 1
		for ; j < len(format) && strings.IndexByte("+-# 0123456789.*[]", format[j]) >= 0; j++ {
			plus = plus || format[j] == '+'
			sharp = sharp || format[j] == '#'
		}
		if j == len(format) {
			return false
		}
		switch {
		case format[j] == '%':
		case format[j] == 'q' && !plus, format[j] == 'U' && sharp:
			return true
		}
		i = j
	}
	return false
}
