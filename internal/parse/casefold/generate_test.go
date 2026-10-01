package casefold

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// update makes the generator write tables.go instead of comparing it:
//
//	go test ./internal/parse/casefold -run TestTheTablesAreCaseFoldingTxt -update
var update = flag.Bool("update", false, "rewrite tables.go from "+sourcePath)

// The pinned source. Moving to another Unicode version is one act: the file,
// its first line, its address, its digest and the capture date change
// together, and the tables are generated again from it.
const (
	sourcePath    = "testdata/CaseFolding.txt"
	sourceURL     = "https://www.unicode.org/Public/17.0.0/ucd/CaseFolding.txt"
	sourceVersion = "# CaseFolding-17.0.0.txt"
	sourceSHA256  = "ff8d8fefbf123574205085d6714c36149eb946d717a0c585c27f0f4ef58c4183"
	captured      = "2026-09-26"
	tablesPath    = "tables.go"
)

// TestTheTablesAreCaseFoldingTxt is the generator and its guard. It reads the
// pinned CaseFolding.txt, derives the tables the package reads, and fails
// when tables.go is anything else, or when the source is not the one pinned.
func TestTheTablesAreCaseFoldingTxt(t *testing.T) {
	mappings := pinnedMappings(t)
	derived, err := derive(mappings)
	if err != nil {
		t.Fatal(err)
	}
	generated := derived.render()
	if *update {
		if err := os.WriteFile(tablesPath, generated, 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("wrote %s from %d mappings", tablesPath, len(mappings))
		return
	}
	committed, err := os.ReadFile(tablesPath)
	if err != nil {
		t.Fatalf("%v; generate it with -update", err)
	}
	if err := stale(committed, generated); err != nil {
		t.Fatal(err)
	}
	byStatus := map[byte]int{}
	for _, m := range mappings {
		byStatus[m.status]++
	}
	t.Logf("%d mappings read, %d C, %d F, %d S, %d T; %d runes with variants, %d with a wide spelling of their own",
		len(mappings), byStatus['C'], byStatus['F'], byStatus['S'], byStatus['T'], len(derived.variants), len(derived.wide))
}

// TestTheGuardRefusesATableTheSourceDoesNotGenerate: a guard that stopped
// comparing passes every table and, by itself, moves no answer, so only a
// test of its comparison sees it stop. The comparison is handed the
// generated tables with each line dropped in turn, and with a line added,
// and must refuse every one. Dropping U+0149's spelling, whose one folding
// is the full one to U+02BC and n, must be refused by the number of its
// line.
func TestTheGuardRefusesATableTheSourceDoesNotGenerate(t *testing.T) {
	const u0149 = "\t{0x0149, \"\\u02bcn\"},\n"
	derived, err := derive(pinnedMappings(t))
	if err != nil {
		t.Fatal(err)
	}
	generated := derived.render()
	if err := stale(generated, generated); err != nil {
		t.Fatalf("the tables the source generates are refused: %v", err)
	}
	lines := strings.SplitAfter(string(generated), "\n")
	if !slices.Contains(lines, u0149) {
		t.Fatalf("the generated tables hold no line %+q", u0149)
	}
	examined, passed := 0, []int(nil)
	for i, line := range lines {
		if line == "" { // what follows the last line break
			continue
		}
		examined++
		err := stale([]byte(strings.Join(slices.Delete(slices.Clone(lines), i, i+1), "")), generated)
		switch {
		case err == nil:
			passed = append(passed, i)
		case line == u0149 && !strings.Contains(err.Error(), fmt.Sprintf(" line %d:", i+1)):
			t.Errorf("%s without U+0149's spelling, its line %d, is refused without naming that line: %v", tablesPath, i+1, err)
		}
	}
	if len(passed) > 0 {
		t.Errorf("%d of %d tables with one line dropped pass the guard, the first %s without its line %d, %+q",
			len(passed), examined, tablesPath, passed[0]+1, lines[passed[0]])
	}
	if err := stale(append(slices.Clone(generated), u0149...), generated); err == nil {
		t.Errorf("%s with a line added at its end passes the guard", tablesPath)
	}
	t.Logf("%d tables, each the generated one with one line dropped, handed to the guard", examined)
}

// stale is the guard's comparison: nil when the committed tables are the
// bytes the source generates, and otherwise the first line where they part.
func stale(committed, generated []byte) error {
	if !bytes.Equal(committed, generated) {
		have, want := strings.SplitAfter(string(committed), "\n"), strings.SplitAfter(string(generated), "\n")
		n := 0
		for n < len(have) && n < len(want) && have[n] == want[n] {
			n++
		}
		return fmt.Errorf("%s parts from what %s generates at line %d: it holds %s where the source gives %s; generate it again with go test ./internal/parse/casefold -run TestTheTablesAreCaseFoldingTxt -update",
			tablesPath, sourcePath, n+1, lineAt(have, n), lineAt(want, n))
	}
	return nil
}

func lineAt(lines []string, n int) string {
	if n >= len(lines) || lines[n] == "" {
		return "the end of the file"
	}
	return strconv.QuoteToASCII(strings.TrimSuffix(lines[n], "\n"))
}

// pinnedMappings reads the lines of the pinned source, and stops the test
// when the file is not the one pinned.
func pinnedMappings(t *testing.T) []mapping {
	t.Helper()
	source, err := os.ReadFile(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	if sum := sha256.Sum256(source); hex.EncodeToString(sum[:]) != sourceSHA256 {
		t.Fatalf("%s has sha256 %x, not the pinned %s; a new source is a new pin, taken with its version, address and capture date", sourcePath, sum, sourceSHA256)
	}
	if first, _, _ := strings.Cut(string(source), "\n"); first != sourceVersion {
		t.Fatalf("%s begins %q, not %q", sourcePath, first, sourceVersion)
	}
	mappings, err := readCaseFolding(source)
	if err != nil {
		t.Fatal(err)
	}
	return mappings
}

// mapping is one line of CaseFolding.txt: <code>; <status>; <mapping>;
type mapping struct {
	code   rune
	status byte // C common, F full, S simple, T Turkic
	to     []rune
	line   int
}

func readCaseFolding(source []byte) ([]mapping, error) {
	var out []mapping
	for i, line := range strings.Split(string(source), "\n") {
		data, _, _ := strings.Cut(line, "#")
		if strings.TrimSpace(data) == "" {
			continue
		}
		fail := func(why string) error { return fmt.Errorf("%s line %d, %q: %s", sourcePath, i+1, line, why) }
		fields := strings.Split(data, ";")
		if len(fields) != 4 || strings.TrimSpace(fields[3]) != "" {
			return nil, fail("not <code>; <status>; <mapping>;")
		}
		code, err := hexRune(fields[0])
		if err != nil {
			return nil, fail(err.Error())
		}
		status := strings.TrimSpace(fields[1])
		if len(status) != 1 || !strings.Contains("CFST", status) {
			return nil, fail("the status is not C, F, S or T")
		}
		var to []rune
		for _, f := range strings.Fields(fields[2]) {
			r, err := hexRune(f)
			if err != nil {
				return nil, fail(err.Error())
			}
			to = append(to, r)
		}
		if len(to) == 0 || status != "F" && len(to) != 1 {
			return nil, fail("only a full folding maps to more than one code point, and every line maps to one")
		}
		out = append(out, mapping{code: code, status: status[0], to: to, line: i + 1})
	}
	if len(out) == 0 {
		return nil, errors.New(sourcePath + " holds no mappings")
	}
	return out, nil
}

func hexRune(field string) (rune, error) {
	n, err := strconv.ParseUint(strings.TrimSpace(field), 16, 32)
	if err != nil || n > 0x10ffff || 0xd800 <= n && n <= 0xdfff {
		return 0, fmt.Errorf("%q is not a code point", field)
	}
	return rune(n), nil
}

// derived is what the package reads, sorted by rune.
type derived struct {
	variants []rune
	wide     []spelling
}

// derive reads the mappings into the two tables. A rune has variants when a
// line maps it or maps a rune onto it alone. Its wide spelling starts as the
// default full folding, the C and F lines, and every line is then made to
// hold: a simple or Turkic line that relates two runes the full folding
// keeps apart merges them onto the lesser, and a line whose two sides differ
// only by runes at one end reads those runes as nothing. That second case is
// U+0130, which folds to i under T and to i and U+0307 under F: the two
// foldings can be given one spelling only by reading the dot as nothing. A
// line that can be made to hold neither way stops the generator.
func derive(mappings []mapping) (derived, error) {
	w := widest{full: map[rune][]rune{}, merged: map[rune]rune{}, erased: map[rune]bool{}}
	variantOf := map[rune]bool{}
	for _, m := range mappings {
		variantOf[m.code] = true
		if len(m.to) == 1 {
			variantOf[m.to[0]] = true
		}
		if m.status == 'C' || m.status == 'F' {
			if _, twice := w.full[m.code]; twice {
				return derived{}, fmt.Errorf("line %d: U+%04X has a second C or F folding", m.line, m.code)
			}
			w.full[m.code] = m.to
		}
	}
	// The default folding folds nothing twice; spell relies on it to end.
	for _, m := range mappings {
		for _, r := range m.to {
			if _, again := w.full[r]; again && (m.status == 'C' || m.status == 'F') {
				return derived{}, fmt.Errorf("line %d: U+%04X folds to U+%04X, which folds again", m.line, m.code, r)
			}
		}
	}
	for changed := true; changed; {
		changed = false
		for _, m := range mappings {
			a, b := w.spell([]rune{m.code}), w.spell(m.to)
			if slices.Equal(a, b) {
				continue
			}
			if err := w.reconcile(a, b); err != nil {
				return derived{}, fmt.Errorf("line %d, U+%04X; %c: %w", m.line, m.code, m.status, err)
			}
			changed = true
		}
	}
	for r := rune(0); r < 0x80; r++ {
		want := r
		if 'A' <= r && r <= 'Z' {
			want = r + 'a' - 'A'
		}
		if got := w.spell([]rune{r}); !slices.Equal(got, []rune{want}) {
			return derived{}, fmt.Errorf("U+%04X spells %q; an ASCII letter must spell its lower case and every other ASCII character itself", r, string(got))
		}
	}
	var d derived
	seen := map[rune]bool{}
	for _, m := range mappings {
		for _, r := range append([]rune{m.code}, m.to...) {
			if seen[r] {
				continue
			}
			seen[r] = true
			if variantOf[r] {
				d.variants = append(d.variants, r)
			}
			if s := w.spell([]rune{r}); !slices.Equal(s, []rune{r}) {
				d.wide = append(d.wide, spelling{r: r, text: string(s)})
			}
		}
	}
	slices.Sort(d.variants)
	slices.SortFunc(d.wide, func(a, b spelling) int { return int(a.r - b.r) })
	return d, nil
}

// widest is the wide spelling while it is being derived.
type widest struct {
	full   map[rune][]rune // the C and F lines
	merged map[rune]rune   // a rune merged onto a lesser one
	erased map[rune]bool   // a rune read as nothing
}

func (w widest) spell(runes []rune) []rune {
	var out []rune
	for _, r := range runes {
		switch to, folds := w.full[r]; {
		case w.erased[r]:
		case folds:
			out = append(out, w.spell(to)...)
		case w.merged[r] != 0:
			out = append(out, w.spell([]rune{w.merged[r]})...)
		default:
			out = append(out, r)
		}
	}
	return out
}

func (w widest) reconcile(a, b []rune) error {
	if len(a) == 1 && len(b) == 1 {
		w.merged[max(a[0], b[0])] = min(a[0], b[0])
		return nil
	}
	long, short := a, b
	if len(long) < len(short) {
		long, short = short, long
	}
	var extra []rune
	switch {
	case slices.Equal(long[:len(short)], short):
		extra = long[len(short):]
	case slices.Equal(long[len(long)-len(short):], short):
		extra = long[:len(long)-len(short)]
	default:
		return fmt.Errorf("%q and %q cannot be given one spelling", string(a), string(b))
	}
	for _, r := range extra {
		w.erased[r] = true
	}
	return nil
}

// render writes tables.go already in gofmt's layout, so that no formatter's
// version decides the bytes the guard compares.
func (d derived) render() []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "// Code generated from %s by TestTheTablesAreCaseFoldingTxt. DO NOT EDIT.\n\n", sourcePath)
	fmt.Fprintf(&b, "// The source is %s,\n// %s, captured %s, sha256 %s.\n", sourceURL, strings.TrimPrefix(sourceVersion, "# "), captured, sourceSHA256)
	b.WriteString("// It is the Unicode Consortium's data, under the Unicode License v3, whose\n// notice is testdata/license.txt.\n\n")
	b.WriteString("package casefold\n\n")
	b.WriteString("// variants is every rune CaseFolding.txt maps, and every rune it maps one\n// onto alone.\n")
	b.WriteString("var variants = [...]rune{\n")
	for i := 0; i < len(d.variants); i += 8 {
		b.WriteString("\t")
		for j, r := range d.variants[i:min(i+8, len(d.variants))] {
			if j > 0 {
				b.WriteString(" ")
			}
			fmt.Fprintf(&b, "0x%04X,", r)
		}
		b.WriteString("\n")
	}
	b.WriteString("}\n\n")
	b.WriteString("// wide is every rune whose wide spelling is not itself, with that spelling.\n")
	b.WriteString("var wide = [...]spelling{\n")
	for _, s := range d.wide {
		fmt.Fprintf(&b, "\t{0x%04X, %s},\n", s.r, strconv.QuoteToASCII(s.text))
	}
	b.WriteString("}\n")
	return b.Bytes()
}
