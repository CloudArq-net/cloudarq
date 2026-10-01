package casefold

import (
	"testing"
	"unicode"
)

// TestALetterReadsAsEveryStringItMayFoldTo: each pair is one string under
// some case folding of Unicode 17.0.0, and so must be spelled alike. The two
// ligatures are the reason the package exists: Go 1.24's unicode tables
// relate U+FB05 to nothing, and both read as st under full folding. The
// dotless and the dotted i are the Turkic pair; the dotted one is also i
// followed by U+0307 under full folding.
func TestALetterReadsAsEveryStringItMayFoldTo(t *testing.T) {
	for _, pair := range [][2]string{
		{"\ufb05", "st"}, {"\ufb06", "ST"}, {"\ufb05", "\ufb06"}, {"\u017ft", "\ufb06"},
		{"\u00df", "ss"}, {"\u1e9e", "SS"}, {"\u00df", "\u1e9e"},
		{"\u212a", "k"}, {"\u212a", "K"}, {"\u017f", "S"},
		{"\u0130", "i"}, {"\u0130", "i\u0307"}, {"\u0131", "I"}, {"\u0131", "i"},
		{"\u00dc", "\u00fc"}, {"\u03c2", "\u03a3"}, {"\u00b5", "\u039c"},
		{"\u1f88", "\u1f00\u03b9"}, {"\u0390", "\u1fd3"}, {"\ua7cb", "\u0264"},
		{"sts:AssumeRole", "STS:assumerole"}, {"", ""},
	} {
		if a, b := Wide(pair[0]), Wide(pair[1]); a != b {
			t.Errorf("%+q and %+q may be one, and are spelled %+q and %+q", pair[0], pair[1], a, b)
		}
	}
	for _, pair := range [][2]string{
		{"a", "b"}, {"s", "t"}, {"\u4e2d", "\u4e2d\u56fd"}, {"\u00fc", "u"}, {"\u212b", "a"}, {"sts", "st"},
	} {
		if Wide(pair[0]) == Wide(pair[1]) {
			t.Errorf("%+q and %+q are one under no folding, and are spelled alike", pair[0], pair[1])
		}
	}
	if got := Wide("a\xffB\xfe"); got != "a\xffb\xfe" {
		t.Errorf("bytes that are not UTF-8 are kept as they are; got %+q", got)
	}
}

// TestEveryLineOfCaseFoldingTxtHolds: each line of the pinned source says a
// rune may fold to a rune or a sequence. The package must spell the two
// alike, and give variants to the rune and, where the line maps it onto one
// rune alone, to that rune. The examples above name a few foldings; this
// holds the tables to every line, whatever the guard beside the generator
// compares, since a folding the tables lost would read a respelled name as
// a different one: the narrow direction.
func TestEveryLineOfCaseFoldingTxtHolds(t *testing.T) {
	byStatus := map[byte]int{}
	for _, m := range pinnedMappings(t) {
		byStatus[m.status]++
		if a, b := Wide(string(m.code)), Wide(string(m.to)); a != b {
			t.Errorf("line %d: %U may fold to %+q (%c), and they are spelled %+q and %+q", m.line, m.code, string(m.to), m.status, a, b)
		}
		if !HasVariants(m.code) {
			t.Errorf("line %d: %U may fold to %+q (%c), and the tables give it no variants", m.line, m.code, string(m.to), m.status)
		}
		if len(m.to) == 1 && !HasVariants(m.to[0]) {
			t.Errorf("line %d: %U folds onto %U alone (%c), and the tables give %U no variants", m.line, m.code, m.to[0], m.status, m.to[0])
		}
	}
	for _, status := range []byte("CFST") {
		if byStatus[status] == 0 {
			t.Errorf("no %c line of %s examined", status, sourcePath)
		}
	}
	t.Logf("%d C, %d F, %d S and %d T lines examined", byStatus['C'], byStatus['F'], byStatus['S'], byStatus['T'])
}

// TestALetterHasVariantsWhenAFoldingRelatesIt: a letter a line of
// CaseFolding.txt maps has variants, and so does one a line maps a letter
// onto: \u00ff is folded onto by \u0178, the dotless i by I under the Turkic folding.
// A letter with no case, a digit, and the combining dot that appears only
// inside what U+0130 folds to have none.
func TestALetterHasVariantsWhenAFoldingRelatesIt(t *testing.T) {
	for _, r := range []rune{'A', 'z', '\u00df', '\u00ff', '\u0131', '\u0130', '\u212a', '\u017f', '\ufb05', '\ufb06', '\u0149', '\U00010D50'} {
		if !HasVariants(r) {
			t.Errorf("%U has variants", r)
		}
	}
	for _, r := range []rune{'1', '-', ':', '\u4e2d', '\u0307', '\u02bc', '\u00d7'} {
		if HasVariants(r) {
			t.Errorf("%U has no variants", r)
		}
	}
}

// TestIntoASCIIIsTheThirteen: the letters outside ASCII that the foldings
// of CaseFolding.txt 17.0.0, the Turkic pair merged, turn into ASCII text
// are these thirteen, and every code point is examined.
func TestIntoASCIIIsTheThirteen(t *testing.T) {
	thirteen := map[rune]bool{
		'\u00df': true, '\u0130': true, '\u0131': true, '\u017f': true, '\u1e9e': true, '\u212a': true,
		'\ufb00': true, '\ufb01': true, '\ufb02': true, '\ufb03': true, '\ufb04': true, '\ufb05': true, '\ufb06': true,
	}
	examined, into := 0, 0
	for r := rune(0); r <= unicode.MaxRune; r++ {
		examined++
		if IntoASCII(r) {
			into++
		}
		if IntoASCII(r) != thirteen[r] {
			t.Errorf("IntoASCII(%U) = %v", r, IntoASCII(r))
		}
	}
	if into != len(thirteen) || examined != unicode.MaxRune+1 {
		t.Errorf("%d of %d code points turn into ASCII, want %d", into, examined, len(thirteen))
	}
}

// TestTheTablesHoldEveryRelationTheToolchainKnows: whatever Unicode version
// the toolchain running this test carries, every letter its simple folding,
// upper, lower or title case relates to another is related here too, and
// spelled alike. The tables are pinned to Unicode 17.0.0; a toolchain on a
// later version with a case pair the tables lack fails here, and the pin is
// moved on purpose rather than found out by an answer. The standard
// library is read by this test only.
func TestTheTablesHoldEveryRelationTheToolchainKnows(t *testing.T) {
	related := 0
	for r := rune(0); r <= unicode.MaxRune; r++ {
		for _, m := range [...]rune{unicode.SimpleFold(r), unicode.ToUpper(r), unicode.ToLower(r), unicode.ToTitle(r)} {
			if m == r {
				continue
			}
			related++
			if !HasVariants(r) || !HasVariants(m) || Wide(string(r)) != Wide(string(m)) {
				t.Errorf("unicode %s relates %U and %U; the tables give variants %v and %v, spellings %+q and %+q",
					unicode.Version, r, m, HasVariants(r), HasVariants(m), Wide(string(r)), Wide(string(m)))
			}
		}
	}
	if related == 0 {
		t.Fatal("no relation examined")
	}
	t.Logf("unicode %s: %d relations examined", unicode.Version, related)
}
