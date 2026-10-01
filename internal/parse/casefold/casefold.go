// Package casefold says what a name may be when it is compared regardless
// of case. AWS reads action names and condition keys without regard to case
// and documents no folding for a letter outside ASCII, so a letter with case
// variants is read as every rune or sequence Unicode's case folding may turn
// it into: the simple, the full and the Turkic foldings together, and each
// letter another folds onto it. Reading it as one of them would be a guess,
// and on a policy that differs from another by that letter, a guess in the
// narrow direction.
//
// What a letter may be is read from data, never from the standard library.
// The unicode package carries the Unicode version its toolchain was built
// with: Go 1.24's (Unicode 15.0.0) give U+FB05 LATIN SMALL LIGATURE LONG S T
// no simple folding and Go 1.27's (Unicode 17.0.0) fold it onto U+FB06, so an
// answer read from them depends on the compiler, and the WebAssembly engine
// and the command line are built by different ones. The tables here are
// generated from CaseFolding.txt of Unicode 17.0.0, committed under testdata
// with its licence, and a test fails when the two disagree.
package casefold

import (
	"slices"
	"strings"
	"unicode/utf8"
)

// spelling is a rune and its wide spelling.
type spelling struct {
	r    rune
	text string
}

// HasVariants reports whether case folding relates r to another rune or
// sequence: whether a comparison that ignores case may read r as something
// other than itself. A letter with no case, and a mark that appears only
// inside what a letter folds to, has none.
func HasVariants(r rune) bool {
	_, found := slices.BinarySearch(variants[:], r)
	return found
}

// Wide is s spelled so that two strings some case folding may make one are
// spelled alike: each rune reads as its full folding, and runes the simple
// or the Turkic folding relate are read as the least of them. It merges more
// than any one folding does. U+0130 folds to i under the Turkic folding and
// to i with U+0307 COMBINING DOT ABOVE under the full one, so both must be
// spelled alike, and the dot reads as nothing wherever it stands. Equal wide
// spellings mean "may be one", never "are one", which is the reading an
// upper bound needs; a wide spelling is compared, never printed.
//
// A byte that is not UTF-8 is kept as it is, so that two different strings
// never meet through a replacement character.
func Wide(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		switch at, found := slices.BinarySearchFunc(wide[:], r, bySpelledRune); {
		case r == utf8.RuneError && size == 1:
			b.WriteByte(s[i])
		case found:
			b.WriteString(wide[at].text)
		default:
			b.WriteRune(r)
		}
		i += size
	}
	return b.String()
}

// IntoASCII reports whether r lies outside ASCII and case folding may turn
// it into ASCII text: a Kelvin sign into k, a long s into s, a sharp s into
// ss, a ligature into its letters, a dotted or a dotless i into i. A name
// holding one may be a name written wholly in ASCII.
func IntoASCII(r rune) bool {
	if r < utf8.RuneSelf {
		return false
	}
	at, found := slices.BinarySearchFunc(wide[:], r, bySpelledRune)
	if !found || wide[at].text == "" {
		return false
	}
	for i := 0; i < len(wide[at].text); i++ {
		if wide[at].text[i] >= utf8.RuneSelf {
			return false
		}
	}
	return true
}

func bySpelledRune(s spelling, r rune) int { return int(s.r - r) }
