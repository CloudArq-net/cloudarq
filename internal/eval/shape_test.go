package eval

import (
	"reflect"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"

	"pgregory.net/rapid"
)

// TestShapeOfEachNode pins what the view reads for every node the package
// builds, normalised forms included: a Glob with no metacharacter is an
// exact value, and a Meet with an Unknown keeps the narrower side.
func TestShapeOfEachNode(t *testing.T) {
	cases := []struct {
		name string
		s    StringSet
		want Shape
	}{
		{"exact, its star literal", Exact("a*"), Shape{Kind: ShapeExact, Text: "a*"}},
		{"exact, empty", Exact(""), Shape{Kind: ShapeExact, Text: ""}},
		{"glob", Glob("repo:acme/*"), Shape{Kind: ShapeGlob, Text: "repo:acme/*"}},
		{"glob with a question mark", Glob("repo:acm?/*"), Shape{Kind: ShapeGlob, Text: "repo:acm?/*"}},
		{"glob without a metacharacter is exact", Glob("abc"), Shape{Kind: ShapeExact, Text: "abc"}},
		{"glob of stars is any", Glob("**"), Shape{Kind: ShapeAny}},
		{"any", Any(), Shape{Kind: ShapeAny}},
		{"none", None(), Shape{Kind: ShapeNone}},
		{"unknown", Unknown("r"), Shape{Kind: ShapeUnknown}},
		{"unknown kept by a meet that narrowed nothing", Any().Meet(Unknown("k")), Shape{Kind: ShapeUnknown}},
		{"unknown dropped by a meet that narrowed", Unknown("k").Meet(Exact("a")), Shape{Kind: ShapeExact, Text: "a"}},
		{"union", Exact("a").Join(Glob("b*")), Shape{Kind: ShapeUnion, Members: []Shape{
			{Kind: ShapeExact, Text: "a"},
			{Kind: ShapeGlob, Text: "b*"},
		}}},
		{"intersection", Glob("a*").Meet(Glob("*b")), Shape{Kind: ShapeIntersection, Members: []Shape{
			{Kind: ShapeGlob, Text: "*b"},
			{Kind: ShapeGlob, Text: "a*"},
		}}},
		{"union holding an intersection", Glob("a*").Meet(Glob("*b")).Join(Exact("c")), Shape{Kind: ShapeUnion, Members: []Shape{
			{Kind: ShapeExact, Text: "c"},
			{Kind: ShapeIntersection, Members: []Shape{
				{Kind: ShapeGlob, Text: "*b"},
				{Kind: ShapeGlob, Text: "a*"},
			}},
		}}},
	}
	for _, c := range cases {
		if got := ShapeOf(c.s); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: ShapeOf(%s) = %+v, want %+v", c.name, c.s, got, c.want)
		}
	}
}

// TestZeroShapeClaimsNothing: a Shape nobody filled in reads as Unknown,
// every string and unsure of it, so a caller that forgot to read a set can
// neither find a value or a pattern in it to narrow on nor call what it
// read exact.
func TestZeroShapeClaimsNothing(t *testing.T) {
	var zero Shape
	if zero.Kind != ShapeUnknown || zero.Text != "" || zero.Members != nil {
		t.Fatalf("the zero Shape is %+v, want the kind that admits every string and claims no certainty", zero)
	}
}

// foreignSet is a StringSet this package did not build. Nothing in the tree
// implements one, and the view must still not invent a structure for it.
type foreignSet struct{}

func (foreignSet) Contains(string) bool       { return false }
func (f foreignSet) Meet(StringSet) StringSet { return f }
func (f foreignSet) Join(StringSet) StringSet { return f }
func (foreignSet) IsEmpty() bool              { return true }
func (foreignSet) IsTop() bool                { return false }
func (foreignSet) String() string             { return `"looks exact"` }

func TestShapeOfAForeignSetClaimsNothing(t *testing.T) {
	// It claims to be empty and renders like an exact value; the view
	// believes neither, because it cannot see the structure behind either.
	if got := ShapeOf(foreignSet{}); !reflect.DeepEqual(got, Shape{Kind: ShapeUnknown}) {
		t.Fatalf("ShapeOf(a foreign set) = %+v, want Unknown", got)
	}
}

// TestShapeIsACopy: the view hands out data, never a way into the set.
func TestShapeIsACopy(t *testing.T) {
	s := Glob("a*").Meet(Glob("*b")).Join(Exact("c"))
	before := s.String()
	sh := ShapeOf(s)
	sh.Members[0].Text = "changed"
	sh.Members[1].Members[0].Text = "changed"
	if s.String() != before {
		t.Fatalf("editing the view changed the set: %s, was %s", s, before)
	}
	if again := ShapeOf(s); again.Members[0].Text != "c" || again.Members[1].Members[0].Text != "*b" {
		t.Fatalf("editing one view changed the next: %+v", again)
	}
}

// admits is what a Shape says about v, read from the Shape alone. A
// pattern is matched by Glob, whose matcher answers to its own reference
// oracle; the law below is about the structure the view reports.
func (sh Shape) admits(v string) bool {
	switch sh.Kind {
	case ShapeAny, ShapeUnknown:
		return true
	case ShapeNone:
		return false
	case ShapeExact:
		return v == sh.Text
	case ShapeGlob:
		return Glob(sh.Text).Contains(v)
	case ShapeUnion:
		for _, m := range sh.Members {
			if m.admits(v) {
				return true
			}
		}
		return false
	}
	for _, m := range sh.Members {
		if !m.admits(v) {
			return false
		}
	}
	return true
}

// genShaped draws every kind of node directly, beside genSet's random
// compositions: genSet reaches a union or an intersection only when its
// dice line up, and a hundred draws of it can miss both. A pattern built
// around "?" is always a real glob, never normalised to Exact or Any, and
// two patterns of the shapes "p?*" and "*?q" meet in an intersection. The
// compound builders come first because rapid draws early entries of a
// list more often, and they are the kinds only a builder produces.
func genShaped() *rapid.Generator[StringSet] {
	return rapid.Custom(func(t *rapid.T) StringSet {
		pattern := func(label string) StringSet {
			return Glob(genString().Draw(t, label+" head") + "?" + genString().Draw(t, label+" tail") + "*")
		}
		leaf := func(label string) StringSet {
			if rapid.Bool().Draw(t, label+" exact") {
				return Exact(genString().Draw(t, label))
			}
			return pattern(label)
		}
		intersection := func() StringSet {
			return Glob(genString().Draw(t, "p") + "?*").Meet(Glob("*?" + genString().Draw(t, "q")))
		}
		builders := []func() StringSet{
			intersection,
			func() StringSet { return intersection().Join(leaf("beside")) },
			func() StringSet { return leaf("left").Join(leaf("right")) },
			func() StringSet { return pattern("glob") },
			func() StringSet { return Exact(genString().Draw(t, "exact")) },
			None,
			func() StringSet { return Unknown(rapid.SampledFrom([]string{"r1", "r2"}).Draw(t, "reason")) },
			Any,
			func() StringSet { return genSet(3).Draw(t, "composed") },
		}
		return rapid.SampledFrom(builders).Draw(t, "builder")()
	})
}

// shapeCensus counts what a run of draws exercised, so that a generator
// that stopped producing a kind fails the law that needs it.
type shapeCensus struct {
	kinds          map[ShapeKind]int
	nestedCompound int // a union holding an intersection
}

func (c *shapeCensus) count(sh Shape) {
	c.kinds[sh.Kind]++
	if sh.Kind == ShapeUnion {
		for _, m := range sh.Members {
			if m.Kind == ShapeIntersection {
				c.nestedCompound++
				return
			}
		}
	}
}

func (c *shapeCensus) check(t *testing.T) {
	t.Helper()
	for _, k := range []ShapeKind{ShapeAny, ShapeUnknown, ShapeNone, ShapeExact, ShapeGlob, ShapeUnion, ShapeIntersection} {
		if c.kinds[k] == 0 {
			t.Fatalf("no draw had kind %d (counts %v, nested %d); the law was never exercised on it", k, c.kinds, c.nestedCompound)
		}
	}
	if c.nestedCompound == 0 {
		t.Fatalf("no draw was a union holding an intersection (counts %v); the recursion was never exercised", c.kinds)
	}
	t.Logf("kinds %v, unions holding an intersection %d", c.kinds, c.nestedCompound)
}

// checkShapeLaw holds the view to one law over four sets a case, drawn by
// genShaped, and fails when the run left a kind unexamined. With one set a
// case a kind went unexamined in one run of 1,200, measured; four sets a
// case put about four times as many draws behind each kind.
func checkShapeLaw(t *testing.T, law func(t *rapid.T, s StringSet, sh Shape)) {
	t.Helper()
	census := shapeCensus{kinds: map[ShapeKind]int{}}
	rapid.Check(t, func(t *rapid.T) {
		for _, s := range rapid.SliceOfN(genShaped(), 4, 4).Draw(t, "sets") {
			sh := ShapeOf(s)
			census.count(sh)
			law(t, s, sh)
		}
	})
	census.check(t)
}

// TestShapeDenotesTheSet is the law the view is held to: read from the
// Shape alone, a value is admitted exactly when the set contains it. A view
// that called a union an intersection, lost a member, took an exact value
// for a pattern or an Unknown for nothing would disagree on some probe.
func TestShapeDenotesTheSet(t *testing.T) {
	checkShapeLaw(t, func(t *rapid.T, s StringSet, sh Shape) {
		for _, v := range probesFor(t) {
			if got, want := sh.admits(v), s.Contains(v); got != want {
				t.Fatalf("ShapeOf(%s) = %+v admits %q: %v, the set says %v", s, sh, v, got, want)
			}
		}
	})
}

// TestShapeIsDeterministic is TestStringIsDeterministic read through the
// view: the same set built in any order reads as the same Shape, members in
// the same order. The rings read the view rather than the rendering, and a
// view whose members followed the order a policy wrote its values in would
// let statement order move a placement. The count proves compound sets were
// compared, where member order can differ at all.
func TestShapeIsDeterministic(t *testing.T) {
	compound := 0
	rapid.Check(t, func(t *rapid.T) {
		a, b, c := genSet(1).Draw(t, "a"), genSet(1).Draw(t, "b"), genSet(1).Draw(t, "c")
		for _, pair := range [][2]StringSet{
			{a.Join(b).Join(c), c.Join(b).Join(a)},
			{a.Meet(b).Meet(c), c.Meet(b).Meet(a)},
		} {
			x, y := ShapeOf(pair[0]), ShapeOf(pair[1])
			if !reflect.DeepEqual(x, y) {
				t.Fatalf("the order %s and %s were built in changed the view: %+v, %+v", pair[0], pair[1], x, y)
			}
			if len(x.Members) > 0 {
				compound++
			}
		}
	})
	if compound == 0 {
		t.Fatalf("no compound set was compared; the law was never exercised where order can differ")
	}
	t.Logf("compound sets compared: %d", compound)
}

// rendered writes a Shape in the grammar String uses. Unknown carries its
// reasons in the rendering and not in the view, so it is left to the kind
// law below.
func rendered(sh Shape) string {
	switch sh.Kind {
	case ShapeExact:
		return strconv.QuoteToASCII(sh.Text)
	case ShapeGlob:
		return "like:" + strconv.QuoteToASCII(sh.Text)
	case ShapeAny:
		return "*"
	case ShapeNone:
		return "∅"
	}
	sep := " | "
	if sh.Kind == ShapeIntersection {
		sep = " & "
	}
	parts := make([]string, len(sh.Members))
	for i, m := range sh.Members {
		parts[i] = rendered(m)
	}
	return "(" + strings.Join(parts, sep) + ")"
}

// TestShapeAgreesWithTheRendering: the view carries what String prints, in
// the order String prints it. The join and the report read that rendering
// back, and the rings read the view; this law is why the two can never see
// different structures, and why the view's member order is as canonical as
// the rendering golden files hold.
func TestShapeAgreesWithTheRendering(t *testing.T) {
	checkShapeLaw(t, func(t *rapid.T, s StringSet, sh Shape) {
		if sh.Kind == ShapeUnknown {
			return
		}
		if got := rendered(sh); got != s.String() {
			t.Fatalf("ShapeOf(%s) renders as %s", s, got)
		}
	})
}

// TestShapeKindAgreesWithThePredicates: the kinds that claim everything or
// nothing are exactly the sets whose IsTop, IsEmpty and IsUnknown say so, so
// a caller reading the kind never learns more than the set could prove.
func TestShapeKindAgreesWithThePredicates(t *testing.T) {
	checkShapeLaw(t, func(t *rapid.T, s StringSet, sh Shape) {
		k := sh.Kind
		if (k == ShapeUnknown) != IsUnknown(s) {
			t.Fatalf("ShapeOf(%s).Kind = %d, IsUnknown = %v", s, k, IsUnknown(s))
		}
		if (k == ShapeNone) != s.IsEmpty() {
			t.Fatalf("ShapeOf(%s).Kind = %d, IsEmpty = %v", s, k, s.IsEmpty())
		}
		if (k == ShapeAny || k == ShapeUnknown) != s.IsTop() {
			t.Fatalf("ShapeOf(%s).Kind = %d, IsTop = %v", s, k, s.IsTop())
		}
	})
}

// TestShapeHoldsTheNodeInvariants: a union has two or more members, none of
// them everything, nothing or another union; an intersection has two or
// more patterns; only an exact value or a pattern has Text, and only a
// compound has members. A caller walking the view relies on each.
func TestShapeHoldsTheNodeInvariants(t *testing.T) {
	var check func(t *rapid.T, sh Shape)
	check = func(t *rapid.T, sh Shape) {
		compound := sh.Kind == ShapeUnion || sh.Kind == ShapeIntersection
		if compound != (len(sh.Members) > 0) {
			t.Fatalf("%+v: members %d on kind %d", sh, len(sh.Members), sh.Kind)
		}
		if sh.Text != "" && sh.Kind != ShapeExact && sh.Kind != ShapeGlob {
			t.Fatalf("%+v: text on kind %d", sh, sh.Kind)
		}
		if compound && len(sh.Members) < 2 {
			t.Fatalf("%+v: a compound of one", sh)
		}
		for _, m := range sh.Members {
			if sh.Kind == ShapeIntersection && m.Kind != ShapeGlob {
				t.Fatalf("%+v: an intersection member of kind %d", sh, m.Kind)
			}
			if sh.Kind == ShapeUnion && m.Kind != ShapeExact && m.Kind != ShapeGlob && m.Kind != ShapeIntersection {
				t.Fatalf("%+v: a union member of kind %d", sh, m.Kind)
			}
			check(t, m)
		}
	}
	checkShapeLaw(t, func(t *rapid.T, _ StringSet, sh Shape) { check(t, sh) })
}

// TestLiteralPrefix pins the prefix for the patterns the rings meet, and
// that it is the longest run the text can vouch for: cutting one character
// early would lose a pin that exists.
func TestLiteralPrefix(t *testing.T) {
	cases := []struct{ pattern, want string }{
		{"repo:acme/*", "repo:acme/"},
		{"repo:acme*", "repo:acme"},
		{"repo:acm?/*", "repo:acm"},
		{"repo:acme@123456/*", "repo:acme@123456/"},
		{"repo:*@123456/*", "repo:"},
		{"arn:aws:iam::123456789012:role/*", "arn:aws:iam::123456789012:role/"},
		{"*", ""},
		{"?", ""},
		{"*abc", ""},
		{"a?*", "a"},
		{"abc", "abc"},
		{"", ""},
		{"café/*", "café/"},
		{"a�b*", "a"},
		{"a\xffb*", "a"},
		{"\xff", ""},
	}
	for _, c := range cases {
		if got := LiteralPrefix(c.pattern); got != c.want {
			t.Errorf("LiteralPrefix(%q) = %q, want %q", c.pattern, got, c.want)
		}
	}
}

// pieces is the alphabet the prefix law draws patterns and values from:
// both metacharacters, a delimiter, a two-byte letter, U+FFFD written
// validly, and two bytes that are not UTF-8. The matcher reads U+FFFD and
// each invalid byte alike, so a prefix that kept one would be contradicted
// by a value holding another.
var pieces = []string{"a", "b", "/", "*", "?", "é", "�", "\xff", "\xfe"}

// replacements are the one-character spellings the matcher reads as the
// same rune as U+FFFD.
var replacements = []string{"�", "\xff", "\xfe"}

func genPieces(min, max int) *rapid.Generator[string] {
	return rapid.Custom(func(t *rapid.T) string {
		return strings.Join(rapid.SliceOfN(rapid.SampledFrom(pieces), min, max).Draw(t, "pieces"), "")
	})
}

// instance is a value the pattern matches, built rune by rune: a star
// becomes any run, a question mark any one character, U+FFFD or an invalid
// byte any spelling the matcher reads as U+FFFD, and every other rune
// itself. Building values from the pattern, rather than hoping a random
// one matches, is what makes admitted values common enough to test. A
// pattern with no metacharacter is an exact value, compared byte for byte,
// and its one instance is itself.
func instance(t *rapid.T, pattern string) string {
	if !strings.ContainsAny(pattern, "*?") {
		return pattern
	}
	var b strings.Builder
	for _, r := range pattern {
		switch r {
		case '*':
			b.WriteString(genPieces(0, 2).Draw(t, "star"))
		case '?':
			b.WriteString(rapid.SampledFrom(pieces).Draw(t, "question"))
		case utf8.RuneError:
			b.WriteString(rapid.SampledFrom(replacements).Draw(t, "replacement"))
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// TestLiteralPrefixBoundsEveryMatch is the prefix law: every value a
// pattern admits begins with the pattern's literal prefix, byte for byte,
// and the prefix stops only where the pattern's next character does not
// stand for itself. The first half is the fact a pin rests on; a prefix
// that kept a "?" or a U+FFFD would name an owner some admitted value does
// not have. The second is why a pin that exists is found; a prefix cut
// short would lose it. The counts prove the draws reached a question mark,
// a replacement character and a non-empty prefix, each followed by a value
// that differs from the pattern there.
func TestLiteralPrefixBoundsEveryMatch(t *testing.T) {
	admitted, questioned, replaced, prefixed := 0, 0, 0, 0
	rapid.Check(t, func(t *rapid.T) {
		pattern := genPieces(0, 6).Draw(t, "pattern")
		prefix := LiteralPrefix(pattern)
		if !strings.HasPrefix(pattern, prefix) || strings.ContainsAny(prefix, "*?�") || !utf8.ValidString(prefix) {
			t.Fatalf("LiteralPrefix(%q) = %q, which is not a literal run at the front of it", pattern, prefix)
		}
		if next, _ := utf8.DecodeRuneInString(pattern[len(prefix):]); len(prefix) < len(pattern) && next != '*' && next != '?' && next != utf8.RuneError {
			t.Fatalf("LiteralPrefix(%q) = %q, which stops before %q, a character that stands for itself", pattern, prefix, next)
		}
		for range 4 {
			v := instance(t, pattern)
			if !Glob(pattern).Contains(v) {
				t.Fatalf("Glob(%q) rejects %q, an instance built from it", pattern, v)
			}
			admitted++
			if !strings.HasPrefix(v, prefix) {
				t.Fatalf("Glob(%q) admits %q, which does not begin with LiteralPrefix = %q", pattern, v, prefix)
			}
			rest := pattern[len(prefix):]
			switch {
			case strings.HasPrefix(rest, "?") && !strings.HasPrefix(v[len(prefix):], "?"):
				questioned++
			case rest != "" && !strings.HasPrefix(rest, "*") && !strings.HasPrefix(rest, "?") && !strings.HasPrefix(v[len(prefix):], rest[:1]):
				replaced++
			}
			if prefix != "" {
				prefixed++
			}
		}
	})
	if admitted == 0 || questioned == 0 || replaced == 0 || prefixed == 0 {
		t.Fatalf("admitted=%d questioned=%d replaced=%d prefixed=%d; every count must be positive", admitted, questioned, replaced, prefixed)
	}
	t.Logf("admitted=%d questioned=%d replaced=%d prefixed=%d", admitted, questioned, replaced, prefixed)
}
