package join

import (
	"reflect"
	"strconv"
	"strings"
	"testing"

	"pgregory.net/rapid"

	"github.com/CloudArq-net/cloudarq/internal/eval"
)

// TestSharedInstanceFindsTheShortestCommonString pins the walk on the
// pairs the product exists to decide: a branch pin against a repository
// pin, a lookalike organisation, an environment pin against a branch pin.
// Each expected string is the shortest one every pattern matches, with
// stars deleted wherever a star can be deleted and "?" filled with "x".
func TestSharedInstanceFindsTheShortestCommonString(t *testing.T) {
	cases := []struct {
		patterns []string
		want     string
		found    bool
	}{
		{[]string{"repo:acme/*:ref:refs/heads/main", "repo:acme/infra:*"}, "repo:acme/infra:ref:refs/heads/main", true},
		{[]string{"repo:acme/infra:*", "repo:acme/*:ref:refs/heads/main"}, "repo:acme/infra:ref:refs/heads/main", true},
		{[]string{"repo:acme/*", "repo:acme/infra:*"}, "repo:acme/infra:", true},
		{[]string{"repo:acme/?????:ref:*", "repo:acme/*:ref:refs/heads/main"}, "repo:acme/xxxxx:ref:refs/heads/main", true},
		{[]string{"*infra:ref:refs/heads/main", "repo:acme/*"}, "repo:acme/infra:ref:refs/heads/main", true},
		{[]string{"*:ref:*", "repo:acme/*", "repo:acme/infra:*"}, "repo:acme/infra:ref:", true},
		{[]string{"a*", "*b", "*c*"}, "acb", true},
		{[]string{"a*b", "a*b"}, "ab", true},
		{[]string{"a?c", "a*"}, "axc", true},
		{[]string{"é*", "*ü"}, "éü", true},
		{[]string{"repo:acme/*:ref:refs/heads/main"}, "repo:acme/:ref:refs/heads/main", true},
		{[]string{"?"}, "x", true},
		{[]string{"*"}, "", true},
		{[]string{"", ""}, "", true},
		{[]string{"abc", "abc"}, "abc", true},
		{[]string{"repo:acme/*:ref:refs/heads/main", "repo:acme/*:environment:production"}, "", false},
		{[]string{"repo:acme/*", "repo:acme-evil/*"}, "", false},
		{[]string{"a*", "b*"}, "", false},
		{[]string{"*a", "*b"}, "", false},
		{[]string{"a", "b"}, "", false},
		{[]string{"a?", "a"}, "", false},
	}
	for _, c := range cases {
		got, found := sharedInstance(c.patterns)
		if got != c.want || found != c.found {
			t.Errorf("sharedInstance(%q) = (%q, %v), want (%q, %v)", c.patterns, got, found, c.want, c.found)
		}
		for _, p := range c.patterns {
			if found && !eval.Glob(p).Contains(got) {
				t.Errorf("sharedInstance(%q) = %q, which %q does not match", c.patterns, got, p)
			}
		}
	}
}

// values is every string over "ab" up to length 9, which bounds the
// shortest common instance of three patterns of three literals each: a
// rune every pattern consumes with a star can be deleted, so a minimal
// witness has at most as many runes as the patterns have literals.
var values = allStrings([]rune("ab"), 9)

func allStrings(alphabet []rune, maxLen int) []string {
	out := []string{""}
	frontier := []string{""}
	for n := 0; n < maxLen; n++ {
		var next []string
		for _, s := range frontier {
			for _, r := range alphabet {
				next = append(next, s+string(r))
			}
		}
		out = append(out, next...)
		frontier = next
	}
	return out
}

func TestValuesAreExhaustive(t *testing.T) {
	if len(values) != 1<<10-1 {
		t.Fatalf("values has %d strings, want %d", len(values), 1<<10-1)
	}
}

func genPattern() *rapid.Generator[string] {
	return rapid.StringOfN(rapid.RuneFrom([]rune("ab*?")), 0, 3, -1)
}

// TestSharedInstanceIsExact is both halves of the walk's contract: a
// witness it returns matches every pattern, and when it runs to the end
// and returns none, no string does. The second half is what lets the join
// trust the first: a walk that missed real overlaps would make the honest
// Indeterminate common enough to be worthless. Three patterns of three
// runes have at most 64 states, so no draw here reaches the bound.
func TestSharedInstanceIsExact(t *testing.T) {
	found, missing, starred := 0, 0, 0
	rapid.Check(t, func(t *rapid.T) {
		patterns := rapid.SliceOfN(genPattern(), 1, 3).Draw(t, "patterns")
		if strings.ContainsAny(strings.Join(patterns, ""), "*?") {
			starred++
		}
		w, ok := sharedInstance(patterns)
		if ok {
			found++
			for _, p := range patterns {
				if !eval.Glob(p).Contains(w) {
					t.Fatalf("sharedInstance(%q) = %q, which %q does not match", patterns, w, p)
				}
			}
			return
		}
		missing++
		for _, v := range values {
			if matchesAll(patterns, v) {
				t.Fatalf("sharedInstance(%q) found nothing, but %q matches every pattern", patterns, v)
			}
		}
	})
	if found == 0 || missing == 0 || starred == 0 {
		t.Fatalf("found %d, missing %d, with a star or a ? %d; one half of the contract, or the walk itself, was never exercised", found, missing, starred)
	}
	t.Logf("found %d, missing %d, with a star or a ? %d", found, missing, starred)
}

func matchesAll(patterns []string, v string) bool {
	for _, p := range patterns {
		if !eval.Glob(p).Contains(v) {
			return false
		}
	}
	return true
}

func TestReadShape(t *testing.T) {
	cases := []struct {
		text string
		want shape
	}{
		{`"repo:acme/infra"`, shape{kind: exactValue, text: "repo:acme/infra"}},
		{`"with \"quotes\", a | and an & like:"`, shape{kind: exactValue, text: `with "quotes", a | and an & like:`}},
		{`"\u00e9\x1b"`, shape{kind: exactValue, text: "é\x1b"}},
		{`like:"repo:acme/*"`, shape{kind: globPattern, text: "repo:acme/*"}},
		{`(like:"*b" & like:"a*")`, shape{kind: allOf, members: []shape{{kind: globPattern, text: "*b"}, {kind: globPattern, text: "a*"}}}},
		{`("a" | like:"b*")`, shape{kind: anyOf, members: []shape{{kind: exactValue, text: "a"}, {kind: globPattern, text: "b*"}}}},
		{`("z" | (like:"*b" & like:"a*") | like:"c*")`, shape{kind: anyOf, members: []shape{
			{kind: exactValue, text: "z"},
			{kind: allOf, members: []shape{{kind: globPattern, text: "*b"}, {kind: globPattern, text: "a*"}}},
			{kind: globPattern, text: "c*"},
		}}},
	}
	for _, c := range cases {
		if got := readShape(c.text); !reflect.DeepEqual(got, c.want) {
			t.Errorf("readShape(%s) = %+v, want %+v", c.text, got, c.want)
		}
	}
}

// TestReadShapeRefusesWhatEvalNeverRenders: the reader is total over the
// renderings a Term can hold and nothing else. A rendering it does not
// know is a change in eval that this package has not been taught, and
// guessing at it would turn a wrong witness into an Established sentence.
func TestReadShapeRefusesWhatEvalNeverRenders(t *testing.T) {
	for _, text := range []string{
		"",
		"*",
		"∅",
		`?("r")`,
		`like:`,
		`like:"unterminated`,
		`"a" trailing`,
		`(like:"a*")`,
		`("a" | like:"b*" & like:"c*")`,
		`("a" & "b")`,
		`("a" | like:"b*"`,
		`("a" | *)`,
		`(`,
	} {
		func() {
			defer func() {
				if r := recover(); r == nil {
					t.Errorf("readShape(%q) returned instead of refusing", text)
				} else if !strings.Contains(r.(string), strconv.Quote(text)) {
					t.Errorf("readShape(%q) refused without naming the rendering: %v", text, r)
				}
			}()
			readShape(text)
		}()
	}
}

// TestShapeWitness pins each shape's witness: a value is its own, a
// pattern's is its shortest instance, an intersection's is the walk's, and
// a union's is the first member's that exists, or none when every member
// is an intersection with no string in common.
func TestShapeWitness(t *testing.T) {
	disjoint := shape{kind: allOf, members: []shape{{kind: globPattern, text: "a*"}, {kind: globPattern, text: "b*"}}}
	cases := []struct {
		shape shape
		want  string
		found bool
	}{
		{shape{kind: exactValue, text: "a*b"}, "a*b", true},
		{shape{kind: globPattern, text: "a*b"}, "ab", true},
		{shape{kind: allOf, members: []shape{{kind: globPattern, text: "a*"}, {kind: globPattern, text: "*b"}}}, "ab", true},
		{disjoint, "", false},
		{shape{kind: anyOf, members: []shape{disjoint, {kind: exactValue, text: "z"}}}, "z", true},
		{shape{kind: anyOf, members: []shape{disjoint, disjoint}}, "", false},
	}
	for _, c := range cases {
		if got, found := c.shape.witness(); got != c.want || found != c.found {
			t.Errorf("witness of %s = (%q, %v), want (%q, %v)", c.shape.describe(), got, found, c.want, c.found)
		}
	}
}

// genConstraint draws the constraints a Term can hold: values and patterns
// over a tiny alphabet, their unions and intersections, and, often enough
// to count on, the intersection of two patterns with no string in common,
// the one shape that has no witness.
func genConstraint(depth int) *rapid.Generator[eval.StringSet] {
	return rapid.Custom(func(t *rapid.T) eval.StringSet {
		kinds := 2
		if depth > 0 {
			kinds = 5
		}
		switch rapid.IntRange(0, kinds-1).Draw(t, "kind") {
		case 0:
			return eval.Exact(genPattern().Draw(t, "value"))
		case 1:
			return eval.Glob(genPattern().Draw(t, "pattern"))
		case 2:
			return genConstraint(depth-1).Draw(t, "l").Meet(genConstraint(depth-1).Draw(t, "r"))
		case 3:
			return eval.Glob("a*" + genPattern().Draw(t, "p")).Meet(eval.Glob("b*" + genPattern().Draw(t, "q")))
		default:
			return genConstraint(depth-1).Draw(t, "l").Join(genConstraint(depth-1).Draw(t, "r"))
		}
	})
}

// TestShapesReadFromEval: every constraint eval renders reads back into a
// shape whose witness the constraint contains, and whose description is a
// sentence fragment. The reader is judged on eval's own output, which is
// the only input it will ever see.
func TestShapesReadFromEval(t *testing.T) {
	witnessed, unwitnessed := 0, 0
	rapid.Check(t, func(t *rapid.T) {
		s := genConstraint(2).Draw(t, "s")
		if s.IsTop() || s.IsEmpty() {
			return
		}
		sh := readShape(s.String())
		if d := sh.describe(); d == "" || strings.Contains(d, "like:") {
			t.Fatalf("describe(%s) = %q; a description is prose, not a rendering", s, d)
		}
		w, ok := sh.witness()
		if !ok {
			unwitnessed++
			for _, v := range values {
				if s.Contains(v) {
					t.Fatalf("%s has no witness, but contains %q", s, v)
				}
			}
			return
		}
		witnessed++
		if !s.Contains(w) {
			t.Fatalf("%s does not contain its own witness %q", s, w)
		}
	})
	if witnessed == 0 || unwitnessed == 0 {
		t.Fatalf("witnessed %d, unwitnessed %d; one half of the contract was never exercised", witnessed, unwitnessed)
	}
	t.Logf("witnessed %d, unwitnessed %d", witnessed, unwitnessed)
}

// TestSharedInstanceGivesUpPastTheBound: the walk is exact when it
// finishes, and it does not always finish. Patterns of the form *a*b*c*
// make the shortest common instance the shortest common supersequence
// problem, NP-hard in the number of patterns, so the walk is bounded in
// the states it visits and gives up past the bound. Giving up is never a
// decision: the pair stays, Indeterminate, with no example.
func TestSharedInstanceGivesUpPastTheBound(t *testing.T) {
	branchAndRepository := []string{"repo:acme/*:ref:refs/heads/main", "repo:acme/infra:*"}
	if w, ok := shortestShared(branchAndRepository, 10); ok {
		t.Errorf("a walk of 10 states found %q; it must give up first", w)
	}
	if w, ok := shortestShared(branchAndRepository, walkBound); !ok || w != mainBranch {
		t.Errorf("the full walk = (%q, %v), want %q", w, ok, mainBranch)
	}
	var supersequence []string
	for _, last := range "abcdef" {
		supersequence = append(supersequence, strings.Repeat("*x", 10)+"*"+string(last))
	}
	if w, ok := sharedInstance(supersequence); ok {
		t.Errorf("sharedInstance(%q) = %q, though no string ends in six different letters", supersequence, w)
	}
	// A pair whose overlap is real but past the bound is a link without an
	// example, never a missing link and never an Established one.
	aws := awsGrant(pinned(inter("repo:acme/*:ref:refs/heads/*", "repo:*/infra:*", "*main*", "repo:acme/infra:ref:refs/heads/*", "*/heads/*", "repo:acme/infra:*"), awsAudience))
	azure := azureGrant(pinned(inter("repo:acme/infra:*", "*:ref:refs/heads/*", "repo:*:ref:*", "*infra*", "repo:acme/*", "*:ref:*"), azureAudience))
	l, err := NewLink(aws, azure)
	if err != nil {
		t.Fatalf("NewLink: %v", err)
	}
	if l.Confidence() != Indeterminate || l.Subject().Witness != nil || !strings.HasPrefix(l.Reason(), "no example identity could be constructed for identities from https://token.actions.githubusercontent.com with sub matching all of ") {
		t.Errorf("past the bound: %s", l.Sentence())
	}
}

// inter is the intersection of the patterns, as a parser's Meet of several
// StringLike constraints on one claim produces it.
func inter(patterns ...string) eval.StringSet {
	s := eval.Glob(patterns[0])
	for _, p := range patterns[1:] {
		s = s.Meet(eval.Glob(p))
	}
	return s
}

// union is the union of the patterns, as a parser's Join of the values a
// StringLike lists for one claim produces it.
func union(patterns ...string) eval.StringSet {
	s := eval.Glob(patterns[0])
	for _, p := range patterns[1:] {
		s = s.Join(eval.Glob(p))
	}
	return s
}

// TestWitnessOfAsksBothSides: the overlap is the lattice's Meet, which
// never admits more than both operands today; witnessOf still asks each
// side, so that a widening in eval could not turn into a printed promise.
// The overlap here is deliberately wider than either side would yield.
func TestWitnessOfAsksBothSides(t *testing.T) {
	everything := eval.Everything()
	pinned := eval.NewAdmittedSet(eval.Term{"sub": eval.Exact("repo:acme/infra:ref:refs/heads/main")})
	if w := witnessOf(everything, everything, pinned); w != nil {
		t.Fatalf("a witness %v the second side rejects", w)
	}
	if w := witnessOf(everything, pinned, everything); w != nil {
		t.Fatalf("a witness %v the first side rejects", w)
	}
	if w := witnessOf(pinned, pinned, everything); w == nil || w["sub"] != "repo:acme/infra:ref:refs/heads/main" {
		t.Fatalf("witness %v, want the pinned subject", w)
	}
}
