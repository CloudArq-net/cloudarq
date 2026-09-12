package eval

import (
	"regexp"
	"strings"
	"testing"

	"pgregory.net/rapid"
)

// alphabet is deliberately tiny, and includes both metacharacters, so that
// random patterns and values collide constantly. Over a large alphabet every
// pair of sets is disjoint and the laws below pass without testing anything.
var alphabet = []rune("ab/*?")

// corpus is every string over the alphabet up to length 3, so that "agrees
// on the corpus" is exhaustive at that length rather than lucky. Property
// tests judge equality on it; reflect.DeepEqual would compare structure,
// which the spec allows to differ.
var corpus = buildCorpus(3)

func buildCorpus(maxLen int) []string {
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

// TestCorpusIsExhaustive guards the guard. Every law below judges equality
// on the corpus, so a corpus that silently shrank would weaken all of them
// at once without failing any.
func TestCorpusIsExhaustive(t *testing.T) {
	const want = 1 + 5 + 25 + 125 // lengths 0 to 3 over five runes
	if len(corpus) != want {
		t.Fatalf("corpus has %d strings, want %d", len(corpus), want)
	}
	seen := make(map[string]bool, len(corpus))
	for _, s := range corpus {
		if seen[s] {
			t.Fatalf("corpus repeats %q", s)
		}
		seen[s] = true
	}
}

func genString() *rapid.Generator[string] {
	return rapid.StringOfN(rapid.RuneFrom(alphabet), 0, 4, -1)
}

// genSet draws from all five constructors and, below the depth limit, from
// Meet and Join of smaller draws, so that union and intersection nodes are
// subject to the same laws as the primitives.
func genSet(depth int) *rapid.Generator[StringSet] {
	return rapid.Custom(func(t *rapid.T) StringSet {
		kinds := 5
		if depth > 0 {
			kinds = 7
		}
		switch rapid.IntRange(0, kinds-1).Draw(t, "kind") {
		case 0:
			return Exact(genString().Draw(t, "exact"))
		case 1:
			return Glob(genString().Draw(t, "glob"))
		case 2:
			return Any()
		case 3:
			return None()
		case 4:
			return Unknown(rapid.SampledFrom([]string{"r1", "r2"}).Draw(t, "reason"))
		case 5:
			return genSet(depth-1).Draw(t, "l").Meet(genSet(depth-1).Draw(t, "r"))
		default:
			return genSet(depth-1).Draw(t, "l").Join(genSet(depth-1).Draw(t, "r"))
		}
	})
}

// probesFor is the fixed corpus plus a few random strings: the same ground
// every run, and some ground nobody chose.
func probesFor(t *rapid.T) []string {
	extra := rapid.SliceOfN(genString(), 0, 4).Draw(t, "probes")
	return append(append([]string{}, corpus...), extra...)
}

// disagreement returns a probe on which a and b differ, and whether one exists.
func disagreement(a, b StringSet, ps []string) (string, bool) {
	for _, p := range ps {
		if a.Contains(p) != b.Contains(p) {
			return p, true
		}
	}
	return "", false
}

func TestMeetCommutative(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		a, b := genSet(2).Draw(t, "a"), genSet(2).Draw(t, "b")
		if p, bad := disagreement(a.Meet(b), b.Meet(a), probesFor(t)); bad {
			t.Fatalf("%s ∧ %s and %s ∧ %s disagree on %q", a, b, b, a, p)
		}
	})
}

func TestJoinCommutative(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		a, b := genSet(2).Draw(t, "a"), genSet(2).Draw(t, "b")
		if p, bad := disagreement(a.Join(b), b.Join(a), probesFor(t)); bad {
			t.Fatalf("%s ∨ %s and %s ∨ %s disagree on %q", a, b, b, a, p)
		}
	})
}

func TestMeetAssociative(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		a, b, c := genSet(1).Draw(t, "a"), genSet(1).Draw(t, "b"), genSet(1).Draw(t, "c")
		if p, bad := disagreement(a.Meet(b).Meet(c), a.Meet(b.Meet(c)), probesFor(t)); bad {
			t.Fatalf("(%s ∧ %s) ∧ %s and %s ∧ (%s ∧ %s) disagree on %q", a, b, c, a, b, c, p)
		}
	})
}

func TestJoinAssociative(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		a, b, c := genSet(1).Draw(t, "a"), genSet(1).Draw(t, "b"), genSet(1).Draw(t, "c")
		if p, bad := disagreement(a.Join(b).Join(c), a.Join(b.Join(c)), probesFor(t)); bad {
			t.Fatalf("(%s ∨ %s) ∨ %s and %s ∨ (%s ∨ %s) disagree on %q", a, b, c, a, b, c, p)
		}
	})
}

func TestMeetIdempotent(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		a := genSet(2).Draw(t, "a")
		if p, bad := disagreement(a.Meet(a), a, probesFor(t)); bad {
			t.Fatalf("%s ∧ %s disagrees with %s on %q", a, a, a, p)
		}
	})
}

func TestJoinIdempotent(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		a := genSet(2).Draw(t, "a")
		if p, bad := disagreement(a.Join(a), a, probesFor(t)); bad {
			t.Fatalf("%s ∨ %s disagrees with %s on %q", a, a, a, p)
		}
	})
}

func TestAbsorption(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		a, b := genSet(2).Draw(t, "a"), genSet(2).Draw(t, "b")
		ps := probesFor(t)
		if p, bad := disagreement(a.Meet(a.Join(b)), a, ps); bad {
			t.Fatalf("%s ∧ (%s ∨ %s) disagrees with %s on %q", a, a, b, a, p)
		}
		if p, bad := disagreement(a.Join(a.Meet(b)), a, ps); bad {
			t.Fatalf("%s ∨ (%s ∧ %s) disagrees with %s on %q", a, a, b, a, p)
		}
	})
}

// TestMeetNarrows is monotonicity: adding a constraint can never widen the
// admitted set. Without it a policy with more conditions could be reported
// as admitting more, and nothing downstream could be trusted.
func TestMeetNarrows(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		a, b := genSet(2).Draw(t, "a"), genSet(2).Draw(t, "b")
		m := a.Meet(b)
		for _, s := range probesFor(t) {
			if m.Contains(s) && !(a.Contains(s) && b.Contains(s)) {
				t.Fatalf("%s ∧ %s = %s admits %q, which one operand rejects", a, b, m, s)
			}
		}
	})
}

func TestJoinWidens(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		a, b := genSet(2).Draw(t, "a"), genSet(2).Draw(t, "b")
		j := a.Join(b)
		for _, s := range probesFor(t) {
			if (a.Contains(s) || b.Contains(s)) && !j.Contains(s) {
				t.Fatalf("%s ∨ %s = %s rejects %q, which one operand admits", a, b, j, s)
			}
		}
	})
}

// TestMeetIsExact is the other half of TestMeetNarrows: Meet must not drop a
// value both operands admit. That would be under-approximation, a set
// reported smaller than reality, which is the failure this product exists
// to never produce.
func TestMeetIsExact(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		a, b := genSet(2).Draw(t, "a"), genSet(2).Draw(t, "b")
		m := a.Meet(b)
		for _, s := range probesFor(t) {
			if a.Contains(s) && b.Contains(s) && !m.Contains(s) {
				t.Fatalf("%s ∧ %s = %s rejects %q, which both operands admit", a, b, m, s)
			}
		}
	})
}

// TestJoinIsExact is the other half of TestJoinWidens: Join must not admit a
// value neither operand does, or every finding would be a false alarm.
func TestJoinIsExact(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		a, b := genSet(2).Draw(t, "a"), genSet(2).Draw(t, "b")
		j := a.Join(b)
		for _, s := range probesFor(t) {
			if j.Contains(s) && !(a.Contains(s) || b.Contains(s)) {
				t.Fatalf("%s ∨ %s = %s admits %q, which neither operand does", a, b, j, s)
			}
		}
	})
}

// TestEmptyImpliesNoMembers checks IsEmpty in the only direction it promises.
// The converse is deliberately not asserted: a set with no member in the
// corpus may still be undecided, and undecided must answer false.
func TestEmptyImpliesNoMembers(t *testing.T) {
	exercised := 0
	rapid.Check(t, func(t *rapid.T) {
		a := genSet(3).Draw(t, "a")
		if !a.IsEmpty() {
			return
		}
		exercised++
		for _, s := range probesFor(t) {
			if a.Contains(s) {
				t.Fatalf("%s.IsEmpty() = true, but it contains %q", a, s)
			}
		}
	})
	// A law that fires only on empty sets is vacuous if the generator never
	// produced one, and nothing above would have noticed.
	if exercised == 0 {
		t.Fatalf("no generated set was empty; the property was never exercised")
	}
	t.Logf("exercised on %d empty sets", exercised)
}

func TestTopImpliesAllMembers(t *testing.T) {
	exercised := 0
	rapid.Check(t, func(t *rapid.T) {
		a := genSet(3).Draw(t, "a")
		if !a.IsTop() {
			return
		}
		exercised++
		for _, s := range probesFor(t) {
			if !a.Contains(s) {
				t.Fatalf("%s.IsTop() = true, but it rejects %q", a, s)
			}
		}
	})
	if exercised == 0 {
		t.Fatalf("no generated set was top; the property was never exercised")
	}
	t.Logf("exercised on %d top sets", exercised)
}

// referenceMatch is an independent oracle for the hand-written matcher: the
// pattern compiled to a regexp with every literal escaped, "*" as ".*" and
// "?" as ".", anchored, and "." permitted to match a newline. It is the
// approach the spec warns against when done carelessly; done carefully it is
// a second opinion that shares no code with glob.go.
func referenceMatch(pattern, value string) bool {
	var re strings.Builder
	re.WriteString("^(?s:")
	for _, r := range pattern {
		switch r {
		case '*':
			re.WriteString(".*")
		case '?':
			re.WriteString(".")
		default:
			re.WriteString(regexp.QuoteMeta(string(r)))
		}
	}
	re.WriteString(")$")
	return regexp.MustCompile(re.String()).MatchString(value)
}

// TestGlobAgreesWithReferenceMatcher checks the matcher itself, which no
// lattice law can: the laws hold just as well over a consistently wrong
// Contains. The alphabet adds a two-byte rune so that "one character" is
// checked at the rune level, which is also what the reference's "." means,
// and every regexp metacharacter, so that an implementation that escaped
// only some of them could not agree with the reference.
func TestGlobAgreesWithReferenceMatcher(t *testing.T) {
	wide := rapid.StringOfN(rapid.RuneFrom([]rune(`ab/*?é.+()[]|\^$`)), 0, 6, -1)
	rapid.Check(t, func(t *rapid.T) {
		p := wide.Draw(t, "pattern")
		g := Glob(p)
		values := append(probesFor(t), rapid.SliceOfN(wide, 1, 6).Draw(t, "wide")...)
		for _, v := range values {
			if got, want := g.Contains(v), referenceMatch(p, v); got != want {
				t.Fatalf("Glob(%q).Contains(%q) = %v, reference matcher says %v", p, v, got, want)
			}
		}
	})
}

// TestStringIsDeterministic is the section 2 promise at this layer: the same
// set built in any order renders byte-identically, so golden files and
// content-addressed finding IDs cannot depend on statement order.
func TestStringIsDeterministic(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		a, b, c := genSet(1).Draw(t, "a"), genSet(1).Draw(t, "b"), genSet(1).Draw(t, "c")
		if x, y := a.Join(b).Join(c).String(), c.Join(b).Join(a).String(); x != y {
			t.Fatalf("join order changed the rendering: %q vs %q", x, y)
		}
		if x, y := a.Meet(b).Meet(c).String(), c.Meet(b).Meet(a).String(); x != y {
			t.Fatalf("meet order changed the rendering: %q vs %q", x, y)
		}
	})
}
