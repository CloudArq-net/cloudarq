package eval

import (
	"strconv"
	"testing"
)

// token is the claim assignment a policy is asked about.
type token = map[ClaimKey]string

const overflowReason = "term count exceeded 256; widened to unconstrained"

func hasOverflowCaveat(s AdmittedSet, source string) bool {
	for _, c := range s.Caveats() {
		if c.Reason == overflowReason && c.Source == source && c.Claim == "" {
			return true
		}
	}
	return false
}

// wideSet is n disjoint terms on one claim, the shape that makes a cross
// product exceed the term cap.
func wideSet(claim ClaimKey, n int) AdmittedSet {
	terms := make([]Term, n)
	for i := range terms {
		terms[i] = Term{claim: Exact(string(claim) + "-" + strconv.Itoa(i))}
	}
	return NewAdmittedSet(terms...)
}

func TestAbsentClaimIsUnconstrained(t *testing.T) {
	arbitrary := token{"sub": "repo:acme/app", "aud": "sts.amazonaws.com", "iss": "x"}
	if !NewAdmittedSet(Term{}).Admits(arbitrary) {
		t.Errorf("Term{} must admit every token")
	}
	if !NewAdmittedSet(Term{"sub": Any()}).Admits(token{"aud": "x"}) {
		t.Errorf(`Term{"sub": Any()} must admit a token with no sub at all`)
	}
	if !NewAdmittedSet(Term{"sub": Unknown("r")}).Admits(token{}) {
		t.Errorf(`Term{"sub": Unknown} must admit a token with no sub: Unknown is top`)
	}
	// A constraint that does not admit everything requires the claim.
	if NewAdmittedSet(Term{"sub": Exact("x")}).Admits(token{"aud": "x"}) {
		t.Errorf(`Term{"sub": Exact("x")} must not admit a token with no sub`)
	}
	if NewAdmittedSet(Term{"sub": Glob("repo:*")}).Admits(token{}) {
		t.Errorf(`Term{"sub": Glob} must not admit a token with no sub`)
	}
	// A Term constrains only the claims it names.
	if !NewAdmittedSet(Term{"sub": Exact("x")}).Admits(token{"sub": "x", "extra": "anything"}) {
		t.Errorf("claims the Term does not name must not matter")
	}
	// An empty value is present, not absent.
	if !NewAdmittedSet(Term{"sub": Exact("")}).Admits(token{"sub": ""}) {
		t.Errorf(`an empty sub is a present sub and must satisfy Exact("")`)
	}
}

func TestMeetIsCrossProduct(t *testing.T) {
	a := NewAdmittedSet(Term{"a": Exact("1")}, Term{"a": Exact("2")})
	b := NewAdmittedSet(Term{"b": Exact("1")}, Term{"b": Exact("2")})
	m := a.Meet(b)
	for _, av := range []string{"1", "2"} {
		for _, bv := range []string{"1", "2"} {
			if !m.Admits(token{"a": av, "b": bv}) {
				t.Errorf("%s must admit a=%s b=%s", m, av, bv)
			}
		}
	}
	for _, tok := range []token{{"a": "1"}, {"b": "2"}, {"a": "3", "b": "1"}, {"a": "1", "b": "3"}, {}} {
		if m.Admits(tok) {
			t.Errorf("%s must not admit %v", m, tok)
		}
	}
	if m.IsEmpty() || m.IsTop() {
		t.Errorf("%s: IsEmpty() = %v, IsTop() = %v; want both false", m, m.IsEmpty(), m.IsTop())
	}
	// Meet on a shared claim narrows that claim rather than duplicating it.
	shared := NewAdmittedSet(Term{"sub": Glob("repo:acme/*")}).Meet(NewAdmittedSet(Term{"sub": Glob("*:ref:refs/heads/main")}))
	if !shared.Admits(token{"sub": "repo:acme/app:ref:refs/heads/main"}) || shared.Admits(token{"sub": "repo:acme/app:ref:refs/heads/dev"}) {
		t.Errorf("%s must be the intersection of both globs on sub", shared)
	}
}

// TestAdmittedIsEmptyNeverGuesses is the AdmittedSet half of B1a's rule: a
// claim constrained by two globs is undecided, and undecided must never read
// as empty, whether or not the two patterns can agree.
func TestAdmittedIsEmptyNeverGuesses(t *testing.T) {
	overlapping := NewAdmittedSet(Term{"sub": Glob("repo:acme/*")}).Meet(NewAdmittedSet(Term{"sub": Glob("*:ref:refs/heads/main")}))
	disjoint := NewAdmittedSet(Term{"sub": Glob("a*")}).Meet(NewAdmittedSet(Term{"sub": Glob("b*")}))
	for _, s := range []AdmittedSet{overlapping, disjoint} {
		if s.IsEmpty() {
			t.Errorf("%s.IsEmpty() = true; emptiness of two globs is undecided here and must not be claimed", s)
		}
		if s.IsTop() {
			t.Errorf("%s.IsTop() = true", s)
		}
	}
	if !overlapping.Admits(token{"sub": "repo:acme/app:ref:refs/heads/main"}) {
		t.Errorf("%s rejects a token it admits", overlapping)
	}
}

// TestUnknownTermIsTop: a Term whose every constraint is Unknown admits
// every token, so the set is Everything, exact, and provenance is the
// parser's caveat, not a Term. Mixing an Unknown with a real constraint
// keeps both.
func TestUnknownTermIsTop(t *testing.T) {
	u := NewAdmittedSet(Term{"sub": Unknown("r")})
	if !u.IsTop() || !u.Exact() || u.String() != "{}" {
		t.Errorf("Unknown-only Term: IsTop() = %v, Exact() = %v, String() = %q", u.IsTop(), u.Exact(), u.String())
	}
	joined := u.Join(wideSet("x", 256))
	if !joined.IsTop() || !joined.Exact() {
		t.Errorf("a top set joined with 256 terms is still exactly Everything; got Exact() = %v with caveats %v", joined.Exact(), joined.Caveats())
	}
	if got := NewAdmittedSet(Term{"sub": Exact("x")}, Term{"sub": Unknown("r")}); !got.IsTop() || got.String() != "{}" {
		t.Errorf("a set with an Unknown-only Term is Everything; got %s", got)
	}
	mixed := NewAdmittedSet(Term{"sub": Unknown("r"), "aud": Exact("x")})
	if mixed.IsTop() || mixed.Admits(token{"aud": "y"}) || !mixed.Admits(token{"aud": "x"}) {
		t.Errorf("%s: IsTop() = %v; aud must still be constrained", mixed, mixed.IsTop())
	}
	if got := mixed.String(); got != `{aud="x", sub=?("r")}` {
		t.Errorf("String() = %q; the Unknown is kept where a real constraint sits beside it", got)
	}
}

func TestMeetDropsEmptyTerms(t *testing.T) {
	m := NewAdmittedSet(Term{"sub": Exact("a")}).Meet(NewAdmittedSet(Term{"sub": Exact("b")}))
	if !m.IsEmpty() {
		t.Errorf("%s: IsEmpty() = false; sub cannot be both a and b", m)
	}
	if m.Admits(token{"sub": "a"}) || m.Admits(token{"sub": "b"}) {
		t.Errorf("%s admits a token", m)
	}
	// Only the contradictory pairs are dropped.
	ab := NewAdmittedSet(Term{"sub": Exact("a")}, Term{"sub": Exact("b")})
	bc := NewAdmittedSet(Term{"sub": Exact("b")}, Term{"sub": Exact("c")})
	m = ab.Meet(bc)
	if m.IsEmpty() || !m.Admits(token{"sub": "b"}) || m.Admits(token{"sub": "a"}) || m.Admits(token{"sub": "c"}) {
		t.Errorf("(a | b) ∧ (b | c) = %s, want exactly sub=b", m)
	}
	// A term that is empty on construction is dropped too.
	if !NewAdmittedSet(Term{"sub": None()}).IsEmpty() {
		t.Errorf("a Term with a provably empty claim admits nothing")
	}
}

func TestTermCapWidensNeverTruncates(t *testing.T) {
	a, b := wideSet("x", 17), wideSet("y", 17) // 289 terms in the true intersection
	m := a.Meet(b)
	if !m.IsTop() {
		t.Fatalf("overflowed Meet must widen to everything; got %s", m)
	}
	if !hasOverflowCaveat(m, "Meet") {
		t.Errorf("overflowed Meet must carry the overflow caveat from Meet; caveats: %v", m.Caveats())
	}
	if m.Exact() {
		t.Errorf("a widened set is not exact")
	}
	// Never fewer members than reality: every token the true intersection
	// admits is admitted after widening.
	for i := 0; i < 17; i++ {
		for j := 0; j < 17; j++ {
			tok := token{"x": "x-" + strconv.Itoa(i), "y": "y-" + strconv.Itoa(j)}
			if !(a.Admits(tok) && b.Admits(tok)) {
				t.Fatalf("test is wrong: operands must admit %v", tok)
			}
			if !m.Admits(tok) {
				t.Fatalf("%v is in the true intersection but the widened Meet rejects it", tok)
			}
		}
	}

	// Exactly at the cap nothing is widened.
	exact := wideSet("x", 16).Meet(wideSet("y", 16)) // 256 terms
	if exact.IsTop() || !exact.Exact() || len(exact.Terms()) != 256 {
		t.Errorf("256 terms is within the cap: IsTop() = %v, Exact() = %v, terms = %d", exact.IsTop(), exact.Exact(), len(exact.Terms()))
	}

	// Join overflows the same way, with its own source.
	j := wideSet("x", 200).Join(wideSet("y", 100))
	if !j.IsTop() || !hasOverflowCaveat(j, "Join") {
		t.Errorf("overflowed Join must widen and say so; got %s with caveats %v", j, j.Caveats())
	}
	if !j.Admits(token{"x": "x-199"}) || !j.Admits(token{}) {
		t.Errorf("a widened Join admits everything")
	}

	// So does the constructor, so the bound holds for every value.
	if c := wideSet("x", 257); !c.IsTop() || !hasOverflowCaveat(c, "NewAdmittedSet") {
		t.Errorf("257 terms on construction must widen and say so; got %s with caveats %v", c, c.Caveats())
	}
	if c := wideSet("x", 256); c.IsTop() || !c.Exact() {
		t.Errorf("256 terms on construction is within the cap")
	}
}

func TestJoinConcatenatesAndKeepsCaveats(t *testing.T) {
	c1 := Caveat{Claim: "sub", Reason: "operator NumericLessThan is not modelled", Source: "statement[0].Condition"}
	c2 := Caveat{Reason: "NotPrincipal is not modelled", Source: "statement[1]"}
	a := NewAdmittedSet(Term{"sub": Exact("a")}).WithCaveat(c1)
	b := NewAdmittedSet(Term{"sub": Exact("b")}).WithCaveat(c2)
	j := a.Join(b)
	for _, v := range []string{"a", "b"} {
		if !j.Admits(token{"sub": v}) {
			t.Errorf("%s must admit sub=%s", j, v)
		}
	}
	if j.Admits(token{"sub": "c"}) {
		t.Errorf("%s must not admit sub=c", j)
	}
	if j.Exact() || len(j.Caveats()) != 2 {
		t.Errorf("Join must keep both caveats; got %v", j.Caveats())
	}
	// Caveat order is canonical, not construction order.
	if x, y := j.Caveats(), b.Join(a).Caveats(); x[0] != y[0] || x[1] != y[1] {
		t.Errorf("caveat order depends on operand order: %v vs %v", x, y)
	}
	// Meet carries caveats the same way, and a caveat is not duplicated.
	m := a.Meet(a.Join(b))
	if len(m.Caveats()) != 2 {
		t.Errorf("Meet must carry every distinct caveat once; got %v", m.Caveats())
	}
}

func TestNothingAndEverything(t *testing.T) {
	var zero AdmittedSet
	for _, s := range []AdmittedSet{zero, Nothing()} {
		if s.Admits(token{}) || s.Admits(token{"sub": "x"}) {
			t.Errorf("%s admits a token", s)
		}
		if !s.IsEmpty() || s.IsTop() || !s.Exact() {
			t.Errorf("%s: IsEmpty() = %v, IsTop() = %v, Exact() = %v", s, s.IsEmpty(), s.IsTop(), s.Exact())
		}
		if s.String() != "∅" || len(s.Terms()) != 0 || len(s.Caveats()) != 0 {
			t.Errorf("%q: Terms() = %v, Caveats() = %v", s.String(), s.Terms(), s.Caveats())
		}
	}
	all := Everything()
	if !all.Admits(token{}) || !all.Admits(token{"sub": "x", "aud": "y"}) {
		t.Errorf("Everything must admit every token")
	}
	if !all.IsTop() || all.IsEmpty() || all.String() != "{}" {
		t.Errorf("Everything: IsTop() = %v, IsEmpty() = %v, String() = %q", all.IsTop(), all.IsEmpty(), all.String())
	}
	some := NewAdmittedSet(Term{"sub": Exact("x")})
	cases := []struct {
		name string
		got  AdmittedSet
		want string
	}{
		{"Nothing ∧ Everything", zero.Meet(all), "∅"},
		{"Everything ∧ Nothing", all.Meet(zero), "∅"},
		{"Nothing ∨ Everything", zero.Join(all), "{}"},
		{"Nothing ∨ Nothing", zero.Join(zero), "∅"},
		{"Everything ∧ some", all.Meet(some), some.String()},
		{"some ∧ Everything", some.Meet(all), some.String()},
		{"some ∨ Everything", some.Join(all), "{}"},
		{"Nothing ∨ some", zero.Join(some), some.String()},
		{"some ∧ Nothing", some.Meet(zero), "∅"},
	}
	for _, c := range cases {
		if got := c.got.String(); got != c.want {
			t.Errorf("%s = %q, want %q", c.name, got, c.want)
		}
	}
	if _, _, ok := zero.Excludes(token{}); !ok {
		t.Errorf("the zero value excludes every token")
	}
}

func TestAdmittedStringIsStable(t *testing.T) {
	t1 := Term{"sub": Glob("repo:acme/*"), "aud": Exact("sts.amazonaws.com")}
	t2 := Term{"sub": Exact("x")}
	want := `{aud="sts.amazonaws.com", sub=like:"repo:acme/*"} | {sub="x"}`
	same := []struct {
		name string
		s    AdmittedSet
	}{
		{"constructor", NewAdmittedSet(t1, t2)},
		{"constructor, other order", NewAdmittedSet(t2, t1)},
		{"join", NewAdmittedSet(t2).Join(NewAdmittedSet(t1))},
		{"join, other order", NewAdmittedSet(t1).Join(NewAdmittedSet(t2))},
		{"duplicate terms", NewAdmittedSet(t1, t2, t1, t2)},
		{"Any-valued claim is no claim", NewAdmittedSet(Term{"sub": Glob("repo:acme/*"), "aud": Exact("sts.amazonaws.com"), "iss": Any()}, t2)},
		{"caveats do not render", NewAdmittedSet(t1, t2).WithCaveat(Caveat{Reason: "r", Source: "s"})},
	}
	for _, c := range same {
		if got := c.s.String(); got != want {
			t.Errorf("%s: String() = %q, want %q", c.name, got, want)
		}
	}
	// An Unknown beside a real constraint is rendered, for provenance.
	if got := NewAdmittedSet(Term{"sub": Unknown("r"), "aud": Exact("x")}).String(); got != `{aud="x", sub=?("r")}` {
		t.Errorf("String() = %q; Unknown is kept for provenance", got)
	}
}

func TestExactTracksCaveats(t *testing.T) {
	s := NewAdmittedSet(Term{"sub": Exact("x")})
	if !s.Exact() {
		t.Errorf("a set with no caveats is exact")
	}
	c := Caveat{Claim: "sub", Reason: "operator NumericLessThan is not modelled", Source: "statement[1].Condition"}
	inexact := s.WithCaveat(c)
	if inexact.Exact() || len(inexact.Caveats()) != 1 || inexact.Caveats()[0] != c {
		t.Errorf("WithCaveat: Exact() = %v, Caveats() = %v", inexact.Exact(), inexact.Caveats())
	}
	if !s.Exact() {
		t.Errorf("WithCaveat must not mutate its receiver")
	}
	if inexact.WithCaveat(c).Caveats()[0] != c || len(inexact.WithCaveat(c).Caveats()) != 1 {
		t.Errorf("the same caveat twice is one caveat")
	}
	// Caveats() is a copy.
	got := inexact.Caveats()
	got[0].Reason = "tampered"
	if inexact.Caveats()[0].Reason == "tampered" {
		t.Errorf("Caveats() must return a copy")
	}
	// Meet and Join with an inexact operand are inexact, whichever side it is on.
	for _, got := range []AdmittedSet{s.Meet(inexact), inexact.Meet(s), s.Join(inexact), inexact.Join(s)} {
		if got.Exact() || len(got.Caveats()) != 1 || got.Caveats()[0] != c {
			t.Errorf("inexactness must survive Meet and Join on either side; got caveats %v", got.Caveats())
		}
	}
	// Widening is inexact even from exact operands.
	if wideSet("x", 17).Meet(wideSet("y", 17)).Exact() {
		t.Errorf("a widened set is not exact")
	}
}

func TestTermsIsADefensiveCopy(t *testing.T) {
	input := Term{"sub": Exact("x")}
	s := NewAdmittedSet(input)
	input["sub"] = None()
	if !s.Admits(token{"sub": "x"}) {
		t.Errorf("mutating the input Term after construction must not change the set")
	}
	terms := s.Terms()
	terms[0]["sub"] = None()
	terms[0]["aud"] = Exact("y")
	if !s.Admits(token{"sub": "x"}) {
		t.Errorf("mutating Terms() must not change the set")
	}
	if got := s.Terms(); len(got) != 1 || len(got[0]) != 1 || !got[0]["sub"].Contains("x") {
		t.Errorf("Terms() = %v, want the original single term", got)
	}
}
