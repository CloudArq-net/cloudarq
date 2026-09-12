package eval

import (
	"slices"
	"testing"
)

// probes is the fixed corpus every table cell is judged on. "ab" is in both
// Glob("a*") and Glob("*b"); "ba" is in neither; "c" is in nothing but Any.
var probes = []string{"", "a", "b", "ab", "ba", "c"}

// assertMembers checks s against every probe: the listed ones must be
// contained and every other probe must be rejected.
func assertMembers(t *testing.T, label string, s StringSet, want []string) {
	t.Helper()
	for _, p := range probes {
		exp := slices.Contains(want, p)
		if got := s.Contains(p); got != exp {
			t.Errorf("%s = %s: Contains(%q) = %v, want %v", label, s, p, got, exp)
		}
	}
}

// cell is one entry of an operation table: two operands and the behaviour
// the result must exhibit. Concrete types are never asserted, because the
// spec allows a node to be normalised.
type cell struct {
	name    string
	x, y    StringSet
	want    []string // probes the result contains
	empty   bool     // IsEmpty
	top     bool     // IsTop
	unknown bool     // IsUnknown
}

func checkTable(t *testing.T, opName string, op func(a, b StringSet) StringSet, table []cell) {
	t.Helper()
	all := probes
	for _, c := range table {
		want := c.want
		if want == nil && c.top {
			want = all
		}
		// Every cell is checked in both operand orders; the tables are
		// symmetric and an asymmetric implementation must not pass.
		for _, o := range []struct {
			label string
			got   StringSet
		}{
			{c.name, op(c.x, c.y)},
			{c.name + " (flipped)", op(c.y, c.x)},
		} {
			assertMembers(t, opName+" "+o.label, o.got, want)
			if o.got.IsEmpty() != c.empty {
				t.Errorf("%s %s = %s: IsEmpty() = %v, want %v", opName, o.label, o.got, o.got.IsEmpty(), c.empty)
			}
			if o.got.IsTop() != c.top {
				t.Errorf("%s %s = %s: IsTop() = %v, want %v", opName, o.label, o.got, o.got.IsTop(), c.top)
			}
			if IsUnknown(o.got) != c.unknown {
				t.Errorf("%s %s = %s: IsUnknown() = %v, want %v", opName, o.label, o.got, IsUnknown(o.got), c.unknown)
			}
		}
	}
}

func TestMeetTable(t *testing.T) {
	none, top, unk := None(), Any(), Unknown("r")
	exA, exB := Exact("a"), Exact("b")
	gA, gB := Glob("a*"), Glob("*b")
	checkTable(t, "Meet", StringSet.Meet, []cell{
		{name: "None ∧ None", x: none, y: none, empty: true},
		{name: "None ∧ Exact", x: none, y: exA, empty: true},
		{name: "None ∧ Glob", x: none, y: gA, empty: true},
		{name: "None ∧ Any", x: none, y: top, empty: true},
		{name: "None ∧ Unknown", x: none, y: unk, empty: true},

		{name: "Exact ∧ Exact, equal", x: exA, y: Exact("a"), want: []string{"a"}},
		{name: "Exact ∧ Exact, different", x: exA, y: exB, empty: true},
		{name: "Exact ∧ Glob, matching", x: exA, y: gA, want: []string{"a"}},
		{name: "Exact ∧ Glob, not matching", x: exA, y: gB, empty: true},
		{name: "Exact ∧ Any", x: exA, y: top, want: []string{"a"}},
		{name: "Exact ∧ Unknown", x: exA, y: unk, want: []string{"a"}},

		{name: "Glob ∧ Glob, same", x: gA, y: Glob("a*"), want: []string{"a", "ab"}},
		{name: "Glob ∧ Glob, different", x: gA, y: gB, want: []string{"ab"}},
		{name: "Glob ∧ Any", x: gA, y: top, want: []string{"a", "ab"}},
		{name: "Glob ∧ Unknown", x: gA, y: unk, want: []string{"a", "ab"}},

		{name: "Any ∧ Any", x: top, y: top, top: true},
		{name: "Any ∧ Unknown", x: top, y: unk, top: true, unknown: true},

		{name: "Unknown ∧ Unknown", x: unk, y: Unknown("s"), top: true, unknown: true},
	})
}

func TestJoinTable(t *testing.T) {
	none, top, unk := None(), Any(), Unknown("r")
	exA, exB := Exact("a"), Exact("b")
	gA, gB := Glob("a*"), Glob("*b")
	checkTable(t, "Join", StringSet.Join, []cell{
		{name: "None ∨ None", x: none, y: none, empty: true},
		{name: "None ∨ Exact", x: none, y: exA, want: []string{"a"}},
		{name: "None ∨ Glob", x: none, y: gA, want: []string{"a", "ab"}},
		{name: "None ∨ Any", x: none, y: top, top: true},
		{name: "None ∨ Unknown", x: none, y: unk, top: true, unknown: true},

		{name: "Exact ∨ Exact, equal", x: exA, y: Exact("a"), want: []string{"a"}},
		{name: "Exact ∨ Exact, different", x: exA, y: exB, want: []string{"a", "b"}},
		{name: "Exact ∨ Glob, matching", x: exA, y: gA, want: []string{"a", "ab"}},
		{name: "Exact ∨ Glob, not matching", x: exA, y: gB, want: []string{"a", "b", "ab"}},
		{name: "Exact ∨ Any", x: exA, y: top, top: true},
		{name: "Exact ∨ Unknown", x: exA, y: unk, top: true, unknown: true},

		{name: "Glob ∨ Glob, same", x: gA, y: Glob("a*"), want: []string{"a", "ab"}},
		{name: "Glob ∨ Glob, different", x: gA, y: gB, want: []string{"a", "b", "ab"}},
		{name: "Glob ∨ Any", x: gA, y: top, top: true},
		{name: "Glob ∨ Unknown", x: gA, y: unk, top: true, unknown: true},

		{name: "Any ∨ Any", x: top, y: top, top: true},
		{name: "Any ∨ Unknown", x: top, y: unk, top: true, unknown: true},

		{name: "Unknown ∨ Unknown", x: unk, y: Unknown("s"), top: true, unknown: true},
	})
}

func TestIsEmptyNeverGuesses(t *testing.T) {
	s := Glob("a*").Meet(Glob("*b"))
	if s.IsEmpty() {
		t.Fatalf("%s.IsEmpty() = true; the set contains %q", s, "ab")
	}
	if !s.Contains("ab") {
		t.Fatalf("%s.Contains(%q) = false", s, "ab")
	}
	// Semantically empty: nothing starts with both "a" and "b". Deciding that
	// needs automata, so the only sound answer today is "not proven".
	d := Glob("a*").Meet(Glob("b*"))
	if d.IsEmpty() {
		t.Fatalf("%s.IsEmpty() = true; emptiness of two globs is undecided here and must not be claimed", d)
	}
}

// compounds are the two node kinds the tables do not name, so that every
// rule is also exercised against them.
func compounds() []StringSet {
	return []StringSet{
		Exact("a").Join(Glob("b*")), // union
		Glob("a*").Meet(Glob("*b")), // intersection
	}
}

func TestUnknownAbsorbsUnderJoin(t *testing.T) {
	unk := Unknown("r")
	others := append([]StringSet{None(), Exact("a"), Glob("a*"), Any(), Unknown("s")}, compounds()...)
	for _, x := range others {
		for _, got := range []StringSet{unk.Join(x), x.Join(unk)} {
			if !IsUnknown(got) || !got.IsTop() {
				t.Errorf("Unknown ∨ %s = %s: IsUnknown() = %v, IsTop() = %v; want both true", x, got, IsUnknown(got), got.IsTop())
			}
			assertMembers(t, "Unknown ∨ "+x.String(), got, probes)
		}
	}
}

func TestUnknownIsIdentityUnderMeet(t *testing.T) {
	unk := Unknown("r")
	narrowing := append([]StringSet{None(), Exact("a"), Glob("a*")}, compounds()...)
	for _, x := range narrowing {
		for _, got := range []StringSet{unk.Meet(x), x.Meet(unk)} {
			for _, p := range probes {
				if got.Contains(p) != x.Contains(p) {
					t.Errorf("Unknown ∧ %s = %s: disagrees with %s on %q", x, got, x, p)
				}
			}
			if got.IsEmpty() != x.IsEmpty() {
				t.Errorf("Unknown ∧ %s = %s: IsEmpty() = %v, want %v", x, got, got.IsEmpty(), x.IsEmpty())
			}
			// The flag is dropped deliberately: B1b records inexactness per
			// result, and a lattice that kept it would call everything unknown.
			if IsUnknown(got) {
				t.Errorf("Unknown ∧ %s = %s: IsUnknown() = true; Meet must not carry the flag", x, got)
			}
		}
	}
	// Nothing narrowed, so the flag survives: the claim is still unconstrained
	// AND a constraint on it went unevaluated.
	for _, x := range []StringSet{Any(), Unknown("s")} {
		for _, got := range []StringSet{unk.Meet(x), x.Meet(unk)} {
			if !IsUnknown(got) || !got.IsTop() {
				t.Errorf("Unknown ∧ %s = %s: IsUnknown() = %v, IsTop() = %v; want both true", x, got, IsUnknown(got), got.IsTop())
			}
		}
	}
}

func TestIsUnknownPropagatesThroughJoin(t *testing.T) {
	s := Exact("a").Join(Unknown("r")).Join(Glob("b*"))
	if !IsUnknown(s) {
		t.Errorf("IsUnknown(%s) = false after a Join with an Unknown", s)
	}
	if got := Reason(s); got != "r" {
		t.Errorf("Reason(%s) = %q, want %q", s, got, "r")
	}
	// A Join whose Unknown is buried under a Meet of a Join still surfaces it.
	deep := Glob("a*").Join(Unknown("r")).Meet(Any())
	if !IsUnknown(deep) {
		t.Errorf("IsUnknown(%s) = false", deep)
	}
	m := Unknown("r").Meet(Exact("a"))
	if IsUnknown(m) || Reason(m) != "" {
		t.Errorf("IsUnknown(%s) = %v, Reason = %q; Meet must drop the flag", m, IsUnknown(m), Reason(m))
	}
}

func TestStringIsStable(t *testing.T) {
	same := []struct {
		name string
		a, b StringSet
	}{
		{
			"union built in two orders",
			Exact("a").Join(Glob("b*")).Join(Exact("c")),
			Exact("c").Join(Glob("b*").Join(Exact("a"))),
		},
		{
			"intersection built in two orders",
			Glob("a*").Meet(Glob("*b")),
			Glob("*b").Meet(Glob("a*")),
		},
		{
			"unknown reasons in two orders",
			Unknown("x").Join(Unknown("y")),
			Unknown("y").Join(Unknown("x")),
		},
		{
			"distribution reaches the same normal form",
			Exact("a").Join(Glob("b*")).Meet(Glob("*c")),
			Glob("*c").Meet(Glob("b*")).Join(Glob("*c").Meet(Exact("a"))),
		},
		{
			"nested unions flatten",
			Exact("a").Join(Exact("b")).Join(Exact("c").Join(Exact("d"))),
			Exact("d").Join(Exact("c")).Join(Exact("b")).Join(Exact("a")),
		},
	}
	for _, c := range same {
		if c.a.String() != c.b.String() {
			t.Errorf("%s: %q != %q", c.name, c.a.String(), c.b.String())
		}
	}
}

// TestStringForms pins the rendering, because golden files and finding IDs
// are content-addressed on it. Values and patterns are quoted so that no two
// distinct sets share a rendering, and non-ASCII is escaped so that the
// rendering cannot change when a Go release updates its Unicode tables.
func TestStringForms(t *testing.T) {
	cases := []struct {
		s    StringSet
		want string
	}{
		{Exact("x"), `"x"`},
		{Exact("like:a*"), `"like:a*"`},
		{Glob("a*"), `like:"a*"`},
		{Any(), `*`},
		{None(), `∅`},
		{Unknown("r"), `?("r")`},
		{Unknown("b").Join(Unknown("a")), `?("a", "b")`},
		{Exact("a").Join(Glob("b*")), `("a" | like:"b*")`},
		{Glob("a*").Meet(Glob("*b")), `(like:"*b" & like:"a*")`},
		{Glob("a*").Meet(Glob("*b")).Join(Exact("c")), `("c" | (like:"*b" & like:"a*"))`},
		{Exact(`a"b`), `"a\"b"`},
		{Exact("café"), `"caf\` + `u00e9"`},
		{Glob("caf*é"), `like:"caf*\` + `u00e9"`},
		{Unknown("é"), `?("\` + `u00e9")`},
		{Exact("\xff"), `"\xff"`},
	}
	for _, c := range cases {
		if got := c.s.String(); got != c.want {
			t.Errorf("String() = %q, want %q", got, c.want)
		}
	}
	if Exact("like:a*").String() == Glob("a*").String() {
		t.Errorf("an Exact and a Glob must never render identically")
	}
}

func TestReason(t *testing.T) {
	if got := Reason(Unknown("r")); got != "r" {
		t.Errorf("Reason(Unknown(%q)) = %q", "r", got)
	}
	if got := Reason(Unknown("b").Join(Unknown("a"))); got != "a; b" {
		t.Errorf("Reason of two joined Unknowns = %q, want %q", got, "a; b")
	}
	if got := Reason(Unknown("a").Meet(Unknown("a"))); got != "a" {
		t.Errorf("Reason of the same Unknown twice = %q, want %q", got, "a")
	}
	if got := Reason(Any().Meet(Unknown("k"))); got != "k" {
		t.Errorf("Reason(Any ∧ Unknown) = %q, want %q", got, "k")
	}
	others := append([]StringSet{Exact("a"), Glob("a*"), Any(), None()}, compounds()...)
	for _, s := range others {
		if got := Reason(s); got != "" {
			t.Errorf("Reason(%s) = %q, want empty", s, got)
		}
	}
}

func TestExactIsLiteral(t *testing.T) {
	if Exact("a*").Contains("ab") || !Exact("a*").Contains("a*") {
		t.Errorf(`Exact("a*") must contain "a*" and nothing else`)
	}
	if Exact("a?").Contains("ab") {
		t.Errorf(`Exact("a?") must not contain "ab"`)
	}
}

func TestMeetDistributesOverUnion(t *testing.T) {
	s := Exact("a").Join(Glob("b*")).Meet(Glob("*c"))
	for _, v := range []string{"bc", "bxc", "b/c"} {
		if !s.Contains(v) {
			t.Errorf("%s.Contains(%q) = false", s, v)
		}
	}
	for _, v := range []string{"a", "b", "c", "ac"} {
		if s.Contains(v) {
			t.Errorf("%s.Contains(%q) = true", s, v)
		}
	}
	if s.IsEmpty() {
		t.Errorf("%s.IsEmpty() = true", s)
	}
	if got := s.String(); got != `(like:"*c" & like:"b*")` {
		t.Errorf("String() = %q; the empty branch must be dropped", got)
	}
}

func TestMeetOfUnionsIsPairwise(t *testing.T) {
	ab := Exact("a").Join(Exact("b"))
	bc := Exact("b").Join(Exact("c"))
	if got := ab.Meet(bc).String(); got != `"b"` {
		t.Errorf("(a | b) ∧ (b | c) = %s, want \"b\"", got)
	}
	// Two unions of Exacts with nothing in common are PROVABLY empty: every
	// pairwise Meet is decided, so the lattice may say so.
	cd := Exact("c").Join(Exact("d"))
	if got := ab.Meet(cd); !got.IsEmpty() {
		t.Errorf("(a | b) ∧ (c | d) = %s, want a provably empty set", got)
	}
	mixed := Exact("a").Join(Glob("b*")).Meet(Exact("bb").Join(Glob("a*")))
	assertMembers(t, "(a | b*) ∧ (bb | a*)", mixed, []string{"a"})
	if !mixed.Contains("bb") {
		t.Errorf("%s must contain %q", mixed, "bb")
	}
}

func TestJoinFlattensNestedUnions(t *testing.T) {
	s := Exact("a").Join(Exact("b")).Join(Exact("c").Join(Exact("a")))
	if got := s.String(); got != `("a" | "b" | "c")` {
		t.Errorf("String() = %q", got)
	}
	assertMembers(t, "flattened union", s, []string{"a", "b", "c"})
}

func TestJoinAbsorbsExactIntoContainingTerm(t *testing.T) {
	cases := []struct {
		name string
		s    StringSet
		want string
	}{
		{"exact into glob", Exact("ab").Join(Exact("c")).Join(Glob("a*")), `("c" | like:"a*")`},
		{"exact into glob, other nesting", Exact("ab").Join(Exact("c").Join(Glob("a*"))), `("c" | like:"a*")`},
		{"exact into intersection", Exact("ab").Join(Glob("a*").Meet(Glob("*b"))), `(like:"*b" & like:"a*")`},
		{"exact kept when nothing contains it", Exact("ba").Join(Glob("a*")), `("ba" | like:"a*")`},
	}
	for _, c := range cases {
		if got := c.s.String(); got != c.want {
			t.Errorf("%s: String() = %q, want %q", c.name, got, c.want)
		}
	}
}

func TestMeetMergesIntersections(t *testing.T) {
	i := Glob("a*").Meet(Glob("*b"))
	cases := []struct {
		name string
		s    StringSet
		want string
	}{
		{"same glob again", i.Meet(Glob("a*")), `(like:"*b" & like:"a*")`},
		{"new glob", i.Meet(Glob("?*")), `(like:"*b" & like:"?*" & like:"a*")`},
		{"intersection with intersection", i.Meet(Glob("?*").Meet(Glob("a*"))), `(like:"*b" & like:"?*" & like:"a*")`},
		{"exact resolves an intersection", Exact("ab").Meet(i), `"ab"`},
	}
	for _, c := range cases {
		if got := c.s.String(); got != c.want {
			t.Errorf("%s: String() = %q, want %q", c.name, got, c.want)
		}
	}
	if got := Exact("b").Meet(i); !got.IsEmpty() {
		t.Errorf("Exact(\"b\") ∧ %s = %s, want a provably empty set", i, got)
	}
	if got := Exact("ab").Meet(Exact("c").Join(Glob("a*"))); got.String() != `"ab"` {
		t.Errorf("Exact ∧ union = %s, want \"ab\"", got)
	}
}

func TestJoinKeepsIntersectionsAsMembers(t *testing.T) {
	i := Glob("a*").Meet(Glob("*b"))
	j := Glob("c*").Meet(Glob("*d"))
	s := i.Join(j)
	if got := s.String(); got != `((like:"*b" & like:"a*") | (like:"*d" & like:"c*"))` {
		t.Errorf("String() = %q", got)
	}
	for _, v := range []string{"ab", "axb", "cd", "cxd"} {
		if !s.Contains(v) {
			t.Errorf("%s.Contains(%q) = false", s, v)
		}
	}
	for _, v := range []string{"ad", "cb", ""} {
		if s.Contains(v) {
			t.Errorf("%s.Contains(%q) = true", s, v)
		}
	}
}

// TestCompoundNodesMakeNoClaims: a union or intersection node never asserts
// emptiness or totality. The one below IS every string, but proving that
// needs automata, so IsTop must stay false while Contains stays true.
func TestCompoundNodesMakeNoClaims(t *testing.T) {
	total := Glob("?*").Join(Exact(""))
	if total.IsTop() {
		t.Errorf("%s.IsTop() = true; totality of a union is undecided and must not be claimed", total)
	}
	for _, p := range probes {
		if !total.Contains(p) {
			t.Errorf("%s.Contains(%q) = false", total, p)
		}
	}
	for _, s := range compounds() {
		if s.IsTop() || s.IsEmpty() {
			t.Errorf("%s: IsTop() = %v, IsEmpty() = %v; want both false", s, s.IsTop(), s.IsEmpty())
		}
	}
}

func TestCompoundsAgainstAny(t *testing.T) {
	for _, s := range compounds() {
		for _, got := range []StringSet{s.Meet(Any()), Any().Meet(s)} {
			if got.String() != s.String() {
				t.Errorf("%s ∧ Any = %s, want the set unchanged", s, got)
			}
		}
		for _, got := range []StringSet{s.Join(Any()), Any().Join(s)} {
			if !got.IsTop() || IsUnknown(got) {
				t.Errorf("%s ∨ Any = %s, want Any", s, got)
			}
		}
		for _, got := range []StringSet{s.Meet(None()), None().Meet(s)} {
			if !got.IsEmpty() {
				t.Errorf("%s ∧ None = %s, want None", s, got)
			}
		}
		for _, got := range []StringSet{s.Join(None()), None().Join(s)} {
			if got.String() != s.String() {
				t.Errorf("%s ∨ None = %s, want the set unchanged", s, got)
			}
		}
	}
}
