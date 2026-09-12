package eval

import (
	"slices"
	"strconv"
	"strings"
)

// StringSet is a set of possible values for a single claim.
//
// Implementations are immutable. Every operation returns a new value.
type StringSet interface {
	// Contains reports whether v is a member. Exact for every implementation.
	Contains(v string) bool

	// Meet is intersection: the values admitted by BOTH sets.
	Meet(StringSet) StringSet

	// Join is union: the values admitted by EITHER set.
	Join(StringSet) StringSet

	// IsEmpty reports whether the set is PROVABLY empty.
	// It returns false whenever emptiness cannot be decided. Never the reverse.
	IsEmpty() bool

	// IsTop reports whether the set provably admits every string.
	IsTop() bool

	// String renders the set for humans and for golden files. Stable across runs.
	String() string
}

// Exact is the singleton {v}. The value is literal: "*" and "?" in v are
// ordinary characters, which is what an exact-match claim value means.
func Exact(v string) StringSet { return exact{v} }

// Any is the set of every string.
func Any() StringSet { return full{} }

// None is the set with no members.
func None() StringSet { return empty{} }

// Unknown is every string, because a constraint on this claim existed and
// could not be evaluated. It is the top element: as far as we can prove, the
// claim is unconstrained. What distinguishes it from Any is provenance, which
// Reason and IsUnknown expose so that a union that swallowed one stays
// observable.
func Unknown(reason string) StringSet { return unknown{reasons: []string{reason}} }

// Reason returns the explanation carried by an Unknown, and "" for anything
// else. Two Unknowns that met or joined carry both explanations.
func Reason(s StringSet) string {
	if u, ok := s.(unknown); ok {
		return strings.Join(u.reasons, "; ")
	}
	return ""
}

// IsUnknown reports whether s is an Unknown, or was derived from one.
//
// Only Join preserves the flag. Meet drops it on purpose: an un-evaluated
// AND-constraint can only narrow, so the other operand is already the sound
// upper bound, and the inexactness is recorded per result by the parser, the
// one layer that knows why evaluation failed.
func IsUnknown(s StringSet) bool {
	_, ok := s.(unknown)
	return ok
}

// exact is the singleton set.
type exact struct{ v string }

func (e exact) Contains(v string) bool     { return v == e.v }
func (e exact) IsEmpty() bool              { return false }
func (e exact) IsTop() bool                { return false }
func (e exact) Meet(o StringSet) StringSet { return meet(e, o) }
func (e exact) Join(o StringSet) StringSet { return join(e, o) }
func (e exact) String() string             { return strconv.Quote(e.v) }

// full is the set of every string.
type full struct{}

func (full) Contains(string) bool         { return true }
func (full) IsEmpty() bool                { return false }
func (full) IsTop() bool                  { return true }
func (f full) Meet(o StringSet) StringSet { return meet(f, o) }
func (f full) Join(o StringSet) StringSet { return join(f, o) }
func (full) String() string               { return "*" }

// empty is the set with no members. It is the only value for which IsEmpty
// is true, because it is the only one whose emptiness is proven rather than
// suspected.
type empty struct{}

func (empty) Contains(string) bool         { return false }
func (empty) IsEmpty() bool                { return true }
func (empty) IsTop() bool                  { return false }
func (e empty) Meet(o StringSet) StringSet { return meet(e, o) }
func (e empty) Join(o StringSet) StringSet { return join(e, o) }
func (empty) String() string               { return "∅" }

// unknown is every string, flagged. See Unknown.
type unknown struct {
	// reasons is sorted and deduplicated so that two Unknowns combined in
	// either order render identically; finding IDs depend on that.
	reasons []string
}

func (unknown) Contains(string) bool         { return true }
func (unknown) IsEmpty() bool                { return false }
func (unknown) IsTop() bool                  { return true }
func (u unknown) Meet(o StringSet) StringSet { return meet(u, o) }
func (u unknown) Join(o StringSet) StringSet { return join(u, o) }

func (u unknown) String() string {
	quoted := make([]string, len(u.reasons))
	for i, r := range u.reasons {
		quoted[i] = strconv.Quote(r)
	}
	return "?(" + strings.Join(quoted, ", ") + ")"
}

func mergeUnknown(a, b unknown) unknown {
	reasons := slices.Concat(a.reasons, b.reasons)
	slices.Sort(reasons)
	return unknown{reasons: slices.Compact(reasons)}
}

// union is the set of strings in at least one member.
//
// Members are exact, glob or inter nodes, never None, Any or Unknown: join
// folds those away first, so a union node exists only where no single member
// decides the whole set.
type union struct {
	members []StringSet // sorted by String, no duplicates, at least two
}

func (u union) Contains(v string) bool {
	for _, m := range u.members {
		if m.Contains(v) {
			return true
		}
	}
	return false
}

// IsEmpty and IsTop are false. The rules are "empty only when every member is
// empty" and "top only when some member is top", and by construction no
// member is either: exact and glob always have a witness, an intersection
// never claims emptiness, and join removes None, Any and Unknown before a
// union node is built. Both rules therefore evaluate to false, which is also
// the sound answer to each question when it cannot be decided.
func (union) IsEmpty() bool { return false }
func (union) IsTop() bool   { return false }

func (u union) Meet(o StringSet) StringSet { return meet(u, o) }
func (u union) Join(o StringSet) StringSet { return join(u, o) }
func (u union) String() string             { return renderMembers(u.members, " | ") }

// inter is the set of strings matching every one of at least two distinct
// globs. It exists because deciding whether two patterns share a string needs
// automata, which a later unit builds. Until then the node keeps every
// pattern and answers Contains exactly.
type inter struct {
	members []glob // sorted by pattern, no duplicates, at least two
}

func (i inter) Contains(v string) bool {
	for _, m := range i.members {
		if !m.Contains(v) {
			return false
		}
	}
	return true
}

// IsEmpty is false even when the patterns cannot possibly agree, such as "a*"
// and "b*". Emptiness is undecided here, and undecided must read as "not
// proven empty": reporting a dangerous policy as admitting nothing is the
// worst output this program can produce.
func (inter) IsEmpty() bool { return false }

// IsTop is false: every member rejects the empty string, so the intersection
// does too.
func (inter) IsTop() bool { return false }

func (i inter) Meet(o StringSet) StringSet { return meet(i, o) }
func (i inter) Join(o StringSet) StringSet { return join(i, o) }
func (i inter) String() string             { return renderMembers(i.members, " & ") }

// meet implements Meet for every node.
//
// The rules are applied in an order that matters. None wins over Unknown,
// because Unknown ∧ None is None: an unevaluated constraint cannot resurrect
// a set that is proven empty. Unknown then wins over Any, because a set that
// already admits everything gains nothing from Any but must not lose the
// flag that says a constraint went unevaluated.
func meet(a, b StringSet) StringSet {
	if a.IsEmpty() || b.IsEmpty() {
		return empty{}
	}
	ua, aUnknown := a.(unknown)
	ub, bUnknown := b.(unknown)
	switch {
	case aUnknown && bUnknown:
		return mergeUnknown(ua, ub)
	case aUnknown:
		return meetUnknown(ua, b)
	case bUnknown:
		return meetUnknown(ub, a)
	}
	if a.IsTop() {
		return b
	}
	if b.IsTop() {
		return a
	}
	// Both sides are now unions of terms. Intersection distributes over
	// union, and each pairwise Meet of terms is either decided outright or
	// becomes an intersection node.
	var out StringSet = empty{}
	for _, s := range terms(a) {
		for _, t := range terms(b) {
			out = join(out, meetTerms(s, t))
		}
	}
	return out
}

// meetUnknown is Unknown ∧ x for a non-empty x that is not itself Unknown:
// x, because an unevaluated AND-constraint can only ever narrow, so x is a
// sound upper bound. When x provably admits everything nothing narrowed, and
// the Unknown is kept so that IsUnknown stays true.
func meetUnknown(u unknown, x StringSet) StringSet {
	if x.IsTop() {
		return u
	}
	return x
}

// meetTerms is Meet between two terms, a term being an exact, a glob or an
// intersection node. An exact decides the answer outright by membership.
// Anything else is the merged list of patterns, because glob ∧ glob is not
// decidable in this unit.
func meetTerms(s, t StringSet) StringSet {
	if e, ok := s.(exact); ok {
		return meetExact(e, t)
	}
	if e, ok := t.(exact); ok {
		return meetExact(e, s)
	}
	return newInter(slices.Concat(globsOf(s), globsOf(t)))
}

func meetExact(e exact, o StringSet) StringSet {
	if o.Contains(e.v) {
		return e
	}
	return empty{}
}

// terms flattens a union into its members; anything else is a single term.
func terms(s StringSet) []StringSet {
	if u, ok := s.(union); ok {
		return u.members
	}
	return []StringSet{s}
}

// globsOf flattens an intersection into its patterns; a glob is a single
// pattern. Callers guarantee no other kind reaches here, and a violation of
// that guarantee must fail loudly rather than produce a wrong set.
func globsOf(s StringSet) []glob {
	if i, ok := s.(inter); ok {
		return i.members
	}
	return []glob{s.(glob)}
}

// newInter normalises a fresh list of patterns: sorted for a stable
// rendering, deduplicated so that p ∧ p is p, and collapsed to the bare glob
// when only one remains.
func newInter(globs []glob) StringSet {
	slices.SortFunc(globs, func(a, b glob) int { return strings.Compare(a.pattern, b.pattern) })
	globs = slices.CompactFunc(globs, func(a, b glob) bool { return a.pattern == b.pattern })
	if len(globs) == 1 {
		return globs[0]
	}
	return inter{members: globs}
}

// join implements Join for every node.
//
// Unknown absorbs everything, including None: an unevaluated branch could
// admit anything, so the union could admit anything. Any absorbs the rest,
// None contributes nothing, and whatever remains is flattened into one union.
func join(a, b StringSet) StringSet {
	ua, aUnknown := a.(unknown)
	ub, bUnknown := b.(unknown)
	switch {
	case aUnknown && bUnknown:
		return mergeUnknown(ua, ub)
	case aUnknown:
		return ua
	case bUnknown:
		return ub
	}
	if a.IsTop() || b.IsTop() {
		return full{}
	}
	if a.IsEmpty() {
		return b
	}
	if b.IsEmpty() {
		return a
	}
	return newUnion(slices.Concat(terms(a), terms(b)))
}

// newUnion normalises a fresh list of terms. Duplicates are dropped; an exact
// that another term already contains is dropped, which is the rule that
// Exact(a) ∨ Glob(q) is Glob(q) when q matches a; the rest are sorted by
// rendering so that the same set built in any order prints identically; and
// a single survivor is returned bare.
func newUnion(members []StringSet) StringSet {
	slices.SortFunc(members, func(a, b StringSet) int { return strings.Compare(a.String(), b.String()) })
	members = slices.CompactFunc(members, func(a, b StringSet) bool { return a.String() == b.String() })
	kept := make([]StringSet, 0, len(members))
	for i, m := range members {
		if e, ok := m.(exact); ok && containedByOther(e.v, members, i) {
			continue
		}
		kept = append(kept, m)
	}
	if len(kept) == 1 {
		return kept[0]
	}
	return union{members: kept}
}

// containedByOther reports whether a member other than members[skip] contains v.
func containedByOther(v string, members []StringSet, skip int) bool {
	for j, m := range members {
		if j != skip && m.Contains(v) {
			return true
		}
	}
	return false
}

func renderMembers[S StringSet](members []S, sep string) string {
	parts := make([]string, len(members))
	for i, m := range members {
		parts[i] = m.String()
	}
	return "(" + strings.Join(parts, sep) + ")"
}
