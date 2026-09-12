package eval

import (
	"maps"
	"slices"
	"strings"
)

// ClaimKey is a normalised claim name: "sub", "aud", "repository_id".
// Comparison is case-sensitive. Callers normalise before constructing.
type ClaimKey string

// Term is one conjunction: every listed claim must satisfy its StringSet.
//
// A claim ABSENT from a Term is UNCONSTRAINED, i.e. Any. It is not empty.
// This is the single easiest thing in the package to get backwards. It
// mirrors IAM, where a condition constrains only the keys it names.
//
// A nil StringSet in a Term is a programming error and panics.
type Term map[ClaimKey]StringSet

// AdmittedSet is a union of Terms: disjunctive normal form over claims.
//
// The zero value admits nothing. Use Everything() for the unconstrained set.
//
// Every value is canonical: no Term carries an Any-valued claim, because an
// absent claim already means that; no Term is provably empty; Terms are
// deduplicated and sorted by rendering; and a Term that admits every token
// makes the set Everything, whose only Term is empty. String therefore
// depends on the canonical term list alone, never on the order the Terms
// arrived in. Two sets that admit the same tokens through different Terms
// still render differently, as with StringSet.
type AdmittedSet struct {
	terms   []Term   // canonical, at most termCap
	caveats []Caveat // sorted, deduplicated
}

// termCap bounds the disjunction. The cross product is quadratic and real
// policies nest; past the cap the set widens to Everything with a caveat,
// never truncates, because a truncated list would under-approximate.
const termCap = 256

// NewAdmittedSet is the union of the given Terms. The Terms are copied, so
// the caller may keep mutating its maps. The term cap applies here as it
// does in Meet and Join, with Source "NewAdmittedSet", so that the bound is
// an invariant of every value rather than of two methods.
func NewAdmittedSet(terms ...Term) AdmittedSet { return normalise(terms, nil, "NewAdmittedSet") }

// Everything admits every token: one Term with no constraints.
func Everything() AdmittedSet { return AdmittedSet{terms: []Term{{}}} }

// Nothing admits no token: no Terms.
func Nothing() AdmittedSet { return AdmittedSet{} }

// Meet is conjunction: the cross product of the two term lists, each pair
// merged claim by claim.
func (a AdmittedSet) Meet(b AdmittedSet) AdmittedSet {
	product := make([]Term, 0, len(a.terms)*len(b.terms))
	for _, x := range a.terms {
		for _, y := range b.terms {
			product = append(product, conjoin(x, y))
		}
	}
	return normalise(product, slices.Concat(a.caveats, b.caveats), "Meet")
}

// conjoin merges two conjunctions: a claim in both is the Meet of its two
// constraints, a claim in one carries over unchanged.
func conjoin(x, y Term) Term {
	merged := maps.Clone(x)
	for k, s := range y {
		if existing, ok := merged[k]; ok {
			merged[k] = existing.Meet(s)
		} else {
			merged[k] = s
		}
	}
	return merged
}

// Join is disjunction: the concatenation of both term lists.
func (a AdmittedSet) Join(b AdmittedSet) AdmittedSet {
	return normalise(slices.Concat(a.terms, b.terms), slices.Concat(a.caveats, b.caveats), "Join")
}

// normalise builds the canonical form described on AdmittedSet. op names
// the operation for the overflow caveat.
//
// Two passes, so that the answer cannot depend on the order the Terms
// arrived in: the first decides whether any Term admits everything, which
// makes the whole set Everything with no widening to report; the second
// renders and deduplicates, and stops as soon as the cap is exceeded, since
// rendering a 65,536-term cross product that is about to collapse would
// cost more than the answer is worth.
func normalise(terms []Term, caveats []Caveat, op string) AdmittedSet {
	live := make([]Term, 0, len(terms))
	for _, t := range terms {
		term, ok := normaliseTerm(t)
		if !ok {
			continue
		}
		if allTop(term) {
			return AdmittedSet{terms: []Term{{}}, caveats: normaliseCaveats(caveats)}
		}
		live = append(live, term)
	}
	seen := make(map[string]struct{}, len(live))
	kept := make([]renderedTerm, 0, len(live))
	for _, term := range live {
		text := renderTerm(term)
		if _, dup := seen[text]; dup {
			continue
		}
		seen[text] = struct{}{}
		kept = append(kept, renderedTerm{term, text})
		if len(kept) > termCap {
			return AdmittedSet{terms: []Term{{}}, caveats: normaliseCaveats(append(caveats, overflow(op)))}
		}
	}
	slices.SortFunc(kept, func(x, y renderedTerm) int { return strings.Compare(x.text, y.text) })
	out := make([]Term, len(kept))
	for i, r := range kept {
		out[i] = r.term
	}
	return AdmittedSet{terms: out, caveats: normaliseCaveats(caveats)}
}

// renderedTerm pairs a Term with its rendering, so that sorting a term list
// renders each Term once.
type renderedTerm struct {
	term Term
	text string
}

// normaliseTerm copies a Term into canonical form. A claim admitting
// everything with no provenance is dropped, because an absent claim means
// exactly that; an Unknown is kept, because it says a constraint went
// unevaluated. A Term with a provably empty claim admits nothing and is
// reported dead.
func normaliseTerm(t Term) (Term, bool) {
	term := make(Term, len(t))
	for k, s := range t {
		if s.IsEmpty() {
			return nil, false
		}
		if s.IsTop() && !IsUnknown(s) {
			continue
		}
		term[k] = s
	}
	return term, true
}

// allTop reports whether every constraint of a Term admits everything, so
// that the Term admits every token. The empty Term qualifies.
func allTop(term Term) bool {
	for _, s := range term {
		if !s.IsTop() {
			return false
		}
	}
	return true
}

// Admits reports whether a token satisfies at least one Term.
// A claim present in a Term but missing from the token is NOT admitted by that
// Term, unless the Term's StringSet for it is top.
func (a AdmittedSet) Admits(token map[ClaimKey]string) bool {
	for _, term := range a.terms {
		if len(failures(term, token)) == 0 {
			return true
		}
	}
	return false
}

// Excludes explains a rejection. It returns the claim whose constraint kept the
// token out, and that constraint. ok is false when the token IS admitted.
//
// With several Terms, it reports the failure from the Term the token came
// closest to satisfying: fewest failing claims, then the lexicographically
// smallest failing ClaimKey, then the Term that sorts first in canonical
// order. The answer is therefore a function of the set and the token alone.
//
// On a set that admits nothing at all, ok is true with an empty claim and a
// nil constraint: there is no single claim to blame.
func (a AdmittedSet) Excludes(token map[ClaimKey]string) (claim ClaimKey, got StringSet, ok bool) {
	var closest []ClaimKey
	var closestTerm Term
	for _, term := range a.terms {
		failed := failures(term, token)
		if len(failed) == 0 {
			return "", nil, false
		}
		if closest == nil || len(failed) < len(closest) || (len(failed) == len(closest) && failed[0] < closest[0]) {
			closest, closestTerm = failed, term
		}
	}
	if closest == nil {
		return "", nil, true
	}
	return closest[0], closestTerm[closest[0]], true
}

// failures lists, in key order, the claims of term the token does not
// satisfy. A claim absent from the token satisfies only a constraint that
// admits everything, because an unconstrained claim places no requirement
// on the token.
func failures(term Term, token map[ClaimKey]string) []ClaimKey {
	var failed []ClaimKey
	for k, s := range term {
		v, present := token[k]
		if (present && s.Contains(v)) || (!present && s.IsTop()) {
			continue
		}
		failed = append(failed, k)
	}
	slices.Sort(failed)
	return failed
}

// IsEmpty reports whether the set provably admits no token. Only a set with
// no live Terms qualifies; a Term whose claims are undecided stays.
func (a AdmittedSet) IsEmpty() bool { return len(a.terms) == 0 }

// IsTop reports whether the set provably admits every token. Canonical form
// makes that one shape: the single, empty Term.
func (a AdmittedSet) IsTop() bool { return len(a.terms) == 1 && len(a.terms[0]) == 0 }

// Terms returns a copy of the Terms, so that a caller cannot reach into the
// set's maps.
func (a AdmittedSet) Terms() []Term {
	out := make([]Term, len(a.terms))
	for i, t := range a.terms {
		out[i] = maps.Clone(t)
	}
	return out
}

// String renders the Terms in canonical order, so the same set built any
// way prints identically. Caveats are not part of the rendering; they are
// reachable through Caveats.
func (a AdmittedSet) String() string {
	if len(a.terms) == 0 {
		return "∅"
	}
	parts := make([]string, len(a.terms))
	for i, t := range a.terms {
		parts[i] = renderTerm(t)
	}
	return strings.Join(parts, " | ")
}

// renderTerm sorts the claims by key: a Term is a map, and a rendering that
// followed map order would differ between runs.
func renderTerm(t Term) string {
	keys := slices.Sorted(maps.Keys(t))
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = string(k) + "=" + t[k].String()
	}
	return "{" + strings.Join(parts, ", ") + "}"
}
