package eval

import (
	"cmp"
	"slices"
	"strconv"
)

// Caveat records why an AdmittedSet is not exact: a construct the parser
// could not evaluate, or a widening the lattice applied. The lattice itself
// carries no inexactness, so this is the only place a reader learns that a
// clean-looking set is an upper bound.
type Caveat struct {
	Claim  ClaimKey // "" when it applies to the whole set
	Reason string   // human sentence: "operator NumericLessThan is not modelled"
	Source string   // where it came from: "statement[1].Condition"
}

// WithCaveat returns the set with c recorded. The receiver is unchanged.
func (a AdmittedSet) WithCaveat(c Caveat) AdmittedSet {
	return AdmittedSet{terms: a.terms, caveats: normaliseCaveats(append(slices.Clone(a.caveats), c))}
}

// Caveats returns a copy of the caveats, in canonical order.
func (a AdmittedSet) Caveats() []Caveat { return slices.Clone(a.caveats) }

// Exact reports whether the set carries no caveat: it is the admitted set,
// not an upper bound on it.
func (a AdmittedSet) Exact() bool { return len(a.caveats) == 0 }

// normaliseCaveats sorts and deduplicates, so that the caveats of a Join or
// Meet do not depend on operand order and a caveat recorded twice reads once.
func normaliseCaveats(cs []Caveat) []Caveat {
	if len(cs) == 0 {
		return nil
	}
	sorted := slices.Clone(cs)
	slices.SortFunc(sorted, func(x, y Caveat) int {
		return cmp.Or(
			cmp.Compare(x.Source, y.Source),
			cmp.Compare(x.Claim, y.Claim),
			cmp.Compare(x.Reason, y.Reason),
		)
	})
	return slices.Compact(sorted)
}

// overflow is the caveat attached when op widened the set to Everything
// because the term list would have exceeded termCap.
func overflow(op string) Caveat {
	return Caveat{
		Reason: "term count exceeded " + strconv.Itoa(termCap) + "; widened to unconstrained",
		Source: op,
	}
}
