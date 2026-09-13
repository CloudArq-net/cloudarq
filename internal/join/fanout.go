package join

import (
	"cmp"
	"errors"
	"slices"

	"github.com/CloudArq-net/cloudarq/internal/trust"
)

// FanOut is J6 over a corpus: every pair of grants on two targets, from
// one issuer or from an issuer one of them does not name, whose admitted
// identities are not provably disjoint, as one Link each, in canonical
// order. The corpus is a set: a grant listed twice is one grant, and two
// grants that differ only in what no Link reads are one grant. Deny grants
// are never a side, and a grant whose effect could not be read is a side
// and a possible Deny at once; each counts against every pair on its
// target that it can touch, or that its reading cannot rule out. Links are
// pairwise, so a counterparty trusted by n targets yields n(n-1)/2 of
// them; the reporter folds those into one cluster and one sentence.
//
// A grant that names no target is a parser bug, and one with no evidence
// record, or none that names its call and its status, is a collector bug.
// Such a grant is never a side, but it does not silence the corpus: the
// links between every other grant are returned beside an error naming
// each such grant once, in canonical order, wrapping ErrNoTarget,
// ErrNoEvidence or ErrMalformedEvidence. A Deny without evidence is named
// too and still casts its doubt, because doubt needs no proof. A malformed
// record beside well-formed ones refuses nothing: the grant is a side, the
// record a doubt its links name, so that a collector bug on one record
// reads as a doubted fan-out and not as none.
//
// Issuer identity is the IssuerRef string. Two spellings of one issuer,
// such as a GitHub enterprise's own issuer path beside the public host, are
// two issuers here and never pair; aliases are the registry's to declare.
// A grant whose issuer is blank names none, as the AWS parser emits for a
// bare "*" principal that admits every provider's tokens: it pairs with
// every issuer's grants on other targets, and every such link is
// Indeterminate, because which counterparty it admits is not known.
func FanOut(grants []trust.Grant) ([]Link, error) {
	sorted := slices.SortedFunc(slices.Values(grants), compareGrants)
	sorted = slices.CompactFunc(sorted, func(x, y trust.Grant) bool { return compareGrants(x, y) == 0 })
	var denials []trust.Grant
	var refused []error
	for _, g := range sorted {
		if err := wellFormed(g); err != nil {
			refused = append(refused, err)
		}
		if g.Effect != trust.Allow {
			denials = append(denials, g)
		}
	}
	links := []Link{}
	for i, a := range sorted {
		for _, b := range sorted[i+1:] {
			l, err := NewLink(a, b, denials...)
			if err != nil {
				// Every refusal NewLink gives says the two are not a pair:
				// one target, two issuers, a Deny, a provably empty overlap,
				// or a side that is not well formed, which is reported once
				// per grant above rather than once per partner.
				continue
			}
			links = append(links, l)
		}
	}
	slices.SortFunc(links, compareLinks)
	return links, errors.Join(refused...)
}

// compareLinks orders links by their pair of statements, then by what can
// still differ between two links of one pair: the evidence, when one
// statement was read twice, and the confidence and reason that follow
// from it.
func compareLinks(x, y Link) int {
	return cmp.Or(
		compareRefs(x.grants[0], y.grants[0]),
		compareRefs(x.grants[1], y.grants[1]),
		cmp.Compare(x.confidence, y.confidence),
		cmp.Compare(x.reason, y.reason),
		slices.CompareFunc(x.provenance, y.provenance, compareRecords),
	)
}
