// Package aws turns an AWS role trust policy into trust.Grants without
// evaluating, normalising away or discarding anything.
//
// It exists because every incumbent in this space parses a trust policy by
// recognising the shapes it expects and skipping the rest, and skipping is
// an under-approximation: a condition the tool did not understand is
// reported as if it were absent, or a principal it did not expect never
// enters the check at all, and the role reads as narrower than it is. The
// rule here is the opposite. An input this parser does not fully understand
// becomes Unknown, the top of the lattice, declared by a caveat on the
// claim and an anomaly whose sentence a customer can read; a principal the
// parser cannot model still projects a grant; a statement is never dropped
// from the loop; and the customer's bytes are kept, so a finding quotes the
// policy rather than a re-rendering of it.
//
// The one construct where Unknown must point the other way is a Deny. The
// admitted set is Allow minus Deny, so an Unknown that widened a Deny would
// deny more than the policy does. A Deny the parser cannot fully evaluate
// is not applied, and says so.
//
// What a claim is called belongs to the issuer, not to this package: the
// parser hands each spelling to a ClaimVocabulary and leaves the claim
// Unknown when the vocabulary does not know the issuer. No issuer hostname
// appears in this package; the registry is where such facts live.
package aws
