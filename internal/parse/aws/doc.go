// Package aws turns an AWS role trust policy into trust.Grants without
// evaluating, normalising away or discarding anything.
//
// A reader that recognises the shapes it expects and skips the rest
// under-approximates: a condition it did not understand reads as if it
// were absent, a principal it did not expect never enters the answer, and
// the role reads as narrower than it is. So an input this parser does not
// fully understand becomes Unknown, the top of the lattice, declared by a
// caveat on the claim and an anomaly whose sentence a user can read; a
// principal the parser cannot model still projects a grant; a statement is
// never dropped from the loop; and the user's bytes are kept, so an answer
// quotes the policy rather than a re-rendering of it.
//
// The one construct where Unknown must point the other way is a Deny. The
// admitted set is Allow minus Deny, so an Unknown that widened a Deny would
// deny more than the policy does. A Deny the parser cannot fully evaluate
// is not applied, and says so.
//
// What a claim is called belongs to the issuer, not to this package, and
// which condition keys AWS documents for an issuer belongs to the census:
// the parser hands each key to a ClaimVocabulary and leaves the claim
// Unknown when the vocabulary does not know the issuer or AWS does not
// document the key. No issuer hostname appears in this package; the
// registry is where such facts live.
package aws
