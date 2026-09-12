// Package trust is the provider-neutral model of a trust grant: some set of
// external identities, from some issuer, may assume some target, when the
// claims in their token satisfy some constraints.
//
// Every provider parser produces Grants, and nothing downstream of this
// package knows which cloud a Grant came from. That is the whole
// architectural bet: incumbents keep a check per provider, per format, per
// operator, and the combinations nobody fills in are where the wrong answers
// live. A lattice has no cells. Adding a provider must cost one parser and one
// collector, so nothing in this package enumerates clouds: how a provider
// spells a claim, names an issuer or identifies a target is the parser's
// knowledge, and the conformance harness is what makes the claim checkable
// rather than rhetorical.
//
// The claim constraints of a Grant are one eval.AdmittedSet over canonical
// claim keys, aud included. A per-claim map could not hold what AWS expresses
// through several statements, where sub and aud vary together; projecting
// that to independent per-claim sets would admit combinations the policy does
// not, which is the silent widening this product exists to never produce.
package trust

import (
	"encoding/json"

	"github.com/CloudArq-net/cloudarq/internal/eval"
	"github.com/CloudArq-net/cloudarq/internal/evidence"
)

// Provider names a cloud. It appears on parser registration and in the
// conformance triples, never on a Grant.
type Provider string

const (
	AWS   Provider = "aws"
	Azure Provider = "azure"
	GCP   Provider = "gcp"
)

// ClaimKey is the canonical name of a token claim: the name as the issuer
// spells it, with no provider prefix. It is eval's own key type, so that a
// Grant's constraints and the lattice they live in never need converting.
type ClaimKey = eval.ClaimKey

// Effect is what a matching token gets. EffectUnknown is a malformed effect
// the parser could not read; the evaluator must treat it as possibly Allow,
// because assuming Deny would report a policy as narrower than it is.
type Effect string

const (
	Allow         Effect = "Allow"
	Deny          Effect = "Deny"
	EffectUnknown Effect = "Unknown"
)

// TargetKind names what a token becomes when the grant applies: a role, a
// service account, an application. The parser names it after the resource
// it read, in the provider's own vocabulary; nothing here enumerates clouds,
// so a fourth provider adds no constant to this package.
type TargetKind string

// TargetRef identifies the thing a token may assume, by the provider's own
// identifier: a role ARN, an application object id, a service account email.
type TargetRef struct {
	Kind TargetKind
	ID   string
}

// IssuerRef is the normalised issuer URL, the key every issuer is known by in
// the registry. Build one with NormaliseIssuer.
type IssuerRef string

// Unmodelled is the Anomaly kind for a construct the parser recognised but
// could not express in the lattice, and therefore widened to Unknown.
const Unmodelled = "unmodelled-construct"

// Anomaly is a fact about the source document that the evaluator or the
// reporter may need: a construct that could not be modelled, a duplicate
// key, a condition that does not do what it looks like it does. It is never
// a warning to be logged and dropped. An anomaly that changes what the Grant
// admits is also recorded as a caveat on Admits, so Exact answers from the
// set alone.
type Anomaly struct {
	Kind      string   // Unmodelled, or a kind the parser defines
	Claim     ClaimKey // "" when it applies to the whole grant
	Construct string   // the provider's own name for what was met: "ForAllValues:StringLike"
	Message   string   // a sentence that can be printed to a customer verbatim
	Source    string   // where it came from: "statement[1].Condition"
}

// Grant is one provider-neutral statement of trust.
//
// Admits is the set of token claim-assignments the grant accepts, aud
// included as the claim "aud". Unknown is a legitimate value for any claim
// and is the correct one whenever the parser met something it does not fully
// model; the parser records why as a caveat and an anomaly.
type Grant struct {
	Target     TargetRef
	Issuer     IssuerRef
	Admits     eval.AdmittedSet
	Effect     Effect
	Provenance []evidence.Record
	Anomalies  []Anomaly
	Source     json.RawMessage // the customer's own bytes, for quoting back
}

// aud is the audience claim, which every provider constrains under its own
// name and which is not an authorisation boundary on its own.
const aud ClaimKey = "aud"

// Audience is the set of aud values the grant accepts, projected out of
// Admits: what the reporter prints when asked who the token must be for.
func (g Grant) Audience() eval.AdmittedSet {
	return project(g.Admits, func(k ClaimKey) bool { return k == aud })
}

// WithoutAudience is Admits with the aud claim unconstrained, which is the
// part of a grant that means the same thing in every cloud: audiences are
// provider-specific by nature, the identities admitted are not.
func (g Grant) WithoutAudience() eval.AdmittedSet {
	return project(g.Admits, func(k ClaimKey) bool { return k != aud })
}

// Exact reports whether Admits is the admitted set rather than an upper
// bound on it.
func (g Grant) Exact() bool { return g.Admits.Exact() }

// project keeps the claims keep accepts and carries every caveat over: a
// projection of an inexact set is still inexact, and a reporter handed
// "any audience" must not print it as a clean result.
func project(s eval.AdmittedSet, keep func(ClaimKey) bool) eval.AdmittedSet {
	terms := s.Terms()
	for _, term := range terms {
		for k := range term {
			if !keep(k) {
				delete(term, k)
			}
		}
	}
	out := eval.NewAdmittedSet(terms...)
	for _, c := range s.Caveats() {
		out = out.WithCaveat(c)
	}
	return out
}
