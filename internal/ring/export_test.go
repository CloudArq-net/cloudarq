package ring

import (
	"slices"

	"github.com/CloudArq-net/cloudarq/internal/trust"
)

// The stand-in for the census, as this package's external tests read it.
// internal/registry reads the census and imports this package, so only an
// external test can hold the stand-in to it.
var (
	CensusFacts  = censusFacts
	GitHubIssuer = githubIssuer
	AWSKeys      = awsKeys
	StandInKeys  = standInKeys
	// StandInMultivalued is whether the stand-in reads a key as one AWS
	// documents as multivalued.
	StandInMultivalued = standInMultivalued
	// StandInMultiValuedClaim is whether the stand-in reads a key from a
	// claim the issuer's tokens may carry with several values.
	StandInMultiValuedClaim = standInMultiValuedClaim
)

// StandInIssuers are the issuers the stand-in lists, in its order.
func StandInIssuers() []trust.IssuerRef {
	var out []trust.IssuerRef
	for _, e := range standIn {
		out = append(out, e.issuer)
	}
	return out
}

// CorpusIssuers are the issuers the corpus expects a grant of, once each,
// in the order the corpus first names them.
func CorpusIssuers() []trust.IssuerRef {
	var out []trust.IssuerRef
	for _, c := range corpus {
		for _, g := range c.grants {
			if !slices.Contains(out, g.issuer) {
				out = append(out, g.issuer)
			}
		}
	}
	return out
}
