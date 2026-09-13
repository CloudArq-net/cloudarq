package registry

import (
	"slices"
	"strings"

	"github.com/CloudArq-net/issuers"

	"github.com/CloudArq-net/cloudarq/internal/trust"
)

// Entry is what the engine knows about an issuer: the census fields that
// change how a policy is read, in the engine's own types.
type Entry struct {
	// Issuer is the normalised exact issuer, or empty when the census
	// records a per-tenant pattern: a placeholder is not an issuer.
	Issuer trust.IssuerRef
	Host   string
	Name   string
	Vendor string
	// TenancyModel is one of shared, per_tenant_host, per_tenant_path or
	// unverified, in the census's words.
	TenancyModel string
	// Claims is the token's documented vocabulary and ImmutableIDClaims the
	// identifiers the census records as never reused (not always inside
	// Claims: five entries list identifiers their vocabulary omits). Each is
	// nil when nobody surveyed it and empty when the survey found none; the
	// census keeps the two apart and so does the engine.
	Claims            []trust.ClaimKey
	ImmutableIDClaims []trust.ClaimKey
	// AudControlledBy is one of relying_party, issuer, workload or
	// unverified: who picks the audience, and therefore whether aud is a
	// boundary at all.
	AudControlledBy string
}

// Lookup finds the census entry for an issuer given as an IssuerRef, a URL
// or a bare host, normalised the way the engine normalises issuers first.
// The second return is false when nobody surveyed that host, which never
// means it is safe.
//
// The census keys by host, and a per-tenant entry is keyed by its
// placeholder host (<account>.app.spacelift.io), so a real tenant's host
// does not reach it: such an issuer answers "not surveyed" here although
// the census surveyed its vendor. Matching a host against a pattern is the
// module's to add; until it does, a consumer must not print "not surveyed"
// as a fact about the vendor.
func Lookup(ref trust.IssuerRef) (Entry, bool) {
	e, ok := census(ref)
	if !ok {
		return Entry{}, false
	}
	return entryOf(e), true
}

// AudienceIsBoundary reports whether conditioning on aud constrains anything
// for the issuer. known is false when the census has not confirmed it or
// has not surveyed the issuer; a caller must not read that as a boundary.
func AudienceIsBoundary(ref trust.IssuerRef) (isBoundary, known bool) {
	e, ok := census(ref)
	if !ok {
		return false, false
	}
	return e.AudienceIsBoundary()
}

// SubjectsAreRecyclable reports whether every subject written against the
// issuer is a name that can be released and registered by someone else,
// because the census records no immutable identifier for it. known is
// false when the issuer is unsurveyed or its identifiers were never
// surveyed (the census leaves the field absent, which is not the same as
// empty); the answer beside a false known is the cautious one, recyclable.
func SubjectsAreRecyclable(ref trust.IssuerRef) (recyclable, known bool) {
	e, ok := census(ref)
	if !ok || e.ImmutableIDClaims == nil {
		return true, false
	}
	return e.SubjectsAreRecyclable(), true
}

// KnownIssuers is every exact issuer in the census, normalised, sorted and
// unique. Entries whose issuer is a per-tenant placeholder are left out: a
// caller seeding a claim vocabulary needs issuers a token can carry.
func KnownIssuers() []trust.IssuerRef {
	var out []trust.IssuerRef
	for _, e := range issuers.All() {
		if ref, ok := exactIssuer(e); ok {
			out = append(out, ref)
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// MultiTenantHosts is every host shared between the tenants of one vendor,
// sorted, so that conditioning on the issuer alone never identifies a
// tenant on them.
func MultiTenantHosts() []string {
	hosts := issuers.MultiTenantHosts()
	slices.Sort(hosts)
	return slices.Compact(hosts)
}

// CensusDate is the date of the embedded snapshot, YYYY-MM-DD.
func CensusDate() string { return issuers.CensusDate() }

// census is the module's entry for a ref, after the engine's normalisation,
// and only when the entry describes an issuer: the census also carries
// notes in the issuer field ("unverified", "not an OIDC issuer") that the
// module keys like hosts, and a note is not a surveyed host.
func census(ref trust.IssuerRef) (issuers.Issuer, bool) {
	normalised, ok := trust.NormaliseIssuer(string(ref))
	if !ok {
		return issuers.Issuer{}, false
	}
	e, ok := issuers.Get(string(normalised))
	if !ok || !(strings.HasPrefix(e.Issuer, "https://") || strings.HasPrefix(e.IssuerPattern, "https://")) {
		return issuers.Issuer{}, false
	}
	return e, true
}

// exactIssuer is the census issuer as an IssuerRef, when the entry records
// one a token can carry: an https URL with no placeholder in it.
func exactIssuer(e issuers.Issuer) (trust.IssuerRef, bool) {
	if !strings.HasPrefix(e.Issuer, "https://") || strings.ContainsAny(e.Issuer, "<> ") {
		return "", false
	}
	return trust.NormaliseIssuer(e.Issuer)
}

func entryOf(e issuers.Issuer) Entry {
	ref, _ := exactIssuer(e)
	return Entry{
		Issuer:            ref,
		Host:              e.Host(),
		Name:              e.Name,
		Vendor:            e.Vendor,
		TenancyModel:      e.TenancyModel,
		Claims:            claimKeys(e.Claims),
		ImmutableIDClaims: claimKeys(e.ImmutableIDClaims),
		AudControlledBy:   e.AudControlledBy,
	}
}

// claimKeys copies the census's claim names into the engine's type, nil
// for nil: the copy is what lets a caller sort or edit what it was handed
// without changing the next answer, and nil is what says "not surveyed".
func claimKeys(names []string) []trust.ClaimKey {
	if names == nil {
		return nil
	}
	out := make([]trust.ClaimKey, 0, len(names))
	for _, n := range names {
		out = append(out, trust.ClaimKey(n))
	}
	return out
}
