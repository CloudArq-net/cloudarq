package registry

import (
	"cmp"
	"slices"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/CloudArq-net/issuers"
	"github.com/CloudArq-net/issuers/tenancy"

	"github.com/CloudArq-net/cloudarq/internal/ring"
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
// The census keys this lookup by host, and a per-tenant entry is keyed by
// its placeholder host (<account>.app.spacelift.io), so a real tenant's
// host does not reach it: such an issuer answers "not surveyed" here
// although the census surveyed its vendor. Facts reads an issuer through
// the census's Match, which reads a tenant's URL; a consumer of Lookup must
// not print "not surveyed" as a fact about the vendor.
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
	key, ok := censusKey(ref)
	if !ok {
		return issuers.Issuer{}, false
	}
	e, ok := issuers.Get(key)
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

// censusKey is an issuer the way the census is asked about one: an https
// URL, its host in lower case, or false for an issuer the census cannot
// hold. Every census host is ASCII, so an issuer that holds any other
// character is none of them, and it is turned away here, whatever folding
// a reader of its host might apply: read as a k, a Kelvin sign would pass a
// look-alike host off as a surveyed one. On ASCII, lower-casing is ASCII
// folding, the only folding the census applies.
func censusKey(ref trust.IssuerRef) (string, bool) {
	for i := 0; i < len(ref); i++ {
		if ref[i] >= utf8.RuneSelf {
			return "", false
		}
	}
	normalised, ok := trust.NormaliseIssuer(string(ref))
	return string(normalised), ok
}

// Facts is what the census records about who can hold a token issuer mints,
// in the classifier's terms, and how the census names the issuer. It reads
// the census's tenancy sub-package through Match, which reads a tenant's
// host and path against every entry's pattern, so a per-tenant issuer's URL
// reaches its entry and names its tenant, and a URL that names no tenant,
// or a host alone, reaches none. Only that sub-package is read: the census
// whole is not linked into the WebAssembly engine.
//
// An issuer the census has not surveyed is the zero Facts and no names. A
// value the census does not settle reads the cautious way the classifier
// reads a zero: unverified. What the parser reads of the statement a grant
// came from is not the census's, and is left to the caller.
func Facts(issuer trust.IssuerRef) (ring.Facts, Names) {
	key, ok := censusKey(issuer)
	if !ok {
		return ring.Facts{}, Names{}
	}
	e, tenant, ok := tenancy.Match(key)
	if !ok {
		return ring.Facts{}, Names{}
	}
	return factsOf(e, tenant), Names{Entry: e.Name, Platform: e.Platform}
}

// Names is how the census names an issuer: its entry's name, and the
// platform the issuer's tenants hold their accounts on, where a vendor
// sentence names it, as GitHub for GitHub Actions and Bitbucket for
// Bitbucket Pipelines. The platform is empty where no sentence names it.
type Names struct {
	Entry    string
	Platform string
}

// factsOf is one census entry's facts, for the tenant a matching URL names.
func factsOf(e tenancy.Issuer, tenant string) ring.Facts {
	f := ring.Facts{AnonymousTokens: established(e.IssuesAnonymousTokens())}
	switch {
	case e.TenantPlaceholder != "":
		f.IssuerKind, f.Namespace = ring.PerTenant, ring.NamespaceIssuer
		f.Tenant = ring.Tenant{Value: tenant, Kind: tenantKind(e.TenantKind), Recyclable: established(e.TenantIsRecyclable()), Membership: membership(e.ControlledTenant(tenant))}
	default:
		f.IssuerKind, f.Namespace, f.Tenancy = ring.Shared, namespace(e.DeclarationNamespace), tenancyOf(e)
	}
	return f
}

// namespace is where a user declares a shared issuer's owners by name,
// given the prefix the census records for it: the same owner name under
// another issuer is another owner, so only the census says which issuer's
// owners a prefix holds. The engine reads a declaration's grammar only for
// the prefixes it knows, so one it has no grammar for declares nobody, and
// so do the prefixes it keeps for owners it reads without the census.
func namespace(prefix string) ring.Namespace {
	if ring.Namespace(prefix) == ring.NamespaceGitHub {
		return ring.NamespaceGitHub
	}
	return ""
}

// keyed holds the census entry the four condition-key lookups below read,
// for the issuer they were last asked about. A document asks them about its
// issuer for every condition key of every statement, and tenancy.Match walks
// every entry's pattern and hands back a copy of the entry it finds, so that
// a caller's edit never reaches the census the next caller reads. The
// lookups only read the entry and never hand it out, so while the issuer is
// the same they read the copy they hold. Facts hands parts of its entry to
// the classifier, and takes a copy of its own from Match.
var keyed struct {
	sync.Mutex
	asked  bool
	issuer trust.IssuerRef
	entry  tenancy.Issuer
	found  bool
}

// keyEntry is the census entry for issuer's condition keys, and false when
// the census cannot hold the issuer or nobody surveyed it.
func keyEntry(issuer trust.IssuerRef) (tenancy.Issuer, bool) {
	keyed.Lock()
	if !keyed.asked || keyed.issuer != issuer {
		keyed.asked, keyed.issuer, keyed.entry, keyed.found = true, issuer, tenancy.Issuer{}, false
		if k, ok := censusKey(issuer); ok {
			keyed.entry, _, keyed.found = tenancy.Match(k)
		}
	}
	e, found := keyed.entry, keyed.found
	keyed.Unlock()
	return e, found
}

// AWSDocumentsConditionKey reports whether AWS documents key, the part of a
// condition key after the provider and the colon, for the tokens of issuer,
// which is what puts the claim it names in the request context a trust
// policy's condition reads. Keys compare without ASCII case, as AWS reads
// them. known is false when the census does not record AWS's keys for the
// issuer or has not surveyed it, and the answer beside it is then false: a
// condition on a key not known to be documented is read as not read.
func AWSDocumentsConditionKey(issuer trust.IssuerRef, key string) (documented, known bool) {
	e, ok := keyEntry(issuer)
	if !ok {
		return false, false
	}
	return e.AWSMapsConditionKey(key)
}

// AWSDocumentsMultivalued reports whether AWS documents key, the part of a
// condition key after the provider and the colon, as multivalued for the
// tokens of issuer, as the census records it: "The key is multivalued,
// meaning that you test it in a policy using condition set operators." Keys
// compare without ASCII case. The census answers a key it holds no such
// sentence for as possibly multivalued and not known; only the documented
// answer is true here, so a key the census has no sentence for, one AWS
// does not document for the issuer, and every key of an issuer whose keys
// are not recorded are false.
func AWSDocumentsMultivalued(issuer trust.IssuerRef, key string) bool {
	e, ok := keyEntry(issuer)
	if !ok {
		return false
	}
	record, ok := e.AWSConditionKey(key)
	if !ok {
		return false
	}
	multivalued, known := record.IsMultivalued()
	return multivalued && known
}

// AWSReadsAMultiValuedClaim reports whether AWS reads key, the part of a
// condition key after the provider and the colon, from a claim the census
// records the issuer's tokens may carry with several values, on a sentence
// saying so: the claim AWS reads it from, or the one it reads instead when
// the token sets none. The Default tab's aud reads azp, or aud when the
// token sets no azp, and a Kubernetes service account token may carry
// several audiences. Keys compare without ASCII case and claims as written.
// A key AWS does not document for the issuer, and every key of an issuer
// whose keys are not recorded, is false, as is a claim the census holds no
// such sentence for: it answers that one as possibly several and not known.
func AWSReadsAMultiValuedClaim(issuer trust.IssuerRef, key string) bool {
	e, ok := keyEntry(issuer)
	if !ok {
		return false
	}
	record, ok := e.AWSConditionKey(key)
	if !ok {
		return false
	}
	for _, claim := range []string{record.Claim, record.FallbackClaim} {
		if multiValued, known := e.ClaimIsMultiValued(claim); claim != "" && multiValued && known {
			return true
		}
	}
	return false
}

// KeyClaim is where AWS reads a condition key of an issuer's tokens from.
type KeyClaim struct {
	// Claim is the claim AWS reads the key from, and Fallback the one it
	// reads instead when the token sets no value for Claim, empty when AWS
	// names none. They are not always the claim of the key's own name: on
	// AWS's Default tab oaud reads aud, and aud reads azp, or aud when the
	// token sets no azp. Both are written as AWS's table writes them, which
	// is not always a claim name, as Login with Amazon's "User ID". Claim is
	// empty where no vendor sentence says the issuer's tokens carry a claim
	// spelled as AWS's table spells it, and a reader then has no claim to
	// look the key up in.
	Claim, Fallback string
	// Table is AWS's table's spelling of what it reads the key from: Claim,
	// or where Claim is empty the spelling no claim is known to carry.
	Table string
}

// AWSConditionKeyClaim is where AWS reads the condition key key of issuer's
// tokens from. ok is false when AWS documents no such key for the issuer,
// or when the census does not record the issuer's keys.
func AWSConditionKeyClaim(issuer trust.IssuerRef, key string) (read KeyClaim, ok bool) {
	e, ok := keyEntry(issuer)
	if !ok {
		return KeyClaim{}, false
	}
	record, ok := e.AWSConditionKey(key)
	return KeyClaim{Claim: record.Claim, Fallback: record.FallbackClaim, Table: cmp.Or(record.Claim, record.TableClaim)}, ok
}

// established is a census answer and whether the census knows it.
func established(value, known bool) ring.Established {
	switch {
	case !known:
		return ring.Unverified
	case value:
		return ring.Yes
	}
	return ring.No
}

// membership is whether a tenant's owner controls who obtains its tokens:
// known and not controlled is a tenant the census lists as open to anyone.
func membership(controlled, known bool) ring.Membership {
	switch {
	case !known:
		return ring.MembershipUnverified
	case controlled:
		return ring.Controlled
	}
	return ring.OpenToAnyone
}

// tenantKind is a tenant's kind. A name is the reading that assumes least,
// since a name can pass to someone else.
func tenantKind(kind string) ring.Kind {
	if kind == "id" {
		return ring.KindID
	}
	return ring.KindName
}

// tenancyOf is how a shared issuer's tokens name a tenant, or nil when the
// census does not record it. The claims and the subject forms are one
// reading of the vendor's pages, and the census writes a half it did not
// verify as absent, which the classifier would read as naming no tenant:
// with either half absent the tenancy is not recorded, and a constraint
// that may name an owner is read as unread rather than as naming nobody.
//
// The classifier reads a condition on a key as a constraint on the claim
// of the key's name, so a claim is read as naming a tenant only while AWS
// reads its key from it alone, and the subject forms only while AWS reads
// sub from sub.
func tenancyOf(e tenancy.Issuer) *ring.Tenancy {
	if len(e.TenancyClaims) == 0 || len(e.SubjectForms) == 0 || !readsItsOwnClaim(e, "sub") {
		return nil
	}
	withoutCase, known := e.NamesCompareWithoutCase()
	t := &ring.Tenancy{
		NotTenancy:      claimKeys(e.NotTenancy),
		NeverPin:        e.NeverPin,
		OwnerCharacters: characters(e.OwnerNameCharacters),
		NamesIgnoreCase: withoutCase && known,
	}
	for _, c := range e.TenancyClaims {
		kind, known := partKind(c.Kind)
		claim := ring.TenancyClaim{Claim: trust.ClaimKey(c.Claim), Scope: scope(c.Scope), Kind: kind, Recyclable: established(c.ValueIsRecyclable())}
		if !known || !readsItsOwnClaim(e, c.Claim) {
			claim.Scope = ring.ScopeNone
		}
		t.Claims = append(t.Claims, claim)
	}
	for _, f := range e.SubjectForms {
		t.SubjectForms = append(t.SubjectForms, subjectForm(f))
	}
	return t
}

// readsItsOwnClaim reports whether a condition on the key named claim
// tests that claim and no other: AWS reads the key from it alone, or does
// not document the key, and the parser then reads a condition on it as not
// read, which constrains nothing.
func readsItsOwnClaim(e tenancy.Issuer, claim string) bool {
	record, documented := e.AWSConditionKey(claim)
	return !documented || record.Claim == claim && record.FallbackClaim == ""
}

// subjectForm is one form of sub: its leading literal, then the owner's
// parts, or the repository's in a form that names no owner. A form that
// names both is read by its owner, who holds the repository, which confines
// no less. A part of a kind the classifier does not know leaves the form
// naming nobody.
func subjectForm(f tenancy.SubjectForm) ring.SubjectForm {
	out := ring.SubjectForm{Lead: f.LeadingLiteral, Scope: ring.ScopeOwner}
	parts := f.OwnerParts
	if len(parts) == 0 {
		out.Scope, parts = ring.ScopeRepository, f.RepositoryParts
	}
	if len(parts) == 0 {
		out.Scope = ring.ScopeNone
	}
	for _, p := range parts {
		kind, known := partKind(p.Kind)
		if !known {
			out.Scope = ring.ScopeNone
		}
		out.Parts = append(out.Parts, ring.Part{Kind: kind, Delimiter: p.DelimiterAfter})
	}
	return out
}

// scope is the tenant a claim or a form names, in the census's words. A
// scope the classifier does not know names no tenant.
func scope(s string) ring.Scope {
	switch s {
	case "owner":
		return ring.ScopeOwner
	case "repository":
		return ring.ScopeRepository
	case "enterprise":
		return ring.ScopeEnterprise
	}
	return ring.ScopeNone
}

// partKind is whether a claim's or a part's value is a name or an id, and
// false for a kind the classifier does not know.
func partKind(s string) (ring.Kind, bool) {
	switch s {
	case "name":
		return ring.KindName, true
	case "id":
		return ring.KindID, true
	}
	return ring.KindName, false
}

// characters is an owner name's character set as ranges, read as the
// census reads it: a single character, or a range such as a-z whose ends
// are in order. An entry it cannot read leaves the whole set unread, and
// then any character may occur in a name, so no delimiter can be shown to
// end one and no subject pins.
func characters(set []string) []ring.CharRange {
	var out []ring.CharRange
	for _, c := range set {
		switch {
		case len(c) == 1:
			out = append(out, ring.CharRange{First: rune(c[0]), Last: rune(c[0])})
		case len(c) == 3 && c[1] == '-' && c[0] < c[2]:
			out = append(out, ring.CharRange{First: rune(c[0]), Last: rune(c[2])})
		default:
			return nil
		}
	}
	return out
}
