package ring

import (
	"github.com/CloudArq-net/cloudarq/internal/parse/aws"
	"github.com/CloudArq-net/cloudarq/internal/trust"
)

// Facts is what is known about who can hold a credential that a grant's
// issuer vouches for: the census's entry for an OIDC issuer, in the engine's
// types, and what the parser read of the statement the grant came from,
// whether it modelled the grant's principal and, for a grant that names no
// issuer, who the statement admits. The zero value knows nothing, and every
// grant it places lands anyone. The AWS pseudo-issuers, a SAML provider, a
// service and the AWS principals, need nothing from the census: they are
// read from the grant itself, by the parser's own predicates.
type Facts struct {
	// IssuerKind is how the issuer names a tenant.
	IssuerKind IssuerKind
	// Namespace is where a user declares this issuer's owners, empty
	// when they cannot be declared: the same owner name on another host is
	// another owner, so a declaration matches only the issuers the census
	// puts in its namespace.
	Namespace Namespace
	// AnonymousTokens is whether the issuer mints tokens to people with no
	// account anywhere. Unverified reads as yes.
	AnonymousTokens Established
	// Tenancy is how a shared issuer's tokens name an owner. Nil when the
	// census records none, and then no owner is read from its tokens.
	Tenancy *Tenancy
	// Tenant is what a per-tenant issuer's URL names.
	Tenant Tenant
	// Issuerless is who a grant with no issuer admits, as the parser reads
	// the statement it came from. The zero value is every issuer.
	Issuerless aws.Population
	// PrincipalModelled is whether the parser can say what kind of identity
	// the grant's principal names. It cannot for a CanonicalUser or an AWS
	// ARN of another service, which it files under the AWS issuer all the
	// same, or for a principal it could not read. The zero value is that it
	// cannot, and the grant is then anyone's.
	PrincipalModelled bool
}

// IssuerKind is how an issuer names a tenant. The zero value is
// NotSurveyed.
type IssuerKind int

const (
	// NotSurveyed: the census has no entry for the issuer.
	NotSurveyed IssuerKind = iota
	// Shared: one issuer for every tenant, which its tokens' claims name.
	Shared
	// PerTenant: the issuer URL itself names the tenant.
	PerTenant
)

// Established is whether a vendor sentence establishes a census fact, and
// which way. The zero value is Unverified, and every reader takes it the
// cautious way.
type Established int

const (
	// Unverified: no vendor sentence settles the fact either way.
	Unverified Established = iota
	// Yes: a vendor sentence establishes the fact.
	Yes
	// No: a vendor sentence establishes that the fact does not hold.
	No
)

// Tenancy is how a shared issuer's tokens name an owner. The census records
// the claims, the subject forms and the literals that never pin in one
// reading of the vendor's pages, so they are present or absent together;
// the character set and the case rule are facts of their own.
type Tenancy struct {
	// Claims are the claims whose single value names a tenant. A claim not
	// listed names none.
	Claims []TenancyClaim
	// NotTenancy are claims that look as if they name a tenant and do not.
	// A name ending in * stands for every claim that begins with the text
	// before it. A claim listed here never pins, whatever Claims says of it.
	NotTenancy []trust.ClaimKey
	// SubjectForms are the forms of sub that lead with a tenant. A subject
	// led by anything else names none.
	SubjectForms []SubjectForm
	// NeverPin are leading literals whose subjects name no tenant of the
	// token's own, as GitHub's job_workflow_ref, which names the called
	// workflow rather than the caller.
	NeverPin []string
	// OwnerCharacters are the characters an owner's name may hold. Empty
	// when no vendor sentence states them, and then no delimiter can be
	// shown to end an owner, so no subject pins.
	OwnerCharacters []CharRange
	// NamesIgnoreCase is true only when a vendor sentence says owners'
	// names are unique regardless of case; otherwise names compare exactly,
	// which can only leave a declared owner unmatched.
	NamesIgnoreCase bool
}

// TenancyClaim is one claim whose single value names a tenant.
type TenancyClaim struct {
	Claim trust.ClaimKey
	// Scope is the tenant the value names. A claim with no scope names none.
	Scope Scope
	// Kind is whether the value is a name or an id, which is how an owner
	// is declared.
	Kind Kind
	// Recyclable is whether a value can be released and pass to someone
	// else, whose tokens a pin on it would then admit. Unverified reads as
	// yes, whatever the kind: an id no sentence calls immutable may be
	// reused for all anyone has read.
	Recyclable Established
}

// SubjectForm is one way an issuer spells sub with a tenant at its head: a
// leading literal, then the tenant's parts in order, each ended by its
// delimiter.
type SubjectForm struct {
	Lead  string
	Scope Scope
	Parts []Part
}

// Part is one part of a subject form's tenant: a name or an id, and the
// delimiter after it, one character. A delimiter the owner characters allow
// cannot end the part, and a form that holds one pins nothing.
type Part struct {
	Kind      Kind
	Delimiter string
}

// CharRange is the characters from First to Last, both included.
type CharRange struct {
	First, Last rune
}

// Tenant is what a per-tenant issuer's URL names, as the census matched it
// against the issuer's pattern.
type Tenant struct {
	// Value is the tenant the URL spells, empty when it spells none.
	Value string
	Kind  Kind
	// Recyclable is whether the tenant's name can pass to another customer,
	// which would put that customer behind the same issuer URL. Unverified
	// reads as yes.
	Recyclable Established
	Membership Membership
}

// Membership is whether a per-tenant issuer's tenant is closed to strangers.
// The zero value is MembershipUnverified.
type Membership int

const (
	// MembershipUnverified: no vendor sentence says the tenant's owner
	// decides who obtains its tokens.
	MembershipUnverified Membership = iota
	// Controlled: the tenant's owner decides who obtains its tokens.
	Controlled
	// OpenToAnyone: the census lists this tenant as one anyone can join.
	OpenToAnyone
)
