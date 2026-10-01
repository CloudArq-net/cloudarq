package ring

import (
	"strconv"
	"strings"
)

// Place is where one population of a grant lands: one of the five rings,
// ordered from the outermost, or one of the two lines beside them. The zero
// value is Anyone, so a place nobody computed can never read as a nearer one.
type Place int

const (
	// Anyone is anyone at all, people with no account anywhere included.
	Anyone Place = iota
	// Platform is anyone who can hold an account on the issuer's platform.
	Platform
	// Outsider is one named tenant the user has not declared as theirs.
	Outsider
	// Yours is a tenant the user declared as theirs.
	Yours
	// People is the sign-ins of a SAML provider the user declared as its
	// own.
	People
	// SAML is the sign-ins of a SAML provider nobody declared: who it signs
	// in is set in the provider's metadata, which a trust policy does not
	// carry. It sits beside the rings, never among them.
	SAML
	// Service is an AWS service a grant lets assume the role: who can make
	// it act, or receives its session, is not read, and some services hand
	// the session to identities outside IAM. It sits beside the rings, never
	// among them.
	Service
)

var placeNames = [...]string{"anyone", "platform", "outsider", "yours", "people", "saml", "service"}

// String is the place's id in the answer's vocabulary.
func (p Place) String() string { return name(placeNames[:], int(p), "place") }

// Ring reports whether the place is one of the five rings rather than a
// line beside them.
func (p Place) Ring() bool { return p >= Anyone && p <= People }

// State is how certain a place is: exact for the document as read and no
// more, since what can narrow a ring from outside the document (an
// organisation's policies, whether a provider exists) is listed apart. The
// zero value is StateUnknown, which never claims a certainty nobody showed.
type State int

const (
	// StateUnknown is a place that rests on a fact nobody verified, a
	// constraint the engine could not read, or a population the document
	// does not reveal.
	StateUnknown State = iota
	// StateExact is a place that follows from verified facts and from
	// constraints read exactly.
	StateExact
)

var stateNames = [...]string{"unknown", "exact"}

// String is the state's id in the answer's vocabulary.
func (s State) String() string { return name(stateNames[:], int(s), "state") }

// Basis is what decided a population's place, which is what its sentence
// says. The zero value is IssuerNotSurveyed, the basis of the outermost
// place.
type Basis int

const (
	// IssuerNotSurveyed: the census has not surveyed the issuer, so whether
	// its tokens need an account was not determined. Anyone, unknown.
	IssuerNotSurveyed Basis = iota
	// TokensWithoutAccount: the issuer mints tokens to people with no
	// account anywhere, as an identity pool's guests. Anyone, unknown.
	TokensWithoutAccount
	// AccountNotVerified: no vendor sentence establishes that the issuer's
	// tokens need an account. Anyone, unknown.
	AccountNotVerified
	// AnyIssuer: the grant names no issuer and admits every issuer's
	// tokens, as the face of "*" on a web-identity action does. Anyone,
	// unknown.
	AnyIssuer
	// PrincipalNotModelled: the parser cannot say what kind of identity the
	// grant's principal names, a CanonicalUser, an AWS ARN of another
	// service or a principal it could not read, so the issuer the grant is
	// filed under bounds nobody. Anyone, unknown.
	PrincipalNotModelled
	// Unpinned: nothing the grant constrains names a tenant, so any account
	// holder on the platform can present a credential it admits.
	Unpinned
	// UnreadConstraint: a constraint that could name a tenant could not be
	// read, so whether it does is not known. Platform, unknown.
	UnreadConstraint
	// TenancyNotRecorded: the census does not record how the issuer's tokens
	// name a tenant, so none is read from them. Platform, unknown.
	TenancyNotRecorded
	// OpenTenant: the issuer names a tenant anyone can join, as Microsoft's
	// personal-account tenant. Platform, exact.
	OpenTenant
	// MembershipNotVerified: the issuer names a tenant, and no vendor
	// sentence establishes that the tenant's owner decides who obtains its
	// tokens. Platform, unknown.
	MembershipNotVerified
	// Pinned: a constraint confines every credential admitted to named
	// owners. Outsider or yours.
	Pinned
	// ControlledTenant: the issuer itself names the tenant, whose owner
	// decides who obtains its tokens. Outsider or yours.
	ControlledTenant
	// SAMLProvider: one SAML provider signs the assertions. SAML sign-ins,
	// or your people once declared.
	SAMLProvider
	// AccountSAMLProviders: the face of "*" on sts:AssumeRoleWithSAML, which
	// AWS limits to the SAML providers in the role's own account. SAML
	// sign-ins.
	AccountSAMLProviders
	// ServicePrincipal: one AWS service is the principal. Cloud services.
	ServicePrincipal
	// AnyService: the face of "*" on sts:AssumeRole alone, which admits
	// every AWS service. Cloud services.
	AnyService
	// ServiceIntermediary: one AWS service the parser's table of
	// intermediaries lists is the principal, and AWS documents it as
	// assuming a role for identities outside IAM, as IAM Roles Anywhere does
	// for whoever holds a certificate its trust anchor accepts. Who they are
	// is set in the service's own resources, which no trust policy carries,
	// so the place is never exact. Cloud services.
	ServiceIntermediary
)

var basisNames = [...]string{
	"issuer-not-surveyed", "tokens-without-account", "account-not-verified", "any-issuer",
	"principal-not-modelled", "unpinned", "unread-constraint", "tenancy-not-recorded", "open-tenant",
	"membership-not-verified", "pinned", "controlled-tenant",
	"saml-provider", "account-saml-providers", "service-principal", "any-service", "service-intermediary",
}

// String is the basis's id in the answer's vocabulary.
func (b Basis) String() string { return name(basisNames[:], int(b), "basis") }

// Outcome says whether a grant is placed at all.
type Outcome int

const (
	// Placed: the grant lets someone in, and Places says where they are.
	Placed Outcome = iota
	// Refused: the grant is a Deny. A refusal is in no ring and never
	// subtracted from an Allow's, because what it takes away is not a set
	// the lattice can take away.
	Refused
	// Nobody: the grant admits no token, provably.
	Nobody
)

var outcomeNames = [...]string{"placed", "refused", "nobody"}

// String is the outcome's id in the answer's vocabulary.
func (o Outcome) String() string { return name(outcomeNames[:], int(o), "outcome") }

// Population is where one alternative of a grant's admitted set lands. One
// alternative is one population, except the face of "*" that admits both
// the account's SAML providers and every AWS service, which is two.
type Population struct {
	// Term is the alternative's index in the admitted set's Terms.
	Term   int
	Place  Place
	State  State
	Basis  Basis
	Owners []Owner
}

// Placement is where a grant lands.
type Placement struct {
	Outcome Outcome
	// Places is where a placed grant lands: the outermost ring its
	// populations reach, and the line beside the rings of each population
	// that is on one. In the rings' order, then SAML before services.
	Places []Place
	// State is exact when every place named is reached by a population
	// whose own place is exact.
	State State
	// Owners are the owners the populations at those places name, sorted.
	Owners []Owner
	// Populations is every alternative's own place, in term order.
	Populations []Population
}

// String renders a placement in one line whose bytes depend on the
// placement alone, for goldens and for the determinism gate.
func (p Placement) String() string {
	if p.Outcome != Placed {
		return p.Outcome.String()
	}
	places := make([]string, len(p.Places))
	for i, place := range p.Places {
		places[i] = place.String()
	}
	return strings.Join(places, "+") + " " + p.State.String() + renderOwners(p.Owners)
}

// String renders one population the way Placement renders a grant.
func (p Population) String() string {
	return strconv.Itoa(p.Term) + ": " + p.Place.String() + " " + p.State.String() + " " + p.Basis.String() + renderOwners(p.Owners)
}

func renderOwners(owners []Owner) string {
	if len(owners) == 0 {
		return ""
	}
	parts := make([]string, len(owners))
	for i, o := range owners {
		parts[i] = o.String()
	}
	return " [" + strings.Join(parts, "; ") + "]"
}

// name is an enumeration value's id, or the kind of value and its number
// when the value is none this package defines: a value no table holds is a
// defect, and printing it as a real one would hide it.
func name(names []string, i int, kind string) string {
	if i >= 0 && i < len(names) {
		return names[i]
	}
	return kind + "(" + strconv.Itoa(i) + ")"
}
