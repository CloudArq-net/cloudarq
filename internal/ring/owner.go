package ring

import (
	"strconv"
	"strings"

	"github.com/CloudArq-net/cloudarq/internal/trust"
)

// Namespace is where a user declares an owner as theirs: the prefix of
// a declaration, github:acme or aws:111122223333.
type Namespace string

const (
	// NamespaceGitHub holds github.com's owners, by name, by id, or both.
	NamespaceGitHub Namespace = "github"
	// NamespaceAWS holds AWS accounts and organisations, by id.
	NamespaceAWS Namespace = "aws"
	// NamespaceSAML holds SAML providers, by ARN.
	NamespaceSAML Namespace = "saml"
	// NamespaceIssuer holds the tenants of per-tenant issuers, by issuer
	// URL.
	NamespaceIssuer Namespace = "issuer"
)

// Scope is what kind of tenant an owner is. The zero value, ScopeNone, is
// not a tenant at all: a fact that names no scope pins nothing.
type Scope int

const (
	// ScopeNone: the value names no tenant.
	ScopeNone Scope = iota
	// ScopeOwner is the account or organisation a repository belongs to.
	ScopeOwner
	// ScopeRepository is one repository, whatever owner holds it.
	ScopeRepository
	// ScopeEnterprise is an enterprise and every owner in it.
	ScopeEnterprise
	// ScopeAccount is one AWS account.
	ScopeAccount
	// ScopeOrganisation is one organisation in AWS Organizations.
	ScopeOrganisation
	// ScopeTenant is the tenant a per-tenant issuer's URL names.
	ScopeTenant
	// ScopeProvider is one SAML provider.
	ScopeProvider
)

var scopeNames = [...]string{"none", "owner", "repository", "enterprise", "account", "organisation", "tenant", "provider"}

// String is the scope's id in the answer's vocabulary.
func (s Scope) String() string { return name(scopeNames[:], int(s), "scope") }

// Kind is whether an owner is named by a name or by an id. A name can be
// released and registered by someone else; an id is never reused. The zero
// value is KindName, the cautious one.
type Kind int

const (
	// KindName: the value is the owner's name.
	KindName Kind = iota
	// KindID: the value is an id the platform assigned the owner.
	KindID
)

var kindNames = [...]string{"name", "id"}

// String is the kind's id in the answer's vocabulary.
func (k Kind) String() string { return name(kindNames[:], int(k), "kind") }

// Owner is one tenant a population is confined to, typed by the issuer it
// was pinned under, its scope and its kind: the same number read as a
// repository id and as an owner id names two different things.
type Owner struct {
	// Issuer is the issuer the owner was pinned under.
	Issuer trust.IssuerRef
	// Namespace is where the owner can be declared, empty when it cannot.
	Namespace Namespace
	Scope     Scope
	Kind      Kind
	// Value is the name or the id that pins, the provider's ARN, or the
	// tenant a per-tenant issuer's URL names.
	Value string
	// Name is the owner's name beside an id, when the subject that pinned
	// the id spelled the name before it, as acme in acme@123456.
	Name string
	// Recyclable is whether whoever holds Value can change: a name pin can
	// be taken over by whoever registers the name next, and so can a pin on
	// an id no vendor sentence calls immutable.
	Recyclable bool
	// Declared is whether the user declared the owner as theirs.
	Declared bool
}

// Declaration is what a user writes to declare this owner as theirs,
// and what --owner takes: github:acme, github:acme@123456,
// github:@123456, aws:111122223333, saml:<provider ARN>, issuer:<URL>. It is
// empty for an owner the declaration grammar has no form for: a
// repository, an enterprise, or an owner outside every namespace.
func (o Owner) Declaration() string {
	switch {
	case o.Namespace == NamespaceGitHub && o.Scope == ScopeOwner && o.Kind == KindName:
		return "github:" + o.Value
	case o.Namespace == NamespaceGitHub && o.Scope == ScopeOwner && o.Kind == KindID:
		return "github:" + o.Name + "@" + o.Value
	case o.Namespace == NamespaceAWS && (o.Scope == ScopeAccount || o.Scope == ScopeOrganisation):
		return "aws:" + o.Value
	case o.Namespace == NamespaceSAML && o.Scope == ScopeProvider:
		return "saml:" + o.Value
	case o.Namespace == NamespaceIssuer && o.Scope == ScopeTenant:
		return "issuer:" + string(o.Issuer)
	}
	return ""
}

// String renders every field of the owner, its value quoted, so that two
// different owners never render alike.
func (o Owner) String() string {
	var b strings.Builder
	b.WriteString(o.Scope.String() + " " + o.Kind.String() + " " + strconv.QuoteToASCII(o.Value))
	if o.Name != "" {
		b.WriteString(" named " + strconv.QuoteToASCII(o.Name))
	}
	b.WriteString(" on " + strconv.QuoteToASCII(string(o.Issuer)))
	if o.Namespace != "" {
		b.WriteString(" in " + string(o.Namespace))
	}
	if o.Recyclable {
		b.WriteString(" recyclable")
	}
	if o.Declared {
		b.WriteString(" declared")
	}
	return b.String()
}
