package ring

import (
	"cmp"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/CloudArq-net/cloudarq/internal/eval"
	"github.com/CloudArq-net/cloudarq/internal/parse/aws"
	"github.com/CloudArq-net/cloudarq/internal/trust"
)

// subject is the claim an OIDC token names its subject by, the one the
// census's subject forms describe.
const subject trust.ClaimKey = "sub"

// Classify places one grant, given the facts for its issuer and its
// statement and the owners the user declared. A Deny is a refusal and
// an Allow that provably admits no token is nobody; an effect the parser
// could not read is placed as an Allow, since reading it as a Deny would
// report the role narrower than it is, and never exactly, since it may be a
// Deny that admits nobody. Every other grant has each alternative of its
// admitted set placed on its own, and lands at the outermost of them.
func Classify(g trust.Grant, facts Facts, declared []Declaration) Placement {
	switch {
	case g.Effect == trust.Deny:
		return Placement{Outcome: Refused}
	case g.Admits.IsEmpty():
		return Placement{Outcome: Nobody}
	}
	c := classifier{grant: g, facts: facts, declared: declared}
	var populations []Population
	for i, term := range g.Admits.Terms() {
		for _, pop := range c.place(term) {
			pop.Term = i
			if g.Effect == trust.EffectUnknown {
				pop.State = StateUnknown
			}
			populations = append(populations, pop)
		}
	}
	return outermost(populations)
}

// classifier is one grant being placed.
type classifier struct {
	grant    trust.Grant
	facts    Facts
	declared []Declaration
}

// place is where one alternative of the admitted set lands. A principal the
// parser did not model is anyone's, whatever issuer its grant is filed
// under. The AWS parser's pseudo-issuers are recognised by its own
// predicates: a grant with no issuer stands for whoever its statement
// admits, a SAML provider's sign-ins and a service's callers are read from
// no trust policy, and an AWS principal's tenancy facts are the parser's.
// Every other issuer is an OIDC issuer the census may know.
func (c classifier) place(term eval.Term) []Population {
	issuer := c.grant.Issuer
	switch {
	case !c.facts.PrincipalModelled:
		return []Population{{Place: Anyone, Basis: PrincipalNotModelled}}
	case issuer == "":
		return issuerless(c.facts.Issuerless)
	case aws.IsSAMLIssuer(issuer):
		return []Population{c.samlProvider()}
	case strings.HasPrefix(string(issuer), aws.ServiceIssuerPrefix):
		return []Population{service(issuer)}
	case issuer == aws.AWSPrincipalIssuer:
		return []Population{c.awsPrincipal(term)}
	}
	return []Population{c.oidc(term)}
}

// service places a service's callers beside the rings, and never exactly:
// who can make a service act, or receives its session, is not in a trust
// policy. A service the parser's table of intermediaries lists, each of
// which AWS documents as assuming a role for identities outside IAM, is
// placed as that. A condition naming the account or the trust anchor it
// acts for would not change the state: it names nobody who receives the
// session, as a certificate holder does from IAM Roles Anywhere.
func service(issuer trust.IssuerRef) Population {
	pop := Population{Place: Service, Basis: ServicePrincipal}
	if _, ok := aws.IntermediaryOf(strings.TrimPrefix(string(issuer), aws.ServiceIssuerPrefix)); ok {
		pop.Basis = ServiceIntermediary
	}
	return pop
}

// issuerless places a grant that names no issuer by who its statement
// admits. Every AWS service assumes through sts:AssumeRole and every SAML
// provider of the role's own account through sts:AssumeRoleWithSAML; any
// other population, a value this package does not know among them, is every
// issuer's tokens, and an identity pool mints those to people with no
// account.
func issuerless(p aws.Population) []Population {
	switch p {
	case aws.AWSServices:
		return []Population{{Place: Service, Basis: AnyService}}
	case aws.AccountSAMLProviders:
		return []Population{{Place: SAML, Basis: AccountSAMLProviders}}
	case aws.AWSServicesAndAccountSAMLProviders:
		return []Population{{Place: SAML, Basis: AccountSAMLProviders}, {Place: Service, Basis: AnyService}}
	}
	return []Population{{Place: Anyone, Basis: AnyIssuer}}
}

// samlProvider places a SAML provider's sign-ins beside the rings, and in
// the user's people once the user declares the provider. Who the
// provider signs in is set in its metadata, which no trust policy carries,
// so the place is never exact.
func (c classifier) samlProvider() Population {
	owner := Owner{Issuer: c.grant.Issuer, Namespace: NamespaceSAML, Scope: ScopeProvider, Kind: KindName, Value: string(c.grant.Issuer), Recyclable: true}
	pop := Population{Place: SAML, Basis: SAMLProvider}
	if c.covered(owner) {
		owner.Declared = true
		pop.Place = People
	}
	pop.Owners = []Owner{owner}
	return pop
}

// oidc places an OIDC issuer's alternative, outermost first: anyone when
// the census has not surveyed the issuer or does not show that its tokens
// need an account; then the tenant a per-tenant issuer's URL names; then
// the owners a shared issuer's claims pin.
func (c classifier) oidc(term eval.Term) Population {
	switch {
	case c.facts.IssuerKind != Shared && c.facts.IssuerKind != PerTenant:
		return Population{Place: Anyone, Basis: IssuerNotSurveyed}
	case c.facts.AnonymousTokens == Yes:
		return Population{Place: Anyone, Basis: TokensWithoutAccount}
	case c.facts.AnonymousTokens != No:
		return Population{Place: Anyone, Basis: AccountNotVerified}
	case c.facts.IssuerKind == PerTenant:
		return c.tenant()
	}
	return c.shared(term)
}

// tenant places a per-tenant issuer's grant: a named outsider when the
// tenant's owner controls who obtains its tokens, the platform when anyone
// can join the tenant, and the platform, unknown, when neither is shown or
// the URL names no tenant. A tenant is recyclable unless a vendor sentence
// says its name never passes on.
func (c classifier) tenant() Population {
	t := c.facts.Tenant
	switch {
	case t.Membership == OpenToAnyone:
		return Population{Place: Platform, State: StateExact, Basis: OpenTenant}
	case t.Membership != Controlled || t.Value == "":
		return Population{Place: Platform, Basis: MembershipNotVerified}
	}
	owner := Owner{Issuer: c.grant.Issuer, Namespace: NamespaceIssuer, Scope: ScopeTenant, Kind: t.Kind, Value: t.Value, Recyclable: t.Recyclable != No}
	return c.pinned([][]Owner{{owner}}, ControlledTenant)
}

// shared places a shared issuer's alternative by the owners its claims pin:
// the claims the census records as naming a tenant, through exact values,
// and the subject, through the forms the census records.
func (c classifier) shared(term eval.Term) Population {
	t := c.facts.Tenancy
	if t == nil {
		return Population{Place: Platform, Basis: TenancyNotRecorded}
	}
	var r reading
	for _, claim := range t.Claims {
		if claim.Scope == ScopeNone || t.namesNoTenant(claim.Claim) {
			continue
		}
		r.add(c.confine(term, claim.Claim, c.claimOwner(t, claim), patternOn(claim)))
	}
	r.add(c.subject(term, t))
	return c.decide(r)
}

// awsPrincipal places an AWS principal's alternative by the tenancy facts
// the parser keeps for its pseudo-issuer: an account or an organisation an
// exact value names, or an ARN whose prefix runs through the account;
// otherwise anyone with an AWS account.
func (c classifier) awsPrincipal(term eval.Term) Population {
	var r reading
	for _, claim := range aws.TenancyClaims() {
		value := func(v string) []Owner { return c.awsOwner(aws.TenantOfValue(claim, v)) }
		prefix := func(p string) []Owner { return c.awsOwner(aws.TenantOfPrefix(claim, p)) }
		r.add(c.confine(term, claim, value, prefix))
	}
	return c.decide(r)
}

func (c classifier) awsOwner(t aws.Tenant, ok bool) []Owner {
	scope, known := awsScope(t)
	if !ok || !known {
		return nil
	}
	return []Owner{{Issuer: c.grant.Issuer, Namespace: NamespaceAWS, Scope: scope, Kind: KindID, Value: t.ID}}
}

// awsScopes are the parser's tenant scopes in this package's words. A scope
// the parser adds later names no owner here until this map names it.
var awsScopes = map[aws.TenantScope]Scope{aws.AccountScope: ScopeAccount, aws.OrganisationScope: ScopeOrganisation}

func awsScope(t aws.Tenant) (Scope, bool) {
	scope, known := awsScopes[t.Scope]
	return scope, known
}

// reading is what the constraints of one alternative say about who can
// satisfy them all: the pins, each confining every credential admitted to
// its owners, and whether a constraint that could pin went unread, with the
// basis of the doubt.
type reading struct {
	pins   [][]Owner
	unread bool
	doubt  Basis
}

// add takes one constraint's confinement. Of two doubts, a fact missing
// from the census outranks a constraint the parser could not read, so the
// basis does not depend on the order the claims were read in.
func (r *reading) add(c confinement) {
	switch {
	case c.owners != nil:
		r.pins = append(r.pins, c.owners)
	case c.unread && (!r.unread || c.doubt == TenancyNotRecorded):
		r.unread, r.doubt = true, c.doubt
	}
}

// decide places an alternative by what its constraints said. Any pin
// confines it, because an alternative is a conjunction. With none, it is
// the platform, exact only when every constraint that could have pinned was
// read and found not to. A condition on a key of AWS's request context is
// one that could have: some of those keys name the account or organisation
// a request comes from (aws:PrincipalOrgPaths, aws:SourceAccount), some are
// absent from whole kinds of request, and a condition on an absent key is
// false. The parser reads none of them beyond the tenancy claims.
func (c classifier) decide(r reading) Population {
	switch {
	case len(r.pins) > 0:
		return c.pinned(r.pins, Pinned)
	case r.unread:
		return Population{Place: Platform, Basis: r.doubt}
	case c.requestUnread():
		return Population{Place: Platform, Basis: UnreadConstraint}
	}
	return Population{Place: Platform, State: StateExact, Basis: Unpinned}
}

// requestUnread reports whether the grant is an upper bound because a
// condition on a key an AWS service fills was not read.
func (c classifier) requestUnread() bool {
	return slices.ContainsFunc(c.grant.Admits.Caveats(), func(cv eval.Caveat) bool {
		return aws.IsServiceKey(cv.Claim)
	})
}

// pinned places an alternative confined by pins: yours when every owner of
// some pin is declared, since that pin alone holds every credential
// admitted, and a named outsider otherwise. Declaring moves nothing else.
func (c classifier) pinned(pins [][]Owner, basis Basis) Population {
	pop := Population{Place: Outsider, State: StateExact, Basis: basis}
	for _, pin := range pins {
		all := true
		for i := range pin {
			pin[i].Declared = c.covered(pin[i])
			all = all && pin[i].Declared
		}
		if all {
			pop.Place = Yours
		}
		pop.Owners = append(pop.Owners, pin...)
	}
	pop.Owners = distinct(pop.Owners)
	return pop
}

// confinement is what one constraint says about who can satisfy it: the
// owners every value it admits belongs to, nil when it names none, and
// whether that is because it could not be read, with the basis of the doubt.
type confinement struct {
	owners []Owner
	unread bool
	doubt  Basis
}

// confine reads claim's constraint in term. value names the owners one
// exact value confines to, and prefix the owners every value beginning with
// a pattern's literal prefix does, or is nil where a pattern on the claim
// cannot be read for an owner. An absent claim is unconstrained, which
// pins nothing. What was read and pins nothing is unread all the same when
// the grant carries a caveat that may be on the claim: an Unknown met with
// another constraint vanishes from the term (Meet's identity), so a claim
// present with an open pattern may also have had a constraint that pinned,
// and nobody read it.
func (c classifier) confine(term eval.Term, claim trust.ClaimKey, value, prefix func(string) []Owner) confinement {
	var read confinement
	if set, present := term[claim]; present {
		read = confineShape(eval.ShapeOf(set), value, prefix)
	}
	if read.owners == nil && !read.unread && c.widenedOn(claim) {
		return confinement{unread: true, doubt: UnreadConstraint}
	}
	return read
}

// confineShape reads one constraint by its shape. A union confines only
// when every alternative does, to all their owners; an intersection when
// any of its patterns does, since the others only narrow, and is unread
// when none does and one could not be read. Unknown pins nothing and says
// so, and so does a pattern with no prefix reader; Any and None, which no
// term holds, name no owner.
func confineShape(s eval.Shape, value, prefix func(string) []Owner) confinement {
	switch s.Kind {
	case eval.ShapeExact:
		return confinement{owners: value(s.Text)}
	case eval.ShapeGlob:
		if prefix == nil {
			return confinement{unread: true, doubt: UnreadConstraint}
		}
		return confinement{owners: prefix(eval.LiteralPrefix(s.Text))}
	case eval.ShapeUnion:
		var owners []Owner
		for _, m := range s.Members {
			member := confineShape(m, value, prefix)
			if member.owners == nil {
				return member
			}
			owners = append(owners, member.owners...)
		}
		return confinement{owners: owners}
	case eval.ShapeIntersection:
		var owners []Owner
		var unread confinement
		for _, m := range s.Members {
			member := confineShape(m, value, prefix)
			owners = append(owners, member.owners...)
			if member.unread {
				unread = member
			}
		}
		if owners == nil {
			return unread
		}
		return confinement{owners: owners}
	case eval.ShapeUnknown:
		return confinement{unread: true, doubt: UnreadConstraint}
	}
	return confinement{}
}

// widenedOn reports whether the grant is only an upper bound on claim: a
// caveat on the whole set, or one the parser filed under a key that may be
// the claim, which it decides by its own rules for keys.
func (c classifier) widenedOn(claim trust.ClaimKey) bool {
	return slices.ContainsFunc(c.grant.Admits.Caveats(), func(cv eval.Caveat) bool {
		return cv.Claim == "" || aws.MayName(cv.Claim, c.grant.Issuer, claim)
	})
}

// noOwner is a pattern on a claim whose whole value is the tenant: it
// admits values beyond its literal prefix, and whoever registers one of
// them, so it pins nothing.
func noOwner(string) []Owner { return nil }

// patternOn is how a pattern on a claim naming a tenant is read for an
// owner: as pinning nothing, where the claim's whole value is the tenant,
// an owner or an id, and as not read, where the value is a repository's
// name. A repository's name may lead with its owner's, as GitHub's
// owner/repo does, so a pattern closing that part confines every value to
// one owner, and the census records the claim's scope, not how its value
// is composed. Read as pinning nothing, the grant would be placed with
// anyone on the platform, exactly, under a sentence saying no condition
// confines it.
func patternOn(claim TenancyClaim) func(string) []Owner {
	if claim.Scope == ScopeRepository && claim.Kind == KindName {
		return nil
	}
	return noOwner
}

// claimOwner is the owner one exact value of a tenancy claim names: the
// whole value, recyclable unless a sentence says the claim's values never
// pass on. An empty value names nobody, and an owner's name holding a
// character the verified set excludes names nobody real.
func (c classifier) claimOwner(t *Tenancy, claim TenancyClaim) func(string) []Owner {
	return func(v string) []Owner {
		if v == "" || claim.Scope == ScopeOwner && len(t.OwnerCharacters) > 0 && t.ownerRun(v) != v {
			return nil
		}
		return []Owner{{Issuer: c.grant.Issuer, Namespace: c.facts.Namespace, Scope: claim.Scope, Kind: claim.Kind, Value: v, Recyclable: claim.Recyclable != No}}
	}
}

// namesNoTenant reports whether the census records claim among those that
// look as if they name a tenant and do not: by its name, or by a name
// ending in *, which stands for every claim that begins with the text
// before it.
func (t *Tenancy) namesNoTenant(claim trust.ClaimKey) bool {
	return slices.ContainsFunc(t.NotTenancy, func(listed trust.ClaimKey) bool {
		prefix, every := strings.CutSuffix(string(listed), "*")
		return listed == claim || every && strings.HasPrefix(string(claim), prefix)
	})
}

// subject reads the sub constraint through the census's subject forms. With
// no verified owner character set, no delimiter can be shown to end an
// owner, so a constrained subject cannot be read for one.
func (c classifier) subject(term eval.Term, t *Tenancy) confinement {
	if _, present := term[subject]; present && len(t.OwnerCharacters) == 0 {
		return confinement{unread: true, doubt: TenancyNotRecorded}
	}
	value := func(v string) []Owner { return c.subjectOwners(t, v, true) }
	prefix := func(p string) []Owner { return c.subjectOwners(t, p, false) }
	return c.confine(term, subject, value, prefix)
}

// subjectOwners is who every subject that is text, or begins with it when
// complete is false, belongs to. A literal that never pins, or one the
// census does not record, confines nobody; so does text any form could
// read without reaching an owner. Otherwise the owners are those of every
// form that can read it, each through the deepest part the text closes.
func (c classifier) subjectOwners(t *Tenancy, text string, complete bool) []Owner {
	for _, lead := range t.NeverPin {
		if leads(text, lead, complete) {
			return nil
		}
	}
	var owners []Owner
	for _, form := range t.SubjectForms {
		owner, fits := c.readForm(t, form, text, complete)
		switch {
		case !fits:
			continue
		case owner == nil:
			return nil
		}
		owners = append(owners, *owner)
	}
	return owners
}

// leads reports whether a subject led by lead can be text, or begin with
// it when complete is false: a prefix shorter than the literal is
// compatible with it too.
func leads(text, lead string, complete bool) bool {
	return strings.HasPrefix(text, lead) || !complete && strings.HasPrefix(lead, text)
}

// partRecyclable reports whether an owner a subject form's part names can
// pass to someone else. The part is the value of the tenancy claim of the
// form's scope and the part's kind, as GitHub's repository_owner_id: leads
// the owner's id, and reads as that claim's census fact does. A part that
// no claim of that scope and kind records, or that two do, is recyclable:
// which claim it is was not established.
func (t *Tenancy) partRecyclable(scope Scope, kind Kind) bool {
	var of []TenancyClaim
	for _, c := range t.Claims {
		if c.Scope == scope && c.Kind == kind {
			of = append(of, c)
		}
	}
	return len(of) != 1 || of[0].Recyclable != No
}

// readForm reads text by one subject form. fits is false when no subject of
// the form can be text or begin with it: another literal leads it, or a
// character stands where the form allows neither an owner's character nor
// the part's delimiter. When it fits, owner is who the deepest part the
// text closes names, nil when it closes none: the text stops before a
// delimiter, a part is empty, or the form cannot show where its parts end.
// A complete value closes its last part where it ends.
func (c classifier) readForm(t *Tenancy, f SubjectForm, text string, complete bool) (owner *Owner, fits bool) {
	switch {
	case !leads(text, f.Lead, complete):
		return nil, false
	case len(text) < len(f.Lead) || !t.readable(f):
		return nil, true
	}
	rest, name := text[len(f.Lead):], ""
	for _, part := range f.Parts {
		run := t.ownerRun(rest)
		after := rest[len(run):]
		switch {
		case after == "" && !complete:
			return owner, true
		case after != "" && !strings.HasPrefix(after, part.Delimiter):
			return nil, false
		case run == "":
			return owner, true
		}
		o := Owner{Issuer: c.grant.Issuer, Namespace: c.facts.Namespace, Scope: f.Scope, Kind: part.Kind, Value: run, Recyclable: t.partRecyclable(f.Scope, part.Kind)}
		if part.Kind == KindID {
			o.Name = name
		} else {
			name = run
		}
		owner = &o
		if after == "" {
			return owner, true
		}
		rest = after[len(part.Delimiter):]
	}
	return owner, true
}

// readable reports whether a form can show where each of its parts ends: it
// names a tenant, and every delimiter is one character no owner's name
// holds.
func (t *Tenancy) readable(f SubjectForm) bool {
	if f.Scope == ScopeNone {
		return false
	}
	for _, part := range f.Parts {
		r, size := utf8.DecodeRuneInString(part.Delimiter)
		if size == 0 || size != len(part.Delimiter) || t.allows(r) {
			return false
		}
	}
	return true
}

// ownerRun is the longest run at the head of s that an owner's name can
// hold.
func (t *Tenancy) ownerRun(s string) string {
	for i, r := range s {
		if !t.allows(r) {
			return s[:i]
		}
	}
	return s
}

func (t *Tenancy) allows(r rune) bool {
	return slices.ContainsFunc(t.OwnerCharacters, func(cr CharRange) bool { return cr.First <= r && r <= cr.Last })
}

// covered reports whether the user declared o as theirs.
func (c classifier) covered(o Owner) bool {
	return slices.ContainsFunc(c.declared, func(d Declaration) bool { return d.Names(o, c.facts) })
}

// outermost is where a grant lands: the outermost ring any population
// reaches, beside it each line one reaches, exact when every place named is
// reached by an exact population, and the owners of the populations at
// those places.
func outermost(populations []Population) Placement {
	var ring Place = -1
	for _, pop := range populations {
		if pop.Place.Ring() && (ring < 0 || pop.Place < ring) {
			ring = pop.Place
		}
	}
	var named []Place
	if ring >= 0 {
		named = append(named, ring)
	}
	for _, line := range []Place{SAML, Service} {
		if slices.ContainsFunc(populations, func(pop Population) bool { return pop.Place == line }) {
			named = append(named, line)
		}
	}
	p := Placement{Outcome: Placed, Places: named, State: StateExact, Populations: populations}
	for _, place := range named {
		if !slices.ContainsFunc(populations, func(pop Population) bool { return pop.Place == place && pop.State == StateExact }) {
			p.State = StateUnknown
		}
	}
	for _, pop := range populations {
		if slices.Contains(named, pop.Place) {
			p.Owners = append(p.Owners, pop.Owners...)
		}
	}
	p.Owners = distinct(p.Owners)
	return p
}

// distinct sorts owners into one order and drops repeats, so that the same
// owners pinned in any order, by any number of claims, render alike.
func distinct(owners []Owner) []Owner {
	sortOwners(owners)
	return slices.Compact(owners)
}

// sortOwners is a merge sort by compareOwners. It is written out because
// slices.SortFunc in its place, instantiated for Owner, measured 10,565
// bytes more of the WebAssembly engine, 3,107 once compressed with brotli,
// against a whole budget of 400,000 compressed; and an insertion sort would
// be quadratic in a union a 256 KiB document can hold thousands of owners
// in. The left half is copied out, so the merge writes each owner back
// before the right half's next unread one.
func sortOwners(owners []Owner) {
	if len(owners) < 2 {
		return
	}
	mid := len(owners) / 2
	left := append([]Owner(nil), owners[:mid]...)
	right := owners[mid:]
	sortOwners(left)
	sortOwners(right)
	i, j := 0, 0
	for i < len(left) && j < len(right) {
		if compareOwners(right[j], left[i]) < 0 {
			owners[i+j] = right[j]
			j++
		} else {
			owners[i+j] = left[i]
			i++
		}
	}
	copy(owners[i+j:], left[i:])
}

// compareOwners orders owners by namespace, scope, kind, value and name,
// then by the issuer and the two facts, so that no two different owners
// compare equal.
func compareOwners(a, b Owner) int {
	return cmp.Or(
		strings.Compare(string(a.Namespace), string(b.Namespace)),
		cmp.Compare(a.Scope, b.Scope),
		cmp.Compare(a.Kind, b.Kind),
		strings.Compare(a.Value, b.Value),
		strings.Compare(a.Name, b.Name),
		strings.Compare(string(a.Issuer), string(b.Issuer)),
		compareBool(a.Recyclable, b.Recyclable),
		compareBool(a.Declared, b.Declared),
	)
}

func compareBool(a, b bool) int {
	switch {
	case a == b:
		return 0
	case a:
		return 1
	}
	return -1
}
