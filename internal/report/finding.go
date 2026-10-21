package report

import (
	"slices"
	"strings"

	"github.com/CloudArq-net/cloudarq/internal/eval"
	"github.com/CloudArq-net/cloudarq/internal/parse/aws"
	"github.com/CloudArq-net/cloudarq/internal/ring"
	"github.com/CloudArq-net/cloudarq/internal/trust"
)

// Finding is what the engine finds of one way in when it meets a rule: the
// rule, by its id, and the inputs, facts about the way in a reader weighs
// it by. A population whose state is not exact meets none, so a way in
// with no finding is not one the engine found clean: its state and basis
// say how far it was read.
type Finding struct {
	// Rule is the id of the rule the way in meets. Values:
	// web-identity/no-owner, web-identity/owner-left-open,
	// aws-account/no-external-id, aws-account/any-account.
	Rule string `json:"rule"`
	// ID is the finding's stable id: the same wherever the same rule is
	// met by the same way into the same role, however its policy is
	// written, and another wherever any of those is another, as keysOf
	// makes it. A role a scan's bundle lists gives one to each of its
	// findings; a policy read alone names no role, and its findings have
	// none.
	ID string `json:"id,omitempty"`
	// PairingKey is ID made without the way in's condition: the same for
	// the findings of one rule that a role meets through one issuer,
	// whatever each asks of the caller, so that a reader comparing two
	// reads of a role pairs a finding with what it was before its
	// condition changed. It is present exactly where ID is.
	PairingKey string `json:"pairingKey,omitempty"`
	// Callers are who the way in lets in that the rule is about, each by
	// its kind and its value, never empty: the whole platform for a rule
	// met by anyone with an account on it, and each AWS account the way
	// in names that the reader has neither declared nor been recognised
	// as holding, in the order its owners are listed, for one met by an
	// outsider.
	Callers []Caller `json:"callers"`
	// Through is what the way in comes through, as the statement writes
	// it: the identity provider a web-identity or SAML principal names, by
	// its ARN, or the service a service principal names. Null for an AWS
	// principal, which comes through none.
	Through *string `json:"through"`
	// Condition is what the way in's term holds of a caller, one claim a
	// string, as conditionOf writes them: the same however the policy
	// writes them, and the condition the finding's id is made from. Empty
	// where the term holds no claim, and null only where the population's
	// term is not one its grant holds, which says it is not known.
	Condition []string `json:"condition"`
	// Unread are the conditions the way in's statement writes that its
	// grant does not read, as unreadOf writes them, and as its grant's
	// Unread writes them: the id is made from them too. Null where the
	// engine cannot tell which of the statement's principals the grant was
	// read from, which says they are not known, never that there are none.
	Unread []string `json:"unread"`
	// Inputs are the facts about the way in, each written whatever it is.
	Inputs Inputs `json:"inputs"`
}

// Caller is one of whom a finding's way in lets in: what kind of caller,
// and the value that names it, null where the kind names none, as the
// whole platform.
type Caller struct {
	// Kind is the kind of caller: platform, everyone with an account on
	// the platform the grant's issuer is on, whose value is null; or
	// aws-account, one AWS account, whose value is its id. Values:
	// platform, aws-account.
	Kind  string  `json:"kind"`
	Value *string `json:"value"`
}

// The kinds of callers, each defined here and nowhere else.
const (
	callerPlatform   = "platform"
	callerAWSAccount = "aws-account"
)

// Inputs are facts about a finding's way in: what a caller must know or
// hold to come in by it, and where the role is. Each is written on every
// finding, so that one the engine did not read says so, as not-read, or
// not-checked for one only a live check can say, and never reads as
// nothing to say. They are facts, never a weighing of them: that is the
// reader's.
type Inputs struct {
	// NoSecret is whether anyone with an account on the platform comes in,
	// with nothing of the reader's to know or hold: the way in is placed
	// with the whole platform because nothing it constrains names an
	// owner, or an account, and it asks for no external ID. Values: yes,
	// no.
	NoSecret string `json:"noSecret"`
	// OwnerLeftOpen are the starts of an owner's name the subject writes
	// and leaves to a wildcard, as the policy writes them: "acme" of
	// "repo:acme*", "acm" of "repo:acm?/x", "acme" and "beta" of
	// "repo:acme*" beside "repo:beta*". They are in byte order, each once,
	// and none begins with another, which admits every name it would:
	// "repo:acme*" beside "repo:acmex*" leaves "acme". Empty when it writes
	// none.
	OwnerLeftOpen []string `json:"ownerLeftOpen"`
	// ExternalID is what the way in asks of the sts:ExternalId a caller
	// sends, for an AWS principal: required, a value of the policy's own;
	// absent, none, or any the caller chooses, as StringLike "*" or "?*",
	// or a condition the caller meets by sending none, as
	// StringEqualsIfExists or StringNotEquals;
	// not-known, where it holds a constraint the engine did not read. A
	// principal of another kind sends none. Values: required, absent,
	// not-applicable, not-known.
	ExternalID string `json:"externalId"`
	// Refs is which git refs a token may come from. Values: not-read.
	Refs string `json:"refs"`
	// Management is whether the role is in the management account of its
	// AWS Organization, as a scan's bundle says: yes or no for an account
	// in one, and not-known for any other, and for a policy read alone,
	// which names no account it is in. Values: yes, no, not-known.
	Management string `json:"management"`
	// RegistrableName is whether a name the way in trusts is free for
	// anyone to register today. Values: not-checked.
	RegistrableName string `json:"registrableName"`
	// DanglingIssuer is whether the issuer the way in trusts still answers
	// for its own. Values: not-checked.
	DanglingIssuer string `json:"danglingIssuer"`
	// Reach is what the role may do once assumed. Values: not-read.
	Reach string `json:"reach"`
	// Used is whether the way in has been used. Values: not-read.
	Used string `json:"used"`
}

// The values the inputs take beside the start of an owner's name, each
// defined here and nowhere else.
const (
	inputYes           = "yes"
	inputNo            = "no"
	inputNotKnown      = "not-known"
	inputNotRead       = "not-read"
	inputNotChecked    = "not-checked"
	inputNotApplicable = "not-applicable"
	externalIDRequired = "required"
	externalIDAbsent   = "absent"
)

// The rules' ids. An id is permanent: once a rule has one it is never
// renamed and never given to another rule, so that what a reader keyed on
// an id stays what it meant. Each is defined here and nowhere else.
const (
	// RuleNoOwner: anyone who holds an account on a web-identity issuer's
	// platform can present a token the grant admits, since nothing the
	// grant constrains names an owner: for GitHub, no subject at all, or
	// one such as "repo:*", which every repository's subject matches.
	RuleNoOwner = "web-identity/no-owner"
	// RuleOwnerLeftOpen: as RuleNoOwner, but the subject writes the start
	// of an owner's name and leaves the rest to a wildcard, as
	// "repo:acme*" or "repo:acm?/x" do, or several such starts, one in
	// each pattern of a list: whoever registers a name that begins with
	// one, "acme-evil" or "acmz", can present a token the grant admits.
	RuleOwnerLeftOpen = "web-identity/owner-left-open"
	// RuleNoExternalID: a named AWS account, or a role or user in it, that
	// nobody declared as theirs and no scan recognised as the account it
	// read, can assume the role without sending any particular external
	// ID: the grant asks for none, or accepts any value, as StringLike "*"
	// does, or passes when the caller sends none, as StringEqualsIfExists,
	// StringNotEquals and Null "true" do. AWS, of sts:ExternalId: "Use this key to require that a
	// principal provide a specific identifier when assuming an IAM role."
	// (https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_iam-condition-keys.html)
	RuleNoExternalID = "aws-account/no-external-id"
	// RuleAnyAccount: anyone with an AWS account can assume the role: the
	// principal is "*" or {"AWS": "*"}, and nothing the grant constrains
	// names an account or an organisation.
	RuleAnyAccount = "aws-account/any-account"
)

// externalID is the claim the AWS parser files a condition on
// sts:ExternalId under for an AWS principal.
const externalID = aws.ExternalIDClaim

// wayIn is what the rules read of one population: the grant it is a term
// of, where the classifier placed it, its owners as the answer marks them,
// declared, recognised, both or neither, and the Deny grants of the same
// policy read exactly.
type wayIn struct {
	grant    trust.Grant
	pop      ring.Population
	owners   []Owner
	refusals []trust.Grant
}

// rule is one rule: its id, whether a way in placed exactly meets it, and
// whom a way in that meets it lets in, as its finding names them.
type rule struct {
	id      string
	meets   func(w wayIn) bool
	callers func(w wayIn) []Caller
}

// rules are the rules in the order they are asked. The first a way in
// meets is its finding, so a rule that names a narrower case of another is
// listed before it, and the wider one never names that case.
var rules = [...]rule{
	{RuleOwnerLeftOpen, ownerLeftOpen, wholePlatform},
	{RuleNoOwner, noOwner, wholePlatform},
	{RuleNoExternalID, noExternalID, outsideAccounts},
	{RuleAnyAccount, anyAccount, wholePlatform},
}

// wholePlatform is whom a way in placed with the whole platform lets in:
// everyone with an account on it.
func wholePlatform(wayIn) []Caller { return []Caller{{Kind: callerPlatform}} }

// outsideAccounts is whom a way in placed as a named outsider lets in that
// the reader does not hold: each AWS account among its owners that is
// neither declared nor recognised, by its id. An account the reader holds
// is let in too, and is theirs, not the finding's.
func outsideAccounts(w wayIn) []Caller {
	var out []Caller
	for _, o := range w.owners {
		if o.Scope == ring.ScopeAccount.String() && !o.Declared && !o.Recognised {
			id := o.Value
			out = append(out, Caller{Kind: callerAWSAccount, Value: &id})
		}
	}
	return out
}

// findingOf is the finding of a way in: the first rule it meets, with
// whom that rule says it lets in and the condition its term holds, and none
// when its place is not exact, since a place resting on a fact nobody
// verified or a constraint nobody read cannot be said to meet a rule; nor
// when a Deny of the same policy provably refuses every token it admits,
// since then it lets nobody in, though the classifier, which never takes a
// Deny from an Allow, places it.
func findingOf(w wayIn) *Finding {
	if w.pop.State != ring.StateExact || refused(w) {
		return nil
	}
	for _, r := range rules {
		if r.meets(w) {
			f := &Finding{Rule: r.id, Callers: r.callers(w), Inputs: wayInputs(w)}
			if terms := w.grant.Admits.Terms(); w.pop.Term >= 0 && w.pop.Term < len(terms) {
				f.Condition = conditionOf(terms[w.pop.Term])
			}
			return f
		}
	}
	return nil
}

// wayInputs are the inputs of a way in placed exactly, as one policy says
// them: where the role is, which only a scan's bundle says, is not known.
// A way in placed with the whole platform has no secret only where it asks
// for no external ID, or a principal that sends none: one it asks for is a
// value the caller must know, and one the engine did not read may be.
func wayInputs(w wayIn) Inputs {
	in := Inputs{NoSecret: inputNo, ExternalID: externalIDOf(w), Refs: inputNotRead, Management: inputNotKnown,
		RegistrableName: inputNotChecked, DanglingIssuer: inputNotChecked, Reach: inputNotRead, Used: inputNotRead}
	asksNone := in.ExternalID == externalIDAbsent || in.ExternalID == inputNotApplicable
	if w.pop.Place == ring.Platform && w.pop.Basis == ring.Unpinned && asksNone {
		in.NoSecret = inputYes
	}
	in.OwnerLeftOpen = append([]string{}, w.pop.OwnerStarts...)
	return in
}

// externalIDOf is what a way in asks of the external ID a caller sends:
// for an AWS principal, absent where asksNoExternalID says it asks for
// none, required where its term holds every caller to a value of the
// policy's own, which a condition the engine did not read could only
// narrow, and not-known for anything else.
func externalIDOf(w wayIn) string {
	if w.grant.Issuer != aws.AWSPrincipalIssuer {
		return inputNotApplicable
	}
	terms := w.grant.Admits.Terms()
	if w.pop.Term < 0 || w.pop.Term >= len(terms) {
		return inputNotKnown
	}
	term := terms[w.pop.Term]
	if asksNoExternalID(w.grant, term) {
		return externalIDAbsent
	}
	if set, present := term[externalID]; present && asksAValue(eval.ShapeOf(set)) {
		return externalIDRequired
	}
	return inputNotKnown
}

// asksAValue reports whether a constraint holds every caller to a value of
// the policy's own: a value; a pattern with a character of its own, as
// "abc*"; a list of only such; or an intersection with one, since the
// others only narrow it. Unknown asks for nothing anybody read.
func asksAValue(s eval.Shape) bool {
	switch s.Kind {
	case eval.ShapeExact:
		return true
	case eval.ShapeGlob:
		return !anyValue(s)
	case eval.ShapeUnion:
		return len(s.Members) > 0 && !slices.ContainsFunc(s.Members, func(m eval.Shape) bool { return !asksAValue(m) })
	case eval.ShapeIntersection:
		return slices.ContainsFunc(s.Members, asksAValue)
	}
	return false
}

// noOwner is RuleNoOwner: a web-identity issuer's population placed with
// the whole platform because nothing it constrains names an owner.
func noOwner(w wayIn) bool {
	return webIdentity(w.grant.Issuer) && w.pop.Place == ring.Platform && w.pop.Basis == ring.Unpinned
}

// ownerLeftOpen is RuleOwnerLeftOpen: a population noOwner names whose
// subject writes the start of an owner's name, or several, which the
// classifier keeps.
func ownerLeftOpen(w wayIn) bool {
	return noOwner(w) && len(w.pop.OwnerStarts) > 0
}

// anyAccount is RuleAnyAccount: an AWS principal's population placed with
// the whole platform, anyone with an AWS account, because nothing it
// constrains names an account or an organisation.
func anyAccount(w wayIn) bool {
	return w.grant.Issuer == aws.AWSPrincipalIssuer && w.pop.Place == ring.Platform && w.pop.Basis == ring.Unpinned
}

// noExternalID is RuleNoExternalID: an AWS principal's population placed
// as a named outsider, with an account among its owners that is neither
// declared nor recognised, and a term that asks for no external ID. An
// outsider pinned only to an organisation names no account, and meets it
// not.
func noExternalID(w wayIn) bool {
	if w.grant.Issuer != aws.AWSPrincipalIssuer || w.pop.Place != ring.Outsider {
		return false
	}
	outside := false
	for _, o := range w.owners {
		outside = outside || o.Scope == ring.ScopeAccount.String() && !o.Declared && !o.Recognised
	}
	terms := w.grant.Admits.Terms()
	return outside && w.pop.Term >= 0 && w.pop.Term < len(terms) && asksNoExternalID(w.grant, terms[w.pop.Term])
}

// asksNoExternalID reports whether a caller of term is let in sending no
// external ID, or one of its own choosing: the term holds no value for it,
// because the statement writes no condition on it, or writes only
// conditions the parser says ask for no value in particular and leaves
// Unknown, a StringLike whose values admit every string, an IfExists, a
// ForAllValues, a StringNotEquals or a Null among them, or patterns of
// wildcards alone, which anyValue reads. A condition of those beside one
// that asks for a value leaves that value in the term, and asks for it. A
// caveat that may be on the external ID for any other reason, or on the
// whole grant, is a condition nobody read, and it may ask for one.
func asksNoExternalID(g trust.Grant, term eval.Term) bool {
	for _, c := range g.Admits.Caveats() {
		switch {
		case c.Claim == externalID && aws.AsksNoParticularValue(c):
		case c.Claim == "" || aws.MayName(c.Claim, g.Issuer, externalID):
			return false
		}
	}
	set, present := term[externalID]
	return !present || eval.ShapeOf(set).Kind == eval.ShapeUnknown || anyValue(eval.ShapeOf(set))
}

// anyValue reports whether a constraint lets the caller send a value of
// their own choosing: a StringLike pattern written of wildcards alone, as
// "?*" or "??*", which matches every value of some length, a list holding
// one, or an intersection of such patterns only. A pattern holding any
// other character asks for a value the caller must know.
func anyValue(s eval.Shape) bool {
	switch s.Kind {
	case eval.ShapeGlob:
		return strings.Trim(s.Text, "*?") == ""
	case eval.ShapeUnion:
		return slices.ContainsFunc(s.Members, anyValue)
	case eval.ShapeIntersection:
		return !slices.ContainsFunc(s.Members, func(m eval.Shape) bool { return !anyValue(m) })
	}
	return false
}

// deniesOf are the Deny grants of a policy's grants that the parser read
// exactly. A Deny it could not read whole is left unapplied, and admits
// nothing, with a caveat saying so; it refuses no way in provably.
func deniesOf(grants []trust.Grant) []trust.Grant {
	var out []trust.Grant
	for _, g := range grants {
		if g.Effect == trust.Deny && g.Exact() {
			out = append(out, g)
		}
	}
	return out
}

// refused reports whether a Deny of the way in's policy, for the same
// issuer, refuses every token its term admits: one of the Deny's terms
// admits all the way in's term does, as far as the two terms prove it.
// Where they do not, as for a Deny naming one role of an account the way
// in names whole, the way in is open at least in part, and is not refused.
func refused(w wayIn) bool {
	terms := w.grant.Admits.Terms()
	if w.pop.Term < 0 || w.pop.Term >= len(terms) {
		return false
	}
	term := terms[w.pop.Term]
	for _, d := range w.refusals {
		if d.Issuer == w.grant.Issuer && slices.ContainsFunc(d.Admits.Terms(), func(deny eval.Term) bool { return within(term, deny) }) {
			return true
		}
	}
	return false
}

// within reports whether every token term admits, deny admits too, proven
// claim by claim: each claim deny constrains, term constrains to a set
// whose meet with deny's is that set, which eval decides for a value by
// membership and for a pattern only against the same pattern. A claim
// either holds as Unknown proves nothing.
func within(term, deny eval.Term) bool {
	for claim, d := range deny {
		t, constrained := term[claim]
		if !constrained || eval.IsUnknown(t) || eval.IsUnknown(d) || t.Meet(d).String() != t.String() {
			return false
		}
	}
	return true
}

// webIdentity reports whether an issuer is one whose tokens are presented
// through sts:AssumeRoleWithWebIdentity: one the grant names, that is not
// the AWS parser's own pseudo-issuer for AWS principals, a service, or a
// SAML provider.
func webIdentity(issuer trust.IssuerRef) bool {
	return issuer != "" && issuer != aws.AWSPrincipalIssuer && !strings.HasPrefix(string(issuer), aws.ServiceIssuerPrefix) && !aws.IsSAMLIssuer(issuer)
}
