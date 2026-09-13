package azure

import (
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/CloudArq-net/cloudarq/internal/eval"
	"github.com/CloudArq-net/cloudarq/internal/trust"
)

// The anomaly kinds this parser defines beside trust.Unmodelled, spelt as
// the AWS parser spells the same defects so that a reporter switching on
// the kind treats one defect one way. The first six change what a grant
// admits and are paired with a caveat whenever they do; the rest are facts
// a reporter prints and admission does not depend on. Every anomaly names
// a construct: the member it is about, the operator, claim lookup, pattern
// or version literal the document wrote, or a fixed phrase for a fact the
// document has no name for, so that a reporter can count credentials by
// (Kind, Construct); what the document wrote is quoted in the sentence.
const (
	// DuplicateKey is a member written more than once. Which copy Entra
	// applies is not stated, so the member is not read.
	DuplicateKey = "duplicate-key"
	// Malformed is a member written with a JSON type Graph does not define
	// for it, or a required member left out, which is therefore not read.
	Malformed = "malformed"
	// NoSubjectConstraint marks a credential that constrains the subject by
	// neither subject nor claimsMatchingExpression, the shape a flexible
	// credential has when read through Graph v1.0.
	NoSubjectConstraint = "no-subject-constraint"
	// SubjectAndExpression marks a credential that sets both, which
	// Microsoft says cannot be; the credential is read as admitting what
	// either alone would.
	SubjectAndExpression = "subject-and-expression"
	// ClaimFolded marks a claim name read as the documented claim it
	// differs from only in case.
	ClaimFolded = "claim-folded"
	// AudienceCount marks an audiences list that does not hold the one
	// audience Microsoft requires. An empty list, or one past what this
	// parser reads, is Unknown and caveated; several audiences are a fact.
	AudienceCount = "audience-count"
	// MiscasedKey marks a member that matches a Graph member name only in
	// case, and is therefore not read as it.
	MiscasedKey = "miscased-key"
	// EmptySubject marks a subject written as the empty string, which is
	// read as no subject: Graph documents the member as nullable, and no
	// documented issuer mints a token whose sub is empty.
	EmptySubject = "empty-subject"
	// MissingIssuer marks a credential whose issuer is absent, empty, or
	// names no host.
	MissingIssuer = "missing-issuer"
	// IssuerScheme marks an issuer that does not begin with https://.
	IssuerScheme = "issuer-scheme"
	// IssuerWhitespace marks an issuer with leading or trailing whitespace,
	// which Microsoft says blocks the token exchange.
	IssuerWhitespace = "issuer-whitespace"
	// UndocumentedAcceptance marks a clause that constrains nothing, a
	// matches against a pattern of stars alone: Microsoft does not say
	// whether Entra accepts such a credential, and if it does, the clause
	// admits every value, which is what the set says.
	UndocumentedAcceptance = "undocumented-acceptance"
)

// Credential is one federated identity credential as the document states
// it, a Graph federatedIdentityCredential or a Resource Manager resource
// holding one. The exported fields are the document's own values, kept as
// written; what they admit is computed once, when the document is read,
// and handed out by Grants, so that a Credential and its Grant can never
// disagree. Only the parser makes a Credential that states a Grant.
//
// Graph must be read at /beta: v1.0 omits claimsMatchingExpression, so a
// flexible credential read there looks like one with no subject at all.
// That reading is the first thing this parser refuses to mistake for an
// unconstrained credential.
type Credential struct {
	ID         string // Graph's id, or the resource id
	Name       string
	Issuer     string      // as written; the Grant carries the normalised issuer
	Subject    string      // "" when the document sets none
	Audiences  []string    // nil when the list is not read: absent, malformed or past audienceCap
	Expression *Expression // nil when the document sets none
	// Anomalies are the facts about the document a reporter may need, in
	// canonical order. Every one that makes the admitted set an upper bound
	// is also a caveat on the Grant, carrying the same sentence.
	Anomalies []trust.Anomaly

	issuer trust.IssuerRef
	admits eval.AdmittedSet
	raw    json.RawMessage
}

// Expression is the claimsMatchingExpression member: the text and the
// language version it claims. LanguageVersion is 0 when the document's
// value is not the integer Microsoft documents; the anomaly says what it
// was, and the expression is not modelled.
type Expression struct {
	Value           string
	LanguageVersion int64
}

// credentialMembers are the members that state what a credential admits,
// and whose presence, in any ASCII case, makes an object a credential
// rather than something else that is JSON; labelMembers name it. A member
// named otherwise, @odata annotations and Resource Manager's type included,
// is ignored; one that matches only in case is recorded and not read.
var (
	credentialMembers = []string{"issuer", "subject", "audiences", "claimsMatchingExpression"}
	labelMembers      = []string{"id", "name", "description"}
	expressionMembers = []string{"value", "languageVersion"}
)

// ParseFederatedCredentials reads a document from either API that returns
// federated identity credentials and returns one Credential per credential
// in it. From Graph, which holds an application's: one credential object,
// the collection the list endpoint returns ({"value": [...]}), or the single
// credential Microsoft's page shows a GET answering with ({"value": {...}}).
// From Resource Manager, which holds a user-assigned managed identity's: a
// resource whose properties object carries the credential, or the value
// collection of those. A bare list of either is read too. An error means
// the input is not a credential document at all: not one JSON value in
// valid UTF-8 with every escape representable, nested deeper than the
// reader follows, not one of those shapes, an object with no member that
// states a credential, or one that could be read as two of the shapes at
// once. Everything else is read, and what cannot be understood is Unknown
// with the reason attached.
func ParseFederatedCredentials(raw []byte) ([]Credential, error) {
	root, err := readDocument(raw)
	if err != nil {
		return nil, fmt.Errorf("federated identity credential: %w", err)
	}
	resources, err := resourcesIn(root)
	if err != nil {
		return nil, fmt.Errorf("federated identity credential: %w", err)
	}
	credentials := make([]Credential, len(resources))
	for i, r := range resources {
		credentials[i] = parseCredential(r)
	}
	return credentials, nil
}

// ParseFederatedCredential reads a document that holds exactly one
// credential: the object itself, or a collection of one.
func ParseFederatedCredential(raw []byte) (Credential, error) {
	credentials, err := ParseFederatedCredentials(raw)
	if err != nil {
		return Credential{}, err
	}
	if len(credentials) != 1 {
		return Credential{}, fmt.Errorf("federated identity credential: a collection of %d credentials, not one; use ParseFederatedCredentials", len(credentials))
	}
	return credentials[0], nil
}

// resource is one credential as a document holds it: the object that
// labels it and whose bytes are quoted back, and the object that states it.
// On a Graph object the two are one; on a Resource Manager resource the
// credential sits under properties, beside the id, name and type of the
// resource.
type resource struct {
	object     *value
	credential *value
}

// resourcesIn finds the credentials in a document: the items of a bare
// list; the object itself when it is a credential or a resource holding
// one; or, when it is neither, what its value member holds, a list for the
// collection either list endpoint returns and an object for the single
// credential Microsoft's page shows a GET answering with. A document that
// could be read two ways is read neither: a value member written twice, a
// value container beside a credential, or a container under a name that
// matches value only in case, would under either reading drop credentials
// without a trace, and a credential that vanishes from the report is
// silence.
func resourcesIn(root *value) ([]resource, error) {
	switch root.kind {
	case kindList:
		return listedResources(root, "")
	case kindObject:
	default:
		return nil, fmt.Errorf("the document is %s, not an object or a list", root.kind)
	}
	values := members(root.members, "value")
	if len(values) > 1 {
		return nil, fmt.Errorf("the member \"value\" is written %d times, so the document is not one collection", len(values))
	}
	if m, near := miscasedCollection(root.members); near {
		return nil, fmt.Errorf("the member %s holds %s and differs from Graph's \"value\" only in case; Graph member names are exact, so the document is neither one credential nor a collection", quote(m.name), m.value.kind)
	}
	var container *value
	if len(values) == 1 && (values[0].kind == kindList || values[0].kind == kindObject) {
		container = values[0]
	}
	own, err := resourceOf(root, "the document")
	switch {
	case err != nil:
		return nil, err
	case container != nil && own.credential == root:
		return nil, fmt.Errorf("the document carries both %s and credential members, so it is neither one credential nor a collection", describe(container))
	case container != nil && own.credential != nil:
		return nil, fmt.Errorf("the document carries both %s and a properties object holding credential members, so it is neither one resource nor a collection", describe(container))
	case own.credential != nil:
		return []resource{own}, nil
	case container == nil:
		return nil, errors.New(notACredential("the document"))
	case container.kind == kindList:
		return listedResources(container, "value")
	}
	single, err := resourceOf(container, "value")
	switch {
	case err != nil:
		return nil, err
	case single.credential == nil:
		return nil, errors.New(notACredential("value"))
	}
	return []resource{single}, nil
}

// resourceOf reads an object as the credential it holds: the object itself
// when it carries a credential member, or its properties object when that
// does, which is how Resource Manager returns a managed identity's. The
// credential is nil when the object holds none. An object that could be
// read both ways, or whose properties member is written more than once, is
// refused, because under either reading a credential would vanish.
func resourceOf(object *value, where string) (resource, error) {
	properties := members(object.members, "properties")
	if len(properties) > 1 {
		return resource{}, fmt.Errorf("the member \"properties\" is written %d times, so %s is not one resource", len(properties), where)
	}
	own := isCredential(object.members)
	held := len(properties) == 1 && properties[0].kind == kindObject && isCredential(properties[0].members)
	switch {
	case own && held:
		return resource{}, fmt.Errorf("%s carries both credential members and a properties object holding credential members, so it is neither one credential nor one resource", where)
	case own:
		return resource{object: object, credential: object}, nil
	case held:
		return resource{object: object, credential: properties[0]}, nil
	}
	return resource{object: object}, nil
}

// miscasedCollection finds a member that matches the collection member
// only in ASCII case and holds a list or an object. A serialiser that does
// not spell members as Graph does may have written a collection under it;
// a scalar under such a name is no collection under any spelling and is
// ignored as any unknown member is.
func miscasedCollection(ms []member) (member, bool) {
	for _, m := range ms {
		if m.name != "value" && equalFoldASCII("value", m.name) && (m.value.kind == kindList || m.value.kind == kindObject) {
			return m, true
		}
	}
	return member{}, false
}

func describe(container *value) string {
	if container.kind == kindList {
		return "a value list"
	}
	return "a value object"
}

func listedResources(list *value, prefix string) ([]resource, error) {
	resources := make([]resource, len(list.items))
	for i, item := range list.items {
		where := prefix + "[" + strconv.Itoa(i) + "]"
		if item.kind != kindObject {
			return nil, fmt.Errorf("%s is %s, not a credential", where, item.kind)
		}
		r, err := resourceOf(item, where)
		switch {
		case err != nil:
			return nil, err
		case r.credential == nil:
			return nil, errors.New(notACredential(where))
		}
		resources[i] = r
	}
	return resources, nil
}

func notACredential(where string) string {
	return where + " is not a credential: no issuer, subject, audiences or claimsMatchingExpression member, and no properties member holding one"
}

// isCredential recognises a credential by any of the members that state
// one, in any ASCII case, so that a document whose every member is misspelt
// in case is still read, and every misspelling reported, rather than
// refused as not a credential. A label is no mark: a name and a type are
// what every resource has.
func isCredential(members []member) bool {
	for _, m := range members {
		if slices.ContainsFunc(credentialMembers, func(mark string) bool { return equalFoldASCII(mark, m.name) }) {
			return true
		}
	}
	return false
}

// members returns every value written under a name, in document order.
func members(ms []member, name string) []*value {
	var out []*value
	for _, m := range ms {
		if m.name == name {
			out = append(out, m.value)
		}
	}
	return out
}

// reading collects what one credential document states and what it leaves
// in doubt. Every fact is an Anomaly; a fact that makes the admitted set an
// upper bound rather than the set itself is also a Caveat on the claim it
// touches, carrying the same sentence, so that the two can never disagree
// about why.
type reading struct {
	anomalies []trust.Anomaly
	caveats   []eval.Caveat
}

// note records a fact that changes nothing about admission.
func (r *reading) note(a trust.Anomaly) { r.anomalies = append(r.anomalies, a) }

// doubt records a fact and the caveat it implies.
func (r *reading) doubt(a trust.Anomaly) {
	r.note(a)
	r.caveats = append(r.caveats, eval.Caveat{Claim: a.Claim, Reason: a.Message, Source: a.Source})
}

// unread records that a member was not read: a doubt when the member
// constrains a claim, a fact otherwise.
func (r *reading) unread(a trust.Anomaly) {
	if a.Claim == "" {
		r.note(a)
		return
	}
	r.doubt(a)
}

// parseCredential reads one credential. It is total: every member is either
// read, or not read for a stated reason, and a member that constrains a
// claim and could not be read leaves that claim Unknown.
//
// The reader's values slice the caller's buffer, which a collector reuses
// for its next page; a Credential outlives the parse, so it keeps a copy of
// its own bytes, and of nothing around them.
func parseCredential(res resource) Credential {
	r := &reading{}
	labels := r.file(res.object.members, labelMembers, "")
	filed := r.file(res.credential.members, credentialMembers, "")
	c := Credential{ID: r.label(labels, "id"), Name: r.label(labels, "name"), raw: slices.Clone(res.object.raw)}
	c.Issuer, c.issuer = r.issuerOf(filed)
	var subjectTerm, expressionTerm eval.Term
	c.Subject, subjectTerm = r.subjectTerm(filed)
	c.Expression, expressionTerm = r.expressionTerm(filed, c.issuer)
	var terms []eval.Term
	switch {
	case subjectTerm != nil && expressionTerm != nil:
		// Microsoft says the two cannot both be set, so which one Entra
		// applies cannot be known: the credential admits what either would.
		r.doubt(trust.Anomaly{
			Kind:      SubjectAndExpression,
			Claim:     "sub",
			Construct: "subject",
			Message:   "subject and claimsMatchingExpression are both set; Microsoft says they are mutually exclusive, so the credential is read as admitting what either alone would",
			Source:    "subject",
		})
		terms = []eval.Term{subjectTerm, expressionTerm}
	case expressionTerm != nil:
		terms = []eval.Term{expressionTerm}
	case subjectTerm != nil:
		terms = []eval.Term{subjectTerm}
	default:
		r.doubt(trust.Anomaly{
			Kind:      NoSubjectConstraint,
			Claim:     "sub",
			Construct: "subject",
			Message:   "neither subject nor claimsMatchingExpression constrains the subject; a Graph v1.0 read omits claimsMatchingExpression, so a constraint on sub may exist that this document does not show",
			Source:    "subject",
		})
		terms = []eval.Term{{"sub": eval.Unknown("no subject constraint")}}
	}
	// The audience is a claim like any other, met with whatever the
	// expression said about it: a clause on aud is undocumented and Unknown,
	// and Unknown is the identity under Meet, so the audience stands.
	var aud eval.StringSet
	c.Audiences, aud = r.audience(filed)
	for _, term := range terms {
		if s, constrained := term["aud"]; constrained {
			term["aud"] = s.Meet(aud)
		} else {
			term["aud"] = aud
		}
	}
	c.admits = eval.NewAdmittedSet(terms...)
	for _, caveat := range r.caveats {
		c.admits = c.admits.WithCaveat(caveat)
	}
	c.Anomalies = canonical(r.anomalies)
	return c
}

// canonical sorts the anomalies so that a reordered document reports the
// same list. Every fact recorded is kept, two pieces outside the grammar
// that read alike once quoting cut them included: a fact dropped for
// resembling another would be silence.
func canonical(anomalies []trust.Anomaly) []trust.Anomaly {
	if len(anomalies) == 0 {
		return nil
	}
	sorted := slices.Clone(anomalies)
	slices.SortFunc(sorted, func(x, y trust.Anomaly) int {
		return cmp.Or(
			cmp.Compare(x.Kind, y.Kind),
			cmp.Compare(x.Claim, y.Claim),
			cmp.Compare(x.Construct, y.Construct),
			cmp.Compare(x.Message, y.Message),
			cmp.Compare(x.Source, y.Source),
		)
	})
	return sorted
}

// Grants is the one Grant the credential states: Allow for the target the
// collector read it from, with the credential's own bytes as Source. A
// credential with no readable issuer is still a Grant, with the issuer
// empty and the anomaly saying so; a credential that vanished from the
// report because its issuer could not be read would be silence.
//
// A Credential the parser did not produce, the zero value or one built by
// hand, states no Grant: there is no document behind it to quote, and the
// Grant its empty admitted set would make is an Allow that admits nothing,
// exactly and without a caveat, which is a proven emptiness the lattice
// would believe.
func (c Credential) Grants(target trust.TargetRef) []trust.Grant {
	if c.raw == nil {
		return nil
	}
	return []trust.Grant{{
		Target:    target,
		Issuer:    c.issuer,
		Admits:    c.admits,
		Effect:    trust.Allow,
		Anomalies: slices.Clone(c.Anomalies),
		Source:    slices.Clone(c.raw),
	}}
}

// file sorts an object's members under the Graph names they match exactly,
// duplicates kept, and records a member that matches a Graph name only in
// ASCII case: Graph spells its members exactly, so such a member is not
// read as the one it resembles, and a name from another script that only
// Unicode folding would equate is not a misspelling but another member.
// where prefixes the source of a fact about a member inside
// claimsMatchingExpression.
func (r *reading) file(members []member, known []string, where string) map[string][]*value {
	filed := map[string][]*value{}
	for _, m := range members {
		if slices.Contains(known, m.name) {
			filed[m.name] = append(filed[m.name], m.value)
			continue
		}
		for _, name := range known {
			if equalFoldASCII(name, m.name) {
				r.note(trust.Anomaly{
					Kind:      MiscasedKey,
					Construct: m.name,
					Message:   "the member " + quote(m.name) + " differs from Graph's " + quote(name) + " only in case; Graph member names are exact, so it is not read as " + name,
					Source:    where + m.name,
				})
				break
			}
		}
	}
	return filed
}

// member returns what the document writes for one member, nil when it is
// absent or null. A member written more than once is not read: the fact is
// recorded, and the Unknown returned beside it is what the member's claim
// becomes.
func (r *reading) member(filed map[string][]*value, name string, claim trust.ClaimKey, where string) (*value, eval.StringSet) {
	values := filed[name]
	if len(values) > 1 {
		r.unread(trust.Anomaly{
			Kind:      DuplicateKey,
			Claim:     claim,
			Construct: name,
			Message:   "the member " + quote(name) + " is written " + strconv.Itoa(len(values)) + " times; which one Entra would apply is not stated, so it is not read",
			Source:    where + name,
		})
		return nil, eval.Unknown("duplicate key")
	}
	if len(values) == 0 || values[0].kind == kindNull {
		return nil, nil
	}
	return values[0], nil
}

// wrongType records a member written with a type Graph does not define for
// it, and returns what its claim becomes.
func (r *reading) wrongType(v *value, name string, claim trust.ClaimKey, where, defined string) eval.StringSet {
	r.unread(trust.Anomaly{
		Kind:      Malformed,
		Claim:     claim,
		Construct: name,
		Message:   where + name + " is " + v.kind.String() + "; Graph defines it as " + defined + ", so it is not read",
		Source:    where + name,
	})
	return eval.Unknown("wrong type")
}

// text reads a member Graph defines as a string. set is false when the
// member is absent or null; unknown is what the member's claim becomes when
// the member is written but cannot be read.
func (r *reading) text(filed map[string][]*value, name string, claim trust.ClaimKey, where string) (text string, set bool, unknown eval.StringSet) {
	v, unknown := r.member(filed, name, claim, where)
	switch {
	case unknown != nil:
		return "", true, unknown
	case v == nil:
		return "", false, nil
	case v.kind != kindString:
		return "", true, r.wrongType(v, name, claim, where, "a string")
	}
	return v.text, true, nil
}

// label reads a member that names the credential and constrains nothing.
func (r *reading) label(filed map[string][]*value, name string) string {
	text, _, _ := r.text(filed, name, "", "")
	return text
}

// issuerOf reads the issuer as written and normalises it to the registry
// key. An issuer with no host is no issuer, which the Grant carries as ""
// with the fact stated. Two forms are read as the issuer they resemble and
// recorded, because under each the credential may admit no token at all:
// surrounding whitespace, which Microsoft says blocks the exchange, and a
// scheme other than https, which no documented issuer states in its iss.
// Reading the resembled issuer is the wide direction, and the anomaly is
// what keeps it from passing as an unqualified trust. The issuer never
// caveats the admitted set: the set is what the document says, the issuer
// is what is unknown.
func (r *reading) issuerOf(filed map[string][]*value) (written string, issuer trust.IssuerRef) {
	written, set, unknown := r.text(filed, "issuer", "", "")
	if unknown != nil {
		return "", ""
	}
	trimmed := strings.TrimSpace(written)
	if !set || trimmed == "" {
		r.note(trust.Anomaly{
			Kind:      MissingIssuer,
			Construct: "issuer",
			Message:   "no issuer is set; Microsoft requires one, so which identity provider this credential trusts is not stated",
			Source:    "issuer",
		})
		return written, ""
	}
	issuer, ok := trust.NormaliseIssuer(trimmed)
	if !ok {
		r.note(trust.Anomaly{
			Kind:      MissingIssuer,
			Construct: "issuer",
			Message:   "issuer " + quote(written) + " names no host, so which identity provider this credential trusts is not stated",
			Source:    "issuer",
		})
		return written, ""
	}
	if trimmed != written {
		r.note(trust.Anomaly{
			Kind:      IssuerWhitespace,
			Construct: "issuer",
			Message:   "issuer " + quote(written) + " has leading or trailing whitespace; Microsoft says an issuer claim with leading or trailing whitespace blocks the token exchange, so this credential may admit no token; it is read as trusting the issuer with the whitespace removed",
			Source:    "issuer",
		})
	}
	if !strings.HasPrefix(trimmed, "https://") {
		r.note(trust.Anomaly{
			Kind:      IssuerScheme,
			Construct: "issuer",
			Message:   "issuer " + quote(written) + " does not begin with https://; Entra matches it against the token's iss claim, and every documented issuer states its iss as an https URL",
			Source:    "issuer",
		})
	}
	return written, issuer
}

// subjectTerm is the classic reading: the subject as one exact value. The
// Term is nil when the document sets no subject, and the empty string is
// no subject: no documented issuer mints a token whose sub is empty, so
// Exact("") would be a credential that admits nobody, on a value a
// serialiser writing "" for null could produce. That the member was
// written is still a fact, recorded so that a member dropped is never a
// member unmentioned; it changes nothing about admission, because no real
// token could have matched it.
func (r *reading) subjectTerm(filed map[string][]*value) (subject string, term eval.Term) {
	subject, set, unknown := r.text(filed, "subject", "sub", "")
	switch {
	case unknown != nil:
		return "", eval.Term{"sub": unknown}
	case !set:
		return "", nil
	case subject == "":
		r.note(trust.Anomaly{
			Kind:      EmptySubject,
			Claim:     "sub",
			Construct: "subject",
			Message:   "subject is the empty string; Graph documents subject as nullable and no documented issuer mints a token whose sub is empty, so it is read as no subject",
			Source:    "subject",
		})
		return "", nil
	}
	return subject, eval.Term{"sub": eval.Exact(subject)}
}

// audienceCap bounds the audiences read from one list. The union of exact
// audiences costs eval a comparison per pair of members and a sort per
// Join, so a list long enough would take minutes to read; a list of
// 200,000 ran for minutes. Microsoft accepts exactly one audience, so the
// cap refuses nothing Graph produces, and past it the audience widens to
// Unknown with the fact stated, never to a truncated union, which would
// under-approximate.
const audienceCap = 256

// audience is the aud constraint: the one audience Graph requires, the
// union of several, or Unknown when the list is missing, empty, past the
// cap or could not be read. Several audiences are outside Graph's contract
// and recorded; the union is sound whichever one Entra applies. An
// audience that is the empty string is Unknown on its own: no documented
// issuer mints a token whose aud is empty and Microsoft does not say what
// Entra does with one, so Exact("") would report a credential as admitting
// nobody on a construct whose meaning is not stated; Unknown absorbs the
// rest under Join, which is the honest reading of a list that holds one.
func (r *reading) audience(filed map[string][]*value) ([]string, eval.StringSet) {
	none := func() eval.StringSet {
		r.doubt(trust.Anomaly{
			Kind:      AudienceCount,
			Claim:     "aud",
			Construct: "audiences",
			Message:   "no audience is set; Microsoft requires exactly one, so the audience this credential accepts is not stated",
			Source:    "audiences",
		})
		return eval.Unknown("no audience")
	}
	v, unknown := r.member(filed, "audiences", "aud", "")
	switch {
	case unknown != nil:
		return nil, unknown
	case v == nil:
		return nil, none()
	case v.kind != kindList:
		return nil, r.wrongType(v, "audiences", "aud", "", "a list of strings")
	case len(v.items) > audienceCap:
		r.doubt(trust.Anomaly{
			Kind:      AudienceCount,
			Claim:     "aud",
			Construct: "audiences",
			Message:   strconv.Itoa(len(v.items)) + " audiences are set; Microsoft accepts exactly one, and this parser reads at most " + strconv.Itoa(audienceCap) + ", so the audience this credential accepts is not stated",
			Source:    "audiences",
		})
		return nil, eval.Unknown("too many audiences")
	}
	audiences := make([]string, 0, len(v.items))
	sets := make([]eval.StringSet, 0, len(v.items))
	for i, item := range v.items {
		if item.kind != kindString {
			r.doubt(trust.Anomaly{
				Kind:      Malformed,
				Claim:     "aud",
				Construct: "audiences",
				Message:   "audiences[" + strconv.Itoa(i) + "] is " + item.kind.String() + "; Graph defines audiences as a list of strings, so it is not read",
				Source:    "audiences",
			})
			return nil, eval.Unknown("wrong type")
		}
		audiences = append(audiences, item.text)
		if item.text == "" {
			r.doubt(trust.Anomaly{
				Kind:      trust.Unmodelled,
				Claim:     "aud",
				Construct: "empty audience",
				Message:   "audiences[" + strconv.Itoa(i) + "] is the empty string; no documented issuer mints a token whose aud is empty and Microsoft does not say what Entra does with an empty audience, so the audience this credential accepts is not stated",
				Source:    "audiences",
			})
			sets = append(sets, eval.Unknown("empty audience"))
			continue
		}
		sets = append(sets, eval.Exact(item.text))
	}
	if len(audiences) == 0 {
		return nil, none()
	}
	if len(audiences) > 1 {
		r.note(trust.Anomaly{
			Kind:      AudienceCount,
			Claim:     "aud",
			Construct: "audiences",
			Message:   strconv.Itoa(len(audiences)) + " audiences are set; Microsoft accepts exactly one, so the credential is read as accepting any of them",
			Source:    "audiences",
		})
	}
	aud := sets[0]
	for _, set := range sets[1:] {
		aud = aud.Join(set)
	}
	return audiences, aud
}

// expressionTerm is the flexible reading. The Term is nil when the document
// sets no claimsMatchingExpression. An expression object whose value or
// languageVersion is missing, of the wrong type, or a version Microsoft does
// not document leaves sub Unknown: nothing the expression says can be read
// without knowing the language it is written in.
func (r *reading) expressionTerm(filed map[string][]*value, issuer trust.IssuerRef) (*Expression, eval.Term) {
	v, unknown := r.member(filed, "claimsMatchingExpression", "sub", "")
	switch {
	case unknown != nil:
		return nil, eval.Term{"sub": unknown}
	case v == nil:
		return nil, nil
	case v.kind != kindObject:
		return nil, eval.Term{"sub": r.wrongType(v, "claimsMatchingExpression", "sub", "", "an object")}
	}
	const where = "claimsMatchingExpression."
	inner := r.file(v.members, expressionMembers, where)
	e := &Expression{}
	text, set, unknown := r.text(inner, "value", "sub", where)
	switch {
	case unknown != nil:
		return e, eval.Term{"sub": unknown}
	case !set:
		r.doubt(trust.Anomaly{
			Kind:      Malformed,
			Claim:     "sub",
			Construct: "value",
			Message:   "claimsMatchingExpression has no value; Graph requires one, so the expression is not read",
			Source:    where + "value",
		})
		return e, eval.Term{"sub": eval.Unknown("unreadable expression")}
	}
	e.Value = text
	version, unknown := r.member(inner, "languageVersion", "sub", where)
	switch {
	case unknown != nil:
		return e, eval.Term{"sub": unknown}
	case version == nil:
		r.doubt(trust.Anomaly{
			Kind:      Malformed,
			Claim:     "sub",
			Construct: "languageVersion",
			Message:   "claimsMatchingExpression has no languageVersion; Graph requires one, so the expression is not read",
			Source:    where + "languageVersion",
		})
		return e, eval.Term{"sub": eval.Unknown("language version")}
	case version.kind != kindNumber:
		return e, eval.Term{"sub": r.wrongType(version, "languageVersion", "sub", where, "an integer")}
	}
	// The literal must be the integer 1 as written: 1.0 or 1e0 is not what
	// Graph serialises an Int32 as, and a document that writes it is
	// outside the contract, not a version 1 expression by arithmetic.
	if n, err := strconv.ParseInt(version.text, 10, 32); err != nil || n != 1 {
		r.doubt(trust.Anomaly{
			Kind:      trust.Unmodelled,
			Claim:     "sub",
			Construct: truncated(version.text),
			Message:   "claimsMatchingExpression.languageVersion is " + truncated(version.text) + "; Microsoft documents version 1 only, so the expression is not modelled",
			Source:    where + "languageVersion",
		})
		return e, eval.Term{"sub": eval.Unknown("language version")}
	}
	e.LanguageVersion = 1
	return e, r.evaluate(text, issuer)
}

// quoteLimit bounds how much of the document an anomaly repeats: the
// expression value has no documented length limit, and a sentence that
// grows with the input is not a sentence.
const quoteLimit = 200

// quote renders document text for a sentence a customer will read: ASCII
// only, so that a control character or a terminal escape written into a
// credential cannot rewrite the line that reports it, and cut at a rune
// boundary past quoteLimit bytes.
func quote(s string) string {
	s, cut := clip(s)
	quoted := strconv.QuoteToASCII(s)
	if cut {
		quoted += "..."
	}
	return quoted
}

// claimLookup renders a claim name the way the expression language spells
// a lookup, claims['sub'], with the name escaped and cut as quote would
// have it: the name is document text too.
func claimLookup(name string) string {
	name, cut := clip(name)
	quoted := strconv.QuoteToASCII(name)
	escaped := quoted[1 : len(quoted)-1]
	if cut {
		escaped += "..."
	}
	return "claims['" + escaped + "']"
}

// truncated renders document text that is ASCII by construction, a number
// literal or an operator word, for a sentence or a construct: only its
// length needs bounding.
func truncated(s string) string {
	s, cut := clip(s)
	if cut {
		s += "..."
	}
	return s
}

// clip cuts s at a rune boundary past quoteLimit bytes and reports whether
// it did, so that a cut never yields a broken character that would render
// as U+FFFD and misreport the document.
func clip(s string) (string, bool) {
	if len(s) <= quoteLimit {
		return s, false
	}
	cut := quoteLimit
	for !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut], true
}
