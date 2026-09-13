package gcp

import (
	"cmp"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"

	"github.com/CloudArq-net/cloudarq/internal/eval"
	"github.com/CloudArq-net/cloudarq/internal/trust"
)

// The anomaly kinds this parser defines beside trust.Unmodelled, spelt as
// the AWS and Azure parsers spell the same defects so that a reporter
// switching on the kind treats one defect one way. Every anomaly names a
// construct: the member it is about, the operator or function the
// condition wrote, or a fixed phrase for a fact the document has no name
// for; what the document wrote is quoted in the sentence.
const (
	// DuplicateKey is a member written more than once, the proto spelling
	// counted with the documented one. Which copy Google applies is not
	// stated, so the member is not read.
	DuplicateKey = "duplicate-key"
	// Malformed is a member written with a JSON type Google does not
	// define for it, a mapping key Google does not document, or a required
	// member left out, which is therefore not read.
	Malformed = "malformed"
	// MiscasedKey marks a member that matches a documented name only in
	// case. Whether Google reads it as that member is not stated, so
	// neither it nor the documented member beside it is read, and what
	// the member bears on is Unknown, as for a member written twice.
	MiscasedKey = "miscased-key"
	// MissingIssuer marks a provider whose issuer is absent or names no
	// host, or that sets no provider_config at all.
	MissingIssuer = "missing-issuer"
	// IssuerScheme marks an issuerUri that does not begin with https://.
	IssuerScheme = "issuer-scheme"
	// IssuerWhitespace marks an issuerUri with leading or trailing
	// whitespace.
	IssuerWhitespace = "issuer-whitespace"
	// AudienceCount marks an allowedAudiences list longer than Google
	// accepts. Past what this parser reads, aud is Unknown and caveated;
	// under that, the list is a fact.
	AudienceCount = "audience-count"
	// DefaultAudience marks a provider with no allowedAudiences, whose
	// audience is the provider's own resource name: a fact when the name
	// lets the two forms be derived, a doubt when it does not.
	DefaultAudience = "default-audience"
	// ProviderDisabled marks a disabled provider. Google says existing
	// tokens still grant access, and the flag is one update from false, so
	// the set is kept and declared an upper bound.
	ProviderDisabled = "provider-disabled"
	// ProviderDeleted marks a soft-deleted provider, restorable for about
	// thirty days; the set is kept and declared an upper bound.
	ProviderDeleted = "provider-deleted"
	// SubjectLength marks a value written for the claim google.subject maps
	// to, by a binding or by the condition, longer than Google's limit on
	// the subject: no credential maps to it, so the set stated is an upper
	// bound.
	SubjectLength = "subject-length"
)

// subjectLimit is Google's bound on the mapped subject, in bytes as Google
// counts it: "google.subject: … Cannot exceed 127 bytes."
const subjectLimit = 127

// awsIssuer is the pseudo-issuer under which the AWS parser files every
// AWS principal, spelt here so that a join can pair an AWS provider of a
// pool with an AWS trust policy on the same account. It is a copy of that
// parser's constant, and the test that compares the two is what keeps it
// one.
const awsIssuer trust.IssuerRef = "aws:sts"

// accountClaim is the claim the AWS parser gives an AWS account, and the
// claim an AWS provider's accountId constrains: the value space is the
// same twelve digits on both sides, so the join pairs them exactly. The
// ARN is not respelt onto the AWS parser's claim: Google's assertion.arn
// holds the STS form of an assumed role, the trust policy's principal the
// IAM role's, and an Exact on one never equals an Exact on the other.
const accountClaim trust.ClaimKey = "aws:principalaccount"

// awsClaims respells the assertion fields of an AWS credential whose
// value space is the AWS parser's own claim.
var awsClaims = map[string]trust.ClaimKey{"account": accountClaim}

// awsRoleExpression is the expression Google's default mapping for AWS
// providers gives attribute.aws_role, as the reference page prints it
// once its string pieces are joined.
const awsRoleExpression = "assertion.arn.contains('assumed-role') ? assertion.arn.extract('{account_arn}assumed-role/') + 'assumed-role/' + assertion.arn.extract('assumed-role/{role_name}/') : assertion.arn"

// defaultAWSMapping is Google's own: "For AWS providers, if no attribute
// mapping is defined, the following default mapping applies:
// {"google.subject":"assertion.arn", "attribute.aws_role": ...}". It
// applies when the mapping member is absent or an empty object, which
// proto3 JSON cannot tell apart; a custom mapping replaces it entirely.
func defaultAWSMapping() map[string]mapped {
	return map[string]mapped{
		"google.subject":     {claim: "arn", expression: "assertion.arn"},
		"attribute.aws_role": {expression: awsRoleExpression, why: "Google's default mapping for AWS providers maps by the expression " + quote(awsRoleExpression) + "; this parser does not evaluate mapping expressions"},
	}
}

// Provider is one workload identity pool provider as the document states
// it. The exported fields are the document's own values, kept as written
// under whichever spelling proto3 JSON accepts; what they admit is
// computed once, when the document is read, and handed out by Grants and
// Bind, so that a Provider and its Grant can never disagree. Only the
// parser makes a Provider that states a Grant.
type Provider struct {
	Name        string
	DisplayName string
	Description string
	State       string // ACTIVE, DELETED or STATE_UNSPECIFIED as written, "" when unset
	Disabled    bool
	ExpireTime  string
	// AttributeMapping holds the entries read: a documented key, mapped
	// by a string, written once. Nil when the document maps nothing.
	AttributeMapping   map[string]string
	AttributeCondition string
	// Type is the provider_config member the document sets, oidc, aws,
	// saml or x509, and "" when it sets none or more than one.
	Type string
	OIDC *OIDC // nil unless Type is oidc and the member was read
	AWS  *AWS  // nil unless Type is aws and the member was read
	// Anomalies are the facts about the document a reporter may need, in
	// canonical order. Every one that makes the admitted set an upper
	// bound is also a caveat on the Grant, carrying the same sentence.
	Anomalies []trust.Anomaly

	issuer   trust.IssuerRef
	admits   eval.AdmittedSet
	resolver resolver // how a condition or a binding names a claim under this provider
	raw      []byte
}

// OIDC is the oidc member: the issuer as written, and the audiences read
// from allowedAudiences, nil when the list is absent, empty or not read.
type OIDC struct {
	IssuerURI        string
	AllowedAudiences []string
}

// AWS is the aws member.
type AWS struct {
	AccountID string
}

// Page is one page of the list method's response: the providers it holds
// and the token that fetches the next page, "" on the last. A page with a
// token is an incomplete pool, and a binding on the whole pool depends on
// every provider, so a collector reads the token before it stops.
type Page struct {
	Providers     []Provider
	NextPageToken string
}

// ParsePage reads a document in any shape the API hands out: one
// provider, as get returns it; the page the list method returns,
// {"workloadIdentityPoolProviders": [...], "nextPageToken": ...}, whose
// empty form is {}; or a bare list of providers. A list never shows a
// soft-deleted provider unless the collector asked for them. An error
// means the input is not a provider document at all: not one JSON value
// in valid UTF-8 with every escape representable, nested deeper than the
// reader follows, not one of those shapes, an object with no member that
// states a provider, or one that could be read as two of the shapes at
// once. Everything else is read, and what cannot be understood is Unknown
// with the reason attached.
func ParsePage(raw []byte) (Page, error) {
	page, err := parsePage(raw)
	if err != nil {
		return Page{}, fmt.Errorf("workload identity pool provider: %w", err)
	}
	return page, nil
}

// ParseProviders is ParsePage for a document that holds every provider it
// lists. A page that carries a nextPageToken is refused, so that a pool
// read from its first page alone never passes as the whole pool.
func ParseProviders(raw []byte) ([]Provider, error) {
	page, err := ParsePage(raw)
	if err != nil {
		return nil, err
	}
	if page.NextPageToken != "" {
		return nil, errors.New("workload identity pool provider: the page carries a nextPageToken, so the pool has providers this document does not hold; read every page with ParsePage")
	}
	return page.Providers, nil
}

// ParseProvider reads a document that holds exactly one provider: the
// object itself, or a list of one.
func ParseProvider(raw []byte) (Provider, error) {
	providers, err := ParseProviders(raw)
	if err != nil {
		return Provider{}, err
	}
	if len(providers) != 1 {
		return Provider{}, fmt.Errorf("workload identity pool provider: the document holds %d providers, not one; use ParseProviders", len(providers))
	}
	return providers[0], nil
}

func parsePage(raw []byte) (Page, error) {
	root, err := readDocument(raw)
	if err != nil {
		return Page{}, err
	}
	switch root.kind {
	case kindList:
		providers, err := listedProviders(root.items, "")
		return Page{Providers: providers}, err
	case kindObject:
		return pageOf(root)
	}
	return Page{}, fmt.Errorf("the document is %s, not an object or a list", root.kind)
}

// spellings maps each name proto3's JSON mapping accepts for a member,
// the lowerCamelCase name Google documents and the original field name,
// to the documented one. A member is read under either, the two count as
// one member, and a name that matches one only in ASCII case is reported.
type spellings map[string]string

var (
	providerSpellings = spellings{
		"name": "name", "displayName": "displayName", "display_name": "displayName", "description": "description",
		"state": "state", "disabled": "disabled", "expireTime": "expireTime", "expire_time": "expireTime",
		"attributeMapping": "attributeMapping", "attribute_mapping": "attributeMapping",
		"attributeCondition": "attributeCondition", "attribute_condition": "attributeCondition",
		"oidc": "oidc", "aws": "aws", "saml": "saml", "x509": "x509",
	}
	oidcSpellings = spellings{"issuerUri": "issuerUri", "issuer_uri": "issuerUri", "allowedAudiences": "allowedAudiences", "allowed_audiences": "allowedAudiences"}
	awsSpellings  = spellings{"accountId": "accountId", "account_id": "accountId"}
	pageSpellings = spellings{"workloadIdentityPoolProviders": "workloadIdentityPoolProviders", "workload_identity_pool_providers": "workloadIdentityPoolProviders", "nextPageToken": "nextPageToken", "next_page_token": "nextPageToken"}
)

// marks are the members only a provider has, in either spelling. Any of
// them, in any ASCII case, makes an object a provider rather than
// something else that is JSON, so that a document whose every member is
// misspelt in case is still read and every misspelling reported. A label
// is no mark: a name, a state and a description are what every resource
// has, a pool included.
var marks = []string{"attributeMapping", "attribute_mapping", "attributeCondition", "attribute_condition", "oidc", "aws", "saml", "x509"}

const noMarks = "no attributeMapping, attributeCondition, oidc, aws, saml or x509 member"

func isProvider(v *value) bool {
	for _, m := range v.members {
		if slices.ContainsFunc(marks, func(mark string) bool { return equalFoldASCII(mark, m.name) }) {
			return true
		}
	}
	return false
}

// pageOf reads an object as the page or the provider it is. A document
// that could be read both ways is read neither: a list or a page token
// beside provider members, a page member written twice or spelt in
// another case, would under either reading drop a provider without a
// trace, and a provider that vanishes from the report is silence. An
// object with no member at all is the page the list method returns for a
// pool with no providers.
func pageOf(root *value) (Page, error) {
	var lists, tokens []*value
	for _, m := range root.members {
		if near, ok := resembles(m.name, pageSpellings); ok {
			return Page{}, fmt.Errorf("the member %s differs from %s only in case; whether Google reads it as that member is not stated, so the document is neither a provider nor a page", quote(m.name), quote(near))
		}
		switch pageSpellings[m.name] {
		case "workloadIdentityPoolProviders":
			lists = append(lists, m.value)
		case "nextPageToken":
			tokens = append(tokens, m.value)
		}
	}
	switch {
	case len(lists) > 1:
		return Page{}, fmt.Errorf("the member \"workloadIdentityPoolProviders\" is written %d times, so the document is not one page", len(lists))
	case len(tokens) > 1:
		return Page{}, fmt.Errorf("the member \"nextPageToken\" is written %d times, so the document is not one page", len(tokens))
	case len(lists) == 1 && isProvider(root):
		return Page{}, errors.New("the document carries both a provider list and provider members, so it is neither one provider nor a page")
	case len(tokens) == 1 && isProvider(root):
		return Page{}, errors.New("the document carries both a nextPageToken and provider members, so it is neither one provider nor a page")
	case isProvider(root):
		return Page{Providers: []Provider{parseProvider(root)}}, nil
	case len(lists) == 0 && len(tokens) == 0 && len(root.members) > 0:
		return Page{}, errors.New("the document is not a provider: " + noMarks + ", and no workloadIdentityPoolProviders list")
	}
	var page Page
	if len(tokens) == 1 && tokens[0].kind != kindNull {
		if tokens[0].kind != kindString {
			return Page{}, fmt.Errorf("the member \"nextPageToken\" is %s, not a string", tokens[0].kind)
		}
		page.NextPageToken = tokens[0].text
	}
	if len(lists) == 1 && lists[0].kind != kindNull {
		if lists[0].kind != kindList {
			return Page{}, fmt.Errorf("the member \"workloadIdentityPoolProviders\" is %s, not a list", lists[0].kind)
		}
		providers, err := listedProviders(lists[0].items, "workloadIdentityPoolProviders")
		if err != nil {
			return Page{}, err
		}
		page.Providers = providers
	}
	return page, nil
}

func listedProviders(items []*value, where string) ([]Provider, error) {
	providers := make([]Provider, 0, len(items))
	for i, item := range items {
		at := where + "[" + strconv.Itoa(i) + "]"
		switch {
		case item.kind != kindObject:
			return nil, fmt.Errorf("%s is %s, not a provider", at, item.kind)
		case !isProvider(item):
			return nil, fmt.Errorf("%s is not a provider: %s", at, noMarks)
		}
		providers = append(providers, parseProvider(item))
	}
	return providers, nil
}

// reading collects what one document states and what it leaves in doubt.
// Every fact is an Anomaly; a fact that makes the admitted set an upper
// bound rather than the set itself is also a Caveat on the claim it
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

// written is one member as the document wrote it: the spelling it used
// and its value.
type written struct {
	spelling string
	value    *value
}

// resembling is a member whose name matches a documented spelling only in
// ASCII case: the name as written, and the spelling it resembles.
type resembling struct {
	spelling  string
	resembles string
}

// filed is an object's members sorted under the documented names they
// spell, duplicates kept in document order, and, apart, the members that
// resemble a documented name in case alone.
type filed struct {
	members  map[string][]written
	miscased map[string][]resembling
}

// file sorts an object's members. Whether a proto3 JSON parser folds case
// is not stated, so a member that matches a documented name only in ASCII
// case is filed apart, for member to report under the bearing of the name
// it resembles; a name from another script that only Unicode folding
// would equate is not a misspelling but another member.
func file(v *value, known spellings) filed {
	f := filed{members: map[string][]written{}, miscased: map[string][]resembling{}}
	for _, m := range v.members {
		if name, ok := known[m.name]; ok {
			f.members[name] = append(f.members[name], written{m.name, m.value})
			continue
		}
		if near, ok := resembles(m.name, known); ok {
			f.miscased[known[near]] = append(f.miscased[known[near]], resembling{m.name, near})
		}
	}
	return f
}

// resembles finds the documented spelling a member's name matches only in
// ASCII case, so that a serialiser that does not spell members as Google
// does is reported rather than ignored.
func resembles(name string, known spellings) (string, bool) {
	for _, spelling := range slices.Sorted(maps.Keys(known)) {
		if spelling != name && equalFoldASCII(spelling, name) {
			return spelling, true
		}
	}
	return "", false
}

// equalFoldASCII reports whether two names differ at most in the case of
// ASCII letters. Every other byte must match exactly.
func equalFoldASCII(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		if lowerASCII(a[i]) != lowerASCII(b[i]) {
			return false
		}
	}
	return true
}

func lowerASCII(c byte) byte {
	if 'A' <= c && c <= 'Z' {
		return c + 'a' - 'A'
	}
	return c
}

// presence is how a member stands once read: absent, which proto3 JSON
// also writes as null and, for a string, as ""; present with its value;
// or written but not read, more than once, under a spelling that matches
// only in case, or with the wrong type, the fact recorded.
type presence int

const (
	absent presence = iota
	present
	duplicated
	miscased
	malformed
)

// unknown is what a claim the member bears on becomes when the member is
// not read.
func (how presence) unknown() eval.StringSet {
	switch how {
	case duplicated:
		return eval.Unknown("duplicate key")
	case miscased:
		return eval.Unknown("miscased key")
	}
	return eval.Unknown("wrong type")
}

// bearing is what a member that cannot be read does to the admitted set:
// nothing, for a member that labels the provider; the whole set becomes
// an upper bound, for one that decides whether or what the provider
// admits; or one claim becomes Unknown.
type bearing struct {
	claim trust.ClaimKey
	doubt bool
}

var (
	labels     = bearing{}
	wholeGrant = bearing{doubt: true}
	onAudience = bearing{claim: "aud", doubt: true}
	onAccount  = bearing{claim: accountClaim, doubt: true}
)

// unread records that a member was not read, as a doubt or a fact by its
// bearing.
func (r *reading) unread(a trust.Anomaly, b bearing) {
	if b.doubt {
		r.doubt(a)
		return
	}
	r.note(a)
}

// defined names the type Google's reference gives a member, for the
// sentence about one written with another.
var defined = map[kind]string{kindString: "a string", kindBool: "a boolean", kindObject: "an object", kindList: "a list of strings"}

// member is what the document writes for one member, with the type Google
// defines for it. A member written more than once, under a spelling that
// matches only in case, or with another type, is not read: which copy
// Google would apply, whether it reads the miscased one, or what it would
// make of the value, is not stated. A miscased spelling is reported first,
// one fact per spelling, and stops the documented member beside it from
// being read: which of the two Google applies is exactly as unstated.
func (r *reading) member(f filed, name, where string, want kind, b bearing) (*value, presence) {
	for _, m := range f.miscased[name] {
		r.unread(trust.Anomaly{
			Kind:      MiscasedKey,
			Claim:     b.claim,
			Construct: printable(m.spelling),
			Message:   "the member " + quote(m.spelling) + " differs from " + quote(m.resembles) + " only in case; whether Google reads it as that member is not stated, so " + name + " is not read",
			Source:    where + printable(m.spelling),
		}, b)
	}
	ws := f.members[name]
	switch {
	case len(ws) > 1:
		r.unread(trust.Anomaly{
			Kind:      DuplicateKey,
			Claim:     b.claim,
			Construct: name,
			Message:   "the member " + quote(name) + " is written " + strconv.Itoa(len(ws)) + " times" + countingProto(name, ws) + "; which one Google would apply is not stated, so it is not read",
			Source:    where + name,
		}, b)
		return nil, duplicated
	case len(f.miscased[name]) > 0:
		return nil, miscased
	case len(ws) == 0 || ws[0].value.kind == kindNull:
		return nil, absent
	case ws[0].value.kind != want:
		r.unread(trust.Anomaly{
			Kind:      Malformed,
			Claim:     b.claim,
			Construct: name,
			Message:   where + name + " is " + ws[0].value.kind.String() + "; Google defines it as " + defined[want] + ", so it is not read",
			Source:    where + name,
		}, b)
		return nil, malformed
	}
	return ws[0].value, present
}

// countingProto says, for a member written more than once, that a copy
// under the proto spelling was counted, since a reader who sees two
// different names may not know they are one member.
func countingProto(name string, ws []written) string {
	for _, w := range ws {
		if w.spelling != name {
			return ", counting its proto spelling " + quote(w.spelling)
		}
	}
	return ""
}

// text reads a string member. The empty string is absent: proto3 JSON
// leaves an unset string indistinguishable from an empty one.
func (r *reading) text(f filed, name, where string, b bearing) (string, presence) {
	v, how := r.member(f, name, where, kindString, b)
	if how != present {
		return "", how
	}
	if v.text == "" {
		return "", absent
	}
	return v.text, present
}

// parseProvider reads one provider. It is total: every member is either
// read, or not read for a stated reason, and a member that bears on
// admission and could not be read leaves what it bears on Unknown.
//
// The reader's values slice the caller's buffer, which a collector reuses
// for its next page; a Provider outlives the parse, so it keeps a copy of
// its own bytes, and of nothing around them.
func parseProvider(v *value) Provider {
	r := &reading{}
	f := file(v, providerSpellings)
	p := Provider{raw: slices.Clone(v.raw)}
	var named presence
	p.Name, named = r.text(f, "name", "", labels)
	p.DisplayName, _ = r.text(f, "displayName", "", labels)
	p.Description, _ = r.text(f, "description", "", labels)
	p.ExpireTime, _ = r.text(f, "expireTime", "", labels)
	p.State = r.state(f)
	p.Disabled = r.disabled(f)
	// identity is what the provider's kind itself constrains: the audience
	// of an OIDC token, the account of an AWS credential. It is met with
	// the condition, so a clause on the same claim narrows it.
	identity := eval.Term{}
	switch set := r.configured(f); {
	case len(set) == 0:
		r.doubt(trust.Anomaly{Kind: MissingIssuer, Construct: "provider_config", Message: "none of oidc, aws, saml or x509 is set; Google says provider_config must be one of them, so which identity provider this provider trusts, and the shape of its credential, is not stated", Source: "provider_config"})
		p.resolver.unattributable = "the provider sets none of oidc, aws, saml or x509, which leaves the shape of its credential unstated"
	case len(set) > 1:
		verb := " are all set"
		if len(set) == 2 {
			verb = " are set"
		}
		r.doubt(trust.Anomaly{Kind: trust.Unmodelled, Construct: "provider_config", Message: listed(set) + verb + "; Google says provider_config can be only one of them, so which identity provider this provider trusts, and the shape of its credential, is not stated", Source: "provider_config"})
		p.resolver.unattributable = "the provider sets " + listed(set) + ", which Google says cannot be, leaving the shape of its credential unstated"
		// None of them is read for its value, so each is read for its
		// record: a copy written twice or miscased is a fact of its own.
		for _, name := range set {
			r.member(f, name, "", kindObject, wholeGrant)
		}
	default:
		p.Type = set[0]
	}
	switch p.Type {
	case "oidc":
		p.OIDC, p.issuer, identity["aud"] = r.oidc(f, p.Name, named)
	case "aws":
		p.AWS, identity[accountClaim] = r.aws(f)
		p.issuer = awsIssuer
		p.resolver.translate = awsClaims
	case "saml":
		r.member(f, "saml", "", kindObject, wholeGrant)
		p.resolver.unattributable = "the provider is a SAML 2.0 provider, whose assertion this parser does not model as claims"
		r.doubt(trust.Anomaly{Kind: trust.Unmodelled, Construct: "saml", Message: p.resolver.unattributable + ", so the grant is read as every credential the provider admits", Source: "saml"})
	case "x509":
		r.member(f, "x509", "", kindObject, wholeGrant)
		p.resolver.unattributable = "the provider is an X.509 provider, whose certificate this parser does not model as claims"
		r.doubt(trust.Anomaly{Kind: trust.Unmodelled, Construct: "x509", Message: p.resolver.unattributable + ", so the grant is read as every credential the provider admits", Source: "x509"})
	}
	p.AttributeMapping = r.mapping(f, p.Type == "aws", &p.resolver)
	var condition eval.AdmittedSet
	p.AttributeCondition, condition = r.condition(f, p.resolver)
	p.admits = meetTerm(condition, identity)
	for _, c := range r.caveats {
		p.admits = p.admits.WithCaveat(c)
	}
	p.Anomalies = canonical(r.anomalies)
	return p
}

// meetTerm meets one conjunction into every Term of a set, claim by
// claim: the provider's identity into its condition, a binding's member
// into the provider's set. Meeting a set built from the conjunction alone
// would not do: a Term whose one constraint is an Unknown is everything
// to the lattice, which normalises it away before the Meet, and the doubt
// about that claim would leave no trace in the set.
func meetTerm(set eval.AdmittedSet, conjunction eval.Term) eval.AdmittedSet {
	terms := set.Terms()
	for _, term := range terms {
		for claim, constraint := range conjunction {
			if own, ok := term[claim]; ok {
				constraint = own.Meet(constraint)
			}
			term[claim] = constraint
		}
	}
	out := eval.NewAdmittedSet(terms...)
	for _, c := range set.Caveats() {
		out = out.WithCaveat(c)
	}
	return out
}

// configured lists the provider_config members the document sets, in
// name order: written at least once with a value that is not null, or
// under a spelling that matches one of the four only in case, which
// counts as set because whether Google reads it is not stated and a
// provider_config that vanished would read as no provider at all.
func (r *reading) configured(f filed) []string {
	var set []string
	for _, name := range []string{"aws", "oidc", "saml", "x509"} {
		ws := f.members[name]
		if len(ws) > 1 || (len(ws) == 1 && ws[0].value.kind != kindNull) || len(f.miscased[name]) > 0 {
			set = append(set, name)
		}
	}
	return set
}

// listed spells two or more member names for a sentence: "both aws and
// oidc", "aws, oidc, saml and x509".
func listed(names []string) string {
	last := len(names) - 1
	if last == 1 {
		return "both " + names[0] + " and " + names[1]
	}
	return strings.Join(names[:last], ", ") + " and " + names[last]
}

// state reads the provider's state. DELETED is a fact about admission; an
// unspecified state is the proto3 default; a value Google does not
// document leaves whether the provider can be used unstated, and the set
// stands as an upper bound, never as admitting nobody.
func (r *reading) state(f filed) string {
	state, how := r.text(f, "state", "", wholeGrant)
	switch {
	case how != present:
	case state == "DELETED":
		r.doubt(trust.Anomaly{Kind: ProviderDeleted, Construct: "state", Message: "the provider is soft-deleted; Google says soft-deleted providers are permanently deleted after approximately 30 days and can be restored until then, so the set stated is what the condition admits and is read as an upper bound", Source: "state"})
	case state != "ACTIVE" && state != "STATE_UNSPECIFIED":
		r.doubt(trust.Anomaly{Kind: trust.Unmodelled, Construct: printable(state), Message: "state is " + quote(state) + "; Google documents STATE_UNSPECIFIED, ACTIVE and DELETED, so whether the provider can be used to exchange tokens is not stated and the set stated is read as an upper bound", Source: "state"})
	}
	return state
}

// disabled reads the disabled flag. A disabled provider keeps its set,
// declared an upper bound: Google says existing tokens still grant
// access, one update re-enables it, and proven emptiness is the one
// output the lattice must never produce from a reversible flag.
func (r *reading) disabled(f filed) bool {
	v, how := r.member(f, "disabled", "", kindBool, wholeGrant)
	if how != present || !v.truth {
		return false
	}
	r.doubt(trust.Anomaly{Kind: ProviderDisabled, Construct: "disabled", Message: "the provider is disabled; Google says a disabled provider cannot be used to exchange tokens but existing tokens still grant access; the flag is set by an update and cleared by another, so the set stated is what the condition admits and is read as an upper bound", Source: "disabled"})
	return true
}

// oidc reads the oidc member: the issuer and the audience it constrains.
// The member is set, so it is never absent here; written twice or with
// the wrong type, it is not read and the audience is Unknown.
func (r *reading) oidc(f filed, name string, named presence) (*OIDC, trust.IssuerRef, eval.StringSet) {
	v, how := r.member(f, "oidc", "", kindObject, onAudience)
	if how != present {
		return nil, "", how.unknown()
	}
	inner := file(v, oidcSpellings)
	o := &OIDC{}
	var issuer trust.IssuerRef
	o.IssuerURI, issuer = r.issuerOf(inner)
	var aud eval.StringSet
	o.AllowedAudiences, aud = r.audience(inner, name, named)
	return o, issuer, aud
}

// issuerOf reads the issuer as written and normalises it to the registry
// key. An issuer that is absent or names no host is no issuer, which the
// Grant carries as "" with the fact stated. A scheme other than https,
// which Google says the issuer must have, and surrounding whitespace, which
// no documented issuer states in its iss, are read as the issuer they name
// once normalised, and recorded. That is not the wider of the two readings
// downstream: the join pairs a blank issuer with every counterparty and a
// named one with its own, so "" would pair more. It is chosen because the
// document names one host and no reading of it admits a token from
// another, which makes the named reading no narrower than Google, while a
// blank issuer would report a doubt about the scheme as the absence of an
// issuer; the anomaly is what keeps the named reading from passing as an
// unqualified trust, and it is the convention the Azure parser follows for
// the same defect. The issuer never caveats the admitted set: the set is
// what the document says, the issuer is what is doubtful.
func (r *reading) issuerOf(f filed) (written string, issuer trust.IssuerRef) {
	written, how := r.text(f, "issuerUri", "oidc.", labels)
	missing := func(message string) (string, trust.IssuerRef) {
		r.note(trust.Anomaly{Kind: MissingIssuer, Construct: "issuerUri", Message: message, Source: "oidc.issuerUri"})
		return written, ""
	}
	switch how {
	case absent:
		return missing("no issuerUri is set; Google requires one, so which identity provider this provider trusts is not stated")
	case present:
	default:
		return "", ""
	}
	trimmed := strings.TrimSpace(written)
	issuer, ok := trust.NormaliseIssuer(trimmed)
	if trimmed == "" || !ok {
		return missing("issuerUri " + quote(written) + " names no host, so which identity provider this provider trusts is not stated")
	}
	if trimmed != written {
		r.note(trust.Anomaly{Kind: IssuerWhitespace, Construct: "issuerUri", Message: "issuerUri " + quote(written) + " has leading or trailing whitespace; Google says the issuer must be an HTTPS endpoint, and it is read as the issuer it resembles with the whitespace removed", Source: "oidc.issuerUri"})
	}
	if !strings.HasPrefix(trimmed, "https://") {
		r.note(trust.Anomaly{Kind: IssuerScheme, Construct: "issuerUri", Message: "issuerUri " + quote(written) + " does not begin with https://; Google says the issuer must be an HTTPS endpoint, and it is read as the issuer it resembles", Source: "oidc.issuerUri"})
	}
	return written, issuer
}

// audienceCap bounds the audiences read from one list. The union of
// exact audiences costs eval a comparison per pair of members and a sort
// per Join, so a list long enough would take minutes to read. Google
// accepts at most ten, so the cap refuses nothing the API produces, and
// past it the audience widens to Unknown with the fact stated, never to a
// truncated union, which would under-approximate.
const audienceCap = 256

// googleAudienceLimit is Google's own bound: "A maximum of 10 audiences
// may be configured."
const googleAudienceLimit = 10

// audience is the aud constraint: the union of the audiences listed, the
// provider's own resource name when the list is empty, or Unknown when
// the list could not be read. An audience that is the empty string is
// Unknown on its own: no documented issuer mints a token whose aud is
// empty and Google does not say what the provider does with one, so
// Exact("") would report a provider as admitting nobody on a construct
// whose meaning is not stated; Unknown absorbs the rest under Join, which
// is the honest reading of a list that holds one.
func (r *reading) audience(f filed, name string, named presence) ([]string, eval.StringSet) {
	v, how := r.member(f, "allowedAudiences", "oidc.", kindList, onAudience)
	switch {
	case how == absent || (how == present && len(v.items) == 0):
		return nil, r.defaultAudience(name, named)
	case how != present:
		return nil, how.unknown()
	case len(v.items) > audienceCap:
		r.doubt(trust.Anomaly{Kind: AudienceCount, Claim: "aud", Construct: "allowedAudiences", Message: strconv.Itoa(len(v.items)) + " audiences are set; Google accepts at most " + strconv.Itoa(googleAudienceLimit) + " and this parser reads at most " + strconv.Itoa(audienceCap) + ", so aud is read as unconstrained", Source: "oidc.allowedAudiences"})
		return nil, eval.Unknown("too many audiences")
	}
	audiences := make([]string, 0, len(v.items))
	sets := make([]eval.StringSet, 0, len(v.items))
	for i, item := range v.items {
		at := "allowedAudiences[" + strconv.Itoa(i) + "]"
		if item.kind != kindString {
			r.doubt(trust.Anomaly{Kind: Malformed, Claim: "aud", Construct: "allowedAudiences", Message: "oidc." + at + " is " + item.kind.String() + "; Google defines allowedAudiences as a list of strings, so it is not read", Source: "oidc.allowedAudiences"})
			return nil, eval.Unknown("wrong type")
		}
		audiences = append(audiences, item.text)
		if item.text == "" {
			r.doubt(trust.Anomaly{Kind: trust.Unmodelled, Claim: "aud", Construct: "empty audience", Message: at + " is the empty string; no documented issuer mints a token whose aud is empty and Google does not say what the provider does with one, so aud is read as unconstrained", Source: "oidc.allowedAudiences"})
			sets = append(sets, eval.Unknown("empty audience"))
			continue
		}
		sets = append(sets, eval.Exact(item.text))
	}
	if len(audiences) > googleAudienceLimit {
		r.note(trust.Anomaly{Kind: AudienceCount, Claim: "aud", Construct: "allowedAudiences", Message: strconv.Itoa(len(audiences)) + " audiences are set; Google accepts at most " + strconv.Itoa(googleAudienceLimit) + ", so the provider is read as accepting any of them", Source: "oidc.allowedAudiences"})
	}
	return audiences, union(sets)
}

// canonicalNameForm is the shape of the names the API returns, with the
// project spelt by number, as both of Google's examples of the default
// audience spell it.
const canonicalNameForm = "projects/<number>/locations/<location>/workloadIdentityPools/<pool>/providers/<provider>"

// defaultAudience is the audience of a provider with no allowedAudiences:
// "the OIDC token audience must be equal to the full canonical resource
// name of the WorkloadIdentityPoolProvider, with or without the HTTPS
// prefix". The two forms are derived only from a name of the shape the
// API returns; a request body or a Terraform rendering may spell the
// project by ID, name nothing, or name something else, and an Exact on a
// string Google may not use would be narrower than Google, so aud is then
// Unknown with the reason stated.
func (r *reading) defaultAudience(name string, named presence) eval.StringSet {
	underivable := func(why string) eval.StringSet {
		r.doubt(trust.Anomaly{Kind: DefaultAudience, Claim: "aud", Construct: "allowedAudiences", Message: "allowedAudiences is empty and " + why + " and aud is read as unconstrained", Source: "oidc.allowedAudiences"})
		return eval.Unknown("default audience")
	}
	switch named {
	case absent:
		return underivable("no name is set, so the audience Google requires, the provider's full resource name, cannot be derived")
	case present:
	default:
		return underivable("the name is not read, so the audience Google requires, the provider's full resource name, cannot be derived")
	}
	if n, ok := parseProviderName(name); !ok || !n.numbered() {
		return underivable("name " + quote(name) + " is not of the form " + canonicalNameForm + ", so the audience Google requires cannot be derived")
	}
	with, without := "https://iam.googleapis.com/"+name, "//iam.googleapis.com/"+name
	r.note(trust.Anomaly{Kind: DefaultAudience, Claim: "aud", Construct: "allowedAudiences", Message: "allowedAudiences is empty, so Google requires the token audience to be the provider's full resource name, with or without the https prefix: " + quote(with) + " or " + quote(without), Source: "oidc.allowedAudiences"})
	return eval.Exact(with).Join(eval.Exact(without))
}

// aws reads the aws member: the account whose credentials the provider
// accepts, as the AWS parser's own claim. The member is set, so it is
// never absent here.
func (r *reading) aws(f filed) (*AWS, eval.StringSet) {
	v, how := r.member(f, "aws", "", kindObject, onAccount)
	if how != present {
		return nil, how.unknown()
	}
	inner := file(v, awsSpellings)
	account, how := r.text(inner, "accountId", "aws.", onAccount)
	switch how {
	case absent:
		r.doubt(trust.Anomaly{Kind: Malformed, Claim: accountClaim, Construct: "accountId", Message: "aws.accountId is not set; Google requires one, so which AWS account this provider trusts is not stated", Source: "aws.accountId"})
		return &AWS{}, eval.Unknown("account")
	case present:
	default:
		return &AWS{}, how.unknown()
	}
	return &AWS{AccountID: account}, eval.Exact(account)
}

// mapping reads attributeMapping into the entries a Provider reports, and
// sets on the resolver what each attribute resolves to when a condition or
// a binding names it. An entry whose key Google does not document, whose
// value is not a string, or that is written more than once is not read,
// and a reference to it cannot be attributed to a claim. For an AWS
// provider that maps nothing, Google's default mapping applies; for one
// whose mapping is written but not read, it does not: under a reader that
// applied the written mapping, the default would name the wrong claims.
func (r *reading) mapping(f filed, aws bool, res *resolver) map[string]string {
	v, how := r.member(f, "attributeMapping", "", kindObject, labels)
	switch {
	case how == absent || (how == present && len(v.members) == 0):
		if aws {
			res.mapping = defaultAWSMapping()
		}
		return nil
	case how != present:
		res.mappingUnread = true
		return nil
	}
	copies := map[string]int{}
	for _, m := range v.members {
		copies[m.name]++
	}
	entries := map[string]string{}
	resolved := map[string]mapped{}
	reported := map[string]bool{}
	for _, m := range v.members {
		key := m.name
		where := "attributeMapping." + printable(key)
		switch {
		case reported[key]:
			// A further copy of a key already reported: one fact is one
			// sentence.
		case !documentedAttribute(key):
			reported[key] = true
			r.note(trust.Anomaly{Kind: Malformed, Construct: printable(key), Message: "attributeMapping key " + quote(key) + " is not google.subject, google.groups or attribute.<name>, which are the keys Google documents, so it is not read", Source: where})
		case copies[key] > 1:
			reported[key] = true
			r.note(trust.Anomaly{Kind: DuplicateKey, Construct: printable(key), Message: "the member " + quote(key) + " is written " + strconv.Itoa(copies[key]) + " times; which one Google would apply is not stated, so it is not read", Source: where})
			resolved[key] = mapped{why: "the attribute mapping maps " + strconv.Itoa(copies[key]) + " times"}
		case m.value.kind == kindNull:
			// Unset, as proto3 JSON writes it.
		case m.value.kind != kindString:
			r.note(trust.Anomaly{Kind: Malformed, Construct: printable(key), Message: where + " is " + m.value.kind.String() + "; Google defines it as a string, so it is not read", Source: where})
			resolved[key] = mapped{why: "the attribute mapping maps by " + m.value.kind.String() + ", not a string"}
		default:
			entries[key] = m.value.text
			resolved[key] = mappedBy(m.value.text)
		}
	}
	if len(entries) == 0 {
		entries = nil
	}
	res.mapping = resolved
	return entries
}

// documentedAttribute reports whether a mapping key is one Google
// documents: google.subject, google.groups, or attribute.{custom_attribute}.
func documentedAttribute(key string) bool {
	if key == "google.subject" || key == "google.groups" {
		return true
	}
	name, custom := strings.CutPrefix(key, "attribute.")
	return custom && name != ""
}

// condition reads attributeCondition into the set it admits: everything,
// when the document sets none, which Google reads as "all valid
// authentication credential are accepted".
func (r *reading) condition(f filed, res resolver) (string, eval.AdmittedSet) {
	text, how := r.text(f, "attributeCondition", "", wholeGrant)
	if how != present {
		return text, eval.Everything()
	}
	return text, r.evaluate(text, res, "attributeCondition")
}

// canonical sorts the anomalies so that a reordered document reports the
// same list. Every fact recorded is kept: a fact dropped for resembling
// another would be silence.
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

// Grants is the one Grant the provider states: Allow for the target the
// collector read it from, with the provider's own bytes as Source. A
// provider whose issuer could not be read is still a Grant, with the
// issuer empty and the anomaly saying so; a provider that vanished from
// the report because its issuer could not be read would be silence.
//
// A Provider the parser did not produce, the zero value or one built by
// hand, states no Grant: there is no document behind it to quote, and the
// Grant its empty admitted set would make is an Allow that admits nothing,
// exactly and without a caveat, which is a proven emptiness the lattice
// would believe.
func (p Provider) Grants(target trust.TargetRef) []trust.Grant {
	if p.raw == nil {
		return nil
	}
	return []trust.Grant{{
		Target:    target,
		Issuer:    p.issuer,
		Admits:    p.admits,
		Effect:    trust.Allow,
		Anomalies: slices.Clone(p.Anomalies),
		Source:    slices.Clone(p.raw),
	}}
}

// resourceName is a provider's or a pool's full resource name taken
// apart. The API returns names with the project spelt by number; a
// request body or a Terraform rendering may spell it by ID, so the shape
// and the number are checked apart.
type resourceName struct {
	project, location, pool, provider string
}

// parseProviderName takes apart
// projects/<project>/locations/<location>/workloadIdentityPools/<pool>/providers/<provider>.
func parseProviderName(name string) (resourceName, bool) {
	parts := strings.Split(name, "/")
	if len(parts) != 8 || parts[6] != "providers" || parts[7] == "" {
		return resourceName{}, false
	}
	pool, ok := parsePoolName(strings.Join(parts[:6], "/"))
	pool.provider = parts[7]
	return pool, ok
}

// parsePoolName takes apart
// projects/<project>/locations/<location>/workloadIdentityPools/<pool>.
func parsePoolName(name string) (resourceName, bool) {
	parts := strings.Split(name, "/")
	if len(parts) != 6 || parts[0] != "projects" || parts[2] != "locations" || parts[4] != "workloadIdentityPools" || parts[1] == "" || parts[3] == "" || parts[5] == "" {
		return resourceName{}, false
	}
	return resourceName{project: parts[1], location: parts[3], pool: parts[5]}, true
}

// numbered reports whether the project is spelt by number, as the API
// spells it, rather than by ID.
func (n resourceName) numbered() bool {
	return n.project != "" && strings.Trim(n.project, "0123456789") == ""
}

// poolName is the pool's full resource name, the prefix a binding's
// member names it by.
func (n resourceName) poolName() string {
	return "projects/" + n.project + "/locations/" + n.location + "/workloadIdentityPools/" + n.pool
}
