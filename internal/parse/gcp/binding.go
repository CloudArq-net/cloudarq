package gcp

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"

	"github.com/CloudArq-net/cloudarq/internal/eval"
	"github.com/CloudArq-net/cloudarq/internal/trust"
)

// Member is one member of an IAM binding, as ParseMembers reads it. Text
// is the member as written. A workload identity pool principal is taken
// apart into the pool it names and what it selects from the pool; every
// other member, a user, a group, a service account, a workforce pool
// principal, keeps Text alone, so that a member this parser does not
// model still appears in the list rather than vanishing from it.
type Member struct {
	Text      string
	Role      string
	Condition string // the binding's condition expression, "" when it has none
	Pool      string // projects/<project>/locations/<location>/workloadIdentityPools/<pool>, the fixed text in Google's spelling and the values as written; "" when Text is not a workload identity pool principal
	Selector  string // what follows the pool: subject/<value>, attribute.<name>/<value>, group/<value>, *, a form Google does not document, or ""
	Attribute string // google.subject, attribute.<name> or google.groups when Selector is one of the three documented forms that name a value
	Value     string // the value the selector names
	Resource  string // the resource the policy is set on, as a Cloud Asset search result names it; "" for a policy handed over alone

	form     memberForm
	spelling resemblance
	binding  string // bindings[i]
	source   string // bindings[i].members[j]
	raw      []byte // the binding's own bytes
}

// resemblance is how a member's fixed text, the scheme, the host and the
// segments projects, locations and workloadIdentityPools, matches the text
// Google prints: exactly when neither flag is set, or in a way the pages
// do not settle, a piece spelt in another ASCII case or holding a percent
// escape. RFC 3986 makes a scheme case-insensitive and lets a host hold
// percent-encoding, so both spellings exist for a URL; whether IAM reads a
// principal identifier as one is what is not stated.
type resemblance struct {
	miscased bool
	escaped  bool
}

// matches reports whether a piece of fixed text is the one Google prints
// under some reading, recording the reading it needs. A percent escape is
// never decoded (see Bind), so a piece holding one is undecided against
// any text; a piece that differs otherwise is another piece under every
// reading.
func (r *resemblance) matches(got, want string) bool {
	switch {
	case got == want:
		return true
	case strings.Contains(got, "%"):
		r.escaped = true
		return true
	case equalFoldASCII(got, want):
		r.miscased = true
		return true
	}
	return false
}

// memberForm is which of the forms Google documents a pool member takes.
// The scheme is part of the form: a subject is selected by principal://,
// the other three by principalSet://, and a selector under the other
// scheme is a form Google does not document, as is an empty or absent
// selector. A selector whose kind, the text before its first slash, holds
// a percent escape has no form as written and, decoded, may have any: it
// is kept apart from the undocumented forms so that the sentence about it
// names the escape, though both are read as the whole pool.
type memberForm int

const (
	formUndocumented memberForm = iota
	formEscaped                 // a percent escape where the form is named
	formSubject                 // principal://…/subject/<value>
	formAttribute               // principalSet://…/attribute.<name>/<value>
	formGroup                   // principalSet://…/group/<value>
	formPool                    // principalSet://…/*
)

// ParseMembers reads an IAM policy into the members of its bindings in
// document order, each with its role and the binding's condition. The
// policy may come alone, as getIamPolicy returns it; inside one result of
// Cloud Asset's searchAllIamPolicies, under "policy" beside the resource
// the policy is set on, which the query policy:principalSet is the way to
// find every binding on a pool; or in a page of such results. A policy
// with no bindings has no members, and a search result's policy holds
// only the bindings that matched the query. A page that carries a
// nextPageToken is refused, so that a policy on a later page never reads
// as absent. An error otherwise means the input is none of the three: not
// one JSON value in valid UTF-8, not an object, an object in none of the
// shapes or in two of them at once, or a member written twice or with a
// type the API does not define; a member that could not be read would
// otherwise vanish from the list, and a member that vanishes is silence.
func ParseMembers(policy []byte) ([]Member, error) {
	members, err := parseMembers(policy)
	if err != nil {
		return nil, fmt.Errorf("IAM policy: %w", err)
	}
	return members, nil
}

// The members that mark each shape, under the two spellings proto3 JSON
// accepts, and the documented name each spells. An object with none of
// them, other than the empty object, is refused: a shape this parser does
// not know read as a policy with no bindings would be silence about every
// binding it holds.
var (
	policyMarks = spellings{"version": "version", "bindings": "bindings", "auditConfigs": "auditConfigs", "audit_configs": "auditConfigs", "etag": "etag"}
	resultMarks = spellings{"resource": "resource", "assetType": "assetType", "asset_type": "assetType", "project": "project", "folders": "folders", "organization": "organization", "policy": "policy", "explanation": "explanation"}
	pageMarks   = spellings{"results": "results", "nextPageToken": "nextPageToken", "next_page_token": "nextPageToken"}
)

func parseMembers(policy []byte) ([]Member, error) {
	root, err := readDocument(policy)
	if err != nil {
		return nil, err
	}
	if root.kind != kindObject {
		return nil, fmt.Errorf("the document is %s, not an IAM policy", root.kind)
	}
	for _, marks := range []spellings{policyMarks, resultMarks, pageMarks} {
		if err := exactlySpelt(root, marks); err != nil {
			return nil, err
		}
	}
	isPolicy, isResult, isPage := marked(root, policyMarks), marked(root, resultMarks), marked(root, pageMarks)
	switch {
	case isPolicy && isResult, isPolicy && isPage, isResult && isPage:
		return nil, errors.New("the document carries the members of both a policy and a policy search result or a page of results, so it is neither")
	case isResult:
		return searchResult(root, "")
	case isPage:
		token, err := only(root, "nextPageToken", kindString, "")
		if err != nil {
			return nil, err
		}
		if token != nil && token.text != "" {
			return nil, errors.New("the page carries a nextPageToken, so there are policies this document does not hold; read every page")
		}
		results, err := only(root, "results", kindList, "")
		if err != nil || results == nil {
			return nil, err
		}
		var members []Member
		for i, item := range results.items {
			where := "results[" + strconv.Itoa(i) + "]"
			if item.kind != kindObject {
				return nil, fmt.Errorf("%s is %s, not a policy search result", where, item.kind)
			}
			if !marked(item, resultMarks) {
				return nil, errors.New(where + " is not a policy search result: none of " + strings.Join(documented(resultMarks), ", "))
			}
			found, err := searchResult(item, where+".")
			if err != nil {
				return nil, err
			}
			members = append(members, found...)
		}
		return members, nil
	case isPolicy || len(root.members) == 0:
		return bindingsOf(root, "")
	}
	return nil, errors.New("the document is not an IAM policy, a policy search result or a page of results: none of " + strings.Join(slices.Concat(documented(policyMarks), documented(resultMarks), documented(pageMarks)), ", "))
}

// marked reports whether an object writes at least one of the members that
// mark a shape.
func marked(v *value, marks spellings) bool {
	return slices.ContainsFunc(v.members, func(m member) bool { _, ok := marks[m.name]; return ok })
}

// documented lists the names a shape's members are documented under, once
// each, in name order.
func documented(marks spellings) []string {
	return slices.Compact(slices.Sorted(maps.Values(marks)))
}

// exactlySpelt refuses an object with a member that matches a shape's
// member only in ASCII case: read as another member it would drop a
// policy without a trace, and read as the member it resembles it would be
// a guess about the API.
func exactlySpelt(v *value, marks spellings) error {
	for _, m := range v.members {
		if near, ok := resembles(m.name, marks); ok {
			return fmt.Errorf("the member %s differs from %s only in case, so the document is not read", quote(m.name), quote(near))
		}
	}
	return nil
}

// searchResult reads one IamPolicySearchResult: the policy under "policy",
// each member carrying the resource the policy is set on. where prefixes
// the sources of the members, for a result inside a page.
func searchResult(v *value, where string) ([]Member, error) {
	policy, err := only(v, "policy", kindObject, strings.TrimSuffix(where, "."))
	if err != nil || policy == nil {
		return nil, err
	}
	resource, err := only(v, "resource", kindString, strings.TrimSuffix(where, "."))
	if err != nil {
		return nil, err
	}
	members, err := bindingsOf(policy, where+"policy.")
	for i := range members {
		members[i].Resource = textOf(resource)
	}
	return members, err
}

// bindingsOf reads the bindings of one policy object. where prefixes the
// sources of the members: "" for a policy handed over alone.
func bindingsOf(policy *value, where string) ([]Member, error) {
	bindings, err := only(policy, "bindings", kindList, strings.TrimSuffix(where, "."))
	if err != nil || bindings == nil {
		return nil, err
	}
	var members []Member
	for i, b := range bindings.items {
		at := where + "bindings[" + strconv.Itoa(i) + "]"
		if b.kind != kindObject {
			return nil, fmt.Errorf("%s is %s, not a binding", at, b.kind)
		}
		role, err := only(b, "role", kindString, at)
		if err != nil {
			return nil, err
		}
		list, err := only(b, "members", kindList, at)
		if err != nil {
			return nil, err
		}
		condition, err := only(b, "condition", kindObject, at)
		if err != nil {
			return nil, err
		}
		var expression *value
		if condition != nil {
			if expression, err = only(condition, "expression", kindString, at+".condition"); err != nil {
				return nil, err
			}
		}
		if list == nil {
			continue
		}
		for j, item := range list.items {
			source := at + ".members[" + strconv.Itoa(j) + "]"
			if item.kind != kindString {
				return nil, fmt.Errorf("%s is %s, not a string", source, item.kind)
			}
			m := parseMember(item.text)
			m.Role, m.Condition = textOf(role), textOf(expression)
			m.binding, m.source, m.raw = at, source, slices.Clone(b.raw)
			members = append(members, m)
		}
	}
	return members, nil
}

// only is the one value written under a member, by its documented name or
// its proto spelling, nil when the member is absent or null. A member
// written twice, the two spellings counted together, or with a type the
// API does not define for it, is an error: a policy read either way could
// drop a member or a condition without a trace. where names the object
// for the sentence, "" for the document itself.
func only(v *value, name string, want kind, where string) (*value, error) {
	var found []*value
	for _, m := range v.members {
		if m.name == name || policyMarks[m.name] == name || resultMarks[m.name] == name || pageMarks[m.name] == name {
			found = append(found, m.value)
		}
	}
	of := ""
	if where != "" {
		of = " of " + where
	}
	switch {
	case len(found) > 1:
		return nil, fmt.Errorf("the member %s%s is written %d times", quote(name), of, len(found))
	case len(found) == 0 || found[0].kind == kindNull:
		return nil, nil
	case found[0].kind != want:
		return nil, fmt.Errorf("the member %s%s is %s, not %s", quote(name), of, found[0].kind, policyTypes[want])
	}
	return found[0], nil
}

// policyTypes names the type an IAM policy gives a member, for the error
// about one written with another.
var policyTypes = map[kind]string{kindString: "a string", kindList: "a list", kindObject: "an object"}

func textOf(v *value) string {
	if v == nil {
		return ""
	}
	return v.text
}

// The fixed text of a workload identity pool principal, as Google prints
// it: the two schemes, the host, and the segments around the values.
const (
	principalScheme    = "principal"
	principalSetScheme = "principalSet"
	principalHost      = "iam.googleapis.com"
)

// parseMember takes a member apart when it is a workload identity pool
// principal in one of the forms Google documents:
//
//	principal://iam.googleapis.com/projects/P/locations/L/workloadIdentityPools/POOL/subject/VALUE
//	principalSet://iam.googleapis.com/projects/P/locations/L/workloadIdentityPools/POOL/group/VALUE
//	principalSet://iam.googleapis.com/projects/P/locations/L/workloadIdentityPools/POOL/attribute.NAME/VALUE
//	principalSet://iam.googleapis.com/projects/P/locations/L/workloadIdentityPools/POOL/*
//
// or resembles one: the scheme, the host and the segments projects,
// locations and workloadIdentityPools are Google's own text, and a member
// that spells any of them in another ASCII case, or with a percent escape,
// names the same pool under a reading the pages do not settle, which is
// kept on the member for Bind to state. The scheme alone is matched by
// case and never by escape: RFC 3986 defines a scheme as letters, digits,
// "+", "-" and ".", with no percent-encoding, so text holding "%" before
// "://" is no scheme. The segments that carry values, the project, the
// location, the pool and the selector, are kept as written, percent
// escapes included, for Bind to weigh; a value segment left empty names
// no pool. A selector on the pool that is none of the four forms, or is
// absent, keeps the pool and the selector with no attribute; a member that
// names no pool under any reading keeps its text alone.
func parseMember(text string) Member {
	m := Member{Text: text}
	scheme, rest, ok := strings.Cut(text, "://")
	if !ok {
		return m
	}
	var set bool
	switch {
	case scheme == principalScheme, scheme == principalSetScheme:
		set = scheme == principalSetScheme
	case equalFoldASCII(scheme, principalScheme), equalFoldASCII(scheme, principalSetScheme):
		set, m.spelling.miscased = len(scheme) == len(principalSetScheme), true
	default:
		return m
	}
	host, path, _ := strings.Cut(rest, "/")
	parts := strings.SplitN(path, "/", 7)
	if len(parts) < 6 {
		return Member{Text: text}
	}
	// A piece that matched before one that did not may have left a flag
	// on m, so a member that names no pool is returned afresh.
	fixed := [...]struct{ got, want string }{{host, principalHost}, {parts[0], "projects"}, {parts[2], "locations"}, {parts[4], "workloadIdentityPools"}}
	for _, piece := range fixed {
		if !m.spelling.matches(piece.got, piece.want) {
			return Member{Text: text}
		}
	}
	pool := resourceName{project: parts[1], location: parts[3], pool: parts[5]}
	if pool.project == "" || pool.location == "" || pool.pool == "" {
		return Member{Text: text}
	}
	m.Pool = pool.poolName()
	if len(parts) == 7 {
		m.Selector = parts[6]
	}
	kind, value, _ := strings.Cut(m.Selector, "/")
	switch {
	case strings.Contains(kind, "%"):
		m.form = formEscaped
	case set && m.Selector == "*":
		m.form = formPool
	case !set && kind == "subject" && value != "":
		m.form, m.Attribute, m.Value = formSubject, "google.subject", value
	case set && kind == "group" && value != "":
		m.form, m.Attribute, m.Value = formGroup, "google.groups", value
	case set && strings.HasPrefix(kind, "attribute.") && kind != "attribute." && value != "":
		m.form, m.Attribute, m.Value = formAttribute, kind, value
	}
	return m
}

// Bind is the grant a binding's member gives the identities of this
// provider on the target, typically a service account under
// roles/iam.workloadIdentityUser: the Meet of what the provider admits
// with what the member selects, carrying both documents' facts and both
// documents' bytes. It is false when the member is not a binding on this
// provider: it is not a workload identity pool principal under any
// reading, a user, a service account, a workforce pool principal, or it
// names another pool; and when the Provider or the Member is not one the
// parser produced, since there is no document behind either to quote.
//
// A member on a subject or an attribute is resolved through the
// provider's attribute mapping exactly as a condition on the same name
// is, and a member the mapping cannot attribute to a claim admits the
// whole pool with the reason stated: Google's own default mapping for AWS
// providers maps attribute.aws_role by an expression, so a member on it is
// the common binding for such a provider, and a Term keyed on the mapping
// text would admit nobody.
//
// Every form the pages do not settle is read as the widest thing it may
// be, with the doubt stated, so that a binding that may exist never reads
// as absent. A member that selects from the pool by a form Google
// documents for no workload identity pool, or for the GKE pool alone,
// namespace/NAMESPACE, a subject under principalSet://, a star under
// principal://, an empty or absent selector, is read as the whole pool:
// whether IAM accepts it and what it would select are not stated, and the
// union of every reading is at most the pool. A member whose fixed text
// is Google's only under a reading the pages do not give, another ASCII
// case or a percent escape, is read as the principal it resembles. A
// principal identifier is URL-path text, and whether Google decodes
// percent escapes in one is not documented on the pages read, so an
// escape is never decoded and never compared as written either: in the
// fixed text it leaves whether the member is a pool principal undecided;
// in the pool it leaves whether the member names this provider's pool
// undecided, and the member is read as binding it; in the selector's kind
// it leaves the form undecided, and the member is read as the whole pool;
// in a value it leaves the claim Unknown.
func (p Provider) Bind(m Member, target trust.TargetRef) (trust.Grant, bool) {
	if p.raw == nil || m.raw == nil || m.Pool == "" {
		return trust.Grant{}, false
	}
	r := &reading{}
	if !p.samePool(r, m) {
		return trust.Grant{}, false
	}
	r.respelt(m)
	admits := meetTerm(p.admits, r.selected(p.resolver, m))
	if m.Condition != "" {
		r.doubt(trust.Anomaly{Kind: trust.Unmodelled, Construct: "condition", Message: "the binding carries the condition " + quote(m.Condition) + ", which this parser does not evaluate; the grant is read as if the binding applied unconditionally", Source: m.binding + ".condition"})
	}
	for _, c := range r.caveats {
		admits = admits.WithCaveat(c)
	}
	return trust.Grant{
		Target:    target,
		Issuer:    p.issuer,
		Admits:    admits,
		Effect:    trust.Allow,
		Anomalies: canonical(slices.Concat(p.Anomalies, r.anomalies)),
		Source:    slices.Concat([]byte(`{"provider": `), p.raw, []byte(`, "binding": `), m.raw, []byte(`}`)),
	}, true
}

// samePool reports whether the member's pool is this provider's. Names
// compare segment by segment, and a segment of the member's that holds a
// percent escape compares under neither reading; a project spelt by
// number on one side and by ID on the other cannot be told apart from
// these two documents alone either. A member whose pool differs in no
// segment and is undecided in one is read as binding this provider, the
// wide reading, with the doubt stated. The provider's own name is compared
// as written: Google returns it, and a document that spells it with an
// escape carries a name that is not Google's. A provider whose name is not
// of the form the API returns cannot be placed in any pool, and every
// member is read as binding it, again with the doubt stated.
func (p Provider) samePool(r *reading, m Member) bool {
	provider, ok := parseProviderName(p.Name)
	if !ok {
		r.doubt(trust.Anomaly{Kind: trust.Unmodelled, Construct: "name", Message: "the provider has no name of the form " + canonicalNameForm + ", so whether the member's pool " + quote(m.Pool) + " is this provider's is not stated; the binding is read as applying to this provider", Source: "name"})
		return true
	}
	member, _ := parsePoolName(m.Pool)
	switch {
	case differs(provider.location, member.location), differs(provider.pool, member.pool):
		return false
	case differs(provider.project, member.project) && provider.numbered() == member.numbered():
		return false
	case strings.Contains(m.Pool, "%"):
		r.doubt(trust.Anomaly{Kind: trust.Unmodelled, Construct: "%", Message: "the member names the pool " + quote(m.Pool) + ", which contains \"%\"" + percentDoubt + "whether it is the provider's pool " + quote(provider.poolName()) + " is not stated and the binding is read as applying to this provider", Source: m.source})
	case provider.project != member.project:
		r.doubt(trust.Anomaly{Kind: trust.Unmodelled, Construct: "pool", Message: "the member names the pool " + quote(m.Pool) + " and the provider " + quote(provider.poolName()) + "; whether they are the same project is not stated, so the binding is read as applying to this provider", Source: m.source})
	}
	return true
}

// differs reports whether a segment of the member's pool name is another
// than the provider's under every reading: the two are not the same text
// and the member's holds no percent escape, which decoded could spell the
// provider's.
func differs(provider, member string) bool {
	return provider != member && !strings.Contains(member, "%")
}

// percentDoubt is the middle of every sentence about a percent escape in
// a principal identifier: the fact the pages read do not settle.
const percentDoubt = "; whether Google decodes percent escapes in a principal identifier is not documented, so "

// fixedText names, for a sentence, the pieces of a principal identifier
// that are Google's own text rather than a value.
const fixedText = "the host iam.googleapis.com or the segments projects, locations and workloadIdentityPools"

// respelt records how the member's fixed text differs from Google's
// spelling, one fact per way it differs. The doubt is on the whole grant:
// it is the binding's existence that is undecided, not a claim.
func (r *reading) respelt(m Member) {
	if m.spelling.escaped {
		r.doubt(trust.Anomaly{Kind: trust.Unmodelled, Construct: "%", Message: "the member " + quote(m.Text) + " holds a percent escape in " + fixedText + percentDoubt + "whether it is a workload identity pool principal at all is not stated and it is read as the principal it resembles", Source: m.source})
	}
	if m.spelling.miscased {
		r.doubt(trust.Anomaly{Kind: trust.Unmodelled, Construct: "spelling", Message: "the member " + quote(m.Text) + " spells the scheme, " + fixedText + " in another case than Google prints it; whether Google reads it as a workload identity pool principal is not stated, so it is read as the principal it resembles", Source: m.source})
	}
}

// documentedForms ends every sentence about a selector Google does not
// document: what Google does document, and the reading that follows.
const documentedForms = "for a workload identity pool Google documents subject/VALUE under principal://, and group/VALUE, attribute.NAME/VALUE and * under principalSet://, and no other form, so whether Google accepts the member, and which identities it selects, is not stated; the whole pool is read as admitted"

// selected is what the member selects from the pool, as a conjunction
// to meet into the provider's set: nothing further for the whole pool,
// one value of the claim an attribute maps to, or, where the value cannot
// be attributed to a claim or the form cannot be read, nothing further
// with the doubt stated. The construct of an undocumented form is the
// selector's kind, the text before its first slash, so that a reporter
// counts members by the form rather than by the value; a selector with no
// kind is named whole, and an absent one by a phrase.
func (r *reading) selected(res resolver, m Member) eval.Term {
	switch m.form {
	case formPool:
		return nil
	case formEscaped:
		r.doubt(trust.Anomaly{Kind: trust.Unmodelled, Construct: "%", Message: "the member selects from the pool by " + quote(m.Selector) + ", which contains \"%\"" + percentDoubt + "which identities it selects is not stated and the whole pool is read as admitted", Source: m.source})
		return nil
	case formUndocumented:
		kind, _, _ := strings.Cut(m.Selector, "/")
		construct, by := printable(kind), "selects from the pool by "+quote(m.Selector)
		switch {
		case m.Selector == "":
			construct, by = "no selector", "names the pool and selects nothing from it"
		case kind == "":
			construct = printable(m.Selector)
		}
		r.doubt(trust.Anomaly{Kind: trust.Unmodelled, Construct: construct, Message: "the member " + by + "; " + documentedForms, Source: m.source})
		return nil
	}
	root, field, _ := strings.Cut(m.Attribute, ".")
	claim, failed := res.resolve(reference{root: root, field: field})
	if failed != nil {
		selects := "the member selects " + m.Attribute + " " + quote(m.Value)
		switch failed.about {
		case theProvider:
			r.doubt(trust.Anomaly{Kind: trust.Unmodelled, Construct: failed.construct, Message: selects + ", but " + failed.why + ", so nothing it says about the credential is modelled", Source: m.source})
		case theUnreadMapping:
			r.doubt(trust.Anomaly{Kind: trust.Unmodelled, Construct: failed.construct, Message: selects + ", but " + failed.why + ", so which claim the member constrains is not stated and the whole pool is read as admitted", Source: m.source})
		default:
			r.doubt(trust.Anomaly{Kind: trust.Unmodelled, Construct: failed.construct, Message: selects + ", which " + failed.why + ", so which claim the member constrains is not stated and the whole pool is read as admitted", Source: m.source})
		}
		return nil
	}
	switch {
	case m.form == formGroup:
		r.doubt(trust.Anomaly{Kind: trust.Unmodelled, Claim: claim, Construct: "group", Message: "the member selects the group " + quote(m.Value) + " of google.groups, which maps to the claim " + string(claim) + "; a list-valued claim is outside what this parser models, so " + string(claim) + " is read as unconstrained", Source: m.source})
		return eval.Term{claim: eval.Unknown("group membership")}
	case strings.Contains(m.Value, "%"):
		r.doubt(trust.Anomaly{Kind: trust.Unmodelled, Claim: claim, Construct: "%", Message: "the member's value " + quote(m.Value) + " contains \"%\"" + percentDoubt + "the value is not read and " + string(claim) + " is read as unconstrained", Source: m.source})
		return eval.Term{claim: eval.Unknown("percent escape")}
	case claim == res.subject() && len(m.Value) > subjectLimit:
		kind, _, _ := strings.Cut(m.Selector, "/")
		r.doubt(trust.Anomaly{Kind: SubjectLength, Claim: claim, Construct: kind, Message: "the member selects " + m.Attribute + " " + quote(m.Value) + ", which is " + strconv.Itoa(len(m.Value)) + " bytes long" + subjectLimitDoubt(claim, "that value"), Source: m.source})
	}
	return eval.Term{claim: eval.Exact(m.Value)}
}
