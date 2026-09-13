package aws

import (
	"slices"
	"strconv"
	"strings"

	"github.com/CloudArq-net/cloudarq/internal/eval"
	"github.com/CloudArq-net/cloudarq/internal/trust"
)

// AWSPrincipalIssuer is the pseudo-issuer of every AWS principal: an
// account, a role, a user, a session, the anonymous "*". Their identity is
// minted by AWS STS rather than by an OIDC provider, and it reaches a trust
// policy through the aws:PrincipalArn family of keys, which are the claims
// of this issuer.
//
// It is not spelled as a URL on purpose. Every issuer a Federated
// principal can name comes out of NormaliseIssuer with an https scheme or
// is a SAML provider ARN, and a service's issuer begins with
// ServiceIssuerPrefix, so no Service or Federated principal can land on
// this issuer; a Deny on the service sts.amazonaws.com must never subtract
// from every account's grant.
const AWSPrincipalIssuer trust.IssuerRef = "aws:sts"

// ServiceIssuerPrefix begins the pseudo-issuer of an AWS service principal:
// "aws:service:" followed by the service's name, ASCII lower-cased because
// a service principal is a DNS name. A service is not an identity provider
// and has no URL of its own, and a Federated principal can spell any host,
// cognito-identity.amazonaws.com among the four built-in providers, so a
// service that took the https form of its name would share an issuer with
// the provider of the same name, and a Deny on the one would subtract from
// the other's grants.
const ServiceIssuerPrefix = "aws:service:"

// Principals is the statement's Principal element: every principal it
// names, in document order, or one unreadable principal when it names
// nobody this parser can read. A statement always projects at least one
// grant, because a principal that exists and produces no grant is the
// incumbents' bug one level up.
type Principals struct {
	list []principal
}

// nobody is the Principals of a statement whose principal could not be
// read: one unreadable principal, so that the statement still projects a
// grant. The findings that say why are recorded by the caller.
func nobody() Principals { return Principals{list: []principal{{kind: principalUnreadable}}} }

type principalKind int

const (
	// principalUnreadable names nobody this parser can read: NotPrincipal,
	// no Principal, a mis-shaped value, an unknown kind, a bad ARN. Its
	// grant has no issuer and admits everything, declared.
	principalUnreadable principalKind = iota
	// principalAnyone is "*" seen as every AWS principal, anonymous ones
	// included; principalAnyIssuer is the same "*" seen as every identity
	// whose issuer the statement does not name: every AWS service, and
	// every provider's tokens. One "*" is both, each assuming through its
	// own actions, so each projects its own grant.
	principalAnyone
	principalAnyIssuer
	principalAccount       // an AWS account, by bare id or root ARN
	principalIdentity      // an AWS role, user or federated-user session, by ARN
	principalOpaque        // an AWS principal whose ARN aws:PrincipalArn does not carry
	principalOIDC          // an OIDC provider, by ARN or by bare name
	principalSAML          // a SAML provider, by ARN
	principalService       // an AWS service
	principalCanonicalUser // an S3 canonical user id
)

// principal is one thing a statement trusts, resolved to what the grant
// needs: an issuer, the identifier its own condition keys start with, the
// account it belongs to, and what its parse found. A widening finding
// means the grant admits everything as far as this parser can prove.
type principal struct {
	kind       principalKind
	text       string
	issuer     trust.IssuerRef
	identifier string         // OIDC: the provider name as written, which its condition keys start with
	ident      string         // OIDC: the identifier ASCII case-folded, the way every key is compared
	wideIdent  string         // OIDC: the identifier under the widest folding, when it holds a letter ASCII folding cannot place; "" otherwise
	account    string         // AWS: the account id, when the text names one
	undecided  trust.ClaimKey // opaque: the identity claim the text leaves Unknown
	findings   findings
}

// unmodelled is a principal whose grant admits everything, declared by a.
func unmodelled(kind principalKind, text string, issuer trust.IssuerRef, a trust.Anomaly) principal {
	p := principal{kind: kind, text: text, issuer: issuer}
	p.findings.widen(a)
	return p
}

// parsePrincipals reads Principal, or NotPrincipal, which AWS does not
// support in a role trust policy and which names who is excluded rather
// than who is admitted. Both together, neither, or a NotPrincipal leave the
// statement unevaluated.
func parsePrincipals(named, excluded *memberGroup, src string, f *findings) Principals {
	noPrincipal := trust.Anomaly{Kind: trust.Unmodelled, Construct: "Principal", Message: "the statement names no Principal, so who may assume the role through it is not known", Source: src + ".Principal"}
	switch {
	case named != nil && excluded != nil:
		f.widen(trust.Anomaly{Kind: DuplicateKey, Construct: "Principal", Message: "the statement has both Principal and NotPrincipal; the IAM grammar allows one, so who it names is not known", Source: src})
		return nobody()
	case excluded != nil:
		if len(excluded.values) > 1 {
			f.note(duplicated(*excluded, "who it excludes is not known", src))
		}
		f.widen(trust.Anomaly{Kind: trust.Unmodelled, Construct: "NotPrincipal", Message: "NotPrincipal is not supported in a role trust policy and names who is excluded rather than who is admitted, so who the statement admits is not known", Source: src + ".Principal"})
		return nobody()
	case named == nil:
		f.widen(noPrincipal)
		return nobody()
	}
	if len(named.values) > 1 {
		f.widen(duplicated(*named, "every principal named in any copy is taken and who the statement names is not known", src))
	}
	var list []principal
	for _, v := range named.values {
		list = append(list, principalsIn(v, src+".Principal", f)...)
	}
	if len(list) == 0 {
		f.widen(noPrincipal)
		return nobody()
	}
	return Principals{list: list}
}

// principalsIn reads one Principal value: "*", or an object of principal
// kinds each holding a string or a list of strings. A kind this parser
// does not know, or a value of the wrong shape, is a principal it cannot
// read, beside the ones it can. A kind written twice names every
// principal in every copy, each doubted: a decoder keeps one copy, so
// whether any one of them is deployed is not known.
func principalsIn(v *value, src string, f *findings) []principal {
	if v.kind == kindString && v.text == "*" {
		return []principal{anyone(src)}
	}
	if v.kind != kindObject {
		f.widen(trust.Anomaly{Kind: Malformed, Construct: "Principal", Message: "Principal is " + describe(v) + `, not "*" or an object, so who it names is not known`, Source: src})
		return []principal{{kind: principalUnreadable}}
	}
	var out []principal
	for _, g := range groupMembers(v, exactName) {
		var found []principal
		switch g.name {
		case "AWS", "Federated", "Service", "CanonicalUser":
			for _, val := range g.values {
				// An empty list names nobody and is outside the grammar,
				// which gives a list one or more values; whether IAM deploys
				// the document as written is not known, so the grants
				// beside it are upper bounds.
				if val.kind == kindArray && len(val.items) == 0 {
					f.doubt(trust.Anomaly{Kind: Malformed, Construct: g.name, Message: "the " + g.name + " principal lists no principals; the IAM grammar requires at least one, so whether the statement deploys as written is not known", Source: src})
					continue
				}
				found = append(found, principalsOfKind(g.name, val, src)...)
			}
		default:
			found = []principal{unmodelled(principalUnreadable, "", "", trust.Anomaly{Kind: trust.Unmodelled, Construct: g.name, Message: "the principal kind " + strconv.QuoteToASCII(g.name) + " is not AWS, Federated, Service or CanonicalUser, so who it names is not known", Source: src})}
		}
		if len(g.values) > 1 {
			for i := range found {
				found[i].findings.doubt(trust.Anomaly{Kind: DuplicateKey, Construct: g.name, Message: "the member " + g.name + " appears more than once in Principal; a JSON decoder keeps one and the deployed policy may carry either, so whether this principal is deployed is not known", Source: src})
			}
		}
		out = append(out, found...)
	}
	return out
}

// principalsOfKind reads one principal kind's value, a string or a list of
// strings, item by item. Each principal's grant stands alone, so an item
// that is not a string costs only its own grant, which admits everything,
// declared, and the readable principals beside it keep theirs.
func principalsOfKind(kind string, v *value, src string) []principal {
	items, inList := []*value{v}, false
	if v.kind == kindArray {
		items, inList = v.items, true
	}
	out := make([]principal, 0, len(items))
	for _, item := range items {
		switch {
		case item.kind == kindString:
			out = append(out, principalOfKind(kind, item.text, src))
		case inList:
			out = append(out, unmodelled(principalUnreadable, "", "", trust.Anomaly{Kind: Malformed, Construct: kind, Message: "the " + kind + " principal lists " + describe(item) + " where a string is expected, so who it names is not known", Source: src}))
		default:
			out = append(out, unmodelled(principalUnreadable, "", "", trust.Anomaly{Kind: Malformed, Construct: kind, Message: "the " + kind + " principal is " + describe(item) + " where a string or a list of strings is expected, so who it names is not known", Source: src}))
		}
	}
	return out
}

// principalOfKind reads one principal string. A policy variable is refused
// before the kind is read: the 2012 language resolves it per request, so
// the text is not the spelling of any principal and must never be compared
// as one, whatever the document's Version says.
func principalOfKind(kind, text, src string) principal {
	if reference, ok := variableReference(text); ok {
		return unmodelled(principalUnreadable, text, "", trust.Anomaly{Kind: trust.Unmodelled, Construct: reference, Message: "the " + kind + " principal " + strconv.QuoteToASCII(text) + " holds the policy variable " + reference + "; a policy variable is resolved per request and names no principal this parser can read, so who it names is not known", Source: src})
	}
	switch kind {
	case "AWS":
		return awsPrincipal(text, src)
	case "Federated":
		return federatedPrincipal(text, src)
	case "Service":
		return servicePrincipal(text, src)
	}
	return unmodelled(principalCanonicalUser, text, AWSPrincipalIssuer, trust.Anomaly{Kind: trust.Unmodelled, Construct: "CanonicalUser", Message: "a CanonicalUser principal is not modelled by this parser, so who it names is not known", Source: src})
}

// variableReference is the first "${…}" in text, or "${" when the
// reference is unterminated, and whether there is one.
func variableReference(text string) (string, bool) {
	i := strings.Index(text, "${")
	if i < 0 {
		return "", false
	}
	rest := text[i:]
	if j := strings.Index(rest, "}"); j >= 0 {
		return rest[:j+1], true
	}
	return "${", true
}

func anyone(src string) principal {
	p := principal{kind: principalAnyone, text: "*", issuer: AWSPrincipalIssuer}
	p.findings.note(trust.Anomaly{Kind: AnyPrincipal, Construct: "Principal", Message: "the statement applies to every principal, including anonymous ones", Source: src})
	return p
}

// faces is what the principal projects to, src being where the Principal
// element was read. "*" is every AWS principal and every other identity
// at once, and they assume a role through different actions, so they are
// two grants: the AWS face on the pseudo-issuer, and a face with no
// issuer for the identities whose issuer the statement does not name,
// every AWS service through sts:AssumeRole and every provider's tokens
// through the federated actions, because which of them a bare "*"
// admits is not stated anywhere read. The second face exists only when
// the statement grants some assume action, or when its actions cannot be
// read; a face admitting nobody through an action the statement never
// names would say nothing, and its sentence names the actions it does.
// Every other principal is one face.
func (p principal) faces(actions ActionSet, src string) []principal {
	if p.kind != principalAnyone {
		return []principal{p}
	}
	var granted []string
	for _, action := range []string{assumeRole, assumeWithWebIdentity, assumeWithSAML} {
		if actions.unknown || actions.covers(action) {
			granted = append(granted, action)
		}
	}
	if len(granted) == 0 {
		return []principal{p}
	}
	whose := "AWS services and identity providers' tokens"
	switch {
	case len(granted) == 1 && granted[0] == assumeRole:
		whose = "AWS services"
	case !slices.Contains(granted, assumeRole):
		whose = "identity providers' tokens"
	}
	other := principal{kind: principalAnyIssuer, text: p.text, findings: p.findings.clone()}
	other.findings.widen(trust.Anomaly{Kind: trust.Unmodelled, Construct: "Principal", Message: "the statement applies to every principal, and which " + whose + " it covers through " + spellActions(granted) + " is not known", Source: src})
	return []principal{p, other}
}

// awsPrincipal reads an AWS principal. A bare account id and the account's
// root ARN mean the same thing, every principal in that account, and are
// kept as the account constraint rather than normalised into each other.
// A role or user ARN, and a federated-user session ARN, are the values
// aws:PrincipalArn carries for those callers and are kept as written. A
// role session ARN is not: the request context of a session carries the
// role's ARN, which the session ARN does not spell, so the account is the
// constraint and the ARN is Unknown. AWS stores a role or user ARN as a
// unique id and shows the id once the principal is deleted, so a string
// that is neither an id nor an ARN is exactly that case; it, and an ARN of
// another service, are Unknown too.
//
// An ARN that no documented principal has, a wildcard in it, a region, an
// account that is not an id, a resource that is not the root, a role or a
// user, is Unknown as well, with the account kept when the field holds
// one: what IAM does with such a value at save time is not stated, and
// read as a literal it claimed the policy trusts a role named "*",
// exactly, for a document that either does not deploy or, were the
// wildcard honoured, admits every role in the account.
func awsPrincipal(text, src string) principal {
	if text == "*" {
		return anyone(src)
	}
	if isAccountID(text) {
		return principal{kind: principalAccount, text: text, issuer: AWSPrincipalIssuer, account: text}
	}
	opaque := func(kind string, undecided trust.ClaimKey, account, message string) principal {
		p := principal{kind: principalOpaque, text: text, issuer: AWSPrincipalIssuer, account: account, undecided: undecided}
		p.findings.doubt(trust.Anomaly{
			Kind: kind, Claim: undecided, Construct: text,
			Message: "the AWS principal " + strconv.QuoteToASCII(text) + " " + message,
			Source:  src,
		})
		return p
	}
	fields, ok := arnFields(text)
	if !ok {
		return opaque(trust.Unmodelled, arnClaim, "", "is neither an account id nor an ARN; it may be the unique id of a principal that has been deleted, so who it names is not known")
	}
	partition, service, region, account, resource := fields[1], fields[2], fields[3], fields[4], fields[5]
	if service != "iam" && service != "sts" {
		return opaque(trust.Unmodelled, arnClaim, "", "is an ARN of a service other than IAM or STS, which names no principal this parser knows, so who it names is not known")
	}
	// A malformed ARN keeps its account when the field holds an id: under
	// every reading of the value, whatever it names lies in that account.
	inAccount := ""
	if isAccountID(account) {
		inAccount = account
	}
	malformed := func(message string) principal { return opaque(Malformed, arnClaim, inAccount, message) }
	switch {
	case strings.ContainsAny(text, "*?"):
		return malformed("holds a wildcard, which AWS documents cannot match part of a principal name or ARN, so who it names is not known")
	case partition == "":
		return malformed("has no partition, so who it names is not known")
	case region != "":
		return malformed("names a region, which an IAM or STS principal ARN never has, so who it names is not known")
	case account != "" && inAccount == "":
		return malformed("has " + strconv.QuoteToASCII(account) + " where a 12-digit account id belongs, so who it names is not known")
	case service == "iam" && resource == "root" && account == "":
		// Every principal of no account at all: the constraint the root
		// ARN stands for has nothing to hold, and dropping it would read
		// the ARN as everyone, exactly.
		return opaque(trust.Unmodelled, accountClaim, "", "is a root ARN with no account id, so which account it names is not known")
	case service == "iam" && resource == "root":
		return principal{kind: principalAccount, text: text, issuer: AWSPrincipalIssuer, account: account}
	}
	kind, name, _ := strings.Cut(resource, "/")
	named := name != ""
	if service == "iam" && !(named && (kind == "role" || kind == "user")) {
		return malformed("names no account root, role or user, which are the IAM principals AWS documents, so who it names is not known")
	}
	if account == "" {
		return malformed("has no account id, so who it names is not known")
	}
	identity := principal{kind: principalIdentity, text: text, issuer: AWSPrincipalIssuer, account: account}
	switch {
	case service == "iam", named && kind == "federated-user":
		return identity
	case named && kind == "assumed-role":
		return opaque(trust.Unmodelled, arnClaim, account, "is one session of a role in account "+account+"; aws:PrincipalArn holds the role's ARN, which the session ARN does not spell, so which identity of that account it names is not known")
	}
	return opaque(trust.Unmodelled, arnClaim, account, "is an STS ARN of a kind this parser does not know, so which identity of account "+account+" it names is not known")
}

func isAccountID(text string) bool {
	if len(text) != 12 {
		return false
	}
	for _, c := range text {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// arnFields splits an ARN into its six fields: arn, partition, service,
// region, account, resource. The resource keeps any colon of its own,
// which an OIDC provider with a port has. The partition is not checked, so
// GovCloud and China ARNs read like any other.
func arnFields(text string) ([]string, bool) {
	fields := strings.SplitN(text, ":", 6)
	if len(fields) != 6 || fields[0] != "arn" {
		return nil, false
	}
	return fields, true
}

// federatedPrincipal reads a Federated principal: an IAM provider ARN, or
// the bare name AWS documents for its built-in providers, and by the same
// rule any other bare name. The issuer is recovered with NormaliseIssuer
// so that it is the registry's key for the provider.
func federatedPrincipal(text, src string) principal {
	unreadable := func(kind, message string) principal {
		return unmodelled(principalUnreadable, text, "", trust.Anomaly{Kind: kind, Construct: "Federated", Message: "the Federated principal " + strconv.QuoteToASCII(text) + " " + message + ", so its issuer is not known", Source: src})
	}
	if !strings.HasPrefix(text, "arn:") {
		issuer, ok := providerIssuer(text)
		if !ok {
			return unreadable(Malformed, "is not a provider identifier")
		}
		return oidcPrincipal(text, text, issuer)
	}
	fields, ok := arnFields(text)
	if !ok || fields[2] != "iam" {
		return unreadable(Malformed, "is not an IAM provider ARN")
	}
	resource := fields[5]
	switch {
	case strings.HasPrefix(resource, "oidc-provider/"):
		identifier := strings.TrimPrefix(resource, "oidc-provider/")
		issuer, ok := providerIssuer(identifier)
		if !ok {
			return unreadable(Malformed, "names no provider")
		}
		return oidcPrincipal(text, identifier, issuer)
	case strings.HasPrefix(resource, "saml-provider/"):
		// IAM gives a SAML provider no URL, so the ARN is the only name it
		// has, and SAML assertions are not tokens this parser models.
		return unmodelled(principalSAML, text, trust.IssuerRef(text), trust.Anomaly{Kind: trust.Unmodelled, Construct: "SAML", Message: "SAML federation through " + strconv.QuoteToASCII(text) + " is not modelled by this parser, so which identities it admits is not known", Source: src})
	}
	return unreadable(trust.Unmodelled, "is neither an OIDC nor a SAML provider")
}

// providerIssuer recovers the issuer named by a provider identifier: a
// host, with a path or a port when the provider has one, in any case. A
// wildcard or whitespace names no provider.
func providerIssuer(identifier string) (trust.IssuerRef, bool) {
	if !namesAHost(identifier) {
		return "", false
	}
	return trust.NormaliseIssuer(identifier)
}

func namesAHost(text string) bool {
	return text != "" && !strings.ContainsAny(text, "* \t\n\r")
}

// oidcPrincipal keys its own condition keys by the provider name as
// written in the principal, not by the issuer: AWS forms the keys from
// the name as registered, and a provider registered from an issuer URL
// that ends in a slash keeps the slash, which the registry key drops. The
// name is folded the way every condition key is, because AWS matches keys
// without regard to case.
func oidcPrincipal(text, identifier string, issuer trust.IssuerRef) principal {
	p := principal{kind: principalOIDC, text: text, issuer: issuer, identifier: identifier, ident: fold(identifier)}
	if foldsBeyondASCII(identifier) {
		p.wideIdent = foldWide(identifier)
	}
	return p
}

// ownClaim reports whether key belongs to this OIDC principal, as the
// name after its identifier and a colon. The identifier may hold a colon
// of its own, a port, so every colon is a candidate split. The comparison
// folds ASCII case and nothing else, the folding AWS documents; a key
// that would match only under a wider folding holds a letter
// foldsBeyondASCII sees, or is placed by mayOwn, and is Unknown on that
// account whoever it would belong to.
func (p principal) ownClaim(key string) (string, bool) {
	if p.kind != principalOIDC {
		return "", false
	}
	for i := 0; i < len(key); i++ {
		if key[i] == ':' && fold(key[:i]) == p.ident {
			return fold(key[i+1:]), true
		}
	}
	return "", false
}

// mayOwn reports whether key would belong to this OIDC principal under
// the widest folding AWS could apply when it does not under the ASCII
// one: the identifier holds a letter outside ASCII with case variants,
// and the key spells it another way. Which reading AWS takes is not
// documented, so such a key is Unknown rather than another provider's.
func (p principal) mayOwn(key string) bool {
	if p.wideIdent == "" {
		return false
	}
	for i := 0; i < len(key); i++ {
		if key[i] == ':' && foldWide(key[:i]) == p.wideIdent {
			return true
		}
	}
	return false
}

// servicePrincipal reads a Service principal onto the service's own
// pseudo-issuer. The name is ASCII lower-cased because a service
// principal is a DNS name; a wildcard, which the principal page rules out
// for a service, or whitespace names no service.
func servicePrincipal(text, src string) principal {
	if !namesAHost(text) {
		return unmodelled(principalUnreadable, text, "", trust.Anomaly{Kind: Malformed, Construct: "Service", Message: "the Service principal " + strconv.QuoteToASCII(text) + " is not a service identifier, so which service it names is not known", Source: src})
	}
	p := principal{kind: principalService, text: text, issuer: trust.IssuerRef(ServiceIssuerPrefix + fold(text))}
	p.findings.note(trust.Anomaly{Kind: ServicePrincipal, Construct: "Service", Message: text + " is an AWS service principal, not an external identity", Source: src})
	return p
}

// The actions a principal assumes a role through, lower-cased for matching
// and spelled as AWS spells them for printing.
const (
	assumeRole            = "sts:assumerole"
	assumeWithWebIdentity = "sts:assumerolewithwebidentity"
	assumeWithSAML        = "sts:assumerolewithsaml"
)

var actionSpelling = map[string]string{
	assumeRole:            "sts:AssumeRole",
	assumeWithWebIdentity: "sts:AssumeRoleWithWebIdentity",
	assumeWithSAML:        "sts:AssumeRoleWithSAML",
}

// assumeActions lists the actions through which a principal of this kind
// can assume the role. A principal this parser cannot read or does not
// model could use any.
func (p principal) assumeActions() []string {
	switch p.kind {
	case principalOIDC:
		return []string{assumeWithWebIdentity}
	case principalSAML:
		return []string{assumeWithSAML}
	case principalAnyIssuer, principalUnreadable, principalCanonicalUser:
		return []string{assumeRole, assumeWithWebIdentity, assumeWithSAML}
	}
	return []string{assumeRole}
}

// spellActions renders an action list for a sentence: "a", "a or b",
// "a, b or c".
func spellActions(actions []string) string {
	spelled := make([]string, len(actions))
	for i, a := range actions {
		spelled[i] = actionSpelling[a]
	}
	if len(spelled) == 1 {
		return spelled[0]
	}
	return strings.Join(spelled[:len(spelled)-1], ", ") + " or " + spelled[len(spelled)-1]
}

// The claims of the pseudo-issuer that a principal itself constrains: the
// aws:PrincipalArn and aws:PrincipalAccount keys, lower-cased.
const (
	arnClaim     trust.ClaimKey = "aws:principalarn"
	accountClaim trust.ClaimKey = "aws:principalaccount"
)

// identity is the constraint the principal itself places on the claims of
// the pseudo-issuer, as the Term the conditions are met into. For an OIDC
// provider the principal names the issuer and nothing more; the
// conditions say which of its identities are admitted. An opaque
// principal leaves one identity claim Unknown, declared by the doubt its
// parse recorded.
func (p principal) identity() eval.Term {
	term := eval.Term{}
	if p.account != "" {
		term[accountClaim] = eval.Exact(p.account)
	}
	switch p.kind {
	case principalIdentity:
		term[arnClaim] = eval.Exact(p.text)
	case principalOpaque:
		term[p.undecided] = eval.Unknown(p.text)
	}
	return term
}

// awsIdentity reports whether the principal's identity is what AWS's own
// principal keys describe, so that those keys are claims rather than
// facts about the request.
func (p principal) awsIdentity() bool {
	switch p.kind {
	case principalAnyone, principalAccount, principalIdentity, principalOpaque:
		return true
	}
	return false
}
