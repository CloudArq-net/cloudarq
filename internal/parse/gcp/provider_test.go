package gcp

import (
	"encoding/json"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/CloudArq-net/cloudarq/internal/eval"
	"github.com/CloudArq-net/cloudarq/internal/parse/aws"
	"github.com/CloudArq-net/cloudarq/internal/trust"
)

// providersDir holds one document per row of the Pass 1 table, each with
// a sibling rationale. Loaded by tests only; the package reads no files.
const providersDir = "../../../testdata/providers"

const (
	github         trust.IssuerRef = "https://token.actions.githubusercontent.com"
	audienceName                   = "https://iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/github/providers/github"
	audience                       = `aud="` + audienceName + `"`
	mainBranch                     = "repo:acme/infra:ref:refs/heads/main"
	main                           = `sub="` + mainBranch + `"`
	anyBranch                      = `sub=like:"repo:acme/infra:*"`
	providerName                   = "projects/123456789012/locations/global/workloadIdentityPools/github/providers/github"
	awsProviderRaw                 = `{"aws": {"accountId": "123456789012"}}`
	awsRoleText                    = "assertion.arn.contains('assumed-role') ? assertion.arn.extract('{account_arn}assumed-role/') + 'assumed-role/' + assertion.arn.extract('assumed-role/{role_name}/') : assertion.arn"
)

var (
	githubProvider = trust.TargetRef{Kind: "workloadIdentityPoolProvider", ID: providerName}
	deployAccount  = trust.TargetRef{Kind: "serviceAccount", ID: "deploy@acme-prod.iam.gserviceaccount.com"}
)

// fact is an expected anomaly, and whether it also caveats the admitted set.
type fact struct {
	anomaly trust.Anomaly
	doubt   bool
}

func unmodelled(claim trust.ClaimKey, construct, message, source string) fact {
	return fact{trust.Anomaly{Kind: trust.Unmodelled, Claim: claim, Construct: construct, Message: message, Source: source}, true}
}

// The sentences several documents share, pinned once: a drift in one is a
// change in what the product says.
const (
	disabledSentence = "the provider is disabled; Google says a disabled provider cannot be used to exchange tokens but existing tokens still grant access; the flag is set by an update and cleared by another, so the set stated is what the condition admits and is read as an upper bound"
	deletedSentence  = "the provider is soft-deleted; Google says soft-deleted providers are permanently deleted after approximately 30 days and can be restored until then, so the set stated is what the condition admits and is read as an upper bound"
	samlSentence     = "the provider is a SAML 2.0 provider, whose assertion this parser does not model as claims, so the grant is read as every credential the provider admits"
	x509Sentence     = "the provider is an X.509 provider, whose certificate this parser does not model as claims, so the grant is read as every credential the provider admits"
	noConfigSentence = "none of oidc, aws, saml or x509 is set; Google says provider_config must be one of them, so which identity provider this provider trusts, and the shape of its credential, is not stated"
	noNameAudience   = "allowedAudiences is empty and no name is set, so the audience Google requires, the provider's full resource name, cannot be derived and aud is read as unconstrained"
	derivedAudience  = `allowedAudiences is empty, so Google requires the token audience to be the provider's full resource name, with or without the https prefix: "https://iam.googleapis.com/` + providerName + `" or "//iam.googleapis.com/` + providerName + `"`
	groupSentence    = `the member selects the group "admins" of google.groups, which maps to the claim groups; a list-valued claim is outside what this parser models, so groups is read as unconstrained`
	percentSaid      = `; whether Google decodes percent escapes in a principal identifier is not documented, so `
	subjectLimitSaid = `; Google says google.subject, which maps to sub, cannot exceed 127 bytes, so no credential carrying that value can be exchanged and the set stated is read as an upper bound`
)

// longSubject is a subject one byte past Google's limit on google.subject
// ("Cannot exceed 127 bytes") when its prefix is the fixtures' repository,
// and well past it as the 216-byte value fixtures 48 and 51 write.
var (
	longSubject      = "repo:acme/infra:" + strings.Repeat("x", 200)
	escapedPool      = "projects/123456789012/locations/global/workloadIdentityPools/git%68ub"
	percentInPool    = `the member names the pool "` + escapedPool + `", which contains "%"` + percentSaid + `whether it is the provider's pool "projects/123456789012/locations/global/workloadIdentityPools/github" is not stated and the binding is read as applying to this provider`
	percentInSelect  = `the member selects from the pool by "%73ubject/` + mainBranch + `", which contains "%"` + percentSaid + `which identities it selects is not stated and the whole pool is read as admitted`
	subjectOverLimit = `the member selects google.subject ` + quote(longSubject) + `, which is 216 bytes long` + subjectLimitSaid
	clauseOverLimit  = quote("assertion.sub == '"+longSubject+"'") + ` compares sub against a value 216 bytes long` + subjectLimitSaid
)

// golden is what each document must parse to. A provider document states
// one Grant on githubProvider; a binding document is bound against the
// provider named by bindTo and states one Grant on deployAccount, or none.
var golden = map[string]struct {
	issuer trust.IssuerRef
	admits string
	facts  []fact
	bindTo string // a provider document, for a binding document
	bound  bool
}{
	"01-equals":                   {issuer: github, admits: `{` + audience + `, ` + main + `}`},
	"02-in-list":                  {issuer: github, admits: `{` + audience + `, repository=("acme/infra" | "acme/web")}`},
	"03-starts-with":              {issuer: github, admits: `{` + audience + `, ` + anyBranch + `}`},
	"04-ends-with-and-contains":   {issuer: github, admits: `{` + audience + `, sub=(like:"*/infra:*" & like:"*:ref:refs/heads/main")}`},
	"05-and":                      {issuer: github, admits: `{` + audience + `, repository_owner_id="123456", sub=like:"repo:acme/*"}`},
	"06-google-recommended":       {issuer: github, admits: `{` + audience + `, ref="refs/heads/main", repository_owner="acme"}`},
	"07-or":                       {issuer: github, admits: `{` + audience + `, sub="repo:acme/infra:ref:refs/heads/dev"} | {` + audience + `, ` + main + `}`},
	"08-or-with-unmodelled-side":  {issuer: github, admits: `{` + audience + `}`, facts: []fact{unmodelled("repository_id", "!=", `"assertion.repository_id != '1'" constrains repository_id with the operator "!=", which this parser does not model, so repository_id is read as unconstrained`, "attributeCondition")}},
	"09-wildcard-prefix":          {issuer: github, admits: `{` + audience + `}`, facts: []fact{unmodelled("sub", "startsWith", `"assertion.sub.startsWith('repo:acme/*')" tests sub for a prefix containing "*", which this parser's patterns read as a wildcard, so it cannot be stated as a pattern and sub is read as unconstrained`, "attributeCondition")}},
	"10-expression-mapping":       {issuer: github, admits: `{` + audience + `}`, facts: []fact{unmodelled("", "assertion.repository.extract('{org}/')", `"attribute.repository == 'acme'" constrains attribute.repository, which the attribute mapping maps by the expression "assertion.repository.extract('{org}/')"; this parser does not evaluate mapping expressions, so which claim the clause constrains is not stated and nothing it says about the credential is modelled`, "attributeCondition")}},
	"11-subject-through-mapping":  {issuer: github, admits: `{` + audience + `, ` + main + `}`},
	"12-not-equal":                {issuer: github, admits: `{` + audience + `}`, facts: []fact{unmodelled("sub", "!=", `"assertion.sub != 'repo:acme/infra:ref:refs/heads/main'" constrains sub with the operator "!=", which this parser does not model, so sub is read as unconstrained`, "attributeCondition")}},
	"13-matches":                  {issuer: github, admits: `{` + audience + `}`, facts: []fact{unmodelled("sub", "matches", `"assertion.sub.matches('^repo:acme/[a-z]+:ref:refs/heads/main$')" constrains sub with the function "matches", which this parser does not model, so sub is read as unconstrained`, "attributeCondition")}},
	"14-raw-string":               {issuer: github, admits: `{` + audience + `, sub="repo:acme\\infra"}`},
	"15-disabled":                 {issuer: github, admits: `{` + audience + `, ` + main + `}`, facts: []fact{{trust.Anomaly{Kind: ProviderDisabled, Construct: "disabled", Message: disabledSentence, Source: "disabled"}, true}}},
	"16-deleted":                  {issuer: github, admits: `{` + audience + `, ` + main + `}`, facts: []fact{{trust.Anomaly{Kind: ProviderDeleted, Construct: "state", Message: deletedSentence, Source: "state"}, true}}},
	"17-default-audience":         {issuer: github, admits: `{aud=("//iam.googleapis.com/` + providerName + `" | "https://iam.googleapis.com/` + providerName + `"), ` + main + `}`, facts: []fact{{trust.Anomaly{Kind: DefaultAudience, Claim: "aud", Construct: "allowedAudiences", Message: derivedAudience, Source: "oidc.allowedAudiences"}, false}}},
	"18-default-audience-no-name": {issuer: github, admits: `{aud=?("default audience"), ` + main + `}`, facts: []fact{{trust.Anomaly{Kind: DefaultAudience, Claim: "aud", Construct: "allowedAudiences", Message: noNameAudience, Source: "oidc.allowedAudiences"}, true}}},
	"19-aws":                      {issuer: awsIssuer, admits: `{arn=like:"arn:aws:sts::123456789012:assumed-role/*", aws:principalaccount="123456789012"}`},
	"20-saml": {issuer: "", admits: `{}`, facts: []fact{
		unmodelled("", "assertion.subject", `"assertion.subject == 'deploy'" constrains assertion.subject, but the provider is a SAML 2.0 provider, whose assertion this parser does not model as claims, so nothing it says about the credential is modelled`, "attributeCondition"),
		unmodelled("", "saml", samlSentence, "saml"),
	}},
	"21-duplicate-member":      {issuer: github, admits: `{` + audience + `}`, facts: []fact{{trust.Anomaly{Kind: DuplicateKey, Construct: "attributeCondition", Message: `the member "attributeCondition" is written 2 times; which one Google would apply is not stated, so it is not read`, Source: "attributeCondition"}, true}}},
	"23-not":                   {issuer: github, admits: `{` + audience + `}`, facts: []fact{unmodelled("sub", "!", `"!(assertion.sub == 'repo:acme/infra:ref:refs/heads/main')" negates a comparison on sub; this parser models what a condition admits, not what it excludes, so sub is read as unconstrained`, "attributeCondition")}},
	"24-not-conjunction":       {issuer: github, admits: `{` + audience + `}`, facts: []fact{unmodelled("", "!", `"!(assertion.sub == 'repo:acme/infra:ref:refs/heads/main' && assertion.repository_id == '456789')" negates an expression that is not a single comparison on one claim, so nothing it says about the credential is modelled`, "attributeCondition")}},
	"25-group-membership":      {issuer: "https://acme.okta.com/oauth2/default", admits: `{aud="https://iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/okta/providers/okta"}`, facts: []fact{unmodelled("groups", "in", `"'admins' in google.groups" tests membership of google.groups, which maps to the claim groups; a list-valued claim is outside what this parser models, so groups is read as unconstrained`, "attributeCondition")}},
	"26-unparseable":           {issuer: github, admits: `{` + audience + `}`, facts: []fact{unmodelled("", "unparseable expression", "attributeCondition is not an expression this parser can read: unexpected end of expression at character 58; nothing it says about the credential is modelled", "attributeCondition")}},
	"27-x509":                  {issuer: "", admits: `{}`, facts: []fact{unmodelled("", "x509", x509Sentence, "x509")}},
	"28-empty-prefix":          {issuer: github, admits: `{` + audience + `}`, facts: []fact{unmodelled("sub", "startsWith", `"assertion.sub.startsWith('')" tests sub for the empty prefix, which every value has but only when the claim is present; this parser cannot express presence, so sub is read as unconstrained`, "attributeCondition")}},
	"29-precedence":            {issuer: github, admits: `{` + audience + `, repository_id="456789", ` + main + `} | {` + audience + `, repository_owner_id="123456"}`},
	"30-snake-case":            {issuer: github, admits: `{` + audience + `, ` + main + `}`},
	"31-comparison-non-string": {issuer: github, admits: `{` + audience + `}`, facts: []fact{unmodelled("repository_id", "456789", `"assertion.repository_id == 456789" compares repository_id against 456789, which is not a string literal, so repository_id is read as unconstrained`, "attributeCondition")}},
	"32-no-provider-config": {issuer: "", admits: `{}`, facts: []fact{
		{trust.Anomaly{Kind: MissingIssuer, Construct: "provider_config", Message: noConfigSentence, Source: "provider_config"}, true},
		unmodelled("", "assertion.sub", `"assertion.sub == 'repo:acme/infra:ref:refs/heads/main'" constrains assertion.sub, but the provider sets none of oidc, aws, saml or x509, which leaves the shape of its credential unstated, so nothing it says about the credential is modelled`, "attributeCondition"),
	}},
	"33-http-issuer":      {issuer: github, admits: `{` + audience + `, ` + main + `}`, facts: []fact{{trust.Anomaly{Kind: IssuerScheme, Construct: "issuerUri", Message: `issuerUri "http://token.actions.githubusercontent.com" does not begin with https://; Google says the issuer must be an HTTPS endpoint, and it is read as the issuer it resembles`, Source: "oidc.issuerUri"}, false}}},
	"34-unmapped-subject": {issuer: github, admits: `{` + audience + `}`, facts: []fact{unmodelled("", "google.subject", `"google.subject == 'repo:acme/infra:ref:refs/heads/main'" constrains google.subject, which the attribute mapping does not map; Google says the mapping must include google.subject, so which claim the clause constrains is not stated and nothing it says about the credential is modelled`, "attributeCondition")}},

	"41-triple-quoted-newline": {issuer: github, admits: `{` + audience + `}`, facts: []fact{unmodelled("sub", "carriage return", `"assertion.sub == '''deploy\r\nmain'''" compares sub against a literal holding an unescaped carriage return; cel-go and cel-cpp read one as a line feed and the CEL language definition does not say, so the value is not read and sub is read as unconstrained`, "attributeCondition")}},
	"42-reserved-word-field":   {issuer: github, admits: `{` + audience + `, namespace="acme", ` + main + `}`},
	"43-comparison-as-operand": {issuer: github, admits: `{` + audience + `}`, facts: []fact{unmodelled("sub", "assertion.sub == '"+mainBranch+"'", `"assertion.sub == '`+mainBranch+`' == true" constrains sub inside assertion.sub == '`+mainBranch+`', a condition written as an operand of "=="; this parser models such a condition only as a clause of its own, so sub is read as unconstrained`, "attributeCondition")}},
	"44-miscased-audiences":    {issuer: github, admits: `{aud=?("miscased key"), ` + main + `}`, facts: []fact{{trust.Anomaly{Kind: MiscasedKey, Claim: "aud", Construct: "AllowedAudiences", Message: `the member "AllowedAudiences" differs from "allowedAudiences" only in case; whether Google reads it as that member is not stated, so allowedAudiences is not read`, Source: "oidc.AllowedAudiences"}, true}}},
	"45-groups-compared":       {issuer: github, admits: `{` + audience + `}`, facts: []fact{unmodelled("groups", "google.groups", `"google.groups == 'admins'" constrains google.groups, which maps to the claim groups and which Google documents as the set of groups the identity belongs to; a list-valued claim is outside what this parser models, so groups is read as unconstrained`, "attributeCondition")}},
	"48-subject-over-limit":    {issuer: github, admits: `{` + audience + `, sub="` + longSubject + `"}`, facts: []fact{{trust.Anomaly{Kind: SubjectLength, Claim: "sub", Construct: "==", Message: clauseOverLimit, Source: "attributeCondition"}, true}}},

	"35-binding-by-subject":   {bindTo: "03-starts-with", bound: true, issuer: github, admits: `{` + audience + `, ` + main + `}`},
	"36-binding-by-attribute": {bindTo: "03-starts-with", bound: true, issuer: github, admits: `{` + audience + `, repository="acme/infra", ` + anyBranch + `}`},
	"37-binding-by-group":     {bindTo: "03-starts-with", bound: true, issuer: github, admits: `{` + audience + `, groups=?("group membership"), ` + anyBranch + `}`, facts: []fact{unmodelled("groups", "group", groupSentence, "bindings[0].members[0]")}},
	"38-binding-whole-pool":   {bindTo: "03-starts-with", bound: true, issuer: github, admits: `{` + audience + `, ` + anyBranch + `}`},
	"39-binding-other-pool":   {bindTo: "03-starts-with", bound: false},
	"40-binding-expression-attribute": {bindTo: "19-aws", bound: true, issuer: awsIssuer, admits: `{arn=like:"arn:aws:sts::123456789012:assumed-role/*", aws:principalaccount="123456789012"}`, facts: []fact{
		unmodelled("", awsRoleText, `the member selects attribute.aws_role "arn:aws:sts::123456789012:assumed-role/deploy", which Google's default mapping for AWS providers maps by the expression "`+awsRoleText+`"; this parser does not evaluate mapping expressions, so which claim the member constrains is not stated and the whole pool is read as admitted`, "bindings[0].members[0]"),
	}},
	"46-binding-search-result":         {bindTo: "03-starts-with", bound: true, issuer: github, admits: `{` + audience + `, ` + anyBranch + `}`},
	"47-binding-undocumented-selector": {bindTo: "03-starts-with", bound: true, issuer: github, admits: `{` + audience + `, ` + anyBranch + `}`, facts: []fact{undocumented("namespace", "namespace/default")}},
	"49-binding-percent-in-pool":       {bindTo: "03-starts-with", bound: true, issuer: github, admits: `{` + audience + `, ` + anyBranch + `}`, facts: []fact{unmodelled("", "%", percentInPool, memberSource)}},
	"50-binding-percent-in-selector":   {bindTo: "03-starts-with", bound: true, issuer: github, admits: `{` + audience + `, ` + anyBranch + `}`, facts: []fact{unmodelled("", "%", percentInSelect, memberSource)}},
	"51-binding-subject-over-limit":    {bindTo: "03-starts-with", bound: true, issuer: github, admits: `{` + audience + `, sub="` + longSubject + `"}`, facts: []fact{{trust.Anomaly{Kind: SubjectLength, Claim: "sub", Construct: "subject", Message: subjectOverLimit, Source: memberSource}, true}}},
	"52-binding-wrong-scheme":          {bindTo: "03-starts-with", bound: true, issuer: github, admits: `{` + audience + `, ` + anyBranch + `}`, facts: []fact{undocumented("subject", "subject/"+mainBranch)}},
	"53-binding-respelt":               {bindTo: "03-starts-with", bound: true, issuer: github, admits: `{` + audience + `, ` + main + `}`, facts: []fact{miscasedMember("Principal://IAM.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/github/subject/" + mainBranch)}},
	"54-binding-percent-in-fixed-text": {bindTo: "03-starts-with", bound: true, issuer: github, admits: `{` + audience + `, ` + main + `}`, facts: []fact{escapedMember("principal://iam.googleapis.com/projects/123456789012/loc%61tions/global/workloadIdentityPools/github/subject/" + mainBranch)}},
}

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(providersDir, name+".json"))
	if err != nil {
		t.Fatalf("%v", err)
	}
	return raw
}

func parseOne(t *testing.T, raw []byte) (Provider, trust.Grant) {
	t.Helper()
	p, err := ParseProvider(raw)
	if err != nil {
		t.Fatalf("%v", err)
	}
	grants := p.Grants(githubProvider)
	if len(grants) != 1 {
		t.Fatalf("%d grants, want 1", len(grants))
	}
	return p, grants[0]
}

func renderAnomalies(as []trust.Anomaly) string {
	var b strings.Builder
	for _, a := range as {
		b.WriteString("\n  " + a.Kind + " claim=" + string(a.Claim) + " construct=" + strconv.Quote(a.Construct) + " source=" + a.Source + "\n    " + a.Message)
	}
	return b.String()
}

func renderCaveats(cs []eval.Caveat) string {
	var b strings.Builder
	for _, c := range cs {
		b.WriteString(string(c.Claim) + "|" + c.Reason + "|" + c.Source + "\n")
	}
	return b.String()
}

func hasCaveatOn(cs []eval.Caveat, k trust.ClaimKey) bool {
	return slices.ContainsFunc(cs, func(c eval.Caveat) bool { return c.Claim == k })
}

func mustJSON(v any) []byte {
	raw, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return raw
}

// grantOf produces the Grant a golden entry describes: the provider's own,
// or the one its binding states against the provider it names.
func grantOf(t *testing.T, name string) (trust.Grant, bool) {
	t.Helper()
	entry := golden[name]
	if entry.bindTo == "" {
		_, g := parseOne(t, fixture(t, name))
		return g, true
	}
	provider, err := ParseProvider(fixture(t, entry.bindTo))
	if err != nil {
		t.Fatalf("%s: %v", entry.bindTo, err)
	}
	members, err := ParseMembers(fixture(t, name))
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	if len(members) == 0 {
		t.Fatalf("%s: no members", name)
	}
	var bound *trust.Grant
	for _, m := range members {
		if name == "46-binding-search-result" && m.Resource != "//iam.googleapis.com/projects/acme-prod/serviceAccounts/deploy@acme-prod.iam.gserviceaccount.com" {
			t.Fatalf("%s: resource %q", name, m.Resource)
		}
		g, ok := provider.Bind(m, deployAccount)
		if !ok {
			continue
		}
		if bound != nil {
			t.Fatalf("%s: more than one member binds", name)
		}
		bound = &g
	}
	if bound == nil {
		return trust.Grant{}, false
	}
	return *bound, true
}

// TestGoldenProviders: every document in the corpus parses to its stated
// grant, sentence for sentence, and every entry of the table has a document
// and a rationale, so that neither the table nor the corpus can drift alone.
func TestGoldenProviders(t *testing.T) {
	entries, err := os.ReadDir(providersDir)
	if err != nil {
		t.Fatalf("%v", err)
	}
	seen := map[string]bool{}
	for _, e := range entries {
		name, isJSON := strings.CutSuffix(e.Name(), ".json")
		if !isJSON {
			continue
		}
		seen[name] = true
		if _, ok := golden[name]; !ok && name != "22-list" {
			t.Errorf("%s.json has no entry in the golden table; it would be examined by nothing", name)
		}
		if _, err := os.Stat(filepath.Join(providersDir, name+".rationale.md")); err != nil {
			t.Errorf("%s has no rationale: %v", name, err)
		}
	}
	for name := range golden {
		if !seen[name] {
			t.Errorf("golden entry %s has no document", name)
		}
	}
	if len(seen) == 0 {
		t.Fatalf("no documents under %s; the corpus is empty", providersDir)
	}
	for _, name := range slices.Sorted(maps.Keys(golden)) {
		want := golden[name]
		g, bound := grantOf(t, name)
		if bound != (want.bindTo == "" || want.bound) {
			t.Errorf("%s: bound %v, want %v", name, bound, want.bound)
			continue
		}
		if !bound {
			continue
		}
		if g.Issuer != want.issuer {
			t.Errorf("%s: issuer %q, want %q", name, g.Issuer, want.issuer)
		}
		if got := g.Admits.String(); got != want.admits {
			t.Errorf("%s: admits %s\n  want %s", name, got, want.admits)
		}
		wantTarget := githubProvider
		if want.bindTo != "" {
			wantTarget = deployAccount
		}
		if g.Effect != trust.Allow || g.Target != wantTarget {
			t.Errorf("%s: effect %q target %+v", name, g.Effect, g.Target)
		}
		wantAnomalies := make([]trust.Anomaly, len(want.facts))
		var wantCaveats []eval.Caveat
		for i, f := range want.facts {
			wantAnomalies[i] = f.anomaly
			if f.doubt {
				wantCaveats = append(wantCaveats, eval.Caveat{Claim: f.anomaly.Claim, Reason: f.anomaly.Message, Source: f.anomaly.Source})
			}
		}
		if !slices.Equal(g.Anomalies, wantAnomalies) {
			t.Errorf("%s: anomalies%s\n  want%s", name, renderAnomalies(g.Anomalies), renderAnomalies(wantAnomalies))
		}
		gotCaveats := g.Admits.Caveats()
		if len(gotCaveats) != len(wantCaveats) {
			t.Errorf("%s: caveats\n%s  want\n%s", name, renderCaveats(gotCaveats), renderCaveats(wantCaveats))
		}
		for _, cv := range wantCaveats {
			if !slices.Contains(gotCaveats, cv) {
				t.Errorf("%s: missing caveat %+v; got %v", name, cv, gotCaveats)
			}
		}
		if g.Exact() != (len(wantCaveats) == 0) {
			t.Errorf("%s: Exact() = %v with caveats %v", name, g.Exact(), gotCaveats)
		}
		for _, term := range g.Admits.Terms() {
			for k, s := range term {
				if eval.IsUnknown(s) && !hasCaveatOn(gotCaveats, k) {
					t.Errorf("%s: %s is Unknown without a caveat: silence read as clean", name, k)
				}
			}
		}
		if g.Admits.IsEmpty() {
			t.Errorf("%s: the grant admits nothing", name)
		}
		if want.bindTo == "" && string(g.Source) != strings.TrimSpace(string(fixture(t, name))) {
			t.Errorf("%s: Source is not the document's own bytes", name)
		}
	}
}

// TestBoundGrantQuotesBothDocuments: a bound grant's Source holds the
// provider's own bytes and the binding's own bytes, verbatim, under one
// object, so that a finding can quote the condition and the member that
// together admit the identity.
func TestBoundGrantQuotesBothDocuments(t *testing.T) {
	provider, err := ParseProvider(fixture(t, "03-starts-with"))
	if err != nil {
		t.Fatal(err)
	}
	policy := fixture(t, "35-binding-by-subject")
	members, err := ParseMembers(policy)
	if err != nil {
		t.Fatal(err)
	}
	g, ok := provider.Bind(members[0], deployAccount)
	if !ok {
		t.Fatal("not bound")
	}
	var quoted struct {
		Provider json.RawMessage `json:"provider"`
		Binding  json.RawMessage `json:"binding"`
	}
	if err := json.Unmarshal(g.Source, &quoted); err != nil {
		t.Fatalf("%v: %s", err, g.Source)
	}
	if string(quoted.Provider) != strings.TrimSpace(string(fixture(t, "03-starts-with"))) {
		t.Errorf("provider bytes: %s", quoted.Provider)
	}
	if !strings.HasPrefix(string(quoted.Binding), `{
      "role": "roles/iam.workloadIdentityUser"`) || !strings.Contains(string(quoted.Binding), members[0].Text) {
		t.Errorf("binding bytes: %s", quoted.Binding)
	}
	if !json.Valid(g.Source) {
		t.Errorf("Source is not JSON: %s", g.Source)
	}
}

// TestListDocument: the list response parses to one provider per item, in
// document order, each with its own bytes as Source; a page that carries
// a token is refused by ParseProviders and read by ParsePage.
func TestListDocument(t *testing.T) {
	raw := fixture(t, "22-list")
	providers, err := ParseProviders(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(providers) != 2 {
		t.Fatalf("%d providers", len(providers))
	}
	first := providers[0].Grants(githubProvider)[0]
	second := providers[1].Grants(trust.TargetRef{Kind: "workloadIdentityPoolProvider", ID: providers[1].Name})[0]
	if first.Issuer != github || first.Admits.String() != `{`+audience+`, `+main+`}` || !first.Exact() {
		t.Errorf("first: %s %s %v", first.Issuer, first.Admits, first.Admits.Caveats())
	}
	if second.Issuer != "https://gitlab.com" || second.Admits.String() != `{aud="https://iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/github/providers/gitlab", namespace_id="9876"}` || !second.Exact() {
		t.Errorf("second: %s %s %v", second.Issuer, second.Admits, second.Admits.Caveats())
	}
	if !strings.HasPrefix(string(first.Source), `{
      "name": "`+providerName+`"`) || strings.Contains(string(first.Source), "gitlab") {
		t.Errorf("first Source: %s", first.Source)
	}
	if !strings.HasSuffix(string(second.Source), "}") || !strings.Contains(string(second.Source), `"displayName": "GitLab"`) || strings.Contains(string(second.Source), "GitHub Actions") {
		t.Errorf("second Source: %s", second.Source)
	}
	if _, err := ParseProvider(raw); err == nil || !strings.Contains(err.Error(), "2 providers, not one") {
		t.Errorf("ParseProvider on a list: %v", err)
	}
	page, err := ParsePage(raw)
	if err != nil || len(page.Providers) != 2 || page.NextPageToken != "" {
		t.Errorf("page: %+v %v", page, err)
	}
	paged := []byte(strings.Replace(string(raw), `"workloadIdentityPoolProviders"`, `"nextPageToken": "CAE=", "workloadIdentityPoolProviders"`, 1))
	if _, err := ParseProviders(paged); err == nil || !strings.Contains(err.Error(), "nextPageToken") || !strings.Contains(err.Error(), "ParsePage") {
		t.Errorf("ParseProviders on a page: %v", err)
	}
	page, err = ParsePage(paged)
	if err != nil || len(page.Providers) != 2 || page.NextPageToken != "CAE=" {
		t.Errorf("page: %+v %v", page, err)
	}
	page, err = ParsePage([]byte(`{"nextPageToken": "x"}`))
	if err != nil || len(page.Providers) != 0 || page.NextPageToken != "x" {
		t.Errorf("a page of no providers: %+v %v", page, err)
	}
	if _, err := ParseProviders([]byte(`{"nextPageToken": "x"}`)); err == nil || !strings.Contains(err.Error(), "nextPageToken") {
		t.Errorf("ParseProviders on a page of no providers: %v", err)
	}
	snake := []byte(strings.Replace(strings.Replace(string(paged), `"nextPageToken"`, `"next_page_token"`, 1), `"workloadIdentityPoolProviders"`, `"workload_identity_pool_providers"`, 1))
	page, err = ParsePage(snake)
	if err != nil || len(page.Providers) != 2 || page.NextPageToken != "CAE=" {
		t.Errorf("snake page: %+v %v", page, err)
	}
	bare, err := ParseProviders([]byte(`[` + awsProviderRaw + `, ` + awsProviderRaw + `]`))
	if err != nil || len(bare) != 2 {
		t.Errorf("bare list: %d %v", len(bare), err)
	}
	for _, raw := range []string{`[]`, `{"workloadIdentityPoolProviders": []}`, `{}`} {
		providers, err := ParseProviders([]byte(raw))
		if err != nil || len(providers) != 0 {
			t.Errorf("%s: %d providers, %v", raw, len(providers), err)
		}
	}
	single, err := ParseProvider([]byte(`{"workloadIdentityPoolProviders": [` + awsProviderRaw + `]}`))
	if err != nil || single.AWS == nil {
		t.Errorf("a list of one: %+v %v", single, err)
	}
}

// TestNotAProviderDocument: an error means the input is not a provider
// document at all, and says why; a document read as no provider would be
// silence.
func TestNotAProviderDocument(t *testing.T) {
	cases := map[string]string{
		``:                "empty input",
		`   `:             "empty input",
		`null`:            "the document is null, not an object or a list",
		`"x"`:             "the document is a string, not an object or a list",
		`123`:             "the document is a number, not an object or a list",
		`{"name": "x"}`:   "not a provider",
		`{"foo": 1}`:      "not a provider",
		`[1]`:             "[0] is a number, not a provider",
		`[{"name": "x"}]`: "[0] is not a provider",
		`{"workloadIdentityPoolProviders": [{}]}`:                                             "workloadIdentityPoolProviders[0] is not a provider",
		`{"workloadIdentityPoolProviders": {}}`:                                               `the member "workloadIdentityPoolProviders" is an object, not a list`,
		`{"workloadIdentityPoolProviders": [], "workloadIdentityPoolProviders": []}`:          `the member "workloadIdentityPoolProviders" is written 2 times`,
		`{"workloadIdentityPoolProviders": [], "workload_identity_pool_providers": []}`:       `the member "workloadIdentityPoolProviders" is written 2 times`,
		`{"workloadIdentityPoolProviders": [], "oidc": {}}`:                                   "carries both a provider list and provider members",
		`{"nextPageToken": "x", "oidc": {}}`:                                                  "carries both a nextPageToken and provider members",
		`{"WorkloadIdentityPoolProviders": []}`:                                               `differs from "workloadIdentityPoolProviders" only in case`,
		`{"nextPageToken": 1, "workloadIdentityPoolProviders": []}`:                           `the member "nextPageToken" is a number, not a string`,
		`{"nextPageToken": "a", "next_page_token": "b"}`:                                      `the member "nextPageToken" is written 2 times`,
		`{"oidc": {"issuerUri": "\ud800"}}`:                                                   "lone surrogate escape at byte 24",
		`{"oidc": {"issuerUri": "\ud800\u0041"}}`:                                             "lone surrogate escape",
		`{"oidc": {"issuerUri": "\ud800\n"}}`:                                                 "lone surrogate escape",
		`{"oidc": {"issuerUri": "\udc00x"}}`:                                                  "lone surrogate escape",
		`{"oidc": {}, "\udc00": 1}`:                                                           "lone surrogate escape at byte 14",
		awsProviderRaw + ` x`:                                                                 "after the document",
		awsProviderRaw + awsProviderRaw:                                                       "a second value",
		`{"oidc": {"issuerUri": "https://x"}`:                                                 "unexpected EOF",
		"\xff" + awsProviderRaw:                                                               "not valid UTF-8 at byte 0",
		"{\"oidc\": {\"issuerUri\": \"https://x\xff\"}}":                                      "not valid UTF-8",
		`{"oidc": {}, "x509": ` + strings.Repeat("[", 1001) + strings.Repeat("]", 1001) + `}`: "nested more than 1000 levels deep",
	}
	for raw, problem := range cases {
		providers, err := ParseProviders([]byte(raw))
		if err == nil || !strings.Contains(err.Error(), problem) {
			t.Errorf("%.60q: err %v, want %q", raw, err, problem)
		}
		if providers != nil {
			t.Errorf("%.60q: an error came with providers", raw)
		}
		if _, err := ParseProvider([]byte(raw)); err == nil {
			t.Errorf("%.60q: the singular parse accepted what the plural refused", raw)
		}
		if _, err := ParsePage([]byte(raw)); err == nil {
			t.Errorf("%.60q: ParsePage accepted what ParseProviders refused", raw)
		}
	}
	// Right at the nesting bound the document is read; the trust store is
	// skipped, not modelled.
	deep := `{"oidc": {}, "x509": ` + strings.Repeat("[", 999) + strings.Repeat("]", 999) + `}`
	if _, err := ParseProvider([]byte(deep)); err != nil {
		t.Errorf("999 levels: %v", err)
	}
	// A surrogate pair, in either case of hex digit, is one character.
	for _, pair := range []string{`\ud83d\ude00`, `\uD83D\uDE00`} {
		p, err := ParseProvider([]byte(`{"oidc": {"issuerUri": "https://x/` + pair + `", "allowedAudiences": ["x"]}}`))
		if err != nil || p.OIDC.IssuerURI != "https://x/😀" {
			t.Errorf("%s: %+v %v", pair, p.OIDC, err)
		}
	}
}

// TestProviderFieldsAreTheDocuments: the exported fields hold what the
// document wrote, spelling of the member names aside.
func TestProviderFieldsAreTheDocuments(t *testing.T) {
	p, _ := parseOne(t, fixture(t, "16-deleted"))
	if p.Name != providerName || p.DisplayName != "GitHub Actions" || p.Description != "a soft-deleted provider, as a get with the provider name returns it" {
		t.Errorf("labels: %+v", p)
	}
	if p.State != "DELETED" || p.Disabled || p.ExpireTime != "2026-10-13T09:00:00Z" {
		t.Errorf("state: %+v", p)
	}
	if p.AttributeCondition != "assertion.sub == '"+mainBranch+"'" || !maps.Equal(p.AttributeMapping, map[string]string{"google.subject": "assertion.sub"}) {
		t.Errorf("condition: %+v", p)
	}
	if p.Type != "oidc" || p.OIDC == nil || p.OIDC.IssuerURI != string(github) || !slices.Equal(p.OIDC.AllowedAudiences, []string{audienceName}) || p.AWS != nil {
		t.Errorf("oidc: %+v %+v", p.Type, p.OIDC)
	}
	aws, _ := parseOne(t, fixture(t, "19-aws"))
	if aws.Type != "aws" || aws.AWS == nil || aws.AWS.AccountID != "123456789012" || aws.OIDC != nil || aws.AttributeMapping != nil {
		t.Errorf("aws: %+v", aws)
	}
	snake, _ := parseOne(t, fixture(t, "30-snake-case"))
	if snake.DisplayName != "GitHub Actions" || snake.AttributeCondition == "" || snake.OIDC == nil || len(snake.OIDC.AllowedAudiences) != 1 {
		t.Errorf("snake: %+v", snake)
	}
	saml, _ := parseOne(t, fixture(t, "20-saml"))
	if saml.Type != "saml" || saml.OIDC != nil || saml.AWS != nil {
		t.Errorf("saml: %+v", saml)
	}
	p, _ = parseOne(t, fixture(t, "15-disabled"))
	if !p.Disabled {
		t.Errorf("disabled: %+v", p)
	}
}

// TestAProviderTheParserDidNotProduceStatesNoGrant: the zero value, or a
// Provider built by hand, has no document behind it and states nothing.
func TestAProviderTheParserDidNotProduceStatesNoGrant(t *testing.T) {
	if grants := (Provider{}).Grants(githubProvider); grants != nil {
		t.Errorf("zero value: %v", grants)
	}
	if grants := (Provider{Name: providerName, Type: "oidc"}).Grants(githubProvider); grants != nil {
		t.Errorf("hand-built: %v", grants)
	}
	members, err := ParseMembers(fixture(t, "38-binding-whole-pool"))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := (Provider{}).Bind(members[0], deployAccount); ok {
		t.Errorf("the zero value bound a member")
	}
	p, _ := parseOne(t, fixture(t, "03-starts-with"))
	if _, ok := p.Bind(Member{Text: members[0].Text, Pool: members[0].Pool, Selector: "*"}, deployAccount); ok {
		t.Errorf("a hand-built member bound")
	}
}

// TestGrantsIsIndependentOfTheProvider: the caller may mutate what Grants
// returned without changing what the next call returns.
func TestGrantsIsIndependentOfTheProvider(t *testing.T) {
	p, _ := parseOne(t, fixture(t, "15-disabled"))
	g := p.Grants(githubProvider)[0]
	g.Anomalies[0].Message = "changed"
	g.Source[0] = 'X'
	again := p.Grants(githubProvider)[0]
	if again.Anomalies[0].Message == "changed" || again.Source[0] == 'X' || p.Anomalies[0].Message == "changed" {
		t.Errorf("Grants shares memory with the caller")
	}
}

// TestSourceOutlivesTheCallersBuffer: a collector reuses its buffer for
// the next page; the Provider must not slice it.
func TestSourceOutlivesTheCallersBuffer(t *testing.T) {
	raw := fixture(t, "01-equals")
	p, err := ParseProvider(raw)
	if err != nil {
		t.Fatal(err)
	}
	for i := range raw {
		raw[i] = ' '
	}
	if !strings.Contains(string(p.Grants(githubProvider)[0].Source), providerName) {
		t.Errorf("Source was overwritten with the buffer")
	}
}

// wrongTypes: each member written with a type Google does not define for
// it, the sentence, and what the grant becomes.
func TestMembersOfTheWrongType(t *testing.T) {
	base := map[string]any{
		"name":               providerName,
		"attributeMapping":   map[string]any{"google.subject": "assertion.sub"},
		"attributeCondition": "assertion.sub == 'a'",
		"oidc":               map[string]any{"issuerUri": string(github), "allowedAudiences": []string{"x"}},
	}
	cases := []struct {
		member  string
		value   any
		nested  string // "oidc" when the member sits inside it
		admits  string
		issuer  trust.IssuerRef
		anomaly trust.Anomaly
		doubt   bool
	}{
		{"attributeCondition", 1, "", `{aud="x"}`, github, trust.Anomaly{Kind: Malformed, Construct: "attributeCondition", Message: "attributeCondition is a number; Google defines it as a string, so it is not read", Source: "attributeCondition"}, true},
		{"attributeMapping", []any{}, "", `{aud="x", sub="a"}`, github, trust.Anomaly{Kind: Malformed, Construct: "attributeMapping", Message: "attributeMapping is a list; Google defines it as an object, so it is not read", Source: "attributeMapping"}, false},
		{"disabled", "true", "", `{aud="x", sub="a"}`, github, trust.Anomaly{Kind: Malformed, Construct: "disabled", Message: "disabled is a string; Google defines it as a boolean, so it is not read", Source: "disabled"}, true},
		{"state", true, "", `{aud="x", sub="a"}`, github, trust.Anomaly{Kind: Malformed, Construct: "state", Message: "state is a boolean; Google defines it as a string, so it is not read", Source: "state"}, true},
		{"name", 5, "", `{aud="x", sub="a"}`, github, trust.Anomaly{Kind: Malformed, Construct: "name", Message: "name is a number; Google defines it as a string, so it is not read", Source: "name"}, false},
		{"displayName", 5, "", `{aud="x", sub="a"}`, github, trust.Anomaly{Kind: Malformed, Construct: "displayName", Message: "displayName is a number; Google defines it as a string, so it is not read", Source: "displayName"}, false},
		{"oidc", "x", "", `{aud=?("wrong type"), sub="a"}`, "", trust.Anomaly{Kind: Malformed, Claim: "aud", Construct: "oidc", Message: "oidc is a string; Google defines it as an object, so it is not read", Source: "oidc"}, true},
		{"issuerUri", 1, "oidc", `{aud="x", sub="a"}`, "", trust.Anomaly{Kind: Malformed, Construct: "issuerUri", Message: "oidc.issuerUri is a number; Google defines it as a string, so it is not read", Source: "oidc.issuerUri"}, false},
		{"allowedAudiences", "x", "oidc", `{aud=?("wrong type"), sub="a"}`, github, trust.Anomaly{Kind: Malformed, Claim: "aud", Construct: "allowedAudiences", Message: "oidc.allowedAudiences is a string; Google defines it as a list of strings, so it is not read", Source: "oidc.allowedAudiences"}, true},
		{"allowedAudiences", []any{"x", 1}, "oidc", `{aud=?("wrong type"), sub="a"}`, github, trust.Anomaly{Kind: Malformed, Claim: "aud", Construct: "allowedAudiences", Message: "oidc.allowedAudiences[1] is a number; Google defines allowedAudiences as a list of strings, so it is not read", Source: "oidc.allowedAudiences"}, true},
	}
	for _, c := range cases {
		doc := maps.Clone(base)
		if c.nested == "oidc" {
			oidc := maps.Clone(base["oidc"].(map[string]any))
			oidc[c.member] = c.value
			doc["oidc"] = oidc
		} else {
			doc[c.member] = c.value
		}
		_, g := parseOne(t, mustJSON(doc))
		if g.Admits.String() != c.admits || g.Issuer != c.issuer {
			t.Errorf("%s=%v: admits %s issuer %q, want %s %q", c.member, c.value, g.Admits, g.Issuer, c.admits, c.issuer)
		}
		if !slices.Contains(g.Anomalies, c.anomaly) {
			t.Errorf("%s=%v: anomalies%s\n  want%s", c.member, c.value, renderAnomalies(g.Anomalies), renderAnomalies([]trust.Anomaly{c.anomaly}))
		}
		caveat := eval.Caveat{Claim: c.anomaly.Claim, Reason: c.anomaly.Message, Source: c.anomaly.Source}
		if slices.Contains(g.Admits.Caveats(), caveat) != c.doubt {
			t.Errorf("%s=%v: caveats %v, doubt want %v", c.member, c.value, g.Admits.Caveats(), c.doubt)
		}
	}
	// aws.accountId of the wrong type, missing, and empty, each leaves the
	// account Unknown with the fact stated.
	for _, aws := range []string{`{"accountId": 1}`, `{}`, `{"accountId": ""}`, `{"accountId": null}`} {
		_, g := parseOne(t, []byte(`{"aws": `+aws+`}`))
		if g.Admits.String() != `{}` || g.Issuer != awsIssuer || !hasCaveatOn(g.Admits.Caveats(), "aws:principalaccount") {
			t.Errorf("aws %s: %s %q %v", aws, g.Admits, g.Issuer, g.Admits.Caveats())
		}
		want := "aws.accountId is not set; Google requires one, so which AWS account this provider trusts is not stated"
		if aws == `{"accountId": 1}` {
			want = "aws.accountId is a number; Google defines it as a string, so it is not read"
		}
		if len(g.Anomalies) != 1 || g.Anomalies[0].Kind != Malformed || g.Anomalies[0].Message != want {
			t.Errorf("aws %s: %s", aws, renderAnomalies(g.Anomalies))
		}
	}
}

// TestDuplicateMembers: a member written twice is not read, the fact is
// recorded with the count, and what depends on it is Unknown; the proto
// spelling counts as the same member.
func TestDuplicateMembers(t *testing.T) {
	cases := []struct {
		raw     string
		admits  string
		issuer  trust.IssuerRef
		claim   trust.ClaimKey
		message string
		source  string
		doubt   bool
	}{
		{`{"attributeCondition": "assertion.sub == 'a'", "attributeCondition": "assertion.sub == 'b'", "oidc": {"issuerUri": "https://x", "allowedAudiences": ["x"]}}`, `{aud="x"}`, "https://x", "", `the member "attributeCondition" is written 2 times; which one Google would apply is not stated, so it is not read`, "attributeCondition", true},
		{`{"attributeCondition": "assertion.sub == 'a'", "attribute_condition": "assertion.sub == 'b'", "oidc": {"issuerUri": "https://x", "allowedAudiences": ["x"]}}`, `{aud="x"}`, "https://x", "", `the member "attributeCondition" is written 2 times, counting its proto spelling "attribute_condition"; which one Google would apply is not stated, so it is not read`, "attributeCondition", true},
		{`{"disabled": true, "disabled": false, "oidc": {"issuerUri": "https://x", "allowedAudiences": ["x"]}}`, `{aud="x"}`, "https://x", "", `the member "disabled" is written 2 times; which one Google would apply is not stated, so it is not read`, "disabled", true},
		{`{"state": "ACTIVE", "state": "DELETED", "oidc": {"issuerUri": "https://x", "allowedAudiences": ["x"]}}`, `{aud="x"}`, "https://x", "", `the member "state" is written 2 times; which one Google would apply is not stated, so it is not read`, "state", true},
		{`{"oidc": {"issuerUri": "https://x", "allowedAudiences": ["x"]}, "oidc": {"issuerUri": "https://y"}}`, `{}`, "", "aud", `the member "oidc" is written 2 times; which one Google would apply is not stated, so it is not read`, "oidc", true},
		{`{"oidc": {"issuerUri": "https://x", "issuerUri": "https://y", "allowedAudiences": ["x"]}}`, `{aud="x"}`, "", "", `the member "issuerUri" is written 2 times; which one Google would apply is not stated, so it is not read`, "oidc.issuerUri", false},
		{`{"oidc": {"issuerUri": "https://x", "allowedAudiences": ["x"], "allowed_audiences": ["y"]}}`, `{}`, "https://x", "aud", `the member "allowedAudiences" is written 2 times, counting its proto spelling "allowed_audiences"; which one Google would apply is not stated, so it is not read`, "oidc.allowedAudiences", true},
		{`{"aws": {"accountId": "1"}, "aws": {"accountId": "2"}}`, `{}`, awsIssuer, "aws:principalaccount", `the member "aws" is written 2 times; which one Google would apply is not stated, so it is not read`, "aws", true},
		{`{"aws": {"accountId": "1", "accountId": "2"}}`, `{}`, awsIssuer, "aws:principalaccount", `the member "accountId" is written 2 times; which one Google would apply is not stated, so it is not read`, "aws.accountId", true},
		{`{"name": "a", "name": "b", "oidc": {"issuerUri": "https://x", "allowedAudiences": ["x"]}}`, `{aud="x"}`, "https://x", "", `the member "name" is written 2 times; which one Google would apply is not stated, so it is not read`, "name", false},
		{`{"attributeMapping": {"google.subject": "assertion.sub"}, "attributeMapping": {"google.subject": "assertion.sub"}, "oidc": {"issuerUri": "https://x", "allowedAudiences": ["x"]}}`, `{aud="x"}`, "https://x", "", `the member "attributeMapping" is written 2 times; which one Google would apply is not stated, so it is not read`, "attributeMapping", false},
		{`{"attributeMapping": {"attribute.r": "assertion.r", "attribute.r": "assertion.s"}, "oidc": {"issuerUri": "https://x", "allowedAudiences": ["x"]}}`, `{aud="x"}`, "https://x", "", `the member "attribute.r" is written 2 times; which one Google would apply is not stated, so it is not read`, "attributeMapping.attribute.r", false},
	}
	for _, c := range cases {
		_, g := parseOne(t, []byte(c.raw))
		if g.Admits.String() != c.admits || g.Issuer != c.issuer {
			t.Errorf("%s: admits %s issuer %q, want %s %q", c.raw, g.Admits, g.Issuer, c.admits, c.issuer)
		}
		want := trust.Anomaly{Kind: DuplicateKey, Claim: c.claim, Construct: strings.TrimPrefix(strings.TrimPrefix(strings.TrimPrefix(c.source, "attributeMapping."), "oidc."), "aws."), Message: c.message, Source: c.source}
		if !slices.Contains(g.Anomalies, want) {
			t.Errorf("%s: anomalies%s\n  want%s", c.raw, renderAnomalies(g.Anomalies), renderAnomalies([]trust.Anomaly{want}))
		}
		caveat := eval.Caveat{Claim: c.claim, Reason: c.message, Source: c.source}
		if slices.Contains(g.Admits.Caveats(), caveat) != c.doubt {
			t.Errorf("%s: caveats %v, doubt want %v", c.raw, g.Admits.Caveats(), c.doubt)
		}
	}
	// A duplicated mapping entry makes a reference to it unattributable,
	// with the count in the sentence.
	_, g := parseOne(t, []byte(`{"attributeMapping": {"attribute.r": "assertion.r", "attribute.r": "assertion.s"}, "attributeCondition": "attribute.r == 'x'", "oidc": {"issuerUri": "https://x", "allowedAudiences": ["x"]}}`))
	want := trust.Anomaly{Kind: trust.Unmodelled, Construct: "attribute.r", Message: `"attribute.r == 'x'" constrains attribute.r, which the attribute mapping maps 2 times, so which claim the clause constrains is not stated and nothing it says about the credential is modelled`, Source: "attributeCondition"}
	if g.Admits.String() != `{aud="x"}` || !slices.Contains(g.Anomalies, want) || !hasCaveatOn(g.Admits.Caveats(), "") {
		t.Errorf("duplicated mapping entry: %s%s", g.Admits, renderAnomalies(g.Anomalies))
	}
}

// TestMiscasedKeys: a member that matches a documented name only in case
// is not read, and neither is the documented member beside it: whether
// Google folds case is not stated, so which of the two Google applies, or
// whether it applies the miscased one at all, is not stated either. What
// the member bears on is Unknown with a caveat, exactly as for a member
// written twice; a label is a fact. Not reading a miscased allowedAudiences
// and deriving the default audience instead would be an Exact on a list
// Google may not apply, which is the narrowing this rule exists to refuse.
// A term whose one claim is Unknown renders as {}, the lattice's own
// canonical form; the caveat on aud is what declares it.
func TestMiscasedKeys(t *testing.T) {
	miscasedKey := func(claim trust.ClaimKey, spelling, near, name, source string) trust.Anomaly {
		return trust.Anomaly{Kind: MiscasedKey, Claim: claim, Construct: spelling, Message: "the member " + strconv.Quote(spelling) + " differs from " + strconv.Quote(near) + " only in case; whether Google reads it as that member is not stated, so " + name + " is not read", Source: source}
	}
	cases := []struct {
		raw       string
		admits    string
		issuer    trust.IssuerRef
		exact     bool
		anomalies []trust.Anomaly
		caveats   []eval.Caveat
	}{
		{`{"name": "` + providerName + `", "oidc": {"issuerUri": "https://x", "AllowedAudiences": ["x"]}}`, `{}`, "https://x", false,
			[]trust.Anomaly{miscasedKey("aud", "AllowedAudiences", "allowedAudiences", "allowedAudiences", "oidc.AllowedAudiences")},
			[]eval.Caveat{{Claim: "aud", Reason: miscasedKey("aud", "AllowedAudiences", "allowedAudiences", "allowedAudiences", "oidc.AllowedAudiences").Message, Source: "oidc.AllowedAudiences"}}},
		{`{"name": "` + providerName + `", "oidc": {"issuerUri": "https://x", "allowed_Audiences": ["x"]}}`, `{}`, "https://x", false,
			[]trust.Anomaly{miscasedKey("aud", "allowed_Audiences", "allowed_audiences", "allowedAudiences", "oidc.allowed_Audiences")},
			[]eval.Caveat{{Claim: "aud", Reason: miscasedKey("aud", "allowed_Audiences", "allowed_audiences", "allowedAudiences", "oidc.allowed_Audiences").Message, Source: "oidc.allowed_Audiences"}}},
		// Beside the documented spelling, the documented one is not read either.
		{`{"oidc": {"issuerUri": "https://x", "allowedAudiences": ["x"], "AllowedAudiences": ["y"]}}`, `{}`, "https://x", false,
			[]trust.Anomaly{miscasedKey("aud", "AllowedAudiences", "allowedAudiences", "allowedAudiences", "oidc.AllowedAudiences")},
			[]eval.Caveat{{Claim: "aud", Reason: miscasedKey("aud", "AllowedAudiences", "allowedAudiences", "allowedAudiences", "oidc.AllowedAudiences").Message, Source: "oidc.AllowedAudiences"}}},
		{`{"AttributeCondition": "assertion.sub == 'a'", "attributeCondition": "assertion.sub == 'b'", "oidc": {"issuerUri": "https://x", "allowedAudiences": ["x"]}}`, `{aud="x"}`, "https://x", false,
			[]trust.Anomaly{miscasedKey("", "AttributeCondition", "attributeCondition", "attributeCondition", "AttributeCondition")},
			[]eval.Caveat{{Reason: miscasedKey("", "AttributeCondition", "attributeCondition", "attributeCondition", "AttributeCondition").Message, Source: "AttributeCondition"}}},
		{`{"Disabled": true, "State": "DELETED", "oidc": {"issuerUri": "https://x", "allowedAudiences": ["x"]}}`, `{aud="x"}`, "https://x", false,
			[]trust.Anomaly{miscasedKey("", "Disabled", "disabled", "disabled", "Disabled"), miscasedKey("", "State", "state", "state", "State")},
			[]eval.Caveat{{Reason: miscasedKey("", "Disabled", "disabled", "disabled", "Disabled").Message, Source: "Disabled"}, {Reason: miscasedKey("", "State", "state", "state", "State").Message, Source: "State"}}},
		// Labels are facts: the issuer is "" and the name is not read, so the
		// default audience cannot be derived.
		{`{"Name": "` + providerName + `", "oidc": {"IssuerUri": "https://x", "allowedAudiences": ["x"]}}`, `{aud="x"}`, "", true,
			[]trust.Anomaly{miscasedKey("", "IssuerUri", "issuerUri", "issuerUri", "oidc.IssuerUri"), miscasedKey("", "Name", "name", "name", "Name")}, nil},
		{`{"Name": "` + providerName + `", "oidc": {"issuerUri": "https://x"}}`, `{}`, "https://x", false,
			[]trust.Anomaly{
				{Kind: DefaultAudience, Claim: "aud", Construct: "allowedAudiences", Message: "allowedAudiences is empty and the name is not read, so the audience Google requires, the provider's full resource name, cannot be derived and aud is read as unconstrained", Source: "oidc.allowedAudiences"},
				miscasedKey("", "Name", "name", "name", "Name"),
			},
			[]eval.Caveat{{Claim: "aud", Reason: "allowedAudiences is empty and the name is not read, so the audience Google requires, the provider's full resource name, cannot be derived and aud is read as unconstrained", Source: "oidc.allowedAudiences"}}},
		// An AWS provider whose custom mapping is not read does not fall back
		// to Google's default: under a folding reader the custom mapping
		// would apply, so google.subject is unattributable, not the ARN.
		{`{"aws": {"accountId": "1"}, "AttributeMapping": {"google.subject": "assertion.account"}, "attributeCondition": "google.subject == '1'"}`, `{aws:principalaccount="1"}`, awsIssuer, false,
			[]trust.Anomaly{
				miscasedKey("", "AttributeMapping", "attributeMapping", "attributeMapping", "AttributeMapping"),
				{Kind: trust.Unmodelled, Construct: "google.subject", Message: `"google.subject == '1'" constrains google.subject, but the attribute mapping is not read, so which claim the clause constrains is not stated and nothing it says about the credential is modelled`, Source: "attributeCondition"},
			},
			[]eval.Caveat{{Reason: `"google.subject == '1'" constrains google.subject, but the attribute mapping is not read, so which claim the clause constrains is not stated and nothing it says about the credential is modelled`, Source: "attributeCondition"}}},
		// A miscased provider_config member counts as set, so that it neither
		// vanishes nor reads as no provider at all; the member itself is not
		// read, so the audience is Unknown and the issuer unknown.
		{`{"Oidc": {"issuerUri": "https://x", "allowedAudiences": ["x"]}, "attributeCondition": "assertion.sub == 'a'"}`, `{aud=?("miscased key"), sub="a"}`, "", false,
			[]trust.Anomaly{miscasedKey("aud", "Oidc", "oidc", "oidc", "Oidc")},
			[]eval.Caveat{{Claim: "aud", Reason: miscasedKey("aud", "Oidc", "oidc", "oidc", "Oidc").Message, Source: "Oidc"}}},
		{`{"Oidc": {"issuerUri": "https://x"}, "aws": {"accountId": "1"}}`, `{}`, "", false,
			[]trust.Anomaly{
				miscasedKey("", "Oidc", "oidc", "oidc", "Oidc"),
				{Kind: trust.Unmodelled, Construct: "provider_config", Message: "both aws and oidc are set; Google says provider_config can be only one of them, so which identity provider this provider trusts, and the shape of its credential, is not stated", Source: "provider_config"},
			},
			[]eval.Caveat{{Reason: miscasedKey("", "Oidc", "oidc", "oidc", "Oidc").Message, Source: "Oidc"}, {Reason: "both aws and oidc are set; Google says provider_config can be only one of them, so which identity provider this provider trusts, and the shape of its credential, is not stated", Source: "provider_config"}}},
		{`{"SAML": {"idpMetadataXml": "<x/>"}}`, `{}`, "", false,
			[]trust.Anomaly{
				miscasedKey("", "SAML", "saml", "saml", "SAML"),
				{Kind: trust.Unmodelled, Construct: "saml", Message: samlSentence, Source: "saml"},
			},
			[]eval.Caveat{{Reason: miscasedKey("", "SAML", "saml", "saml", "SAML").Message, Source: "SAML"}, {Reason: samlSentence, Source: "saml"}}},
	}
	for _, c := range cases {
		p, g := parseOne(t, []byte(c.raw))
		if g.Admits.String() != c.admits || g.Issuer != c.issuer || g.Exact() != c.exact {
			t.Errorf("%s: admits %s issuer %q exact %v, want %s %q %v", c.raw, g.Admits, g.Issuer, g.Exact(), c.admits, c.issuer, c.exact)
		}
		if !slices.Equal(g.Anomalies, canonical(c.anomalies)) {
			t.Errorf("%s: anomalies%s\n  want%s", c.raw, renderAnomalies(g.Anomalies), renderAnomalies(canonical(c.anomalies)))
		}
		normalised := eval.Nothing()
		for _, cv := range c.caveats {
			normalised = normalised.WithCaveat(cv)
		}
		if !slices.Equal(g.Admits.Caveats(), normalised.Caveats()) {
			t.Errorf("%s: caveats\n%s  want\n%s", c.raw, renderCaveats(g.Admits.Caveats()), renderCaveats(normalised.Caveats()))
		}
		if p.Disabled || p.State != "" || p.AttributeMapping != nil {
			t.Errorf("%s: a miscased member was read: %+v", c.raw, p)
		}
	}
	// A name from another script that only Unicode folding would equate is
	// another member, not a misspelling.
	_, g := parseOne(t, []byte(`{"ｎame": "x", "oidc": {"issuerUri": "https://x", "allowedAudiences": ["x"]}}`))
	if !g.Exact() || len(g.Anomalies) != 0 {
		t.Errorf("fullwidth: %v%s", g.Admits.Caveats(), renderAnomalies(g.Anomalies))
	}
}

// TestNullMembersAreAbsent: proto3 JSON writes an unset member as absent or
// null, and an unset string as "", so each reads as absent, exactly.
func TestNullMembersAreAbsent(t *testing.T) {
	_, g := parseOne(t, []byte(`{"name": null, "state": null, "disabled": null, "attributeMapping": null, "attributeCondition": null, "expireTime": null, "oidc": {"issuerUri": "https://x", "allowedAudiences": null}}`))
	if g.Admits.String() != `{}` || len(g.Anomalies) != 1 || g.Anomalies[0].Kind != DefaultAudience || !hasCaveatOn(g.Admits.Caveats(), "aud") {
		t.Errorf("nulls: %s%s", g.Admits, renderAnomalies(g.Anomalies))
	}
	_, g = parseOne(t, []byte(`{"state": "", "attributeCondition": "", "name": "", "oidc": {"issuerUri": "https://x", "allowedAudiences": ["x"]}}`))
	if g.Admits.String() != `{aud="x"}` || len(g.Anomalies) != 0 {
		t.Errorf("empty strings: %s%s", g.Admits, renderAnomalies(g.Anomalies))
	}
	// Whitespace alone is a condition Google would try to parse, and this
	// parser cannot read it.
	_, g = parseOne(t, []byte(`{"attributeCondition": " ", "oidc": {"issuerUri": "https://x", "allowedAudiences": ["x"]}}`))
	if g.Admits.String() != `{aud="x"}` || len(g.Anomalies) != 1 || g.Anomalies[0].Construct != "unparseable expression" {
		t.Errorf("blank condition: %s%s", g.Admits, renderAnomalies(g.Anomalies))
	}
}

// TestStateForms: only DELETED is a fact about admission; an unspecified
// state is the proto3 default and an undocumented value is read as active
// with the doubt stated, never as admitting nobody.
func TestStateForms(t *testing.T) {
	for _, state := range []string{`"ACTIVE"`, `"STATE_UNSPECIFIED"`} {
		_, g := parseOne(t, []byte(`{"state": `+state+`, "oidc": {"issuerUri": "https://x", "allowedAudiences": ["x"]}}`))
		if !g.Exact() || len(g.Anomalies) != 0 {
			t.Errorf("state %s: %v%s", state, g.Admits.Caveats(), renderAnomalies(g.Anomalies))
		}
	}
	_, g := parseOne(t, []byte(`{"state": "deleted", "attributeCondition": "assertion.sub == 'a'", "oidc": {"issuerUri": "https://x", "allowedAudiences": ["x"]}}`))
	want := trust.Anomaly{Kind: trust.Unmodelled, Construct: "deleted", Message: `state is "deleted"; Google documents STATE_UNSPECIFIED, ACTIVE and DELETED, so whether the provider can be used to exchange tokens is not stated and the set stated is read as an upper bound`, Source: "state"}
	if g.Admits.String() != `{aud="x", sub="a"}` || !slices.Equal(g.Anomalies, []trust.Anomaly{want}) || !hasCaveatOn(g.Admits.Caveats(), "") {
		t.Errorf("state deleted: %s%s %v", g.Admits, renderAnomalies(g.Anomalies), g.Admits.Caveats())
	}
	_, g = parseOne(t, []byte(`{"disabled": false, "oidc": {"issuerUri": "https://x", "allowedAudiences": ["x"]}}`))
	if !g.Exact() || len(g.Anomalies) != 0 {
		t.Errorf("disabled false: %v%s", g.Admits.Caveats(), renderAnomalies(g.Anomalies))
	}
	// Disabled and deleted together are two facts, both recorded.
	_, g = parseOne(t, []byte(`{"disabled": true, "state": "DELETED", "oidc": {"issuerUri": "https://x", "allowedAudiences": ["x"]}}`))
	if len(g.Anomalies) != 2 || g.Anomalies[0].Kind != ProviderDeleted || g.Anomalies[1].Kind != ProviderDisabled || len(g.Admits.Caveats()) != 2 {
		t.Errorf("both: %s %v", renderAnomalies(g.Anomalies), g.Admits.Caveats())
	}
}

// TestAudienceForms: Google's limit of ten is a fact, this parser's cap is
// a widening, an empty audience is Unknown, and a name the default cannot
// be derived from leaves aud Unknown.
func TestAudienceForms(t *testing.T) {
	numbered := func(n int) []string {
		out := make([]string, n)
		for i := range out {
			out[i] = "aud" + strconv.Itoa(i)
		}
		return out
	}
	doc := func(audiences any, name string) []byte {
		d := map[string]any{"oidc": map[string]any{"issuerUri": "https://x", "allowedAudiences": audiences}}
		if name != "" {
			d["name"] = name
		}
		return mustJSON(d)
	}
	_, g := parseOne(t, doc(numbered(11), ""))
	if strings.Count(g.Admits.String(), "|") != 10 || !g.Exact() || len(g.Anomalies) != 1 || g.Anomalies[0] != (trust.Anomaly{Kind: AudienceCount, Claim: "aud", Construct: "allowedAudiences", Message: "11 audiences are set; Google accepts at most 10, so the provider is read as accepting any of them", Source: "oidc.allowedAudiences"}) {
		t.Errorf("11: %s %v%s", g.Admits, g.Admits.Caveats(), renderAnomalies(g.Anomalies))
	}
	_, g = parseOne(t, doc(numbered(audienceCap+1), ""))
	if g.Admits.String() != `{}` || len(g.Anomalies) != 1 || g.Anomalies[0] != (trust.Anomaly{Kind: AudienceCount, Claim: "aud", Construct: "allowedAudiences", Message: strconv.Itoa(audienceCap+1) + " audiences are set; Google accepts at most 10 and this parser reads at most " + strconv.Itoa(audienceCap) + ", so aud is read as unconstrained", Source: "oidc.allowedAudiences"}) || !hasCaveatOn(g.Admits.Caveats(), "aud") {
		t.Errorf("cap: %s%s", g.Admits, renderAnomalies(g.Anomalies))
	}
	_, g = parseOne(t, doc([]string{"x", ""}, ""))
	if g.Admits.String() != `{}` || len(g.Anomalies) != 1 || g.Anomalies[0] != (trust.Anomaly{Kind: trust.Unmodelled, Claim: "aud", Construct: "empty audience", Message: "allowedAudiences[1] is the empty string; no documented issuer mints a token whose aud is empty and Google does not say what the provider does with one, so aud is read as unconstrained", Source: "oidc.allowedAudiences"}) || !hasCaveatOn(g.Admits.Caveats(), "aud") {
		t.Errorf("empty: %s%s", g.Admits, renderAnomalies(g.Anomalies))
	}
	for _, name := range []string{
		"projects/my-project/locations/global/workloadIdentityPools/github/providers/github",
		"projects/123/locations/global/workloadIdentityPools/github",
		"projects/123/locations/global/workloadIdentityPools/github/providers/github/extra",
		"projects/123/locations//workloadIdentityPools/github/providers/github",
		"projects/123/locations/global/workloadIdentityPools/github/providers/",
		"//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/github/providers/github",
		"projects/12a/locations/global/workloadIdentityPools/github/providers/github",
		"x",
	} {
		_, g := parseOne(t, doc([]string{}, name))
		want := trust.Anomaly{Kind: DefaultAudience, Claim: "aud", Construct: "allowedAudiences", Message: "allowedAudiences is empty and name " + strconv.Quote(name) + " is not of the form projects/<number>/locations/<location>/workloadIdentityPools/<pool>/providers/<provider>, so the audience Google requires cannot be derived and aud is read as unconstrained", Source: "oidc.allowedAudiences"}
		if g.Admits.String() != `{}` || !slices.Equal(g.Anomalies, []trust.Anomaly{want}) || !hasCaveatOn(g.Admits.Caveats(), "aud") {
			t.Errorf("name %q: %s%s", name, g.Admits, renderAnomalies(g.Anomalies))
		}
	}
	_, g = parseOne(t, []byte(`{"name": "`+providerName+`", "name": "`+providerName+`", "oidc": {"issuerUri": "https://x"}}`))
	unread := trust.Anomaly{Kind: DefaultAudience, Claim: "aud", Construct: "allowedAudiences", Message: "allowedAudiences is empty and the name is not read, so the audience Google requires, the provider's full resource name, cannot be derived and aud is read as unconstrained", Source: "oidc.allowedAudiences"}
	if g.Admits.String() != `{}` || !slices.Contains(g.Anomalies, unread) || !hasCaveatOn(g.Admits.Caveats(), "aud") {
		t.Errorf("name written twice: %s%s", g.Admits, renderAnomalies(g.Anomalies))
	}
	_, g = parseOne(t, doc(nil, "projects/1/locations/europe-west1/workloadIdentityPools/p/providers/q"))
	if g.Admits.String() != `{aud=("//iam.googleapis.com/projects/1/locations/europe-west1/workloadIdentityPools/p/providers/q" | "https://iam.googleapis.com/projects/1/locations/europe-west1/workloadIdentityPools/p/providers/q")}` || !g.Exact() {
		t.Errorf("derived: %s %v", g.Admits, g.Admits.Caveats())
	}
	// A condition on aud meets the audience, whatever it says.
	_, g = parseOne(t, []byte(`{"attributeCondition": "assertion.aud == 'x'", "oidc": {"issuerUri": "https://x", "allowedAudiences": ["x", "y"]}}`))
	if g.Admits.String() != `{aud="x"}` {
		t.Errorf("aud met: %s", g.Admits)
	}
}

// TestIssuerForms: the issuer is the registry key of what was written, or
// "" with the fact stated.
func TestIssuerForms(t *testing.T) {
	cases := map[string]struct {
		issuer  trust.IssuerRef
		kind    string
		message string
	}{
		`"https://Token.Actions.GitHubUserContent.com/"`: {github, "", ""},
		`"https://gitlab.com/"`:                          {"https://gitlab.com", "", ""},
		`"http://gitlab.com"`:                            {"https://gitlab.com", IssuerScheme, `issuerUri "http://gitlab.com" does not begin with https://; Google says the issuer must be an HTTPS endpoint, and it is read as the issuer it resembles`},
		`"gitlab.com"`:                                   {"https://gitlab.com", IssuerScheme, `issuerUri "gitlab.com" does not begin with https://; Google says the issuer must be an HTTPS endpoint, and it is read as the issuer it resembles`},
		`""`:                                             {"", MissingIssuer, "no issuerUri is set; Google requires one, so which identity provider this provider trusts is not stated"},
		`null`:                                           {"", MissingIssuer, "no issuerUri is set; Google requires one, so which identity provider this provider trusts is not stated"},
		`"https://"`:                                     {"", MissingIssuer, `issuerUri "https://" names no host, so which identity provider this provider trusts is not stated`},
		`"https:///path"`:                                {"", MissingIssuer, `issuerUri "https:///path" names no host, so which identity provider this provider trusts is not stated`},
		`" https://gitlab.com "`:                         {"https://gitlab.com", IssuerWhitespace, `issuerUri " https://gitlab.com " has leading or trailing whitespace; Google says the issuer must be an HTTPS endpoint, and it is read as the issuer it resembles with the whitespace removed`},
		`"  "`:                                           {"", MissingIssuer, `issuerUri "  " names no host, so which identity provider this provider trusts is not stated`},
	}
	for written, want := range cases {
		_, g := parseOne(t, []byte(`{"oidc": {"issuerUri": `+written+`, "allowedAudiences": ["x"]}}`))
		if g.Issuer != want.issuer || !g.Exact() {
			t.Errorf("%s: issuer %q exact %v, want %q", written, g.Issuer, g.Exact(), want.issuer)
		}
		if want.kind == "" {
			if len(g.Anomalies) != 0 {
				t.Errorf("%s: %s", written, renderAnomalies(g.Anomalies))
			}
			continue
		}
		if len(g.Anomalies) != 1 || g.Anomalies[0] != (trust.Anomaly{Kind: want.kind, Construct: "issuerUri", Message: want.message, Source: "oidc.issuerUri"}) {
			t.Errorf("%s: %s", written, renderAnomalies(g.Anomalies))
		}
	}
	_, g := parseOne(t, []byte(`{"oidc": {"allowedAudiences": ["x"]}}`))
	if g.Issuer != "" || len(g.Anomalies) != 1 || g.Anomalies[0].Kind != MissingIssuer {
		t.Errorf("absent: %q %s", g.Issuer, renderAnomalies(g.Anomalies))
	}
}

// TestProviderConfigUnion: none of the four, or more than one, leaves the
// identity provider and the claim space unstated; the condition is still
// kept on the Provider, unread.
func TestProviderConfigUnion(t *testing.T) {
	_, g := parseOne(t, []byte(`{"oidc": {"issuerUri": "https://x", "allowedAudiences": ["x"]}, "aws": {"accountId": "1"}, "attributeCondition": "assertion.sub == 'a'"}`))
	want := []trust.Anomaly{
		{Kind: trust.Unmodelled, Construct: "assertion.sub", Message: `"assertion.sub == 'a'" constrains assertion.sub, but the provider sets both aws and oidc, which Google says cannot be, leaving the shape of its credential unstated, so nothing it says about the credential is modelled`, Source: "attributeCondition"},
		{Kind: trust.Unmodelled, Construct: "provider_config", Message: "both aws and oidc are set; Google says provider_config can be only one of them, so which identity provider this provider trusts, and the shape of its credential, is not stated", Source: "provider_config"},
	}
	if g.Admits.String() != "{}" || g.Issuer != "" || !slices.Equal(g.Anomalies, want) || len(g.Admits.Caveats()) != 2 {
		t.Errorf("two: %s %q%s %v", g.Admits, g.Issuer, renderAnomalies(g.Anomalies), g.Admits.Caveats())
	}
	p, g := parseOne(t, []byte(`{"oidc": {}, "aws": {}, "saml": {}, "x509": {}}`))
	if p.Type != "" || p.OIDC != nil || p.AWS != nil || len(g.Anomalies) != 1 || !strings.HasPrefix(g.Anomalies[0].Message, "aws, oidc, saml and x509 are all set;") {
		t.Errorf("four: %+v%s", p, renderAnomalies(g.Anomalies))
	}
	p, g = parseOne(t, []byte(`{"attributeCondition": "assertion.sub == 'a'"}`))
	if p.Type != "" || g.Admits.String() != "{}" || len(g.Anomalies) != 2 || g.Anomalies[0].Kind != MissingIssuer || !hasCaveatOn(g.Admits.Caveats(), "") {
		t.Errorf("none: %+v %s%s", p, g.Admits, renderAnomalies(g.Anomalies))
	}
	// An x509 provider with a condition: the kind's doubt and the clause's.
	_, g = parseOne(t, []byte(`{"x509": {"trustStore": {}}, "attributeCondition": "assertion.subject.dn.cn == 'a'"}`))
	if len(g.Anomalies) != 2 || g.Anomalies[0].Construct != "assertion.subject.dn.cn" || g.Anomalies[1].Construct != "x509" {
		t.Errorf("x509: %s", renderAnomalies(g.Anomalies))
	}
}

// TestMappingForms: keys Google does not document, values of the wrong
// type, and the empty mapping under an AWS provider.
func TestMappingForms(t *testing.T) {
	_, g := parseOne(t, []byte(`{"attributeMapping": {"foo": "assertion.sub", "google.subject": 1, "attribute.ok": "assertion.ok"}, "attributeCondition": "google.subject == 'a' && attribute.ok == 'b'", "oidc": {"issuerUri": "https://x", "allowedAudiences": ["x"]}}`))
	want := []trust.Anomaly{
		{Kind: Malformed, Construct: "foo", Message: `attributeMapping key "foo" is not google.subject, google.groups or attribute.<name>, which are the keys Google documents, so it is not read`, Source: "attributeMapping.foo"},
		{Kind: Malformed, Construct: "google.subject", Message: "attributeMapping.google.subject is a number; Google defines it as a string, so it is not read", Source: "attributeMapping.google.subject"},
		{Kind: trust.Unmodelled, Construct: "google.subject", Message: `"google.subject == 'a'" constrains google.subject, which the attribute mapping maps by a number, not a string, so which claim the clause constrains is not stated and nothing it says about the credential is modelled`, Source: "attributeCondition"},
	}
	if g.Admits.String() != `{aud="x", ok="b"}` || !slices.Equal(g.Anomalies, want) {
		t.Errorf("%s%s\n  want%s", g.Admits, renderAnomalies(g.Anomalies), renderAnomalies(want))
	}
	p, _ := parseOne(t, []byte(`{"attributeMapping": {"foo": "assertion.sub", "google.subject": 1, "attribute.ok": "assertion.ok"}, "oidc": {"issuerUri": "https://x", "allowedAudiences": ["x"]}}`))
	if !maps.Equal(p.AttributeMapping, map[string]string{"attribute.ok": "assertion.ok"}) {
		t.Errorf("read mapping: %v", p.AttributeMapping)
	}
	// A null value is an unset entry.
	p, g = parseOne(t, []byte(`{"attributeMapping": {"google.subject": null, "attribute.ok": "assertion.ok"}, "attributeCondition": "attribute.ok == 'b'", "oidc": {"issuerUri": "https://x", "allowedAudiences": ["x"]}}`))
	if !maps.Equal(p.AttributeMapping, map[string]string{"attribute.ok": "assertion.ok"}) || g.Admits.String() != `{aud="x", ok="b"}` || len(g.Anomalies) != 0 {
		t.Errorf("null entry: %v %s%s", p.AttributeMapping, g.Admits, renderAnomalies(g.Anomalies))
	}
	// The empty mapping is the proto3 default: for AWS the documented
	// default applies, and google.subject is the ARN.
	_, g = parseOne(t, []byte(`{"aws": {"accountId": "1"}, "attributeMapping": {}, "attributeCondition": "google.subject == 'arn:aws:sts::1:assumed-role/x/y'"}`))
	if g.Admits.String() != `{arn="arn:aws:sts::1:assumed-role/x/y", aws:principalaccount="1"}` || !g.Exact() {
		t.Errorf("aws default: %s %v", g.Admits, g.Admits.Caveats())
	}
	// A custom AWS mapping replaces the default entirely, as Google says
	// it must then include google.subject.
	_, g = parseOne(t, []byte(`{"aws": {"accountId": "1"}, "attributeMapping": {"attribute.account": "assertion.account"}, "attributeCondition": "google.subject == 'x' || attribute.account == '1'"}`))
	if g.Admits.String() != `{aws:principalaccount="1"}` || g.Exact() || len(g.Anomalies) != 1 || g.Anomalies[0].Construct != "google.subject" {
		t.Errorf("aws custom: %s%s", g.Admits, renderAnomalies(g.Anomalies))
	}
	// An unreadable mapping expression is unattributable when referenced.
	_, g = parseOne(t, []byte(`{"attributeMapping": {"google.subject": "assertion.sub +"}, "attributeCondition": "google.subject == 'a'", "oidc": {"issuerUri": "https://x", "allowedAudiences": ["x"]}}`))
	if g.Admits.String() != `{aud="x"}` || len(g.Anomalies) != 1 || g.Anomalies[0].Construct != "assertion.sub +" || !strings.Contains(g.Anomalies[0].Message, `which the attribute mapping maps by "assertion.sub +", which is not an expression this parser can read, so which claim`) {
		t.Errorf("unreadable mapping: %s%s", g.Admits, renderAnomalies(g.Anomalies))
	}
	// attributeMapping not an object: the mapping is written but not read,
	// so what it maps is not stated, which is not the same as mapping nothing.
	_, g = parseOne(t, []byte(`{"attributeMapping": "x", "attributeCondition": "google.subject == 'a' && assertion.sub == 'b'", "oidc": {"issuerUri": "https://x", "allowedAudiences": ["x"]}}`))
	if g.Admits.String() != `{aud="x", sub="b"}` || len(g.Anomalies) != 2 || g.Anomalies[0].Kind != Malformed || g.Anomalies[1].Message != `"google.subject == 'a'" constrains google.subject, but the attribute mapping is not read, so which claim the clause constrains is not stated and nothing it says about the credential is modelled` {
		t.Errorf("mapping not an object: %s%s", g.Admits, renderAnomalies(g.Anomalies))
	}
	// An AWS provider whose mapping is not read gets no default mapping.
	_, g = parseOne(t, []byte(`{"aws": {"accountId": "1"}, "attributeMapping": {"google.subject": "assertion.account"}, "attributeMapping": {}, "attributeCondition": "google.subject == '1'"}`))
	if g.Admits.String() != `{aws:principalaccount="1"}` || g.Exact() || len(g.Anomalies) != 2 || g.Anomalies[0].Kind != DuplicateKey || !strings.Contains(g.Anomalies[1].Message, "but the attribute mapping is not read") {
		t.Errorf("aws unread mapping: %s%s", g.Admits, renderAnomalies(g.Anomalies))
	}
}

// TestLargeDocumentsParseInBoundedTime: every list a document can inflate
// is read up to a cap or in linear time, so a document built to be large
// parses in well under a second.
func TestLargeDocumentsParseInBoundedTime(t *testing.T) {
	audiences := make([]string, 200000)
	for i := range audiences {
		audiences[i] = "aud" + strconv.Itoa(i)
	}
	mapping := map[string]any{}
	for i := 0; i < 20000; i++ {
		mapping["attribute.a"+strconv.Itoa(i)] = "assertion.a" + strconv.Itoa(i)
	}
	clauses := make([]string, 300)
	for i := range clauses {
		clauses[i] = "assertion.c" + strconv.Itoa(i) + " == 'v'"
	}
	docs := [][]byte{
		mustJSON(map[string]any{"oidc": map[string]any{"issuerUri": "https://x", "allowedAudiences": audiences}}),
		mustJSON(map[string]any{"attributeMapping": mapping, "attributeCondition": "attribute.a19999 == 'x'", "oidc": map[string]any{"issuerUri": "https://x", "allowedAudiences": []string{"x"}}}),
		mustJSON(map[string]any{"attributeCondition": strings.Join(clauses, " || "), "oidc": map[string]any{"issuerUri": "https://x", "allowedAudiences": []string{"x"}}}),
		mustJSON(map[string]any{"attributeCondition": strings.Join(clauses, " && "), "oidc": map[string]any{"issuerUri": "https://x", "allowedAudiences": []string{"x"}}}),
		mustJSON(map[string]any{"attributeCondition": strings.Repeat("!", 4000) + "(assertion.sub == 'a')", "oidc": map[string]any{"issuerUri": "https://x", "allowedAudiences": []string{"x"}}}),
		mustJSON(map[string]any{"attributeCondition": strings.Repeat("assertion.sub != 'a' && ", 150) + "true", "oidc": map[string]any{"issuerUri": "https://x", "allowedAudiences": []string{"x"}}}),
		[]byte(`{"oidc": {"issuerUri": "https://x"}, "x509": {"trustStore": ` + strings.Repeat("[", 900) + strings.Repeat("]", 900) + `}}`),
	}
	for i, raw := range docs {
		start := time.Now()
		_, g := parseOne(t, raw)
		if took := time.Since(start); took > 2*time.Second {
			t.Errorf("document %d took %v", i, took)
		}
		if g.Admits.IsEmpty() {
			t.Errorf("document %d admits nothing", i)
		}
	}
}

// TestTermCapWidensWithItsCaveat: a condition whose disjunctive normal
// form exceeds the lattice's term cap is everything from the issuer, with
// the lattice's own caveat carried onto the grant; the audience still
// applies.
func TestTermCapWidensWithItsCaveat(t *testing.T) {
	groups := make([]string, 9)
	for i := range groups {
		claim := "assertion.c" + strconv.Itoa(i)
		groups[i] = "(" + claim + " == '1' || " + claim + " == '2')"
	}
	_, g := parseOne(t, mustJSON(map[string]any{"attributeCondition": strings.Join(groups, " && "), "oidc": map[string]any{"issuerUri": "https://x", "allowedAudiences": []string{"x"}}}))
	if g.Admits.String() != `{aud="x"}` || g.Exact() || len(g.Anomalies) != 0 {
		t.Errorf("%s %v%s", g.Admits, g.Admits.Caveats(), renderAnomalies(g.Anomalies))
	}
	if caveats := g.Admits.Caveats(); len(caveats) != 1 || !strings.Contains(caveats[0].Reason, "term count exceeded") {
		t.Errorf("%v", caveats)
	}
	// One group fewer fits: 256 terms, every one exact.
	_, g = parseOne(t, mustJSON(map[string]any{"attributeCondition": strings.Join(groups[:8], " && "), "oidc": map[string]any{"issuerUri": "https://x", "allowedAudiences": []string{"x"}}}))
	if strings.Count(g.Admits.String(), " | ") != 255 || !g.Exact() {
		t.Errorf("%d terms, exact %v", strings.Count(g.Admits.String(), " | ")+1, g.Exact())
	}
}

// TestSentencesArePrintable: control characters in the document never
// reach a sentence, whichever member carries them.
func TestSentencesArePrintable(t *testing.T) {
	esc := `\u001b[2K`
	_, g := parseOne(t, []byte(`{"state": "x`+esc+`", "attributeMapping": {"foo`+esc+`": "x", "attribute.a": "assertion.a.b`+esc+`"}, "attributeCondition": "attribute.a == 'x' && assertion.b != '`+esc+`'", "oidc": {"issuerUri": "http://x`+esc+`", "allowedAudiences": ["x"]}, "Name`+esc+`": "x"}`))
	if len(g.Anomalies) < 5 {
		t.Fatalf("%s", renderAnomalies(g.Anomalies))
	}
	for _, a := range g.Anomalies {
		if strings.ContainsRune(a.Message, 0x1b) || strings.ContainsRune(a.Construct, 0x1b) {
			t.Errorf("escape in a sentence: %+v", a)
		}
	}
}

// TestDeterminism is the section 2 promise at this layer, run in-process;
// the Makefile runs it again in fresh processes.
func TestDeterminism(t *testing.T) {
	names := slices.Sorted(maps.Keys(golden))
	names = append(names, "22-list")
	first := map[string]string{}
	for i := 0; i < 20; i++ {
		for _, name := range names {
			var rendered string
			if name == "22-list" {
				providers, err := ParseProviders(fixture(t, name))
				if err != nil {
					t.Fatal(err)
				}
				for _, p := range providers {
					g := p.Grants(githubProvider)[0]
					rendered += fingerprint(g)
				}
			} else if g, bound := grantOf(t, name); bound {
				rendered = fingerprint(g)
			} else {
				rendered = "not bound"
			}
			if prior, seen := first[name]; seen && prior != rendered {
				t.Fatalf("%s: run %d rendered differently:\n%s\n---\n%s", name, i, prior, rendered)
			}
			first[name] = rendered
		}
	}
	if len(first) != len(names) {
		t.Fatalf("rendered %d of %d documents", len(first), len(names))
	}
}

// fingerprint is everything a Grant states, rendered, for equality.
func fingerprint(g trust.Grant) string {
	return string(g.Issuer) + "\n" + string(g.Effect) + "\n" + g.Admits.String() + "\n" + renderCaveats(g.Admits.Caveats()) + renderAnomalies(g.Anomalies) + "\n"
}

// TestAnomaliesAreSortedNotAppended: facts recorded in document order come
// back in canonical order, so a reordered document renders the same list.
func TestAnomaliesAreSortedNotAppended(t *testing.T) {
	forward := `{"disabled": true, "attributeCondition": "assertion.a != 'x' && assertion.b.matches('y')", "oidc": {"issuerUri": "http://x", "allowedAudiences": ["x"]}}`
	backward := `{"oidc": {"allowedAudiences": ["x"], "issuerUri": "http://x"}, "attributeCondition": "assertion.b.matches('y') && assertion.a != 'x'", "disabled": true}`
	_, a := parseOne(t, []byte(forward))
	_, b := parseOne(t, []byte(backward))
	if !slices.Equal(a.Anomalies, b.Anomalies) || a.Admits.String() != b.Admits.String() || !slices.Equal(a.Admits.Caveats(), b.Admits.Caveats()) {
		t.Errorf("order changed the grant:%s\n---%s", renderAnomalies(a.Anomalies), renderAnomalies(b.Anomalies))
	}
	if len(a.Anomalies) != 4 || a.Anomalies[0].Kind != IssuerScheme || a.Anomalies[1].Kind != ProviderDisabled || a.Anomalies[2].Claim != "a" || a.Anomalies[3].Claim != "b" {
		t.Errorf("anomalies are not in canonical order:%s", renderAnomalies(a.Anomalies))
	}
	if !slices.Equal(a.Anomalies, canonical(a.Anomalies)) || len(canonical(nil)) != 0 {
		t.Errorf("canonical is not idempotent")
	}
}

// TestAWSIssuerIsTheAWSParsers: the pseudo-issuer under which the join
// pairs a GCP AWS provider with an AWS trust policy is the AWS parser's
// own constant, and the account claim is the one that parser puts an
// account under; a copy that drifted would pair nothing, silently.
func TestAWSIssuerIsTheAWSParsers(t *testing.T) {
	if awsIssuer != aws.AWSPrincipalIssuer {
		t.Errorf("awsIssuer %q, the AWS parser's %q", awsIssuer, aws.AWSPrincipalIssuer)
	}
	policy, err := aws.ParseTrustPolicy([]byte(`{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"AWS": "123456789012"}, "Action": "sts:AssumeRole"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	theirs := policy.Grants(trust.TargetRef{Kind: "role", ID: "arn:aws:iam::999999999999:role/Deploy"}, aws.LowercaseVocabulary())
	_, ours := parseOne(t, fixture(t, "19-aws"))
	if len(theirs) != 1 || theirs[0].Issuer != ours.Issuer || !theirs[0].Exact() {
		t.Fatalf("the AWS parser's grant: %+v", theirs)
	}
	account := func(g trust.Grant) string {
		for _, term := range g.Admits.Terms() {
			if s, ok := term[accountClaim]; ok {
				return s.String()
			}
		}
		return ""
	}
	if account(theirs[0]) != `"123456789012"` || account(ours) != `"123456789012"` {
		t.Errorf("the account claim differs: AWS parser %q, this parser %q", account(theirs[0]), account(ours))
	}
}
