package azure

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
	"github.com/CloudArq-net/cloudarq/internal/trust"
)

// credentialsDir holds one document per row of the Pass 1 table, each with
// a sibling rationale. Loaded by tests only; the package reads no files.
const credentialsDir = "../../../testdata/credentials"

const (
	audience   = `aud="api://AzureADTokenExchange"`
	mainBranch = "repo:acme/infra:ref:refs/heads/main"
	githubText = `"https://token.actions.githubusercontent.com"`
)

var infraApp = trust.TargetRef{Kind: "application", ID: "6b1e6c7e-0f1a-4d2b-9c3d-8e4f5a6b7c8d"}

// fact is an expected anomaly, and whether it also caveats the admitted set.
type fact struct {
	anomaly trust.Anomaly
	doubt   bool
}

// The sentences a fact prints, pinned once where several documents share
// them: a drift in one is a change in what the product says.
const (
	noSubjectConstraint = "neither subject nor claimsMatchingExpression constrains the subject; a Graph v1.0 read omits claimsMatchingExpression, so a constraint on sub may exist that this document does not show"
	emptySubject        = "subject is the empty string; Graph documents subject as nullable and no documented issuer mints a token whose sub is empty, so it is read as no subject"
	notOfTheForm        = " is not of the form claims['<name>'] eq '<value>' or claims['<name>'] matches '<value>'; Microsoft documents no other form, so nothing the expression says about the token is modelled"
)

// golden is what each document must parse to: the admitted set rendered
// canonically, the issuer, and every anomaly with its sentence. A caveat is
// expected for exactly the facts marked doubt, carrying the same sentence.
var golden = map[string]struct {
	issuer trust.IssuerRef
	admits string
	facts  []fact
}{
	"01-classic-subject":  {github, `{` + audience + `, sub="` + mainBranch + `"}`, nil},
	"02-flexible-eq":      {github, `{` + audience + `, repository_id="456789", sub="` + mainBranch + `"}`, nil},
	"03-flexible-matches": {github, `{` + audience + `, repository_owner_id="123456", sub=like:"repo:acme/*"}`, nil},
	"04-matches-everything": {github, `{` + audience + `, repository_id="456789"}`, []fact{{
		anomaly: trust.Anomaly{Kind: "undocumented-acceptance", Claim: "sub", Construct: "*",
			Message: `"claims['sub'] matches '*'" matches every value; Microsoft does not say whether Entra accepts a pattern that constrains nothing`,
			Source:  "claimsMatchingExpression.value"},
	}}},
	"05-subject-and-expression": {github,
		`{` + audience + `, repository_id="456789", sub=like:"repo:acme/*"} | {` + audience + `, sub="` + mainBranch + `"}`, []fact{{
			anomaly: trust.Anomaly{Kind: "subject-and-expression", Claim: "sub", Construct: "subject",
				Message: "subject and claimsMatchingExpression are both set; Microsoft says they are mutually exclusive, so the credential is read as admitting what either alone would",
				Source:  "subject"},
			doubt: true,
		}}},
	"06-no-subject-constraint": {github, `{` + audience + `, sub=?("no subject constraint")}`, []fact{{
		anomaly: trust.Anomaly{Kind: "no-subject-constraint", Claim: "sub", Construct: "subject", Message: noSubjectConstraint, Source: "subject"},
		doubt:   true,
	}}},
	"07-unmodelled-operator": {github, `{` + audience + `, sub=?("unparseable expression")}`, []fact{{
		anomaly: trust.Anomaly{Kind: trust.Unmodelled, Claim: "sub", Construct: "unparseable clause",
			Message: `"claims['sub'] eq 'repo:acme/infra:ref:refs/heads/main' or claims['sub'] eq 'repo:acme/infra:ref:refs/heads/dev'"` + notOfTheForm,
			Source:  "claimsMatchingExpression.value"},
		doubt: true,
	}}},
	"08-unparseable-expression": {github, `{` + audience + `, sub=?("unparseable expression")}`, []fact{{
		anomaly: trust.Anomaly{Kind: trust.Unmodelled, Claim: "sub", Construct: "unparseable clause",
			Message: `"claims[sub] == 'repo:acme/infra:ref:refs/heads/main'"` + notOfTheForm,
			Source:  "claimsMatchingExpression.value"},
		doubt: true,
	}}},
	"09-language-version-2": {github, `{` + audience + `, sub=?("language version")}`, []fact{{
		anomaly: trust.Anomaly{Kind: trust.Unmodelled, Claim: "sub", Construct: "2",
			Message: "claimsMatchingExpression.languageVersion is 2; Microsoft documents version 1 only, so the expression is not modelled",
			Source:  "claimsMatchingExpression.languageVersion"},
		doubt: true,
	}}},
	"10-missing-issuer": {"", `{` + audience + `, sub="` + mainBranch + `"}`, []fact{{
		anomaly: trust.Anomaly{Kind: "missing-issuer", Construct: "issuer",
			Message: "no issuer is set; Microsoft requires one, so which identity provider this credential trusts is not stated",
			Source:  "issuer"},
	}}},
	"11-several-audiences": {github, `{aud=("api://AzureADTokenExchange" | "api://acme-exchange"), sub="` + mainBranch + `"}`, []fact{{
		anomaly: trust.Anomaly{Kind: "audience-count", Claim: "aud", Construct: "audiences",
			Message: "2 audiences are set; Microsoft accepts exactly one, so the credential is read as accepting any of them",
			Source:  "audiences"},
	}}},
	"12-claim-name-case": {github, `{` + audience + `, repository_id="456789", sub="` + mainBranch + `"}`, []fact{
		{
			anomaly: trust.Anomaly{Kind: "claim-folded", Claim: "repository_id", Construct: "claims['REPOSITORY_ID']",
				Message: "claims['REPOSITORY_ID'] is read as claims['repository_id']; Microsoft does not say whether claim names are case-sensitive",
				Source:  "claimsMatchingExpression.value"},
			doubt: true,
		},
		{
			anomaly: trust.Anomaly{Kind: "claim-folded", Claim: "sub", Construct: "claims['SUB']",
				Message: "claims['SUB'] is read as claims['sub']; Microsoft does not say whether claim names are case-sensitive",
				Source:  "claimsMatchingExpression.value"},
			doubt: true,
		},
	}},
	"13-repeated-claim": {github, `{` + audience + `, repository_id="456789", sub=?("repeated claim")}`, []fact{{
		anomaly: trust.Anomaly{Kind: trust.Unmodelled, Claim: "sub", Construct: "repeated claim",
			Message: `claims['sub'] is constrained by 2 clauses; Microsoft documents "and" for combining expressions against different claims and does not say what a repeated claim means`,
			Source:  "claimsMatchingExpression.value"},
		doubt: true,
	}}},
	"14-no-audience": {github, `{aud=?("no audience"), sub="` + mainBranch + `"}`, []fact{{
		anomaly: trust.Anomaly{Kind: "audience-count", Claim: "aud", Construct: "audiences",
			Message: "no audience is set; Microsoft requires exactly one, so the audience this credential accepts is not stated",
			Source:  "audiences"},
		doubt: true,
	}}},
	"15-undocumented-clause": {github, `{` + audience + `, environment=?("undocumented claim"), repository_id=?("undocumented operator"), sub="` + mainBranch + `"}`, []fact{
		{
			anomaly: trust.Anomaly{Kind: trust.Unmodelled, Claim: "environment", Construct: "claims['environment']",
				Message: `Microsoft does not list claims['environment'] for issuer ` + githubText + `, so whether Entra evaluates "claims['environment'] eq 'production'" is not documented`,
				Source:  "claimsMatchingExpression.value"},
			doubt: true,
		},
		{
			anomaly: trust.Anomaly{Kind: trust.Unmodelled, Claim: "repository_id", Construct: "matches",
				Message: `Microsoft lists "eq" for claims['repository_id'] under issuer ` + githubText + `, not "matches", so whether Entra evaluates "claims['repository_id'] matches '45*'" is not documented`,
				Source:  "claimsMatchingExpression.value"},
			doubt: true,
		},
	}},
	"16-undocumented-comparand": {github, `{` + audience + `, repository_id="456789", sub=?("escaped quote")}`, []fact{{
		anomaly: trust.Anomaly{Kind: trust.Unmodelled, Claim: "sub", Construct: "escaped quote",
			Message: `the comparand of "claims['sub'] eq 'repo:acme/it''s:ref:refs/heads/main'" holds a doubled single quote; Microsoft says single quotes are escape characters and does not say what a doubled quote means`,
			Source:  "claimsMatchingExpression.value"},
		doubt: true,
	}}},
	"17-duplicate-key": {github, `{` + audience + `, sub=?("duplicate key")}`, []fact{{
		anomaly: trust.Anomaly{Kind: "duplicate-key", Claim: "sub", Construct: "subject",
			Message: `the member "subject" is written 2 times; which one Entra would apply is not stated, so it is not read`,
			Source:  "subject"},
		doubt: true,
	}}},
	"18-empty-subject": {github, `{` + audience + `, sub=?("no subject constraint")}`, []fact{
		{anomaly: trust.Anomaly{Kind: "empty-subject", Claim: "sub", Construct: "subject", Message: emptySubject, Source: "subject"}},
		{
			anomaly: trust.Anomaly{Kind: "no-subject-constraint", Claim: "sub", Construct: "subject", Message: noSubjectConstraint, Source: "subject"},
			doubt:   true,
		},
	}},
	"19-malformed-issuer": {github, `{` + audience + `, sub="` + mainBranch + `"}`, []fact{{
		anomaly: trust.Anomaly{Kind: "issuer-scheme", Construct: "issuer",
			Message: `issuer "http://token.actions.githubusercontent.com" does not begin with https://; Entra matches it against the token's iss claim, and every documented issuer states its iss as an https URL`,
			Source:  "issuer"},
	}}},
	"20-miscased-key": {github, `{` + audience + `, sub=?("no subject constraint")}`, []fact{
		{
			anomaly: trust.Anomaly{Kind: "miscased-key", Construct: "Subject",
				Message: `the member "Subject" differs from Graph's "subject" only in case; Graph member names are exact, so it is not read as subject`,
				Source:  "Subject"},
		},
		{
			anomaly: trust.Anomaly{Kind: "no-subject-constraint", Claim: "sub", Construct: "subject", Message: noSubjectConstraint, Source: "subject"},
			doubt:   true,
		},
	}},
	"21-undocumented-issuer": {google, `{` + audience + `, sub=?("undocumented issuer")}`, []fact{{
		anomaly: trust.Anomaly{Kind: trust.Unmodelled, Claim: "sub", Construct: `"https://accounts.google.com"`,
			Message: `Microsoft documents claim expressions for GitHub, GitLab and Terraform Cloud issuers; whether Entra evaluates "claims['sub'] eq '112633961854638529490'" for issuer "https://accounts.google.com" is not documented`,
			Source:  "claimsMatchingExpression.value"},
		doubt: true,
	}}},
	"22-unmodelled-clause-operator": {github, `{` + audience + `, repository_id=?("undocumented operator"), sub="` + mainBranch + `"}`, []fact{{
		anomaly: trust.Anomaly{Kind: trust.Unmodelled, Claim: "repository_id", Construct: "startsWith",
			Message: `Microsoft lists "eq" for claims['repository_id'] under issuer ` + githubText + `, not "startsWith", so whether Entra evaluates "claims['repository_id'] startsWith '4567'" is not documented`,
			Source:  "claimsMatchingExpression.value"},
		doubt: true,
	}}},
	"23-no-immutable-claim": {github, `{` + audience + `, sub=?("required claim missing")}`, []fact{{
		anomaly: trust.Anomaly{Kind: trust.Unmodelled, Claim: "sub", Construct: "missing required claim",
			Message: `the expression names no clause on repository_id or repository_owner_id; Microsoft says a flexible federated identity credential for issuer ` + githubText + ` must match one of them, so whether Entra accepts or evaluates this expression is not documented`,
			Source:  "claimsMatchingExpression.value"},
		doubt: true,
	}}},
	"24-no-sub-clause": {github, `{` + audience + `, sub=?("required claim missing")}`, []fact{{
		anomaly: trust.Anomaly{Kind: trust.Unmodelled, Claim: "sub", Construct: "missing required claim",
			Message: `the expression names no clause on sub; Microsoft says a flexible federated identity credential for issuer ` + githubText + ` must match it, so whether Entra accepts or evaluates this expression is not documented`,
			Source:  "claimsMatchingExpression.value"},
		doubt: true,
	}}},
	"25-empty-audience": {github, `{aud=?("empty audience"), sub="` + mainBranch + `"}`, []fact{{
		anomaly: trust.Anomaly{Kind: trust.Unmodelled, Claim: "aud", Construct: "empty audience",
			Message: "audiences[0] is the empty string; no documented issuer mints a token whose aud is empty and Microsoft does not say what Entra does with an empty audience, so the audience this credential accepts is not stated",
			Source:  "audiences"},
		doubt: true,
	}}},
	"26-unbalanced-quote": {github, `{` + audience + `, sub=?("unparseable expression")}`, []fact{{
		anomaly: trust.Anomaly{Kind: trust.Unmodelled, Claim: "sub", Construct: "unbalanced quote",
			Message: "the expression holds an odd number of single quotes, so where its claim names and comparands begin and end cannot be read; Microsoft's grammar encloses each in single quotes, so nothing the expression says about the token is modelled",
			Source:  "claimsMatchingExpression.value"},
		doubt: true,
	}}},
	"27-issuer-whitespace": {github, `{` + audience + `, sub="` + mainBranch + `"}`, []fact{{
		anomaly: trust.Anomaly{Kind: "issuer-whitespace", Construct: "issuer",
			Message: `issuer " https://token.actions.githubusercontent.com" has leading or trailing whitespace; Microsoft says an issuer claim with leading or trailing whitespace blocks the token exchange, so this credential may admit no token; it is read as trusting the issuer with the whitespace removed`,
			Source:  "issuer"},
	}}},
	"28-managed-identity-resource": {"https://oidc.prod-aks.azure.com/TenantGUID/IssuerGUID", `{` + audience + `, sub="system:serviceaccount:ns:svcaccount"}`, nil},
	"29-empty-subject-with-expression": {github, `{` + audience + `, repository_id="456789", sub="` + mainBranch + `"}`, []fact{
		{anomaly: trust.Anomaly{Kind: "empty-subject", Claim: "sub", Construct: "subject", Message: emptySubject, Source: "subject"}},
	}},
}

// readCredential loads one golden document by its case name.
func readCredential(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(credentialsDir, name+".json"))
	if err != nil {
		t.Fatalf("%v", err)
	}
	return raw
}

// parseOne parses a document that must be exactly one credential and
// returns its single Grant for the application target.
func parseOne(t *testing.T, raw []byte) (Credential, trust.Grant) {
	t.Helper()
	c, err := ParseFederatedCredential(raw)
	if err != nil {
		t.Fatalf("ParseFederatedCredential: %v", err)
	}
	grants := c.Grants(infraApp)
	if len(grants) != 1 {
		t.Fatalf("Grants() returned %d grants, want 1: a credential that exists is one grant", len(grants))
	}
	return c, grants[0]
}

func renderAnomalies(as []trust.Anomaly) string {
	var b strings.Builder
	for _, a := range as {
		b.WriteString("\n  " + a.Kind + " claim=" + string(a.Claim) + " construct=" + a.Construct + " source=" + a.Source + "\n    " + a.Message)
	}
	return b.String()
}

// TestGoldenCredentials: every document in the corpus parses to its stated
// grant, sentence for sentence, and every entry of the table has a document
// and a rationale, so that neither the table nor the corpus can drift alone.
func TestGoldenCredentials(t *testing.T) {
	entries, err := os.ReadDir(credentialsDir)
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
		if _, ok := golden[name]; !ok {
			t.Errorf("%s.json has no entry in the golden table; it would be examined by nothing", name)
		}
		if _, err := os.Stat(filepath.Join(credentialsDir, name+".rationale.md")); err != nil {
			t.Errorf("%s has no rationale: %v", name, err)
		}
	}
	for name := range golden {
		if !seen[name] {
			t.Errorf("golden entry %s has no document", name)
		}
	}
	if len(seen) == 0 {
		t.Fatalf("no documents under %s; the corpus is empty", credentialsDir)
	}
	for _, name := range slices.Sorted(maps.Keys(golden)) {
		want := golden[name]
		raw := readCredential(t, name)
		c, g := parseOne(t, raw)
		if g.Issuer != want.issuer {
			t.Errorf("%s: issuer %q, want %q", name, g.Issuer, want.issuer)
		}
		if got := g.Admits.String(); got != want.admits {
			t.Errorf("%s: admits %s\n  want %s", name, got, want.admits)
		}
		if g.Effect != trust.Allow || g.Target != infraApp {
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
		if !slices.Equal(c.Anomalies, g.Anomalies) {
			t.Errorf("%s: the grant's anomalies differ from the credential's", name)
		}
		gotCaveats := g.Admits.Caveats()
		if len(gotCaveats) != len(wantCaveats) {
			t.Errorf("%s: caveats %v\n  want %v", name, gotCaveats, wantCaveats)
		}
		for _, cv := range wantCaveats {
			if !slices.Contains(gotCaveats, cv) {
				t.Errorf("%s: missing caveat %+v; got %v", name, cv, gotCaveats)
			}
		}
		if g.Exact() != (len(wantCaveats) == 0) {
			t.Errorf("%s: Exact() = %v with caveats %v", name, g.Exact(), gotCaveats)
		}
		// Every Unknown claim is declared by a caveat on that claim.
		for _, term := range g.Admits.Terms() {
			for k, s := range term {
				if eval.IsUnknown(s) && !hasCaveatOn(gotCaveats, k) {
					t.Errorf("%s: %s is Unknown without a caveat: silence read as clean", name, k)
				}
			}
		}
		if g.Admits.IsEmpty() {
			t.Errorf("%s: the grant admits nothing, the one output this parser must never produce", name)
		}
		if string(g.Source) != strings.TrimSpace(string(raw)) {
			t.Errorf("%s: Source is not the document's own bytes", name)
		}
	}
}

func TestCredentialFieldsAreTheDocuments(t *testing.T) {
	c, _ := parseOne(t, readCredential(t, "01-classic-subject"))
	if c.Name != "github-infra-main" || c.ID != "00aa00aa-bb11-cc22-dd33-44ee44ee44ee" {
		t.Errorf("name %q id %q", c.Name, c.ID)
	}
	if c.Issuer != "https://token.actions.githubusercontent.com" || c.Subject != mainBranch || c.Expression != nil {
		t.Errorf("issuer %q subject %q expression %+v", c.Issuer, c.Subject, c.Expression)
	}
	if !slices.Equal(c.Audiences, []string{"api://AzureADTokenExchange"}) {
		t.Errorf("audiences %q", c.Audiences)
	}
	c, _ = parseOne(t, readCredential(t, "03-flexible-matches"))
	if c.Subject != "" || c.Expression == nil || c.Expression.LanguageVersion != 1 ||
		c.Expression.Value != "claims['sub'] matches 'repo:acme/*' and claims['repository_owner_id'] eq '123456'" {
		t.Errorf("subject %q expression %+v", c.Subject, c.Expression)
	}
	// The issuer is kept as written; only the grant carries the normalised one.
	c, g := parseOne(t, []byte(`{"issuer": " HTTPS://Token.Actions.GitHubUserContent.com/ ", "subject": "s", "audiences": ["a"]}`))
	if c.Issuer != " HTTPS://Token.Actions.GitHubUserContent.com/ " || g.Issuer != github {
		t.Errorf("issuer as written %q, normalised %q", c.Issuer, g.Issuer)
	}
}

func TestShapesAccepted(t *testing.T) {
	one := readCredential(t, "01-classic-subject")
	two := readCredential(t, "03-flexible-matches")
	collection := []byte(`{"@odata.context": "https://graph.microsoft.com/beta/$metadata#applications('x')/federatedIdentityCredentials", "value": [` + string(one) + `, ` + string(two) + `]}`)
	array := []byte("[" + string(one) + ",\n" + string(two) + "]")
	for name, raw := range map[string][]byte{"collection": collection, "array": array} {
		cs, err := ParseFederatedCredentials(raw)
		if err != nil || len(cs) != 2 {
			t.Fatalf("%s: %d credentials, err %v", name, len(cs), err)
		}
		if cs[0].Name != "github-infra-main" || cs[1].Name != "github-acme-org" {
			t.Errorf("%s: names %q, %q", name, cs[0].Name, cs[1].Name)
		}
		// Each element's Source is its own bytes, not the collection's.
		if g := cs[1].Grants(infraApp)[0]; string(g.Source) != strings.TrimSpace(string(two)) {
			t.Errorf("%s: Source = %s", name, g.Source)
		}
		if _, err := ParseFederatedCredential(raw); err == nil || !strings.Contains(err.Error(), "a collection of 2 credentials") {
			t.Errorf("%s: ParseFederatedCredential = %v, want a refusal naming the count", name, err)
		}
	}
	// A single object is a collection of one, and a collection of one is a credential.
	if cs, err := ParseFederatedCredentials(one); err != nil || len(cs) != 1 {
		t.Errorf("single object: %d credentials, err %v", len(cs), err)
	}
	if c, err := ParseFederatedCredential([]byte(`{"value": [` + string(one) + `]}`)); err != nil || c.Name != "github-infra-main" {
		t.Errorf("collection of one: %+v, err %v", c.Name, err)
	}
	// An empty collection is no credentials, not an error: an application
	// with none is a fact, not a malformed document.
	if cs, err := ParseFederatedCredentials([]byte(`{"value": []}`)); err != nil || len(cs) != 0 {
		t.Errorf("empty collection: %d credentials, err %v", len(cs), err)
	}
	if _, err := ParseFederatedCredential([]byte(`[]`)); err == nil || !strings.Contains(err.Error(), "a collection of 0 credentials") {
		t.Errorf("empty array to the singular: %v", err)
	}
	// Unknown members and @odata annotations are ignored deliberately, and a
	// value member holding a scalar is not a collection whatever its case.
	c, g := parseOne(t, []byte(`{"@odata.type": "#microsoft.graph.federatedIdentityCredential", "issuer": "https://gitlab.com", "subject": "project_path:acme/infra:ref_type:branch:ref:main", "audiences": ["a"], "description": "d", "id": "x", "future": {"nested": [1]}, "value": "not a collection", "Value": 1}`))
	if len(g.Anomalies) != 0 || !g.Exact() || c.Name != "" {
		t.Errorf("unknown members must be ignored: anomalies %v", g.Anomalies)
	}
	// Microsoft's own page shows a GET of one credential answered with the
	// object under a value member; that wrapper is one credential.
	wrapped := []byte(`{"@odata.context": "https://graph.microsoft.com/$metadata#applications('x')/federatedIdentityCredentials", "value": ` + string(one) + `}`)
	if c, err := ParseFederatedCredential(wrapped); err != nil || c.Name != "github-infra-main" || string(c.Grants(infraApp)[0].Source) != strings.TrimSpace(string(one)) {
		t.Errorf("value object wrapper: %+v, err %v", c.Name, err)
	}
	if _, err := ParseFederatedCredentials([]byte(`{"value": {"appId": "x"}}`)); err == nil || !strings.Contains(err.Error(), "value is not a credential: no issuer") {
		t.Errorf("a value object that is not a credential: %v", err)
	}
}

// TestResourceManagerShape: a user-assigned managed identity's credentials
// are read through Azure Resource Manager, which returns a resource: id,
// name, type and a properties object holding issuer, subject and audiences.
// The properties are the credential, the resource's id and name label it,
// and the resource's own bytes are the Source, because they are what the
// API returned. The list endpoint wraps resources in the same value
// collection Graph uses.
func TestResourceManagerShape(t *testing.T) {
	raw := readCredential(t, "28-managed-identity-resource")
	c, g := parseOne(t, raw)
	if c.Name != "ficResourceName" || !strings.HasSuffix(c.ID, "/federatedIdentityCredentials/ficResourceName") {
		t.Errorf("name %q id %q; the resource labels its credential", c.Name, c.ID)
	}
	if c.Issuer != "https://oidc.prod-aks.azure.com/TenantGUID/IssuerGUID" || c.Subject != "system:serviceaccount:ns:svcaccount" || !slices.Equal(c.Audiences, []string{"api://AzureADTokenExchange"}) {
		t.Errorf("issuer %q subject %q audiences %q; the properties are the credential", c.Issuer, c.Subject, c.Audiences)
	}
	if len(g.Anomalies) != 0 || !g.Exact() {
		t.Errorf("a resource is an ordinary credential: anomalies%s caveats %v", renderAnomalies(g.Anomalies), g.Admits.Caveats())
	}
	if string(g.Source) != strings.TrimSpace(string(raw)) {
		t.Errorf("Source is not the resource's own bytes: %s", g.Source)
	}
	// The list endpoint's collection, nextLink included.
	cs, err := ParseFederatedCredentials([]byte(`{"value": [` + string(raw) + `, ` + string(raw) + `], "nextLink": "https://management.azure.com/next"}`))
	if err != nil || len(cs) != 2 || cs[1].Name != "ficResourceName" || string(cs[1].Grants(infraApp)[0].Source) != strings.TrimSpace(string(raw)) {
		t.Errorf("resource collection: %d credentials, err %v", len(cs), err)
	}
	// The resource's labels are read from the resource: a name written in
	// the properties is an unknown member there, ignored as any other.
	c, g = parseOne(t, []byte(`{"name": "outer", "properties": {"issuer": "https://gitlab.com", "subject": "s", "audiences": ["a"], "name": "inner", "id": "inner"}}`))
	if c.Name != "outer" || c.ID != "" || g.Admits.String() != `{aud="a", sub="s"}` || len(g.Anomalies) != 0 {
		t.Errorf("labels inside the properties are not the resource's: name %q id %q admits %s%s", c.Name, c.ID, g.Admits, renderAnomalies(g.Anomalies))
	}
	// Miscased members are reported wherever they sit, as they are on a
	// Graph object, under the same sentence.
	_, g = parseOne(t, []byte(`{"Name": "fic", "properties": {"Issuer": "https://gitlab.com", "subject": "s", "audiences": ["a"]}}`))
	if kinds := joinKinds(g.Anomalies); kinds != "miscased-key,miscased-key,missing-issuer" {
		t.Errorf("miscased members of a resource: kinds %s%s", kinds, renderAnomalies(g.Anomalies))
	}
}

// TestOnlyCredentialMembersMarkACredential: a resource that is not a
// credential, a storage account say, carries a name and a type and nothing
// a credential has; it is refused, never read as a credential with no
// issuer, no subject and no audience, which would be an Allow grant admitting
// everything with anomalies whose sentences are false for the document.
func TestOnlyCredentialMembersMarkACredential(t *testing.T) {
	for _, raw := range []string{
		`{"name": "prod-storage", "type": "Microsoft.Storage/storageAccounts", "location": "westeurope"}`,
		`{"id": "/subscriptions/x", "name": "fic01", "type": "Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials"}`,
		`{"name": "fic01", "properties": {"location": "westeurope"}}`,
		`{"name": "fic01", "properties": "not an object"}`,
		`{"description": "d", "id": "x"}`,
	} {
		cs, err := ParseFederatedCredentials([]byte(raw))
		if err == nil {
			t.Errorf("%s: parsed %d credentials, want a refusal", raw, len(cs))
			continue
		}
		if !strings.Contains(err.Error(), "is not a credential: no issuer, subject, audiences or claimsMatchingExpression member, and no properties member holding one") {
			t.Errorf("%s: %v", raw, err)
		}
	}
}

// TestAmbiguousShapesAreRefused: a document that could be read two ways is
// read neither way. A collection with its value member written twice, or an
// object carrying credential members beside a value list, would under
// either reading lose credentials without a trace, and a credential that
// vanishes from the report is silence.
func TestAmbiguousShapesAreRefused(t *testing.T) {
	one := string(readCredential(t, "01-classic-subject"))
	two := string(readCredential(t, "03-flexible-matches"))
	cases := []struct{ name, raw, want string }{
		{"value twice", `{"value": [` + one + `], "value": [` + two + `]}`, `the member "value" is written 2 times, so the document is not one collection`},
		{"value then a scalar value", `{"value": [` + one + `], "value": 1}`, `the member "value" is written 2 times`},
		{"scalar value then the list", `{"value": "x", "value": [` + one + `]}`, `the member "value" is written 2 times`},
		{"value thrice", `{"value": [` + one + `], "value": [], "value": {}}`, `the member "value" is written 3 times`},
		{"marks beside a value list", `{"subject": "page", "value": [` + one + `, ` + two + `]}`, `the document carries both a value list and credential members, so it is neither one credential nor a collection`},
		{"marks beside a value object", `{"issuer": "https://x", "value": ` + one + `}`, `the document carries both a value object and credential members`},
		{"marks in another case beside a value list", `{"SUBJECT": "s", "value": [` + one + `]}`, `neither one credential nor a collection`},
		// A resource whose properties hold a credential beside credential
		// members of its own could be read as either; and a properties member
		// written twice is two resources at once.
		{"marks beside a properties object holding a credential", `{"subject": "s", "properties": {"issuer": "https://x", "subject": "t", "audiences": ["a"]}}`, `the document carries both credential members and a properties object holding credential members, so it is neither one credential nor one resource`},
		{"marks in another case beside a properties object", `{"Issuer": "https://x", "properties": {"subject": "t"}}`, `neither one credential nor one resource`},
		{"properties twice", `{"name": "fic", "properties": {"subject": "s"}, "properties": {"subject": "t"}}`, `the member "properties" is written 2 times, so the document is not one resource`},
		{"properties twice, one of them not a credential", `{"name": "fic", "properties": {"subject": "s"}, "properties": 1}`, `the member "properties" is written 2 times`},
		{"a value list beside a properties object holding a credential", `{"value": [` + one + `], "properties": {"subject": "t"}}`, `the document carries both a value list and a properties object holding credential members, so it is neither one resource nor a collection`},
		{"a resource inside a collection beside its own marks", `{"value": [{"issuer": "https://x", "properties": {"subject": "t"}}]}`, `value[0] carries both credential members and a properties object holding credential members`},
		{"a resource under a value object beside its own marks", `{"value": {"issuer": "https://x", "properties": {"subject": "t"}}}`, `value carries both credential members and a properties object holding credential members`},
		{"a resource in a bare list beside its own marks", `[{"issuer": "https://x", "properties": {"subject": "t"}}]`, `[0] carries both credential members and a properties object holding credential members`},
		// A collection member in another case may be a collection written by
		// a serialiser that does not spell members as Graph does; read
		// strictly it would be ignored and every credential under it would
		// vanish, so the document is refused and the member named.
		{"a value list in another case", `{"Value": [` + one + `]}`, `the member "Value" holds a list and differs from Graph's "value" only in case; Graph member names are exact, so the document is neither one credential nor a collection`},
		{"a value list in another case beside the collection", `{"value": [` + one + `], "Value": [` + two + `]}`, `the member "Value" holds a list and differs from Graph's "value" only in case`},
		{"a value list in another case before the collection", `{"VALUE": [` + two + `], "value": [` + one + `]}`, `the member "VALUE" holds a list and differs from Graph's "value" only in case`},
		{"a value object in another case beside credential members", `{"issuer": "https://x", "subject": "s", "audiences": ["a"], "VALUE": ` + one + `}`, `the member "VALUE" holds an object and differs from Graph's "value" only in case`},
		{"a value object in another case alone", `{"vAlUe": ` + one + `}`, `the member "vAlUe" holds an object and differs from Graph's "value" only in case`},
	}
	for _, c := range cases {
		cs, err := ParseFederatedCredentials([]byte(c.raw))
		if err == nil {
			t.Errorf("%s: parsed %d credentials, want an error", c.name, len(cs))
			continue
		}
		if !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: error %q does not carry %q", c.name, err, c.want)
		}
		if _, err := ParseFederatedCredential([]byte(c.raw)); err == nil {
			t.Errorf("%s: the singular parse accepted what the plural refused", c.name)
		}
	}
}

// TestEmptyAudience: no documented issuer mints a token whose aud is
// empty, and Microsoft does not say what Entra does with an empty audience
// string, so Exact("") would report a credential as admitting nobody on a
// construct whose meaning is not stated. The member is Unknown, and Unknown
// absorbs the other audiences under Join.
func TestEmptyAudience(t *testing.T) {
	_, g := parseOne(t, []byte(`{"issuer": "https://gitlab.com", "subject": "s", "audiences": [""]}`))
	if got := g.Admits.String(); got != `{aud=?("empty audience"), sub="s"}` {
		t.Errorf("admits %s", got)
	}
	want := trust.Anomaly{Kind: trust.Unmodelled, Claim: "aud", Construct: "empty audience",
		Message: "audiences[0] is the empty string; no documented issuer mints a token whose aud is empty and Microsoft does not say what Entra does with an empty audience, so the audience this credential accepts is not stated",
		Source:  "audiences"}
	if len(g.Anomalies) != 1 || g.Anomalies[0] != want || !hasCaveatOn(g.Admits.Caveats(), "aud") {
		t.Errorf("anomalies%s caveats %v", renderAnomalies(g.Anomalies), g.Admits.Caveats())
	}
	c, g := parseOne(t, []byte(`{"issuer": "https://gitlab.com", "subject": "s", "audiences": ["a", ""]}`))
	if got := g.Admits.String(); got != `{aud=?("empty audience"), sub="s"}` {
		t.Errorf("beside another audience: admits %s", got)
	}
	if kinds := joinKinds(g.Anomalies); kinds != "audience-count,unmodelled-construct" || g.Anomalies[1].Message[:12] != "audiences[1]" {
		t.Errorf("beside another audience: kinds %s%s", kinds, renderAnomalies(g.Anomalies))
	}
	if !slices.Equal(c.Audiences, []string{"a", ""}) {
		t.Errorf("the document's own values are kept: %q", c.Audiences)
	}
}

// TestSentencesStayBoundedForEveryMember: no member of the document has a
// documented length limit this parser can rely on, so every one that
// reaches a sentence is cut, the number literal of languageVersion
// included.
func TestSentencesStayBoundedForEveryMember(t *testing.T) {
	digits := strings.Repeat("9", 5000)
	_, g := parseOne(t, []byte(`{"issuer": "https://gitlab.com", "audiences": ["a"], "claimsMatchingExpression": {"value": "claims['sub'] eq 'x'", "languageVersion": `+digits+`}}`))
	if got := g.Admits.String(); got != `{aud="a", sub=?("language version")}` {
		t.Errorf("admits %s", got)
	}
	if len(g.Anomalies) != 1 {
		t.Fatalf("anomalies%s", renderAnomalies(g.Anomalies))
	}
	a := g.Anomalies[0]
	if a.Construct != strings.Repeat("9", 200)+"..." || len(a.Message) > 400 || !strings.Contains(a.Message, "is "+strings.Repeat("9", 200)+"...; Microsoft") {
		t.Errorf("unbounded numeral: construct %d bytes, message %d bytes", len(a.Construct), len(a.Message))
	}
	for _, c := range g.Admits.Caveats() {
		if len(c.Reason) > 400 {
			t.Errorf("unbounded caveat: %d bytes", len(c.Reason))
		}
	}
}

// TestLargeDocumentsParseInBoundedTime: the parser is total over arbitrary
// bytes, and neither audiences nor the expression have a documented length
// limit, so a document a hand or a generator inflates must not take
// minutes. The bound is an order of magnitude above what the two cases
// take together here, so that a loaded machine passes and a superlinear
// parser, which took seconds to minutes on these sizes, does not. Both
// lists ran for that long before their caps: the union of exact audiences
// is quadratic in its members inside eval, and so is attaching one caveat
// per clause the language does not model.
func TestLargeDocumentsParseInBoundedTime(t *testing.T) {
	audiences := numberedAudiences(200000)
	clauses := make([]string, 16000)
	for i := range clauses {
		clauses[i] = "claims['c" + strconv.Itoa(i) + "'] eq 'v'"
	}
	cases := []struct {
		name string
		raw  []byte
	}{
		{"200000 audiences", []byte(`{"issuer": "https://token.actions.githubusercontent.com", "subject": "x", "audiences": ` + string(mustJSON(audiences)) + `}`)},
		{"16000 clauses", []byte(`{"issuer": "https://token.actions.githubusercontent.com", "audiences": ["a"], "claimsMatchingExpression": {"value": ` + string(mustJSON(strings.Join(clauses, " and "))) + `, "languageVersion": 1}}`)},
	}
	for _, c := range cases {
		start := time.Now()
		_, g := parseOne(t, c.raw)
		if took := time.Since(start); took > 3*time.Second {
			t.Errorf("%s: %d-byte document took %v", c.name, len(c.raw), took)
		}
		if g.Admits.IsEmpty() {
			t.Errorf("%s: admits nothing", c.name)
		}
		t.Logf("%s: %d bytes, %d anomalies, %d caveats", c.name, len(c.raw), len(g.Anomalies), len(g.Admits.Caveats()))
	}
}

func numberedAudiences(n int) []string {
	audiences := make([]string, n)
	for i := range audiences {
		audiences[i] = "api://aud-" + strconv.Itoa(i)
	}
	return audiences
}

// TestAudiencesPastTheCapAreUnknown: the union of exact audiences costs
// eval a comparison per pair, so a list long enough would take minutes,
// and Microsoft accepts exactly one audience anyway. Up to the cap the
// list is the union it says; past it the audience is Unknown with the
// fact stated, which is wider than any union, never a truncation of one.
func TestAudiencesPastTheCapAreUnknown(t *testing.T) {
	document := func(n int) []byte {
		return []byte(`{"issuer": "https://gitlab.com", "subject": "s", "audiences": ` + string(mustJSON(numberedAudiences(n))) + `}`)
	}
	_, g := parseOne(t, document(256))
	if !g.Admits.Admits(token{"aud": "api://aud-255", "sub": "s"}) || !g.Admits.Admits(token{"aud": "api://aud-0", "sub": "s"}) || g.Admits.Admits(token{"aud": "api://aud-256", "sub": "s"}) || !g.Exact() {
		t.Errorf("at the cap the audiences are the union they say: %s exact %v", g.Admits, g.Exact())
	}
	if kinds := joinKinds(g.Anomalies); kinds != "audience-count" || !strings.HasPrefix(g.Anomalies[0].Message, "256 audiences are set; Microsoft accepts exactly one, so") {
		t.Errorf("at the cap: kinds %s%s", kinds, renderAnomalies(g.Anomalies))
	}
	c, g := parseOne(t, document(257))
	if got := g.Admits.String(); got != `{aud=?("too many audiences"), sub="s"}` {
		t.Errorf("past the cap: admits %s", got)
	}
	want := trust.Anomaly{Kind: "audience-count", Claim: "aud", Construct: "audiences",
		Message: "257 audiences are set; Microsoft accepts exactly one, and this parser reads at most 256, so the audience this credential accepts is not stated",
		Source:  "audiences"}
	if len(g.Anomalies) != 1 || g.Anomalies[0] != want || !hasCaveatOn(g.Admits.Caveats(), "aud") {
		t.Errorf("past the cap: anomalies%s caveats %v", renderAnomalies(g.Anomalies), g.Admits.Caveats())
	}
	if c.Audiences != nil {
		t.Errorf("a list past the cap is not read; got %d audiences", len(c.Audiences))
	}
	// A list past the cap is Unknown whatever it holds: an empty string in
	// it is not read far enough to be reported on its own.
	_, g = parseOne(t, []byte(`{"issuer": "https://gitlab.com", "subject": "s", "audiences": `+string(mustJSON(append(numberedAudiences(256), "")))+`}`))
	if kinds := joinKinds(g.Anomalies); kinds != "audience-count" || g.Admits.String() != `{aud=?("too many audiences"), sub="s"}` {
		t.Errorf("past the cap with an empty audience: kinds %s admits %s", kinds, g.Admits)
	}
}

func TestNotACredentialDocument(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want string
	}{
		{"empty", "", "empty input"},
		{"whitespace", " \n\t ", "empty input"},
		{"invalid utf-8", "{\"subject\":\"a\xffb\"}", "not valid UTF-8 at byte 13"},
		{"byte order mark", "\xEF\xBB\xBF{}", "invalid character"},
		{"not json", "issuer: x", "invalid character"},
		{"string", `"x"`, "the document is a string, not an object or a list"},
		{"number", `42`, "the document is a number, not an object or a list"},
		{"null", `null`, "the document is null, not an object or a list"},
		{"boolean", `true`, "the document is a boolean, not an object or a list"},
		{"second document", `{"issuer":"x"} {"issuer":"y"}`, "after the document: a second value"},
		{"trailing garbage", `{"issuer":"x"} xyz`, "after the document: invalid character 'x'"},
		{"unterminated object", `{"issuer": "x"`, "unexpected EOF"},
		{"unterminated list", `{"audiences": ["a"`, "unexpected EOF"},
		{"truncated value", `{"issuer": `, "unexpected EOF"},
		{"truncated item", `{"audiences": ["a", `, "unexpected EOF"},
		{"bad literal", `{"issuer": tru}`, "invalid character"},
		{"leading zero", `{"languageVersion": 01}`, "invalid character"},
		{"deep nesting", strings.Repeat("[", 20000) + strings.Repeat("]", 20000), "nested more than 1000 levels deep"},
		{"empty object", `{}`, "the document is not a credential: no issuer, subject, audiences or claimsMatchingExpression member, and no properties member holding one"},
		{"unrelated object", `{"@odata.type": "#microsoft.graph.application", "appId": "x"}`, "the document is not a credential"},
		{"a name alone", `{"name": "github-infra-main"}`, "the document is not a credential"},
		{"value that is not a collection", `{"value": "x"}`, "the document is not a credential"},
		{"scalar element", `[{"issuer":"x"}, 1]`, "[1] is a number, not a credential"},
		{"null element", `{"value": [null]}`, "value[0] is null, not a credential"},
		{"unrelated element", `{"value": [{"issuer":"x"}, {"appId": "x"}]}`, "value[1] is not a credential: no issuer"},
		{"a resource that is not a credential inside a collection", `{"value": [{"name": "x", "properties": {"location": "westeurope"}}]}`, "value[0] is not a credential: no issuer"},
		// The decoder's own sentence, which the toolchain's two JSON
		// implementations spell the same way for this defect.
		{"malformed inside a collection", `{"value": [{"issuer": "x" "subject": "y"}]}`, `invalid character '"' after object key:value pair`},
	}
	for _, c := range cases {
		cs, err := ParseFederatedCredentials([]byte(c.raw))
		if err == nil {
			t.Errorf("%s: parsed %d credentials, want an error", c.name, len(cs))
			continue
		}
		if !strings.HasPrefix(err.Error(), "federated identity credential: ") || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: error %q does not carry %q", c.name, err, c.want)
		}
		if _, err := ParseFederatedCredential([]byte(c.raw)); err == nil {
			t.Errorf("%s: the singular parse accepted what the plural refused", c.name)
		}
	}
	// A document recognisable only by a member's case is still a credential
	// document: every member is refused by name and the facts say so.
	c, g := parseOne(t, []byte(`{"Issuer": "https://x", "SUBJECT": "s", "AUDIENCES": ["a"]}`))
	if len(g.Anomalies) != 6 || c.Issuer != "" || c.Subject != "" || c.Audiences != nil {
		t.Errorf("miscased everything: %+v%s", c, renderAnomalies(g.Anomalies))
	}
	// The case that makes a member a misspelling is ASCII case: a name from
	// another script that only Unicode folding would equate with Graph's is
	// another member, and neither a mark nor a misspelling.
	c, g = parseOne(t, []byte(`{"iſſuer": "https://x", "ſubject": "s", "audiences": ["a"]}`))
	if kinds := joinKinds(g.Anomalies); kinds != "missing-issuer,no-subject-constraint" || c.Issuer != "" || c.Subject != "" {
		t.Errorf("long s in member names: kinds %s issuer %q subject %q", kinds, c.Issuer, c.Subject)
	}
	if _, err := ParseFederatedCredentials([]byte(`{"iſſuer": "https://x", "ſubject": "s"}`)); err == nil || !strings.Contains(err.Error(), "not a credential") {
		t.Errorf("long s in every member is no mark: %v", err)
	}
}

// TestNestingIsBoundedByTheReader: the reader descends once per container,
// so a document nested deep enough exhausts the goroutine stack, which no
// recover can catch; a 2,000,000-deep list killed the process under Go
// 1.24, whose decoder applies no depth limit of its own. The bound is the
// reader's, so that the refusal is this package's sentence on every
// toolchain, and it sits below the 10,000 the newer decoder allows so that
// the decoder never answers first.
func TestNestingIsBoundedByTheReader(t *testing.T) {
	nested := func(open, close string, depth int) string {
		return strings.Repeat(open, depth) + strings.Repeat(close, depth)
	}
	const refused = "nested more than 1000 levels deep"
	cases := []struct{ name, raw, want string }{
		// At the bound the document is read in full, and refused only for
		// what it is: a list of lists is not a credential.
		{"lists at the bound", nested("[", "]", 1000), "[0] is a list, not a credential"},
		{"lists one past the bound", nested("[", "]", 1001), refused},
		{"objects one past the bound", strings.Repeat(`{"subject":`, 1001) + `"s"` + strings.Repeat("}", 1001), refused},
		{"the list that overflowed the stack", nested("[", "]", 2000000), refused},
		{"the object that overflowed the stack", strings.Repeat(`{"subject":`, 2000000) + `"s"` + strings.Repeat("}", 2000000), refused},
		{"inside an ignored member, past the bound", `{"issuer": "https://gitlab.com", "subject": "s", "audiences": ["a"], "future": ` + nested("[", "]", 1000) + `}`, refused},
	}
	for _, c := range cases {
		cs, err := ParseFederatedCredentials([]byte(c.raw))
		if err == nil {
			t.Errorf("%s: parsed %d credentials, want an error", c.name, len(cs))
			continue
		}
		if !strings.HasPrefix(err.Error(), "federated identity credential: ") || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: error %q does not carry %q", c.name, err, c.want)
		}
	}
	// Inside an ignored member, at the bound, the credential is read and the
	// member ignored as any other.
	_, g := parseOne(t, []byte(`{"issuer": "https://gitlab.com", "subject": "s", "audiences": ["a"], "future": `+nested("[", "]", 999)+`}`))
	if got := g.Admits.String(); got != `{aud="a", sub="s"}` || len(g.Anomalies) != 0 {
		t.Errorf("nesting at the bound inside an ignored member: admits %s anomalies%s", got, renderAnomalies(g.Anomalies))
	}
}

// TestLoneSurrogateEscapesAreRefused: a \u escape naming half of a UTF-16
// pair is replaced by the decoder with U+FFFD, so a value read through it
// would not be the customer's value, which is the same reason invalid
// UTF-8 is refused. The bytes are valid UTF-8 and valid JSON, so only a
// look at the escape itself can catch it.
func TestLoneSurrogateEscapesAreRefused(t *testing.T) {
	cases := []struct{ name, raw, want string }{
		{"high alone in the subject", `{"issuer": "https://gitlab.com", "subject": "a\ud800b", "audiences": ["a"]}`, "lone surrogate escape at byte 46"},
		{"low alone", `{"issuer": "https://gitlab.com", "subject": "\udc00", "audiences": ["a"]}`, "lone surrogate escape at byte 45"},
		{"high then a non-surrogate escape", `{"issuer": "https://gitlab.com", "subject": "\ud800A", "audiences": ["a"]}`, "lone surrogate escape at byte 45"},
		{"high then a high", `{"issuer": "https://gitlab.com", "subject": "\ud83d\ud83d\ude00", "audiences": ["a"]}`, "lone surrogate escape at byte 45"},
		{"high at the end of the string", `{"issuer": "https://gitlab.com", "subject": "repo:acme\ud800", "audiences": ["a"]}`, "lone surrogate escape at byte 54"},
		{"in an audience", `{"issuer": "https://gitlab.com", "subject": "s", "audiences": ["api://\uD800"]}`, "lone surrogate escape at byte 70"},
		{"in the expression", `{"issuer": "https://gitlab.com", "audiences": ["a"], "claimsMatchingExpression": {"value": "claims['sub'] eq 'repo:\ud800'", "languageVersion": 1}}`, "lone surrogate escape"},
		{"in a member name", `{"\udc00issuer": "https://gitlab.com", "subject": "s", "audiences": ["a"]}`, "lone surrogate escape at byte 2"},
		{"in a member name inside the expression", `{"issuer": "https://gitlab.com", "audiences": ["a"], "claimsMatchingExpression": {"\ud800value": "x", "languageVersion": 1}}`, "lone surrogate escape"},
		{"in an ignored member", `{"issuer": "https://gitlab.com", "subject": "s", "audiences": ["a"], "description": "\udfff"}`, "lone surrogate escape"},
		{"inside a collection", `{"value": [{"issuer": "https://gitlab.com", "subject": "\ud800", "audiences": ["a"]}]}`, "lone surrogate escape"},
	}
	for _, c := range cases {
		cs, err := ParseFederatedCredentials([]byte(c.raw))
		if err == nil {
			t.Errorf("%s: parsed %d credentials, want an error", c.name, len(cs))
			continue
		}
		if !strings.HasPrefix(err.Error(), "federated identity credential: ") || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: error %q does not carry %q", c.name, err, c.want)
		}
	}
	// A pair, U+FFFD spelt out either way, and an escaped backslash before
	// the letters of an escape are all the customer's own text.
	c, _ := parseOne(t, []byte(`{"issuer": "https://gitlab.com", "subject": "\ud83d\ude00 \ufffd `+"\xef\xbf\xbd"+` \\ud800 \"\\\/", "audiences": ["\uD83D\uDE00"]}`))
	if c.Subject != "\U0001F600 \uFFFD \uFFFD \\ud800 \"\\/" || c.Audiences[0] != "\U0001F600" {
		t.Errorf("subject %q audiences %q", c.Subject, c.Audiences)
	}
}

// TestMembersOfTheWrongType: a member Graph defines with one type that is
// written with another is not read, and the claim it would have constrained
// is Unknown with the fact stated. The document is still a credential.
func TestMembersOfTheWrongType(t *testing.T) {
	cases := []struct {
		name    string
		raw     string
		admits  string
		anomaly trust.Anomaly
		doubt   bool
	}{
		{
			"subject", `{"issuer": "https://gitlab.com", "subject": 5, "audiences": ["a"]}`,
			`{aud="a", sub=?("wrong type")}`,
			trust.Anomaly{Kind: "malformed", Claim: "sub", Construct: "subject", Message: "subject is a number; Graph defines it as a string, so it is not read", Source: "subject"},
			true,
		},
		{
			"audiences", `{"issuer": "https://gitlab.com", "subject": "s", "audiences": "a"}`,
			`{aud=?("wrong type"), sub="s"}`,
			trust.Anomaly{Kind: "malformed", Claim: "aud", Construct: "audiences", Message: "audiences is a string; Graph defines it as a list of strings, so it is not read", Source: "audiences"},
			true,
		},
		{
			"audience element", `{"issuer": "https://gitlab.com", "subject": "s", "audiences": ["a", null]}`,
			`{aud=?("wrong type"), sub="s"}`,
			trust.Anomaly{Kind: "malformed", Claim: "aud", Construct: "audiences", Message: "audiences[1] is null; Graph defines audiences as a list of strings, so it is not read", Source: "audiences"},
			true,
		},
		{
			"issuer", `{"issuer": ["https://gitlab.com"], "subject": "s", "audiences": ["a"]}`,
			`{aud="a", sub="s"}`,
			trust.Anomaly{Kind: "malformed", Construct: "issuer", Message: "issuer is a list; Graph defines it as a string, so it is not read", Source: "issuer"},
			false,
		},
		{
			"claimsMatchingExpression", `{"issuer": "https://gitlab.com", "audiences": ["a"], "claimsMatchingExpression": "claims['sub'] eq 'x'"}`,
			`{aud="a", sub=?("wrong type")}`,
			trust.Anomaly{Kind: "malformed", Claim: "sub", Construct: "claimsMatchingExpression", Message: "claimsMatchingExpression is a string; Graph defines it as an object, so it is not read", Source: "claimsMatchingExpression"},
			true,
		},
		{
			"name", `{"issuer": "https://gitlab.com", "subject": "s", "audiences": ["a"], "name": true}`,
			`{aud="a", sub="s"}`,
			trust.Anomaly{Kind: "malformed", Construct: "name", Message: "name is a boolean; Graph defines it as a string, so it is not read", Source: "name"},
			false,
		},
		{
			"expression value missing", `{"issuer": "https://gitlab.com", "audiences": ["a"], "claimsMatchingExpression": {"languageVersion": 1}}`,
			`{aud="a", sub=?("unreadable expression")}`,
			trust.Anomaly{Kind: "malformed", Claim: "sub", Construct: "value", Message: "claimsMatchingExpression has no value; Graph requires one, so the expression is not read", Source: "claimsMatchingExpression.value"},
			true,
		},
		{
			"expression value null", `{"issuer": "https://gitlab.com", "audiences": ["a"], "claimsMatchingExpression": {"value": null, "languageVersion": 1}}`,
			`{aud="a", sub=?("unreadable expression")}`,
			trust.Anomaly{Kind: "malformed", Claim: "sub", Construct: "value", Message: "claimsMatchingExpression has no value; Graph requires one, so the expression is not read", Source: "claimsMatchingExpression.value"},
			true,
		},
		{
			"expression value of the wrong type", `{"issuer": "https://gitlab.com", "audiences": ["a"], "claimsMatchingExpression": {"value": ["claims['sub'] eq 'x'"], "languageVersion": 1}}`,
			`{aud="a", sub=?("wrong type")}`,
			trust.Anomaly{Kind: "malformed", Claim: "sub", Construct: "value", Message: "claimsMatchingExpression.value is a list; Graph defines it as a string, so it is not read", Source: "claimsMatchingExpression.value"},
			true,
		},
		{
			"languageVersion missing", `{"issuer": "https://gitlab.com", "audiences": ["a"], "claimsMatchingExpression": {"value": "claims['sub'] eq 'x'"}}`,
			`{aud="a", sub=?("language version")}`,
			trust.Anomaly{Kind: "malformed", Claim: "sub", Construct: "languageVersion", Message: "claimsMatchingExpression has no languageVersion; Graph requires one, so the expression is not read", Source: "claimsMatchingExpression.languageVersion"},
			true,
		},
		{
			"languageVersion as a string", `{"issuer": "https://gitlab.com", "audiences": ["a"], "claimsMatchingExpression": {"value": "claims['sub'] eq 'x'", "languageVersion": "1"}}`,
			`{aud="a", sub=?("wrong type")}`,
			trust.Anomaly{Kind: "malformed", Claim: "sub", Construct: "languageVersion", Message: "claimsMatchingExpression.languageVersion is a string; Graph defines it as an integer, so it is not read", Source: "claimsMatchingExpression.languageVersion"},
			true,
		},
		{
			"languageVersion as a fraction", `{"issuer": "https://gitlab.com", "audiences": ["a"], "claimsMatchingExpression": {"value": "claims['sub'] eq 'x'", "languageVersion": 1.0}}`,
			`{aud="a", sub=?("language version")}`,
			trust.Anomaly{Kind: trust.Unmodelled, Claim: "sub", Construct: "1.0", Message: "claimsMatchingExpression.languageVersion is 1.0; Microsoft documents version 1 only, so the expression is not modelled", Source: "claimsMatchingExpression.languageVersion"},
			true,
		},
	}
	for _, c := range cases {
		cred, g := parseOne(t, []byte(c.raw))
		if got := g.Admits.String(); got != c.admits {
			t.Errorf("%s: admits %s, want %s", c.name, got, c.admits)
		}
		if len(g.Anomalies) != 1 || g.Anomalies[0] != c.anomaly {
			t.Errorf("%s: anomalies%s\n  want%s", c.name, renderAnomalies(g.Anomalies), renderAnomalies([]trust.Anomaly{c.anomaly}))
		}
		caveats := g.Admits.Caveats()
		if c.doubt != (len(caveats) == 1 && caveats[0] == eval.Caveat{Claim: c.anomaly.Claim, Reason: c.anomaly.Message, Source: c.anomaly.Source}) {
			t.Errorf("%s: caveats %v, doubt %v", c.name, caveats, c.doubt)
		}
		if cred.Expression != nil && strings.HasPrefix(c.name, "expression") && cred.Expression.Value != "" {
			t.Errorf("%s: an unreadable expression must not carry a value: %+v", c.name, cred.Expression)
		}
	}
	// A null member is an absent one, for every member. With nothing
	// constrained the lattice renders Everything; the caveats say why.
	_, g := parseOne(t, []byte(`{"issuer": null, "subject": null, "audiences": null, "claimsMatchingExpression": null, "name": null}`))
	if got := g.Admits.String(); got != `{}` || g.Issuer != "" || len(g.Admits.Caveats()) != 2 {
		t.Errorf("all null: admits %s issuer %q caveats %v", got, g.Issuer, g.Admits.Caveats())
	}
	if kinds := joinKinds(g.Anomalies); kinds != "audience-count,missing-issuer,no-subject-constraint" {
		t.Errorf("all null: anomaly kinds %s", kinds)
	}
}

func TestDuplicateMembers(t *testing.T) {
	cases := []struct {
		name   string
		raw    string
		admits string
		issuer trust.IssuerRef
		kinds  string
		doubts []trust.ClaimKey
	}{
		{
			"audiences", `{"issuer": "https://gitlab.com", "subject": "s", "audiences": ["a"], "audiences": ["b"]}`,
			`{aud=?("duplicate key"), sub="s"}`, gitlab, "duplicate-key", []trust.ClaimKey{"aud"},
		},
		{
			"issuer", `{"issuer": "https://gitlab.com", "issuer": "https://token.actions.githubusercontent.com", "subject": "s", "audiences": ["a"]}`,
			`{aud="a", sub="s"}`, "", "duplicate-key", nil,
		},
		{
			"claimsMatchingExpression", `{"issuer": "https://gitlab.com", "audiences": ["a"], "claimsMatchingExpression": {"value": "claims['sub'] eq 'x'", "languageVersion": 1}, "claimsMatchingExpression": null}`,
			`{aud="a", sub=?("duplicate key")}`, gitlab, "duplicate-key", []trust.ClaimKey{"sub"},
		},
		{
			"value inside the expression", `{"issuer": "https://gitlab.com", "audiences": ["a"], "claimsMatchingExpression": {"value": "claims['sub'] eq 'x'", "value": "claims['sub'] eq 'y'", "languageVersion": 1}}`,
			`{aud="a", sub=?("duplicate key")}`, gitlab, "duplicate-key", []trust.ClaimKey{"sub"},
		},
		{
			"languageVersion inside the expression", `{"issuer": "https://gitlab.com", "audiences": ["a"], "claimsMatchingExpression": {"value": "claims['sub'] eq 'x'", "languageVersion": 1, "languageVersion": 1}}`,
			`{aud="a", sub=?("duplicate key")}`, gitlab, "duplicate-key", []trust.ClaimKey{"sub"},
		},
		{
			"name", `{"issuer": "https://gitlab.com", "subject": "s", "audiences": ["a"], "name": "x", "name": "y"}`,
			`{aud="a", sub="s"}`, gitlab, "duplicate-key", nil,
		},
		// Three copies are one fact, counted.
		{
			"subject three times", `{"issuer": "https://gitlab.com", "subject": "a", "subject": "b", "subject": "c", "audiences": ["a"]}`,
			`{aud="a", sub=?("duplicate key")}`, gitlab, "duplicate-key", []trust.ClaimKey{"sub"},
		},
	}
	for _, c := range cases {
		cred, g := parseOne(t, []byte(c.raw))
		if got := g.Admits.String(); got != c.admits {
			t.Errorf("%s: admits %s, want %s", c.name, got, c.admits)
		}
		if g.Issuer != c.issuer {
			t.Errorf("%s: issuer %q, want %q", c.name, g.Issuer, c.issuer)
		}
		if kinds := joinKinds(g.Anomalies); kinds != c.kinds {
			t.Errorf("%s: anomaly kinds %s, want %s", c.name, kinds, c.kinds)
		}
		for _, k := range c.doubts {
			if !hasCaveatOn(g.Admits.Caveats(), k) {
				t.Errorf("%s: no caveat on %s", c.name, k)
			}
		}
		if len(c.doubts) == 0 && !g.Exact() {
			t.Errorf("%s: a duplicate of a member that does not constrain admission must not caveat the set: %v", c.name, g.Admits.Caveats())
		}
		if c.name == "name" && cred.Name != "" {
			t.Errorf("a duplicated name is not read; got %q", cred.Name)
		}
	}
	_, g := parseOne(t, []byte(`{"issuer": "https://gitlab.com", "subject": "a", "subject": "b", "subject": "c", "audiences": ["a"]}`))
	if want := `the member "subject" is written 3 times; which one Entra would apply is not stated, so it is not read`; len(g.Anomalies) != 1 || g.Anomalies[0].Message != want {
		t.Errorf("subject three times: anomalies%s\n  want one saying %q", renderAnomalies(g.Anomalies), want)
	}
	// A duplicate written in another case is a miscased member, not a duplicate.
	_, g = parseOne(t, []byte(`{"issuer": "https://gitlab.com", "subject": "a", "Subject": "b", "audiences": ["a"]}`))
	if kinds := joinKinds(g.Anomalies); kinds != "miscased-key" || g.Admits.String() != `{aud="a", sub="a"}` {
		t.Errorf("subject beside Subject: kinds %s admits %s", kinds, g.Admits)
	}
	// Inside the expression too.
	_, g = parseOne(t, []byte(`{"issuer": "https://gitlab.com", "audiences": ["a"], "claimsMatchingExpression": {"Value": "claims['sub'] eq 'x'", "value": "claims['sub'] eq 'y'", "languageVersion": 1}}`))
	if kinds := joinKinds(g.Anomalies); kinds != "miscased-key" || g.Admits.String() != `{aud="a", sub="y"}` {
		t.Errorf("Value beside value: kinds %s admits %s", kinds, g.Admits)
	}
	if len(g.Anomalies) != 1 || g.Anomalies[0].Source != "claimsMatchingExpression.Value" || g.Anomalies[0].Message != `the member "Value" differs from Graph's "value" only in case; Graph member names are exact, so it is not read as value` {
		t.Errorf("miscased member inside the expression:%s", renderAnomalies(g.Anomalies))
	}
}

func TestIssuerForms(t *testing.T) {
	cases := []struct {
		raw    string
		issuer trust.IssuerRef
		kinds  string
	}{
		{"https://token.actions.githubusercontent.com", github, ""},
		{"https://token.actions.githubusercontent.com/", github, ""},
		{"https://gitlab.acme.com", "https://gitlab.acme.com", ""},
		// Surrounding whitespace: the issuer that remains is read, and the
		// fact recorded, because Microsoft says the exchange is blocked.
		{" https://token.actions.githubusercontent.com", github, "issuer-whitespace"},
		{"https://token.actions.githubusercontent.com ", github, "issuer-whitespace"},
		{"  https://token.actions.githubusercontent.com  ", github, "issuer-whitespace"},
		{"\thttps://token.actions.githubusercontent.com\n", github, "issuer-whitespace"},
		{" https://token.actions.githubusercontent.com", github, "issuer-whitespace"},
		{" http://token.actions.githubusercontent.com", github, "issuer-scheme,issuer-whitespace"},
		{"https://oidc.circleci.com/org/2C3F7A0E/", "https://oidc.circleci.com/org/2C3F7A0E", ""},
		// Not https: normalised all the same, and the fact recorded.
		{"http://token.actions.githubusercontent.com", github, "issuer-scheme"},
		{"token.actions.githubusercontent.com", github, "issuer-scheme"},
		{"ftp://token.actions.githubusercontent.com", github, "issuer-scheme"},
		{"Https://token.actions.githubusercontent.com", github, "issuer-scheme"},
		{"HTTPS://Token.Actions.GitHubUserContent.com", github, "issuer-scheme"},
		// No host: no issuer.
		{"", "", "missing-issuer"},
		{"   ", "", "missing-issuer"},
		{"https://", "", "missing-issuer"},
		{"/", "", "missing-issuer"},
		{"https:///org/x", "", "missing-issuer"},
	}
	for _, c := range cases {
		raw := `{"issuer": ` + string(mustJSON(c.raw)) + `, "subject": "s", "audiences": ["a"]}`
		_, g := parseOne(t, []byte(raw))
		if g.Issuer != c.issuer {
			t.Errorf("issuer %q: normalised to %q, want %q", c.raw, g.Issuer, c.issuer)
		}
		if kinds := joinKinds(g.Anomalies); kinds != c.kinds {
			t.Errorf("issuer %q: anomaly kinds %q, want %q", c.raw, kinds, c.kinds)
		}
		if !g.Exact() {
			t.Errorf("issuer %q: the issuer never caveats the admitted set; got %v", c.raw, g.Admits.Caveats())
		}
	}
	_, g := parseOne(t, []byte(`{"issuer": "https:///org/x", "subject": "s", "audiences": ["a"]}`))
	if want := `issuer "https:///org/x" names no host, so which identity provider this credential trusts is not stated`; len(g.Anomalies) != 1 || g.Anomalies[0].Message != want || g.Anomalies[0].Construct != "issuer" {
		t.Errorf("no host:%s", renderAnomalies(g.Anomalies))
	}
	_, g = parseOne(t, []byte(`{"issuer": "token.actions.githubusercontent.com", "subject": "s", "audiences": ["a"]}`))
	if want := `issuer "token.actions.githubusercontent.com" does not begin with https://; Entra matches it against the token's iss claim, and every documented issuer states its iss as an https URL`; len(g.Anomalies) != 1 || g.Anomalies[0].Message != want {
		t.Errorf("bare host:%s", renderAnomalies(g.Anomalies))
	}
	// Whitespace around the issuer is a fact Microsoft attaches a
	// consequence to, so the sentence quotes the value as written and
	// says what may follow; the Grant still names the trimmed issuer.
	c, g := parseOne(t, []byte(`{"issuer": "\thttps://token.actions.githubusercontent.com\n", "subject": "s", "audiences": ["a"]}`))
	want := trust.Anomaly{Kind: "issuer-whitespace", Construct: "issuer",
		Message: `issuer "\thttps://token.actions.githubusercontent.com\n" has leading or trailing whitespace; Microsoft says an issuer claim with leading or trailing whitespace blocks the token exchange, so this credential may admit no token; it is read as trusting the issuer with the whitespace removed`,
		Source:  "issuer"}
	if len(g.Anomalies) != 1 || g.Anomalies[0] != want || g.Issuer != github || c.Issuer != "\thttps://token.actions.githubusercontent.com\n" {
		t.Errorf("whitespace: issuer %q as written %q anomalies%s", g.Issuer, c.Issuer, renderAnomalies(g.Anomalies))
	}
	// Whitespace alone is no issuer, and is not reported twice.
	_, g = parseOne(t, []byte(`{"issuer": " \n ", "subject": "s", "audiences": ["a"]}`))
	if kinds := joinKinds(g.Anomalies); kinds != "missing-issuer" {
		t.Errorf("whitespace only: kinds %s", kinds)
	}
}

func mustJSON(v any) []byte {
	raw, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return raw
}

// TestEmptySubject: the empty string is no subject, and a fact. Alone it is
// no subject constraint, with the fact recorded beside the doubt; beside an
// expression it is not a second reading of the document, so the expression
// stands alone and exact, with the fact recorded and nothing else: no
// subject-and-expression doubt, no caveat. The golden corpus pins the
// sentences; this test pins that the fact is a note wherever it sits.
func TestEmptySubject(t *testing.T) {
	c, g := parseOne(t, readCredential(t, "18-empty-subject"))
	if c.Subject != "" {
		t.Errorf("subject %q, want the document's empty string", c.Subject)
	}
	if kinds := joinKinds(g.Anomalies); kinds != "empty-subject,no-subject-constraint" || len(g.Admits.Caveats()) != 1 {
		t.Errorf("empty subject alone: kinds %s caveats %v", kinds, g.Admits.Caveats())
	}
	for _, expression := range []string{
		"claims['sub'] eq 'x'",
		"claims['sub'] eq 'a' or claims['sub'] eq 'b'",
	} {
		_, g = parseOne(t, []byte(`{"issuer": "https://gitlab.com", "subject": "", "audiences": ["a"], "claimsMatchingExpression": {"value": "`+expression+`", "languageVersion": 1}}`))
		if kinds := joinKinds(g.Anomalies); !strings.HasPrefix(kinds, "empty-subject") || strings.Contains(kinds, "subject-and-expression") {
			t.Errorf("empty subject beside %q: kinds %s", expression, kinds)
		}
		if hasCaveatOn(g.Admits.Caveats(), "sub") != strings.Contains(expression, " or ") {
			t.Errorf("empty subject beside %q: the caveats are the expression's alone: %v", expression, g.Admits.Caveats())
		}
	}
}

func TestSubjectAndExpressionAdmitEitherReading(t *testing.T) {
	_, g := parseOne(t, readCredential(t, "05-subject-and-expression"))
	for _, tok := range []map[trust.ClaimKey]string{
		{"aud": "api://AzureADTokenExchange", "sub": mainBranch},
		{"aud": "api://AzureADTokenExchange", "sub": mainBranch, "repository_id": "999999"},
		{"aud": "api://AzureADTokenExchange", "sub": "repo:acme/other:ref:refs/heads/dev", "repository_id": "456789"},
	} {
		if !g.Admits.Admits(tok) {
			t.Errorf("%s must admit %v: one of the two readings does", g.Admits, tok)
		}
	}
	for _, tok := range []map[trust.ClaimKey]string{
		{"aud": "api://AzureADTokenExchange", "sub": "repo:acme-evil/infra:ref:refs/heads/main", "repository_id": "456789"},
		{"aud": "api://AzureADTokenExchange", "sub": "repo:acme/other:ref:refs/heads/dev"},
		{"sub": mainBranch},
	} {
		if g.Admits.Admits(tok) {
			t.Errorf("%s must not admit %v: neither reading does", g.Admits, tok)
		}
	}
	// An unreadable expression beside a subject: the subject's reading
	// stands beside an Unknown one, never alone.
	_, g = parseOne(t, []byte(`{"issuer": "https://gitlab.com", "subject": "s", "audiences": ["a"], "claimsMatchingExpression": {"value": "claims['sub'] eq 'a' or claims['sub'] eq 'b'", "languageVersion": 1}}`))
	if got := g.Admits.String(); got != `{aud="a", sub="s"} | {aud="a", sub=?("unparseable expression")}` {
		t.Errorf("subject beside an unparseable expression: %s", got)
	}
	if kinds := joinKinds(g.Anomalies); kinds != "subject-and-expression,unmodelled-construct" {
		t.Errorf("kinds %s", kinds)
	}
}

// TestAudienceIsMetWithTheExpression: a clause on aud is a claim Microsoft
// lists for no issuer, so it is Unknown, and the audience the document
// states is met with it rather than written over it.
func TestAudienceIsMetWithTheExpression(t *testing.T) {
	_, g := parseOne(t, []byte(`{"issuer": "https://token.actions.githubusercontent.com", "audiences": ["a"], "claimsMatchingExpression": {"value": "claims['sub'] eq 's' and claims['aud'] eq 'x' and claims['repository_id'] eq '1'", "languageVersion": 1}}`))
	if got := g.Admits.String(); got != `{aud="a", repository_id="1", sub="s"}` {
		t.Errorf("admits %s", got)
	}
	if !hasCaveatOn(g.Admits.Caveats(), "aud") || len(g.Anomalies) != 1 || g.Anomalies[0].Kind != trust.Unmodelled || g.Anomalies[0].Claim != "aud" {
		t.Errorf("the clause on aud must be declared: caveats %v anomalies%s", g.Admits.Caveats(), renderAnomalies(g.Anomalies))
	}
	if g.Admits.Admits(token{"aud": "x", "sub": "s"}) {
		t.Errorf("the audience the document states must stand: %s admits aud x", g.Admits)
	}
}

// TestUnknownEverywhereIsStillDeclared: a credential with no audience and
// no subject constraint admits every token as far as the document shows,
// which the lattice renders as Everything; the caveats are the only trace
// and must survive.
func TestUnknownEverywhereIsStillDeclared(t *testing.T) {
	_, g := parseOne(t, []byte(`{"issuer": "https://gitlab.com", "audiences": []}`))
	if !g.Admits.IsTop() || g.Exact() {
		t.Errorf("admits %s exact %v", g.Admits, g.Exact())
	}
	if caveats := g.Admits.Caveats(); len(caveats) != 2 || !hasCaveatOn(caveats, "aud") || !hasCaveatOn(caveats, "sub") {
		t.Errorf("caveats %v", caveats)
	}
}

// TestACredentialTheParserDidNotProduceStatesNoGrant: the zero value has
// no document behind it, and a Grant for it would be an Allow that admits
// nothing, exactly and without a caveat, the one shape the lattice reads as
// a proven emptiness. A caller that drops the parse error, or builds a
// Credential by hand, gets no Grant at all rather than a measured-looking
// one.
func TestACredentialTheParserDidNotProduceStatesNoGrant(t *testing.T) {
	if grants := (Credential{}).Grants(infraApp); len(grants) != 0 {
		t.Errorf("the zero Credential states %d grants: %s", len(grants), grants[0].Admits)
	}
	handmade := Credential{Issuer: "https://token.actions.githubusercontent.com", Subject: mainBranch, Audiences: []string{audienceName}}
	if grants := handmade.Grants(infraApp); len(grants) != 0 {
		t.Errorf("a hand-built Credential states %d grants: %s", len(grants), grants[0].Admits)
	}
	c, err := ParseFederatedCredential([]byte(`[]`))
	if err == nil {
		t.Fatalf("an empty list parsed as one credential")
	}
	if grants := c.Grants(infraApp); len(grants) != 0 {
		t.Errorf("the Credential returned beside an error states %d grants: %s", len(grants), grants[0].Admits)
	}
}

func TestGrantsIsIndependentOfTheCredential(t *testing.T) {
	c, _ := parseOne(t, readCredential(t, "13-repeated-claim"))
	g := c.Grants(infraApp)[0]
	if len(g.Anomalies) == 0 {
		t.Fatalf("the repeated-claim document recorded no anomaly; there is nothing to tamper with")
	}
	g.Anomalies[0].Kind = "tampered"
	g.Source[0] = 'x'
	if c.Anomalies[0].Kind == "tampered" || c.Grants(infraApp)[0].Anomalies[0].Kind == "tampered" {
		t.Errorf("Grants() must hand out a copy of the anomalies")
	}
	if c.Grants(infraApp)[0].Source[0] == 'x' {
		t.Errorf("Grants() must hand out a copy of the source bytes")
	}
	if g.Provenance != nil {
		t.Errorf("the parser has no evidence to attach; provenance is the collector's")
	}
}

// TestSourceOutlivesTheCallersBuffer: a collector reads Graph into a buffer
// it reuses, and a Credential is kept long after the parse. Source must be
// the bytes as read, not whatever the buffer holds when the Grant is asked
// for, or a finding would quote a credential that was never deployed.
func TestSourceOutlivesTheCallersBuffer(t *testing.T) {
	one := readCredential(t, "01-classic-subject")
	raw := slices.Clone(one)
	c, err := ParseFederatedCredential(raw)
	if err != nil {
		t.Fatalf("%v", err)
	}
	before := string(c.Grants(infraApp)[0].Source)
	for i := range raw {
		raw[i] = 'X'
	}
	if after := string(c.Grants(infraApp)[0].Source); after != before || after != strings.TrimSpace(string(one)) {
		t.Errorf("Source followed the caller's buffer:\n  before %s\n  after  %s", before, after)
	}
	// Each credential of a collection keeps its own bytes the same way.
	collection := []byte(`{"value": [` + string(one) + `]}`)
	cs, err := ParseFederatedCredentials(collection)
	if err != nil {
		t.Fatalf("%v", err)
	}
	for i := range collection {
		collection[i] = 'X'
	}
	if got := string(cs[0].Grants(infraApp)[0].Source); got != strings.TrimSpace(string(one)) {
		t.Errorf("a collection element's Source followed the caller's buffer: %s", got)
	}
}

// TestQuotedTextIsPrintable: document text reaches a sentence only through
// quote, which keeps it ASCII and bounded, so that a credential written to
// rewrite the terminal line that reports it cannot.
func TestQuotedTextIsPrintable(t *testing.T) {
	// The expectations spell the escapes as backslash + name so that the
	// source holds the six characters of a \u escape, never the rune.
	const bs = "\\"
	cases := []struct{ in, want string }{
		{"plain", `"plain"`},
		{"it's", `"it's"`},
		{"a\x1b[2Kb", `"a` + bs + `x1b[2Kb"`},
		{"a\ab\r\n", `"a` + bs + `ab` + bs + `r` + bs + `n"`},
		{"h\xc3\xa9llo \xe2\x88\x85", `"h` + bs + `u00e9llo ` + bs + `u2205"`},
	}
	for _, c := range cases {
		if got := quote(c.in); got != c.want {
			t.Errorf("quote(%q) = %s, want %s", c.in, got, c.want)
		}
	}
	long := strings.Repeat("\xc3\xa9", 150) // 300 bytes of é
	got := quote(long)
	if !strings.HasSuffix(got, `"...`) || strings.Count(got, bs+"u00e9") != 100 {
		t.Errorf("quote of 300 bytes = %s; want 100 runes then a marker", got)
	}
	for i := range got {
		if got[i] >= 0x80 || got[i] < 0x20 {
			t.Errorf("quote produced a non-ASCII or control byte at %d: %s", i, got)
			break
		}
	}
	// A limit that falls inside a rune backs up to the rune's start, so the
	// cut never yields a broken character, which QuoteToASCII would render
	// as a \x escape of the dangling byte and misreport.
	if got := quote("a" + long); !strings.HasSuffix(got, `"...`) || strings.Count(got, bs+"u00e9") != 99 || strings.Contains(got, bs+"x") {
		t.Errorf("quote cut inside a rune = %s; want a then 99 runes then a marker", got)
	}
	// A long clause yields a bounded sentence.
	value := "claims['sub'] eq 'a' and claims['x'] eq '" + strings.Repeat("a", 5000) + "'"
	_, g := parseOne(t, []byte(`{"issuer": "https://gitlab.com", "audiences": ["a"], "claimsMatchingExpression": {"value": `+string(mustJSON(value))+`, "languageVersion": 1}}`))
	if len(g.Anomalies) != 1 {
		t.Fatalf("anomalies%s", renderAnomalies(g.Anomalies))
	}
	if a := g.Anomalies[0]; len(a.Message) > 600 || !strings.Contains(a.Message, `"...`) || a.Construct != "claims['x']" {
		t.Errorf("unbounded anomaly: %d-byte message, construct %s", len(a.Message), a.Construct)
	}
	// A control character written into the expression through a JSON
	// escape comes out escaped again, never as itself.
	escape := "claims['sub'] eq 'a\x1b[2Kb' or x"
	_, g = parseOne(t, []byte(`{"issuer": "https://gitlab.com", "audiences": ["a"], "claimsMatchingExpression": {"value": `+string(mustJSON(escape))+`, "languageVersion": 1}}`))
	if len(g.Anomalies) != 1 || !strings.Contains(g.Anomalies[0].Message, bs+"x1b[2K") || strings.ContainsRune(g.Anomalies[0].Message, 0x1b) {
		t.Errorf("escape in a sentence: %+v", g.Anomalies)
	}
}

// TestDeterminism is the section 2 promise at this layer, run in-process;
// the Makefile runs it again in fresh processes.
func TestDeterminism(t *testing.T) {
	names := slices.Sorted(maps.Keys(golden))
	first := map[string]string{}
	for i := 0; i < 20; i++ {
		for _, name := range names {
			_, g := parseOne(t, readCredential(t, name))
			rendered := g.Admits.String() + "\n" + renderCaveats(g.Admits.Caveats()) + renderAnomalies(g.Anomalies) + "\n" + string(g.Issuer)
			if prior, seen := first[name]; seen && prior != rendered {
				t.Fatalf("%s: run %d rendered differently:\n%s\n---\n%s", name, i, prior, rendered)
			}
			first[name] = rendered
		}
	}
}

func renderCaveats(cs []eval.Caveat) string {
	var b strings.Builder
	for _, c := range cs {
		b.WriteString(string(c.Claim) + "|" + c.Reason + "|" + c.Source + "\n")
	}
	return b.String()
}

// TestEveryFactRecordedIsReported: two pieces outside the grammar that
// read alike once the quoting cut them are two facts on the Grant, not
// one; a fact dropped for resembling another would be silence.
func TestEveryFactRecordedIsReported(t *testing.T) {
	long := strings.Repeat("a", 210)
	value := "claims['sub'] eq " + long + "X and claims['sub'] eq " + long + "Y"
	_, g := parseOne(t, []byte(`{"issuer": "https://gitlab.com", "audiences": ["a"], "claimsMatchingExpression": {"value": `+string(mustJSON(value))+`, "languageVersion": 1}}`))
	if len(g.Anomalies) != 2 || g.Anomalies[0] != g.Anomalies[1] {
		t.Errorf("two broken pieces, want two facts:%s", renderAnomalies(g.Anomalies))
	}
}

// TestAnomaliesAreSortedNotAppended: two facts recorded in document order
// come back in canonical order, so that a reordered document renders the
// same anomaly list.
func TestAnomaliesAreSortedNotAppended(t *testing.T) {
	forward := `{"issuer": "https://token.actions.githubusercontent.com", "audiences": ["a"], "claimsMatchingExpression": {"value": "claims['sub'] eq 'a' and claims['repository_id'] matches '4*' and claims['environment'] eq 'p'", "languageVersion": 1}}`
	backward := `{"issuer": "https://token.actions.githubusercontent.com", "audiences": ["a"], "claimsMatchingExpression": {"value": "claims['environment'] eq 'p' and claims['repository_id'] matches '4*' and claims['sub'] eq 'a'", "languageVersion": 1}}`
	_, a := parseOne(t, []byte(forward))
	_, b := parseOne(t, []byte(backward))
	if !slices.Equal(a.Anomalies, b.Anomalies) || a.Admits.String() != b.Admits.String() {
		t.Errorf("clause order changed the grant:%s\n---%s", renderAnomalies(a.Anomalies), renderAnomalies(b.Anomalies))
	}
	if len(a.Anomalies) != 2 || a.Anomalies[0].Claim != "environment" || a.Anomalies[1].Claim != "repository_id" {
		t.Errorf("anomalies are not in canonical order:%s", renderAnomalies(a.Anomalies))
	}
}
