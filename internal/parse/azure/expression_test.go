package azure

import (
	"maps"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/CloudArq-net/cloudarq/internal/eval"
	"github.com/CloudArq-net/cloudarq/internal/trust"
)

const (
	github    = trust.IssuerRef("https://token.actions.githubusercontent.com")
	gitlab    = trust.IssuerRef("https://gitlab.com")
	terraform = trust.IssuerRef("https://app.terraform.io")
	google    = trust.IssuerRef("https://accounts.google.com")
)

// TestSplitClausesScansQuotesFirst: " and " is a separator only outside a
// comparand, so a subject that happens to contain the word is one clause.
func TestSplitClausesScansQuotesFirst(t *testing.T) {
	cases := []struct {
		expression string
		want       []string
	}{
		{"claims['sub'] eq 'a'", []string{"claims['sub'] eq 'a'"}},
		{
			"claims['sub'] eq 'a' and claims['repository_id'] eq '1' and claims['job_workflow_ref'] matches 'x/*'",
			[]string{"claims['sub'] eq 'a'", "claims['repository_id'] eq '1'", "claims['job_workflow_ref'] matches 'x/*'"},
		},
		{
			"claims['sub'] eq 'repo:acme/a and b:ref:refs/heads/main' and claims['repository_id'] eq '1'",
			[]string{"claims['sub'] eq 'repo:acme/a and b:ref:refs/heads/main'", "claims['repository_id'] eq '1'"},
		},
		// A doubled quote stays inside the comparand while the split runs.
		{
			"claims['sub'] eq 'it''s and more' and claims['repository_id'] eq '1'",
			[]string{"claims['sub'] eq 'it''s and more'", "claims['repository_id'] eq '1'"},
		},
		// An unterminated comparand swallows the rest of the expression.
		{"claims['sub'] eq 'a and claims['repository_id'] eq '1'", []string{"claims['sub'] eq 'a and claims['repository_id'] eq '1'"}},
		// The separator is exactly " and ": other spellings are clause text.
		{"claims['sub'] eq 'a' AND claims['repository_id'] eq '1'", []string{"claims['sub'] eq 'a' AND claims['repository_id'] eq '1'"}},
		{"claims['sub'] eq 'a'  and  claims['repository_id'] eq '1'", []string{"claims['sub'] eq 'a' ", " claims['repository_id'] eq '1'"}},
		// Empty pieces are kept, so the grammar can refuse them.
		{"claims['sub'] eq 'a' and ", []string{"claims['sub'] eq 'a'", ""}},
		{" and claims['sub'] eq 'a'", []string{"", "claims['sub'] eq 'a'"}},
		{"", []string{""}},
	}
	for _, c := range cases {
		got := splitClauses(c.expression)
		if strings.Join(got, "\x00") != strings.Join(c.want, "\x00") {
			t.Errorf("splitClauses(%q) = %q, want %q", c.expression, got, c.want)
		}
	}
}

func TestParseClauseIsStrict(t *testing.T) {
	accepted := []struct {
		text string
		want clause
	}{
		{"claims['sub'] eq 'repo:acme/infra:ref:refs/heads/main'", clause{name: "sub", operator: "eq", comparand: "repo:acme/infra:ref:refs/heads/main"}},
		{"claims['sub'] matches 'repo:acme/*'", clause{name: "sub", operator: "matches", comparand: "repo:acme/*"}},
		// An operator the grammar does not know still parses as a clause;
		// what it means is decided by evaluation, not by the tokenizer.
		{"claims['repository_id'] startsWith '4567'", clause{name: "repository_id", operator: "startsWith", comparand: "4567"}},
		{"claims['sub'] EQ 'a'", clause{name: "sub", operator: "EQ", comparand: "a"}},
		// The claim name is kept as written, quotes in the comparand as written.
		{"claims['SUB'] eq 'a'", clause{name: "SUB", operator: "eq", comparand: "a"}},
		{"claims['sub'] eq 'it''s'", clause{name: "sub", operator: "eq", comparand: "it''s"}},
		// The leftmost pair is the escape, so this comparand is a'' and the
		// third quote closes it; what the pair means is evaluation's question.
		{"claims['sub'] eq 'a'''", clause{name: "sub", operator: "eq", comparand: "a''"}},
		{"claims['sub'] eq ''", clause{name: "sub", operator: "eq", comparand: ""}},
		{"claims['sub'] eq ' and '", clause{name: "sub", operator: "eq", comparand: " and "}},
		{"claims['oidc.circleci.com/project-id'] eq 'x'", clause{name: "oidc.circleci.com/project-id", operator: "eq", comparand: "x"}},
	}
	for _, c := range accepted {
		got, ok := parseClause(c.text)
		c.want.text = c.text
		if !ok || got != c.want {
			t.Errorf("parseClause(%q) = (%+v, %v), want (%+v, true)", c.text, got, ok, c.want)
		}
	}
	rejected := []string{
		"",
		" ",
		"claims['sub'] eq 'a' ",
		" claims['sub'] eq 'a'",
		"claims['sub']  eq 'a'",
		"claims['sub'] eq  'a'",
		"claims['sub']\teq 'a'",
		"claims['sub'] eq\t'a'",
		"claims['sub']eq'a'",
		"claims['sub'] eq a",
		"claims['sub'] eq \"a\"",
		"claims[\"sub\"] eq 'a'",
		"claims[ 'sub' ] eq 'a'",
		"claims['sub'] eq 'a' and claims['repository_id'] eq '1'",
		"claims['sub'] eq 'a' or claims['sub'] eq 'b'",
		"not claims['sub'] eq 'a'",
		"(claims['sub'] eq 'a')",
		"claims['sub'] == 'a'",
		"claims[sub] eq 'a'",
		"claims['sub",
		"claims['",
		"claims['sub'] eq 'a",
		"claims['sub'] eq a'",
		"claims['sub'] eq 'a'b'",
		"claims[''] eq 'a'",
		"claims['a b'] eq 'a'",
		"claims['a\nb'] eq 'a'",
		"claims['sub'] 'a'",
		"claims['sub'] eq",
		"claims['sub'] e-q 'a'",
		"claims['sub'] eq 'a' 'b'",
		"Claims['sub'] eq 'a'",
		"claims['sub'].value eq 'a'",
	}
	for _, text := range rejected {
		if got, ok := parseClause(text); ok {
			t.Errorf("parseClause(%q) = %+v, want refused", text, got)
		}
	}
}

func TestDocumentedClaimsFollowMicrosoftsTable(t *testing.T) {
	ops := func(issuer trust.IssuerRef, claim trust.ClaimKey) string {
		lang, ok := documentedLanguage(issuer)
		if !ok {
			return "issuer undocumented"
		}
		return strings.Join(lang.operators[claim], ",")
	}
	cases := []struct {
		issuer trust.IssuerRef
		claim  trust.ClaimKey
		want   string
	}{
		{github, "sub", "eq,matches"},
		{github, "job_workflow_ref", "eq,matches"},
		{github, "repository_id", "eq"},
		{github, "repository_owner_id", "eq"},
		{github, "environment", ""},
		{github, "aud", ""},
		{gitlab, "sub", "eq,matches"},
		{gitlab, "repository_id", ""},
		{"https://gitlab.acme.com", "sub", "eq,matches"},
		{"https://gitlab.acme.ca", "sub", "eq,matches"},
		{"https://gitlab.acme.co.uk.ca", "sub", "eq,matches"},
		{terraform, "sub", "eq,matches"},
		{"https://app.eu.terraform.io", "sub", "eq,matches"},
		// Outside the documented forms.
		{google, "sub", "issuer undocumented"},
		{"", "sub", "issuer undocumented"},
		{"https://gitlab.acme.org", "sub", "issuer undocumented"},
		{"https://gitlab.com/group", "sub", "issuer undocumented"},
		{"https://gitlab.ca", "sub", "issuer undocumented"},
		{"https://gitlabx.com", "sub", "issuer undocumented"},
		{"https://mygitlab.acme.com", "sub", "issuer undocumented"},
		{"https://token.actions.githubusercontent.com/acme", "sub", "issuer undocumented"},
		{"https://app.terraform.io/x", "sub", "issuer undocumented"},
	}
	for _, c := range cases {
		if got := ops(c.issuer, c.claim); got != c.want {
			t.Errorf("documentedClaims(%q)[%q] = %q, want %q", c.issuer, c.claim, got, c.want)
		}
	}
	// What an expression must name: sub and an immutable claim for GitHub,
	// nothing stated for the others.
	required := func(issuer trust.IssuerRef) string {
		lang, _ := documentedLanguage(issuer)
		groups := make([]string, len(lang.required))
		for i, g := range lang.required {
			groups[i] = spellClaims(g)
		}
		return strings.Join(groups, "; ")
	}
	if got := required(github); got != "sub; repository_id or repository_owner_id" {
		t.Errorf("GitHub requires %q", got)
	}
	for _, issuer := range []trust.IssuerRef{gitlab, "https://gitlab.acme.com", terraform} {
		if got := required(issuer); got != "" {
			t.Errorf("%s requires %q, want nothing stated", issuer, got)
		}
	}
}

// evaluated runs one expression under an issuer and renders the Term it
// produces claim by claim, before any normalisation: a Term whose only
// claim is Unknown would collapse to Everything inside an AdmittedSet, and
// the tests here are about what the evaluator said, not what the lattice
// keeps of it.
func evaluated(expression string, issuer trust.IssuerRef) (string, *reading) {
	r := &reading{}
	term := r.evaluate(expression, issuer)
	parts := make([]string, 0, len(term))
	for _, k := range slices.Sorted(maps.Keys(term)) {
		parts = append(parts, string(k)+"="+term[k].String())
	}
	return "{" + strings.Join(parts, ", ") + "}", r
}

func TestEvaluateModelsTheDocumentedLanguage(t *testing.T) {
	cases := []struct {
		expression string
		want       string
	}{
		{"claims['sub'] eq 'repo:acme/infra:ref:refs/heads/main' and claims['repository_id'] eq '456789'", `{repository_id="456789", sub="repo:acme/infra:ref:refs/heads/main"}`},
		{"claims['sub'] matches 'repo:acme/*' and claims['repository_owner_id'] eq '123456'", `{repository_owner_id="123456", sub=like:"repo:acme/*"}`},
		{"claims['sub'] matches 'repo:acme/infra:ref:refs/heads/????' and claims['repository_id'] eq '1'", `{repository_id="1", sub=like:"repo:acme/infra:ref:refs/heads/????"}`},
		// A pattern without a wildcard is an exact value; eq never has one.
		{"claims['sub'] matches 'repo:acme/infra:ref:refs/heads/main' and claims['repository_id'] eq '1'", `{repository_id="1", sub="repo:acme/infra:ref:refs/heads/main"}`},
		{"claims['sub'] eq 'repo:acme/*' and claims['repository_id'] eq '1'", `{repository_id="1", sub="repo:acme/*"}`},
		// Both immutable claims, in any order.
		{"claims['repository_owner_id'] eq '123456' and claims['sub'] eq 'a' and claims['repository_id'] eq '1'", `{repository_id="1", repository_owner_id="123456", sub="a"}`},
		// A pattern that matches everything is Any, which the lattice drops.
		{"claims['sub'] matches '*' and claims['repository_id'] eq '456789'", `{repository_id="456789", sub=*}`},
		{"claims['sub'] matches '**' and claims['repository_id'] eq '456789'", `{repository_id="456789", sub=*}`},
		{"claims['job_workflow_ref'] matches 'acme/workflows/.github/workflows/deploy.yml@refs/heads/main' and claims['sub'] eq 'a' and claims['repository_id'] eq '1'", `{job_workflow_ref="acme/workflows/.github/workflows/deploy.yml@refs/heads/main", repository_id="1", sub="a"}`},
	}
	for _, c := range cases {
		got, r := evaluated(c.expression, github)
		if got != c.want {
			t.Errorf("evaluate(%q) = %s, want %s", c.expression, got, c.want)
		}
		if len(r.caveats) != 0 {
			t.Errorf("evaluate(%q) caveats = %v, want none: the language models every clause", c.expression, r.caveats)
		}
	}
}

func TestEvaluateWidensWhatItDoesNotModel(t *testing.T) {
	cases := []struct {
		name       string
		issuer     trust.IssuerRef
		expression string
		want       string
		unknown    []trust.ClaimKey // claims left Unknown, each of which must carry a caveat
		kinds      string
	}{
		{
			"repeated claim", github,
			"claims['sub'] eq 'a' and claims['sub'] eq 'b' and claims['repository_id'] eq '1'",
			`{repository_id="1", sub=?("repeated claim")}`, []trust.ClaimKey{"sub"}, "unmodelled-construct",
		},
		{
			"repeated claim, identical clauses", github,
			"claims['sub'] eq 'a' and claims['sub'] eq 'a' and claims['repository_id'] eq '1'",
			`{repository_id="1", sub=?("repeated claim")}`, []trust.ClaimKey{"sub"}, "unmodelled-construct",
		},
		{
			"escaped quote", github,
			"claims['sub'] eq 'repo:acme/it''s:ref:refs/heads/main' and claims['repository_id'] eq '1'",
			`{repository_id="1", sub=?("escaped quote")}`, []trust.ClaimKey{"sub"}, "unmodelled-construct",
		},
		{
			"empty comparand", github,
			"claims['sub'] eq '' and claims['repository_id'] eq '1'",
			`{repository_id="1", sub=?("empty comparand")}`, []trust.ClaimKey{"sub"}, "unmodelled-construct",
		},
		{
			"empty pattern", github,
			"claims['sub'] matches '' and claims['repository_id'] eq '1'",
			`{repository_id="1", sub=?("empty comparand")}`, []trust.ClaimKey{"sub"}, "unmodelled-construct",
		},
		{
			"undocumented claim", github,
			"claims['sub'] eq 'a' and claims['environment'] eq 'production' and claims['repository_id'] eq '1'",
			`{environment=?("undocumented claim"), repository_id="1", sub="a"}`, []trust.ClaimKey{"environment"}, "unmodelled-construct",
		},
		{
			"undocumented operator for the claim", github,
			"claims['sub'] eq 'a' and claims['repository_id'] matches '45*'",
			`{repository_id=?("undocumented operator"), sub="a"}`, []trust.ClaimKey{"repository_id"}, "unmodelled-construct",
		},
		{
			"operator the language does not have", github,
			"claims['sub'] eq 'a' and claims['repository_id'] startsWith '4567'",
			`{repository_id=?("undocumented operator"), sub="a"}`, []trust.ClaimKey{"repository_id"}, "unmodelled-construct",
		},
		{
			"operator in the wrong case", github,
			"claims['sub'] EQ 'a' and claims['repository_id'] eq '1'",
			`{repository_id="1", sub=?("undocumented operator")}`, []trust.ClaimKey{"sub"}, "unmodelled-construct",
		},
		{
			"claim name folded", github,
			"claims['SUB'] eq 'a' and claims['Repository_Id'] eq '1'",
			`{repository_id="1", sub="a"}`, nil, "claim-folded,claim-folded",
		},
		{
			"claim name folded onto a repeated claim", github,
			"claims['SUB'] eq 'a' and claims['sub'] eq 'b' and claims['repository_id'] eq '1'",
			`{repository_id="1", sub=?("repeated claim")}`, []trust.ClaimKey{"sub"}, "claim-folded,unmodelled-construct",
		},
		{
			"issuer Microsoft does not list", google,
			"claims['sub'] eq 'a' and claims['repository_id'] eq '1'",
			`{repository_id=?("undocumented issuer"), sub=?("undocumented issuer")}`, []trust.ClaimKey{"repository_id", "sub"}, "unmodelled-construct,unmodelled-construct",
		},
		{
			"no issuer at all", "",
			"claims['sub'] eq 'a'",
			`{sub=?("undocumented issuer")}`, []trust.ClaimKey{"sub"}, "unmodelled-construct",
		},
		{
			"gitlab does not document repository_id", gitlab,
			"claims['sub'] matches 'project_path:acme/*' and claims['repository_id'] eq '1'",
			`{repository_id=?("undocumented claim"), sub=like:"project_path:acme/*"}`, []trust.ClaimKey{"repository_id"}, "unmodelled-construct",
		},
		{
			"matches everything is exact and noted", github,
			"claims['sub'] matches '*' and claims['repository_id'] eq '1'",
			`{repository_id="1", sub=*}`, nil, "undocumented-acceptance",
		},
	}
	for _, c := range cases {
		got, r := evaluated(c.expression, c.issuer)
		if got != c.want {
			t.Errorf("%s: evaluate(%q) = %s, want %s", c.name, c.expression, got, c.want)
		}
		if kinds := joinKinds(r.anomalies); kinds != c.kinds {
			t.Errorf("%s: anomaly kinds %q, want %q", c.name, kinds, c.kinds)
		}
		for _, k := range c.unknown {
			if !hasCaveatOn(r.caveats, k) {
				t.Errorf("%s: %s is Unknown without a caveat: %v", c.name, k, r.caveats)
			}
		}
		if len(c.unknown) == 0 && len(r.caveats) != 0 && !strings.Contains(c.kinds, "claim-folded") {
			t.Errorf("%s: unexpected caveats %v", c.name, r.caveats)
		}
	}
}

// TestExpressionSentences pins, word for word, the sentences the golden
// corpus does not: a customer reads these verbatim, so a drift in one is a
// change in what the product says.
func TestExpressionSentences(t *testing.T) {
	cases := []struct {
		name       string
		issuer     trust.IssuerRef
		expression string
		want       trust.Anomaly
	}{
		{
			"empty expression", github, "",
			trust.Anomaly{Kind: trust.Unmodelled, Claim: "sub", Construct: "empty expression",
				Message: "claimsMatchingExpression.value is empty; Microsoft documents no empty expression, so nothing the expression says about the token is modelled",
				Source:  "claimsMatchingExpression.value"},
		},
		{
			"no issuer", "", "claims['sub'] eq 'a'",
			trust.Anomaly{Kind: trust.Unmodelled, Claim: "sub", Construct: `""`,
				Message: `Microsoft documents claim expressions for GitHub, GitLab and Terraform Cloud issuers; whether Entra evaluates "claims['sub'] eq 'a'" without an issuer is not documented`,
				Source:  "claimsMatchingExpression.value"},
		},
		{
			"empty comparand", github, "claims['sub'] eq '' and claims['repository_id'] eq '1'",
			trust.Anomaly{Kind: trust.Unmodelled, Claim: "sub", Construct: "empty comparand",
				Message: `"claims['sub'] eq ''" compares against the empty string; Microsoft does not say whether Entra accepts an empty comparand`,
				Source:  "claimsMatchingExpression.value"},
		},
		{
			"empty pattern", github, "claims['sub'] matches '' and claims['repository_id'] eq '1'",
			trust.Anomaly{Kind: trust.Unmodelled, Claim: "sub", Construct: "empty comparand",
				Message: `"claims['sub'] matches ''" compares against the empty string; Microsoft does not say whether Entra accepts an empty comparand`,
				Source:  "claimsMatchingExpression.value"},
		},
		{
			"operator outside the two listed", github, "claims['sub'] EQ 'a' and claims['repository_id'] eq '1'",
			trust.Anomaly{Kind: trust.Unmodelled, Claim: "sub", Construct: "EQ",
				Message: `Microsoft lists "eq" and "matches" for claims['sub'] under issuer "https://token.actions.githubusercontent.com", not "EQ", so whether Entra evaluates "claims['sub'] EQ 'a'" is not documented`,
				Source:  "claimsMatchingExpression.value"},
		},
		{
			"empty clause", github, "claims['sub'] eq 'a' and claims['repository_id'] eq '1' and ",
			trust.Anomaly{Kind: trust.Unmodelled, Claim: "sub", Construct: "empty clause",
				Message: `the expression has an empty clause: "and" is written with nothing on one side of it; Microsoft's grammar joins clauses of the form claims['<name>'] eq '<value>' or claims['<name>'] matches '<value>' with "and", so nothing the expression says about the token is modelled`,
				Source:  "claimsMatchingExpression.value"},
		},
		{
			"unbalanced quote", github, "claims['sub'] eq 'o'reilly' and claims['repository_id'] eq '1'",
			trust.Anomaly{Kind: trust.Unmodelled, Claim: "sub", Construct: "unbalanced quote",
				Message: `the expression holds an odd number of single quotes, so where its claim names and comparands begin and end cannot be read; Microsoft's grammar encloses each in single quotes, so nothing the expression says about the token is modelled`,
				Source:  "claimsMatchingExpression.value"},
		},
		{
			"no clause on sub", github, "claims['repository_id'] eq '456789'",
			trust.Anomaly{Kind: trust.Unmodelled, Claim: "sub", Construct: "missing required claim",
				Message: `the expression names no clause on sub; Microsoft says a flexible federated identity credential for issuer "https://token.actions.githubusercontent.com" must match it, so whether Entra accepts or evaluates this expression is not documented`,
				Source:  "claimsMatchingExpression.value"},
		},
		{
			"no immutable claim", github, "claims['sub'] matches 'repo:acme/*'",
			trust.Anomaly{Kind: trust.Unmodelled, Claim: "sub", Construct: "missing required claim",
				Message: `the expression names no clause on repository_id or repository_owner_id; Microsoft says a flexible federated identity credential for issuer "https://token.actions.githubusercontent.com" must match one of them, so whether Entra accepts or evaluates this expression is not documented`,
				Source:  "claimsMatchingExpression.value"},
		},
		{
			"claim GitLab does not list", gitlab, "claims['repository_id'] eq '1'",
			trust.Anomaly{Kind: trust.Unmodelled, Claim: "repository_id", Construct: "claims['repository_id']",
				Message: `Microsoft does not list claims['repository_id'] for issuer "https://gitlab.com", so whether Entra evaluates "claims['repository_id'] eq '1'" is not documented`,
				Source:  "claimsMatchingExpression.value"},
		},
	}
	for _, c := range cases {
		_, r := evaluated(c.expression, c.issuer)
		if len(r.anomalies) != 1 || r.anomalies[0] != c.want {
			t.Errorf("%s: anomalies%s\n  want%s", c.name, renderAnomalies(r.anomalies), renderAnomalies([]trust.Anomaly{c.want}))
		}
		if len(r.caveats) != 1 || r.caveats[0] != (eval.Caveat{Claim: c.want.Claim, Reason: c.want.Message, Source: c.want.Source}) {
			t.Errorf("%s: caveats %v must carry the anomaly's sentence", c.name, r.caveats)
		}
	}
}

// TestUnparseableExpressionDropsEveryClause: when one clause is outside the
// grammar the operator that was dropped may have governed the others, so
// nothing survives but the audience; sub carries the Unknown.
func TestUnparseableExpressionDropsEveryClause(t *testing.T) {
	expressions := []string{
		"claims['sub'] eq 'a' or claims['sub'] eq 'b'",
		"claims['repository_id'] eq '1' and claims['sub'] eq 'a' or claims['sub'] eq 'b'",
		"claims['repository_id'] eq '1' and not claims['sub'] eq 'a'",
		"claims['repository_id'] eq '1' and (claims['sub'] eq 'a')",
		"claims['repository_id'] eq '1' AND claims['sub'] eq 'a'",
		"claims['repository_id'] eq '1' and claims['sub'] eq a",
		"claims['repository_id'] eq '1' and claims[sub] == 'a'",
		"claims['repository_id'] eq '1' and ",
		"claims['repository_id'] eq '1' and claims['sub'] eq 'a",
		" claims['repository_id'] eq '1'",
		"",
		"   ",
	}
	for _, expression := range expressions {
		got, r := evaluated(expression, github)
		if got != `{sub=?("unparseable expression")}` {
			t.Errorf("evaluate(%q) = %s; every clause must be dropped and sub left Unknown", expression, got)
		}
		if !hasCaveatOn(r.caveats, "sub") {
			t.Errorf("evaluate(%q): sub is Unknown without a caveat", expression)
		}
		if len(r.anomalies) != 1 || r.anomalies[0].Kind != trust.Unmodelled || r.anomalies[0].Claim != "sub" {
			t.Errorf("evaluate(%q): anomalies = %+v, want one unmodelled-construct on sub", expression, r.anomalies)
		}
	}
	// The sentence names the clause that broke the grammar, not the whole
	// expression, so the customer can see which part is outside the language;
	// the construct names the fact, so a reporter can count it.
	_, r := evaluated("claims['repository_id'] eq '1' and claims['sub'] eq 'a' or claims['sub'] eq 'b'", github)
	if a := r.anomalies[0]; a.Construct != "unparseable clause" || !strings.HasPrefix(a.Message, `"claims['sub'] eq 'a' or claims['sub'] eq 'b'" is not of the form`) {
		t.Errorf("anomaly = %+v, want the offending clause named", a)
	}
	_, r = evaluated("", github)
	if c := r.anomalies[0].Construct; c != "empty expression" {
		t.Errorf("Construct = %s, want the empty expression named", c)
	}
	// Every piece outside the grammar is named, not only the first, so that
	// the list is the same whichever order the clauses were written in.
	got, r := evaluated("claims['sub'] eq a and claims['repository_id'] eq '1' and claims['x'] eq y", github)
	if got != `{sub=?("unparseable expression")}` || len(r.anomalies) != 2 || len(r.caveats) != 2 ||
		!strings.HasPrefix(r.anomalies[0].Message, `"claims['sub'] eq a" is`) || !strings.HasPrefix(r.anomalies[1].Message, `"claims['x'] eq y" is`) {
		t.Errorf("two broken clauses: %s %+v", got, r.anomalies)
	}
	// Two pieces that read alike once the quoting cut them are still two
	// facts: a fact dropped for resembling another would be silence.
	long := strings.Repeat("a", 210)
	got, r = evaluated("claims['sub'] eq "+long+"X and claims['sub'] eq "+long+"Y", github)
	if got != `{sub=?("unparseable expression")}` || len(r.anomalies) != 2 || r.anomalies[0] != r.anomalies[1] {
		t.Errorf("two long broken clauses: %s%s", got, renderAnomalies(r.anomalies))
	}
	// An empty piece is named as such, so that the sentence says what was
	// wrong rather than quoting nothing.
	for _, expression := range []string{
		"claims['sub'] eq 'a' and claims['repository_id'] eq '1' and ",
		" and claims['sub'] eq 'a' and claims['repository_id'] eq '1'",
		"claims['sub'] eq 'a' and  and claims['repository_id'] eq '1'",
	} {
		got, r := evaluated(expression, github)
		if got != `{sub=?("unparseable expression")}` || len(r.anomalies) != 1 || r.anomalies[0].Construct != "empty clause" {
			t.Errorf("evaluate(%q) = %s%s", expression, got, renderAnomalies(r.anomalies))
		}
	}
}

// TestClausesPastTheCapAreUnknown: an expression is read up to clauseCap
// clauses, where every clause is what it says; past the cap nothing of it
// is read, sub is Unknown with the count stated, and no clause survives,
// which is wider than any conjunction and never a truncation of one.
func TestClausesPastTheCapAreUnknown(t *testing.T) {
	expression := func(n int) string {
		clauses := make([]string, n)
		for i := range clauses {
			clauses[i] = "claims['c" + strconv.Itoa(i) + "'] eq 'v'"
		}
		return strings.Join(clauses, " and ")
	}
	got, r := evaluated(expression(clauseCap), gitlab)
	if !strings.HasPrefix(got, `{c0=?("undocumented claim"), `) || !strings.Contains(got, `c255=?("undocumented claim")`) || len(r.anomalies) != clauseCap {
		t.Errorf("at the cap every clause is read: %d anomalies, %.80s", len(r.anomalies), got)
	}
	got, r = evaluated(expression(clauseCap+1), gitlab)
	if got != `{sub=?("too many clauses")}` {
		t.Errorf("past the cap: evaluate = %s", got)
	}
	want := trust.Anomaly{Kind: trust.Unmodelled, Claim: "sub", Construct: "clause count",
		Message: "the expression has 257 clauses; Microsoft documents at most four claims for any issuer, and this parser reads at most 256 clauses, so nothing the expression says about the token is modelled",
		Source:  "claimsMatchingExpression.value"}
	if len(r.anomalies) != 1 || r.anomalies[0] != want || !hasCaveatOn(r.caveats, "sub") {
		t.Errorf("past the cap: anomalies%s caveats %v", renderAnomalies(r.anomalies), r.caveats)
	}
	// Past the cap the pieces are not read far enough to be judged: a clause
	// outside the grammar among them is not reported on its own.
	_, r = evaluated(expression(clauseCap+1)+" and not a clause", gitlab)
	if len(r.anomalies) != 1 || r.anomalies[0].Construct != "clause count" {
		t.Errorf("past the cap with a broken piece: anomalies%s", renderAnomalies(r.anomalies))
	}
}

// TestUnbalancedQuoteIsOneFactWhateverTheOrder: with a stray single quote
// the lexer cannot tell where the comparands end, so which text a piece
// holds depends on which clause the quote sits in. The expression is
// therefore judged as a whole, by its quote count, which no reordering
// changes; naming pieces would name different pieces for the same clauses
// in another order.
func TestUnbalancedQuoteIsOneFactWhateverTheOrder(t *testing.T) {
	forward := "claims['sub'] eq 'o'reilly' and claims['repository_id'] eq '1'"
	backward := "claims['repository_id'] eq '1' and claims['sub'] eq 'o'reilly'"
	a, ra := evaluated(forward, github)
	b, rb := evaluated(backward, github)
	if a != b || a != `{sub=?("unparseable expression")}` {
		t.Errorf("evaluate = %s and %s", a, b)
	}
	if !slices.Equal(ra.anomalies, rb.anomalies) || !slices.Equal(ra.caveats, rb.caveats) {
		t.Errorf("clause order changed the facts:%s\n---%s", renderAnomalies(ra.anomalies), renderAnomalies(rb.anomalies))
	}
	if len(ra.anomalies) != 1 || ra.anomalies[0].Construct != "unbalanced quote" || !hasCaveatOn(ra.caveats, "sub") {
		t.Errorf("anomalies%s caveats %v", renderAnomalies(ra.anomalies), ra.caveats)
	}
	// A doubled quote is two quotes: the comparand is not the problem the
	// sentence above describes, and the escape it holds is named instead.
	_, r := evaluated("claims['sub'] eq 'it''s' and claims['repository_id'] eq '1'", github)
	if len(r.anomalies) != 1 || r.anomalies[0].Construct != "escaped quote" {
		t.Errorf("a doubled quote is balanced: %s", renderAnomalies(r.anomalies))
	}
}

// TestGitHubExpressionMustMatchSubAndAnImmutableClaim: Microsoft says a
// GitHub expression must match sub and one or both of repository_id and
// repository_owner_id. One that does not is outside the documented
// language, and nothing it says is modelled: sub carries the Unknown and
// an anomaly names each missing clause. The facts about the clauses it
// does hold are still recorded, so that a customer reading the anomaly
// list sees why a claim that looks present is not the one required.
func TestGitHubExpressionMustMatchSubAndAnImmutableClaim(t *testing.T) {
	const missing = "missing required claim"
	cases := []struct {
		expression string
		constructs []string
		kinds      string
	}{
		{"claims['sub'] matches 'repo:acme/*'", []string{missing}, "unmodelled-construct"},
		{"claims['sub'] eq 'repo:acme/infra:ref:refs/heads/main'", []string{missing}, "unmodelled-construct"},
		{"claims['sub'] matches '*'", []string{"*", missing}, "undocumented-acceptance,unmodelled-construct"},
		{"claims['sub'] matches 'repo:acme/*' and claims['job_workflow_ref'] matches 'acme/*'", []string{missing}, "unmodelled-construct"},
		{"claims['repository_id'] eq '456789'", []string{missing}, "unmodelled-construct"},
		{"claims['repository_owner_id'] eq '123456'", []string{missing}, "unmodelled-construct"},
		{"claims['job_workflow_ref'] eq 'acme/infra/.github/workflows/deploy.yml@refs/heads/main'", []string{missing, missing}, "unmodelled-construct,unmodelled-construct"},
		{"claims['environment'] eq 'production'", []string{"claims['environment']", missing, missing}, "unmodelled-construct,unmodelled-construct,unmodelled-construct"},
		// A homoglyph of sub is a claim no token carries, not sub.
		{"claims['ſub'] eq 'a' and claims['repository_id'] eq '1'", []string{`claims['\u017fub']`, missing}, "unmodelled-construct,unmodelled-construct"},
	}
	for _, c := range cases {
		got, r := evaluated(c.expression, github)
		if got != `{sub=?("required claim missing")}` {
			t.Errorf("evaluate(%q) = %s; nothing outside the documented shape is modelled", c.expression, got)
		}
		constructs := make([]string, len(r.anomalies))
		for i, a := range r.anomalies {
			constructs[i] = a.Construct
		}
		if !slices.Equal(constructs, c.constructs) || joinKinds(r.anomalies) != c.kinds {
			t.Errorf("evaluate(%q): constructs %q of kinds %s, want %q of kinds %s", c.expression, constructs, joinKinds(r.anomalies), c.constructs, c.kinds)
		}
		// Each missing group is its own fact, named in the sentence.
		named := 0
		for _, a := range r.anomalies {
			if a.Construct == missing && (strings.HasPrefix(a.Message, "the expression names no clause on sub;") || strings.HasPrefix(a.Message, "the expression names no clause on repository_id or repository_owner_id;")) {
				named++
			}
		}
		if want := strings.Count(strings.Join(c.constructs, ","), missing); named != want {
			t.Errorf("evaluate(%q): %d missing-claim sentences name their group, want %d", c.expression, named, want)
		}
		if !hasCaveatOn(r.caveats, "sub") {
			t.Errorf("evaluate(%q): sub is Unknown without a caveat", c.expression)
		}
	}
	// A clause on a required claim counts whatever it evaluated to, and the
	// folded spelling is the reading.
	for expression, want := range map[string]string{
		"claims['sub'] EQ 'a' and claims['repository_id'] matches '4*'":                    `{repository_id=?("undocumented operator"), sub=?("undocumented operator")}`,
		"claims['SUB'] eq 'a' and claims['REPOSITORY_OWNER_ID'] eq '1'":                    `{repository_owner_id="1", sub="a"}`,
		"claims['sub'] eq 'a' and claims['sub'] eq 'b' and claims['repository_id'] eq '1'": `{repository_id="1", sub=?("repeated claim")}`,
	} {
		if got, _ := evaluated(expression, github); got != want {
			t.Errorf("evaluate(%q) = %s, want %s", expression, got, want)
		}
	}
	// The shape is Microsoft's rule for GitHub alone; GitLab and Terraform
	// Cloud document sub and nothing else.
	for _, issuer := range []trust.IssuerRef{gitlab, terraform} {
		got, r := evaluated("claims['sub'] matches 'project_path:acme/*'", issuer)
		if got != `{sub=like:"project_path:acme/*"}` || len(r.anomalies) != 0 {
			t.Errorf("%s: evaluate = %s%s", issuer, got, renderAnomalies(r.anomalies))
		}
	}
}

// TestClaimNamesFoldInASCIICaseOnly: ſ (U+017F) and K (U+212A) fold to s
// and k under Unicode case folding, and a fold that wide would read a
// name from another script as a documented claim. The rule is ASCII case,
// which is the only variation a hand typing a documented name produces.
func TestClaimNamesFoldInASCIICaseOnly(t *testing.T) {
	_, r := evaluated("claims['ſub'] eq 'a' and claims['repository_id'] eq '1'", github)
	for _, a := range r.anomalies {
		if a.Kind == "claim-folded" {
			t.Errorf("a homoglyph was folded: %+v", a)
		}
		if strings.ContainsRune(a.Message, 'ſ') || strings.ContainsRune(a.Construct, 'ſ') {
			t.Errorf("a non-ASCII name reached a sentence unescaped: %+v", a)
		}
	}
	if !strings.Contains(r.anomalies[0].Message, `Microsoft does not list claims['\u017fub'] for issuer`) {
		t.Errorf("the undocumented clause is not named with its escaped spelling: %s", r.anomalies[0].Message)
	}
	got, r := evaluated("claims['Key'] eq 'a' and claims['sub'] eq 's' and claims['repository_id'] eq '1'", github)
	if got != "{repository_id=\"1\", sub=\"s\", Key=?(\"undocumented claim\")}" || joinKinds(r.anomalies) != "unmodelled-construct" {
		t.Errorf("Kelvin sign: %s%s", got, renderAnomalies(r.anomalies))
	}
	for name, want := range map[string]string{"SUB": "sub", "Repository_ID": "repository_id", "JOB_WORKFLOW_REF": "job_workflow_ref"} {
		if got := foldedName(t, name); got != want {
			t.Errorf("%q folds to %q, want %q", name, got, want)
		}
	}
	for _, name := range []string{"sub ", "su", "subx", "ſub", "Key", "répository_id"} {
		if got := foldedName(t, name); got != "" {
			t.Errorf("%q folds to %q, want no fold", name, got)
		}
	}
}

// foldedName reports which documented GitHub claim a name folds to, or ""
// when it folds to none, by the claim-folded anomaly the fold records.
func foldedName(t *testing.T, name string) string {
	t.Helper()
	r := &reading{}
	lang, _ := documentedLanguage(github)
	key := r.claimKey(name, lang)
	for _, a := range r.anomalies {
		if a.Kind == "claim-folded" {
			return string(a.Claim)
		}
	}
	if string(key) != name {
		t.Fatalf("claimKey(%q) = %q with no claim-folded anomaly", name, key)
	}
	return ""
}

// TestCaseVariantsOfSubAndAudFoldUnderAnyIssuer: the doubt about a clause
// must sit on the claim a reader asks about. sub and aud are the two claims
// every credential constrains whatever its issuer, so a name that differs
// from either only in ASCII case folds to it even where Microsoft documents
// no claims at all, and even though no issuer's table lists aud.
func TestCaseVariantsOfSubAndAudFoldUnderAnyIssuer(t *testing.T) {
	got, r := evaluated("claims['Sub'] eq 'x'", google)
	if got != `{sub=?("undocumented issuer")}` || joinKinds(r.anomalies) != "claim-folded,unmodelled-construct" || !hasCaveatOn(r.caveats, "sub") {
		t.Errorf("Sub under an undocumented issuer: %s%s caveats %v", got, renderAnomalies(r.anomalies), r.caveats)
	}
	got, r = evaluated("claims['sub'] eq 'a' and claims['AUD'] eq 'other' and claims['repository_id'] eq '1'", github)
	if got != `{aud=?("undocumented claim"), repository_id="1", sub="a"}` || joinKinds(r.anomalies) != "claim-folded,unmodelled-construct" || !hasCaveatOn(r.caveats, "aud") {
		t.Errorf("AUD under GitHub: %s%s caveats %v", got, renderAnomalies(r.anomalies), r.caveats)
	}
	if want := "claims['AUD'] is read as claims['aud']; Microsoft does not say whether claim names are case-sensitive"; r.anomalies[0].Message != want {
		t.Errorf("message %q, want %q", r.anomalies[0].Message, want)
	}
}

// TestClaimNamesInSentencesAreASCII: a claim name reaches a sentence only
// escaped, like every other piece of document text, so that a control
// character written into a lookup cannot rewrite the line that reports it.
func TestClaimNamesInSentencesAreASCII(t *testing.T) {
	for _, expression := range []string{
		"claims['\x1bx'] eq 'a' and claims['sub'] eq 's' and claims['repository_id'] eq '1'",
		"claims['\x1bx'] eq 'a' and claims['\x1bx'] eq 'b' and claims['sub'] eq 's' and claims['repository_id'] eq '1'",
		"claims['\x1bSUB'] eq 'a' and claims['sub'] eq 's' and claims['repository_id'] eq '1'",
	} {
		_, r := evaluated(expression, github)
		if len(r.anomalies) == 0 {
			t.Fatalf("evaluate(%q) recorded nothing", expression)
		}
		for _, a := range r.anomalies {
			if strings.ContainsRune(a.Message, 0x1b) || strings.ContainsRune(a.Construct, 0x1b) {
				t.Errorf("a control character reached a sentence: %+v", a)
			}
			if !strings.Contains(a.Message, `claims['\x1b`) {
				t.Errorf("the lookup is not spelt with its escape: %s", a.Message)
			}
		}
		for _, c := range r.caveats {
			if strings.ContainsRune(c.Reason, 0x1b) {
				t.Errorf("a control character reached a caveat: %+v", c)
			}
		}
	}
	// A name as long as a document is cut like any other quoted text.
	long := strings.Repeat("x", 5000)
	_, r := evaluated("claims['"+long+"'] eq 'a' and claims['sub'] eq 's' and claims['repository_id'] eq '1'", github)
	if a := r.anomalies[0]; len(a.Message) > 800 || !strings.Contains(a.Message, "claims['"+strings.Repeat("x", 200)+"...']") {
		t.Errorf("unbounded lookup in a sentence: %d bytes: %s", len(a.Message), a.Message[:300])
	}
}

func joinKinds(as []trust.Anomaly) string {
	kinds := make([]string, len(as))
	for i, a := range as {
		kinds[i] = a.Kind
	}
	return strings.Join(kinds, ",")
}

func hasCaveatOn(cs []eval.Caveat, k trust.ClaimKey) bool {
	for _, c := range cs {
		if c.Claim == k {
			return true
		}
	}
	return false
}
