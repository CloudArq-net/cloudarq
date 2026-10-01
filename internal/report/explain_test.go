package report

import (
	"encoding/base64"
	"encoding/json"
	"slices"
	"strconv"
	"strings"
	"testing"

	"pgregory.net/rapid"

	"github.com/CloudArq-net/cloudarq/internal/eval"
	"github.com/CloudArq-net/cloudarq/internal/parse/aws"
	"github.com/CloudArq-net/cloudarq/internal/trust"
)

const rejectedToken = `{
  "iss": "https://token.actions.githubusercontent.com",
  "aud": "https://github.com/acme",
  "sub": "repo:acme/infra:ref:refs/heads/main",
  "ref": "refs/heads/main",
  "repository_id": "456789",
  "repository_owner_id": "123456",
  "workflow_ref": "acme/infra/.github/workflows/deploy.yml@refs/heads/main"
}`

func results(o Outcome) map[string]string {
	out := map[string]string{}
	for _, c := range o.Claims {
		out[c.Claim] = c.Result
	}
	return out
}

func TestTheRejectedTokenAgainstTheWholeOrganisation(t *testing.T) {
	e := explanationFor(t, grantCase(t, "03-whole-organisation"), []byte(rejectedToken))
	if e.Token.Claims != 7 || e.Token.Decoded || e.Token.Error != "" {
		t.Fatalf("token = %+v", e.Token)
	}
	o := e.Grants[0]
	if o.Admitted || o.Excludes == nil || o.Excludes.Claim != "aud" || o.Excludes.Constraint != `"sts.amazonaws.com"` {
		t.Errorf("outcome = admitted %v, excludes %+v", o.Admitted, o.Excludes)
	}
	if got := plain(o.Heading); got != "Not admitted: one claim short of grant 1." {
		t.Errorf("heading = %q", got)
	}
	want := "Rejected on aud: the token carries https://github.com/acme; grant 1 admits only sts.amazonaws.com. repository_owner_id and sub satisfy grant 1, iss is grant 1's issuer, and the other 3 claims are not named by it."
	if o.Sentence != want {
		t.Errorf("sentence:\n got %q\nwant %q", o.Sentence, want)
	}
	order := []string{}
	for _, c := range o.Claims {
		order = append(order, c.Claim)
	}
	if !slices.Equal(order, []string{"iss", "aud", "repository_owner_id", "sub", "ref", "repository_id", "workflow_ref"}) {
		t.Errorf("row order = %v", order)
	}
	if r := results(o); r["iss"] != satisfies || r["aud"] != fails || r["sub"] != satisfies || r["ref"] != notNamed {
		t.Errorf("results = %v", r)
	}
	if !slices.Equal(o.Named, []string{"aud", "repository_owner_id", "sub"}) {
		t.Errorf("named = %v", o.Named)
	}
	if o.Claims[0].Written[0].Line != 8 || o.Claims[1].Written[0].Line != 13 {
		t.Errorf("the issuer is written on L8 and aud on L13: %+v %+v", o.Claims[0].Written, o.Claims[1].Written)
	}
}

func TestTheRenamedRepositoryIsNotDecided(t *testing.T) {
	renamed := `{"iss": "https://token.actions.githubusercontent.com", "aud": "sts.amazonaws.com", "sub": "repo:acme/other:ref:refs/heads/main", "repository_id": "456789"}`
	o := explanationFor(t, grantCase(t, "07-expressible-by-one-provider"), []byte(renamed)).Grants[0]
	if !o.Admitted || o.Exact || o.Excludes != nil {
		t.Errorf("outcome = %+v", o)
	}
	if got := plain(o.Heading); got != "Not excluded, and not proven admitted: sub was not evaluated." {
		t.Errorf("heading = %q", got)
	}
	want := "aud and repository_id satisfy grant 1, and iss is grant 1's issuer. sub was not evaluated: ForAllValues:StringLike on sub passes when the claim is absent, so it does not restrict what it looks like it restricts. Whether it excludes the token is not decided here. The token is admitted by the upper bound, not proven admitted by the policy."
	if o.Sentence != want {
		t.Errorf("sentence:\n got %q\nwant %q", o.Sentence, want)
	}
	if r := results(o); r["sub"] != notEvaluated {
		t.Errorf("results = %v", r)
	}
	if !slices.ContainsFunc(o.Spans, func(s Span) bool { return s.Mark == "unknown" && s.Note == 1 }) {
		t.Errorf("the unknown clause refers to note 1: %+v", o.Spans)
	}
}

func TestWhereThePatternParts(t *testing.T) {
	evil := `{"iss": "https://token.actions.githubusercontent.com", "aud": "sts.amazonaws.com", "sub": "repo:acme-evil/infra:ref:refs/heads/main", "repository_owner_id": "123456"}`
	o := explanationFor(t, grantCase(t, "03-whole-organisation"), []byte(evil)).Grants[0]
	want := "the token carries repo:acme-evil/infra:ref:refs/heads/main; grant 1 admits only a subject matching repo:acme/*; after repo:acme the pattern requires / and the token has - there"
	if o.Claims[3].Claim != "sub" || o.Claims[3].Why != want {
		t.Errorf("why = %q", o.Claims[3].Why)
	}
	cases := []struct{ pattern, value, want string }{
		{"repo:acme/infra:*", "repo:acme/other:ref:refs/heads/main", "; after repo:acme/ the pattern requires infra: and the token has other: there"},
		{"repo:acme/*", "repo:ac", "; after repo:ac the pattern requires me/ and the token ends there"},
		{"repo:acme/*", "repo:acme/x", ""},
		{"*x", "y", ""},
		{"répo:*", "rèpo:x", "; after r the pattern requires épo: and the token has èpo: there"},
	}
	for _, c := range cases {
		if got := plain(mismatch(Constraint{Kind: kindLike, Value: c.pattern}, c.value)); got != c.want {
			t.Errorf("%q vs %q: %q, want %q", c.pattern, c.value, got, c.want)
		}
	}
}

func TestTheIssuerIsCheckedBeforeTheClaims(t *testing.T) {
	foreign := `{"iss": "https://gitlab.com", "aud": "sts.amazonaws.com", "sub": "repo:acme/infra:ref:refs/heads/main", "repository_owner_id": "123456"}`
	o := explanationFor(t, grantCase(t, "03-whole-organisation"), []byte(foreign)).Grants[0]
	if o.Admitted || o.Excludes == nil || o.Excludes.Claim != "iss" || results(o)["iss"] != fails {
		t.Errorf("outcome = %+v", o)
	}
	if got := plain(o.Heading); got != "Not admitted: not from grant 1's issuer." {
		t.Errorf("heading = %q", got)
	}
	spelled := `{"iss": "HTTPS://Token.Actions.GitHubUserContent.com/", "aud": "sts.amazonaws.com", "sub": "repo:acme/infra:ref:refs/heads/main", "repository_owner_id": "123456"}`
	if o := explanationFor(t, grantCase(t, "03-whole-organisation"), []byte(spelled)).Grants[0]; !o.Admitted || results(o)["iss"] != satisfies {
		t.Errorf("an issuer spelled in another case is the same issuer: %+v", o)
	}
	absent := `{"aud": "sts.amazonaws.com", "sub": "repo:acme/infra:ref:refs/heads/main", "repository_owner_id": "123456"}`
	if o := explanationFor(t, grantCase(t, "03-whole-organisation"), []byte(absent)).Grants[0]; !o.Admitted || len(o.Claims) != 3 {
		t.Errorf("a token with no iss is read on its claims alone: %+v", o)
	}
}

// TestAnIssuerThatDiffersBeyondASCIIIsNotDecided: an issuer's host is
// compared in ASCII case, and a token whose host differs from the grant's in
// a letter outside ASCII that a case folding may make one, a Kelvin sign
// where the grant has a k, may be from the grant's issuer or not: no AWS
// page says how it compares the two. The iss row is not evaluated, an Allow
// admits the token as an upper bound, and a Deny is not applied, since it
// refuses under one reading and not under the other. A host that differs in
// ASCII case is the grant's issuer, and one that differs in any other way is
// not.
func TestAnIssuerThatDiffersBeyondASCIIIsNotDecided(t *testing.T) {
	const claims = `"aud": "sts.amazonaws.com", "sub": "repo:acme/infra:ref:refs/heads/main", "repository_owner_id": "123456"}`
	kelvin := `{"iss": "https://to\u212aen.actions.githubusercontent.com", ` + claims
	e := explanationFor(t, grantCase(t, "03-whole-organisation"), []byte(kelvin))
	o := e.Grants[0]
	if !o.Admitted || o.Excludes != nil || results(o)["iss"] != notEvaluated || e.Result != notProvenResult {
		t.Errorf("result %q, outcome %+v", e.Result, o)
	}
	if got := plain(o.Heading); got != "Not excluded, and not proven admitted: iss was not evaluated." {
		t.Errorf("heading = %q", got)
	}
	why := "iss was not evaluated: the token was issued by https://to\u212aen.actions.githubusercontent.com; grant 1 admits tokens from token.actions.githubusercontent.com, and the two hosts differ in letters outside ASCII that a case folding may make one; whether AWS reads them as one is not documented. Whether it excludes the token is not decided here."
	if !strings.Contains(o.Sentence, why) {
		t.Errorf("sentence:\n got %q\nwant it to hold %q", o.Sentence, why)
	}
	provider := `{"Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"}`
	deny := []byte(`{"Version": "2012-10-17", "Statement": [` +
		`{"Effect": "Allow", "Principal": ` + provider + `, "Action": "sts:AssumeRoleWithWebIdentity", "Condition": {"StringEquals": {"token.actions.githubusercontent.com:aud": "sts.amazonaws.com"}}}, ` +
		`{"Effect": "Deny", "Principal": ` + provider + `, "Action": "sts:AssumeRoleWithWebIdentity", "Condition": {"StringEquals": {"token.actions.githubusercontent.com:sub": "repo:acme/infra:ref:refs/heads/main"}}}]}`)
	e = explanationFor(t, deny, []byte(kelvin))
	if len(e.Grants) != 2 || e.Result != notProvenResult || e.Grants[1].Admitted || results(e.Grants[1])["iss"] != notEvaluated {
		t.Errorf("a Deny whose issuer is not decided refuses under one reading only: %q, %+v", e.Result, e.Grants)
	}
	for iss, want := range map[string]string{
		"HTTPS://TOKEN.Actions.GitHubUserContent.com":          satisfies,
		"https://tolen.actions.githubusercontent.com":          fails,
		"https://to\u212aen.actions.githubusercontent.com/org": fails,
	} {
		if got := results(explanationFor(t, grantCase(t, "03-whole-organisation"), []byte(`{"iss": "`+iss+`", `+claims)).Grants[0])["iss"]; got != want {
			t.Errorf("%+q: iss %s, want %s", iss, got, want)
		}
	}
}

// TestATokenIsNotPresentedThroughAnotherPrincipal: a web-identity token is
// presented through sts:AssumeRoleWithWebIdentity, and an AWS principal or
// a service assumes a role through sts:AssumeRole, as the engine places
// them: "The Action element describes the specific action or actions that
// will be allowed or denied."
// (https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_action.html).
// So a Deny whose principal is a service or an AWS principal refuses no
// token, and an Allow of such a principal admits none; a SAML provider's
// grant, whose sign-ins come through sts:AssumeRoleWithSAML, neither. Only
// the grant that names no issuer, the face of "*" for every identity, stays
// an upper bound. What names no issuer is no identity provider's token, and
// is read on its claims alone, as the admits view's witness of an AWS
// principal is.
func TestATokenIsNotPresentedThroughAnotherPrincipal(t *testing.T) {
	const allowGitHub = `{"Sid":"DeployFromMain","Effect":"Allow","Principal":{"Federated":"arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"},"Action":"sts:AssumeRoleWithWebIdentity","Condition":{"StringEquals":{"token.actions.githubusercontent.com:aud":"sts.amazonaws.com","token.actions.githubusercontent.com:sub":"repo:acme/infra:ref:refs/heads/main"}}}`
	policy := func(statements ...string) []byte {
		return []byte(`{"Version":"2012-10-17","Statement":[` + strings.Join(statements, ",") + `]}`)
	}
	token := []byte(`{"iss":"https://token.actions.githubusercontent.com","aud":"sts.amazonaws.com","sub":"repo:acme/infra:ref:refs/heads/main"}`)
	account := []byte(`{"aws:principalaccount":"111122223333"}`)
	for _, c := range []struct {
		name   string
		policy []byte
		token  []byte
		result string
		// the outcome of each grant, by issuer, that is not the GitHub Allow
		admitted map[string]bool
	}{
		{"a Deny of a service", policy(allowGitHub, `{"Sid":"NoEC2","Effect":"Deny","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}`), token, "admitted", map[string]bool{"aws:service:ec2.amazonaws.com": false}},
		{"a Deny of every AWS principal", policy(allowGitHub, `{"Sid":"NoAWS","Effect":"Deny","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}`), token, "admitted", map[string]bool{"aws:sts": false, "": false}},
		{"an Allow of every AWS principal", policy(`{"Sid":"AnyAWS","Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}`), token, "not proven", map[string]bool{"aws:sts": false, "": true}},
		{"an Allow of an account", policy(`{"Sid":"Partner","Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111122223333:root"},"Action":"sts:AssumeRole"}`), token, "not admitted", map[string]bool{"aws:sts": false}},
		{"an Allow of a SAML provider", policy(`{"Sid":"Corp","Effect":"Allow","Principal":{"Federated":"arn:aws:iam::123456789012:saml-provider/CorpIdP"},"Action":"sts:AssumeRoleWithSAML"}`), token, "not admitted", map[string]bool{"arn:aws:iam::123456789012:saml-provider/CorpIdP": false}},
		{"an Allow of an account, for its own claims", policy(`{"Sid":"Partner","Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111122223333:root"},"Action":"sts:AssumeRole"}`), account, "admitted", map[string]bool{"aws:sts": true}},
	} {
		e := explanationFor(t, c.policy, c.token)
		if e.Result != c.result {
			t.Errorf("%s: result %q, want %q: %s", c.name, e.Result, c.result, plain(e.Heading))
		}
		checked := 0
		for _, o := range e.Grants {
			want, named := c.admitted[o.Issuer]
			if !named {
				continue
			}
			checked++
			if o.Admitted != want {
				t.Errorf("%s: grant %d of %q admitted %v, want %v: %s %s", c.name, o.Number, o.Issuer, o.Admitted, want, plain(o.Heading), o.Sentence)
			}
			if !want && o.Issuer != "" && (o.Excludes == nil || o.Excludes.Claim != "iss" || results(o)["iss"] != fails || !strings.Contains(o.Sentence, "presented through sts:AssumeRoleWithWebIdentity")) {
				t.Errorf("%s: grant %d of %q is not refused its token on iss: %+v", c.name, o.Number, o.Issuer, o)
			}
		}
		if checked != len(c.admitted) {
			t.Errorf("%s: %d grants checked, %d expected", c.name, checked, len(c.admitted))
		}
	}
}

// TestAKeyNoTokenIsKnownToCarryIsNotDecided: AWS's Google tab writes the
// claim it reads google/organization_number from as
// google:organization_number, and Google's reference prints the number
// inside a google claim; no page says which of the two AWS reads, so the
// census records the key with AWS's spelling and no claim. A token is then
// neither admitted nor rejected on the key, the sentence names the spelling
// AWS's table writes, and the grant has no witness, which would have to
// carry the number in some claim.
func TestAKeyNoTokenIsKnownToCarryIsNotDecided(t *testing.T) {
	policy := []byte(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Federated":"accounts.google.com"},"Action":"sts:AssumeRoleWithWebIdentity","Condition":{"StringEquals":{"accounts.google.com:aud":"my-client-id","accounts.google.com:google/organization_number":"123456"}}}]}`)
	for _, token := range []string{
		`{"iss":"https://accounts.google.com","aud":"my-client-id","sub":"1","google":{"organization_number":123456}}`,
		`{"iss":"https://accounts.google.com","aud":"my-client-id","sub":"1","google:organization_number":"123456"}`,
		`{"iss":"https://accounts.google.com","aud":"my-client-id","sub":"1"}`,
	} {
		e := explanationFor(t, policy, []byte(token))
		o := e.Grants[0]
		var row ClaimOutcome
		for _, c := range o.Claims {
			if c.Claim == "google/organization_number" {
				row = c
			}
		}
		want := `AWS reads google/organization_number from what its table writes as "google:organization_number", which names no claim a token is known to carry, so what this token carries for it is not known`
		if e.Result != notProvenResult || row.Result != notEvaluated || row.Why != want {
			t.Errorf("%s: result %q, row %+v; want not proven, and the row not evaluated because\n %s", token, e.Result, row, want)
		}
	}
	if a := answerFor(t, policy); a.Grants[0].Witness != "" {
		t.Errorf("the grant's witness carries the key in a claim no token is known to carry: %s", a.Grants[0].Witness)
	}
}

// TestAClaimThatIsNotAStringIsNotDecided: AWS documents string conditions
// as comparing a key to a string, and no rule for what one compares when the
// token's claim is a list, an object, a number or a boolean. Its own post on
// IAM roles for service accounts shows a trust policy with StringEquals on
// aud "sts.amazonaws.com" allowing a pod whose token carries
// "aud": [ "sts.amazonaws.com" ]
// (https://aws.amazon.com/blogs/containers/diving-into-iam-roles-for-service-accounts/),
// so reading the list as its JSON text and rejecting the token is a guess
// AWS's own example refutes. Such a claim is not evaluated: an Allow admits
// the token only as not proven, and a Deny may refuse it. The census records
// that a cluster's tokens may carry several audiences, so that example's
// condition on aud is itself not evaluated, whatever the token carries; the
// rule is held here on GitHub's aud, which the census records no such
// sentence for, and a token with aud as a string is admitted.
func TestAClaimThatIsNotAStringIsNotDecided(t *testing.T) {
	irsa := []byte(`{ "Version": "2012-10-17", "Statement": [ { "Effect": "Allow", "Principal": { "Federated": "arn:aws:iam::111122223333:oidc-provider/oidc.eks.us-east-2.amazonaws.com/id/xxxx" }, "Action": "sts:AssumeRoleWithWebIdentity", "Condition": { "StringEquals": { "oidc.eks.us-east-2.amazonaws.com/id/xxxx:aud": "sts.amazonaws.com", "oidc.eks.us-east-2.amazonaws.com/id/xxxx:sub": "system:serviceaccount:default:my-sa" } } } ] }`)
	pod := func(aud string) []byte {
		return []byte(`{ "aud": ` + aud + `, "exp": "2022-02-19T16:43:55+00:00", "iat": "2022-02-18T16:43:55+00:00", "iss": "https://oidc.eks.us-east-2.amazonaws.com/id/xxxx", "kubernetes.io": { "namespace": "default", "pod": { "name": "eks-iam-test3", "uid": "6fd2f65f-4554-4317-9343-c8e5d28029c3" }, "serviceaccount": { "name": "my-sa", "uid": "2c935d89-3ff0-425d-85c2-8236a6d626aa" } }, "nbf": "2022-02-18T16:43:55+00:00", "sub": "system:serviceaccount:default:my-sa" }`)
	}
	const several = "may carry several values in the claim AWS reads the condition key"
	for _, aud := range []string{`"sts.amazonaws.com"`, `[ "sts.amazonaws.com" ]`, `["other"]`} {
		e := explanationFor(t, irsa, pod(aud))
		o := e.Grants[0]
		if e.Result != notProvenResult || !o.Admitted || o.Excludes != nil || results(o)["aud"] != notEvaluated || !strings.Contains(o.Sentence, several) {
			t.Errorf("a cluster's aud %s: result %q, outcome %s / %s; want not proven, aud not evaluated because a token %s", aud, e.Result, plain(o.Heading), o.Sentence, several)
		}
	}
	workflow := []byte(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Federated":"arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"},"Action":"sts:AssumeRoleWithWebIdentity","Condition":{"StringEquals":{"token.actions.githubusercontent.com:aud":"sts.amazonaws.com","token.actions.githubusercontent.com:sub":"repo:acme/infra:ref:refs/heads/main"}}}]}`)
	run := func(aud string) []byte {
		return []byte(`{"aud": ` + aud + `, "iss": "https://token.actions.githubusercontent.com", "sub": "repo:acme/infra:ref:refs/heads/main", "repository": "acme/infra"}`)
	}
	if e := explanationFor(t, workflow, run(`"sts.amazonaws.com"`)); e.Result != admittedResult {
		t.Errorf("aud as a string: result %q, want admitted: %s", e.Result, plain(e.Heading))
	}
	for aud, shape := range map[string]string{
		`[ "sts.amazonaws.com" ]`:        "a list",
		`["other", "sts.amazonaws.com"]`: "a list",
		`["other"]`:                      "a list",
		`{"sts.amazonaws.com": true}`:    "an object",
		`12`:                             "a number",
		`true`:                           "a boolean",
	} {
		e := explanationFor(t, workflow, run(aud))
		o := e.Grants[0]
		why := "the token carries aud as " + shape + ", not a string, and AWS documents no rule for what a string condition compares in such a claim, so what AWS reads for aud is not known"
		if e.Result != notProvenResult || !o.Admitted || o.Excludes != nil || results(o)["aud"] != notEvaluated || !strings.Contains(o.Sentence, "aud was not evaluated: "+why+". ") {
			t.Errorf("aud %s: result %q, outcome %s / %s; want not proven, aud not evaluated because\n %s", aud, e.Result, plain(o.Heading), o.Sentence, why)
		}
	}
	// A Deny on a claim the token carries as a list may refuse it: Cognito
	// documents amr as a list, and a guest's holds unauthenticated.
	deny := []byte(`{"Version":"2012-10-17","Statement":[
{"Sid":"PoolIdentities","Effect":"Allow","Principal":{"Federated":"cognito-identity.amazonaws.com"},"Action":"sts:AssumeRoleWithWebIdentity","Condition":{"StringEquals":{"cognito-identity.amazonaws.com:aud":"us-east-1:12345678-1234-1234-1234-123456789012"}}},
{"Sid":"NoGuests","Effect":"Deny","Principal":{"Federated":"cognito-identity.amazonaws.com"},"Action":"sts:AssumeRoleWithWebIdentity","Condition":{"StringEquals":{"cognito-identity.amazonaws.com:amr":"unauthenticated"}}}]}`)
	guest := []byte(`{"iss":"https://cognito-identity.amazonaws.com","aud":"us-east-1:12345678-1234-1234-1234-123456789012","sub":"us-east-1:aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee","amr":["unauthenticated"]}`)
	if e := explanationFor(t, deny, guest); e.Result != notProvenResult || plain(e.Heading) != "Not excluded, and not proven admitted: grant 1 admits it, and grant 2 may refuse it." {
		t.Errorf("a guest against a Deny on amr: result %q, heading %q", e.Result, plain(e.Heading))
	}
}

// TestADenyNotAppliedMayRefuse: a Deny the parser could not fully evaluate
// is not applied, which keeps what the policy admits an upper bound, and a
// token it may name is then not proven admitted: "An explicit deny in either
// of these policies overrides the allow."
// (https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html).
// The guard that refuses every repository but the organisation's, written
// with StringNotLike, and a Deny of every principal on the web-identity
// action, both refuse the token AWS evaluates here; the explanation says the
// Deny was not applied and may refuse it. A Deny whose issuer the token's
// rules out refuses nothing, applied or not.
func TestADenyNotAppliedMayRefuse(t *testing.T) {
	const provider = `{"Federated":"arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"}`
	policy := func(statements ...string) []byte {
		return []byte(`{"Version":"2012-10-17","Statement":[` + strings.Join(statements, ",") + `]}`)
	}
	anyRepo := `{"Sid":"AnyRepo","Effect":"Allow","Principal":` + provider + `,"Action":"sts:AssumeRoleWithWebIdentity","Condition":{"StringEquals":{"token.actions.githubusercontent.com:aud":"sts.amazonaws.com"},"StringLike":{"token.actions.githubusercontent.com:sub":"repo:*"}}}`
	main := `{"Sid":"DeployFromMain","Effect":"Allow","Principal":` + provider + `,"Action":"sts:AssumeRoleWithWebIdentity","Condition":{"StringEquals":{"token.actions.githubusercontent.com:aud":"sts.amazonaws.com","token.actions.githubusercontent.com:sub":"repo:acme/infra:ref:refs/heads/main"}}}`
	token := func(sub string) []byte {
		return []byte(`{"iss":"https://token.actions.githubusercontent.com","aud":"sts.amazonaws.com","sub":"` + sub + `"}`)
	}
	for _, c := range []struct {
		name          string
		policy, token []byte
		deny          int
		heading       string
	}{
		{"a guard written with StringNotLike", policy(anyRepo, `{"Sid":"OnlyAcme","Effect":"Deny","Principal":`+provider+`,"Action":"sts:AssumeRoleWithWebIdentity","Condition":{"StringNotLike":{"token.actions.githubusercontent.com:sub":"repo:acme/*"}}}`),
			token("repo:evil/x:ref:refs/heads/main"), 2, "Not excluded, and not proven admitted: grant 1 admits it, and grant 2 may refuse it."},
		{"a Deny of every principal", policy(main, `{"Sid":"DenyAllWebIdentity","Effect":"Deny","Principal":"*","Action":"sts:AssumeRoleWithWebIdentity"}`),
			token("repo:acme/infra:ref:refs/heads/main"), 1, "Not excluded, and not proven admitted: grant 3 admits it, and grant 1 may refuse it."},
		{"a guard written with StringNotEquals", policy(main, `{"Sid":"OnlyMain","Effect":"Deny","Principal":`+provider+`,"Action":"sts:AssumeRoleWithWebIdentity","Condition":{"StringNotEquals":{"token.actions.githubusercontent.com:sub":"repo:acme/infra:ref:refs/heads/main"}}}`),
			token("repo:acme/infra:ref:refs/heads/main"), 2, "Not excluded, and not proven admitted: grant 1 admits it, and grant 2 may refuse it."},
	} {
		e := explanationFor(t, c.policy, c.token)
		if e.Result != notProvenResult || plain(e.Heading) != c.heading {
			t.Errorf("%s: result %q, heading %q; want not proven, %q", c.name, e.Result, plain(e.Heading), c.heading)
		}
		o := e.Grants[c.deny-1]
		if o.Effect != "Deny" || o.Exact || plain(o.Heading) != "Not excluded, and not proven refused: grant "+strconv.Itoa(c.deny)+" could not be fully evaluated, so it is not applied." {
			t.Errorf("%s: grant %d is %s, exact %v, heading %q", c.name, c.deny, o.Effect, o.Exact, plain(o.Heading))
		}
		if !strings.Contains(strings.ToLower(e.Sentence), "grant "+strconv.Itoa(c.deny)+" may refuse it") {
			t.Errorf("%s: sentence %q", c.name, e.Sentence)
		}
	}
	// a token from another issuer is one the Deny does not name
	gitlab := []byte(`{"iss":"https://gitlab.com","sub":"project_path:acme/infra"}`)
	guard := policy(anyRepo, `{"Sid":"OnlyAcme","Effect":"Deny","Principal":`+provider+`,"Action":"sts:AssumeRoleWithWebIdentity","Condition":{"StringNotLike":{"token.actions.githubusercontent.com:sub":"repo:acme/*"}}}`)
	if e := explanationFor(t, guard, gitlab); e.Result != notAdmittedResult || strings.Contains(e.Sentence, "may refuse") {
		t.Errorf("a token of another issuer: result %q, %q", e.Result, e.Sentence)
	}
}

// TestAPlainConditionOnAMultivaluedKeyDecidesNothing: AWS documents amr as
// multivalued, "meaning that you test it in a policy using condition set
// operators", and does not say what an operator without a set prefix does
// on it (https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_iam-condition-keys.html).
// Cognito says that an authenticated user's amr holds authenticated and "any
// providers used during authentication"
// (https://docs.aws.amazon.com/cognito/latest/developerguide/iam-roles.html),
// and Microsoft that "The amr claim is an array that can contain multiple
// items". A role naming two values one user carries, under two operators
// without a set prefix, is not read as admitting nobody; no token is
// admitted or refused on such a condition; and a Deny so written is not
// applied, so it may refuse any token of its issuer.
func TestAPlainConditionOnAMultivaluedKeyDecidesNothing(t *testing.T) {
	const pool = "us-east-1:12345678-1234-1234-1234-123456789012"
	const tenant = "login.microsoftonline.com/ffffffff-eeee-dddd-cccc-bbbbbbbbbbb0/v2.0"
	facebook := []byte(`{"Version":"2012-10-17","Statement":[{"Sid":"PoolSignedInThroughFacebook","Effect":"Allow","Principal":{"Federated":"cognito-identity.amazonaws.com"},"Action":"sts:AssumeRoleWithWebIdentity","Condition":{"StringEquals":{"cognito-identity.amazonaws.com:aud":"` + pool + `","cognito-identity.amazonaws.com:amr":"authenticated"},"StringLike":{"cognito-identity.amazonaws.com:amr":"graph.facebook.com"}}}]}`)
	entra := []byte(`{"Version":"2012-10-17","Statement":[{"Sid":"WorkforceWithMFA","Effect":"Allow","Principal":{"Federated":"arn:aws:iam::123456789012:oidc-provider/` + tenant + `"},"Action":"sts:AssumeRoleWithWebIdentity","Condition":{"StringEquals":{"` + tenant + `:aud":"api://acme-aws","` + tenant + `:amr":"mfa"},"StringLike":{"` + tenant + `:amr":"pwd"}}}]}`)
	noGuests := []byte(`{"Version":"2012-10-17","Statement":[
{"Sid":"PoolIdentities","Effect":"Allow","Principal":{"Federated":"cognito-identity.amazonaws.com"},"Action":"sts:AssumeRoleWithWebIdentity","Condition":{"StringEquals":{"cognito-identity.amazonaws.com:aud":"` + pool + `"}}},
{"Sid":"NoGuests","Effect":"Deny","Principal":{"Federated":"cognito-identity.amazonaws.com"},"Action":"sts:AssumeRoleWithWebIdentity","Condition":{"StringEquals":{"cognito-identity.amazonaws.com:amr":"unauthenticated"}}}]}`)
	cognitoToken := func(amr string) []byte {
		return []byte(`{"iss":"https://cognito-identity.amazonaws.com","aud":"` + pool + `","sub":"us-east-1:aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee","amr":` + amr + `}`)
	}
	multivalued := func(key string) func(Note) bool {
		return func(n Note) bool {
			return n.Claim == "amr" && n.Construct == key && strings.Contains(n.Message, "as multivalued")
		}
	}
	for _, c := range []struct {
		name, key, headline, place string
		policy                     []byte
	}{
		{"a Facebook user's two values", "cognito-identity.amazonaws.com:amr", "Anyone could assume this role.", "anyone", facebook},
		{"a password and a second factor", tenant + ":amr", "Anyone on login.microsoftonline.com could assume this role.", "platform", entra},
	} {
		a := ringsOf(t, Admits(c.policy))
		if a.Headline == nil || a.Headline.Sentence != c.headline || len(a.Grants) != 1 || a.Grants[0].Empty || !slices.Equal(a.Grants[0].Placement, []string{c.place}) || a.Grants[0].PlacementState != "unknown" {
			t.Errorf("%s: headline %+v, grants %+v", c.name, a.Headline, a.Grants)
		}
		if g := answerFor(t, c.policy).Grants; len(g) != 1 || g[0].Exact || !slices.ContainsFunc(g[0].Notes, multivalued(c.key)) {
			t.Errorf("%s: %+v", c.name, g)
		}
	}
	// aud is satisfied, and amr is not compared, whatever it holds
	for _, amr := range []string{`["authenticated","graph.facebook.com"]`, `"authenticated"`} {
		if e := explanationFor(t, facebook, cognitoToken(amr)); e.Result != notProvenResult || e.Grants[0].Excludes != nil {
			t.Errorf("amr %s against the Facebook role: result %q, %q", amr, e.Result, plain(e.Heading))
		}
	}
	// A claim the token carries as a list is not compared, for a reason of
	// its own, so the tokens that carry amr as a string are the ones that
	// show the key's reading.
	if g := answerFor(t, noGuests).Grants; len(g) != 2 || g[1].Effect != "Deny" || g[1].Exact || !slices.ContainsFunc(g[1].Notes, multivalued("cognito-identity.amazonaws.com:amr")) {
		t.Errorf("a Deny on amr: %+v", g)
	}
	for _, amr := range []string{`["unauthenticated"]`, `"unauthenticated"`, `"authenticated"`} {
		e := explanationFor(t, noGuests, cognitoToken(amr))
		if e.Result != notProvenResult || plain(e.Heading) != "Not excluded, and not proven admitted: grant 1 admits it, and grant 2 may refuse it." {
			t.Errorf("amr %s against a Deny on amr: result %q, heading %q", amr, e.Result, plain(e.Heading))
		}
		if o := e.Grants[1]; o.Effect != "Deny" || o.Exact || plain(o.Heading) != "Not excluded, and not proven refused: grant 2 could not be fully evaluated, so it is not applied." {
			t.Errorf("amr %s: grant 2 is %s, exact %v, heading %q", amr, o.Effect, o.Exact, plain(o.Heading))
		}
	}
}

// TestAConditionOnAClaimOfSeveralValuesDecidesNothing: RFC 7519 says that in
// the general case aud is an array, and the census records, on each vendor's
// sentences, the issuers whose tokens may carry several audiences: a
// Kubernetes service account token "May be repeated to request a token valid
// for multiple audiences", AWS's GetWebIdentityToken takes up to ten, and a
// Bitbucket pipeline declares a list. AWS does not say how many values its
// aud and oaud keys hold, nor what an operator without a set prefix compares
// on a claim holding several. A role naming two audiences one token carries,
// under two such operators, on aud or on oaud, which AWS reads from aud, is
// not read as admitting nobody, and a token carrying both is not refused on
// them. Where no sentence says an issuer's tokens carry several audiences, as
// for GitHub's, a condition on aud is compared as before.
func TestAConditionOnAClaimOfSeveralValuesDecidesNothing(t *testing.T) {
	const cluster = "oidc.eks.us-east-2.amazonaws.com/id/EXAMPLED539D4633E53DE1B71EXAMPLE"
	const outbound = "12345678-90ab-cdef-1234-567890abcdef.tokens.sts.global.api.aws"
	const workspace = "api.bitbucket.org/2.0/workspaces/acme/pipelines-config/identity/oidc"
	role := func(sid, provider, conditions string) []byte {
		return []byte(`{"Version":"2012-10-17","Statement":[{"Sid":"` + sid + `","Effect":"Allow","Principal":{"Federated":"arn:aws:iam::111122223333:oidc-provider/` + provider + `"},"Action":"sts:AssumeRoleWithWebIdentity","Condition":` + conditions + `}]}`)
	}
	eks := role("PodWithTwoAudiences", cluster, `{"StringEquals":{"`+cluster+`:aud":"sts.amazonaws.com"},"StringLike":{"`+cluster+`:aud":"vault*"}}`)
	for _, c := range []struct {
		name, claim, key string
		policy           []byte
	}{
		{"a cluster's aud named twice", "aud", cluster + ":aud", eks},
		{"AWS's outbound aud named twice", "aud", outbound + ":aud", role("OutboundTokenForTwoAudiences", outbound, `{"StringEquals":{"`+outbound+`:aud":"https://api.example.com","`+outbound+`:sub":"arn:aws:iam::444455556666:role/Caller"},"StringLike":{"`+outbound+`:aud":"sts.amazonaws.com"}}`)},
		{"a pipeline's aud named twice", "aud", workspace + ":aud", role("PipelineWithTwoAudiences", workspace, `{"StringEquals":{"`+workspace+`:aud":"ari:cloud:bitbucket::workspace/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"},"StringLike":{"`+workspace+`:aud":"api://vault*"}}`)},
		{"a cluster's oaud named twice", "oaud", cluster + ":oaud", role("PodOaudTwice", cluster, `{"StringEquals":{"`+cluster+`:oaud":"sts.amazonaws.com"},"StringLike":{"`+cluster+`:oaud":"vault*"}}`)},
	} {
		a := ringsOf(t, Admits(c.policy))
		if a.Headline == nil || a.Headline.Sentence == "Nothing outside your company can assume this role." || len(a.Grants) != 1 || a.Grants[0].Empty || slices.Contains(a.Grants[0].Placement, "nobody") {
			t.Errorf("%s: headline %+v, grants %+v", c.name, a.Headline, a.Grants)
		}
		g := answerFor(t, c.policy).Grants
		if len(g) != 1 || g[0].Exact || g[0].Empty || !slices.ContainsFunc(g[0].Notes, func(n Note) bool {
			return n.Claim == c.claim && n.Construct == c.key && strings.Contains(n.Message, "may carry several values")
		}) {
			t.Errorf("%s: %+v", c.name, g)
		}
	}
	both := []byte(`{"aud":["sts.amazonaws.com","vault"],"iss":"https://` + cluster + `","sub":"system:serviceaccount:default:my-sa"}`)
	if e := explanationFor(t, eks, both); e.Result != notProvenResult || e.Grants[0].Excludes != nil {
		t.Errorf("a token carrying both audiences: result %q, %q, excludes %+v", e.Result, plain(e.Heading), e.Grants[0].Excludes)
	}
	github := []byte(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Federated":"arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"},"Action":"sts:AssumeRoleWithWebIdentity","Condition":{"StringEquals":{"token.actions.githubusercontent.com:aud":"sts.amazonaws.com","token.actions.githubusercontent.com:sub":"repo:acme/infra:ref:refs/heads/main"}}}]}`)
	if g := answerFor(t, github).Grants; len(g) != 1 || !g[0].Exact || g[0].Admits != `{aud="sts.amazonaws.com", sub="repo:acme/infra:ref:refs/heads/main"}` {
		t.Errorf("GitHub's aud, which no sentence says carries several values: %+v", g)
	}
}

// TestADenyNotAppliedNamesItsClaims: the parser keeps no term for a Deny it
// could not fully evaluate, and the token view still lists every claim that
// Deny's conditions name, each not evaluated, since no constraint of a Deny
// not applied is compared with the token, and each with the note that kept
// it from being read where the grant carries one. A claim the Deny does not
// name is not named by it; a row saying so of a claim its statement names
// would contradict the statement, and leave the reader with no word on why
// the Deny was not applied.
func TestADenyNotAppliedNamesItsClaims(t *testing.T) {
	const pool = "us-east-1:12345678-1234-1234-1234-123456789012"
	const cognito = `{"Federated":"cognito-identity.amazonaws.com"}`
	const github = `{"Federated":"arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"}`
	allowPool := `{"Sid":"PoolIdentities","Effect":"Allow","Principal":` + cognito + `,"Action":"sts:AssumeRoleWithWebIdentity","Condition":{"StringEquals":{"cognito-identity.amazonaws.com:aud":"` + pool + `"}}}`
	policy := func(statements ...string) []byte {
		return []byte(`{"Version":"2012-10-17","Statement":[` + strings.Join(statements, ",") + `]}`)
	}
	noGuests := policy(allowPool, `{"Sid":"NoGuests","Effect":"Deny","Principal":`+cognito+`,"Action":"sts:AssumeRoleWithWebIdentity","Condition":{"StringEquals":{"cognito-identity.amazonaws.com:amr":"unauthenticated"}}}`)
	noGuestOfOne := policy(allowPool, `{"Sid":"NoGuestOfOne","Effect":"Deny","Principal":`+cognito+`,"Action":"sts:AssumeRoleWithWebIdentity","Condition":{"StringEquals":{"cognito-identity.amazonaws.com:sub":"us-east-1:aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee","cognito-identity.amazonaws.com:amr":"unauthenticated"}}}`)
	onlyAcme := policy(`{"Sid":"AnyRepo","Effect":"Allow","Principal":`+github+`,"Action":"sts:AssumeRoleWithWebIdentity","Condition":{"StringLike":{"token.actions.githubusercontent.com:sub":"repo:*"}}}`,
		`{"Sid":"OnlyAcme","Effect":"Deny","Principal":`+github+`,"Action":"sts:AssumeRoleWithWebIdentity","Condition":{"StringNotLike":{"token.actions.githubusercontent.com:sub":"repo:acme/*"}}}`)
	everyone := policy(allowPool, `{"Sid":"DenyAllWebIdentity","Effect":"Deny","Principal":"*","Action":"sts:AssumeRoleWithWebIdentity"}`)
	guest := []byte(`{"iss":"https://cognito-identity.amazonaws.com","aud":"` + pool + `","sub":"us-east-1:aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee","amr":"unauthenticated"}`)
	withoutAmr := []byte(`{"iss":"https://cognito-identity.amazonaws.com","aud":"` + pool + `","sub":"us-east-1:aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"}`)
	evil := []byte(`{"iss":"https://token.actions.githubusercontent.com","aud":"sts.amazonaws.com","sub":"repo:evil/x:ref:refs/heads/main"}`)
	// noteSaying is the number of the grant's caveat on claim whose sentence
	// holds text, or 0.
	noteSaying := func(notes []Note, claim, text string) int {
		for _, n := range notes {
			if n.Kind == "caveat" && n.Claim == claim && strings.Contains(n.Message, text) {
				return n.Number
			}
		}
		return 0
	}
	for _, c := range []struct {
		name          string
		policy, token []byte
		deny          int
		// named are the claims the Deny names, each with the claim its
		// note is filed under and a phrase of the note's sentence; an
		// empty phrase is the note that says the Deny was not applied.
		named    map[string][2]string
		notNamed []string
		reason   string
	}{
		{"a Deny on amr", noGuests, guest, 2,
			map[string][2]string{"amr": {"amr", "as multivalued"}}, []string{"aud", "sub"},
			"amr was not evaluated: StringEquals on amr has no set prefix, and AWS documents the condition key"},
		{"a Deny on amr, for a token without amr", noGuests, withoutAmr, 2,
			map[string][2]string{"amr": {"amr", "as multivalued"}}, []string{"aud", "sub"},
			"amr was not evaluated: StringEquals on amr has no set prefix"},
		{"a Deny on amr beside an exact sub", noGuestOfOne, guest, 2,
			map[string][2]string{"amr": {"amr", "as multivalued"}, "sub": {"", "could not be fully evaluated"}}, []string{"aud"},
			"amr was not evaluated: StringEquals on amr has no set prefix"},
		{"a guard written with StringNotLike", onlyAcme, evil, 2,
			map[string][2]string{"sub": {"sub", "does not model complements"}}, []string{"aud"},
			"sub was not evaluated: StringNotLike on sub admits every value but the ones listed"},
	} {
		e := explanationFor(t, c.policy, c.token)
		o := e.Grants[c.deny-1]
		if o.Effect != "Deny" || o.Exact || plain(o.Heading) != "Not excluded, and not proven refused: grant "+strconv.Itoa(c.deny)+" could not be fully evaluated, so it is not applied." {
			t.Errorf("%s: grant %d is %s, exact %v, heading %q", c.name, c.deny, o.Effect, o.Exact, plain(o.Heading))
			continue
		}
		g := answerFor(t, c.policy).Grants[c.deny-1]
		rows := map[string]ClaimOutcome{}
		for _, row := range o.Claims {
			rows[row.Claim] = row
		}
		for claim, note := range c.named {
			row, listed := rows[claim]
			want := noteSaying(g.Notes, note[0], note[1])
			switch {
			case !listed:
				t.Errorf("%s: no row for %s, which the Deny names: %+v", c.name, claim, o.Claims)
			case row.Result != notEvaluated || row.Constraint.Kind != kindUnknown || row.Mark != "unknown":
				t.Errorf("%s: %s is %q, %+v, marked %q; want not evaluated", c.name, claim, row.Result, row.Constraint, row.Mark)
			case want == 0 || row.Note != want:
				t.Errorf("%s: %s refers to note %d; want %d, the caveat on %q saying %q, of %+v", c.name, claim, row.Note, want, note[0], note[1], g.Notes)
			case len(row.Written) == 0:
				t.Errorf("%s: %s is written in the Deny's statement, and its row says nowhere", c.name, claim)
			}
		}
		for _, claim := range c.notNamed {
			if row := rows[claim]; row.Result != notNamed {
				t.Errorf("%s: %s, which the Deny does not name, is %q", c.name, claim, row.Result)
			}
		}
		if !strings.Contains(o.Sentence, c.reason) {
			t.Errorf("%s: the sentence does not say why the Deny was not applied:\n got %q\nwant it to hold %q", c.name, o.Sentence, c.reason)
		}
	}
	// A Deny that names no claim leaves every claim of the token not named.
	if o := explanationFor(t, everyone, guest).Grants[0]; o.Effect != "Deny" || slices.ContainsFunc(o.Claims, func(row ClaimOutcome) bool {
		return row.Claim != "iss" && row.Result != notNamed
	}) {
		t.Errorf("a Deny that names no claim: %s, %+v", o.Effect, o.Claims)
	}
}

func TestTheBeyondGrantSaysSoForTheToken(t *testing.T) {
	evil := `{"iss": "https://token.actions.githubusercontent.com", "aud": "sts.amazonaws.com", "sub": "repo:acme-evil/infra:ref:refs/heads/main"}`
	o := explanationFor(t, grantCase(t, "06-unconstrained"), []byte(evil)).Grants[0]
	want := "Every claim grant 1 names is satisfied: aud. No claim but aud is named, so any identity the issuer signs for passes."
	if !o.Admitted || o.Sentence != want {
		t.Errorf("outcome = admitted %v, %q", o.Admitted, o.Sentence)
	}
	if sub := o.Claims[2]; sub.Claim != "sub" || sub.Result != notNamed || sub.Mark != "beyond" {
		t.Errorf("sub row = %+v", sub)
	}
}

func TestATokenIsReadAsPayloadOrWhole(t *testing.T) {
	payload := `{"iss":"https://token.actions.githubusercontent.com","aud":"sts.amazonaws.com","sub":"repo:acme/infra:ref:refs/heads/main","repository_owner_id":"123456","iat":1700000000,"nested":{"a":[1, 2]},"flag":true}`
	segment := func(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }
	whole := segment(`{"alg":"RS256","kid":"x"}`) + "." + segment(payload) + ".c2ln"
	for _, text := range []string{payload, whole, "  " + whole + "\n"} {
		tok, err := readToken([]byte(text))
		if err != nil {
			t.Fatalf("%q: %v", text, err)
		}
		if tok.decoded != strings.Contains(text, ".c2ln") {
			t.Errorf("decoded = %v for %q", tok.decoded, text)
		}
		if !slices.Equal(tok.order, []string{"iss", "aud", "sub", "repository_owner_id", "iat", "nested", "flag"}) {
			t.Errorf("order = %v", tok.order)
		}
		if tok.values["iat"] != "1700000000" || tok.values["nested"] != `{"a":[1,2]}` || tok.values["flag"] != "true" {
			t.Errorf("values = %v", tok.values)
		}
	}
	e := explanationFor(t, grantCase(t, "03-whole-organisation"), []byte(whole))
	if !e.Token.Decoded || e.Token.Claims != 7 || !e.Grants[0].Admitted {
		t.Errorf("a whole token: %+v", e.Token)
	}
	for _, bad := range []string{"", "[1]", `"x"`, `{"a": 1} x`, "a.b.c", "not json"} {
		if e := explanationFor(t, grantCase(t, "03-whole-organisation"), []byte(bad)); e.Token.Error == "" || len(e.Grants) != 0 {
			t.Errorf("%q read as a token: %+v", bad, e)
		}
	}
	dup, err := readToken([]byte(`{"a": "1", "a": "2"}`))
	if err != nil || dup.values["a"] != "2" || len(dup.order) != 1 {
		t.Errorf("a claim written twice: %+v, %v", dup, err)
	}
}

func TestEmptyAndWidenedGrantsForTheToken(t *testing.T) {
	raw := []byte(`{"Version":"2012-10-17","Statement":[
	  {"Sid":"Nobody","Effect":"Allow","Principal":{"Federated":"token.actions.githubusercontent.com"},"Action":"sts:AssumeRole"},
	  {"Sid":"NotKnown","Effect":"Allow","Principal":{"Federated":"token.actions.githubusercontent.com"},"NotAction":"s3:*"}]}`)
	e := explanationFor(t, raw, []byte(`{"iss":"https://token.actions.githubusercontent.com","sub":"x"}`))
	if len(e.Grants) != 2 {
		t.Fatalf("%d outcomes", len(e.Grants))
	}
	for _, o := range e.Grants {
		switch o.Sid {
		case "Nobody":
			if o.Admitted || plain(o.Heading) != "Not admitted: grant "+string(rune('0'+o.Number))+" admits nobody." {
				t.Errorf("Nobody: %+v", o)
			}
		case "NotKnown":
			if !o.Admitted || o.Exact || !strings.HasPrefix(plain(o.Heading), "Not excluded, and not proven admitted: the set is an upper bound.") || !strings.Contains(o.Sentence, "NotAction grants every action but the ones listed") {
				t.Errorf("NotKnown: %+v", o)
			}
		}
	}
}

func TestDenyOutcomesUseTheDenyWords(t *testing.T) {
	raw := []byte(`{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Principal":{"Federated":"token.actions.githubusercontent.com"},"Action":"sts:AssumeRoleWithWebIdentity","Condition":{"StringEquals":{"token.actions.githubusercontent.com:sub":"repo:a/b:ref:refs/heads/main"}}}]}`)
	yes := explanationFor(t, raw, []byte(`{"sub":"repo:a/b:ref:refs/heads/main"}`)).Grants[0]
	no := explanationFor(t, raw, []byte(`{"sub":"repo:a/c:ref:refs/heads/main"}`)).Grants[0]
	if plain(yes.Heading) != "Refused by grant 1." || plain(no.Heading) != "Not refused: one claim short of grant 1." {
		t.Errorf("headings = %q, %q", plain(yes.Heading), plain(no.Heading))
	}
	a := answerFor(t, raw)
	if !strings.HasPrefix(a.Grants[0].Sentence, "This role refuses any token from") || a.Grants[0].Caption != "A Deny subtracts from what the Allow statements admit; it admits nobody by itself." {
		t.Errorf("Deny sentence = %q, caption %q", a.Grants[0].Sentence, a.Grants[0].Caption)
	}
}

// TestClosestAgreesWithExcludes: the term the token view shows is chosen by
// the engine's own rule for Excludes, so the claim Excludes blames must be
// the first failing claim of that term, with the same constraint.
func TestClosestAgreesWithExcludes(t *testing.T) {
	values := []string{"a", "b", "c", ""}
	blamed := 0
	rapid.Check(t, func(t *rapid.T) {
		var terms []eval.Term
		for i := rapid.IntRange(0, 4).Draw(t, "terms"); i > 0; i-- {
			term := eval.Term{}
			for _, k := range []trust.ClaimKey{"aud", "sub", "x"} {
				switch rapid.IntRange(0, 3).Draw(t, "shape") {
				case 0:
					term[k] = eval.Exact(rapid.SampledFrom(values).Draw(t, "exact"))
				case 1:
					term[k] = eval.Glob(rapid.SampledFrom(values).Draw(t, "prefix") + "*")
				case 2:
					term[k] = eval.Unknown("why")
				}
			}
			terms = append(terms, term)
		}
		set := eval.NewAdmittedSet(terms...)
		token := map[trust.ClaimKey]string{}
		for _, k := range []trust.ClaimKey{"aud", "sub", "x"} {
			if rapid.Bool().Draw(t, "present") {
				token[k] = rapid.SampledFrom(values).Draw(t, "value")
			}
		}
		// every key read from the claim of its own name, and every claim
		// settled, as a token of an issuer whose keys each read their own
		// claim is read
		reads := map[trust.ClaimKey]keyRead{}
		for _, k := range []trust.ClaimKey{"aud", "sub", "x"} {
			value, present := token[k]
			reads[k] = keyRead{claim: string(k), value: value, present: present}
		}
		term, failed := closest(set, reads, false)
		if (len(failed) == 0 && len(set.Terms()) > 0) != set.Admits(token) {
			t.Fatalf("closest says failures %v on %s for %v; Admits says %v", failed, set, token, set.Admits(token))
		}
		claim, got, ok := set.Excludes(token)
		if !ok || claim == "" {
			return
		}
		blamed++
		if failed[0] != claim || term[claim].String() != got.String() {
			t.Fatalf("closest blames %v (%s) on %s for %v; Excludes blames %s (%s)", failed, term[failed[0]], set, token, claim, got)
		}
	})
	// the property is about rejections; a generator that stopped producing
	// them would pass vacuously
	if blamed < 20 {
		t.Fatalf("only %d rejections were generated", blamed)
	}
}

func TestTheAnswerMarshalsWithoutMaps(t *testing.T) {
	// A map in the answer would marshal in key order, but a witness or a
	// row order that depended on one would not be the engine's order.
	out := Admits(grantCase(t, "03-whole-organisation"))
	var generic map[string]any
	if err := json.Unmarshal(out, &generic); err != nil {
		t.Fatal(err)
	}
	witness := generic["grants"].([]any)[0].(map[string]any)["witness"].(string)
	if !strings.HasPrefix(witness, "{\n  \"iss\": ") || !strings.Contains(witness, "\"aud\": \"sts.amazonaws.com\",\n  \"sub\": ") {
		t.Errorf("the witness lists iss, aud, sub first: %q", witness)
	}
}

// A value the grant admits is data, and a renderer sets data in code
// coloured by what the engine knows of it: the token view's sentence must carry the
// same marks as the admits view's, or the two views show one value two ways.
func TestTheRejectionSentenceMarksWhatTheGrantAdmits(t *testing.T) {
	marked := func(spans []Span, text, mark string) bool {
		return slices.ContainsFunc(spans, func(s Span) bool { return s.Text == text && s.Mark == mark })
	}
	o := explanationFor(t, grantCase(t, "03-whole-organisation"), []byte(rejectedToken)).Grants[0]
	if !marked(o.Spans, "sts.amazonaws.com", "exact") {
		t.Errorf("the audience the grant admits is not marked exact: %+v", o.Spans)
	}
	if !marked(o.Spans, "https://github.com/acme", "code") {
		t.Errorf("the token's own value is not marked code: %+v", o.Spans)
	}
	evil := `{"iss": "https://token.actions.githubusercontent.com", "aud": "sts.amazonaws.com", "sub": "repo:acme-evil/infra:ref:refs/heads/main", "repository_owner_id": "123456"}`
	o = explanationFor(t, grantCase(t, "03-whole-organisation"), []byte(evil)).Grants[0]
	if !marked(o.Spans, "repo:acme/*", "exact") {
		t.Errorf("the pattern the grant admits is not marked exact: %+v", o.Spans)
	}
	union := []byte(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Federated":"token.actions.githubusercontent.com"},"Action":"sts:AssumeRoleWithWebIdentity","Condition":{"StringEquals":{"token.actions.githubusercontent.com:sub":["repo:a/b:ref:refs/heads/main","repo:a/b:environment:prod"]}}}]}`)
	o = explanationFor(t, union, []byte(`{"sub":"repo:a/c"}`)).Grants[0]
	if !marked(o.Spans, "repo:a/b:environment:prod", "exact") || !marked(o.Spans, "repo:a/b:ref:refs/heads/main", "exact") {
		t.Errorf("the alternatives the grant admits are not marked exact: %+v", o.Spans)
	}
	if want := "Rejected on sub: the token carries repo:a/c; grant 1 admits only one of repo:a/b:environment:prod and repo:a/b:ref:refs/heads/main. "; !strings.HasPrefix(o.Sentence, want) {
		t.Errorf("sentence = %q", o.Sentence)
	}
	absent := explanationFor(t, grantCase(t, "03-whole-organisation"), []byte(`{"aud": "sts.amazonaws.com"}`)).Grants[0]
	if !marked(absent.Spans, "123456", "exact") {
		t.Errorf("the value a missing claim would need is not marked exact: %+v", absent.Spans)
	}
}

const allowAndDeny = `{"Version":"2012-10-17","Statement":[
  {"Sid":"AllowOrg","Effect":"Allow","Principal":{"Federated":"arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"},"Action":"sts:AssumeRoleWithWebIdentity","Condition":{"StringEquals":{"token.actions.githubusercontent.com:aud":"sts.amazonaws.com"},"StringLike":{"token.actions.githubusercontent.com:sub":"repo:acme/*"}}},
  {"Sid":"DenyForks","Effect":"Deny","Principal":{"Federated":"arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"},"Action":"sts:AssumeRoleWithWebIdentity","Condition":{"StringLike":{"token.actions.githubusercontent.com:sub":"repo:acme/*:pull_request"}}}]}`

// netOf reads the policy's own answer for the token, above the grants,
// through the JSON: what a reader sees before any grant.
func netOf(t *testing.T, policy, token []byte) (heading, sentence string) {
	t.Helper()
	var generic map[string]any
	if err := json.Unmarshal(Explain(policy, token), &generic); err != nil {
		t.Fatal(err)
	}
	if spans, ok := generic["heading"].([]any); ok {
		for _, s := range spans {
			heading += s.(map[string]any)["text"].(string)
		}
	}
	sentence, _ = generic["sentence"].(string)
	return heading, sentence
}

// A policy admits a token when an Allow admits it and no Deny refuses it;
// the answer for the token is that, said once above the grants. Grants sort
// Allow before Deny, so a reader that took the first grant's heading would
// show a refused token as admitted.
func TestThePolicyAnswersForTheTokenAboveItsGrants(t *testing.T) {
	policy := []byte(allowAndDeny)
	fork := []byte(`{"iss":"https://token.actions.githubusercontent.com","aud":"sts.amazonaws.com","sub":"repo:acme/infra:pull_request"}`)
	heading, sentence := netOf(t, policy, fork)
	if heading != "Refused by grant 2, though grant 1 admits it." {
		t.Errorf("fork: heading %q", heading)
	}
	if sentence != "Grant 1 admits it; grant 2 refuses it: a Deny subtracts from what the Allow statements admit." {
		t.Errorf("fork: sentence %q", sentence)
	}
	branch := []byte(`{"iss":"https://token.actions.githubusercontent.com","aud":"sts.amazonaws.com","sub":"repo:acme/infra:ref:refs/heads/main"}`)
	heading, sentence = netOf(t, policy, branch)
	if heading != "Admitted by grant 1." || sentence != "Grant 1 admits it; grant 2 does not refuse it." {
		t.Errorf("branch: heading %q, sentence %q", heading, sentence)
	}
	stranger := []byte(`{"iss":"https://token.actions.githubusercontent.com","aud":"sts.amazonaws.com","sub":"repo:other/infra:pull_request"}`)
	heading, sentence = netOf(t, policy, stranger)
	if heading != "Not admitted by any grant." || sentence != "Grant 1 rejects it on sub; grant 2 does not refuse it." {
		t.Errorf("stranger: heading %q, sentence %q", heading, sentence)
	}
	// one grant: the policy's answer is the grant's own, so the answer says it once
	e := explanationFor(t, grantCase(t, "03-whole-organisation"), []byte(rejectedToken))
	heading, sentence = netOf(t, grantCase(t, "03-whole-organisation"), []byte(rejectedToken))
	if heading != plain(e.Grants[0].Heading) || sentence != e.Grants[0].Sentence {
		t.Errorf("one grant: heading %q, sentence %q", heading, sentence)
	}
	// an upper bound admits without proving, and an effect that could not be read decides nothing
	bound := []byte(`{"Version":"2012-10-17","Statement":[
	  {"Sid":"Bound","Effect":"Allow","Principal":{"Federated":"token.actions.githubusercontent.com"},"Action":"sts:AssumeRoleWithWebIdentity","Condition":{"ForAllValues:StringLike":{"token.actions.githubusercontent.com:sub":"repo:acme/*"}}},
	  {"Sid":"Unread","Effect":"Maybe","Principal":{"Federated":"token.actions.githubusercontent.com"},"Action":"sts:AssumeRoleWithWebIdentity","Condition":{"StringEquals":{"token.actions.githubusercontent.com:aud":"sts.amazonaws.com"}}}]}`)
	heading, sentence = netOf(t, bound, branch)
	if heading != "Not excluded, and not proven admitted: grant 1 is an upper bound, and grant 2's effect could not be read." {
		t.Errorf("bound: heading %q", heading)
	}
	if sentence != "Grant 1 admits it as an upper bound; grant 2 matches it, with an effect that could not be read." {
		t.Errorf("bound: sentence %q", sentence)
	}
	// a policy with no grant holds no statement, and whether it admits the
	// token is not known, as its answer says of who can assume the role
	heading, sentence = netOf(t, []byte(`{"Version":"2012-10-17","Statement":[]}`), branch)
	if heading != "The document holds no statement, so whether this token is admitted is not known." || sentence != "" {
		t.Errorf("no grant: heading %q, sentence %q", heading, sentence)
	}
}

// The token reader recurses once per level, on a stack the WebAssembly
// build fixes at link time, so its depth is bounded the way a document's
// is: refused by the entry with the depth, the bound and the byte, never a
// trap that kills the engine.
func TestATokenNestedTooDeepIsRefused(t *testing.T) {
	deep := func(n int) string { return `{"a":` + strings.Repeat("[", n) + strings.Repeat("]", n) + `}` }
	policy := grantCase(t, "03-whole-organisation")
	if e := explanationFor(t, policy, []byte(deep(MaxTokenNesting-1))); e.Token.Error != "" || e.Token.Claims != 1 {
		t.Errorf("%d levels inside the claim, the bound itself: %+v", MaxTokenNesting, e.Token)
	}
	for _, n := range []int{500, 5000, 8000} {
		e := explanationFor(t, policy, []byte(deep(n)))
		want := "the token is nested " + strconv.Itoa(n+1) + " levels deep; the engine reads up to 500 levels, and level 501 opens at byte 504"
		if e.Token.Error != want || len(e.Grants) != 0 {
			t.Errorf("%d levels:\n got %q\nwant %q", n, e.Token.Error, want)
		}
	}
	// past the size bound the size is what is said: it is checked first
	if e := explanationFor(t, policy, []byte(deep(9990))); e.Token.Error != "the token is 19986 bytes; the engine reads up to 16384" {
		t.Errorf("9990 levels: %+v", e.Token)
	}
	objects := `{"a":` + strings.Repeat(`{"b":`, 500) + "1" + strings.Repeat("}", 500) + "}"
	if e := explanationFor(t, policy, []byte(objects)); e.Token.Error != "the token is nested 501 levels deep; the engine reads up to 500 levels, and level 501 opens at byte 2500" {
		t.Errorf("500 objects inside the claim: %+v", e.Token)
	}
	whole := "eyJhbGciOiJSUzI1NiJ9." + base64.RawURLEncoding.EncodeToString([]byte(deep(5000))) + ".c2ln"
	if e := explanationFor(t, policy, []byte(whole)); !strings.HasPrefix(e.Token.Error, "the token is nested 5001 levels deep;") {
		t.Errorf("a whole token nested 5000 deep: %+v", e.Token)
	}
	// a bracket inside a claim's string is text
	if e := explanationFor(t, policy, []byte(`{"sub":"`+strings.Repeat(`[{`, 600)+`"}`)); e.Token.Error != "" || e.Token.Claims != 1 {
		t.Errorf("brackets inside a string: %+v", e.Token)
	}
}

// resultRead is the policy's result for a token and the outcomes it rests
// on, read from the JSON the WebAssembly engine returns.
type resultRead struct {
	Error  string `json:"error"`
	Token  Token  `json:"token"`
	Result string `json:"result"`
	Grants []struct {
		Statement int    `json:"statement"`
		Issuer    string `json:"issuer"`
		Effect    string `json:"effect"`
		Exact     bool   `json:"exact"`
		Admitted  bool   `json:"admitted"`
		Claims    []struct {
			Result     string `json:"result"`
			Constraint struct {
				Kind string `json:"kind"`
			} `json:"constraint"`
		} `json:"claims"`
	} `json:"grants"`
}

// expectedResult is the policy's result by the rule the heading is written
// by, applied here to the outcomes alone: a Deny that matches refuses the
// token whatever the Allows say; otherwise an exact Allow that matches, and
// whose claims the token all settles, admits it, unless a Deny may refuse
// it, as one that was not applied may unless the token's issuer, or the
// actions of the face of "*" it is, rule it out; otherwise an Allow that
// matches as an upper bound or on a claim the token leaves unsettled, or a
// statement whose effect could not be read that matches, leaves it not
// proven; otherwise no grant admits it. The token leaves a claim unsettled
// where a claim the grant read exactly is not evaluated. A document with no
// grant holds no statement, and what it admits is not known.
func expectedResult(t *testing.T, r resultRead, policy []byte) string {
	t.Helper()
	if len(r.Grants) == 0 {
		return "not known"
	}
	d, err := aws.ParseTrustPolicy(policy)
	if err != nil {
		t.Fatalf("the policy the explanation read: %v", err)
	}
	var admitted, bounded, mayRefuse bool
	for _, g := range r.Grants {
		unsettled, otherIssuer := false, false
		for _, c := range g.Claims {
			unsettled = unsettled || c.Result == "not evaluated" && c.Constraint.Kind != "unknown"
			otherIssuer = otherIssuer || c.Constraint.Kind == "issuer" && c.Result == "fails"
		}
		// a face of "*" whose actions are sts:AssumeRole or
		// sts:AssumeRoleWithSAML names no web-identity token
		noToken := g.Issuer == "" && d.Statements[g.Statement].IssuerlessPopulation() != aws.EveryIssuer
		switch {
		case g.Effect == "Deny" && g.Admitted:
			return "refused"
		case g.Effect == "Deny":
			mayRefuse = mayRefuse || unsettled || !g.Exact && !otherIssuer && !noToken
		case !g.Admitted:
		case g.Effect == "Allow" && g.Exact && !unsettled:
			admitted = true
		default:
			bounded = true
		}
	}
	switch {
	case admitted && !mayRefuse:
		return "admitted"
	case admitted || bounded:
		return "not proven"
	}
	return "not admitted"
}

// TestThePolicysResultIsCarried: the explanation carries the policy's
// result for the token as a value, so that a caller can lead with the claims
// that refused a token without reading the heading's words or deciding the
// result itself. It is set with one grant and with none as with several,
// it agrees with the rule the heading is written by, and an explanation
// that read no policy or no token carries none.
func TestThePolicysResultIsCarried(t *testing.T) {
	read := func(policy, token []byte) resultRead {
		t.Helper()
		var r resultRead
		if err := json.Unmarshal(Explain(policy, token), &r); err != nil {
			t.Fatal(err)
		}
		return r
	}
	branch := []byte(`{"iss":"https://token.actions.githubusercontent.com","aud":"sts.amazonaws.com","sub":"repo:acme/infra:ref:refs/heads/main"}`)
	// AWS reads aud from azp, and from aud when the token sets no azp;
	// whether an azp of null is no azp is not documented
	unsettled := []byte(`{"iss":"https://token.actions.githubusercontent.com","aud":"sts.amazonaws.com","azp":null,"sub":"repo:acme/infra:ref:refs/heads/main","repository_owner_id":"123456"}`)
	fork := []byte(`{"iss":"https://token.actions.githubusercontent.com","aud":"sts.amazonaws.com","sub":"repo:acme/infra:pull_request"}`)
	stranger := []byte(`{"iss":"https://token.actions.githubusercontent.com","aud":"sts.amazonaws.com","sub":"repo:other/infra:pull_request"}`)
	oneBound := []byte(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Federated":"token.actions.githubusercontent.com"},"Action":"sts:AssumeRoleWithWebIdentity","Condition":{"ForAllValues:StringLike":{"token.actions.githubusercontent.com:sub":"repo:acme/*"}}}]}`)
	oneUnread := []byte(`{"Version":"2012-10-17","Statement":[{"Effect":"Maybe","Principal":{"Federated":"token.actions.githubusercontent.com"},"Action":"sts:AssumeRoleWithWebIdentity"}]}`)
	oneDeny := []byte(`{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Principal":{"Federated":"token.actions.githubusercontent.com"},"Action":"sts:AssumeRoleWithWebIdentity"}]}`)
	noGrant := []byte(`{"Version":"2012-10-17","Statement":[]}`)
	organisation := grantCase(t, "03-whole-organisation")
	for _, c := range []struct {
		name          string
		policy, token []byte
		want          string
	}{
		{"a Deny that matches, beside an Allow that admits", []byte(allowAndDeny), fork, "refused"},
		{"an Allow that admits, beside a Deny that does not match", []byte(allowAndDeny), branch, "admitted"},
		{"no grant matches", []byte(allowAndDeny), stranger, "not admitted"},
		{"an upper bound, and an effect not read", []byte(`{"Version":"2012-10-17","Statement":[
		  {"Sid":"Bound","Effect":"Allow","Principal":{"Federated":"token.actions.githubusercontent.com"},"Action":"sts:AssumeRoleWithWebIdentity","Condition":{"ForAllValues:StringLike":{"token.actions.githubusercontent.com:sub":"repo:acme/*"}}},
		  {"Sid":"Unread","Effect":"Maybe","Principal":{"Federated":"token.actions.githubusercontent.com"},"Action":"sts:AssumeRoleWithWebIdentity","Condition":{"StringEquals":{"token.actions.githubusercontent.com:aud":"sts.amazonaws.com"}}}]}`), branch, "not proven"},
		{"one grant that admits", organisation, []byte(`{"iss":"https://token.actions.githubusercontent.com","aud":"sts.amazonaws.com","sub":"repo:acme/infra:ref:refs/heads/main","repository_owner_id":"123456"}`), "admitted"},
		{"one grant that rejects", organisation, []byte(rejectedToken), "not admitted"},
		{"one upper bound", oneBound, branch, "not proven"},
		{"one effect not read", oneUnread, branch, "not proven"},
		{"one Deny that matches", oneDeny, branch, "refused"},
		{"one Deny that does not match", oneDeny, []byte(`{"iss":"https://gitlab.com"}`), "not admitted"},
		{"no grant at all", noGrant, branch, "not known"},
		{"an Allow on a claim the token leaves unsettled", organisation, unsettled, "not proven"},
		{"an Allow that admits, beside a Deny that may refuse", []byte(`{"Version":"2012-10-17","Statement":[
		  {"Effect":"Allow","Principal":{"Federated":"token.actions.githubusercontent.com"},"Action":"sts:AssumeRoleWithWebIdentity","Condition":{"StringLike":{"token.actions.githubusercontent.com:sub":"repo:acme/*"}}},
		  {"Effect":"Deny","Principal":{"Federated":"token.actions.githubusercontent.com"},"Action":"sts:AssumeRoleWithWebIdentity","Condition":{"StringEquals":{"token.actions.githubusercontent.com:aud":"sts.amazonaws.com"}}}]}`), unsettled, "not proven"},
	} {
		if got := read(c.policy, c.token); got.Result != c.want || expectedResult(t, got, c.policy) != c.want {
			t.Errorf("%s: result %q, by the outcomes %q; want %q", c.name, got.Result, expectedResult(t, got, c.policy), c.want)
		}
	}
	for name, r := range map[string]resultRead{
		"a policy not read": read([]byte("not a policy"), branch),
		"a token not read":  read(organisation, []byte("not a token")),
	} {
		if r.Result != "" {
			t.Errorf("%s carries the result %q", name, r.Result)
		}
	}
	// and over the corpus, each document explained for every token of the
	// sweep: the result is always one of the five and always the rule's
	tokens := [][]byte{branch, fork, stranger, unsettled, []byte(rejectedToken), []byte(`{"iss":"https://gitlab.com","sub":"project_path:acme/infra"}`), []byte(`{}`)}
	seen := map[string]int{}
	for path, doc := range corpus(t) {
		for _, token := range tokens {
			r := read(doc, token)
			if r.Error != "" || r.Token.Error != "" {
				continue
			}
			if want := expectedResult(t, r, doc); r.Result != want {
				t.Errorf("%s with %s: result %q, want %q", path, token, r.Result, want)
			}
			seen[r.Result]++
		}
	}
	for _, v := range []string{"refused", "admitted", "not proven", "not admitted"} {
		if seen[v] == 0 {
			t.Errorf("no explanation of the corpus is %q; that branch went unexamined", v)
		}
	}
	t.Logf("the corpus's results: %v", seen)
}
