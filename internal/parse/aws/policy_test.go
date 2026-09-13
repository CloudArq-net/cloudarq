package aws

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/CloudArq-net/cloudarq/internal/eval"
	"github.com/CloudArq-net/cloudarq/internal/trust"
)

// The GitHub Actions issuer, in the three spellings a trust policy meets it
// in: the registry key, the OIDC provider ARN, and the condition key prefix.
const (
	githubIssuer   = trust.IssuerRef("https://token.actions.githubusercontent.com")
	githubProvider = "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
	githubHost     = "token.actions.githubusercontent.com"
	mainBranch     = "repo:acme/infra:ref:refs/heads/main"
	devBranch      = "repo:acme/infra:ref:refs/heads/dev"
)

// policiesDir holds the golden documents, one per semantic case in the
// brief, each beside the rationale that cites the AWS sentence making its
// expected answer correct.
const policiesDir = "../../../testdata/policies"

var role = trust.TargetRef{Kind: "role", ID: "arn:aws:iam::123456789012:role/deploy"}

type token = map[trust.ClaimKey]string

// vocabulary knows GitHub's claims, as the registry will one day know
// every issuer's.
var vocabulary = LowercaseVocabulary(githubIssuer)

func mustParse(t *testing.T, raw string) Document {
	t.Helper()
	d, err := ParseTrustPolicy([]byte(raw))
	if err != nil {
		t.Fatalf("ParseTrustPolicy: %v", err)
	}
	return d
}

func grantsOf(t *testing.T, raw string) []trust.Grant {
	t.Helper()
	return mustParse(t, raw).Grants(role, vocabulary)
}

// oneGrant parses a document that must project to exactly one grant.
func oneGrant(t *testing.T, raw string) trust.Grant {
	t.Helper()
	gs := grantsOf(t, raw)
	if len(gs) != 1 {
		t.Fatalf("%d grants, want 1: %+v", len(gs), gs)
	}
	return gs[0]
}

// awsFace parses a document and picks the one grant on the AWS
// pseudo-issuer: for a "*" principal, the face that is every AWS
// principal, beside the face that is every other identity.
func awsFace(t *testing.T, raw string) trust.Grant {
	t.Helper()
	var faces []trust.Grant
	for _, g := range grantsOf(t, raw) {
		if g.Issuer == AWSPrincipalIssuer {
			faces = append(faces, g)
		}
	}
	if len(faces) != 1 {
		t.Fatalf("%d grants on %s, want 1: %+v", len(faces), AWSPrincipalIssuer, faces)
	}
	return faces[0]
}

func readPolicy(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(policiesDir, name+".json"))
	if err != nil {
		t.Fatalf("%v", err)
	}
	return raw
}

func policyGrants(t *testing.T, name string) []trust.Grant {
	t.Helper()
	return grantsOf(t, string(readPolicy(t, name)))
}

// github wraps a condition block in the one-statement document every
// condition test uses: an Allow for the GitHub provider on the web
// identity action.
func github(condition string) string {
	return statement(`"Effect": "Allow",
      "Principal": {"Federated": "` + githubProvider + `"},
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": ` + condition)
}

// statement wraps statement members in a one-statement document.
func statement(members string) string {
	return `{"Version": "2012-10-17", "Statement": [{` + members + `}]}`
}

func findAnomaly(g trust.Grant, kind, construct string) (trust.Anomaly, bool) {
	for _, a := range g.Anomalies {
		if a.Kind == kind && a.Construct == construct {
			return a, true
		}
	}
	return trust.Anomaly{}, false
}

func hasCaveatOn(g trust.Grant, claim trust.ClaimKey) bool {
	return slices.ContainsFunc(g.Admits.Caveats(), func(c eval.Caveat) bool { return c.Claim == claim })
}

// bySid picks the grants that came from the statement with the given Sid,
// through the source bytes every grant carries.
func bySid(gs []trust.Grant, sid string) []trust.Grant {
	var out []trust.Grant
	for _, g := range gs {
		if strings.Contains(string(g.Source), `"Sid": "`+sid+`"`) {
			out = append(out, g)
		}
	}
	return out
}

func TestParseRefusesWhatIsNotAPolicyDocument(t *testing.T) {
	cases := []struct {
		name, raw, want string
	}{
		{"empty", "", "empty"},
		{"whitespace", " \n", "empty"},
		{"not json", "Statement", "invalid character"},
		{"array root", `[{"Effect": "Allow"}]`, "a list, not an object"},
		{"string root", `"x"`, "a string, not an object"},
		{"number root", `1`, "a number, not an object"},
		{"null root", `null`, "null, not an object"},
		{"two documents", `{"Statement": []} {"Statement": []}`, "after the document"},
		{"trailing bytes", `{"Statement": []} x`, "after the document"},
		{"byte order mark", "\xEF\xBB\xBF{}", "invalid character"},
		{"invalid utf-8", "{\"Sid\": \"a\xffb\"}", "not valid UTF-8"},
	}
	for _, c := range cases {
		d, err := ParseTrustPolicy([]byte(c.raw))
		if err == nil {
			t.Errorf("%s: parsed %+v, want an error", c.name, d)
			continue
		}
		if !strings.HasPrefix(err.Error(), "parse trust policy: ") || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: error %q must carry its story and mention %q", c.name, err, c.want)
		}
	}
}

// Case 1: a single statement written as an object is one statement, not
// zero. The array form of the same statement projects the same grants.
func TestStatementIsAnObjectOrAnArray(t *testing.T) {
	object := string(readPolicy(t, "01-statement-object-or-array"))
	d := mustParse(t, object)
	if len(d.Statements) != 1 || d.Statements[0].Sid != "SingleObjectStatement" {
		t.Fatalf("statements = %+v, want the one object statement", d.Statements)
	}
	if len(d.Anomalies) != 0 {
		t.Errorf("an object statement is valid and carries no anomaly; got %v", d.Anomalies)
	}
	array := strings.Replace(strings.Replace(object, `"Statement": {`, `"Statement": [{`, 1), "\n  }\n}", "\n  }]\n}", 1)
	if array == object {
		t.Fatalf("the array form was not built")
	}
	a, b := grantsOf(t, object), grantsOf(t, array)
	if len(a) != 1 || len(b) != 1 || a[0].Admits.String() != b[0].Admits.String() || a[0].Issuer != b[0].Issuer {
		t.Errorf("object form %v, array form %v; they must project the same grant", a, b)
	}
	if want := `{aud="sts.amazonaws.com", sub="` + mainBranch + `"}`; a[0].Admits.String() != want || !a[0].Exact() {
		t.Errorf("Admits = %s, exact %v; want %s exact", a[0].Admits, a[0].Exact(), want)
	}
}

// Case 2: "allow" is not an Allow. It is a malformed effect, which the
// evaluator must read as possibly Allow; reading it as Deny would report
// the role as narrower than it is.
func TestEffectIsCaseSensitive(t *testing.T) {
	d := mustParse(t, string(readPolicy(t, "02-effect-case")))
	if d.Statements[0].Effect != trust.EffectUnknown {
		t.Fatalf("Effect = %q, want %q", d.Statements[0].Effect, trust.EffectUnknown)
	}
	g := oneGrant(t, string(readPolicy(t, "02-effect-case")))
	if g.Effect != trust.EffectUnknown {
		t.Errorf("grant effect = %q, want %q", g.Effect, trust.EffectUnknown)
	}
	// The conditions are still honoured: possibly-Allow keeps its set.
	if want := `{aud="sts.amazonaws.com", sub="` + mainBranch + `"}`; g.Admits.String() != want || !g.Exact() {
		t.Errorf("Admits = %s, exact %v; want %s exact", g.Admits, g.Exact(), want)
	}
	a, ok := findAnomaly(g, Malformed, "Effect")
	if !ok {
		t.Fatalf("no %s anomaly on Effect: %v", Malformed, g.Anomalies)
	}
	want := `Effect is "allow"; AWS accepts exactly "Allow" or "Deny", so the effect is not known and is read as possibly Allow`
	if a.Message != want || a.Source != "statement[0].Effect" || a.Claim != "" {
		t.Errorf("anomaly = %+v, want message %q at statement[0].Effect", a, want)
	}
	for _, effect := range []string{`"Deny "`, `"ALLOW"`, `true`, `["Allow"]`, `null`} {
		g := oneGrant(t, statement(`"Effect": `+effect+`, "Principal": {"Federated": "`+githubProvider+`"}, "Action": "sts:AssumeRoleWithWebIdentity"`))
		if g.Effect != trust.EffectUnknown {
			t.Errorf("Effect %s: grant effect = %q, want %q", effect, g.Effect, trust.EffectUnknown)
		}
		if _, ok := findAnomaly(g, Malformed, "Effect"); !ok {
			t.Errorf("Effect %s: no malformed anomaly", effect)
		}
	}
	for _, effect := range []string{"Allow", "Deny"} {
		g := oneGrant(t, statement(`"Effect": "`+effect+`", "Principal": {"Federated": "`+githubProvider+`"}, "Action": "sts:AssumeRoleWithWebIdentity"`))
		if string(g.Effect) != effect || len(g.Anomalies) != 0 {
			t.Errorf("Effect %s: grant effect %q, anomalies %v", effect, g.Effect, g.Anomalies)
		}
	}
	// No Effect at all is not an Allow and not a Deny either.
	missing := oneGrant(t, statement(`"Principal": {"Federated": "`+githubProvider+`"}, "Action": "sts:AssumeRoleWithWebIdentity", "Condition": {"StringEquals": {"`+gh("sub")+`": "`+mainBranch+`"}}`))
	if missing.Effect != trust.EffectUnknown || missing.Admits.String() != `{sub="`+mainBranch+`"}` || !missing.Exact() {
		t.Errorf("no Effect: effect %q, admits %s, exact %v", missing.Effect, missing.Admits, missing.Exact())
	}
	if a, ok := findAnomaly(missing, Malformed, "Effect"); !ok || a.Message != "the statement has no Effect member, so the effect is not known and is read as possibly Allow" || a.Source != "statement[0].Effect" {
		t.Errorf("no Effect: anomaly = %+v, %v", a, ok)
	}
	boolean := oneGrant(t, statement(`"Effect": true, "Principal": {"Federated": "`+githubProvider+`"}, "Action": "sts:AssumeRoleWithWebIdentity"`))
	if a, ok := findAnomaly(boolean, Malformed, "Effect"); !ok || a.Message != "Effect is a boolean (true), not a string, so the effect is not known and is read as possibly Allow" {
		t.Errorf("boolean Effect: anomaly = %+v, %v", a, ok)
	}
}

// Case 11: every principal shape the brief names projects a grant; none is
// dropped, because a principal that exists and produces no grant is the
// Prowler bug one level up.
func TestPrincipalShapes(t *testing.T) {
	raw := string(readPolicy(t, "11-principal-shapes"))
	d := mustParse(t, raw)
	if len(d.Statements) != 8 {
		t.Fatalf("%d statements, want 8", len(d.Statements))
	}
	// Google's built-in provider spells its claims in lower case too; the
	// vocabulary is seeded with it so that its grant is exact.
	gs := d.Grants(role, LowercaseVocabulary(githubIssuer, "https://accounts.google.com"))
	if len(gs) != 11 {
		t.Fatalf("%d grants, want 11: %+v", len(gs), gs)
	}
	// "*" is two faces: every AWS principal, exactly, and every other
	// identity, which here means every AWS service, as an upper bound.
	for _, sid := range []string{"BareStar", "AWSStar"} {
		faces := bySid(gs, sid)
		if len(faces) != 2 {
			t.Fatalf("%s: %d grants, want 2", sid, len(faces))
		}
		for _, g := range faces {
			if a, ok := findAnomaly(g, AnyPrincipal, "Principal"); !ok || a.Message != "the statement applies to every principal, including anonymous ones" {
				t.Errorf("%s: any-principal anomaly = %+v, %v", sid, a, ok)
			}
			switch g.Issuer {
			case AWSPrincipalIssuer:
				if !g.Admits.IsTop() || !g.Exact() {
					t.Errorf("%s: AWS face admits %s, exact %v; want everything, exactly", sid, g.Admits, g.Exact())
				}
			case "":
				if !g.Admits.IsTop() || g.Exact() || !hasCaveatOn(g, "") {
					t.Errorf("%s: unnamed face admits %s, exact %v; want everything, declared", sid, g.Admits, g.Exact())
				}
				if a, ok := findAnomaly(g, trust.Unmodelled, "Principal"); !ok || a.Message != "the statement applies to every principal, and which AWS services it covers through sts:AssumeRole is not known" {
					t.Errorf("%s: unnamed face anomaly = %+v, %v", sid, a, ok)
				}
			default:
				t.Errorf("%s: unexpected issuer %q", sid, g.Issuer)
			}
		}
	}

	both := bySid(gs, "RoleArnAndBareAccountId")
	if len(both) != 2 {
		t.Fatalf("two AWS principals must be two grants; got %d", len(both))
	}
	renderings := []string{both[0].Admits.String(), both[1].Admits.String()}
	slices.Sort(renderings)
	wantRole := `{aws:principalaccount="123456789012", aws:principalarn="arn:aws:iam::123456789012:role/ci"}`
	wantAccount := `{aws:principalaccount="999999999999"}`
	if renderings[0] != wantRole || renderings[1] != wantAccount {
		t.Errorf("AWS grants render %q; want %q and %q", renderings, wantRole, wantAccount)
	}
	for _, g := range both {
		if g.Issuer != AWSPrincipalIssuer || !g.Exact() {
			t.Errorf("AWS principal grant: issuer %q, exact %v", g.Issuer, g.Exact())
		}
		if !g.Admits.Admits(token{"aws:principalaccount": "999999999999"}) && !g.Admits.Admits(token{"aws:principalaccount": "123456789012", "aws:principalarn": "arn:aws:iam::123456789012:role/ci"}) {
			t.Errorf("%s admits neither identity", g.Admits)
		}
	}

	oidc := bySid(gs, "FederatedOIDCProvider")
	if len(oidc) != 1 || oidc[0].Issuer != githubIssuer || oidc[0].Admits.String() != `{sub="`+mainBranch+`"}` || !oidc[0].Exact() {
		t.Errorf("OIDC grant = %+v", oidc)
	}

	google := bySid(gs, "FederatedBuiltInProvider")
	if len(google) != 1 || google[0].Issuer != "https://accounts.google.com" || !google[0].Exact() {
		t.Errorf("built-in provider grant = %+v; a bare provider name is an issuer", google)
	}
	if len(google) == 1 && google[0].Admits.String() != `{aud="123456789012-abcdef.apps.googleusercontent.com"}` {
		t.Errorf("built-in provider admits %s", google[0].Admits)
	}

	service := bySid(gs, "ServicePrincipal")
	if len(service) != 1 || service[0].Issuer != "aws:service:ec2.amazonaws.com" || !service[0].Admits.IsTop() || !service[0].Exact() {
		t.Errorf("service grant = %+v; want the service's own pseudo-issuer", service)
	}
	if a, ok := findAnomaly(service[0], ServicePrincipal, "Service"); !ok || a.Message != "ec2.amazonaws.com is an AWS service principal, not an external identity" {
		t.Errorf("service anomaly = %+v, %v", a, ok)
	}

	canonical := bySid(gs, "CanonicalUser")
	if len(canonical) != 1 || canonical[0].Issuer != AWSPrincipalIssuer || !canonical[0].Admits.IsTop() || canonical[0].Exact() {
		t.Errorf("canonical user grant = %+v; want everything, inexact", canonical)
	}
	if a, ok := findAnomaly(canonical[0], trust.Unmodelled, "CanonicalUser"); !ok || a.Message != "a CanonicalUser principal is not modelled by this parser, so who it names is not known" {
		t.Errorf("canonical user anomaly = %+v, %v", a, ok)
	}

	not := bySid(gs, "NotPrincipalIsADifferentThing")
	if len(not) != 1 || not[0].Issuer != "" || not[0].Effect != trust.Deny || !not[0].Admits.IsEmpty() || not[0].Exact() {
		t.Errorf("NotPrincipal grant = %+v; want no issuer, a Deny that denies nothing, inexact", not)
	}
	a, ok := findAnomaly(not[0], trust.Unmodelled, "NotPrincipal")
	if !ok || a.Message != "NotPrincipal is not supported in a role trust policy and names who is excluded rather than who is admitted, so who the statement admits is not known" {
		t.Errorf("NotPrincipal anomaly = %+v, %v", a, ok)
	}
	if _, ok := findAnomaly(not[0], trust.Unmodelled, "Deny"); !ok {
		t.Errorf("a Deny that is not applied must say so: %v", not[0].Anomalies)
	}
}

// Case 12: the action name is case-insensitive and takes wildcards
// anywhere; NotAction is marked and widens rather than computed.
func TestActionCaseAndNotAction(t *testing.T) {
	gs := policyGrants(t, "12-action-case-and-notaction")
	if len(gs) != 6 {
		t.Fatalf("%d grants, want 6", len(gs))
	}
	for _, sid := range []string{"ActionNameIsCaseInsensitive", "WildcardAnywhereInTheName", "EveryAction", "SingleCharacterWildcard"} {
		g := bySid(gs, sid)
		if len(g) != 1 || g[0].Admits.String() != `{sub="`+mainBranch+`"}` || !g[0].Exact() {
			t.Errorf("%s: grants = %+v; the action covers the web identity assume, so the condition is the set", sid, g)
		}
	}
	g := bySid(gs, "AssumeRoleIsNotTheWebIdentityAction")
	if len(g) != 1 || !g[0].Admits.IsEmpty() || !g[0].Exact() {
		t.Fatalf("sts:AssumeRole on an OIDC principal: grants = %+v; want nothing, exactly", g)
	}
	a, ok := findAnomaly(g[0], NotAnAssumeAction, "Action")
	if !ok || a.Message != "the actions do not include sts:AssumeRoleWithWebIdentity, so this statement lets nobody assume the role through this principal" {
		t.Errorf("not-an-assume-action anomaly = %+v, %v", a, ok)
	}
	g = bySid(gs, "NotActionInverts")
	if len(g) != 1 || !g[0].Admits.IsTop() || g[0].Exact() {
		t.Fatalf("NotAction: grants = %+v; want everything, inexact", g)
	}
	a, ok = findAnomaly(g[0], trust.Unmodelled, "NotAction")
	if !ok || a.Message != "NotAction grants every action but the ones listed; this parser does not compute that complement, so which actions the statement grants is not known" || a.Source != "statement[5].Action" {
		t.Errorf("NotAction anomaly = %+v, %v", a, ok)
	}
	if !hasCaveatOn(g[0], "") {
		t.Errorf("a whole-grant Unknown carries a caveat with an empty claim; got %v", g[0].Admits.Caveats())
	}
}

// TestActionCoverageFollowsThePrincipalKind: an AWS principal assumes
// through sts:AssumeRole, a SAML one through sts:AssumeRoleWithSAML, and
// the anonymous principal through any of the three.
func TestActionCoverageFollowsThePrincipalKind(t *testing.T) {
	aws := oneGrant(t, statement(`"Effect": "Allow", "Principal": {"AWS": "123456789012"}, "Action": "sts:AssumeRoleWithWebIdentity"`))
	if !aws.Admits.IsEmpty() || !aws.Exact() {
		t.Errorf("an AWS principal cannot assume through the web identity action; got %s", aws.Admits)
	}
	if a, ok := findAnomaly(aws, NotAnAssumeAction, "Action"); !ok || a.Message != "the actions do not include sts:AssumeRole, so this statement lets nobody assume the role through this principal" {
		t.Errorf("anomaly = %+v, %v", a, ok)
	}
	saml := oneGrant(t, statement(`"Effect": "Allow", "Principal": {"Federated": "arn:aws:iam::123456789012:saml-provider/okta"}, "Action": ["sts:AssumeRoleWithSAML", "sts:TagSession"]`))
	if saml.Issuer != "arn:aws:iam::123456789012:saml-provider/okta" || !saml.Admits.IsTop() || saml.Exact() {
		t.Errorf("SAML grant = %+v; want the ARN as issuer, everything, inexact", saml)
	}
	if a, ok := findAnomaly(saml, trust.Unmodelled, "SAML"); !ok || a.Message != `SAML federation through "arn:aws:iam::123456789012:saml-provider/okta" is not modelled by this parser, so which identities it admits is not known` {
		t.Errorf("SAML anomaly = %+v, %v", a, ok)
	}
	if g := oneGrant(t, statement(`"Effect": "Allow", "Principal": {"Federated": "arn:aws:iam::123456789012:saml-provider/okta"}, "Action": "sts:AssumeRole"`)); !g.Admits.IsEmpty() {
		t.Errorf("a SAML principal cannot assume through sts:AssumeRole; got %s", g.Admits)
	}
	// "*" is every AWS principal, which assumes through sts:AssumeRole, and
	// every other identity: every service, which assumes through the same
	// action, and every provider's tokens, which assume through the two
	// federated actions. Each face admits everything under its own actions.
	if g := awsFace(t, statement(`"Effect": "Allow", "Principal": "*", "Action": "sts:AssumeRole"`)); !g.Admits.IsTop() || !g.Exact() {
		t.Errorf("sts:AssumeRole: the AWS face admits everything, exactly; got %s exact %v", g.Admits, g.Exact())
	}
	for _, action := range []string{"sts:AssumeRoleWithWebIdentity", "sts:AssumeRoleWithSAML"} {
		gs := grantsOf(t, statement(`"Effect": "Allow", "Principal": "*", "Action": "`+action+`"`))
		if len(gs) != 2 {
			t.Fatalf("%s: %d grants, want the AWS face and the unnamed face", action, len(gs))
		}
		for _, g := range gs {
			if unnamed := g.Issuer == ""; g.Admits.IsTop() != unnamed {
				t.Errorf("%s: face on %q admits %s; the unnamed face admits everything, the AWS face nobody", action, g.Issuer, g.Admits)
			}
		}
	}
	anyone := oneGrant(t, statement(`"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject"`))
	if a, ok := findAnomaly(anyone, NotAnAssumeAction, "Action"); !anyone.Admits.IsEmpty() || !ok || a.Message != "the actions do not include sts:AssumeRole, so this statement lets nobody assume the role through this principal" {
		t.Errorf("anonymous principal without an assume action: %s, %+v", anyone.Admits, a)
	}
}

// TestNoStatementIsLostFromTheLoop: malformed, unprojectable and unknown
// statements all reach the Document and all project a grant. The brief's
// last line: not one continue or early return that discards a statement.
func TestNoStatementIsLostFromTheLoop(t *testing.T) {
	raw := `{"Version": "2012-10-17", "Statement": [
		5,
		{"Sid": "NoPrincipal", "Effect": "Allow", "Action": "sts:AssumeRole"},
		{"Sid": "UnknownMember", "Effect": "Allow", "Principal": {"Federated": "` + githubProvider + `"}, "Action": "sts:AssumeRoleWithWebIdentity", "Resource": "*"},
		{"Sid": "MalformedEffect", "Effect": "maybe", "Principal": {"Federated": "` + githubProvider + `"}, "Action": "sts:AssumeRoleWithWebIdentity"},
		{"Sid": "UnknownPrincipalKind", "Effect": "Allow", "Principal": {"Foo": "bar"}, "Action": "sts:AssumeRole"},
		{"Sid": "MisShapedPrincipal", "Effect": "Allow", "Principal": 5, "Action": "sts:AssumeRole"}
	]}`
	d := mustParse(t, raw)
	if len(d.Statements) != 6 {
		t.Fatalf("%d statements, want 6", len(d.Statements))
	}
	gs := d.Grants(role, vocabulary)
	if len(gs) != 6 {
		t.Fatalf("%d grants, want one per statement: %+v", len(gs), gs)
	}
	for _, g := range gs {
		if g.Admits.IsEmpty() {
			t.Errorf("a statement this parser cannot read admits everything, not nothing: %+v", g)
		}
	}
	number := d.Statements[0]
	if number.Effect != trust.EffectUnknown || string(number.Raw) != "5" {
		t.Errorf("a statement that is a number: effect %q, raw %q", number.Effect, number.Raw)
	}
	// A statement the parser cannot read at all has no issuer; a member it
	// does not model leaves the principal it did read in place, so the
	// reporter can still say whose grant is unconstrained.
	cases := []struct {
		sid    string
		issuer trust.IssuerRef
		want   string
	}{
		{"", "", "the statement is a number (5), not an object, so what it grants is not known"},
		{"NoPrincipal", "", "the statement names no Principal, so who may assume the role through it is not known"},
		{"UnknownMember", githubIssuer, `the statement member "Resource" is not one this parser models, so what it does to the statement is not known`},
		{"UnknownPrincipalKind", "", `the principal kind "Foo" is not AWS, Federated, Service or CanonicalUser, so who it names is not known`},
		{"MisShapedPrincipal", "", `Principal is a number (5), not "*" or an object, so who it names is not known`},
	}
	for _, c := range cases {
		matched := bySid(gs, c.sid)
		if c.sid == "" {
			matched = nil
			for _, g := range gs {
				if string(g.Source) == "5" {
					matched = append(matched, g)
				}
			}
		}
		if len(matched) != 1 {
			t.Errorf("%q: %d grants, want 1", c.sid, len(matched))
			continue
		}
		g := matched[0]
		if !slices.ContainsFunc(g.Anomalies, func(a trust.Anomaly) bool { return a.Message == c.want }) {
			t.Errorf("%q: anomalies %v lack %q", c.sid, g.Anomalies, c.want)
		}
		if g.Issuer != c.issuer || !g.Admits.IsTop() || g.Exact() || !hasCaveatOn(g, "") {
			t.Errorf("%q: issuer %q, admits %s, exact %v; want issuer %q, everything, declared", c.sid, g.Issuer, g.Admits, g.Exact(), c.issuer)
		}
	}
	malformed := bySid(gs, "MalformedEffect")
	if len(malformed) != 1 || malformed[0].Effect != trust.EffectUnknown || malformed[0].Issuer != githubIssuer || !malformed[0].Admits.IsTop() || !malformed[0].Exact() {
		t.Errorf("a malformed effect keeps its principal and its set: %+v", malformed)
	}
}

// TestRawIsTheCustomersBytes: Statement.Raw is exactly the statement's own
// text, escapes and formatting as written, and it is a copy, so a caller
// that reuses its buffer cannot rewrite the Document.
func TestRawIsTheCustomersBytes(t *testing.T) {
	raw := []byte("{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [ {\n    \"Sid\": \"\\u0041llow\",\n    \"Effect\": \"Allow\",\n    \"Principal\": { \"Federated\": \"" + githubProvider + "\" },\n    \"Action\": \"sts:AssumeRoleWithWebIdentity\"\n  } ,\n  {\"Effect\":\"Deny\",\"Principal\":\"*\",\"Action\":\"sts:AssumeRole\"} ]\n}\n")
	d, err := ParseTrustPolicy(raw)
	if err != nil {
		t.Fatalf("ParseTrustPolicy: %v", err)
	}
	if len(d.Statements) != 2 {
		t.Fatalf("%d statements, want 2", len(d.Statements))
	}
	first := string(d.Statements[0].Raw)
	if !strings.HasPrefix(first, "{\n    \"Sid\": \"\\u0041llow\"") || !strings.HasSuffix(first, "\"sts:AssumeRoleWithWebIdentity\"\n  }") {
		t.Errorf("Raw = %q; want the bytes from { to } with the escape as written", first)
	}
	if d.Statements[0].Sid != "Allow" {
		t.Errorf("Sid = %q; the text decodes even though Raw keeps the escape", d.Statements[0].Sid)
	}
	if got := string(d.Statements[1].Raw); got != `{"Effect":"Deny","Principal":"*","Action":"sts:AssumeRole"}` {
		t.Errorf("second Raw = %q", got)
	}
	gs := d.Grants(role, vocabulary)
	// Two statements, three grants: "*" is two faces.
	if len(gs) != 3 {
		t.Fatalf("%d grants", len(gs))
	}
	for _, g := range gs {
		if g.Target != role {
			t.Errorf("Target = %+v, want %+v", g.Target, role)
		}
		if !bytes.Equal(g.Source, d.Statements[0].Raw) && !bytes.Equal(g.Source, d.Statements[1].Raw) {
			t.Errorf("Source = %q is not a statement's Raw", g.Source)
		}
	}
	for i := range raw {
		raw[i] = 'X'
	}
	if string(d.Statements[1].Raw) != `{"Effect":"Deny","Principal":"*","Action":"sts:AssumeRole"}` {
		t.Errorf("mutating the caller's buffer changed Raw to %q", d.Statements[1].Raw)
	}
}

// TestDuplicateMembersAtThreeDepths: the same member twice at the top
// level, in a statement, and in a condition block. A decoder into a map
// would keep one and lose the fact; the fact is what matters, because the
// deployed policy may carry either.
func TestDuplicateMembersAtThreeDepths(t *testing.T) {
	raw := `{
	  "Version": "2012-10-17",
	  "Version": "2008-10-17",
	  "Statement": [{
	    "Effect": "Allow",
	    "Effect": "Deny",
	    "Principal": {"Federated": "` + githubProvider + `"},
	    "Action": "sts:AssumeRoleWithWebIdentity",
	    "Condition": {"StringEquals": {
	      "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
	      "token.actions.githubusercontent.com:sub": "` + mainBranch + `",
	      "token.actions.githubusercontent.com:sub": "` + devBranch + `"
	    }}
	  }],
	  "Statement": [{
	    "Effect": "Allow",
	    "Principal": {"Federated": "` + githubProvider + `"},
	    "Action": "sts:AssumeRoleWithWebIdentity"
	  }]
	}`
	d := mustParse(t, raw)
	if len(d.Statements) != 2 {
		t.Fatalf("%d statements; every statement of every Statement copy is kept", len(d.Statements))
	}
	wantDocument := []string{
		"the member Version appears more than once in the document; policy variables are read as unresolved",
		"the member Statement appears more than once in the document; every statement in every copy is kept",
	}
	for _, want := range wantDocument {
		if !slices.ContainsFunc(d.Anomalies, func(a trust.Anomaly) bool {
			return a.Kind == DuplicateKey && a.Message == want && a.Source == "document"
		}) {
			t.Errorf("document anomalies %v lack %q", d.Anomalies, want)
		}
	}
	if d.Statements[0].Effect != trust.EffectUnknown {
		t.Errorf("duplicate Effect: %q, want %q", d.Statements[0].Effect, trust.EffectUnknown)
	}
	gs := d.Grants(role, vocabulary)
	if len(gs) != 2 {
		t.Fatalf("%d grants", len(gs))
	}
	var first trust.Grant
	for _, g := range gs {
		if strings.Contains(string(g.Source), "Condition") {
			first = g
		}
	}
	if first.Effect != trust.EffectUnknown {
		t.Errorf("effect = %q", first.Effect)
	}
	a, ok := findAnomaly(first, DuplicateKey, "Effect")
	if !ok || a.Message != "the member Effect appears more than once in the statement; a JSON decoder keeps one and the deployed policy may carry either, so the effect is not known and is read as possibly Allow" || a.Source != "statement[0]" {
		t.Errorf("duplicate Effect anomaly = %+v, %v", a, ok)
	}
	if want := `{aud="sts.amazonaws.com", sub=?("duplicate key token.actions.githubusercontent.com:sub")}`; first.Admits.String() != want {
		t.Errorf("Admits = %s, want %s", first.Admits, want)
	}
	if !hasCaveatOn(first, "sub") {
		t.Errorf("sub is Unknown without a caveat: %v", first.Admits.Caveats())
	}
	a, ok = findAnomaly(first, DuplicateKey, "StringEquals")
	if !ok || a.Claim != "sub" || a.Message != `the key "token.actions.githubusercontent.com:sub" appears more than once under StringEquals; a JSON decoder keeps one and the deployed policy may carry either, so the claim is not constrained` {
		t.Errorf("duplicate key anomaly = %+v, %v", a, ok)
	}
}

func TestVersionIdAndUnknownMembers(t *testing.T) {
	d := mustParse(t, `{"Version": "2012-10-17", "Id": "policy-1", "Statement": []}`)
	if d.Version != "2012-10-17" || len(d.Statements) != 0 {
		t.Errorf("Version %q, %d statements", d.Version, len(d.Statements))
	}
	if !slices.ContainsFunc(d.Anomalies, func(a trust.Anomaly) bool {
		return a.Kind == Malformed && a.Message == "Statement is an empty list, so the document grants nothing"
	}) {
		t.Errorf("an empty Statement list is a fact worth stating; got %v", d.Anomalies)
	}
	cases := []struct {
		raw  string
		kind string
		want string
	}{
		{`{"Version": 1, "Statement": []}`, Malformed, "Version is a number (1), not a string; policy variables are read as unresolved"},
		{`{"Version": "2020-01-01", "Statement": []}`, Malformed, `Version "2020-01-01" is neither "2012-10-17" nor "2008-10-17"; policy variables are read as unresolved`},
		{`{"Id": 7, "Statement": []}`, Malformed, "Id is a number (7), not a string"},
		{`{"Id": "a", "Id": "b", "Statement": []}`, DuplicateKey, "the member Id appears more than once in the document"},
		{`{"Version": "2012-10-17"}`, Malformed, "the document has no Statement member; the IAM grammar requires one"},
	}
	for _, c := range cases {
		d := mustParse(t, c.raw)
		if !slices.ContainsFunc(d.Anomalies, func(a trust.Anomaly) bool { return a.Kind == c.kind && a.Message == c.want && a.Source == "document" }) {
			t.Errorf("%s: anomalies %v lack %s %q", c.raw, d.Anomalies, c.kind, c.want)
		}
	}
	// No Version at all is the documented older behaviour, not an anomaly.
	if d := mustParse(t, `{"Statement": []}`); len(d.Anomalies) != 1 {
		t.Errorf("a document without Version: %v; only the empty list is worth a word", d.Anomalies)
	}
	if d := mustParse(t, `{"Statement": [{"Sid": 5, "Effect": "Allow", "Principal": "*", "Action": "sts:AssumeRole"}]}`); !slices.ContainsFunc(d.Grants(role, vocabulary)[0].Anomalies, func(a trust.Anomaly) bool {
		return a.Kind == Malformed && a.Message == "Sid is a number (5), not a string" && a.Source == "statement[0].Sid"
	}) {
		t.Errorf("a mis-shaped Sid is noted: %v", d.Grants(role, vocabulary)[0].Anomalies)
	}
}

// renderGrants writes every field of every grant, Source strings and the
// customer's bytes included, so that two renderings can be compared byte
// for byte.
func renderGrants(gs []trust.Grant) string {
	var b strings.Builder
	for _, g := range gs {
		fmt.Fprintf(&b, "target %s %s\nissuer %s\neffect %s\nadmits %s\n", g.Target.Kind, g.Target.ID, g.Issuer, g.Effect, g.Admits)
		for _, c := range g.Admits.Caveats() {
			fmt.Fprintf(&b, "caveat %s|%s|%s\n", c.Claim, c.Reason, c.Source)
		}
		for _, a := range g.Anomalies {
			fmt.Fprintf(&b, "anomaly %s|%s|%s|%s|%s\n", a.Kind, a.Claim, a.Construct, a.Message, a.Source)
		}
		fmt.Fprintf(&b, "source %s\n\n", g.Source)
	}
	return b.String()
}

// TestDeterminism is the promise of docs/ENGINEERING.md section 2 at this
// layer: the same document parsed twice from fresh state renders the same
// grants byte for byte, Source strings and anomaly order included. The
// Makefile runs it twenty times in fresh processes, so a map iterated into
// output would be caught across runs as well as within one.
func TestDeterminism(t *testing.T) {
	entries, err := os.ReadDir(policiesDir)
	if err != nil {
		t.Fatalf("%v", err)
	}
	examined := 0
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		examined++
		raw, err := os.ReadFile(filepath.Join(policiesDir, e.Name()))
		if err != nil {
			t.Fatalf("%v", err)
		}
		first := renderGrants(mustParse(t, string(raw)).Grants(role, vocabulary))
		again := renderGrants(mustParse(t, string(raw)).Grants(role, vocabulary))
		if first != again {
			t.Errorf("%s rendered differently on a second parse:\n%s\n---\n%s", e.Name(), first, again)
		}
		if first == "" {
			t.Errorf("%s rendered no grants; the comparison examined nothing", e.Name())
		}
	}
	if examined != 24 {
		t.Fatalf("examined %d golden documents, want the twelve cases of the brief and the twelve QA added", examined)
	}
	t.Logf("examined %d golden documents twice each", examined)
}

// TestEveryAnomalyKindHasASentence pins, for every kind this parser emits,
// one document that produces it and the sentence a customer reads.
func TestEveryAnomalyKindHasASentence(t *testing.T) {
	cases := []struct {
		kind      string
		construct string
		raw       string
		want      string
	}{
		{trust.Unmodelled, "ForAllValues:StringLike", github(`{"ForAllValues:StringLike": {"token.actions.githubusercontent.com:sub": "repo:acme/*"}}`),
			"ForAllValues:StringLike on sub passes when the claim is absent, so it does not restrict what it looks like it restricts"},
		{DuplicateKey, "StringEquals", github(`{"StringEquals": {"token.actions.githubusercontent.com:sub": "a", "token.actions.githubusercontent.com:sub": "b"}}`),
			`the key "token.actions.githubusercontent.com:sub" appears more than once under StringEquals; a JSON decoder keeps one and the deployed policy may carry either, so the claim is not constrained`},
		{Malformed, "StringEquals", github(`{"StringEquals": {"token.actions.githubusercontent.com:sub": 123}}`),
			"StringEquals on sub has a value that is a number (123) where a string or a list of strings is expected, so the claim is not constrained"},
		{AnyPrincipal, "Principal", statement(`"Effect": "Allow", "Principal": "*", "Action": "sts:AssumeRole"`),
			"the statement applies to every principal, including anonymous ones"},
		{ServicePrincipal, "Service", statement(`"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"`),
			"lambda.amazonaws.com is an AWS service principal, not an external identity"},
		{NotAnAssumeAction, "Action", statement(`"Effect": "Allow", "Principal": {"Federated": "` + githubProvider + `"}, "Action": "sts:GetCallerIdentity"`),
			"the actions do not include sts:AssumeRoleWithWebIdentity, so this statement lets nobody assume the role through this principal"},
		{VariableIsLiteral, "${aws:username}", `{"Statement": [{"Effect": "Allow", "Principal": {"Federated": "` + githubProvider + `"}, "Action": "sts:AssumeRoleWithWebIdentity", "Condition": {"StringEquals": {"` + gh("sub") + `": "${aws:username}"}}}]}`,
			`the value "${aws:username}" on sub holds "${aws:username}", which is literal text because this document's Version does not resolve policy variables; if a variable was meant, the condition does not do what it looks like it does`},
	}
	seen := map[string]bool{}
	for _, c := range cases {
		gs := grantsOf(t, c.raw)
		if len(gs) == 0 {
			t.Fatalf("%s on %s: no grant", c.kind, c.construct)
		}
		// The sentence is on every face of the statement; the first will do.
		a, ok := findAnomaly(gs[0], c.kind, c.construct)
		if !ok {
			t.Errorf("%s on %s: no anomaly; got %v", c.kind, c.construct, gs[0].Anomalies)
			continue
		}
		seen[c.kind] = true
		if a.Message != c.want {
			t.Errorf("%s on %s: message %q, want %q", c.kind, c.construct, a.Message, c.want)
		}
		if !strings.HasSuffix(a.Message, ")") && strings.HasSuffix(a.Message, ".") {
			t.Errorf("%s: the sentence is printed inside a larger one and must not end with a full stop: %q", c.kind, a.Message)
		}
	}
	for _, kind := range []string{trust.Unmodelled, DuplicateKey, Malformed, AnyPrincipal, ServicePrincipal, NotAnAssumeAction, VariableIsLiteral} {
		if !seen[kind] {
			t.Errorf("kind %s has no sentence pinned here", kind)
		}
	}
}

// TestUnreadableStatementMemberIsAStatement: a Statement member that is
// neither an object nor a list is one unreadable statement, exactly as
// the same value inside brackets is. Dropping it left the document with
// zero grants and only a document anomaly, which the trust harness and
// every Grant consumer never see: a policy read as trusting nobody.
func TestUnreadableStatementMemberIsAStatement(t *testing.T) {
	cases := []struct {
		raw  string
		want string
	}{
		{`{"Version": "2012-10-17", "Statement": 5}`, "the statement is a number (5), not an object, so what it grants is not known"},
		{`{"Version": "2012-10-17", "Statement": "x"}`, `the statement is a string ("x"), not an object, so what it grants is not known`},
		{`{"Version": "2012-10-17", "Statement": null}`, "the statement is null (null), not an object, so what it grants is not known"},
		{`{"Version": "2012-10-17", "Statement": true}`, "the statement is a boolean (true), not an object, so what it grants is not known"},
		{`{"Version": "2012-10-17", "Statement": 5, "Statement": []}`, "the statement is a number (5), not an object, so what it grants is not known"},
	}
	for _, c := range cases {
		d := mustParse(t, c.raw)
		if len(d.Statements) != 1 || d.Statements[0].Effect != trust.EffectUnknown {
			t.Errorf("%s: statements %+v; want one, unreadable", c.raw, d.Statements)
			continue
		}
		g := oneGrant(t, c.raw)
		if g.Issuer != "" || g.Effect != trust.EffectUnknown || !g.Admits.IsTop() || g.Exact() || !hasCaveatOn(g, "") {
			t.Errorf("%s: issuer %q, effect %q, admits %s, exact %v; want no issuer, everything, declared", c.raw, g.Issuer, g.Effect, g.Admits, g.Exact())
		}
		if a, ok := findAnomaly(g, Malformed, "Statement"); !ok || a.Message != c.want || a.Source != "statement[0]" {
			t.Errorf("%s: anomaly = %+v, %v; want %q at statement[0]", c.raw, a, ok, c.want)
		}
		if slices.ContainsFunc(d.Anomalies, func(a trust.Anomaly) bool { return a.Message == c.want }) {
			t.Errorf("%s: the fact belongs on the grant, not on the document: %v", c.raw, d.Anomalies)
		}
	}
	// The same value inside brackets says the same thing.
	bracketed := oneGrant(t, `{"Version": "2012-10-17", "Statement": [5]}`)
	bare := oneGrant(t, `{"Version": "2012-10-17", "Statement": 5}`)
	if semanticOf(bracketed) != semanticOf(bare) || string(bare.Source) != "5" {
		t.Errorf("bracketed %+v, bare %+v; want the same grant with Raw 5", semanticOf(bracketed), semanticOf(bare))
	}
}

// TestUnrecognisedDocumentMemberIsAStatement: a top-level member the
// grammar does not define may be a misspelled Statement, and what it
// grants is not known. It projects one grant admitting everything,
// declared; reading the document as granting nothing was the silence the
// statement-level rule already refuses for the same class of member.
func TestUnrecognisedDocumentMemberIsAStatement(t *testing.T) {
	lower := `{"Version": "2012-10-17", "statement": [{"Effect": "Allow", "Principal": {"Federated": "` + githubProvider + `"}, "Action": "sts:AssumeRoleWithWebIdentity"}]}`
	d := mustParse(t, lower)
	if len(d.Statements) != 1 || !strings.HasPrefix(string(d.Statements[0].Raw), `[{"Effect"`) {
		t.Fatalf("statements = %+v; want the member's value as one statement", d.Statements)
	}
	g := oneGrant(t, lower)
	if g.Issuer != "" || g.Effect != trust.EffectUnknown || !g.Admits.IsTop() || g.Exact() || !hasCaveatOn(g, "") {
		t.Errorf("issuer %q, effect %q, admits %s, exact %v; want no issuer, everything, declared", g.Issuer, g.Effect, g.Admits, g.Exact())
	}
	want := `the document member "statement" is not one the IAM policy grammar defines, so what it grants is not known`
	if a, ok := findAnomaly(g, Malformed, "statement"); !ok || a.Message != want || a.Source != "statement[0]" {
		t.Errorf("anomaly = %+v, %v; want %q at statement[0]", a, ok, want)
	}
	for _, a := range d.Anomalies {
		if strings.Contains(a.Message, "grants nothing") {
			t.Errorf("the document asserts a conclusion about a member it did not read: %q", a.Message)
		}
	}
	// Beside a Statement the grammar defines, the unread member is one
	// more grant, in document order; the readable statement keeps its own.
	gs := grantsOf(t, `{"Statement": {"Effect": "Allow", "Principal": "*", "Action": "sts:AssumeRole"}, "Foo": 1, "Foo": 2}`)
	if len(gs) != 4 {
		t.Fatalf("%d grants, want the statement's two faces and one per copy of Foo", len(gs))
	}
	unread := 0
	for _, g := range gs {
		if a, ok := findAnomaly(g, Malformed, "Foo"); ok {
			unread++
			if a.Message != `the document member "Foo" is not one the IAM policy grammar defines, so what it grants is not known` || !g.Admits.IsTop() || g.Exact() {
				t.Errorf("unread member grant = %+v", g)
			}
		}
	}
	if unread != 2 {
		t.Errorf("%d unread-member grants, want 2", unread)
	}
	if d := mustParse(t, `{"Statement": [], "Foo": 1}`); len(d.Statements) != 1 || d.Statements[0].findings.anomalies[0].Source != "statement[0]" {
		t.Errorf("an unread member after an empty list is statement[0]: %+v", d.Statements)
	}
}

// TestSentencesQuoteNonASCIIVisibly: a sentence that quotes the customer's
// text must show a letter outside ASCII as its escape, or a lookalike
// letter prints identically to the one it resembles and the sentence
// contradicts itself: Effect is "Аllow" with a Cyrillic A read as "not
// Allow". The same goes for every value a sentence describes.
func TestSentencesQuoteNonASCIIVisibly(t *testing.T) {
	g := oneGrant(t, statement(`"Effect": "\u0410llow", "Principal": {"Federated": "`+githubProvider+`"}, "Action": "sts:AssumeRoleWithWebIdentity"`))
	if a, ok := findAnomaly(g, Malformed, "Effect"); !ok || a.Message != `Effect is "\u0410llow"; AWS accepts exactly "Allow" or "Deny", so the effect is not known and is read as possibly Allow` {
		t.Errorf("anomaly = %+v, %v", a, ok)
	}
	// describe quotes the source bytes, escapes as written and letters
	// outside ASCII as escapes.
	g = oneGrant(t, statement(`"Effect": ["\u0410llow", "Deny"], "Principal": {"Federated": "`+githubProvider+`"}, "Action": "sts:AssumeRoleWithWebIdentity"`))
	if a, ok := findAnomaly(g, Malformed, "Effect"); !ok || a.Message != `Effect is a list (["\u0410llow", "Deny"]), not a string, so the effect is not known and is read as possibly Allow` {
		t.Errorf("anomaly = %+v, %v", a, ok)
	}
	g = oneGrant(t, statement(`"Effect": ["Аllow"], "Principal": {"Federated": "`+githubProvider+`"}, "Action": "sts:AssumeRoleWithWebIdentity"`))
	if a, ok := findAnomaly(g, Malformed, "Effect"); !ok || a.Message != `Effect is a list (["\u0410llow"]), not a string, so the effect is not known and is read as possibly Allow` {
		t.Errorf("raw letter in the source: anomaly = %+v, %v", a, ok)
	}
	for _, a := range g.Anomalies {
		for _, r := range a.Message {
			if r > 0x7e {
				t.Errorf("sentence carries a raw non-ASCII rune %q: %q", r, a.Message)
			}
		}
	}
}
