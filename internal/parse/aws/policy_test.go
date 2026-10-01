package aws

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"unicode/utf16"
	"unicode/utf8"

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

// policiesDir holds the golden documents, one per case of AWS's policy
// semantics that changes an answer when it is read wrongly, each beside
// the rationale that cites the AWS sentence making its expected answer
// correct.
const policiesDir = "../../../testdata/policies"

var role = trust.TargetRef{Kind: "role", ID: "arn:aws:iam::123456789012:role/deploy"}

type token = map[trust.ClaimKey]string

// vocabulary knows GitHub's claims, spelled as the tests write them; the
// command's comes from the census, through the registry.
var vocabulary = LowercaseVocabulary(githubIssuer)

func mustParse(t *testing.T, raw string) Document {
	t.Helper()
	d, err := ParseTrustPolicy([]byte(asAWSHoldsIt(raw)))
	if err != nil {
		t.Fatalf("ParseTrustPolicy: %v", err)
	}
	return d
}

// asAWSHoldsIt is raw with every character above U+00FF written as its JSON
// escape, the only form in which a policy document carries one: AWS refuses
// a document holding such a character as itself
// (TestADocumentHoldingACharacterAWSRefusesIsRefused). A test that writes
// the character inside a string means the document holding its escape,
// which decodes to it. A byte that is not UTF-8 is kept as it is.
func asAWSHoldsIt(raw string) string {
	var b strings.Builder
	for i := 0; i < len(raw); {
		r, size := utf8.DecodeRuneInString(raw[i:])
		switch {
		case r == utf8.RuneError && size == 1, r <= 0xff:
			b.WriteString(raw[i : i+size])
		default:
			for _, unit := range utf16.Encode([]rune{r}) {
				fmt.Fprintf(&b, `\u%04x`, unit)
			}
		}
		i += size
	}
	return b.String()
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
		{"byte order mark", "\xEF\xBB\xBF{}", "U+FEFF at byte 0"},
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

// TestADocumentHoldingACharacterAWSRefusesIsRefused: "Policy documents can
// contain only the following Unicode characters: horizontal tab (U+0009),
// linefeed (U+000A), carriage return (U+000D), and characters in the range
// U+0020 to U+00FF."
// (https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_iam-quotas.html),
// and CreateRole validates the document it is given, "a JSON policy that has
// been converted to a string", against [\u0009\u000A\u000D -ÿ]+
// (https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreateRole.html).
// A document holding any other character is one AWS refuses, so the parser
// refuses it, naming the character and its byte, and reads it as admitting
// neither anyone nor no one. The rule is on the characters written: the
// escape ﬅ is six of them, each in range, and the letter it stands for
// is read as what it may fold to. What is wrong first, in reading order, is
// what is named: a byte that is not UTF-8 before the character, or the
// character before such a byte.
func TestADocumentHoldingACharacterAWSRefusesIsRefused(t *testing.T) {
	const words = " is a character AWS refuses in a policy document, which may hold only tab, line feed, carriage return and U+0020 to U+00FF"
	refused := []struct{ raw, character string }{
		{statement(`"Effect": "Allow", "Principal": "*", "Action": "` + "\ufb05" + `s:AssumeRole"`), "\ufb05"},
		{statement(`"Effect": "Allow", "Principal": "*", "Action": "` + "\ufb06" + `s:AssumeRole"`), "\ufb06"},
		{statement(`"Effect": "Allow", "Principal": {"Federated": "to` + "\u212a" + `en.actions.githubusercontent.com"}, "Action": "sts:AssumeRoleWithWebIdentity"`), "\u212a"},
		{statement(`"Effect": "Allow", "Principal": "*", "Action": "sts:AssumeRole", "Condition": {"StringEquals": {"aws:` + "\u017f" + `ourceAccount": "1"}}`), "\u017f"},
		{statement(`"Sid": "` + "\u4e2d" + `", "Effect": "Allow", "Principal": "*", "Action": "sts:AssumeRole"`), "\u4e2d"},
		{statement(`"Sid": "` + "\U0001f600" + `", "Effect": "Allow", "Principal": "*", "Action": "sts:AssumeRole"`), "\U0001f600"},
		{statement(`"Sid": "` + "\ufffd" + `", "Effect": "Allow", "Principal": "*", "Action": "sts:AssumeRole"`), "\ufffd"},
		{"\ufeff" + statement(`"Effect": "Allow", "Principal": "*", "Action": "sts:AssumeRole"`), "\ufeff"},
		{statement(`"Effect": "Allow",` + "\v" + `"Principal": "*", "Action": "sts:AssumeRole"`), "\v"},
		{statement(`"Effect": "Allow",` + "\f" + `"Principal": "*", "Action": "sts:AssumeRole"`), "\f"},
		{statement(`"Sid": "` + "\ufb05\xff" + `", "Effect": "Allow", "Principal": "*", "Action": "sts:AssumeRole"`), "\ufb05"},
	}
	for _, c := range refused {
		at := strings.Index(c.raw, c.character)
		want := "parse trust policy: " + fmt.Sprintf("%U at byte %d", []rune(c.character)[0], at) + words
		if d, err := ParseTrustPolicy([]byte(c.raw)); err == nil || err.Error() != want {
			t.Errorf("%+q: %v, %+v; want %q", c.raw, err, d, want)
		}
	}
	notUTF8First := statement(`"Sid": "` + "\xff\ufb05" + `", "Effect": "Allow", "Principal": "*", "Action": "sts:AssumeRole"`)
	if _, err := ParseTrustPolicy([]byte(notUTF8First)); err == nil || !strings.Contains(err.Error(), "not valid UTF-8 at byte") {
		t.Errorf("a byte that is not UTF-8 before the character is named first: %v", err)
	}
	for _, raw := range []string{
		statement(`"Sid": "Caf` + "\u00e9 \u00a0\u0080\u00ff" + `", "Effect": "Allow", "Principal": "*", "Action": "sts:AssumeRole"`),
		statement("\t\"Effect\": \"Allow\",\r\n\"Principal\": \"*\", \"Action\": \"sts:AssumeRole\""),
		statement(`"Effect": "Allow", "Principal": "*", "Action": "\ufb05s:AssumeRole"`),
		statement(`"Sid": "\u4e2d\ud83d\ude00", "Effect": "Allow", "Principal": "*", "Action": "sts:AssumeRole"`),
	} {
		if _, err := ParseTrustPolicy([]byte(raw)); err != nil {
			t.Errorf("%+q holds only characters AWS accepts: %v", raw, err)
		}
	}
	escaped := awsFace(t, statement(`"Effect": "Allow", "Principal": "*", "Action": "\ufb05s:AssumeRole"`))
	if !escaped.Admits.IsTop() || escaped.Exact() {
		t.Errorf("an escaped ligature is read as what it may fold to, st: %s, exact %v", escaped.Admits, escaped.Exact())
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

// Case 11: every principal shape in the document projects a grant; none is
// dropped, because a principal that exists and produces no grant is a
// trust no reader of the answer ever sees.
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
	if a, ok := findAnomaly(service[0], ServicePrincipal, "Service"); !ok || a.Message != "ec2.amazonaws.com is an AWS service principal; who can make it act, or receives its session, is not read" {
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

// caseImagesInASCII is every code point outside ASCII that a case mapping
// in Unicode 17.0.0 turns into ASCII text, beside that text lower-cased:
// the simple mappings of UnicodeData.txt, the full ones of
// SpecialCasing.txt under every condition, and every status of
// CaseFolding.txt, read 2026-09-23 from
// https://www.unicode.org/Public/17.0.0/ucd/. Java's String and Character
// case methods, in the root, Turkish, Azeri and Lithuanian locales, turn
// the same thirteen into ASCII and no other code point (JDK 21.0.4 and
// 23.0.1, every code point tried).
var caseImagesInASCII = []struct {
	letter rune
	image  string
}{
	{'\u00df', "ss"},  // LATIN SMALL LETTER SHARP S
	{'\u0130', "i"},   // LATIN CAPITAL LETTER I WITH DOT ABOVE
	{'\u0131', "i"},   // LATIN SMALL LETTER DOTLESS I
	{'\u017f', "s"},   // LATIN SMALL LETTER LONG S
	{'\u1e9e', "ss"},  // LATIN CAPITAL LETTER SHARP S
	{'\u212a', "k"},   // KELVIN SIGN
	{'\ufb00', "ff"},  // LATIN SMALL LIGATURE FF
	{'\ufb01', "fi"},  // LATIN SMALL LIGATURE FI
	{'\ufb02', "fl"},  // LATIN SMALL LIGATURE FL
	{'\ufb03', "ffi"}, // LATIN SMALL LIGATURE FFI
	{'\ufb04', "ffl"}, // LATIN SMALL LIGATURE FFL
	{'\ufb05', "st"},  // LATIN SMALL LIGATURE LONG S T
	{'\ufb06', "st"},  // LATIN SMALL LIGATURE ST
}

// respelling is an ASCII action with one run of its letters written as a
// code point whose case mapping gives them, that code point, and how many
// letters it stands for.
type respelling struct {
	text    string
	letter  rune
	letters int
}

// respellingsOf is every respelling of an ASCII action.
func respellingsOf(action string) []respelling {
	folded := strings.ToLower(action)
	var out []respelling
	for _, c := range caseImagesInASCII {
		for i := 0; i+len(c.image) <= len(folded); i++ {
			if folded[i:i+len(c.image)] == c.image {
				out = append(out, respelling{action[:i] + string(c.letter) + action[i+len(c.image):], c.letter, len(c.image)})
			}
		}
	}
	return out
}

// foldingSentence is what the parser says of a grant that its statement
// may make only through an action it cannot place.
func foldingSentence(action, names string) string {
	return "the action " + strconv.QuoteToASCII(action) + " holds a letter outside ASCII with case variants of its own; AWS documents no folding for it, so whether it names " + names + " is not known"
}

// grantsByIssuer keys a document's grants by issuer, which tells the two
// faces of one "*" apart.
func grantsByIssuer(t *testing.T, raw string) map[trust.IssuerRef]trust.Grant {
	t.Helper()
	out := map[trust.IssuerRef]trust.Grant{}
	for _, g := range grantsOf(t, raw) {
		if _, twice := out[g.Issuer]; twice {
			t.Fatalf("%s: two grants on %q", raw, g.Issuer)
		}
		out[g.Issuer] = g
	}
	return out
}

// TestARespelledActionIsReadAsWhatItMayBe: AWS matches action names
// regardless of case, "The prefix and the action name are case
// insensitive."
// (https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_action.html),
// and documents no folding for a letter outside ASCII, so an action with a
// run of its letters written as a code point whose case mapping gives them
// may be that action. Where the ASCII spelling lets a principal in, so does
// the respelling, as an upper bound: the same set, declared, and one
// sentence more, saying why. Where the ASCII spelling lets nobody in, so
// does the respelling, exactly, since no case mapping makes it the
// principal's assume action. Reading the letter as itself had put every
// respelled assume action beyond every principal, nobody, exactly, for
// statements Java's equalsIgnoreCase reads as the ASCII ones. Every
// respelling of the three assume actions and of sts:TagSession is tried
// on every kind of principal, "*" with both its faces, and the counts show
// both outcomes were reached through letters that give one letter and
// letters that give two. A letter above U+00FF is read as the document
// carries it, as its JSON escape: written as itself it is a character AWS
// refuses in a policy document, and that document is refused, naming it.
func TestARespelledActionIsReadAsWhatItMayBe(t *testing.T) {
	principals := []struct{ principal, condition string }{
		{`"*"`, ""},
		{`{"AWS": "111122223333"}`, ""},
		{`{"AWS": "arn:aws:iam::111122223333:role/deploy"}`, ""},
		{`{"Service": "ec2.amazonaws.com"}`, ""},
		{`{"Federated": "` + githubProvider + `"}`, `, "Condition": {"StringLike": {"` + gh("sub") + `": "repo:acme/*"}}`},
		{`{"Federated": "cognito-identity.amazonaws.com"}`, ""},
		{`{"Federated": "` + samlProvider + `"}`, ""},
	}
	type outcome struct {
		admits     bool
		twoLetters bool
	}
	counts := map[outcome]int{}
	for _, p := range principals {
		document := func(action string) string {
			return statement(`"Effect": "Allow", "Principal": ` + p.principal + `, "Action": "` + action + `"` + p.condition)
		}
		for _, action := range []string{"sts:AssumeRole", "sts:AssumeRoleWithWebIdentity", "sts:AssumeRoleWithSAML", "sts:TagSession"} {
			ascii := grantsByIssuer(t, document(action))
			for _, r := range respellingsOf(action) {
				if _, err := ParseTrustPolicy([]byte(document(r.text))); r.letter > 0xff && (err == nil || !strings.Contains(err.Error(), fmt.Sprintf("%U at byte", r.letter))) {
					t.Errorf("%s: %v; AWS refuses the letter written as itself", document(r.text), err)
				}
				respelled := grantsByIssuer(t, document(r.text))
				if len(respelled) != len(ascii) {
					t.Errorf("%s: %d grants, and %d for %s", document(r.text), len(respelled), len(ascii), action)
				}
				for issuer, want := range ascii {
					got, ok := respelled[issuer]
					if !ok {
						t.Errorf("%s: no grant on %q, which %s has", document(r.text), issuer, action)
						continue
					}
					o := outcome{!want.Admits.IsEmpty(), r.letters > 1}
					counts[o]++
					if !o.admits {
						if !got.Admits.IsEmpty() || !got.Exact() || !slices.Equal(got.Anomalies, want.Anomalies) {
							t.Errorf("%s on %q: %s lets nobody in, and %q admits %s, exact %v, anomalies %v", p.principal, issuer, action, r.text, got.Admits, got.Exact(), got.Anomalies)
						}
						continue
					}
					doubt := trust.Anomaly{Kind: trust.Unmodelled, Construct: "Action", Message: foldingSentence(r.text, action), Source: "statement[0].Action"}
					if got.Admits.String() != want.Admits.String() || got.Exact() || !hasCaveatOn(got, "") || !slices.Equal(got.Anomalies, append(slices.Clone(want.Anomalies), doubt)) {
						t.Errorf("%s on %q: %s admits %s, exact %v; %q admits %s, exact %v, caveats %v, anomalies %v", p.principal, issuer, action, want.Admits, want.Exact(), r.text, got.Admits, got.Exact(), got.Admits.Caveats(), got.Anomalies)
					}
				}
			}
		}
	}
	for _, o := range []outcome{{true, false}, {true, true}, {false, false}, {false, true}} {
		if counts[o] == 0 {
			t.Fatalf("no respelled grant %+v (counts %v); the reading was not examined on it", o, counts)
		}
	}
	t.Logf("respelled grants by outcome: %v", counts)
}

// TestAnActionBeyondASCIIDoubtsOnlyWhatItMayName pins the edges of that
// reading. A respelled action ending in a wildcard may name every assume
// action, and each face of "*" names those it assumes through; a letter
// with no case of its own is read as itself, since no case mapping gives
// it anything; an ASCII spelling beside a respelled one settles the
// question, and the grant is exact; one action written twice is one
// sentence; and a Deny whose action may be the assume action is not
// applied, because applying it would refuse more than the policy may.
func TestAnActionBeyondASCIIDoubtsOnlyWhatItMayName(t *testing.T) {
	const wide = longS + "ts:AssumeRole*"
	faces := grantsByIssuer(t, statement(`"Effect": "Allow", "Principal": "*", "Action": "`+wide+`"`))
	for issuer, names := range map[trust.IssuerRef]string{
		AWSPrincipalIssuer: "sts:AssumeRole",
		"":                 "sts:AssumeRole, sts:AssumeRoleWithWebIdentity or sts:AssumeRoleWithSAML",
	} {
		g, ok := faces[issuer]
		if !ok || !g.Admits.IsTop() || g.Exact() {
			t.Fatalf("the face on %q: %+v, %v; want everything, declared", issuer, g, ok)
		}
		if a, ok := findAnomaly(g, trust.Unmodelled, "Action"); !ok || a.Message != foldingSentence(wide, names) || a.Source != "statement[0].Action" || a.Claim != "" {
			t.Errorf("the face on %q: anomaly %+v, %v", issuer, a, ok)
		}
	}
	if a, ok := findAnomaly(faces[""], trust.Unmodelled, "Principal"); !ok || a.Message != "the statement applies to every principal, and which AWS services and identity providers' tokens it covers through sts:AssumeRole, sts:AssumeRoleWithWebIdentity or sts:AssumeRoleWithSAML is not known" {
		t.Errorf("the face of \"*\" with no issuer: %+v, %v", a, ok)
	}
	account := func(action string) trust.Grant {
		return oneGrant(t, statement(`"Effect": "Allow", "Principal": {"AWS": "111122223333"}, "Action": `+action))
	}
	for _, action := range []string{`"sts:AssumeRole` + cjk + `"`, `"sts:Assume` + cjk + `Role"`} {
		if g := account(action); !g.Admits.IsEmpty() || !g.Exact() {
			t.Errorf("%s: a letter with no case is read as itself, and names no assume action; got %s, exact %v", action, g.Admits, g.Exact())
		}
	}
	beside := account(`["sts:A` + longS + `sumeRole", "sts:AssumeRole"]`)
	if _, doubted := findAnomaly(beside, trust.Unmodelled, "Action"); beside.Admits.String() != `{aws:principalaccount="111122223333"}` || !beside.Exact() || doubted {
		t.Errorf("sts:AssumeRole beside a respelling: %s, exact %v, %v; the ASCII spelling settles it", beside.Admits, beside.Exact(), beside.Anomalies)
	}
	twice := account(`["sts:A` + longS + `sumeRole", "sts:A` + longS + `sumeRole"]`)
	if doubts := slices.DeleteFunc(slices.Clone(twice.Anomalies), func(a trust.Anomaly) bool { return a.Construct != "Action" }); len(doubts) != 1 || twice.Exact() {
		t.Errorf("a respelling written twice: exact %v, %v; want one sentence, declared", twice.Exact(), twice.Anomalies)
	}
	deny := oneGrant(t, statement(`"Effect": "Deny", "Principal": {"AWS": "111122223333"}, "Action": "sts:A`+longS+`sumeRole"`))
	_, doubted := findAnomaly(deny, trust.Unmodelled, "Action")
	_, notApplied := findAnomaly(deny, trust.Unmodelled, "Deny")
	if !deny.Admits.IsEmpty() || deny.Exact() || !doubted || !notApplied {
		t.Errorf("a Deny whose action may be sts:AssumeRole: %s, exact %v, %v; want nothing refused, declared, and why", deny.Admits, deny.Exact(), deny.Anomalies)
	}
}

// TestNoStatementIsLostFromTheLoop: malformed, unprojectable and unknown
// statements all reach the Document and all project a grant: not one
// continue or early return discards a statement.
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

// TestRawIsTheStatementsOwnBytes: Statement.Raw is exactly the statement's own
// text, escapes and formatting as written, and it is a copy, so a caller
// that reuses its buffer cannot rewrite the Document.
func TestRawIsTheStatementsOwnBytes(t *testing.T) {
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

// TestTheCopyIsTheDocumentsLength: the one copy of the input a Document
// keeps holds the input and nothing past it. A copy appended onto an empty
// slice is as long as the allocator rounds it: to a size class here, and in
// the WebAssembly engine to the next power of two, where a 28,480-byte
// document took a 32 KiB block on every call and the collector, finding no
// room for one, doubled linear memory. Every Raw slices the copy, so from
// where the last statement starts its capacity reaches the copy's end.
func TestTheCopyIsTheDocumentsLength(t *testing.T) {
	for _, statements := range []int{1, 5, 50} {
		var doc strings.Builder
		doc.WriteString(`{"Version":"2012-10-17","Statement":[`)
		for i := range statements {
			if i > 0 {
				doc.WriteString(",")
			}
			doc.WriteString(`{"Sid":"S` + strconv.Itoa(i) + `","Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:root"},"Action":"sts:AssumeRole"}`)
		}
		doc.WriteString("]}")
		raw := []byte(doc.String())
		d, err := ParseTrustPolicy(raw)
		if err != nil {
			t.Fatalf("%d statements: %v", statements, err)
		}
		last := d.Statements[len(d.Statements)-1].Raw
		if held := bytes.LastIndex(raw, last) + cap(last); held != len(raw) {
			t.Errorf("%d statements: the copy of a %d-byte document holds %d bytes", statements, len(raw), held)
		}
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
// user's bytes included, so that two renderings can be compared byte
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

// TestDeterminism holds identical input to identical bytes at this
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
		t.Fatalf("examined %d golden documents, want the 24 under testdata/policies", examined)
	}
	t.Logf("examined %d golden documents twice each", examined)
}

// TestAServiceSaysWhoItActsFor: a service the table of intermediaries
// lists, which AWS documents as assuming a role for identities outside IAM
// and passing them its session or acting with it for them, says so in its
// note, and that who they are is not read; one whose row records other uses
// names that use as one among others and says who can make it act is not
// read; any other service says what is not read in words true of every
// service. No note says a service is not an outside identity: IAM Roles
// Anywhere hands a role's session to whoever holds a certificate its trust
// anchor accepts.
// The note is the principal's, carried by every grant it projects, a Deny's
// and one whose statement grants no assume action among them, so it speaks
// of a role the service can assume and never of this one. A service is
// found in whatever case it is written, since a service principal is a DNS
// name, and named as written.
func TestAServiceSaysWhoItActsFor(t *testing.T) {
	const neutral = " is an AWS service principal; who can make it act, or receives its session, is not read"
	cases := []struct{ service, want string }{
		{"rolesanywhere.amazonaws.com", "rolesanywhere.amazonaws.com can assume a role for workloads that hold a certificate a trust anchor in the account accepts, and pass them its session; who they are is not read"},
		{"credentials.iot.amazonaws.com", "credentials.iot.amazonaws.com can assume a role for devices that present an X.509 certificate AWS IoT accepts, and pass them its session; who they are is not read"},
		{"ssm.amazonaws.com", "ssm.amazonaws.com can assume a role for machines registered by a hybrid activation, and pass them its session, among other uses; who can make it act, or receives its session, is not read"},
		{"pods.eks.amazonaws.com", "pods.eks.amazonaws.com can assume a role for the pods of an EKS cluster in the account whose service account is associated with it, and pass them its session; who they are is not read"},
		{"transfer.amazonaws.com", "transfer.amazonaws.com can assume a role for the users of a Transfer Family server, and act with its session for them, among other uses; who can make it act, or receives its session, is not read"},
		{"RolesAnywhere.amazonaws.com", "RolesAnywhere.amazonaws.com can assume a role for workloads that hold a certificate a trust anchor in the account accepts, and pass them its session; who they are is not read"},
		{"sns.amazonaws.com", "sns.amazonaws.com" + neutral},
		{"EC2.amazonaws.com", "EC2.amazonaws.com" + neutral},
	}
	for _, c := range cases {
		for _, statementOf := range []string{
			`"Effect": "Allow", "Principal": {"Service": "` + c.service + `"}, "Action": "sts:AssumeRole"`,
			`"Effect": "Deny", "Principal": {"Service": "` + c.service + `"}, "Action": "sts:AssumeRole"`,
			`"Effect": "Allow", "Principal": {"Service": "` + c.service + `"}, "Action": "sts:TagSession"`,
		} {
			g := oneGrant(t, statement(statementOf))
			a, ok := findAnomaly(g, ServicePrincipal, "Service")
			if !ok || a.Message != c.want {
				t.Errorf("%s: note %q, %v; want %q", statementOf, a.Message, ok, c.want)
			}
			if strings.Contains(a.Message, "external identity") || strings.Contains(a.Message, "outside identity") || strings.Contains(a.Message, "this role") {
				t.Errorf("%s: the note %q says a service is not an outside identity, or speaks of this role", statementOf, a.Message)
			}
		}
	}
}

// TestEveryAnomalyKindHasASentence pins, for every kind this parser emits,
// one document that produces it and the sentence a user reads.
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
			"lambda.amazonaws.com is an AWS service principal; who can make it act, or receives its session, is not read"},
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
// zero grants and only a document anomaly, which the conformance suite
// and every Grant consumer never see: a policy read as trusting nobody.
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

// TestSentencesQuoteNonASCIIVisibly: a sentence that quotes the user's
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
	// A letter outside ASCII that AWS accepts written as itself, a Latin-1
	// one, is escaped by describe too; a letter beyond U+00FF can reach a
	// policy only as its escape.
	g = oneGrant(t, statement(`"Effect": ["Àllow"], "Principal": {"Federated": "`+githubProvider+`"}, "Action": "sts:AssumeRoleWithWebIdentity"`))
	if a, ok := findAnomaly(g, Malformed, "Effect"); !ok || a.Message != `Effect is a list (["\u00c0llow"]), not a string, so the effect is not known and is read as possibly Allow` {
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
