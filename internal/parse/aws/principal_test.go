package aws

import (
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"pgregory.net/rapid"

	"github.com/CloudArq-net/cloudarq/internal/eval"
	"github.com/CloudArq-net/cloudarq/internal/trust"
)

const samlProvider = "arn:aws:iam::111122223333:saml-provider/VendorSSO"

// TestIsSAMLIssuer: an issuer is a SAML provider's exactly when it is the
// IAM ARN of one. An OIDC provider's ARN, an STS ARN, a role whose path
// says saml-provider, and every issuer the parser spells otherwise are not.
func TestIsSAMLIssuer(t *testing.T) {
	cases := []struct {
		issuer trust.IssuerRef
		want   bool
	}{
		{samlProvider, true},
		{"arn:aws-cn:iam::111122223333:saml-provider/ExampleOrgSSOProvider", true},
		{"arn:aws-us-gov:iam::111122223333:saml-provider/x", true},
		{"arn:aws:iam::111122223333:oidc-provider/token.actions.githubusercontent.com", false},
		{"arn:aws:sts::111122223333:saml-provider/x", false},
		{"arn:aws:iam::111122223333:saml-provider", false},
		{"arn:aws:iam::111122223333:role/saml-provider/x", false},
		{"ARN:aws:iam::111122223333:saml-provider/x", false},
		{"saml-provider/x", false},
		{"https://token.actions.githubusercontent.com", false},
		{AWSPrincipalIssuer, false},
		{ServiceIssuerPrefix + "sns.amazonaws.com", false},
		{"", false},
	}
	for _, c := range cases {
		if got := IsSAMLIssuer(c.issuer); got != c.want {
			t.Errorf("IsSAMLIssuer(%q) = %v, want %v", c.issuer, got, c.want)
		}
	}
}

// federatesSAML reports whether the parser read the grant's principal as a
// SAML provider, by the sentence it wrote for one. Tests may read the
// parser's sentences; the classifier may not, which is why the predicate
// exists.
func federatesSAML(g trust.Grant) bool {
	return slices.ContainsFunc(g.Anomalies, func(a trust.Anomaly) bool {
		return a.Kind == trust.Unmodelled && a.Construct == "SAML" && strings.HasPrefix(a.Message, "SAML federation through ")
	})
}

// TestIsSAMLIssuerIsTheParsersOwnReading: over every golden document and a
// set of principals written every way the Federated element takes one, a
// grant's issuer satisfies IsSAMLIssuer exactly when the parser read its
// principal as a SAML provider. A predicate that drifted from the parser
// would put a SAML trust in a ring, or an OIDC trust among the unread.
func TestIsSAMLIssuerIsTheParsersOwnReading(t *testing.T) {
	var documents []string
	entries, err := os.ReadDir(policiesDir)
	if err != nil {
		t.Fatalf("%v", err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".json") {
			raw, err := os.ReadFile(filepath.Join(policiesDir, e.Name()))
			if err != nil {
				t.Fatalf("%v", err)
			}
			documents = append(documents, string(raw))
		}
	}
	for _, federated := range []string{
		samlProvider,
		"arn:aws-cn:iam::111122223333:saml-provider/x",
		"arn:aws:iam::111122223333:saml-provider",
		"arn:aws:sts::111122223333:saml-provider/x",
		"ARN:aws:iam::111122223333:saml-provider/x",
		githubProvider,
		"accounts.google.com",
		"cognito-identity.amazonaws.com",
	} {
		documents = append(documents, statement(`"Effect": "Allow", "Principal": {"Federated": "`+federated+`"}, "Action": ["sts:AssumeRoleWithSAML", "sts:AssumeRoleWithWebIdentity"]`))
	}
	saml, other := 0, 0
	for _, raw := range documents {
		for _, g := range grantsOf(t, raw) {
			if IsSAMLIssuer(g.Issuer) != federatesSAML(g) {
				t.Errorf("issuer %q: IsSAMLIssuer = %v, the parser read a SAML provider: %v", g.Issuer, IsSAMLIssuer(g.Issuer), federatesSAML(g))
			}
			if federatesSAML(g) {
				saml++
			} else {
				other++
			}
		}
	}
	if saml < 2 || other == 0 {
		t.Fatalf("saml=%d other=%d; the comparison must meet SAML grants in two partitions and grants of other kinds", saml, other)
	}
	t.Logf("saml=%d other=%d over %d documents", saml, other, len(documents))
}

// TestIssuerlessPopulation pins, for every way a statement can project a
// grant with no issuer, who that grant stands for. "*" on sts:AssumeRole
// written out in full is every AWS service; on sts:AssumeRoleWithSAML, the
// role's own account's SAML providers; on both, both; and whatever else the
// statement says beside its principal and its actions leaves that answer
// alone. Everything else is every issuer: web identity, a wildcard, actions
// the parser could not read or a spelling it cannot place, and any
// principal it could not read, beside "*" or not.
func TestIssuerlessPopulation(t *testing.T) {
	anyone := func(rest string) string { return statement(`"Effect": "Allow", "Principal": "*", ` + rest) }
	cases := []struct {
		name string
		raw  string
		want Population
	}{
		{"sts:AssumeRole", anyone(`"Action": "sts:AssumeRole"`), AWSServices},
		{"AWS \"*\" on sts:AssumeRole", statement(`"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "sts:AssumeRole"`), AWSServices},
		{"sts:AssumeRole beside actions that assume nothing", anyone(`"Action": ["sts:AssumeRole", "sts:TagSession", "sts:SetSourceIdentity"]`), AWSServices},
		{"sts:AssumeRole in another case", anyone(`"Action": "STS:AssumeROLE"`), AWSServices},
		{"a Deny", statement(`"Effect": "Deny", "Principal": "*", "Action": "sts:AssumeRole"`), AWSServices},
		{"an organisation condition", anyone(`"Action": "sts:AssumeRole", "Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-a1b2c3d4e5"}}`), AWSServices},
		{"a principal read beside \"*\"", statement(`"Effect": "Allow", "Principal": {"AWS": "*", "Federated": "` + samlProvider + `"}, "Action": "sts:AssumeRoleWithSAML"`), AccountSAMLProviders},
		{"an unmodelled principal on the AWS issuer beside \"*\"", statement(`"Effect": "Allow", "Principal": {"AWS": "*", "CanonicalUser": "79a59df900b949e55d96a1e698fbaced"}, "Action": "sts:AssumeRole"`), AWSServices},
		{"sts:AssumeRoleWithSAML", anyone(`"Action": "sts:AssumeRoleWithSAML"`), AccountSAMLProviders},
		{"sts:AssumeRole and sts:AssumeRoleWithSAML", anyone(`"Action": ["sts:AssumeRole", "sts:AssumeRoleWithSAML"]`), AWSServicesAndAccountSAMLProviders},
		{"a letter outside ASCII with no case of its own", anyone(`"Action": ["sts:AssumeRole", "s3:Get中"]`), AWSServices},

		// A condition only narrows, and no member but Action or NotAction
		// is an action block, so what the parser could not read beside them
		// leaves the population where the actions put it.
		{"a member the parser does not read", anyone(`"Action": "sts:AssumeRole", "Resource": "*"`), AWSServices},
		{"a member spelled like Action", anyone(`"Action": "sts:AssumeRole", "action": "sts:AssumeRoleWithWebIdentity"`), AWSServices},
		{"a Condition that is not an object", anyone(`"Action": "sts:AssumeRole", "Condition": "x"`), AWSServices},
		{"an operator block that is not an object", anyone(`"Action": "sts:AssumeRole", "Condition": {"StringEquals": "x"}`), AWSServices},
		{"Condition written twice", anyone(`"Action": "sts:AssumeRole", "Condition": {}, "Condition": {}`), AWSServices},
		{"Principal written twice", statement(`"Effect": "Allow", "Principal": "*", "Principal": "*", "Action": "sts:AssumeRoleWithSAML"`), AccountSAMLProviders},

		{"sts:AssumeRoleWithWebIdentity", anyone(`"Action": "sts:AssumeRoleWithWebIdentity"`), EveryIssuer},
		{"web identity beside sts:AssumeRole", anyone(`"Action": ["sts:AssumeRole", "sts:AssumeRoleWithWebIdentity"]`), EveryIssuer},
		{"web identity beside SAML", anyone(`"Action": ["sts:AssumeRoleWithSAML", "sts:AssumeRoleWithWebIdentity"]`), EveryIssuer},
		{"web identity spelled with a long s", anyone(`"Action": ["sts:AssumeRole", "ſts:AssumeRoleWithWebIdentity"]`), EveryIssuer},
		{"web identity spelled with a dotless i", anyone(`"Action": ["sts:AssumeRole", "sts:AssumeRoleWıthWebIdentıty"]`), EveryIssuer},
		{"a letter outside ASCII with a case of its own, whatever it names", anyone(`"Action": ["sts:AssumeRole", "s3:GetObjé"]`), EveryIssuer},
		{"sts:*", anyone(`"Action": "sts:*"`), EveryIssuer},
		{"*", anyone(`"Action": "*"`), EveryIssuer},
		{"a wildcard that reaches sts:AssumeRole alone", anyone(`"Action": "sts:AssumeRol?"`), EveryIssuer},
		{"a wildcard beside sts:AssumeRole", anyone(`"Action": ["sts:AssumeRole", "s3:*"]`), EveryIssuer},
		{"NotAction", anyone(`"NotAction": "s3:*"`), EveryIssuer},
		{"no Action", statement(`"Effect": "Allow", "Principal": "*"`), EveryIssuer},
		{"Action written twice", anyone(`"Action": "sts:AssumeRole", "Action": "sts:AssumeRole"`), EveryIssuer},
		{"a policy variable beside \"*\"", statement(`"Effect": "Allow", "Principal": {"AWS": ["*", "${aws:username}"]}, "Action": "sts:AssumeRole"`), EveryIssuer},
		{"a principal kind beside \"*\"", statement(`"Effect": "Allow", "Principal": {"AWS": "*", "Foo": "x"}, "Action": "sts:AssumeRole"`), EveryIssuer},
		{"a mis-shaped principal beside \"*\"", statement(`"Effect": "Allow", "Principal": {"AWS": ["*", 5]}, "Action": "sts:AssumeRole"`), EveryIssuer},
		{"NotPrincipal", statement(`"Effect": "Allow", "NotPrincipal": {"AWS": "*"}, "Action": "sts:AssumeRole"`), EveryIssuer},
		{"no Principal", statement(`"Effect": "Allow", "Action": "sts:AssumeRole"`), EveryIssuer},
		{"a policy variable", statement(`"Effect": "Allow", "Principal": {"AWS": "${aws:username}"}, "Action": "sts:AssumeRole"`), EveryIssuer},
		{"a Principal that is a list", statement(`"Effect": "Allow", "Principal": ["*"], "Action": "sts:AssumeRole"`), EveryIssuer},
		{"a service, with no issuer-less grant", statement(`"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"`), EveryIssuer},
		{"\"*\" with no assume action", anyone(`"Action": "sts:TagSession"`), EveryIssuer},
	}
	for _, c := range cases {
		d := mustParse(t, c.raw)
		if len(d.Statements) != 1 {
			t.Fatalf("%s: %d statements", c.name, len(d.Statements))
		}
		if got := d.Statements[0].IssuerlessPopulation(); got != c.want {
			t.Errorf("%s: IssuerlessPopulation() = %d, want %d", c.name, got, c.want)
		}
	}
	// A statement that is not an object, and a document member outside the
	// grammar read as a statement, have no principal anyone could read.
	for _, raw := range []string{`{"Version": "2012-10-17", "Statement": [5]}`, `{"Version": "2012-10-17", "Statement": [], "Statment": {}}`} {
		for _, s := range mustParse(t, raw).Statements {
			if got := s.IssuerlessPopulation(); got != EveryIssuer {
				t.Errorf("%s: IssuerlessPopulation() = %d, want every issuer", raw, got)
			}
		}
	}
}

// TestIssuerlessPopulationOfUnreadActions: actions the parser could not
// read make the answer every issuer even beside actions it did read. The
// parser keeps no pattern beside an Action it could not read today, and
// the rule must not lean on that: a reader that one day kept the readable
// items of a list would otherwise turn every such statement into a
// service's face.
func TestIssuerlessPopulationOfUnreadActions(t *testing.T) {
	s := Statement{
		Principals: Principals{list: []principal{anyone("statement[0].Principal")}},
		Actions:    ActionSet{unknown: true, patterns: []eval.StringSet{eval.Exact(assumeRole)}},
	}
	if got := s.IssuerlessPopulation(); got != EveryIssuer {
		t.Fatalf("IssuerlessPopulation() = %d with the actions unread beside sts:AssumeRole, want every issuer", got)
	}
}

// TestZeroPopulationIsEveryIssuer: an answer nobody computed reads as the
// outermost one, never as a narrower one.
func TestZeroPopulationIsEveryIssuer(t *testing.T) {
	var zero Population
	if zero != EveryIssuer {
		t.Fatalf("the zero Population is %d, want EveryIssuer", zero)
	}
}

// The populations as sets of what they cover, for the laws below.
const (
	coversServices = 1 << iota
	coversSAML
	coversEveryIssuer
)

var covers = map[Population]int{
	EveryIssuer:                        coversServices | coversSAML | coversEveryIssuer,
	AWSServices:                        coversServices,
	AccountSAMLProviders:               coversSAML,
	AWSServicesAndAccountSAMLProviders: coversServices | coversSAML,
}

// principalMember is a Principal member drawn for the laws below, with
// what the test knows of it because it wrote it: whether the parser can
// read who it names, and whether it names "*".
type principalMember struct {
	json     string
	readable bool
	anyone   bool
}

// principalMembers are Principal members every way a trust names someone:
// "*", principals the parser reads, and principals it cannot, among them a
// variable, a mis-shaped item beside "*" and a kind it does not know.
var principalMembers = []principalMember{
	{`"AWS": "*"`, true, true},
	{`"AWS": "111122223333"`, true, false},
	{`"AWS": "${aws:username}"`, false, false},
	{`"AWS": ["*", 5]`, false, true},
	{`"Federated": "` + samlProvider + `"`, true, false},
	{`"Federated": "` + githubProvider + `"`, true, false},
	{`"Service": "ec2.amazonaws.com"`, true, false},
	{`"Foo": "x"`, false, false},
}

// actionItem is an Action entry drawn for the laws below: whether it is
// written out in full, with no wildcard and no letter outside ASCII that
// has a case of its own, and, when it is, which assume action it names.
// AWS: "The prefix and the action name are case insensitive."
// (https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_action.html),
// so an ASCII spelling in another case names the same action.
type actionItem struct {
	text    string
	written bool
	names   string // assumeRole, assumeWithWebIdentity, assumeWithSAML, or "" for none
}

var (
	assumeRoleItem = actionItem{"sts:AssumeRole", true, assumeRole}
	assumeSAMLItem = actionItem{"sts:AssumeRoleWithSAML", true, assumeWithSAML}
)

// actionItems are the three assume actions, one in another case, actions
// that assume nothing, wildcards that reach one assume action, all three or
// none, and web identity spelled with a letter AWS may fold onto an ASCII
// one.
var actionItems = []actionItem{
	assumeRoleItem,
	assumeSAMLItem,
	{"STS:ASSUMEROLE", true, assumeRole},
	{"sts:TagSession", true, ""},
	{"s3:GetObject", true, ""},
	{"sts:AssumeRoleWithWebIdentity", true, assumeWithWebIdentity},
	{"sts:*", false, ""},
	{"sts:AssumeRol?", false, ""},
	{"s3:*", false, ""},
	{"*", false, ""},
	{"ſts:AssumeRoleWithWebIdentity", false, ""},
}

// assumeSets are the assume actions a narrow population is granted
// through, one set for each such population.
var assumeSets = [][]actionItem{
	{assumeRoleItem},
	{assumeSAMLItem},
	{assumeRoleItem, assumeSAMLItem},
}

// otherMember is what a statement may say beside its Effect, Principal and
// Action, and whether the parser reads it without leaving the statement's
// grants unevaluated.
type otherMember struct {
	json string
	read bool
}

// otherMembers are a condition the parser reads, conditions it cannot, and
// members it does not read, one of them spelled like Action.
var otherMembers = []otherMember{
	{`"Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-a1b2c3d4e5"}}`, true},
	{`"Condition": "x"`, false},
	{`"Condition": {"StringEquals": "x"}`, false},
	{`"Condition": {}, "Condition": {}`, false},
	{`"Resource": "*"`, false},
	{`"action": "sts:AssumeRoleWithWebIdentity"`, false},
}

// populationShape is a statement drawn for the laws below.
type populationShape struct {
	effect         string
	principals     []principalMember // Principal members, or none for "*" alone
	principalTwice bool              // the Principal member written twice
	actions        []actionItem      // Action items, or none for NotAction
	others         []otherMember
}

// anyone reports whether the statement names "*".
func (p populationShape) anyone() bool {
	return len(p.principals) == 0 || slices.ContainsFunc(p.principals, func(m principalMember) bool { return m.anyone })
}

// readable reports whether the parser can read every principal the
// statement names.
func (p populationShape) readable() bool {
	return !slices.ContainsFunc(p.principals, func(m principalMember) bool { return !m.readable })
}

// written reports whether the statement has an Action whose every item is
// written out in full.
func (p populationShape) written() bool {
	return len(p.actions) > 0 && !slices.ContainsFunc(p.actions, func(a actionItem) bool { return !a.written })
}

// unreadBeside reports whether the statement says something beside its
// principal and its actions that leaves its grants unevaluated.
func (p populationShape) unreadBeside() bool {
	return p.principalTwice || slices.ContainsFunc(p.others, func(m otherMember) bool { return !m.read })
}

// named is the population the assume actions of a written statement name,
// by the rule as the test states it from the items it drew.
func (p populationShape) named() Population {
	services, saml := false, false
	for _, a := range p.actions {
		switch a.names {
		case assumeWithWebIdentity:
			return EveryIssuer
		case assumeRole:
			services = true
		case assumeWithSAML:
			saml = true
		}
	}
	switch {
	case services && saml:
		return AWSServicesAndAccountSAMLProviders
	case services:
		return AWSServices
	case saml:
		return AccountSAMLProviders
	}
	return EveryIssuer
}

// genPopulationShape draws "*" alone half the time, and otherwise one to
// three Principal members, three kinds in eight of them unreadable. Its
// actions are one of the assume sets and up to two more items, so that
// each narrow population is as common as the others, and every so often
// NotAction instead. Now and then the Principal member is written twice,
// and about half the statements say one more thing beside the rest.
func genPopulationShape() *rapid.Generator[populationShape] {
	return rapid.Custom(func(t *rapid.T) populationShape {
		var principals []principalMember
		if rapid.Bool().Draw(t, "members") {
			principals = rapid.SliceOfN(rapid.SampledFrom(principalMembers), 1, 3).Draw(t, "principals")
		}
		var actions []actionItem
		if rapid.IntRange(0, 7).Draw(t, "not action") != 0 {
			actions = slices.Concat(rapid.SampledFrom(assumeSets).Draw(t, "assume"), rapid.SliceOfN(rapid.SampledFrom(actionItems), 0, 2).Draw(t, "actions"))
		}
		return populationShape{
			effect:         rapid.SampledFrom([]string{"Allow", "Deny"}).Draw(t, "effect"),
			principals:     principals,
			principalTwice: rapid.IntRange(0, 7).Draw(t, "principal twice") == 0,
			actions:        actions,
			others:         rapid.SliceOfN(rapid.SampledFrom(otherMembers), 0, 1).Draw(t, "others"),
		}
	})
}

// genPopulationShapes draws four statements a case, which puts about four
// times the draws behind each population a law must reach.
func genPopulationShapes() *rapid.Generator[[]populationShape] {
	return rapid.SliceOfN(genPopulationShape(), 4, 4)
}

func (p populationShape) render(t *rapid.T) string {
	principal := `"*"`
	if len(p.principals) > 0 {
		members := make([]string, len(p.principals))
		for i, m := range p.principals {
			members[i] = m.json
		}
		principal = "{" + strings.Join(members, ", ") + "}"
	}
	members := []string{`"Effect": ` + jsonText(t, p.effect), `"Principal": ` + principal}
	if p.principalTwice {
		members = append(members, `"Principal": `+principal)
	}
	action := `"NotAction": "s3:*"`
	if len(p.actions) > 0 {
		texts := make([]string, len(p.actions))
		for i, a := range p.actions {
			texts[i] = a.text
		}
		action = `"Action": ` + jsonList(t, texts)
	}
	members = append(members, action)
	for _, m := range p.others {
		members = append(members, m.json)
	}
	return statement(strings.Join(members, ", "))
}

// parsePopulation parses a one-statement document: its statement's
// population and its grants with no issuer, each marked by whether the
// parser read it as the face of "*".
func parsePopulation(t *rapid.T, raw string) (Population, []bool) {
	d, err := ParseTrustPolicy([]byte(asAWSHoldsIt(raw)))
	if err != nil || len(d.Statements) != 1 {
		t.Fatalf("ParseTrustPolicy(%s): %v, %d statements", raw, err, len(d.Statements))
	}
	var faces []bool
	for _, g := range d.Grants(role, vocabulary) {
		if g.Issuer == "" {
			_, face := findAnomaly(g, AnyPrincipal, "Principal")
			faces = append(faces, face)
		}
	}
	return d.Statements[0].IssuerlessPopulation(), faces
}

// TestIssuerlessPopulationNeverExemptsAnUnreadablePrincipal checks the
// predicate against the grants the parser projects: whenever a statement
// has a grant with no issuer that is not the face of "*", a principal the
// parser could not read, the statement's population is every issuer, since
// that principal may name anyone. The counts prove the draws reached both
// kinds of issuer-less grant and a statement read as an exception.
func TestIssuerlessPopulationNeverExemptsAnUnreadablePrincipal(t *testing.T) {
	unreadable, faces, exceptions := 0, 0, 0
	rapid.Check(t, func(t *rapid.T) {
		for _, s := range genPopulationShapes().Draw(t, "statements") {
			raw := s.render(t)
			population, issuerless := parsePopulation(t, raw)
			for _, face := range issuerless {
				if face {
					faces++
					continue
				}
				unreadable++
				if population != EveryIssuer {
					t.Fatalf("%s projects a grant for a principal the parser could not read, and its population is %d", raw, population)
				}
			}
			if population != EveryIssuer {
				exceptions++
			}
		}
	})
	if unreadable == 0 || faces == 0 || exceptions == 0 {
		t.Fatalf("unreadable=%d faces=%d exceptions=%d; every count must be positive", unreadable, faces, exceptions)
	}
	t.Logf("unreadable=%d faces=%d exceptions=%d", unreadable, faces, exceptions)
}

// TestIssuerlessPopulationIsWhatTheActionsName is the rule stated from
// what the test drew, for a statement that names "*" and whose every
// principal the parser reads. When every action is written out in full,
// the statement has a face of "*", and its population is the one its
// assume actions name, whatever else the statement says: a condition only
// narrows and no member but Action or NotAction is an action block, so a
// predicate that took a condition or a member the parser could not read
// for a reason to answer every issuer would put a service's face among
// grants anyone can use. When any action is not written out in full, a
// wildcard, a spelling beyond ASCII or NotAction, the population is every
// issuer, since which assume actions it reaches is not read. The counts
// prove each population was reached, and that statements saying something
// the parser could not read beside their actions, and statements with an
// action not written out in full, were among those checked.
func TestIssuerlessPopulationIsWhatTheActionsName(t *testing.T) {
	checked := map[Population]int{}
	unreadBeside, unwritten := 0, 0
	rapid.Check(t, func(t *rapid.T) {
		for _, s := range genPopulationShapes().Draw(t, "statements") {
			if !s.anyone() || !s.readable() {
				continue
			}
			raw := s.render(t)
			population, issuerless := parsePopulation(t, raw)
			want := EveryIssuer
			if s.written() {
				if !slices.Contains(issuerless, true) {
					t.Fatalf("%s names \"*\" and an assume action, and the parser projected no face of \"*\"", raw)
				}
				want = s.named()
			} else {
				unwritten++
			}
			if population != want {
				t.Fatalf("%s: IssuerlessPopulation() = %d, its actions name %d", raw, population, want)
			}
			checked[population]++
			if s.unreadBeside() {
				unreadBeside++
			}
		}
	})
	for p := range covers {
		if checked[p] == 0 {
			t.Fatalf("no statement had population %d (checked %v); the rule was never examined on it", p, checked)
		}
	}
	if unreadBeside == 0 || unwritten == 0 {
		t.Fatalf("checked %v, %d with something unread beside the actions, %d with an action not written out in full; both must be positive", checked, unreadBeside, unwritten)
	}
	t.Logf("checked %v, %d with something unread beside the actions, %d with an action not written out in full", checked, unreadBeside, unwritten)
}

// faceSentence is what the parser says of the face of "*" whose population
// is an exception, in its own words: the assume actions it found the
// statement granting.
var faceSentence = map[Population]string{
	AWSServices:                        "the statement applies to every principal, and which AWS services it covers through sts:AssumeRole is not known",
	AccountSAMLProviders:               "the statement applies to every principal, and which identity providers' tokens it covers through sts:AssumeRoleWithSAML is not known",
	AWSServicesAndAccountSAMLProviders: "the statement applies to every principal, and which AWS services and identity providers' tokens it covers through sts:AssumeRole or sts:AssumeRoleWithSAML is not known",
}

// TestIssuerlessPopulationAgreesWithTheFace: when the predicate names an
// exception, the face the parser projected for "*" exists and says it
// covers exactly those actions. The predicate reads the statement and the
// parser's sentence reads the same actions another way, through the
// matcher; were the predicate to miss an action a pattern reaches, the
// sentence would name one it did not.
func TestIssuerlessPopulationAgreesWithTheFace(t *testing.T) {
	checked := map[Population]int{}
	rapid.Check(t, func(t *rapid.T) {
		for _, s := range genPopulationShapes().Draw(t, "statements") {
			raw := s.render(t)
			d, err := ParseTrustPolicy([]byte(asAWSHoldsIt(raw)))
			if err != nil {
				t.Fatalf("ParseTrustPolicy(%s): %v", raw, err)
			}
			population := d.Statements[0].IssuerlessPopulation()
			want, exception := faceSentence[population]
			if !exception {
				continue
			}
			var sentences []string
			for _, g := range d.Grants(role, vocabulary) {
				if a, ok := findAnomaly(g, trust.Unmodelled, "Principal"); g.Issuer == "" && ok {
					sentences = append(sentences, a.Message)
				}
			}
			// "*" written twice is two faces, each saying the same.
			if len(sentences) == 0 || slices.ContainsFunc(sentences, func(s string) bool { return s != want }) {
				t.Fatalf("%s: population %d, and the faces of \"*\" say %q", raw, population, sentences)
			}
			checked[population]++
		}
	})
	for p := range faceSentence {
		if checked[p] == 0 {
			t.Fatalf("no draw had population %d (checked %v); the agreement was never examined on it", p, checked)
		}
	}
	t.Logf("checked %v", checked)
}

// TestIssuerlessPopulationWidensWithTheStatement is monotonicity: adding an
// action, a principal or anything else to a statement that has a grant
// with no issuer never takes a population out of it. A predicate that read
// "sts:*" beside sts:AssumeRole as services, or dropped an unreadable
// principal added beside "*", would narrow here.
func TestIssuerlessPopulationWidensWithTheStatement(t *testing.T) {
	compared, widened := 0, 0
	rapid.Check(t, func(t *rapid.T) {
		for _, s := range genPopulationShapes().Draw(t, "statements") {
			population, issuerless := parsePopulation(t, s.render(t))
			if len(issuerless) == 0 {
				continue
			}
			more := s
			switch rapid.IntRange(0, 2).Draw(t, "add") {
			case 0:
				if len(s.actions) > 0 {
					more.actions = append(slices.Clone(s.actions), rapid.SampledFrom(actionItems).Draw(t, "action"))
					break
				}
				fallthrough
			case 1:
				if len(s.principals) == 0 {
					more.principals = []principalMember{principalMembers[0]}
				}
				more.principals = append(slices.Clone(more.principals), rapid.SampledFrom(principalMembers).Draw(t, "principal"))
			default:
				more.others = append(slices.Clone(s.others), rapid.SampledFrom(otherMembers).Draw(t, "other"))
			}
			after, _ := parsePopulation(t, more.render(t))
			compared++
			if covers[population]&^covers[after] != 0 {
				t.Fatalf("%s: population %d\n%s: population %d\nthe larger statement covers less", s.render(t), population, more.render(t), after)
			}
			if after != population {
				widened++
			}
		}
	})
	if compared == 0 || widened == 0 {
		t.Fatalf("compared=%d widened=%d; both must be positive", compared, widened)
	}
	t.Logf("compared=%d widened=%d", compared, widened)
}

// TestModelsPrincipalOf pins, for every shape of principal, whether the
// parser can say what kind of identity a grant of it stands for. A
// CanonicalUser, an AWS ARN of another service, a Federated IAM ARN that
// names no provider and every principal the parser could not read are not
// modelled, whatever the actions; an ARN whose account or ARN is Unknown
// still names an identity of an AWS account and is; and each principal
// beside another keeps its own answer.
func TestModelsPrincipalOf(t *testing.T) {
	const canonical = `"CanonicalUser": "79a59df900b949e55d96a1e698fbacedfd6e09d98eacf8f8d5218e7cd47ef2be"`
	allow := func(principal, action string) string {
		return statement(`"Effect": "Allow", "Principal": ` + principal + `, "Action": ` + action)
	}
	none := []trust.IssuerRef(nil)
	sts := []trust.IssuerRef{AWSPrincipalIssuer}
	noIssuer := []trust.IssuerRef{""}
	cases := []struct {
		name       string
		raw        string
		grants     int
		unmodelled []trust.IssuerRef // the issuers of the grants not modelled, sorted
	}{
		{"a CanonicalUser", allow(`{`+canonical+`}`, `"sts:AssumeRole"`), 1, sts},
		{"a CanonicalUser with no assume action", allow(`{`+canonical+`}`, `"s3:GetObject"`), 1, sts},
		{"an ARN of another service", allow(`{"AWS": "arn:aws:s3:::acme-artifacts"}`, `"sts:AssumeRole"`), 1, sts},
		{"a role's ARN under Federated", allow(`{"Federated": "arn:aws:iam::111122223333:role/Deploy"}`, `"sts:AssumeRoleWithWebIdentity"`), 1, noIssuer},
		{"an account beside an ARN of another service", allow(`{"AWS": ["111122223333", "arn:aws:s3:::acme-artifacts"]}`, `"sts:AssumeRole"`), 2, sts},
		{`"*" beside a CanonicalUser`, allow(`{"AWS": "*", `+canonical+`}`, `"sts:AssumeRole"`), 3, sts},
		{`"*" beside a mis-shaped principal`, allow(`{"AWS": ["*", 5]}`, `"sts:AssumeRole"`), 3, noIssuer},
		{"a policy variable", allow(`{"AWS": "${aws:username}"}`, `"sts:AssumeRole"`), 1, noIssuer},
		{"a principal kind the parser does not know", allow(`{"Foo": "x"}`, `"sts:AssumeRole"`), 1, noIssuer},
		{"a Federated principal that is no provider", allow(`{"Federated": "not a provider"}`, `"sts:AssumeRoleWithWebIdentity"`), 1, noIssuer},
		{"a Service principal that is no service", allow(`{"Service": "not a service"}`, `"sts:AssumeRole"`), 1, noIssuer},
		{"NotPrincipal", statement(`"Effect": "Allow", "NotPrincipal": {"AWS": "*"}, "Action": "sts:AssumeRole"`), 1, noIssuer},
		{"no Principal", statement(`"Effect": "Allow", "Action": "sts:AssumeRole"`), 1, noIssuer},
		{"a Principal that is a list", allow(`["*"]`, `"sts:AssumeRole"`), 1, noIssuer},
		// A copy of Principal that is not an object names nothing to match
		// grants by, so every grant of its statement is reported: outward.
		{"Principal written twice, one copy not an object", statement(`"Effect": "Allow", "Principal": 5, "Principal": {"AWS": "111122223333"}, "Action": "sts:AssumeRole"`), 2, []trust.IssuerRef{"", AWSPrincipalIssuer}},

		{`"*"`, allow(`"*"`, `"sts:*"`), 2, none},
		{"an account", allow(`{"AWS": "111122223333"}`, `"sts:AssumeRole"`), 1, none},
		{"a role", allow(`{"AWS": "arn:aws:iam::111122223333:role/deploy"}`, `"sts:AssumeRole"`), 1, none},
		{"a role session", allow(`{"AWS": "arn:aws:sts::111122223333:assumed-role/deploy/s"}`, `"sts:AssumeRole"`), 1, none},
		{"an STS ARN of a kind the parser does not know", allow(`{"AWS": "arn:aws:sts::111122223333:other/x"}`, `"sts:AssumeRole"`), 1, none},
		{"a root ARN with no account", allow(`{"AWS": "arn:aws:iam:::root"}`, `"sts:AssumeRole"`), 1, none},
		{"the unique id of a deleted principal", allow(`{"AWS": "AROAEXAMPLEID1234567"}`, `"sts:AssumeRole"`), 1, none},
		{"an OIDC provider", allow(`{"Federated": "`+githubProvider+`"}`, `"sts:AssumeRoleWithWebIdentity"`), 1, none},
		{"a provider AWS builds in", allow(`{"Federated": "accounts.google.com"}`, `"sts:AssumeRoleWithWebIdentity"`), 1, none},
		{"a SAML provider", allow(`{"Federated": "`+samlProvider+`"}`, `"sts:AssumeRoleWithSAML"`), 1, none},
		{"a service", allow(`{"Service": "ec2.amazonaws.com"}`, `"sts:AssumeRole"`), 1, none},
		{"an account its statement leaves unevaluated", statement(`"Effect": "Allow", "Principal": {"AWS": "111122223333"}, "NotAction": "s3:*"`), 1, none},
	}
	for _, c := range cases {
		d := mustParse(t, c.raw)
		grants := d.Grants(role, vocabulary)
		var unmodelled []trust.IssuerRef
		for _, g := range grants {
			if !d.Statements[0].ModelsPrincipalOf(g) {
				unmodelled = append(unmodelled, g.Issuer)
			}
		}
		slices.Sort(unmodelled)
		if len(grants) != c.grants || !slices.Equal(unmodelled, c.unmodelled) {
			t.Errorf("%s: %d grants, not modelled on %q; want %d grants, not modelled on %q", c.name, len(grants), unmodelled, c.grants, c.unmodelled)
		}
	}
}

// TestAnARNOfAnotherServiceIsReadAsItWas: giving an AWS ARN of another
// service a kind of its own changed nothing the parser reads of it. Its
// ARN is Unknown and it names no account, the pseudo-issuer's keys in a
// condition are claims of it rather than facts about the request, and the
// grant is doubted on the ARN, as when it was read as one more opaque
// principal.
func TestAnARNOfAnotherServiceIsReadAsItWas(t *testing.T) {
	cases := []struct{ condition, want string }{
		{``, `{}`},
		{`, "Condition": {"StringEquals": {"aws:PrincipalAccount": "111122223333"}}`, `{aws:principalaccount="111122223333", aws:principalarn=?("arn:aws:s3:::acme-artifacts")}`},
		{`, "Condition": {"StringLike": {"aws:PrincipalArn": "arn:aws:iam::111122223333:role/*"}}`, `{aws:principalarn=like:"arn:aws:iam::111122223333:role/*"}`},
	}
	for _, c := range cases {
		g := oneGrant(t, statement(`"Effect": "Allow", "Principal": {"AWS": "arn:aws:s3:::acme-artifacts"}, "Action": "sts:AssumeRole"`+c.condition))
		caveats := g.Admits.Caveats()
		if g.Issuer != AWSPrincipalIssuer || g.Admits.String() != c.want || g.Exact() || len(caveats) != 1 || caveats[0].Claim != arnClaim {
			t.Errorf("condition %q: %s admits %s with caveats %+v; want %s, doubted on %s alone", c.condition, g.Issuer, g.Admits, caveats, c.want, arnClaim)
		}
	}
}

// namedPrincipal is one principal a statement may name, under its key, and
// whether the parser can say what kind of identity it names, as the test
// knows because it wrote it.
type namedPrincipal struct {
	key, value string // value is JSON
	modelled   bool
}

// namedPrincipals are principals of every key: the ones the parser models,
// among them ARNs whose account or ARN it leaves Unknown, and the ones it
// does not: a CanonicalUser, an AWS ARN of another service, a Federated IAM
// ARN that names no provider, and those it could not read.
var namedPrincipals = []namedPrincipal{
	{"AWS", `"*"`, true},
	{"AWS", `"111122223333"`, true},
	{"AWS", `"arn:aws:iam::111122223333:role/deploy"`, true},
	{"AWS", `"arn:aws:sts::111122223333:assumed-role/deploy/s"`, true},
	{"AWS", `"arn:aws:sts::111122223333:other/x"`, true},
	{"AWS", `"arn:aws:iam:::root"`, true},
	{"AWS", `"AROAEXAMPLEID1234567"`, true},
	{"AWS", `"arn:aws:s3:::acme-artifacts"`, false},
	{"AWS", `"${aws:username}"`, false},
	{"AWS", `5`, false},
	{"Federated", `"` + githubProvider + `"`, true},
	{"Federated", `"` + samlProvider + `"`, true},
	{"Federated", `"accounts.google.com"`, true},
	{"Federated", `"arn:aws:iam::111122223333:role/Deploy"`, false},
	{"Service", `"ec2.amazonaws.com"`, true},
	{"CanonicalUser", `"79a59df900b949e55d96a1e698fbacedfd6e09d98eacf8f8d5218e7cd47ef2be"`, false},
}

// TestModelsPrincipalOfCountsThePrincipals is the predicate against what
// the test wrote: a principal the parser does not model is never "*", so it
// projects exactly one grant, and the grants the predicate reports as not
// modelled are exactly as many as such principals, whatever the actions
// and whatever else the statement names. The counts prove the draws named
// principals of both kinds, together and apart.
func TestModelsPrincipalOfCountsThePrincipals(t *testing.T) {
	examined, withUnmodelled, mixed := 0, 0, 0
	rapid.Check(t, func(t *rapid.T) {
		drawn := rapid.SliceOfN(rapid.SampledFrom(namedPrincipals), 1, 4).Draw(t, "principals")
		byKey := map[string][]string{}
		unmodelled, modelled := 0, 0
		for _, p := range drawn {
			byKey[p.key] = append(byKey[p.key], p.value)
			if p.modelled {
				modelled++
			} else {
				unmodelled++
			}
		}
		var members []string
		for _, key := range []string{"AWS", "Federated", "Service", "CanonicalUser"} {
			if values := byKey[key]; values != nil {
				members = append(members, `"`+key+`": [`+strings.Join(values, ", ")+`]`)
			}
		}
		action := `"NotAction": "s3:*"`
		if rapid.IntRange(0, 5).Draw(t, "not action") != 0 {
			action = `"Action": ` + jsonList(t, rapid.SliceOfN(rapid.SampledFrom([]string{
				"sts:AssumeRole", "sts:AssumeRoleWithWebIdentity", "sts:AssumeRoleWithSAML", "sts:*", "s3:GetObject",
			}), 1, 3).Draw(t, "actions"))
		}
		raw := statement(`"Effect": "Allow", "Principal": {` + strings.Join(members, ", ") + `}, ` + action)
		d, err := ParseTrustPolicy([]byte(asAWSHoldsIt(raw)))
		if err != nil || len(d.Statements) != 1 {
			t.Fatalf("ParseTrustPolicy(%s): %v, %d statements", raw, err, len(d.Statements))
		}
		reported := 0
		for _, g := range d.Grants(role, vocabulary) {
			if !d.Statements[0].ModelsPrincipalOf(g) {
				reported++
			}
		}
		if reported != unmodelled {
			t.Fatalf("%s: %d grants reported not modelled, %d principals drawn not modelled", raw, reported, unmodelled)
		}
		examined++
		if unmodelled > 0 {
			withUnmodelled++
			if modelled > 0 {
				mixed++
			}
		}
	})
	if examined == 0 || withUnmodelled == 0 || mixed == 0 {
		t.Fatalf("examined=%d withUnmodelled=%d mixed=%d; every count must be positive", examined, withUnmodelled, mixed)
	}
	t.Logf("examined=%d withUnmodelled=%d mixed=%d", examined, withUnmodelled, mixed)
}

// TestAHostSpelledToFoldOntoAnotherNamesNoIssuer: case folding turns a
// Kelvin sign into k, a capital I with a dot above and a dotless i into i, a
// long s into s and a ligature into its letters, so a provider whose host
// holds one may be the host it folds onto, GitHub's or a real EKS
// cluster's, although whoever registered the look-alike host runs it.
// Whether AWS reads such a host as the ASCII one is not documented, so the
// parser names no issuer for it: the principal is one it cannot read, and
// its grant admits everything, declared. A letter outside ASCII that folds
// to itself or to another such letter keeps its provider, spelled with the
// letter's own case, as does one in the path, which keeps its case.
func TestAHostSpelledToFoldOntoAnotherNamesNoIssuer(t *testing.T) {
	const kelvinSign, dottedI = "K", "İ"
	for _, provider := range []string{
		"arn:aws:iam::123456789012:oidc-provider/to" + kelvinSign + "en.actions.githubusercontent.com",
		"to" + kelvinSign + "en.actions.githubusercontent.com",
		"https://to" + kelvinSign + "en.actions.githubusercontent.com",
		"arn:aws:iam::123456789012:oidc-provider/o" + dottedI + "dc.eks.us-east-1.amazonaws.com/id/EXAMPLED539D4633E53DE1B71EXAMPLE",
		"arn:aws:iam::123456789012:oidc-provider/token.actions.githubu" + longS + "ercontent.com",
		"arn:aws:iam::123456789012:oidc-provider/token.act\u0131ons.githubusercontent.com",
		"arn:aws:iam::123456789012:oidc-provider/oidc.eks.us-ea\ufb06-1.amazonaws.com/id/EXAMPLED539D4633E53DE1B71EXAMPLE",
	} {
		raw := statement(`"Effect": "Allow", "Principal": {"Federated": "` + provider + `"}, "Action": "sts:AssumeRoleWithWebIdentity", "Condition": {"StringLike": {"token.actions.githubusercontent.com:sub": "repo:acme/*"}}`)
		d := mustParse(t, raw)
		g := oneGrant(t, raw)
		if g.Issuer != "" || !g.Admits.IsTop() || g.Exact() {
			t.Errorf("%q: filed under %q, admitting %s, exact %v; want no issuer, everything, declared", provider, g.Issuer, g.Admits, g.Exact())
		}
		if d.Statements[0].ModelsPrincipalOf(g) || d.Statements[0].IssuerlessPopulation() != EveryIssuer {
			t.Errorf("%q: read as a principal the parser models", provider)
		}
		want := "the Federated principal " + strconv.QuoteToASCII(provider) + " names a host holding a letter outside ASCII that case folding may turn into ASCII text, and whether AWS reads the host with that letter or with that text is not documented, so its issuer is not known"
		if a, ok := findAnomaly(g, trust.Unmodelled, "Federated"); !ok || a.Message != want {
			t.Errorf("%q: anomaly %+v", provider, a)
		}
		if issuer, ok := ProviderIssuer(strings.TrimPrefix(provider, "arn:aws:iam::123456789012:oidc-provider/")); ok {
			t.Errorf("%q: ProviderIssuer names %q", provider, issuer)
		}
	}
	for provider, issuer := range map[string]trust.IssuerRef{
		"arn:aws:iam::123456789012:oidc-provider/ünicode.example":                                         "https://ünicode.example",
		"arn:aws:iam::123456789012:oidc-provider/Ünicode.example":                                         "https://Ünicode.example",
		"arn:aws:iam::123456789012:oidc-provider/oidc.eks.us-west-2.amazonaws.com/id/" + kelvinSign + "1": trust.IssuerRef("https://oidc.eks.us-west-2.amazonaws.com/id/" + kelvinSign + "1"),
		"arn:aws:iam::123456789012:oidc-provider/Token.Actions.GitHubUserContent.com":                     githubIssuer,
	} {
		g := oneGrant(t, statement(`"Effect": "Allow", "Principal": {"Federated": "`+provider+`"}, "Action": "sts:AssumeRoleWithWebIdentity"`))
		if g.Issuer != issuer {
			t.Errorf("%q: filed under %q, want %q", provider, g.Issuer, issuer)
		}
	}
}

// TestProviderIssuer: the issuer a provider identifier names is the one the
// parser files a Federated principal's grants under, so that an issuer a
// user declares and one a policy names compare alike.
func TestProviderIssuer(t *testing.T) {
	cases := []struct {
		identifier string
		want       trust.IssuerRef
		ok         bool
	}{
		{"token.actions.githubusercontent.com", githubIssuer, true},
		{"HTTPS://Token.Actions.GitHubUserContent.com/", githubIssuer, true},
		{"oidc.eks.us-east-1.amazonaws.com/id/ABC/", "https://oidc.eks.us-east-1.amazonaws.com/id/ABC", true},
		{"toKen.actions.githubusercontent.com", "", false},
		{"token.actions.githubu" + longS + "ercontent.com", "", false},
		{"https://gİtlab.com/x", "", false},
		{"*.example.com", "", false},
		{"a b", "", false},
		{"", "", false},
		{"https://", "", false},
	}
	for _, c := range cases {
		if got, ok := ProviderIssuer(c.identifier); got != c.want || ok != c.ok {
			t.Errorf("ProviderIssuer(%q) = %q, %v; want %q, %v", c.identifier, got, ok, c.want, c.ok)
		}
	}
}
