package ring

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"pgregory.net/rapid"

	"github.com/CloudArq-net/cloudarq/internal/eval"
	"github.com/CloudArq-net/cloudarq/internal/parse/aws"
	"github.com/CloudArq-net/cloudarq/internal/parse/azure"
	"github.com/CloudArq-net/cloudarq/internal/parse/gcp"
	"github.com/CloudArq-net/cloudarq/internal/trust"
)

// ringOf is the ring a placed grant is in, or -1 when it is only beside
// the rings.
func ringOf(p Placement) Place {
	for _, place := range p.Places {
		if place.Ring() {
			return place
		}
	}
	return -1
}

// drawnGrant is a generated grant and the census's facts for its issuer.
type drawnGrant struct {
	grant trust.Grant
	facts Facts
}

// genAnyGrant draws a grant of every kind the classifier meets: GitHub's,
// an AWS principal's, a per-tenant issuer's, one with no issuer, a SAML
// provider's, a service's, and others the census records or does not.
func genAnyGrant(t *rapid.T) drawnGrant {
	switch rapid.IntRange(0, 7).Draw(t, "kind") {
	case 0, 1, 2:
		facts := githubFacts()
		facts.Tenancy.NamesIgnoreCase = rapid.Bool().Draw(t, "ignore case")
		return drawnGrant{genGitHubGrant(t).grant, facts}
	case 3:
		term := eval.Term{}
		if rapid.Bool().Draw(t, "account") {
			term["aws:principalaccount"] = eval.Exact(rapid.SampledFrom(universeAccounts).Draw(t, "account id"))
		}
		if rapid.Bool().Draw(t, "arn") {
			term["aws:principalarn"] = rapid.SampledFrom([]eval.StringSet{eval.Glob("arn:aws:iam::111122223333:*"), eval.Unknown("x"), eval.Glob("arn:aws:iam::*")}).Draw(t, "arn pattern")
		}
		return drawnGrant{grantOf(aws.AWSPrincipalIssuer, term), Facts{PrincipalModelled: true}}
	case 4:
		facts := perTenantFacts("tenant-1", rapid.SampledFrom([]Kind{KindName, KindID}).Draw(t, "tenant kind"),
			rapid.SampledFrom([]Established{Unverified, Yes, No}).Draw(t, "recyclable"),
			rapid.SampledFrom([]Membership{MembershipUnverified, Controlled, OpenToAnyone}).Draw(t, "membership"))
		return drawnGrant{grantOf("https://oidc.example.com/tenant-1", eval.Term{"sub": eval.Exact("x")}), facts}
	case 5:
		population := rapid.SampledFrom([]aws.Population{aws.EveryIssuer, aws.AWSServices, aws.AccountSAMLProviders, aws.AWSServicesAndAccountSAMLProviders}).Draw(t, "population")
		return drawnGrant{grantOf("", eval.Term{}), Facts{Issuerless: population, PrincipalModelled: true}}
	case 6:
		issuer := rapid.SampledFrom([]trust.IssuerRef{samlVendor, serviceIssuer("sns.amazonaws.com"), serviceIssuer(rapid.SampledFrom(intermediaryServices).Draw(t, "intermediary"))}).Draw(t, "unread")
		return drawnGrant{grantOf(issuer, genSourceTerm(t)), Facts{PrincipalModelled: true}}
	}
	issuer := rapid.SampledFrom([]trust.IssuerRef{cognitoIssuer, googleIssuer, facebookIssuer, "https://ci.example.com"}).Draw(t, "other issuer")
	return drawnGrant{grantOf(issuer, eval.Term{"sub": eval.Exact("x")}), censusFacts(issuer)}
}

// intermediaryServices are the services the parser's table of
// intermediaries lists, each of which AWS documents as assuming a role for
// identities outside IAM. The generators draw them beside a service the
// table does not list.
var intermediaryServices = []string{"rolesanywhere.amazonaws.com", "credentials.iot.amazonaws.com", "ssm.amazonaws.com", "pods.eks.amazonaws.com", "transfer.amazonaws.com"}

func serviceIssuer(name string) trust.IssuerRef {
	return trust.IssuerRef(aws.ServiceIssuerPrefix + name)
}

// isIntermediary reports whether a grant's issuer is a service the
// generators draw as one the table lists.
func isIntermediary(issuer trust.IssuerRef) bool {
	return slices.ContainsFunc(intermediaryServices, func(name string) bool { return serviceIssuer(name) == issuer })
}

// genSourceTerm draws the conditions a service's grant may carry: none, or
// the source account and the source ARN AWS recommends, read exactly, so
// that a place a later reading of them could make certain is drawn with
// them already there.
func genSourceTerm(t *rapid.T) eval.Term {
	term := eval.Term{}
	if rapid.Bool().Draw(t, "source account") {
		term["aws:sourceaccount"] = eval.Exact(rapid.SampledFrom(universeAccounts).Draw(t, "source account id"))
	}
	if rapid.Bool().Draw(t, "source arn") {
		term["aws:sourcearn"] = rapid.SampledFrom([]eval.StringSet{
			eval.Exact("arn:aws:rolesanywhere:us-east-1:111122223333:trust-anchor/TA_ID"),
			eval.Glob("arn:aws:ssm:us-east-1:111122223333:*"),
		}).Draw(t, "source arn value")
	}
	return term
}

// genAnyDeclared draws declarations over every namespace the generators pin
// in, so that each kind of grant meets a declaration that matches it, and
// the URLs of the other issuers the generators draw, which a user
// running one of them would declare, though that moves none of their
// grants.
func genAnyDeclared(t *rapid.T) []Declaration {
	candidates := []string{
		"github:acme", "github:@123456", "github:beta@654321", "github:ACME",
		"aws:111122223333", "aws:o-a1b2c3d4e5", "saml:" + string(samlVendor),
		"issuer:https://oidc.example.com/tenant-1",
		"issuer:" + string(cognitoIssuer), "issuer:" + string(googleIssuer), "issuer:" + string(facebookIssuer), "issuer:https://ci.example.com",
	}
	var lines []string
	for _, c := range candidates {
		if rapid.IntRange(0, 2).Draw(t, "declare "+c) == 0 {
			lines = append(lines, c)
		}
	}
	d := ReadDeclarations(strings.Join(lines, "\n"))
	if d.Overrun != nil || len(d.Refused) != 0 {
		t.Fatalf("the generator wrote a declaration the parser refused: %+v %v", d.Overrun, d.Refused)
	}
	return d.Owners
}

// unverifications are every census fact turned to what the census writes
// when no vendor sentence establishes it.
var unverifications = []struct {
	name   string
	forget func(*Facts)
}{
	{"the issuer", func(f *Facts) { f.IssuerKind = NotSurveyed }},
	{"anonymous tokens", func(f *Facts) { f.AnonymousTokens = Unverified }},
	{"the namespace", func(f *Facts) { f.Namespace = "" }},
	{"the tenancy facts", func(f *Facts) { f.Tenancy = nil }},
	{"the owner characters", func(f *Facts) {
		if f.Tenancy != nil {
			f.Tenancy.OwnerCharacters = nil
		}
	}},
	{"the case rule", func(f *Facts) {
		if f.Tenancy != nil {
			f.Tenancy.NamesIgnoreCase = false
		}
	}},
	{"the tenant", func(f *Facts) { f.Tenant.Value = "" }},
	{"the membership", func(f *Facts) { f.Tenant.Membership = MembershipUnverified }},
	{"the recyclability", func(f *Facts) { f.Tenant.Recyclable = Unverified }},
	{"the population", func(f *Facts) { f.Issuerless = aws.EveryIssuer }},
	{"the principal", func(f *Facts) { f.PrincipalModelled = false }},
}

// TestUnverifiedFactsNeverMoveAGrantInward is data monotonicity: turning
// any census fact to unverified never moves a grant inward, never out of
// the rings, and never makes a place it leaves where it was more certain
// than it was.
func TestUnverifiedFactsNeverMoveAGrantInward(t *testing.T) {
	compared, moved, lessCertain, intermediaries := 0, 0, 0, 0
	enoughExamples(t, func(t *rapid.T) {
		d := genAnyGrant(t)
		declared := genAnyDeclared(t)
		if isIntermediary(d.grant.Issuer) {
			intermediaries++
		}
		before := Classify(d.grant, d.facts, declared)
		for _, u := range unverifications {
			facts := d.facts
			if facts.Tenancy != nil {
				tenancy := *facts.Tenancy
				facts.Tenancy = &tenancy
			}
			u.forget(&facts)
			after := Classify(d.grant, facts, declared)
			compared++
			if after.Outcome != before.Outcome {
				t.Fatalf("forgetting %s turned %s into %s", u.name, before, after)
			}
			rb, ra := ringOf(before), ringOf(after)
			switch {
			case ra == Anyone:
			case rb < 0 && ra >= 0, rb >= 0 && ra < 0:
				t.Fatalf("forgetting %s moved %s to %s", u.name, before, after)
			case rb < 0 && !slices.Equal(before.Places, after.Places):
				t.Fatalf("forgetting %s moved %s to %s", u.name, before, after)
			case ra > rb:
				t.Fatalf("forgetting %s moved %s inward to %s", u.name, before, after)
			}
			if ra != rb {
				moved++
			}
			if slices.Equal(before.Places, after.Places) {
				if before.State == StateUnknown && after.State == StateExact {
					t.Fatalf("forgetting %s made %s certain: %s", u.name, before, after)
				}
				if before.State == StateExact && after.State == StateUnknown {
					lessCertain++
				}
			}
		}
	})
	if compared == 0 || moved == 0 || lessCertain == 0 || intermediaries == 0 {
		t.Fatalf("compared=%d moved=%d lessCertain=%d intermediaries=%d; every count must be positive", compared, moved, lessCertain, intermediaries)
	}
	t.Logf("compared=%d moved=%d lessCertain=%d intermediaries=%d", compared, moved, lessCertain, intermediaries)
}

// policyStatement is one generated statement of a trust policy.
type policyStatement struct {
	sid        string
	effect     string
	principal  string
	action     string
	conditions []policyCondition
}

type policyCondition struct {
	operator, key string
	values        []string
}

var (
	// GitHub, any AWS account and the web-identity action GitHub's tokens
	// need are drawn more often than the rest, because a condition pins an
	// owner there, and so removing one moves a grant.
	policyPrincipals = []string{
		`{"Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"}`,
		`{"Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"}`,
		`{"Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"}`,
		`"*"`,
		`{"AWS": "*"}`,
		`{"AWS": "*"}`,
		`{"AWS": "111122223333"}`,
		`{"AWS": "arn:aws:iam::111122223333:role/deploy"}`,
		`{"Federated": "cognito-identity.amazonaws.com"}`,
		`{"Federated": "accounts.google.com"}`,
		`{"Federated": "arn:aws:iam::123456789012:oidc-provider/oidc.eks.us-east-1.amazonaws.com/id/EXAMPLED539D4633E53DE1B71EXAMPLE"}`,
		`{"Federated": "` + string(samlVendor) + `"}`,
		`{"Service": "sns.amazonaws.com"}`,
		`{"Federated": "arn:aws:iam::123456789012:oidc-provider/ci.example.com"}`,
		`{"CanonicalUser": "79a59df900b949e55d96a1e698fbacedfd6e09d98eacf8f8d5218e7cd47ef2be"}`,
		`{"AWS": ["111122223333", "arn:aws:s3:::acme-artifacts"]}`,
	}
	policyActions = []string{
		`"sts:AssumeRoleWithWebIdentity"`, `"sts:AssumeRoleWithWebIdentity"`, `"sts:AssumeRole"`, `"sts:AssumeRoleWithSAML"`, `"sts:*"`,
		`["sts:AssumeRole", "sts:AssumeRoleWithSAML"]`,
	}
	policyOperators = []string{"StringEquals", "StringLike", "StringEquals", "StringLike", "ForAllValues:StringLike", "StringEqualsIfExists"}
	policyKeys      = []string{
		"token.actions.githubusercontent.com:sub", "token.actions.githubusercontent.com:sub",
		"token.actions.githubusercontent.com:aud", "token.actions.githubusercontent.com:repository_owner",
		"token.actions.githubusercontent.com:repository_owner_id", "token.actions.githubusercontent.com:repository_id",
		"token.actions.githubusercontent.com:actor_id",
		"aws:PrincipalAccount", "aws:PrincipalOrgID", "aws:PrincipalArn", "sts:ExternalId", "aws:SourceIp",
	}
)

// genPolicyValue draws a value for a condition on key from the shapes the
// rings read there: values that pin and values that nearly do, owners,
// ids, accounts, ARNs. A value written for one key is sometimes put on
// another, as a policy can.
func genPolicyValue(t *rapid.T, key string) string {
	owner := rapid.SampledFrom(universeOwners).Draw(t, "value owner")
	id := universeIDs[owner]
	byKey := map[string][]string{
		"token.actions.githubusercontent.com:sub": {
			"repo:" + owner + "/*", "repo:" + owner + "*", "repo:" + owner + "@" + id + "/*", "repo:*@" + id + "/*",
			"repo:" + owner + "/infra:ref:refs/heads/main", "job_workflow_ref:" + owner + "/deploy/*",
		},
		"token.actions.githubusercontent.com:aud":                 {"sts.amazonaws.com"},
		"token.actions.githubusercontent.com:repository_owner":    {owner, owner + "*"},
		"token.actions.githubusercontent.com:repository_owner_id": {id, id[:3] + "*"},
		"token.actions.githubusercontent.com:repository_id":       {"456789", "4567*"},
		"token.actions.githubusercontent.com:actor_id":            {"583231"},
		"aws:PrincipalAccount":                                    {"111122223333", "1111*"},
		"aws:PrincipalOrgID":                                      {"o-a1b2c3d4e5", "o-a1b2*"},
		"aws:PrincipalArn":                                        {"arn:aws:iam::111122223333:role/*", "arn:aws:iam::1111*"},
		"sts:ExternalId":                                          {"vendor-abc"},
		"aws:SourceIp":                                            {"x"},
	}
	if rapid.IntRange(0, 4).Draw(t, "another key's value") == 0 {
		key = rapid.SampledFrom(policyKeys).Draw(t, "value key")
	}
	return rapid.SampledFrom(byKey[key]).Draw(t, "value")
}

func genPolicyStatement(t *rapid.T) policyStatement {
	s := policyStatement{
		sid:       "S" + strconv.Itoa(rapid.IntRange(0, 999).Draw(t, "sid")),
		effect:    rapid.SampledFrom([]string{"Allow", "Allow", "Allow", "Deny"}).Draw(t, "effect"),
		principal: rapid.SampledFrom(policyPrincipals).Draw(t, "principal"),
		action:    rapid.SampledFrom(policyActions).Draw(t, "action"),
	}
	one := rapid.Custom(func(t *rapid.T) policyCondition {
		key := rapid.SampledFrom(policyKeys).Draw(t, "key")
		value := rapid.Custom(func(t *rapid.T) string { return genPolicyValue(t, key) })
		return policyCondition{
			operator: rapid.SampledFrom(policyOperators).Draw(t, "operator"),
			key:      key,
			values:   rapid.SliceOfN(value, 1, 2).Draw(t, "values"),
		}
	})
	s.conditions = rapid.SliceOfNDistinct(one, 0, 3, func(c policyCondition) string {
		return c.operator + "\x00" + strings.ToLower(c.key)
	}).Draw(t, "conditions")
	return s
}

func renderPolicy(t *rapid.T, statements []policyStatement) []byte {
	var parts []string
	for _, s := range statements {
		blocks := map[string]map[string][]string{}
		for _, c := range s.conditions {
			if blocks[c.operator] == nil {
				blocks[c.operator] = map[string][]string{}
			}
			blocks[c.operator][c.key] = c.values
		}
		condition, err := json.Marshal(blocks)
		if err != nil {
			t.Fatalf("%v", err)
		}
		parts = append(parts, `{"Sid": "`+s.sid+`", "Effect": "`+s.effect+`", "Principal": `+s.principal+`, "Action": `+s.action+`, "Condition": `+string(condition)+`}`)
	}
	return []byte(`{"Version": "2012-10-17", "Statement": [` + strings.Join(parts, ", ") + `]}`)
}

// placeAll reads a document and places every grant of it.
func placeAll(t failer, raw []byte, declared []Declaration) ([]trust.Grant, []Placement) {
	d, grants := parse(t, raw)
	placements := make([]Placement, len(grants))
	for i, g := range grants {
		placements[i] = Classify(g, factsOf(t, g, d), declared)
	}
	return grants, placements
}

// outward reports whether removing a condition can have turned before into
// after: a refusal stays one, a grant that admitted nobody may now be
// anywhere, a grant beside the rings stays where it was, and a grant in a
// ring stays in a ring no nearer than its own.
func outward(before, after Placement) bool {
	switch {
	case before.Outcome == Refused || after.Outcome == Refused:
		return before.Outcome == after.Outcome
	case before.Outcome == Nobody:
		return true
	case after.Outcome == Nobody:
		return false
	case ringOf(before) < 0 || ringOf(after) < 0:
		return slices.Equal(before.Places, after.Places)
	}
	return ringOf(after) <= ringOf(before)
}

// pairOutward pairs every grant of a statement before an edit with one
// after it, on the same issuer, such that each moved only outward, and
// reports whether it could: after[pairing[j]] is before[j]'s. Two
// principals of one issuer are told apart by nothing their grants carry,
// and the engine orders grants by what they admit, so a condition can make
// two of them trade places; every pairing is tried, and a statement
// projects a handful of grants.
func pairOutward(before, after []trust.Grant, from, to []Placement) ([]int, bool) {
	pairing := make([]int, len(before))
	used := make([]bool, len(after))
	var pair func(j int) bool
	pair = func(j int) bool {
		if j == len(before) {
			return true
		}
		for k := range after {
			if used[k] || after[k].Issuer != before[j].Issuer || !outward(from[j], to[k]) {
				continue
			}
			used[k], pairing[j] = true, k
			if pair(j + 1) {
				return true
			}
			used[k] = false
		}
		return false
	}
	return pairing, len(before) == len(after) && pair(0)
}

// TestRemovingAConditionNeverMovesAGrantInward is removal monotonicity, in
// TestMonotonicityOfIgnorance's form: removing a condition from a statement
// never moves a grant of it inward. Adding one is not the law: a key
// written twice widens by design.
func TestRemovingAConditionNeverMovesAGrantInward(t *testing.T) {
	exercised, moved, pinned := 0, 0, 0
	enoughExamples(t, func(t *rapid.T) {
		s := genPolicyStatement(t)
		if len(s.conditions) == 0 {
			return
		}
		i := rapid.IntRange(0, len(s.conditions)-1).Draw(t, "removed")
		reduced := s
		reduced.conditions = slices.Concat(s.conditions[:i], s.conditions[i+1:])
		declared := genAnyDeclared(t)
		fullGrants, full := placeAll(t, renderPolicy(t, []policyStatement{s}), declared)
		lessGrants, less := placeAll(t, renderPolicy(t, []policyStatement{reduced}), declared)
		pairing, ok := pairOutward(fullGrants, lessGrants, full, less)
		if !ok {
			t.Fatalf("removing %+v moved a grant inward, or out of its issuer:\nbefore %v\nafter  %v", s.conditions[i], full, less)
		}
		for j, k := range pairing {
			if full[j].Outcome == Refused {
				continue
			}
			exercised++
			if ringOf(less[k]) != ringOf(full[j]) {
				moved++
			}
			if r := ringOf(full[j]); r == Outsider || r == Yours {
				pinned++
			}
		}
	})
	if exercised == 0 || moved == 0 || pinned == 0 {
		t.Fatalf("exercised=%d moved=%d pinned=%d; every count must be positive", exercised, moved, pinned)
	}
	t.Logf("exercised=%d moved=%d pinned=%d", exercised, moved, pinned)
}

// placementsOf renders every placement of a document, sorted, so that two
// documents holding the same statements in another order compare equal.
func placementsOf(t failer, raw []byte, declared []Declaration) []string {
	grants, placements := placeAll(t, raw, declared)
	out := make([]string, len(placements))
	for i, p := range placements {
		out[i] = string(grants[i].Issuer) + " " + grants[i].Admits.String() + " " + p.String()
	}
	slices.Sort(out)
	return out
}

// TestStatementOrderNeverMovesAGrant: shuffling the statements of a policy
// places every grant where it was: the parser's order independence, one
// layer up, where a placement that returned from inside the statement loop
// would fail it.
func TestStatementOrderNeverMovesAGrant(t *testing.T) {
	shuffled, multi := 0, 0
	enoughExamples(t, func(t *rapid.T) {
		statements := rapid.SliceOfN(rapid.Custom(genPolicyStatement), 2, 5).Draw(t, "statements")
		identity := make([]int, len(statements))
		for i := range identity {
			identity[i] = i
		}
		perm := rapid.Permutation(identity).Draw(t, "permutation")
		reordered := make([]policyStatement, len(statements))
		for i, p := range perm {
			reordered[i] = statements[p]
		}
		if !slices.Equal(perm, identity) {
			shuffled++
		}
		declared := genAnyDeclared(t)
		a := placementsOf(t, renderPolicy(t, statements), declared)
		b := placementsOf(t, renderPolicy(t, reordered), declared)
		if len(a) > 1 {
			multi++
		}
		if !slices.Equal(a, b) {
			t.Fatalf("statement order moved a grant:\n%v\n%v", a, b)
		}
	})
	if shuffled == 0 || multi == 0 {
		t.Fatalf("shuffled=%d multi=%d; every count must be positive", shuffled, multi)
	}
	t.Logf("shuffled=%d multi=%d", shuffled, multi)
}

// TestOwnerOrderNeverMovesAGrant: the order owners are declared in changes
// neither the owners read nor any placement, because declaring acme then
// beta and declaring beta then acme ask one question.
func TestOwnerOrderNeverMovesAGrant(t *testing.T) {
	permuted, declaredSome := 0, 0
	enoughExamples(t, func(t *rapid.T) {
		d := genAnyGrant(t)
		lines := rapid.SliceOfN(rapid.SampledFrom([]string{
			"github:acme", "github:@123456", "github:beta@654321", "github:acme@123456", "aws:111122223333",
			"aws:o-a1b2c3d4e5", "saml:" + string(samlVendor), "issuer:https://oidc.example.com/tenant-1", "gitlab:x", "nonsense",
		}), 0, 6).Draw(t, "lines")
		order := make([]int, len(lines))
		for i := range order {
			order[i] = i
		}
		perm := rapid.Permutation(order).Draw(t, "permutation")
		reordered := make([]string, len(lines))
		for i, p := range perm {
			reordered[i] = lines[p]
		}
		if !slices.Equal(perm, order) {
			permuted++
		}
		a, b := ReadDeclarations(strings.Join(lines, "\n")), ReadDeclarations(strings.Join(reordered, "\n"))
		if a.Overrun != nil || b.Overrun != nil {
			t.Fatalf("%+v %+v", a.Overrun, b.Overrun)
		}
		if !slices.Equal(a.Owners, b.Owners) {
			t.Fatalf("declaration order changed the owners read: %v and %v", texts(a.Owners), texts(b.Owners))
		}
		reversed := slices.Clone(a.Owners)
		slices.Reverse(reversed)
		pa, pb, pr := Classify(d.grant, d.facts, a.Owners), Classify(d.grant, d.facts, b.Owners), Classify(d.grant, d.facts, reversed)
		if pa.String() != pb.String() || pa.String() != pr.String() {
			t.Fatalf("declaration order moved a grant: %s, %s, %s", pa, pb, pr)
		}
		if slices.ContainsFunc(pa.Owners, func(o Owner) bool { return o.Declared }) {
			declaredSome++
		}
	})
	if permuted == 0 || declaredSome == 0 {
		t.Fatalf("permuted=%d declaredSome=%d; every count must be positive", permuted, declaredSome)
	}
	t.Logf("permuted=%d declaredSome=%d", permuted, declaredSome)
}

// declaredCounterpart is where declaring can move a place, and the only
// places it can move: a named outsider to yours, and a SAML provider's
// sign-ins to your people. Nothing moves out of anyone, off the platform,
// outward, or out of the rings.
func declaredCounterpart(p Place) Place {
	switch p {
	case Outsider:
		return Yours
	case SAML:
		return People
	}
	return p
}

// TestDeclaringOnlyMovesInward: declaring owners, from none and then more,
// moves a named outsider to yours and a SAML provider to your people, and
// does nothing else. The run counts the times a grant at anyone met its own
// issuer's URL newly declared, since nothing moves out of anyone and a run
// that never declared one proves nothing of it.
func TestDeclaringOnlyMovesInward(t *testing.T) {
	compared, moved, ownIssuer := 0, 0, 0
	enoughExamples(t, func(t *rapid.T) {
		d := genAnyGrant(t)
		fewer := genAnyDeclared(t)
		more := slices.Concat(fewer, genAnyDeclared(t))
		for _, step := range [][2][]Declaration{{nil, fewer}, {fewer, more}} {
			before := Classify(d.grant, d.facts, step[0])
			after := Classify(d.grant, d.facts, step[1])
			compared++
			if ringOf(before) == Anyone && !declaresIssuer(step[0], d.grant.Issuer) && declaresIssuer(step[1], d.grant.Issuer) {
				ownIssuer++
			}
			if before.Outcome != after.Outcome || len(before.Places) != len(after.Places) {
				t.Fatalf("declaring more moved %s to %s", before, after)
			}
			for i, place := range before.Places {
				if after.Places[i] != place && after.Places[i] != declaredCounterpart(place) {
					t.Fatalf("declaring more moved %s to %s", before, after)
				}
				if after.Places[i] != place {
					moved++
				}
			}
			// Each alternative is held to the same law, and an owner declared
			// stays declared, wherever its alternative now lies.
			for i, pop := range before.Populations {
				now := after.Populations[i]
				if now.Place != pop.Place && now.Place != declaredCounterpart(pop.Place) {
					t.Fatalf("declaring more moved alternative %s to %s", pop, now)
				}
				for _, o := range pop.Owners {
					if o.Declared && !slices.ContainsFunc(now.Owners, func(a Owner) bool { return a.Declared && a.Value == o.Value && a.Scope == o.Scope }) {
						t.Fatalf("declaring more undeclared %s: %s to %s", o, pop, now)
					}
				}
			}
		}
	})
	if compared == 0 || moved == 0 || ownIssuer == 0 {
		t.Fatalf("compared=%d moved=%d ownIssuer=%d; every count must be positive", compared, moved, ownIssuer)
	}
	t.Logf("compared=%d moved=%d ownIssuer=%d", compared, moved, ownIssuer)
}

// declaresIssuer reports whether one of the declarations is issuer's own
// URL.
func declaresIssuer(declared []Declaration, issuer trust.IssuerRef) bool {
	return slices.ContainsFunc(declared, func(d Declaration) bool { return d.Namespace == NamespaceIssuer && d.Value == string(issuer) })
}

// crossProviderGrants parses every provider's document of every conformance
// case, once.
func crossProviderGrants(t *testing.T) map[string]map[trust.Provider]trust.Grant {
	const grantsDir = "../../testdata/grants"
	parsers := map[trust.Provider]func([]byte) ([]trust.Grant, error){
		trust.AWS: func(raw []byte) ([]trust.Grant, error) {
			d, err := aws.ParseTrustPolicy(raw)
			if err != nil {
				return nil, err
			}
			return d.Grants(role, vocabulary), nil
		},
		trust.Azure: func(raw []byte) ([]trust.Grant, error) {
			c, err := azure.ParseFederatedCredential(raw)
			if err != nil {
				return nil, err
			}
			return c.Grants(trust.TargetRef{Kind: "application"}), nil
		},
		trust.GCP: func(raw []byte) ([]trust.Grant, error) {
			p, err := gcp.ParseProvider(raw)
			if err != nil {
				return nil, err
			}
			return p.Grants(trust.TargetRef{Kind: "workload-identity-pool-provider"}), nil
		},
	}
	out := map[string]map[trust.Provider]trust.Grant{}
	for _, c := range trust.Cases() {
		out[c.Name] = map[trust.Provider]trust.Grant{}
		for _, p := range trust.Providers {
			if _, no := c.Inexpressible[p]; no {
				continue
			}
			raw, err := os.ReadFile(filepath.Join(grantsDir, c.Name, string(p)+".json"))
			if err != nil {
				t.Fatalf("%v", err)
			}
			grants, err := parsers[p](raw)
			if err != nil || len(grants) != 1 {
				t.Fatalf("%s/%s: %d grants, %v", c.Name, p, len(grants), err)
			}
			out[c.Name][p] = grants[0]
		}
	}
	return out
}

// TestRingsAreProviderNeutral: every conformance triple in trust.Cases()
// lands in one ring whichever cloud's dialect states it, and whatever the
// user declared. The one provider that can say more than the others for
// a case, and whose parse therefore widens, lands no nearer than they do.
func TestRingsAreProviderNeutral(t *testing.T) {
	grants := crossProviderGrants(t)
	compared, pinned := 0, 0
	enoughExamples(t, func(t *rapid.T) {
		declared := genDeclared(t)
		for _, c := range trust.Cases() {
			places := map[trust.Provider]Placement{}
			for p, g := range grants[c.Name] {
				places[p] = Classify(g, githubFacts(), declared)
			}
			for p, placement := range places {
				for q, other := range places {
					if p == q {
						continue
					}
					compared++
					switch {
					case p == c.Expressive:
						if ringOf(placement) > ringOf(other) {
							t.Fatalf("%s: %s, which widens, placed %s nearer than %s's %s", c.Name, p, placement, q, other)
						}
					case q != c.Expressive && !slices.Equal(placement.Places, other.Places):
						t.Fatalf("%s: %s placed %s, %s placed %s", c.Name, p, placement, q, other)
					}
				}
				if r := ringOf(placement); r == Outsider || r == Yours {
					pinned++
				}
			}
		}
	})
	if compared == 0 || pinned == 0 {
		t.Fatalf("compared=%d pinned=%d; both must be positive", compared, pinned)
	}
	t.Logf("compared=%d pinned=%d", compared, pinned)
}
