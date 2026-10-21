package report

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"pgregory.net/rapid"

	"github.com/CloudArq-net/cloudarq/internal/parse/aws"
)

// serviceLinkedTrust is the trust policy AWS writes for a service-linked
// role, as ListRoles returns the three an account in an AWS Organization
// holds: the service, and nothing else, may assume it.
func serviceLinkedTrust(service string) string {
	return `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"` + service + `"},"Action":"sts:AssumeRole"}]}`
}

const organizations = "organizations.amazonaws.com"

// awsOwnRoles are the service-linked roles AWS makes in an account that
// joins an AWS Organization and opens support, at the paths IAM lists them.
var awsOwnRoles = []testRole{
	{"aws-service-role/organizations.amazonaws.com/AWSServiceRoleForOrganizations", serviceLinkedTrust(organizations)},
	{"aws-service-role/support.amazonaws.com/AWSServiceRoleForSupport", serviceLinkedTrust("support.amazonaws.com")},
	{"aws-service-role/trustedadvisor.amazonaws.com/AWSServiceRoleForTrustedAdvisor", serviceLinkedTrust("trustedadvisor.amazonaws.com")},
}

// managedShape is a role's managed member as the findings write it.
type managedShape struct {
	By       string `json:"by"`
	Service  string `json:"service"`
	Sentence string `json:"sentence"`
	Caption  string `json:"caption"`
}

// managedIn decodes a role's managed member, which is null for a role
// nothing is said of and must be present either way.
func managedIn(t *testing.T, raw json.RawMessage) *managedShape {
	t.Helper()
	if raw == nil {
		t.Fatal("the role has no managed member")
	}
	var m *managedShape
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("managed is %s: %v", raw, err)
	}
	return m
}

func TestAWSsOwnRolesSayWhatTheyAreAndStayUnknown(t *testing.T) {
	bundle := bundleOf(t, nil, awsOwnRoles...)
	for _, owners := range []string{"", "aws:111122223333\ngithub:acme", strings.Repeat("github:o\n", 65)} {
		f := findingsOf(t, bundle, owners)
		if f.Error != "" || len(f.Roles) != len(awsOwnRoles) {
			t.Fatalf("owners %+q: error %q, %d roles", owners, f.Error, len(f.Roles))
		}
		for i, role := range f.Roles {
			service := strings.Split(awsOwnRoles[i].name, "/")[1]
			want := managedShape{
				By: "aws", Service: service,
				Sentence: "AWS made this role for " + service + " and manages it: the service wrote its trust policy and permissions, and nobody in this account can edit them.",
				Caption: "Who gets in through it is whoever can make " + service + " act. That may be someone this account lets call it, or, if this account's AWS Organization gives the service trusted access, " +
					"the Organization's management account or a delegated administrator. The engine does not read who yet.",
			}
			if got := managedIn(t, role.Managed); got == nil || *got != want {
				t.Errorf("owners %+q, %s: managed %+v, want %+v", owners, role.Name, got, want)
			}
			if !bytes.Equal(role.Answer, admitsWith(nil, []byte(awsOwnRoles[i].document), []byte(owners), bundleRead.recognised())) {
				t.Errorf("owners %+q, %s: the answer is not its trust policy's", owners, role.Name)
			}
		}
	}
	// what the answer says of each is what it said before the role was
	// explained: the service, its callers not read
	for _, role := range findingsOf(t, bundle, "").Roles {
		var a Answer
		if err := json.Unmarshal(role.Answer, &a); err != nil {
			t.Fatal(err)
		}
		if len(a.Grants) != 1 || !slices.Equal(a.Grants[0].Placement, []string{"service"}) || a.Grants[0].PlacementState != "unknown" {
			t.Errorf("%s: the grant is placed %v, %s", role.Name, a.Grants[0].Placement, a.Grants[0].PlacementState)
		}
	}
}

// statements is a trust policy of the statements given.
func statements(s ...string) string {
	return `{"Version":"2012-10-17","Statement":[` + strings.Join(s, ",") + `]}`
}

const (
	allowOrganizations = `{"Effect":"Allow","Principal":{"Service":"organizations.amazonaws.com"},"Action":"sts:AssumeRole"}`
	allowAnAccount     = `{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111122223333:root"},"Action":"sts:AssumeRole"}`
	denyAnAccount      = `{"Effect":"Deny","Principal":{"AWS":"arn:aws:iam::111122223333:root"},"Action":"sts:AssumeRole"}`
)

// TestOnlyAWSsPathAndATrustOfThatServiceAloneAreExplained holds the two
// halves of the rule to their edges. The path is AWS's when it is exactly
// /aws-service-role/ and one segment, which IAM refuses to anyone but AWS;
// the trust is that service's alone when every grant that may admit names
// it and nothing else, and at least one admits. Anything short of either
// is not explained, which costs a sentence and never a finding: the
// explanation moves nothing.
func TestOnlyAWSsPathAndATrustOfThatServiceAloneAreExplained(t *testing.T) {
	const at = "aws-service-role/organizations.amazonaws.com/AWSServiceRoleForOrganizations"
	cases := []struct {
		name      string
		role      testRole
		edit      func(map[string]any)
		explained bool
	}{
		{"AWS's role", testRole{at, serviceLinkedTrust(organizations)}, nil, true},
		{"the service in a list", testRole{at, `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":["organizations.amazonaws.com"]},"Action":"sts:AssumeRole"}]}`}, nil, true},
		{"the service twice", testRole{at, statements(allowOrganizations, allowOrganizations)}, nil, true},
		{"the service bounded by a source account", testRole{at, `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"organizations.amazonaws.com"},"Action":"sts:AssumeRole","Condition":{"StringEquals":{"aws:SourceAccount":"123456789012"}}}]}`}, nil, true},
		{"a Deny of an account beside it", testRole{at, statements(allowOrganizations, denyAnAccount)}, nil, true},
		{"a Deny of anyone beside it", testRole{at, statements(allowOrganizations, `{"Effect":"Deny","Principal":"*","Action":"sts:AssumeRole"}`)}, nil, true},

		{"the path of a service role anybody makes", testRole{"service-role/organizations.amazonaws.com/x", serviceLinkedTrust(organizations)}, nil, false},
		{"AWS's path with no service", testRole{"aws-service-role/x", serviceLinkedTrust(organizations)}, nil, false},
		{"AWS's path in capitals", testRole{"AWS-Service-Role/organizations.amazonaws.com/x", serviceLinkedTrust(organizations)}, nil, false},
		{"a path AWS's begins", testRole{"aws-service-role-x/organizations.amazonaws.com/x", serviceLinkedTrust(organizations)}, nil, false},
		{"AWS's path with two segments", testRole{"aws-service-role/organizations.amazonaws.com/extra/x", serviceLinkedTrust(organizations)}, nil, false},
		{"another service's path", testRole{"aws-service-role/support.amazonaws.com/x", serviceLinkedTrust(organizations)}, nil, false},
		{"the service in capitals in both", testRole{"aws-service-role/Organizations.amazonaws.com/x", serviceLinkedTrust("Organizations.amazonaws.com")}, nil, false},
		{"an account beside the service", testRole{at, `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"organizations.amazonaws.com","AWS":"arn:aws:iam::111122223333:root"},"Action":"sts:AssumeRole"}]}`}, nil, false},
		{"an account in a statement of its own", testRole{at, statements(allowOrganizations, allowAnAccount)}, nil, false},
		{"a second service beside it", testRole{at, `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":["organizations.amazonaws.com","support.amazonaws.com"]},"Action":"sts:AssumeRole"}]}`}, nil, false},
		{"anyone", testRole{at, `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"sts:AssumeRole"}]}`}, nil, false},
		{"any AWS principal", testRole{at, `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}`}, nil, false},
		{"a provider spelling the service's name", testRole{at, `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Federated":"organizations.amazonaws.com"},"Action":"sts:AssumeRoleWithWebIdentity"}]}`}, nil, false},
		{"NotPrincipal", testRole{at, `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","NotPrincipal":{"Service":"organizations.amazonaws.com"},"Action":"sts:AssumeRole"}]}`}, nil, false},
		{"an effect not read, of an account", testRole{at, statements(allowOrganizations, `{"Effect":"Maybe","Principal":{"AWS":"arn:aws:iam::111122223333:root"},"Action":"sts:AssumeRole"}`)}, nil, false},
		{"only a Deny of the service", testRole{at, `{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Principal":{"Service":"organizations.amazonaws.com"},"Action":"sts:AssumeRole"}]}`}, nil, false},
		{"a trust that is not JSON", testRole{at, "not json"}, nil, false},
		{"no trust", testRole{at, serviceLinkedTrust(organizations)}, func(b map[string]any) {
			delete(b["pages"].([]any)[0].(map[string]any)["Roles"].([]any)[0].(map[string]any), "AssumeRolePolicyDocument")
		}, false},
		{"AWS's ARN, listed with no path", testRole{at, serviceLinkedTrust(organizations)}, listedAt(nil), false},
	}
	for _, c := range cases {
		f := findingsOf(t, bundleOf(t, c.edit, c.role), "")
		if f.Error != "" || len(f.Roles) != 1 {
			t.Fatalf("%s: error %q, %d roles", c.name, f.Error, len(f.Roles))
		}
		m := managedIn(t, f.Roles[0].Managed)
		if (m != nil) != c.explained {
			t.Errorf("%s: managed %+v, explained should be %v", c.name, m, c.explained)
		}
		if m != nil && (m.Service != organizations || m.By != "aws") {
			t.Errorf("%s: managed %+v names another service or maker", c.name, m)
		}
	}
}

// policyAt is a one-role bundle of policy at path, or listed with no path
// when path is "".
func policyAt(t interface {
	Helper()
	Fatal(...any)
}, policy, path string) []byte {
	t.Helper()
	role := map[string]any{"RoleName": "r", "RoleId": "AROAR", "Arn": "arn:aws:iam::" + bundleAccount + ":role" + path + "r",
		"CreateDate": "2024-01-02T03:04:05Z", "AssumeRolePolicyDocument": policy}
	if path == "" {
		role["Arn"] = "arn:aws:iam::" + bundleAccount + ":role/r"
	} else {
		role["Path"] = path
	}
	raw, err := json.Marshal(map[string]any{
		"format": "cloudarq.collect/v1", "provider": "aws", "account": bundleAccount, "partition": "aws", "alias": nil,
		"collected_at": "2026-10-02T18:00:00Z", "collector": "cloudarq-collect 0.2.0",
		"pages": []any{map[string]any{"Roles": []any{role}, "IsTruncated": false}}, "refused": []any{}, "limits": []any{},
	})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// bundleRead is the bundle policyAt writes, as far as what it recognises:
// the account it was read from.
var bundleRead = Bundle{Account: bundleAccount}

// servicesOf are the services a policy's grants name, read from the answer.
func servicesOf(policy []byte) []string {
	var services []string
	for _, g := range AnswerOf(policy).Grants {
		if s, ok := strings.CutPrefix(g.Issuer, aws.ServiceIssuerPrefix); ok && !slices.Contains(services, s) {
			services = append(services, s)
		}
	}
	return services
}

// explanations counts what the property saw, so that a run whose inputs
// never reached the case it is about fails instead of passing.
type explanations struct{ explained, notOnAWSsPath, onAWSsPathNotExplained int }

// check holds one policy at one path to the property: whatever the owners,
// the role's answer is the bytes its trust policy gives with the account
// the bundle was read from recognised, wherever the role is listed, and
// what is said of the role is the same with any owners as with none. A role
// explained is on AWS's path for the service it is explained as made for,
// exactly: a path that only resembles AWS's is anybody's.
func (n *explanations) check(t interface {
	Helper()
	Fatal(...any)
	Fatalf(string, ...any)
}, policy []byte, path string, owners []string) {
	t.Helper()
	var said json.RawMessage
	for i, declared := range owners {
		var f findingsShape
		if err := json.Unmarshal(Findings(policyAt(t, string(policy), path), []byte(declared), "cloudarq test"), &f); err != nil || len(f.Roles) != 1 {
			t.Fatalf("at %+q: %v, %+v", path, err, f)
		}
		role := f.Roles[0]
		if want := admitsWith(nil, policy, []byte(declared), bundleRead.recognised()); !bytes.Equal(roleUnkeyed(t, role.Answer), want) {
			t.Fatalf("at %+q with owners %+q, the answer moved:\n got %s\nwant %s\npolicy %s", path, declared, role.Answer, want, policy)
		}
		if role.Managed == nil {
			t.Fatalf("at %+q, the role has no managed member", path)
		}
		if i == 0 {
			said = role.Managed
			var m *managedShape
			if err := json.Unmarshal(said, &m); err != nil {
				t.Fatalf("at %+q, managed is %s: %v", path, said, err)
			}
			switch {
			case m != nil && path != "/aws-service-role/"+m.Service+"/":
				t.Fatalf("at %+q, the role is explained as made for %s: %s\npolicy %s", path, m.Service, said, policy)
			case m != nil:
				n.explained++
			case onAWSsPath(path):
				n.onAWSsPathNotExplained++
			default:
				n.notOnAWSsPath++
			}
		} else if !bytes.Equal(role.Managed, said) {
			t.Fatalf("at %+q, the owners %+q changed what is said of the role: %s, with none %s", path, declared, role.Managed, said)
		}
	}
}

// onAWSsPath reports whether a path is AWS's for one service exactly:
// /aws-service-role/ and one segment. A role there that is not explained
// is one whose trust the rule turned away.
func onAWSsPath(path string) bool {
	service, ok := strings.CutPrefix(path, "/aws-service-role/")
	return ok && len(service) > 1 && strings.Count(service, "/") == 1 && strings.HasSuffix(service, "/")
}

// nearAWSsPath is AWS's path for a service, and the paths that resemble it
// and are anybody's: the path of a service role anyone makes, AWS's in
// capitals, one its first segment only begins, and one a segment deeper.
func nearAWSsPath(service string) []string {
	return []string{
		"/aws-service-role/" + service + "/", "/service-role/" + service + "/", "/AWS-Service-Role/" + service + "/",
		"/aws-service-role-x/" + service + "/", "/aws-service-role/" + service + "/x/",
	}
}

// TestTheExplanationNeverMovesAnAnswerByte is the property over every
// policy of the corpus and over generated ones: at "/", listed with no
// path, and on AWS's path and each path that resembles it, for each service
// the policy names and for one it does not, the role's answer is the one
// its trust policy gives with the bundle's account recognised, byte for
// byte but for the keys every finding of the role carries, which name the
// role and so its path, with no owner, with owners and with owners past
// their bounds; and
// only a role on AWS's own path is explained. A count of zero explained
// roles, or of none on AWS's path left unexplained, fails: the property
// would then have examined only one side of the rule.
func TestTheExplanationNeverMovesAnAnswerByte(t *testing.T) {
	owners := []string{"", "aws:111122223333\ngithub:acme", strings.Repeat("github:o\n", 65)}
	var corpusSeen explanations
	documents := corpus(t)
	rings, err := filepath.Glob(filepath.Join(testdata, "rings", "*", "aws.json"))
	if err != nil || len(rings) == 0 {
		t.Fatalf("%d rings cases: %v", len(rings), err)
	}
	for _, p := range rings {
		raw, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		documents[p] = raw
	}
	for _, policy := range documents {
		paths := []string{"/", ""}
		for _, s := range append(servicesOf(policy), organizations) {
			for _, path := range nearAWSsPath(s) {
				if iamPath(path) && !slices.Contains(paths, path) {
					paths = append(paths, path)
				}
			}
		}
		for _, path := range paths {
			corpusSeen.check(t, policy, path, owners)
		}
	}
	t.Logf("corpus: %d documents, %+v", len(documents), corpusSeen)
	if corpusSeen.explained == 0 || corpusSeen.onAWSsPathNotExplained == 0 || corpusSeen.notOnAWSsPath == 0 {
		t.Fatalf("over the corpus the property saw %+v; a side of the rule went unexamined", corpusSeen)
	}

	var generated explanations
	// Half the draws are a role of AWS's own shape, on its path and trusting
	// the service in every statement, which an Allow among them makes
	// explained; the rest mix the service with every principal the
	// classifier places, at every path, which the rule turns away.
	service := rapid.Custom(func(t *rapid.T) string {
		effect := rapid.SampledFrom([]string{"Allow", "Allow", "Deny"}).Draw(t, "effect")
		return `{"Effect":"` + effect + `","Principal":{"Service":"` + organizations + `"},"Action":"sts:AssumeRole"}`
	})
	anyStatement := rapid.Custom(func(t *rapid.T) string {
		if rapid.Bool().Draw(t, "the service") {
			return service.Draw(t, "service statement")
		}
		return genRemarkStatement(t).text
	})
	rapid.Check(t, func(t *rapid.T) {
		texts := rapid.SliceOfN(service, 1, 3).Draw(t, "AWS's statements")
		path := "/aws-service-role/" + organizations + "/"
		if !rapid.Bool().Draw(t, "AWS's own shape") {
			texts = rapid.SliceOfN(anyStatement, 1, 3).Draw(t, "statements")
			path = rapid.SampledFrom(append([]string{"/", "", "/aws-service-role/sns.amazonaws.com/"}, nearAWSsPath(organizations)...)).Draw(t, "path")
		}
		generated.check(t, []byte(statements(texts...)), path, []string{"", genRemarkOwners(t, "owners", nil)})
	})
	t.Logf("generated: %+v", generated)
	if generated.explained == 0 || generated.onAWSsPathNotExplained == 0 || generated.notOnAWSsPath == 0 {
		t.Fatalf("over generated policies the property saw %+v; a side of the rule went unexamined", generated)
	}
}
