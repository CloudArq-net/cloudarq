package gcp

import (
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/CloudArq-net/cloudarq/internal/eval"
	"github.com/CloudArq-net/cloudarq/internal/trust"
)

const (
	githubPool    = "projects/123456789012/locations/global/workloadIdentityPools/github"
	subjectMember = "principal://iam.googleapis.com/" + githubPool + "/subject/" + mainBranch
	poolMember    = "principalSet://iam.googleapis.com/" + githubPool + "/*"
)

func policy(members ...string) []byte {
	quoted := make([]string, len(members))
	for i, m := range members {
		quoted[i] = `"` + m + `"`
	}
	return []byte(`{"version": 1, "etag": "BwYRz0m4XsE=", "bindings": [{"role": "roles/iam.workloadIdentityUser", "members": [` + strings.Join(quoted, ", ") + `]}]}`)
}

// stated renders what a Member states, the exported fields, for
// comparison.
func stated(m Member) string {
	return strings.Join([]string{m.Text, m.Role, m.Condition, m.Pool, m.Selector, m.Attribute, m.Value, m.Resource}, " | ")
}

func mustMembers(t *testing.T, raw []byte) []Member {
	t.Helper()
	members, err := ParseMembers(raw)
	if err != nil {
		t.Fatalf("%v", err)
	}
	return members
}

func mustProvider(t *testing.T, raw string) Provider {
	t.Helper()
	p, err := ParseProvider([]byte(raw))
	if err != nil {
		t.Fatalf("%v", err)
	}
	return p
}

const anyBranchProvider = `{"name": "` + providerName + `", "attributeMapping": {"google.subject": "assertion.sub", "google.groups": "assertion.groups", "attribute.repository": "assertion.repository"}, "attributeCondition": "assertion.sub.startsWith('repo:acme/infra:')", "oidc": {"issuerUri": "https://token.actions.githubusercontent.com", "allowedAudiences": ["` + audienceName + `"]}}`

// TestParseMembers: every member of every binding comes back in document
// order with its role, its condition and, for a workload identity pool
// principal, the pool and what it selects.
func TestParseMembers(t *testing.T) {
	raw := []byte(`{
	  "version": 3,
	  "etag": "BwYRz0m4XsE=",
	  "bindings": [
	    {"role": "roles/iam.workloadIdentityUser", "members": [
	      "` + subjectMember + `",
	      "principalSet://iam.googleapis.com/` + githubPool + `/attribute.repository/acme/infra",
	      "principalSet://iam.googleapis.com/` + githubPool + `/group/admins",
	      "` + poolMember + `",
	      "principalSet://iam.googleapis.com/` + githubPool + `/namespace/default",
	      "principal://iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/acme.svc.id.goog/subject/ns/default/sa/deploy",
	      "principalSet://iam.googleapis.com/` + githubPool + `/attribute./x",
	      "principalSet://iam.googleapis.com/` + githubPool + `/attribute.repository",
	      "principalSet://iam.googleapis.com/` + githubPool + `/subject/x",
	      "principal://iam.googleapis.com/` + githubPool + `/*",
	      "principalSet://iam.googleapis.com/projects/123456789012/locations/global/workforcePools/contractors/*",
	      "principalSet://iam.googleapis.com/locations/global/workforcePools/contractors/*",
	      "principalSet://iam.googleapis.com/` + escapedPool + `/*",
	      "principal://iam.googleapis.com/` + githubPool + `/%73ubject/x",
	      "principalSet://iam.googleapis.com/` + githubPool + `/%2A",
	      "principal://iam.googleapis.com/` + githubPool + `/subject/re%70o",
	      "serviceAccount:deploy@acme-prod.iam.gserviceaccount.com",
	      "user:raha@altostrat.com",
	      "allUsers",
	      "deleted:serviceAccount:x@acme.iam.gserviceaccount.com?uid=1"
	    ]},
	    {"role": "roles/viewer", "members": ["` + poolMember + `"], "condition": {"title": "hours", "expression": "request.time < timestamp('2026-12-31T00:00:00Z')"}},
	    {"role": "roles/editor", "members": []}
	  ]
	}`)
	members := mustMembers(t, raw)
	want := []Member{
		{Text: subjectMember, Role: "roles/iam.workloadIdentityUser", Pool: githubPool, Selector: "subject/" + mainBranch, Attribute: "google.subject", Value: mainBranch},
		{Text: "principalSet://iam.googleapis.com/" + githubPool + "/attribute.repository/acme/infra", Role: "roles/iam.workloadIdentityUser", Pool: githubPool, Selector: "attribute.repository/acme/infra", Attribute: "attribute.repository", Value: "acme/infra"},
		{Text: "principalSet://iam.googleapis.com/" + githubPool + "/group/admins", Role: "roles/iam.workloadIdentityUser", Pool: githubPool, Selector: "group/admins", Attribute: "google.groups", Value: "admins"},
		{Text: poolMember, Role: "roles/iam.workloadIdentityUser", Pool: githubPool, Selector: "*"},
		{Text: "principalSet://iam.googleapis.com/" + githubPool + "/namespace/default", Role: "roles/iam.workloadIdentityUser", Pool: githubPool, Selector: "namespace/default"},
		{Text: "principal://iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/acme.svc.id.goog/subject/ns/default/sa/deploy", Role: "roles/iam.workloadIdentityUser", Pool: "projects/123456789012/locations/global/workloadIdentityPools/acme.svc.id.goog", Selector: "subject/ns/default/sa/deploy", Attribute: "google.subject", Value: "ns/default/sa/deploy"},
		{Text: "principalSet://iam.googleapis.com/" + githubPool + "/attribute./x", Role: "roles/iam.workloadIdentityUser", Pool: githubPool, Selector: "attribute./x"},
		{Text: "principalSet://iam.googleapis.com/" + githubPool + "/attribute.repository", Role: "roles/iam.workloadIdentityUser", Pool: githubPool, Selector: "attribute.repository"},
		{Text: "principalSet://iam.googleapis.com/" + githubPool + "/subject/x", Role: "roles/iam.workloadIdentityUser", Pool: githubPool, Selector: "subject/x"},
		{Text: "principal://iam.googleapis.com/" + githubPool + "/*", Role: "roles/iam.workloadIdentityUser", Pool: githubPool, Selector: "*"},
		{Text: "principalSet://iam.googleapis.com/projects/123456789012/locations/global/workforcePools/contractors/*", Role: "roles/iam.workloadIdentityUser"},
		{Text: "principalSet://iam.googleapis.com/locations/global/workforcePools/contractors/*", Role: "roles/iam.workloadIdentityUser"},
		// A percent escape is kept as written wherever it stands: in the
		// pool, in the selector, whose kind then names no documented form,
		// or in a value.
		{Text: "principalSet://iam.googleapis.com/" + escapedPool + "/*", Role: "roles/iam.workloadIdentityUser", Pool: escapedPool, Selector: "*"},
		{Text: "principal://iam.googleapis.com/" + githubPool + "/%73ubject/x", Role: "roles/iam.workloadIdentityUser", Pool: githubPool, Selector: "%73ubject/x"},
		{Text: "principalSet://iam.googleapis.com/" + githubPool + "/%2A", Role: "roles/iam.workloadIdentityUser", Pool: githubPool, Selector: "%2A"},
		{Text: "principal://iam.googleapis.com/" + githubPool + "/subject/re%70o", Role: "roles/iam.workloadIdentityUser", Pool: githubPool, Selector: "subject/re%70o", Attribute: "google.subject", Value: "re%70o"},
		{Text: "serviceAccount:deploy@acme-prod.iam.gserviceaccount.com", Role: "roles/iam.workloadIdentityUser"},
		{Text: "user:raha@altostrat.com", Role: "roles/iam.workloadIdentityUser"},
		{Text: "allUsers", Role: "roles/iam.workloadIdentityUser"},
		{Text: "deleted:serviceAccount:x@acme.iam.gserviceaccount.com?uid=1", Role: "roles/iam.workloadIdentityUser"},
		{Text: poolMember, Role: "roles/viewer", Condition: "request.time < timestamp('2026-12-31T00:00:00Z')", Pool: githubPool, Selector: "*"},
	}
	if len(members) != len(want) {
		t.Fatalf("%d members, want %d", len(members), len(want))
	}
	for i := range want {
		if got := members[i]; stated(got) != stated(want[i]) {
			t.Errorf("members[%d]\n  got  %s\n  want %s", i, stated(got), stated(want[i]))
		}
	}
	viewer := len(want) - 1
	if members[0].source != "bindings[0].members[0]" || members[viewer].source != "bindings[1].members[0]" || members[viewer].binding != "bindings[1]" {
		t.Errorf("sources %q %q %q", members[0].source, members[viewer].source, members[viewer].binding)
	}
	if !strings.HasPrefix(string(members[viewer].raw), `{"role": "roles/viewer"`) || !strings.HasSuffix(string(members[viewer].raw), `}`) {
		t.Errorf("raw %s", members[viewer].raw)
	}
	// A policy with no bindings is a policy.
	if members := mustMembers(t, []byte(`{"etag": "x"}`)); len(members) != 0 {
		t.Errorf("no bindings: %v", members)
	}
	// The fixed text of a principal, spelt in another case or with a percent
	// escape, still names the pool, in Google's spelling, and the way it
	// differed is kept for Bind to state; a member with no selector, or an
	// empty one, names the pool and selects nothing.
	respelt := map[string]struct {
		selector, attribute, value string
		miscased, escaped          bool
	}{
		"Principal://iam.googleapis.com/" + githubPool + "/subject/x":                                               {"subject/x", "google.subject", "x", true, false},
		"principalset://iam.googleapis.com/" + githubPool + "/*":                                                    {"*", "", "", true, false},
		"principalSet://IAM.googleapis.com/" + githubPool + "/*":                                                    {"*", "", "", true, false},
		"principalSet://iam.googleapis.com/Projects/123456789012/Locations/global/WorkloadIdentityPools/github/*":   {"*", "", "", true, false},
		"principalSet://iam.googleapis.com/projects/123456789012/loc%61tions/global/workloadIdentityPools/github/*": {"*", "", "", false, true},
		"principalSet://iam%2Egoogleapis.com/" + githubPool + "/*":                                                  {"*", "", "", false, true},
		"PrincipalSet://iam.googleapis.com/projects/123456789012/locations/global/workload%49dentityPools/github/*": {"*", "", "", true, true},
		"PRINCIPALSET://iam.googleapis.com/" + githubPool + "/attribute.repository/acme/infra":                      {"attribute.repository/acme/infra", "attribute.repository", "acme/infra", true, false},
		"principalSet://iam.googleapis.com/" + githubPool:                                                           {"", "", "", false, false},
		"principalSet://iam.googleapis.com/" + githubPool + "/":                                                     {"", "", "", false, false},
	}
	for text, want := range respelt {
		m := mustMembers(t, policy(text))[0]
		if m.Pool != githubPool || m.Selector != want.selector || m.Attribute != want.attribute || m.Value != want.value || m.spelling.miscased != want.miscased || m.spelling.escaped != want.escaped {
			t.Errorf("%s: %s, spelling %+v", text, stated(m), m.spelling)
		}
	}
	// Text that names no workload identity pool under any reading keeps
	// its text alone: another scheme, a scheme holding an escape, which no
	// scheme can, another host, a workforce pool, a service account
	// resource name, or a value segment left empty.
	for _, text := range []string{
		"principals://iam.googleapis.com/" + githubPool + "/*",
		"princip%61l://iam.googleapis.com/" + githubPool + "/subject/x",
		"principal:/iam.googleapis.com/" + githubPool + "/subject/x",
		"principalSet://example.com/" + githubPool + "/*",
		"principalSet://iam.googleapis.com",
		"principalSet://iam.googleapis.com/",
		"principalSet://iam.googleapis.com/projects/123456789012/locations/global/workforcePools/contractors/*",
		"principal://iam.googleapis.com/projects/-/serviceAccounts/deploy@acme-prod.iam.gserviceaccount.com",
		"principalSet://iam.googleapis.com/projects//locations/global/workloadIdentityPools/github/*",
		"principalSet://iam.googleapis.com/projects/123456789012/locations//workloadIdentityPools/github/*",
		"principalSet://iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools//*",
		"deleted:principal://iam.googleapis.com/" + githubPool + "/subject/x",
	} {
		if m := mustMembers(t, policy(text))[0]; m.Pool != "" || m.Selector != "" || m.spelling != (resemblance{}) {
			t.Errorf("%s: %s", text, stated(m))
		}
	}
}

// TestNotAPolicy: an error means the input is not an IAM policy, and says
// why; a member that vanished from the list would be silence.
func TestNotAPolicy(t *testing.T) {
	cases := map[string]string{
		``:                                 "empty input",
		`[]`:                               "the document is a list, not an IAM policy",
		`"x"`:                              "the document is a string, not an IAM policy",
		`{"bindings": {}}`:                 `the member "bindings" is an object, not a list`,
		`{"bindings": [], "bindings": []}`: `the member "bindings" is written 2 times`,
		`{"bindings": [1]}`:                "bindings[0] is a number, not a binding",
		`{"bindings": [{"members": "x"}]}`: `the member "members" of bindings[0] is a string, not a list`,
		`{"bindings": [{"members": [1]}]}`: "bindings[0].members[0] is a number, not a string",
		`{"bindings": [{"role": 1, "members": []}]}`:                                           `the member "role" of bindings[0] is a number, not a string`,
		`{"bindings": [{"members": [], "members": []}]}`:                                       `the member "members" of bindings[0] is written 2 times`,
		`{"bindings": [{"members": [], "condition": "x"}]}`:                                    `the member "condition" of bindings[0] is a string, not an object`,
		`{"bindings": [{"members": [], "condition": {"expression": 1}}]}`:                      `the member "expression" of bindings[0].condition is a number, not a string`,
		`{"bindings": [{"members": [], "condition": {"expression": "a", "expression": "b"}}]}`: `the member "expression" of bindings[0].condition is written 2 times`,
		`{"bindings": [{"members": ["x"]}]} x`:                                                 "after the document",
		"\xff":                                                                                 "not valid UTF-8",
	}
	for raw, problem := range cases {
		members, err := ParseMembers([]byte(raw))
		if err == nil || !strings.Contains(err.Error(), problem) {
			t.Errorf("%q: err %v, want %q", raw, err, problem)
		}
		if members != nil {
			t.Errorf("%q: an error came with members", raw)
		}
	}
	// bindings and members are lists of bindings and of members, not of
	// strings, and the sentence stops at "a list".
	if _, err := ParseMembers([]byte(`{"bindings": {}}`)); err == nil || !strings.HasSuffix(err.Error(), "not a list") {
		t.Errorf("%v", err)
	}
	// A binding with no members, no role, or a null condition is read.
	members := mustMembers(t, []byte(`{"bindings": [{"role": null, "members": null, "condition": null}, {"members": ["allUsers"], "condition": {"title": "t"}}]}`))
	if len(members) != 1 || members[0].Text != "allUsers" || members[0].Condition != "" || members[0].Role != "" {
		t.Errorf("%+v", members)
	}
}

// TestParseMembersReadsPolicySearchResults: the shapes Cloud Asset's
// searchAllIamPolicies hands out, one result with the policy under
// "policy" and a page of results, read to the same members as the policy
// alone, each carrying the resource the policy is set on; a page that
// carries a nextPageToken is refused, so that a policy on a later page
// never passes as absent; and an object in none of the three shapes is
// refused rather than read as a policy with no bindings.
func TestParseMembersReadsPolicySearchResults(t *testing.T) {
	const account = "//iam.googleapis.com/projects/acme-prod/serviceAccounts/deploy@acme-prod.iam.gserviceaccount.com"
	result := `{"resource": "` + account + `", "assetType": "iam.googleapis.com/ServiceAccount", "project": "projects/123456789012", "policy": {"bindings": [{"role": "roles/iam.workloadIdentityUser", "members": ["` + poolMember + `"]}]}}`
	other := `{"resource": "//cloudresourcemanager.googleapis.com/projects/123456789012", "assetType": "cloudresourcemanager.googleapis.com/Project", "policy": {"bindings": [{"role": "roles/viewer", "members": ["` + subjectMember + `"], "condition": {"expression": "request.time < timestamp('2026-12-31T00:00:00Z')"}}]}}`
	members := mustMembers(t, []byte(result))
	want := Member{Text: poolMember, Role: "roles/iam.workloadIdentityUser", Pool: githubPool, Selector: "*", Resource: account}
	if len(members) != 1 || stated(members[0]) != stated(want) || members[0].source != "policy.bindings[0].members[0]" || members[0].binding != "policy.bindings[0]" {
		t.Fatalf("a search result: %+v", members)
	}
	page := mustMembers(t, []byte(`{"results": [`+result+`, `+other+`]}`))
	wantOther := Member{Text: subjectMember, Role: "roles/viewer", Condition: "request.time < timestamp('2026-12-31T00:00:00Z')", Pool: githubPool, Selector: "subject/" + mainBranch, Attribute: "google.subject", Value: mainBranch, Resource: "//cloudresourcemanager.googleapis.com/projects/123456789012"}
	if len(page) != 2 || stated(page[0]) != stated(want) || stated(page[1]) != stated(wantOther) || page[1].source != "results[1].policy.bindings[0].members[0]" {
		t.Fatalf("a page: %+v", page)
	}
	if !strings.HasPrefix(string(page[1].raw), `{"role": "roles/viewer"`) {
		t.Errorf("raw %s", page[1].raw)
	}
	// The bound grant is the same whichever shape the member came in.
	p := mustProvider(t, anyBranchProvider)
	direct, _ := p.Bind(mustMembers(t, policy(poolMember))[0], deployAccount)
	searched, ok := p.Bind(members[0], deployAccount)
	if !ok || searched.Admits.String() != direct.Admits.String() || !searched.Exact() {
		t.Errorf("bound through a search result: %s %v", searched.Admits, searched.Admits.Caveats())
	}
	for raw, members := range map[string]int{
		`{"results": []}`:                      0,
		`{}`:                                   0,
		`{"etag": "ACAB"}`:                     0,
		`{"version": 3, "etag": "ACAB"}`:       0,
		`{"resource": "` + account + `"}`:      0,
		`{"resource": "x", "policy": {}}`:      0,
		`{"results": [{"resource": "x"}]}`:     0,
		`{"results": null}`:                    0,
		`{"policy": null, "resource": "x"}`:    0,
		`{"nextPageToken": "", "results": []}`: 0,
	} {
		if got := mustMembers(t, []byte(raw)); len(got) != members {
			t.Errorf("%s: %d members, want %d", raw, len(got), members)
		}
	}
	refused := map[string]string{
		`{"results": [], "nextPageToken": "CAE="}`:                 "nextPageToken",
		`{"results": [` + result + `], "next_page_token": "CAE="}`: "nextPageToken",
		`{"foo": 1}`:                                   "not an IAM policy, a policy search result or a page of results",
		`{"policy": {}, "bindings": []}`:               "both",
		`{"results": [], "bindings": []}`:              "both",
		`{"results": [], "policy": {}}`:                "both",
		`{"policy": "x"}`:                              `the member "policy" is a string, not an object`,
		`{"resource": 1, "policy": {}}`:                `the member "resource" is a number, not a string`,
		`{"results": [{"resource": 1, "policy": {}}]}`: `the member "resource" of results[0] is a number, not a string`,
		`{"results": {}}`:                              `the member "results" is an object, not a list`,
		`{"results": [1]}`:                             "results[0] is a number, not a policy search result",
		`{"results": [{"foo": 1}]}`:                    "results[0] is not a policy search result",
		`{"results": [{"policy": {"bindings": {}}}]}`:  `the member "bindings" of results[0].policy is an object, not a list`,
		`{"policy": {}, "policy": {}}`:                 `the member "policy" is written 2 times`,
		`{"results": [], "results": []}`:               `the member "results" is written 2 times`,
		`{"nextPageToken": 1, "results": []}`:          `the member "nextPageToken" is a number, not a string`,
		`{"Results": []}`:                              `differs from "results" only in case`,
		`{"Bindings": []}`:                             `differs from "bindings" only in case`,
		`{"Policy": {}}`:                               `differs from "policy" only in case`,
	}
	for raw, problem := range refused {
		members, err := ParseMembers([]byte(raw))
		if err == nil || !strings.Contains(err.Error(), problem) {
			t.Errorf("%s: err %v, want %q", raw, err, problem)
		}
		if members != nil {
			t.Errorf("%s: an error came with members", raw)
		}
	}
}

// binding is one Bind case: the provider, the member text, and what the
// bound grant must say.
type binding struct {
	provider string
	member   string
	bound    bool
	admits   string
	facts    []fact
}

func checkBinding(t *testing.T, name string, c binding) {
	t.Helper()
	p := mustProvider(t, c.provider)
	m := mustMembers(t, policy(c.member))[0]
	g, ok := p.Bind(m, deployAccount)
	if ok != c.bound {
		t.Errorf("%s: bound %v, want %v", name, ok, c.bound)
		return
	}
	if !ok {
		if g.Admits.String() != "∅" || g.Target != (trust.TargetRef{}) {
			t.Errorf("%s: an unbound member came with a grant: %+v", name, g)
		}
		return
	}
	if g.Target != deployAccount || g.Effect != trust.Allow || g.Issuer != p.Grants(githubProvider)[0].Issuer {
		t.Errorf("%s: target %+v effect %s issuer %q", name, g.Target, g.Effect, g.Issuer)
	}
	if got := g.Admits.String(); got != c.admits {
		t.Errorf("%s: admits %s\n  want %s", name, got, c.admits)
	}
	var wantAnomalies []trust.Anomaly
	var wantCaveats []eval.Caveat
	for _, f := range c.facts {
		wantAnomalies = append(wantAnomalies, f.anomaly)
		if f.doubt {
			wantCaveats = append(wantCaveats, eval.Caveat{Claim: f.anomaly.Claim, Reason: f.anomaly.Message, Source: f.anomaly.Source})
		}
	}
	if !slices.Equal(g.Anomalies, canonical(wantAnomalies)) {
		t.Errorf("%s: anomalies%s\n  want%s", name, renderAnomalies(g.Anomalies), renderAnomalies(canonical(wantAnomalies)))
	}
	normalised := eval.Nothing()
	for _, cv := range wantCaveats {
		normalised = normalised.WithCaveat(cv)
	}
	if !slices.Equal(g.Admits.Caveats(), normalised.Caveats()) {
		t.Errorf("%s: caveats\n%s  want\n%s", name, renderCaveats(g.Admits.Caveats()), renderCaveats(normalised.Caveats()))
	}
	for _, term := range g.Admits.Terms() {
		for k, s := range term {
			if eval.IsUnknown(s) && !hasCaveatOn(g.Admits.Caveats(), k) {
				t.Errorf("%s: %s is Unknown without a caveat", name, k)
			}
		}
	}
}

const memberSource = "bindings[0].members[0]"

// The sentences every doubt about a member's form or spelling ends with,
// pinned once: what Google documents, and which text is Google's own.
const (
	documentedFormsSaid = "for a workload identity pool Google documents subject/VALUE under principal://, and group/VALUE, attribute.NAME/VALUE and * under principalSet://, and no other form, so whether Google accepts the member, and which identities it selects, is not stated; the whole pool is read as admitted"
	fixedTextSaid       = "the host iam.googleapis.com or the segments projects, locations and workloadIdentityPools"
)

// undocumented is the doubt for a member that names the pool and selects
// from it by a form Google does not document for it; the construct is the
// selector's kind.
func undocumented(construct, selector string) fact {
	by := "selects from the pool by " + quote(selector)
	if selector == "" {
		by = "names the pool and selects nothing from it"
	}
	return unmodelled("", construct, "the member "+by+"; "+documentedFormsSaid, memberSource)
}

// miscasedMember is the doubt for a member whose fixed text matches
// Google's only in ASCII case.
func miscasedMember(text string) fact {
	return unmodelled("", "spelling", "the member "+quote(text)+" spells the scheme, "+fixedTextSaid+" in another case than Google prints it; whether Google reads it as a workload identity pool principal is not stated, so it is read as the principal it resembles", memberSource)
}

// escapedMember is the doubt for a member whose fixed text holds a percent
// escape.
func escapedMember(text string) fact {
	return unmodelled("", "%", "the member "+quote(text)+" holds a percent escape in "+fixedTextSaid+percentSaid+"whether it is a workload identity pool principal at all is not stated and it is read as the principal it resembles", memberSource)
}

// TestBind: the Meet of the provider's set with what the member selects,
// on the service account, with every doubt from either side declared.
func TestBind(t *testing.T) {
	cases := map[string]binding{
		"subject":   {anyBranchProvider, subjectMember, true, `{` + audience + `, ` + main + `}`, nil},
		"attribute": {anyBranchProvider, "principalSet://iam.googleapis.com/" + githubPool + "/attribute.repository/acme/infra", true, `{` + audience + `, repository="acme/infra", ` + anyBranch + `}`, nil},
		"attribute value with slashes and a colon": {anyBranchProvider, "principalSet://iam.googleapis.com/" + githubPool + "/attribute.repository/a/b:c/d", true, `{` + audience + `, repository="a/b:c/d", ` + anyBranch + `}`, nil},
		"whole pool":                    {anyBranchProvider, poolMember, true, `{` + audience + `, ` + anyBranch + `}`, nil},
		"subject outside the condition": {anyBranchProvider, "principal://iam.googleapis.com/" + githubPool + "/subject/repo:other/x:ref:refs/heads/main", true, `∅`, nil},
		"group":                         {anyBranchProvider, "principalSet://iam.googleapis.com/" + githubPool + "/group/admins", true, `{` + audience + `, groups=?("group membership"), ` + anyBranch + `}`, []fact{unmodelled("groups", "group", groupSentence, memberSource)}},
		"other pool":                    {anyBranchProvider, "principalSet://iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/gitlab/*", false, "", nil},
		"other project":                 {anyBranchProvider, "principalSet://iam.googleapis.com/projects/999999999999/locations/global/workloadIdentityPools/github/*", false, "", nil},
		"other location":                {anyBranchProvider, "principalSet://iam.googleapis.com/projects/123456789012/locations/europe/workloadIdentityPools/github/*", false, "", nil},
		"not a pool principal":          {anyBranchProvider, "serviceAccount:deploy@acme-prod.iam.gserviceaccount.com", false, "", nil},
		"project id in the member":      {anyBranchProvider, "principalSet://iam.googleapis.com/projects/acme-prod/locations/global/workloadIdentityPools/github/*", true, `{` + audience + `, ` + anyBranch + `}`, []fact{unmodelled("", "pool", `the member names the pool "projects/acme-prod/locations/global/workloadIdentityPools/github" and the provider "`+githubPool+`"; whether they are the same project is not stated, so the binding is read as applying to this provider`, memberSource)}},
		"project id in the provider": {strings.Replace(anyBranchProvider, "projects/123456789012/", "projects/acme-prod/", 1), poolMember, true, `{` + audience + `, ` + anyBranch + `}`, []fact{
			unmodelled("", "pool", `the member names the pool "`+githubPool+`" and the provider "projects/acme-prod/locations/global/workloadIdentityPools/github"; whether they are the same project is not stated, so the binding is read as applying to this provider`, memberSource),
		}},
		"project ids that differ": {strings.Replace(anyBranchProvider, "projects/123456789012/", "projects/acme-prod/", 1), "principalSet://iam.googleapis.com/projects/acme-dev/locations/global/workloadIdentityPools/github/*", false, "", nil},
		"provider without a name": {strings.Replace(anyBranchProvider, `"name": "`+providerName+`", `, "", 1), poolMember, true, `{` + audience + `, ` + anyBranch + `}`, []fact{
			unmodelled("", "name", `the provider has no name of the form projects/<number>/locations/<location>/workloadIdentityPools/<pool>/providers/<provider>, so whether the member's pool "`+githubPool+`" is this provider's is not stated; the binding is read as applying to this provider`, "name"),
		}},
		"percent in the value": {anyBranchProvider, "principal://iam.googleapis.com/" + githubPool + "/subject/repo%3Aacme", true, `{` + audience + `, ` + anyBranch + `}`, []fact{unmodelled("sub", "%", `the member's value "repo%3Aacme" contains "%"; whether Google decodes percent escapes in a principal identifier is not documented, so the value is not read and sub is read as unconstrained`, memberSource)}},
		// A percent escape in the pool leaves the pool undecided under
		// either reading, so the member binds this provider with the doubt
		// stated; a segment that differs and holds no escape differs under
		// every reading. One escape is one fact, whichever segment holds it
		// and whether or not the project's spelling would be a doubt too.
		"percent in the pool id":                    {anyBranchProvider, "principalSet://iam.googleapis.com/" + escapedPool + "/*", true, `{` + audience + `, ` + anyBranch + `}`, []fact{unmodelled("", "%", percentInPool, memberSource)}},
		"percent in the location":                   {anyBranchProvider, "principalSet://iam.googleapis.com/projects/123456789012/locations/%67lobal/workloadIdentityPools/github/*", true, `{` + audience + `, ` + anyBranch + `}`, []fact{unmodelled("", "%", `the member names the pool "projects/123456789012/locations/%67lobal/workloadIdentityPools/github", which contains "%"`+percentSaid+`whether it is the provider's pool "`+githubPool+`" is not stated and the binding is read as applying to this provider`, memberSource)}},
		"percent in the project":                    {anyBranchProvider, "principalSet://iam.googleapis.com/projects/12345678901%32/locations/global/workloadIdentityPools/github/*", true, `{` + audience + `, ` + anyBranch + `}`, []fact{unmodelled("", "%", `the member names the pool "projects/12345678901%32/locations/global/workloadIdentityPools/github", which contains "%"`+percentSaid+`whether it is the provider's pool "`+githubPool+`" is not stated and the binding is read as applying to this provider`, memberSource)}},
		"percent in the pool by project id":         {anyBranchProvider, "principalSet://iam.googleapis.com/projects/acme-prod/locations/global/workloadIdentityPools/git%68ub/*", true, `{` + audience + `, ` + anyBranch + `}`, []fact{unmodelled("", "%", `the member names the pool "projects/acme-prod/locations/global/workloadIdentityPools/git%68ub", which contains "%"`+percentSaid+`whether it is the provider's pool "`+githubPool+`" is not stated and the binding is read as applying to this provider`, memberSource)}},
		"percent in the pool, a subject":            {anyBranchProvider, "principal://iam.googleapis.com/" + escapedPool + "/subject/" + mainBranch, true, `{` + audience + `, ` + main + `}`, []fact{unmodelled("", "%", percentInPool, memberSource)}},
		"percent in the pool, another location":     {anyBranchProvider, "principalSet://iam.googleapis.com/projects/123456789012/locations/europe/workloadIdentityPools/git%68ub/*", false, "", nil},
		"percent in the pool, another project":      {anyBranchProvider, "principalSet://iam.googleapis.com/projects/999999999999/locations/global/workloadIdentityPools/git%68ub/*", false, "", nil},
		"percent in the pool, another pool as well": {anyBranchProvider, "principalSet://iam.googleapis.com/projects/12345678901%32/locations/global/workloadIdentityPools/gitlab/*", false, "", nil},
		// A percent escape in the selector's kind leaves the form undecided:
		// as written it is a form Google documents for no pool, decoded it
		// may be any of the four, and the union is at most the whole pool.
		"percent in the selector kind":            {anyBranchProvider, "principal://iam.googleapis.com/" + githubPool + "/%73ubject/" + mainBranch, true, `{` + audience + `, ` + anyBranch + `}`, []fact{unmodelled("", "%", percentInSelect, memberSource)}},
		"percent as the star":                     {anyBranchProvider, "principalSet://iam.googleapis.com/" + githubPool + "/%2A", true, `{` + audience + `, ` + anyBranch + `}`, []fact{unmodelled("", "%", `the member selects from the pool by "%2A", which contains "%"`+percentSaid+`which identities it selects is not stated and the whole pool is read as admitted`, memberSource)}},
		"percent in the attribute name":           {anyBranchProvider, "principalSet://iam.googleapis.com/" + githubPool + "/attribute.%72epository/acme/infra", true, `{` + audience + `, ` + anyBranch + `}`, []fact{unmodelled("", "%", `the member selects from the pool by "attribute.%72epository/acme/infra", which contains "%"`+percentSaid+`which identities it selects is not stated and the whole pool is read as admitted`, memberSource)}},
		"percent for the selector's slash":        {anyBranchProvider, "principal://iam.googleapis.com/" + githubPool + "/subject%2Fx", true, `{` + audience + `, ` + anyBranch + `}`, []fact{unmodelled("", "%", `the member selects from the pool by "subject%2Fx", which contains "%"`+percentSaid+`which identities it selects is not stated and the whole pool is read as admitted`, memberSource)}},
		"percent in the selector of another pool": {anyBranchProvider, "principalSet://iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/gitlab/%2A", false, "", nil},
		"percent in the pool and the selector":    {anyBranchProvider, "principalSet://iam.googleapis.com/" + escapedPool + "/%2A", true, `{` + audience + `, ` + anyBranch + `}`, []fact{unmodelled("", "%", percentInPool, memberSource), unmodelled("", "%", `the member selects from the pool by "%2A", which contains "%"`+percentSaid+`which identities it selects is not stated and the whole pool is read as admitted`, memberSource)}},
		// A subject past Google's limit on google.subject is one no
		// credential maps to; the value is kept, declared an upper bound.
		// The limit is 127 bytes, so a 127-byte subject is exact and a
		// 128-byte one of 72 characters is not.
		"subject over the limit":                                  {anyBranchProvider, subjectMember[:len(subjectMember)-len(mainBranch)] + longSubject, true, `{` + audience + `, sub="` + longSubject + `"}`, []fact{{trust.Anomaly{Kind: SubjectLength, Claim: "sub", Construct: "subject", Message: subjectOverLimit, Source: memberSource}, true}}},
		"subject at the limit":                                    {anyBranchProvider, subjectMember[:len(subjectMember)-len(mainBranch)] + longSubject[:127], true, `{` + audience + `, sub="` + longSubject[:127] + `"}`, nil},
		"subject over the limit in bytes":                         {anyBranchProvider, subjectMember[:len(subjectMember)-len(mainBranch)] + "repo:acme/infra:" + strings.Repeat("é", 56), true, `{` + audience + `, sub=` + strconv.QuoteToASCII("repo:acme/infra:"+strings.Repeat("é", 56)) + `}`, []fact{{trust.Anomaly{Kind: SubjectLength, Claim: "sub", Construct: "subject", Message: `the member selects google.subject ` + quote("repo:acme/infra:"+strings.Repeat("é", 56)) + `, which is 128 bytes long` + subjectLimitSaid, Source: memberSource}, true}}},
		"attribute mapped to the subject's claim, over the limit": {strings.Replace(anyBranchProvider, `"attribute.repository": "assertion.repository"`, `"attribute.repository": "assertion.sub"`, 1), "principalSet://iam.googleapis.com/" + githubPool + "/attribute.repository/" + longSubject, true, `{` + audience + `, sub="` + longSubject + `"}`, []fact{{trust.Anomaly{Kind: SubjectLength, Claim: "sub", Construct: "attribute.repository", Message: `the member selects attribute.repository ` + quote(longSubject) + `, which is 216 bytes long` + subjectLimitSaid, Source: memberSource}, true}}},
		"attribute over the limit":                                {anyBranchProvider, "principalSet://iam.googleapis.com/" + githubPool + "/attribute.repository/" + longSubject, true, `{` + audience + `, repository="` + longSubject + `", ` + anyBranch + `}`, nil},
		"aws default subject over the limit":                      {`{"name": "projects/123456789012/locations/global/workloadIdentityPools/github/providers/aws", "aws": {"accountId": "1"}}`, "principal://iam.googleapis.com/" + githubPool + "/subject/arn:aws:sts::1:assumed-role/" + longSubject, true, `{arn="arn:aws:sts::1:assumed-role/` + longSubject + `", aws:principalaccount="1"}`, []fact{{trust.Anomaly{Kind: SubjectLength, Claim: "arn", Construct: "subject", Message: `the member selects google.subject ` + quote("arn:aws:sts::1:assumed-role/"+longSubject) + `, which is 244 bytes long; Google says google.subject, which maps to arn, cannot exceed 127 bytes, so no credential carrying that value can be exchanged and the set stated is read as an upper bound`, Source: memberSource}, true}}},
		// A selector Google documents for no workload identity pool, or for
		// the GKE pool alone, names the pool and selects from it by a form
		// whose acceptance and meaning the pages do not state: the union of
		// every reading is at most the whole pool, so the member binds as the
		// pool with the doubt stated, never as absent. Google's four forms
		// are the subject, a group, an attribute and the whole pool, each
		// under its own scheme; the scheme is part of the form.
		"unrecognised selector":           {anyBranchProvider, "principalSet://iam.googleapis.com/" + githubPool + "/namespace/default", true, `{` + audience + `, ` + anyBranch + `}`, []fact{undocumented("namespace", "namespace/default")}},
		"gke service account selector":    {anyBranchProvider, "principal://iam.googleapis.com/" + githubPool + "/kubernetes.serviceaccount.uid/abc-123", true, `{` + audience + `, ` + anyBranch + `}`, []fact{undocumented("kubernetes.serviceaccount.uid", "kubernetes.serviceaccount.uid/abc-123")}},
		"gke cluster selector":            {anyBranchProvider, "principalSet://iam.googleapis.com/" + githubPool + "/kubernetes.cluster/https://container.googleapis.com/v1/projects/acme/locations/europe-west1/clusters/prod", true, `{` + audience + `, ` + anyBranch + `}`, []fact{undocumented("kubernetes.cluster", "kubernetes.cluster/https://container.googleapis.com/v1/projects/acme/locations/europe-west1/clusters/prod")}},
		"subject with the wrong scheme":   {anyBranchProvider, "principalSet://iam.googleapis.com/" + githubPool + "/subject/" + mainBranch, true, `{` + audience + `, ` + anyBranch + `}`, []fact{undocumented("subject", "subject/"+mainBranch)}},
		"the pool with the wrong scheme":  {anyBranchProvider, "principal://iam.googleapis.com/" + githubPool + "/*", true, `{` + audience + `, ` + anyBranch + `}`, []fact{undocumented("*", "*")}},
		"attribute with the wrong scheme": {anyBranchProvider, "principal://iam.googleapis.com/" + githubPool + "/attribute.repository/acme/infra", true, `{` + audience + `, ` + anyBranch + `}`, []fact{undocumented("attribute.repository", "attribute.repository/acme/infra")}},
		"group with the wrong scheme":     {anyBranchProvider, "principal://iam.googleapis.com/" + githubPool + "/group/admins", true, `{` + audience + `, ` + anyBranch + `}`, []fact{undocumented("group", "group/admins")}},
		"two stars":                       {anyBranchProvider, "principalSet://iam.googleapis.com/" + githubPool + "/**", true, `{` + audience + `, ` + anyBranch + `}`, []fact{undocumented("**", "**")}},
		"a star with a trailing space":    {anyBranchProvider, "principalSet://iam.googleapis.com/" + githubPool + "/* ", true, `{` + audience + `, ` + anyBranch + `}`, []fact{undocumented("* ", "* ")}},
		"a doubled slash":                 {anyBranchProvider, "principalSet://iam.googleapis.com/" + githubPool + "//*", true, `{` + audience + `, ` + anyBranch + `}`, []fact{undocumented("/*", "/*")}},
		"an empty subject":                {anyBranchProvider, "principal://iam.googleapis.com/" + githubPool + "/subject/", true, `{` + audience + `, ` + anyBranch + `}`, []fact{undocumented("subject", "subject/")}},
		"an empty attribute name":         {anyBranchProvider, "principalSet://iam.googleapis.com/" + githubPool + "/attribute./x", true, `{` + audience + `, ` + anyBranch + `}`, []fact{undocumented("attribute.", "attribute./x")}},
		"an attribute with no value":      {anyBranchProvider, "principalSet://iam.googleapis.com/" + githubPool + "/attribute.repository", true, `{` + audience + `, ` + anyBranch + `}`, []fact{undocumented("attribute.repository", "attribute.repository")}},
		"no selector":                     {anyBranchProvider, "principalSet://iam.googleapis.com/" + githubPool, true, `{` + audience + `, ` + anyBranch + `}`, []fact{undocumented("no selector", "")}},
		"an empty selector":               {anyBranchProvider, "principalSet://iam.googleapis.com/" + githubPool + "/", true, `{` + audience + `, ` + anyBranch + `}`, []fact{undocumented("no selector", "")}},
		// The fixed text of a principal, the scheme, the host and the
		// segments projects, locations and workloadIdentityPools, is
		// Google's own; spelt in another case, or with a percent escape,
		// whether Google reads the member as a pool principal is not stated,
		// so it is read as the principal it resembles with the doubt stated.
		// The values it names are compared as before: a resembled principal
		// of another pool is no binding on this provider.
		"scheme in another case":                   {anyBranchProvider, "Principal://iam.googleapis.com/" + githubPool + "/subject/" + mainBranch, true, `{` + audience + `, ` + main + `}`, []fact{miscasedMember("Principal://iam.googleapis.com/" + githubPool + "/subject/" + mainBranch)}},
		"scheme set in another case":               {anyBranchProvider, "principalset://iam.googleapis.com/" + githubPool + "/*", true, `{` + audience + `, ` + anyBranch + `}`, []fact{miscasedMember("principalset://iam.googleapis.com/" + githubPool + "/*")}},
		"host in another case":                     {anyBranchProvider, "principalSet://IAM.googleapis.com/" + githubPool + "/*", true, `{` + audience + `, ` + anyBranch + `}`, []fact{miscasedMember("principalSet://IAM.googleapis.com/" + githubPool + "/*")}},
		"fixed segments in another case":           {anyBranchProvider, "principalSet://iam.googleapis.com/Projects/123456789012/locations/global/WorkloadIdentityPools/github/*", true, `{` + audience + `, ` + anyBranch + `}`, []fact{miscasedMember("principalSet://iam.googleapis.com/Projects/123456789012/locations/global/WorkloadIdentityPools/github/*")}},
		"a percent escape in a fixed segment":      {anyBranchProvider, "principal://iam.googleapis.com/projects/123456789012/loc%61tions/global/workloadIdentityPools/github/subject/" + mainBranch, true, `{` + audience + `, ` + main + `}`, []fact{escapedMember("principal://iam.googleapis.com/projects/123456789012/loc%61tions/global/workloadIdentityPools/github/subject/" + mainBranch)}},
		"a percent escape in the host":             {anyBranchProvider, "principalSet://iam%2Egoogleapis.com/" + githubPool + "/*", true, `{` + audience + `, ` + anyBranch + `}`, []fact{escapedMember("principalSet://iam%2Egoogleapis.com/" + githubPool + "/*")}},
		"case and an escape in the fixed text":     {anyBranchProvider, "PrincipalSet://iam.googleapis.com/projects/123456789012/locations/global/workload%49dentityPools/github/*", true, `{` + audience + `, ` + anyBranch + `}`, []fact{escapedMember("PrincipalSet://iam.googleapis.com/projects/123456789012/locations/global/workload%49dentityPools/github/*"), miscasedMember("PrincipalSet://iam.googleapis.com/projects/123456789012/locations/global/workload%49dentityPools/github/*")}},
		"a respelt member on an undocumented form": {anyBranchProvider, "Principal://iam.googleapis.com/" + githubPool + "/*", true, `{` + audience + `, ` + anyBranch + `}`, []fact{miscasedMember("Principal://iam.googleapis.com/" + githubPool + "/*"), undocumented("*", "*")}},
		"a respelt member of another pool":         {anyBranchProvider, "Principal://iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/gitlab/subject/x", false, "", nil},
		"a respelt member of another project":      {anyBranchProvider, "principalSet://IAM.googleapis.com/projects/999999999999/locations/global/workloadIdentityPools/github/*", false, "", nil},
		// Members Google documents as other kinds of principal name no
		// workload identity pool: a workforce pool, under a project or not,
		// another host, another scheme, or a deleted principal, which Google
		// documents for workforce pool subjects alone.
		"a workforce pool":                 {anyBranchProvider, "principalSet://iam.googleapis.com/locations/global/workforcePools/contractors/*", false, "", nil},
		"a workforce pool under a project": {anyBranchProvider, "principalSet://iam.googleapis.com/projects/123456789012/locations/global/workforcePools/contractors/*", false, "", nil},
		"another host":                     {anyBranchProvider, "principalSet://example.com/" + githubPool + "/*", false, "", nil},
		"another scheme":                   {anyBranchProvider, "principals://iam.googleapis.com/" + githubPool + "/*", false, "", nil},
		"a scheme with an escape":          {anyBranchProvider, "princip%61l://iam.googleapis.com/" + githubPool + "/subject/x", false, "", nil},
		"a deleted subject":                {anyBranchProvider, "deleted:principal://iam.googleapis.com/" + githubPool + "/subject/x", false, "", nil},
		"a service account":                {anyBranchProvider, "principal://iam.googleapis.com/projects/-/serviceAccounts/deploy@acme-prod.iam.gserviceaccount.com", false, "", nil},
		"expression-mapped attribute":      {strings.Replace(anyBranchProvider, `"attribute.repository": "assertion.repository"`, `"attribute.repository": "assertion.repository.extract('{org}/')"`, 1), "principalSet://iam.googleapis.com/" + githubPool + "/attribute.repository/acme", true, `{` + audience + `, ` + anyBranch + `}`, []fact{unmodelled("", "assertion.repository.extract('{org}/')", `the member selects attribute.repository "acme", which the attribute mapping maps by the expression "assertion.repository.extract('{org}/')"; this parser does not evaluate mapping expressions, so which claim the member constrains is not stated and the whole pool is read as admitted`, memberSource)}},
		"unmapped attribute":               {anyBranchProvider, "principalSet://iam.googleapis.com/" + githubPool + "/attribute.team/ops", true, `{` + audience + `, ` + anyBranch + `}`, []fact{unmodelled("", "attribute.team", `the member selects attribute.team "ops", which the attribute mapping does not map, so which claim the member constrains is not stated and the whole pool is read as admitted`, memberSource)}},
		"unread mapping": {strings.Replace(anyBranchProvider, `"attributeMapping"`, `"attributeMapping": [], "attributeMapping"`, 1), "principalSet://iam.googleapis.com/" + githubPool + "/attribute.repository/acme/infra", true, `{` + audience + `, ` + anyBranch + `}`, []fact{
			{trust.Anomaly{Kind: DuplicateKey, Construct: "attributeMapping", Message: `the member "attributeMapping" is written 2 times; which one Google would apply is not stated, so it is not read`, Source: "attributeMapping"}, false},
			unmodelled("", "attribute.repository", `the member selects attribute.repository "acme/infra", but the attribute mapping is not read, so which claim the member constrains is not stated and the whole pool is read as admitted`, memberSource),
		}},
		"unmapped subject": {strings.Replace(anyBranchProvider, `"google.subject": "assertion.sub", `, "", 1), subjectMember, true, `{` + audience + `, ` + anyBranch + `}`, []fact{unmodelled("", "google.subject", `the member selects google.subject "`+mainBranch+`", which the attribute mapping does not map; Google says the mapping must include google.subject, so which claim the member constrains is not stated and the whole pool is read as admitted`, memberSource)}},
		"saml provider": {`{"name": "` + providerName + `", "attributeMapping": {"google.subject": "assertion.subject"}, "saml": {"idpMetadataXml": "<x/>"}}`, subjectMember, true, `{}`, []fact{
			unmodelled("", "saml", samlSentence, "saml"),
			unmodelled("", "google.subject", `the member selects google.subject "`+mainBranch+`", but the provider is a SAML 2.0 provider, whose assertion this parser does not model as claims, so nothing it says about the credential is modelled`, memberSource),
		}},
		"aws default role attribute": {`{"name": "projects/123456789012/locations/global/workloadIdentityPools/github/providers/aws", "aws": {"accountId": "1"}}`, "principalSet://iam.googleapis.com/" + githubPool + "/attribute.aws_role/arn:aws:sts::1:assumed-role/deploy", true, `{aws:principalaccount="1"}`, []fact{unmodelled("", awsRoleText, `the member selects attribute.aws_role "arn:aws:sts::1:assumed-role/deploy", which Google's default mapping for AWS providers maps by the expression "`+awsRoleText+`"; this parser does not evaluate mapping expressions, so which claim the member constrains is not stated and the whole pool is read as admitted`, memberSource)}},
		"aws default subject":        {`{"name": "projects/123456789012/locations/global/workloadIdentityPools/github/providers/aws", "aws": {"accountId": "1"}}`, "principal://iam.googleapis.com/" + githubPool + "/subject/arn:aws:sts::1:assumed-role/deploy/i-1", true, `{arn="arn:aws:sts::1:assumed-role/deploy/i-1", aws:principalaccount="1"}`, nil},
		"disabled provider":          {strings.Replace(anyBranchProvider, `"name"`, `"disabled": true, "name"`, 1), subjectMember, true, `{` + audience + `, ` + main + `}`, []fact{{trust.Anomaly{Kind: ProviderDisabled, Construct: "disabled", Message: disabledSentence, Source: "disabled"}, true}}},
	}
	for name, c := range cases {
		checkBinding(t, name, c)
	}
}

// TestBindCarriesTheBindingsCondition: an IAM condition on the binding
// narrows what the member gets in ways this parser does not evaluate, so
// the grant is declared an upper bound rather than read as unconditional
// in silence.
func TestBindCarriesTheBindingsCondition(t *testing.T) {
	p := mustProvider(t, anyBranchProvider)
	members := mustMembers(t, []byte(`{"bindings": [{"role": "roles/iam.workloadIdentityUser", "members": ["`+poolMember+`"], "condition": {"expression": "request.time < timestamp('2026-12-31T00:00:00Z')", "title": "until the end of the year"}}]}`))
	g, ok := p.Bind(members[0], deployAccount)
	if !ok {
		t.Fatal("not bound")
	}
	want := trust.Anomaly{Kind: trust.Unmodelled, Construct: "condition", Message: `the binding carries the condition "request.time < timestamp('2026-12-31T00:00:00Z')", which this parser does not evaluate; the grant is read as if the binding applied unconditionally`, Source: "bindings[0].condition"}
	if g.Admits.String() != `{`+audience+`, `+anyBranch+`}` || !slices.Equal(g.Anomalies, []trust.Anomaly{want}) || !hasCaveatOn(g.Admits.Caveats(), "") {
		t.Errorf("%s%s %v", g.Admits, renderAnomalies(g.Anomalies), g.Admits.Caveats())
	}
}

// TestBindIsIndependentOfItsInputs: binding does not change the provider
// or the member, and the bound grant shares no memory with either.
func TestBindIsIndependentOfItsInputs(t *testing.T) {
	p := mustProvider(t, strings.Replace(anyBranchProvider, `"name"`, `"disabled": true, "name"`, 1))
	m := mustMembers(t, policy(subjectMember))[0]
	before := fingerprint(p.Grants(githubProvider)[0])
	g, _ := p.Bind(m, deployAccount)
	g.Anomalies[0].Message = "changed"
	g.Source[0] = 'X'
	if fingerprint(p.Grants(githubProvider)[0]) != before || p.Anomalies[0].Message == "changed" {
		t.Errorf("Bind changed the provider")
	}
	again, _ := p.Bind(m, deployAccount)
	if again.Anomalies[0].Message == "changed" || again.Source[0] == 'X' {
		t.Errorf("Bind shares memory with the caller")
	}
}
