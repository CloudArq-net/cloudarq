package terraform

import (
	"slices"
	"strings"
	"testing"

	"github.com/CloudArq-net/cloudarq/internal/eval"
	"github.com/CloudArq-net/cloudarq/internal/parse/aws"
	"github.com/CloudArq-net/cloudarq/internal/trust"
)

// planOf wraps resource changes, and optionally a configuration and a
// prior state, in a plan document.
func planOf(changes string, extra ...string) []byte {
	doc := `{"format_version": "1.2", "terraform_version": "1.15.5", "resource_changes": [` + changes + `]`
	for _, e := range extra {
		doc += ", " + e
	}
	return []byte(doc + "}")
}

// stateOf wraps root-module resources in a state document.
func stateOf(resources string) []byte {
	return []byte(`{"format_version": "1.0", "terraform_version": "1.15.5", "values": {"root_module": {"resources": [` + resources + `]}}}`)
}

// created is one create change with the given after object and marks.
func created(address, typ, after, unknown, sensitive string) string {
	return `{"address": ` + quote(address) + `, "mode": "managed", "type": ` + quote(typ) + `, "change": {"actions": ["create"], "before": null, "after": ` + after + `, "after_unknown": ` + unknown + `, "before_sensitive": false, "after_sensitive": ` + sensitive + `}}`
}

func quote(s string) string { return `"` + strings.ReplaceAll(s, `"`, `\"`) + `"` }

func planGrants(t *testing.T, raw []byte) []trust.Grant {
	t.Helper()
	p, err := ParsePlan(raw, "plan.json")
	if err != nil {
		t.Fatalf("%v\n%s", err, raw)
	}
	return p.Grants(clock, vocabulary)
}

func stateGrants(t *testing.T, raw []byte) []trust.Grant {
	t.Helper()
	s, err := ParseState(raw, "state.json")
	if err != nil {
		t.Fatalf("%v\n%s", err, raw)
	}
	return s.Grants(clock, vocabulary)
}

// oneWidened asserts that a document states exactly one grant, admitting
// everything with the given anomaly kind and a message holding want.
func oneWidened(t *testing.T, gs []trust.Grant, kind, want string) trust.Grant {
	t.Helper()
	if len(gs) != 1 {
		t.Fatalf("%d grants, want 1:\n%s", len(gs), render(gs))
	}
	g := gs[0]
	a := anomalyOf(g, kind)
	if !g.Admits.IsTop() || g.Exact() || a.Kind == "" || !strings.Contains(a.Message, want) {
		t.Fatalf("admits %s exact %v; %s anomaly %+v, want a message holding %q", g.Admits, g.Exact(), kind, a, want)
	}
	if !slices.ContainsFunc(g.Admits.Caveats(), func(c eval.Caveat) bool { return c.Reason == a.Message }) {
		t.Fatalf("the widening is not the caveat: %v", g.Admits.Caveats())
	}
	return g
}

// TestMalformedShapes: an attribute whose shape the provider's schema
// does not give it, or a string that is not the document it should be,
// widens the grant with the malformed anomaly naming the attribute; the
// reader never hands the parser a guess.
func TestMalformedShapes(t *testing.T) {
	role := func(after string) []byte {
		return planOf(created("aws_iam_role.a", "aws_iam_role", after, `{"arn": true}`, `{}`))
	}
	oneWidened(t, planGrants(t, role(`{"assume_role_policy": {"Statement": []}}`)), Malformed, "assume_role_policy of aws_iam_role.a is an object, not a string")
	oneWidened(t, planGrants(t, role(`{"assume_role_policy": "not json"}`)), Malformed, "assume_role_policy of aws_iam_role.a is not a trust policy document (")

	provider := func(after string) []byte {
		return planOf(created("google_iam_workload_identity_pool_provider.p", "google_iam_workload_identity_pool_provider", after, `{"name": true}`, `{}`))
	}
	oneWidened(t, planGrants(t, provider(`{"attribute_mapping": [1]}`)), Malformed, "attribute_mapping of google_iam_workload_identity_pool_provider.p is a list, not an object")
	oneWidened(t, planGrants(t, provider(`{"disabled": "yes"}`)), Malformed, "disabled of google_iam_workload_identity_pool_provider.p is a string, not a boolean")
	oneWidened(t, planGrants(t, provider(`{"oidc": {"issuer_uri": "https://x"}}`)), Malformed, "oidc of google_iam_workload_identity_pool_provider.p is not a list of at most one object")
	oneWidened(t, planGrants(t, provider(`{"aws": [{"account_id": "1"}, {"account_id": "2"}]}`)), Malformed, "aws of google_iam_workload_identity_pool_provider.p is not a list of at most one object")
	oneWidened(t, planGrants(t, provider(`{"attribute_condition": "\ud800", "oidc": [{"issuer_uri": "https://token.actions.githubusercontent.com"}]}`)), Malformed, "cannot be read as a provider (")

	credential := func(after string) []byte {
		return planOf(created("azuread_application_federated_identity_credential.c", "azuread_application_federated_identity_credential", after, `{"credential_id": true}`, `{}`))
	}
	oneWidened(t, planGrants(t, credential(`{"application_id": "/applications/x", "audiences": ["a"], "issuer": "https://token.actions.githubusercontent.com", "subject": "\ud800"}`)), Malformed, "cannot be read as a credential (")

	binding := func(typ, after string) []byte {
		return planOf(created("google_service_account_iam_"+typ+".b", "google_service_account_iam_"+typ, after, `{"etag": true}`, `{}`))
	}
	oneWidened(t, planGrants(t, binding("policy", `{"service_account_id": "sa", "policy_data": {"bindings": []}}`)), Malformed, "policy_data of google_service_account_iam_policy.b is an object, not a string")
	oneWidened(t, planGrants(t, binding("policy", `{"service_account_id": "sa", "policy_data": "[]"}`)), Malformed, "cannot be read as an IAM policy (")
	oneWidened(t, planGrants(t, binding("binding", `{"service_account_id": "sa", "role": "r", "members": [1]}`)), Malformed, "cannot be read as an IAM policy (")
	oneWidened(t, planGrants(t, binding("binding", `{"service_account_id": "sa", "role": "r", "members": ["user:a"], "condition": {"expression": "x"}}`)), Malformed, "condition of google_service_account_iam_binding.b is not a list of at most one object")
}

// TestProviderShapes: the saml and x509 blocks set the provider's type,
// the aws block its pseudo-issuer, and a provider whose admission is
// unknown still names the issuer it states.
func TestProviderShapes(t *testing.T) {
	provider := func(after, unknown string) []byte {
		return planOf(created("google_iam_workload_identity_pool_provider.p", "google_iam_workload_identity_pool_provider", after, unknown, `{}`))
	}
	saml := planGrants(t, provider(`{"saml": [{"idp_metadata_xml": "<xml/>"}], "attribute_mapping": {"google.subject": "assertion.subject"}}`, `{"name": true}`))
	if len(saml) != 1 || saml[0].Issuer != "" || !strings.Contains(string(saml[0].Source), `"saml":{"idp_metadata_xml":"<xml/>"}`) || !slices.ContainsFunc(saml[0].Anomalies, func(a trust.Anomaly) bool { return a.Kind == trust.Unmodelled && a.Construct == "saml" }) {
		t.Errorf("saml: %s", render(saml))
	}
	x509 := planGrants(t, provider(`{"x509": [{"trust_store": [{"trust_anchors": [{"pem_certificate": "PEM"}]}]}]}`, `{"name": true}`))
	if len(x509) != 1 || !slices.ContainsFunc(x509[0].Anomalies, func(a trust.Anomaly) bool { return a.Kind == trust.Unmodelled && a.Construct == "x509" }) {
		t.Errorf("x509: %s", render(x509))
	}
	// An AWS provider whose condition is unknown names the AWS pseudo-issuer.
	unknownAWS := planGrants(t, provider(`{"aws": [{"account_id": "123456789012"}]}`, `{"attribute_condition": true}`))
	g := oneWidened(t, unknownAWS, KnownAfterApply, "attribute_condition of google_iam_workload_identity_pool_provider.p is known only after apply; the configuration does not describe it")
	if g.Issuer != aws.AWSPrincipalIssuer {
		t.Errorf("issuer %q", g.Issuer)
	}
	// One whose issuer names no host, or whose block is not a list, names none.
	for _, after := range []string{`{"oidc": [{"issuer_uri": "https://"}]}`, `{"oidc": 5}`, `{}`} {
		g := oneWidened(t, planGrants(t, provider(after, `{"attribute_condition": true}`)), KnownAfterApply, "known only after apply")
		if g.Issuer != "" {
			t.Errorf("%s: issuer %q", after, g.Issuer)
		}
	}
	// An Azure credential whose subject is unknown and whose issuer names
	// no host names none either.
	credential := planOf(created("azuread_application_federated_identity_credential.c", "azuread_application_federated_identity_credential", `{"application_id": "/applications/x", "audiences": ["a"], "issuer": ""}`, `{"subject": true}`, `{}`))
	if g := oneWidened(t, planGrants(t, credential), KnownAfterApply, "subject of"); g.Issuer != "" {
		t.Errorf("issuer %q", g.Issuer)
	}
	// A whole object marked unknown marks every attribute.
	whole := oneWidened(t, planGrants(t, provider(`{}`, `true`)), KnownAfterApply, "attribute_condition, attribute_mapping, aws, disabled, oidc, saml and x509 of")
	if whole.Anomalies[0].Construct != "attribute_condition, attribute_mapping, aws, disabled, oidc, saml, x509" {
		t.Errorf("construct %q", whole.Anomalies[0].Construct)
	}
	// A mark on a leaf the reader does not read, a JWKS document inside the
	// oidc block, widens nothing.
	jwks := planGrants(t, provider(`{"attribute_mapping": {"google.subject": "assertion.sub"}, "attribute_condition": "assertion.sub == 'x'", "oidc": [{"issuer_uri": "https://token.actions.githubusercontent.com", "allowed_audiences": ["a"]}]}`, `{"name": true, "oidc": [{"jwks_json": true}]}`))
	if len(jwks) != 1 || !jwks[0].Exact() || jwks[0].Admits.String() != `{aud="a", sub="x"}` {
		t.Errorf("jwks: %s", render(jwks))
	}
}

// TestBindingShapes: a member of a named pool of another location is
// bound by no provider and says so; a provider of another pool id is
// never asked; a member inside a policy_data that is not JSON is
// malformed; and a nil vocabulary reads every AWS claim as Unknown with
// the parser's caveat.
func TestBindingShapes(t *testing.T) {
	other := stateOf(`
	  {"address": "google_iam_workload_identity_pool_provider.p", "mode": "managed", "type": "google_iam_workload_identity_pool_provider", "values": {"name": "projects/123456789012/locations/global/workloadIdentityPools/github/providers/p", "attribute_mapping": {"google.subject": "assertion.sub"}, "oidc": [{"issuer_uri": "https://token.actions.githubusercontent.com", "allowed_audiences": ["a"]}], "workload_identity_pool_id": "github"}, "sensitive_values": {}},
	  {"address": "google_iam_workload_identity_pool_provider.q", "mode": "managed", "type": "google_iam_workload_identity_pool_provider", "values": {"attribute_mapping": {"google.subject": "assertion.sub"}, "oidc": [{"issuer_uri": "https://gitlab.com", "allowed_audiences": ["a"]}], "workload_identity_pool_id": "gitlab"}, "sensitive_values": {}},
	  {"address": "google_service_account_iam_member.m", "mode": "managed", "type": "google_service_account_iam_member", "values": {"service_account_id": "sa", "role": "r", "member": "principalSet://iam.googleapis.com/projects/123456789012/locations/europe/workloadIdentityPools/github/*"}, "sensitive_values": {}},
	  {"address": "data.google_iam_policy.d", "mode": "data", "type": "google_iam_policy", "values": {"policy_data": "{}"}, "sensitive_values": {}}`)
	gs := stateGrants(t, other)
	var bound []trust.Grant
	for _, g := range gs {
		if g.Target.ID == "sa" {
			bound = append(bound, g)
		}
	}
	oneWidened(t, bound, UnboundMember, "names the pool projects/123456789012/locations/europe/workloadIdentityPools/github, and no provider of that pool is in this state")

	nilVocabulary := planOf(created("aws_iam_role.a", "aws_iam_role", `{"assume_role_policy": `+quote(policyFor("repo:acme/x"))+`}`, `{"arn": true}`, `{}`))
	p, err := ParsePlan(nilVocabulary, "plan.json")
	if err != nil {
		t.Fatalf("%v", err)
	}
	gs = p.Grants(clock, nil)
	if len(gs) != 1 || gs[0].Exact() || !gs[0].Admits.IsTop() || !strings.Contains(gs[0].Admits.Caveats()[0].Reason, "claim vocabulary") {
		t.Errorf("a nil vocabulary: %s", render(gs))
	}
}

// TestReadingEdges: the branches a well-formed document rarely takes.
func TestReadingEdges(t *testing.T) {
	// A data document the role references whose rendering is not a string
	// attaches nothing; a resource_changes entry in a module is looked up
	// in the module's configuration.
	role := created("module.m.aws_iam_role.r", "aws_iam_role", `{"name": "r"}`, `{"assume_role_policy": true}`, `{}`)
	config := `"configuration": {"root_module": {"module_calls": {"m": {"module": {"resources": [{"address": "aws_iam_role.r", "expressions": {"assume_role_policy": {"references": ["data.aws_iam_policy_document.d.json", "data.aws_iam_policy_document.d"]}}}]}}}}}`
	prior := `"prior_state": {"format_version": "1.0", "values": {"root_module": {"child_modules": [{"address": "module.m", "resources": [{"address": "module.m.data.aws_iam_policy_document.d", "mode": "data", "type": "aws_iam_policy_document", "values": {"json": null}}]}]}}}`
	g := oneWidened(t, planGrants(t, planOf(role, config, prior)), KnownAfterApply, "the expression references data.aws_iam_policy_document.d.json, so")
	if len(g.Provenance) != 1 || slices.ContainsFunc(g.Anomalies, func(a trust.Anomaly) bool { return a.Kind == RenderedDocument }) {
		t.Errorf("a rendering that is not a string was attached: %s", render([]trust.Grant{g}))
	}
	// A values member with no root_module is a state with nothing in it.
	for _, raw := range []string{`{"format_version": "1.0", "values": {}}`, `{"format_version": "1.0", "values": {"root_module": null}}`, `{"format_version": "1.0", "values": null}`} {
		if s, err := ParseState([]byte(raw), "state.json"); err != nil || len(s.Resources) != 0 {
			t.Errorf("%s: %v %+v", raw, err, s.Resources)
		}
	}
	// A state's data resources are passed over; a values member that is
	// not a resource object, or a child module that is not one, is refused.
	if gs := stateGrants(t, stateOf(`{"address": "data.aws_iam_policy_document.d", "mode": "data", "type": "aws_iam_policy_document", "values": {"json": "{}"}}`)); len(gs) != 0 {
		t.Errorf("a data resource in a state states %d grants", len(gs))
	}
	for raw, want := range map[string]string{
		`{"format_version": "1.0", "values": {"root_module": 1}}`:                                              "values.root_module is not an object",
		`{"format_version": "1.0", "values": {"root_module": {"resources": {}}}}`:                              "values.root_module is not a module object",
		`{"format_version": "1.0", "values": {"root_module": {"resources": [{"address": "a", "values": 5}]}}}`: "values.root_module.resources[0] is not a resource object",
		`{"format_version": "1.0", "values": {"root_module": {"child_modules": {}}}}`:                          "values.root_module is not a module object",
		`{"format_version": "1.0", "values": {"root_module": {"child_modules": [{"resources": 5}]}}}`:          "values.root_module.child_modules[0] is not a module object",
		`{"format_version": "1.0", "values": {"root_module": {"child_modules": [{"child_modules": [1]}]}}}`:    "values.root_module.child_modules[0].child_modules[0] is not an object",
	} {
		if _, err := ParseState([]byte(raw), "state.json"); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v, want %q", raw, err, want)
		}
	}
	for raw, want := range map[string]string{
		`{"format_version": "1.2", "resource_changes": [{"address": "a", "change": {"actions": "x"}}]}`: "resource_changes[0] is not a change object",
		`{"format_version": "1.2", "resource_changes": [], "prior_state": {"values": []}}`:              "prior_state values is not an object",
	} {
		if _, err := ParsePlan([]byte(raw), "plan.json"); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v, want %q", raw, err, want)
		}
	}
	// A target attribute that is absent and unmarked, in a state, stands in
	// its own address with the reason.
	absentTarget := stateOf(`{"address": "google_service_account_iam_member.m", "mode": "managed", "type": "google_service_account_iam_member", "values": {"role": "r", "member": "user:a"}, "sensitive_values": {}}`)
	gs := stateGrants(t, absentTarget)
	if len(gs) != 1 || gs[0].Target.ID != "google_service_account_iam_member.m" || !strings.Contains(anomalyOf(gs[0], TargetAfterApply).Message, "service_account_id of google_service_account_iam_member.m is absent from the document and the expression references no single resource instance of this state") {
		t.Errorf("absent target: %s", render(gs))
	}
	// A binding that names no member states one grant admitting nothing,
	// exactly, rather than none: the emptiness is the document's.
	for _, after := range []string{`{"service_account_id": "sa", "role": "r", "members": []}`, `{"service_account_id": "sa", "policy_data": "{\"bindings\":[]}"}`} {
		typ := "google_service_account_iam_binding"
		if strings.Contains(after, "policy_data") {
			typ = "google_service_account_iam_policy"
		}
		gs := planGrants(t, planOf(created(typ+".b", typ, after, `{"etag": true}`, `{}`)))
		if len(gs) != 1 || !gs[0].Admits.IsEmpty() || !gs[0].Exact() || anomalyOf(gs[0], NoMembers).Message != typ+".b names no member, so it grants nobody anything; the list is known and empty, which is the one emptiness a document proves" || gs[0].Target.ID != "sa" {
			t.Errorf("no members: %s", render(gs))
		}
	}
	// Two unread types are named in type order on every grant, whatever
	// order the document lists them in.
	twoUnread := stateOf(`{"address": "google_iam_workforce_pool_provider.w", "mode": "managed", "type": "google_iam_workforce_pool_provider", "values": {}, "sensitive_values": {}},
	  {"address": "awscc_iam_role.cc", "mode": "managed", "type": "awscc_iam_role", "values": {}, "sensitive_values": {}},
	  {"address": "awscc_iam_role.dd", "mode": "managed", "type": "awscc_iam_role", "values": {}, "sensitive_values": {}},
	  {"address": "aws_iam_role.r", "mode": "managed", "type": "aws_iam_role", "values": {"assume_role_policy": ` + quote(policyFor("repo:acme/x")) + `}, "sensitive_values": {}}`)
	gs = stateGrants(t, twoUnread)
	var unread []string
	for _, a := range gs[0].Anomalies {
		if a.Kind == UnreadResource {
			unread = append(unread, a.Construct+": "+a.Message)
		}
	}
	if !slices.Equal(unread, []string{
		"awscc_iam_role: the state holds 2 instances of awscc_iam_role, which resembles a trust-bearing resource this reader does not map; they were not read",
		"google_iam_workforce_pool_provider: the state holds 1 instance of google_iam_workforce_pool_provider, which resembles a trust-bearing resource this reader does not map; it was not read",
	}) {
		t.Errorf("unread types: %q", unread)
	}
	// Several attributes marked sensitive are named together.
	several := planOf(created("azuread_application_federated_identity_credential.c", "azuread_application_federated_identity_credential", `{"application_id": "/applications/x", "audiences": ["a"], "issuer": "https://token.actions.githubusercontent.com", "subject": "s"}`, `{"credential_id": true}`, `{"issuer": true, "subject": true}`))
	gs = planGrants(t, several)
	if len(gs) != 1 || anomalyOf(gs[0], SensitiveValue).Message != "issuer and subject of azuread_application_federated_identity_credential.c are marked sensitive; they were read and evaluated, and are not quoted: the evidence carries their digest" || !gs[0].Exact() {
		t.Errorf("several sensitive attributes: %s", render(gs))
	}
	// A sensitive provider's document is redacted in the grants bound on it.
	sensitiveProvider := planOf(
		created("google_iam_workload_identity_pool_provider.p", "google_iam_workload_identity_pool_provider", `{"attribute_mapping": {"google.subject": "assertion.sub"}, "attribute_condition": "assertion.sub == 'x'", "oidc": [{"issuer_uri": "https://token.actions.githubusercontent.com", "allowed_audiences": ["a"]}], "workload_identity_pool_id": "github"}`, `{"name": true}`, `{"attribute_condition": true}`) + "," +
			created("google_service_account_iam_member.m", "google_service_account_iam_member", `{"service_account_id": "sa", "role": "r", "member": "principalSet://iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/github/*"}`, `{"etag": true}`, `{}`))
	gs = planGrants(t, sensitiveProvider)
	if len(gs) != 2 || strings.Contains(string(gs[1].Source), "assertion.sub") || !strings.Contains(string(gs[1].Source), "sha256") || strings.Contains(string(gs[1].Provenance[1].Bytes), "assertion.sub") {
		t.Errorf("sensitive provider: %s", render(gs))
	}
}

// changed is one resource change with every side spelt out, for the
// actions a create cannot express.
func changed(address, typ, actions, before, after, unknown, beforeSensitive, afterSensitive string) string {
	return `{"address": ` + quote(address) + `, "mode": "managed", "type": ` + quote(typ) + `, "change": {"actions": ` + actions + `, "before": ` + before + `, "after": ` + after + `, "after_unknown": ` + unknown + `, "before_sensitive": ` + beforeSensitive + `, "after_sensitive": ` + afterSensitive + `}}`
}

// roleValues is a role's attribute object with a known policy, as a state
// or a before side holds it.
func roleValues(name, subject string) string {
	return `{"arn": "arn:aws:iam::123456789012:role/` + name + `", "assume_role_policy": ` + quote(policyFor(subject)) + `, "name": ` + quote(name) + `}`
}

// priorRole is a role in a prior state.
func priorRole(name, subject string) string {
	return `{"address": "aws_iam_role.` + name + `", "mode": "managed", "type": "aws_iam_role", "name": ` + quote(name) + `, "values": ` + roleValues(name, subject) + `, "sensitive_values": {}}`
}

func priorStateOf(resources string) string {
	return `"prior_state": {"format_version": "1.0", "terraform_version": "1.15.5", "values": {"root_module": {"resources": [` + resources + `]}}}`
}

func messageOf(g trust.Grant, kind string) string { return anomalyOf(g, kind).Message }

func fromOf(t *testing.T, g trust.Grant) string {
	t.Helper()
	from, _ := paramsOf(t, g.Provenance[0])["from"].(string)
	return from
}

// TestForgetReadsBefore: a change whose actions include "forget" is read
// from before, as a delete is: Terraform's own plan says the object "will
// no longer be managed by Terraform, but will not be destroyed", so its
// trust continues to exist after apply and is never read as absent. A
// replace that forgets reads both objects, the one created and the one
// forgotten.
func TestForgetReadsBefore(t *testing.T) {
	forgotten := changed("aws_iam_role.r", "aws_iam_role", `["forget"]`, roleValues("r", "repo:acme/infra:ref:refs/heads/main"), "null", "{}", "{}", "false")
	gs := planGrants(t, planOf(forgotten))
	if len(gs) != 1 || !gs[0].Exact() || gs[0].Admits.String() != `{sub="repo:acme/infra:ref:refs/heads/main"}` {
		t.Fatalf("a forgotten role: %s", render(gs))
	}
	g := gs[0]
	if want := "the plan forgets aws_iam_role.r: Terraform will discard its tracking information for it and will not delete it, so the object and what it admits continue to exist, unmanaged, once the plan is applied"; messageOf(g, PlannedForget) != want {
		t.Errorf("planned-forget: %q\n  want %q", messageOf(g, PlannedForget), want)
	}
	if a := anomalyOf(g, PlannedForget); a.Construct != "forget" || a.Source != "aws_iam_role.r" {
		t.Errorf("planned-forget names %+v", a)
	}
	if messageOf(g, TerraformOrigin) != "aws_iam_role.r is read from the plan's prior state, as Terraform last recorded it; the deployed resource was not fetched from the cloud" {
		t.Errorf("origin: %q", messageOf(g, TerraformOrigin))
	}
	if anomalyOf(g, AbsentAttribute).Kind != "" || anomalyOf(g, PlannedDelete).Kind != "" {
		t.Errorf("a forgotten object is read as absent or deleted: %s", render(gs))
	}
	params := g.Provenance[0].Params
	if !strings.Contains(params, `"arn":"arn:aws:iam::123456789012:role/r"`) || !strings.Contains(params, `"name":"r"`) || fromOf(t, g) != "before" {
		t.Errorf("params %s", params)
	}
	p, err := ParsePlan(planOf(forgotten), "plan.json")
	if err != nil || len(p.Resources) != 1 || !slices.Equal(p.Resources[0].Actions, []string{"forget"}) {
		t.Errorf("listing %+v %v", p.Resources, err)
	}

	// A replace that forgets: the created object first, from after, then
	// the forgotten one, from before; both exist once the plan is applied.
	for _, actions := range []string{`["create", "forget"]`, `["forget", "create"]`} {
		replaced := changed("aws_iam_role.r", "aws_iam_role", actions, roleValues("r", "repo:acme/old:*"), `{"assume_role_policy": `+quote(policyFor("repo:acme/new:*"))+`, "name": "r"}`, `{"arn": true}`, "{}", "{}")
		gs := planGrants(t, planOf(replaced))
		if len(gs) != 2 || gs[0].Admits.String() != `{sub="repo:acme/new:*"}` || gs[1].Admits.String() != `{sub="repo:acme/old:*"}` {
			t.Fatalf("%s: %s", actions, render(gs))
		}
		if anomalyOf(gs[0], PlannedForget).Kind != "" || anomalyOf(gs[1], PlannedForget).Kind == "" || fromOf(t, gs[0]) != "after" || fromOf(t, gs[1]) != "before" {
			t.Errorf("%s: the forgotten object is not told from the created one: %s", actions, render(gs))
		}
		p, err := ParsePlan(planOf(replaced), "plan.json")
		if err != nil || len(p.Resources) != 1 {
			t.Errorf("%s: the listing holds %d resources, want one change", actions, len(p.Resources))
		}
	}
	// A delete still reads before, and a replace that deletes reads after
	// alone: the deleted object will not exist.
	deleted := changed("aws_iam_role.r", "aws_iam_role", `["delete", "create"]`, roleValues("r", "repo:acme/old:*"), `{"assume_role_policy": `+quote(policyFor("repo:acme/new:*"))+`, "name": "r"}`, `{"arn": true}`, "{}", "{}")
	if gs := planGrants(t, planOf(deleted)); len(gs) != 1 || gs[0].Admits.String() != `{sub="repo:acme/new:*"}` {
		t.Errorf("a replace that deletes: %s", render(gs))
	}
}

// TestUnlistedPriorState: a plan that lists no change for a resource its
// prior state holds, as a refresh-only plan lists none and a targeted plan
// lists only its targets, reads the resource from the prior state with the
// no-change-listed fact. Terraform's own reason for writing no-op changes
// is to let a consumer tell "we checked something and concluded no changes
// were needed" from "something being entirely excluded e.g. due to
// -target"; an excluded resource still exists and is never read as absent.
func TestUnlistedPriorState(t *testing.T) {
	prior := priorStateOf(priorRole("r", "repo:acme/infra:ref:refs/heads/main") + `, {"address": "data.aws_iam_policy_document.doc", "mode": "data", "type": "aws_iam_policy_document", "values": {"json": "{}"}, "sensitive_values": {}}, {"address": "awscc_iam_role.cc", "mode": "managed", "type": "awscc_iam_role", "values": {}, "sensitive_values": {}}`)
	want := "the plan lists no change for aws_iam_role.r, as a refresh-only plan lists none and a targeted plan lists only its targets; the grant is what the plan's prior state holds, which the plan leaves as it is"

	// The refresh-only shape recorded with Terraform 1.15.5: no
	// resource_changes member, every resource in prior_state, complete true.
	refreshOnly := []byte(`{"format_version": "1.2", "terraform_version": "1.15.5", "planned_values": {"root_module": {}}, ` + prior + `, "applyable": false, "complete": true, "errored": false}`)
	p, err := ParsePlan(refreshOnly, "plan.json")
	if err != nil {
		t.Fatalf("%v", err)
	}
	if len(p.Resources) != 1 || p.Resources[0].Address != "aws_iam_role.r" || p.Resources[0].Actions != nil || len(p.Unread) != 1 || p.Unread[0].Address != "awscc_iam_role.cc" {
		t.Errorf("listing: resources %+v unread %+v", p.Resources, p.Unread)
	}
	gs := p.Grants(clock, vocabulary)
	if len(gs) != 1 || !gs[0].Exact() || gs[0].Admits.String() != `{sub="repo:acme/infra:ref:refs/heads/main"}` {
		t.Fatalf("refresh-only: %s", render(gs))
	}
	g := gs[0]
	if messageOf(g, NoChangeListed) != want || anomalyOf(g, NoChangeListed).Construct != "prior_state" || anomalyOf(g, NoChangeListed).Source != "aws_iam_role.r" {
		t.Errorf("no-change-listed: %+v", anomalyOf(g, NoChangeListed))
	}
	if !strings.Contains(messageOf(g, TerraformOrigin), "read from the plan's prior state") || fromOf(t, g) != "prior_state" || anomalyOf(g, PlanIncomplete).Kind != "" || anomalyOf(g, UnreadResource).Kind == "" {
		t.Errorf("refresh-only grant: %s", render(gs))
	}
	if !strings.Contains(g.Provenance[0].Params, `"arn":"arn:aws:iam::123456789012:role/r"`) {
		t.Errorf("params %s", g.Provenance[0].Params)
	}

	// The targeted shape: one no-op change for the target, the rest in
	// prior_state alone, complete false.
	targeted := planOf(changed("aws_s3_bucket.b", "aws_s3_bucket", `["no-op"]`, `{"bucket": "b"}`, `{"bucket": "b"}`, "{}", "{}", "{}"), prior, `"complete": false`)
	gs = planGrants(t, targeted)
	if len(gs) != 1 || messageOf(gs[0], NoChangeListed) != want || anomalyOf(gs[0], PlanIncomplete).Kind == "" {
		t.Fatalf("targeted: %s", render(gs))
	}

	// An address the plan lists a change for is read from the change, once.
	both := planOf(changed("aws_iam_role.r", "aws_iam_role", `["delete"]`, roleValues("r", "repo:acme/infra:ref:refs/heads/main"), "null", "{}", "{}", "false"), prior)
	gs = planGrants(t, both)
	if len(gs) != 1 || anomalyOf(gs[0], PlannedDelete).Kind == "" || anomalyOf(gs[0], NoChangeListed).Kind != "" {
		t.Fatalf("listed and prior: %s", render(gs))
	}
	// A deposed object listed for the address counts as listed too.
	deposed := planOf(`{"address": "aws_iam_role.r", "mode": "managed", "type": "aws_iam_role", "deposed": "deadbeef", "change": {"actions": ["delete"], "before": `+roleValues("r", "repo:acme/old:*")+`, "after": null, "after_unknown": {}, "before_sensitive": {}, "after_sensitive": false}}`, prior)
	if gs := planGrants(t, deposed); len(gs) != 1 || anomalyOf(gs[0], PlannedDelete).Kind == "" {
		t.Errorf("a deposed change beside a prior current object: %s", render(gs))
	}
	// A plan whose prior state is in a child module lists the module's
	// resource under its absolute address.
	nested := []byte(`{"format_version": "1.2", "planned_values": {"root_module": {}}, "prior_state": {"values": {"root_module": {"child_modules": [{"address": "module.m", "resources": [{"address": "module.m.aws_iam_role.r", "mode": "managed", "type": "aws_iam_role", "values": ` + roleValues("r", "repo:acme/x") + `, "sensitive_values": {}}]}]}}}}`)
	if gs := planGrants(t, nested); len(gs) != 1 || gs[0].Target.ID != "module.m.aws_iam_role.r" || anomalyOf(gs[0], NoChangeListed).Kind == "" {
		t.Errorf("a prior-state module resource: %s", render(gs))
	}
}

// TestEncodingAsWritten: a string attribute whose token holds invalid
// UTF-8 or a lone UTF-16 surrogate escape is not read as the repaired
// string encoding/json would hand over, since the cloud parsers refuse
// both: the grant is malformed with the byte named, and the record digests
// the attribute as the document writes it. Well-formed escapes decode as
// written.
func TestEncodingAsWritten(t *testing.T) {
	policy := func(subject string) string {
		return `"{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"Federated\":\"` + federated + `\"},\"Action\":\"sts:AssumeRoleWithWebIdentity\",\"Condition\":{\"StringEquals\":{\"token.actions.githubusercontent.com:sub\":\"` + subject + `\"}}}]}"`
	}
	role := func(token string) []byte {
		return planOf(created("aws_iam_role.a", "aws_iam_role", `{"assume_role_policy": `+token+`}`, `{"arn": true}`, `{}`))
	}
	invalid := policy("repo:acme/\xff")
	g := oneWidened(t, planGrants(t, role(invalid)), Malformed, "assume_role_policy of aws_iam_role.a holds invalid UTF-8 at byte 310 of the value as written; it is not read and the grant is read as admitting everything")
	if string(g.Provenance[0].Bytes) != `{"malformed":["assume_role_policy"],"sha256":"`+digest(invalid)+`"}` || string(g.Source) != string(g.Provenance[0].Bytes) {
		t.Errorf("record %s\n  source %s", g.Provenance[0].Bytes, g.Source)
	}
	// The escapes below sit in the plan's own string token, one level above
	// the policy, which is where the reader decodes and the parser does not.
	surrogate := policy(`repo:acme/\ud800`)
	g = oneWidened(t, planGrants(t, role(surrogate)), Malformed, `assume_role_policy of aws_iam_role.a holds a lone UTF-16 surrogate escape, \ud800, in the value as written; it is not read`)
	if string(g.Provenance[0].Bytes) != `{"malformed":["assume_role_policy"],"sha256":"`+digest(surrogate)+`"}` {
		t.Errorf("record %s", g.Provenance[0].Bytes)
	}
	// A low surrogate alone, and a high one followed by anything but a low
	// one, are lone too; a pair is one character, and \u00e9 and \/ are what
	// they escape.
	oneWidened(t, planGrants(t, role(policy(`\udc00`))), Malformed, `lone UTF-16 surrogate escape, \udc00,`)
	oneWidened(t, planGrants(t, role(policy(`\ud800\u0041`))), Malformed, `lone UTF-16 surrogate escape, \ud800,`)
	gs := planGrants(t, role(policy(`repo:acme/caf\u00e9:\ud83d\ude00:\/x`)))
	if len(gs) != 1 || !gs[0].Exact() || gs[0].Admits.String() != `{sub="repo:acme/caf\u00e9:\U0001f600:/x"}` {
		t.Errorf("escapes: %s", render(gs))
	}
	// The same escape one level down, inside the policy, is the parser's to
	// refuse, in its own words.
	oneWidened(t, planGrants(t, role(policy(`repo:acme/\\ud800`))), Malformed, "is not a trust policy document (parse trust policy: lone UTF-16 surrogate escape")
	// The malformed record of a policy that is a string but not a document
	// digests the token too.
	g = oneWidened(t, planGrants(t, role(`"not json"`)), Malformed, "is not a trust policy document (")
	if string(g.Provenance[0].Bytes) != `{"malformed":["assume_role_policy"],"sha256":"`+digest(`"not json"`)+`"}` {
		t.Errorf("record %s", g.Provenance[0].Bytes)
	}
	// The same for a binding's policy_data.
	binding := planOf(created("google_service_account_iam_policy.b", "google_service_account_iam_policy", `{"service_account_id": "sa", "policy_data": "{\"bindings\":[{\"role\":\"r\",\"members\":[\"user:\ud800\"]}]}"}`, `{"etag": true}`, `{}`))
	oneWidened(t, planGrants(t, binding), Malformed, `policy_data of google_service_account_iam_policy.b holds a lone UTF-16 surrogate escape, \ud800, in the value as written`)
	// A rendering that cannot be read as written is not attached.
	rendering := planOf(created("aws_iam_role.a", "aws_iam_role", `{"name": "a"}`, `{"assume_role_policy": true}`, `{}`),
		`"configuration": {"root_module": {"resources": [{"address": "aws_iam_role.a", "expressions": {"assume_role_policy": {"references": ["data.aws_iam_policy_document.d.json", "data.aws_iam_policy_document.d"]}}}]}}`,
		priorStateOf(`{"address": "data.aws_iam_policy_document.d", "mode": "data", "type": "aws_iam_policy_document", "values": {"json": "{\"a\":\"`+"\xff"+`\"}"}, "sensitive_values": {}}`))
	g = oneWidened(t, planGrants(t, rendering), KnownAfterApply, "known only after apply")
	if len(g.Provenance) != 1 || anomalyOf(g, RenderedDocument).Kind != "" {
		t.Errorf("an unreadable rendering was attached: %s", render([]trust.Grant{g}))
	}
}

// TestSensitiveRendering: a data document whose json the prior state
// marks sensitive is attached redacted to its digest, and the sentence
// says so.
func TestSensitiveRendering(t *testing.T) {
	rendered := `{"Statement":[{"Condition":{"StringEquals":{"token.actions.githubusercontent.com:sub":"SECRETSUBJECT"}}}]}`
	raw := planOf(created("aws_iam_role.a", "aws_iam_role", `{"name": "a"}`, `{"assume_role_policy": true, "arn": true}`, `{"assume_role_policy": true}`),
		`"configuration": {"root_module": {"resources": [{"address": "aws_iam_role.a", "expressions": {"assume_role_policy": {"references": ["data.aws_iam_policy_document.doc.json", "data.aws_iam_policy_document.doc"]}}}]}}`,
		priorStateOf(`{"address": "data.aws_iam_policy_document.doc", "mode": "data", "type": "aws_iam_policy_document", "values": {"json": `+quote(rendered)+`, "minified_json": "x"}, "sensitive_values": {"json": true, "minified_json": true}}`))
	g := oneWidened(t, planGrants(t, raw), KnownAfterApply, "known only after apply")
	if len(g.Provenance) != 2 {
		t.Fatalf("records %d", len(g.Provenance))
	}
	if rec := g.Provenance[1]; string(rec.Bytes) != `{"sensitive":["json"],"sha256":"`+digest(rendered)+`"}` || !strings.Contains(rec.Params, `"rendering_for":"aws_iam_role.a"`) {
		t.Errorf("the rendering is quoted: %s %s", rec.Bytes, rec.Params)
	}
	if want := "the expression references data.aws_iam_policy_document.doc, whose json the plan rendered before apply and marks sensitive; the rendering is attached as evidence redacted to its digest, and assume_role_policy of aws_iam_role.a may differ from it"; messageOf(g, RenderedDocument) != want {
		t.Errorf("rendered-document: %q", messageOf(g, RenderedDocument))
	}
	if strings.Contains(string(render([]trust.Grant{g})), "SECRETSUBJECT") {
		t.Errorf("the sensitive rendering leaks: %s", render([]trust.Grant{g}))
	}
}

// TestSensitiveWithoutValue: an attribute marked sensitive whose value the
// document does not state, known only after apply or absent, states the
// sensitive fact beside the widening, with the sentence saying no value
// was read; a mark is never dropped because there was nothing to redact.
func TestSensitiveWithoutValue(t *testing.T) {
	unknown := planOf(created("aws_iam_role.r", "aws_iam_role", `{"name": "r"}`, `{"assume_role_policy": true, "arn": true}`, `{"assume_role_policy": true}`))
	g := oneWidened(t, planGrants(t, unknown), KnownAfterApply, "known only after apply")
	if want := "assume_role_policy of aws_iam_role.r is marked sensitive; no value of it was read and none is quoted"; messageOf(g, SensitiveValue) != want {
		t.Errorf("sensitive: %q, want %q", messageOf(g, SensitiveValue), want)
	}
	var kinds []string
	for _, a := range g.Anomalies {
		kinds = append(kinds, a.Kind)
	}
	if !slices.Equal(kinds, []string{KnownAfterApply, SensitiveValue, TerraformOrigin}) {
		t.Errorf("kinds %v", kinds)
	}
	absent := stateOf(`{"address": "aws_iam_role.r", "mode": "managed", "type": "aws_iam_role", "values": {"name": "r"}, "sensitive_values": {"assume_role_policy": true}}`)
	g = oneWidened(t, stateGrants(t, absent), AbsentAttribute, "absent from the state")
	if messageOf(g, SensitiveValue) != "assume_role_policy of aws_iam_role.r is marked sensitive; no value of it was read and none is quoted" {
		t.Errorf("absent and sensitive: %s", render([]trust.Grant{g}))
	}
	several := planOf(created("azuread_application_federated_identity_credential.c", "azuread_application_federated_identity_credential", `{"application_id": "/applications/x", "audiences": ["a"]}`, `{"issuer": true, "subject": true}`, `{"issuer": true, "subject": true}`))
	g = oneWidened(t, planGrants(t, several), KnownAfterApply, "issuer and subject of")
	if messageOf(g, SensitiveValue) != "issuer and subject of azuread_application_federated_identity_credential.c are marked sensitive; no value of them was read and none is quoted" {
		t.Errorf("several: %q", messageOf(g, SensitiveValue))
	}
}

// TestNoStatements: a policy the AWS parser projects no statement from
// states one grant admitting nothing, exactly, with the parser's own
// sentence about the document beside the reader's; and a document's facts
// ride on every grant of a policy that does project statements, so that
// nothing the parser said about the document is lost.
func TestNoStatements(t *testing.T) {
	role := func(policy string) []byte {
		return planOf(created("aws_iam_role.r", "aws_iam_role", `{"assume_role_policy": `+quote(policy)+`}`, `{"arn": true}`, `{}`))
	}
	for policy, parserSays := range map[string]string{
		`{"Version":"2012-10-17","Statement":[]}`: "Statement is an empty list, so the document grants nothing",
		`{"Version":"2012-10-17"}`:                "the document has no Statement member; the IAM grammar requires one",
		`{}`:                                      "the document has no Statement member; the IAM grammar requires one",
	} {
		gs := planGrants(t, role(policy))
		if len(gs) != 1 || !gs[0].Admits.IsEmpty() || !gs[0].Exact() || gs[0].Effect != trust.Allow || gs[0].Target.ID != "aws_iam_role.r" {
			t.Fatalf("%s: %s", policy, render(gs))
		}
		g := gs[0]
		if want := "assume_role_policy of aws_iam_role.r projects no statement, so it grants nobody anything: the one emptiness a policy proves"; messageOf(g, NoStatements) != want || anomalyOf(g, NoStatements).Construct != "Statement" {
			t.Errorf("%s: no-statements %+v", policy, anomalyOf(g, NoStatements))
		}
		if !slices.ContainsFunc(g.Anomalies, func(a trust.Anomaly) bool {
			return a.Kind == aws.Malformed && a.Message == parserSays && a.Source == "document"
		}) {
			t.Errorf("%s: the parser's sentence %q is lost: %s", policy, parserSays, renderAnomalies(g.Anomalies))
		}
		if string(g.Source) != policy || string(g.Provenance[0].Bytes) != policy {
			t.Errorf("%s: source %s bytes %s", policy, g.Source, g.Provenance[0].Bytes)
		}
	}
	// A document fact beside statements rides on every grant, after the
	// parser's own anomalies of the grant.
	gs := planGrants(t, role(`{"Version":"2020-01-01","Statement":[`+strings.TrimSuffix(strings.TrimPrefix(policyFor("repo:acme/a"), `{"Statement":[`), `],"Version":"2012-10-17"}`)+`,`+strings.TrimSuffix(strings.TrimPrefix(policyFor("repo:acme/b"), `{"Statement":[`), `],"Version":"2012-10-17"}`)+`]}`))
	if len(gs) != 2 {
		t.Fatalf("%s", render(gs))
	}
	for _, g := range gs {
		if !slices.ContainsFunc(g.Anomalies, func(a trust.Anomaly) bool {
			return a.Kind == aws.Malformed && a.Message == `Version "2020-01-01" is neither "2012-10-17" nor "2008-10-17"; policy variables are read as unresolved` && a.Source == "document"
		}) {
			t.Errorf("the document's fact is not on the grant: %s", renderAnomalies(g.Anomalies))
		}
	}
}

// TestTargetInParams: the record of a credential or a binding names the
// value of the attribute its target was read from, when the document
// states it, beside the identifiers; a target resolved by reference is not
// a value the document states and is not in Params.
func TestTargetInParams(t *testing.T) {
	credential := planOf(created("azuread_application_federated_identity_credential.c", "azuread_application_federated_identity_credential", `{"application_id": "/applications/x", "audiences": ["a"], "issuer": "https://token.actions.githubusercontent.com", "subject": "repo:acme/x:ref:refs/heads/main"}`, `{"credential_id": true}`, `{}`))
	gs := planGrants(t, credential)
	if len(gs) != 1 || gs[0].Target.ID != "/applications/x" || !strings.Contains(gs[0].Provenance[0].Params, `"application_id":"/applications/x"`) {
		t.Errorf("credential: %s", render(gs))
	}
	member := stateOf(`{"address": "google_service_account_iam_member.m", "mode": "managed", "type": "google_service_account_iam_member", "values": {"service_account_id": "projects/p/serviceAccounts/sa@p.iam.gserviceaccount.com", "role": "r", "member": "user:a", "id": "x"}, "sensitive_values": {}}`)
	gs = stateGrants(t, member)
	if len(gs) != 1 || !strings.Contains(gs[0].Provenance[0].Params, `"service_account_id":"projects/p/serviceAccounts/sa@p.iam.gserviceaccount.com"`) {
		t.Errorf("member: %s", render(gs))
	}
	unknownTarget := planOf(created("azuread_application_federated_identity_credential.c", "azuread_application_federated_identity_credential", `{"audiences": ["a"], "issuer": "https://token.actions.githubusercontent.com", "subject": "s"}`, `{"application_id": true, "credential_id": true}`, `{}`))
	gs = planGrants(t, unknownTarget)
	if len(gs) != 1 || strings.Contains(gs[0].Provenance[0].Params, "application_id") {
		t.Errorf("unknown target: %s", render(gs))
	}
}

// TestSensitiveUnreadable: a value marked sensitive that the reader could
// not read states the mark with the no-value sentence, and the malformed
// record digests the attribute as written rather than quoting it.
func TestSensitiveUnreadable(t *testing.T) {
	raw := planOf(created("aws_iam_role.r", "aws_iam_role", `{"assume_role_policy": "SECRET but not json", "name": "r"}`, `{"arn": true}`, `{"assume_role_policy": true}`))
	g := oneWidened(t, planGrants(t, raw), Malformed, "is not a trust policy document (")
	if messageOf(g, SensitiveValue) != "assume_role_policy of aws_iam_role.r is marked sensitive; no value of it was read and none is quoted" {
		t.Errorf("sensitive: %q", messageOf(g, SensitiveValue))
	}
	if strings.Contains(string(render([]trust.Grant{g})), "SECRET") {
		t.Errorf("the value is quoted: %s", render([]trust.Grant{g}))
	}
}

// TestDeferredBeatsPrior: a data document the plan lists as read only
// after apply is not read from a prior_state entry of the same address,
// which would be a stale rendering; the deferral is stated and nothing is
// attached.
func TestDeferredBeatsPrior(t *testing.T) {
	deferred := `{"address": "data.aws_iam_policy_document.d", "mode": "data", "type": "aws_iam_policy_document", "action_reason": "read_because_dependency_pending", "change": {"actions": ["read"], "before": null, "after": {"statement": []}, "after_unknown": {"json": true, "minified_json": true, "id": true}, "before_sensitive": false, "after_sensitive": {}}}`
	raw := planOf(created("aws_iam_role.a", "aws_iam_role", `{"name": "a"}`, `{"assume_role_policy": true}`, `{}`)+", "+deferred,
		`"configuration": {"root_module": {"resources": [{"address": "aws_iam_role.a", "expressions": {"assume_role_policy": {"references": ["data.aws_iam_policy_document.d.json", "data.aws_iam_policy_document.d"]}}}]}}`,
		priorStateOf(`{"address": "data.aws_iam_policy_document.d", "mode": "data", "type": "aws_iam_policy_document", "values": {"json": "{\"Statement\":[]}"}, "sensitive_values": {}}`))
	g := oneWidened(t, planGrants(t, raw), KnownAfterApply, "and the data document data.aws_iam_policy_document.d is itself read only after apply")
	if len(g.Provenance) != 1 || anomalyOf(g, RenderedDocument).Kind != "" {
		t.Errorf("a stale rendering was attached: %s", render([]trust.Grant{g}))
	}
}
