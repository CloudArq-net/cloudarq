package terraform

import (
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/CloudArq-net/cloudarq/internal/eval"
	"github.com/CloudArq-net/cloudarq/internal/evidence"
	"github.com/CloudArq-net/cloudarq/internal/parse/aws"
	"github.com/CloudArq-net/cloudarq/internal/trust"
)

// sentence is one anomaly the reader itself writes, pinned word for word:
// these are what a customer reads, and a drift in one is a change in what
// the product says.
type sentence struct {
	kind, construct, source, message string
}

// sentences maps a case, then the address of the resource, to the reader's
// own anomalies on the first grant of that address. Every kind the reader
// defines is pinned at least once.
var sentences = map[string]map[string][]sentence{
	"01-aws-plan": {
		"aws_iam_role.known": {{TerraformOrigin, "plan", "aws_iam_role.known", "aws_iam_role.known is read from the plan, as Terraform will send it, provider-normalised; the deployed resource was not fetched from the cloud"}},
		"aws_iam_role.unknown": {
			{KnownAfterApply, "assume_role_policy", "aws_iam_role.unknown", "assume_role_policy of aws_iam_role.unknown is known only after apply; the expression references aws_iam_openid_connect_provider.gh.arn and local.sub, so what the grant admits is not stated and it is read as admitting everything"},
			{TerraformOrigin, "plan", "aws_iam_role.unknown", "aws_iam_role.unknown is read from the plan, as Terraform will send it, provider-normalised; the deployed resource was not fetched from the cloud"},
		},
		"aws_iam_role.deferred": {
			{KnownAfterApply, "assume_role_policy", "aws_iam_role.deferred", "assume_role_policy of aws_iam_role.deferred is known only after apply; the expression references data.aws_iam_policy_document.deferred.json, and the data document data.aws_iam_policy_document.deferred is itself read only after apply, so what the grant admits is not stated and it is read as admitting everything"},
		},
		"aws_iam_role.transformed": {
			{KnownAfterApply, "assume_role_policy", "aws_iam_role.transformed", "assume_role_policy of aws_iam_role.transformed is known only after apply; the expression references data.aws_iam_policy_document.doc.json and aws_iam_openid_connect_provider.gh.arn, so what the grant admits is not stated and it is read as admitting everything"},
			{RenderedDocument, "data.aws_iam_policy_document.doc", "aws_iam_role.transformed", "the expression references data.aws_iam_policy_document.doc, whose json the plan rendered before apply; the rendering is attached as evidence, and assume_role_policy of aws_iam_role.transformed may differ from it"},
		},
		"aws_iam_role.marked": {
			{SensitiveValue, "assume_role_policy", "aws_iam_role.marked", "assume_role_policy of aws_iam_role.marked is marked sensitive; it was read and evaluated, and is not quoted: the evidence carries its digest"},
		},
	},
	"02-gcp-plan": {
		"google_iam_workload_identity_pool_provider.nested_unknown": {
			{KnownAfterApply, "attribute_mapping, oidc[0].allowed_audiences", "google_iam_workload_identity_pool_provider.nested_unknown", "attribute_mapping and oidc[0].allowed_audiences of google_iam_workload_identity_pool_provider.nested_unknown are known only after apply; the expression references google_iam_workload_identity_pool.github.name, so what the grant admits is not stated and it is read as admitting everything"},
		},
		"google_iam_workload_identity_pool_provider.known": {{TerraformOrigin, "plan", "google_iam_workload_identity_pool_provider.known", "google_iam_workload_identity_pool_provider.known is read from the plan, as Terraform will send it, provider-normalised; the deployed resource was not fetched from the cloud"}},
		"google_service_account_iam_member.deploy": {
			{TargetAfterApply, "service_account_id", "google_service_account_iam_member.deploy", "service_account_id of google_service_account_iam_member.deploy is known only after apply; the target is named by the address of the resource the expression references, google_service_account.deploy"},
		},
	},
	"03-azure-plan": {
		"azuread_application_federated_identity_credential.immutable": {
			{TargetAfterApply, "application_id", "azuread_application_federated_identity_credential.immutable", "application_id of azuread_application_federated_identity_credential.immutable is known only after apply; the target is named by the address of the resource the expression references, azuread_application_registration.infra"},
		},
		"azuread_application_federated_identity_credential.unknown_subject": {
			{KnownAfterApply, "subject", "azuread_application_federated_identity_credential.unknown_subject", "subject of azuread_application_federated_identity_credential.unknown_subject is known only after apply; the expression references azuread_application_registration.infra.client_id, so what the grant admits is not stated and it is read as admitting everything"},
		},
	},
	"04-aws-state": {
		"aws_iam_role.legacy": {
			{AbsentAttribute, "assume_role_policy", "aws_iam_role.legacy", "assume_role_policy of aws_iam_role.legacy is absent from the state, which Terraform writes for a value that is unset or unknown; what the grant admits is not stated and it is read as admitting everything"},
			{TerraformOrigin, "state", "aws_iam_role.legacy", "aws_iam_role.legacy is read from the state, as Terraform last recorded it; the deployed resource was not fetched from the cloud"},
			{UnreadResource, "awscc_iam_role", "state", "the state holds 1 instance of awscc_iam_role, which resembles a trust-bearing resource this reader does not map; it was not read"},
		},
	},
	"05-gcp-state": {
		"google_service_account_iam_policy.release": {
			{TerraformOrigin, "state", "google_service_account_iam_policy.release", "google_service_account_iam_policy.release is read from the state, as Terraform last recorded it; the deployed resource was not fetched from the cloud"},
			{UnreadResource, "google_iam_workforce_pool_provider", "state", "the state holds 1 instance of google_iam_workforce_pool_provider, which resembles a trust-bearing resource this reader does not map; it was not read"},
		},
	},
	"06-aws-plan-actions": {
		"aws_iam_role.old": {
			{PlannedDelete, "delete", "aws_iam_role.old", "the plan deletes aws_iam_role.old; the grant is what the prior state holds and will not exist once the plan is applied"},
			{TerraformOrigin, "plan", "aws_iam_role.old", "aws_iam_role.old is read from the plan's prior state, as Terraform last recorded it; the deployed resource was not fetched from the cloud"},
			{PlanIncomplete, "complete", "plan", "the plan is marked complete: false, as a targeted or partial plan is, so resources it does not list are not absent; the grants read from it are a lower bound on the configuration's"},
		},
		"aws_iam_role.forgotten": {
			{PlannedForget, "forget", "aws_iam_role.forgotten", "the plan forgets aws_iam_role.forgotten: Terraform will discard its tracking information for it and will not delete it, so the object and what it admits continue to exist, unmanaged, once the plan is applied"},
			{TerraformOrigin, "plan", "aws_iam_role.forgotten", "aws_iam_role.forgotten is read from the plan's prior state, as Terraform last recorded it; the deployed resource was not fetched from the cloud"},
		},
		"aws_iam_role.hollow": {
			{NoStatements, "Statement", "aws_iam_role.hollow", "assume_role_policy of aws_iam_role.hollow projects no statement, so it grants nobody anything: the one emptiness a policy proves"},
			{aws.Malformed, "Statement", "document", "Statement is an empty list, so the document grants nothing"},
		},
		"aws_iam_role.untargeted": {
			{NoChangeListed, "prior_state", "aws_iam_role.untargeted", "the plan lists no change for aws_iam_role.untargeted, as a refresh-only plan lists none and a targeted plan lists only its targets; the grant is what the plan's prior state holds, which the plan leaves as it is"},
			{TerraformOrigin, "plan", "aws_iam_role.untargeted", "aws_iam_role.untargeted is read from the plan's prior state, as Terraform last recorded it; the deployed resource was not fetched from the cloud"},
		},
	},
	"14-refresh-only-plan": {
		"aws_iam_role.marked": {
			{SensitiveValue, "assume_role_policy", "aws_iam_role.marked", "assume_role_policy of aws_iam_role.marked is marked sensitive; it was read and evaluated, and is not quoted: the evidence carries its digest"},
			{NoChangeListed, "prior_state", "aws_iam_role.marked", "the plan lists no change for aws_iam_role.marked, as a refresh-only plan lists none and a targeted plan lists only its targets; the grant is what the plan's prior state holds, which the plan leaves as it is"},
			{UnreadResource, "awscc_iam_role", "plan", "the plan holds 1 instance of awscc_iam_role, which resembles a trust-bearing resource this reader does not map; it was not read"},
		},
	},
	"13-errored-plan": {
		"aws_iam_role.deploy": {
			{PlanIncomplete, "errored", "plan", "the plan is marked errored: true; it holds the actions planned before the failure, and the rest are not stated"},
		},
	},
}

// The two sentences about members no provider binds, and the ones for a
// mapping entry and a list element that are unknown one level down, are
// pinned apart because their grants are not the first of their address.
const (
	unboundUser = "the member user:alice@acme.example is not a workload identity pool principal; what it admits is outside what this reader models and the grant is read as admitting everything"
	unboundPool = "the member principalSet://iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/legacy/* names the pool projects/123456789012/locations/global/workloadIdentityPools/legacy, and no provider of that pool is in this state; what the pool admits is not stated and the grant is read as admitting everything"
)

func TestSentences(t *testing.T) {
	examined := 0
	// The table pins a sentence of every kind the reader defines, except
	// the three pinned word for word beside their shapes in
	// reading_test.go and below; a kind pinned nowhere would be a sentence
	// nobody reads.
	pinned := map[string]bool{UnboundMember: true, Malformed: true, NoMembers: true}
	for _, by := range sentences {
		for _, ws := range by {
			for _, w := range ws {
				pinned[w.kind] = true
			}
		}
	}
	for _, kind := range readerKinds {
		if !pinned[kind] {
			t.Errorf("the sentence of %s is pinned nowhere", kind)
		}
	}
	for _, name := range mapKeys(sentences) {
		by, _ := grantsByAddress(t, mustGrants(t, name))
		for address, wants := range sentences[name] {
			gs := by[address]
			if len(gs) == 0 {
				t.Errorf("%s: %s yields no grant", name, address)
				continue
			}
			for _, w := range wants {
				examined++
				found := false
				for _, a := range gs[0].Anomalies {
					if a.Kind == w.kind && a.Construct == w.construct && a.Source == w.source && a.Message == w.message {
						found = true
					}
				}
				if !found {
					t.Errorf("%s: %s lacks %s\n  construct %q source %q\n  %q\n  has%s", name, address, w.kind, w.construct, w.source, w.message, renderAnomalies(gs[0].Anomalies))
				}
			}
		}
	}
	for _, c := range []struct{ name, address, message, construct string }{
		{"05-gcp-state", "google_service_account_iam_binding.ci", unboundUser, "user:alice@acme.example"},
		{"05-gcp-state", "google_service_account_iam_policy.release", unboundPool, "principalSet://iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/legacy/*"},
	} {
		examined++
		by, _ := grantsByAddress(t, mustGrants(t, c.name))
		if !slices.ContainsFunc(by[c.address], func(g trust.Grant) bool {
			return slices.Contains(g.Anomalies, trust.Anomaly{Kind: UnboundMember, Construct: c.construct, Message: c.message, Source: c.address}) &&
				slices.ContainsFunc(g.Admits.Caveats(), func(cv eval.Caveat) bool { return cv.Reason == c.message && cv.Source == c.address })
		}) {
			t.Errorf("%s: no grant of %s carries the unbound-member anomaly and caveat %q", c.name, c.address, c.message)
		}
	}
	if examined < 20 {
		t.Fatalf("examined %d sentences", examined)
	}
}

func renderAnomalies(as []trust.Anomaly) string {
	var b strings.Builder
	for _, a := range as {
		b.WriteString("\n  " + a.Kind + " construct=" + a.Construct + " source=" + a.Source + "\n    " + a.Message)
	}
	return b.String()
}

func mapKeys[M ~map[K]V, K cmp.Ordered, V any](m M) []K {
	keys := make([]K, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

// TestCaveatsFollowTheReader: every reader anomaly that widens a grant to
// everything is also its caveat, word for word, and no other reader
// anomaly is: exactness answers from the set alone.
func TestCaveatsFollowTheReader(t *testing.T) {
	widening := map[string]bool{KnownAfterApply: true, AbsentAttribute: true, UnboundMember: true, Malformed: true}
	examined := 0
	for _, d := range documents(t) {
		if _, no := refused[d.name]; no {
			continue
		}
		gs, err := grantsOf(t, d)
		if err != nil {
			t.Fatalf("%s: %v", d.name, err)
		}
		for _, g := range gs {
			address, _ := paramsOf(t, g.Provenance[0])["address"].(string)
			for _, a := range g.Anomalies {
				if !readerAnomaly(a, address) {
					continue
				}
				examined++
				caveated := slices.ContainsFunc(g.Admits.Caveats(), func(c eval.Caveat) bool { return c.Reason == a.Message && c.Source == a.Source && c.Claim == "" })
				if caveated != widening[a.Kind] {
					t.Errorf("%s: %s %q caveated %v", d.name, a.Kind, a.Message, caveated)
				}
				if widening[a.Kind] && !g.Admits.IsTop() {
					t.Errorf("%s: %s did not widen the grant to everything: %s", d.name, a.Kind, g.Admits)
				}
			}
		}
	}
	if examined == 0 {
		t.Fatalf("examined no reader anomalies")
	}
}

// readerKinds are every anomaly kind the reader itself defines.
var readerKinds = []string{TerraformOrigin, KnownAfterApply, AbsentAttribute, SensitiveValue, PlannedDelete, PlannedForget, NoChangeListed, PlanIncomplete, UnreadResource, TargetAfterApply, UnboundMember, NoMembers, NoStatements, RenderedDocument, Malformed}

// readerAnomaly reports whether an anomaly is the reader's own rather
// than a cloud parser's: the reader's kinds, on the instance's address or
// on the artefact. Malformed is spelt the same by every parser, and the
// parsers' own facts, on "document" or a member path, must not be taken
// for the reader's.
func readerAnomaly(a trust.Anomaly, address string) bool {
	return slices.Contains(readerKinds, a.Kind) && (a.Source == address || a.Source == "plan" || a.Source == "state")
}

// record is what one evidence record of a grant must hold.
type record struct {
	params string
	bytes  string // "" when only the digest is pinned
	sha256 string // "" when the digest of bytes is expected
}

func digest(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

const (
	knownPolicy       = `{"Statement":[{"Action":"sts:AssumeRoleWithWebIdentity","Condition":{"StringEquals":{"token.actions.githubusercontent.com:aud":"sts.amazonaws.com"},"StringLike":{"token.actions.githubusercontent.com:sub":"repo:acme/*"}},"Effect":"Allow","Principal":{"Federated":"arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"}}],"Version":"2012-10-17"}`
	markedPolicy      = `{"Statement":[{"Action":"sts:AssumeRoleWithWebIdentity","Condition":{"StringEquals":{"token.actions.githubusercontent.com:sub":"repo:acme/secret:ref:refs/heads/main"}},"Effect":"Allow","Principal":{"Federated":"arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"}}],"Version":"2012-10-17"}`
	docRendering      = "{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [\n    {\n      \"Effect\": \"Allow\",\n      \"Action\": \"sts:AssumeRoleWithWebIdentity\",\n      \"Principal\": {\n        \"Federated\": \"arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com\"\n      },\n      \"Condition\": {\n        \"StringLike\": {\n          \"token.actions.githubusercontent.com:sub\": [\n            \"repo:acme/*\",\n            \"repo:acme/infra:*\"\n          ]\n        }\n      }\n    }\n  ]\n}"
	existingDocument  = `{"audiences":["api://AzureADTokenExchange"],"issuer":"https://gitlab.com","name":"gitlab-web","subject":"project_path:acme/web:ref_type:branch:ref:main"}`
	knownProviderDoc  = `{"attributeCondition":"assertion.sub == 'repo:acme/infra:ref:refs/heads/main'","attributeMapping":{"attribute.repository":"assertion.repository","attribute.repository_owner_id":"assertion.repository_owner_id","google.subject":"assertion.sub"},"displayName":"GitHub Actions","oidc":{"allowedAudiences":["https://iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/github/providers/github"],"issuerUri":"https://token.actions.githubusercontent.com"}}`
	stateProviderDoc  = `{"attributeCondition":"assertion.repository_owner_id == '123456'","attributeMapping":{"attribute.repository":"assertion.repository","attribute.repository_owner_id":"assertion.repository_owner_id","google.subject":"assertion.sub"},"displayName":"GitHub Actions","name":"projects/123456789012/locations/global/workloadIdentityPools/github/providers/github","oidc":{"issuerUri":"https://token.actions.githubusercontent.com"},"state":"ACTIVE"}`
	ciBindingDocument = `{"bindings":[{"condition":{"expression":"request.time < timestamp('2027-01-01T00:00:00Z')","title":"expires"},"members":["principal://iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/github/subject/repo:acme/infra:ref:refs/heads/main","user:alice@acme.example"],"role":"roles/iam.workloadIdentityUser"}]}`
	releasePolicyData = `{"bindings":[{"members":["principalSet://iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/gitlab/attribute.namespace_path/acme","principalSet://iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/legacy/*"],"role":"roles/iam.workloadIdentityUser"}]}`
)

// records maps a case, then an address, to the records of the first grant
// of that address, in order.
var records = map[string]map[string][]record{
	"01-aws-plan": {
		"aws_iam_role.known":   {{`{"address":"aws_iam_role.known","attributes":["assume_role_policy"],"format_version":"1.2","from":"after","name":"known","source":"01-aws-plan/plan.json","terraform_version":"1.15.5"}`, knownPolicy, ""}},
		"aws_iam_role.unknown": {{`{"address":"aws_iam_role.unknown","attributes":["assume_role_policy"],"format_version":"1.2","from":"after","name":"unknown","source":"01-aws-plan/plan.json","terraform_version":"1.15.5"}`, `{"references":["aws_iam_openid_connect_provider.gh.arn","local.sub"],"unknown":["assume_role_policy"]}`, ""}},
		"aws_iam_role.marked":  {{`{"address":"aws_iam_role.marked","attributes":["assume_role_policy"],"format_version":"1.2","from":"after","name":"marked","source":"01-aws-plan/plan.json","terraform_version":"1.15.5"}`, `{"sensitive":["assume_role_policy"],"sha256":"` + digest(markedPolicy) + `"}`, ""}},
		"aws_iam_role.transformed": {
			{`{"address":"aws_iam_role.transformed","attributes":["assume_role_policy"],"format_version":"1.2","from":"after","name":"transformed","source":"01-aws-plan/plan.json","terraform_version":"1.15.5"}`, `{"references":["data.aws_iam_policy_document.doc.json","aws_iam_openid_connect_provider.gh.arn"],"unknown":["assume_role_policy"]}`, ""},
			{`{"address":"data.aws_iam_policy_document.doc","attributes":["json"],"format_version":"1.2","from":"prior_state","rendering_for":"aws_iam_role.transformed","source":"01-aws-plan/plan.json","terraform_version":"1.15.5"}`, docRendering, ""},
		},
	},
	"02-gcp-plan": {
		"google_iam_workload_identity_pool_provider.known":          {{`{"address":"google_iam_workload_identity_pool_provider.known","attributes":["attribute_condition","attribute_mapping","aws","disabled","oidc","saml","x509"],"format_version":"1.2","from":"after","source":"02-gcp-plan/plan.json","terraform_version":"1.15.5"}`, knownProviderDoc, ""}},
		"google_iam_workload_identity_pool_provider.nested_unknown": {{`{"address":"google_iam_workload_identity_pool_provider.nested_unknown","attributes":["attribute_condition","attribute_mapping","aws","disabled","oidc","saml","x509"],"format_version":"1.2","from":"after","source":"02-gcp-plan/plan.json","terraform_version":"1.15.5"}`, `{"references":["google_iam_workload_identity_pool.github.name"],"unknown":["attribute_mapping","oidc[0].allowed_audiences"]}`, ""}},
	},
	"03-azure-plan": {
		"azuread_application_federated_identity_credential.existing": {{`{"address":"azuread_application_federated_identity_credential.existing","application_id":"/applications/6b1e6c7e-0f1a-4d2b-9c3d-8e4f5a6b7c8d","attributes":["audiences","issuer","subject"],"display_name":"gitlab-web","format_version":"1.2","from":"after","source":"03-azure-plan/plan.json","terraform_version":"1.15.5"}`, existingDocument, ""}},
	},
	"04-aws-state": {
		"aws_iam_role.deploy": {{`{"address":"aws_iam_role.deploy","arn":"arn:aws:iam::123456789012:role/deploy","attributes":["assume_role_policy"],"format_version":"1.0","name":"deploy","source":"04-aws-state/state.json","terraform_version":"1.15.5"}`, "", ""}},
		"aws_iam_role.legacy": {{`{"address":"aws_iam_role.legacy","arn":"arn:aws:iam::123456789012:role/legacy","attributes":["assume_role_policy"],"format_version":"1.0","name":"legacy","source":"04-aws-state/state.json","terraform_version":"1.15.5"}`, `{"absent":["assume_role_policy"]}`, ""}},
	},
	"05-gcp-state": {
		"google_iam_workload_identity_pool_provider.github": {{`{"address":"google_iam_workload_identity_pool_provider.github","attributes":["attribute_condition","attribute_mapping","aws","disabled","oidc","saml","x509"],"format_version":"1.0","id":"projects/acme-prod/locations/global/workloadIdentityPools/github/providers/github","name":"projects/123456789012/locations/global/workloadIdentityPools/github/providers/github","source":"05-gcp-state/state.json","terraform_version":"1.15.5"}`, stateProviderDoc, ""}},
		// A bound grant carries the binding's record and the provider's.
		"google_service_account_iam_binding.ci": {
			{`{"address":"google_service_account_iam_binding.ci","attributes":["condition","members","role"],"format_version":"1.0","id":"projects/acme-prod/serviceAccounts/ci-runner@acme-prod.iam.gserviceaccount.com/roles/iam.workloadIdentityUser/expires","service_account_id":"projects/acme-prod/serviceAccounts/ci-runner@acme-prod.iam.gserviceaccount.com","source":"05-gcp-state/state.json","terraform_version":"1.15.5"}`, ciBindingDocument, ""},
			{`{"address":"google_iam_workload_identity_pool_provider.github","attributes":["attribute_condition","attribute_mapping","aws","disabled","oidc","saml","x509"],"format_version":"1.0","id":"projects/acme-prod/locations/global/workloadIdentityPools/github/providers/github","name":"projects/123456789012/locations/global/workloadIdentityPools/github/providers/github","source":"05-gcp-state/state.json","terraform_version":"1.15.5"}`, stateProviderDoc, ""},
		},
		"google_service_account_iam_policy.release": {
			{`{"address":"google_service_account_iam_policy.release","attributes":["policy_data"],"format_version":"1.0","id":"projects/acme-prod/serviceAccounts/release@acme-prod.iam.gserviceaccount.com","service_account_id":"projects/acme-prod/serviceAccounts/release@acme-prod.iam.gserviceaccount.com","source":"05-gcp-state/state.json","terraform_version":"1.15.5"}`, releasePolicyData, ""},
			{`{"address":"google_iam_workload_identity_pool_provider.gitlab","attributes":["attribute_condition","attribute_mapping","aws","disabled","oidc","saml","x509"],"format_version":"1.0","id":"projects/acme-prod/locations/global/workloadIdentityPools/gitlab/providers/gitlab","name":"projects/123456789012/locations/global/workloadIdentityPools/gitlab/providers/gitlab","source":"05-gcp-state/state.json","terraform_version":"1.15.5"}`, "", ""},
		},
	},
	"06-aws-plan-actions": {
		"aws_iam_role.old":       {{`{"address":"aws_iam_role.old","arn":"arn:aws:iam::123456789012:role/old","attributes":["assume_role_policy"],"format_version":"1.2","from":"before","name":"old","source":"06-aws-plan-actions/plan.json","terraform_version":"1.15.5"}`, "", ""}},
		"aws_iam_role.forgotten": {{`{"address":"aws_iam_role.forgotten","arn":"arn:aws:iam::123456789012:role/forgotten","attributes":["assume_role_policy"],"format_version":"1.2","from":"before","name":"forgotten","source":"06-aws-plan-actions/plan.json","terraform_version":"1.15.5"}`, "", ""}},
		"aws_iam_role.hollow":    {{`{"address":"aws_iam_role.hollow","attributes":["assume_role_policy"],"format_version":"1.2","from":"after","name":"hollow","source":"06-aws-plan-actions/plan.json","terraform_version":"1.15.5"}`, `{"Statement":[],"Version":"2012-10-17"}`, ""}},
	},
	"14-refresh-only-plan": {
		"aws_iam_role.deploy": {{`{"address":"aws_iam_role.deploy","arn":"arn:aws:iam::123456789012:role/deploy","attributes":["assume_role_policy"],"format_version":"1.2","from":"prior_state","name":"deploy","source":"14-refresh-only-plan/plan.json","terraform_version":"1.15.5"}`, "", ""}},
		"aws_iam_role.marked": {{`{"address":"aws_iam_role.marked","arn":"arn:aws:iam::123456789012:role/marked","attributes":["assume_role_policy"],"format_version":"1.2","from":"prior_state","name":"marked","source":"14-refresh-only-plan/plan.json","terraform_version":"1.15.5"}`, `{"sensitive":["assume_role_policy"],"sha256":"` + digest(`{"Statement":[{"Action":"sts:AssumeRoleWithWebIdentity","Condition":{"StringEquals":{"token.actions.githubusercontent.com:aud":"sts.amazonaws.com","token.actions.githubusercontent.com:sub":"repo:acme/secret:ref:refs/heads/main"}},"Effect":"Allow","Principal":{"Federated":"arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"}}],"Version":"2012-10-17"}`) + `"}`, ""}},
	},
}

// TestEvidence: every record names the artefact, the address and the
// attributes it read in canonical Params, carries the value itself or the
// reader's own statement about it as Bytes, and seals the digest over
// Bytes. The deposed object's record names its key.
func TestEvidence(t *testing.T) {
	examined := 0
	for _, name := range mapKeys(records) {
		by, _ := grantsByAddress(t, mustGrants(t, name))
		for address, wants := range records[name] {
			gs := by[address]
			if len(gs) == 0 {
				t.Errorf("%s: %s yields no grant", name, address)
				continue
			}
			got := gs[0].Provenance
			if len(got) != len(wants) {
				t.Errorf("%s: %s carries %d records, want %d", name, address, len(got), len(wants))
				continue
			}
			for i, w := range wants {
				examined++
				r := got[i]
				if r.Params != w.params {
					t.Errorf("%s: %s record %d params\n  %s\n  want %s", name, address, i, r.Params, w.params)
				}
				if w.bytes != "" && string(r.Bytes) != w.bytes {
					t.Errorf("%s: %s record %d bytes\n  %s\n  want %s", name, address, i, r.Bytes, w.bytes)
				}
				if r.SHA256 != digest(string(r.Bytes)) {
					t.Errorf("%s: %s record %d digest %s is not over its bytes", name, address, i, r.SHA256)
				}
				if r.Status != evidence.StatusOK || r.FetchedAt != clock {
					t.Errorf("%s: %s record %d status %q at %v", name, address, i, r.Status, r.FetchedAt)
				}
				if !json.Valid(r.Bytes) {
					t.Errorf("%s: %s record %d bytes are not JSON", name, address, i)
				}
			}
		}
	}
	by, _ := grantsByAddress(t, mustGrants(t, "06-aws-plan-actions"))
	old := by["aws_iam_role.old"]
	if len(old) != 2 || strings.Contains(old[0].Provenance[0].Params, "deposed") || !strings.Contains(old[1].Provenance[0].Params, `"deposed":"deadbeef"`) {
		t.Errorf("the deposed object's record does not name its key: %+v", old)
	}
	examined++
	// The redaction is the whole quote: Source, too, is the reader's statement.
	marked := grantsByAddressOf(t, "01-aws-plan", "aws_iam_role.marked")[0]
	if string(marked.Source) != string(marked.Provenance[0].Bytes) || strings.Contains(string(marked.Source), "secret") {
		t.Errorf("the sensitive value is quoted: %s", marked.Source)
	}
	// A known value is quoted by the parser's own Source: the statement's
	// bytes for AWS, the built document for the others.
	known := grantsByAddressOf(t, "01-aws-plan", "aws_iam_role.known")[0]
	if !strings.HasPrefix(string(known.Source), `{"Action":"sts:AssumeRoleWithWebIdentity"`) {
		t.Errorf("Source of a known role is not the statement's bytes: %s", known.Source)
	}
	existing := grantsByAddressOf(t, "03-azure-plan", "azuread_application_federated_identity_credential.existing")[0]
	if string(existing.Source) != existingDocument {
		t.Errorf("Source of a credential is not the built document: %s", existing.Source)
	}
	if examined < 12 {
		t.Fatalf("examined %d records", examined)
	}
}

func grantsByAddressOf(t testing.TB, name, address string) []trust.Grant {
	t.Helper()
	by, _ := grantsByAddress(t, mustGrants(t, name))
	if len(by[address]) == 0 {
		t.Fatalf("%s: %s yields no grant", name, address)
	}
	return by[address]
}

// TestBuiltDocumentsAreCanonical: the documents the reader builds for the
// Azure and GCP parsers are its own construction, so they are declared
// canonical, members in a fixed order with sorted keys, and two reads of
// one resource build the same bytes. The differential test proves they
// mean what the API document means.
func TestBuiltDocumentsAreCanonical(t *testing.T) {
	for _, c := range []struct{ name, address, want string }{
		{"02-gcp-plan", "google_iam_workload_identity_pool_provider.known", knownProviderDoc},
		{"03-azure-plan", "azuread_application_federated_identity_credential.existing", existingDocument},
		{"05-gcp-state", "google_iam_workload_identity_pool_provider.github", stateProviderDoc},
	} {
		g := grantsByAddressOf(t, c.name, c.address)[0]
		if string(g.Provenance[0].Bytes) != c.want {
			t.Errorf("%s: %s built\n  %s\n  want %s", c.name, c.address, g.Provenance[0].Bytes, c.want)
		}
		var decoded map[string]json.RawMessage
		if err := json.Unmarshal(g.Provenance[0].Bytes, &decoded); err != nil {
			t.Errorf("%s: %v", c.address, err)
		}
		keys := (mapKeys(decoded))
		var inOrder []string
		dec := json.NewDecoder(strings.NewReader(string(g.Provenance[0].Bytes)))
		dec.Token()
		for dec.More() {
			tok, _ := dec.Token()
			inOrder = append(inOrder, tok.(string))
			var skip json.RawMessage
			dec.Decode(&skip)
		}
		if !slices.Equal(keys, inOrder) {
			t.Errorf("%s: members %v are not in sorted order", c.address, inOrder)
		}
	}
}
