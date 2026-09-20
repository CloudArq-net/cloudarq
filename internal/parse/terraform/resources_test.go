package terraform

import (
	"slices"
	"testing"
)

// TestTable: the resource table is well formed and says one thing per
// resource type: every type once, a target kind spelt as the cloud parsers
// and the join spell it, the attribute that names the target or the
// resource itself, at least one admission attribute, and the parser that
// reads it.
func TestTable(t *testing.T) {
	if len(Table) < 7 {
		t.Fatalf("the table names %d resource types; unit A names seven", len(Table))
	}
	seen := map[string]bool{}
	kinds := map[string]string{
		"aws_iam_role": "role",
		"azuread_application_federated_identity_credential": "application",
		"azurerm_federated_identity_credential":             "userAssignedIdentity",
		"google_iam_workload_identity_pool_provider":        "workloadIdentityPoolProvider",
		"google_service_account_iam_member":                 "serviceAccount",
		"google_service_account_iam_binding":                "serviceAccount",
		"google_service_account_iam_policy":                 "serviceAccount",
	}
	targets := map[string]string{
		"azuread_application_federated_identity_credential": "application_id",
		"azurerm_federated_identity_credential":             "user_assigned_identity_id",
		"google_service_account_iam_member":                 "service_account_id",
		"google_service_account_iam_binding":                "service_account_id",
		"google_service_account_iam_policy":                 "service_account_id",
	}
	for _, r := range Table {
		if seen[r.Type] {
			t.Errorf("%s is in the table twice", r.Type)
		}
		seen[r.Type] = true
		if string(r.Kind) != kinds[r.Type] {
			t.Errorf("%s: kind %q, want %q", r.Type, r.Kind, kinds[r.Type])
		}
		if r.Target != targets[r.Type] {
			t.Errorf("%s: target attribute %q, want %q", r.Type, r.Target, targets[r.Type])
		}
		if len(r.Attributes) == 0 {
			t.Errorf("%s: no attribute bears on admission", r.Type)
		}
		names := map[string]bool{}
		for _, a := range r.Attributes {
			if a.Name == "" || names[a.Name] {
				t.Errorf("%s: attribute %+v is unnamed or repeated", r.Type, a)
			}
			names[a.Name] = true
		}
		for _, id := range r.Identifiers {
			if names[id] || id == r.Target {
				t.Errorf("%s: %s is both an identifier and something else", r.Type, id)
			}
		}
		if _, ok := lookup(r.Type); !ok {
			t.Errorf("%s: lookup finds nothing", r.Type)
		}
		if !trustShaped(r.Type) {
			t.Errorf("%s: the table maps it but the families do not cover it", r.Type)
		}
	}
	for name := range kinds {
		if !seen[name] {
			t.Errorf("%s is not in the table", name)
		}
	}
	required := map[string][]string{
		"aws_iam_role": {"assume_role_policy"},
		"azuread_application_federated_identity_credential": {"audiences", "issuer", "subject"},
		"azurerm_federated_identity_credential":             {"audience", "issuer", "subject"},
		"google_service_account_iam_member":                 {"member", "role"},
		"google_service_account_iam_binding":                {"members", "role"},
		"google_service_account_iam_policy":                 {"policy_data"},
	}
	for typeName, want := range required {
		r, _ := lookup(typeName)
		var got []string
		for _, a := range r.Attributes {
			if a.Required {
				got = append(got, a.Name)
			}
		}
		slices.Sort(got)
		if !slices.Equal(got, want) {
			t.Errorf("%s: required attributes %v, want %v", typeName, got, want)
		}
	}
	provider, _ := lookup("google_iam_workload_identity_pool_provider")
	for _, a := range provider.Attributes {
		if a.Required {
			t.Errorf("google_iam_workload_identity_pool_provider: %s is required, but Google's schema makes every admission attribute optional", a.Name)
		}
	}
}

// TestTrustShaped: a resource type the table does not map but whose name
// belongs to a trust-bearing family is recognised, so that it is reported
// as unread rather than passed over; a type outside the families is not.
func TestTrustShaped(t *testing.T) {
	for _, name := range []string{"awscc_iam_role", "google_iam_workforce_pool_provider", "google-beta_iam_workload_identity_pool_provider", "azurerm_user_assigned_identity_federated_identity_credential", "google_service_account_iam_binding_v2", "oci_iam_role"} {
		if !trustShaped(name) {
			t.Errorf("%s is not recognised as trust-shaped", name)
		}
		if _, mapped := lookup(name); mapped {
			t.Errorf("%s is mapped; the test wants an unmapped one", name)
		}
	}
	for _, name := range []string{"aws_iam_openid_connect_provider", "google_service_account", "azuread_application_registration", "aws_iam_role_policy", "aws_iam_role_policy_attachment", "terraform_data", "google_iam_workload_identity_pool", "aws_iam_policy_document"} {
		if trustShaped(name) {
			t.Errorf("%s is recognised as trust-shaped; it holds no trust", name)
		}
	}
}
