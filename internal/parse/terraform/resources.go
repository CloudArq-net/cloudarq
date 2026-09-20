package terraform

import (
	"strings"

	"github.com/CloudArq-net/cloudarq/internal/trust"
)

// parser names the cloud parser a resource type's document is handed to.
type parser int

const (
	awsTrustPolicy  parser = iota // aws.ParseTrustPolicy over one string attribute
	azureCredential               // azure.ParseFederatedCredential over a built credential
	gcpProvider                   // gcp.ParseProvider over a built provider
	gcpBinding                    // gcp.ParseMembers over a built policy, bound to the document's providers
)

// Attribute is one attribute of a resource type that bears on what the
// resource admits. Required is Terraform's own marking: for a required
// attribute an absent or null value cannot mean unset, so the reader
// widens the grant rather than hand the parser a document with a hole.
// Leaves names, for a block attribute, the members inside it that the
// reader hands on; a mark on any other member of the block, a JWKS
// document inside an oidc block say, bears on nothing the parser reads
// and is passed over. An attribute with no Leaves is read whole.
type Attribute struct {
	Name     string
	Required bool
	Leaves   []string
}

// consults reports whether a marked path beneath the attribute is one
// the reader reads: the attribute or a whole element of it, or a leaf
// the row names.
func (a Attribute) consults(path string) bool {
	rest := strings.TrimPrefix(path, a.Name)
	if strings.HasPrefix(rest, "[") {
		rest = rest[strings.Index(rest, "]")+1:]
	}
	if len(a.Leaves) == 0 || rest == "" {
		return true
	}
	for _, leaf := range a.Leaves {
		if strings.HasPrefix(rest, "."+leaf) && (len(rest) == len(leaf)+1 || strings.ContainsRune("[.", rune(rest[len(leaf)+1]))) {
			return true
		}
	}
	return false
}

// ResourceType is one row of the table: how instances of one Terraform
// resource type are read into Grants. Target is the attribute whose value
// names the thing a token becomes, "" when the resource is that thing
// itself; Attributes are the ones handed to the parser; Identifiers are
// the attributes whose known values go into the evidence record, never
// into the target.
type ResourceType struct {
	Type        string
	Kind        trust.TargetKind
	Target      string
	Attributes  []Attribute
	Identifiers []string
	parser      parser
	// labels are the attributes that name the resource for the parser's
	// document, by the member the API spells each as: display_name is
	// Graph's name and Google's displayName. They constrain nothing.
	labels map[string]string
}

// Table is the resource-type table: which attributes of which resource
// type are handed to which cloud parser, and what the target of the grant
// is. It is data so that a resource type is added by a row, and so that a
// reader can print what it reads. The kinds are spelt as the cloud
// parsers' tests spell them ("role", "application", "serviceAccount",
// "workloadIdentityPoolProvider"), because the join compares targets by
// struct equality; the managed identity's kind follows the same
// convention, Resource Manager's own noun for the resource type.
var Table = []ResourceType{
	{
		Type:        "aws_iam_role",
		Kind:        "role",
		Attributes:  []Attribute{{Name: "assume_role_policy", Required: true}},
		Identifiers: []string{"arn", "name"},
		parser:      awsTrustPolicy,
	},
	{
		Type:        "azuread_application_federated_identity_credential",
		Kind:        "application",
		Target:      "application_id",
		Attributes:  []Attribute{{Name: "audiences", Required: true}, {Name: "issuer", Required: true}, {Name: "subject", Required: true}},
		Identifiers: []string{"credential_id", "display_name"},
		parser:      azureCredential,
		labels:      map[string]string{"credential_id": "id", "description": "description", "display_name": "name"},
	},
	{
		Type:        "azurerm_federated_identity_credential",
		Kind:        "userAssignedIdentity",
		Target:      "user_assigned_identity_id",
		Attributes:  []Attribute{{Name: "audience", Required: true}, {Name: "issuer", Required: true}, {Name: "subject", Required: true}},
		Identifiers: []string{"id", "name"},
		parser:      azureCredential,
		labels:      map[string]string{"id": "id", "name": "name"},
	},
	{
		Type:        "google_iam_workload_identity_pool_provider",
		Kind:        "workloadIdentityPoolProvider",
		Attributes:  []Attribute{{Name: "attribute_condition"}, {Name: "attribute_mapping"}, {Name: "aws", Leaves: []string{"account_id"}}, {Name: "disabled"}, {Name: "oidc", Leaves: []string{"allowed_audiences", "issuer_uri"}}, {Name: "saml"}, {Name: "x509"}},
		Identifiers: []string{"id", "name"},
		parser:      gcpProvider,
		labels:      map[string]string{"description": "description", "display_name": "displayName", "name": "name", "state": "state"},
	},
	{
		Type:        "google_service_account_iam_member",
		Kind:        "serviceAccount",
		Target:      "service_account_id",
		Attributes:  []Attribute{{Name: "condition", Leaves: []string{"expression"}}, {Name: "member", Required: true}, {Name: "role", Required: true}},
		Identifiers: []string{"id"},
		parser:      gcpBinding,
	},
	{
		Type:        "google_service_account_iam_binding",
		Kind:        "serviceAccount",
		Target:      "service_account_id",
		Attributes:  []Attribute{{Name: "condition", Leaves: []string{"expression"}}, {Name: "members", Required: true}, {Name: "role", Required: true}},
		Identifiers: []string{"id"},
		parser:      gcpBinding,
	},
	{
		Type:        "google_service_account_iam_policy",
		Kind:        "serviceAccount",
		Target:      "service_account_id",
		Attributes:  []Attribute{{Name: "policy_data", Required: true}},
		Identifiers: []string{"id"},
		parser:      gcpBinding,
	},
}

// lookup finds the row for a resource type.
func lookup(typeName string) (ResourceType, bool) {
	for _, r := range Table {
		if r.Type == typeName {
			return r, true
		}
	}
	return ResourceType{}, false
}

// families are the fragments of a resource type's name that mark it as
// one that may hold a federation trust: a role's trust policy, a federated
// credential, a pool provider, a binding on a service account. A type the
// table does not map but a family covers is reported as unread, so that a
// customer whose trust sits in a resource this reader does not know sees
// "not read" rather than nothing. A type outside every family holds no
// trust the product models and is passed over without a word.
var families = []struct{ suffix, fragment string }{
	{suffix: "_iam_role"},
	{fragment: "federated_identity_credential"},
	{fragment: "pool_provider"},
	{fragment: "service_account_iam"},
}

// trustShaped reports whether a resource type's name belongs to one of
// the families.
func trustShaped(typeName string) bool {
	for _, f := range families {
		if f.suffix != "" && strings.HasSuffix(typeName, f.suffix) {
			return true
		}
		if f.fragment != "" && strings.Contains(typeName, f.fragment) {
			return true
		}
	}
	return false
}

// names lists the attribute names of a row, in table order, which is
// alphabetical: the order the evidence record states them in.
func (r ResourceType) names() []string {
	out := make([]string, len(r.Attributes))
	for i, a := range r.Attributes {
		out[i] = a.Name
	}
	return out
}
