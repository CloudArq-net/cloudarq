package aws

import (
	"strings"

	"github.com/CloudArq-net/cloudarq/internal/trust"
)

// Whether a grant on the pseudo-issuer admits one tenant or anyone with an
// AWS account is decided by the claims below, and which of them names a
// tenant is a fact about AWS, not about any issuer the census surveys: the
// pseudo-issuer is this parser's own. So the facts live here, beside the
// reading of the principal keys they are about, and the classifier asks
// them rather than reading a sentence this parser wrote. Every fact below
// cites the AWS sentence it rests on, read on 23 September 2026.

// orgClaim is the organisation's identity claim of the pseudo-issuer, beside
// the two a principal itself constrains, lower-cased as the parser writes
// every key.
const orgClaim trust.ClaimKey = "aws:principalorgid"

// TenantScope is what a tenant of the pseudo-issuer is: the AWS account a
// caller belongs to, or the organisation in AWS Organizations that account
// belongs to. An owner is declared at one of these scopes and matches a
// pin only at the same one, so the scope travels with every tenant.
type TenantScope string

const (
	// AccountScope is one AWS account, by its 12-digit id.
	AccountScope TenantScope = "account"
	// OrganisationScope is one organisation in AWS Organizations, by its
	// "o-" id: every account the organisation holds.
	OrganisationScope TenantScope = "organisation"
)

// Tenant is one account or one organisation, by the identifier AWS gives
// it: a pin on the pseudo-issuer names callers by the tenant they belong
// to, and one tenant is one owner, where anyone with an AWS account is
// everyone.
type Tenant struct {
	Scope TenantScope
	ID    string
}

// TenancyClaims are the claims of the pseudo-issuer whose value can name
// the tenant a caller belongs to, in sorted order. AWS, on the global
// condition keys page
// (https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html):
//
//   - aws:PrincipalAccount: "Use this key to compare the account to which
//     the requesting principal belongs with the account identifier that you
//     specify in the policy."
//   - aws:PrincipalArn: "Use this key to compare the Amazon Resource Name
//     (ARN) of the principal that made the request with the ARN that you
//     specify in the policy."
//   - aws:PrincipalOrgID: "Use this key to compare the identifier of the
//     organization in AWS Organizations to which the requesting principal
//     belongs with the identifier specified in the policy."
//
// The list is the caller's to keep.
func TenancyClaims() []trust.ClaimKey { return []trust.ClaimKey{accountClaim, arnClaim, orgClaim} }

// TenantOfValue is the tenant every caller whose claim holds exactly value
// belongs to, when the value names one. An account claim names the account
// when the value is an account id, and an organisation claim the
// organisation when it is an organisation id. A value that is no identifier
// names no tenant, which keeps the grant outward rather than naming an
// owner that cannot exist; aws:PrincipalAccount holds one such value, "For
// anonymous requests, the request context returns anonymous." (the global
// condition keys page). An ARN names the account in its fifth field, as
// any prefix of it that runs through that field does, so an exact value
// is read as TenantOfPrefix reads one.
func TenantOfValue(claim trust.ClaimKey, value string) (Tenant, bool) {
	switch {
	case claim == accountClaim && isAccountID(value):
		return Tenant{Scope: AccountScope, ID: value}, true
	case claim == orgClaim && isOrganisationID(value):
		return Tenant{Scope: OrganisationScope, ID: value}, true
	}
	return TenantOfPrefix(claim, value)
}

// TenantOfPrefix is the tenant every caller whose claim begins with prefix
// belongs to, when the prefix settles one: what a classifier asks of a
// pattern's literal prefix. Only an ARN names a tenant through a prefix,
// its account being the fifth colon-separated field,
// "arn:partition:service:region:account-id:resource-id", where the account
// id is "The ID of the AWS account that owns the resource, without the
// hyphens." (https://docs.aws.amazon.com/IAM/latest/UserGuide/reference-arns.html).
// The prefix settles it only when it runs through the colon after that
// field: "arn:aws:iam::111122223333" could still run on. An account or an
// organisation claim pins through exact values alone.
func TenantOfPrefix(claim trust.ClaimKey, prefix string) (Tenant, bool) {
	fields, ok := arnFields(prefix)
	if claim != arnClaim || !ok || !isAccountID(fields[4]) {
		return Tenant{}, false
	}
	return Tenant{Scope: AccountScope, ID: fields[4]}, true
}

// isOrganisationID reports whether text is an organisation id in the form
// AWS gives one: "The regex pattern for an organization ID string requires
// "o-" followed by from 10 to 32 lowercase letters or digits."
// (https://docs.aws.amazon.com/organizations/latest/APIReference/API_Organization.html).
// An account id is 12 digits, "A 12-digit number, such as 012345678901,
// that uniquely identifies an AWS account."
// (https://docs.aws.amazon.com/accounts/latest/reference/manage-acct-identifiers.html),
// which isAccountID has always read.
func isOrganisationID(text string) bool {
	id, ok := strings.CutPrefix(text, "o-")
	if !ok || len(id) < 10 || len(id) > 32 {
		return false
	}
	for _, c := range id {
		if !('a' <= c && c <= 'z' || '0' <= c && c <= '9') {
			return false
		}
	}
	return true
}
