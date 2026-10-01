package ring

import (
	"slices"

	"github.com/CloudArq-net/cloudarq/internal/eval"
	"github.com/CloudArq-net/cloudarq/internal/parse/aws"
	"github.com/CloudArq-net/cloudarq/internal/trust"
)

// The facts below stand in for the census, as internal/registry maps
// census v0.2.0 into them, for a grant of a principal the parser modelled: every
// value is one the census records with its vendor sentence, and
// TestTheStandInIsTheCensus holds them to what internal/registry reads, so
// that the corpus here and the answers the command prints rest on one
// reading. A value the census does not establish is left at its zero, which
// is unverified. factsOf reads what the statement says of its own grants,
// as internal/report does.

const (
	githubIssuer     trust.IssuerRef = "https://token.actions.githubusercontent.com"
	cognitoIssuer    trust.IssuerRef = "https://cognito-identity.amazonaws.com"
	googleIssuer     trust.IssuerRef = "https://accounts.google.com"
	amazonIssuer     trust.IssuerRef = "https://www.amazon.com"
	facebookIssuer   trust.IssuerRef = "https://graph.facebook.com"
	gitlabIssuer     trust.IssuerRef = "https://gitlab.com"
	eksIssuer        trust.IssuerRef = "https://oidc.eks.us-east-1.amazonaws.com/id/EXAMPLED539D4633E53DE1B71EXAMPLE"
	entraPersonal    trust.IssuerRef = "https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0"
	entraWork        trust.IssuerRef = "https://login.microsoftonline.com/ffffffff-eeee-dddd-cccc-bbbbbbbbbbb0/v2.0"
	enterpriseIssuer trust.IssuerRef = "https://token.actions.githubusercontent.com/acme-ent"
	samlVendor       trust.IssuerRef = "arn:aws:iam::123456789012:saml-provider/VendorSSO"
	spaceliftIssuer  trust.IssuerRef = "https://acme.app.spacelift.io"
	bitbucketIssuer  trust.IssuerRef = "https://api.bitbucket.org/2.0/workspaces/acme/pipelines-config/identity/oidc"
	aksIssuer        trust.IssuerRef = "https://eastus.oic.prod-aks.azure.com/" + aksTenantIDs
	eksOtherRegion   trust.IssuerRef = "https://oidc.eks.eu-west-1.amazonaws.com/id/" + eksCluster
	gkeIssuer        trust.IssuerRef = "https://container.googleapis.com/v1/projects/proj/locations/us-central1/clusters/c1"
)

// The tenants the census's Match names in the issuers above: an EKS
// cluster's id, the same in every region, and an AKS cluster's whole path,
// region and both GUIDs, since no sentence says what either GUID is.
const (
	eksCluster   = "EXAMPLED539D4633E53DE1B71EXAMPLE"
	aksTenantIDs = "ffffffff-eeee-dddd-cccc-bbbbbbbbbbb0/00000000-0000-0000-0000-000000000000"
	aksTenant    = "eastus/" + aksTenantIDs
)

// githubOwnerCharacters is letters, digits and dashes, plus the underscore
// GitHub appends to managed users' names: "Usernames for user accounts on
// GitHub can only contain alphanumeric characters and dashes (`-`)." and
// "On GitHub.com, GitHub also adds an underscore and your enterprise's
// shortcode to the end of each username."
var githubOwnerCharacters = []CharRange{{'A', 'Z'}, {'a', 'z'}, {'0', '9'}, {'-', '-'}, {'_', '_'}}

// githubFacts is GitHub Actions' entry, built afresh for every caller so
// that a test that edits it edits nothing else. Census v0.2.0 records GitHub's
// enterprise claim as not naming a tenant, unverified, so it is not among
// the claims but among those that look as if they name one and do not,
// beside the called workflow's literal, which never pins. GitHub says an
// owner's or a repository's name is released on a rename and their ids
// are immutable; of the enterprise's id it says only that a slug change
// leaves it alone, so whether it can pass on is unverified.
func githubFacts() Facts {
	return Facts{
		IssuerKind:        Shared,
		Namespace:         NamespaceGitHub,
		AnonymousTokens:   No,
		PrincipalModelled: true,
		Tenancy: &Tenancy{
			Claims: []TenancyClaim{
				{Claim: "repository_owner", Scope: ScopeOwner, Kind: KindName, Recyclable: Yes},
				{Claim: "repository_owner_id", Scope: ScopeOwner, Kind: KindID, Recyclable: No},
				{Claim: "repository", Scope: ScopeRepository, Kind: KindName, Recyclable: Yes},
				{Claim: "repository_id", Scope: ScopeRepository, Kind: KindID, Recyclable: No},
				{Claim: "enterprise_id", Scope: ScopeEnterprise, Kind: KindID},
			},
			SubjectForms: []SubjectForm{
				{Lead: "repo:", Scope: ScopeOwner, Parts: []Part{{KindName, "/"}}},
				{Lead: "repo:", Scope: ScopeOwner, Parts: []Part{{KindName, "@"}, {KindID, "/"}}},
				{Lead: "repository_owner:", Scope: ScopeOwner, Parts: []Part{{KindName, ":"}}},
				{Lead: "repository_owner_id:", Scope: ScopeOwner, Parts: []Part{{KindID, ":"}}},
				{Lead: "repository_id:", Scope: ScopeRepository, Parts: []Part{{KindID, ":"}}},
			},
			NotTenancy: []trust.ClaimKey{
				"actor", "actor_id", "job_workflow_ref", "job_workflow_sha", "enterprise", "workflow_ref", "environment", "ref", "event_name",
				"runner_environment", "repository_visibility", "workflow", "head_ref", "base_ref", "repo_property_*", "aud", "issuer_scope",
			},
			NeverPin:        []string{"job_workflow_ref:", "repo_property_"},
			OwnerCharacters: githubOwnerCharacters,
		},
	}
}

// sharedFacts is an entry census v0.2.0 records with anonymous_tokens alone: the
// four providers STS names, and GitLab.com.
func sharedFacts(anonymous Established) Facts {
	return Facts{IssuerKind: Shared, AnonymousTokens: anonymous, PrincipalModelled: true}
}

// perTenantFacts is an entry whose issuer URL names its tenant, which is
// declared by that URL.
func perTenantFacts(tenant string, kind Kind, recyclable Established, membership Membership) Facts {
	return Facts{
		IssuerKind: PerTenant, Namespace: NamespaceIssuer, AnonymousTokens: No, PrincipalModelled: true,
		Tenant: Tenant{Value: tenant, Kind: kind, Recyclable: recyclable, Membership: membership},
	}
}

// standIn is the registry the tests stand in for: the facts of every issuer
// the corpus and the generators use, each built afresh for every caller.
// internal/registry imports this package, so only an external test can
// read the census through it: TestTheStandInIsTheCensus holds every entry
// here, and every issuer the corpus expects a grant of, to what
// internal/registry reads from the census.
var standIn = []struct {
	issuer trust.IssuerRef
	facts  func() Facts
}{
	{githubIssuer, githubFacts},
	{cognitoIssuer, func() Facts { return sharedFacts(Yes) }},
	{googleIssuer, func() Facts { return sharedFacts(No) }},
	{amazonIssuer, func() Facts { return sharedFacts(No) }},
	{facebookIssuer, func() Facts { return sharedFacts(Unverified) }},
	{gitlabIssuer, func() Facts { return sharedFacts(Unverified) }},
	{eksIssuer, func() Facts { return perTenantFacts(eksCluster, KindID, Unverified, Controlled) }},
	{eksOtherRegion, func() Facts { return perTenantFacts(eksCluster, KindID, Unverified, Controlled) }},
	{aksIssuer, func() Facts { return perTenantFacts(aksTenant, KindID, Unverified, Controlled) }},
	{gkeIssuer, func() Facts { return perTenantFacts("proj/us-central1/c1", KindName, Unverified, Controlled) }},
	{spaceliftIssuer, func() Facts { return perTenantFacts("acme", KindName, Unverified, MembershipUnverified) }},
	{bitbucketIssuer, func() Facts { return perTenantFacts("acme", KindName, Unverified, MembershipUnverified) }},
	{entraPersonal, func() Facts {
		return perTenantFacts("9188040d-6c67-4c5b-b112-36a304b66dad", KindID, Unverified, OpenToAnyone)
	}},
	{entraWork, func() Facts {
		return perTenantFacts("ffffffff-eeee-dddd-cccc-bbbbbbbbbbb0", KindID, Unverified, MembershipUnverified)
	}},
	{enterpriseIssuer, func() Facts { return perTenantFacts("acme-ent", KindName, Yes, Controlled) }},
}

// censusFacts is the stand-in's facts for issuer. An issuer it does not
// list is not surveyed.
func censusFacts(issuer trust.IssuerRef) Facts {
	for _, e := range standIn {
		if e.issuer == issuer {
			return e.facts()
		}
	}
	return Facts{PrincipalModelled: true}
}

// factsOf is the facts internal/report hands the classifier for a grant of d:
// the census's for its issuer, and what the parser reads of the statement
// the grant came from, whether it modelled the grant's principal and who
// a grant that names no issuer admits.
func factsOf(t failer, g trust.Grant, d aws.Document) Facts {
	t.Helper()
	s, ok := statementOf(g, d)
	if !ok {
		t.Fatalf("a grant came from no statement of the document")
	}
	facts := censusFacts(g.Issuer)
	facts.Issuerless = s.IssuerlessPopulation()
	facts.PrincipalModelled = s.ModelsPrincipalOf(g)
	return facts
}

// statementOf finds the statement a grant came from by identity, as
// internal/report does: a grant's Source is its statement's own slice of
// the parser's copy of the document.
func statementOf(g trust.Grant, d aws.Document) (aws.Statement, bool) {
	for _, s := range d.Statements {
		if len(g.Source) > 0 && len(g.Source) == len(s.Raw) && &g.Source[0] == &s.Raw[0] {
			return s, true
		}
	}
	return aws.Statement{}, false
}

// failer is what the helpers need of a test: *testing.T and *rapid.T are
// both one.
type failer interface {
	Helper()
	Fatalf(format string, args ...any)
}

// role is the target a trust policy is attached to; the classifier never
// reads it.
var role = trust.TargetRef{Kind: "role", ID: "arn:aws:iam::123456789012:role/deploy"}

// vocabulary is the one the command and the WebAssembly engine read
// policies with: a condition reads only the keys AWS documents for the
// issuer's tokens, and one on a key AWS documents as multivalued, or reads
// from a claim the issuer's tokens may carry with several values, under an
// operator without a set prefix, is not evaluated.
var vocabulary = aws.DocumentedKeys(standInKeys, standInMultivalued, standInMultiValuedClaim)

// conditionKey is one condition key AWS documents for an issuer and the
// claim AWS reads it from, with the claim it reads when the token sets no
// value for that one. A key whose claim no vendor sentence says a token
// carries as AWS's table spells it has no Claim, and Table holds the
// spelling. Multivalued is "yes" where AWS documents the key as
// multivalued, and empty where the census holds no such sentence.
type conditionKey struct{ Key, Claim, Fallback, Table, Multivalued string }

// spelledOnly is a key AWS's table spells the claim of, which no token is
// known to carry so spelled.
func spelledOnly(key, spelling string) conditionKey { return conditionKey{Key: key, Table: spelling} }

// multivaluedAMR is amr, which AWS reads from the claim of its name and
// documents as multivalued on its Default tab and on Amazon Cognito's: "The
// key is multivalued, meaning that you test it in a policy using condition
// set operators."
var multivaluedAMR = conditionKey{Key: "amr", Claim: "amr", Multivalued: "yes"}

// defaultTabKeys are the keys of AWS's Default tab, which reads GitHub's
// and Google's tokens and those of every issuer without a tab of its own:
// oaud reads aud, and aud reads azp, or aud when the token sets no azp.
var defaultTabKeys = []conditionKey{
	multivaluedAMR, {Key: "aud", Claim: "azp", Fallback: "aud"}, {Key: "email", Claim: "email"}, {Key: "oaud", Claim: "aud"}, {Key: "sub", Claim: "sub"},
}

// githubAWSKeys are the condition keys AWS documents for GitHub's tokens,
// the default ones and its GitHub tab's. It has no repository_owner,
// enterprise or workflow_ref.
var githubAWSKeys = slices.Concat(defaultTabKeys, []conditionKey{
	{Key: "actor", Claim: "actor"}, {Key: "actor_id", Claim: "actor_id"}, {Key: "job_workflow_ref", Claim: "job_workflow_ref"},
	{Key: "repository", Claim: "repository"}, {Key: "repository_id", Claim: "repository_id"},
	{Key: "repository_owner_id", Claim: "repository_owner_id"}, {Key: "workflow", Claim: "workflow"}, {Key: "ref", Claim: "ref"},
	{Key: "environment", Claim: "environment"}, {Key: "enterprise_id", Claim: "enterprise_id"},
})

// awsKeys are the condition keys AWS documents for the tokens of each
// issuer the stand-in lists, as the census records them, which
// TestTheStandInReadsTheKeysAWSDocuments holds to the census. An issuer not
// here has none recorded: GitLab.com's, and GitHub's enterprise path, which
// no AWS sentence names. Login with Amazon's and Facebook's claims are the
// phrases AWS's table writes, not claim names. AWS's Google tab spells the
// claim of google/organization_number google:organization_number, and
// Google's reference prints the number inside a google claim, so no claim
// is known to carry it as spelled.
var awsKeys = map[trust.IssuerRef][]conditionKey{
	githubIssuer:    githubAWSKeys,
	googleIssuer:    slices.Concat(defaultTabKeys, []conditionKey{spelledOnly("google/organization_number", "google:organization_number")}),
	cognitoIssuer:   {multivaluedAMR, {Key: "aud", Claim: "aud"}, {Key: "oaud", Claim: "aud"}, {Key: "sub", Claim: "sub"}},
	amazonIssuer:    {{Key: "app_id", Claim: "Application ID"}, {Key: "sub", Claim: "User ID"}, {Key: "user_id", Claim: "User ID"}},
	facebookIssuer:  {{Key: "app_id", Claim: "Application ID"}, {Key: "id", Claim: "id"}},
	eksIssuer:       defaultTabKeys,
	eksOtherRegion:  defaultTabKeys,
	aksIssuer:       defaultTabKeys,
	gkeIssuer:       defaultTabKeys,
	spaceliftIssuer: defaultTabKeys,
	bitbucketIssuer: defaultTabKeys,
	entraPersonal:   defaultTabKeys,
	entraWork:       defaultTabKeys,
}

// standInKeys is whether AWS documents key for issuer's tokens, as the
// registry answers it from the census, compared without ASCII case, as AWS
// reads keys.
func standInKeys(issuer trust.IssuerRef, key string) (documented, known bool) {
	keys, known := awsKeys[issuer]
	return slices.ContainsFunc(keys, func(k conditionKey) bool { return equalFoldASCII(k.Key, key) }), known
}

// standInMultivalued is whether AWS documents key as multivalued for
// issuer's tokens, as the registry answers it from the census.
func standInMultivalued(issuer trust.IssuerRef, key string) bool {
	return slices.ContainsFunc(awsKeys[issuer], func(k conditionKey) bool { return equalFoldASCII(k.Key, key) && k.Multivalued == "yes" })
}

// multiValuedClaims are the claims the census records each listed issuer's
// tokens may carry with several values, which
// TestTheStandInReadsTheKeysAWSDocuments holds to the census: a Kubernetes
// service account token "May be repeated to request a token valid for
// multiple audiences", and a Bitbucket pipeline declares a list of them.
var multiValuedClaims = map[trust.IssuerRef][]string{
	eksIssuer: {"aud"}, eksOtherRegion: {"aud"}, aksIssuer: {"aud"}, gkeIssuer: {"aud"}, bitbucketIssuer: {"aud"},
}

// standInMultiValuedClaim is whether AWS reads key, for issuer's tokens,
// from a claim they may carry with several values, or reads such a claim in
// its place when the token sets none, as the registry answers it from the
// census.
func standInMultiValuedClaim(issuer trust.IssuerRef, key string) bool {
	return slices.ContainsFunc(awsKeys[issuer], func(k conditionKey) bool {
		return equalFoldASCII(k.Key, key) && slices.ContainsFunc([]string{k.Claim, k.Fallback}, func(claim string) bool {
			return claim != "" && slices.Contains(multiValuedClaims[issuer], claim)
		})
	})
}

// parse reads a trust policy the way the command does, failing the test on
// a document the parser refuses.
func parse(t failer, raw []byte) (aws.Document, []trust.Grant) {
	t.Helper()
	d, err := aws.ParseTrustPolicy(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return d, d.Grants(role, vocabulary)
}

// grantOf builds a grant on issuer admitting the terms, for the tests that
// state a grant directly rather than through a document.
func grantOf(issuer trust.IssuerRef, terms ...eval.Term) trust.Grant {
	return trust.Grant{Target: role, Issuer: issuer, Effect: trust.Allow, Admits: eval.NewAdmittedSet(terms...)}
}
