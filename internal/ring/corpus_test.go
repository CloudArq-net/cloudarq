package ring

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/CloudArq-net/cloudarq/internal/parse/aws"
	"github.com/CloudArq-net/cloudarq/internal/trust"
)

// ringsDir holds one directory per case: the trust policy, aws.json;
// rationale.md, which says what each grant's place is and quotes the vendor
// sentence it rests on; and, for a case that declares owners, owners.txt,
// one declaration a line, which the command's goldens read too, so that the
// corpus here and the answers the command prints are of one declaration.
const ringsDir = "../../testdata/rings"

// The owners the corpus pins, built the way the classifier must build them.
func githubName(v string) Owner {
	return Owner{Issuer: githubIssuer, Namespace: NamespaceGitHub, Scope: ScopeOwner, Kind: KindName, Value: v, Recyclable: true}
}

func githubID(id, name string) Owner {
	return Owner{Issuer: githubIssuer, Namespace: NamespaceGitHub, Scope: ScopeOwner, Kind: KindID, Value: id, Name: name}
}

func githubRepositoryID(id string) Owner {
	return Owner{Issuer: githubIssuer, Namespace: NamespaceGitHub, Scope: ScopeRepository, Kind: KindID, Value: id}
}

func awsTenant(scope Scope, id string) Owner {
	return Owner{Issuer: aws.AWSPrincipalIssuer, Namespace: NamespaceAWS, Scope: scope, Kind: KindID, Value: id}
}

func samlOwner(arn trust.IssuerRef) Owner {
	return Owner{Issuer: arn, Namespace: NamespaceSAML, Scope: ScopeProvider, Kind: KindName, Value: string(arn), Recyclable: true}
}

func tenantOwner(issuer trust.IssuerRef, tenant string, kind Kind) Owner {
	return Owner{Issuer: issuer, Namespace: NamespaceIssuer, Scope: ScopeTenant, Kind: kind, Value: tenant, Recyclable: true}
}

func declaredAs(o Owner) Owner {
	o.Declared = true
	return o
}

// expectation is one grant's place, the grant named by its statement's Sid
// and its issuer, which together tell apart the faces of one "*".
type expectation struct {
	sid     string
	issuer  trust.IssuerRef
	outcome Outcome
	places  []Place
	state   State
	bases   []Basis
	owners  []Owner
}

func at(sid string, issuer trust.IssuerRef, place Place, state State, basis Basis, owners ...Owner) expectation {
	return expectation{sid: sid, issuer: issuer, outcome: Placed, places: []Place{place}, state: state, bases: []Basis{basis}, owners: owners}
}

func refused(sid string, issuer trust.IssuerRef) expectation {
	return expectation{sid: sid, issuer: issuer, outcome: Refused}
}

func nobody(sid string, issuer trust.IssuerRef) expectation {
	return expectation{sid: sid, issuer: issuer, outcome: Nobody}
}

func (e expectation) String() string {
	p := Placement{Outcome: e.outcome, Places: e.places, State: e.state, Owners: e.owners}
	return p.String()
}

type corpusCase struct {
	name   string
	grants []expectation
}

const sts = aws.AWSPrincipalIssuer

// corpus is every case under testdata/rings with the place of each of its
// grants. Each rationale.md says why, with the vendor's sentence.
var corpus = []corpusCase{
	{"01-branch-pin-and-owner-prefix", []expectation{
		at("DeployFromMain", githubIssuer, Outsider, StateExact, Pinned, githubName("acme")),
		at("PreviewFromAcmeRepositories", githubIssuer, Platform, StateExact, Unpinned),
	}},
	{"02-owner-name-and-id", []expectation{
		at("OwnerByNameAndID", githubIssuer, Outsider, StateExact, Pinned, githubID("123456", "acme")),
	}},
	{"03-owner-name-any-id", []expectation{
		at("OwnerNameAnyID", githubIssuer, Outsider, StateExact, Pinned, githubName("acme")),
	}},
	{"04-owner-name-legacy-form", []expectation{
		at("OwnerNameLegacyForm", githubIssuer, Outsider, StateExact, Pinned, githubName("acme")),
	}},
	{"05-owner-id-not-closed", []expectation{
		at("OwnerIDNotClosed", githubIssuer, Outsider, StateExact, Pinned, githubName("acme")),
	}},
	{"06-owner-id-after-a-wildcard", []expectation{
		at("OwnerIDAfterAWildcard", githubIssuer, Platform, StateExact, Unpinned),
	}},
	{"07-anyone-on-web-identity", []expectation{
		at("AnyWebIdentity", "", Anyone, StateUnknown, AnyIssuer),
		nobody("AnyWebIdentity", sts),
	}},
	{"08-anyone-on-saml-alone", []expectation{
		at("AnySAMLSignIn", "", SAML, StateUnknown, AccountSAMLProviders),
		nobody("AnySAMLSignIn", sts),
	}},
	{"09-anyone-on-every-sts-action", []expectation{
		at("AnyoneAnySTSAction", "", Anyone, StateUnknown, AnyIssuer),
		at("AnyoneAnySTSAction", sts, Platform, StateExact, Unpinned),
	}},
	{"10-anyone-on-assume-role", []expectation{
		at("AnyoneAssumeRole", "", Service, StateUnknown, AnyService),
		at("AnyoneAssumeRole", sts, Platform, StateExact, Unpinned),
	}},
	{"11-cognito-guests", []expectation{
		at("IdentityPoolGuests", cognitoIssuer, Anyone, StateUnknown, TokensWithoutAccount),
	}},
	{"12-cognito-authenticated", []expectation{
		at("IdentityPoolSignedIn", cognitoIssuer, Anyone, StateUnknown, TokensWithoutAccount),
	}},
	{"13-google", []expectation{
		at("GoogleAudience", googleIssuer, Platform, StateUnknown, TenancyNotRecorded),
	}},
	{"14-login-with-amazon", []expectation{
		at("LoginWithAmazonApp", amazonIssuer, Platform, StateUnknown, TenancyNotRecorded),
	}},
	{"15-facebook", []expectation{
		at("FacebookApp", facebookIssuer, Anyone, StateUnknown, AccountNotVerified),
	}},
	{"16-actor-is-not-a-tenant", []expectation{
		at("OneActorAnyRepository", githubIssuer, Platform, StateExact, Unpinned),
	}},
	{"17-gitlab-ci-config-ref-uri", []expectation{
		at("GitLabPipelineDefinition", gitlabIssuer, Anyone, StateUnknown, AccountNotVerified),
	}},
	{"18-external-id-under-any-aws-account", []expectation{
		at("AnyAccountWithTheExternalID", "", Service, StateUnknown, AnyService),
		at("AnyAccountWithTheExternalID", sts, Platform, StateExact, Unpinned),
	}},
	{"19-organisation-behind-any-principal", []expectation{
		at("OneOrganisation", "", Service, StateUnknown, AnyService),
		at("OneOrganisation", sts, Outsider, StateExact, Pinned, awsTenant(ScopeOrganisation, "o-a1b2c3d4e5")),
	}},
	{"20-saml-provider-of-a-vendor", []expectation{
		at("VendorSSO", samlVendor, SAML, StateUnknown, SAMLProvider, samlOwner(samlVendor)),
	}},
	{"21-service-without-source-account", []expectation{
		at("ServiceAssumes", aws.ServiceIssuerPrefix+"sns.amazonaws.com", Service, StateUnknown, ServicePrincipal),
	}},
	{"22-job-workflow-ref-subject", []expectation{
		at("CalledWorkflow", githubIssuer, Platform, StateExact, Unpinned),
	}},
	{"23-gitlab-nested-group", []expectation{
		at("GitLabSubgroup", gitlabIssuer, Anyone, StateUnknown, AccountNotVerified),
	}},
	{"24-gitlab-project-id-subject", []expectation{
		at("GitLabProjectByID", gitlabIssuer, Anyone, StateUnknown, AccountNotVerified),
	}},
	{"25-eks-cluster", []expectation{
		at("ClusterServiceAccount", eksIssuer, Outsider, StateExact, ControlledTenant, tenantOwner(eksIssuer, "EXAMPLED539D4633E53DE1B71EXAMPLE", KindID)),
	}},
	{"26-question-mark-in-the-owner", []expectation{
		at("OneCharacterOfTheOwnerOpen", githubIssuer, Platform, StateExact, Unpinned),
	}},
	{"27-deny-for-anyone", []expectation{
		refused("DenyEveryoneElse", ""),
		refused("DenyEveryoneElse", sts),
		at("AcmeRepositories", githubIssuer, Outsider, StateExact, Pinned, githubName("acme")),
	}},
	{"28-no-assume-action", []expectation{
		nobody("WrongAction", githubIssuer),
	}},
	{"29-unsurveyed-issuer", []expectation{
		at("UnsurveyedIssuer", "https://ci.example.com", Anyone, StateUnknown, IssuerNotSurveyed),
	}},
	{"30-union-with-one-open-member", []expectation{
		at("AcmeOrAnythingBeginningAcme", githubIssuer, Platform, StateExact, Unpinned),
	}},
	{"31-unread-subject", []expectation{
		at("SubjectUnderForAllValues", githubIssuer, Platform, StateUnknown, UnreadConstraint),
	}},
	{"32-default-with-acme-declared", []expectation{
		at("DeployFromMain", githubIssuer, Yours, StateExact, Pinned, declaredAs(githubName("acme"))),
		at("PreviewFromAcmeRepositories", githubIssuer, Platform, StateExact, Unpinned),
	}},
	{"33-declared-in-another-case", []expectation{
		at("DeployFromMain", githubIssuer, Outsider, StateExact, Pinned, githubName("acme")),
		at("PreviewFromAcmeRepositories", githubIssuer, Platform, StateExact, Unpinned),
	}},
	{"34-aws-account", []expectation{
		at("PartnerAccount", sts, Outsider, StateExact, Pinned, awsTenant(ScopeAccount, "111122223333")),
	}},
	{"35-saml-provider-declared", []expectation{
		at("CompanySSO", samlVendor, People, StateUnknown, SAMLProvider, declaredAs(samlOwner(samlVendor))),
	}},
	{"36-entra-tenants", []expectation{
		at("PersonalMicrosoftAccounts", entraPersonal, Platform, StateExact, OpenTenant),
		at("OneWorkTenant", entraWork, Platform, StateUnknown, MembershipNotVerified),
	}},
	{"37-enterprise-issuer", []expectation{
		at("EnterpriseIssuer", enterpriseIssuer, Outsider, StateExact, ControlledTenant, tenantOwner(enterpriseIssuer, "acme-ent", KindName)),
	}},
	{"38-repository-id-subject", []expectation{
		at("RepositoryByID", githubIssuer, Outsider, StateExact, Pinned, githubRepositoryID("456789")),
	}},
	{"39-owner-led-subjects", []expectation{
		at("OwnerLedByName", githubIssuer, Outsider, StateExact, Pinned, githubName("acme")),
		at("OwnerLedByID", githubIssuer, Outsider, StateExact, Pinned, githubID("123456", "")),
	}},
	{"40-principal-arn-patterns", []expectation{
		at("RolesOfOneAccount", "", Service, StateUnknown, AnyService),
		at("AccountNotClosed", "", Service, StateUnknown, AnyService),
		at("AccountNotClosed", sts, Platform, StateExact, Unpinned),
		at("RolesOfOneAccount", sts, Outsider, StateExact, Pinned, awsTenant(ScopeAccount, "111122223333")),
	}},
	{"41-union-of-owners", []expectation{
		at("ThreeOwners", githubIssuer, Outsider, StateExact, Pinned, githubName("acme"), githubName("beta"), githubName("gamma")),
	}},
	{"42-principals-not-modelled", []expectation{
		at("S3CanonicalUser", sts, Anyone, StateUnknown, PrincipalNotModelled),
		at("BucketAsPrincipal", sts, Anyone, StateUnknown, PrincipalNotModelled),
		at("RoleAsFederatedProvider", "", Anyone, StateUnknown, PrincipalNotModelled),
	}},
	{"43-spacelift-account", []expectation{
		at("SpaceliftAccount", spaceliftIssuer, Platform, StateUnknown, MembershipNotVerified),
	}},
	{"44-bitbucket-workspace", []expectation{
		at("BitbucketWorkspace", bitbucketIssuer, Platform, StateUnknown, MembershipNotVerified),
	}},
	{"45-aks-cluster", []expectation{
		at("ClusterServiceAccount", aksIssuer, Outsider, StateExact, ControlledTenant, tenantOwner(aksIssuer, aksTenant, KindID)),
	}},
	{"46-look-alike-hosts", []expectation{
		at("KelvinSignForK", "", Anyone, StateUnknown, PrincipalNotModelled),
		at("DottedCapitalIForI", "", Anyone, StateUnknown, PrincipalNotModelled),
	}},
	{"47-cluster-id-in-another-region", []expectation{
		at("DeclaredCluster", eksIssuer, Yours, StateExact, ControlledTenant, declaredAs(tenantOwner(eksIssuer, eksCluster, KindID))),
		at("SameIDOtherRegion", eksOtherRegion, Outsider, StateExact, ControlledTenant, tenantOwner(eksOtherRegion, eksCluster, KindID)),
	}},
	{"48-enterprise-claim-by-name", []expectation{
		at("EnterpriseByName", githubIssuer, Platform, StateExact, Unpinned),
	}},
	{"49-assume-actions-beyond-ascii", []expectation{
		at("GitHubThroughADotlessI", githubIssuer, Platform, StateUnknown, UnreadConstraint),
		at("AnyoneThroughALongS", "", Anyone, StateUnknown, AnyIssuer),
		nobody("AnyoneThroughALongS", sts),
		at("AnySAMLThroughADotlessI", "", Anyone, StateUnknown, AnyIssuer),
		nobody("AnySAMLThroughADotlessI", sts),
		at("AccountThroughALongS", sts, Outsider, StateExact, Pinned, awsTenant(ScopeAccount, "111122223333")),
		at("SAMLProviderThroughADotlessI", samlVendor, SAML, StateUnknown, SAMLProvider, samlOwner(samlVendor)),
		at("ServiceThroughALongS", aws.ServiceIssuerPrefix+"ec2.amazonaws.com", Service, StateUnknown, ServicePrincipal),
		at("CognitoThroughADottedCapitalI", cognitoIssuer, Anyone, StateUnknown, TokensWithoutAccount),
	}},
	{"50-unread-subject-beside-an-open-one", []expectation{
		at("OpenSubjectBesideAnUnreadOne", githubIssuer, Platform, StateUnknown, UnreadConstraint),
	}},
	{"51-subject-key-beyond-ascii", []expectation{
		at("SubjectKeyWithALongS", githubIssuer, Platform, StateUnknown, UnreadConstraint),
		at("ProviderKeyWithALongS", githubIssuer, Platform, StateUnknown, UnreadConstraint),
	}},
	{"52-no-statement", nil},
	{"53-identity-pool-issuer-declared", []expectation{
		at("IdentityPoolSignedIn", cognitoIssuer, Anyone, StateUnknown, TokensWithoutAccount),
	}},
	{"54-region-host-declared", []expectation{
		at("ClusterServiceAccount", eksIssuer, Outsider, StateExact, ControlledTenant, tenantOwner(eksIssuer, eksCluster, KindID)),
	}},
	{"55-gke-cluster", []expectation{
		at("ClusterServiceAccount", gkeIssuer, Outsider, StateExact, ControlledTenant, tenantOwner(gkeIssuer, "proj/us-central1/c1", KindName)),
	}},
	{"56-owner-key-aws-does-not-document", []expectation{
		at("OwnerByAKeyAWSDoesNotDocument", githubIssuer, Platform, StateUnknown, UnreadConstraint),
	}},
	{"57-id-keys-aws-documents", []expectation{
		at("OwnerByID", githubIssuer, Outsider, StateExact, Pinned, githubID("123456", "")),
		at("RepositoryByID", githubIssuer, Outsider, StateExact, Pinned, githubRepositoryID("456789")),
		at("EnterpriseByID", githubIssuer, Outsider, StateExact, Pinned, Owner{Issuer: githubIssuer, Namespace: NamespaceGitHub, Scope: ScopeEnterprise, Kind: KindID, Value: "123", Recyclable: true}),
	}},
	{"58-oaud-reads-aud", []expectation{
		at("AudienceByOaud", githubIssuer, Outsider, StateExact, Pinned, githubName("acme")),
	}},
	{"59-entra-audience-reads-azp", []expectation{
		at("OneClientOfAWorkTenant", entraWork, Platform, StateUnknown, MembershipNotVerified),
	}},
	{"60-saml-provider-near-miss-declared", []expectation{
		at("CorpIdQ", "arn:aws:iam::123456789012:saml-provider/CorpIdQ", SAML, StateUnknown, SAMLProvider, samlOwner("arn:aws:iam::123456789012:saml-provider/CorpIdQ")),
	}},
	{"61-aws-account-near-miss-declared", []expectation{
		at("PartnerAccount", sts, Outsider, StateExact, Pinned, awsTenant(ScopeAccount, "111122223334")),
	}},
	{"62-repository-pattern-closing-the-owner", []expectation{
		at("AnyRepositoryOfAcme", githubIssuer, Platform, StateUnknown, UnreadConstraint),
	}},
	{"63-amr-named-twice-cognito", []expectation{
		at("PoolSignedInThroughFacebook", cognitoIssuer, Anyone, StateUnknown, TokensWithoutAccount),
	}},
	{"64-amr-named-twice-entra", []expectation{
		at("WorkforceWithMFA", entraWork, Platform, StateUnknown, MembershipNotVerified),
	}},
	{"65-aud-named-twice-eks", []expectation{
		at("PodWithTwoAudiences", eksIssuer, Outsider, StateExact, ControlledTenant, tenantOwner(eksIssuer, eksCluster, KindID)),
	}},
	// AWS's own trust policies for the services that assume a role for
	// identities outside IAM: each a door, unknown, whatever its conditions
	{"66-roles-anywhere-documented-policy", []expectation{
		at("", serviceIssuer("rolesanywhere.amazonaws.com"), Service, StateUnknown, ServiceIntermediary),
	}},
	{"67-iot-credentials-provider", []expectation{
		at("", serviceIssuer("credentials.iot.amazonaws.com"), Service, StateUnknown, ServiceIntermediary),
	}},
	{"68-ssm-hybrid-activation-role", []expectation{
		at("", serviceIssuer("ssm.amazonaws.com"), Service, StateUnknown, ServiceIntermediary),
	}},
	{"69-any-service-face-with-source-account", []expectation{
		at("AnyoneFromOneSourceAccount", "", Service, StateUnknown, AnyService),
		at("AnyoneFromOneSourceAccount", sts, Platform, StateUnknown, UnreadConstraint),
	}},
	{"70-eks-pod-identity-documented-policy", []expectation{
		at("AllowEksAuthToAssumeRoleForPodIdentity", serviceIssuer("pods.eks.amazonaws.com"), Service, StateUnknown, ServiceIntermediary),
	}},
	{"71-transfer-family-user-role", []expectation{
		at("", serviceIssuer("transfer.amazonaws.com"), Service, StateUnknown, ServiceIntermediary),
	}},
	{"72-ec2-and-ssm-in-one-statement", []expectation{
		at("InstancesAndHybridMachines", serviceIssuer("ec2.amazonaws.com"), Service, StateUnknown, ServicePrincipal),
		at("InstancesAndHybridMachines", serviceIssuer("ssm.amazonaws.com"), Service, StateUnknown, ServiceIntermediary),
	}},
	{"73-five-services-acting-for-identities-outside-iam", []expectation{
		at("FiveServicesActingForIdentitiesOutsideIAM", serviceIssuer("credentials.iot.amazonaws.com"), Service, StateUnknown, ServiceIntermediary),
		at("FiveServicesActingForIdentitiesOutsideIAM", serviceIssuer("pods.eks.amazonaws.com"), Service, StateUnknown, ServiceIntermediary),
		at("FiveServicesActingForIdentitiesOutsideIAM", serviceIssuer("rolesanywhere.amazonaws.com"), Service, StateUnknown, ServiceIntermediary),
		at("FiveServicesActingForIdentitiesOutsideIAM", serviceIssuer("ssm.amazonaws.com"), Service, StateUnknown, ServiceIntermediary),
		at("FiveServicesActingForIdentitiesOutsideIAM", serviceIssuer("transfer.amazonaws.com"), Service, StateUnknown, ServiceIntermediary),
	}},
	// AWS's own trust policies for two more of the roles Systems Manager
	// assumes: the service is placed as it is for a hybrid activation's
	{"74-ssm-maintenance-window-service-role", []expectation{
		at("", serviceIssuer("ssm.amazonaws.com"), Service, StateUnknown, ServiceIntermediary),
	}},
	{"75-ssm-automation-service-role", []expectation{
		at("", serviceIssuer("ssm.amazonaws.com"), Service, StateUnknown, ServiceIntermediary),
	}},
}

// readOn is the date a rationale says a quoted sentence was read.
var readOn = regexp.MustCompile(`read \d{4}-\d{2}-\d{2}`)

// classified is one grant of a corpus document with its placement, and the
// owners its case declared.
type classified struct {
	sid       string
	grant     trust.Grant
	placement Placement
	declared  []Declaration
}

// owners is what a case declares: its owners.txt, or nothing.
func owners(t failer, name string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(ringsDir, name, "owners.txt"))
	if errors.Is(err, fs.ErrNotExist) {
		return ""
	}
	if err != nil {
		t.Fatalf("%v", err)
	}
	return string(raw)
}

// classifyCase reads a case's document and declaration and places every
// grant, the way internal/report's answer does.
func classifyCase(t failer, c corpusCase) []classified {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(ringsDir, c.name, "aws.json"))
	if err != nil {
		t.Fatalf("%v", err)
	}
	d, grants := parse(t, raw)
	declared := ReadDeclarations(owners(t, c.name))
	if declared.Overrun != nil {
		t.Fatalf("%s: declarations: %+v", c.name, declared.Overrun)
	}
	if len(declared.Refused) != 0 {
		t.Fatalf("%s: declarations refused: %v", c.name, declared.Refused)
	}
	var out []classified
	for _, g := range grants {
		s, ok := statementOf(g, d)
		if !ok {
			t.Fatalf("%s: a grant came from no statement", c.name)
		}
		out = append(out, classified{s.Sid, g, Classify(g, factsOf(t, g, d), declared.Owners), declared.Owners})
	}
	return out
}

// TestRingsCorpus places every grant of every case and compares it with the
// place its rationale gives, and holds the corpus to itself: every case
// directory has a document and a rationale that quotes a vendor sentence,
// every case in the table has a directory, and every grant a document
// projects is expected, so that nothing under testdata/rings is examined by
// nothing.
func TestRingsCorpus(t *testing.T) {
	entries, err := os.ReadDir(ringsDir)
	if err != nil {
		t.Fatalf("%v", err)
	}
	var dirs []string
	for _, e := range entries {
		if e.IsDir() {
			dirs = append(dirs, e.Name())
		}
	}
	var named []string
	for _, c := range corpus {
		named = append(named, c.name)
	}
	if !slices.Equal(dirs, named) {
		t.Fatalf("the directories under %s and the cases in the table differ:\n dirs  %v\n table %v", ringsDir, dirs, named)
	}
	examined, declaring := 0, 0
	for _, c := range corpus {
		files, err := os.ReadDir(filepath.Join(ringsDir, c.name))
		if err != nil {
			t.Fatalf("%v", err)
		}
		for _, f := range files {
			switch f.Name() {
			case "aws.json", "rationale.md":
			case "owners.txt":
				declaring++
			default:
				t.Errorf("%s: %s is no file a case holds, and nothing would read it", c.name, f.Name())
			}
		}
		rationale, err := os.ReadFile(filepath.Join(ringsDir, c.name, "rationale.md"))
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		if !strings.Contains(string(rationale), "\n> ") || !readOn.Match(rationale) || !strings.Contains(string(rationale), "https://") {
			t.Errorf("%s: the rationale quotes no vendor sentence with its source and the date it was read", c.name)
		}
		got := classifyCase(t, c)
		if len(got) != len(c.grants) {
			t.Errorf("%s: %d grants, the table expects %d", c.name, len(got), len(c.grants))
			continue
		}
		for _, want := range c.grants {
			i := slices.IndexFunc(got, func(g classified) bool { return g.sid == want.sid && g.grant.Issuer == want.issuer })
			if i < 0 {
				t.Errorf("%s: no grant of %s on %q", c.name, want.sid, want.issuer)
				continue
			}
			examined++
			p := got[i].placement
			if p.String() != want.String() {
				t.Errorf("%s, %s on %q:\n got  %s\n want %s", c.name, want.sid, want.issuer, p, want)
			}
			var bases []Basis
			for _, pop := range p.Populations {
				bases = append(bases, pop.Basis)
			}
			if p.Outcome == Placed && !slices.Equal(bases, want.bases) {
				t.Errorf("%s, %s on %q: populations decided by %v, want %v", c.name, want.sid, want.issuer, bases, want.bases)
			}
		}
	}
	if examined == 0 || declaring == 0 {
		t.Fatalf("%d grants examined, %d cases declaring owners; the corpus examined too little", examined, declaring)
	}
	t.Logf("examined %d grants in %d cases, %d of them declaring owners", examined, len(corpus), declaring)
}

// TestDeterminismOfThePlacements places the whole corpus twenty times in
// one process and requires the same bytes every time: the Makefile's gate
// runs this in twenty fresh processes too, where map order and anything
// else that varies between runs would show.
func TestDeterminismOfThePlacements(t *testing.T) {
	render := func() string {
		var b strings.Builder
		for _, c := range corpus {
			for _, g := range classifyCase(t, c) {
				b.WriteString(c.name + " " + g.sid + " " + string(g.grant.Issuer) + ": " + g.placement.String() + "\n")
				for _, pop := range g.placement.Populations {
					b.WriteString("  " + pop.String() + "\n")
				}
			}
		}
		return b.String()
	}
	first := render()
	if !strings.Contains(first, "outsider") || !strings.Contains(first, "declared") || !strings.Contains(first, `"gamma"`) {
		t.Fatalf("the rendering places nobody outside the platform, declares nothing or names no grant's several owners; the comparison would prove little:\n%s", first)
	}
	for i := 1; i < 20; i++ {
		if again := render(); again != first {
			t.Fatalf("run %d rendered differently:\n%s\nfirst:\n%s", i, again, first)
		}
	}
	t.Logf("20 runs, %d bytes each", len(first))
}
