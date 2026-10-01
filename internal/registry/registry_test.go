package registry

import (
	"os"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/CloudArq-net/issuers/tenancy"

	"github.com/CloudArq-net/cloudarq/internal/eval"
	"github.com/CloudArq-net/cloudarq/internal/ring"
	"github.com/CloudArq-net/cloudarq/internal/trust"
)

const github = trust.IssuerRef("https://token.actions.githubusercontent.com")

// The census the engine is built against: the two lists below change only
// when the census does, and then the requirement and these lists move in
// the same commit, which is the cost of the import made visible. They are
// census v0.2.0's, which corrects the entries its vendors contradict: Codeberg's
// issuer and Azure DevOps' are unverified in it, so neither is a host a
// token can be matched to.
var (
	exactIssuers = []trust.IssuerRef{
		"https://accounts.google.com", "https://agent.buildkite.com", "https://api.cursor.com",
		"https://api.pulumi.com/oidc", "https://api2.cursor.sh/cloud-agent/identity", "https://app.devin.ai",
		"https://app.terraform.io", "https://app.warp.dev", "https://federation.namespaceapis.com",
		"https://gitlab.com", "https://identity.depot.dev", "https://issuer.enforce.dev",
		"https://login.app.env0.com", "https://oidc.codefresh.io", "https://oidc.modal.com", "https://scalr.io", github,
	}
	multiTenantHosts = []string{
		"accounts.google.com", "agent.buildkite.com", "api.bitbucket.org", "api.cursor.com", "api.pulumi.com",
		"api2.cursor.sh", "app.devin.ai", "app.harness.io", "app.terraform.io", "app.warp.dev",
		"container.googleapis.com", "federation.namespaceapis.com", "gitlab.com", "identity.depot.dev",
		"issuer.enforce.dev", "login.app.env0.com", "login.microsoftonline.com", "oidc.circleci.com",
		"oidc.codefresh.io", "oidc.modal.com", "scalr.io", "token.actions.githubusercontent.com",
	}
)

// TestTheCensusIsTheRequiredModule: the census the engine reads is the one
// go.mod requires, by its tag, and never a copy a replace directive points
// at. A replace committed to go.mod would build every clone against a tree
// no tag holds; developing against an unreleased census is what a go.work
// that git ignores is for.
func TestTheCensusIsTheRequiredModule(t *testing.T) {
	raw, err := os.ReadFile("../../go.mod")
	if err != nil {
		t.Fatalf("read go.mod: %v", err)
	}
	required := false
	for i, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if fields[0] == "replace" || strings.HasPrefix(fields[0], "replace(") {
			t.Errorf("go.mod line %d replaces a module: %q; the census is required by its tag, and a local census is used through a go.work git ignores", i+1, line)
		}
		for j, field := range fields[:len(fields)-1] {
			if field == "github.com/CloudArq-net/issuers" && strings.HasPrefix(fields[j+1], "v") {
				required = true
			}
		}
	}
	if !required {
		t.Fatalf("go.mod does not require github.com/CloudArq-net/issuers at a version; the gate read nothing it guards:\n%s", raw)
	}
}

// TestLookupBySpelling: a URL, a bare host, a scheme and host in capitals,
// and a trailing slash all reach the same entry, because the engine
// normalises before the census, which keys by host, is asked.
func TestLookupBySpelling(t *testing.T) {
	for _, spelling := range []string{
		"https://token.actions.githubusercontent.com",
		"token.actions.githubusercontent.com",
		"HTTPS://Token.Actions.GitHubUserContent.com/",
		"oidc://token.actions.githubusercontent.com/",
	} {
		e, ok := Lookup(trust.IssuerRef(spelling))
		if !ok {
			t.Fatalf("%q: not found", spelling)
		}
		if e.Issuer != github || e.Host != "token.actions.githubusercontent.com" || e.Name != "GitHub Actions" {
			t.Fatalf("%q: %+v", spelling, e)
		}
		if !slices.Contains(e.Claims, "repository_id") || !slices.Contains(e.ImmutableIDClaims, "repository_owner_id") {
			t.Fatalf("%q: claims %v immutable %v", spelling, e.Claims, e.ImmutableIDClaims)
		}
		// sub is a claim and a name, never an immutable identifier.
		if !slices.Contains(e.Claims, "sub") || slices.Contains(e.ImmutableIDClaims, "sub") {
			t.Fatalf("%q: immutable claims %v carry sub, or claims %v lack it", spelling, e.ImmutableIDClaims, e.Claims)
		}
		if e.AudControlledBy != "workload" || e.TenancyModel != "shared" {
			t.Fatalf("%q: aud %q tenancy %q", spelling, e.AudControlledBy, e.TenancyModel)
		}
	}
}

// TestLookupUnsurveyed: a host nobody surveyed is false, which the caller
// must read as "not surveyed", never as "safe"; a ref with no host is false;
// and the notes the census writes in the issuer field ("unverified" on the
// entry for the CI service at app.harness.io) are not hosts, although the
// module keys them like hosts.
func TestLookupUnsurveyed(t *testing.T) {
	for _, spelling := range []string{"https://oidc.example.test", "", "https://", "unverified", "https://unverified"} {
		if e, ok := Lookup(trust.IssuerRef(spelling)); ok {
			t.Fatalf("%q: found %+v", spelling, e)
		}
	}
}

// TestLookupPerTenantPattern: a per-tenant entry is reachable by Lookup only
// through its placeholder host, and a real tenant's host is not surveyed as
// far as Lookup can tell; the doc comment on Lookup says so, and Facts is
// what reads a tenant's URL.
func TestLookupPerTenantPattern(t *testing.T) {
	e, ok := Lookup("https://<account>.app.spacelift.io")
	if !ok || e.Issuer != "" || e.Name != "Spacelift" {
		t.Fatalf("placeholder host: ok %v entry %+v", ok, e)
	}
	if e, ok := Lookup("https://acme.app.spacelift.io"); ok {
		t.Fatalf("a real tenant host matched the pattern entry: %+v", e)
	}
}

// TestAbsentIsNotEmpty: Depot's census entry has no claims field at all
// (nobody surveyed the token), env0's says the survey found no claims and no
// immutable identifier; the engine keeps nil apart from empty.
func TestAbsentIsNotEmpty(t *testing.T) {
	depot, ok := Lookup("https://identity.depot.dev")
	if !ok || depot.Claims != nil || depot.ImmutableIDClaims != nil {
		t.Fatalf("depot: ok %v claims %#v immutable %#v; want nil for unsurveyed", ok, depot.Claims, depot.ImmutableIDClaims)
	}
	env0, ok := Lookup("https://login.app.env0.com")
	if !ok || env0.Claims == nil || env0.ImmutableIDClaims == nil || len(env0.ImmutableIDClaims) != 0 {
		t.Fatalf("env0: ok %v claims %#v immutable %#v; want empty, not nil", ok, env0.Claims, env0.ImmutableIDClaims)
	}
}

// TestAudienceIsBoundary: GitHub lets the workload pick the audience, so aud
// is not a boundary and that is known; an entry the census marks unverified
// answers known == false, which is never read as a boundary.
func TestAudienceIsBoundary(t *testing.T) {
	if isBoundary, known := AudienceIsBoundary(github); isBoundary || !known {
		t.Fatalf("github: boundary %v known %v", isBoundary, known)
	}
	if isBoundary, known := AudienceIsBoundary("https://login.app.env0.com"); isBoundary || known {
		t.Fatalf("env0 (unverified): boundary %v known %v", isBoundary, known)
	}
	for _, ref := range []trust.IssuerRef{"https://oidc.example.test", ""} {
		if isBoundary, known := AudienceIsBoundary(ref); isBoundary || known {
			t.Fatalf("%q: boundary %v known %v", ref, isBoundary, known)
		}
	}
}

// TestSubjectsAreRecyclable: GitHub carries immutable id claims, so its
// subjects need not be recyclable names; env0's survey found none, so they
// are; Depot's were never surveyed, so the answer is cautious and not
// known; an unsurveyed issuer is the same.
func TestSubjectsAreRecyclable(t *testing.T) {
	if recyclable, known := SubjectsAreRecyclable(github); recyclable || !known {
		t.Fatalf("github: recyclable %v known %v", recyclable, known)
	}
	if recyclable, known := SubjectsAreRecyclable("https://login.app.env0.com"); !recyclable || !known {
		t.Fatalf("env0: recyclable %v known %v", recyclable, known)
	}
	for _, ref := range []trust.IssuerRef{"https://identity.depot.dev", "https://oidc.example.test", ""} {
		if recyclable, known := SubjectsAreRecyclable(ref); !recyclable || known {
			t.Fatalf("%q: recyclable %v known %v", ref, recyclable, known)
		}
	}
}

// TestKnownIssuers: exactly the census's exact issuers, normalised (env0's
// trailing slash gone, Pulumi's and Cursor's paths kept), sorted, once.
func TestKnownIssuers(t *testing.T) {
	if got := KnownIssuers(); !slices.Equal(got, exactIssuers) {
		t.Fatalf("known issuers:\n got %v\nwant %v", got, exactIssuers)
	}
}

// TestMultiTenantHosts: exactly the census's shared and per-tenant-path
// hosts, sorted; a host missing here is one where aud alone would be read
// as a boundary it is not.
func TestMultiTenantHosts(t *testing.T) {
	if got := MultiTenantHosts(); !slices.Equal(got, multiTenantHosts) {
		t.Fatalf("multi-tenant hosts:\n got %v\nwant %v", got, multiTenantHosts)
	}
}

func TestCensusDate(t *testing.T) {
	if d := CensusDate(); d != "2026-09-13" {
		t.Fatalf("census date %q, want the pinned snapshot's", d)
	}
}

// TestDeterminism: two reads give the same answers, and a caller that
// edits what it was handed does not change the next answer.
func TestDeterminism(t *testing.T) {
	if a, b := KnownIssuers(), KnownIssuers(); !slices.Equal(a, b) {
		t.Fatalf("known issuers differ between calls")
	}
	if a, b := MultiTenantHosts(), MultiTenantHosts(); !slices.Equal(a, b) {
		t.Fatalf("multi-tenant hosts differ between calls")
	}
	a, _ := Lookup(github)
	b, _ := Lookup(github)
	if !slices.Equal(a.Claims, b.Claims) || !slices.Equal(a.ImmutableIDClaims, b.ImmutableIDClaims) {
		t.Fatalf("entries differ between calls")
	}
	a.Claims[0] = "edited"
	if c, _ := Lookup(github); c.Claims[0] == "edited" {
		t.Fatalf("the entry shares its slices with the caller")
	}
	f, _ := Facts(github)
	f.Tenancy.Claims[0].Claim = "edited"
	f.Tenancy.SubjectForms[0].Parts[0].Delimiter = "edited"
	f.Tenancy.OwnerCharacters[0].First = 'x'
	if g, _ := Facts(github); g.Tenancy.Claims[0].Claim == "edited" || g.Tenancy.SubjectForms[0].Parts[0].Delimiter == "edited" || g.Tenancy.OwnerCharacters[0].First == 'x' {
		t.Fatalf("the facts share their slices with the caller:\n%+v", g.Tenancy)
	}
}

// The look-alikes: case folding turns a Kelvin sign into k and a capital I
// with a dot above into i, so a reader that folded the host would take each
// of these for a census host. Every census host is ASCII, so none of them
// is one.
const (
	kelvinSign = "\u212a"
	dottedI    = "\u0130"
)

// TestALookAlikeHostIsNotSurveyed is the trap at the seam for a grant
// placed nearer than its population: a host spelled with a letter that
// case folding turns into an ASCII one is not the census host it would
// fold onto, and every answer about it is the one for an issuer
// nobody surveyed. Read as the census host, GitHub's look-alike would place
// a pinned subject with a named outsider, and the EKS look-alike would name
// a cluster a declaration could then move into the user's own ring, for
// an issuer whoever registered the look-alike host controls.
func TestALookAlikeHostIsNotSurveyed(t *testing.T) {
	cluster := "EXAMPLED539D4633E53DE1B71EXAMPLE"
	for _, c := range []struct{ lookAlike, surveyed trust.IssuerRef }{
		{"https://to" + kelvinSign + "en.actions.githubusercontent.com", github},
		{"https://TO" + kelvinSign + "EN.ACTIONS.GITHUBUSERCONTENT.COM", github},
		{"https://o" + dottedI + "dc.eks.us-east-1.amazonaws.com/id/" + trust.IssuerRef(cluster), "https://oidc.eks.us-east-1.amazonaws.com/id/" + trust.IssuerRef(cluster)},
		{"https://g" + dottedI + "tlab.com", "https://gitlab.com"},
	} {
		// the host spelled in ASCII is surveyed, so a look-alike read as that
		// host would be found: the trap tests something
		if f, names := Facts(c.surveyed); f.IssuerKind == ring.NotSurveyed || names.Entry == "" {
			t.Fatalf("%q is not surveyed; the trap proves nothing", c.surveyed)
		}
		if _, ok := Lookup(c.surveyed); !ok && !strings.Contains(string(c.surveyed), "/id/") {
			t.Fatalf("%q is not found by Lookup; the trap proves nothing", c.surveyed)
		}
		if f, names := Facts(c.lookAlike); !reflect.DeepEqual(f, ring.Facts{}) || names != (Names{}) {
			t.Errorf("%q read as surveyed: %+v, %+v", c.lookAlike, names, f)
		}
		if e, ok := Lookup(c.lookAlike); ok {
			t.Errorf("%q found as %q", c.lookAlike, e.Name)
		}
		if _, known := AudienceIsBoundary(c.lookAlike); known {
			t.Errorf("%q: the audience rule is known", c.lookAlike)
		}
		if _, known := SubjectsAreRecyclable(c.lookAlike); known {
			t.Errorf("%q: recyclability is known", c.lookAlike)
		}
	}
}

// TestTheFactsTheCorpusRestsOn: every issuer testdata/rings names is
// matched to the census entry named here, and a URL that names no tenant,
// or one of the AWS parser's pseudo-issuers, to none. The facts the corpus
// reads for each are internal/ring's stand-in's, which
// TestTheStandInIsTheCensus there holds to Facts; the facts here are those
// of the entries the corpus does not name, and of the URLs no entry
// matches.
func TestTheFactsTheCorpusRestsOn(t *testing.T) {
	named := []struct {
		issuer trust.IssuerRef
		name   string
	}{
		{github, "GitHub Actions"},
		{"https://token.actions.githubusercontent.com/", "GitHub Actions"},
		{"https://cognito-identity.amazonaws.com", "Amazon Cognito identity pools"},
		{"https://accounts.google.com", "Google (accounts.google.com)"},
		{"https://www.amazon.com", "Login with Amazon"},
		{"https://graph.facebook.com", "Facebook"},
		{"https://gitlab.com", "GitLab.com"},
		{"https://oidc.eks.us-east-1.amazonaws.com/id/EXAMPLED539D4633E53DE1B71EXAMPLE", "Amazon EKS (Kubernetes service account issuer / IRSA)"},
		{"https://oidc.eks.eu-west-1.amazonaws.com/id/EXAMPLED539D4633E53DE1B71EXAMPLE", "Amazon EKS (Kubernetes service account issuer / IRSA)"},
		{"https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0", "Microsoft Entra ID"},
		{"https://login.microsoftonline.com/ffffffff-eeee-dddd-cccc-bbbbbbbbbbb0/v2.0", "Microsoft Entra ID"},
		{"https://token.actions.githubusercontent.com/acme-ent", "GitHub Actions (enterprise issuer path)"},
		{"https://eastus.oic.prod-aks.azure.com/ffffffff-eeee-dddd-cccc-bbbbbbbbbbb0/00000000-0000-0000-0000-000000000000", "Azure Kubernetes Service (AKS workload identity)"},
		{"https://acme.app.spacelift.io", "Spacelift"},
		{"https://api.bitbucket.org/2.0/workspaces/acme/pipelines-config/identity/oidc", "Bitbucket Pipelines"},
		{"https://container.googleapis.com/v1/projects/proj/locations/us-central1/clusters/c1", "Google Kubernetes Engine (GKE)"},
	}
	for _, c := range named {
		if f, names := Facts(c.issuer); names.Entry != c.name || f.IssuerKind == ring.NotSurveyed {
			t.Errorf("%q: matched to %q, surveyed %v; want %q", c.issuer, names.Entry, f.IssuerKind != ring.NotSurveyed, c.name)
		}
	}
	// a trailing slash spells the same issuer
	withSlash, _ := Facts("https://token.actions.githubusercontent.com/")
	if bare, _ := Facts(github); !reflect.DeepEqual(bare, withSlash) {
		t.Errorf("GitHub's issuer with a trailing slash reads other facts than without it:\n%+v\n%+v", withSlash, bare)
	}
	shared := func(anonymous ring.Established) ring.Facts {
		return ring.Facts{IssuerKind: ring.Shared, AnonymousTokens: anonymous}
	}
	cases := []struct {
		issuer trust.IssuerRef
		name   string
		want   ring.Facts
	}{
		{"https://app.terraform.io", "HCP Terraform (Terraform Cloud)", shared(ring.Unverified)},
		{"https://agent.buildkite.com", "Buildkite", shared(ring.Unverified)},
		{"https://oidc.circleci.com/org/2c3f7a0e-0000-4000-8000-000000000000", "CircleCI", ring.Facts{
			IssuerKind: ring.PerTenant, Namespace: ring.NamespaceIssuer, AnonymousTokens: ring.No,
			Tenant: ring.Tenant{Value: "2c3f7a0e-0000-4000-8000-000000000000", Kind: ring.KindID, Recyclable: ring.Unverified, Membership: ring.Controlled},
		}},
		// the issuer a tenant's URL names is not the issuer's host, and a
		// URL that names no tenant is nobody's surveyed issuer
		{"https://oidc.eks.us-east-1.amazonaws.com", "", ring.Facts{}},
		{"https://oidc.circleci.com", "", ring.Facts{}},
		{"https://login.microsoftonline.com/common/v2.0", "", ring.Facts{}},
		{"https://ci.example.com", "", ring.Facts{}},
		// the pseudo-issuers the AWS parser names are no census issuer's
		{"aws:sts", "", ring.Facts{}},
		{"aws:service:sns.amazonaws.com", "", ring.Facts{}},
		{"arn:aws:iam::123456789012:saml-provider/VendorSSO", "", ring.Facts{}},
		{"", "", ring.Facts{}},
	}
	for _, c := range cases {
		got, names := Facts(c.issuer)
		if names.Entry != c.name || !reflect.DeepEqual(got, c.want) {
			t.Errorf("%q:\n got %q %+v %+v\nwant %q %+v %+v", c.issuer, names.Entry, got, got.Tenancy, c.name, c.want, c.want.Tenancy)
		}
	}
}

// instance is an issuer the entry matches: its exact issuer, or its pattern
// with every placeholder filled, a GUID where the census records one.
func instance(e tenancy.Issuer) string {
	s := e.Issuer
	for n := 1; strings.Contains(s, "<"); n++ {
		open := strings.Index(s, "<")
		end := open + strings.Index(s[open:], ">")
		value := "p" + strconv.Itoa(n)
		if e.TenantSyntax == "guid" {
			value = "ffffffff-eeee-dddd-cccc-bbbbbbbbbbb" + strconv.Itoa(n%10)
		}
		s = s[:open] + value + s[end+1:]
	}
	return s
}

// TestFactsReadEveryEntryAsTheCensusDoes holds the mapping to the census's
// own readers, entry by entry: a fact the census answers one way is never
// read another, and every value it does not settle reads the cautious way.
// The census's readers are the oracle, so the mapping cannot drift from the
// release it is built against without this failing.
func TestFactsReadEveryEntryAsTheCensusDoes(t *testing.T) {
	established := func(value, known bool) ring.Established {
		switch {
		case !known:
			return ring.Unverified
		case value:
			return ring.Yes
		}
		return ring.No
	}
	probes := []rune("\x00 !-./09:@AZ_`az{~\u007f\u00e9\u0130\u212a\U0001f600")
	entries := tenancy.All()
	if len(entries) < 25 {
		t.Fatalf("%d census entries; the test would examine too little", len(entries))
	}
	var perTenantEntries, tenancyEntries, platforms, namespaces int
	for _, e := range entries {
		issuer := trust.IssuerRef(instance(e))
		got, names := Facts(issuer)
		matched, tenant, ok := tenancy.Match(instance(e))
		if !ok || matched.Name != e.Name {
			t.Fatalf("%s: the census does not match its own instance %q", e.Name, issuer)
		}
		if names != (Names{Entry: e.Name, Platform: e.Platform}) {
			t.Errorf("%s: named %+v", e.Name, names)
		}
		if names.Platform != "" {
			platforms++
		}
		if want := established(e.IssuesAnonymousTokens()); got.AnonymousTokens != want {
			t.Errorf("%s: anonymous tokens %v, want %v", e.Name, got.AnonymousTokens, want)
		}
		if got.Issuerless != 0 || got.PrincipalModelled {
			t.Errorf("%s: the census answered for the statement: %+v", e.Name, got)
		}
		if e.TenantPlaceholder != "" {
			perTenantEntries++
			controlled, known := e.ControlledTenant(tenant)
			membership := ring.MembershipUnverified
			if known {
				membership = map[bool]ring.Membership{true: ring.Controlled, false: ring.OpenToAnyone}[controlled]
			}
			kind := map[bool]ring.Kind{true: ring.KindID, false: ring.KindName}[e.TenantKind == "id"]
			want := ring.Tenant{Value: tenant, Kind: kind, Recyclable: established(e.TenantIsRecyclable()), Membership: membership}
			if got.IssuerKind != ring.PerTenant || got.Namespace != ring.NamespaceIssuer || got.Tenant != want || got.Tenancy != nil {
				t.Errorf("%s: %+v, want a per-tenant issuer declared by URL with %+v", e.Name, got, want)
			}
			continue
		}
		if got.IssuerKind != ring.Shared || got.Tenant != (ring.Tenant{}) {
			t.Errorf("%s: %+v, want a shared issuer", e.Name, got)
		}
		if string(got.Namespace) != e.DeclarationNamespace {
			t.Errorf("%s: declared in %q, the census says %q", e.Name, got.Namespace, e.DeclarationNamespace)
		}
		if got.Namespace != "" {
			namespaces++
		}
		if len(e.TenancyClaims) == 0 || len(e.SubjectForms) == 0 {
			if got.Tenancy != nil {
				t.Errorf("%s: tenancy read from a census that records half of it: %+v", e.Name, got.Tenancy)
			}
			continue
		}
		tenancyEntries++
		if got.Tenancy == nil || len(got.Tenancy.Claims) != len(e.TenancyClaims) || len(got.Tenancy.SubjectForms) != len(e.SubjectForms) {
			t.Fatalf("%s: tenancy %+v", e.Name, got.Tenancy)
		}
		for i, c := range e.TenancyClaims {
			if g := got.Tenancy.Claims[i]; string(g.Claim) != c.Claim || g.Scope.String() != c.Scope || g.Kind.String() != c.Kind || g.Recyclable != established(c.ValueIsRecyclable()) {
				t.Errorf("%s: claim %d read as %+v from %+v", e.Name, i, g, c)
			}
		}
		for i, f := range e.SubjectForms {
			g := got.Tenancy.SubjectForms[i]
			parts, scope := f.OwnerParts, "owner"
			if len(parts) == 0 {
				parts, scope = f.RepositoryParts, "repository"
			}
			if g.Lead != f.LeadingLiteral || g.Scope.String() != scope || len(g.Parts) != len(parts) {
				t.Errorf("%s: form %d read as %+v from %+v", e.Name, i, g, f)
				continue
			}
			for j, p := range parts {
				if g.Parts[j].Kind.String() != p.Kind || g.Parts[j].Delimiter != p.DelimiterAfter {
					t.Errorf("%s: form %d part %d read as %+v from %+v", e.Name, i, j, g.Parts[j], p)
				}
			}
		}
		for _, r := range probes {
			in := len(got.Tenancy.OwnerCharacters) == 0 || slices.ContainsFunc(got.Tenancy.OwnerCharacters, func(cr ring.CharRange) bool { return cr.First <= r && r <= cr.Last })
			if in != e.OwnerNameMayContain(r) {
				t.Errorf("%s: %q allowed in an owner name: %v, the census says %v", e.Name, r, in, e.OwnerNameMayContain(r))
			}
		}
		if !slices.Equal(got.Tenancy.NeverPin, e.NeverPin) || !slices.Equal(claimKeys(e.NotTenancy), got.Tenancy.NotTenancy) {
			t.Errorf("%s: never pins %q and names no tenant %q, the census says %q and %q", e.Name, got.Tenancy.NeverPin, got.Tenancy.NotTenancy, e.NeverPin, e.NotTenancy)
		}
		if withoutCase, known := e.NamesCompareWithoutCase(); got.Tenancy.NamesIgnoreCase != (withoutCase && known) {
			t.Errorf("%s: names ignore case %v", e.Name, got.Tenancy.NamesIgnoreCase)
		}
	}
	if perTenantEntries == 0 || tenancyEntries == 0 || platforms == 0 || namespaces == 0 {
		t.Fatalf("%d per-tenant entries, %d with tenancy facts, %d naming a platform and %d declared by name examined; the mapping went untested", perTenantEntries, tenancyEntries, platforms, namespaces)
	}
	t.Logf("%d entries, %d per tenant, %d with tenancy facts, %d naming a platform, %d declared by name", len(entries), perTenantEntries, tenancyEntries, platforms, namespaces)
}

// TestWhatNeverPinsReachesTheClassifier: the literals whose subjects name
// no tenant of the token's, and the claims that look like tenants and name
// none, reach the classifier from the census. The census builds neither to
// overlap what pins, so no answer moves on today's data; a literal that
// extends a form's lead, or a name ending in * that covers a tenancy claim,
// is what a later census could write, and what it covers must not pin.
func TestWhatNeverPinsReachesTheClassifier(t *testing.T) {
	e := tenancy.Issuer{
		TenancyClaims:       []tenancy.Claim{{Claim: "owner", Kind: "name", Scope: "owner"}, {Claim: "owner_id", Kind: "id", Scope: "owner"}},
		SubjectForms:        []tenancy.SubjectForm{{LeadingLiteral: "x:", OwnerParts: []tenancy.Part{{Kind: "name", DelimiterAfter: "/"}}}},
		NeverPin:            []string{"x:shared/"},
		NotTenancy:          []string{"owner_*"},
		OwnerNameCharacters: []string{"a-z", "0-9"},
	}
	facts := ring.Facts{IssuerKind: ring.Shared, AnonymousTokens: ring.No, PrincipalModelled: true, Tenancy: tenancyOf(e)}
	const issuer = trust.IssuerRef("https://x.example.com")
	cases := []struct {
		term eval.Term
		want ring.Place
	}{
		{eval.Term{"sub": eval.Exact("x:acme/infra")}, ring.Outsider},
		{eval.Term{"sub": eval.Exact("x:shared/infra")}, ring.Platform},
		{eval.Term{"owner": eval.Exact("acme")}, ring.Outsider},
		{eval.Term{"owner_id": eval.Exact("42")}, ring.Platform},
	}
	for _, c := range cases {
		g := trust.Grant{Issuer: issuer, Effect: trust.Allow, Admits: eval.NewAdmittedSet(c.term)}
		if p := ring.Classify(g, facts, nil); !slices.Equal(p.Places, []ring.Place{c.want}) || p.State != ring.StateExact {
			t.Errorf("%v: placed %s, want %s exact", c.term, p, c.want)
		}
	}
}

// TestTheNamespaceIsTheCensus: which issuer's owners are declared by name,
// and under which prefix, is the census's to say, so that a release of it
// can move or add one with no change here. A namespace whose grammar the
// engine does not read, or one it keeps for its own declarations, declares
// nobody by name.
func TestTheNamespaceIsTheCensus(t *testing.T) {
	shared := func(issuer, namespace string) tenancy.Issuer {
		return tenancy.Issuer{Issuer: issuer, AnonymousTokens: "no", DeclarationNamespace: namespace}
	}
	cases := []struct {
		name  string
		entry tenancy.Issuer
		want  ring.Namespace
	}{
		{"GitHub's issuer, declared in github", shared(string(github), "github"), ring.NamespaceGitHub},
		{"another issuer the census declares in github", shared("https://ghe.example.com/_services/token", "github"), ring.NamespaceGitHub},
		{"GitHub's issuer with no namespace recorded", shared(string(github), ""), ""},
		{"a namespace the engine reads no grammar for", shared("https://ci.example.com", "gitlab"), ""},
		{"the namespace of AWS accounts", shared("https://ci.example.com", "aws"), ""},
		{"the namespace of SAML providers", shared("https://ci.example.com", "saml"), ""},
		{"the namespace of issuer URLs", shared("https://ci.example.com", "issuer"), ""},
	}
	for _, c := range cases {
		if got := factsOf(c.entry, "").Namespace; got != c.want {
			t.Errorf("%s: declared in %q, want %q", c.name, got, c.want)
		}
	}
}

// TestTheKeysAWSDocuments: the condition keys AWS documents for GitHub's
// tokens are the census's, and internal/ring holds its stand-in's list to
// them. AWS's GitHub tab has no repository_owner, enterprise or
// workflow_ref key, and the vendor's own hardening, the owner's and the
// repository's ids, is documented. A key compares without ASCII case, and
// an issuer whose keys the census does not record, or has not surveyed,
// has no key known to be documented. GitHub's enterprise path is one: AWS
// names a condition key by the provider, and no AWS sentence names a
// provider at a path under GitHub's issuer, so the census writes the
// path's keys unverified.
func TestTheKeysAWSDocuments(t *testing.T) {
	cases := []struct {
		issuer            trust.IssuerRef
		key               string
		documented, known bool
	}{
		{github, "sub", true, true},
		{github, "aud", true, true},
		{github, "Repository_Owner_ID", true, true},
		{github, "repository_id", true, true},
		{github, "enterprise_id", true, true},
		{github, "repository_owner", false, true},
		{github, "enterprise", false, true},
		{github, "workflow_ref", false, true},
		{"https://token.actions.githubusercontent.com/acme-ent", "repository_owner_id", false, false},
		{"https://token.actions.githubusercontent.com/acme-ent", "sub", false, false},
		{"https://gitlab.com", "sub", false, false},
		{"https://ci.example.com", "sub", false, false},
		{"https://to" + kelvinSign + "en.actions.githubusercontent.com", "sub", false, false},
	}
	for _, c := range cases {
		if documented, known := AWSDocumentsConditionKey(c.issuer, c.key); documented != c.documented || known != c.known {
			t.Errorf("%s, %s: (%v, %v), want (%v, %v)", c.issuer, c.key, documented, known, c.documented, c.known)
		}
	}
}

// TestWhichKeysAWSDocumentsAsMultivalued: AWS says of amr, on its Default
// tab and on Amazon Cognito's, "The key is multivalued, meaning that you
// test it in a policy using condition set operators", and the census records
// that sentence for the ten issuers whose keys include amr, each on the tab
// that reads its tokens. It records it for no other key, and a key it holds
// no such sentence for is not read as documented multivalued: GitHub's sub
// and aud, Cognito's aud, CircleCI's one key and an amr it does not have, an
// issuer whose keys the census does not record, and one it has not surveyed.
func TestWhichKeysAWSDocumentsAsMultivalued(t *testing.T) {
	cases := []struct {
		issuer      trust.IssuerRef
		key         string
		multivalued bool
	}{
		{github, "amr", true},
		{github, "AMR", true},
		{"https://cognito-identity.amazonaws.com", "amr", true},
		{"https://accounts.google.com", "Amr", true},
		{"https://login.microsoftonline.com/ffffffff-eeee-dddd-cccc-bbbbbbbbbbb0/v2.0", "amr", true},
		{"https://oidc.eks.us-east-1.amazonaws.com/id/EXAMPLED539D4633E53DE1B71EXAMPLE", "amr", true},
		{"https://eastus.oic.prod-aks.azure.com/ffffffff-eeee-dddd-cccc-bbbbbbbbbbb0/00000000-0000-0000-0000-000000000000/", "amr", true},
		{"https://container.googleapis.com/v1/projects/proj/locations/us-central1/clusters/c1", "amr", true},
		{"https://acme.app.spacelift.io", "amr", true},
		{"https://api.bitbucket.org/2.0/workspaces/acme/pipelines-config/identity/oidc", "amr", true},
		{"https://12345678-90ab-cdef-1234-567890abcdef.tokens.sts.global.api.aws", "amr", true},
		{github, "sub", false},
		{github, "aud", false},
		{github, "repository_owner", false},
		{"https://cognito-identity.amazonaws.com", "aud", false},
		{"https://oidc.circleci.com/org/0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0", "amr", false},
		{"https://oidc.circleci.com/org/0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0", "oidc.circleci.com/project-id", false},
		{"https://gitlab.com", "amr", false},
		{"https://ci.example.com", "amr", false},
	}
	for _, c := range cases {
		if got := AWSDocumentsMultivalued(c.issuer, c.key); got != c.multivalued {
			t.Errorf("%s, %s: %v, want %v", c.issuer, c.key, got, c.multivalued)
		}
	}
}

// TestWhichKeysReadAClaimOfSeveralValues: the census records that the tokens
// of an EKS, AKS or GKE cluster, of AWS's outbound federation and of a
// Bitbucket workspace may carry several audiences, each on its vendor's
// sentences. AWS reads their aud key from azp, or from aud when the token
// sets no azp, and their oaud key from aud, so both keys read a claim of
// several values, in any ASCII case. No other key of theirs does, and no key
// of an issuer whose tokens the census records no such sentence for:
// GitHub's, Cognito's, Google's, Entra's and Spacelift's aud, an issuer
// whose keys are not recorded, one not surveyed, and a look-alike host.
func TestWhichKeysReadAClaimOfSeveralValues(t *testing.T) {
	const cluster = "https://oidc.eks.us-east-1.amazonaws.com/id/EXAMPLED539D4633E53DE1B71EXAMPLE"
	cases := []struct {
		issuer  trust.IssuerRef
		key     string
		several bool
	}{
		{cluster, "aud", true},
		{cluster, "AUD", true},
		{cluster, "oaud", true},
		{"https://eastus.oic.prod-aks.azure.com/ffffffff-eeee-dddd-cccc-bbbbbbbbbbb0/00000000-0000-0000-0000-000000000000/", "aud", true},
		{"https://container.googleapis.com/v1/projects/proj/locations/us-central1/clusters/c1", "Oaud", true},
		{"https://12345678-90ab-cdef-1234-567890abcdef.tokens.sts.global.api.aws", "aud", true},
		{"https://api.bitbucket.org/2.0/workspaces/acme/pipelines-config/identity/oidc", "oaud", true},
		{cluster, "sub", false},
		{cluster, "amr", false},
		{cluster, "email", false},
		{cluster, "azp", false},
		{github, "aud", false},
		{github, "oaud", false},
		{"https://cognito-identity.amazonaws.com", "aud", false},
		{"https://accounts.google.com", "aud", false},
		{"https://login.microsoftonline.com/ffffffff-eeee-dddd-cccc-bbbbbbbbbbb0/v2.0", "aud", false},
		{"https://acme.app.spacelift.io", "aud", false},
		{"https://gitlab.com", "aud", false},
		{"https://ci.example.com", "aud", false},
		{"https://oidc.eKs.us-east-1.amazonaws.com/id/EXAMPLED539D4633E53DE1B71EXAMPLE", "aud", false},
	}
	for _, c := range cases {
		if got := AWSReadsAMultiValuedClaim(c.issuer, c.key); got != c.several {
			t.Errorf("%s, %s: %v, want %v", c.issuer, c.key, got, c.several)
		}
	}
}

// TestWhereAWSReadsAKey: the claim AWS reads each key from is the census's,
// with the one it reads when the token sets none of that, and AWS's table's
// spelling of it. A phrase is kept as the claim, and a reader tells it from
// a claim name. A spelling no vendor sentence ties to a claim, as AWS's
// google:organization_number beside Google's nested google claim, is no
// claim, and only the spelling is handed out.
func TestWhereAWSReadsAKey(t *testing.T) {
	cases := []struct {
		issuer trust.IssuerRef
		key    string
		want   KeyClaim
		ok     bool
	}{
		{github, "aud", KeyClaim{Claim: "azp", Fallback: "aud", Table: "azp"}, true},
		{github, "OAUD", KeyClaim{Claim: "aud", Table: "aud"}, true},
		{"https://accounts.google.com", "google/organization_number", KeyClaim{Table: "google:organization_number"}, true},
		{"https://www.amazon.com", "user_id", KeyClaim{Claim: "User ID", Table: "User ID"}, true},
		{github, "repository_owner", KeyClaim{}, false},
		{"https://gitlab.com", "sub", KeyClaim{}, false},
	}
	for _, c := range cases {
		if got, ok := AWSConditionKeyClaim(c.issuer, c.key); got != c.want || ok != c.ok {
			t.Errorf("%s, %s: %+v, %v; want %+v, %v", c.issuer, c.key, got, ok, c.want, c.ok)
		}
	}
}

// TestKeyLookupsAboutOneIssuerMatchTheCensusOnce: a document asks the four
// key lookups about its issuer for every condition key of every statement,
// and the census's Match walks every entry's pattern and copies the entry it
// finds each time it is asked. Asked again about the issuer they were last
// asked about, the lookups read the entry they already hold, and so allocate
// nothing, which neither the walk nor the copy can do. It holds for an exact
// issuer, for a per-tenant one and for one nobody surveyed.
func TestKeyLookupsAboutOneIssuerMatchTheCensusOnce(t *testing.T) {
	for _, issuer := range []trust.IssuerRef{
		github,
		"https://oidc.eks.us-east-1.amazonaws.com/id/EXAMPLED539D4633E53DE1B71EXAMPLE",
		"https://ci.example.com",
	} {
		AWSDocumentsConditionKey(issuer, "sub")
		allocations := testing.AllocsPerRun(100, func() {
			AWSDocumentsConditionKey(issuer, "sub")
			AWSDocumentsMultivalued(issuer, "amr")
			AWSReadsAMultiValuedClaim(issuer, "aud")
			AWSConditionKeyClaim(issuer, "repository_id")
		})
		if allocations != 0 {
			t.Errorf("%s: four lookups about the issuer asked about last made %v allocations; the census was matched again", issuer, allocations)
		}
	}
}

// TestATenancyClaimIsReadThroughTheKeyOfItsName: the classifier reads a
// condition on a key as a constraint on the claim of the key's name, which
// holds only while AWS reads the key from that claim alone. Census v0.2.0 records
// no tenancy claim, nor sub, whose key AWS reads from another claim, and
// its build refuses one; a later census might. A tenancy claim whose key
// AWS reads from another claim, or from another when the token sets none,
// names no tenant, and a sub whose key AWS reads so leaves the tenancy not
// recorded, which is the reading that can only keep a grant outward.
func TestATenancyClaimIsReadThroughTheKeyOfItsName(t *testing.T) {
	form := tenancy.SubjectForm{LeadingLiteral: "x:", OwnerParts: []tenancy.Part{{Kind: "name", DelimiterAfter: "/"}}}
	claims := []tenancy.Claim{
		{Claim: "owner", Kind: "name", Scope: "owner"},
		{Claim: "owner_id", Kind: "id", Scope: "owner"},
		{Claim: "repository", Kind: "name", Scope: "repository"},
		{Claim: "undocumented", Kind: "name", Scope: "owner"},
	}
	keys := []tenancy.ConditionKey{
		{Key: "sub", Claim: "sub"},
		{Key: "owner", Claim: "owner"},
		{Key: "owner_id", Claim: "account_id"},
		{Key: "repository", Claim: "repository", FallbackClaim: "project"},
	}
	e := tenancy.Issuer{TenancyClaims: claims, SubjectForms: []tenancy.SubjectForm{form}, AWSConditionKeys: keys, OwnerNameCharacters: []string{"a-z"}}
	got := tenancyOf(e)
	if got == nil {
		t.Fatal("the tenancy was not read")
	}
	want := []ring.Scope{ring.ScopeOwner, ring.ScopeNone, ring.ScopeNone, ring.ScopeOwner}
	for i, c := range got.Claims {
		if c.Scope != want[i] {
			t.Errorf("%s: scope %v, want %v", c.Claim, c.Scope, want[i])
		}
	}
	e.AWSConditionKeys = append(keys[1:], tenancy.ConditionKey{Key: "sub", Claim: "subject"})
	if got := tenancyOf(e); got != nil {
		t.Errorf("a sub AWS reads from another claim: tenancy read as %+v", got)
	}
}

// TestASubjectPartReadsTheCensus: an owner a subject names is the value of
// the tenancy claim of its form's scope and its part's kind, and the
// classifier reads its recyclability from that claim's census fact, as it
// reads an owner a claim names. Every form the census records for GitHub is
// read through its deepest part, and the owner it names is recyclable
// exactly as the census says that claim's value is.
func TestASubjectPartReadsTheCensus(t *testing.T) {
	e, _, ok := tenancy.Match(string(github))
	facts, _ := Facts(github)
	if !ok || facts.Tenancy == nil {
		t.Fatalf("the census records no tenancy for %s", github)
	}
	// whether the parser modelled the principal is the statement's to say
	facts.PrincipalModelled = true
	checked := 0
	for _, f := range e.SubjectForms {
		scope, parts := "owner", f.OwnerParts
		if len(parts) == 0 {
			scope, parts = "repository", f.RepositoryParts
		}
		subject := f.LeadingLiteral
		for _, p := range parts {
			value := "acme"
			if p.Kind == "id" {
				value = "123456"
			}
			subject += value + p.DelimiterAfter
		}
		deepest := parts[len(parts)-1]
		want, claims := true, 0
		for _, c := range e.TenancyClaims {
			if c.Scope == scope && c.Kind == deepest.Kind {
				want, _ = c.ValueIsRecyclable()
				claims++
			}
		}
		if claims != 1 {
			want = true
		}
		g := trust.Grant{Issuer: github, Effect: trust.Allow, Admits: eval.NewAdmittedSet(eval.Term{"sub": eval.Glob(subject + "*")})}
		p := ring.Classify(g, facts, nil)
		if len(p.Populations) != 1 || len(p.Populations[0].Owners) != 1 {
			t.Errorf("%s*: placed %s", subject, p)
			continue
		}
		if got := p.Populations[0].Owners[0]; got.Recyclable != want {
			t.Errorf("%s*: %s recyclable %v; the census's %s %s claim says %v", subject, got, got.Recyclable, scope, deepest.Kind, want)
		}
		checked++
	}
	if checked == 0 {
		t.Fatal("no subject form was read")
	}
	t.Logf("%d subject forms read", checked)
}

// TestAValueTheClassifierDoesNotKnowNamesNobody: census v0.2.0 writes no such
// value, and a later census might. A scope, a kind or a character set the
// mapping cannot read, a form with no parts, and tenancy the census records
// only half of each leave the claim, the form or the issuer naming no
// tenant, which is the reading that can only keep a grant outward.
func TestAValueTheClassifierDoesNotKnowNamesNobody(t *testing.T) {
	part := func(kind, delimiter string) tenancy.Part { return tenancy.Part{Kind: kind, DelimiterAfter: delimiter} }
	form := func(parts ...tenancy.Part) tenancy.SubjectForm {
		return tenancy.SubjectForm{LeadingLiteral: "x:", OwnerParts: parts}
	}
	claims := []tenancy.Claim{
		{Claim: "owner", Kind: "name", Scope: "owner"},
		{Claim: "actor", Kind: "name", Scope: "actor"},
		{Claim: "handle", Kind: "handle", Scope: "owner"},
	}
	e := tenancy.Issuer{TenancyClaims: claims, SubjectForms: []tenancy.SubjectForm{form(part("name", "/"))}, OwnerNameCharacters: []string{"a-z"}}
	got := tenancyOf(e)
	if got == nil || got.Claims[0].Scope != ring.ScopeOwner || got.Claims[1].Scope != ring.ScopeNone || got.Claims[2].Scope != ring.ScopeNone {
		t.Errorf("claims of an unknown scope or kind: %+v", got)
	}
	for name, half := range map[string]tenancy.Issuer{
		"claims alone": {TenancyClaims: claims},
		"forms alone":  {SubjectForms: e.SubjectForms},
		"neither":      {},
	} {
		if got := tenancyOf(half); got != nil {
			t.Errorf("%s: tenancy read from %+v", name, got)
		}
	}
	forms := []struct {
		name string
		form tenancy.SubjectForm
		want ring.SubjectForm
	}{
		{"an owner", form(part("name", "/")), ring.SubjectForm{Lead: "x:", Scope: ring.ScopeOwner, Parts: []ring.Part{{Kind: ring.KindName, Delimiter: "/"}}}},
		{"a repository", tenancy.SubjectForm{LeadingLiteral: "x:", RepositoryParts: []tenancy.Part{part("id", ":")}}, ring.SubjectForm{Lead: "x:", Scope: ring.ScopeRepository, Parts: []ring.Part{{Kind: ring.KindID, Delimiter: ":"}}}},
		{"both, read by the owner", tenancy.SubjectForm{LeadingLiteral: "x:", OwnerParts: []tenancy.Part{part("name", "/")}, RepositoryParts: []tenancy.Part{part("name", ":")}}, ring.SubjectForm{Lead: "x:", Scope: ring.ScopeOwner, Parts: []ring.Part{{Kind: ring.KindName, Delimiter: "/"}}}},
		{"no parts", tenancy.SubjectForm{LeadingLiteral: "x:"}, ring.SubjectForm{Lead: "x:"}},
		{"a part of an unknown kind", form(part("name", "@"), part("slug", "/")), ring.SubjectForm{Lead: "x:", Parts: []ring.Part{{Kind: ring.KindName, Delimiter: "@"}, {Kind: ring.KindName, Delimiter: "/"}}}},
	}
	for _, c := range forms {
		if got := subjectForm(c.form); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: %+v, want %+v", c.name, got, c.want)
		}
	}
	sets := []struct {
		set  []string
		want []ring.CharRange
	}{
		{[]string{"a-z", "_"}, []ring.CharRange{{First: 'a', Last: 'z'}, {First: '_', Last: '_'}}},
		{nil, nil},
		{[]string{"a-z", "é"}, nil},
		{[]string{"z-a"}, nil},
		{[]string{"a-z-"}, nil},
		{[]string{"a+z"}, nil},
	}
	for _, c := range sets {
		if got := characters(c.set); !reflect.DeepEqual(got, c.want) {
			t.Errorf("characters %q: %+v, want %+v", c.set, got, c.want)
		}
	}
}
