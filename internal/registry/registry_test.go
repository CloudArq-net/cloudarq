package registry

import (
	"slices"
	"testing"

	"github.com/CloudArq-net/cloudarq/internal/trust"
)

const github = trust.IssuerRef("https://token.actions.githubusercontent.com")

// The census at v0.1.0, pinned in go.mod: the two lists below change only
// when the census does, and then the requirement and these lists move in
// the same commit, which is the cost of the import made visible.
var (
	exactIssuers = []trust.IssuerRef{
		"https://accounts.google.com", "https://agent.buildkite.com", "https://api.cursor.com",
		"https://api.pulumi.com/oidc", "https://api2.cursor.sh/cloud-agent/identity", "https://app.devin.ai",
		"https://app.terraform.io", "https://app.warp.dev", "https://codeberg.org",
		"https://federation.namespaceapis.com", "https://gitlab.com", "https://identity.depot.dev",
		"https://issuer.enforce.dev", "https://login.app.env0.com", "https://oidc.codefresh.io",
		"https://oidc.modal.com", "https://scalr.io", github, "https://vstoken.dev.azure.com",
	}
	multiTenantHosts = []string{
		"accounts.google.com", "agent.buildkite.com", "api.bitbucket.org", "api.cursor.com", "api.pulumi.com",
		"api2.cursor.sh", "app.devin.ai", "app.harness.io", "app.terraform.io", "app.warp.dev", "codeberg.org",
		"container.googleapis.com", "federation.namespaceapis.com", "gitlab.com", "identity.depot.dev",
		"issuer.enforce.dev", "login.app.env0.com", "login.microsoftonline.com", "oidc.circleci.com",
		"oidc.codefresh.io", "oidc.modal.com", "scalr.io", "token.actions.githubusercontent.com", "vstoken.dev.azure.com",
	}
)

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
// and the notes the census writes in the issuer field ("unverified" on one
// Harness entry) are not hosts, although the module keys them like hosts.
func TestLookupUnsurveyed(t *testing.T) {
	for _, spelling := range []string{"https://oidc.example.test", "", "https://", "unverified", "https://unverified"} {
		if e, ok := Lookup(trust.IssuerRef(spelling)); ok {
			t.Fatalf("%q: found %+v", spelling, e)
		}
	}
}

// TestLookupPerTenantPattern: a per-tenant entry is reachable only by its
// placeholder host, and a real tenant's host is not surveyed as far as the
// seam can tell; the doc comment on Lookup says so, and this pins it.
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
// (nobody surveyed the token), Codeberg's says the survey found no
// immutable identifier; the engine keeps nil apart from empty.
func TestAbsentIsNotEmpty(t *testing.T) {
	depot, ok := Lookup("https://identity.depot.dev")
	if !ok || depot.Claims != nil || depot.ImmutableIDClaims != nil {
		t.Fatalf("depot: ok %v claims %#v immutable %#v; want nil for unsurveyed", ok, depot.Claims, depot.ImmutableIDClaims)
	}
	codeberg, ok := Lookup("https://codeberg.org")
	if !ok || codeberg.Claims == nil || codeberg.ImmutableIDClaims == nil || len(codeberg.ImmutableIDClaims) != 0 {
		t.Fatalf("codeberg: ok %v claims %#v immutable %#v; want empty, not nil", ok, codeberg.Claims, codeberg.ImmutableIDClaims)
	}
}

// TestAudienceIsBoundary: GitHub lets the workload pick the audience, so aud
// is not a boundary and that is known; an entry the census marks unverified
// answers known == false, which is never read as a boundary.
func TestAudienceIsBoundary(t *testing.T) {
	if isBoundary, known := AudienceIsBoundary(github); isBoundary || !known {
		t.Fatalf("github: boundary %v known %v", isBoundary, known)
	}
	if isBoundary, known := AudienceIsBoundary("https://codeberg.org"); isBoundary || known {
		t.Fatalf("codeberg (unverified): boundary %v known %v", isBoundary, known)
	}
	for _, ref := range []trust.IssuerRef{"https://oidc.example.test", ""} {
		if isBoundary, known := AudienceIsBoundary(ref); isBoundary || known {
			t.Fatalf("%q: boundary %v known %v", ref, isBoundary, known)
		}
	}
}

// TestSubjectsAreRecyclable: GitHub carries immutable id claims, so its
// subjects need not be recyclable names; Codeberg's survey found none, so
// they are; Depot's were never surveyed, so the answer is cautious and not
// known; an unsurveyed issuer is the same.
func TestSubjectsAreRecyclable(t *testing.T) {
	if recyclable, known := SubjectsAreRecyclable(github); recyclable || !known {
		t.Fatalf("github: recyclable %v known %v", recyclable, known)
	}
	if recyclable, known := SubjectsAreRecyclable("https://codeberg.org"); !recyclable || !known {
		t.Fatalf("codeberg: recyclable %v known %v", recyclable, known)
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
}
