package ring

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"pgregory.net/rapid"

	"github.com/CloudArq-net/cloudarq/internal/eval"
	"github.com/CloudArq-net/cloudarq/internal/parse/aws"
	"github.com/CloudArq-net/cloudarq/internal/trust"
)

// declare reads a declaration the test states, failing on any refusal.
func declare(t testing.TB, text string) []Declaration {
	t.Helper()
	d := ReadDeclarations(text)
	if d.Overrun != nil || len(d.Refused) != 0 {
		t.Fatalf("declaration %q: %+v %v", text, d.Overrun, d.Refused)
	}
	return d.Owners
}

func ownersText(owners []Owner) string {
	parts := make([]string, len(owners))
	for i, o := range owners {
		parts[i] = o.String()
	}
	return strings.Join(parts, "; ")
}

func like(pattern string) eval.StringSet { return eval.Glob(pattern) }

func either(sets ...eval.StringSet) eval.StringSet {
	out := sets[0]
	for _, s := range sets[1:] {
		out = out.Join(s)
	}
	return out
}

func both(sets ...eval.StringSet) eval.StringSet {
	out := sets[0]
	for _, s := range sets[1:] {
		out = out.Meet(s)
	}
	return out
}

// TestSubjectPins holds the pin rule to every form GitHub documents: a
// subject pins through the deepest owner part its literal prefix runs
// through, delimiter included, and pins nothing when the prefix stops
// short, a wildcard stands before the owner, the owner is empty or holds a
// character GitHub's names cannot, the subject is led by a literal that
// never pins or by one the census does not record, or any alternative of a
// union does not pin.
func TestSubjectPins(t *testing.T) {
	cases := []struct {
		name string
		sub  eval.StringSet
		want []Owner
	}{
		{"a branch of one repository", eval.Exact("repo:acme/infra:ref:refs/heads/main"), []Owner{githubName("acme")}},
		{"every repository of an owner", like("repo:acme/*"), []Owner{githubName("acme")}},
		{"a prefix that stops before the delimiter", like("repo:acme*"), nil},
		{"a wildcard between the owner and its delimiter", like("repo:acme*/*"), nil},
		{"the name closed and any id", like("repo:acme@*/*"), []Owner{githubName("acme")}},
		{"the name and the id", like("repo:acme@123456/*"), []Owner{githubID("123456", "acme")}},
		{"an id not closed", like("repo:acme@123*"), []Owner{githubName("acme")}},
		{"an id after a wildcard", like("repo:*@123456/*"), nil},
		{"a question mark in the owner", like("repo:acm?/*"), nil},
		{"a question mark closing the owner", like("repo:acme?*"), nil},
		{"the immutable form, exactly", eval.Exact("repo:acme@123456/infra@456789:ref:refs/heads/main"), []Owner{githubID("123456", "acme")}},
		{"led by the owner, exactly", eval.Exact("repository_owner:acme"), []Owner{githubName("acme")}},
		{"led by the owner", like("repository_owner:acme:*"), []Owner{githubName("acme")}},
		{"led by the owner id, exactly", eval.Exact("repository_owner_id:123456"), []Owner{githubID("123456", "")}},
		{"led by the owner id", like("repository_owner_id:123456:*"), []Owner{githubID("123456", "")}},
		{"an owner id not closed", like("repository_owner_id:123*"), nil},
		{"led by the repository id", like("repository_id:456789:*"), []Owner{githubRepositoryID("456789")}},
		{"a called workflow", like("job_workflow_ref:acme/deploy/.github/workflows/deploy.yml@*"), nil},
		{"a called workflow, exactly", eval.Exact("job_workflow_ref:acme/deploy/.github/workflows/deploy.yml@refs/heads/main"), nil},
		{"a custom property", like("repo_property_workspace_id:ws-*"), nil},
		{"a prefix a never-pin literal extends", like("repo_prop*"), nil},
		{"an empty owner", like("repo:/*"), nil},
		{"an empty owner, exactly", eval.Exact("repo:/infra:ref:refs/heads/main"), nil},
		{"a character GitHub's names cannot hold", like("repo:ac.me/*"), nil},
		{"a replacement character", like("repo:ac\ufffdme/*"), nil},
		{"a byte that is not UTF-8", eval.Exact("repo:ac\xffme/x"), nil},
		{"a subject that ends after the owner", eval.Exact("repo:acme"), []Owner{githubName("acme")}},
		{"an empty id after a closed name", like("repo:acme@/*"), []Owner{githubName("acme")}},
		{"a prefix inside the leading literal", like("rep*"), nil},
		{"a prefix that is the leading literal", like("repo:*"), nil},
		{"a literal the census does not record", eval.Exact("foo:acme/x"), nil},
		{"an owner key that does not lead", eval.Exact("environment:production%3Aeastus:repository_owner:octo-org"), nil},
		{"a recorded literal after another key", eval.Exact("user:acme/infra:repo:acme/infra"), nil},
		{"a character after the owner that is not its delimiter", eval.Exact("repository_owner:acme/x"), nil},
		{"a pattern no recorded form can match", like("repository:acme/*"), nil},
		{"a union of two owners", either(like("repo:acme/*"), like("repo:beta/*")), []Owner{githubName("acme"), githubName("beta")}},
		{"a union with one open member", either(like("repo:acme/*"), like("repo:acme*")), nil},
		{"a union with a called workflow", either(eval.Exact("repo:acme/x:ref:refs/heads/main"), like("job_workflow_ref:acme/*")), nil},
		{"an intersection one member pins", both(like("repo:acme/*"), like("repo:*/infra:*")), []Owner{githubName("acme")}},
		{"an intersection no member pins", both(like("repo:*"), like("*:ref:refs/heads/main")), nil},
		{"an intersection of two owners", both(like("repo:acme/*"), like("repo:beta/*")), []Owner{githubName("acme"), githubName("beta")}},
	}
	for _, c := range cases {
		p := Classify(grantOf(githubIssuer, eval.Term{"sub": c.sub}), githubFacts(), nil)
		wantPlace, wantBasis := Outsider, Pinned
		if c.want == nil {
			wantPlace, wantBasis = Platform, Unpinned
		}
		if !slices.Equal(p.Places, []Place{wantPlace}) || p.State != StateExact || ownersText(p.Owners) != ownersText(c.want) || p.Populations[0].Basis != wantBasis {
			t.Errorf("%s: sub %s placed %s (%v), want %s exact %s [%s]", c.name, c.sub, p, p.Populations[0].Basis, wantPlace, wantBasis, ownersText(c.want))
		}
	}
}

// TestTenancyClaimPins: a claim the census records as naming a tenant pins
// through a finite set of exact values, the whole value being the tenant;
// a pattern, a value no owner can have, a claim with no scope and a claim
// also recorded as naming none, by its name or by a name ending in *, pin
// nothing.
func TestTenancyClaimPins(t *testing.T) {
	unscoped := githubFacts()
	unscoped.Tenancy.Claims = append(unscoped.Tenancy.Claims, TenancyClaim{Claim: "workspace", Kind: KindID})
	contradicted := githubFacts()
	contradicted.Tenancy.Claims = append(contradicted.Tenancy.Claims, TenancyClaim{Claim: "actor_id", Scope: ScopeOwner, Kind: KindID})
	contradicted.Tenancy.NotTenancy = []trust.ClaimKey{"actor_id"}
	covered := githubFacts()
	covered.Tenancy.Claims = append(covered.Tenancy.Claims, TenancyClaim{Claim: "repo_property_team", Scope: ScopeOwner, Kind: KindName})
	covered.Tenancy.NotTenancy = []trust.ClaimKey{"repo_property_*"}
	noCharacters := githubFacts()
	noCharacters.Tenancy.OwnerCharacters = nil
	// no sentence says an enterprise's id never passes on, so it is
	// recyclable although it is an id
	enterprise := func(v string, k Kind) Owner {
		return Owner{Issuer: githubIssuer, Namespace: NamespaceGitHub, Scope: ScopeEnterprise, Kind: k, Value: v, Recyclable: true}
	}
	cases := []struct {
		name  string
		facts Facts
		term  eval.Term
		want  []Owner
	}{
		{"an owner by name", githubFacts(), eval.Term{"repository_owner": eval.Exact("acme")}, []Owner{githubName("acme")}},
		{"an owner by id", githubFacts(), eval.Term{"repository_owner_id": eval.Exact("123456")}, []Owner{githubID("123456", "")}},
		{"two owners", githubFacts(), eval.Term{"repository_owner": either(eval.Exact("acme"), eval.Exact("beta"))}, []Owner{githubName("acme"), githubName("beta")}},
		{"one owner pinned twice", githubFacts(), eval.Term{"repository_owner": eval.Exact("acme"), "sub": like("repo:acme/*")}, []Owner{githubName("acme")}},
		{"a repository by name", githubFacts(), eval.Term{"repository": eval.Exact("acme/infra")}, []Owner{{Issuer: githubIssuer, Namespace: NamespaceGitHub, Scope: ScopeRepository, Kind: KindName, Value: "acme/infra", Recyclable: true}}},
		{"a repository by id", githubFacts(), eval.Term{"repository_id": eval.Exact("456789")}, []Owner{githubRepositoryID("456789")}},
		// Census v0.2.0 records the enterprise's name as not naming a tenant,
		// unverified: a claim the census does not list pins nothing
		{"an enterprise by name", githubFacts(), eval.Term{"enterprise": eval.Exact("acme-ent")}, nil},
		{"an enterprise by id", githubFacts(), eval.Term{"enterprise_id": eval.Exact("42")}, []Owner{enterprise("42", KindID)}},
		{"an owner pattern", githubFacts(), eval.Term{"repository_owner": like("acme*")}, nil},
		{"an owner and a pattern", githubFacts(), eval.Term{"repository_owner": either(eval.Exact("acme"), like("acme-*"))}, nil},
		{"an intersection of patterns", githubFacts(), eval.Term{"repository_owner": both(like("acme*"), like("*me"))}, nil},
		{"an empty owner", githubFacts(), eval.Term{"repository_owner": eval.Exact("")}, nil},
		{"an empty repository", githubFacts(), eval.Term{"repository": eval.Exact("")}, nil},
		{"a character GitHub's names cannot hold", githubFacts(), eval.Term{"repository_owner": eval.Exact("ac.me")}, nil},
		{"any character, when none is verified", noCharacters, eval.Term{"repository_owner": eval.Exact("ac.me")}, []Owner{githubName("ac.me")}},
		{"a claim with no scope", unscoped, eval.Term{"workspace": eval.Exact("ws-1")}, nil},
		{"a claim also recorded as naming none", contradicted, eval.Term{"actor_id": eval.Exact("583231")}, nil},
		{"a claim every name beginning so is recorded as naming none", covered, eval.Term{"repo_property_team": eval.Exact("acme")}, nil},
		{"the person who started the run", githubFacts(), eval.Term{"actor_id": eval.Exact("583231")}, nil},
		{"a claim the census does not list", githubFacts(), eval.Term{"repository_visibility": eval.Exact("private")}, nil},
	}
	for _, c := range cases {
		p := Classify(grantOf(githubIssuer, c.term), c.facts, nil)
		want := Placement{Outcome: Placed, Places: []Place{Platform}, State: StateExact}
		if c.want != nil {
			want = Placement{Outcome: Placed, Places: []Place{Outsider}, State: StateExact, Owners: c.want}
		}
		if p.String() != want.String() {
			t.Errorf("%s: %v placed\n got  %s\n want %s", c.name, eval.NewAdmittedSet(c.term), p, want)
		}
	}
}

// TestASubjectPartIsRecyclableAsItsClaimIs: an owner a subject names is the
// value of the tenancy claim of its form's scope and its part's kind, as
// GitHub's repository_owner_id:123456: is repository_owner_id's, and it can
// pass to someone else unless the census records that the claim's value
// cannot, as an owner a claim names reads. A part that no claim of that
// scope and kind records, or that two do, is recyclable: which claim it is
// was not established.
func TestASubjectPartIsRecyclableAsItsClaimIs(t *testing.T) {
	recording := func(claim trust.ClaimKey, recyclable Established) Facts {
		f := githubFacts()
		for i, c := range f.Tenancy.Claims {
			if c.Claim == claim {
				f.Tenancy.Claims[i].Recyclable = recyclable
			}
		}
		return f
	}
	twoOwnerIDs := githubFacts()
	twoOwnerIDs.Tenancy.Claims = append(twoOwnerIDs.Tenancy.Claims, TenancyClaim{Claim: "owner_account_id", Scope: ScopeOwner, Kind: KindID, Recyclable: No})
	cases := []struct {
		name  string
		facts Facts
		sub   string
		want  bool
	}{
		{"an owner id the census calls immutable", githubFacts(), "repository_owner_id:123456:*", false},
		{"an owner id whose immutability is unverified", recording("repository_owner_id", Unverified), "repository_owner_id:123456:*", true},
		{"an owner id after its name, unverified", recording("repository_owner_id", Unverified), "repo:acme@123456/*", true},
		{"a repository id whose immutability is unverified", recording("repository_id", Unverified), "repository_id:456789:*", true},
		{"a repository id the census calls immutable", githubFacts(), "repository_id:456789:*", false},
		{"an owner name the census says passes on", githubFacts(), "repo:acme/*", true},
		{"an owner name a census calls immutable", recording("repository_owner", No), "repo:acme/*", false},
		{"an owner id two claims could be", twoOwnerIDs, "repository_owner_id:123456:*", true},
	}
	for _, c := range cases {
		p := Classify(grantOf(githubIssuer, eval.Term{"sub": like(c.sub)}), c.facts, nil)
		if len(p.Populations) != 1 || len(p.Populations[0].Owners) != 1 {
			t.Fatalf("%s: placed %s", c.name, p)
		}
		if got := p.Populations[0].Owners[0].Recyclable; got != c.want {
			t.Errorf("%s: %s recyclable %v, want %v", c.name, p.Populations[0].Owners[0], got, c.want)
		}
	}
}

// TestPinsAcrossClaims: a term is a conjunction, so any one claim that
// pins confines it, and declaring every owner of any one pin moves it to
// yours.
func TestPinsAcrossClaims(t *testing.T) {
	term := eval.Term{"sub": like("repo:acme/*"), "repository_owner_id": eval.Exact("123456")}
	cases := []struct {
		declared string
		want     string
	}{
		{"", Placement{Outcome: Placed, Places: []Place{Outsider}, State: StateExact, Owners: []Owner{githubName("acme"), githubID("123456", "")}}.String()},
		{"github:acme", Placement{Outcome: Placed, Places: []Place{Yours}, State: StateExact, Owners: []Owner{declaredAs(githubName("acme")), githubID("123456", "")}}.String()},
		{"github:@123456", Placement{Outcome: Placed, Places: []Place{Yours}, State: StateExact, Owners: []Owner{githubName("acme"), declaredAs(githubID("123456", ""))}}.String()},
		{"github:beta", Placement{Outcome: Placed, Places: []Place{Outsider}, State: StateExact, Owners: []Owner{githubName("acme"), githubID("123456", "")}}.String()},
	}
	for _, c := range cases {
		if got := Classify(grantOf(githubIssuer, term), githubFacts(), declare(t, c.declared)).String(); got != c.want {
			t.Errorf("declared %q:\n got  %s\n want %s", c.declared, got, c.want)
		}
	}
	// A union pin moves to yours only when every owner it names is declared.
	union := eval.Term{"sub": either(like("repo:acme/*"), like("repo:beta/*"))}
	if got := Classify(grantOf(githubIssuer, union), githubFacts(), declare(t, "github:acme")); got.Places[0] != Outsider {
		t.Errorf("a union of acme and beta with acme alone declared placed %s, want outsider", got)
	}
	if got := Classify(grantOf(githubIssuer, union), githubFacts(), declare(t, "github:beta")); got.Places[0] != Outsider {
		t.Errorf("a union of acme and beta with beta alone declared placed %s, want outsider", got)
	}
	if got := Classify(grantOf(githubIssuer, union), githubFacts(), declare(t, "github:acme\ngithub:beta")); got.Places[0] != Yours {
		t.Errorf("a union of acme and beta with both declared placed %s, want yours", got)
	}
}

// TestDistinctIsTheSortedSetOfOwners holds the merge sort written out for
// Owner to the standard library's: over lists with repeats, distinct keeps
// every owner once, in compareOwners' order, exactly as slices sorts and
// compacts them. The counts prove the lists repeated owners and were long
// enough for the merge to recurse.
func TestDistinctIsTheSortedSetOfOwners(t *testing.T) {
	genOwner := rapid.Custom(func(t *rapid.T) Owner {
		return Owner{
			Issuer:     rapid.SampledFrom([]trust.IssuerRef{githubIssuer, aws.AWSPrincipalIssuer}).Draw(t, "issuer"),
			Namespace:  rapid.SampledFrom([]Namespace{"", NamespaceGitHub, NamespaceAWS}).Draw(t, "namespace"),
			Scope:      Scope(rapid.IntRange(int(ScopeNone), int(ScopeProvider)).Draw(t, "scope")),
			Kind:       Kind(rapid.IntRange(int(KindName), int(KindID)).Draw(t, "kind")),
			Value:      rapid.SampledFrom([]string{"", "acm", "acme", "beta", "123456"}).Draw(t, "value"),
			Name:       rapid.SampledFrom([]string{"", "acme"}).Draw(t, "name"),
			Recyclable: rapid.Bool().Draw(t, "recyclable"),
			Declared:   rapid.Bool().Draw(t, "declared"),
		}
	})
	examined, repeated, long := 0, 0, 0
	enoughExamples(t, func(t *rapid.T) {
		pool := rapid.SliceOfN(genOwner, 1, 8).Draw(t, "pool")
		owners := rapid.SliceOfN(rapid.SampledFrom(pool), 0, 30).Draw(t, "owners")
		want := slices.Compact(slices.SortedFunc(slices.Values(owners), compareOwners))
		if got := distinct(slices.Clone(owners)); !slices.Equal(got, want) {
			t.Fatalf("distinct(%s)\n got  %s\n want %s", ownersText(owners), ownersText(got), ownersText(want))
		}
		examined++
		if len(want) < len(owners) {
			repeated++
		}
		if len(owners) >= 8 {
			long++
		}
	})
	if examined == 0 || repeated == 0 || long == 0 {
		t.Fatalf("examined=%d repeated=%d long=%d; every count must be positive", examined, repeated, long)
	}
	t.Logf("examined=%d repeated=%d long=%d", examined, repeated, long)
}

// TestDeclaredOwnersMatchAsTheirPlatformCompares: a declaration matches a
// pin of the same namespace, scope and kind; names compare exactly unless a
// vendor sentence says they are unique regardless of case; a name-and-id
// declaration matches either pin, an id-only one only an id pin, a
// name-only one only a name pin; and an owner in no namespace, or pinned as
// a repository, is never matched.
func TestDeclaredOwnersMatchAsTheirPlatformCompares(t *testing.T) {
	ignoringCase := githubFacts()
	ignoringCase.Tenancy.NamesIgnoreCase = true
	elsewhere := githubFacts()
	elsewhere.Namespace = ""
	anotherPlatform := githubFacts()
	anotherPlatform.Namespace = "ghes"
	byName := eval.Term{"sub": like("repo:acme/*")}
	byID := eval.Term{"sub": like("repo:acme@123456/*")}
	repository := eval.Term{"repository": eval.Exact("acme/infra")}
	cases := []struct {
		name     string
		facts    Facts
		term     eval.Term
		declared string
		want     Place
	}{
		{"the name", githubFacts(), byName, "github:acme", Yours},
		{"the name in another case", githubFacts(), byName, "github:ACME", Outsider},
		{"the name in another case, case ignored by the platform", ignoringCase, byName, "github:ACME", Yours},
		{"name and id against a name pin", githubFacts(), byName, "github:acme@999", Yours},
		{"name and id against an id pin", githubFacts(), byID, "github:other@123456", Yours},
		{"an id against a name pin", githubFacts(), byName, "github:@123456", Outsider},
		{"a name against an id pin", githubFacts(), byID, "github:acme", Outsider},
		{"another id", githubFacts(), byID, "github:@1234567", Outsider},
		{"a look-alike name", githubFacts(), byName, "github:acme-evil", Outsider},
		{"a shorter name", githubFacts(), byName, "github:acm", Outsider},
		{"an issuer outside the namespace", elsewhere, byName, "github:acme", Outsider},
		{"an issuer in another namespace", anotherPlatform, byName, "github:acme", Outsider},
		{"an owner id against a repository id", githubFacts(), eval.Term{"repository_id": eval.Exact("456789")}, "github:@456789", Outsider},
		{"a repository", githubFacts(), repository, "github:acme", Outsider},
		{"an account", githubFacts(), byName, "aws:111122223333", Outsider},
	}
	for _, c := range cases {
		p := Classify(grantOf(githubIssuer, c.term), c.facts, declare(t, c.declared))
		if !slices.Equal(p.Places, []Place{c.want}) {
			t.Errorf("%s: declared %q, placed %s, want %s", c.name, c.declared, p, c.want)
		}
		if declared := slices.ContainsFunc(p.Owners, func(o Owner) bool { return o.Declared }); declared != (c.want == Yours) {
			t.Errorf("%s: an owner is marked declared: %v, want %v", c.name, declared, c.want == Yours)
		}
	}
}

// TestStateOfAPlace: a place is exact only when verified facts and
// constraints read exactly decide it. An Unknown on a claim that could pin,
// a grant widened as a whole, a caveat on the subject, missing tenancy
// facts or owner characters all leave an unpinned grant's place unknown; an
// Unknown on a claim that cannot pin, or a caveat beside a pin, does not. A
// caveat leaves the place unknown whether or not the claim it is on was
// also constrained in a way that pins nothing, and whether the key it was
// filed under spells the claim or only may, in letters AWS might fold onto
// it or through a variable in the key.
func TestStateOfAPlace(t *testing.T) {
	noCharacters := githubFacts()
	noCharacters.Tenancy.OwnerCharacters = nil
	noTenancy := githubFacts()
	noTenancy.Tenancy = nil
	unknown := eval.Unknown("not read")
	caveat := func(g trust.Grant, claim trust.ClaimKey) trust.Grant {
		g.Admits = g.Admits.WithCaveat(eval.Caveat{Claim: claim, Reason: "not read", Source: "test"})
		return g
	}
	cases := []struct {
		name  string
		facts Facts
		grant trust.Grant
		place Place
		state State
		basis Basis
	}{
		{"nothing pins, all read", githubFacts(), grantOf(githubIssuer, eval.Term{"sub": like("repo:acme*")}), Platform, StateExact, Unpinned},
		{"nothing constrained", githubFacts(), grantOf(githubIssuer, eval.Term{}), Platform, StateExact, Unpinned},
		{"the subject unread", githubFacts(), grantOf(githubIssuer, eval.Term{"sub": unknown, "aud": eval.Exact("sts.amazonaws.com")}), Platform, StateUnknown, UnreadConstraint},
		{"an owner claim unread", githubFacts(), grantOf(githubIssuer, eval.Term{"sub": like("repo:acme*"), "repository_owner": unknown}), Platform, StateUnknown, UnreadConstraint},
		{"a claim that cannot pin, unread", githubFacts(), grantOf(githubIssuer, eval.Term{"sub": like("repo:acme*"), "actor": unknown}), Platform, StateExact, Unpinned},
		{"the grant widened as a whole", githubFacts(), caveat(grantOf(githubIssuer, eval.Term{}), ""), Platform, StateUnknown, UnreadConstraint},
		{"a caveat on the absent subject", githubFacts(), caveat(grantOf(githubIssuer, eval.Term{"aud": eval.Exact("x")}), "sub"), Platform, StateUnknown, UnreadConstraint},
		{"a caveat on an absent owner claim", githubFacts(), caveat(grantOf(githubIssuer, eval.Term{"sub": like("repo:acme*")}), "repository_owner_id"), Platform, StateUnknown, UnreadConstraint},
		{"a caveat on a claim that cannot pin", githubFacts(), caveat(grantOf(githubIssuer, eval.Term{"sub": like("repo:acme*")}), "actor"), Platform, StateExact, Unpinned},
		{"a caveat beside a pin", githubFacts(), caveat(grantOf(githubIssuer, eval.Term{"sub": like("repo:acme/*")}), ""), Outsider, StateExact, Pinned},
		{"an unread claim beside a pin", githubFacts(), grantOf(githubIssuer, eval.Term{"sub": like("repo:acme/*"), "repository_id": unknown}), Outsider, StateExact, Pinned},
		{"no tenancy facts", noTenancy, grantOf(githubIssuer, eval.Term{"sub": like("repo:acme/*")}), Platform, StateUnknown, TenancyNotRecorded},
		{"no owner characters, the subject constrained", noCharacters, grantOf(githubIssuer, eval.Term{"sub": like("repo:acme/*")}), Platform, StateUnknown, TenancyNotRecorded},
		{"no owner characters, the subject unconstrained", noCharacters, grantOf(githubIssuer, eval.Term{"aud": eval.Exact("x")}), Platform, StateExact, Unpinned},
		{"no owner characters, a claim pins", noCharacters, grantOf(githubIssuer, eval.Term{"sub": like("repo:acme/*"), "repository_owner_id": eval.Exact("1")}), Outsider, StateExact, Pinned},
		{"a caveat on the subject beside an open pattern on it", githubFacts(), caveat(grantOf(githubIssuer, eval.Term{"sub": like("repo:*"), "aud": eval.Exact("x")}), "sub"), Platform, StateUnknown, UnreadConstraint},
		{"a caveat on an owner claim beside a value naming nobody", githubFacts(), caveat(grantOf(githubIssuer, eval.Term{"repository_owner": eval.Exact("")}), "repository_owner"), Platform, StateUnknown, UnreadConstraint},
		{"a caveat on a spelling that may be the subject", githubFacts(), caveat(grantOf(githubIssuer, eval.Term{"aud": eval.Exact("x")}), "ſub"), Platform, StateUnknown, UnreadConstraint},
		{"a caveat on a spelling that may be an owner claim", githubFacts(), caveat(grantOf(githubIssuer, eval.Term{"sub": like("repo:acme*")}), "repoſitory_owner"), Platform, StateUnknown, UnreadConstraint},
		{"a caveat on the issuer's key spelled beyond ASCII", githubFacts(), caveat(grantOf(githubIssuer, eval.Term{"aud": eval.Exact("x")}), "token.actions.githubuſercontent.com:sub"), Platform, StateUnknown, UnreadConstraint},
		{"a caveat on a key holding a variable", githubFacts(), caveat(grantOf(githubIssuer, eval.Term{"aud": eval.Exact("x")}), "${aws:username}"), Platform, StateUnknown, UnreadConstraint},
		{"a caveat on another provider's subject", githubFacts(), caveat(grantOf(githubIssuer, eval.Term{"aud": eval.Exact("x")}), "gitlab.com:sub"), Platform, StateExact, Unpinned},
		{"a caveat on a spelling of a claim that cannot pin", githubFacts(), caveat(grantOf(githubIssuer, eval.Term{"aud": eval.Exact("x")}), "job_workflow_ſha"), Platform, StateExact, Unpinned},
		{"a caveat on an account beside a pattern naming none", Facts{PrincipalModelled: true}, caveat(grantOf(aws.AWSPrincipalIssuer, eval.Term{"aws:principalaccount": like("4*")}), "aws:principalaccount"), Platform, StateUnknown, UnreadConstraint},
		{"a caveat on a spelling that may be the organisation", Facts{PrincipalModelled: true}, caveat(grantOf(aws.AWSPrincipalIssuer, eval.Term{}), "aws:principalorgıd"), Platform, StateUnknown, UnreadConstraint},
		// a key of AWS's request context may confine callers to an account
		// or an organisation, or be absent from their requests, and no key
		// of it the tenancy claims do not name is read
		{"an organisation path unread", Facts{PrincipalModelled: true}, caveat(grantOf(aws.AWSPrincipalIssuer, eval.Term{}), "aws:principalorgpaths"), Platform, StateUnknown, UnreadConstraint},
		{"a source account unread", Facts{PrincipalModelled: true}, caveat(grantOf(aws.AWSPrincipalIssuer, eval.Term{}), "aws:sourceaccount"), Platform, StateUnknown, UnreadConstraint},
		{"a session name unread", Facts{PrincipalModelled: true}, caveat(grantOf(aws.AWSPrincipalIssuer, eval.Term{}), "sts:rolesessionname"), Platform, StateUnknown, UnreadConstraint},
		{"a source account unread on a token", githubFacts(), caveat(grantOf(githubIssuer, eval.Term{"aud": eval.Exact("x")}), "aws:sourceaccount"), Platform, StateUnknown, UnreadConstraint},
		{"a source account unread beside a pin", githubFacts(), caveat(grantOf(githubIssuer, eval.Term{"sub": like("repo:acme/*")}), "aws:sourceaccount"), Outsider, StateExact, Pinned},
		{"a source account unread beside an account", Facts{PrincipalModelled: true}, caveat(grantOf(aws.AWSPrincipalIssuer, eval.Term{"aws:principalaccount": eval.Exact("111122223333")}), "aws:sourceaccount"), Outsider, StateExact, Pinned},
		// a repository's name may lead with its owner's, which a pattern may
		// close, and the census does not record how the name is composed
		{"a pattern on a repository's name", githubFacts(), grantOf(githubIssuer, eval.Term{"repository": like("acme/*")}), Platform, StateUnknown, UnreadConstraint},
		{"patterns met on a repository's name", githubFacts(), grantOf(githubIssuer, eval.Term{"repository": both(like("acme/*"), like("*/infra"))}), Platform, StateUnknown, UnreadConstraint},
		{"a pattern on a repository's name beside a pin", githubFacts(), grantOf(githubIssuer, eval.Term{"repository": like("acme/*"), "sub": like("repo:acme/*")}), Outsider, StateExact, Pinned},
		{"a pattern on a repository's id", githubFacts(), grantOf(githubIssuer, eval.Term{"repository_id": like("4567*")}), Platform, StateExact, Unpinned},
		{"patterns met on an owner's name", githubFacts(), grantOf(githubIssuer, eval.Term{"repository_owner": both(like("acme*"), like("*me"))}), Platform, StateExact, Unpinned},
	}
	for _, c := range cases {
		p := Classify(c.grant, c.facts, nil)
		if !slices.Equal(p.Places, []Place{c.place}) || p.State != c.state || p.Populations[0].Basis != c.basis {
			t.Errorf("%s: placed %s by %v, want %s %s by %v", c.name, p, p.Populations[0].Basis, c.place, c.state, c.basis)
		}
	}
}

// TestUnreadableForms: a form whose delimiter the owner characters allow,
// or that has no delimiter, cannot show where an owner ends; it pins
// nothing, and a subject any prefix of which it could match pins nothing
// either, whatever another form says.
func TestUnreadableForms(t *testing.T) {
	dashed := githubFacts()
	dashed.Tenancy.SubjectForms = append(dashed.Tenancy.SubjectForms, SubjectForm{Lead: "repo:", Scope: ScopeOwner, Parts: []Part{{KindName, "-"}, {KindID, "/"}}})
	bare := githubFacts()
	bare.Tenancy.SubjectForms = append(bare.Tenancy.SubjectForms, SubjectForm{Lead: "repo:", Scope: ScopeOwner, Parts: []Part{{KindName, ""}}})
	extended := githubFacts()
	extended.Tenancy.NeverPin = append(extended.Tenancy.NeverPin, "repo:acme/")
	longer := githubFacts()
	longer.Tenancy.NeverPin = append(longer.Tenancy.NeverPin, "repo:acme/deploy:")
	noForms := githubFacts()
	noForms.Tenancy.SubjectForms = nil
	unscoped := githubFacts()
	unscoped.Tenancy.SubjectForms = append(unscoped.Tenancy.SubjectForms, SubjectForm{Lead: "repo:", Parts: []Part{{KindName, "/"}}})
	long := githubFacts()
	long.Tenancy.SubjectForms = append(long.Tenancy.SubjectForms, SubjectForm{Lead: "repo:", Scope: ScopeOwner, Parts: []Part{{KindName, "//"}}})
	for name, facts := range map[string]Facts{
		"a delimiter inside the characters": dashed, "no delimiter": bare, "a delimiter of two characters": long,
		"a form that names no tenant": unscoped, "a never-pin literal the prefix runs into": extended,
		"a never-pin literal the prefix stops inside": longer, "no forms": noForms,
	} {
		p := Classify(grantOf(githubIssuer, eval.Term{"sub": like("repo:acme/*")}), facts, nil)
		if p.String() != (Placement{Outcome: Placed, Places: []Place{Platform}, State: StateExact}).String() {
			t.Errorf("%s: repo:acme/* placed %s, want platform exact", name, p)
		}
	}
	// A form led by a literal the subject does not reach leaves the others
	// to decide.
	unrelated := githubFacts()
	unrelated.Tenancy.SubjectForms = append(unrelated.Tenancy.SubjectForms, SubjectForm{Lead: "team:", Scope: ScopeOwner, Parts: []Part{{KindName, "-"}}})
	if p := Classify(grantOf(githubIssuer, eval.Term{"sub": like("repo:acme/*")}), unrelated, nil); p.Places[0] != Outsider {
		t.Errorf("an unreadable form under another literal changed repo:acme/* to %s", p)
	}
}

// TestShapesNoTermHolds: a term drops a claim that admits everything and
// dies with one that admits nothing, so no alternative reaches the reader
// with either; the reader still names no owner for them, and does not call
// them unread.
func TestShapesNoTermHolds(t *testing.T) {
	pins := func(string) []Owner { return []Owner{githubName("acme")} }
	for _, s := range []eval.StringSet{eval.Any(), eval.None()} {
		if got := confineShape(eval.ShapeOf(s), pins, pins); got.owners != nil || got.unread {
			t.Errorf("%s confines to %+v", s, got)
		}
	}
}

// TestAWSPrincipals: the pseudo-issuer's tenancy facts are the parser's. An
// account or organisation pinned exactly, or an ARN whose prefix runs
// through the account's closing colon, is a named outsider; anything else
// read exactly is anyone with an AWS account; an Unknown on a tenancy claim
// leaves that unknown.
func TestAWSPrincipals(t *testing.T) {
	account := awsTenant(ScopeAccount, "111122223333")
	cases := []struct {
		name     string
		term     eval.Term
		declared string
		want     string
		basis    Basis
	}{
		{"an account", eval.Term{"aws:principalaccount": eval.Exact("111122223333")}, "", "outsider exact [" + account.String() + "]", Pinned},
		{"an organisation", eval.Term{"aws:principalorgid": eval.Exact("o-a1b2c3d4e5")}, "", "outsider exact [" + awsTenant(ScopeOrganisation, "o-a1b2c3d4e5").String() + "]", Pinned},
		{"a role", eval.Term{"aws:principalarn": eval.Exact("arn:aws:iam::111122223333:role/deploy")}, "", "outsider exact [" + account.String() + "]", Pinned},
		{"a role pattern closed", eval.Term{"aws:principalarn": like("arn:aws:iam::111122223333:role/*")}, "", "outsider exact [" + account.String() + "]", Pinned},
		{"an account not closed", eval.Term{"aws:principalarn": like("arn:aws:iam::11112222333*")}, "", "platform exact", Unpinned},
		{"any account", eval.Term{"aws:principalarn": like("arn:aws:iam::*:role/deploy")}, "", "platform exact", Unpinned},
		{"an account by pattern", eval.Term{"aws:principalaccount": like("11112222333?")}, "", "platform exact", Unpinned},
		{"anonymous", eval.Term{"aws:principalaccount": eval.Exact("anonymous")}, "", "platform exact", Unpinned},
		{"two accounts", eval.Term{"aws:principalaccount": either(eval.Exact("111122223333"), eval.Exact("444455556666"))}, "", "outsider exact [" + account.String() + "; " + awsTenant(ScopeAccount, "444455556666").String() + "]", Pinned},
		{"an account or anyone", eval.Term{"aws:principalaccount": either(eval.Exact("111122223333"), like("4*"))}, "", "platform exact", Unpinned},
		{"an external id", eval.Term{"sts:externalid": eval.Exact("vendor-abc")}, "", "platform exact", Unpinned},
		{"a principal type", eval.Term{"aws:principaltype": eval.Exact("AssumedRole")}, "", "platform exact", Unpinned},
		{"everyone", eval.Term{}, "", "platform exact", Unpinned},
		{"an ARN unread", eval.Term{"aws:principalarn": eval.Unknown("deleted"), "aws:principaltype": eval.Exact("x")}, "", "platform unknown", UnreadConstraint},
		{"an account beside an unread ARN", eval.Term{"aws:principalaccount": eval.Exact("111122223333"), "aws:principalarn": eval.Unknown("session")}, "", "outsider exact [" + account.String() + "]", Pinned},
		{"the account declared", eval.Term{"aws:principalaccount": eval.Exact("111122223333")}, "aws:111122223333", "yours exact [" + declaredAs(account).String() + "]", Pinned},
		{"an organisation declared for an account", eval.Term{"aws:principalaccount": eval.Exact("111122223333")}, "aws:o-a1b2c3d4e5", "outsider exact [" + account.String() + "]", Pinned},
		{"another account declared", eval.Term{"aws:principalaccount": eval.Exact("111122223333")}, "aws:444455556666", "outsider exact [" + account.String() + "]", Pinned},
	}
	for _, c := range cases {
		p := Classify(grantOf(aws.AWSPrincipalIssuer, c.term), Facts{PrincipalModelled: true}, declare(t, c.declared))
		if p.String() != c.want || p.Populations[0].Basis != c.basis {
			t.Errorf("%s: placed %s by %v, want %s by %v", c.name, p, p.Populations[0].Basis, c.want, c.basis)
		}
	}
}

// TestPrincipalsTheParserDoesNotModel: a principal whose kind of identity
// the parser cannot say, a CanonicalUser, an AWS ARN of another service or
// a role's ARN under Federated, is anyone's, whatever issuer its grant is
// filed under. A principal the parser modelled keeps its place beside one,
// and so does one whose statement, not its own reading, left its grant
// unevaluated. An STS ARN of a kind the parser does not know, and a root
// ARN with no account, still name identities of AWS accounts, and stay with
// the AWS issuer.
func TestPrincipalsTheParserDoesNotModel(t *testing.T) {
	const canonical = `"CanonicalUser": "79a59df900b949e55d96a1e698fbacedfd6e09d98eacf8f8d5218e7cd47ef2be"`
	trap, err := os.ReadFile(filepath.Join(ringsDir, "42-principals-not-modelled", "aws.json"))
	if err != nil {
		t.Fatalf("%v", err)
	}
	account := awsTenant(ScopeAccount, "111122223333").String()
	cases := []struct {
		name string
		raw  string
		want []string // every grant's issuer and placement, sorted
	}{
		{"the trap", string(trap), []string{": anyone unknown", "aws:sts: anyone unknown", "aws:sts: anyone unknown"}},
		{"a CanonicalUser on web identity", statementDocument(`{`+canonical+`}`, `"Action": "sts:AssumeRoleWithWebIdentity"`), []string{"aws:sts: anyone unknown"}},
		{"an account beside an ARN of another service", statementDocument(`{"AWS": ["111122223333", "arn:aws:s3:::acme-artifacts"]}`, `"Action": "sts:AssumeRole"`), []string{"aws:sts: anyone unknown", "aws:sts: outsider exact [" + account + "]"}},
		{`"*" beside a CanonicalUser`, statementDocument(`{"AWS": "*", `+canonical+`}`, `"Action": "sts:AssumeRole"`), []string{": service unknown", "aws:sts: anyone unknown", "aws:sts: platform exact"}},
		{"an account its statement leaves unevaluated", statementDocument(`{"AWS": "111122223333"}`, `"NotAction": "s3:*"`), []string{"aws:sts: platform unknown"}},
		{"an STS ARN of a kind the parser does not know", statementDocument(`{"AWS": "arn:aws:sts::111122223333:other/x"}`, `"Action": "sts:AssumeRole"`), []string{"aws:sts: outsider exact [" + account + "]"}},
		{"a root ARN with no account", statementDocument(`{"AWS": "arn:aws:iam:::root"}`, `"Action": "sts:AssumeRole"`), []string{"aws:sts: platform unknown"}},
	}
	for _, c := range cases {
		grants, placements := placeAll(t, []byte(c.raw), nil)
		var got []string
		for i, g := range grants {
			got = append(got, string(g.Issuer)+": "+placements[i].String())
		}
		slices.Sort(got)
		if !slices.Equal(got, c.want) {
			t.Errorf("%s:\n got  %q\n want %q", c.name, got, c.want)
		}
	}
}

// statementDocument is a trust policy of one Allow statement naming
// principal, with the member that says what it grants.
func statementDocument(principal, grants string) string {
	return `{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": ` + principal + `, ` + grants + `}]}`
}

// TestPerTenantIssuers: of a per-tenant issuer whose tokens are shown to
// need an account, a tenant whose owner controls membership is a named
// outsider, or yours once its issuer is declared; a tenant anyone can join
// is anyone on the platform, exact; and a tenant nobody showed to be
// controlled, or no tenant at all, is the platform, unknown. Recyclability
// is read the cautious way. A declaration names its tenant by the whole
// issuer URL: a URL the issuer's begins with, as a region's host begins
// every cluster's there, or one that runs past it, is another issuer's.
func TestPerTenantIssuers(t *testing.T) {
	const issuer trust.IssuerRef = "https://oidc.example.com/tenant-1"
	tenant := func(recyclable bool, declared bool) string {
		o := Owner{Issuer: issuer, Namespace: NamespaceIssuer, Scope: ScopeTenant, Kind: KindID, Value: "tenant-1", Recyclable: recyclable, Declared: declared}
		return "[" + o.String() + "]"
	}
	anonymous := perTenantFacts("tenant-1", KindID, Unverified, Controlled)
	anonymous.AnonymousTokens = Unverified
	cases := []struct {
		name     string
		facts    Facts
		declared string
		want     string
		basis    Basis
	}{
		{"controlled", perTenantFacts("tenant-1", KindID, Unverified, Controlled), "", "outsider exact " + tenant(true, false), ControlledTenant},
		{"controlled, never recycled", perTenantFacts("tenant-1", KindID, No, Controlled), "", "outsider exact " + tenant(false, false), ControlledTenant},
		{"controlled, recycled", perTenantFacts("tenant-1", KindID, Yes, Controlled), "", "outsider exact " + tenant(true, false), ControlledTenant},
		{"declared", perTenantFacts("tenant-1", KindID, No, Controlled), "issuer:https://OIDC.example.com/tenant-1/", "yours exact " + tenant(false, true), ControlledTenant},
		{"another tenant declared", perTenantFacts("tenant-1", KindID, No, Controlled), "issuer:https://oidc.example.com/tenant-2", "outsider exact " + tenant(false, false), ControlledTenant},
		{"the issuer's host declared", perTenantFacts("tenant-1", KindID, No, Controlled), "issuer:https://oidc.example.com", "outsider exact " + tenant(false, false), ControlledTenant},
		{"the issuer cut short declared", perTenantFacts("tenant-1", KindID, No, Controlled), "issuer:https://oidc.example.com/tenant-", "outsider exact " + tenant(false, false), ControlledTenant},
		{"an issuer running past it declared", perTenantFacts("tenant-1", KindID, No, Controlled), "issuer:https://oidc.example.com/tenant-1/x", "outsider exact " + tenant(false, false), ControlledTenant},
		{"open to anyone", perTenantFacts("tenant-1", KindID, No, OpenToAnyone), "", "platform exact", OpenTenant},
		{"open to anyone, declared", perTenantFacts("tenant-1", KindID, No, OpenToAnyone), "issuer:https://oidc.example.com/tenant-1", "platform exact", OpenTenant},
		{"membership unverified", perTenantFacts("tenant-1", KindID, No, MembershipUnverified), "", "platform unknown", MembershipNotVerified},
		{"no tenant named", perTenantFacts("", KindID, No, Controlled), "", "platform unknown", MembershipNotVerified},
		{"tokens without an account unverified", anonymous, "issuer:https://oidc.example.com/tenant-1", "anyone unknown", AccountNotVerified},
	}
	for _, c := range cases {
		p := Classify(grantOf(issuer, eval.Term{"sub": eval.Exact("system:serviceaccount:a:b")}), c.facts, declare(t, c.declared))
		if p.String() != c.want || p.Populations[0].Basis != c.basis {
			t.Errorf("%s: placed %s by %v, want %s by %v", c.name, p, p.Populations[0].Basis, c.want, c.basis)
		}
	}
}

// TestAnyoneFirst: whatever the grant constrains, an issuer the census has
// not surveyed, or one whose tokens need no account or are not shown to, is
// anyone, unknown. An identity pool's id in aud pins the pool, never who
// can get into it, guests or whoever its providers sign in. Declaring never
// moves such a grant: not the owners its conditions name, and not its
// issuer's own URL, which is what a user running the issuer would
// declare, since who runs an issuer does not bound who can obtain its
// tokens.
func TestAnyoneFirst(t *testing.T) {
	const pool = "us-east-1:12345678-abcd-abcd-abcd-123456789012"
	pinned := eval.Term{"aud": eval.Exact("sts.amazonaws.com"), "sub": like("repo:acme/*"), "repository_owner_id": eval.Exact("123456")}
	anonymous := githubFacts()
	anonymous.AnonymousTokens = Yes
	unverified := githubFacts()
	unverified.AnonymousTokens = Unverified
	surveyedNothing := githubFacts()
	surveyedNothing.IssuerKind = NotSurveyed
	for _, c := range []struct {
		name   string
		issuer trust.IssuerRef
		term   eval.Term
		facts  Facts
		basis  Basis
	}{
		{"not surveyed", githubIssuer, pinned, Facts{PrincipalModelled: true}, IssuerNotSurveyed},
		{"not surveyed, whatever else is recorded", githubIssuer, pinned, surveyedNothing, IssuerNotSurveyed},
		{"tokens without an account", githubIssuer, pinned, anonymous, TokensWithoutAccount},
		{"not shown to need an account", githubIssuer, pinned, unverified, AccountNotVerified},
		{"an identity pool's id", cognitoIssuer, eval.Term{"aud": eval.Exact(pool)}, censusFacts(cognitoIssuer), TokensWithoutAccount},
		{"an identity pool's guests", cognitoIssuer, eval.Term{"aud": eval.Exact(pool), "amr": eval.Exact("unauthenticated")}, censusFacts(cognitoIssuer), TokensWithoutAccount},
		{"an identity pool's signed-in identities", cognitoIssuer, eval.Term{"aud": eval.Exact(pool), "amr": eval.Exact("authenticated")}, censusFacts(cognitoIssuer), TokensWithoutAccount},
	} {
		for _, declared := range []string{"", "github:acme\ngithub:@123456", "issuer:" + string(c.issuer)} {
			p := Classify(grantOf(c.issuer, c.term), c.facts, declare(t, declared))
			if p.String() != "anyone unknown" || p.Populations[0].Basis != c.basis {
				t.Errorf("%s, declaring %q: placed %s by %v, want anyone unknown by %v", c.name, declared, p, p.Populations[0].Basis, c.basis)
			}
		}
	}
}

// TestIssuerlessGrants: a grant with no issuer is anyone, unknown, unless
// the statement it came from grants "*" the assume actions of AWS services
// or of the account's SAML providers only; both together are both named. A
// population this package does not know reads as every issuer.
func TestIssuerlessGrants(t *testing.T) {
	cases := []struct {
		population aws.Population
		want       string
		bases      []Basis
	}{
		{aws.EveryIssuer, "anyone unknown", []Basis{AnyIssuer}},
		{aws.AWSServices, "service unknown", []Basis{AnyService}},
		{aws.AccountSAMLProviders, "saml unknown", []Basis{AccountSAMLProviders}},
		{aws.AWSServicesAndAccountSAMLProviders, "saml+service unknown", []Basis{AccountSAMLProviders, AnyService}},
		{aws.Population(99), "anyone unknown", []Basis{AnyIssuer}},
	}
	for _, c := range cases {
		p := Classify(grantOf("", eval.Term{}), Facts{Issuerless: c.population, PrincipalModelled: true}, declare(t, "saml:arn:aws:iam::123456789012:saml-provider/VendorSSO"))
		var bases []Basis
		for _, pop := range p.Populations {
			bases = append(bases, pop.Basis)
		}
		if p.String() != c.want || !slices.Equal(bases, c.bases) {
			t.Errorf("population %d: placed %s by %v, want %s by %v", c.population, p, bases, c.want, c.bases)
		}
	}
}

// TestSAMLAndServices: a SAML provider's sign-ins and a service's callers
// are read from no trust policy, so they sit beside the rings, unknown; a
// SAML provider the user declares moves into their people, still unknown,
// and nothing else does. A service the parser's table of intermediaries
// lists is placed as one assuming a role for identities outside IAM, on the
// same line and as unknown: who receives its session is set in the
// service's own resources.
func TestSAMLAndServices(t *testing.T) {
	const other trust.IssuerRef = "arn:aws:iam::123456789012:saml-provider/CompanySSO"
	service := func(name string) trust.IssuerRef { return trust.IssuerRef(aws.ServiceIssuerPrefix + name) }
	cases := []struct {
		name     string
		issuer   trust.IssuerRef
		declared string
		want     string
		basis    Basis
	}{
		{"a SAML provider", samlVendor, "", "saml unknown [" + samlOwner(samlVendor).String() + "]", SAMLProvider},
		{"the provider declared", samlVendor, "saml:" + string(samlVendor), "people unknown [" + declaredAs(samlOwner(samlVendor)).String() + "]", SAMLProvider},
		{"another provider declared", samlVendor, "saml:" + string(other), "saml unknown [" + samlOwner(samlVendor).String() + "]", SAMLProvider},
		{"a service", service("ec2.amazonaws.com"), "saml:" + string(samlVendor), "service unknown", ServicePrincipal},
		{"IAM Roles Anywhere", service("rolesanywhere.amazonaws.com"), "", "service unknown", ServiceIntermediary},
		{"the IoT credentials provider", service("credentials.iot.amazonaws.com"), "", "service unknown", ServiceIntermediary},
		{"Systems Manager", service("ssm.amazonaws.com"), "", "service unknown", ServiceIntermediary},
		{"EKS Pod Identity", service("pods.eks.amazonaws.com"), "aws:111122223333", "service unknown", ServiceIntermediary},
		{"Transfer Family", service("transfer.amazonaws.com"), "", "service unknown", ServiceIntermediary},
		{"a partition's suffix no row holds", service("rolesanywhere.amazonaws.com.cn"), "", "service unknown", ServicePrincipal},
	}
	for _, c := range cases {
		p := Classify(grantOf(c.issuer, eval.Term{}), Facts{PrincipalModelled: true}, declare(t, c.declared))
		if p.String() != c.want || p.Populations[0].Basis != c.basis {
			t.Errorf("%s: placed %s by %v, want %s by %v", c.name, p, p.Populations[0].Basis, c.want, c.basis)
		}
	}
}

// TestRefusalsAndNobody: a Deny is a refusal whatever it admits, an Allow
// that provably admits no token is in no ring, and an effect the parser
// could not read is placed as an Allow, never exactly: it may be a Deny,
// and then the ring is not reached at all.
func TestRefusalsAndNobody(t *testing.T) {
	deny := grantOf(githubIssuer, eval.Term{})
	deny.Effect = trust.Deny
	denyNothing := grantOf(githubIssuer)
	denyNothing.Effect = trust.Deny
	denyNothing.Admits = denyNothing.Admits.WithCaveat(eval.Caveat{Reason: "not applied", Source: "test"})
	unknownEffect := grantOf(githubIssuer, eval.Term{"sub": like("repo:acme*")})
	unknownEffect.Effect = trust.EffectUnknown
	pinnedUnknownEffect := grantOf(githubIssuer, eval.Term{"sub": like("repo:acme/*")})
	pinnedUnknownEffect.Effect = trust.EffectUnknown
	cases := []struct {
		name  string
		grant trust.Grant
		want  string
	}{
		{"a Deny", deny, "refused"},
		{"a Deny not applied", denyNothing, "refused"},
		{"an Allow that admits nothing", grantOf(githubIssuer), "nobody"},
		{"an effect not read", unknownEffect, "platform unknown"},
		{"an effect not read, on a pinned owner", pinnedUnknownEffect, "outsider unknown [" + githubName("acme").String() + "]"},
	}
	for _, c := range cases {
		p := Classify(c.grant, githubFacts(), nil)
		if p.String() != c.want {
			t.Errorf("%s: placed %s, want %s", c.name, p, c.want)
		}
		if p.Outcome != Placed && (p.Places != nil || p.Populations != nil || p.Owners != nil) {
			t.Errorf("%s: a grant in no ring carries places, populations or owners: %+v", c.name, p)
		}
	}
}

// TestOutermostTerm: each alternative of an admitted set is placed on its
// own and the grant takes the outermost; its state is exact when some
// population at that place is; its owners are those of the populations
// there.
func TestOutermostTerm(t *testing.T) {
	acme := eval.Term{"sub": like("repo:acme/*")}
	beta := eval.Term{"sub": like("repo:beta/*")}
	open := eval.Term{"sub": like("repo:acme*")}
	unread := eval.Term{"sub": eval.Unknown("not read"), "aud": eval.Exact("x")}
	cases := []struct {
		name     string
		terms    []eval.Term
		declared string
		want     string
		places   []Place
	}{
		{"an owner and anyone on the platform", []eval.Term{acme, open}, "", "platform exact", []Place{Outsider, Platform}},
		{"two owners", []eval.Term{acme, beta}, "", "outsider exact [" + githubName("acme").String() + "; " + githubName("beta").String() + "]", []Place{Outsider, Outsider}},
		{"yours beside an outsider", []eval.Term{acme, beta}, "github:acme", "outsider exact [" + githubName("beta").String() + "]", []Place{Yours, Outsider}},
		{"a pin beside an unread subject", []eval.Term{acme, unread}, "", "platform unknown", []Place{Outsider, Platform}},
		{"an exact and an unknown platform", []eval.Term{open, unread}, "", "platform exact", []Place{Platform, Platform}},
	}
	for _, c := range cases {
		g := grantOf(githubIssuer, c.terms...)
		p := Classify(g, githubFacts(), declare(t, c.declared))
		var places []Place
		for i, pop := range p.Populations {
			places = append(places, pop.Place)
			if pop.Term != i {
				t.Errorf("%s: population %d is of term %d", c.name, i, pop.Term)
			}
		}
		if p.String() != c.want {
			t.Errorf("%s: placed %s, want %s", c.name, p, c.want)
		}
		// The admitted set orders its terms by rendering; the populations
		// follow that order, whichever it is.
		if !slices.Equal(slices.Sorted(slices.Values(places)), slices.Sorted(slices.Values(c.places))) || len(places) != len(g.Admits.Terms()) {
			t.Errorf("%s: populations at %v, want %v, one per term", c.name, places, c.places)
		}
	}
}

// TestZeroValues: every zero value is the cautious one, so a value nobody
// set can never read as a nearer place or a verified fact.
func TestZeroValues(t *testing.T) {
	if Place(0) != Anyone || State(0) != StateUnknown || Basis(0) != IssuerNotSurveyed || Outcome(0) != Placed {
		t.Errorf("zero place %v, state %v, basis %v, outcome %v", Place(0), State(0), Basis(0), Outcome(0))
	}
	if IssuerKind(0) != NotSurveyed || Established(0) != Unverified || Membership(0) != MembershipUnverified {
		t.Errorf("zero issuer kind %v, established %v, membership %v", IssuerKind(0), Established(0), Membership(0))
	}
	if Kind(0) != KindName || Scope(0) != ScopeNone {
		t.Errorf("zero kind %v, scope %v", Kind(0), Scope(0))
	}
	if p := Classify(grantOf(githubIssuer, eval.Term{"sub": like("repo:acme/*")}), Facts{}, nil); p.String() != "anyone unknown" || p.Populations[0].Basis != PrincipalNotModelled {
		t.Errorf("zero facts placed a pinned grant %s by %v", p, p.Populations[0].Basis)
	}
	if (Owner{Value: "acme"}).Declaration() != "" {
		t.Errorf("an owner in no namespace can be declared")
	}
}

// TestVocabulary pins every id the answer will carry: a consumer built for
// one vocabulary reads another's words as values it does not know.
func TestVocabulary(t *testing.T) {
	ids := func(n int, name func(int) string) []string {
		out := make([]string, n)
		for i := range out {
			out[i] = name(i)
		}
		return out
	}
	cases := []struct {
		got, want []string
	}{
		{ids(7, func(i int) string { return Place(i).String() }), []string{"anyone", "platform", "outsider", "yours", "people", "saml", "service"}},
		{ids(2, func(i int) string { return State(i).String() }), []string{"unknown", "exact"}},
		{ids(3, func(i int) string { return Outcome(i).String() }), []string{"placed", "refused", "nobody"}},
		{ids(8, func(i int) string { return Scope(i).String() }), []string{"none", "owner", "repository", "enterprise", "account", "organisation", "tenant", "provider"}},
		{ids(2, func(i int) string { return Kind(i).String() }), []string{"name", "id"}},
		{ids(17, func(i int) string { return Basis(i).String() }), []string{
			"issuer-not-surveyed", "tokens-without-account", "account-not-verified", "any-issuer",
			"principal-not-modelled", "unpinned", "unread-constraint", "tenancy-not-recorded", "open-tenant",
			"membership-not-verified", "pinned", "controlled-tenant",
			"saml-provider", "account-saml-providers", "service-principal", "any-service", "service-intermediary",
		}},
	}
	for _, c := range cases {
		if !slices.Equal(c.got, c.want) {
			t.Errorf("ids %q, want %q", c.got, c.want)
		}
	}
	for p := Anyone; p <= Service; p++ {
		if p.Ring() != (p <= People) {
			t.Errorf("%s: Ring() = %v", p, p.Ring())
		}
	}
}

// TestRendering: every value renders to text a reader can tell apart from
// every other, and a value no table holds says so instead of passing for
// one that exists.
func TestRendering(t *testing.T) {
	cases := []struct {
		got, want string
	}{
		{Place(7).String(), "place(7)"},
		{Place(-1).String(), "place(-1)"},
		{State(2).String(), "state(2)"},
		{Basis(17).String(), "basis(17)"},
		{Outcome(3).String(), "outcome(3)"},
		{Scope(8).String(), "scope(8)"},
		{Kind(2).String(), "kind(2)"},
		{Placement{Outcome: Refused}.String(), "refused"},
		{Placement{Outcome: Nobody}.String(), "nobody"},
		{Placement{Outcome: Placed, Places: []Place{SAML, Service}, State: StateUnknown}.String(), "saml+service unknown"},
		{Population{Term: 2, Place: Yours, State: StateExact, Basis: Pinned, Owners: []Owner{githubName("acme")}}.String(), `2: yours exact pinned [owner name "acme" on "https://token.actions.githubusercontent.com" in github recyclable]`},
		{declaredAs(githubID("123456", "acme")).String(), `owner id "123456" named "acme" on "https://token.actions.githubusercontent.com" in github declared`},
		{(Owner{Scope: ScopeTenant, Value: "t\n"}).String(), `tenant name "t\n" on ""`},
		{githubName("acme").Declaration(), "github:acme"},
		{githubID("123456", "acme").Declaration(), "github:acme@123456"},
		{githubID("123456", "").Declaration(), "github:@123456"},
		{githubRepositoryID("456789").Declaration(), ""},
		{awsTenant(ScopeAccount, "111122223333").Declaration(), "aws:111122223333"},
		{awsTenant(ScopeOrganisation, "o-a1b2c3d4e5").Declaration(), "aws:o-a1b2c3d4e5"},
		{samlOwner(samlVendor).Declaration(), "saml:" + string(samlVendor)},
		{tenantOwner(eksIssuer, "x", KindID).Declaration(), "issuer:" + string(eksIssuer)},
		{(Declaration{Namespace: NamespaceGitHub, Name: "acme"}).String(), "github:acme"},
		{(Declaration{Namespace: NamespaceAWS, Value: "111122223333"}).String(), "aws:111122223333"},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("rendered %q, want %q", c.got, c.want)
		}
	}
}
