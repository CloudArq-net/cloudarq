package aws

import (
	"maps"
	"regexp"
	"slices"
	"strings"
	"testing"

	"pgregory.net/rapid"

	"github.com/CloudArq-net/cloudarq/internal/eval"
	"github.com/CloudArq-net/cloudarq/internal/trust"
)

func account(id string) Tenant      { return Tenant{Scope: AccountScope, ID: id} }
func organisation(id string) Tenant { return Tenant{Scope: OrganisationScope, ID: id} }

// tenancyCase is one question put to the facts: under this claim, does this
// text name a tenant, and which.
type tenancyCase struct {
	claim trust.ClaimKey
	text  string
	want  Tenant
	names bool
}

func checkTenancy(t *testing.T, name string, read func(trust.ClaimKey, string) (Tenant, bool), cases []tenancyCase) {
	t.Helper()
	for _, c := range cases {
		got, names := read(c.claim, c.text)
		if names != c.names || got != c.want {
			t.Errorf("%s(%s, %q) = %+v, %v; want %+v, %v", name, c.claim, c.text, got, names, c.want, c.names)
		}
	}
}

// TestTenantOfValue: an exact value names a tenant only when it is one, in
// the form AWS gives it. "anonymous" is what aws:PrincipalAccount carries
// for an anonymous request, and no account is called that; a value of
// sts:ExternalId or aws:PrincipalType names nobody whatever it spells.
func TestTenantOfValue(t *testing.T) {
	const id = "111122223333"
	longOrg := "o-" + strings.Repeat("a1", 16)
	checkTenancy(t, "TenantOfValue", TenantOfValue, []tenancyCase{
		{"aws:principalaccount", id, account(id), true},
		{"aws:principalaccount", "012345678901", account("012345678901"), true},
		{"aws:principalaccount", "anonymous", Tenant{}, false},
		{"aws:principalaccount", "11112222333", Tenant{}, false},
		{"aws:principalaccount", "1111222233334", Tenant{}, false},
		{"aws:principalaccount", "11112222333a", Tenant{}, false},
		{"aws:principalaccount", "", Tenant{}, false},
		{"aws:principalaccount", "arn:aws:iam::" + id + ":root", Tenant{}, false},

		{"aws:principalorgid", "o-a1b2c3d4e5", organisation("o-a1b2c3d4e5"), true},
		{"aws:principalorgid", longOrg, organisation(longOrg), true},
		{"aws:principalorgid", "o-a1b2c3d4e", Tenant{}, false},
		{"aws:principalorgid", longOrg + "a", Tenant{}, false},
		{"aws:principalorgid", "o-A1B2C3D4E5", Tenant{}, false},
		{"aws:principalorgid", "O-a1b2c3d4e5", Tenant{}, false},
		{"aws:principalorgid", "o-a1b2c3d4é5", Tenant{}, false},
		{"aws:principalorgid", "o-a1b2-3d4e5", Tenant{}, false},
		{"aws:principalorgid", "a1b2c3d4e5", Tenant{}, false},
		{"aws:principalorgid", "", Tenant{}, false},

		{"aws:principalarn", "arn:aws:iam::" + id + ":role/deploy", account(id), true},
		{"aws:principalarn", "arn:aws:iam::" + id + ":user/alice", account(id), true},
		{"aws:principalarn", "arn:aws:iam::" + id + ":root", account(id), true},
		{"aws:principalarn", "arn:aws:sts::" + id + ":federated-user/bob", account(id), true},
		{"aws:principalarn", "arn:aws-cn:iam::" + id + ":role/deploy", account(id), true},
		{"aws:principalarn", "arn:aws:iam::" + id + ":role/a:b:c", account(id), true},
		{"aws:principalarn", "arn:aws:iam::" + id, Tenant{}, false},
		{"aws:principalarn", "arn:aws:iam:::role/deploy", Tenant{}, false},
		{"aws:principalarn", "arn:aws:iam::anonymous:role/deploy", Tenant{}, false},
		{"aws:principalarn", "arn:aws:iam::o-a1b2c3d4e5:role/deploy", Tenant{}, false},
		{"aws:principalarn", "xrn:aws:iam::" + id + ":role/deploy", Tenant{}, false},
		{"aws:principalarn", id, Tenant{}, false},

		{"sts:externalid", id, Tenant{}, false},
		{"sts:externalid", "o-a1b2c3d4e5", Tenant{}, false},
		{"sts:externalid", "arn:aws:iam::" + id + ":role/deploy", Tenant{}, false},
		{"aws:principaltype", "AssumedRole", Tenant{}, false},
		{"aws:principaltype", id, Tenant{}, false},
		{"sub", id, Tenant{}, false},
		{"aws:sourceaccount", id, Tenant{}, false},
		{"AWS:PrincipalAccount", id, Tenant{}, false},
	})
}

// The identifier forms AWS documents, transcribed from its sentences as an
// oracle that shares no code with the one under test: an account id is "A
// 12-digit number", and an organisation id is "o-" followed by from 10 to
// 32 lowercase letters or digits.
var (
	accountIDForm      = regexp.MustCompile(`^[0-9]{12}$`)
	organisationIDForm = regexp.MustCompile(`^o-[a-z0-9]{10,32}$`)
)

// genIdentifierLike draws values near both forms: a run of digits around
// twelve long, or a run of lower-case letters and digits around ten to
// thirty-two long behind "o-" or a near miss of it, one time in four with
// one character replaced by an upper-case letter, a dash, a letter outside
// ASCII, or a letter that changes nothing for an organisation.
func genIdentifierLike() *rapid.Generator[string] {
	return rapid.Custom(func(t *rapid.T) string {
		head, body := "", rapid.StringOfN(rapid.RuneFrom([]rune("0123456789")), 10, 14, -1).Draw(t, "digits")
		if rapid.Bool().Draw(t, "organisation-shaped") {
			head = rapid.SampledFrom([]string{"o-", "o-", "O-", "o", "0-"}).Draw(t, "head")
			body = rapid.StringOfN(rapid.RuneFrom([]rune("0123456789abcdefghijklmnopqrstuvwxyz")), 8, 34, -1).Draw(t, "id")
		}
		if rapid.IntRange(0, 3).Draw(t, "flaw") == 0 {
			i := rapid.IntRange(0, len(body)-1).Draw(t, "at")
			body = body[:i] + rapid.SampledFrom([]string{"A", "-", "é", "x"}).Draw(t, "with") + body[i+1:]
		}
		return head + body
	})
}

// TestTenantOfValueIsTheDocumentedForm: an account or an organisation claim
// names a tenant exactly when its value has the form AWS documents for that
// identifier, and then names that identifier at that scope. A value a digit
// short, in upper case or with a dash inside is no account and no
// organisation, and a tenant named for it would be an owner that cannot
// exist. The counts prove both forms were met, and missed.
func TestTenantOfValueIsTheDocumentedForm(t *testing.T) {
	accounts, organisations, neither := 0, 0, 0
	rapid.Check(t, func(t *rapid.T) {
		for _, v := range rapid.SliceOfN(genIdentifierLike(), 4, 4).Draw(t, "values") {
			tenant, isAccount := TenantOfValue(accountClaim, v)
			if isAccount != accountIDForm.MatchString(v) || isAccount && tenant != account(v) {
				t.Fatalf("TenantOfValue(%s, %q) = %+v, %v; the documented form says %v", accountClaim, v, tenant, isAccount, accountIDForm.MatchString(v))
			}
			tenant, isOrganisation := TenantOfValue(orgClaim, v)
			if isOrganisation != organisationIDForm.MatchString(v) || isOrganisation && tenant != organisation(v) {
				t.Fatalf("TenantOfValue(%s, %q) = %+v, %v; the documented form says %v", orgClaim, v, tenant, isOrganisation, organisationIDForm.MatchString(v))
			}
			switch {
			case isAccount:
				accounts++
			case isOrganisation:
				organisations++
			default:
				neither++
			}
		}
	})
	if accounts == 0 || organisations == 0 || neither == 0 {
		t.Fatalf("accounts=%d organisations=%d neither=%d; every count must be positive", accounts, organisations, neither)
	}
	t.Logf("accounts=%d organisations=%d neither=%d", accounts, organisations, neither)
}

// TestTenantOfPrefix: a pattern's literal prefix names the account only
// when it runs through the ARN's fifth field and the colon after it; an
// account written up to the colon could still run on. An account or an
// organisation claim pins through exact values alone.
func TestTenantOfPrefix(t *testing.T) {
	const id = "111122223333"
	checkTenancy(t, "TenantOfPrefix", TenantOfPrefix, []tenancyCase{
		{"aws:principalarn", "arn:aws:iam::" + id + ":", account(id), true},
		{"aws:principalarn", "arn:aws:iam::" + id + ":role/", account(id), true},
		{"aws:principalarn", "arn:aws:sts::" + id + ":federated-user/", account(id), true},
		{"aws:principalarn", "arn:aws:iam::" + id, Tenant{}, false},
		{"aws:principalarn", "arn:aws:iam::11112222333", Tenant{}, false},
		{"aws:principalarn", "arn:aws:iam::", Tenant{}, false},
		{"aws:principalarn", "arn:", Tenant{}, false},
		{"aws:principalarn", "", Tenant{}, false},
		{"aws:principalaccount", id, Tenant{}, false},
		{"aws:principalorgid", "o-a1b2c3d4e5", Tenant{}, false},
		{"sts:externalid", "arn:aws:iam::" + id + ":", Tenant{}, false},
	})
}

// notTenancy are the claims of the pseudo-issuer that describe a caller and
// name no tenant, so that no classifier asks them for one, in sorted order:
//
//   - aws:PrincipalType names a kind of caller. AWS: "Use this key to
//     compare the type of principal making the request with the principal
//     type that you specify in the policy." (the global condition keys page)
//   - sts:ExternalId is a value the caller sends. AWS: "Use this key to
//     require that a principal provide a specific identifier when assuming
//     an IAM role."
//     (https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_iam-condition-keys.html),
//     and of the parameter, "This value can be any string, such as a
//     passphrase or account number."
//     (https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html).
//     Under "Principal": {"AWS": "*"} it admits anyone with an AWS account
//     who sends it, whatever it spells.
var notTenancy = []trust.ClaimKey{"aws:principaltype", "sts:externalid"}

// TestTenancyClaimsPartitionTheIdentityKeys: every key the parser reads as
// a claim of the pseudo-issuer is either a tenancy claim or one of the
// claims above that name none, and nothing else is a tenancy claim. A
// tenancy claim the parser read as request context would be Unknown on
// every grant and pin nothing, a fact that looked alive and was not.
func TestTenancyClaimsPartitionTheIdentityKeys(t *testing.T) {
	tenancy := TenancyClaims()
	for _, list := range [][]trust.ClaimKey{tenancy, notTenancy} {
		if len(list) == 0 || !slices.IsSorted(list) || len(slices.Compact(slices.Clone(list))) != len(list) {
			t.Fatalf("%v: want a sorted list of distinct claims", list)
		}
	}
	recorded := map[string]bool{}
	for _, c := range slices.Concat(tenancy, notTenancy) {
		if recorded[string(c)] {
			t.Errorf("%s is recorded both as naming a tenant and as naming none", c)
		}
		recorded[string(c)] = true
	}
	if !maps.Equal(recorded, identityKeys) {
		t.Errorf("recorded %v; the parser reads %v as claims of %s", slices.Sorted(maps.Keys(recorded)), slices.Sorted(maps.Keys(identityKeys)), AWSPrincipalIssuer)
	}
	for _, c := range notTenancy {
		if _, names := TenantOfValue(c, "111122223333"); names {
			t.Errorf("%s names a tenant", c)
		}
	}
	want := []trust.ClaimKey{"aws:principalaccount", "aws:principalarn", "aws:principalorgid"}
	if !slices.Equal(tenancy, want) {
		t.Errorf("TenancyClaims() = %v, want %v", tenancy, want)
	}
	// The list is the caller's to keep: changing it changes no fact.
	tenancy[0] = "sub"
	if TenancyClaims()[0] != "aws:principalaccount" {
		t.Errorf("a caller's copy reached the facts")
	}
}

// tenantOfConstraint is what a classifier reads, through eval's view, from
// one claim's constraint: an exact value names what it names, a pattern
// what its literal prefix names, and anything else nothing. The rules for
// unions and intersections are the classifier's; these tests put one value
// or one pattern on a claim.
func tenantOfConstraint(claim trust.ClaimKey, s eval.StringSet) (Tenant, bool) {
	switch sh := eval.ShapeOf(s); sh.Kind {
	case eval.ShapeExact:
		return TenantOfValue(claim, sh.Text)
	case eval.ShapeGlob:
		return TenantOfPrefix(claim, eval.LiteralPrefix(sh.Text))
	}
	return Tenant{}, false
}

// TestTenancyFactsReadTheParsedTerms puts the facts to the terms the parser
// writes: the claims the facts name are the claims a principal and its
// conditions constrain, spelled as the parser spells them. A fact keyed on
// "aws:PrincipalOrgID" as AWS prints it would never meet the folded claim.
func TestTenancyFactsReadTheParsedTerms(t *testing.T) {
	const id = "111122223333"
	anyone := func(condition string) string {
		return statement(`"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "sts:AssumeRole", "Condition": ` + condition)
	}
	cases := []struct {
		name string
		raw  string
		want map[trust.ClaimKey]Tenant // the claims that name a tenant; every other claim of the term names none
	}{
		{"an account principal", statement(`"Effect": "Allow", "Principal": {"AWS": "` + id + `"}, "Action": "sts:AssumeRole"`),
			map[trust.ClaimKey]Tenant{"aws:principalaccount": account(id)}},
		{"a role principal", statement(`"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::` + id + `:role/deploy"}, "Action": "sts:AssumeRole"`),
			map[trust.ClaimKey]Tenant{"aws:principalaccount": account(id), "aws:principalarn": account(id)}},
		{"a role session principal", statement(`"Effect": "Allow", "Principal": {"AWS": "arn:aws:sts::` + id + `:assumed-role/deploy/s"}, "Action": "sts:AssumeRole"`),
			map[trust.ClaimKey]Tenant{"aws:principalaccount": account(id)}},
		{"an organisation", anyone(`{"StringEquals": {"aws:PrincipalOrgID": "o-a1b2c3d4e5"}}`),
			map[trust.ClaimKey]Tenant{"aws:principalorgid": organisation("o-a1b2c3d4e5")}},
		{"an account by condition", anyone(`{"StringEquals": {"AWS:PRINCIPALACCOUNT": "` + id + `"}}`),
			map[trust.ClaimKey]Tenant{"aws:principalaccount": account(id)}},
		{"roles of an account by pattern", anyone(`{"StringLike": {"aws:PrincipalArn": "arn:aws:iam::` + id + `:role/*"}}`),
			map[trust.ClaimKey]Tenant{"aws:principalarn": account(id)}},
		{"a pattern cut inside the account", anyone(`{"StringLike": {"aws:PrincipalArn": "arn:aws:iam::11112222333?:role/*"}}`),
			map[trust.ClaimKey]Tenant{}},
		{"an account after a wildcard", anyone(`{"StringLike": {"aws:PrincipalArn": "arn:*:iam::` + id + `:role/deploy"}}`),
			map[trust.ClaimKey]Tenant{}},
		{"an external id spelled like an account", anyone(`{"StringEquals": {"sts:ExternalId": "` + id + `"}}`),
			map[trust.ClaimKey]Tenant{}},
		{"a principal type", anyone(`{"StringEquals": {"aws:PrincipalType": "AssumedRole"}}`),
			map[trust.ClaimKey]Tenant{}},
	}
	for _, c := range cases {
		g := awsFace(t, c.raw)
		terms := g.Admits.Terms()
		if len(terms) != 1 || len(terms[0]) == 0 {
			t.Fatalf("%s: %s, want one term with a constraint", c.name, g.Admits)
		}
		got := map[trust.ClaimKey]Tenant{}
		for claim, s := range terms[0] {
			if tenant, names := tenantOfConstraint(claim, s); names {
				got[claim] = tenant
			}
		}
		if !maps.Equal(got, c.want) {
			t.Errorf("%s: %s names %v, want %v", c.name, g.Admits, got, c.want)
		}
	}
}

// genARNPrefix draws the front of something shaped like an ARN: six
// fields, each the value an ARN has there or one it must not have, cut at
// any point. It is where a rule that read the wrong field, or a field not
// yet closed, would name a tenant. The cut is a distance from the end,
// mostly short enough to keep the colon that closes the account field, the
// case a pin needs, and sometimes long enough to cut into any field.
func genARNPrefix() *rapid.Generator[string] {
	return rapid.Custom(func(t *rapid.T) string {
		field := func(label string, choices ...string) string { return rapid.SampledFrom(choices).Draw(t, label) }
		arn := strings.Join([]string{
			field("scheme", "arn", "xrn"),
			field("partition", "aws", "aws-cn", ""),
			field("service", "iam", "sts", "s3"),
			field("region", "", "us-east-1"),
			field("account", "111122223333", "444455556666", "11112222333", "", "o-a1b2c3d4e5"),
			field("resource", "role/x", "root", "a:b", ""),
		}, ":")
		back := rapid.SampledFrom([]int{0, 1, 2, 3, 5, 7, 12, 20, 30}).Draw(t, "cut from the end")
		return arn[:max(0, len(arn)-back)]
	})
}

// TestTenantOfPrefixHoldsForEveryValueItBegins is the law a pin rests on:
// when a prefix names a tenant, every value that begins with it names the
// same one. A classifier pins a pattern by its literal prefix and never
// sees the values the pattern admits; this is why it need not.
func TestTenantOfPrefixHoldsForEveryValueItBegins(t *testing.T) {
	suffix := rapid.StringOfN(rapid.SampledFrom([]rune("1:/xo-")), 0, 16, -1)
	pinned, open := 0, 0
	rapid.Check(t, func(t *rapid.T) {
		for _, prefix := range rapid.SliceOfN(genARNPrefix(), 4, 4).Draw(t, "prefixes") {
			claim := arnClaim
			if rapid.Bool().Draw(t, "another claim") {
				claim = rapid.SampledFrom(slices.Concat(TenancyClaims(), notTenancy)).Draw(t, "claim")
			}
			tenant, names := TenantOfPrefix(claim, prefix)
			if !names {
				open++
				continue
			}
			pinned++
			for _, s := range rapid.SliceOfN(suffix, 1, 4).Draw(t, "suffixes") {
				if got, ok := TenantOfValue(claim, prefix+s); !ok || got != tenant {
					t.Fatalf("TenantOfPrefix(%s, %q) = %+v, but the value %q names %+v, %v", claim, prefix, tenant, prefix+s, got, ok)
				}
			}
		}
	})
	if pinned == 0 || open == 0 {
		t.Fatalf("pinned=%d open=%d; both must be positive", pinned, open)
	}
	t.Logf("pinned=%d open=%d", pinned, open)
}

// TestTenancyNamesOnlyTheMintedAccount is the soundness oracle at this
// seam, in the form of the classifier's own: principal ARNs are minted
// for accounts that differ from one another in a single digit, and every
// prefix of every minted ARN names either nothing or the account it was
// minted for. The account is known because the test minted it; nothing is
// parsed back to find it.
func TestTenancyNamesOnlyTheMintedAccount(t *testing.T) {
	accounts := []string{"111122223333", "111122223334", "011122223333"}
	resources := []string{"root", "role/deploy", "role/path/to/deploy", "user/alice", "role/a:b"}
	pinned, open := 0, 0
	rapid.Check(t, func(t *rapid.T) {
		acct := rapid.SampledFrom(accounts).Draw(t, "account")
		service, resource := "iam", rapid.SampledFrom(resources).Draw(t, "resource")
		if rapid.Bool().Draw(t, "federated") {
			service, resource = "sts", "federated-user/bob"
		}
		arn := "arn:" + rapid.SampledFrom([]string{"aws", "aws-cn", "aws-us-gov"}).Draw(t, "partition") + ":" + service + "::" + acct + ":" + resource
		if got, ok := TenantOfValue(arnClaim, arn); !ok || got != account(acct) {
			t.Fatalf("TenantOfValue(%s, %q) = %+v, %v; want the account it was minted for", arnClaim, arn, got, ok)
		}
		for i := range len(arn) + 1 {
			tenant, names := TenantOfPrefix(arnClaim, arn[:i])
			switch {
			case !names:
				open++
			case tenant == account(acct):
				pinned++
			default:
				t.Fatalf("the prefix %q of %q names %+v; it was minted for %s", arn[:i], arn, tenant, acct)
			}
		}
	})
	if pinned == 0 || open == 0 {
		t.Fatalf("pinned=%d open=%d; both must be positive", pinned, open)
	}
	t.Logf("pinned=%d open=%d", pinned, open)
}
