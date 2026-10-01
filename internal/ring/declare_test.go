package ring

import (
	"slices"
	"strconv"
	"strings"
	"testing"
)

func texts(ds []Declaration) []string {
	out := make([]string, len(ds))
	for i, d := range ds {
		out[i] = d.String()
	}
	return out
}

// TestReadDeclarations holds the declaration syntax: one owner per line in
// the namespaces an owner is declared in, normalised, sorted and
// deduplicated, and every other line refused alone with the reason, which
// internal/report words.
func TestReadDeclarations(t *testing.T) {
	type refusal struct {
		line   int
		reason Reason
	}
	cases := []struct {
		name    string
		text    string
		owners  []string
		refused []refusal
	}{
		{"nothing", "", nil, nil},
		{"blank lines only", "\n  \n\t\n", nil, nil},
		{"one owner", "github:acme", []string{"github:acme"}, nil},
		{"trailing newline and carriage return", "github:acme\r\n", []string{"github:acme"}, nil},
		{"surrounding spaces", "  github:acme \t", []string{"github:acme"}, nil},
		{"namespace in any case", "GitHub:acme", []string{"github:acme"}, nil},
		{"a name keeps its case", "github:Acme", []string{"github:Acme"}, nil},
		{"deduplicated", "github:acme\ngithub:acme\nGITHUB:acme", []string{"github:acme"}, nil},
		{"sorted by text", "github:zeta\naws:111122223333\ngithub:acme", []string{"aws:111122223333", "github:acme", "github:zeta"}, nil},
		{"name and id", "github:acme@123456", []string{"github:acme@123456"}, nil},
		{"id alone", "github:@123456", []string{"github:@123456"}, nil},
		{"an account", "aws:111122223333", []string{"aws:111122223333"}, nil},
		{"an organisation", "aws:o-a1b2c3d4e5", []string{"aws:o-a1b2c3d4e5"}, nil},
		{"a SAML provider", "saml:arn:aws:iam::111122223333:saml-provider/Name", []string{"saml:arn:aws:iam::111122223333:saml-provider/Name"}, nil},
		{"an issuer, normalised", "issuer:HTTPS://OIDC.EKS.us-east-1.amazonaws.com/id/ABC/", []string{"issuer:https://oidc.eks.us-east-1.amazonaws.com/id/ABC"}, nil},
		{"no namespace", "acme", nil, []refusal{{1, NoNamespace}}},
		{"an unknown namespace", "bitbucket:acme", nil, []refusal{{1, UnknownNamespace}}},
		{"GitLab", "gitlab:acme/sub", nil, []refusal{{1, ClaimsNotRead}}},
		{"HCP Terraform", "terraform:acme", nil, []refusal{{1, ClaimsNotRead}}},
		{"Buildkite", "buildkite:acme", nil, []refusal{{1, ClaimsNotRead}}},
		{"no owner", "github:", nil, []refusal{{1, NoOwner}}},
		{"a repository", "github:acme/infra", nil, []refusal{{1, ARepository}}},
		{"a colon in a name", "github:acme:x", nil, []refusal{{1, NotAGitHubOwner}}},
		{"a space in a name", "github:ac me", nil, []refusal{{1, NotAGitHubOwner}}},
		{"a control character in a name", "github:ac\x01me", nil, []refusal{{1, NotAGitHubOwner}}},
		// which characters beyond ASCII are printable is the toolchain's
		// Unicode version: U+A7CB was assigned in Unicode 16
		{"a letter beyond ASCII in a name", "github:acm\u00e9", nil, []refusal{{1, NotAGitHubOwner}}},
		{"a letter newer than some toolchains in a name", "github:acme\ua7cb", nil, []refusal{{1, NotAGitHubOwner}}},
		{"an empty id", "github:acme@", nil, []refusal{{1, NotAGitHubOwner}}},
		{"an id that is not a number", "github:acme@12a", nil, []refusal{{1, NotAGitHubOwner}}},
		{"only the separator", "github:@", nil, []refusal{{1, NotAGitHubOwner}}},
		{"two separators", "github:acme@1@2", nil, []refusal{{1, NotAGitHubOwner}}},
		{"an account one digit short", "aws:11112222333", nil, []refusal{{1, NotAnAWSID}}},
		{"an organisation in upper case", "aws:O-A1B2C3D4E5", nil, []refusal{{1, NotAnAWSID}}},
		{"an ARN where an account belongs", "aws:arn:aws:iam::111122223333:root", nil, []refusal{{1, NotAnAWSID}}},
		{"a role where a SAML provider belongs", "saml:arn:aws:iam::111122223333:role/x", nil, []refusal{{1, NotASAMLProvider}}},
		{"an issuer without https", "issuer:http://oidc.example.com", nil, []refusal{{1, NotAnIssuerURL}}},
		{"an issuer with no host", "issuer:https://", nil, []refusal{{1, NotAnIssuerURL}}},
		{"an issuer with a space", "issuer:https://oidc.example.com/a b", nil, []refusal{{1, NotAnIssuerURL}}},
		{"an issuer with a wildcard", "issuer:https://*.app.spacelift.io", nil, []refusal{{1, NotAnIssuerURL}}},
		// the parser reads a provider whose host holds a Kelvin sign as no
		// provider, so a declaration that folded it onto the ASCII host would
		// name a cluster no policy's look-alike principal ever reaches, and
		// echo the ASCII host as what the user wrote
		{"an issuer spelled to fold onto another", "issuer:https://oidc.e\u212as.us-east-1.amazonaws.com/id/ABC", nil, []refusal{{1, NotAnIssuerURL}}},
		{"not UTF-8", "github:ac\xffme", nil, []refusal{{1, NotUTF8}}},
		{"refused lines beside good ones, numbered as written", "github:acme\n\ngitlab:x\naws:111122223333\nnope", []string{"aws:111122223333", "github:acme"}, []refusal{{3, ClaimsNotRead}, {5, NoNamespace}}},
		{"a refused line echoed with its spaces", "  gitlab:x \t", nil, []refusal{{1, ClaimsNotRead}}},
	}
	for _, c := range cases {
		got := ReadDeclarations(c.text)
		if got.Overrun != nil {
			t.Errorf("%s: ReadDeclarations(%q) refused the whole input: %+v", c.name, c.text, got.Overrun)
			continue
		}
		if owners := texts(got.Owners); !slices.Equal(owners, c.owners) {
			t.Errorf("%s: ReadDeclarations(%q) owners = %q, want %q", c.name, c.text, owners, c.owners)
		}
		if len(got.Refused) != len(c.refused) {
			t.Errorf("%s: ReadDeclarations(%q) refused %+v, want %+v", c.name, c.text, got.Refused, c.refused)
			continue
		}
		for i, r := range got.Refused {
			if r.Line != c.refused[i].line || r.Reason != c.refused[i].reason {
				t.Errorf("%s: refusal %d is line %d for %v; want line %d for %v", c.name, i, r.Line, r.Reason, c.refused[i].line, c.refused[i].reason)
			}
			lines := strings.Split(c.text, "\n")
			if r.Text != strings.TrimRight(lines[r.Line-1], "\r") {
				t.Errorf("%s: refusal %d echoes %q, want the line as written, %q", c.name, i, r.Text, lines[r.Line-1])
			}
		}
	}
}

// TestReasonIDs pins the id of every reason, which the answer carries and
// a reader of it keys on; a reason no table holds says so.
func TestReasonIDs(t *testing.T) {
	var got []string
	for r := NoReason; r <= NotAnIssuerURL; r++ {
		got = append(got, r.String())
	}
	want := []string{"none", "not-utf-8", "no-namespace", "unknown-namespace", "claims-not-read", "no-owner", "a-repository", "not-a-github-owner", "not-an-aws-id", "not-a-saml-provider", "not-an-issuer-url"}
	if !slices.Equal(got, want) || Reason(11).String() != "reason(11)" {
		t.Errorf("reason ids %q, want %q", got, want)
	}
}

// TestDeclarationFields: each declaration carries the typed owner it names,
// the fields a pin is matched against.
func TestDeclarationFields(t *testing.T) {
	got := ReadDeclarations("github:acme@123456\ngithub:beta\ngithub:@7\naws:111122223333\naws:o-a1b2c3d4e5\nsaml:arn:aws:iam::111122223333:saml-provider/Name\nissuer:https://oidc.example.com")
	if got.Overrun != nil {
		t.Fatalf("%+v", got.Overrun)
	}
	want := []Declaration{
		{Namespace: NamespaceAWS, Scope: ScopeAccount, Value: "111122223333"},
		{Namespace: NamespaceAWS, Scope: ScopeOrganisation, Value: "o-a1b2c3d4e5"},
		{Namespace: NamespaceGitHub, Scope: ScopeOwner, ID: "7"},
		{Namespace: NamespaceGitHub, Scope: ScopeOwner, Name: "acme", ID: "123456"},
		{Namespace: NamespaceGitHub, Scope: ScopeOwner, Name: "beta"},
		{Namespace: NamespaceIssuer, Scope: ScopeTenant, Value: "https://oidc.example.com"},
		{Namespace: NamespaceSAML, Scope: ScopeProvider, Value: "arn:aws:iam::111122223333:saml-provider/Name"},
	}
	if !slices.Equal(got.Owners, want) {
		t.Fatalf("owners\n got %+v\nwant %+v", got.Owners, want)
	}
}

// TestDeclarationBounds: past any bound the whole input is refused, as a
// document past its bound is, with the bound it went past and by how much,
// which internal/report words; at the bound it is read.
func TestDeclarationBounds(t *testing.T) {
	line := func(n int) string { return "github:" + strings.Repeat("a", n-len("github:")) }
	lines := func(n int) string {
		var b strings.Builder
		for i := range n {
			b.WriteString("github:o" + strconv.Itoa(i) + "\n")
		}
		return b.String()
	}
	within := []string{
		line(MaxDeclarationLineBytes),
		lines(MaxDeclarationLines),
		strings.Repeat(line(MaxDeclarationLineBytes-1)+"\n", MaxDeclarationBytes/MaxDeclarationLineBytes)[:MaxDeclarationBytes],
	}
	for _, text := range within {
		if got := ReadDeclarations(text); got.Overrun != nil {
			t.Errorf("a declaration of %d bytes and %d lines was refused: %+v", len(text), strings.Count(text, "\n"), got.Overrun)
		}
	}
	tooManyBytes := strings.Repeat(line(MaxDeclarationLineBytes-1)+"\n", MaxDeclarationBytes/MaxDeclarationLineBytes+1)
	beyond := map[string]struct {
		text string
		want Overrun
	}{
		"a line past its bound":                   {line(MaxDeclarationLineBytes + 1), Overrun{Bound: LineBytes, Line: 1, Size: MaxDeclarationLineBytes + 1}},
		"too many lines":                          {lines(MaxDeclarationLines + 1), Overrun{Bound: DeclarationLines, Size: MaxDeclarationLines + 1}},
		"too many bytes":                          {tooManyBytes, Overrun{Bound: DeclarationBytes, Size: len(tooManyBytes)}},
		"a long line beside one":                  {"github:acme\n" + line(MaxDeclarationLineBytes+1), Overrun{Bound: LineBytes, Line: 2, Size: MaxDeclarationLineBytes + 1}},
		"a long line ending in a carriage return": {"github:acme\r\n" + line(MaxDeclarationLineBytes+1) + "\r\n", Overrun{Bound: LineBytes, Line: 2, Size: MaxDeclarationLineBytes + 1}},
	}
	for name, c := range beyond {
		got := ReadDeclarations(c.text)
		if got.Overrun == nil || *got.Overrun != c.want || got.Owners != nil || got.Refused != nil {
			t.Errorf("%s: read as %+v, %d owners and %d refusals, want the whole input refused past %+v", name, got.Overrun, len(got.Owners), len(got.Refused), c.want)
		}
	}
}

// TestSpelledLike: a declaration is spelled like an owner when it is that
// owner's declaration in another letter case, which is the one miss a
// user can mend by changing letters: names compare exactly. The owner's
// own declaration, another owner's, and an owner that cannot be declared
// are not.
func TestSpelledLike(t *testing.T) {
	acme := Owner{Issuer: githubIssuer, Namespace: NamespaceGitHub, Scope: ScopeOwner, Kind: KindName, Value: "acme"}
	repository := Owner{Issuer: githubIssuer, Namespace: NamespaceGitHub, Scope: ScopeRepository, Kind: KindID, Value: "456789"}
	for text, want := range map[string]bool{
		"github:Acme":      true,
		"github:ACME":      true,
		"github:acme":      false,
		"github:acme-evil": false,
		"github:@456789":   false,
	} {
		d := declare(t, text)[0]
		if got := d.SpelledLike(acme); got != want {
			t.Errorf("%s spelled like github:acme: %v, want %v", text, got, want)
		}
		if d.SpelledLike(repository) {
			t.Errorf("%s spelled like a repository, which has no declaration", text)
		}
	}
}
