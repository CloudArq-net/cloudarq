package trust

import "testing"

func TestClaimKeepsTheIssuersSpelling(t *testing.T) {
	for _, name := range []string{
		"sub", "aud", "repository_id", "repository_owner_id", "job_workflow_ref",
		"spaceId", "callerType", // Spacelift issues camelCase claims
		"oidc.circleci.com/project-id",
		"http://schemas.microsoft.com/identity/claims/tenantid",
	} {
		got, ok := Claim(name)
		if !ok || string(got) != name {
			t.Errorf("Claim(%q) = (%q, %v), want the name itself", name, got, ok)
		}
	}
	// A key that differs in case names a claim no token carries.
	a, _ := Claim("spaceId")
	b, _ := Claim("spaceid")
	if a == b {
		t.Errorf("Claim folded case: %q == %q", a, b)
	}
}

func TestClaimRefusesWhatIsNotAName(t *testing.T) {
	for _, name := range []string{"", " ", "sub ", " sub", "repository id", "a\tb", "a\nb"} {
		if got, ok := Claim(name); ok {
			t.Errorf("Claim(%q) = (%q, true), want refused", name, got)
		}
	}
}

func TestNormaliseIssuer(t *testing.T) {
	cases := []struct {
		raw  string
		want IssuerRef
		ok   bool
	}{
		{"https://token.actions.githubusercontent.com", "https://token.actions.githubusercontent.com", true},
		{"https://token.actions.githubusercontent.com/", "https://token.actions.githubusercontent.com", true},
		{"token.actions.githubusercontent.com", "https://token.actions.githubusercontent.com", true},
		{"HTTPS://Token.Actions.GitHubUserContent.com/", "https://token.actions.githubusercontent.com", true},
		{"http://gitlab.example.com:8443/", "https://gitlab.example.com:8443", true},
		// A path is part of the issuer's identity and keeps its case.
		{"https://oidc.circleci.com/org/2C3F7A0E/", "https://oidc.circleci.com/org/2C3F7A0E", true},
		{"https://app.harness.io/ng/api/oidc/account/AbC123", "https://app.harness.io/ng/api/oidc/account/AbC123", true},
		// No host, no issuer.
		{"", "", false},
		{"/", "", false},
		{"https://", "", false},
		{"https:///org/x", "", false},
	}
	for _, c := range cases {
		got, ok := NormaliseIssuer(c.raw)
		if ok != c.ok || got != c.want {
			t.Errorf("NormaliseIssuer(%q) = (%q, %v), want (%q, %v)", c.raw, got, ok, c.want, c.ok)
		}
	}
}
