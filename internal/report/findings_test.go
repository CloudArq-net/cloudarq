package report

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"strings"
	"testing"
)

const (
	bundleAccount = "123456789012"
	githubTrust   = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Federated":"arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"},"Action":"sts:AssumeRoleWithWebIdentity","Condition":{"StringEquals":{"token.actions.githubusercontent.com:aud":"sts.amazonaws.com"},"StringLike":{"token.actions.githubusercontent.com:sub":"repo:acme/*"}}}]}`
	serviceTrust  = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}`
)

type testRole struct{ name, document string }

// bundleOf writes a bundle as cloudarq-collect does, its roles across pages of two.
func bundleOf(t *testing.T, edit func(map[string]any), roles ...testRole) []byte {
	t.Helper()
	var pages []any
	for start := 0; start < len(roles); start += 2 {
		var page []any
		for _, r := range roles[start:min(start+2, len(roles))] {
			page = append(page, map[string]any{
				"Path": "/", "RoleName": r.name, "RoleId": "AROA" + strings.ToUpper(r.name),
				"Arn": "arn:aws:iam::" + bundleAccount + ":role/" + r.name, "CreateDate": "2024-01-02T03:04:05Z",
				"AssumeRolePolicyDocument": r.document,
			})
		}
		pages = append(pages, map[string]any{"Roles": page, "IsTruncated": start+2 < len(roles)})
	}
	if pages == nil {
		pages = []any{}
	}
	b := map[string]any{
		"format": "cloudarq.collect/v1", "provider": "aws", "account": bundleAccount, "partition": "aws", "alias": "production",
		"collected_at": "2026-10-02T18:00:00Z", "collector": "cloudarq-collect 0.2.0", "pages": pages,
		"refused": []any{map[string]any{"call": "iam:ListAccountAliases", "code": "AccessDenied", "message": "not authorized"}},
		"limits":  []any{},
	}
	if edit != nil {
		edit(b)
	}
	raw, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

type findingsShape struct {
	Format       string  `json:"format"`
	Error        string  `json:"error"`
	Provider     string  `json:"provider"`
	Account      string  `json:"account"`
	Alias        *string `json:"alias"`
	CollectedAt  *string `json:"collected_at"`
	Collector    *string `json:"collector"`
	Engine       string  `json:"engine"`
	BundleSHA256 string  `json:"bundle_sha256"`
	Roles        []struct {
		Arn            string          `json:"arn"`
		Name           string          `json:"name"`
		DocumentSHA256 string          `json:"document_sha256"`
		Answer         json.RawMessage `json:"answer"`
	} `json:"roles"`
	Refused []BundleRefusal `json:"refused"`
	Limits  []string        `json:"limits"`
}

func findingsOf(t *testing.T, bundle []byte, owners string) findingsShape {
	t.Helper()
	raw := Findings(bundle, []byte(owners), "cloudarq test")
	var f findingsShape
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatalf("the findings are not JSON: %v\n%s", err, raw)
	}
	return f
}

func hexOf(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func TestEachRoleIsAnsweredAsAdmitsForAnswersItsPolicyAlone(t *testing.T) {
	bundle := bundleOf(t, nil, testRole{"deploy", githubTrust}, testRole{"worker", serviceTrust}, testRole{"broken", "not json"})
	for _, owners := range []string{"", "github:acme"} {
		f := findingsOf(t, bundle, owners)
		if f.Format != "cloudarq.findings/v1" || f.Error != "" || len(f.Roles) != 3 {
			t.Fatalf("owners %+q: format %s, error %s, %d roles", owners, f.Format, f.Error, len(f.Roles))
		}
		for i, document := range []string{githubTrust, serviceTrust, "not json"} {
			role := f.Roles[i]
			want := AdmitsFor([]byte(document), []byte(owners))
			if !bytes.Equal(role.Answer, want) {
				t.Errorf("owners %+q, %s: the answer is not AdmitsFor's\n got %s\nwant %s", owners, role.Name, role.Answer, want)
			}
			if role.DocumentSHA256 != hexOf([]byte(document)) {
				t.Errorf("%s: document_sha256 %s is not the policy's", role.Name, role.DocumentSHA256)
			}
		}
	}
}

func TestTheFindingsCarryTheBundlesFactsAndItsHash(t *testing.T) {
	bundle := bundleOf(t, nil, testRole{"deploy", githubTrust})
	f := findingsOf(t, bundle, "")
	if f.Provider != "aws" || f.Account != bundleAccount || *f.Alias != "production" || *f.CollectedAt != "2026-10-02T18:00:00Z" ||
		*f.Collector != "cloudarq-collect 0.2.0" || f.Engine != "cloudarq test" {
		t.Fatalf("the findings are %+v", f)
	}
	if f.BundleSHA256 != hexOf(bundle) {
		t.Fatalf("bundle_sha256 %s is not the hash of the bytes read", f.BundleSHA256)
	}
	if len(f.Refused) != 1 || f.Refused[0] != (BundleRefusal{Call: "iam:ListAccountAliases", Code: "AccessDenied", Message: "not authorized"}) || len(f.Limits) != 0 {
		t.Fatalf("refused %+v, limits %+v", f.Refused, f.Limits)
	}
	if f.Roles[0].Arn != "arn:aws:iam::"+bundleAccount+":role/deploy" || f.Roles[0].Name != "deploy" {
		t.Fatalf("role %+v", f.Roles[0])
	}
}

func TestAnAbsentAliasAndAnEmptyAccountAreWrittenAsSuch(t *testing.T) {
	raw := Findings(bundleOf(t, func(b map[string]any) { b["alias"] = nil; delete(b, "collector") }), nil, "cloudarq test")
	for _, member := range []string{`"alias":null`, `"collector":null`, `"roles":[]`, `"limits":[]`} {
		if !bytes.Contains(raw, []byte(member)) {
			t.Errorf("the findings lack %s:\n%s", member, raw)
		}
	}
}

func TestTheSameBundleGivesTheSameBytes(t *testing.T) {
	bundle := bundleOf(t, nil, testRole{"deploy", githubTrust}, testRole{"worker", serviceTrust})
	first := Findings(bundle, []byte("github:acme"), "cloudarq test")
	for i := 0; i < 20; i++ {
		if again := Findings(bundle, []byte("github:acme"), "cloudarq test"); !bytes.Equal(first, again) {
			t.Fatalf("run %d differs:\n%s\n%s", i, first, again)
		}
	}
	if appended := AppendFindings([]byte("x"), bundle, []byte("github:acme"), "cloudarq test"); !bytes.Equal(appended, append([]byte("x"), first...)) {
		t.Fatal("AppendFindings does not append what Findings renders")
	}
}

func TestABundleThisDoesNotReadIsRefusedInWordsAndAnswersNothing(t *testing.T) {
	stranger := bytes.Replace(bundleOf(t, nil, testRole{"deploy", githubTrust}),
		[]byte("arn:aws:iam::123456789012:role/deploy"), []byte("arn:aws:iam::999999999999:role/deploy"), 1)
	cases := []struct {
		name   string
		bundle []byte
		says   string
	}{
		{"not JSON", []byte("PK\x03\x04 a zip"), "this file is not a CloudArq bundle ("},
		{"no format", bundleOf(t, func(b map[string]any) { delete(b, "format") }), "it names no format"},
		{"a newer format", bundleOf(t, func(b map[string]any) { b["format"] = "cloudarq.collect/v2" }), `this bundle's format is "cloudarq.collect/v2", and this engine reads cloudarq.collect/v1`},
		{"another cloud", bundleOf(t, func(b map[string]any) { b["provider"] = "gcp" }), `this bundle is of "gcp"`},
		{"not an account", bundleOf(t, func(b map[string]any) { b["account"] = "12345" }), `account "12345" is not an AWS account ID`},
		{"no partition", bundleOf(t, func(b map[string]any) { b["partition"] = "" }), "is not an AWS partition"},
		{"a stranger's role", stranger, `the role "arn:aws:iam::999999999999:role/deploy" is not a role of account 123456789012`},
		{"a role twice", bundleOf(t, nil, testRole{"deploy", githubTrust}, testRole{"deploy", serviceTrust}), "appears twice"},
		{"too large", append(bundleOf(t, nil), bytes.Repeat([]byte(" "), MaxBundleBytes)...), "larger than 64 MB"},
	}
	for _, c := range cases {
		f := findingsOf(t, c.bundle, "")
		if f.Format != "cloudarq.findings/v1" || !strings.Contains(f.Error, c.says) || f.Roles != nil || f.Account != "" {
			t.Errorf("%s: format %s, error %q, roles %v", c.name, f.Format, f.Error, f.Roles)
		}
	}
}

func TestMoreRolesThanIAMHoldsIsNotOneAccount(t *testing.T) {
	roles := make([]testRole, MaxBundleRoles+1)
	for i := range roles {
		roles[i] = testRole{name: "r" + strconv.Itoa(i), document: serviceTrust}
	}
	if f := findingsOf(t, bundleOf(t, nil, roles...), ""); !strings.Contains(f.Error, "holds 5001 roles, more than the 5000 IAM holds") {
		t.Fatalf("error %q", f.Error)
	}
}

func TestARoleWithNoPolicyIsAnsweredAsAnEmptyOne(t *testing.T) {
	bundle := bundleOf(t, func(b map[string]any) {
		page := b["pages"].([]any)[0].(map[string]any)
		delete(page["Roles"].([]any)[0].(map[string]any), "AssumeRolePolicyDocument")
	}, testRole{"bare", serviceTrust})
	f := findingsOf(t, bundle, "")
	if !bytes.Equal(f.Roles[0].Answer, AdmitsFor(nil, nil)) || f.Roles[0].DocumentSHA256 != hexOf(nil) {
		t.Fatalf("the role with no policy is answered %s, %s", f.Roles[0].Answer, f.Roles[0].DocumentSHA256)
	}
}
