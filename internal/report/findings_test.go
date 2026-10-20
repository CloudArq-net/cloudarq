package report

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"

	"pgregory.net/rapid"

	"github.com/CloudArq-net/cloudarq/internal/ring"
)

const (
	bundleAccount = "123456789012"
	githubTrust   = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Federated":"arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"},"Action":"sts:AssumeRoleWithWebIdentity","Condition":{"StringEquals":{"token.actions.githubusercontent.com:aud":"sts.amazonaws.com"},"StringLike":{"token.actions.githubusercontent.com:sub":"repo:acme/*"}}}]}`
	serviceTrust  = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}`
)

// testRole is a role as its ARN names it after "role/", path and all, and
// its trust policy: "deploy" is at the path "/", and
// "aws-service-role/support.amazonaws.com/AWSServiceRoleForSupport" at
// "/aws-service-role/support.amazonaws.com/".
type testRole struct{ name, document string }

// bundleOf writes a bundle as cloudarq-collect does, its roles across pages
// of two, each with the path and the name IAM lists for the ARN it has.
func bundleOf(t *testing.T, edit func(map[string]any), roles ...testRole) []byte {
	t.Helper()
	var pages []any
	for start := 0; start < len(roles); start += 2 {
		var page []any
		for _, r := range roles[start:min(start+2, len(roles))] {
			slash := strings.LastIndexByte(r.name, '/')
			path, name := "/"+r.name[:slash+1], r.name[slash+1:]
			page = append(page, map[string]any{
				"Path": path, "RoleName": name, "RoleId": "AROA" + strings.ToUpper(name),
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
	Format       string             `json:"format"`
	Error        string             `json:"error"`
	Provider     string             `json:"provider"`
	Account      string             `json:"account"`
	Alias        *string            `json:"alias"`
	Organization *organizationShape `json:"organization"`
	Recognised   []Recognition      `json:"recognised"`
	Suggested    []suggestedShape   `json:"suggested"`
	CollectedAt  *string            `json:"collected_at"`
	Collector    *string            `json:"collector"`
	Engine       string             `json:"engine"`
	BundleSHA256 string             `json:"bundle_sha256"`
	Roles        []struct {
		Arn            string          `json:"arn"`
		Name           string          `json:"name"`
		Path           *string         `json:"path"`
		Managed        json.RawMessage `json:"managed"`
		DocumentSHA256 string          `json:"document_sha256"`
		Answer         json.RawMessage `json:"answer"`
		WouldMove      []moveShape     `json:"would_move"`
	} `json:"roles"`
	Refused []BundleRefusal `json:"refused"`
	Limits  []string        `json:"limits"`
}

type suggestedShape struct {
	Declaration string `json:"declaration"`
	Question    string `json:"question"`
	Declared    bool   `json:"declared"`
}

type moveShape struct {
	Declaration string `json:"declaration"`
	Question    string `json:"question"`
	Sentence    string `json:"sentence"`
	Spans       []Span `json:"spans"`
}

type organizationShape struct {
	Status            string `json:"status"`
	ID                string `json:"id"`
	ManagementAccount string `json:"management_account"`
	FeatureSet        string `json:"feature_set"`
}

// The Organization of the bundles below: AWS's own example ID, managed by
// an account other than the one the bundle was read from.
const (
	orgID      = "o-exampleorgid"
	management = "111122223333"
)

// organizationMember is the member cloudarq-collect writes for an account
// in orgID, managed by account; edit changes it before it is written.
func organizationMember(account string, edit func(map[string]any)) func(map[string]any) {
	return func(b map[string]any) {
		o := map[string]any{
			"status": "member", "id": orgID, "arn": "arn:aws:organizations::" + account + ":organization/" + orgID,
			"management_account": account, "management_account_arn": "arn:aws:organizations::" + account + ":account/" + orgID + "/" + account,
			"feature_set": "ALL",
		}
		if edit != nil {
			edit(o)
		}
		b["organization"] = o
	}
}

// statusOnly is the member of an account in no Organization, or of one
// whose Organization AWS refused to describe, with that refusal listed.
func statusOnly(status string) func(map[string]any) {
	return func(b map[string]any) {
		b["organization"] = map[string]any{"status": status}
		if status == "refused" {
			b["refused"] = append(b["refused"].([]any), map[string]any{"call": "organizations:DescribeOrganization", "code": "AccessDeniedException", "message": "not authorized"})
		}
	}
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

// Each role is answered as AdmitsFor answers its trust policy alone, with
// the account the bundle was read from recognised: none of these roles is
// pinned to it, so the answer is AdmitsFor's but for the echo that names
// it, and a policy that is not read, which echoes nothing, is AdmitsFor's
// whole.
func TestEachRoleIsAnsweredAsAdmitsForAnswersItsPolicyAlone(t *testing.T) {
	bundle := bundleOf(t, nil, testRole{"deploy", githubTrust}, testRole{"worker", serviceTrust}, testRole{"broken", "not json"},
		testRole{"aws-service-role/lambda.amazonaws.com/AWSServiceRoleForLambda", serviceTrust})
	for _, owners := range []string{"", "github:acme"} {
		f := findingsOf(t, bundle, owners)
		if f.Format != "cloudarq.findings/v1" || f.Error != "" || len(f.Roles) != 4 {
			t.Fatalf("owners %+q: format %s, error %s, %d roles", owners, f.Format, f.Error, len(f.Roles))
		}
		for i, document := range []string{githubTrust, serviceTrust, "not json", serviceTrust} {
			role := f.Roles[i]
			want := AdmitsFor([]byte(document), []byte(owners))
			if got := bytes.Replace(role.Answer, []byte(recognitionEchoed), nil, 1); !bytes.Equal(got, want) {
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

// listedAt is an edit that lists the bundle's first role at path, or with
// no Path member when path is nil, and leaves its ARN as it was.
func listedAt(path *string) func(map[string]any) {
	return func(b map[string]any) {
		role := b["pages"].([]any)[0].(map[string]any)["Roles"].([]any)[0].(map[string]any)
		if path == nil {
			delete(role, "Path")
			return
		}
		role["Path"] = *path
	}
}

func TestEachRoleCarriesThePathIAMListsItAt(t *testing.T) {
	longest := "/" + strings.Repeat("p", 510) + "/"
	for _, c := range []struct{ role, path string }{
		{"deploy", "/"},
		{"team/build/deploy", "/team/build/"},
		{"aws-service-role/support.amazonaws.com/AWSServiceRoleForSupport", "/aws-service-role/support.amazonaws.com/"},
		{"!~/deploy", "/!~/"},
		{longest[1:] + "deploy", longest},
	} {
		f := findingsOf(t, bundleOf(t, nil, testRole{c.role, serviceTrust}), "")
		if f.Error != "" || len(f.Roles) != 1 || f.Roles[0].Path == nil || *f.Roles[0].Path != c.path {
			t.Errorf("%s: error %q, roles %+v", c.role, f.Error, f.Roles)
		}
	}
}

// A bundle written without a role's Path was read before the engine read
// paths, under the same format, and is read still: the path is not known,
// which is null, never "/" and never a refusal.
func TestARoleListedWithNoPathIsReadAsNotKnown(t *testing.T) {
	raw := Findings(bundleOf(t, listedAt(nil), testRole{"deploy", githubTrust}), nil, "cloudarq test")
	if !bytes.Contains(raw, []byte(`"name":"deploy","path":null,`)) || bytes.Contains(raw, []byte(`"error"`)) {
		t.Fatalf("the role listed with no path is written as\n%s", raw)
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
	at := func(path, role string) []byte { return bundleOf(t, listedAt(&path), testRole{role, githubTrust}) }
	const deploy = `the role "arn:aws:iam::123456789012:role/deploy" is listed with `
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
		{"an empty path", at("", "deploy"), deploy + `the path "", which IAM does not write`},
		{"a path not opened", at("team/", "deploy"), deploy + `the path "team/", which IAM does not write`},
		{"a path not closed", at("/team", "deploy"), deploy + `the path "/team", which IAM does not write`},
		{"a space in a path", at("/te am/", "deploy"), deploy + `the path "/te am/", which IAM does not write`},
		{"a letter past ASCII in a path", at("/t\u00ebam/", "deploy"), deploy + `the path "/t\u00ebam/", which IAM does not write`},
		{"DEL in a path", at("/te\x7fam/", "deploy"), deploy + `the path "/te\x7fam/", which IAM does not write`},
		{"a path past ASCII and past 512 bytes, within 512 characters", at("/"+strings.Repeat("\u00eb", 300)+"/", "deploy"), deploy + `the path "/\u00eb\u00eb`},
		{"a path past IAM's length", at("/"+strings.Repeat("p", 511)+"/", "deploy"), deploy + "a path of 513 characters, longer than the 512 IAM allows"},
		{"a path its ARN does not name", at("/team/", "deploy"), deploy + `the path "/team/", and its ARN names the path "/"`},
		{"an ARN on a path the role is not listed at", at("/", "team/deploy"),
			`the role "arn:aws:iam::123456789012:role/team/deploy" is listed with the path "/", and its ARN names the path "/team/"`},
		{"a path that only begins the ARN's", at("/team/", "team/build/deploy"),
			`the role "arn:aws:iam::123456789012:role/team/build/deploy" is listed with the path "/team/", and its ARN names the path "/team/build/"`},
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

func TestTheOrganizationIsWrittenAsTheBundleSaysIt(t *testing.T) {
	for _, c := range []struct {
		name string
		edit func(map[string]any)
		want organizationShape
	}{
		{"a member", organizationMember(management, nil), organizationShape{Status: "member", ID: orgID, ManagementAccount: management, FeatureSet: "ALL"}},
		{"the management account itself", organizationMember(bundleAccount, nil), organizationShape{Status: "member", ID: orgID, ManagementAccount: bundleAccount, FeatureSet: "ALL"}},
		{"consolidated billing", organizationMember(management, func(o map[string]any) { o["feature_set"] = "CONSOLIDATED_BILLING" }),
			organizationShape{Status: "member", ID: orgID, ManagementAccount: management, FeatureSet: "CONSOLIDATED_BILLING"}},
		{"in no Organization", statusOnly("not-a-member"), organizationShape{Status: "not-a-member"}},
		{"refused", statusOnly("refused"), organizationShape{Status: "refused"}},
		// written before the collector read Organizations: not read, never "in none"
		{"no member", nil, organizationShape{Status: "not-read"}},
		{"a null member", func(b map[string]any) { b["organization"] = nil }, organizationShape{Status: "not-read"}},
	} {
		f := findingsOf(t, bundleOf(t, c.edit, testRole{"deploy", githubTrust}), "")
		if f.Error != "" || f.Organization == nil || *f.Organization != c.want {
			t.Errorf("%s: error %q, organization %+v", c.name, f.Error, f.Organization)
		}
	}
}

// The Organization's answer carries its management account's email
// address, a person's: carried in the organization member, under AWS's
// name for it or the bundle's, the findings never write it. This holds
// that member and nothing else: a refusal's message is written in the
// cloud's own words, as they came.
func TestTheFindingsNeverWriteTheManagementAccountsEmailAddress(t *testing.T) {
	raw := Findings(bundleOf(t, organizationMember(management, func(o map[string]any) {
		o["management_account_email"], o["MasterAccountEmail"] = "bill@example.com", "bill@example.com"
	}), testRole{"deploy", githubTrust}), nil, "cloudarq test")
	if bytes.Contains(raw, []byte("@example.com")) || bytes.Contains(raw, []byte(`"error"`)) {
		t.Fatalf("the findings are\n%s", raw)
	}
}

func TestAnOrganizationThatDoesNotHoldTogetherRefusesTheBundle(t *testing.T) {
	member := func(edit func(map[string]any)) []byte {
		return bundleOf(t, organizationMember(management, edit), testRole{"deploy", githubTrust})
	}
	const org = "this bundle's organization "
	cases := []struct {
		name   string
		bundle []byte
		says   string
	}{
		{"no status", member(func(o map[string]any) { delete(o, "status") }), org + `says "", which is none of member, not-a-member and refused`},
		{"a status AWS has no word for", member(func(o map[string]any) { o["status"] = "Member" }), org + `says "Member", which is none of member, not-a-member and refused`},
		{"an ID too short", member(func(o map[string]any) { o["id"] = "o-abc" }), org + `ID "o-abc" is not one AWS writes`},
		{"an ID in capitals", member(func(o map[string]any) { o["id"] = "o-EXAMPLEORGID" }), org + `ID "o-EXAMPLEORGID" is not one AWS writes`},
		// the ARNs agree with it, so only the ID's own pattern refuses it
		{"an ID in capitals in both ARNs", member(func(o map[string]any) {
			o["id"] = "o-EXAMPLEORGID"
			o["arn"] = "arn:aws:organizations::" + management + ":organization/o-EXAMPLEORGID"
			o["management_account_arn"] = "arn:aws:organizations::" + management + ":account/o-EXAMPLEORGID/" + management
		}), org + `ID "o-EXAMPLEORGID" is not one AWS writes`},
		{"an ID with no o-", member(func(o map[string]any) { o["id"] = "exampleorgid" }), org + `ID "exampleorgid" is not one AWS writes`},
		{"an ID too long", member(func(o map[string]any) { o["id"] = "o-" + strings.Repeat("a", 33) }), org + `ID "o-` + strings.Repeat("a", 33) + `" is not one AWS writes`},
		{"no management account", member(func(o map[string]any) { delete(o, "management_account") }), org + `names the management account "", which is not an AWS account ID`},
		{"a management account of eleven digits", member(func(o map[string]any) { o["management_account"] = "11112222333" }), org + `names the management account "11112222333", which is not an AWS account ID`},
		{"an ARN of another organization", member(func(o map[string]any) {
			o["arn"] = "arn:aws:organizations::" + management + ":organization/o-otherorgid1"
		}),
			org + `ARN "arn:aws:organizations::111122223333:organization/o-otherorgid1" is not the ARN of o-exampleorgid, managed by 111122223333 in aws`},
		{"an ARN of another management account", member(func(o map[string]any) { o["arn"] = "arn:aws:organizations::444455556666:organization/" + orgID }),
			org + `ARN "arn:aws:organizations::444455556666:organization/o-exampleorgid" is not the ARN of o-exampleorgid`},
		{"an ARN in another partition", member(func(o map[string]any) {
			o["arn"] = "arn:aws-cn:organizations::" + management + ":organization/" + orgID
		}),
			org + `ARN "arn:aws-cn:organizations::111122223333:organization/o-exampleorgid" is not the ARN of o-exampleorgid`},
		{"a management account ARN of another account", member(func(o map[string]any) {
			o["management_account_arn"] = "arn:aws:organizations::" + management + ":account/" + orgID + "/444455556666"
		}), org + `management account's ARN "arn:aws:organizations::111122223333:account/o-exampleorgid/444455556666" is not the ARN of 111122223333 in o-exampleorgid`},
		{"no management account ARN", member(func(o map[string]any) { delete(o, "management_account_arn") }), org + `management account's ARN "" is not the ARN of 111122223333 in o-exampleorgid`},
		{"no feature set", member(func(o map[string]any) { delete(o, "feature_set") }), org + `feature set "" is not one AWS writes`},
		{"a feature set of words", member(func(o map[string]any) { o["feature_set"] = "all features" }), org + `feature set "all features" is not one AWS writes`},
		{"in none, naming one", bundleOf(t, func(b map[string]any) { b["organization"] = map[string]any{"status": "not-a-member", "id": orgID} }, testRole{"deploy", githubTrust}),
			org + `says not-a-member and names an organization`},
		{"refused, naming one", bundleOf(t, func(b map[string]any) {
			statusOnly("refused")(b)
			b["organization"].(map[string]any)["management_account"] = management
		}, testRole{"deploy", githubTrust}), org + `says refused and names an organization`},
		{"refused, with no refusal listed", bundleOf(t, func(b map[string]any) { b["organization"] = map[string]any{"status": "refused"} }, testRole{"deploy", githubTrust}),
			org + `says refused, and the bundle lists no refusal of organizations:DescribeOrganization`},
		{"read, with a refusal listed", bundleOf(t, func(b map[string]any) {
			statusOnly("refused")(b)
			organizationMember(management, nil)(b)
		}, testRole{"deploy", githubTrust}), org + `says member, and the bundle lists organizations:DescribeOrganization as refused`},
		{"not an object", bundleOf(t, func(b map[string]any) { b["organization"] = "o-exampleorgid" }, testRole{"deploy", githubTrust}), "this file is not a CloudArq bundle ("},
	}
	for _, c := range cases {
		f := findingsOf(t, c.bundle, "")
		if f.Format != "cloudarq.findings/v1" || !strings.Contains(f.Error, c.says) || f.Roles != nil || f.Account != "" {
			t.Errorf("%s: error %q, roles %v", c.name, f.Error, f.Roles)
		}
	}
}

// Trust policies of the AWS accounts a bundle's roles may trust: the
// account the scan read, its Organization's management account, every
// account in that Organization, and an account outside it.
const (
	ownAccountTrust = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:root"},"Action":"sts:AssumeRole"}]}`
	managementTrust = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111122223333:root"},"Action":"sts:AssumeRole"}]}`
	orgTrust        = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole","Condition":{"StringEquals":{"aws:PrincipalOrgID":"o-exampleorgid"}}}]}`
	strangerTrust   = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::444455556666:root"},"Action":"sts:AssumeRole"}]}`
	ownAndManaging  = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":["arn:aws:iam::111122223333:root","arn:aws:iam::123456789012:root"]},"Action":"sts:AssumeRole"}]}`
)

// roleAnswer is the answer the findings give the role at index i.
func roleAnswer(t *testing.T, f findingsShape, i int) Answer {
	t.Helper()
	return answerOf(t, f.Roles[i].Answer)
}

// ownersIn are the owners of every population of an answer's grants.
func ownersIn(a Answer) []Owner {
	var out []Owner
	for _, g := range a.Grants {
		for _, p := range g.Populations {
			out = append(out, p.Owners...)
		}
	}
	return out
}

func TestTheAccountTheScanReadIsRecognisedAsYours(t *testing.T) {
	for _, edit := range []func(map[string]any){nil, organizationMember(management, nil), statusOnly("not-a-member"), statusOnly("refused")} {
		f := findingsOf(t, bundleOf(t, edit, testRole{"admin", ownAccountTrust}), "")
		a := roleAnswer(t, f, 0)
		owners := ownersIn(a)
		if len(owners) != 1 || owners[0].Declaration != "aws:"+bundleAccount || owners[0].Declared || !owners[0].Recognised {
			t.Fatalf("organization %+v: the owners are %+v", f.Organization, owners)
		}
		if a.Headline.Sentence != "Nothing outside your company can assume this role." || !slices.Equal(a.Rings[ring.Yours].GrantNumbers, []int{1}) ||
			a.Rings[ring.Yours].Sentence != "aws:123456789012, recognised: the account this scan read, can assume this role." {
			t.Fatalf("organization %+v: the answer reads %q, and the ring of yours %+v", f.Organization, a.Headline.Sentence, a.Rings[ring.Yours])
		}
		d := a.Declarations
		if len(d.Normalised) != 0 || len(d.Unmatched) != 0 ||
			!slices.Equal(d.Recognitions, []Recognition{{Declaration: "aws:" + bundleAccount, Sentence: "recognised: the account this scan read"}}) {
			t.Fatalf("organization %+v: the echo is %+v", f.Organization, d)
		}
		if !slices.Equal(f.Recognised, []Recognition{{Declaration: "aws:" + bundleAccount, Sentence: "recognised: the account this scan read"}}) {
			t.Fatalf("organization %+v: the findings recognise %+v", f.Organization, f.Recognised)
		}
	}
}

// recognitionEchoed is the member the echo of an answer in the findings
// ends with: the account the scan read, recognised.
const recognitionEchoed = `,"recognitions":[{"declaration":"aws:123456789012","sentence":"recognised: the account this scan read"}]`

// A role whose grants no recognised owner is pinned to is answered as its
// trust policy is alone, byte for byte, but for the echo of the account
// recognised: recognising moves nothing there, and says nothing else.
func TestARoleNotPinnedToTheAccountIsAnsweredAsItsPolicyAlone(t *testing.T) {
	bundle := bundleOf(t, organizationMember(management, nil), testRole{"deploy", githubTrust}, testRole{"stranger", strangerTrust},
		testRole{"managed", managementTrust}, testRole{"org", orgTrust}, testRole{"worker", serviceTrust})
	for _, owners := range []string{"", "github:acme", "aws:444455556666"} {
		f := findingsOf(t, bundle, owners)
		for i, document := range []string{githubTrust, strangerTrust, managementTrust, orgTrust, serviceTrust} {
			got := f.Roles[i].Answer
			if bytes.Count(got, []byte(recognitionEchoed)) != 1 {
				t.Fatalf("owners %+q, %s: the account is not echoed as recognised once:\n%s", owners, f.Roles[i].Name, got)
			}
			if want := AdmitsFor([]byte(document), []byte(owners)); !bytes.Equal(bytes.Replace(got, []byte(recognitionEchoed), nil, 1), want) {
				t.Errorf("owners %+q, %s: the answer is not AdmitsFor's\n got %s\nwant %s", owners, f.Roles[i].Name, got, want)
			}
		}
	}
}

// Recognising the account is declaring it, but for the marks that say which
// it was and their words: every grant lands where it lands with the account
// declared, and every ring holds what it holds then.
func TestRecognisingTheAccountPlacesAsDeclaringItDoes(t *testing.T) {
	for _, document := range []string{ownAccountTrust, ownAndManaging} {
		recognised := roleAnswer(t, findingsOf(t, bundleOf(t, nil, testRole{"admin", document}), ""), 0)
		declared := answerOf(t, AdmitsFor([]byte(document), []byte("aws:"+bundleAccount)))
		for i := range declared.Grants {
			g, h := recognised.Grants[i], declared.Grants[i]
			if !slices.Equal(g.Placement, h.Placement) || g.PlacementState != h.PlacementState || len(g.Populations) != len(h.Populations) {
				t.Fatalf("grant %d lands at %v %s recognised, %v %s declared", i+1, g.Placement, g.PlacementState, h.Placement, h.PlacementState)
			}
			for j := range h.Populations {
				p, q := g.Populations[j], h.Populations[j]
				if p.Place != q.Place || p.State != q.State || len(p.Owners) != len(q.Owners) {
					t.Fatalf("grant %d, population %d: %+v recognised, %+v declared", i+1, j, p, q)
				}
				for k := range q.Owners {
					if o, d := p.Owners[k], q.Owners[k]; o.Declared || o.Recognised != d.Declared || o.Declaration != d.Declaration {
						t.Fatalf("grant %d, owner %d: %+v recognised, %+v declared", i+1, k, o, d)
					}
				}
			}
		}
		for i := range declared.Rings {
			if r, d := recognised.Rings[i], declared.Rings[i]; r.State != d.State || !slices.Equal(r.GrantNumbers, d.GrantNumbers) {
				t.Fatalf("%s: %s %v recognised, %s %v declared", d.Place, r.State, r.GrantNumbers, d.State, d.GrantNumbers)
			}
		}
		if recognised.Headline.Sentence != declared.Headline.Sentence {
			t.Fatalf("the headline is %q recognised, %q declared", recognised.Headline.Sentence, declared.Headline.Sentence)
		}
	}
}

func TestAnOwnerDeclaredBesideTheAccountRecognisedIsSaidToBeEach(t *testing.T) {
	a := roleAnswer(t, findingsOf(t, bundleOf(t, nil, testRole{"admin", ownAndManaging}), "aws:"+management), 0)
	if got := a.Rings[ring.Yours].Sentence; got != "aws:111122223333, declared as yours, and aws:123456789012, recognised: the account this scan read, can assume this role." {
		t.Fatalf("the ring of yours reads %q", got)
	}
}

// The account the scan read, declared too, is the reader's twice over: the
// owner is marked both ways and said to be declared, and on a role pinned
// to nothing it is never an owner that moved nothing.
func TestTheAccountRecognisedAndDeclaredIsNeverUnmatched(t *testing.T) {
	f := findingsOf(t, bundleOf(t, nil, testRole{"admin", ownAccountTrust}, testRole{"deploy", githubTrust}), "aws:"+bundleAccount+"\ngithub:other")
	admin, deploy := roleAnswer(t, f, 0), roleAnswer(t, f, 1)
	if o := ownersIn(admin); len(o) != 1 || !o[0].Declared || !o[0].Recognised {
		t.Fatalf("the account declared and recognised is %+v", o)
	}
	if got := admin.Rings[ring.Yours].Sentence; got != "aws:123456789012, declared as yours, can assume this role." {
		t.Fatalf("the ring of yours reads %q", got)
	}
	for _, a := range []Answer{admin, deploy} {
		for _, u := range a.Declarations.Unmatched {
			if u.Declaration == "aws:"+bundleAccount {
				t.Fatalf("the account recognised is echoed as unmatched: %+v", a.Declarations.Unmatched)
			}
		}
	}
	if len(deploy.Declarations.Unmatched) != 1 || deploy.Declarations.Unmatched[0].Declaration != "github:other" {
		t.Fatalf("the owner that moved nothing is not said to: %+v", deploy.Declarations.Unmatched)
	}
	if !slices.Equal(deploy.Declarations.Recognitions, admin.Declarations.Recognitions) || len(admin.Declarations.Recognitions) != 1 {
		t.Fatalf("a role pinned to no owner recognised echoes %+v, and one pinned to it %+v", deploy.Declarations.Recognitions, admin.Declarations.Recognitions)
	}
}

// Only the account the scan read is recognised: the Organization's
// management account and the Organization itself stay named outsiders
// until the reader declares them, since a reseller or a managed service
// provider may run the one and other companies' accounts may sit in the
// other.
func TestNothingButTheAccountReadIsRecognised(t *testing.T) {
	f := findingsOf(t, bundleOf(t, organizationMember(management, nil), testRole{"managed", managementTrust}, testRole{"org", orgTrust}), "")
	for i := range f.Roles {
		a := roleAnswer(t, f, i)
		for _, o := range ownersIn(a) {
			if o.Declared || o.Recognised {
				t.Errorf("%s: %+v is marked as the reader's", f.Roles[i].Name, o)
			}
		}
		if len(a.Rings[ring.Outsider].GrantNumbers) == 0 || len(a.Rings[ring.Yours].GrantNumbers) != 0 ||
			!slices.Equal(a.Declarations.Recognitions, []Recognition{{Declaration: "aws:" + bundleAccount, Sentence: "recognised: the account this scan read"}}) {
			t.Errorf("%s: outsiders %v, yours %v, recognised %+v", f.Roles[i].Name, a.Rings[ring.Outsider].GrantNumbers, a.Rings[ring.Yours].GrantNumbers, a.Declarations.Recognitions)
		}
	}
}

// The answer is written by hand, and TestRenderMatchesEncodingJSON holds
// the hand to the bytes json.Marshal writes from the same Answer; this
// holds it there with an owner recognised, over every document of the
// corpus and the roles above, whose owners the recognition marks.
func TestARecognisingAnswerIsWhatEncodingJSONWrites(t *testing.T) {
	docs := corpus(t)
	for _, d := range []string{ownAccountTrust, ownAndManaging, orgTrust, githubTrust} {
		docs[d] = []byte(d)
	}
	recognised := Bundle{Account: bundleAccount}.recognised()
	marked := 0
	for name, doc := range docs {
		for _, owners := range []string{"", "aws:" + management + "\naws:" + bundleAccount + "\nnot an owner"} {
			a := admitsRecognising(doc, []byte(owners), recognised)
			want, err := json.Marshal(a)
			if err != nil {
				t.Fatal(err)
			}
			if got := admitsWith(nil, doc, []byte(owners), recognised); !bytes.Equal(got, want) {
				t.Fatalf("%s with owners %+q: the hand and encoding/json differ at byte %d", name, owners, firstDifference(got, want))
			}
			if a.Declarations != nil && len(a.Declarations.Recognitions) > 0 {
				marked++
			}
		}
	}
	if marked < 4 {
		t.Fatalf("%d answers recognised an owner; the comparison held the new members over too few", marked)
	}
}

// The questions the findings ask of the Organization the bundle names, in
// the reader's own words.
const (
	managementQuestion   = "Is this account, which manages your AWS Organization, yours? A reseller or a managed service provider may run it."
	organizationQuestion = "Is every account in this AWS Organization yours?"
)

func TestTheFindingsAskWhetherTheOrganizationIsYours(t *testing.T) {
	both := []suggestedShape{{"aws:" + management, managementQuestion, false}, {"aws:" + orgID, organizationQuestion, false}}
	for _, c := range []struct {
		name   string
		edit   func(map[string]any)
		owners string
		want   []suggestedShape
	}{
		{"a member", organizationMember(management, nil), "", both},
		{"a member that declared its management account", organizationMember(management, nil), "aws:" + management,
			[]suggestedShape{{"aws:" + management, managementQuestion, true}, {"aws:" + orgID, organizationQuestion, false}}},
		{"a member that declared its Organization", organizationMember(management, nil), "github:acme\naws:" + orgID,
			[]suggestedShape{{"aws:" + management, managementQuestion, false}, {"aws:" + orgID, organizationQuestion, true}}},
		// a declaration one step from each answers neither question
		{"a member that declared near misses of both", organizationMember(management, nil), "aws:111122223334\naws:o-exampleorgi", both},
		// the account the scan read is recognised, so it is never asked about
		{"the management account itself", organizationMember(bundleAccount, nil), "", []suggestedShape{{"aws:" + orgID, organizationQuestion, false}}},
		{"in no Organization", statusOnly("not-a-member"), "", []suggestedShape{}},
		{"refused", statusOnly("refused"), "", []suggestedShape{}},
		{"not read", nil, "", []suggestedShape{}},
	} {
		f := findingsOf(t, bundleOf(t, c.edit, testRole{"deploy", githubTrust}), c.owners)
		if f.Suggested == nil || !slices.Equal(f.Suggested, c.want) {
			t.Errorf("%s: the findings ask %+v", c.name, f.Suggested)
		}
		for _, s := range f.Suggested {
			if d := ring.ReadDeclarations(s.Declaration); len(d.Owners) != 1 || d.Owners[0].String() != s.Declaration {
				t.Errorf("%s: %s is not a declaration the reader can make", c.name, s.Declaration)
			}
		}
	}
}

// A role an answer of yes would move says so, with the question and what
// its answer would open on; the answer itself stays where it is, the owner
// a named outsider, until the reader declares it. What it would open on is
// what the findings say once the owner is declared.
func TestARoleAnAnswerWouldMoveSaysWhatItWouldRead(t *testing.T) {
	documents := []string{managementTrust, orgTrust, strangerTrust, ownAccountTrust, githubTrust, ownAndManaging}
	var roles []testRole
	for i, d := range documents {
		roles = append(roles, testRole{"role" + strconv.Itoa(i), d})
	}
	bundle := bundleOf(t, organizationMember(management, nil), roles...)
	f := findingsOf(t, bundle, "")
	want := [][]moveShape{
		{{"aws:" + management, managementQuestion, "If aws:111122223333 is yours, this role reads: Nothing outside your company can assume this role.", nil}},
		{{"aws:" + orgID, organizationQuestion, "If aws:o-exampleorgid is yours, this role reads: Any cloud service can assume this role.", nil}},
		{}, {}, {},
		{{"aws:" + management, managementQuestion, "If aws:111122223333 is yours, this role reads: Nothing outside your company can assume this role.", nil}},
	}
	for i, role := range f.Roles {
		if role.WouldMove == nil || len(role.WouldMove) != len(want[i]) {
			t.Fatalf("%s: would move %+v, want %+v", role.Name, role.WouldMove, want[i])
		}
		for j, m := range role.WouldMove {
			w := want[i][j]
			if m.Declaration != w.Declaration || m.Question != w.Question || m.Sentence != w.Sentence || plain(m.Spans) != m.Sentence {
				t.Errorf("%s: would move %+v, want %+v", role.Name, m, w)
			}
			if m.Spans[1] != (Span{Text: m.Declaration, Mark: "code"}) {
				t.Errorf("%s: the owner is not set as code in %+v", role.Name, m.Spans)
			}
			yes := roleAnswer(t, findingsOf(t, bundle, m.Declaration), i)
			if !strings.HasSuffix(m.Sentence, ": "+yes.Headline.Sentence) {
				t.Errorf("%s: would read %q, and reads %q once %s is declared", role.Name, m.Sentence, yes.Headline.Sentence, m.Declaration)
			}
		}
		if a := roleAnswer(t, f, i); len(role.WouldMove) > 0 && a.Headline.Sentence == "Nothing outside your company can assume this role." {
			t.Errorf("%s: an owner nobody declared moved the answer: %q", role.Name, a.Headline.Sentence)
		}
	}
	// declared, the owner is no longer asked about, and the role has moved
	declared := findingsOf(t, bundle, "aws:"+management)
	if len(declared.Roles[0].WouldMove) != 0 || roleAnswer(t, declared, 0).Headline.Sentence != "Nothing outside your company can assume this role." {
		t.Fatalf("declared, the management account's role would move %+v and reads %q", declared.Roles[0].WouldMove, roleAnswer(t, declared, 0).Headline.Sentence)
	}
	// outside an Organization, or with it not read, nothing is asked
	for _, edit := range []func(map[string]any){nil, statusOnly("not-a-member")} {
		for _, role := range findingsOf(t, bundleOf(t, edit, roles...), "").Roles {
			if role.WouldMove == nil || len(role.WouldMove) != 0 {
				t.Fatalf("%s would move %+v with no Organization read", role.Name, role.WouldMove)
			}
		}
	}
}

// Asking about the Organization's owners costs a role nothing when
// declaring them could move none of its grants: its trust policy is read
// and placed once, for the answer, and placed again only for an owner one
// of its populations is pinned to. So the findings of a member account
// whose roles are pinned to neither owner allocate, beyond those of the
// same roles with no Organization read, only what the questions themselves
// take: less than one allocation a role.
func TestAskingAboutOwnersNoGrantIsPinnedToCostsARoleNothing(t *testing.T) {
	roles := make([]testRole, 200)
	for i := range roles {
		roles[i] = testRole{"deploy-" + strconv.Itoa(i), githubTrust}
	}
	member, none := bundleOf(t, organizationMember(management, nil), roles...), bundleOf(t, nil, roles...)
	f := findingsOf(t, member, "")
	if len(f.Suggested) != 2 || len(f.Roles) != len(roles) || len(f.Roles[0].WouldMove) != 0 {
		t.Fatalf("the findings ask %+v of %d roles, and the first would move %+v; the test needs two owners asked about that move nothing",
			f.Suggested, len(f.Roles), f.Roles[0].WouldMove)
	}
	allocations := func(bundle []byte) float64 {
		return testing.AllocsPerRun(2, func() { Findings(bundle, nil, "cloudarq test") })
	}
	asked, notAsked := allocations(member), allocations(none)
	if asked-notAsked >= float64(len(roles)) {
		t.Fatalf("%d roles no owner asked about is pinned to: %.0f allocations with the Organization read, %.0f without, %.1f more a role",
			len(roles), asked, notAsked, (asked-notAsked)/float64(len(roles)))
	}
	t.Logf("%d roles: %.0f allocations with the Organization read, %.0f without", len(roles), asked, notAsked)
}

// An AWS account placed with the reader's own, declared or recognised,
// reads as their account, not under their pipelines; an Organization
// declared is accounts too. The ring names what it holds, and a ring that
// holds nothing keeps the name it has always had.
func TestTheReadersAWSAccountsAreLabelledAsTheirAccounts(t *testing.T) {
	const githubAndAccount = `{"Version":"2012-10-17","Statement":[` +
		`{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111122223333:root"},"Action":"sts:AssumeRole"},` +
		`{"Effect":"Allow","Principal":{"Federated":"arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"},"Action":"sts:AssumeRoleWithWebIdentity","Condition":{"StringEquals":{"token.actions.githubusercontent.com:aud":"sts.amazonaws.com"},"StringLike":{"token.actions.githubusercontent.com:sub":"repo:acme/*"}}}]}`
	for _, c := range []struct {
		name   string
		answer []byte
		label  string
	}{
		{"the account the scan read, recognised", findingsOf(t, bundleOf(t, nil, testRole{"admin", ownAccountTrust}), "").Roles[0].Answer, "Your AWS accounts"},
		{"an account declared", AdmitsFor([]byte(managementTrust), []byte("aws:"+management)), "Your AWS accounts"},
		{"an Organization declared", AdmitsFor([]byte(orgTrust), []byte("aws:"+orgID)), "Your AWS accounts"},
		{"a GitHub owner and an account declared", AdmitsFor([]byte(githubAndAccount), []byte("aws:"+management+"\ngithub:acme")), "Your pipelines and AWS accounts"},
		{"a GitHub owner declared", AdmitsFor([]byte(githubAndAccount), []byte("github:acme")), "Your pipelines"},
		{"nothing declared", AdmitsFor([]byte(githubAndAccount), nil), "Your pipelines"},
	} {
		if got := answerOf(t, c.answer).Rings[ring.Yours].Label; got != c.label {
			t.Errorf("%s: the ring of yours is labelled %q, want %q", c.name, got, c.label)
		}
	}
}

// awsOwnersPinned are the AWS accounts and the AWS Organizations an
// answer's grants are pinned to, each once, by their IDs.
func awsOwnersPinned(a Answer) (accounts, organizations []string) {
	for _, d := range pinnedOwners(a) {
		id, ok := strings.CutPrefix(d, "aws:")
		switch {
		case !ok:
		case awsAccount(id) && !slices.Contains(accounts, id):
			accounts = append(accounts, id)
		case organizationID(id) && !slices.Contains(organizations, id):
			organizations = append(organizations, id)
		}
	}
	return accounts, organizations
}

// withOwner is a declaration with one more line, the owner.
func withOwner(owners, owner string) string {
	if owners == "" {
		return owner
	}
	return owners + "\n" + owner
}

// declaredIn reports whether a declaration declares the owner, in the form
// a declaration of it is written.
func declaredIn(owners, owner string) bool {
	return slices.ContainsFunc(ring.ReadDeclarations(owners).Owners, func(d ring.Declaration) bool { return d.String() == owner })
}

// populationPlaces are where each grant's populations land, grant by grant.
func populationPlaces(a Answer) [][]string {
	out := make([][]string, len(a.Grants))
	for i, g := range a.Grants {
		for _, p := range g.Populations {
			out[i] = append(out[i], p.Place)
		}
	}
	return out
}

// asDeclared is a sentence's spans with the words that say an owner was
// recognised put as the words a declaration of it is said in, and each run
// of unmarked text joined into one span, so that a sentence that names an
// owner recognised compares span for span with the one that names it
// declared.
func asDeclared(in []Span) []Span {
	var out []Span
	for _, s := range in {
		s.Text = strings.ReplaceAll(s.Text, "owners declared or recognised as yours", "owners declared as yours")
		s.Text = strings.ReplaceAll(s.Text, "recognised: the account this scan read", "declared as yours")
		if s.Mark == "" && s.Note == 0 && s.Text == ", declared as yours, and " {
			s.Text = " and "
		}
		if n := len(out); n > 0 && s.Mark == "" && s.Note == 0 && out[n-1].Mark == "" && out[n-1].Note == 0 {
			out[n-1].Text += s.Text
			continue
		}
		out = append(out, s)
	}
	return out
}

// recognitionCounts are what the recognition property examined: answers
// compared; those in which recognising the account moved a grant; those
// whose ring of the reader's own named it recognised on its own, beside an
// owner declared, or among more than two owners; those whose declaration
// declared the account as well; and declarations refused whole, beside
// which nothing is recognised.
type recognitionCounts struct {
	compared, moved, alone, beside, among, declaredToo, refusedWhole int
}

func (c *recognitionCounts) add(d recognitionCounts) {
	c.compared += d.compared
	c.moved += d.moved
	c.alone += d.alone
	c.beside += d.beside
	c.among += d.among
	c.declaredToo += d.declaredToo
	c.refusedWhole += d.refusedWhole
}

// holdRecognising holds one policy, one account and one declaration to the
// property: the answer with the account recognised is the answer with the
// account declared, field for field and word for word, but for the marks
// that say which owner was recognised, the echo of it, and the words that
// say it. An owner recognised and not declared is marked recognised and not
// declared; one recognised and declared is marked both; every other owner
// is marked as the declaration marks it. Owners refused whole refuse the
// answer, and recognising adds nothing to it.
func holdRecognising(t fataler, policy []byte, account, owners string) (c recognitionCounts) {
	got := admitsWith(nil, policy, []byte(owners), Bundle{Account: account}.recognised())
	if pastABound(owners) {
		if want := AdmitsFor(policy, []byte(owners)); !bytes.Equal(got, want) {
			at := firstDifference(got, want)
			t.Fatalf("owners refused whole, account %s recognised: the answer is not AdmitsFor's\n...%s...\n...%s...\npolicy: %s", account, around(got, at), around(want, at), policy)
		}
		c.refusedWhole++
		return c
	}
	own := "aws:" + account
	declaredToo := declaredIn(owners, own)
	byHand := owners
	if !declaredToo {
		byHand = withOwner(owners, own)
	}
	if pastABound(byHand) {
		t.Fatalf("declaring %s beside %q passes a bound; the property needs a smaller declaration", own, clipped(owners))
	}
	rec, dec := answerOf(t, got), answerOf(t, AdmitsFor(policy, []byte(byHand)))
	c.compared++
	if declaredToo {
		c.declaredToo++
	}
	if !slices.EqualFunc(populationPlaces(rec), populationPlaces(answerOf(t, AdmitsFor(policy, []byte(owners)))), slices.Equal) {
		c.moved++
	}
	fail := func(what string, args ...any) {
		t.Fatalf("account %s recognised, owners %q: "+what+"\npolicy: %s", append(append([]any{account, clipped(owners)}, args...), policy)...)
	}
	if len(rec.Grants) != len(dec.Grants) {
		fail("%d grants recognised, %d declared", len(rec.Grants), len(dec.Grants))
	}
	for i := range dec.Grants {
		rg, dg := &rec.Grants[i], &dec.Grants[i]
		if len(rg.Populations) != len(dg.Populations) {
			fail("grant %d has %d populations recognised, %d declared", i+1, len(rg.Populations), len(dg.Populations))
		}
		for j := range dg.Populations {
			rp, dp := &rg.Populations[j], &dg.Populations[j]
			if len(rp.Owners) != len(dp.Owners) {
				fail("grant %d, population %d: %d owners recognised, %d declared", i+1, j, len(rp.Owners), len(dp.Owners))
			}
			for k := range dp.Owners {
				ro, do := &rp.Owners[k], &dp.Owners[k]
				recognised := do.Declared && do.Declaration == own
				if do.Recognised || ro.Recognised != recognised || ro.Declared != (do.Declared && (!recognised || declaredToo)) {
					fail("grant %d, population %d: the owner is %+v recognised and %+v declared", i+1, j, *ro, *do)
				}
				ro.Declared, ro.Recognised = do.Declared, false
			}
			// who a population is, said in the words of its row, says
			// recognised where the row does, and is held as the row is
			if (rp.Way == nil) != (dp.Way == nil) {
				fail("grant %d, population %d: a way recognised %v, declared %v", i+1, j, rp.Way != nil, dp.Way != nil)
			}
			if rp.Way != nil && rp.Way.Who != nil && dp.Way.Who != nil {
				rp.Way.Who.Spans, dp.Way.Who.Spans = asDeclared(rp.Way.Who.Spans), asDeclared(dp.Way.Who.Spans)
				rp.Way.Who.Sentence = plain(rp.Way.Who.Spans)
			}
		}
	}
	if (rec.Declarations == nil) != (dec.Declarations == nil) {
		fail("the echo is %+v recognised and %+v declared", rec.Declarations, dec.Declarations)
	}
	if r, d := rec.Declarations, dec.Declarations; r != nil {
		if want := []Recognition{{Declaration: own, Sentence: "recognised: the account this scan read"}}; !slices.Equal(r.Recognitions, want) {
			fail("the echo recognises %+v", r.Recognitions)
		}
		r.Recognitions = nil
		if !declaredToo {
			d.Normalised = slices.DeleteFunc(d.Normalised, func(s string) bool { return s == own })
		}
		// declared and pinned to nothing, the account is unmatched; recognised, never
		d.Unmatched = slices.DeleteFunc(d.Unmatched, func(u UnmatchedOwner) bool { return u.Declaration == own })
	}
	if len(rec.Rings) != len(dec.Rings) {
		fail("%d rings recognised, %d declared", len(rec.Rings), len(dec.Rings))
	}
	for i := range dec.Rings {
		r, d := &rec.Rings[i], &dec.Rings[i]
		switch said := r.Sentence; {
		case strings.Contains(said, "owners declared or recognised as yours"):
			c.among++
		case strings.Contains(said, ", recognised: the account this scan read,") && strings.Contains(said, "declared as yours"):
			c.beside++
		case strings.Contains(said, ", recognised: the account this scan read,"):
			c.alone++
		}
		r.Spans, d.Spans = asDeclared(r.Spans), asDeclared(d.Spans)
		r.Sentence = plain(r.Spans)
	}
	r, err := json.Marshal(rec)
	if err != nil {
		t.Fatalf("%v", err)
	}
	d, err := json.Marshal(dec)
	if err != nil {
		t.Fatalf("%v", err)
	}
	if !bytes.Equal(r, d) {
		at := firstDifference(r, d)
		fail("but for the marks and their words, the answers differ\nrecognised ...%s...\ndeclared   ...%s...", around(r, at), around(d, at))
	}
	return c
}

// TestRecognisingTheAccountIsDeclaringItButForTheMarks is the property
// behind recognition, over every JSON file under testdata and over
// generated policies: the answer a scan's findings give a trust policy with
// the account the scan read recognised is the answer the policy gives with
// that account declared, but for the marks that say it was recognised, the
// echo of it, and the words that say so. Each document is answered with
// each AWS account it pins recognised, and with an account it does not,
// beside every declaration the Remark property re-marks it with and that
// account declared too. A count of zero of any case the rule has fails,
// since the property would then have examined only some of it.
func TestRecognisingTheAccountIsDeclaringItButForTheMarks(t *testing.T) {
	var mu sync.Mutex
	var corpusSeen recognitionCounts
	docs := everyCorpusDocument(t)
	t.Run("document", func(t *testing.T) {
		for _, doc := range docs {
			name, _ := filepath.Rel(testdata, doc.path)
			t.Run(name, func(t *testing.T) {
				t.Parallel()
				a := answerOf(t, Admits(doc.raw))
				pinned := pinnedOwners(a)
				accounts, _ := awsOwnersPinned(a)
				if !slices.Contains(accounts, bundleAccount) {
					accounts = append(accounts, bundleAccount)
				}
				upload, now := ownerSets(doc, pinned)
				var seen recognitionCounts
				for _, account := range accounts {
					for _, owners := range slices.Concat(upload, now, []string{"aws:" + account}) {
						seen.add(holdRecognising(t, doc.raw, account, owners))
					}
				}
				mu.Lock()
				corpusSeen.add(seen)
				mu.Unlock()
			})
		}
	})
	t.Logf("corpus: %d documents, %+v", len(docs), corpusSeen)
	if corpusSeen.compared == 0 || corpusSeen.moved == 0 || corpusSeen.alone == 0 || corpusSeen.beside == 0 || corpusSeen.among == 0 ||
		corpusSeen.declaredToo == 0 || corpusSeen.refusedWhole == 0 {
		t.Fatalf("over the corpus the property saw %+v; each count must be positive", corpusSeen)
	}

	// Two thousand policies rather than rapid's hundred: an AWS principal is
	// drawn in one statement in five, and a run of five hundred named the
	// account read alone in its ring 4 times and beside an owner declared 3,
	// so in a hundred draws a count below may come to zero by chance.
	var generated recognitionCounts
	// a subtest of its own: rapid panics on a test that a failed corpus
	// subtest has already marked failed, and the panic ends the package's run
	t.Run("drawn", func(t *testing.T) {
		for range 20 {
			rapid.Check(t, func(t *rapid.T) {
				statements := rapid.SliceOfN(rapid.Custom(genRemarkStatement), 1, 3).Draw(t, "statements")
				var texts []string
				for _, s := range statements {
					texts = append(texts, s.text)
				}
				policy := policyOf(texts...)
				account := rapid.SampledFrom(append(slices.Clone(remarkAccounts), bundleAccount)).Draw(t, "account read")
				owners := genRemarkOwners(t, "owners", pinnedOwners(answerOf(t, Admits(policy))))
				generated.add(holdRecognising(t, policy, account, owners))
			})
		}
	})
	t.Logf("generated: %+v", generated)
	if generated.moved == 0 || generated.alone == 0 || generated.beside == 0 || generated.declaredToo == 0 || generated.refusedWhole == 0 {
		t.Fatalf("over generated policies the property saw %+v; moved, alone, beside, declaredToo and refusedWhole must each be positive", generated)
	}
}

// oneRoleBundle is a bundle of one role, read from account, whose trust
// policy is policy; with the member cloudarq-collect writes for an account
// in the AWS Organization id managed by management, or with no
// Organization member when management is "".
func oneRoleBundle(t fataler, policy []byte, account, management, id string) []byte {
	b := map[string]any{
		"format": "cloudarq.collect/v1", "provider": "aws", "account": account, "partition": "aws", "alias": nil,
		"collected_at": "2026-10-02T18:00:00Z", "collector": "cloudarq-collect 0.2.0",
		"pages": []any{map[string]any{"IsTruncated": false, "Roles": []any{map[string]any{
			"Path": "/", "RoleName": "r", "RoleId": "AROAR", "Arn": "arn:aws:iam::" + account + ":role/r",
			"CreateDate": "2024-01-02T03:04:05Z", "AssumeRolePolicyDocument": string(policy),
		}}}},
		"refused": []any{}, "limits": []any{},
	}
	if management != "" {
		b["organization"] = map[string]any{
			"status": "member", "id": id, "arn": "arn:aws:organizations::" + management + ":organization/" + id,
			"management_account": management, "management_account_arn": "arn:aws:organizations::" + management + ":account/" + id + "/" + management,
			"feature_set": "ALL",
		}
	}
	raw, err := json.Marshal(b)
	if err != nil {
		t.Fatalf("%v", err)
	}
	return raw
}

// oneRoleFindings are the findings of a bundle of one role, which must read.
func oneRoleFindings(t fataler, bundle []byte, owners string) findingsShape {
	var f findingsShape
	if err := json.Unmarshal(Findings(bundle, []byte(owners), "cloudarq test"), &f); err != nil || f.Error != "" || len(f.Roles) != 1 {
		t.Fatalf("the findings do not read: %v, %q, %d roles", err, f.Error, len(f.Roles))
	}
	return f
}

// suggestionCounts are what the suggestion property examined: owners asked
// about; a yes that would move the role, for the management account and
// for the Organization; a yes that would move nothing; an owner asked about
// that the declaration already declares; a near miss of one declared,
// which declares something else; an Organization managed by the account
// read, which is recognised and so not asked about; and declarations
// refused whole.
type suggestionCounts struct {
	asked, managementMoves, organizationMoves, movesNothing, declared, nearMiss, managedByTheAccountRead, refusedWhole int
}

func (c *suggestionCounts) add(d suggestionCounts) {
	c.asked += d.asked
	c.managementMoves += d.managementMoves
	c.organizationMoves += d.organizationMoves
	c.movesNothing += d.movesNothing
	c.declared += d.declared
	c.nearMiss += d.nearMiss
	c.managedByTheAccountRead += d.managedByTheAccountRead
	c.refusedWhole += d.refusedWhole
}

// holdSuggesting holds one policy, read from account in the Organization
// id managed by management, with one declaration, to the property: an owner
// the findings ask about moves nothing until it is declared, and declared,
// it is an owner declared by hand. The role's answer is the one it gives
// in a bundle that names no Organization, byte for byte; the findings ask
// about the management account, unless it is the account read, and the
// Organization, each said to be declared exactly when the declaration
// declares it; and declaring one gives the answer a bundle that names no
// Organization gives with it declared, the role saying beforehand what it
// would read exactly when that yes moves a population of it.
func holdSuggesting(t fataler, policy []byte, account, management, id, owners string) (c suggestionCounts) {
	member, none := oneRoleBundle(t, policy, account, management, id), oneRoleBundle(t, policy, account, "", "")
	f, g := oneRoleFindings(t, member, owners), oneRoleFindings(t, none, owners)
	fail := func(what string, args ...any) {
		t.Fatalf("read from %s, managed by %s in %s, owners %q: "+what+"\npolicy: %s", append(append([]any{account, management, id, clipped(owners)}, args...), policy)...)
	}
	answer := f.Roles[0].Answer
	if !bytes.Equal(answer, g.Roles[0].Answer) || !bytes.Equal(answer, admitsWith(nil, policy, []byte(owners), Bundle{Account: account}.recognised())) {
		fail("the Organization moved the answer\nnamed %s\n none %s", answer, g.Roles[0].Answer)
	}
	if len(g.Suggested) != 0 || len(g.Roles[0].WouldMove) != 0 {
		fail("a bundle naming no Organization asks %+v and would move %+v", g.Suggested, g.Roles[0].WouldMove)
	}
	refused := pastABound(owners)
	var want []suggestedShape
	if management != account {
		want = append(want, suggestedShape{"aws:" + management, managementQuestion, !refused && declaredIn(owners, "aws:"+management)})
	} else {
		c.managedByTheAccountRead++
	}
	want = append(want, suggestedShape{"aws:" + id, organizationQuestion, !refused && declaredIn(owners, "aws:"+id)})
	if !slices.Equal(f.Suggested, want) {
		fail("the findings ask %+v, want %+v", f.Suggested, want)
	}
	c.asked += len(want)
	if refused {
		if len(f.Roles[0].WouldMove) != 0 {
			fail("owners refused whole, and the role would move %+v", f.Roles[0].WouldMove)
		}
		c.refusedWhole++
		return c
	}
	if slices.ContainsFunc(want, func(s suggestedShape) bool { return !s.Declared && nearlyDeclares(owners, s.Declaration) }) {
		c.nearMiss++
	}
	before := populationPlaces(answerOf(t, answer))
	said := 0
	for _, s := range want {
		if s.Declared {
			c.declared++
			if slices.ContainsFunc(f.Roles[0].WouldMove, func(m moveShape) bool { return m.Declaration == s.Declaration }) {
				fail("%s is declared, and the role still says what declaring it would move", s.Declaration)
			}
			continue
		}
		yes := withOwner(owners, s.Declaration)
		if pastABound(yes) {
			fail("declaring %s beside the owners passes a bound; the property needs a smaller declaration", s.Declaration)
		}
		fy, gy := oneRoleFindings(t, member, yes), oneRoleFindings(t, none, yes)
		if !bytes.Equal(fy.Roles[0].Answer, gy.Roles[0].Answer) {
			fail("%s declared is not %s declared by hand\nasked %s\n hand %s", s.Declaration, s.Declaration, fy.Roles[0].Answer, gy.Roles[0].Answer)
		}
		if at := slices.IndexFunc(fy.Suggested, func(d suggestedShape) bool { return d.Declaration == s.Declaration }); at < 0 || !fy.Suggested[at].Declared {
			fail("%s declared is asked %+v", s.Declaration, fy.Suggested)
		}
		if slices.ContainsFunc(fy.Roles[0].WouldMove, func(m moveShape) bool { return m.Declaration == s.Declaration }) {
			fail("%s declared, the role still says what declaring it would move: %+v", s.Declaration, fy.Roles[0].WouldMove)
		}
		yesAnswer := answerOf(t, fy.Roles[0].Answer)
		moves := !slices.EqualFunc(before, populationPlaces(yesAnswer), slices.Equal)
		at := slices.IndexFunc(f.Roles[0].WouldMove, func(m moveShape) bool { return m.Declaration == s.Declaration })
		switch {
		case moves != (at >= 0):
			fail("declaring %s moves a population: %v; the role says it would: %+v", s.Declaration, moves, f.Roles[0].WouldMove)
		case !moves:
			c.movesNothing++
			continue
		case s.Question == managementQuestion:
			c.managementMoves++
		default:
			c.organizationMoves++
		}
		said++
		m := f.Roles[0].WouldMove[at]
		if m.Question != s.Question || m.Sentence != "If "+s.Declaration+" is yours, this role reads: "+yesAnswer.Headline.Sentence || plain(m.Spans) != m.Sentence {
			fail("the role would move %+v, and once %s is declared it opens on %q", m, s.Declaration, yesAnswer.Headline.Sentence)
		}
	}
	if len(f.Roles[0].WouldMove) != said {
		fail("the role says %d owners would move it, of which %d do: %+v", len(f.Roles[0].WouldMove), said, f.Roles[0].WouldMove)
	}
	return c
}

// nearlyDeclares reports whether a declaration holds a line one step from
// declaring the owner: a near miss of it, or a beginning of it.
func nearlyDeclares(owners, owner string) bool {
	return slices.ContainsFunc(strings.Split(owners, "\n"), func(line string) bool {
		return line != "" && line != owner && (strings.HasPrefix(owner, line) || slices.Contains(nearMisses(owner), line))
	})
}

// TestAnOwnerAskedAboutMovesNothingUntilDeclared is the property behind
// the questions the findings ask of an AWS Organization, over every JSON
// file under testdata and over generated policies: the management account
// and the Organization the bundle names are never the reader's until they
// declare them, and declared, each is any owner declared. Each document is
// read in an Organization managed by each AWS account it pins, by an
// account it does not and by the account read itself, and in each
// Organization it pins and one it does not, with no owner, all it pins,
// each owner asked about declared, near misses of them, and owners refused
// whole. A count of zero of any case fails, since the property would then
// have examined only part of the rule.
func TestAnOwnerAskedAboutMovesNothingUntilDeclared(t *testing.T) {
	var mu sync.Mutex
	var corpusSeen suggestionCounts
	docs := everyCorpusDocument(t)
	t.Run("document", func(t *testing.T) {
		for _, doc := range docs {
			name, _ := filepath.Rel(testdata, doc.path)
			t.Run(name, func(t *testing.T) {
				t.Parallel()
				a := answerOf(t, Admits(doc.raw))
				pinned := pinnedOwners(a)
				accounts, organizations := awsOwnersPinned(a)
				var managed [][2]string
				for _, m := range slices.Concat(accounts, []string{management, bundleAccount}) {
					managed = append(managed, [2]string{m, slices.Concat(organizations, []string{orgID})[0]})
				}
				for _, o := range organizations {
					managed = append(managed, [2]string{management, o})
				}
				var seen suggestionCounts
				for _, mo := range managed {
					m, o := "aws:"+mo[0], "aws:"+mo[1]
					declarations := []string{"", strings.Join(pinned, "\n"), doc.owners, m, o, m + "\n" + o, overruns[0],
						strings.Join(slices.Concat(nearMisses(m), []string{o[:len(o)-1]}), "\n")}
					for _, owners := range declarations {
						seen.add(holdSuggesting(t, doc.raw, bundleAccount, mo[0], mo[1], owners))
					}
				}
				mu.Lock()
				corpusSeen.add(seen)
				mu.Unlock()
			})
		}
	})
	t.Logf("corpus: %d documents, %+v", len(docs), corpusSeen)
	if corpusSeen.managementMoves == 0 || corpusSeen.organizationMoves == 0 || corpusSeen.movesNothing == 0 || corpusSeen.declared == 0 ||
		corpusSeen.nearMiss == 0 || corpusSeen.managedByTheAccountRead == 0 || corpusSeen.refusedWhole == 0 {
		t.Fatalf("over the corpus the property saw %+v; each count must be positive", corpusSeen)
	}

	// The drawn statements seldom pin an Organization alone: two runs of a
	// thousand policies saw no yes to the Organization move anything. So
	// half the policies hold one statement more that pins one of the
	// Organizations drawn from, beside each principal that may be confined
	// to it.
	orgStatement := rapid.Custom(func(t *rapid.T) string {
		principal := rapid.SampledFrom([]string{`"*"`, `{"AWS":"*"}`, `{"AWS":"111122223333"}`, `{"AWS":["111122223333","444455556666"]}`}).Draw(t, "principal")
		operator := rapid.SampledFrom([]string{"StringEquals", "StringLike", "ForAnyValue:StringEquals", "StringEqualsIfExists"}).Draw(t, "operator")
		return `{"Effect":"Allow","Principal":` + principal + `,"Action":"sts:AssumeRole","Condition":{"` + operator + `":{"aws:PrincipalOrgID":"` +
			rapid.SampledFrom(remarkOrgs).Draw(t, "pinned organization") + `"}}}`
	})
	var generated suggestionCounts
	// a subtest of its own: rapid panics on a test that a failed corpus
	// subtest has already marked failed, and the panic ends the package's run
	t.Run("drawn", func(t *testing.T) {
		for range 10 {
			rapid.Check(t, func(t *rapid.T) {
				statements := rapid.SliceOfN(rapid.Custom(genRemarkStatement), 1, 3).Draw(t, "statements")
				var texts []string
				for _, s := range statements {
					texts = append(texts, s.text)
				}
				if rapid.Bool().Draw(t, "an Organization pinned") {
					texts = append(texts, orgStatement.Draw(t, "organization statement"))
				}
				policy := policyOf(texts...)
				account := rapid.SampledFrom(append(slices.Clone(remarkAccounts), bundleAccount)).Draw(t, "account read")
				management := rapid.SampledFrom(append(slices.Clone(remarkAccounts), account)).Draw(t, "management account")
				id := rapid.SampledFrom(remarkOrgs).Draw(t, "organization")
				owners := genRemarkOwners(t, "owners", pinnedOwners(answerOf(t, Admits(policy))))
				generated.add(holdSuggesting(t, policy, account, management, id, owners))
			})
		}
	})
	t.Logf("generated: %+v", generated)
	if generated.managementMoves == 0 || generated.organizationMoves == 0 || generated.movesNothing == 0 || generated.declared == 0 ||
		generated.managedByTheAccountRead == 0 || generated.refusedWhole == 0 {
		t.Fatalf("over generated policies the property saw %+v; each count but nearMiss must be positive", generated)
	}
}
