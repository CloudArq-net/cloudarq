package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/CloudArq-net/cloudarq/internal/report"
)

const (
	bundleOwnTrust     = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:root"},"Action":"sts:AssumeRole"}]}`
	bundleGitHubTrust  = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Federated":"arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"},"Action":"sts:AssumeRoleWithWebIdentity","Condition":{"StringEquals":{"token.actions.githubusercontent.com:aud":"sts.amazonaws.com"},"StringLike":{"token.actions.githubusercontent.com:sub":"repo:acme/*"}}}]}`
	bundleServiceTrust = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}`
)

// writtenBundle is a bundle as cloudarq-collect writes one, in a file of the test's own.
func writtenBundle(t *testing.T, documents map[string]string, refused, limits []any) (string, []byte) {
	t.Helper()
	var roles []any
	for _, name := range []string{"deploy", "worker", "broken"} {
		if document, ok := documents[name]; ok {
			roles = append(roles, map[string]any{"Path": "/", "RoleName": name, "RoleId": "AROA" + strings.ToUpper(name),
				"Arn": "arn:aws:iam::123456789012:role/" + name, "CreateDate": "2024-01-02T03:04:05Z", "AssumeRolePolicyDocument": document})
		}
	}
	raw, err := json.MarshalIndent(map[string]any{
		"format": "cloudarq.collect/v1", "provider": "aws", "account": "123456789012", "partition": "aws", "alias": nil,
		"collected_at": "2026-10-02T18:00:00Z", "collector": "cloudarq-collect 0.2.0",
		"pages": []any{map[string]any{"Roles": roles, "IsTruncated": false}}, "refused": refused, "limits": limits,
	}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "estate.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path, raw
}

func engineName(t *testing.T) string {
	return "cloudarq " + strings.TrimSpace(strings.TrimPrefix(invocation{args: []string{"version"}}.run(t).stdout, "cloudarq "))
}

func TestABundleAsJSONIsTheEnginesFindingsBytes(t *testing.T) {
	path, raw := writtenBundle(t, map[string]string{"deploy": bundleGitHubTrust, "worker": bundleServiceTrust}, []any{}, []any{})
	for _, owners := range [][]string{nil, {"github:acme"}} {
		args := []string{"--bundle", path, "--json"}
		for _, owner := range owners {
			args = append(args, "--owner", owner)
		}
		got := ask(t, args...)
		want := append(report.Findings(raw, []byte(strings.Join(owners, "\n")), engineName(t)), '\n')
		if got.code != exitAnswered || got.stdout != string(want) || got.stderr != "" {
			t.Fatalf("owners %v: exit %d, stderr %q\n got %s\nwant %s", owners, got.code, got.stderr, got.stdout, want)
		}
	}
}

func TestABundleAsTextIsEachRolesAnswerUnderItsName(t *testing.T) {
	path, _ := writtenBundle(t, map[string]string{"deploy": bundleGitHubTrust, "worker": bundleServiceTrust}, []any{}, []any{})
	got := ask(t, "--bundle", path)
	want := `"deploy"  "arn:aws:iam::123456789012:role/deploy"` + "\n\n" + report.AnswerOf([]byte(bundleGitHubTrust)).Text(report.Options{}) +
		"\n" + `"worker"  "arn:aws:iam::123456789012:role/worker"` + "\n\n" + report.AnswerOf([]byte(bundleServiceTrust)).Text(report.Options{})
	if got.code != exitAnswered || got.stdout != want {
		t.Fatalf("exit %d\n got %s\nwant %s", got.code, got.stdout, want)
	}
}

// The account the bundle was read from is the reader's in the text as in
// the findings: a role trusting it is answered with it recognised.
func TestABundlesTextRecognisesTheAccountItWasReadFrom(t *testing.T) {
	path, raw := writtenBundle(t, map[string]string{"deploy": bundleOwnTrust}, []any{}, []any{})
	b, err := report.ReadBundle(raw)
	if err != nil {
		t.Fatal(err)
	}
	got := ask(t, "--bundle", path)
	want := `"deploy"  "arn:aws:iam::123456789012:role/deploy"` + "\n\n" + b.AnswerFor(b.Roles[0], nil).Text(report.Options{})
	if got.code != exitAnswered || got.stdout != want {
		t.Fatalf("exit %d\n got %s\nwant %s", got.code, got.stdout, want)
	}
	for _, line := range []string{"Nothing outside your company can assume this role.", "aws:123456789012, recognised: the account this scan read, can assume this role."} {
		if !strings.Contains(got.stdout, line) {
			t.Errorf("the text does not say %q:\n%s", line, got.stdout)
		}
	}
}

// A role that declaring its Organization's management account would move
// says so under its name, with the question and what it would then read,
// before its answer, which stays as its trust policy gives it.
func TestARoleTheOrganizationsQuestionWouldMoveSaysSoUnderItsName(t *testing.T) {
	const managementTrust = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111122223333:root"},"Action":"sts:AssumeRole"}]}`
	_, raw := writtenBundle(t, map[string]string{"deploy": managementTrust, "worker": bundleServiceTrust}, []any{}, []any{})
	var bundle map[string]any
	if err := json.Unmarshal(raw, &bundle); err != nil {
		t.Fatal(err)
	}
	bundle["organization"] = map[string]any{"status": "member", "id": "o-exampleorgid", "arn": "arn:aws:organizations::111122223333:organization/o-exampleorgid",
		"management_account": "111122223333", "management_account_arn": "arn:aws:organizations::111122223333:account/o-exampleorgid/111122223333", "feature_set": "ALL"}
	raw, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "member.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	b, err := report.ReadBundle(raw)
	if err != nil {
		t.Fatal(err)
	}
	got := ask(t, "--bundle", path)
	want := `"deploy"  "arn:aws:iam::123456789012:role/deploy"` + "\n\n" +
		"aws:111122223333 · Is this account, which manages your AWS Organization, yours? A reseller or a managed service provider may run it.\n" +
		"If aws:111122223333 is yours, this role reads: Nothing outside your company can assume this role.\n\n" +
		b.AnswerFor(b.Roles[0], nil).Text(report.Options{}) +
		"\n" + `"worker"  "arn:aws:iam::123456789012:role/worker"` + "\n\n" + b.AnswerFor(b.Roles[1], nil).Text(report.Options{})
	if got.code != exitAnswered || got.stdout != want {
		t.Fatalf("exit %d\n got %s\nwant %s", got.code, got.stdout, want)
	}
	if declared := ask(t, "--bundle", path, "--owner", "aws:111122223333"); strings.Contains(declared.stdout, "If aws:111122223333 is yours") {
		t.Fatalf("declared, the management account is still asked about:\n%s", declared.stdout)
	}
}

func TestARoleWhosePolicyIsNotReadIsExit1AndNamedAndTheRestAreAnswered(t *testing.T) {
	path, _ := writtenBundle(t, map[string]string{"deploy": bundleGitHubTrust, "broken": "not json"}, []any{}, []any{})
	got := ask(t, "--bundle", path, "--json")
	var findings struct {
		Roles []struct{ Name string } `json:"roles"`
	}
	if err := json.Unmarshal([]byte(got.stdout), &findings); err != nil || len(findings.Roles) != 2 {
		t.Fatalf("the findings were not written whole: %v %s", err, got.stdout)
	}
	if got.code != exitUnread || !strings.Contains(got.stderr, `cloudarq admits: the role "arn:aws:iam::123456789012:role/broken": parse trust policy:`) {
		t.Fatalf("exit %d, stderr %q", got.code, got.stderr)
	}
}

func TestABundleTheEngineDoesNotReadIsExit1WithTheReason(t *testing.T) {
	path := filepath.Join(t.TempDir(), "not-a-bundle.json")
	if err := os.WriteFile(path, []byte(`{"format":"cloudarq.collect/v9"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, json := range []bool{false, true} {
		args := []string{"--bundle", path}
		if json {
			args = append(args, "--json")
		}
		got := ask(t, args...)
		if got.code != exitUnread || !strings.Contains(got.stderr, `this bundle's format is "cloudarq.collect/v9"`) {
			t.Fatalf("json %v: exit %d, stderr %q", json, got.code, got.stderr)
		}
		if json != strings.Contains(got.stdout, `"format":"cloudarq.findings/v1","error":`) {
			t.Fatalf("json %v: stdout %q", json, got.stdout)
		}
	}
}

func TestWhatTheCollectorWasRefusedOrCappedIsSaidOnStandardError(t *testing.T) {
	path, _ := writtenBundle(t, map[string]string{"deploy": bundleGitHubTrust},
		[]any{map[string]any{"call": "iam:ListAccountAliases", "code": "AccessDenied", "message": "not authorized"}},
		[]any{"iam:ListRoles was still truncated after 100 pages"})
	got := ask(t, "--bundle", path, "--json")
	for _, line := range []string{
		`cloudarq admits: the collector was refused "iam:ListAccountAliases": "AccessDenied: not authorized"`,
		`cloudarq admits: the collector says: "iam:ListRoles was still truncated after 100 pages"`,
	} {
		if !strings.Contains(got.stderr, line+"\n") {
			t.Errorf("stderr lacks %q:\n%s", line, got.stderr)
		}
	}
	if got.code != exitAnswered {
		t.Fatalf("exit %d", got.code)
	}
}

func TestABundleIsReadFromStandardInput(t *testing.T) {
	path, raw := writtenBundle(t, map[string]string{"worker": bundleServiceTrust}, []any{}, []any{})
	fromFile := ask(t, "--bundle", path, "--json")
	fromStdin := invocation{args: []string{"admits", "--bundle", "-", "--json"}, stdin: string(raw)}.run(t)
	if fromStdin.code != exitAnswered || fromStdin.stdout != fromFile.stdout {
		t.Fatalf("exit %d\n%s\n%s", fromStdin.code, fromStdin.stdout, fromFile.stdout)
	}
}

func TestABundleTakesNoDocumentAndNoTokenBesideIt(t *testing.T) {
	path, _ := writtenBundle(t, map[string]string{"worker": bundleServiceTrust}, []any{}, []any{})
	for _, args := range [][]string{{"--bundle", path, path}, {"--bundle", path, "--token", "a.b.c"}} {
		got := ask(t, args...)
		if got.code != exitUsage || got.stdout != "" || !strings.Contains(got.stderr, "--bundle answers the roles of the bundle it names") {
			t.Errorf("%v: exit %d, stdout %q, stderr %q", args, got.code, got.stdout, got.stderr)
		}
	}
}

func TestExplainNamesTheBundleItReads(t *testing.T) {
	path, _ := writtenBundle(t, map[string]string{"worker": bundleServiceTrust}, []any{}, []any{})
	got := ask(t, "--bundle", path, "--json", "--explain")
	if !strings.Contains(got.stderr, "  reads "+path+", and no other file\n") || !strings.Contains(got.stderr, "makes no network request and no API call") {
		t.Fatalf("stderr %q", got.stderr)
	}
	if !bytes.HasPrefix([]byte(got.stdout), []byte(`{"format":"cloudarq.findings/v1"`)) {
		t.Fatalf("stdout %q", got.stdout)
	}
}

const bundleCases = "../../testdata/bundles"

// bundleCase is one case of testdata/bundles: its bundle, and the flags
// that declare its owners, one --owner for each line of its owners.txt.
func bundleCase(t *testing.T, name string) (path string, flags []string) {
	t.Helper()
	path = filepath.Join(bundleCases, name, "bundle.json")
	owners, err := os.ReadFile(filepath.Join(bundleCases, name, "owners.txt"))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		t.Fatal(err)
	}
	for _, line := range strings.Split(strings.TrimSuffix(string(owners), "\n"), "\n") {
		if line != "" {
			flags = append(flags, "--owner", line)
		}
	}
	return path, flags
}

func bundleCaseNames(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(bundleCases)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() {
			names = append(names, e.Name())
		}
	}
	// Ten cases: one fewer, its goldens taken with it, and every test that
	// walks the corpus would pass over what is left.
	if len(names) < 10 {
		t.Fatalf("%d bundle cases, and the corpus holds ten; the goldens would cover too little", len(names))
	}
	return names
}

// TestBundleGoldens runs every case of testdata/bundles end to end: the
// command's text and its JSON, with the case's owners declared, beside the
// case's rationale, which says why each role reads as it does. A bundle
// the engine refuses is a case too, so what the command says on standard
// error, and the exit code, are golden with it: <case>.stderr holds
// "exit N" and then standard error, and a case without one must exit 0
// and say nothing there. Both forms must say the same on standard error.
//
// The findings name the engine that wrote them, which is this build's
// version and changes with every commit, so the goldens hold
// "cloudarq (this build)" in its place.
func TestBundleGoldens(t *testing.T) {
	thisBuild := `"engine":` + strconv.Quote(engineName(t))
	names := bundleCaseNames(t)
	// a golden whose case is gone is read by nothing, so it is no golden
	goldens, err := os.ReadDir(filepath.Join("testdata", "bundles"))
	if err != nil {
		t.Fatal(err)
	}
	for _, g := range goldens {
		if !slices.Contains(names, strings.TrimSuffix(g.Name(), filepath.Ext(g.Name()))) {
			t.Errorf("testdata/bundles/%s is the golden of no case under %s", g.Name(), bundleCases)
		}
	}
	for _, name := range names {
		path, owners := bundleCase(t, name)
		if _, err := os.Stat(filepath.Join(bundleCases, name, "rationale.md")); err != nil {
			t.Errorf("%s has no rationale: %v", name, err)
		}
		var said *result
		for _, form := range []struct {
			extension string
			args      []string
		}{
			{".txt", append(append([]string{}, owners...), "--bundle", path)},
			{".json", append(append([]string{"--json"}, owners...), "--bundle", path)},
		} {
			got := ask(t, form.args...)
			if said == nil {
				said = &got
			} else if got.stderr != said.stderr || got.code != said.code {
				t.Errorf("%s: the JSON exits %d saying %q, the text %d saying %q", name, got.code, got.stderr, said.code, said.stderr)
			}
			stdout := got.stdout
			if form.extension == ".json" && !strings.Contains(stdout, `"error":`) {
				if strings.Count(stdout, thisBuild) != 1 {
					t.Fatalf("%s: the findings do not name this build, %s, once:\n%s", name, thisBuild, stdout)
				}
				stdout = strings.Replace(stdout, thisBuild, `"engine":"cloudarq (this build)"`, 1)
			}
			matchesGolden(t, filepath.Join("testdata", "bundles", name+form.extension), stdout)
		}
		stderr := filepath.Join("testdata", "bundles", name+".stderr")
		if said.code == 0 && said.stderr == "" {
			if *update {
				if err := os.Remove(stderr); err != nil && !errors.Is(err, fs.ErrNotExist) {
					t.Fatal(err)
				}
			} else if _, err := os.Stat(stderr); !errors.Is(err, fs.ErrNotExist) {
				t.Errorf("%s: the command exits 0 saying nothing on standard error, and %s says otherwise", name, stderr)
			}
			continue
		}
		matchesGolden(t, stderr, fmt.Sprintf("exit %d\n%s", said.code, said.stderr))
	}
}

// matchesGolden compares output with a golden file, or writes the file
// under -update.
func matchesGolden(t *testing.T, golden, got string) {
	t.Helper()
	if *update {
		if err := os.MkdirAll(filepath.Dir(golden), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(golden, []byte(got), 0o600); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatal(err)
	}
	if got != string(want) {
		t.Errorf("%s: the output is not the golden file\n--- got ---\n%s\n--- want ---\n%s", golden, got, want)
	}
}

// A role AWS made for one of its services is said to be AWS's under its
// name, in the findings' own words, before its answer, which is the answer
// its trust policy gives alone.
func TestARoleAWSMadeIsSaidToBeAWSsUnderItsName(t *testing.T) {
	path := filepath.Join(bundleCases, "01-aws-service-linked-roles", "bundle.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	b, err := report.ReadBundle(raw)
	if err != nil {
		t.Fatal(err)
	}
	got := ask(t, "--bundle", path)
	explained := 0
	for _, role := range b.Roles {
		if role.Managed == nil {
			continue
		}
		explained++
		want := strconv.QuoteToASCII(role.Name) + "  " + strconv.QuoteToASCII(role.Arn) + "\n\n" +
			role.Managed.Sentence + "\n" + role.Managed.Caption + "\n\n" + report.AnswerOf(role.Document).Text(report.Options{})
		if !strings.Contains(got.stdout, want) {
			t.Errorf("%s is not printed as\n%s\n--- got ---\n%s", role.Name, want, got.stdout)
		}
	}
	if explained != 3 || got.code != exitAnswered {
		t.Fatalf("%d of the case's roles explained, exit %d", explained, got.code)
	}
}

// The Organization's answer carries its management account's email
// address, a person's. A bundle may carry it in its organization member,
// under AWS's name for it or the bundle's: nothing the command writes, in
// either form, explained or not, with any owner declared, says it. This
// holds that member and nothing else: what the collector was refused is
// said in the cloud's own words, but for the person an ARN in them names,
// which testdata/bundles/10-refusal-names-a-person holds.
func TestTheCommandNeverSaysTheManagementAccountsEmailAddress(t *testing.T) {
	const (
		email           = "bill@example.com"
		managementTrust = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111122223333:root"},"Action":"sts:AssumeRole"}]}`
	)
	_, raw := writtenBundle(t, map[string]string{"deploy": bundleOwnTrust, "worker": managementTrust}, []any{}, []any{})
	var bundle map[string]any
	if err := json.Unmarshal(raw, &bundle); err != nil {
		t.Fatal(err)
	}
	bundle["organization"] = map[string]any{"status": "member", "id": "o-exampleorgid", "arn": "arn:aws:organizations::111122223333:organization/o-exampleorgid",
		"management_account": "111122223333", "management_account_arn": "arn:aws:organizations::111122223333:account/o-exampleorgid/111122223333",
		"feature_set": "ALL", "management_account_email": email, "MasterAccountEmail": email}
	raw, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "member.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	asked := 0
	for _, form := range [][]string{nil, {"--json"}, {"--explain"}, {"--json", "--explain"}} {
		for _, owners := range [][]string{nil, {"--owner", "aws:111122223333"}, {"--owner", "aws:o-exampleorgid"}} {
			got := ask(t, slices.Concat([]string{"--bundle", path}, form, owners)...)
			if got.code != exitAnswered || !strings.Contains(got.stdout, "111122223333") {
				t.Fatalf("%v %v: exit %d, stderr %q, and the management account is not named:\n%s", form, owners, got.code, got.stderr, got.stdout)
			}
			if strings.Contains(got.stdout, "@") || strings.Contains(got.stderr, "@") {
				t.Errorf("%v %v: the command wrote an email address:\n%s\n%s", form, owners, got.stdout, got.stderr)
			}
			asked++
		}
	}
	if asked != 12 {
		t.Fatalf("%d runs of the command; the check examined too few", asked)
	}
}
