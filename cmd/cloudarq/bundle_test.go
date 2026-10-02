package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CloudArq-net/cloudarq/internal/report"
)

const (
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
