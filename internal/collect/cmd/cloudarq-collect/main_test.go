package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

// answers is what the stand-in for STS and IAM says to each action.
type answers map[string]func() (int, string)

const (
	callerXML = `<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><GetCallerIdentityResult>` +
		`<Arn>arn:aws:iam::123456789012:user/reader</Arn><UserId>AIDAEXAMPLE</UserId><Account>123456789012</Account></GetCallerIdentityResult></GetCallerIdentityResponse>`
	aliasXML = `<ListAccountAliasesResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/"><ListAccountAliasesResult>` +
		`<IsTruncated>false</IsTruncated><AccountAliases><member>production</member></AccountAliases></ListAccountAliasesResult></ListAccountAliasesResponse>`
	rolesXML = `<ListRolesResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/"><ListRolesResult><IsTruncated>false</IsTruncated><Roles>` +
		`<member><Path>/</Path><AssumeRolePolicyDocument>%7B%22Version%22%3A%222012-10-17%22%7D</AssumeRolePolicyDocument><RoleId>AROAEXAMPLE</RoleId>` +
		`<RoleName>deploy</RoleName><Arn>arn:aws:iam::123456789012:role/deploy</Arn><CreateDate>2024-01-02T03:04:05Z</CreateDate></member>` +
		`</Roles></ListRolesResult></ListRolesResponse>`
)

func refused(code, message string) (int, string) {
	return 403, `<ErrorResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/"><Error><Type>Sender</Type><Code>` + code +
		`</Code><Message>` + message + `</Message></Error></ErrorResponse>`
}

func whole() answers {
	return answers{
		"GetCallerIdentity":  func() (int, string) { return 200, callerXML },
		"ListAccountAliases": func() (int, string) { return 200, aliasXML },
		"ListRoles":          func() (int, string) { return 200, rolesXML },
	}
}

// environment points AWS's own settings at the stand-in: static keys, one
// attempt, no profile files and no instance metadata, so the run reads
// nothing of this machine's AWS set-up.
func environment(t *testing.T, script answers) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		answer, ok := script[r.PostForm.Get("Action")]
		if !ok {
			t.Errorf("the collector asked for %+q", r.PostForm.Get("Action"))
			w.WriteHeader(400)
			return
		}
		status, body := answer()
		w.Header().Set("Content-Type", "text/xml")
		w.WriteHeader(status)
		fmt.Fprint(w, body)
	}))
	t.Cleanup(server.Close)
	none := filepath.Join(t.TempDir(), "none")
	for name, value := range map[string]string{
		"AWS_ACCESS_KEY_ID": "AKIDEXAMPLE", "AWS_SECRET_ACCESS_KEY": "secret", "AWS_SESSION_TOKEN": "", "AWS_REGION": "us-east-1",
		"AWS_ENDPOINT_URL": server.URL, "AWS_CONFIG_FILE": none, "AWS_SHARED_CREDENTIALS_FILE": none, "AWS_PROFILE": "",
		"AWS_EC2_METADATA_DISABLED": "true", "AWS_MAX_ATTEMPTS": "1",
	} {
		t.Setenv(name, value)
	}
}

func ran(t *testing.T, args ...string) (int, string, string) {
	var stdout, stderr bytes.Buffer
	code := run(args, &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

func TestAWholeReadWritesTheBundleAloneOnStandardOutputAndExits0(t *testing.T) {
	environment(t, whole())
	code, out, said := ran(t, "aws")
	if code != exitWhole {
		t.Fatalf("exit %d; said:\n%s", code, said)
	}
	var bundle map[string]any
	if err := json.Unmarshal([]byte(out), &bundle); err != nil {
		t.Fatalf("standard output is not one JSON document: %v\n%s", err, out)
	}
	if bundle["account"] != "123456789012" || bundle["collector"] != "cloudarq-collect dev" {
		t.Fatalf("the bundle is %v", bundle)
	}
	if said != "cloudarq-collect: account 123456789012 (production): 1 role in 1 page\n" {
		t.Fatalf("said %+q", said)
	}
}

func TestAPartialReadStillWritesTheBundleSaysWhatAWSRefusedAndExits3(t *testing.T) {
	script := whole()
	script["ListAccountAliases"] = func() (int, string) {
		return refused("AccessDenied", "not authorized to perform: iam:ListAccountAliases")
	}
	environment(t, script)
	code, out, said := ran(t, "aws")
	if code != exitPartial || !json.Valid([]byte(out)) {
		t.Fatalf("exit %d, bundle valid %v", code, json.Valid([]byte(out)))
	}
	for _, line := range []string{
		"cloudarq-collect: account 123456789012: 1 role in 1 page",
		"cloudarq-collect: AWS refused iam:ListAccountAliases: AccessDenied: not authorized to perform: iam:ListAccountAliases",
		"cloudarq-collect: the bundle is partial, and says what it lacks; a whole read needs iam:ListRoles and iam:ListAccountAliases",
	} {
		if !strings.Contains(said, line+"\n") {
			t.Errorf("standard error lacks %+q:\n%s", line, said)
		}
	}
}

func TestCredentialsSTSRefusesWriteNoBundleAndExit1(t *testing.T) {
	script := whole()
	script["GetCallerIdentity"] = func() (int, string) {
		return refused("InvalidClientTokenId", "The security token included in the request is invalid.")
	}
	environment(t, script)
	code, out, said := ran(t, "aws")
	if code != exitFailed || out != "" || !strings.Contains(said, "could not learn which account these credentials belong to") {
		t.Fatalf("exit %d, stdout %+q, said %+q", code, out, said)
	}
}

func TestAProfileThatDoesNotExistIsNamedAndNothingIsAsked(t *testing.T) {
	environment(t, answers{})
	code, out, said := ran(t, "aws", "--profile", "nowhere")
	if code != exitFailed || out != "" || !strings.Contains(said, "the AWS settings could not be read") || !strings.Contains(said, "nowhere") {
		t.Fatalf("exit %d, stdout %+q, said %+q", code, out, said)
	}
}

func TestExplainNamesTheCallsOnStandardErrorAndLeavesTheBundleAlone(t *testing.T) {
	environment(t, whole())
	code, out, said := ran(t, "aws", "--explain")
	if code != exitWhole || !json.Valid([]byte(out)) || strings.Contains(out, "calling") {
		t.Fatalf("exit %d; stdout:\n%s", code, out)
	}
	for _, call := range []string{"sts:GetCallerIdentity", "iam:ListAccountAliases", "iam:ListRoles"} {
		if !strings.Contains(said, "cloudarq-collect: calling "+call+": ") {
			t.Errorf("--explain did not name %s:\n%s", call, said)
		}
	}
}

func TestAWrongCommandLineIsAUsageErrorThatReadsNothing(t *testing.T) {
	environment(t, answers{})
	for _, args := range [][]string{{}, {"gcp"}, {"aws", "extra"}, {"aws", "--no-such-flag"}} {
		code, out, said := ran(t, args...)
		if code != exitUsage || out != "" || !strings.Contains(said, "usage: cloudarq-collect aws") {
			t.Errorf("%+q: exit %d, stdout %+q, said %+q", args, code, out, said)
		}
	}
}

func TestVersionPrintsTheVersion(t *testing.T) {
	code, out, _ := ran(t, "--version")
	if code != exitWhole || out != "cloudarq-collect dev\n" {
		t.Fatalf("exit %d, %+q", code, out)
	}
}
