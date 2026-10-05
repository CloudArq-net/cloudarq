package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
)

// answers is what the stand-in for STS, IAM and Organizations says to each
// action.
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
	organizationJSON = `{"Organization":{"Arn":"arn:aws:organizations::111122223333:organization/o-exampleorgid","FeatureSet":"ALL","Id":"o-exampleorgid",` +
		`"MasterAccountArn":"arn:aws:organizations::111122223333:account/o-exampleorgid/111122223333","MasterAccountEmail":"bill@example.com","MasterAccountId":"111122223333"}}`
)

func refused(code, message string) (int, string) {
	return 403, `<ErrorResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/"><Error><Type>Sender</Type><Code>` + code +
		`</Code><Message>` + message + `</Message></Error></ErrorResponse>`
}

func whole() answers {
	return answers{
		"GetCallerIdentity":    func() (int, string) { return 200, callerXML },
		"ListAccountAliases":   func() (int, string) { return 200, aliasXML },
		"DescribeOrganization": func() (int, string) { return 200, organizationJSON },
		"ListRoles":            func() (int, string) { return 200, rolesXML },
	}
}

// environment points AWS's own settings at the stand-in: static keys, one
// attempt, no profile files and no instance metadata, so the run reads
// nothing of this machine's AWS set-up.
func environment(t *testing.T, script answers) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		// Organizations names the action in a header, and answers in JSON.
		action, contentType := r.PostForm.Get("Action"), "text/xml"
		if target := r.Header.Get("X-Amz-Target"); target != "" {
			action, contentType = strings.TrimPrefix(target, "AWSOrganizationsV20161128."), "application/x-amz-json-1.1"
		}
		answer, ok := script[action]
		if !ok {
			t.Errorf("the collector asked for %+q", action)
			w.WriteHeader(400)
			return
		}
		status, body := answer()
		w.Header().Set("Content-Type", contentType)
		w.WriteHeader(status)
		fmt.Fprint(w, body)
	}))
	t.Cleanup(server.Close)
	settings(t, server.URL)
}

// settings points AWS's own settings at endpoint, as environment says.
func settings(t *testing.T, endpoint string) {
	none := filepath.Join(t.TempDir(), "none")
	for name, value := range map[string]string{
		"AWS_ACCESS_KEY_ID": "AKIDEXAMPLE", "AWS_SECRET_ACCESS_KEY": "secret", "AWS_SESSION_TOKEN": "", "AWS_REGION": "us-east-1",
		"AWS_ENDPOINT_URL": endpoint, "AWS_CONFIG_FILE": none, "AWS_SHARED_CREDENTIALS_FILE": none, "AWS_PROFILE": "",
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
	if said != "cloudarq-collect: account 123456789012 (production): 1 role in 1 page\n"+
		"cloudarq-collect: in AWS Organization o-exampleorgid, whose management account is 111122223333\n" {
		t.Fatalf("said %+q", said)
	}
	if strings.Contains(out, "bill@example.com") || strings.Contains(said, "bill@example.com") {
		t.Fatalf("the management account's email address was written:\n%s\n%s", out, said)
	}
}

func TestAnAccountInNoOrganizationIsSaidToBeInNoneAndIsAWholeRead(t *testing.T) {
	script := whole()
	script["DescribeOrganization"] = func() (int, string) {
		return 400, `{"__type":"AWSOrganizationsNotInUseException","Message":"Your account is not a member of an organization."}`
	}
	environment(t, script)
	code, _, said := ran(t, "aws")
	if code != exitWhole || !strings.Contains(said, "cloudarq-collect: not in an AWS Organization\n") {
		t.Fatalf("exit %d; said:\n%s", code, said)
	}
}

func TestTheOrganizationRefusedIsAPartialRead(t *testing.T) {
	script := whole()
	script["DescribeOrganization"] = func() (int, string) {
		return 400, `{"__type":"AccessDeniedException","Message":"You don't have permissions to access this resource."}`
	}
	environment(t, script)
	code, out, said := ran(t, "aws")
	if code != exitPartial || !json.Valid([]byte(out)) {
		t.Fatalf("exit %d, bundle valid %v", code, json.Valid([]byte(out)))
	}
	for _, line := range []string{
		"cloudarq-collect: AWS refused organizations:DescribeOrganization: AccessDeniedException: You don't have permissions to access this resource.",
		"cloudarq-collect: the bundle is partial, and says what it lacks; a whole read needs iam:ListRoles, iam:ListAccountAliases and organizations:DescribeOrganization",
	} {
		if !strings.Contains(said, line+"\n") {
			t.Errorf("standard error lacks %+q:\n%s", line, said)
		}
	}
	if strings.Contains(said, "AWS Organization") {
		t.Errorf("a refused read is said to name an Organization:\n%s", said)
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
		"cloudarq-collect: the bundle is partial, and says what it lacks; a whole read needs iam:ListRoles, iam:ListAccountAliases and organizations:DescribeOrganization",
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
	for _, call := range []string{"sts:GetCallerIdentity", "iam:ListAccountAliases", "organizations:DescribeOrganization", "iam:ListRoles"} {
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

// TestTheLineSayingWhatAWSRefusedSaysTheTokenWhereAWSNamedTheCaller: the
// line on standard error is the bundle's message, stripped as it is, so
// the person who ran the collector is named in neither.
func TestTheLineSayingWhatAWSRefusedSaysTheTokenWhereAWSNamedTheCaller(t *testing.T) {
	script := whole()
	script["ListAccountAliases"] = func() (int, string) {
		return refused("AccessDenied", "User: arn:aws:iam::123456789012:user/reader is not authorized to perform: iam:ListAccountAliases")
	}
	environment(t, script)
	code, out, said := ran(t, "aws")
	if code != exitPartial {
		t.Fatalf("exit %d; said:\n%s", code, said)
	}
	const stripped = "User: arn:aws:iam::123456789012:user/(removed) is not authorized to perform: iam:ListAccountAliases"
	if !strings.Contains(said, "cloudarq-collect: AWS refused iam:ListAccountAliases: AccessDenied: "+stripped+"\n") {
		t.Errorf("standard error does not say the token:\n%s", said)
	}
	var bundle struct {
		Refused []struct{ Message string } `json:"refused"`
	}
	if err := json.Unmarshal([]byte(out), &bundle); err != nil || len(bundle.Refused) != 1 || bundle.Refused[0].Message != stripped {
		t.Errorf("the bundle's refusals are %+v (%v)", bundle.Refused, err)
	}
	if strings.Contains(out, "user/reader") || strings.Contains(said, "user/reader") {
		t.Errorf("the caller is named:\n%s\n%s", out, said)
	}
}

// TestTheHomeDirectoryIsTheOneTheSDKReadsFilesUnder: the home the
// collector takes out of what it writes is found as AWS's SDK finds the
// files it reads under it: $HOME, and when that is empty, the home of the
// account the collector runs as.
func TestTheHomeDirectoryIsTheOneTheSDKReadsFilesUnder(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	if got := homeDir(); got != home {
		t.Errorf("with $HOME %+q the home is %+q", home, got)
	}
	t.Setenv("HOME", "")
	account, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	if account.HomeDir == "" {
		t.Fatalf("the account %s names no home, so a home read from it cannot be told from none", account.Username)
	}
	if got := homeDir(); got != account.HomeDir {
		t.Errorf("with $HOME empty the home is %+q, and the account's is %+q", got, account.HomeDir)
	}
}

// TestAnUnansweredCallIsWrittenWithoutTheHomeDirectory: the SDK's words
// for a request that got no answer name the endpoint, and here the
// endpoint's path is the home directory and IAM's calls are hung up on, so
// those words name the home. The bundle and standard error say "~" in its
// place.
func TestAnUnansweredCallIsWrittenWithoutTheHomeDirectory(t *testing.T) {
	home := filepath.Join(t.TempDir(), "jane")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		action, contentType := r.PostForm.Get("Action"), "text/xml"
		if target := r.Header.Get("X-Amz-Target"); target != "" {
			action, contentType = strings.TrimPrefix(target, "AWSOrganizationsV20161128."), "application/x-amz-json-1.1"
		}
		if action == "ListAccountAliases" || action == "ListRoles" {
			conn, _, err := w.(http.Hijacker).Hijack()
			if err != nil {
				t.Errorf("hijack: %v", err)
				return
			}
			conn.Close()
			return
		}
		answer, ok := whole()[action]
		if !ok {
			t.Errorf("the collector asked for %+q", action)
			w.WriteHeader(400)
			return
		}
		status, body := answer()
		w.Header().Set("Content-Type", contentType)
		w.WriteHeader(status)
		fmt.Fprint(w, body)
	}))
	t.Cleanup(server.Close)
	settings(t, server.URL+home)
	t.Setenv("HOME", home)
	code, out, said := ran(t, "aws")
	if code != exitPartial {
		t.Fatalf("exit %d; said:\n%s", code, said)
	}
	var bundle struct {
		Refused []struct{ Call, Code, Message string } `json:"refused"`
	}
	if err := json.Unmarshal([]byte(out), &bundle); err != nil || len(bundle.Refused) != 2 {
		t.Fatalf("the bundle's refusals are %+v (%v)", bundle.Refused, err)
	}
	for _, r := range bundle.Refused {
		if r.Code != "Unanswered" || !strings.Contains(r.Message, server.URL+"~/") {
			t.Errorf("%s: %s %+q", r.Call, r.Code, r.Message)
		}
		if !strings.Contains(said, "cloudarq-collect: AWS refused "+r.Call+": Unanswered: "+r.Message+"\n") {
			t.Errorf("standard error does not say what the bundle says of %s:\n%s", r.Call, said)
		}
	}
	if strings.Contains(out, home) || strings.Contains(said, home) {
		t.Errorf("the home directory is named:\n%s\n%s", out, said)
	}
}
