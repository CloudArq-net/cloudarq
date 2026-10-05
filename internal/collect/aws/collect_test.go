package aws

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	sdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/credentials/processcreds"
	"github.com/aws/aws-sdk-go-v2/credentials/ssocreds"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

const account = "123456789012"

// userReader is the principal ID of an IAM user, as AWS writes one: an ID,
// not a name.
const userReader = "AIDACKCEVSQ6C2EXAMPLE"

var stamp = time.Date(2026, 10, 2, 18, 0, 0, 0, time.UTC)

// stand is a stand-in for STS and IAM's query endpoints and for
// Organizations' JSON one: it answers each action from a script, in each
// service's own wire format, and keeps what it was asked.
type stand struct {
	t            *testing.T
	mu           sync.Mutex
	asked        []url.Values
	journal      *[]string
	identity     func() (int, string)
	aliases      func() (int, string)
	organization func() (int, string)
	page         func(n int, marker string) (int, string)
}

// organizationsTarget prefixes the action an Organizations request names in
// its X-Amz-Target header; STS and IAM name theirs in the form.
const organizationsTarget = "AWSOrganizationsV20161128."

func (s *stand) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.t.Errorf("the stand could not read a request: %v", err)
	}
	asked := r.PostForm
	if target := r.Header.Get("X-Amz-Target"); target != "" {
		asked = url.Values{"Action": {strings.TrimPrefix(target, organizationsTarget)}}
	}
	s.mu.Lock()
	s.asked = append(s.asked, asked)
	if s.journal != nil {
		*s.journal = append(*s.journal, "asked "+asked.Get("Action"))
	}
	pages := 0
	for _, form := range s.asked {
		if form.Get("Action") == "ListRoles" {
			pages++
		}
	}
	s.mu.Unlock()
	var status int
	var body string
	contentType := "text/xml"
	switch asked.Get("Action") {
	case "GetCallerIdentity":
		status, body = s.identity()
	case "ListAccountAliases":
		status, body = s.aliases()
	case "DescribeOrganization":
		status, body = s.organization()
		contentType = "application/x-amz-json-1.1"
	case "ListRoles":
		status, body = s.page(pages, r.PostForm.Get("Marker"))
	default:
		s.t.Errorf("the collector asked for %+q, which it has no reason to", asked.Get("Action"))
		status, body = 400, refusedXML("InvalidAction", "not scripted")
	}
	w.Header().Set("Content-Type", contentType)
	w.WriteHeader(status)
	fmt.Fprint(w, body)
}

func (s *stand) actions() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var names []string
	for _, form := range s.asked {
		names = append(names, form.Get("Action"))
	}
	return names
}

// identityXML is GetCallerIdentity's answer for the caller arn, whose
// principal ID is userID.
func identityXML(arn, userID string) (int, string) {
	return 200, `<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><GetCallerIdentityResult>` +
		`<Arn>` + arn + `</Arn><UserId>` + userID + `</UserId><Account>` + account + `</Account>` +
		`</GetCallerIdentityResult><ResponseMetadata><RequestId>r</RequestId></ResponseMetadata></GetCallerIdentityResponse>`
}

func aliasXML(alias string) (int, string) {
	return 200, `<ListAccountAliasesResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/"><ListAccountAliasesResult>` +
		`<IsTruncated>false</IsTruncated><AccountAliases><member>` + alias + `</member></AccountAliases>` +
		`</ListAccountAliasesResult><ResponseMetadata><RequestId>r</RequestId></ResponseMetadata></ListAccountAliasesResponse>`
}

// The Organization AWS's own example answers with: the documented shape of
// DescribeOrganization's answer, its management account's email address and
// the deprecated policy types included, which the bundle must never carry.
const (
	organizationID    = "o-exampleorgid"
	managementAccount = "111122223333"
	managementEmail   = "bill@example.com"
)

func organizationJSON() (int, string) {
	return 200, `{"Organization":{"Arn":"arn:aws:organizations::` + managementAccount + `:organization/` + organizationID + `",` +
		`"AvailablePolicyTypes":[{"Status":"ENABLED","Type":"SERVICE_CONTROL_POLICY"}],"FeatureSet":"ALL","Id":"` + organizationID + `",` +
		`"MasterAccountArn":"arn:aws:organizations::` + managementAccount + `:account/` + organizationID + `/` + managementAccount + `",` +
		`"MasterAccountEmail":"` + managementEmail + `","MasterAccountId":"` + managementAccount + `"}}`
}

// refusedJSON is an error as Organizations answers one, in its JSON protocol.
func refusedJSON(code, message string) (int, string) {
	return 400, `{"__type":"` + code + `","Message":"` + message + `"}`
}

func refusedXML(code, message string) string {
	return `<ErrorResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/"><Error><Type>Sender</Type>` +
		`<Code>` + code + `</Code><Message>` + message + `</Message></Error><RequestId>r</RequestId></ErrorResponse>`
}

// encoded is a policy as IAM sends it: every character outside RFC 3986's
// unreserved set percent-encoded, a space as %20.
func encoded(policy string) string {
	return strings.ReplaceAll(url.QueryEscape(policy), "+", "%20")
}

// roleXML is one role as ListRoles sends it, its trust policy percent-encoded as IAM encodes it.
func roleXML(name, policy string) string {
	return `<member><Path>/</Path><AssumeRolePolicyDocument>` + encoded(policy) + `</AssumeRolePolicyDocument>` +
		`<MaxSessionDuration>3600</MaxSessionDuration><RoleId>AROA` + strings.ToUpper(name) + `</RoleId><RoleName>` + name + `</RoleName>` +
		`<Arn>arn:aws:iam::` + account + `:role/` + name + `</Arn><CreateDate>2024-01-02T03:04:05Z</CreateDate></member>`
}

func pageXML(truncated bool, marker string, roles ...string) (int, string) {
	next := ""
	if marker != "" {
		next = `<Marker>` + marker + `</Marker>`
	}
	return 200, `<ListRolesResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/"><ListRolesResult>` +
		fmt.Sprintf(`<IsTruncated>%t</IsTruncated>`, truncated) + next + `<Roles>` + strings.Join(roles, "") + `</Roles>` +
		`</ListRolesResult><ResponseMetadata><RequestId>r</RequestId></ResponseMetadata></ListRolesResponse>`
}

const githubPolicy = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Federated":"arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"},"Action":"sts:AssumeRoleWithWebIdentity","Condition":{"StringLike":{"token.actions.githubusercontent.com:sub":"repo:acme/app+infra:ref:refs/heads/main & <tag>"}}}]}`

func standing(t *testing.T) *stand {
	return &stand{
		t:            t,
		identity:     func() (int, string) { return identityXML("arn:aws:iam::"+account+":user/reader", userReader) },
		aliases:      func() (int, string) { return aliasXML("production") },
		organization: organizationJSON,
		page: func(n int, _ string) (int, string) {
			return pageXML(false, "", roleXML("deploy", githubPolicy))
		},
	}
}

// reader points real SDK clients at the stand, one attempt each, so what
// the collector makes of an answer is what the SDK made of IAM's XML.
func reader(t *testing.T, s *stand, explain *bytes.Buffer) Reader {
	server := httptest.NewServer(s)
	t.Cleanup(server.Close)
	settings := sdk.Config{
		Region:           "us-east-1",
		Credentials:      credentials.NewStaticCredentialsProvider("AKIDEXAMPLE", "secret", ""),
		RetryMaxAttempts: 1,
	}
	r := Reader{
		STS:           sts.NewFromConfig(settings, func(o *sts.Options) { o.BaseEndpoint = sdk.String(server.URL) }),
		IAM:           iam.NewFromConfig(settings, func(o *iam.Options) { o.BaseEndpoint = sdk.String(server.URL) }),
		Organizations: organizations.NewFromConfig(settings, func(o *organizations.Options) { o.BaseEndpoint = sdk.String(server.URL) }),
		Clock:         func() time.Time { return stamp },
		Collector:     "cloudarq-collect test",
	}
	if explain != nil {
		r.Explain = explain
	}
	return r
}

func collected(t *testing.T, s *stand) Bundle {
	t.Helper()
	bundle, err := reader(t, s, nil).Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	return bundle
}

func TestAWholeReadNamesTheAccountAndKeepsEachTrustPolicyAsTheAccountHoldsIt(t *testing.T) {
	bundle := collected(t, standing(t))
	if bundle.Format != "cloudarq.collect/v1" || bundle.Provider != "aws" || bundle.Account != account || bundle.Partition != "aws" {
		t.Fatalf("the envelope is %+v", bundle)
	}
	if sdk.ToString(bundle.Alias) != "production" || !bundle.CollectedAt.Equal(stamp) || bundle.Collector != "cloudarq-collect test" {
		t.Fatalf("alias %v, collected %v, collector %+q", bundle.Alias, bundle.CollectedAt, bundle.Collector)
	}
	if bundle.Partial() || bundle.Roles() != 1 {
		t.Fatalf("a whole read of one role reads as partial %v with %d roles", bundle.Partial(), bundle.Roles())
	}
	role := bundle.Pages[0].Roles[0]
	if got := sdk.ToString(role.AssumeRolePolicyDocument); got != githubPolicy {
		t.Fatalf("the trust policy is not the account's text:\n got %s\nwant %s", got, githubPolicy)
	}
	if role.Arn != "arn:aws:iam::"+account+":role/deploy" || role.RoleName != "deploy" || role.RoleId != "AROADEPLOY" || role.Path != "/" {
		t.Fatalf("the role is %+v", role)
	}
	if !role.CreateDate.Equal(time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC)) || sdk.ToInt32(role.MaxSessionDuration) != 3600 {
		t.Fatalf("created %v, session %v", role.CreateDate, role.MaxSessionDuration)
	}
}

func TestTheBundleIsWrittenWithNothingEscapedAndEveryListPresent(t *testing.T) {
	s := standing(t)
	s.aliases = func() (int, string) {
		return 200, `<ListAccountAliasesResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/"><ListAccountAliasesResult>` +
			`<IsTruncated>false</IsTruncated><AccountAliases></AccountAliases></ListAccountAliasesResult></ListAccountAliasesResponse>`
	}
	var out bytes.Buffer
	if err := collected(t, s).Encode(&out); err != nil {
		t.Fatal(err)
	}
	text := out.String()
	// encoding/json's HTML escapes, spelt out: a backslash, then u003c, u003e or u0026.
	escaped := []string{string(rune(92)) + "u003c", string(rune(92)) + "u003e", string(rune(92)) + "u0026"}
	if !strings.Contains(text, `& <tag>`) || strings.Contains(text, escaped[0]) || strings.Contains(text, escaped[1]) || strings.Contains(text, escaped[2]) {
		t.Fatalf("the policy's characters were escaped:\n%s", text)
	}
	var read map[string]any
	if err := json.Unmarshal(out.Bytes(), &read); err != nil {
		t.Fatal(err)
	}
	for _, list := range []string{"pages", "refused", "limits"} {
		if _, ok := read[list].([]any); !ok {
			t.Errorf("%s is %v, not a list: a reader would have to guess what null means", list, read[list])
		}
	}
	if alias, present := read["alias"]; !present || alias != nil {
		t.Errorf("an account with no alias writes alias %v (present %v), not null", alias, present)
	}
	if !strings.HasSuffix(text, "}\n") {
		t.Errorf("the bundle does not end in one newline")
	}
}

func TestEveryPageIsReadInOrderWithTheMarkerIAMGave(t *testing.T) {
	s := standing(t)
	s.page = func(n int, marker string) (int, string) {
		switch n {
		case 1:
			if marker != "" {
				t.Errorf("the first page was asked for with marker %+q", marker)
			}
			return pageXML(true, "after-b", roleXML("a", githubPolicy), roleXML("b", githubPolicy))
		case 2:
			if marker != "after-b" {
				t.Errorf("the second page was asked for with marker %+q, not the one IAM gave", marker)
			}
			return pageXML(false, "", roleXML("c", githubPolicy))
		}
		t.Errorf("a third page was asked for")
		return 400, refusedXML("InvalidInput", "no third page")
	}
	bundle := collected(t, s)
	var names []string
	for _, page := range bundle.Pages {
		for _, role := range page.Roles {
			names = append(names, role.RoleName)
		}
	}
	if strings.Join(names, ",") != "a,b,c" || len(bundle.Pages) != 2 || !bundle.Pages[0].IsTruncated || sdk.ToString(bundle.Pages[0].Marker) != "after-b" {
		t.Fatalf("pages %+v", bundle.Pages)
	}
	for _, form := range s.asked {
		if form.Get("Action") == "ListRoles" && form.Get("MaxItems") != "1000" {
			t.Errorf("a page was asked for %+q roles, not the most IAM gives", form.Get("MaxItems"))
		}
	}
}

func TestAnAliasRefusedIsALineInTheBundleAndTheRolesAreStillRead(t *testing.T) {
	s := standing(t)
	s.aliases = func() (int, string) {
		return 403, refusedXML("AccessDenied", "User: reader is not authorized to perform: iam:ListAccountAliases")
	}
	bundle := collected(t, s)
	want := []Refused{{Call: "iam:ListAccountAliases", Code: "AccessDenied", Message: "User: reader is not authorized to perform: iam:ListAccountAliases"}}
	if fmt.Sprint(bundle.Refused) != fmt.Sprint(want) || bundle.Alias != nil || bundle.Roles() != 1 || !bundle.Partial() {
		t.Fatalf("refused %+v, alias %v, %d roles, partial %v", bundle.Refused, bundle.Alias, bundle.Roles(), bundle.Partial())
	}
}

func TestListRolesRefusedLeavesNoPageAndSaysWhy(t *testing.T) {
	s := standing(t)
	s.page = func(int, string) (int, string) {
		return 403, refusedXML("AccessDenied", "User: reader is not authorized to perform: iam:ListRoles")
	}
	bundle := collected(t, s)
	if len(bundle.Pages) != 0 || len(bundle.Refused) != 1 || bundle.Refused[0].Call != "iam:ListRoles" || bundle.Refused[0].Code != "AccessDenied" {
		t.Fatalf("pages %d, refused %+v", len(bundle.Pages), bundle.Refused)
	}
}

func TestARefusalPartWayKeepsThePagesBeforeItAndNamesTheCall(t *testing.T) {
	s := standing(t)
	s.page = func(n int, _ string) (int, string) {
		if n == 1 {
			return pageXML(true, "m1", roleXML("a", githubPolicy))
		}
		return 400, refusedXML("Throttling", "Rate exceeded")
	}
	bundle := collected(t, s)
	if bundle.Roles() != 1 || len(bundle.Refused) != 1 || bundle.Refused[0] != (Refused{Call: "iam:ListRoles", Code: "Throttling", Message: "Rate exceeded"}) {
		t.Fatalf("%d roles, refused %+v", bundle.Roles(), bundle.Refused)
	}
}

func TestAMarkerThatNeverEndsStopsAtTheCeilingAndSaysSo(t *testing.T) {
	s := standing(t)
	s.page = func(int, string) (int, string) { return pageXML(true, "again", roleXML("loop", githubPolicy)) }
	bundle := collected(t, s)
	if len(bundle.Pages) != MaxPages || len(bundle.Limits) != 1 || !strings.Contains(bundle.Limits[0], "still truncated after 100 pages") {
		t.Fatalf("%d pages, limits %+q", len(bundle.Pages), bundle.Limits)
	}
	if !bundle.Partial() {
		t.Fatal("a capped read is not partial")
	}
}

func TestATrustPolicyThatIsNotPercentEncodedIsKeptAsItCameAndNamed(t *testing.T) {
	s := standing(t)
	s.page = func(int, string) (int, string) {
		return pageXML(false, "", `<member><Path>/</Path><AssumeRolePolicyDocument>%zz</AssumeRolePolicyDocument><RoleId>AROAX</RoleId>`+
			`<RoleName>odd</RoleName><Arn>arn:aws:iam::`+account+`:role/odd</Arn><CreateDate>2024-01-02T03:04:05Z</CreateDate></member>`)
	}
	bundle := collected(t, s)
	role := bundle.Pages[0].Roles[0]
	if sdk.ToString(role.AssumeRolePolicyDocument) != "%zz" || len(bundle.Limits) != 1 || !strings.Contains(bundle.Limits[0], "role/odd") {
		t.Fatalf("document %+q, limits %+q", sdk.ToString(role.AssumeRolePolicyDocument), bundle.Limits)
	}
}

func TestWithoutTheAccountThereIsNoBundle(t *testing.T) {
	s := standing(t)
	s.identity = func() (int, string) {
		return 403, `<ErrorResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><Error><Type>Sender</Type>` +
			`<Code>InvalidClientTokenId</Code><Message>The security token included in the request is invalid.</Message></Error></ErrorResponse>`
	}
	_, err := reader(t, s, nil).Collect(context.Background())
	if err == nil || !strings.Contains(err.Error(), "InvalidClientTokenId") {
		t.Fatalf("err = %v", err)
	}
	if got := strings.Join(s.actions(), ","); got != "GetCallerIdentity" {
		t.Fatalf("after STS refused, the collector went on to ask %s", got)
	}
}

func TestTheCallsAreTheFourReadsAndNothingElse(t *testing.T) {
	s := standing(t)
	collected(t, s)
	if got := strings.Join(s.actions(), ","); got != "GetCallerIdentity,ListAccountAliases,DescribeOrganization,ListRoles" {
		t.Fatalf("the collector asked %s", got)
	}
}

func TestExplainNamesEachCallBeforeItIsMade(t *testing.T) {
	s := standing(t)
	var journal []string
	s.journal = &journal
	var explained journalWriter
	explained.journal = &journal
	r := reader(t, s, nil)
	r.Explain = &explained
	if _, err := r.Collect(context.Background()); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"said cloudarq-collect: calling sts:GetCallerIdentity: which account these credentials belong to",
		"asked GetCallerIdentity",
		"said cloudarq-collect: calling iam:ListAccountAliases: the account's alias, its default name",
		"asked ListAccountAliases",
		"said cloudarq-collect: calling organizations:DescribeOrganization: the AWS Organization the account is in, and which account manages it",
		"asked DescribeOrganization",
		"said cloudarq-collect: calling iam:ListRoles: page 1 of the roles and their trust policies",
		"asked ListRoles",
	}
	if strings.Join(journal, "\n") != strings.Join(want, "\n") {
		t.Fatalf("the journal is\n%s", strings.Join(journal, "\n"))
	}
}

// journalWriter records each explained line in the same journal the stand writes, so their order is the order they happened.
type journalWriter struct{ journal *[]string }

func (w *journalWriter) Write(p []byte) (int, error) {
	*w.journal = append(*w.journal, "said "+strings.TrimSuffix(string(p), "\n"))
	return len(p), nil
}

func TestTheSameAnswersGiveTheSameBytes(t *testing.T) {
	var first, second bytes.Buffer
	if err := collected(t, standing(t)).Encode(&first); err != nil {
		t.Fatal(err)
	}
	if err := collected(t, standing(t)).Encode(&second); err != nil {
		t.Fatal(err)
	}
	if first.String() != second.String() {
		t.Fatalf("two collections of the same answers differ:\n%s\n%s", first.String(), second.String())
	}
}

func TestTheGovCloudPartitionIsReadFromTheCallersARN(t *testing.T) {
	s := standing(t)
	s.identity = func() (int, string) { return identityXML("arn:aws-us-gov:iam::"+account+":user/reader", userReader) }
	if got := collected(t, s).Partition; got != "aws-us-gov" {
		t.Fatalf("partition %+q", got)
	}
}

// IAM encodes the policies it sends to RFC 3986, where a "+" means a plus
// sign; only an HTML form's encoding reads it as a space. An encoder may
// leave a "+" as it is, and the policy must still say "+".
func TestAPlusSignLeftUnencodedIsStillAPlusSign(t *testing.T) {
	s := standing(t)
	s.page = func(int, string) (int, string) {
		return pageXML(false, "", `<member><Path>/</Path><AssumeRolePolicyDocument>%7B%22sub%22%3A%22repo%3Aacme%2Fapp+infra%3A*%22%7D</AssumeRolePolicyDocument>`+
			`<RoleId>AROAX</RoleId><RoleName>plus</RoleName><Arn>arn:aws:iam::`+account+`:role/plus</Arn><CreateDate>2024-01-02T03:04:05Z</CreateDate></member>`)
	}
	if got := sdk.ToString(collected(t, s).Pages[0].Roles[0].AssumeRolePolicyDocument); got != `{"sub":"repo:acme/app+infra:*"}` {
		t.Fatalf("the policy reads %s", got)
	}
}

func TestTheOrganizationIsWrittenAsAWSNamesItAndNothingElseOfIt(t *testing.T) {
	bundle := collected(t, standing(t))
	want := Organization{
		Status: "member", ID: organizationID, Arn: "arn:aws:organizations::" + managementAccount + ":organization/" + organizationID,
		ManagementAccount: managementAccount, ManagementAccountArn: "arn:aws:organizations::" + managementAccount + ":account/" + organizationID + "/" + managementAccount,
		FeatureSet: "ALL",
	}
	if bundle.Organization != want || bundle.Partial() {
		t.Fatalf("the organization is %+v, partial %v", bundle.Organization, bundle.Partial())
	}
	var out bytes.Buffer
	if err := bundle.Encode(&out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), `"organization": {
    "status": "member",
    "id": "`+organizationID+`",`) {
		t.Fatalf("the bundle does not write the organization after the alias:\n%s", out.String())
	}
	// The management account's email address is a person's, and the policy
	// types are deprecated: neither is written, in any spelling.
	for _, never := range []string{managementEmail, "@", "Email", "email", "AvailablePolicyTypes", "SERVICE_CONTROL_POLICY", "ENABLED"} {
		if strings.Contains(out.String(), never) {
			t.Errorf("the bundle holds %+q:\n%s", never, out.String())
		}
	}
}

func TestAnAccountInNoOrganizationSaysSoAndIsAWholeRead(t *testing.T) {
	s := standing(t)
	s.organization = func() (int, string) {
		return refusedJSON("AWSOrganizationsNotInUseException", "Your account is not a member of an organization.")
	}
	bundle := collected(t, s)
	if bundle.Organization != (Organization{Status: "not-a-member"}) || len(bundle.Refused) != 0 || bundle.Partial() || bundle.Roles() != 1 {
		t.Fatalf("organization %+v, refused %+v, partial %v, %d roles", bundle.Organization, bundle.Refused, bundle.Partial(), bundle.Roles())
	}
}

func TestTheOrganizationRefusedIsALineInTheBundleAndItsOwnState(t *testing.T) {
	s := standing(t)
	s.organization = func() (int, string) {
		return refusedJSON("AccessDeniedException", "You don't have permissions to access this resource.")
	}
	bundle := collected(t, s)
	want := []Refused{{Call: "organizations:DescribeOrganization", Code: "AccessDeniedException", Message: "You don't have permissions to access this resource."}}
	if bundle.Organization != (Organization{Status: "refused"}) || fmt.Sprint(bundle.Refused) != fmt.Sprint(want) || !bundle.Partial() || bundle.Roles() != 1 {
		t.Fatalf("organization %+v, refused %+v, partial %v, %d roles", bundle.Organization, bundle.Refused, bundle.Partial(), bundle.Roles())
	}
}

// An answer that names no organization is not one AWS documents; nothing is
// made of it, and the bundle says so as it says of an error that carries no
// code of AWS's.
func TestAnAnswerWithNoOrganizationInItIsNotReadAsOne(t *testing.T) {
	s := standing(t)
	s.organization = func() (int, string) { return 200, `{}` }
	bundle := collected(t, s)
	if bundle.Organization != (Organization{Status: "refused"}) || len(bundle.Refused) != 1 ||
		bundle.Refused[0].Call != "organizations:DescribeOrganization" || bundle.Refused[0].Code != "Unanswered" {
		t.Fatalf("organization %+v, refused %+v", bundle.Organization, bundle.Refused)
	}
}

// heldToTheGrammar: the collector's last act on a message is the strip,
// so the engine's own strip, reading the bundle, changes nothing the
// collector wrote.
func heldToTheGrammar(t *testing.T, bundle Bundle) {
	t.Helper()
	for _, r := range bundle.Refused {
		if again := withoutPeople(r.Message); again != r.Message {
			t.Errorf("%s: the strip, run again, changes what the collector wrote:\n%+q\n%+q", r.Call, r.Message, again)
		}
	}
}

// An IAM Identity Center session as GetCallerIdentity names it, its
// session the person's email address, and its principal ID, the role's
// unique ID and the same session name.
const (
	ssoCaller    = "arn:aws:sts::" + account + ":assumed-role/AWSReservedSSO_Admin_0123456789abcdef/jane@example.com"
	ssoPrincipal = "AROAIDPPEZS35WEXAMPLE:jane@example.com"
)

// TestARefusalNamingTheCallerIsWrittenWithoutThem: AWS's refusal names
// whoever made the call, and the bundle keeps the call, the account, the
// role and the permission, and not the person.
func TestARefusalNamingTheCallerIsWrittenWithoutThem(t *testing.T) {
	s := standing(t)
	s.identity = func() (int, string) { return identityXML(ssoCaller, ssoPrincipal) }
	s.page = func(int, string) (int, string) {
		return 403, refusedXML("AccessDenied", "User: "+ssoCaller+" is not authorized to perform: iam:ListRoles on resource: arn:aws:iam::"+account+
			":role/ because no identity-based policy allows the iam:ListRoles action")
	}
	bundle := collected(t, s)
	want := []Refused{{Call: "iam:ListRoles", Code: "AccessDenied", Message: "User: arn:aws:sts::" + account +
		":assumed-role/AWSReservedSSO_Admin_0123456789abcdef/(removed) is not authorized to perform: iam:ListRoles on resource: arn:aws:iam::" + account +
		":role/ because no identity-based policy allows the iam:ListRoles action"}}
	if !slices.Equal(bundle.Refused, want) {
		t.Fatalf("refused %+v", bundle.Refused)
	}
	var out bytes.Buffer
	if err := bundle.Encode(&out); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "jane") {
		t.Fatalf("the bundle names the caller:\n%s", out.String())
	}
	heldToTheGrammar(t, bundle)
}

// TestTheCallersPrincipalIDIsRemovedWhereverARefusalNamesIt: the caller's
// principal ID, as GetCallerIdentity gives it, holds an assumed role's
// session name or a federated user's name after a colon, in no ARN the
// strip could read. Some services word their refusals otherwise than in
// ARNs, so what follows the colon is taken out wherever the exact ID
// stands outside an ARN. An IAM user's ID and the root user's, the account
// itself, name no one and are left.
func TestTheCallersPrincipalIDIsRemovedWhereverARefusalNamesIt(t *testing.T) {
	for _, c := range []struct{ caller, arn, id, said, want string }{
		{"an Identity Center session", ssoCaller, ssoPrincipal,
			"Access denied to AROAIDPPEZS35WEXAMPLE:jane@example.com for iam:ListAccountAliases; AROAIDPPEZS35WEXAMPLE:jane@example.com may not list aliases",
			"Access denied to AROAIDPPEZS35WEXAMPLE:(removed) for iam:ListAccountAliases; AROAIDPPEZS35WEXAMPLE:(removed) may not list aliases"},
		{"a federated user", "arn:aws:sts::" + account + ":federated-user/Bob", account + ":Bob",
			"Access denied to " + account + ":Bob for iam:ListAccountAliases",
			"Access denied to " + account + ":(removed) for iam:ListAccountAliases"},
		{"an IAM user", "arn:aws:iam::" + account + ":user/reader", userReader,
			"Access denied to " + userReader + " for iam:ListAccountAliases",
			"Access denied to " + userReader + " for iam:ListAccountAliases"},
		{"the root user", "arn:aws:iam::" + account + ":root", account,
			"Access denied to " + account + " for iam:ListAccountAliases",
			"Access denied to " + account + " for iam:ListAccountAliases"},
	} {
		s := standing(t)
		s.identity = func() (int, string) { return identityXML(c.arn, c.id) }
		s.aliases = func() (int, string) { return 403, refusedXML("AccessDenied", c.said) }
		bundle := collected(t, s)
		want := []Refused{{Call: "iam:ListAccountAliases", Code: "AccessDenied", Message: c.want}}
		if !slices.Equal(bundle.Refused, want) {
			t.Errorf("%s: refused %+v\nwant %+v", c.caller, bundle.Refused, want)
		}
		heldToTheGrammar(t, bundle)
	}
}

// TestAFederatedCallersPrincipalIDLeavesEveryARNToTheGrammar: a federated
// user's principal ID is the account, a colon and the name, and the name
// can begin a resource type of the account's own ARNs: "fe" begins
// federated-user/, "us" user/, "as" assumed-role/, "mf" mfa/ and "ro"
// role/. Taken out wherever it stood, the principal would cut that type out
// of every ARN of the account a refusal names, the strip would no longer
// read those ARNs, and whoever they name would reach the bundle. So the
// principal is taken out only where it stands outside an ARN, and every
// ARN, the caller's own among them, reads as the grammar writes it. A
// principal that runs on into an ARN, as "barn" runs into "arn:", takes the
// rest of that ARN with it, since the ARN cut at its "arn:" is one the
// strip could no longer read.
func TestAFederatedCallersPrincipalIDLeavesEveryARNToTheGrammar(t *testing.T) {
	const (
		sts     = "arn:aws:sts::" + account + ":"
		iamARN  = "arn:aws:iam::" + account + ":"
		refused = " is not authorized to perform: iam:ListAccountAliases"
	)
	// gone is what the bundle must not hold: another person's name, or the
	// caller's name as it would read left in place. The principal left in
	// words is followed by a space, since account:fe also begins
	// account:federated-user/ in an ARN stripped as it should be.
	for _, c := range []struct {
		why, name, said, want string
		gone                  []string
	}{
		{"another person's federated user", "fe",
			"User: " + sts + "federated-user/Bob" + refused,
			"User: " + sts + "federated-user/(removed)" + refused, []string{"Bob"}},
		{"another person's user", "us",
			"User: " + iamARN + "user/Jane" + refused,
			"User: " + iamARN + "user/(removed)" + refused, []string{"Jane"}},
		{"another person's session", "as",
			"User: " + sts + "assumed-role/R/alice@example.com" + refused,
			"User: " + sts + "assumed-role/R/(removed)" + refused, []string{"alice"}},
		{"another person's MFA device", "mf",
			"User: " + iamARN + "mfa/JaneMFA" + refused,
			"User: " + iamARN + "mfa/(removed)" + refused, []string{"JaneMFA"}},
		{"the caller's own ARN", "fe",
			"User: " + sts + "federated-user/fe" + refused,
			"User: " + sts + "federated-user/(removed)" + refused, []string{"federated-user/fe"}},
		{"the principal in words", "fe",
			"Access denied: principal " + account + ":fe" + refused,
			"Access denied: principal " + account + ":(removed)" + refused, []string{account + ":fe "}},
		{"the principal in words and another person's ARN", "fe",
			account + ":fe may not act for " + sts + "federated-user/Bob",
			account + ":(removed) may not act for " + sts + "federated-user/(removed)", []string{account + ":fe ", "Bob"}},
		{"a role, which names no one", "ro",
			"User: " + sts + "federated-user/ro" + refused + " on resource: " + iamARN + "role/Admin",
			"User: " + sts + "federated-user/(removed)" + refused + " on resource: " + iamARN + "role/Admin", []string{"federated-user/ro"}},
		{"the principal running on into an arn:", "barn",
			"Access denied: " + account + ":barn: may not list aliases",
			"Access denied: " + account + ":(removed) may not list aliases", []string{"barn"}},
		{"the principal glued to another person's ARN", "barn",
			"Access denied: " + account + ":barn:aws:iam::" + account + ":user/Jane may not list aliases",
			"Access denied: " + account + ":(removed) may not list aliases", []string{"barn", "Jane"}},
		{"a name that begins no type", "Bob",
			"User: " + iamARN + "user/Jane" + refused,
			"User: " + iamARN + "user/(removed)" + refused, []string{"Jane"}},
	} {
		s := standing(t)
		s.identity = func() (int, string) { return identityXML(sts+"federated-user/"+c.name, account+":"+c.name) }
		s.aliases = func() (int, string) { return 403, refusedXML("AccessDenied", c.said) }
		bundle := collected(t, s)
		want := []Refused{{Call: "iam:ListAccountAliases", Code: "AccessDenied", Message: c.want}}
		if !slices.Equal(bundle.Refused, want) {
			t.Errorf("%s, caller %s:\n got %+q\nwant %+q", c.why, c.name, bundle.Refused, want)
		}
		var out bytes.Buffer
		if err := bundle.Encode(&out); err != nil {
			t.Fatal(err)
		}
		for _, name := range c.gone {
			if strings.Contains(out.String(), name) {
				t.Errorf("%s, caller %s: the bundle holds %+q", c.why, c.name, name)
			}
		}
		heldToTheGrammar(t, bundle)
	}
}

// TestNothingButARefusalsMessagePassesThroughTheStrip: the roles, their
// trust policies and what the collector says of them are the account's own
// text, written as IAM sent it, a person's ARN in it included.
func TestNothingButARefusalsMessagePassesThroughTheStrip(t *testing.T) {
	const (
		jane      = "arn:aws:iam::" + account + ":user/Jane"
		janeTrust = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"` + jane + `"},"Action":"sts:AssumeRole"}]}`
		unencoded = `{"Principal":{"AWS":"` + jane + `"}} 100%`
	)
	s := standing(t)
	s.identity = func() (int, string) { return identityXML(jane, userReader) }
	s.aliases = func() (int, string) {
		return 403, refusedXML("AccessDenied", "User: "+jane+" is not authorized to perform: iam:ListAccountAliases")
	}
	s.page = func(int, string) (int, string) {
		return pageXML(false, "", roleXML("jane-admin", janeTrust), `<member><Path>/</Path><AssumeRolePolicyDocument>`+unencoded+
			`</AssumeRolePolicyDocument><RoleId>AROAX</RoleId><RoleName>odd</RoleName><Arn>arn:aws:iam::`+account+
			`:role/odd</Arn><CreateDate>2024-01-02T03:04:05Z</CreateDate></member>`)
	}
	bundle := collected(t, s)
	want := []Refused{{Call: "iam:ListAccountAliases", Code: "AccessDenied", Message: "User: arn:aws:iam::" + account + ":user/(removed) is not authorized to perform: iam:ListAccountAliases"}}
	if !slices.Equal(bundle.Refused, want) {
		t.Errorf("refused %+v", bundle.Refused)
	}
	if bundle.Roles() != 2 {
		t.Fatalf("%d roles", bundle.Roles())
	}
	roles := bundle.Pages[0].Roles
	if sdk.ToString(roles[0].AssumeRolePolicyDocument) != janeTrust || sdk.ToString(roles[1].AssumeRolePolicyDocument) != unencoded {
		t.Errorf("the trust policies read %s and %s", sdk.ToString(roles[0].AssumeRolePolicyDocument), sdk.ToString(roles[1].AssumeRolePolicyDocument))
	}
	if len(bundle.Limits) != 1 || !strings.Contains(bundle.Limits[0], "arn:aws:iam::"+account+":role/odd") {
		t.Errorf("limits %+q", bundle.Limits)
	}
	heldToTheGrammar(t, bundle)
}

// TestAnUnansweredCallSaysTheHomeDirectoryAsATilde: a call that never
// reached AWS is written in the SDK's own words, and they can name a file
// under the home directory of whoever ran the collector. The SDK's own
// IAM Identity Center provider, given a home with no token cached, fails
// every IAM call so, naming the file it could not read.
func TestAnUnansweredCallSaysTheHomeDirectoryAsATilde(t *testing.T) {
	home := filepath.Join(t.TempDir(), "jane")
	t.Setenv("HOME", home)
	r := reader(t, standing(t), nil)
	r.Home = home
	r.IAM = iam.New(r.IAM.Options(), func(o *iam.Options) {
		o.Credentials = sdk.NewCredentialsCache(ssocreds.New(nil, account, "ReadOnly", "https://example.awsapps.com/start"))
	})
	bundle, err := r.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(bundle.Refused) != 2 {
		t.Fatalf("refused %+v", bundle.Refused)
	}
	for _, refused := range bundle.Refused {
		if refused.Code != "Unanswered" || !strings.Contains(refused.Message, "open ~/.aws/sso/cache/") ||
			strings.Contains(refused.Message, home) || strings.Contains(refused.Message, "jane") {
			t.Errorf("%s: %s %+q", refused.Call, refused.Code, refused.Message)
		}
	}
	heldToTheGrammar(t, bundle)
}

// TestACredentialProcessesOutputIsNeverKept: a profile's credential_process
// prints new keys on its stdout each time the SDK asks it for them, and a
// helper can write a line of its own there too, a sign-in notice naming the
// person. Credentials that expire part-way through a run are asked for
// again, and when the SDK cannot read what the process wrote, its error
// holds all of it: the new secret access key, the session token and the
// notice. The call never reaches AWS, and the bundle says so in a sentence
// of the collector's own, holding nothing the process wrote.
func TestACredentialProcessesOutputIsNeverKept(t *testing.T) {
	const (
		notice = "Signing in again as jane@example.com"
		keyID  = "ASIAPROCESSOUTPUTKEY"
		secret = "PROCESSOUTPUTSECRETACCESSKEY"
		token  = "PROCESSOUTPUTSESSIONTOKEN"
	)
	answer := `{"Version":1,"AccessKeyId":"` + keyID + `","SecretAccessKey":"` + secret + `","SessionToken":"` + token +
		`","Expiration":"2026-10-02T19:00:00Z"}`
	process := processcreds.NewProvider(`printf '%s\n' '` + notice + `' '` + answer + `'`)

	// The SDK's own words for it hold everything the process wrote, so a
	// bundle without them shows the collector kept none of it.
	_, err := process.Retrieve(context.Background())
	if err == nil || !strings.Contains(err.Error(), secret) || !strings.Contains(err.Error(), token) || !strings.Contains(err.Error(), notice) {
		t.Fatalf("the credential process's failure does not say what it wrote, so this test shows nothing: %v", err)
	}

	r := reader(t, standing(t), nil)
	refreshed := sdk.NewCredentialsCache(process)
	r.IAM = iam.New(r.IAM.Options(), func(o *iam.Options) { o.Credentials = refreshed })
	r.Organizations = organizations.New(r.Organizations.Options(), func(o *organizations.Options) { o.Credentials = refreshed })
	bundle, err := r.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	const said = "the credentials could not be refreshed: the credential process failed or wrote what the SDK could not read; its output is not kept"
	want := []Refused{
		{Call: "iam:ListAccountAliases", Code: "Unanswered", Message: said},
		{Call: "organizations:DescribeOrganization", Code: "Unanswered", Message: said},
		{Call: "iam:ListRoles", Code: "Unanswered", Message: said},
	}
	if !slices.Equal(bundle.Refused, want) {
		t.Errorf("refused %+v\nwant %+v", bundle.Refused, want)
	}
	var out bytes.Buffer
	if err := bundle.Encode(&out); err != nil {
		t.Fatal(err)
	}
	for _, kept := range []string{secret, token, keyID, notice, "jane"} {
		if n := strings.Count(out.String(), kept); n != 0 {
			t.Errorf("the bundle holds %+q, which the credential process wrote, %d times", kept, n)
		}
	}
	heldToTheGrammar(t, bundle)
}

// failingClient answers every request with an error in its own words, as a
// network that never reaches AWS does.
type failingClient struct{ said string }

func (f failingClient) Do(*http.Request) (*http.Response, error) { return nil, errors.New(f.said) }

// unansweredWith collects with every IAM call failing in said's words and
// home as the reader's home directory, and returns what the bundle says of
// ListAccountAliases.
func unansweredWith(t *testing.T, home, said string) string {
	t.Helper()
	r := reader(t, standing(t), nil)
	r.Home = home
	r.IAM = iam.New(r.IAM.Options(), func(o *iam.Options) { o.HTTPClient = failingClient{said} })
	bundle, err := r.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(bundle.Refused) != 2 || bundle.Refused[0].Call != "iam:ListAccountAliases" || bundle.Refused[0].Code != "Unanswered" {
		t.Fatalf("refused %+v", bundle.Refused)
	}
	heldToTheGrammar(t, bundle)
	return bundle.Refused[0].Message
}

// TestTheHomeDirectoryIsTakenOutOfUnansweredWords: the home is replaced
// with "~" wherever it stands, after the strip and before the strip runs
// again, so a home inside a person's ARN goes with the ARN, and a home
// whose colon split an ARN's fields leaves an ARN the strip then reads. No
// home known, a relative one and the file system's root replace nothing.
func TestTheHomeDirectoryIsTakenOutOfUnansweredWords(t *testing.T) {
	marked := unansweredWith(t, "", "MARK")
	if !strings.HasSuffix(marked, "MARK") {
		t.Fatalf("the SDK's words do not end in the error's own: %+q", marked)
	}
	around := strings.TrimSuffix(marked, "MARK")
	for _, c := range []struct{ why, home, said, want string }{
		{"no home known", "", "open /srv/jane/.aws/config: permission denied", "open /srv/jane/.aws/config: permission denied"},
		{"the file system's root", "/", "open /srv/jane/.aws/config", "open /srv/jane/.aws/config"},
		{"a relative home", "srv/jane", "open srv/jane/.aws/config", "open srv/jane/.aws/config"},
		{"the home", "/srv/jane", "open /srv/jane/.aws/sso/cache/a.json: no such file or directory", "open ~/.aws/sso/cache/a.json: no such file or directory"},
		{"the home twice", "/srv/jane", "/srv/jane/a, then /srv/jane/b", "~/a, then ~/b"},
		{"a person's ARN whose path holds the home", "/srv/jane", "arn:aws:iam::123456789012:user/srv/jane/x was refused", "arn:aws:iam::123456789012:user/(removed) was refused"},
		{"a home whose colon splits an ARN", "/srv/a:b", "open arn:aws:iam::/srv/a:b:user/Bob", "open arn:aws:iam::~:user/(removed)"},
	} {
		if got := unansweredWith(t, c.home, c.said); got != around+c.want {
			t.Errorf("%s: home %+q\n got %+q\nwant %+q", c.why, c.home, got, around+c.want)
		}
	}
	// A home not written as the SDK writes paths: no form of it survives.
	for _, c := range []struct{ why, home, said string }{
		{"a trailing slash", "/srv/jane/", "open /srv/jane/.aws/sso, or /srv/jane"},
		{"a doubled slash", "/srv//jane", "open /srv//jane/.aws, or /srv/jane/.aws"},
		{"another home that begins with it", "/srv/jane", "open /srv/janet/.aws"},
	} {
		if got := unansweredWith(t, c.home, c.said); strings.Contains(got, "/srv/jane") || strings.Contains(got, "/srv//jane") || !strings.Contains(got, "~") {
			t.Errorf("%s: home %+q: %+q", c.why, c.home, got)
		}
	}
}

// TestARefusalFromAWSNamingTheHomeIsLeftAsAWSWroteIt: the home is taken
// out of the collector's own words for a call that was never answered,
// and AWS's words are AWS's: only the strip reads them.
func TestARefusalFromAWSNamingTheHomeIsLeftAsAWSWroteIt(t *testing.T) {
	s := standing(t)
	s.aliases = func() (int, string) { return 403, refusedXML("AccessDenied", "User: reader may not read /srv/jane") }
	r := reader(t, s, nil)
	r.Home = "/srv/jane"
	bundle, err := r.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := []Refused{{Call: "iam:ListAccountAliases", Code: "AccessDenied", Message: "User: reader may not read /srv/jane"}}
	if !slices.Equal(bundle.Refused, want) {
		t.Fatalf("refused %+v", bundle.Refused)
	}
}
