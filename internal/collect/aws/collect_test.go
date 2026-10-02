package aws

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	sdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

const account = "123456789012"

var stamp = time.Date(2026, 10, 2, 18, 0, 0, 0, time.UTC)

// stand is a stand-in for STS and IAM's query endpoints: it answers each
// Action from a script, in IAM's own XML, and keeps what it was asked.
type stand struct {
	t        *testing.T
	mu       sync.Mutex
	asked    []url.Values
	journal  *[]string
	identity func() (int, string)
	aliases  func() (int, string)
	page     func(n int, marker string) (int, string)
}

func (s *stand) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.t.Errorf("the stand could not read a request: %v", err)
	}
	s.mu.Lock()
	s.asked = append(s.asked, r.PostForm)
	if s.journal != nil {
		*s.journal = append(*s.journal, "asked "+r.PostForm.Get("Action"))
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
	switch r.PostForm.Get("Action") {
	case "GetCallerIdentity":
		status, body = s.identity()
	case "ListAccountAliases":
		status, body = s.aliases()
	case "ListRoles":
		status, body = s.page(pages, r.PostForm.Get("Marker"))
	default:
		s.t.Errorf("the collector asked for %+q, which it has no reason to", r.PostForm.Get("Action"))
		status, body = 400, refusedXML("InvalidAction", "not scripted")
	}
	w.Header().Set("Content-Type", "text/xml")
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

func identityXML(arn string) (int, string) {
	return 200, `<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><GetCallerIdentityResult>` +
		`<Arn>` + arn + `</Arn><UserId>AIDAEXAMPLE</UserId><Account>` + account + `</Account>` +
		`</GetCallerIdentityResult><ResponseMetadata><RequestId>r</RequestId></ResponseMetadata></GetCallerIdentityResponse>`
}

func aliasXML(alias string) (int, string) {
	return 200, `<ListAccountAliasesResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/"><ListAccountAliasesResult>` +
		`<IsTruncated>false</IsTruncated><AccountAliases><member>` + alias + `</member></AccountAliases>` +
		`</ListAccountAliasesResult><ResponseMetadata><RequestId>r</RequestId></ResponseMetadata></ListAccountAliasesResponse>`
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
		t:        t,
		identity: func() (int, string) { return identityXML("arn:aws:iam::" + account + ":user/reader") },
		aliases:  func() (int, string) { return aliasXML("production") },
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
		STS:       sts.NewFromConfig(settings, func(o *sts.Options) { o.BaseEndpoint = sdk.String(server.URL) }),
		IAM:       iam.NewFromConfig(settings, func(o *iam.Options) { o.BaseEndpoint = sdk.String(server.URL) }),
		Clock:     func() time.Time { return stamp },
		Collector: "cloudarq-collect test",
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

func TestTheCallsAreTheThreeReadsAndNothingElse(t *testing.T) {
	s := standing(t)
	collected(t, s)
	if got := strings.Join(s.actions(), ","); got != "GetCallerIdentity,ListAccountAliases,ListRoles" {
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
	s.identity = func() (int, string) { return identityXML("arn:aws-us-gov:iam::" + account + ":user/reader") }
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
