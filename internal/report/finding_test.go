package report

import (
	"bytes"
	"encoding/json"
	"maps"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// The rules a way in meets, read as a consumer reads them: through the
// JSON, each population's finding by the id of its rule, so that a build
// whose answer lacks the finding fails here on what a reader would see.

// The rule ids, spelt out rather than taken from the engine: an id is
// permanent, and a renamed one must fail here.
const (
	wantNoOwner       = "web-identity/no-owner"
	wantOwnerLeftOpen = "web-identity/owner-left-open"
	wantNoExternalID  = "aws-account/no-external-id"
	wantAnyAccount    = "aws-account/any-account"
)

// wantRules are the rules the engine names, each spelt out above.
var wantRules = []string{wantNoOwner, wantOwnerLeftOpen, wantNoExternalID, wantAnyAccount}

// findingsAnswer is the part of an answer the rules are read from.
type findingsAnswer struct {
	Error  string `json:"error"`
	Grants []struct {
		Number      int `json:"number"`
		Populations []struct {
			State   string `json:"state"`
			Finding *struct {
				Rule string `json:"rule"`
			} `json:"finding"`
		} `json:"populations"`
	} `json:"grants"`
}

// populationRead is one population as the rules test reads it: its state,
// and the rule its finding names, "-" when it has no finding.
type populationRead struct{ state, rule string }

// rulesRead is every population of an answer by "grant/population", the
// grant by its number and the population by its index in the grant. A
// finding that names no rule reads as "(empty)", never as no finding.
func rulesRead(t *testing.T, answer []byte) map[string]populationRead {
	t.Helper()
	var a findingsAnswer
	if err := json.Unmarshal(answer, &a); err != nil {
		t.Fatalf("the answer is not JSON: %v\n%s", err, answer)
	}
	if a.Error != "" {
		t.Fatalf("the answer is a refusal: %s", a.Error)
	}
	read := map[string]populationRead{}
	for _, g := range a.Grants {
		for i, p := range g.Populations {
			r := populationRead{state: p.State, rule: "-"}
			if p.Finding != nil {
				r.rule = p.Finding.Rule
				if r.rule == "" {
					r.rule = "(empty)"
				}
			}
			read[strconv.Itoa(g.Number)+"/"+strconv.Itoa(i)] = r
		}
	}
	return read
}

// ringsRules is the rule each case of testdata/rings meets, read with the
// case's own declaration, by "grant/population"; every population not
// listed meets none.
var ringsRules = map[string]map[string]string{
	"01-branch-pin-and-owner-prefix":       {"2/0": wantOwnerLeftOpen},
	"06-owner-id-after-a-wildcard":         {"1/0": wantNoOwner},
	"09-anyone-on-every-sts-action":        {"2/0": wantAnyAccount},
	"10-anyone-on-assume-role":             {"2/0": wantAnyAccount},
	"16-actor-is-not-a-tenant":             {"1/0": wantNoOwner},
	"18-external-id-under-any-aws-account": {"2/0": wantAnyAccount},
	"22-job-workflow-ref-subject":          {"1/0": wantNoOwner},
	"26-question-mark-in-the-owner":        {"1/0": wantOwnerLeftOpen},
	"30-union-with-one-open-member":        {"1/0": wantOwnerLeftOpen},
	"32-default-with-acme-declared":        {"2/0": wantOwnerLeftOpen},
	"33-declared-in-another-case":          {"2/0": wantOwnerLeftOpen},
	"34-aws-account":                       {"1/0": wantNoExternalID},
	"40-principal-arn-patterns":            {"3/0": wantAnyAccount, "4/0": wantNoExternalID},
	"48-enterprise-claim-by-name":          {"1/0": wantNoOwner},
	"61-aws-account-near-miss-declared":    {"1/0": wantNoExternalID},
}

// ringsCaseCount is how many cases testdata/rings holds: a case added or
// lost changes what the rules were held over, and must be named above.
const ringsCaseCount = 75

// trustOne is a trust policy of one Allow statement: its principal, its
// action and its Condition, as JSON, with no Condition when it is "".
func trustOne(effect, principal, action, condition string) string {
	s := `{"Effect":` + strconv.Quote(effect) + `,"Principal":` + principal + `,"Action":` + strconv.Quote(action)
	if condition != "" {
		s += `,"Condition":` + condition
	}
	return `{"Version":"2012-10-17","Statement":[` + s + `}]}`
}

const (
	vendorRole   = `{"AWS":"arn:aws:iam::444455556666:role/vendor"}`
	vendorRoot   = `{"AWS":"arn:aws:iam::444455556666:root"}`
	anyAWS       = `{"AWS":"*"}`
	githubIssuer = `{"Federated":"arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"}`
	githubAud    = `"token.actions.githubusercontent.com:aud":"sts.amazonaws.com"`
)

// ruleFixtures are documents beside the corpus, each with the owners it is
// read with and every population it places: its state and the rule it
// meets, "-" for none. Each is a fact the rules rest on that the corpus
// does not show alone.
var ruleFixtures = []struct {
	name, document, owners string
	want                   map[string]populationRead
}{
	// A role of an account nobody declared, with no condition: the role is
	// named, and nothing it must send is asked of it.
	{"outside-role", trustOne("Allow", vendorRole, "sts:AssumeRole", ""), "",
		map[string]populationRead{"1/0": {"exact", wantNoExternalID}}},
	// StringLike "*" passes whatever external ID the caller sends: it asks
	// for none in particular, alone or beside a value in the same list.
	{"external-id-like-anything", trustOne("Allow", vendorRole, "sts:AssumeRole", `{"StringLike":{"sts:ExternalId":"*"}}`), "",
		map[string]populationRead{"1/0": {"exact", wantNoExternalID}}},
	{"external-id-like-anything-in-a-list", trustOne("Allow", vendorRoot, "sts:AssumeRole", `{"StringLike":{"sts:ExternalId":["vendor-abc","*"]}}`), "",
		map[string]populationRead{"1/0": {"exact", wantNoExternalID}}},
	// A value asked for, as a value, a pattern, or a literal "*", is an
	// external ID the caller must send.
	{"external-id-asked", trustOne("Allow", vendorRole, "sts:AssumeRole", `{"StringEquals":{"sts:ExternalId":"vendor-abc"}}`), "",
		map[string]populationRead{"1/0": {"exact", "-"}}},
	{"external-id-pattern", trustOne("Allow", vendorRole, "sts:AssumeRole", `{"StringLike":{"sts:ExternalId":"vendor-*"}}`), "",
		map[string]populationRead{"1/0": {"exact", "-"}}},
	{"external-id-equals-a-star", trustOne("Allow", vendorRoot, "sts:AssumeRole", `{"StringEquals":{"sts:ExternalId":"*"}}`), "",
		map[string]populationRead{"1/0": {"exact", "-"}}},
	{"external-id-like-anything-beside-a-value", trustOne("Allow", vendorRoot, "sts:AssumeRole", `{"StringLike":{"sts:ExternalId":"*"},"StringEquals":{"sts:ExternalId":"vendor-abc"}}`), "",
		map[string]populationRead{"1/0": {"exact", "-"}}},
	// A condition a caller meets by sending no external ID, or one of its
	// own choosing, asks for none in particular, though the engine does not
	// read it as a set of values: IfExists and ForAllValues pass when the
	// key is absent, and so do the operators that admit every value but
	// the ones they list; Null "true" passes only when it is absent, and
	// Null "false" whenever it holds any value.
	{"external-id-equals-if-exists", trustOne("Allow", vendorRole, "sts:AssumeRole", `{"StringEqualsIfExists":{"sts:ExternalId":"vendor-abc"}}`), "",
		map[string]populationRead{"1/0": {"exact", wantNoExternalID}}},
	{"external-id-like-if-exists", trustOne("Allow", vendorRoot, "sts:AssumeRole", `{"StringLikeIfExists":{"sts:ExternalId":"vendor-*"}}`), "",
		map[string]populationRead{"1/0": {"exact", wantNoExternalID}}},
	{"external-id-for-all-values", trustOne("Allow", vendorRole, "sts:AssumeRole", `{"ForAllValues:StringEquals":{"sts:ExternalId":"vendor-abc"}}`), "",
		map[string]populationRead{"1/0": {"exact", wantNoExternalID}}},
	{"external-id-not-equals", trustOne("Allow", vendorRoot, "sts:AssumeRole", `{"StringNotEquals":{"sts:ExternalId":"vendor-abc"}}`), "",
		map[string]populationRead{"1/0": {"exact", wantNoExternalID}}},
	{"external-id-not-like", trustOne("Allow", vendorRole, "sts:AssumeRole", `{"StringNotLike":{"sts:ExternalId":"vendor-*"}}`), "",
		map[string]populationRead{"1/0": {"exact", wantNoExternalID}}},
	{"external-id-not-equals-ignore-case", trustOne("Allow", vendorRoot, "sts:AssumeRole", `{"StringNotEqualsIgnoreCase":{"sts:ExternalId":"vendor-abc"}}`), "",
		map[string]populationRead{"1/0": {"exact", wantNoExternalID}}},
	{"external-id-null-true", trustOne("Allow", vendorRole, "sts:AssumeRole", `{"Null":{"sts:ExternalId":"true"}}`), "",
		map[string]populationRead{"1/0": {"exact", wantNoExternalID}}},
	{"external-id-null-false", trustOne("Allow", vendorRoot, "sts:AssumeRole", `{"Null":{"sts:ExternalId":"false"}}`), "",
		map[string]populationRead{"1/0": {"exact", wantNoExternalID}}},
	{"external-id-like-anything-beside-not-equals", trustOne("Allow", vendorRoot, "sts:AssumeRole", `{"StringLike":{"sts:ExternalId":"*"},"StringNotEquals":{"sts:ExternalId":"vendor-abc"}}`), "",
		map[string]populationRead{"1/0": {"exact", wantNoExternalID}}},
	// Beside a value asked for, such a condition takes nothing from it.
	{"external-id-if-exists-beside-a-value", trustOne("Allow", vendorRoot, "sts:AssumeRole", `{"StringEqualsIfExists":{"sts:ExternalId":"vendor-abc"},"StringEquals":{"sts:ExternalId":"vendor-abc"}}`), "",
		map[string]populationRead{"1/0": {"exact", "-"}}},
	{"external-id-null-false-beside-a-value", trustOne("Allow", vendorRole, "sts:AssumeRole", `{"Null":{"sts:ExternalId":"false"},"StringEquals":{"sts:ExternalId":"vendor-abc"}}`), "",
		map[string]populationRead{"1/0": {"exact", "-"}}},
	// A condition on the external ID the engine does not read may ask for
	// one, so the population, placed exactly by its account, meets no rule.
	{"external-id-not-read", trustOne("Allow", vendorRoot, "sts:AssumeRole", `{"StringEqualsIgnoreCase":{"sts:ExternalId":"vendor-abc"}}`), "",
		map[string]populationRead{"1/0": {"exact", "-"}}},
	{"external-id-for-any-value", trustOne("Allow", vendorRole, "sts:AssumeRole", `{"ForAnyValue:StringEquals":{"sts:ExternalId":"vendor-abc"}}`), "",
		map[string]populationRead{"1/0": {"exact", "-"}}},
	{"external-id-null-of-neither-polarity", trustOne("Allow", vendorRoot, "sts:AssumeRole", `{"Null":{"sts:ExternalId":"maybe"}}`), "",
		map[string]populationRead{"1/0": {"exact", "-"}}},
	{"external-id-like-anything-beside-one-not-read", trustOne("Allow", vendorRoot, "sts:AssumeRole", `{"StringLike":{"sts:ExternalId":"*"},"StringEqualsIgnoreCase":{"sts:ExternalId":"vendor-abc"}}`), "",
		map[string]populationRead{"1/0": {"exact", "-"}}},
	{"external-id-like-no-value", trustOne("Allow", vendorRoot, "sts:AssumeRole", `{"StringLike":{"sts:ExternalId":[]}}`), "",
		map[string]populationRead{"1/0": {"exact", "-"}}},
	{"external-id-key-beyond-ascii", trustOne("Allow", vendorRoot, "sts:AssumeRole", `{"StringEquals":{"\u017fts:ExternalId":"vendor-abc"}}`), "",
		map[string]populationRead{"1/0": {"exact", "-"}}},
	// The account named by a condition under "*" is named all the same.
	{"account-in-a-condition", trustOne("Allow", anyAWS, "sts:AssumeRole", `{"StringEquals":{"aws:PrincipalAccount":"444455556666"}}`), "",
		map[string]populationRead{"1/0": {"unknown", "-"}, "2/0": {"exact", wantNoExternalID}}},
	// The account declared is the reader's own, and no outsider.
	{"account-declared", trustOne("Allow", vendorRole, "sts:AssumeRole", ""), "aws:444455556666\n",
		map[string]populationRead{"1/0": {"exact", "-"}}},
	// Every AWS account, read exactly and not: a key of the request the
	// engine does not read may narrow it.
	{"any-account", trustOne("Allow", anyAWS, "sts:AssumeRole", ""), "",
		map[string]populationRead{"1/0": {"unknown", "-"}, "2/0": {"exact", wantAnyAccount}}},
	{"any-account-request-key-not-read", trustOne("Allow", anyAWS, "sts:AssumeRole", `{"IpAddress":{"aws:SourceIp":"203.0.113.0/24"}}`), "",
		map[string]populationRead{"1/0": {"unknown", "-"}, "2/0": {"unknown", "-"}}},
	// An external ID no particular value of which is asked narrows nobody
	// it names, and leaves every AWS account placed exactly, as "?*" does;
	// one asked in a way the engine does not read may still narrow it.
	{"any-account-external-id-like-anything", trustOne("Allow", anyAWS, "sts:AssumeRole", `{"StringLike":{"sts:ExternalId":"*"}}`), "",
		map[string]populationRead{"1/0": {"unknown", "-"}, "2/0": {"exact", wantAnyAccount}}},
	{"any-account-external-id-of-wildcards-alone", trustOne("Allow", anyAWS, "sts:AssumeRole", `{"StringLike":{"sts:ExternalId":"?*"}}`), "",
		map[string]populationRead{"1/0": {"unknown", "-"}, "2/0": {"exact", wantAnyAccount}}},
	{"any-account-external-id-equals-if-exists", trustOne("Allow", anyAWS, "sts:AssumeRole", `{"StringEqualsIfExists":{"sts:ExternalId":"vendor-abc"}}`), "",
		map[string]populationRead{"1/0": {"unknown", "-"}, "2/0": {"exact", wantAnyAccount}}},
	{"any-account-external-id-null-true", trustOne("Allow", anyAWS, "sts:AssumeRole", `{"Null":{"sts:ExternalId":"true"}}`), "",
		map[string]populationRead{"1/0": {"unknown", "-"}, "2/0": {"exact", wantAnyAccount}}},
	{"any-account-external-id-not-read", trustOne("Allow", anyAWS, "sts:AssumeRole", `{"StringEqualsIgnoreCase":{"sts:ExternalId":"vendor-abc"}}`), "",
		map[string]populationRead{"1/0": {"unknown", "-"}, "2/0": {"unknown", "-"}}},
	// GitHub with no subject at all: anyone on GitHub.
	{"github-no-subject", trustOne("Allow", githubIssuer, "sts:AssumeRoleWithWebIdentity", `{"StringEquals":{`+githubAud+`}}`), "",
		map[string]populationRead{"1/0": {"exact", wantNoOwner}}},
	// An effect the engine could not read is placed as possibly Allow, and
	// never exactly.
	{"github-effect-not-read", trustOne("allow", githubIssuer, "sts:AssumeRoleWithWebIdentity", `{"StringEquals":{`+githubAud+`}}`), "",
		map[string]populationRead{"1/0": {"unknown", "-"}}},
	{"outside-account-effect-not-read", trustOne("allow", vendorRoot, "sts:AssumeRole", ""), "",
		map[string]populationRead{"1/0": {"unknown", "-"}}},
}

// TestRulesOverRings: over every case of testdata/rings, read with its own
// declaration, and the fixtures above, each rule fires on exactly the
// populations named, and on no population whose state is not exact.
func TestRulesOverRings(t *testing.T) {
	names := ringsCases(t)
	if len(names) != ringsCaseCount {
		t.Fatalf("%d cases under %s; the rules are named for %d", len(names), ringsDir, ringsCaseCount)
	}
	fired := map[string]int{}
	var populations, unknown int
	tally := func(where string, read map[string]populationRead) {
		for key, p := range read {
			populations++
			if p.state != "exact" {
				unknown++
				if p.rule != "-" {
					t.Errorf("%s population %s is %s and meets %s; only an exact population meets a rule", where, key, p.state, p.rule)
				}
			}
			if p.rule != "-" {
				fired[p.rule]++
			}
		}
	}
	for _, name := range names {
		doc, owners := ringsCase(t, name)
		read := rulesRead(t, AdmitsFor(doc, owners))
		tally(name, read)
		want := ringsRules[name]
		for _, key := range slices.Sorted(maps.Keys(read)) {
			rule, ok := want[key]
			if !ok {
				rule = "-"
			}
			if read[key].rule != rule {
				t.Errorf("%s population %s meets %s, want %s", name, key, read[key].rule, rule)
			}
		}
		for key := range want {
			if _, ok := read[key]; !ok {
				t.Errorf("%s has no population %s", name, key)
			}
		}
	}
	for name := range ringsRules {
		if !slices.Contains(names, name) {
			t.Errorf("%s is named for a rule and is no case under %s", name, ringsDir)
		}
	}
	for _, f := range ruleFixtures {
		read := rulesRead(t, AdmitsFor([]byte(f.document), []byte(f.owners)))
		tally(f.name, read)
		if !maps.Equal(read, f.want) {
			t.Errorf("%s: populations %v, want %v", f.name, read, f.want)
		}
	}
	for _, rule := range wantRules {
		if fired[rule] == 0 {
			t.Errorf("%s fired nowhere", rule)
		}
	}
	if extra := slices.DeleteFunc(slices.Collect(maps.Keys(fired)), func(r string) bool {
		return slices.Contains(wantRules, r)
	}); len(extra) > 0 {
		t.Errorf("rules fired that are not among those named: %v", extra)
	}
	if unknown == 0 {
		t.Fatal("no population read was unknown; that no rule fires on one went unexamined")
	}
	if !t.Failed() {
		t.Logf("%d cases and %d fixtures: %d populations, %d not exact; fired %v", len(names), len(ruleFixtures), populations, unknown, fired)
	}
}

// TestRulesFollowWhoIsYours: an outside account becomes the reader's when
// declared, or when a scan recognises it as the account it read, and then
// meets no rule; an answer marked again with the declaration withdrawn
// meets it again, as the answer read afresh does.
func TestRulesFollowWhoIsYours(t *testing.T) {
	doc := []byte(trustOne("Allow", vendorRoot, "sts:AssumeRole", ""))
	for _, c := range []struct {
		name   string
		answer []byte
		want   string
	}{
		{"read with no owner", AdmitsFor(doc, nil), wantNoExternalID},
		{"read with the account declared", AdmitsFor(doc, []byte("aws:444455556666\n")), "-"},
		{"declared, then withdrawn", remarkNow(AdmitsFor(doc, []byte("aws:444455556666\n")), ""), wantNoExternalID},
		{"read with no owner, then declared", remarkNow(AdmitsFor(doc, nil), "aws:444455556666\n"), "-"},
	} {
		if got := rulesRead(t, c.answer)["1/0"]; got.state != "exact" || got.rule != c.want {
			t.Errorf("%s: %+v, want exact and %s", c.name, got, c.want)
		}
	}
	bundle := bundleOf(t, nil, testRole{"own", ownAccountTrust}, testRole{"stranger", strangerTrust})
	want := map[string]string{"own": "-", "stranger": wantNoExternalID}
	f := findingsOf(t, bundle, "")
	if len(f.Roles) != len(want) {
		t.Fatalf("%d roles, want %d", len(f.Roles), len(want))
	}
	for _, role := range f.Roles {
		got := rulesRead(t, role.Answer)["1/0"]
		if got.state != "exact" || got.rule != want[role.Name] {
			t.Errorf("the role %s: %+v, want exact and %s", role.Name, got, want[role.Name])
		}
	}
	if !strings.Contains(string(f.Roles[0].Answer)+string(f.Roles[1].Answer), `"recognised":true`) {
		t.Error("no owner was recognised; the account the scan read went unexamined")
	}
}

// githubSubject is a trust policy of one statement admitting GitHub's
// tokens for the audience AWS asks for, whose subject is like subject.
func githubSubject(subject string) string {
	return trustOne("Allow", githubIssuer, "sts:AssumeRoleWithWebIdentity", `{"StringEquals":{`+githubAud+`},"StringLike":{"token.actions.githubusercontent.com:sub":`+subject+`}}`)
}

// TestOwnerLeftOpen: a subject that writes the start of an owner's name and
// leaves the rest to a wildcard, "*" or "?", admits whoever registers a
// name that begins with it, and meets the rule that says so rather than
// the one for a subject that names no owner at all; so does a list of
// patterns each writing a start, the same or another. A subject that
// closes the owner's name pins that owner, and meets neither.
func TestOwnerLeftOpen(t *testing.T) {
	for _, c := range []struct {
		subject string
		want    populationRead
	}{
		{`"repo:acme*"`, populationRead{"exact", wantOwnerLeftOpen}},
		{`"repo:acm?/x"`, populationRead{"exact", wantOwnerLeftOpen}},
		{`["repo:acme*","repo:acme/x"]`, populationRead{"exact", wantOwnerLeftOpen}},
		{`"repo:acme/*"`, populationRead{"exact", "-"}},
		{`"repo:*"`, populationRead{"exact", wantNoOwner}},
		{`["repo:acme*","repo:*"]`, populationRead{"exact", wantNoOwner}},
		{`"repo:acme*:ref:refs/heads/main"`, populationRead{"exact", wantOwnerLeftOpen}},
		{`["repo:acme*","repo:beta*"]`, populationRead{"exact", wantOwnerLeftOpen}},
		{`["repo:acme*","repo:acmex*"]`, populationRead{"exact", wantOwnerLeftOpen}},
		{`["repo:acme*","repo:beta/x","repo:gamm?/*"]`, populationRead{"exact", wantOwnerLeftOpen}},
	} {
		if got := rulesRead(t, AdmitsFor([]byte(githubSubject(c.subject)), nil))["1/0"]; got != c.want {
			t.Errorf("subject %s: %+v, want %+v", c.subject, got, c.want)
		}
	}
}

// TestExternalIDOfWildcardsAlone: a StringLike pattern on sts:ExternalId
// written of wildcards alone, "?*", "*?" or "??*", matches whatever value
// of some length the caller chooses to send, so it asks for no external ID
// in particular, as "*" does; one such pattern in a list is enough. A
// pattern holding any other character is an external ID the caller must
// know, and asks for one.
func TestExternalIDOfWildcardsAlone(t *testing.T) {
	for _, c := range []struct {
		root      bool
		condition string
		want      string
	}{
		{false, `{"StringLike":{"sts:ExternalId":"?*"}}`, wantNoExternalID},
		{true, `{"StringLike":{"sts:ExternalId":"*?"}}`, wantNoExternalID},
		{false, `{"StringLike":{"sts:ExternalId":"??*"}}`, wantNoExternalID},
		{true, `{"StringLike":{"sts:ExternalId":["vendor-abc","?*"]}}`, wantNoExternalID},
		{false, `{"StringLike":{"sts:ExternalId":"abc*"}}`, "-"},
		{true, `{"StringLike":{"sts:ExternalId":"?abc"}}`, "-"},
		{false, `{"StringLike":{"sts:ExternalId":"?*"},"StringEquals":{"sts:ExternalId":"vendor-abc"}}`, "-"},
	} {
		principal := vendorRole
		if c.root {
			principal = vendorRoot
		}
		got := rulesRead(t, AdmitsFor([]byte(trustOne("Allow", principal, "sts:AssumeRole", c.condition)), nil))["1/0"]
		if got != (populationRead{"exact", c.want}) {
			t.Errorf("%s under %s: %+v, want exact and %s", c.condition, principal, got, c.want)
		}
	}
}

// rulesByOwner is the rule each population of an Allow grant meets, by the
// one owner it is pinned to, "-" when it meets none.
func rulesByOwner(t *testing.T, answer []byte) map[string]string {
	t.Helper()
	var a struct {
		Grants []struct {
			Effect      string `json:"effect"`
			Populations []struct {
				Owners []struct {
					Value string `json:"value"`
				} `json:"owners"`
				Finding *struct {
					Rule string `json:"rule"`
				} `json:"finding"`
			} `json:"populations"`
		} `json:"grants"`
	}
	if err := json.Unmarshal(answer, &a); err != nil {
		t.Fatalf("the answer is not JSON: %v\n%s", err, answer)
	}
	read := map[string]string{}
	for _, g := range a.Grants {
		for _, p := range g.Populations {
			if g.Effect != "Allow" || len(p.Owners) != 1 {
				continue
			}
			read[p.Owners[0].Value] = "-"
			if p.Finding != nil {
				read[p.Owners[0].Value] = p.Finding.Rule
			}
		}
	}
	return read
}

// TestDenyRefusesTheWayIn: a way in that a Deny of the same policy, read
// exactly, provably refuses whole is no way in, and meets no rule, though
// the Allow still places it. A Deny that refuses only part of it, one on
// another action, or one the engine could not read and left unapplied,
// refuses it not provably, and the rule still names it.
func TestDenyRefusesTheWayIn(t *testing.T) {
	const partner = "111122223333"
	fixture := func(name string) string {
		b, err := os.ReadFile("../../testdata/fixes/" + name + "/aws.json")
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	allowAndDeny := func(deny string) string {
		return `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::` + partner + `:root"},"Action":"sts:AssumeRole"},` + deny + `]}`
	}
	for _, c := range []struct {
		name, document, owners string
		want                   map[string]string
	}{
		{"the Deny names the outsider the Allow names", fixture("05-deny-names-the-outsider"), "aws:444455556666\n",
			map[string]string{partner: "-", "444455556666": "-"}},
		{"the Deny names the outsider, nobody declared", fixture("05-deny-names-the-outsider"), "",
			map[string]string{partner: "-", "444455556666": wantNoExternalID}},
		{"the Deny names every AWS principal", allowAndDeny(`{"Effect":"Deny","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}`), "",
			map[string]string{partner: "-"}},
		{"the Deny names one role in the account", allowAndDeny(`{"Effect":"Deny","Principal":{"AWS":"arn:aws:iam::` + partner + `:role/x"},"Action":"sts:AssumeRole"}`), "",
			map[string]string{partner: wantNoExternalID}},
		{"the Deny is on another action", allowAndDeny(`{"Effect":"Deny","Principal":{"AWS":"arn:aws:iam::` + partner + `:root"},"Action":"sts:TagSession"}`), "",
			map[string]string{partner: wantNoExternalID}},
		{"the Deny's condition is not read", allowAndDeny(`{"Effect":"Deny","Principal":{"AWS":"arn:aws:iam::` + partner + `:root"},"Action":"sts:AssumeRole","Condition":{"IpAddress":{"aws:SourceIp":"203.0.113.0/24"}}}`), "",
			map[string]string{partner: wantNoExternalID}},
	} {
		if got := rulesByOwner(t, AdmitsFor([]byte(c.document), []byte(c.owners))); !maps.Equal(got, c.want) {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
		// Marked again with the same owners, from an answer read with none,
		// the answer says the same.
		if got := rulesByOwner(t, remarkNow(AdmitsFor([]byte(c.document), nil), c.owners)); !maps.Equal(got, c.want) {
			t.Errorf("%s, marked again: %v, want %v", c.name, got, c.want)
		}
	}
}

// inputValues are the inputs every finding carries, each always present,
// by name, with the values it takes. ownerLeftOpen, the starts of an
// owner's name a subject writes, is a list of the policy's own text, empty
// where it writes none, and takes no value from a list. An input another
// reading supplies, not made yet, is not-checked or not-read, and present
// all the same: a consumer that missed it would read it as nothing to say.
var inputValues = map[string][]string{
	"noSecret":        {"yes", "no"},
	"ownerLeftOpen":   nil,
	"externalId":      {"required", "absent", "not-applicable", "not-known"},
	"refs":            {"not-read"},
	"management":      {"yes", "no", "not-known"},
	"registrableName": {"not-checked"},
	"danglingIssuer":  {"not-checked"},
	"reach":           {"not-read"},
	"used":            {"not-read"},
}

// inputsRead is one finding as the inputs test reads it: its rule, and its
// inputs each as the JSON written, so that one left out reads as missing
// and a null as null. present is false when the finding has no inputs.
type inputsRead struct {
	rule    string
	present bool
	inputs  map[string]json.RawMessage
}

// inputsOf is every finding of an answer by "grant/population", as
// rulesRead numbers them.
func inputsOf(t *testing.T, answer []byte) map[string]inputsRead {
	t.Helper()
	var a struct {
		Grants []struct {
			Number      int `json:"number"`
			Populations []struct {
				Finding *struct {
					Rule   string                     `json:"rule"`
					Inputs map[string]json.RawMessage `json:"inputs"`
				} `json:"finding"`
			} `json:"populations"`
		} `json:"grants"`
	}
	if err := json.Unmarshal(answer, &a); err != nil {
		t.Fatalf("the answer is not JSON: %v\n%s", err, answer)
	}
	read := map[string]inputsRead{}
	for _, g := range a.Grants {
		for i, p := range g.Populations {
			if p.Finding != nil {
				read[strconv.Itoa(g.Number)+"/"+strconv.Itoa(i)] = inputsRead{p.Finding.Rule, p.Finding.Inputs != nil, p.Finding.Inputs}
			}
		}
	}
	return read
}

// inputsHold checks one finding's inputs: every input present, none
// beside them, each a value it takes, and each as its rule has it: no
// secret where anyone on the platform gets in and the way in asks for no
// external ID, the start of an owner's name where the rule says one is
// left open, and an external ID only of an AWS principal, asked for by
// none an outside account meets its rule with. A way in that asks for an
// external ID asks the caller to know it, so it is never one with no
// secret.
func inputsHold(t *testing.T, where string, f inputsRead) {
	t.Helper()
	if !f.present {
		t.Errorf("%s: the finding %s has no inputs", where, f.rule)
		return
	}
	value := map[string]string{}
	for name, allowed := range inputValues {
		raw, ok := f.inputs[name]
		if !ok {
			t.Errorf("%s: the finding %s has no input %s", where, f.rule, name)
			continue
		}
		if name == "ownerLeftOpen" {
			continue
		}
		var v string
		if err := json.Unmarshal(raw, &v); err != nil || v == "" {
			t.Errorf("%s: the finding %s has %s %s, not a string with text", where, f.rule, name, raw)
			continue
		}
		value[name] = v
		if allowed != nil && !slices.Contains(allowed, v) {
			t.Errorf("%s: the finding %s has %s %q, none of %v", where, f.rule, name, v, allowed)
		}
	}
	for name := range f.inputs {
		if _, ok := inputValues[name]; !ok {
			t.Errorf("%s: the finding %s has an input %s nobody named", where, f.rule, name)
		}
	}
	webIdentity := f.rule == wantNoOwner || f.rule == wantOwnerLeftOpen
	var starts []string
	if raw, ok := f.inputs["ownerLeftOpen"]; ok {
		if err := json.Unmarshal(raw, &starts); err != nil || starts == nil || slices.Contains(starts, "") {
			t.Errorf("%s: the finding %s has ownerLeftOpen %s, not a list of strings with text", where, f.rule, raw)
		}
	}
	if (len(starts) > 0) != (f.rule == wantOwnerLeftOpen) {
		t.Errorf("%s: the finding %s has ownerLeftOpen %s", where, f.rule, f.inputs["ownerLeftOpen"])
	}
	for i, start := range starts {
		for j, other := range starts {
			if i != j && strings.HasPrefix(start, other) || j == i+1 && other <= start {
				t.Errorf("%s: the finding %s has ownerLeftOpen %s, not in byte order, each once, none beginning with another", where, f.rule, f.inputs["ownerLeftOpen"])
			}
		}
	}
	if anyone := (webIdentity || f.rule == wantAnyAccount) && value["externalId"] != "required"; (value["noSecret"] == "yes") != anyone {
		t.Errorf("%s: the finding %s has noSecret %q and externalId %q", where, f.rule, value["noSecret"], value["externalId"])
	}
	if value["noSecret"] == "yes" && value["externalId"] != "absent" && value["externalId"] != "not-applicable" {
		t.Errorf("%s: the finding %s has noSecret yes and externalId %q", where, f.rule, value["externalId"])
	}
	if (value["externalId"] == "not-applicable") != webIdentity || f.rule == wantNoExternalID && value["externalId"] != "absent" {
		t.Errorf("%s: the finding %s has externalId %q", where, f.rule, value["externalId"])
	}
}

// inputsWith is the inputs a finding of one policy alone carries, with the
// three the rules read written over them: whether anyone on the platform
// gets in, the starts of an owner's name left open, none for nil, and the
// external ID. Read alone, a policy names no account it is in, so where it
// is is not known.
func inputsWith(noSecret string, ownerLeftOpen []string, externalID string) map[string]any {
	if ownerLeftOpen == nil {
		ownerLeftOpen = []string{}
	}
	return map[string]any{
		"noSecret": noSecret, "ownerLeftOpen": ownerLeftOpen, "externalId": externalID, "refs": "not-read",
		"management": "not-known", "registrableName": "not-checked", "danglingIssuer": "not-checked", "reach": "not-read", "used": "not-read",
	}
}

// TestFindingInputs: every finding carries its inputs, the facts its rule
// rests on and the ones other readings will add, each always present, none
// a judgement, over the corpus, the fixtures beside it and a scan's
// findings; each case below has the inputs named; and where a role is is
// what its bundle says of the AWS Organization, known only of an account
// in one.
func TestFindingInputs(t *testing.T) {
	examined := 0
	hold := func(where string, answer []byte) {
		for key, f := range inputsOf(t, answer) {
			examined++
			inputsHold(t, where+" population "+key, f)
		}
	}
	for _, name := range ringsCases(t) {
		doc, owners := ringsCase(t, name)
		hold(name, AdmitsFor(doc, owners))
	}
	for _, f := range ruleFixtures {
		hold(f.name, AdmitsFor([]byte(f.document), []byte(f.owners)))
	}

	for _, c := range []struct {
		name, document, population string
		want                       map[string]any
	}{
		{"repo:acme*", githubSubject(`"repo:acme*"`), "1/0", inputsWith("yes", []string{"acme"}, "not-applicable")},
		{"repo:acm?/x", githubSubject(`"repo:acm?/x"`), "1/0", inputsWith("yes", []string{"acm"}, "not-applicable")},
		{"repo:acme* and repo:acme/x", githubSubject(`["repo:acme*","repo:acme/x"]`), "1/0", inputsWith("yes", []string{"acme"}, "not-applicable")},
		{"repo:beta* and repo:acme*", githubSubject(`["repo:beta*","repo:acme*"]`), "1/0", inputsWith("yes", []string{"acme", "beta"}, "not-applicable")},
		{"repo:acmex* and repo:acme*", githubSubject(`["repo:acmex*","repo:acme*"]`), "1/0", inputsWith("yes", []string{"acme"}, "not-applicable")},
		{"repo:*", githubSubject(`"repo:*"`), "1/0", inputsWith("yes", nil, "not-applicable")},
		{"no subject", trustOne("Allow", githubIssuer, "sts:AssumeRoleWithWebIdentity", `{"StringEquals":{`+githubAud+`}}`), "1/0", inputsWith("yes", nil, "not-applicable")},
		{"an outside account", trustOne("Allow", vendorRoot, "sts:AssumeRole", ""), "1/0", inputsWith("no", nil, "absent")},
		{"an outside role, external ID like anything", trustOne("Allow", vendorRole, "sts:AssumeRole", `{"StringLike":{"sts:ExternalId":"*"}}`), "1/0", inputsWith("no", nil, "absent")},
		{"an outside role, external ID of wildcards alone", trustOne("Allow", vendorRole, "sts:AssumeRole", `{"StringLike":{"sts:ExternalId":"?*"}}`), "1/0", inputsWith("no", nil, "absent")},
		{"any AWS account", trustOne("Allow", anyAWS, "sts:AssumeRole", ""), "2/0", inputsWith("yes", nil, "absent")},
		{"any AWS account, an external ID asked", trustOne("Allow", anyAWS, "sts:AssumeRole", `{"StringEquals":{"sts:ExternalId":"vendor-abc"}}`), "2/0", inputsWith("no", nil, "required")},
		{"any AWS account, an external ID like a value", trustOne("Allow", anyAWS, "sts:AssumeRole", `{"StringLike":{"sts:ExternalId":"abc*"}}`), "2/0", inputsWith("no", nil, "required")},
		{"any AWS account, an external ID of wildcards alone", trustOne("Allow", anyAWS, "sts:AssumeRole", `{"StringLike":{"sts:ExternalId":"??*"}}`), "2/0", inputsWith("yes", nil, "absent")},
		{"any AWS account, an external ID like anything", trustOne("Allow", anyAWS, "sts:AssumeRole", `{"StringLike":{"sts:ExternalId":"*"}}`), "2/0", inputsWith("yes", nil, "absent")},
		{"any AWS account, an external ID equal if it exists", trustOne("Allow", anyAWS, "sts:AssumeRole", `{"StringEqualsIfExists":{"sts:ExternalId":"vendor-abc"}}`), "2/0", inputsWith("yes", nil, "absent")},
	} {
		answer := AdmitsFor([]byte(c.document), nil)
		hold(c.name, answer)
		f, ok := inputsOf(t, answer)[c.population]
		if !ok {
			t.Errorf("%s: no finding on population %s", c.name, c.population)
			continue
		}
		var got map[string]any
		raw, _ := json.Marshal(f.inputs)
		if err := json.Unmarshal(raw, &got); err != nil {
			t.Fatalf("%s: inputs %s: %v", c.name, raw, err)
		}
		gotJSON, _ := json.Marshal(got)
		if wantJSON, _ := json.Marshal(c.want); !bytes.Equal(gotJSON, wantJSON) {
			t.Errorf("%s: inputs %s, want %s", c.name, gotJSON, wantJSON)
		}
	}

	for _, c := range []struct {
		name       string
		edit       func(map[string]any)
		management string
	}{
		{"an account its Organization's management account manages", organizationMember(management, nil), "no"},
		{"the Organization's management account", organizationMember(bundleAccount, nil), "yes"},
		{"an account in no Organization", statusOnly("not-a-member"), "not-known"},
		{"an Organization AWS refused to describe", statusOnly("refused"), "not-known"},
		{"a bundle that did not read the Organization", nil, "not-known"},
	} {
		bundle := bundleOf(t, c.edit, testRole{"stranger", strangerTrust}, testRole{"deploy", githubSubject(`"repo:*"`)}, testRole{"own", ownAccountTrust})
		f := findingsOf(t, bundle, "")
		if f.Error != "" {
			t.Fatalf("%s: the bundle is refused: %s", c.name, f.Error)
		}
		found := 0
		for _, role := range f.Roles {
			for key, read := range inputsOf(t, role.Answer) {
				found++
				inputsHold(t, c.name+", the role "+role.Name+" population "+key, read)
				if got := string(read.inputs["management"]); got != strconv.Quote(c.management) {
					t.Errorf("%s, the role %s population %s: management %s, want %q", c.name, role.Name, key, got, c.management)
				}
			}
		}
		examined += found
		if found != 2 {
			t.Errorf("%s: %d findings, want one for the stranger and one for deploy", c.name, found)
		}
	}
	if examined == 0 {
		t.Fatal("no finding was examined")
	}
	if !t.Failed() {
		t.Logf("%d findings examined", examined)
	}
}

// TestRemarkKeepsWhereTheRoleIs: owners move nothing of where a role is,
// so an answer a scan's findings kept, marked again with the owners
// declared now, is the answer the findings give with them, each finding
// saying where the role is as the findings said it. An answer that kept no
// finding says nowhere where its role is, so a finding it meets once
// marked again says not-known, never a guess.
func TestRemarkKeepsWhereTheRoleIs(t *testing.T) {
	for _, c := range []struct {
		name, managedBy, where string
	}{
		{"the Organization's management account", bundleAccount, "yes"},
		{"an account its Organization's management account manages", management, "no"},
	} {
		bundle := bundleOf(t, organizationMember(c.managedBy, nil), testRole{"stranger", strangerTrust}, testRole{"deploy", githubSubject(`"repo:*"`)})
		kept := findingsOf(t, bundle, "")
		said := 0
		for _, now := range []string{"", "github:acme\n", "aws:444455556666\n"} {
			want := findingsOf(t, bundle, now)
			for i, role := range kept.Roles {
				got := remarkNow(role.Answer, now)
				if !bytes.Equal(got, want.Roles[i].Answer) {
					t.Errorf("%s, the role %s marked again with %q:\n got %s\nwant %s", c.name, role.Name, now, got, want.Roles[i].Answer)
				}
				for key, f := range inputsOf(t, got) {
					said++
					if m := string(f.inputs["management"]); m != strconv.Quote(c.where) {
						t.Errorf("%s, the role %s marked again with %q, population %s: management %s, want %q", c.name, role.Name, now, key, m, c.where)
					}
				}
			}
		}
		if said == 0 {
			t.Errorf("%s: no finding marked again; where the role is went unexamined", c.name)
		}
		declared := remarkNow(kept.Roles[0].Answer, "aws:444455556666\n")
		if f := inputsOf(t, declared); len(f) != 0 {
			t.Fatalf("%s: the stranger declared still meets %v", c.name, f)
		}
		f, ok := inputsOf(t, remarkNow(declared, ""))["1/0"]
		if !ok || f.rule != wantNoExternalID || string(f.inputs["management"]) != `"not-known"` {
			t.Errorf("%s: declared, then withdrawn from an answer with no finding: %+v, want %s and management not-known", c.name, f, wantNoExternalID)
		}
	}
}

// TestRemarkDeclinesWhereTheRoleIsNotKept: the findings of one answer are
// of one role, in one place, so an answer whose findings say two places,
// or one that no finding this build writes says, is not an answer this
// build wrote, and is declined, never marked again with a place guessed.
func TestRemarkDeclinesWhereTheRoleIsNotKept(t *testing.T) {
	twoOutsiders := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":["arn:aws:iam::444455556666:root","arn:aws:iam::555566667777:root"]},"Action":"sts:AssumeRole"}]}`
	kept := findingsOf(t, bundleOf(t, organizationMember(management, nil), testRole{"two", twoOutsiders}), "").Roles[0].Answer
	if n := bytes.Count(kept, []byte(`"management":"no"`)); n != 2 {
		t.Fatalf("the answer kept has %d findings saying management no, want 2:\n%s", n, kept)
	}
	if _, declined := declinedOf(remarkNow(kept, "")); declined {
		t.Fatal("the answer kept, unchanged, is declined")
	}
	for _, c := range []struct{ name, answer string }{
		{"two places", strings.Replace(string(kept), `"management":"no"`, `"management":"yes"`, 1)},
		{"a place no finding says", strings.ReplaceAll(string(kept), `"management":"no"`, `"management":"production"`)},
		{"no place", strings.ReplaceAll(string(kept), `"management":"no"`, `"management":""`)},
	} {
		d, declined := declinedOf(remarkNow([]byte(c.answer), ""))
		if !declined || d.Declined != "answer" {
			t.Errorf("%s: %+v, declined %v; want declined as answer", c.name, d, declined)
		}
	}
}
