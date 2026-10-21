package report

import (
	"bytes"
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"regexp"
	"slices"
	"strings"
	"testing"

	"pgregory.net/rapid"
)

// A finding's id and pairing key, read as a consumer reads them: through
// the JSON of a scan's findings, so that a build whose answer lacks them
// fails here on what a reader would see.

// keyedFinding is one finding as a reader keys it.
type keyedFinding struct{ rule, id, pairing string }

// failer is what the helpers below report through: a test, or one check of
// a property.
type failer interface {
	Helper()
	Errorf(format string, args ...any)
	Fatalf(format string, args ...any)
}

// keyedFindings is every finding of an answer, in the answer's order.
func keyedFindings(t failer, answer []byte) []keyedFinding {
	t.Helper()
	var a struct {
		Error  string `json:"error"`
		Grants []struct {
			Populations []struct {
				Finding *struct {
					Rule       string `json:"rule"`
					ID         string `json:"id"`
					PairingKey string `json:"pairingKey"`
				} `json:"finding"`
			} `json:"populations"`
		} `json:"grants"`
	}
	if err := json.Unmarshal(answer, &a); err != nil || a.Error != "" {
		t.Fatalf("not an answer: %v %s\n%s", err, a.Error, answer)
	}
	var out []keyedFinding
	for _, g := range a.Grants {
		for _, p := range g.Populations {
			if p.Finding != nil {
				out = append(out, keyedFinding{p.Finding.Rule, p.Finding.ID, p.Finding.PairingKey})
			}
		}
	}
	return out
}

// roleFindings is every finding of the one role of a bundle whose role is
// named name and trusts policy, read with nothing declared.
func roleFindings(t *testing.T, name, policy string) []keyedFinding {
	t.Helper()
	f := findingsOf(t, bundleOf(t, nil, testRole{name, policy}), "")
	if len(f.Roles) != 1 {
		t.Fatalf("%d roles, want 1", len(f.Roles))
	}
	return keyedFindings(t, f.Roles[0].Answer)
}

// isKey reports whether s is a key as the engine writes one: lowercase hex
// of a SHA-256.
func isKey(s string) bool {
	if len(s) != 2*sha256.Size {
		return false
	}
	return strings.Trim(s, "0123456789abcdef") == ""
}

// keysHeld fails for every finding that does not carry both keys.
func keysHeld(t failer, where string, findings []keyedFinding) {
	t.Helper()
	for _, f := range findings {
		if !isKey(f.id) || !isKey(f.pairing) {
			t.Errorf("%s: the finding %s has the id %q and the pairing key %q; want both the lowercase hex of a SHA-256", where, f.rule, f.id, f.pairing)
		}
	}
}

// keysWritten is one finding's keys as an answer writes them, after its
// rule. No string of an answer holds it, since a quotation mark in one is
// escaped.
var keysWritten = regexp.MustCompile(`,"id":"[0-9a-f]{64}","pairingKey":"[0-9a-f]{64}"`)

// unkeyed is an answer with its findings' keys taken out, as an answer that
// names no role, a policy's alone, writes them.
func unkeyed(answer []byte) []byte { return keysWritten.ReplaceAll(answer, nil) }

// roleUnkeyed is the answer to a role of a bundle without its findings'
// keys, which name the role as a policy alone does not. It fails unless
// every finding of the answer carries both.
func roleUnkeyed(t fataler, answer []byte) []byte {
	if keyed, found := len(keysWritten.FindAllIndex(answer, -1)), bytes.Count(answer, []byte(`"finding":{`)); keyed != found {
		t.Fatalf("%d of the %d findings of the answer carry their keys:\n%s", keyed, found, answer)
	}
	return unkeyed(answer)
}

// statement is one statement of a trust policy, as JSON: its Sid when it
// has one, its principal, its action and its Condition when it has one.
func statement(sid, principal, action, condition string) string {
	s := `{`
	if sid != "" {
		s += `"Sid":"` + sid + `",`
	}
	s += `"Effect":"Allow","Principal":` + principal + `,"Action":` + action
	if condition != "" {
		s += `,"Condition":` + condition
	}
	return s + `}`
}

// trustOf is a trust policy of the statements, as policyOf writes it.
func trustOf(statements ...string) string { return string(policyOf(statements...)) }

// indented is a policy laid out by json.Indent, which changes nothing but
// the whitespace between its tokens.
func indented(t failer, policy, prefix, indent string) string {
	t.Helper()
	var b bytes.Buffer
	if err := json.Indent(&b, []byte(policy), prefix, indent); err != nil {
		t.Fatalf("%v\n%s", err, policy)
	}
	return b.String()
}

// The ways in the id tests are written with: an outside account let in
// from two address ranges, which the engine does not read, and GitHub's
// tokens with a subject that names no owner.
const (
	partnerRoot  = `{"AWS":"arn:aws:iam::444455556666:root"}`
	assumeRole   = `"sts:AssumeRole"`
	fromRanges   = `{"IpAddress":{"aws:SourceIp":["10.0.0.0/8","192.168.0.0/16"]}}`
	githubAction = `"sts:AssumeRoleWithWebIdentity"`
	anyRepo      = `{"StringEquals":{` + githubAud + `},"StringLike":{"token.actions.githubusercontent.com:sub":"repo:*"}}`
)

var (
	partnerWay = statement("", partnerRoot, assumeRole, fromRanges)
	ciWay      = statement("", githubIssuer, githubAction, anyRepo)
)

// TestFindingIDKept: a finding's id and pairing key are the same however
// the policy writes the way in, wherever nothing the engine reads of it,
// and no condition it leaves unread, changes: its whitespace, the order of
// its statements, their Sids, the case of a condition key, a value written
// alone or as a list of one, the order and repeats of a list's values, and
// an account written bare or as its root ARN. One way in written in two
// statements is one id, met in two places.
func TestFindingIDKept(t *testing.T) {
	both := trustOf(partnerWay, ciWay)
	cases := []struct {
		name, a, b string
		// places is how many findings b holds, when it is not as many as a
		places int
	}{
		{name: "whitespace", a: both, b: indented(t, both, "\t", "    ")},
		{name: "statement order", a: both, b: trustOf(ciWay, partnerWay)},
		{name: "Sid", a: both, b: trustOf(statement("Partner", partnerRoot, assumeRole, fromRanges), statement("Deploys", githubIssuer, githubAction, anyRepo))},
		{name: "key case",
			a: trustOf(statement("", partnerRoot, assumeRole, `{"IpAddress":{"aws:SourceIp":"10.0.0.0/8"},"StringLike":{"sts:ExternalId":"*"}}`), ciWay),
			b: trustOf(statement("", partnerRoot, assumeRole, `{"IpAddress":{"AWS:SOURCEIP":"10.0.0.0/8"},"StringLike":{"STS:externalID":"*"}}`),
				statement("", githubIssuer, githubAction, `{"StringEquals":{"token.actions.githubusercontent.com:AUD":"sts.amazonaws.com"},"StringLike":{"token.actions.githubusercontent.com:Sub":"repo:*"}}`))},
		{name: "a value alone or a list of one",
			a: trustOf(statement("", partnerRoot, assumeRole, `{"IpAddress":{"aws:SourceIp":"10.0.0.0/8"}}`), ciWay),
			b: trustOf(statement("", `{"AWS":["arn:aws:iam::444455556666:root"]}`, `["sts:AssumeRole"]`, `{"IpAddress":{"aws:SourceIp":["10.0.0.0/8"]}}`),
				statement("", githubIssuer, `["sts:AssumeRoleWithWebIdentity"]`, `{"StringEquals":{`+githubAud+`},"StringLike":{"token.actions.githubusercontent.com:sub":["repo:*"]}}`))},
		{name: "the order and repeats of a list's values",
			a: trustOf(partnerWay, statement("", githubIssuer, githubAction, `{"StringEquals":{`+githubAud+`},"StringLike":{"token.actions.githubusercontent.com:sub":["repo:*:environment:production","repo:*:ref:refs/heads/main"]}}`)),
			b: trustOf(statement("", partnerRoot, assumeRole, `{"IpAddress":{"aws:SourceIp":["192.168.0.0/16","10.0.0.0/8","192.168.0.0/16"]}}`),
				statement("", githubIssuer, githubAction, `{"StringEquals":{`+githubAud+`},"StringLike":{"token.actions.githubusercontent.com:sub":["repo:*:ref:refs/heads/main","repo:*:environment:production","repo:*:ref:refs/heads/main"]}}`))},
		{name: "an account bare or as its root ARN",
			a: trustOf(partnerWay),
			b: trustOf(statement("", `{"AWS":"444455556666"}`, assumeRole, fromRanges))},
		{name: "one way in written in two statements",
			a: trustOf(partnerWay), b: trustOf(partnerWay, statement("Again", partnerRoot, assumeRole, fromRanges)), places: 2},
	}
	for _, c := range cases {
		ka, kb := roleFindings(t, "deploy", c.a), roleFindings(t, "deploy", c.b)
		if len(ka) == 0 {
			t.Fatalf("%s: the policy meets no rule, so its id went unexamined:\n%s", c.name, c.a)
		}
		keysHeld(t, c.name, ka)
		keysHeld(t, c.name, kb)
		if want := cmp.Or(c.places, len(ka)); len(kb) != want {
			t.Errorf("%s: %d findings, want %d: %v", c.name, len(kb), want, kb)
		}
		order := func(x, y keyedFinding) int { return strings.Compare(x.rule+x.id+x.pairing, y.rule+y.id+y.pairing) }
		slices.SortFunc(ka, order)
		slices.SortFunc(kb, order)
		if got, want := slices.Compact(kb), slices.Compact(ka); !slices.Equal(got, want) {
			t.Errorf("%s: the findings are keyed\n %v\nwhere the policy written the other way keys them\n %v", c.name, got, want)
		}
	}
}

// TestFindingIDChanges: a finding's id is another wherever what it is
// changes: a value or an operator that changes what the engine reads, a
// condition the engine does not read added, removed or given another
// value, and the role renamed or moved. A change to the condition alone
// keeps the pairing key, which pairs the finding with what it was; a
// change to the role changes both.
func TestFindingIDChanges(t *testing.T) {
	gh := func(sub string) string {
		return trustOf(statement("", githubIssuer, githubAction, `{"StringEquals":{`+githubAud+`},"StringLike":{"token.actions.githubusercontent.com:sub":`+sub+`}}`))
	}
	outsider := func(condition string) string { return trustOf(statement("", partnerRoot, assumeRole, condition)) }
	const mfa = `"Bool":{"aws:MultiFactorAuthPresent":"true"}`
	const ranges = `"IpAddress":{"aws:SourceIp":"10.0.0.0/8"}`
	cases := []struct {
		name         string
		roleA, a     string
		roleB, b     string
		samePairing  bool
		ruleExpected string
	}{
		{"a subject's value", "deploy", gh(`"repo:*"`), "deploy", gh(`"repo:*:ref:refs/heads/main"`), true, wantNoOwner},
		{"an external ID's value", "deploy", outsider(`{"StringLike":{"sts:ExternalId":"*"}}`), "deploy", outsider(`{"StringLike":{"sts:ExternalId":"?*"}}`), true, wantNoExternalID},
		{"an operator on a key the engine reads", "deploy", outsider(`{"StringEquals":{"aws:PrincipalArn":"arn:aws:iam::444455556666:role/ci*"}}`), "deploy", outsider(`{"StringLike":{"aws:PrincipalArn":"arn:aws:iam::444455556666:role/ci*"}}`), true, wantNoExternalID},
		{"an operator on a key the engine does not read", "deploy", outsider(`{` + ranges + `}`), "deploy", outsider(`{"NotIpAddress":{"aws:SourceIp":"10.0.0.0/8"}}`), true, wantNoExternalID},
		{"a value of a condition the engine does not read", "deploy", outsider(`{` + mfa + `}`), "deploy", outsider(`{"Bool":{"aws:MultiFactorAuthPresent":"false"}}`), true, wantNoExternalID},
		{"a condition the engine does not read added", "deploy", trustOf(statement("", partnerRoot, assumeRole, "")), "deploy", outsider(`{` + mfa + `}`), true, wantNoExternalID},
		{"a condition the engine does not read removed", "deploy", outsider(`{` + ranges + `,` + mfa + `}`), "deploy", outsider(`{` + ranges + `}`), true, wantNoExternalID},
		{"the role renamed", "deploy", trustOf(partnerWay), "deploy-2", trustOf(partnerWay), false, wantNoExternalID},
		{"the role moved", "ci/deploy", trustOf(partnerWay), "build/deploy", trustOf(partnerWay), false, wantNoExternalID},
	}
	for _, c := range cases {
		ka, kb := roleFindings(t, c.roleA, c.a), roleFindings(t, c.roleB, c.b)
		if len(ka) != 1 || len(kb) != 1 {
			t.Errorf("%s: %d and %d findings, want one each: %v %v", c.name, len(ka), len(kb), ka, kb)
			continue
		}
		a, b := ka[0], kb[0]
		keysHeld(t, c.name, ka)
		keysHeld(t, c.name, kb)
		if a.rule != c.ruleExpected || b.rule != c.ruleExpected {
			t.Errorf("%s: the rules are %s and %s, want %s for both", c.name, a.rule, b.rule, c.ruleExpected)
		}
		if a.id == b.id {
			t.Errorf("%s: both are the id %q", c.name, a.id)
		}
		if (a.pairing == b.pairing) != c.samePairing {
			t.Errorf("%s: the pairing keys are %q and %q; want them the same: %v", c.name, a.pairing, b.pairing, c.samePairing)
		}
	}
}

// The fixture whose keys are pinned: the role deploy of the bundles above,
// trusting an outside account by its root ARN with nothing asked of it,
// which meets aws-account/no-external-id. Its condition is the one claim
// its term holds, the account, rendered as the engine renders it.
const (
	pinnedRole      = "arn:aws:iam::123456789012:role/deploy"
	pinnedCondition = `aws:principalaccount="444455556666"`
	pinnedID        = "36dc84a4b9793cce52815111fa52affb5a1fed0075f55ce5300fedbe0bce19b7"
	pinnedPairing   = "1e31930ab13d99c3e44d5ee90e3d8d9440a439ba755d6efcadd7ee3b26914515"
)

// recipe is the SHA-256 of the array a finding's keys are made from, as
// encoding/json writes it, in lowercase hex: the id's array when condition
// is given, the pairing key's, which has none, when it is nil.
func recipe(t failer, rule, role, issuer string, condition []string) string {
	t.Helper()
	parts := []any{"cloudarq.finding/1", rule, role, issuer}
	if condition != nil {
		parts = append(parts, condition)
	}
	b, err := json.Marshal(parts)
	if err != nil {
		t.Fatalf("%v", err)
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// TestFindingIDPinned: one fixture's id and pairing key, as hex, so that a
// change to how either is made fails here; each the recipe's hash of its
// array, the rule in it, so that another rule is another id; the same
// whichever of the bundle's entry points answers the role; and neither for
// the same policy read alone, which names no role.
func TestFindingIDPinned(t *testing.T) {
	bundle := bundleOf(t, nil, testRole{"deploy", strangerTrust})
	f := findingsOf(t, bundle, "")
	if len(f.Roles) != 1 || f.Roles[0].Arn != pinnedRole {
		t.Fatalf("the bundle's roles are %+v, want the one %s", f.Roles, pinnedRole)
	}
	got := keyedFindings(t, f.Roles[0].Answer)
	want := []keyedFinding{{wantNoExternalID, pinnedID, pinnedPairing}}
	if !slices.Equal(got, want) {
		t.Errorf("the findings are keyed %v, want %v", got, want)
	}
	if r := recipe(t, wantNoExternalID, pinnedRole, "aws:sts", []string{pinnedCondition}); r != pinnedID {
		t.Errorf("the recipe gives the id %s, and the pinned one is %s", r, pinnedID)
	}
	if r := recipe(t, wantNoExternalID, pinnedRole, "aws:sts", nil); r != pinnedPairing {
		t.Errorf("the recipe gives the pairing key %s, and the pinned one is %s", r, pinnedPairing)
	}
	for _, other := range wantRules {
		if other != wantNoExternalID && recipe(t, other, pinnedRole, "aws:sts", []string{pinnedCondition}) == pinnedID {
			t.Errorf("the rule %s gives the id of %s", other, wantNoExternalID)
		}
	}
	b, err := ReadBundle(bundle)
	if err != nil {
		t.Fatal(err)
	}
	finding, _ := b.Finding(b.Roles[0], nil)
	for name, a := range map[string]Answer{"AnswerFor": b.AnswerFor(b.Roles[0], nil), "Finding": finding} {
		raw, err := json.Marshal(a)
		if err != nil {
			t.Fatal(err)
		}
		if got := keyedFindings(t, raw); !slices.Equal(got, want) {
			t.Errorf("%s keys the findings %v, want %v", name, got, want)
		}
	}
	alone := keyedFindings(t, AdmitsFor([]byte(strangerTrust), nil))
	if len(alone) != 1 || alone[0] != (keyedFinding{rule: wantNoExternalID}) {
		t.Errorf("the policy read alone keys its findings %v; want one %s with no id and no pairing key", alone, wantNoExternalID)
	}
	if raw := AdmitsFor([]byte(strangerTrust), nil); bytes.Contains(raw, []byte(`"id":`)) || bytes.Contains(raw, []byte(`"pairingKey":`)) {
		t.Errorf("the policy read alone writes an id or a pairing key:\n%s", raw)
	}
}

// TestFindingIDsKeptAcrossOrderAndLayout: whatever the statements of a
// policy, written in another order, laid out with other whitespace and
// given other Sids, its findings are keyed alike.
func TestFindingIDsKeptAcrossOrderAndLayout(t *testing.T) {
	pool := []string{
		partnerWay,
		ciWay,
		statement("", `{"AWS":"arn:aws:iam::555566667777:role/vendor"}`, assumeRole, ""),
		statement("", `{"AWS":"*"}`, assumeRole, ""),
		statement("", githubIssuer, githubAction, `{"StringEquals":{`+githubAud+`},"StringLike":{"token.actions.githubusercontent.com:sub":"repo:acme*"}}`),
		statement("", `{"Service":"lambda.amazonaws.com"}`, assumeRole, ""),
		statement("", partnerRoot, assumeRole, `{"Bool":{"aws:MultiFactorAuthPresent":"true"},"StringLike":{"sts:ExternalId":"*"}}`),
	}
	whitespace := rapid.StringOfN(rapid.SampledFrom([]rune(" \t\n\r")), 0, 3, -1)
	checked := 0
	rapid.Check(t, func(r *rapid.T) {
		chosen := rapid.SliceOfN(rapid.IntRange(0, len(pool)-1), 1, 5).Draw(r, "statements")
		var written []string
		for _, i := range chosen {
			written = append(written, pool[i])
		}
		shuffled := rapid.Permutation(written).Draw(r, "order")
		for i, s := range shuffled {
			if rapid.Bool().Draw(r, "sid") {
				shuffled[i] = `{"Sid":"S` + string(rune('a'+i)) + `",` + s[1:]
			}
		}
		a := roleFindings(t, "deploy", trustOf(written...))
		b := roleFindings(t, "deploy", indented(r, trustOf(shuffled...), whitespace.Draw(r, "prefix"), whitespace.Draw(r, "indent")))
		keysHeld(r, "the policy as drawn", a)
		keysHeld(r, "the policy reordered and laid out again", b)
		order := func(x, y keyedFinding) int { return strings.Compare(x.rule+x.id+x.pairing, y.rule+y.id+y.pairing) }
		slices.SortFunc(a, order)
		slices.SortFunc(b, order)
		if !slices.Equal(a, b) {
			r.Fatalf("the findings are keyed\n %v\nand reordered and laid out again\n %v", a, b)
		}
		if len(a) > 0 {
			checked++
		}
	})
	if checked == 0 {
		t.Error("no drawn policy met a rule, so no id was compared")
	}
}

// TestRemarkKeepsTheFindingID: an answer a scan kept, marked again with
// other owners, keeps each finding's id and pairing key where the finding
// still meets the rule it met, since owners move neither the role, nor the
// way in, nor its condition. A finding met only now has neither, as an
// answer does not name its role; the next read of the role gives them. An
// answer whose keys are not ones this build writes is declined.
func TestRemarkKeepsTheFindingID(t *testing.T) {
	bundle := bundleOf(t, nil, testRole{"stranger", strangerTrust}, testRole{"deploy", githubSubject(`"repo:*"`)})
	kept := findingsOf(t, bundle, "")
	for _, now := range []string{"", "github:acme\n"} {
		for _, role := range kept.Roles {
			before := keyedFindings(t, role.Answer)
			keysHeld(t, role.Name+" as kept", before)
			after := keyedFindings(t, remarkNow(role.Answer, now))
			if len(before) == 0 || !slices.Equal(after, before) {
				t.Errorf("the role %s marked again with %q keys its findings %v; kept, %v", role.Name, now, after, before)
			}
		}
	}
	stranger := kept.Roles[0].Answer
	declared := remarkNow(stranger, "aws:444455556666\n")
	if f := keyedFindings(t, declared); len(f) != 0 {
		t.Fatalf("the stranger declared still meets %v", f)
	}
	if f := keyedFindings(t, remarkNow(declared, "")); len(f) != 1 || f[0] != (keyedFinding{rule: wantNoExternalID}) {
		t.Errorf("the stranger declared, then withdrawn, keys its findings %v; want one %s with no id and no pairing key", f, wantNoExternalID)
	}
	ids := keyedFindings(t, stranger)
	if len(ids) != 1 || !isKey(ids[0].id) || !isKey(ids[0].pairing) {
		t.Fatalf("the stranger kept the findings %v; want one, with its keys", ids)
	}
	for _, c := range []struct{ name, answer string }{
		{"an id that is not hex", strings.Replace(string(stranger), ids[0].id, "not an id", 1)},
		{"an id in capitals", strings.Replace(string(stranger), ids[0].id, strings.ToUpper(ids[0].id), 1)},
		{"a pairing key cut short", strings.Replace(string(stranger), ids[0].pairing, ids[0].pairing[:63], 1)},
		{"an id without its pairing key", strings.Replace(string(stranger), `,"pairingKey":"`+ids[0].pairing+`"`, "", 1)},
		{"a pairing key without its id", strings.Replace(string(stranger), `,"id":"`+ids[0].id+`"`, "", 1)},
	} {
		if c.answer == string(stranger) {
			t.Errorf("%s: the answer kept is unchanged", c.name)
			continue
		}
		d, declined := declinedOf(remarkNow([]byte(c.answer), ""))
		if !declined || d.Declined != "answer" {
			t.Errorf("%s: %+v, declined %v; want declined as answer", c.name, d, declined)
		}
	}
}

// TestBundleFindingIsTheFindingsAnswer: each of a bundle's entry points
// for one role, Finding, AnswerFor and the findings, gives the one answer,
// with where the role is and each finding's keys, for a role in the
// management account of its Organization and for one in another account.
func TestBundleFindingIsTheFindingsAnswer(t *testing.T) {
	for _, managedBy := range []string{bundleAccount, management} {
		bundle := bundleOf(t, organizationMember(managedBy, nil), testRole{"stranger", strangerTrust}, testRole{"deploy", githubSubject(`"repo:*"`)})
		b, err := ReadBundle(bundle)
		if err != nil {
			t.Fatal(err)
		}
		f := findingsOf(t, bundle, "")
		for i, role := range b.Roles {
			finding, _ := b.Finding(role, nil)
			for name, a := range map[string]Answer{"Finding": finding, "AnswerFor": b.AnswerFor(role, nil)} {
				e := &encoder{}
				e.answer(a)
				if !bytes.Equal(e.b, f.Roles[i].Answer) {
					t.Errorf("managed by %s, the role %s: %s answers\n%s\nand the findings\n%s", managedBy, role.Name, name, e.b, f.Roles[i].Answer)
				}
			}
			if len(keyedFindings(t, f.Roles[i].Answer)) == 0 {
				t.Errorf("managed by %s, the role %s meets no rule, so where it is and its keys went unexamined", managedBy, role.Name)
			}
		}
	}
}
