package report

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
)

// fixedOf is what AppendFixed renders, read back.
type fixedOf struct {
	V      int     `json:"v"`
	Policy *string `json:"policy"`
	SHA256 string  `json:"sha256"`
	Error  string  `json:"error"`
}

// The whole fixed policy is made from the bundle the caller holds, for one
// role and one principal, by its offsets: it is the policy with that
// principal removed, or, where that would leave it no statement, the policy
// that lets no one in, the policy the answer's proven fix names by its
// digest, and nothing else. Where the answer proves no fix for that
// principal, or no grant is read from those offsets, or the role or the
// bundle is not one the engine reads, it says why and gives no policy.
func TestFixedIsThePolicyTheProvenFixNames(t *testing.T) {
	twice := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":["arn:aws:iam::111122223333:root","111122223333"]},"Action":"sts:AssumeRole"}]}`
	bundle := bundleOf(t, nil, testRole{"partner", partnerBesideEC2}, testRole{"twice", twice}, testRole{"lambda", serviceTrust}, testRole{"alone", partnerAlone})
	owners := []byte("aws:444455556666")
	arn := "arn:aws:iam::" + bundleAccount + ":role/"
	read := func(b []byte) fixedOf {
		t.Helper()
		var f fixedOf
		if err := json.Unmarshal(b, &f); err != nil || f.V != Version {
			t.Fatalf("%s does not read as what AppendFixed renders: %v", b, err)
		}
		return f
	}
	b, err := ReadBundle(bundle)
	if err != nil {
		t.Fatal(err)
	}
	fix := fixOf(t, b.AnswerFor(b.Roles[0], owners), "arn:aws:iam::111122223333:root")
	if fix.Status != "proven" {
		t.Fatalf("the partner's fix is %+v", *fix)
	}
	got := read(AppendFixed(nil, bundle, owners, arn+"partner", fix.Edit.Leaf.Start, fix.Edit.Leaf.End))
	if got.Policy == nil || *got.Policy != partnerRemoved || got.SHA256 != fix.Edit.SHA256 || got.SHA256 != digest([]byte(partnerRemoved)) || got.Error != "" {
		t.Errorf("the fixed policy is %+v, want the partner removed, with the digest the fix names", got)
	}
	// the same principal, with no owner declared: the edit does not move
	if again := read(AppendFixed(nil, bundle, nil, arn+"partner", fix.Edit.Leaf.Start, fix.Edit.Leaf.End)); again.Policy == nil || *again.Policy != partnerRemoved {
		t.Errorf("with no owner declared the fixed policy is %+v", again)
	}
	// the partner alone in the policy: the policy that lets no one in, with
	// the digest the fix names
	alone := fixOf(t, b.AnswerFor(b.Roles[3], owners), "arn:aws:iam::111122223333:root")
	if alone.Status != "proven" {
		t.Fatalf("the lone partner's fix is %+v", *alone)
	}
	if got := read(AppendFixed(nil, bundle, owners, arn+"alone", alone.Edit.Leaf.Start, alone.Edit.Leaf.End)); got.Policy == nil || *got.Policy != noOneIn || got.SHA256 != alone.Edit.SHA256 || got.SHA256 != digest([]byte(noOneIn)) || got.Error != "" {
		t.Errorf("the fixed policy is %+v, want the policy that lets no one in, with the digest the fix names", got)
	}
	twiceStart := strings.Index(twice, `"arn:aws:iam::111122223333:root"`)
	lambdaStart := strings.Index(serviceTrust, `"lambda.amazonaws.com"`)
	for _, c := range []struct {
		name, bundle, arn string
		start, end        int
		says              string
	}{
		{"a role the bundle does not have", string(bundle), arn + "nobody", fix.Edit.Leaf.Start, fix.Edit.Leaf.End,
			`no role of this bundle has the ARN "arn:aws:iam::123456789012:role/nobody"`},
		{"offsets one byte into the principal", string(bundle), arn + "partner", fix.Edit.Leaf.Start + 1, fix.Edit.Leaf.End,
			fmt.Sprintf("no grant of the role is read from a principal written at bytes %d-%d of its trust policy, so nothing is removed", fix.Edit.Leaf.Start+1, fix.Edit.Leaf.End)},
		{"a principal whose fix is not proven", string(bundle), arn + "twice", twiceStart, twiceStart + len(`"arn:aws:iam::111122223333:root"`),
			"No fix the engine can prove yet: grant 2 also lets aws:111122223333 in by name, so removing this principal does not shut it out."},
		{"a service, whose fix is in words", string(bundle), arn + "lambda", lambdaStart, lambdaStart + len(`"lambda.amazonaws.com"`),
			fmt.Sprintf("the engine proves no edit that removes the principal written at bytes %d-%d of the role's trust policy", lambdaStart, lambdaStart+len(`"lambda.amazonaws.com"`))},
		{"not a bundle", `{"format":"something else"}`, arn + "partner", fix.Edit.Leaf.Start, fix.Edit.Leaf.End,
			`this bundle's format is "something else"`},
	} {
		got := read(AppendFixed(nil, []byte(c.bundle), owners, c.arn, c.start, c.end))
		if got.Policy != nil || got.SHA256 != "" || !strings.HasPrefix(got.Error, c.says) {
			t.Errorf("%s: %+v, want an error that begins %q", c.name, got, c.says)
		}
	}
}

// The case of testdata/fixes whose offsets are not exactly a principal: the
// fixed policy is made at the offsets the answer's proven fix gives, and
// refused, with no policy, at any other: one byte into the literal; the
// literal without its quotes; the same digits as a condition's value; and
// the principal of a Deny.
func TestFixedRefusesOffsetsThatAreNotAPrincipal(t *testing.T) {
	const dir = "../../testdata/fixes/09-unreadable-span/"
	policy, err := os.ReadFile(dir + "aws.json")
	if err != nil {
		t.Fatal(err)
	}
	owners, err := os.ReadFile(dir + "owners.txt")
	if err != nil {
		t.Fatal(err)
	}
	bundle := bundleOf(t, nil, testRole{"partner", string(policy)})
	arn := "arn:aws:iam::" + bundleAccount + ":role/partner"
	b, err := ReadBundle(bundle)
	if err != nil {
		t.Fatal(err)
	}
	fix := fixOf(t, b.AnswerFor(b.Roles[0], owners), "111122223333")
	if fix.Status != "proven" {
		t.Fatalf("the partner's fix is %+v", *fix)
	}
	var made fixedOf
	if err := json.Unmarshal(AppendFixed(nil, bundle, owners, arn, fix.Edit.Leaf.Start, fix.Edit.Leaf.End), &made); err != nil || made.Policy == nil || made.SHA256 != fix.Edit.SHA256 {
		t.Fatalf("at the fix's own offsets: %+v, %v", made, err)
	}
	text := string(policy)
	literal := `"111122223333"`
	condition := strings.Index(text, `"aws:SourceAccount": `) + len(`"aws:SourceAccount": `)
	deny := strings.LastIndex(text, literal)
	if text[condition:condition+len(literal)] != literal || deny <= condition {
		t.Fatalf("the case is not the one its rationale describes")
	}
	for _, c := range []struct {
		name       string
		start, end int
	}{
		{"one byte into the literal", fix.Edit.Leaf.Start + 1, fix.Edit.Leaf.End},
		{"the literal without its quotes", fix.Edit.Leaf.Start + 1, fix.Edit.Leaf.End - 1},
		{"the same digits as a condition's value", condition, condition + len(literal)},
		{"the principal of a Deny", deny, deny + len(literal)},
	} {
		var got fixedOf
		if err := json.Unmarshal(AppendFixed(nil, bundle, owners, arn, c.start, c.end), &got); err != nil || got.Policy != nil || got.SHA256 != "" || got.Error == "" {
			t.Errorf("%s, at %d-%d: %+v, %v; want why, and no policy", c.name, c.start, c.end, got, err)
		}
	}
}

// Of the fixes of the populations read from one principal, the whole fixed
// policy is made by a proven one wherever there is one, whatever comes
// before it; failing that, the first unproven one says why not; and
// failing that, the first in words.
func TestTheFixedPolicyIsMadeByAProvenFixFirst(t *testing.T) {
	proven := &Fix{Status: "proven", Sentence: "proven"}
	unproven := &Fix{Status: "unproven", Check: checkOwner, Sentence: "unproven"}
	other := &Fix{Status: "unproven", Check: checkGrants, Sentence: "another unproven"}
	words := &Fix{Status: "words", Sentence: "words"}
	for _, c := range []struct {
		name  string
		fixes []*Fix
		want  *Fix
	}{
		{"proven after unproven", []*Fix{unproven, proven}, proven},
		{"proven after words", []*Fix{words, nil, proven}, proven},
		{"proven first", []*Fix{proven, unproven, words}, proven},
		{"unproven after words", []*Fix{words, unproven, other}, unproven},
		{"words alone", []*Fix{nil, words}, words},
		{"none", []*Fix{nil}, nil},
	} {
		if got := chosenFix(c.fixes); got != c.want {
			t.Errorf("%s: chose %+v, want %+v", c.name, got, c.want)
		}
	}
}
