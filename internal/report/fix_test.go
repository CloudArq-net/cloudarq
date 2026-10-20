package report

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/CloudArq-net/cloudarq/internal/eval"
	"github.com/CloudArq-net/cloudarq/internal/parse/aws"
	"github.com/CloudArq-net/cloudarq/internal/ring"
	"github.com/CloudArq-net/cloudarq/internal/trust"
)

// partnerBesideEC2 lets EC2 in through its first statement and two
// accounts through its second, one of them the partner's root.
const partnerBesideEC2 = `{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "Instances",
      "Effect": "Allow",
      "Principal": {"Service": "ec2.amazonaws.com"},
      "Action": "sts:AssumeRole"
    },
    {
      "Sid": "Partner",
      "Effect": "Allow",
      "Principal": {"AWS": ["arn:aws:iam::111122223333:root", "444455556666"]},
      "Action": "sts:AssumeRole"
    }
  ]
}`

// partnerRemoved is partnerBesideEC2 with the partner's root removed, as a
// person would remove it by hand.
const partnerRemoved = `{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "Instances",
      "Effect": "Allow",
      "Principal": {"Service": "ec2.amazonaws.com"},
      "Action": "sts:AssumeRole"
    },
    {
      "Sid": "Partner",
      "Effect": "Allow",
      "Principal": {"AWS": ["444455556666"]},
      "Action": "sts:AssumeRole"
    }
  ]
}`

// fixOf is the fix of the first population of the answer's grants whose
// way names the principal text, under Principal.AWS.
func fixOf(t *testing.T, a Answer, text string) *Fix {
	t.Helper()
	for _, g := range a.Grants {
		for _, p := range g.Populations {
			if p.Way != nil && len(p.Way.Principal) > 0 && p.Way.Principal[0].Text == text {
				if p.Way.Fix == nil {
					t.Fatalf("the population read from %q has no fix", text)
				}
				return p.Way.Fix
			}
		}
	}
	t.Fatalf("no population is read from %q", text)
	return nil
}

// A named outsider an Allow statement names by an AWS principal is shut
// out by removing that principal: the answer says where it is written and
// what to remove, which grants go, the headline the policy then opens on,
// read again, and the edited policy's digest, which is the digest of the
// policy a person gets by removing it by hand. The edited policy is never
// in the answer.
func TestAProvenFixSaysWhatToRemoveAndWhatItLeaves(t *testing.T) {
	answer := AdmitsFor([]byte(partnerBesideEC2), []byte("aws:444455556666"))
	a := answerOf(t, answer)
	f := fixOf(t, a, "arn:aws:iam::111122223333:root")
	if f.Status != "proven" || f.Check != "" || f.Edit == nil || f.ShutsOut == nil || f.After == nil {
		t.Fatalf("the fix is %+v, not a proven one", *f)
	}
	start := strings.Index(partnerBesideEC2, `"arn:aws:iam::111122223333:root"`)
	want := Edit{Removes: "principal", Statement: 1, Sid: "Partner", FirstLine: 10, LastLine: 15,
		Leaf:         Leaf{Text: "arn:aws:iam::111122223333:root", Member: "Principal.AWS", Line: 13, Start: start, End: start + len(`"arn:aws:iam::111122223333:root"`)},
		GrantNumbers: []int{2}, SHA256: digest([]byte(partnerRemoved))}
	got := *f.Edit
	if got.Removes != want.Removes || got.Statement != want.Statement || got.Sid != want.Sid || got.FirstLine != want.FirstLine || got.LastLine != want.LastLine || got.Leaf != want.Leaf || got.SHA256 != want.SHA256 || len(got.GrantNumbers) != 1 || got.GrantNumbers[0] != 2 {
		t.Errorf("the edit is\n%+v\nwant\n%+v", got, want)
	}
	for _, c := range []struct{ got, want string }{
		{f.Sentence, `In statement 2 ("Partner"), lines 10-15, remove "arn:aws:iam::111122223333:root" from Principal.AWS.`},
		{f.ShutsOut.Sentence, "Grant 2 is taken out, and no grant left lets aws:111122223333 in by name."},
		{f.After.Sentence, "ec2.amazonaws.com can assume this role."},
	} {
		if c.got != c.want {
			t.Errorf("the fix says %q, want %q", c.got, c.want)
		}
	}
	if again := answerOf(t, AdmitsFor([]byte(partnerRemoved), []byte("aws:444455556666"))); again.Headline.Sentence != f.After.Sentence {
		t.Errorf("the policy edited by hand opens on %q, and the fix says %q", again.Headline.Sentence, f.After.Sentence)
	}
	if bytes.Contains(answer, []byte(`["444455556666"]`)) {
		t.Errorf("the answer carries the edited policy's text")
	}
}

// What the edit removes is the least that takes the principal out: the
// principal from a list that names others, the member it is the only
// value of beside other members, or the statement whose Principal names
// nothing else; and each is said in its own words.
func TestAFixRemovesTheLeastAndSaysWhich(t *testing.T) {
	cases := []struct{ name, policy, removes, sentence string }{
		{"a list that names others", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":["111122223333","arn:aws:iam::444455556666:root"]},"Action":"sts:AssumeRole"}]}`,
			"principal", `In statement 1, line 1, remove "111122223333" from Principal.AWS.`},
		{"the only value of its member", `{"Version":"2012-10-17","Statement":[{"Sid":"Both","Effect":"Allow","Principal":{"AWS":"111122223333","Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}`,
			"member", `In statement 1 ("Both"), line 1, remove Principal.AWS, which names only "111122223333".`},
		{"the only principal of its statement", "{\"Version\":\"2012-10-17\",\"Statement\":[\n{\"Effect\":\"Allow\",\"Principal\":{\"Service\":\"ec2.amazonaws.com\"},\"Action\":\"sts:AssumeRole\"},\n{\"Sid\":\"Partner\",\"Effect\":\"Allow\",\n\"Principal\":{\"AWS\":\"111122223333\"},\n\"Action\":\"sts:AssumeRole\"}\n]}",
			"statement", `Remove statement 2 ("Partner"), lines 3-5: the only principal it names is "111122223333".`},
		{"escaped, as written", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":["arn:aws:iam::111122223333:root","444455556666"]},"Action":"sts:AssumeRole"}]}`,
			"principal", `In statement 1, line 1, remove "arn:aws:iam::111122223333:root" from Principal.AWS.`},
	}
	for _, c := range cases {
		a := answerOf(t, AdmitsFor([]byte(c.policy), []byte("aws:444455556666")))
		var f *Fix
		for _, g := range a.Grants {
			for _, p := range g.Populations {
				if p.Place == "outsider" {
					f = p.Way.Fix
				}
			}
		}
		if f == nil || f.Status != "proven" || f.Edit.Removes != c.removes || f.Sentence != c.sentence {
			t.Errorf("%s: the fix is %+v; want %s removed, saying %q", c.name, f, c.removes, c.sentence)
		}
	}
}

// partnerAlone is a trust policy whose only statement lets one partner in.
const partnerAlone = `{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "Partner",
      "Effect": "Allow",
      "Principal": {"AWS": "arn:aws:iam::111122223333:root"},
      "Action": "sts:AssumeRole"
    }
  ]
}`

// noOneIn is the trust policy that lets no one in, with partnerAlone's
// Version: what replaces a policy that removing a principal would leave
// with no statement.
const noOneIn = `{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyEveryone",
      "Effect": "Deny",
      "Principal": {"AWS": "*"},
      "Action": "sts:AssumeRole"
    }
  ]
}`

// replacedSentence is the sentence of the fix that replaces a policy with one
// that lets no one in: where the only statement is and the only principal
// it names, then what it stops and what it does not.
func replacedSentence(statement, principal, who string) string {
	return "Replace the whole trust policy with one that lets no one in: " + statement + " is its only statement, the only principal it names is " + principal +
		", and IAM refuses a trust policy with no statement. This stops " + who + " from getting in. If you still work with them, don't apply it." +
		` Anyone already in keeps their access until their session ends, which can take hours. The role's "Revoke active sessions" ends those sessions now.` +
		" Deleting the role instead also removes what its permissions allow."
}

// Where removing the principal would leave the policy with no statement
// at all, which IAM refuses, the least edit that shuts the outsider out
// is to replace the policy with one that lets no one in: one Deny of
// sts:AssumeRole to every AWS principal, with the original's Version as it
// is written, or none where it writes none. The fix is proven as an edit
// is, by reading the replacement again with the same owners, and the
// replacement's own answer lets no one in. The answer carries its digest,
// never its text, and says beside it what it stops and what it does not.
func TestAFixReplacesAPolicyRemovingItWouldLeaveWithNoStatement(t *testing.T) {
	cases := []struct {
		name, policy, principal, replacement, statement string
	}{
		{"the only statement of a list", partnerAlone, "arn:aws:iam::111122223333:root", noOneIn, `statement 1 ("Partner"), lines 4-9,`},
		{"a lone Statement object, Version 2008-10-17 after it", "{\n  \"Statement\": {\n    \"Sid\": \"Partner\",\n    \"Effect\": \"Allow\",\n    \"Principal\": {\"AWS\": \"111122223333\"},\n    \"Action\": \"sts:AssumeRole\"\n  },\n  \"Version\": \"2008-10-17\"\n}",
			"111122223333", strings.Replace(noOneIn, "2012-10-17", "2008-10-17", 1), `statement 1 ("Partner"), lines 2-7,`},
		{"no Version, the outsider in a list of one", `{"Statement":[{"Effect":"Allow","Principal":{"AWS":["arn:aws:iam::111122223333:root"]},"Action":"sts:AssumeRole"}]}`,
			"arn:aws:iam::111122223333:root", strings.Replace(noOneIn, "\n  \"Version\": \"2012-10-17\",", "", 1), "statement 1, line 1,"},
	}
	for _, c := range cases {
		answer := AdmitsFor([]byte(c.policy), nil)
		a := answerOf(t, answer)
		f := fixOf(t, a, c.principal)
		if f.Status != "proven" || f.Check != "" || f.Edit == nil || f.ShutsOut == nil || f.After == nil {
			t.Errorf("%s: the fix is %+v, not a proven one", c.name, *f)
			continue
		}
		start := strings.Index(c.policy, `"`+c.principal+`"`)
		if e := f.Edit; e.Removes != "policy" || e.Statement != 0 || e.Leaf.Start != start || e.Leaf.End != start+len(c.principal)+2 || !slices.Equal(e.GrantNumbers, []int{1}) || e.SHA256 != digest([]byte(c.replacement)) {
			t.Errorf("%s: the edit is %+v, want the policy replaced, with the digest of\n%s", c.name, *e, c.replacement)
		}
		for _, s := range []struct{ got, want string }{
			{f.Sentence, replacedSentence(c.statement, `"`+c.principal+`"`, "aws:111122223333")},
			{f.ShutsOut.Sentence, "Grant 1 is taken out, and no grant left lets anyone in."},
			{f.After.Sentence, "Nothing outside your company can assume this role."},
		} {
			if s.got != s.want {
				t.Errorf("%s: the fix says\n%q\nwant\n%q", c.name, s.got, s.want)
			}
		}
		if bytes.Contains(answer, []byte("DenyEveryone")) {
			t.Errorf("%s: the answer carries the replacement's text", c.name)
		}
		// the replacement, read on its own, lets no one in: every grant of
		// it is a Deny, placed in no ring, and its answer opens on the
		// headline the fix says
		again := answerOf(t, AdmitsFor([]byte(c.replacement), []byte("aws:111122223333")))
		if again.Error != "" || len(again.Grants) == 0 || again.Headline.Sentence != f.After.Sentence {
			t.Errorf("%s: the replacement's answer is %+v", c.name, again)
		}
		for _, g := range again.Grants {
			if g.Effect != "Deny" || len(g.Populations) != 0 || !slices.Equal(g.Placement, []string{"refused"}) {
				t.Errorf("%s: the replacement's grant %d is %s placed %v, with %d populations", c.name, g.Number, g.Effect, g.Placement, len(g.Populations))
			}
		}
	}
}

// A statement that is not the policy's only one is removed, never the
// policy replaced, and a principal beside another in the only statement is
// removed alone: the least edit leaves the other in, the reader's own or
// another outsider.
func TestOnlyAPolicyLeftWithNoStatementIsReplaced(t *testing.T) {
	cases := []struct{ name, policy, owners, principal, removes string }{
		{"two outsiders in the only statement", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":["arn:aws:iam::111122223333:root","777788889999"]},"Action":"sts:AssumeRole"}]}`, "",
			"arn:aws:iam::111122223333:root", "principal"},
		{"the reader's own account beside it", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":["arn:aws:iam::111122223333:root","444455556666"]},"Action":"sts:AssumeRole"}]}`, "aws:444455556666",
			"arn:aws:iam::111122223333:root", "principal"},
		{"a statement beside another", "{\"Version\":\"2012-10-17\",\"Statement\":[\n{\"Effect\":\"Allow\",\"Principal\":{\"Service\":\"ec2.amazonaws.com\"},\"Action\":\"sts:AssumeRole\"},\n{\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"111122223333\"},\"Action\":\"sts:AssumeRole\"}\n]}", "",
			"111122223333", "statement"},
	}
	for _, c := range cases {
		f := fixOf(t, answerOf(t, AdmitsFor([]byte(c.policy), []byte(c.owners))), c.principal)
		if f.Status != "proven" || f.Edit == nil || f.Edit.Removes != c.removes || strings.Contains(f.Sentence, "Replace") {
			t.Errorf("%s: the fix is %+v, want the %s removed", c.name, *f, c.removes)
		}
	}
}

// A policy whose Version IAM refuses, written twice, not a string, or
// neither of the two language versions, is not replaced: the replacement
// keeps the Version as written, so IAM would refuse it too, and a proven
// fix is one IAM accepts. The fix says why, and carries no edit.
func TestAPolicyWhoseVersionIAMRefusesIsNotReplaced(t *testing.T) {
	const only = `"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111122223333:root"},"Action":"sts:AssumeRole"}]`
	const keeps = ", which IAM refuses, and the policy that would replace it keeps the Version as written."
	cases := []struct{ name, policy, sentence string }{
		{"written twice", `{"Version":"2012-10-17","Version":"2008-10-17",` + only + `}`,
			"No fix the engine can prove yet: the policy writes Version more than once" + keeps},
		{"an object shaped like an Allow", `{"Version":{"Statement":[{"Effect":"Allow","Principal":"*","Action":"sts:AssumeRole"}]},` + only + `}`,
			`No fix the engine can prove yet: Version is an object ({"Statement":[{"Effect":"Allow","Principal":"*","...), not a string` + keeps},
		{"neither of the two", `{"Version":"2013-10-17",` + only + `}`,
			`No fix the engine can prove yet: Version "2013-10-17" is neither "2012-10-17" nor "2008-10-17"` + keeps},
	}
	for _, c := range cases {
		f := fixOf(t, answerOf(t, AdmitsFor([]byte(c.policy), nil)), "arn:aws:iam::111122223333:root")
		if f.Status != "unproven" || f.Check != "span" || f.Sentence != c.sentence || f.Edit != nil || f.ShutsOut != nil || f.After != nil {
			t.Errorf("%s: the fix is %+v\nwant check span saying %q and nothing more", c.name, *f, c.sentence)
		}
	}
}

// Where no edit can be proven, the fix says which check refused it, in
// words, and carries no edit: the outsider named by a condition rather than
// a principal; a statement not read as an Allow; and the outsider still let
// in by name.
func TestAnUnprovenFixSaysWhichCheckRefusedIt(t *testing.T) {
	cases := []struct{ name, policy, owners, check, sentence string }{
		{"named by a condition on *", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole","Condition":{"StringEquals":{"aws:PrincipalAccount":"111122223333"}}}]}`, "",
			"leaf", "No fix the engine can prove yet: aws:111122223333 is let in by a condition, not by a principal the statement names."},
		{"an Effect not read as Allow", `{"Version":"2012-10-17","Statement":[{"Effect":"allow","Principal":{"AWS":"111122223333"},"Action":"sts:AssumeRole"}]}`, "",
			"effect", "No fix the engine can prove yet: statement 1 is not read as an Allow, and the engine removes a principal only from an Allow statement."},
		{"the account named twice", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":["111122223333","arn:aws:iam::111122223333:root"]},"Action":"sts:AssumeRole"}]}`, "",
			"owner", "No fix the engine can prove yet: grant 2 also lets aws:111122223333 in by name, so removing this principal does not shut it out."},
	}
	for _, c := range cases {
		a := answerOf(t, AdmitsFor([]byte(c.policy), []byte(c.owners)))
		var f *Fix
		for _, g := range a.Grants {
			for _, p := range g.Populations {
				if p.Place == "outsider" && f == nil {
					f = p.Way.Fix
				}
			}
		}
		if f == nil || f.Status != "unproven" || f.Check != c.check || f.Sentence != c.sentence || f.Edit != nil || f.ShutsOut != nil || f.After != nil {
			t.Errorf("%s: the fix is %+v; want check %s saying %q and nothing more", c.name, f, c.check, c.sentence)
		}
	}
}

// A per-tenant issuer, as an EKS, AKS or GKE cluster's or a GitHub
// enterprise's, is named by the provider the statement's Principal
// writes, never by a condition: its fix says that the way in is through
// that provider, as its how does, and that the engine removes only an AWS
// principal so far.
func TestATenantIssuersFixNamesTheProviderItIsLetInThrough(t *testing.T) {
	examined := 0
	for _, name := range ringsCases(t) {
		doc, owners := ringsCase(t, name)
		a := answerOf(t, AdmitsFor(doc, owners))
		for _, g := range a.Grants {
			for _, p := range g.Populations {
				if p.Basis != "controlled-tenant" {
					continue
				}
				examined++
				f := p.Way.Fix
				if len(p.Way.Principal) != 1 || p.Way.Principal[0].Member != "Principal.Federated" {
					t.Fatalf("%s grant %d: the way names %+v, not one provider under Principal.Federated", name, g.Number, p.Way.Principal)
				}
				want := "No fix the engine can prove yet: this way in is through " + p.Way.Principal[0].Text + " at Principal.Federated, and so far the engine removes only a principal written under Principal.AWS, other than \"*\"."
				if f == nil || f.Status != fixUnproven || f.Check != "principal" || f.Sentence != want {
					t.Errorf("%s grant %d: the fix is %+v\nwant check principal saying %q", name, g.Number, f, want)
				}
			}
		}
	}
	if examined < 8 {
		t.Errorf("%d populations of a per-tenant issuer over the rings cases; the test examined too few", examined)
	}
}

// A platform's population let in because one of its conditions was not
// read is confined by a condition that pins an owner as much as one let in
// because nothing pins it: the conditions of a statement all hold at once,
// and a pin is read whatever else was not. Its fix names that condition in
// words, as the unpinned population's does.
func TestAnUnreadConditionStillNamesTheConditionThatWouldPin(t *testing.T) {
	examined := 0
	for _, name := range ringsCases(t) {
		doc, owners := ringsCase(t, name)
		a := answerOf(t, AdmitsFor(doc, owners))
		for _, g := range a.Grants {
			for _, p := range g.Populations {
				if p.Place != "platform" || p.Basis != "unread-constraint" {
					continue
				}
				examined++
				f := p.Way.Fix
				if f == nil || f.Status != fixWords || f.Check != "" || !strings.HasPrefix(f.Sentence, "A condition ") || !strings.HasSuffix(f.Sentence, "; the engine does not prove that change yet.") {
					t.Errorf("%s grant %d: the fix is %+v, not the condition that would pin it, in words", name, g.Number, f)
				}
			}
		}
	}
	if examined < 7 {
		t.Errorf("%d platform populations with a condition not read over the rings cases; the test examined too few", examined)
	}
	doc, owners := ringsCase(t, "69-any-service-face-with-source-account")
	want := "A condition on aws:PrincipalAccount naming your own account, or on aws:PrincipalOrgID naming your AWS Organization, would let in only that account or that Organization's accounts; the engine does not prove that change yet."
	for _, g := range answerOf(t, AdmitsFor(doc, owners)).Grants {
		for _, p := range g.Populations {
			if p.Place == "platform" && p.Way.Fix.Sentence != want {
				t.Errorf("69: the fix says %q, want %q", p.Way.Fix.Sentence, want)
			}
		}
	}
}

// Every way in has a fix, the widest ones included: a population anyone,
// a SAML provider's sign-ins or the reader's people are let in as says
// that no fix is proven yet and why, so that no way in reads as one with
// nothing to fix. The way in is through a principal the engine does not
// remove, said as the statement writes it, or, where the engine reads no
// principal string, said so.
func TestEveryWayInHasAFix(t *testing.T) {
	const rest = ", and so far the engine removes only a principal written under Principal.AWS, other than \"*\"."
	want := map[string][]string{
		"07-anyone-on-web-identity":    {"No fix the engine can prove yet: this way in is through * at Principal" + rest},
		"11-cognito-guests":            {"No fix the engine can prove yet: this way in is through cognito-identity.amazonaws.com at Principal.Federated" + rest},
		"20-saml-provider-of-a-vendor": {"No fix the engine can prove yet: this way in is through arn:aws:iam::123456789012:saml-provider/VendorSSO at Principal.Federated" + rest},
		"35-saml-provider-declared":    {"No fix the engine can prove yet: this way in is through arn:aws:iam::123456789012:saml-provider/VendorSSO at Principal.Federated" + rest},
		"42-principals-not-modelled": {
			"No fix the engine can prove yet: this way in is through arn:aws:iam::123456789012:role/Deploy at Principal.Federated" + rest,
			"No fix the engine can prove yet: no principal the engine reads lets this way in, and so far it removes only a principal written under Principal.AWS, other than \"*\".",
			"No fix the engine can prove yet: this way in is through arn:aws:s3:::acme-artifacts at Principal.AWS, which the engine does not read as naming an AWS account, and so far it removes only a principal it reads as naming one.",
		},
	}
	examined, widest := 0, 0
	for _, name := range ringsCases(t) {
		doc, owners := ringsCase(t, name)
		a := answerOf(t, AdmitsFor(doc, owners))
		var got []string
		for _, g := range a.Grants {
			for _, p := range g.Populations {
				examined++
				f := p.Way.Fix
				if f == nil || f.Sentence == "" {
					t.Errorf("%s grant %d: the population placed at %s has no fix", name, g.Number, p.Place)
					continue
				}
				switch p.Place {
				case "anyone", "saml", "people":
					widest++
					if f.Status != fixUnproven || f.Check != "principal" {
						t.Errorf("%s grant %d: the fix at %s is %+v", name, g.Number, p.Place, *f)
					}
					got = append(got, f.Sentence)
				}
			}
		}
		if w, ok := want[name]; ok && !slices.Equal(got, w) {
			t.Errorf("%s: the fixes say\n%q\nwant\n%q", name, got, w)
		}
	}
	if widest < 20 || examined < 100 {
		t.Errorf("%d populations, %d at anyone, saml or people, over the rings cases; the test examined too few", examined, widest)
	}
}

// Where the outsider is still let in by name once the principal is
// removed, the fix names, of the other grants, each with only the owners it
// lets in by name and only those the edit would leave in: an owner the
// edit shuts out is not said to be let in, and a grant is never said to
// let in an owner it does not.
func TestAnOwnerStillLetInIsNamedWithTheGrantsThatLetItIn(t *testing.T) {
	cases := []struct{ name, policy, sentence string }{
		{"one of two owners, by another grant", `{"Version":"2012-10-17","Statement":[{"Sid":"Other","Effect":"Allow","Principal":{"AWS":"777788889999"},"Action":"sts:AssumeRole"},{"Sid":"Wide","Effect":"Allow","Principal":{"AWS":["arn:aws:iam::*:root","111122223333"]},"Action":"sts:AssumeRole","Condition":{"StringEquals":{"aws:PrincipalAccount":["444455556666","777788889999"]}}}]}`,
			"No fix the engine can prove yet: grant 1 also lets aws:777788889999 in by name, so removing this principal does not shut it out."},
		{"two of three owners, by three grants", `{"Version":"2012-10-17","Statement":[{"Sid":"A","Effect":"Allow","Principal":{"AWS":"777788889999"},"Action":"sts:AssumeRole"},{"Sid":"B","Effect":"Allow","Principal":{"AWS":"444455556666"},"Action":"sts:AssumeRole"},{"Sid":"C","Effect":"Allow","Principal":{"AWS":"arn:aws:iam::777788889999:root"},"Action":"sts:AssumeRole"},{"Sid":"Wide","Effect":"Allow","Principal":{"AWS":["arn:aws:iam::*:root","111122223333"]},"Action":"sts:AssumeRole","Condition":{"StringEquals":{"aws:PrincipalAccount":["444455556666","777788889999","222233334444"]}}}]}`,
			"No fix the engine can prove yet: grant 1 also lets aws:444455556666 in by name and grants 2 and 3 also let aws:777788889999 in by name, so removing this principal does not shut them out."},
	}
	for _, c := range cases {
		f := fixOf(t, answerOf(t, Admits([]byte(c.policy))), "arn:aws:iam::*:root")
		if f.Status != fixUnproven || f.Check != checkOwner || f.Sentence != c.sentence {
			t.Errorf("%s: the fix is %+v\nwant check owner saying %q", c.name, *f, c.sentence)
		}
	}
}

// The engine reads a policy again, and places every grant of it again,
// once for each AWS principal it proves a fix for, and stops before that
// work would pass either of its bounds for one answer: MaxDocumentBytes
// read again, or maxFixGrants placed again, so that the work grows with
// neither the square of a policy's length nor that of its principals. Each
// principal past a bound is said to be past it, counted over every grant
// read from an AWS principal, wherever it lands, so that whether a
// principal is past it does not depend on the owners declared. A trust
// policy within AWS's default 2,048 characters can name 125 accounts.
func TestFixesStopAtTheBound(t *testing.T) {
	policy := func(service string, principals, padding int) string {
		var ids []string
		for i := 0; i < principals; i++ {
			ids = append(ids, fmt.Sprintf(`"1111222%05d"`, i))
		}
		return `{"Version":"2012-10-17","Statement":[` + service + `{"Effect":"Allow","Principal":{"AWS":[` + strings.Join(ids, ",") + `]},"Action":"sts:AssumeRole"}]}` + strings.Repeat(" ", padding)
	}
	bytes := policy(`{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"},`, 20, MaxDocumentBytes/10)
	grants := policy("", 125, 0)
	if len(grants) > 2048 {
		t.Fatalf("the policy of 125 accounts is %d bytes, past AWS's default 2,048 characters", len(grants))
	}
	for _, c := range []struct {
		name, policy string
		principals   int
		within       func(grants int) int
		sentence     string
	}{
		{"bytes read again", bytes, 20, func(int) int { return MaxDocumentBytes / len(bytes) },
			"No fix the engine can prove yet: proving it would take the engine past the 262144 bytes it reads again for one answer's fixes."},
		{"grants placed again", grants, 125, func(n int) int { return maxFixGrants / n },
			"No fix the engine can prove yet: proving it would take the engine past the 256 grants it places again for one answer's fixes."},
	} {
		for _, owners := range []string{"", "aws:111122200000\naws:111122200001"} {
			a := answerOf(t, AdmitsFor([]byte(c.policy), []byte(owners)))
			within := c.within(len(a.Grants))
			proven, bound := 0, 0
			for _, g := range a.Grants {
				for _, p := range g.Populations {
					switch f := p.Way.Fix; {
					case p.Place == "service":
					case f.Status == "proven":
						proven++
					case f.Check == "bound" && f.Sentence == c.sentence:
						bound++
					default:
						t.Fatalf("%s, owners %q: a fix that is neither proven nor past the bound: %+v", c.name, owners, *f)
					}
				}
			}
			if proven != within || bound != c.principals-within || within < 2 || within >= c.principals {
				t.Errorf("%s, owners %q: %d proven and %d past the bound; want %d and %d", c.name, owners, proven, bound, within, c.principals-within)
			}
		}
	}
}

// A check that cannot fail on a policy the reader writes still refuses
// what it is given: offsets outside the statement the grant was read from,
// and a grant left that would be placed by other facts or further out.
func TestTheChecksRefuseWhatTheyAreGiven(t *testing.T) {
	r, err := readPolicy([]byte(partnerBesideEC2))
	if err != nil {
		t.Fatal(err)
	}
	declared := ring.ReadDeclarations("")
	p := &placing{read: r, declared: declared, placed: r.place(declared.Owners)}
	i := 0
	for k, w := range r.written {
		if w.Text == "arn:aws:iam::111122223333:root" {
			i = k
		}
	}
	targets := p.placed[i].placement.Populations[0].Owners
	moved := r
	moved.written = append([]aws.Written(nil), r.written...)
	moved.written[i].Start, moved.written[i].End = 2, 10
	if f := moved.prove(i, targets, p); f.Check != "span" || f.Sentence != "No fix the engine can prove yet: the principal is not written inside the statement its grant was read from." {
		t.Errorf("a principal said to be written outside its statement: %+v", *f)
	}
	shifted := r
	shifted.written = append([]aws.Written(nil), r.written...)
	shifted.written[i].Start++
	if f := shifted.prove(i, targets, p); f.Check != "span" || !strings.Contains(f.Sentence, "are not one principal written under a statement's Principal") {
		t.Errorf("offsets one byte into the principal: %+v", *f)
	}
	// Removing the whole statement would take the account's own grant out
	// with the partner's: the reader removes the principal alone, and the
	// check refuses the statement's removal.
	statement := strings.Index(partnerBesideEC2, `,
    {
      "Sid": "Partner"`)
	end := strings.LastIndex(partnerBesideEC2, "}\n  ]")
	withoutStatement := partnerBesideEC2[:statement] + partnerBesideEC2[end+1:]
	if f := r.check(i, targets, p, []byte(withoutStatement), aws.RemovedStatement); f.Check != "grants" || f.Sentence != "No fix the engine can prove yet: removing it would take grant 3 out as well, which this principal does not make." {
		t.Errorf("the statement removed with the account's own grant in it:\n%s\n%+v", withoutStatement, *f)
	}
	withAnother := strings.Replace(partnerBesideEC2, `"arn:aws:iam::111122223333:root", "444455556666"]`, `"444455556666"]},"Action":"sts:AssumeRole"},{"Effect":"Allow","Principal":{"AWS":"777788889999"`, 1)
	if f := r.check(i, targets, p, []byte(withAnother), aws.RemovedPrincipal); f.Check != "grants" || f.Sentence != "No fix the engine can prove yet: with the principal removed, the policy would make a grant it does not make now." {
		t.Errorf("an edit that makes a grant:\n%s\n%+v", withAnother, *f)
	}
	// an edit that changes who a grant left admits, to an account no grant
	// of the original names: a grant is paired with its twin by issuer,
	// effect and admitted set, never by issuer alone, so the grant left is
	// one the original does not make, though a grant of the same issuer is
	// left unpaired beside it
	replaced := strings.Replace(partnerBesideEC2, `"arn:aws:iam::111122223333:root", "444455556666"]`, `"777788889999"]`, 1)
	if f := r.check(i, targets, p, []byte(replaced), aws.RemovedPrincipal); f.Status != fixUnproven || f.Check != "grants" || f.Sentence != "No fix the engine can prove yet: with the principal removed, the policy would make a grant it does not make now." {
		t.Errorf("an edit that changes who a grant left admits:\n%s\n%+v", replaced, *f)
	}
	// an edit that left the outsider in, through a grant the original does
	// not make: no grant of the original is named as letting it in
	unchanged := strings.Replace(partnerBesideEC2, `"444455556666"]`, `"444455556666"]},"Action":"sts:AssumeRole"},{"Effect":"Allow","Principal":{"AWS":"777788889999"`, 1)
	if f := r.check(i, targets, p, []byte(unchanged), aws.RemovedPrincipal); f.Check != "owner" || f.Sentence != "No fix the engine can prove yet: with the principal removed, a grant would still let aws:111122223333 in by name." {
		t.Errorf("an edit that leaves the outsider in:\n%s\n%+v", unchanged, *f)
	}
	// a grant left that is an upper bound where its twin is exact, or for
	// another reason, is placed with another certainty
	exact, doubted := r.grants[i], r.grants[i]
	doubted.Admits = doubted.Admits.WithCaveat(eval.Caveat{Claim: "aws:principalaccount", Reason: "a reason", Source: "statement[1]"})
	elsewhere := exact
	elsewhere.Admits = elsewhere.Admits.WithCaveat(eval.Caveat{Claim: "aws:principalaccount", Reason: "a reason", Source: "statement[0]"})
	other := exact
	other.Admits = other.Admits.WithCaveat(eval.Caveat{Claim: "aws:principalaccount", Reason: "another reason", Source: "statement[1]"})
	for _, c := range []struct {
		name string
		a, b trust.Grant
		same bool
	}{{"both exact", exact, exact, true}, {"one exact", exact, doubted, false}, {"read elsewhere", doubted, elsewhere, true}, {"another reason", doubted, other, false}} {
		if sameCaveats(c.a, c.b) != c.same {
			t.Errorf("%s: same caveats %v, want %v", c.name, !c.same, c.same)
		}
	}
	original := p.placed[i]
	for _, c := range []struct {
		name  string
		again func(placed) placed
		alike bool
	}{
		{"the same", func(g placed) placed { return g }, true},
		{"another statement's reading of who a grant naming no issuer admits", func(g placed) placed { g.facts.Issuerless = aws.AWSServices; return g }, false},
		{"a principal no longer modelled", func(g placed) placed { g.facts.PrincipalModelled = !g.facts.PrincipalModelled; return g }, false},
		{"further out", func(g placed) placed { g.placement = withPlace(g.placement, ring.Anyone); return g }, false},
		{"nearer", func(g placed) placed { g.placement = withPlace(g.placement, ring.People); return g }, true},
		{"beside the rings", func(g placed) placed { g.placement = withPlace(g.placement, ring.SAML); return g }, false},
		{"refused", func(g placed) placed { g.placement.Outcome = ring.Refused; return g }, false},
		{"one population fewer", func(g placed) placed { g.placement.Populations = nil; return g }, false},
	} {
		if got := placedAlike(c.again(original), original); got != c.alike {
			t.Errorf("%s: placed alike %v, want %v", c.name, got, c.alike)
		}
	}
}

// The checks a replacement is proven by refuse what they are given, though
// the replacement the engine writes passes them all: one that does not
// read, one with a fault the original does not have beside its Deny's own,
// one that lets someone in, one that makes a grant other than a Deny, and
// one that would take out a grant the principal does not make. The faults
// of the replacement's own Deny are what it is allowed beside the
// original's, and only those.
func TestTheReplacementsChecksRefuseWhatTheyAreGiven(t *testing.T) {
	setup := func(policy, principal string) (reading, *placing, int, []ring.Owner) {
		t.Helper()
		r, err := readPolicy([]byte(policy))
		if err != nil {
			t.Fatal(err)
		}
		declared := ring.ReadDeclarations("")
		p := &placing{read: r, declared: declared, placed: r.place(declared.Owners)}
		i := slices.IndexFunc(r.written, func(w aws.Written) bool { return w.Text == principal })
		if i < 0 {
			t.Fatalf("no grant is read from %s", principal)
		}
		return r, p, i, p.placed[i].placement.Populations[0].Owners
	}
	r, p, i, targets := setup(partnerAlone, "arn:aws:iam::111122223333:root")
	if f := r.checkReplaced(i, targets, p, []byte(noOneIn)); f.Status != fixProven {
		t.Fatalf("the replacement the engine writes is refused: %+v", *f)
	}
	for _, c := range []struct{ name, replacement, check, sentence string }{
		{"not read", `{"Statement":[`, "parse", "No fix the engine can prove yet: the policy that would replace it is not read: "},
		{"a Version the original does not have", strings.Replace(noOneIn, "2012-10-17", "2013-10-17", 1), "parse",
			`No fix the engine can prove yet: the policy that would replace it reads with a fault this one does not have: Version "2013-10-17" is neither "2012-10-17" nor "2008-10-17"; policy variables are read as unresolved.`},
		{"an account let in", strings.Replace(strings.Replace(noOneIn, `"Deny"`, `"Allow"`, 1), `"*"`, `"777788889999"`, 1), "owner",
			"No fix the engine can prove yet: the policy that would replace it would still let someone in."},
		{"an Allow that lets no one in", strings.Replace(strings.Replace(strings.Replace(noOneIn, `"Deny"`, `"Allow"`, 1), `"*"`, `"777788889999"`, 1), `"sts:AssumeRole"`, `"sts:AssumeRole", "Condition": {"StringEquals": {"aws:PrincipalAccount": "999999999999"}}`, 1), "grants",
			"No fix the engine can prove yet: the policy that would replace it would make a grant that is not a Deny."},
	} {
		f := r.checkReplaced(i, targets, p, []byte(c.replacement))
		if f.Status != fixUnproven || f.Check != c.check || !strings.HasPrefix(f.Sentence, c.sentence) || f.Edit != nil {
			t.Errorf("%s:\n%s\n%+v\nwant check %s saying %q", c.name, c.replacement, *f, c.check, c.sentence)
		}
	}
	// a policy with another statement: replacing it would take that
	// statement's grants out as well
	r, p, i, targets = setup(partnerBesideEC2, "arn:aws:iam::111122223333:root")
	if f := r.checkReplaced(i, targets, p, []byte(noOneIn)); f.Check != "grants" || f.Sentence != "No fix the engine can prove yet: replacing the policy would take grant 1 out as well, which this principal does not make." {
		t.Errorf("a replacement that takes out another statement's grant: %+v", *f)
	}
	// the faults of the replacement's Deny are counted against it only when
	// a Deny's are asked for
	original, err := readPolicy([]byte(partnerAlone))
	if err != nil {
		t.Fatal(err)
	}
	again, err := readPolicy([]byte(noOneIn))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := newAnomaly(original, again, false); ok {
		t.Errorf("the faults of the replacement's Deny are counted against it")
	}
	if fault, ok := newAnomaly(original, again, true); !ok || fault.Construct == "" {
		t.Errorf("the replacement's Deny has no fault the original lacks, so leaving a Deny's faults out was proven on nothing")
	}
}

// withPlace is a placement with its one population moved to place.
func withPlace(p ring.Placement, place ring.Place) ring.Placement {
	pops := append([]ring.Population(nil), p.Populations...)
	pops[0].Place = place
	p.Populations = pops
	return p
}

// Over the corpus, the rings cases and the fixes cases, with no owner
// declared and with owners: every proven fix is what removing its principal
// by its offsets gives, or, for a policy whose only statement that removes,
// the policy that lets no one in, read again through the public entry
// point. The edited policy's digest is the edit's; every statement but the
// one edited is in it byte for byte; its answer opens on the fix's
// headline; no grant of it lets the outsider in by name; and it has every
// grant of the original but those the fix takes out, or, replacing the
// policy, every grant of the original is taken out and every grant of the
// replacement is a Deny that lets no one in.
func TestEveryProvenFixIsWhatTheEditedPolicyAnswers(t *testing.T) {
	docs := corpus(t)
	for _, name := range ringsCases(t) {
		doc, _ := ringsCase(t, name)
		docs[name] = doc
	}
	docs["two statements"] = []byte(partnerBesideEC2)
	fixes, err := filepath.Glob("../../testdata/fixes/*/aws.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range fixes {
		doc, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		docs[path] = doc
	}
	proven, replaced := 0, 0
	for name, doc := range docs {
		r, unread := readPolicy(doc)
		for _, owners := range []string{"", "aws:444455556666\naws:111122223333\ngithub:acme"} {
			a := answerOf(t, AdmitsFor(doc, []byte(owners)))
			for _, g := range a.Grants {
				for _, p := range g.Populations {
					if p.Way == nil || p.Way.Fix == nil || p.Way.Fix.Status != "proven" {
						continue
					}
					proven++
					e := p.Way.Fix.Edit
					edited, _, err := aws.RemovePrincipal(doc, e.Leaf.Start, e.Leaf.End)
					if e.Removes == "policy" {
						replaced++
						edited, err = aws.LetNoOneIn(doc)
						if len(a.Document.Statements) != 1 || e.Statement != 0 || len(e.GrantNumbers) != len(a.Grants) {
							t.Errorf("%s: the policy is replaced, and it has %d statements and %d grants, %d of them taken out", name, len(a.Document.Statements), len(a.Grants), len(e.GrantNumbers))
						}
					}
					if err != nil || digest(edited) != e.SHA256 {
						t.Fatalf("%s: the edit does not give the policy its digest names: %v", name, err)
					}
					// every statement but the one edited is left byte for byte
					for k, st := range a.Document.Statements {
						if k != e.Statement && (unread != nil || !bytes.Contains(edited, r.doc.Statements[st.Index].Raw)) {
							t.Errorf("%s: statement %d is not left as written: %v", name, k+1, unread)
						}
					}
					again := answerOf(t, AdmitsFor(edited, []byte(owners)))
					if again.Headline.Sentence != p.Way.Fix.After.Sentence {
						t.Errorf("%s: the edited policy opens on %q, the fix says %q", name, again.Headline.Sentence, p.Way.Fix.After.Sentence)
					}
					for _, ag := range again.Grants {
						if e.Removes == "policy" && (ag.Effect != "Deny" || len(ag.Populations) != 0) {
							t.Errorf("%s: the policy that replaces it makes grant %d, %s, with %d populations", name, ag.Number, ag.Effect, len(ag.Populations))
						}
					}
					if e.Removes != "policy" && len(again.Grants) != len(a.Grants)-len(e.GrantNumbers) {
						t.Errorf("%s: the edited policy has %d grants, the original %d and the fix takes out %d", name, len(again.Grants), len(a.Grants), len(e.GrantNumbers))
					}
					for _, ag := range again.Grants {
						for _, ap := range ag.Populations {
							for _, o := range ap.Owners {
								for _, target := range p.Owners {
									if target.Scope == "account" && o.Scope == "account" && o.Value == target.Value {
										t.Errorf("%s: the edited policy still lets %s in by name", name, o.Label)
									}
								}
							}
						}
					}
				}
			}
		}
	}
	if proven < 3 || replaced < 3 {
		t.Fatalf("%d proven fixes over the corpus, %d of them replacing the policy; the property examined too few", proven, replaced)
	}
}

// Bytes that do not read as a policy once edited are refused, with the
// reader's reason, and so is an edited policy that reads with a fault the
// original does not have, in the parser's words.
func TestAnEditThatDoesNotReadIsRefused(t *testing.T) {
	r, err := readPolicy([]byte(partnerBesideEC2))
	if err != nil {
		t.Fatal(err)
	}
	declared := ring.ReadDeclarations("")
	p := &placing{read: r, declared: declared, placed: r.place(declared.Owners)}
	i := slices.IndexFunc(r.written, func(w aws.Written) bool { return w.Text == "arn:aws:iam::111122223333:root" })
	f := r.check(i, p.placed[i].placement.Populations[0].Owners, p, []byte(`{"Statement":[`), aws.RemovedPrincipal)
	if f.Check != "parse" || !strings.HasPrefix(f.Sentence, "No fix the engine can prove yet: with the principal removed, the policy is not read: ") {
		t.Errorf("an edit that does not read: %+v", *f)
	}
	faulty := strings.Replace(partnerRemoved, "2012-10-17", "2013-10-17", 1)
	f = r.check(i, p.placed[i].placement.Populations[0].Owners, p, []byte(faulty), aws.RemovedPrincipal)
	if want := `No fix the engine can prove yet: with the principal removed, the policy reads with a fault it does not have now: Version "2013-10-17" is neither "2012-10-17" nor "2008-10-17"; policy variables are read as unresolved.`; f.Check != "parse" || f.Sentence != want {
		t.Errorf("an edit that reads with a new fault: %+v\nwant check parse saying %q", *f, want)
	}
}

// Re-marked with other owners, a proven fix keeps its edit and says the
// headline the edited policy opens on with those owners, which is what
// answering the policy with them says; a population that moves between a
// named outsider and the reader's keeps the fix it had, in both directions.
func TestARemarkedFixIsWhatTheOwnersNowGive(t *testing.T) {
	policy := []byte(`{"Version":"2012-10-17","Statement":[{"Sid":"Partner","Effect":"Allow","Principal":{"AWS":["arn:aws:iam::111122223333:root","444455556666"]},"Action":"sts:AssumeRole"}]}`)
	const engine = "cloudarq test"
	for _, c := range []struct{ upload, now string }{
		{"", "aws:444455556666"},
		{"aws:444455556666", ""},
		{"aws:111122223333", ""},
		{"", "aws:111122223333\naws:444455556666"},
	} {
		kept := AdmitsFor(policy, []byte(c.upload))
		got := Remark(kept, []byte(c.now), engine, engine)
		if want := AdmitsFor(policy, []byte(c.now)); !bytes.Equal(got, want) {
			at := firstDifference(got, want)
			t.Errorf("kept with %q, re-marked with %q:\n...%s...\nwant\n...%s...", c.upload, c.now, around(got, at), around(want, at))
		}
	}
	before := fixOf(t, answerOf(t, AdmitsFor(policy, nil)), "arn:aws:iam::111122223333:root").After.Sentence
	after := fixOf(t, answerOf(t, Remark(AdmitsFor(policy, nil), []byte("aws:444455556666"), engine, engine)), "arn:aws:iam::111122223333:root").After.Sentence
	if before == after {
		t.Errorf("declaring the other account left the headline after the fix at %q, so re-marking it proved nothing", before)
	}
	// A fix that replaces the policy with one that lets no one in leaves no
	// grant of it, and re-marked with the partner declared, or no longer
	// declared, it says what answering the policy with those owners says.
	for _, c := range []struct{ upload, now string }{
		{"", "aws:111122223333"},
		{"aws:111122223333", ""},
		{"", "aws:444455556666"},
	} {
		kept := AdmitsFor([]byte(partnerAlone), []byte(c.upload))
		got := Remark(kept, []byte(c.now), engine, engine)
		if want := AdmitsFor([]byte(partnerAlone), []byte(c.now)); !bytes.Equal(got, want) {
			at := firstDifference(got, want)
			t.Errorf("the lone partner kept with %q, re-marked with %q:\n...%s...\nwant\n...%s...", c.upload, c.now, around(got, at), around(want, at))
		}
		if f := fixOf(t, answerOf(t, got), "arn:aws:iam::111122223333:root"); f.Status != "proven" || f.Edit.Removes != "policy" {
			t.Errorf("the lone partner kept with %q, re-marked with %q: the fix is %+v, not the policy replaced", c.upload, c.now, *f)
		}
	}
}

// An answer whose population has no fix where this build writes one, or a
// proven fix without its edit, is not an answer this build writes, and is
// declined rather than re-marked.
func TestARemarkWithoutTheFixIsDeclined(t *testing.T) {
	policy := []byte(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":["arn:aws:iam::111122223333:root","444455556666"]},"Action":"sts:AssumeRole"}]}`)
	const engine = "cloudarq test"
	for name, strip := range map[string]func(*Fix) *Fix{
		"no fix":                    func(*Fix) *Fix { return nil },
		"a proven fix with no edit": func(f *Fix) *Fix { g := *f; g.Edit = nil; return &g },
	} {
		a := answerOf(t, AdmitsFor(policy, nil))
		a.Grants[0].Populations[0].Way.Fix = strip(a.Grants[0].Populations[0].Way.Fix)
		kept, err := json.Marshal(a)
		if err != nil {
			t.Fatal(err)
		}
		var d Declined
		if err := json.Unmarshal(Remark(kept, nil, engine, engine), &d); err != nil || d.Declined != "answer" {
			t.Errorf("%s: re-marked rather than declined as not an answer: %+v %v", name, d, err)
		}
	}
}
