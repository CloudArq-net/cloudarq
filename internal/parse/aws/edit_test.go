package aws

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"pgregory.net/rapid"

	"github.com/CloudArq-net/cloudarq/internal/trust"
)

// writtenAt is where the grant read from the principal text, under member,
// is written, as GrantsWritten reads it: the offsets RemovePrincipal is
// given are the reader's, never searched for. nth counts from 0 among the
// grants read from that principal.
func writtenAt(t *testing.T, policy, member, text string, nth int) (int, int) {
	t.Helper()
	_, written := mustParse(t, policy).GrantsWritten(role, LowercaseVocabulary())
	for _, w := range written {
		if w.Member == member && w.Text == text {
			if nth == 0 {
				return w.Start, w.End
			}
			nth--
		}
	}
	t.Fatalf("no grant is read from %s %q in %s", member, text, policy)
	return 0, 0
}

// RemovePrincipal takes out the least that removes the principal: the
// principal from a list that names others, with the comma beside it; the
// member of Principal it is the only value of, beside other members; or
// the statement, when its Principal names nothing else, with the comma
// beside it. Every other byte stays as written: whitespace, escapes and the
// statements around it.
func TestRemovePrincipalTakesOutTheLeast(t *testing.T) {
	cases := []struct {
		name, policy, member, text string
		nth                        int
		want                       string
		removed                    Removed
	}{
		{"the first of a list", `{"Statement":[{"Effect":"Allow","Principal":{"AWS":["111122223333","444455556666"]},"Action":"sts:AssumeRole"}]}`, "AWS", "111122223333", 0,
			`{"Statement":[{"Effect":"Allow","Principal":{"AWS":["444455556666"]},"Action":"sts:AssumeRole"}]}`, RemovedPrincipal},
		{"the middle of a list, spaced", `{"Statement":[{"Effect":"Allow","Principal":{"AWS":[ "777788889999" , "111122223333" , "444455556666" ]},"Action":"sts:AssumeRole"}]}`, "AWS", "111122223333", 0,
			`{"Statement":[{"Effect":"Allow","Principal":{"AWS":[ "777788889999" , "444455556666" ]},"Action":"sts:AssumeRole"}]}`, RemovedPrincipal},
		{"the last of a list, on lines of their own", "{\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"AWS\":[\n  \"444455556666\",\r\n  \"arn:aws:iam::111122223333:root\"\n]},\"Action\":\"sts:AssumeRole\"}]}", "AWS", "arn:aws:iam::111122223333:root", 0,
			"{\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"AWS\":[\n  \"444455556666\"\n]},\"Action\":\"sts:AssumeRole\"}]}", RemovedPrincipal},
		{"one of two spellings of one account, the second", `{"Statement":[{"Effect":"Allow","Principal":{"AWS":["111122223333","111122223333"]},"Action":"sts:AssumeRole"}]}`, "AWS", "111122223333", 1,
			`{"Statement":[{"Effect":"Allow","Principal":{"AWS":["111122223333"]},"Action":"sts:AssumeRole"}]}`, RemovedPrincipal},
		{"escaped, in a list", `{"Statement":[{"Effect":"Allow","Principal":{"AWS":["arn:aws:iam::111122223333:root","444455556666"]},"Action":"sts:AssumeRole"}]}`, "AWS", "arn:aws:iam::111122223333:root", 0,
			`{"Statement":[{"Effect":"Allow","Principal":{"AWS":["444455556666"]},"Action":"sts:AssumeRole"}]}`, RemovedPrincipal},
		{"a string beside another kind", `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"111122223333","Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}`, "AWS", "111122223333", 0,
			`{"Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}`, RemovedKind},
		{"a list of one, after another kind", `{"Statement":[{"Effect":"Allow","Principal":{"Service": "ec2.amazonaws.com", "AWS": ["111122223333"]},"Action":"sts:AssumeRole"}]}`, "AWS", "111122223333", 0,
			`{"Statement":[{"Effect":"Allow","Principal":{"Service": "ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}`, RemovedKind},
		{"a kind written twice, the first copy", `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"111122223333","AWS":"444455556666"},"Action":"sts:AssumeRole"}]}`, "AWS", "111122223333", 0,
			`{"Statement":[{"Effect":"Allow","Principal":{"AWS":"444455556666"},"Action":"sts:AssumeRole"}]}`, RemovedKind},
		{"the only principal of the first statement", `{"Version":"2012-10-17","Statement":[{"Sid":"Partner","Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111122223333:root"},"Action":"sts:AssumeRole"},{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}`, "AWS", "arn:aws:iam::111122223333:root", 0,
			`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}`, RemovedStatement},
		{"the only principal of the last statement, a list of one, indented", "{\n  \"Statement\": [\n    {\"Effect\": \"Allow\", \"Principal\": {\"Service\": \"ec2.amazonaws.com\"}, \"Action\": \"sts:AssumeRole\"},\n    {\"Effect\": \"Allow\", \"Principal\": {\"AWS\": [\"111122223333\"]}, \"Action\": \"sts:AssumeRole\"}\n  ]\n}", "AWS", "111122223333", 0,
			"{\n  \"Statement\": [\n    {\"Effect\": \"Allow\", \"Principal\": {\"Service\": \"ec2.amazonaws.com\"}, \"Action\": \"sts:AssumeRole\"}\n  ]\n}", RemovedStatement},
		{"the only principal of the only statement", `{"Version":"2012-10-17","Statement":[ {"Effect":"Allow","Principal":{"AWS":"111122223333"},"Action":"sts:AssumeRole"} ]}`, "AWS", "111122223333", 0,
			`{"Version":"2012-10-17","Statement":[]}`, RemovedStatement},
		{"a statement written as the Statement member's object", `{"Statement":{"Effect":"Allow","Principal":{"AWS":"111122223333"},"Action":"sts:AssumeRole"},"Version":"2012-10-17"}`, "AWS", "111122223333", 0,
			`{"Version":"2012-10-17"}`, RemovedStatement},
		{"a Principal that is * itself", `{"Statement":[{"Effect":"Allow","Principal":"*","Action":"sts:AssumeRole"},{"Effect":"Allow","Principal":{"AWS":"111122223333"},"Action":"sts:AssumeRole"}]}`, "", "*", 0,
			`{"Statement":[{"Effect":"Allow","Principal":{"AWS":"111122223333"},"Action":"sts:AssumeRole"}]}`, RemovedStatement},
		{"Principal written twice, the copy that names it alone", `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"111122223333"},"Principal":{"AWS":"444455556666"},"Action":"sts:AssumeRole"},{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}`, "AWS", "111122223333", 0,
			`{"Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}`, RemovedStatement},
		{"Statement written twice, the second", `{"Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}],"Statement":[{"Effect":"Allow","Principal":{"AWS":["111122223333","444455556666"]},"Action":"sts:AssumeRole"}]}`, "AWS", "444455556666", 0,
			`{"Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}],"Statement":[{"Effect":"Allow","Principal":{"AWS":["111122223333"]},"Action":"sts:AssumeRole"}]}`, RemovedPrincipal},
	}
	for _, c := range cases {
		start, end := writtenAt(t, c.policy, c.member, c.text, c.nth)
		got, removed, err := RemovePrincipal([]byte(c.policy), start, end)
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		if string(got) != c.want || removed != c.removed {
			t.Errorf("%s: removed %d giving\n%s\nwant %d giving\n%s", c.name, removed, got, c.removed, c.want)
		}
	}
}

// RemovePrincipal refuses offsets that are not exactly one principal string
// under a statement's Principal, and a principal of a statement it may not
// edit: one that is not an Allow written once, or one that writes
// NotPrincipal. It never moves the offsets to the nearest principal, and
// what it refuses it does not change.
func TestRemovePrincipalRefusesWhatItMayNotEdit(t *testing.T) {
	const partner = `{"Statement":[{"Effect":"Allow","Principal":{"AWS":["111122223333","444455556666"]},"Action":"sts:AssumeRole","Condition":{"StringEquals":{"aws:SourceAccount":"111122223333"}}}],"Statment":{"Effect":"Allow","Principal":{"AWS":"777788889999"},"Action":"sts:AssumeRole"}}`
	at := func(policy, literal string, nth int) (int, int) {
		i := -1
		for n := 0; n <= nth; n++ {
			next := strings.Index(policy[i+1:], literal)
			if next < 0 {
				t.Fatalf("%s is not in %s %d times", literal, policy, nth+1)
			}
			i += 1 + next
		}
		return i, i + len(literal)
	}
	leafStart, leafEnd := at(partner, `"111122223333"`, 0)
	condStart, condEnd := at(partner, `"111122223333"`, 1)
	misspeltStart, misspeltEnd := at(partner, `"777788889999"`, 0)
	effectStart, effectEnd := at(partner, `"Allow"`, 0)
	cases := []struct {
		name, policy string
		start, end   int // -1 for where the policy first spells "111122223333"
		says         string
	}{
		{"one byte early", partner, leafStart - 1, leafEnd, "are not one principal"},
		{"inside the quotes", partner, leafStart + 1, leafEnd - 1, "are not one principal"},
		{"one byte long", partner, leafStart, leafEnd + 1, "are not one principal"},
		{"a condition's value that spells the account", partner, condStart, condEnd, "are not one principal"},
		{"the Effect", partner, effectStart, effectEnd, "are not one principal"},
		{"a principal in a member the grammar does not define", partner, misspeltStart, misspeltEnd, "are not one principal"},
		{"past the end", partner, len(partner) + 4, len(partner) + 18, "are not one principal"},
		{"under NotPrincipal", `{"Statement":[{"Effect":"Deny","NotPrincipal":{"AWS":"111122223333"},"Action":"sts:AssumeRole"}]}`, -1, -1, "are not one principal"},
		{"a Deny", `{"Statement":[{"Effect":"Deny","Principal":{"AWS":"111122223333"},"Action":"sts:AssumeRole"}]}`, -1, -1, `Effect once, as "Allow"`},
		{"an Effect in another case", `{"Statement":[{"Effect":"allow","Principal":{"AWS":"111122223333"},"Action":"sts:AssumeRole"}]}`, -1, -1, `Effect once, as "Allow"`},
		{"an Effect written twice", `{"Statement":[{"Effect":"Allow","Effect":"Allow","Principal":{"AWS":"111122223333"},"Action":"sts:AssumeRole"}]}`, -1, -1, `Effect once, as "Allow"`},
		{"an Effect that is not a string", `{"Statement":[{"Effect":true,"Principal":{"AWS":"111122223333"},"Action":"sts:AssumeRole"}]}`, -1, -1, `Effect once, as "Allow"`},
		{"no Effect", `{"Statement":[{"Principal":{"AWS":"111122223333"},"Action":"sts:AssumeRole"}]}`, -1, -1, `Effect once, as "Allow"`},
		{"NotPrincipal beside Principal", `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"111122223333"},"NotPrincipal":{"AWS":"444455556666"},"Action":"sts:AssumeRole"}]}`, -1, -1, "writes NotPrincipal"},
		{"a condition's value in a statement written as the Statement member's object", `{"Statement":{"Effect":"Allow","Principal":{"AWS":"444455556666"},"Action":"sts:AssumeRole","Condition":{"StringEquals":{"aws:SourceAccount":"111122223333"}}}}`, -1, -1, "are not one principal"},
		{"a Statement that is a string", `{"Statement":"111122223333"}`, -1, -1, "are not one principal"},
		{"a statement that is not an object", `{"Statement":["111122223333"]}`, -1, -1, "are not one principal"},
		{"a Principal that is a list", `{"Statement":[{"Effect":"Allow","Principal":["111122223333"],"Action":"sts:AssumeRole"}]}`, -1, -1, "are not one principal"},
		{"not JSON", `{"Statement":["111122223333"`, -1, -1, "the policy is not read"},
		{"not an object", `["111122223333"]`, -1, -1, "not an object"},
	}
	for _, c := range cases {
		if c.start < 0 {
			// the first account the policy spells, as its literal
			c.start, c.end = at(c.policy, `"111122223333"`, 0)
		}
		got, removed, err := RemovePrincipal([]byte(c.policy), c.start, c.end)
		if err == nil || !strings.Contains(err.Error(), c.says) || got != nil || removed != 0 {
			t.Errorf("%s: removed %d giving %s, err %v; want a refusal that says %q", c.name, removed, got, err, c.says)
		}
	}
}

// Over generated policies, removing any principal of an Allow statement
// leaves a policy the parser reads whose principals are the original's but
// that one, or but every principal of its statement when the statement
// went, each still written at offsets that hold it; and the bytes outside
// what was removed are the original's.
func TestRemovePrincipalRemovesThatPrincipalAndNothingElse(t *testing.T) {
	accounts := []string{"111122223333", "444455556666", "arn:aws:iam::777788889999:root", "arn:aws:iam::111122223333:role/a\\u002fb"}
	kinds := []string{"AWS", "Service"}
	removedEach := map[Removed]int{}
	rapid.Check(t, func(t *rapid.T) {
		var statements []string
		for n := rapid.IntRange(1, 3).Draw(t, "statements"); n > 0; n-- {
			var members []string
			for _, kind := range kinds {
				count := rapid.IntRange(0, 3).Draw(t, kind)
				if count == 0 {
					continue
				}
				var names []string
				for ; count > 0; count-- {
					if kind == "Service" {
						names = append(names, `"ec2.amazonaws.com"`)
						continue
					}
					names = append(names, `"`+rapid.SampledFrom(accounts).Draw(t, "account")+`"`)
				}
				if len(names) == 1 && rapid.Bool().Draw(t, "as a string") {
					members = append(members, `"`+kind+`": `+names[0])
					continue
				}
				members = append(members, `"`+kind+`": [`+strings.Join(names, ",\n  ")+`]`)
			}
			if len(members) == 0 {
				members = []string{`"AWS": "111122223333"`}
			}
			effect := rapid.SampledFrom([]string{"Allow", "Allow", "Deny"}).Draw(t, "effect")
			statements = append(statements, `{"Effect": "`+effect+`", "Principal": {`+strings.Join(members, ", ")+`}, "Action": "sts:AssumeRole"}`)
		}
		policy := "{\"Version\": \"2012-10-17\", \"Statement\": [\n" + strings.Join(statements, ",\n") + "\n]}"
		d, err := ParseTrustPolicy([]byte(policy))
		if err != nil {
			t.Fatalf("%s: %v", policy, err)
		}
		_, written := d.GrantsWritten(role, LowercaseVocabulary())
		pick := rapid.IntRange(0, len(written)-1).Draw(t, "principal")
		w := written[pick]
		got, removed, err := RemovePrincipal([]byte(policy), w.Start, w.End)
		statementOf := func(raw string, at int) int { return strings.Count(raw[:at], "\"Effect\"") - 1 }
		allow := strings.Contains(statements[statementOf(policy, w.Start)], `"Allow"`)
		if !allow {
			if err == nil {
				t.Fatalf("%s: the principal at %d-%d of a Deny was removed", policy, w.Start, w.End)
			}
			return
		}
		if err != nil {
			t.Fatalf("%s: %v", policy, err)
		}
		removedEach[removed]++
		after, err := ParseTrustPolicy(got)
		if err != nil {
			t.Fatalf("%s with %d-%d removed is\n%s\nwhich does not read: %v", policy, w.Start, w.End, got, err)
		}
		_, left := after.GrantsWritten(role, LowercaseVocabulary())
		want := map[string]int{}
		for i, o := range written {
			gone := i == pick || removed == RemovedStatement && statementOf(policy, o.Start) == statementOf(policy, w.Start)
			if !gone {
				want[o.Member+" "+o.Text]++
			}
		}
		for _, l := range left {
			want[l.Member+" "+l.Text]--
			var decoded string
			if json.Unmarshal(got[l.Start:l.End], &decoded) != nil || decoded != l.Text {
				t.Fatalf("%s: what is left says %q is written at %d-%d of\n%s", policy, l.Text, l.Start, l.End, got)
			}
		}
		for principal, n := range want {
			if n != 0 {
				t.Fatalf("%s with %d-%d removed (%d) is\n%s\nand %q is left %d times too few", policy, w.Start, w.End, removed, got, principal, n)
			}
		}
		if !strings.HasSuffix(policy, string(got[prefixKept(policy, got):])) {
			t.Fatalf("%s: more than one run of bytes was removed:\n%s", policy, got)
		}
	})
	for _, r := range []Removed{RemovedPrincipal, RemovedKind, RemovedStatement} {
		if removedEach[r] == 0 {
			t.Errorf("no generated policy removed %s; counts %v", fmt.Sprint(r), removedEach)
		}
	}
}

// prefixKept is how many leading bytes the edited policy shares with the
// original.
func prefixKept(original string, edited []byte) int {
	n := 0
	for n < len(original) && n < len(edited) && original[n] == edited[n] {
		n++
	}
	return n
}

// LetNoOneIn writes the trust policy that lets no one in: one statement, a
// Deny of sts:AssumeRole to every AWS principal, after the Version the
// original writes, its value as written, and no other member of the
// original. A policy that writes no Version gets none. A Version IAM
// refuses, written twice, not a string, or neither of the two language
// versions, is refused, since the replacement would keep it.
func TestLetNoOneInKeepsTheVersionAsWritten(t *testing.T) {
	const statement = `"Statement": [
    {
      "Sid": "DenyEveryone",
      "Effect": "Deny",
      "Principal": {"AWS": "*"},
      "Action": "sts:AssumeRole"
    }
  ]
}`
	only := `{"Effect":"Allow","Principal":{"AWS":"111122223333"},"Action":"sts:AssumeRole"}`
	cases := []struct{ name, policy, versions string }{
		{"2012-10-17, spaced", "{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [" + only + "]\n}", `  "Version": "2012-10-17",` + "\n"},
		{"2008-10-17, after the statement, unspaced", `{"Statement":` + only + `,"Version":"2008-10-17"}`, `  "Version": "2008-10-17",` + "\n"},
		{"escaped, the name too", `{"\u0056ersion":"2012\u002d10-17","Statement":[` + only + `]}`, `  "Version": "2012\u002d10-17",` + "\n"},
		{"none, beside an Id", `{"Id":"partner","Statement":[` + only + `]}`, ""},
	}
	for _, c := range cases {
		got, err := LetNoOneIn([]byte(c.policy))
		if want := "{\n" + c.versions + "  " + statement; err != nil || string(got) != want {
			t.Errorf("%s: %v\n%s\nwant\n%s", c.name, err, got, want)
			continue
		}
		d, err := ParseTrustPolicy(got)
		if err != nil || len(d.Statements) != 1 || d.Statements[0].Sid != "DenyEveryone" {
			t.Errorf("%s: the policy written reads as %+v, %v", c.name, d, err)
			continue
		}
		grants, _ := d.GrantsWritten(role, LowercaseVocabulary())
		if len(grants) == 0 {
			t.Errorf("%s: the policy written makes no grant", c.name)
		}
		for _, g := range grants {
			if g.Effect != trust.Deny {
				t.Errorf("%s: the policy written makes a grant whose effect is %s", c.name, g.Effect)
			}
		}
	}
	for _, c := range []struct{ name, policy, says string }{
		{"not JSON", `{"Statement":[`, "the policy is not read"},
		{"not an object", `["2012-10-17"]`, "not an object"},
		{"Version written twice", `{"Version":"2008-10-17","Statement":[` + only + `],"Version":"2012-10-17"}`, "the policy writes Version more than once"},
		{"Version not a string", `{"Version":20121017,"Statement":[` + only + `]}`, "Version is a number (20121017), not a string"},
		{"Version an object", `{"Version":{"Statement":[{"Effect":"Allow","Principal":"*","Action":"sts:AssumeRole"}]},"Statement":[` + only + `]}`, "Version is an object ("},
		{"Version neither of the two", `{"Version":"2013-10-17","Statement":[` + only + `]}`, `Version "2013-10-17" is neither "2012-10-17" nor "2008-10-17"`},
	} {
		if got, err := LetNoOneIn([]byte(c.policy)); err == nil || !strings.Contains(err.Error(), c.says) || got != nil {
			t.Errorf("%s: %s, %v; want a refusal that says %q", c.name, got, err, c.says)
		}
	}
}
