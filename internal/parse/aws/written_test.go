package aws

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"

	"github.com/CloudArq-net/cloudarq/internal/trust"
)

// GrantsWritten gives the grants Grants gives, in the same order, each with
// the principal it was projected from as the statement writes it: the
// member of Principal it sits under and its text, both empty where the
// parser read no principal string.
func TestGrantsWrittenNamesThePrincipalOfEachGrant(t *testing.T) {
	v := LowercaseVocabulary("https://token.actions.githubusercontent.com")
	// what each grant was read from, without where it is written, which
	// TestGrantsWrittenReadsWhereEachPrincipalIsWritten reads
	type named struct{ Member, Text string }
	cases := []struct {
		name, policy string
		want         []named
	}{
		{"the whole Principal is *", `{"Statement":{"Effect":"Allow","Principal":"*","Action":"sts:AssumeRole"}}`,
			[]named{{"", "*"}, {"", "*"}}},
		{"* under AWS", `{"Statement":{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}}`,
			[]named{{"AWS", "*"}, {"AWS", "*"}}},
		{"an account, a root ARN and a role, in canonical order", `{"Statement":{"Effect":"Allow","Principal":{"AWS":["arn:aws:iam::777788889999:role/Deploy","444455556666","arn:aws:iam::111122223333:root"]},"Action":"sts:AssumeRole"}}`,
			[]named{{"AWS", "arn:aws:iam::111122223333:root"}, {"AWS", "444455556666"}, {"AWS", "arn:aws:iam::777788889999:role/Deploy"}}},
		{"one account written twice, in document order", `{"Statement":{"Effect":"Allow","Principal":{"AWS":["arn:aws:iam::111122223333:root","111122223333"]},"Action":"sts:AssumeRole"}}`,
			[]named{{"AWS", "arn:aws:iam::111122223333:root"}, {"AWS", "111122223333"}}},
		{"a provider and a service, in canonical order", `{"Statement":[{"Effect":"Allow","Principal":{"Federated":"token.actions.githubusercontent.com"},"Action":"sts:AssumeRoleWithWebIdentity"},{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}`,
			[]named{{"Service", "ec2.amazonaws.com"}, {"Federated", "token.actions.githubusercontent.com"}}},
		{"a canonical user, which is not modelled", `{"Statement":{"Effect":"Allow","Principal":{"CanonicalUser":"79a59df900b949e55d96a1e698fbacedfd6e09d98eacf8f8d5218e7cd47ef2be"},"Action":"sts:AssumeRole"}}`,
			[]named{{}}},
		{"a policy variable", `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Principal":{"AWS":"${aws:username}"},"Action":"sts:AssumeRole"}}`,
			[]named{{"AWS", "${aws:username}"}}},
		{"a kind the parser does not know", `{"Statement":{"Effect":"Allow","Principal":{"Someone":"x"},"Action":"sts:AssumeRole"}}`,
			[]named{{}}},
		{"a principal that is not a string", `{"Statement":{"Effect":"Allow","Principal":{"AWS":[7]},"Action":"sts:AssumeRole"}}`,
			[]named{{}}},
		{"no Principal", `{"Statement":{"Effect":"Allow","Action":"sts:AssumeRole"}}`,
			[]named{{}}},
		{"NotPrincipal", `{"Statement":{"Effect":"Allow","NotPrincipal":{"AWS":"111122223333"},"Action":"sts:AssumeRole"}}`,
			[]named{{}}},
	}
	for _, c := range cases {
		d := mustParse(t, c.policy)
		grants, written := d.GrantsWritten(role, v)
		if !reflect.DeepEqual(grants, d.Grants(role, v)) {
			t.Errorf("%s: the grants are not the grants Grants gives", c.name)
		}
		got := make([]named, len(written))
		for i, w := range written {
			got[i] = named{w.Member, w.Text}
		}
		if !slices.Equal(got, c.want) {
			t.Errorf("%s: written %+v, want %+v", c.name, got, c.want)
		}
	}
}

// Over the corpus, every grant is given with what it was projected from,
// and the grants are Grants', in Grants' order; every grant read from a
// principal string says where that string is written, and the bytes there
// decode to the principal's text.
func TestGrantsWrittenGivesGrantsOverTheCorpus(t *testing.T) {
	paths, err := filepath.Glob(filepath.Join("..", "..", "..", "testdata", "policies", "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	more, err := filepath.Glob(filepath.Join("..", "..", "..", "testdata", "grants", "*", "aws.json"))
	if err != nil {
		t.Fatal(err)
	}
	examined, spanned := 0, 0
	for _, p := range append(paths, more...) {
		raw, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		d, err := ParseTrustPolicy(raw)
		if err != nil {
			continue
		}
		v := LowercaseVocabulary(trust.IssuerRef("https://token.actions.githubusercontent.com"))
		grants, written := d.GrantsWritten(role, v)
		if len(written) != len(grants) || !reflect.DeepEqual(grants, d.Grants(role, v)) {
			t.Errorf("%s: %d grants, %d written, or the grants are not Grants'", p, len(grants), len(written))
		}
		for i, w := range written {
			var decoded string
			if w.End != 0 && (json.Unmarshal(raw[w.Start:w.End], &decoded) != nil || decoded != w.Text) {
				t.Errorf("%s: grant %d says it is written at %d-%d, which does not hold %q", p, i+1, w.Start, w.End, w.Text)
			}
			if w.End != 0 {
				spanned++
			}
		}
		examined += len(grants)
	}
	// 75 of the 76 were read from a principal string when this was written
	if spanned < 70 {
		t.Fatalf("%d grants were read from a principal string; the corpus did not load", spanned)
	}
	// 76 grants over the policies and grants corpora when this was written
	if examined < 70 {
		t.Fatalf("%d grants examined; the corpus did not load", examined)
	}
}

// Each grant read from a principal string carries where that string is
// written: the byte offsets of its literal in the document, from the
// opening quote to just past the closing one, escapes and all, so that the
// bytes there are the literal as written and decode to the text. A grant
// no string projected carries none.
func TestGrantsWrittenReadsWhereEachPrincipalIsWritten(t *testing.T) {
	v := LowercaseVocabulary()
	cases := []struct {
		name, policy string
		want         []string // the literal at each grant's offsets, "" for none
	}{
		{"a string", `{"Statement":{"Effect":"Allow","Principal":{"AWS":"111122223333"},"Action":"sts:AssumeRole"}}`,
			[]string{`"111122223333"`}},
		{"an array, spaced and on several lines", "{\"Statement\":{\"Effect\":\"Allow\",\"Principal\":{\"AWS\": [\n  \"arn:aws:iam::111122223333:root\" ,\r\n\t\"444455556666\"\n]},\"Action\":\"sts:AssumeRole\"}}",
			[]string{`"arn:aws:iam::111122223333:root"`, `"444455556666"`}},
		{"escaped characters", `{"Statement":{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111122223333:root","Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}}`,
			[]string{`"ec2.amazonaws.com"`, `"arn:aws:iam::111122223333:root"`}},
		{"an escaped slash and quote", `{"Statement":{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111122223333:role\/a\"b"},"Action":"sts:AssumeRole"}}`,
			[]string{`"arn:aws:iam::111122223333:role\/a\"b"`}},
		{"the whole Principal is *, two faces of one string", `{"Statement":{"Effect":"Allow","Principal" : "*","Action":"sts:AssumeRole"}}`,
			[]string{`"*"`, `"*"`}},
		{"a principal that is not a string", `{"Statement":{"Effect":"Allow","Principal":{"AWS":[7]},"Action":"sts:AssumeRole"}}`,
			[]string{""}},
		{"NotPrincipal", `{"Statement":{"Effect":"Allow","NotPrincipal":{"AWS":"111122223333"},"Action":"sts:AssumeRole"}}`,
			[]string{""}},
		{"a canonical user", `{"Statement":{"Effect":"Allow","Principal":{"CanonicalUser":"79a59df900b949e55d96a1e698fbacedfd6e09d98eacf8f8d5218e7cd47ef2be"},"Action":"sts:AssumeRole"}}`,
			[]string{""}},
	}
	for _, c := range cases {
		d := mustParse(t, c.policy)
		_, written := d.GrantsWritten(role, v)
		if len(written) != len(c.want) {
			t.Fatalf("%s: %d grants, want %d", c.name, len(written), len(c.want))
		}
		for i, w := range written {
			if c.want[i] == "" {
				if w.Start != 0 || w.End != 0 {
					t.Errorf("%s: grant %d was read from no string and says it is written at %d-%d", c.name, i+1, w.Start, w.End)
				}
				continue
			}
			if w.Start <= 0 || w.End <= w.Start || w.End > len(c.policy) {
				t.Errorf("%s: grant %d is written at %d-%d, outside the document", c.name, i+1, w.Start, w.End)
				continue
			}
			literal := c.policy[w.Start:w.End]
			var decoded string
			if literal != c.want[i] || json.Unmarshal([]byte(literal), &decoded) != nil || decoded != w.Text {
				t.Errorf("%s: grant %d is written at %d-%d, which holds %s decoding to %q; want %s decoding to %q", c.name, i+1, w.Start, w.End, literal, decoded, c.want[i], w.Text)
			}
		}
	}
}
