package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/CloudArq-net/cloudarq/internal/parse/aws"
)

// The parser turns every member the grammar does not define, and every
// Statement value of the wrong shape, into a statement that admits
// everything, declared; the layout must count and locate exactly those,
// in the parser's order, or the page shows nothing for the one document
// whose answer is the widest.
func TestEveryStatementTheParserReadsIsLocated(t *testing.T) {
	cases := map[string]string{
		"misspelt member":              `{"Version":"2012-10-17","Statement":[],"Statment":{"Effect":"Allow","Principal":"*","Action":"sts:AssumeRole"}}`,
		"scalar Statement":             `{"Version": 2012, "Id": 5, "Statement": "nope"}`,
		"scalar inside the list":       `{"Statement": [ 1 , {"Effect":"Allow","Principal":"*","Action":"sts:AssumeRoleWithWebIdentity"}, "two" ]}`,
		"unknown members either side":  `{"Statment": {"a": 1}, "Statement": [{"Effect":"Allow","Principal":"*","Action":"sts:AssumeRoleWithWebIdentity"}], "Statment": [1, 2], "Other": null}`,
		"member spelt beyond ascii":    "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"sts:AssumeRoleWithWebIdentity\"}],\"\\u00dcnknown\\ud83d\\ude00\": { \"x\": \"y\" }}",
		"Statement written twice":      `{"Statement": {"Effect":"Allow","Principal":"*","Action":"sts:AssumeRoleWithWebIdentity"}, "Version": "2012-10-17", "Statement": [{"Effect":"Deny","Principal":"*","Action":"sts:AssumeRoleWithWebIdentity"}]}`,
		"nothing but unknown members":  `{"a": 1, "b": [true], "a": "again"}`,
		"a Statement value of nothing": `{"Statement": null}`,
	}
	for name, doc := range cases {
		raw := []byte(doc)
		parsed, err := aws.ParseTrustPolicy(raw)
		if err != nil {
			t.Fatalf("%s: the parser refused a document it should read: %v", name, err)
		}
		a := answerFor(t, raw)
		if a.Error != "" {
			t.Errorf("%s: %s", name, a.Error)
			continue
		}
		if len(a.Document.Statements) != len(parsed.Statements) {
			t.Errorf("%s: %d statements located, the parser read %d", name, len(a.Document.Statements), len(parsed.Statements))
			continue
		}
		for _, s := range a.Document.Statements {
			if got := raw[s.Offset : s.Offset+s.Length]; !bytes.Equal(got, parsed.Statements[s.Index].Raw) {
				t.Errorf("%s statement[%d]: located %q, the parser read %q", name, s.Index, got, parsed.Statements[s.Index].Raw)
			}
		}
		if len(a.Grants) != len(parsed.Grants(target, vocabulary)) {
			t.Errorf("%s: %d grants rendered, the engine projects %d", name, len(a.Grants), len(parsed.Grants(target, vocabulary)))
		}
	}
	// the misspelt member's grant is the engine's widest answer, and the page
	// is owed it: everything, declared, with the member's own bytes to quote
	a := answerFor(t, []byte(cases["misspelt member"]))
	if a.Error != "" || len(a.Grants) != 1 {
		t.Fatalf("the misspelt member's answer: %+v", a)
	}
	g := a.Grants[0]
	if !g.Top || g.Exact || g.Witness != "" || !strings.HasPrefix(g.Sentence, `Who this statement admits is not known: the document member "Statment"`) {
		t.Errorf("the misspelt member's grant: %+v", g)
	}
	if s := a.Document.Statements[g.Statement]; string([]byte(cases["misspelt member"])[s.Offset:s.Offset+s.Length]) != `{"Effect":"Allow","Principal":"*","Action":"sts:AssumeRole"}` {
		t.Errorf("the misspelt member's bytes were not located: %+v", s)
	}
}
