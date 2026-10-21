package aws

import (
	"reflect"
	"testing"

	"github.com/CloudArq-net/cloudarq/internal/trust"
)

// Unread names, for one grant, each key under an operator of its statement
// that the grant's projection did not read, with its values as written: a
// key under an operator this parser does not model, a key that describes
// the request rather than the caller, and a value that is not a string,
// each as AWS reads it; and not the keys it read, whatever else the
// statement says of them.
func TestUnreadNamesTheConditionsAGrantDoesNotRead(t *testing.T) {
	v := LowercaseVocabulary("https://token.actions.githubusercontent.com")
	d := mustParse(t, `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::444455556666:root"},"Action":"sts:AssumeRole","Condition":{
		"StringEquals":{"sts:ExternalId":"vendor-abc","aws:PrincipalTag/team":{"a": 1}},
		"IpAddress":{"aws:SourceIp":["10.0.0.0/8","10.0.0.0/8"]},
		"Bool":{"aws:MultiFactorAuthPresent":true},
		"NumericLessThan":{"aws:MultiFactorAuthAge":3600},
		"Null":{"aws:TokenIssueTime":null},
		"StringLike":{"sts:ExternalId":[]}}}]}`)
	grants, written := d.GrantsWritten(role, v)
	if len(grants) != 1 {
		t.Fatalf("%d grants, want 1", len(grants))
	}
	got, ok := d.Unread(0, written[0], grants[0].Issuer, v)
	want := []Condition{
		{"StringEquals", "aws:PrincipalTag/team", []string{`{"a": 1}`}},
		{"IpAddress", "aws:SourceIp", []string{"10.0.0.0/8", "10.0.0.0/8"}},
		{"Bool", "aws:MultiFactorAuthPresent", []string{"true"}},
		{"NumericLessThan", "aws:MultiFactorAuthAge", []string{"3600"}},
		{"Null", "aws:TokenIssueTime", []string{"null"}},
		{"StringLike", "sts:ExternalId", []string{}},
	}
	if !ok || !reflect.DeepEqual(got, want) {
		t.Errorf("unread %v (found %v), want\n%v", got, ok, want)
	}
}

// Of a statement that names everyone, the grant for AWS principals reads
// its conditions as any AWS principal's, and the grant for every other
// issuer reads none of them, since which issuer's tokens it admits is not
// known; and a grant that names nothing read is found nowhere.
func TestUnreadOfEachFaceOfEveryone(t *testing.T) {
	v := LowercaseVocabulary("https://token.actions.githubusercontent.com")
	d := mustParse(t, `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"sts:AssumeRole","Condition":{"StringEquals":{"aws:PrincipalAccount":"111122223333"},"IpAddress":{"aws:SourceIp":"10.0.0.0/8"}}}]}`)
	grants, written := d.GrantsWritten(role, v)
	if len(grants) != 2 {
		t.Fatalf("%d grants, want 2", len(grants))
	}
	ranges := Condition{"IpAddress", "aws:SourceIp", []string{"10.0.0.0/8"}}
	for i, g := range grants {
		got, ok := d.Unread(0, written[i], g.Issuer, v)
		want := []Condition{ranges}
		if g.Issuer != AWSPrincipalIssuer {
			want = []Condition{{"StringEquals", "aws:PrincipalAccount", []string{"111122223333"}}, ranges}
		}
		if !ok || !reflect.DeepEqual(got, want) {
			t.Errorf("the grant for %q: unread %v (found %v), want %v", g.Issuer, got, ok, want)
		}
	}
	for _, c := range []struct {
		name      string
		statement int
		written   Written
		issuer    trust.IssuerRef
	}{
		{"no statement before the first", -1, written[0], grants[0].Issuer},
		{"no statement past the last", 1, written[0], grants[0].Issuer},
		{"a principal the statement does not write", 0, Written{Member: "AWS", Text: "*", Start: 1, End: 4}, grants[0].Issuer},
		{"an issuer no face of it has", 0, written[0], "https://example.com"},
	} {
		if got, ok := d.Unread(c.statement, c.written, c.issuer, v); ok || got != nil {
			t.Errorf("%s: unread %v, found %v; want nothing found", c.name, got, ok)
		}
	}
}

// Two principals the parser read no string of are written alike, so a
// grant of either is not told from the other's, and nothing is found
// rather than one of them guessed at.
func TestUnreadFindsNoGrantWrittenAlikeTwice(t *testing.T) {
	v := LowercaseVocabulary("https://token.actions.githubusercontent.com")
	d := mustParse(t, `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":[7,8]},"Action":"sts:AssumeRole","Condition":{"IpAddress":{"aws:SourceIp":"10.0.0.0/8"}}}]}`)
	grants, written := d.GrantsWritten(role, v)
	if len(grants) == 0 {
		t.Fatal("no grants")
	}
	for i, g := range grants {
		if written[i] != (Written{}) {
			t.Fatalf("grant %d is written %+v; want written as nothing", i, written[i])
		}
		if got, ok := d.Unread(0, written[i], g.Issuer, v); ok || got != nil {
			t.Errorf("grant %d: unread %v, found %v; want nothing found", i, got, ok)
		}
	}
}
