package aws

import (
	"fmt"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/CloudArq-net/cloudarq/internal/trust"
)

// gh prefixes a claim with the GitHub provider's condition key prefix.
func gh(claim string) string { return githubHost + ":" + claim }

// Case 3: condition keys are case-insensitive, values are not. The key is
// matched however it is spelled; the value is kept exactly as written.
func TestKeysAreCaseInsensitiveValuesAreNot(t *testing.T) {
	g := oneGrant(t, string(readPolicy(t, "03-key-case-value-case")))
	want := `{aud="sts.amazonaws.com", sub="repo:Acme/Infra:ref:refs/heads/Main"}`
	if g.Admits.String() != want || !g.Exact() {
		t.Fatalf("Admits = %s, exact %v; want %s exact", g.Admits, g.Exact(), want)
	}
	if !g.Admits.Admits(token{"aud": "sts.amazonaws.com", "sub": "repo:Acme/Infra:ref:refs/heads/Main"}) {
		t.Errorf("the value as written must be admitted")
	}
	if g.Admits.Admits(token{"aud": "sts.amazonaws.com", "sub": "repo:acme/infra:ref:refs/heads/main"}) {
		t.Errorf("a differently cased value is a different value")
	}
	// Operator and member names are matched as the grammar spells them; an
	// unrecognised spelling widens rather than being guessed at.
	other := oneGrant(t, github(`{"stringequals": {"`+gh("sub")+`": "`+mainBranch+`"}}`))
	if !other.Admits.IsTop() || other.Exact() {
		t.Errorf("an operator spelled unlike the grammar is unmodelled; got %s exact %v", other.Admits, other.Exact())
	}
	if a, ok := findAnomaly(other, trust.Unmodelled, "stringequals"); !ok || a.Claim != "sub" {
		t.Errorf("anomaly = %+v, %v", a, ok)
	}
}

// Case 4: the same key twice inside one operator block. Both spellings
// name one key, a decoder would keep one, and the deployed policy may carry
// either; the claim becomes Unknown and the fact is recorded.
func TestDuplicateConditionKeyIsUnknown(t *testing.T) {
	g := oneGrant(t, string(readPolicy(t, "04-duplicate-condition-key")))
	want := `{aud="sts.amazonaws.com", sub=?("duplicate key ` + gh("sub") + `")}`
	if g.Admits.String() != want || g.Exact() {
		t.Fatalf("Admits = %s, exact %v; want %s inexact", g.Admits, g.Exact(), want)
	}
	if !hasCaveatOn(g, "sub") {
		t.Errorf("sub is Unknown without a caveat: %v", g.Admits.Caveats())
	}
	a, ok := findAnomaly(g, DuplicateKey, "StringEquals")
	if !ok || a.Claim != "sub" || a.Source != "statement[0].Condition" {
		t.Fatalf("duplicate-key anomaly = %+v, %v", a, ok)
	}
	if a.Message != `the key "`+gh("sub")+`" appears more than once under StringEquals; a JSON decoder keeps one and the deployed policy may carry either, so the claim is not constrained` {
		t.Errorf("message = %q", a.Message)
	}
	for _, tok := range []token{{"aud": "sts.amazonaws.com", "sub": mainBranch}, {"aud": "sts.amazonaws.com", "sub": devBranch}, {"aud": "sts.amazonaws.com", "sub": "anything"}, {"aud": "sts.amazonaws.com"}} {
		if !g.Admits.Admits(tok) {
			t.Errorf("%s must admit %v: an unknown sub is unconstrained", g.Admits, tok)
		}
	}
	if g.Admits.Admits(token{"sub": mainBranch}) {
		t.Errorf("aud is still required")
	}
}

// TestDuplicateOperatorBlockWidensEveryKeyInIt: two StringEquals blocks
// with different keys. A decoder keeps one block, so any key in either may
// be missing from the deployed policy; every key in both is Unknown.
func TestDuplicateOperatorBlockWidensEveryKeyInIt(t *testing.T) {
	g := oneGrant(t, github(`{"StringEquals": {"`+gh("sub")+`": "`+mainBranch+`"}, "StringEquals": {"`+gh("aud")+`": "sts.amazonaws.com"}}`))
	if !g.Admits.IsTop() || g.Exact() || !hasCaveatOn(g, "sub") || !hasCaveatOn(g, "aud") {
		t.Fatalf("Admits = %s, caveats %v; both keys must be Unknown with caveats", g.Admits, g.Admits.Caveats())
	}
	for _, claim := range []trust.ClaimKey{"sub", "aud"} {
		want := "the operator StringEquals appears more than once in the Condition; a JSON decoder keeps one block and the deployed policy may carry either, so the claim is not constrained"
		if !slices.ContainsFunc(g.Anomalies, func(a trust.Anomaly) bool {
			return a.Kind == DuplicateKey && a.Claim == claim && a.Construct == "StringEquals" && a.Message == want
		}) {
			t.Errorf("no duplicate-block anomaly on %s: %v", claim, g.Anomalies)
		}
	}
}

// Case 5: ForAllValues passes on an absent key, so it restricts nothing on
// its own. The claim is Unknown, declared by a caveat and an anomaly whose
// sentence says what the condition does not do.
func TestForAllValuesIsVacuousOnAbsentKey(t *testing.T) {
	g := oneGrant(t, string(readPolicy(t, "05-forallvalues-vacuous")))
	want := `{aud="sts.amazonaws.com", repository_id="456789", sub=?("ForAllValues:StringLike")}`
	if g.Admits.String() != want || g.Exact() {
		t.Fatalf("Admits = %s, exact %v; want %s inexact", g.Admits, g.Exact(), want)
	}
	if !g.Admits.Admits(token{"aud": "sts.amazonaws.com", "repository_id": "456789"}) {
		t.Errorf("a token without sub is admitted: the condition passes when the claim is absent")
	}
	if g.Admits.Admits(token{"aud": "sts.amazonaws.com", "sub": mainBranch}) {
		t.Errorf("repository_id is still required")
	}
	a, ok := findAnomaly(g, trust.Unmodelled, "ForAllValues:StringLike")
	if !ok || a.Claim != "sub" || a.Source != "statement[0].Condition" {
		t.Fatalf("anomaly = %+v, %v", a, ok)
	}
	if a.Message != "ForAllValues:StringLike on sub passes when the claim is absent, so it does not restrict what it looks like it restricts" {
		t.Errorf("message = %q", a.Message)
	}
	c := g.Admits.Caveats()
	if len(c) != 1 || c[0].Claim != "sub" || c[0].Source != "statement[0].Condition" || c[0].Reason != a.Message {
		t.Errorf("caveats = %v; want one on sub carrying the same sentence", c)
	}
}

// Case 6: IfExists is the same trap with a suffix. The suffix is parsed off
// the operator, so every operator with it is caught, and Null with it is
// not an operator AWS documents.
func TestIfExistsIsVacuousOnAbsentKey(t *testing.T) {
	g := oneGrant(t, string(readPolicy(t, "06-ifexists-vacuous")))
	if want := `{aud="sts.amazonaws.com", sub=?("StringEqualsIfExists")}`; g.Admits.String() != want || g.Exact() {
		t.Fatalf("Admits = %s, exact %v; want %s inexact", g.Admits, g.Exact(), want)
	}
	if !g.Admits.Admits(token{"aud": "sts.amazonaws.com"}) {
		t.Errorf("a token without sub is admitted")
	}
	a, ok := findAnomaly(g, trust.Unmodelled, "StringEqualsIfExists")
	if !ok || a.Claim != "sub" || a.Message != "StringEqualsIfExists on sub passes when the claim is absent, so it does not restrict what it looks like it restricts" {
		t.Errorf("anomaly = %+v, %v", a, ok)
	}
	for _, op := range []string{"StringLikeIfExists", "ArnLikeIfExists", "StringNotEqualsIfExists", "ForAllValues:StringEqualsIfExists"} {
		g := oneGrant(t, github(`{"`+op+`": {"`+gh("sub")+`": "`+mainBranch+`"}}`))
		a, ok := findAnomaly(g, trust.Unmodelled, op)
		if !g.Admits.IsTop() || g.Exact() || !hasCaveatOn(g, "sub") || !ok || !strings.Contains(a.Message, "passes when the claim is absent") {
			t.Errorf("%s: admits %s, anomaly %+v %v", op, g.Admits, a, ok)
		}
	}
	g = oneGrant(t, github(`{"NullIfExists": {"`+gh("sub")+`": "true"}}`))
	if a, ok := findAnomaly(g, trust.Unmodelled, "NullIfExists"); !ok || a.Message != `operator "NullIfExists" on sub is not modelled by this parser, so the claim is not constrained` {
		t.Errorf("NullIfExists is not an operator AWS documents; anomaly = %+v, %v", a, ok)
	}
}

// Case 7: Null reads backwards. "true" means the key must be absent,
// "false" that it must be present, and the value may be a JSON boolean.
// Neither polarity is expressible here, so both are Unknown, each with a
// sentence that says which way it reads.
func TestNullPolarity(t *testing.T) {
	gs := policyGrants(t, "07-null-polarity")
	if len(gs) != 3 {
		t.Fatalf("%d grants, want 3", len(gs))
	}
	messages := map[string]string{
		"NullTrueMeansAbsent":   `Null on sub is "true": the claim must be absent, which this parser cannot express, so the claim is not constrained`,
		"NullFalseMeansPresent": `Null on sub is "false": the claim must be present, which this parser cannot express, so the claim is not constrained`,
		"NullBooleanTyped":      `Null on sub is "true": the claim must be absent, which this parser cannot express, so the claim is not constrained`,
	}
	for sid, want := range messages {
		g := bySid(gs, sid)
		if len(g) != 1 {
			t.Fatalf("%s: %d grants", sid, len(g))
		}
		if got := g[0].Admits.String(); got != `{aud="sts.amazonaws.com", sub=?("Null")}` || g[0].Exact() || !hasCaveatOn(g[0], "sub") {
			t.Errorf("%s: Admits = %s, exact %v, caveats %v", sid, got, g[0].Exact(), g[0].Admits.Caveats())
		}
		if a, ok := findAnomaly(g[0], trust.Unmodelled, "Null"); !ok || a.Claim != "sub" || a.Message != want {
			t.Errorf("%s: anomaly = %+v, %v; want %q", sid, a, ok, want)
		}
	}
	g := oneGrant(t, github(`{"Null": {"`+gh("sub")+`": false}}`))
	if a, ok := findAnomaly(g, trust.Unmodelled, "Null"); !ok || a.Message != messages["NullFalseMeansPresent"] {
		t.Errorf("boolean false: anomaly = %+v, %v", a, ok)
	}
	g = oneGrant(t, github(`{"Null": {"`+gh("sub")+`": "maybe"}}`))
	if a, ok := findAnomaly(g, trust.Unmodelled, "Null"); !ok || a.Message != `Null on sub has the value "maybe", which is neither "true" nor "false", so the claim is not constrained` {
		t.Errorf("undocumented polarity: anomaly = %+v, %v", a, ok)
	}
	if !g.Admits.IsTop() || g.Exact() {
		t.Errorf("undocumented polarity is still Unknown: %s", g.Admits)
	}
}

// Case 8: StringLike wildcards cross every delimiter and are kept intact;
// StringEquals has no wildcard semantics at all.
func TestStringLikeWildcardsAreNotDelimiterAware(t *testing.T) {
	g := oneGrant(t, string(readPolicy(t, "08-stringlike-wildcards")))
	if want := `{aud="*", sub=like:"repo:acme*/infra*:*"}`; g.Admits.String() != want || !g.Exact() {
		t.Fatalf("Admits = %s, exact %v; want %s exact", g.Admits, g.Exact(), want)
	}
	// An organisation an outsider can register, admitted across the "/".
	if !g.Admits.Admits(token{"aud": "*", "sub": "repo:acme-evil/infrastructure:ref:refs/heads/main"}) {
		t.Errorf("the star must cross the delimiter: that is the whole finding")
	}
	if !g.Admits.Admits(token{"aud": "*", "sub": "repo:acme/infra:environment:production"}) {
		t.Errorf("the intended subject is admitted too")
	}
	// The audience is the literal string "*", not any audience.
	if g.Admits.Admits(token{"aud": "sts.amazonaws.com", "sub": mainBranch}) {
		t.Errorf(`StringEquals "*" is a literal asterisk, not a wildcard`)
	}
	q := oneGrant(t, github(`{"StringEquals": {"`+gh("sub")+`": "repo:acme/?"}}`))
	if !q.Admits.Admits(token{"sub": "repo:acme/?"}) || q.Admits.Admits(token{"sub": "repo:acme/x"}) {
		t.Errorf(`StringEquals "?" is a literal question mark: %s`, q.Admits)
	}
}

// Case 9: an operator this parser does not model is Unknown on its key,
// with an anomaly naming the operator. Never skipped.
func TestUnrecognisedOperatorIsUnknown(t *testing.T) {
	g := oneGrant(t, string(readPolicy(t, "09-unrecognised-operator")))
	want := `{actor=?("StringFuzzyMatch"), aud="sts.amazonaws.com", iat=?("DateGreaterThan"), jti=?("BinaryEquals"), repository_visibility=?("Bool"), run_attempt=?("NumericLessThan"), runner_ip=?("IpAddress"), sub=?("ArnLike")}`
	if g.Admits.String() != want || g.Exact() {
		t.Fatalf("Admits = %s, exact %v; want %s inexact", g.Admits, g.Exact(), want)
	}
	operators := map[trust.ClaimKey]string{
		"sub": "ArnLike", "repository_visibility": "Bool", "run_attempt": "NumericLessThan",
		"iat": "DateGreaterThan", "runner_ip": "IpAddress", "jti": "BinaryEquals", "actor": "StringFuzzyMatch",
	}
	for claim, op := range operators {
		if !hasCaveatOn(g, claim) {
			t.Errorf("%s is Unknown without a caveat", claim)
		}
		// An operator AWS documents is spelled as AWS spells it; the one
		// AWS has not invented is quoted, so an empty or lookalike name
		// would be visible.
		name := op
		if op == "StringFuzzyMatch" {
			name = `"StringFuzzyMatch"`
		}
		a, ok := findAnomaly(g, trust.Unmodelled, op)
		if !ok || a.Claim != claim || a.Message != "operator "+name+" on "+string(claim)+" is not modelled by this parser, so the claim is not constrained" {
			t.Errorf("%s: anomaly = %+v, %v", op, a, ok)
		}
	}
	if !g.Admits.Admits(token{"aud": "sts.amazonaws.com"}) || g.Admits.Admits(token{"sub": mainBranch}) {
		t.Errorf("aud is the one constraint that holds: %s", g.Admits)
	}
}

// Case 10: a policy variable is resolved per request and is never a
// literal; the predefined escapes are literals; and under the 2008 language
// version, or with no Version at all, "${" is ordinary text.
func TestPolicyVariablesAreNotLiterals(t *testing.T) {
	gs := policyGrants(t, "10-policy-variable")
	if len(gs) != 3 {
		t.Fatalf("%d grants, want 3", len(gs))
	}
	variable := bySid(gs, "VariableIsNotALiteral")[0]
	if want := `{aud="sts.amazonaws.com", sub=?("${aws:PrincipalTag/team}")}`; variable.Admits.String() != want || variable.Exact() || !hasCaveatOn(variable, "sub") {
		t.Errorf("Admits = %s, exact %v", variable.Admits, variable.Exact())
	}
	a, ok := findAnomaly(variable, trust.Unmodelled, "${aws:PrincipalTag/team}")
	if !ok || a.Claim != "sub" || a.Message != `the value "${aws:PrincipalTag/team}" on sub holds the policy variable ${aws:PrincipalTag/team}, which is resolved per request, so the claim is not constrained` {
		t.Errorf("anomaly = %+v, %v", a, ok)
	}
	star := bySid(gs, "EscapedStarIsALiteralStarUnderStringEquals")[0]
	if want := `{aud="sts.amazonaws.com", sub="repo:acme/*:ref:refs/heads/main"}`; star.Admits.String() != want || !star.Exact() {
		t.Errorf("Admits = %s, exact %v; want %s exact", star.Admits, star.Exact(), want)
	}
	if !star.Admits.Admits(token{"aud": "sts.amazonaws.com", "sub": "repo:acme/*:ref:refs/heads/main"}) || star.Admits.Admits(token{"aud": "sts.amazonaws.com", "sub": mainBranch}) {
		t.Errorf("${*} under StringEquals is one literal asterisk: %s", star.Admits)
	}
	like := bySid(gs, "EscapedStarUnderStringLikeCannotBeExpressed")[0]
	if want := `{aud="sts.amazonaws.com", sub=?("${*}")}`; like.Admits.String() != want || like.Exact() {
		t.Errorf("Admits = %s, exact %v; want %s inexact", like.Admits, like.Exact(), want)
	}
	if a, ok := findAnomaly(like, trust.Unmodelled, "${*}"); !ok || a.Message != `the value "repo:acme/${*}:*" on sub holds the escaped wildcard ${*} under StringLike, which this parser cannot express, so the claim is not constrained` {
		t.Errorf("anomaly = %+v, %v", a, ok)
	}

	escapes := oneGrant(t, github(`{"StringEquals": {"`+gh("sub")+`": "a${?}b${$}c"}}`))
	if escapes.Admits.String() != `{sub="a?b$c"}` || !escapes.Exact() {
		t.Errorf("${?} and ${$} are literals under StringEquals: %s", escapes.Admits)
	}
	dangling := oneGrant(t, github(`{"StringEquals": {"`+gh("sub")+`": "a${b"}}`))
	if a, ok := findAnomaly(dangling, trust.Unmodelled, "${"); !ok || a.Message != `the value "a${b" on sub holds an unterminated "${", which this parser cannot read, so the claim is not constrained` || dangling.Exact() {
		t.Errorf("unterminated variable: anomaly = %+v, %v", a, ok)
	}

	// Under 2008-10-17, or with no Version element, "${" is literal text,
	// and the grant says so: a customer who wrote a variable and got a
	// literal has a condition that does not do what it looks like it does.
	for _, version := range []string{`"Version": "2008-10-17", `, ``} {
		g := oneGrant(t, `{`+version+`"Statement": [{"Effect": "Allow", "Principal": {"Federated": "`+githubProvider+`"}, "Action": "sts:AssumeRoleWithWebIdentity", "Condition": {"StringEquals": {"`+gh("sub")+`": "${aws:username}"}}}]}`)
		if g.Admits.String() != `{sub="${aws:username}"}` || !g.Exact() {
			t.Errorf("version %q: Admits = %s, exact %v; want the literal text", version, g.Admits, g.Exact())
		}
		a, ok := findAnomaly(g, VariableIsLiteral, "${aws:username}")
		if !ok || a.Claim != "sub" || a.Source != "statement[0].Condition" || a.Message != `the value "${aws:username}" on sub holds "${aws:username}", which is literal text because this document's Version does not resolve policy variables; if a variable was meant, the condition does not do what it looks like it does` {
			t.Errorf("version %q: anomaly = %+v, %v", version, a, ok)
		}
	}
	literal := oneGrant(t, string(readPolicy(t, "21-variable-read-as-text")))
	if want := `{aud="sts.amazonaws.com", sub="${aws:username}"}`; literal.Admits.String() != want || !literal.Exact() {
		t.Errorf("case 21: Admits = %s, exact %v; want %s exact", literal.Admits, literal.Exact(), want)
	}
	if a, ok := findAnomaly(literal, VariableIsLiteral, "${aws:username}"); !ok || a.Claim != "sub" || len(literal.Anomalies) != 1 {
		t.Errorf("case 21: anomalies = %v, %v; want the one note", literal.Anomalies, ok)
	}
	// Every "${" in one value is one sentence, whatever follows it.
	if g := oneGrant(t, `{"Statement": [{"Effect": "Allow", "Principal": {"Federated": "`+githubProvider+`"}, "Action": "sts:AssumeRoleWithWebIdentity", "Condition": {"StringEquals": {"`+gh("sub")+`": ["a${b", "${x}${y}"]}}}]}`); len(g.Anomalies) != 2 {
		t.Errorf("literal variables: anomalies %v; want one per value holding ${", g.Anomalies)
	}
	// With a Version this parser cannot read, whether "${" is a variable is
	// not known, and the value is Unknown either way.
	for _, version := range []string{`"Version": "2020-01-01", `, `"Version": 1, `, `"Version": "2012-10-17", "Version": "2008-10-17", `} {
		g := oneGrant(t, `{`+version+`"Statement": [{"Effect": "Allow", "Principal": {"Federated": "`+githubProvider+`"}, "Action": "sts:AssumeRoleWithWebIdentity", "Condition": {"StringEquals": {"`+gh("sub")+`": "x${*}"}}}]}`)
		a, ok := findAnomaly(g, trust.Unmodelled, "${")
		if g.Exact() || !ok || a.Message != `the value "x${*}" on sub holds "${", and whether this document's Version reads it as a policy variable is not known, so the claim is not constrained` {
			t.Errorf("version %q: Admits = %s, anomaly %+v %v", version, g.Admits, a, ok)
		}
	}
}

// Two operators on one key are ANDed; several values under one key are
// ORed; several keys are one Term. That is AWS's own evaluation logic.
func TestOperatorsMeetAndValuesJoin(t *testing.T) {
	g := oneGrant(t, github(`{"StringEquals": {"`+gh("sub")+`": "`+mainBranch+`"}, "StringLike": {"`+gh("sub")+`": "repo:acme/*"}}`))
	if g.Admits.String() != `{sub="`+mainBranch+`"}` || !g.Exact() {
		t.Errorf("Exact ∧ Glob containing it = %s", g.Admits)
	}
	g = oneGrant(t, github(`{"StringEquals": {"`+gh("sub")+`": "`+mainBranch+`"}, "StringLike": {"`+gh("sub")+`": "repo:other/*"}}`))
	if !g.Admits.IsEmpty() || !g.Exact() {
		t.Errorf("Exact ∧ Glob not containing it admits nothing, exactly: %s exact %v", g.Admits, g.Exact())
	}
	g = oneGrant(t, github(`{"StringEquals": {"`+gh("aud")+`": "sts.amazonaws.com"}, "StringLike": {"`+gh("sub")+`": "repo:acme/*"}}`))
	if g.Admits.String() != `{aud="sts.amazonaws.com", sub=like:"repo:acme/*"}` {
		t.Errorf("keys across operator blocks are one Term: %s", g.Admits)
	}
	g = oneGrant(t, github(`{"StringEquals": {"`+gh("sub")+`": ["`+mainBranch+`", "`+devBranch+`"]}}`))
	if g.Admits.String() != `{sub=("`+devBranch+`" | "`+mainBranch+`")}` || !g.Exact() {
		t.Errorf("a value list is a union: %s", g.Admits)
	}
	g = oneGrant(t, github(`{"StringLike": {"`+gh("sub")+`": ["repo:acme/*", "repo:other/*"]}}`))
	if g.Admits.String() != `{sub=(like:"repo:acme/*" | like:"repo:other/*")}` {
		t.Errorf("a pattern list is a union of globs: %s", g.Admits)
	}
	one := oneGrant(t, github(`{"StringEquals": {"`+gh("sub")+`": ["`+mainBranch+`"]}}`))
	bare := oneGrant(t, github(`{"StringEquals": {"`+gh("sub")+`": "`+mainBranch+`"}}`))
	if one.Admits.String() != bare.Admits.String() {
		t.Errorf("a one-element list is the bare value: %s vs %s", one.Admits, bare.Admits)
	}
	if g := oneGrant(t, github(`{}`)); !g.Admits.IsTop() || !g.Exact() {
		t.Errorf("no condition is everything, exactly: %s", g.Admits)
	}
	if g := oneGrant(t, github(`{"StringEquals": {}}`)); !g.Admits.IsTop() || g.Exact() {
		t.Errorf("an operator block with no keys is outside the grammar: everything, as an upper bound; got %s exact %v", g.Admits, g.Exact())
	}
}

// TestEmptyValueListIsUnknown: AWS documents no meaning for an empty value
// list, so asserting emptiness would be a guess in the one direction that
// is never allowed.
func TestEmptyValueListIsUnknown(t *testing.T) {
	for _, op := range []string{"StringEquals", "StringLike"} {
		g := oneGrant(t, github(`{"`+op+`": {"`+gh("sub")+`": []}}`))
		if g.Admits.IsEmpty() || !g.Admits.IsTop() || g.Exact() || !hasCaveatOn(g, "sub") {
			t.Errorf("%s with []: Admits = %s, exact %v; want Unknown, declared", op, g.Admits, g.Exact())
		}
		if a, ok := findAnomaly(g, trust.Unmodelled, op); !ok || a.Message != op+" on sub lists no values; AWS documents no meaning for an empty list, so the claim is not constrained" {
			t.Errorf("%s with []: anomaly = %+v, %v", op, a, ok)
		}
	}
}

// TestForAnyValueIsUnknown: a set operator compares a multivalued request
// key, which a single-valued Term cannot hold. Unknown until set-valued
// claims exist, never the base operator.
func TestForAnyValueIsUnknown(t *testing.T) {
	for _, op := range []string{"ForAnyValue:StringEquals", "ForAnyValue:StringLike"} {
		g := oneGrant(t, github(`{"`+op+`": {"`+gh("amr")+`": "authenticated"}}`))
		if !g.Admits.IsTop() || g.Exact() || !hasCaveatOn(g, "amr") {
			t.Errorf("%s: Admits = %s, exact %v, caveats %v", op, g.Admits, g.Exact(), g.Admits.Caveats())
		}
		if a, ok := findAnomaly(g, trust.Unmodelled, op); !ok || a.Claim != "amr" || a.Message != op+" on amr compares a set of request values, which this parser does not model, so the claim is not constrained" {
			t.Errorf("%s: anomaly = %+v, %v", op, a, ok)
		}
	}
	if g := oneGrant(t, github(`{"ForAnyValue:StringEquals": {"`+gh("amr")+`": []}}`)); g.Admits.IsEmpty() || g.Exact() {
		t.Errorf("ForAnyValue with no values is not proven empty: %s", g.Admits)
	}
}

func TestNegatedAndIgnoreCaseOperatorsAreUnknown(t *testing.T) {
	messages := map[string]string{
		"StringNotEquals":           "StringNotEquals on sub admits every value but the ones listed and passes when the claim is absent; this parser does not model complements, so the claim is not constrained",
		"StringNotLike":             "StringNotLike on sub admits every value but the ones listed and passes when the claim is absent; this parser does not model complements, so the claim is not constrained",
		"StringNotEqualsIgnoreCase": "StringNotEqualsIgnoreCase on sub admits every value but the ones listed and passes when the claim is absent; this parser does not model complements, so the claim is not constrained",
		"StringEqualsIgnoreCase":    "StringEqualsIgnoreCase on sub matches the value in any casing, which this parser cannot express, so the claim is not constrained",
	}
	for op, want := range messages {
		g := oneGrant(t, github(`{"StringEquals": {"`+gh("aud")+`": "sts.amazonaws.com"}, "`+op+`": {"`+gh("sub")+`": "`+mainBranch+`"}}`))
		if g.Admits.String() != `{aud="sts.amazonaws.com", sub=?("`+op+`")}` || g.Exact() || !hasCaveatOn(g, "sub") {
			t.Errorf("%s: Admits = %s, exact %v", op, g.Admits, g.Exact())
		}
		if a, ok := findAnomaly(g, trust.Unmodelled, op); !ok || a.Claim != "sub" || a.Message != want {
			t.Errorf("%s: anomaly = %+v, %v", op, a, ok)
		}
	}
}

// TestMisShapedLeavesAreUnknown: a value that is not a string or a list of
// strings, at any depth of the condition block, is Unknown with a sentence
// naming the JSON type met and quoting the source.
func TestMisShapedLeavesAreUnknown(t *testing.T) {
	claimLevel := []struct {
		value string
		want  string
	}{
		{`123`, "StringEquals on sub has a value that is a number (123) where a string or a list of strings is expected, so the claim is not constrained"},
		{`null`, "StringEquals on sub has a value that is null (null) where a string or a list of strings is expected, so the claim is not constrained"},
		{`{"x": 1}`, `StringEquals on sub has a value that is an object ({"x": 1}) where a string or a list of strings is expected, so the claim is not constrained`},
		{`true`, "StringEquals on sub has a value that is a boolean (true) where a string or a list of strings is expected, so the claim is not constrained"},
		{`["a", 1]`, "StringEquals on sub lists a number (1) where a string is expected, so the claim is not constrained"},
		{`[["a"]]`, `StringEquals on sub lists a list (["a"]) where a string is expected, so the claim is not constrained`},
	}
	for _, c := range claimLevel {
		g := oneGrant(t, github(`{"StringEquals": {"`+gh("aud")+`": "sts.amazonaws.com", "`+gh("sub")+`": `+c.value+`}}`))
		if g.Admits.String() != `{aud="sts.amazonaws.com", sub=?("StringEquals")}` || g.Exact() || !hasCaveatOn(g, "sub") {
			t.Errorf("%s: Admits = %s, exact %v", c.value, g.Admits, g.Exact())
		}
		if a, ok := findAnomaly(g, Malformed, "StringEquals"); !ok || a.Claim != "sub" || a.Message != c.want {
			t.Errorf("%s: anomaly = %+v, %v", c.value, a, ok)
		}
	}
	statementLevel := []struct {
		condition string
		want      string
	}{
		{`"x"`, `Condition is a string ("x"), not an object, so what it requires is not known`},
		{`[]`, `Condition is a list ([]), not an object, so what it requires is not known`},
		{`{"StringEquals": "x"}`, `the operator block StringEquals is a string ("x"), not an object, so what it requires is not known`},
		{`{"StringEquals": ["a"]}`, `the operator block StringEquals is a list (["a"]), not an object, so what it requires is not known`},
	}
	for _, c := range statementLevel {
		g := oneGrant(t, github(c.condition))
		if !g.Admits.IsTop() || g.Exact() || !hasCaveatOn(g, "") {
			t.Errorf("%s: Admits = %s, exact %v, caveats %v; want everything with a whole-grant caveat", c.condition, g.Admits, g.Exact(), g.Admits.Caveats())
		}
		if !slices.ContainsFunc(g.Anomalies, func(a trust.Anomaly) bool {
			return a.Kind == Malformed && a.Message == c.want && a.Source == "statement[0].Condition"
		}) {
			t.Errorf("%s: anomalies %v lack %q", c.condition, g.Anomalies, c.want)
		}
	}
	// A long value is quoted truncated, so a sentence stays a sentence.
	long := oneGrant(t, github(`{"StringEquals": {"`+gh("sub")+`": {"padding": "`+strings.Repeat("x", 200)+`"}}}`))
	if a, ok := findAnomaly(long, Malformed, "StringEquals"); !ok || len(a.Message) > 200 || !strings.Contains(a.Message, "...)") {
		t.Errorf("long value: anomaly = %+v, %v", a, ok)
	}
}

// TestRequestContextKeysAreUnknown: aws: and sts: keys describe the request,
// not the token. A token carries no such claim, so a real constraint on one
// would reject every token; Unknown with an anomaly is the sound reading.
func TestRequestContextKeysAreUnknown(t *testing.T) {
	g := oneGrant(t, github(`{"IpAddress": {"aws:SourceIp": "203.0.113.0/24"}, "StringEquals": {"sts:ExternalId": "x", "`+gh("aud")+`": "sts.amazonaws.com"}}`))
	if want := `{aud="sts.amazonaws.com", aws:sourceip=?("IpAddress", "aws:sourceip"), sts:externalid=?("sts:externalid")}`; g.Admits.String() != want || g.Exact() {
		t.Fatalf("Admits = %s, exact %v; want %s inexact", g.Admits, g.Exact(), want)
	}
	for key, claim := range map[string]trust.ClaimKey{"aws:SourceIp": "aws:sourceip", "sts:ExternalId": "sts:externalid"} {
		if !hasCaveatOn(g, claim) {
			t.Errorf("%s is Unknown without a caveat", claim)
		}
		a, ok := findAnomaly(g, trust.Unmodelled, key)
		if !ok || a.Claim != claim || a.Message != `the condition key "`+key+`" is a fact about the request, not a claim of the token, so this parser does not evaluate it and the claim is not constrained` {
			t.Errorf("%s: anomaly = %+v, %v", key, a, ok)
		}
	}
	if !g.Admits.Admits(token{"aud": "sts.amazonaws.com"}) {
		t.Errorf("a token without request-context claims is admitted")
	}
}

// TestForeignProviderKeysStayVerbatim: a statement with two federated
// providers projects one grant each, and each grant keeps the other
// provider's keys as written. The token of one provider never carries the
// other's keys, so those terms admit nothing through it, which is what AWS
// does with a positive operator on an absent key.
func TestForeignProviderKeysStayVerbatim(t *testing.T) {
	const gitlab = "arn:aws:iam::123456789012:oidc-provider/gitlab.com"
	raw := statement(`"Effect": "Allow",
		"Principal": {"Federated": ["` + githubProvider + `", "` + gitlab + `"]},
		"Action": "sts:AssumeRoleWithWebIdentity",
		"Condition": {
			"StringEquals": {"` + gh("aud") + `": "sts.amazonaws.com", "gitlab.com:aud": "https://gitlab.com"},
			"StringLike": {"` + gh("sub") + `": "repo:acme/*", "gitlab.com:sub": "project_path:acme/*"}
		}`)
	gs := mustParse(t, raw).Grants(role, LowercaseVocabulary(githubIssuer, "https://gitlab.com"))
	if len(gs) != 2 {
		t.Fatalf("%d grants, want one per provider", len(gs))
	}
	var githubGrant, gitlabGrant trust.Grant
	for _, g := range gs {
		switch g.Issuer {
		case githubIssuer:
			githubGrant = g
		case "https://gitlab.com":
			gitlabGrant = g
		default:
			t.Fatalf("unexpected issuer %q", g.Issuer)
		}
	}
	wantGitHub := `{aud="sts.amazonaws.com", gitlab.com:aud="https://gitlab.com", gitlab.com:sub=like:"project_path:acme/*", sub=like:"repo:acme/*"}`
	if githubGrant.Admits.String() != wantGitHub || !githubGrant.Exact() {
		t.Errorf("GitHub grant = %s, exact %v; want %s", githubGrant.Admits, githubGrant.Exact(), wantGitHub)
	}
	wantGitLab := `{aud="https://gitlab.com", sub=like:"project_path:acme/*", token.actions.githubusercontent.com:aud="sts.amazonaws.com", token.actions.githubusercontent.com:sub=like:"repo:acme/*"}`
	if gitlabGrant.Admits.String() != wantGitLab || !gitlabGrant.Exact() {
		t.Errorf("GitLab grant = %s, exact %v; want %s", gitlabGrant.Admits, gitlabGrant.Exact(), wantGitLab)
	}
	if githubGrant.Admits.Admits(token{"aud": "sts.amazonaws.com", "sub": "repo:acme/infra"}) {
		t.Errorf("a GitHub token lacks the GitLab keys, so this statement admits none")
	}
	if githubGrant.Admits.IsEmpty() {
		t.Errorf("that is not proven emptiness; IsEmpty must stay false")
	}
	// Under a vacuous operator a foreign key widens like any other.
	g := oneGrant(t, github(`{"ForAllValues:StringLike": {"gitlab.com:sub": "project_path:acme/*"}}`))
	if !g.Admits.IsTop() || g.Exact() || !hasCaveatOn(g, "gitlab.com:sub") {
		t.Errorf("foreign key under ForAllValues: %s, caveats %v", g.Admits, g.Admits.Caveats())
	}
}

// TestIssuerIdentifiersWithPathsAndPorts: the identifier after
// oidc-provider/ is a host, possibly with a path or a port, and a
// condition key belongs to this principal exactly when it starts with that
// identifier and a colon, compared without regard to ASCII case.
func TestIssuerIdentifiersWithPathsAndPorts(t *testing.T) {
	const circle = "https://oidc.circleci.com/org/2C3F7A0E"
	g := mustParse(t, statement(`"Effect": "Allow",
		"Principal": {"Federated": "arn:aws:iam::123456789012:oidc-provider/oidc.circleci.com/org/2C3F7A0E"},
		"Action": "sts:AssumeRoleWithWebIdentity",
		"Condition": {"StringEquals": {
			"oidc.circleci.com/org/2c3f7a0e:sub": "x",
			"OIDC.CircleCI.com/org/2C3F7A0E:aud": "y",
			"oidc.circleci.com/org/ffffffff:sub": "z"
		}}`)).Grants(role, LowercaseVocabulary(circle))
	if len(g) != 1 || g[0].Issuer != circle {
		t.Fatalf("grants = %+v; want the issuer with its path, case kept", g)
	}
	if want := `{aud="y", oidc.circleci.com/org/ffffffff:sub="z", sub="x"}`; g[0].Admits.String() != want || !g[0].Exact() {
		t.Errorf("Admits = %s, want %s: this org's keys are its claims, the other org's key stays foreign", g[0].Admits, want)
	}
	port := mustParse(t, statement(`"Effect": "Allow",
		"Principal": {"Federated": "arn:aws:iam::123456789012:oidc-provider/gitlab.example.com:8443"},
		"Action": "sts:AssumeRoleWithWebIdentity",
		"Condition": {"StringEquals": {"gitlab.example.com:8443:sub": "x"}}`)).Grants(role, LowercaseVocabulary("https://gitlab.example.com:8443"))
	if len(port) != 1 || port[0].Issuer != "https://gitlab.example.com:8443" || port[0].Admits.String() != `{sub="x"}` {
		t.Errorf("port: grants = %+v", port)
	}
	for _, partition := range []string{"aws", "aws-cn", "aws-us-gov"} {
		g := oneGrant(t, statement(`"Effect": "Allow", "Principal": {"Federated": "arn:`+partition+`:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"}, "Action": "sts:AssumeRoleWithWebIdentity"`))
		if g.Issuer != githubIssuer {
			t.Errorf("partition %s: issuer %q", partition, g.Issuer)
		}
	}
	// Not an ARN at all: a bare provider name, whatever it looks like.
	spoof := oneGrant(t, statement(`"Effect": "Allow", "Principal": {"Federated": "https://evil.example/oidc-provider/token.actions.githubusercontent.com"}, "Action": "sts:AssumeRoleWithWebIdentity"`))
	if spoof.Issuer != "https://evil.example/oidc-provider/token.actions.githubusercontent.com" {
		t.Errorf("a URL that is not an ARN names the host it names: %q", spoof.Issuer)
	}
}

// TestProviderNameIsTheKeyPrefixAsWritten: AWS forms a provider's condition
// keys from the provider's name as registered, and a provider created from
// an issuer URL that ends in a slash keeps the slash. The registry key
// drops it, so the prefix a key is matched against is the name as written
// in the principal, not the issuer.
func TestProviderNameIsTheKeyPrefixAsWritten(t *testing.T) {
	const auth0 = trust.IssuerRef("https://acme.eu.auth0.com")
	raw := string(readPolicy(t, "24-provider-name-with-a-trailing-slash"))
	gs := mustParse(t, raw).Grants(role, LowercaseVocabulary(githubIssuer, auth0))
	if len(gs) != 2 {
		t.Fatalf("%d grants, want 2", len(gs))
	}
	slash := bySid(gs, "ProviderRegisteredWithATrailingSlash")
	if len(slash) != 1 || slash[0].Issuer != auth0 || slash[0].Admits.String() != `{aud="AbCdEf0123456789"}` || !slash[0].Exact() {
		t.Errorf("provider registered with a trailing slash: %+v; want its aud as the claim, exactly, on the registry issuer", slash)
	}
	if len(slash) == 1 && !slash[0].Admits.Admits(token{"aud": "AbCdEf0123456789"}) {
		t.Errorf("the token AWS admits is admitted")
	}
	without := bySid(gs, "KeyWithoutTheSlashNamesAnotherProvider")
	if len(without) != 1 || without[0].Issuer != auth0 || without[0].Admits.String() != `{acme.eu.auth0.com:aud="AbCdEf0123456789"}` || !without[0].Exact() {
		t.Errorf("key without the slash: %+v; want the key kept as another provider's", without)
	}
	// Without the vocabulary the claim is Unknown and the anomaly names the
	// key with its slash.
	unknown := bySid(mustParse(t, raw).Grants(role, vocabulary), "ProviderRegisteredWithATrailingSlash")
	if len(unknown) != 1 || !unknown[0].Admits.IsTop() || unknown[0].Exact() || !hasCaveatOn(unknown[0], "aud") {
		t.Errorf("without the vocabulary: %+v", unknown)
	}
	if a, ok := findAnomaly(unknown[0], trust.Unmodelled, "acme.eu.auth0.com/:aud"); !ok || a.Claim != "aud" {
		t.Errorf("without the vocabulary: anomaly = %+v, %v", a, ok)
	}
	// A path with a trailing slash, and a bare provider name with one.
	for _, c := range []struct{ identifier, issuer string }{
		{"login.example.com/tenant/", "https://login.example.com/tenant"},
		{"login.example.com/", "https://login.example.com"},
	} {
		for _, principal := range []string{"arn:aws:iam::123456789012:oidc-provider/" + c.identifier, c.identifier} {
			g := mustParse(t, statement(`"Effect": "Allow", "Principal": {"Federated": "`+principal+`"}, "Action": "sts:AssumeRoleWithWebIdentity", "Condition": {"StringEquals": {"`+c.identifier+`:sub": "alice"}}`)).Grants(role, LowercaseVocabulary(trust.IssuerRef(c.issuer)))
			if len(g) != 1 || g[0].Issuer != trust.IssuerRef(c.issuer) || g[0].Admits.String() != `{sub="alice"}` || !g[0].Exact() {
				t.Errorf("%s: grants = %+v; want {sub=\"alice\"} on %s", principal, g, c.issuer)
			}
		}
	}
}

// TestUnknownVocabularyIsUnknown: AWS matches keys case-insensitively and
// the token's claim names belong to the issuer. Without the issuer's
// vocabulary the policy's spelling cannot be reconciled with the token's,
// and a guessed spelling could name a claim no token carries, which would
// reject every token. So the claim is Unknown, and declared.
func TestUnknownVocabularyIsUnknown(t *testing.T) {
	raw := statement(`"Effect": "Allow", "Principal": {"Federated": "arn:aws:iam::123456789012:oidc-provider/gitlab.com"}, "Action": "sts:AssumeRoleWithWebIdentity", "Condition": {"StringEquals": {"gitlab.com:sub": "x"}}`)
	for name, v := range map[string]ClaimVocabulary{"github only": vocabulary, "nil": nil} {
		gs := mustParse(t, raw).Grants(role, v)
		if len(gs) != 1 || !gs[0].Admits.IsTop() || gs[0].Exact() || !hasCaveatOn(gs[0], "sub") {
			t.Errorf("%s: grants = %+v", name, gs)
			continue
		}
		a, ok := findAnomaly(gs[0], trust.Unmodelled, "gitlab.com:sub")
		if !ok || a.Claim != "sub" || a.Message != `the claim vocabulary of "https://gitlab.com" is not known to this parser, so the spelling "sub" of the condition key "gitlab.com:sub" cannot be reconciled with the token's and the claim is not constrained` {
			t.Errorf("%s: anomaly = %+v, %v", name, a, ok)
		}
	}
	known := mustParse(t, raw).Grants(role, LowercaseVocabulary(githubIssuer, "https://gitlab.com"))
	if len(known) != 1 || known[0].Admits.String() != `{sub="x"}` || !known[0].Exact() {
		t.Errorf("with the vocabulary: %+v", known)
	}
}

func TestLowercaseVocabulary(t *testing.T) {
	v := LowercaseVocabulary(githubIssuer)
	if key, ok := v(githubIssuer, "Repository_ID"); !ok || key != "repository_id" {
		t.Errorf("known issuer: (%q, %v)", key, ok)
	}
	if key, ok := v("https://gitlab.com", "sub"); ok || key != "" {
		t.Errorf("unknown issuer: (%q, %v)", key, ok)
	}
	if _, ok := LowercaseVocabulary()(githubIssuer, "sub"); ok {
		t.Errorf("an empty vocabulary knows nothing")
	}
}

// TestKeysThatNameNoClaim: a key with an empty claim part, a claim with
// whitespace, or no provider prefix at all is not a condition key this
// parser can read; Unknown, with the key quoted.
func TestKeysThatNameNoClaim(t *testing.T) {
	cases := []struct {
		key  string
		want string
	}{
		{gh(""), `the condition key "token.actions.githubusercontent.com:" names no claim, so the claim is not constrained`},
		{gh("my claim"), `the condition key "token.actions.githubusercontent.com:my claim" names no claim, so the claim is not constrained`},
		{"sub", `the condition key "sub" has no provider prefix, so which request value it names is not known and the claim is not constrained`},
	}
	for _, c := range cases {
		g := oneGrant(t, github(`{"StringEquals": {"`+c.key+`": "x"}}`))
		if !g.Admits.IsTop() || g.Exact() || !hasCaveatOn(g, trust.ClaimKey(strings.ToLower(c.key))) {
			t.Errorf("%q: Admits = %s, exact %v, caveats %v", c.key, g.Admits, g.Exact(), g.Admits.Caveats())
		}
		if a, ok := findAnomaly(g, Malformed, c.key); !ok || a.Message != c.want {
			t.Errorf("%q: anomaly = %+v, %v", c.key, a, ok)
		}
	}
}

// TestVacuityIsNamedWhateverTheKey: the sentence "this condition does not
// do what it looks like it does" is the finding, and it is owed whether or
// not the key could be read. A ForAllValues on a key the parser cannot
// place still passes when the claim is absent, and the anomaly says so
// beside whatever the key's own anomaly says.
func TestVacuityIsNamedWhateverTheKey(t *testing.T) {
	const gitlab = "arn:aws:iam::123456789012:oidc-provider/gitlab.com"
	cases := []struct {
		name     string
		raw      string
		operator string
		claim    trust.ClaimKey
		beside   string // the Construct of the key's own anomaly
	}{
		{"unknown vocabulary", statement(`"Effect": "Allow", "Principal": {"Federated": "` + gitlab + `"}, "Action": "sts:AssumeRoleWithWebIdentity", "Condition": {"ForAllValues:StringLike": {"gitlab.com:sub": "project_path:acme/*"}}`),
			"ForAllValues:StringLike", "sub", "gitlab.com:sub"},
		{"anonymous principal", statement(`"Effect": "Allow", "Principal": "*", "Action": "sts:AssumeRole", "Condition": {"ForAllValues:StringLike": {"` + gh("sub") + `": "repo:acme/*"}}`),
			"ForAllValues:StringLike", trust.ClaimKey(gh("sub")), gh("sub")},
		{"request context key", statement(`"Effect": "Allow", "Principal": {"AWS": "123456789012"}, "Action": "sts:AssumeRole", "Condition": {"ForAllValues:StringEquals": {"aws:TagKeys": "team"}}`),
			"ForAllValues:StringEquals", "aws:tagkeys", "aws:TagKeys"},
		{"service principal", statement(`"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole", "Condition": {"ForAllValues:StringEquals": {"aws:SourceAccount": "123456789012"}}`),
			"ForAllValues:StringEquals", "aws:sourceaccount", "aws:SourceAccount"},
		{"duplicate key", github(`{"ForAllValues:StringEquals": {"` + gh("sub") + `": "a", "` + gh("sub") + `": "b"}}`),
			"ForAllValues:StringEquals", "sub", "ForAllValues:StringEquals"},
		{"ifexists on a request key", github(`{"StringEqualsIfExists": {"aws:SourceIp": "203.0.113.7"}}`),
			"StringEqualsIfExists", "aws:sourceip", "aws:SourceIp"},
	}
	for _, c := range cases {
		gs := mustParse(t, c.raw).Grants(role, vocabulary)
		if len(gs) == 0 {
			t.Fatalf("%s: no grant", c.name)
		}
		// The face read first: for "*" the AWS one, whose issuer sorts last.
		g := gs[len(gs)-1]
		want := c.operator + " on " + string(c.claim) + " passes when the claim is absent, so it does not restrict what it looks like it restricts"
		if !slices.ContainsFunc(g.Anomalies, func(a trust.Anomaly) bool {
			return a.Kind == trust.Unmodelled && a.Claim == c.claim && a.Construct == c.operator && a.Message == want
		}) {
			t.Errorf("%s: anomalies %v lack the vacuity sentence %q", c.name, g.Anomalies, want)
		}
		if c.beside != c.operator && !slices.ContainsFunc(g.Anomalies, func(a trust.Anomaly) bool { return a.Construct == c.beside }) {
			t.Errorf("%s: the key's own anomaly on %q is gone: %v", c.name, c.beside, g.Anomalies)
		}
		if g.Exact() || !hasCaveatOn(g, c.claim) {
			t.Errorf("%s: exact %v, caveats %v; the claim is Unknown and declared", c.name, g.Exact(), g.Admits.Caveats())
		}
	}
}

// TestUnrecognisedOperatorIsNamedWhateverTheKey: an operator this parser
// does not model is named in an anomaly even when the key beside it has
// a story of its own, so a reporter can say both.
func TestUnrecognisedOperatorIsNamedWhateverTheKey(t *testing.T) {
	cases := []struct {
		name     string
		raw      string
		operator string
		claim    trust.ClaimKey
	}{
		{"request context key", github(`{"IpAddress": {"aws:SourceIp": "203.0.113.0/24"}, "StringEquals": {"` + gh("aud") + `": "sts.amazonaws.com"}}`), "IpAddress", "aws:sourceip"},
		{"unknown vocabulary", statement(`"Effect": "Allow", "Principal": {"Federated": "arn:aws:iam::123456789012:oidc-provider/gitlab.com"}, "Action": "sts:AssumeRoleWithWebIdentity", "Condition": {"ArnLike": {"gitlab.com:sub": "x"}}`), "ArnLike", "sub"},
		{"no prefix", github(`{"ArnLike": {"sub": "x"}}`), "ArnLike", "sub"},
		{"no claim", github(`{"ArnLike": {"` + gh("") + `": "x"}}`), "ArnLike", trust.ClaimKey(gh(""))},
	}
	for _, c := range cases {
		g := oneGrant(t, c.raw)
		want := "operator " + c.operator + " on " + string(c.claim) + " is not modelled by this parser, so the claim is not constrained"
		if a, ok := findAnomaly(g, trust.Unmodelled, c.operator); !ok || a.Claim != c.claim || a.Message != want {
			t.Errorf("%s: anomaly = %+v, %v; want %q", c.name, a, ok, want)
		}
		if g.Exact() || !hasCaveatOn(g, c.claim) {
			t.Errorf("%s: exact %v, caveats %v", c.name, g.Exact(), g.Admits.Caveats())
		}
	}
}

// TestForAnyValueWithNoValuesSaysSo: the brief calls ForAnyValue over an
// empty list "always false" without a citation, so the set is Unknown as
// under every other operator, and the sentence states the fact the brief
// cares about: the list is empty.
func TestForAnyValueWithNoValuesSaysSo(t *testing.T) {
	for _, op := range []string{"ForAnyValue:StringEquals", "ForAnyValue:StringLike"} {
		g := oneGrant(t, github(`{"StringEquals": {"`+gh("aud")+`": "sts.amazonaws.com"}, "`+op+`": {"`+gh("sub")+`": []}}`))
		if g.Admits.IsEmpty() || g.Exact() || !hasCaveatOn(g, "sub") {
			t.Errorf("%s with []: Admits = %s, exact %v; want Unknown, declared", op, g.Admits, g.Exact())
		}
		want := op + " on sub lists no values; AWS documents no meaning for an empty list, so the claim is not constrained"
		if !slices.ContainsFunc(g.Anomalies, func(a trust.Anomaly) bool {
			return a.Kind == trust.Unmodelled && a.Claim == "sub" && a.Construct == op && a.Message == want
		}) {
			t.Errorf("%s with []: anomalies %v lack %q", op, g.Anomalies, want)
		}
	}
}

// TestOperatorSpellingsThatAreNotOperators: the vacuity sentence asserts
// an AWS behaviour, so it is printed only for an operator AWS documents.
// A bare suffix, a doubled suffix, two set prefixes, a suffix on Null or a
// space inside the name is not an operator, and says so.
func TestOperatorSpellingsThatAreNotOperators(t *testing.T) {
	for _, op := range []string{"IfExists", "StringEqualsIfExistsIfExists", "StringEquals IfExists", "NULLIfExists", "ForAnyValue:ForAllValues:StringEqualsIfExists", "ForAllValues:", "ForAllValues:FooIfExists", "stringlikeifexists"} {
		g := oneGrant(t, github(`{"`+op+`": {"`+gh("sub")+`": "`+mainBranch+`"}}`))
		want := "operator " + strconv.Quote(op) + " on sub is not modelled by this parser, so the claim is not constrained"
		if a, ok := findAnomaly(g, trust.Unmodelled, op); !ok || a.Message != want {
			t.Errorf("%q: anomaly = %+v, %v; want %q", op, a, ok, want)
		}
		if !g.Admits.IsTop() || g.Exact() || !hasCaveatOn(g, "sub") {
			t.Errorf("%q: Admits = %s, exact %v", op, g.Admits, g.Exact())
		}
	}
	// Every documented operator takes the suffix and either prefix.
	for _, op := range []string{"ForAllValues:ArnLikeIfExists", "ForAnyValue:NumericLessThanIfExists", "BoolIfExists", "ForAllValues:Null"} {
		g := oneGrant(t, github(`{"`+op+`": {"`+gh("sub")+`": "x"}}`))
		if a, ok := findAnomaly(g, trust.Unmodelled, op); !ok || !strings.Contains(a.Message, "passes when the claim is absent") {
			t.Errorf("%q: anomaly = %+v, %v; a documented operator with the suffix or the prefix is vacuous on an absent key", op, a, ok)
		}
	}
}

// TestNullBooleanInAList: a one-element list holds its element's polarity
// whether the element is the string or the JSON boolean.
func TestNullBooleanInAList(t *testing.T) {
	cases := map[string]string{
		`[false]`:       `Null on sub is "false": the claim must be present, which this parser cannot express, so the claim is not constrained`,
		`[true]`:        `Null on sub is "true": the claim must be absent, which this parser cannot express, so the claim is not constrained`,
		`["false"]`:     `Null on sub is "false": the claim must be present, which this parser cannot express, so the claim is not constrained`,
		`[true, false]`: `Null on sub has the value a list ([true, false]), which is neither "true" nor "false", so the claim is not constrained`,
	}
	for value, want := range cases {
		g := oneGrant(t, github(`{"Null": {"`+gh("sub")+`": `+value+`}}`))
		if a, ok := findAnomaly(g, trust.Unmodelled, "Null"); !ok || a.Message != want {
			t.Errorf("%s: anomaly = %+v, %v; want %q", value, a, ok, want)
		}
	}
}

// TestStringLikeStarRequiresPresence: a StringLike of "*" passes only when
// the key is present, whatever its value. eval.Glob("*") admits every
// string and a Term drops such a claim, which would turn a presence test
// into no test at all: an Allow would admit tokens without the claim and
// call itself exact, and a Deny would deny every token. Presence is not a
// set of values, so the claim is Unknown, and a Deny built on it is not
// applied.
func TestStringLikeStarRequiresPresence(t *testing.T) {
	gs := policyGrants(t, "13-stringlike-star-requires-presence")
	if len(gs) != 3 {
		t.Fatalf("%d grants, want 3", len(gs))
	}
	const want = "StringLike on environment matches every value but only when the claim is present, which this parser cannot express, so the claim is not constrained"
	only := bySid(gs, "AllowOnlyJobsThatRunInAnEnvironment")
	if len(only) != 1 || only[0].Admits.String() != `{aud="sts.amazonaws.com", environment=?("StringLike")}` || only[0].Exact() || !hasCaveatOn(only[0], "environment") {
		t.Errorf("Allow with environment \"*\": %+v", only)
	}
	if a, ok := findAnomaly(only[0], trust.Unmodelled, "StringLike"); !ok || a.Claim != "environment" || a.Message != want {
		t.Errorf("presence anomaly = %+v, %v", a, ok)
	}
	acme := bySid(gs, "AllowAcmeRepositories")
	if len(acme) != 1 || acme[0].Admits.String() != `{aud="sts.amazonaws.com", sub=like:"repo:acme/*"}` || !acme[0].Exact() {
		t.Errorf("the ordinary Allow is exact: %+v", acme)
	}
	deny := bySid(gs, "DenyAnyJobThatRunsInAnEnvironment")
	if len(deny) != 1 || !deny[0].Admits.IsEmpty() || deny[0].Exact() {
		t.Fatalf("Deny with environment \"*\": %+v; want nothing denied, declared", deny)
	}
	if _, ok := findAnomaly(deny[0], trust.Unmodelled, "StringLike"); !ok {
		t.Errorf("the Deny names the presence test: %v", deny[0].Anomalies)
	}
	if _, ok := findAnomaly(deny[0], trust.Unmodelled, "Deny"); !ok {
		t.Errorf("the Deny says it is not applied: %v", deny[0].Anomalies)
	}
	noEnvironment := token{"aud": "sts.amazonaws.com", "sub": "repo:acme/infra:ref:refs/heads/main"}
	if !admittedDownstream(gs, githubIssuer, noEnvironment) {
		t.Errorf("a token without an environment claim is admitted by the second Allow and denied by nothing")
	}
	// Every pattern that admits every string is the same presence test, on
	// the principal's own key or on another provider's.
	for _, condition := range []string{
		`{"StringLike": {"` + gh("environment") + `": "**"}}`,
		`{"StringLike": {"` + gh("environment") + `": "***"}}`,
		`{"StringLike": {"` + gh("environment") + `": ["prod-*", "*"]}}`,
		`{"StringLike": {"gitlab.com:sub": "*"}}`,
		`{"StringLike": {"` + gh("aud") + `": "*"}, "StringEquals": {"` + gh("sub") + `": "` + mainBranch + `"}}`,
	} {
		g := oneGrant(t, github(condition))
		if g.Exact() {
			t.Errorf("%s: reported exact; a presence test is not expressible", condition)
		}
		if _, ok := findAnomaly(g, trust.Unmodelled, "StringLike"); !ok {
			t.Errorf("%s: no anomaly on StringLike: %v", condition, g.Anomalies)
		}
		deny := oneGrant(t, statement(`"Effect": "Deny", "Principal": {"Federated": "`+githubProvider+`"}, "Action": "sts:AssumeRoleWithWebIdentity", "Condition": `+condition))
		if !deny.Admits.IsEmpty() || deny.Exact() {
			t.Errorf("Deny %s: %s exact %v; want nothing denied, declared", condition, deny.Admits, deny.Exact())
		}
	}
	// A pattern that rejects some string is a real constraint and stays.
	g := oneGrant(t, github(`{"StringLike": {"`+gh("environment")+`": "?*"}}`))
	if g.Admits.String() != `{environment=like:"?*"}` || !g.Exact() {
		t.Errorf("?* is a pattern, not a presence test: %s exact %v", g.Admits, g.Exact())
	}
}

// admittedDownstream is what a consumer computes from the grants of one
// issuer: admitted by an Allow, or a possibly-Allow, and by no Deny.
func admittedDownstream(gs []trust.Grant, issuer trust.IssuerRef, tok token) bool {
	allowed := false
	for _, g := range gs {
		if g.Issuer != issuer || !g.Admits.Admits(tok) {
			continue
		}
		if g.Effect == trust.Deny {
			return false
		}
		allowed = true
	}
	return allowed
}

// TestOperatorBlockWithoutKeys: the grammar gives an operator block at
// least one key, and no page read says how IAM evaluates a block with
// none. The other blocks' set is a superset of every reading, so it is
// kept as an upper bound with the block named; a Deny built on one is not
// applied.
func TestOperatorBlockWithoutKeys(t *testing.T) {
	gs := policyGrants(t, "17-operator-block-without-keys")
	if len(gs) != 3 {
		t.Fatalf("%d grants, want 3", len(gs))
	}
	sentence := func(op string) string {
		return "the operator block " + op + " lists no keys; the IAM grammar requires at least one, so what it requires is not known"
	}
	beside := bySid(gs, "EmptyStringEqualsBesideAnAudience")
	if len(beside) != 1 || beside[0].Admits.String() != `{sub=like:"repo:acme/*"}` || beside[0].Exact() || !hasCaveatOn(beside[0], "") {
		t.Errorf("empty block beside a pattern: %+v; want the pattern kept as an upper bound", beside)
	}
	if a, ok := findAnomaly(beside[0], Malformed, "StringEquals"); !ok || a.Message != sentence("StringEquals") || a.Source != "statement[0].Condition" {
		t.Errorf("anomaly = %+v, %v", a, ok)
	}
	alone := bySid(gs, "EmptyUnrecognisedOperator")
	if len(alone) != 1 || !alone[0].Admits.IsTop() || alone[0].Exact() {
		t.Errorf("empty unrecognised block: %+v; want everything, inexact", alone)
	}
	if a, ok := findAnomaly(alone[0], Malformed, "ArnLike"); !ok || a.Message != sentence("ArnLike") {
		t.Errorf("anomaly = %+v, %v", a, ok)
	}
	deny := bySid(gs, "DenyWithAnEmptyBlock")
	if len(deny) != 1 || !deny[0].Admits.IsEmpty() || deny[0].Exact() {
		t.Fatalf("Deny with an empty block: %+v; want nothing denied, declared", deny)
	}
	if _, ok := findAnomaly(deny[0], Malformed, "StringEqualsIfExists"); !ok {
		t.Errorf("the empty block is named on the Deny: %v", deny[0].Anomalies)
	}
	if _, ok := findAnomaly(deny[0], trust.Unmodelled, "Deny"); !ok {
		t.Errorf("the Deny says it is not applied: %v", deny[0].Anomalies)
	}
}

// The letters the folding tests turn on, spelled as escapes so that the
// difference from s, k and E is visible in the source.
const (
	longS      = "\u017f" // LATIN SMALL LETTER LONG S, which simple folding equates with s
	kelvinSign = "\u212a" // KELVIN SIGN, which simple folding equates with k
	dotlessI   = "\u0131" // LATIN SMALL LETTER DOTLESS I: upper-cases to I, in no simple-folding orbit
	dottedI    = "\u0130" // LATIN CAPITAL LETTER I WITH DOT ABOVE: lower-cases to i, in no simple-folding orbit
	cyrillicIe = "\u0415" // CYRILLIC CAPITAL LETTER IE, a lookalike of E with no folding relation to it
	umlautU    = "\u00fc" // a letter outside ASCII with a case variant of its own
	umlautUCap = "\u00dc"
	cjk        = "\u4e2d" // a letter with no case at all
)

// TestKeysBeyondASCIICaseAreUnknown: AWS documents that context key names
// are not case-sensitive and shows it on ASCII letters; what it does with
// a letter outside ASCII that has case variants of its own is not
// documented. A parser that folded such a letter would claim AWS folds it,
// and one that did not would claim AWS does not; either guess is the
// narrow direction on one of two documents that differ by one letter. So
// a key holding one is Unknown, declared, whoever it would belong to, and
// two spellings that would be one key under that folding are Unknown as a
// possible duplicate, since a decoder would then keep either.
func TestKeysBeyondASCIICaseAreUnknown(t *testing.T) {
	const issuer = trust.IssuerRef("https://" + umlautU + "nicode.example")
	unicode := func(condition string) string {
		return statement(`"Effect": "Allow", "Principal": {"Federated": "arn:aws:iam::123456789012:oidc-provider/` + umlautU + `nicode.example"}, "Action": "sts:AssumeRoleWithWebIdentity", "Condition": ` + condition)
	}
	const folding = `holds a letter outside ASCII with case variants of its own; AWS documents no folding for it, so which key it names is not known and the claim is not constrained`
	cases := []struct {
		name  string
		raw   string
		claim trust.ClaimKey
		key   string
	}{
		{"identifier spelled beyond ASCII", unicode(`{"StringEquals": {"` + umlautU + `nicode.example:sub": "x"}}`), "sub", umlautU + "nicode.example:sub"},
		{"identifier recased beyond ASCII", unicode(`{"StringEquals": {"` + umlautUCap + `nicode.example:sub": "x"}}`), trust.ClaimKey(umlautUCap + "nicode.example:sub"), umlautUCap + "nicode.example:sub"},
		{"long s in the identifier", github(`{"StringEquals": {"token.actions.githubu` + longS + `ercontent.com:sub": "` + mainBranch + `"}}`), trust.ClaimKey("token.actions.githubu" + longS + "ercontent.com:sub"), "token.actions.githubu" + longS + "ercontent.com:sub"},
		{"kelvin sign in the identifier", github(`{"StringEquals": {"to` + kelvinSign + `en.actions.githubusercontent.com:sub": "` + mainBranch + `"}}`), trust.ClaimKey("to" + kelvinSign + "en.actions.githubusercontent.com:sub"), "to" + kelvinSign + "en.actions.githubusercontent.com:sub"},
		{"long s in the claim", github(`{"StringEquals": {"` + gh(longS+"ub") + `": "` + mainBranch + `"}}`), trust.ClaimKey(longS + "ub"), gh(longS + "ub")},
		{"in a request key", github(`{"StringEquals": {"aw` + longS + `:SourceIp": "203.0.113.7"}}`), trust.ClaimKey("aw" + longS + ":sourceip"), "aw" + longS + ":SourceIp"},
		// The Turkic i's are case variants of i and I through the upper- and
		// lower-case mappings alone; simple folding leaves them in place, and
		// a check that asked simple folding alone read them as letters with
		// no case, admitting nobody, exactly.
		{"dotless i in the identifier", github(`{"StringEquals": {"token.actions.g` + dotlessI + `thubusercontent.com:sub": "` + mainBranch + `"}}`), trust.ClaimKey("token.actions.g" + dotlessI + "thubusercontent.com:sub"), "token.actions.g" + dotlessI + "thubusercontent.com:sub"},
		{"capital i with a dot in the identifier", github(`{"StringEquals": {"TOKEN.ACTIONS.G` + dottedI + `THUBUSERCONTENT.COM:SUB": "` + mainBranch + `"}}`), trust.ClaimKey("token.actions.g" + dottedI + "thubusercontent.com:sub"), "TOKEN.ACTIONS.G" + dottedI + "THUBUSERCONTENT.COM:SUB"},
		{"capital i with a dot in the claim", github(`{"StringEquals": {"` + gh("repository_v"+dottedI+"sibility") + `": "public"}}`), trust.ClaimKey("repository_v" + dottedI + "sibility"), gh("repository_v" + dottedI + "sibility")},
	}
	for _, c := range cases {
		gs := mustParse(t, c.raw).Grants(role, LowercaseVocabulary(githubIssuer, issuer))
		if len(gs) != 1 {
			t.Fatalf("%s: %d grants", c.name, len(gs))
		}
		g := gs[0]
		if !g.Admits.IsTop() || g.Exact() || !hasCaveatOn(g, c.claim) {
			t.Errorf("%s: Admits = %s, exact %v, caveats %v; want Unknown on %q, declared", c.name, g.Admits, g.Exact(), g.Admits.Caveats(), c.claim)
		}
		if a, ok := findAnomaly(g, trust.Unmodelled, c.key); !ok || a.Claim != c.claim || a.Message != "the condition key "+strconv.QuoteToASCII(c.key)+" "+folding {
			t.Errorf("%s: anomaly = %+v, %v", c.name, a, ok)
		}
		// Under a Deny the Unknown makes the Deny inapplicable.
		deny := strings.Replace(c.raw, `"Effect": "Allow"`, `"Effect": "Deny"`, 1)
		if d := mustParse(t, deny).Grants(role, LowercaseVocabulary(githubIssuer, issuer)); len(d) != 1 || !d[0].Admits.IsEmpty() || d[0].Exact() {
			t.Errorf("%s as a Deny: %+v; want nothing denied, declared", c.name, d)
		}
	}
	// A letter outside ASCII with no case variants raises no such question.
	ideograph := oneGrant(t, github(`{"StringEquals": {"`+gh(cjk)+`": "x"}}`))
	if ideograph.Admits.String() != `{`+cjk+`="x"}` || !ideograph.Exact() {
		t.Errorf("a claim spelled with a letter that has no case: %s exact %v", ideograph.Admits, ideograph.Exact())
	}
	// Two spellings that are one key under such a folding may be a
	// duplicate, and a decoder would keep either: every one of them is
	// Unknown, the ASCII spelling included.
	pairs := []struct {
		name string
		raw  string
		keys []string
	}{
		{"identifier recased", unicode(`{"StringEquals": {"` + umlautU + `nicode.example:sub": "a", "` + umlautUCap + `nicode.example:sub": "b"}}`), []string{umlautU + "nicode.example:sub", umlautUCap + "nicode.example:sub"}},
		{"long s", github(`{"StringEquals": {"token.actions.githubu` + longS + `ercontent.com:sub": "` + mainBranch + `", "` + gh("sub") + `": "` + devBranch + `"}}`), []string{"token.actions.githubu" + longS + "ercontent.com:sub", gh("sub")}},
		{"kelvin sign", github(`{"StringEquals": {"` + gh("sub") + `": "` + mainBranch + `", "to` + kelvinSign + `en.actions.githubusercontent.com:sub": "` + devBranch + `"}}`), []string{gh("sub"), "to" + kelvinSign + "en.actions.githubusercontent.com:sub"}},
		{"dotless i", github(`{"StringEquals": {"` + gh("sub") + `": "` + mainBranch + `", "token.actions.g` + dotlessI + `thubusercontent.com:sub": "` + devBranch + `"}}`), []string{gh("sub"), "token.actions.g" + dotlessI + "thubusercontent.com:sub"}},
		{"capital i with a dot", github(`{"StringEquals": {"token.actions.g` + dottedI + `thubusercontent.com:sub": "` + mainBranch + `", "` + gh("sub") + `": "` + devBranch + `"}}`), []string{"token.actions.g" + dottedI + "thubusercontent.com:sub", gh("sub")}},
	}
	for _, c := range pairs {
		gs := mustParse(t, c.raw).Grants(role, LowercaseVocabulary(githubIssuer, issuer))
		if len(gs) != 1 {
			t.Fatalf("%s: %d grants", c.name, len(gs))
		}
		g := gs[0]
		if g.Admits.IsEmpty() || !g.Admits.IsTop() || g.Exact() || !hasCaveatOn(g, "sub") {
			t.Errorf("%s: Admits = %s, exact %v, caveats %v; want Unknown on sub, declared", c.name, g.Admits, g.Exact(), g.Admits.Caveats())
		}
		want := "the keys " + strconv.QuoteToASCII(c.keys[0]) + " and " + strconv.QuoteToASCII(c.keys[1]) + " under StringEquals are one key if AWS folds letters outside ASCII, which no page documents; a JSON decoder would then keep one and the deployed policy may carry either, so the claim is not constrained"
		if !slices.ContainsFunc(g.Anomalies, func(a trust.Anomaly) bool {
			return a.Kind == DuplicateKey && a.Claim == "sub" && a.Construct == "StringEquals" && a.Message == want
		}) {
			t.Errorf("%s: anomalies %v lack the possible-duplicate sentence %q", c.name, g.Anomalies, want)
		}
		if !g.Admits.Admits(token{"sub": mainBranch}) || !g.Admits.Admits(token{"sub": devBranch}) {
			t.Errorf("%s: both branches are admitted: %s", c.name, g.Admits)
		}
	}
	// The golden document, rendered exactly.
	gs := policyGrants(t, "19-keys-beyond-ascii-case")
	if len(gs) != 4 {
		t.Fatalf("%d grants, want 4", len(gs))
	}
	longSKey := "token.actions.githubu" + longS + "ercontent.com:sub"
	deny := bySid(gs, "DenyWithALongSInTheProvider")
	if len(deny) != 1 || !deny[0].Admits.IsEmpty() || deny[0].Exact() {
		t.Fatalf("Deny with a long s: %+v; want nothing denied, declared", deny)
	}
	if a, ok := findAnomaly(deny[0], trust.Unmodelled, longSKey); !ok || a.Message != "the condition key "+strconv.QuoteToASCII(longSKey)+" "+folding {
		t.Errorf("Deny anomaly = %+v, %v", a, ok)
	}
	if _, ok := findAnomaly(deny[0], trust.Unmodelled, "Deny"); !ok {
		t.Errorf("the Deny says it is not applied: %v", deny[0].Anomalies)
	}
	claim := bySid(gs, "LongSInTheClaim")
	if want := `{aud="sts.amazonaws.com", ` + longS + `ub=?(` + strconv.QuoteToASCII("folding of "+gh(longS+"ub")) + `)}`; len(claim) != 1 || claim[0].Admits.String() != want || claim[0].Exact() {
		t.Errorf("long s in the claim: %+v; want %s inexact", claim, want)
	}
	if len(claim) == 1 && !claim[0].Admits.Admits(token{"aud": "sts.amazonaws.com"}) {
		t.Errorf("a token with aud alone is admitted")
	}
	// The reason names the first spelling in the block, the long-s one.
	two := bySid(gs, "TwoSpellingsThatMayBeOneKey")
	possible := strconv.QuoteToASCII("possible duplicate key " + longSKey)
	if want := `{aud="sts.amazonaws.com", sub=?(` + possible + `), ` + longSKey + `=?(` + strconv.QuoteToASCII("folding of "+longSKey) + `, ` + possible + `)}`; len(two) != 1 || two[0].Admits.String() != want || two[0].Exact() {
		t.Errorf("two spellings: %+v; want %s inexact", two, want)
	}
	if len(two) == 1 && (!two[0].Admits.Admits(token{"aud": "sts.amazonaws.com", "sub": mainBranch}) || !two[0].Admits.Admits(token{"aud": "sts.amazonaws.com", "sub": devBranch})) {
		t.Errorf("both branches are admitted: %s", two[0].Admits)
	}
	// Three spellings are listed in full.
	three := oneGrant(t, github(`{"StringEquals": {"`+gh("sub")+`": "a", "to`+kelvinSign+`en.actions.githubusercontent.com:sub": "b", "token.actions.githubu`+longS+`ercontent.com:sub": "c"}}`))
	if !slices.ContainsFunc(three.Anomalies, func(a trust.Anomaly) bool {
		return a.Kind == DuplicateKey && strings.HasPrefix(a.Message, `the keys "token.actions.githubusercontent.com:sub", "to\u212aen.actions.githubusercontent.com:sub" and "token.actions.githubu\u017fercontent.com:sub" under StringEquals are one key`)
	}) {
		t.Errorf("three spellings: %v", three.Anomalies)
	}
	// The mirror: the letter sits in the provider identifier and the key is
	// ASCII. Under a wider folding the key is the provider's own sub.
	const eksProvider = "arn:aws:iam::123456789012:oidc-provider/oidc.eks.us-west-2.amazonaws.com/id/" + kelvinSign + "1"
	eks := bySid(gs, "AsciiKeyOnAProviderSpelledBeyondASCII")
	if len(eks) != 1 || eks[0].Issuer != "https://oidc.eks.us-west-2.amazonaws.com/id/"+kelvinSign+"1" || !eks[0].Admits.IsTop() || eks[0].Exact() || !hasCaveatOn(eks[0], "oidc.eks.us-west-2.amazonaws.com/id/k1:sub") {
		t.Errorf("ASCII key on a provider spelled beyond ASCII: %+v; want everything, declared on the folded key", eks)
	}
	if a, ok := findAnomaly(eks[0], trust.Unmodelled, "oidc.eks.us-west-2.amazonaws.com/id/K1:sub"); !ok || a.Claim != "oidc.eks.us-west-2.amazonaws.com/id/k1:sub" || a.Message != `the condition key "oidc.eks.us-west-2.amazonaws.com/id/K1:sub" is a claim of the Federated principal `+strconv.QuoteToASCII(eksProvider)+` if AWS folds letters outside ASCII, which no page documents, so which key it names is not known and the claim is not constrained` {
		t.Errorf("provider-side folding anomaly = %+v, %v", a, ok)
	}
	if !eks[0].Admits.Admits(token{"sub": "system:serviceaccount:ns:sa"}) {
		t.Errorf("the service account AWS admits under a Unicode folding is admitted")
	}
}

// TestProviderIdentifierBeyondASCIICase: the letter that raises the folding
// question can sit in the provider identifier rather than in the key. A
// key that is the provider's own under simple case folding and another
// provider's under ASCII folding is Unknown, as the same key spelled with
// the letter itself is; a key that is another provider's under every
// folding stays that provider's, and a Deny built on the question is not
// applied.
func TestProviderIdentifierBeyondASCIICase(t *testing.T) {
	const identifier = "oidc.eks.us-west-2.amazonaws.com/id/" + kelvinSign + "1"
	const provider = "arn:aws:iam::123456789012:oidc-provider/" + identifier
	eks := func(effect, condition string) []trust.Grant {
		return mustParse(t, statement(`"Effect": "`+effect+`", "Principal": {"Federated": "`+provider+`"}, "Action": "sts:AssumeRoleWithWebIdentity", "Condition": `+condition)).Grants(role, LowercaseVocabulary(githubIssuer, "https://"+identifier))
	}
	want := `the condition key "oidc.eks.us-west-2.amazonaws.com/id/K1:sub" is a claim of the Federated principal ` + strconv.QuoteToASCII(provider) + ` if AWS folds letters outside ASCII, which no page documents, so which key it names is not known and the claim is not constrained`
	gs := eks("Allow", `{"StringEquals": {"oidc.eks.us-west-2.amazonaws.com/id/K1:sub": "system:serviceaccount:ns:sa", "gitlab.com:sub": "x"}}`)
	if len(gs) != 1 {
		t.Fatalf("%d grants", len(gs))
	}
	g := gs[0]
	const claim = trust.ClaimKey("oidc.eks.us-west-2.amazonaws.com/id/k1:sub")
	if got := g.Admits.String(); got != `{gitlab.com:sub="x", `+string(claim)+`=?(`+strconv.QuoteToASCII("folding of provider "+identifier)+`)}` || g.Exact() || !hasCaveatOn(g, claim) {
		t.Errorf("Admits = %s, exact %v, caveats %v; want the ASCII key Unknown beside the foreign key kept", got, g.Exact(), g.Admits.Caveats())
	}
	if a, ok := findAnomaly(g, trust.Unmodelled, "oidc.eks.us-west-2.amazonaws.com/id/K1:sub"); !ok || a.Claim != claim || a.Message != want {
		t.Errorf("anomaly = %+v, %v; want %q", a, ok, want)
	}
	if !g.Admits.Admits(token{"sub": "system:serviceaccount:ns:sa", "gitlab.com:sub": "x"}) {
		t.Errorf("the key AWS would read as sub under a Unicode folding does not reject the token")
	}
	// The identical spelling is the provider's own key, and Unknown for the
	// letter it holds itself, with that sentence and not this one.
	same := eks("Allow", `{"StringEquals": {"`+identifier+`:sub": "x"}}`)[0]
	if a, ok := findAnomaly(same, trust.Unmodelled, identifier+":sub"); !ok || a.Claim != "sub" || !strings.Contains(a.Message, "holds a letter outside ASCII") || !hasCaveatOn(same, "sub") {
		t.Errorf("identical spelling: anomaly = %+v, %v, caveats %v", a, ok, same.Admits.Caveats())
	}
	if slices.ContainsFunc(same.Anomalies, func(a trust.Anomaly) bool {
		return strings.Contains(a.Message, "is a claim of the Federated principal")
	}) {
		t.Errorf("the provider-side sentence is owed only to a key the ASCII folding does not place: %v", same.Anomalies)
	}
	deny := eks("Deny", `{"StringEquals": {"oidc.eks.us-west-2.amazonaws.com/id/K1:sub": "system:serviceaccount:ns:sa"}}`)[0]
	if !deny.Admits.IsEmpty() || deny.Exact() {
		t.Errorf("Deny: %s exact %v; want nothing denied, declared", deny.Admits, deny.Exact())
	}
	if _, ok := findAnomaly(deny, trust.Unmodelled, "Deny"); !ok {
		t.Errorf("the Deny says it is not applied: %v", deny.Anomalies)
	}
	// A provider identifier with no such letter raises no such question,
	// whatever its case: the ASCII folding places every key.
	plain := mustParse(t, statement(`"Effect": "Allow", "Principal": {"Federated": "arn:aws:iam::123456789012:oidc-provider/oidc.eks.us-west-2.amazonaws.com/id/K1"}, "Action": "sts:AssumeRoleWithWebIdentity", "Condition": {"StringEquals": {"OIDC.EKS.US-WEST-2.AMAZONAWS.COM/ID/k1:sub": "x"}}`)).Grants(role, LowercaseVocabulary("https://oidc.eks.us-west-2.amazonaws.com/id/K1"))
	if len(plain) != 1 || plain[0].Admits.String() != `{sub="x"}` || !plain[0].Exact() {
		t.Errorf("ASCII identifier: %+v", plain)
	}
}

// TestCertainDuplicateBesideAPossibleOne: a block whose spellings of one
// key are a certain duplicate under the ASCII folding AWS documents, beside
// a spelling that is the same key only under a wider folding, is described
// as exactly that. Calling the whole group a possible duplicate was false
// for two of the three keys it named.
func TestCertainDuplicateBesideAPossibleOne(t *testing.T) {
	longSKey := "token.actions.githubu" + longS + "ercontent.com:sub"
	g := oneGrant(t, github(`{"StringEquals": {"`+gh("aud")+`": "sts.amazonaws.com", "`+gh("sub")+`": "`+mainBranch+`", "`+gh("SUB")+`": "`+devBranch+`", "`+longSKey+`": "repo:x/y"}}`))
	want := `the key "token.actions.githubusercontent.com:sub" appears more than once under StringEquals; "token.actions.githubusercontent.com:sub" and "token.actions.githubu\u017fercontent.com:sub" are one key if AWS folds letters outside ASCII, which no page documents; a JSON decoder keeps one and the deployed policy may carry either, so the claim is not constrained`
	for _, claim := range []trust.ClaimKey{"sub", trust.ClaimKey(longSKey)} {
		if !slices.ContainsFunc(g.Anomalies, func(a trust.Anomaly) bool {
			return a.Kind == DuplicateKey && a.Claim == claim && a.Construct == "StringEquals" && a.Message == want
		}) {
			t.Errorf("no duplicate-key anomaly on %q with the mixed sentence: %v", claim, g.Anomalies)
		}
	}
	duplicate := strconv.QuoteToASCII("duplicate key " + gh("sub"))
	if got := g.Admits.String(); got != `{aud="sts.amazonaws.com", sub=?(`+duplicate+`), `+longSKey+`=?(`+duplicate+`, `+strconv.QuoteToASCII("folding of "+longSKey)+`)}` || g.Exact() || !hasCaveatOn(g, "sub") {
		t.Errorf("Admits = %s, exact %v; the certain duplicate names the reason", got, g.Exact())
	}
	for _, tok := range []token{{"aud": "sts.amazonaws.com", "sub": mainBranch}, {"aud": "sts.amazonaws.com", "sub": devBranch}, {"aud": "sts.amazonaws.com", "sub": "repo:x/y"}} {
		if !g.Admits.Admits(tok) {
			t.Errorf("%v is admitted: which copy is deployed is not known", tok)
		}
	}
	// Two certain duplicates that may be one key: each is named, then both.
	two := oneGrant(t, github(`{"StringEquals": {"`+gh("sub")+`": "a", "`+gh("SUB")+`": "b", "`+longSKey+`": "c", "token.actions.githubu`+longS+`ercontent.com:SUB": "d"}}`))
	want = `the keys "token.actions.githubusercontent.com:sub" and "token.actions.githubu\u017fercontent.com:sub" each appear more than once under StringEquals; "token.actions.githubusercontent.com:sub" and "token.actions.githubu\u017fercontent.com:sub" are one key if AWS folds letters outside ASCII, which no page documents; a JSON decoder keeps one and the deployed policy may carry either, so the claim is not constrained`
	if a, ok := findAnomaly(two, DuplicateKey, "StringEquals"); !ok || a.Message != want {
		t.Errorf("two certain groups: anomaly = %+v, %v; want %q", a, ok, want)
	}
}

// TestServiceConditionKeysAreRequestContext: a key whose prefix names an
// AWS service rather than an identity provider, iam:ResourceTag/env or
// saml:sub, describes the request or the role, not a claim of the token.
// Read as another provider's key it became an exact constraint on a claim
// no token carries, and the grant rejected every token AWS admits. A
// provider's prefix is a host, which has a dot; a service prefix never
// does, so the two are told apart by the dot.
func TestServiceConditionKeysAreRequestContext(t *testing.T) {
	const sentence = " is a fact about the request, not a claim of the token, so this parser does not evaluate it and the claim is not constrained"
	gs := policyGrants(t, "18-service-condition-keys")
	if len(gs) != 3 {
		t.Fatalf("%d grants, want 3", len(gs))
	}
	tagged := bySid(gs, "ResourceTagBesideASubject")
	if len(tagged) != 1 {
		t.Fatalf("%d grants for the tagged statement", len(tagged))
	}
	if want := `{aud="sts.amazonaws.com", iam:resourcetag/env=?("iam:resourcetag/env"), sub="` + mainBranch + `"}`; tagged[0].Admits.String() != want || tagged[0].Exact() || !hasCaveatOn(tagged[0], "iam:resourcetag/env") {
		t.Errorf("iam:ResourceTag on an OIDC principal: %s exact %v; want %s inexact", tagged[0].Admits, tagged[0].Exact(), want)
	}
	if a, ok := findAnomaly(tagged[0], trust.Unmodelled, "iam:ResourceTag/env"); !ok || a.Claim != "iam:resourcetag/env" || a.Message != `the condition key "iam:ResourceTag/env"`+sentence {
		t.Errorf("anomaly = %+v, %v", a, ok)
	}
	if !tagged[0].Admits.Admits(token{"aud": "sts.amazonaws.com", "sub": mainBranch}) {
		t.Errorf("the main branch is admitted whatever the role's tags")
	}
	saml := bySid(gs, "SamlSubjectOnARole")
	if len(saml) != 1 {
		t.Fatalf("%d grants for the SAML statement", len(saml))
	}
	if want := `{aws:principalaccount="123456789012", aws:principalarn="arn:aws:iam::123456789012:role/ci", saml:sub=?("saml:sub")}`; saml[0].Issuer != AWSPrincipalIssuer || saml[0].Admits.String() != want || saml[0].Exact() || !hasCaveatOn(saml[0], "saml:sub") {
		t.Errorf("saml:sub on a role principal: %s exact %v; want %s inexact", saml[0].Admits, saml[0].Exact(), want)
	}
	if a, ok := findAnomaly(saml[0], trust.Unmodelled, "saml:sub"); !ok || a.Message != `the condition key "saml:sub"`+sentence {
		t.Errorf("anomaly = %+v, %v", a, ok)
	}
	if !saml[0].Admits.Admits(token{"aws:principalaccount": "123456789012", "aws:principalarn": "arn:aws:iam::123456789012:role/ci"}) {
		t.Errorf("the named role is admitted")
	}
	deny := bySid(gs, "DenyByResourceTag")
	if len(deny) != 1 || !deny[0].Admits.IsEmpty() || deny[0].Exact() {
		t.Fatalf("Deny by a resource tag: %+v; want nothing denied, declared", deny)
	}
	for _, c := range []struct{ kind, construct string }{{trust.Unmodelled, "iam:ResourceTag/env"}, {trust.Unmodelled, "Deny"}} {
		if _, ok := findAnomaly(deny[0], c.kind, c.construct); !ok {
			t.Errorf("the Deny lacks the %s anomaly: %v", c.construct, deny[0].Anomalies)
		}
	}
	// Any service prefix reads the same way, and a Deny built on one is
	// not applied.
	for _, key := range []string{"iam:ResourceTag/env", "saml:namequalifier", "ec2:SourceInstanceARN"} {
		deny := oneGrant(t, statement(`"Effect": "Deny", "Principal": {"AWS": "123456789012"}, "Action": "sts:AssumeRole", "Condition": {"StringEquals": {"`+key+`": "x"}}`))
		if !deny.Admits.IsEmpty() || deny.Exact() {
			t.Errorf("Deny on %s: %s exact %v; want nothing denied, declared", key, deny.Admits, deny.Exact())
		}
		if _, ok := findAnomaly(deny, trust.Unmodelled, "Deny"); !ok {
			t.Errorf("Deny on %s does not say it is not applied: %v", key, deny.Anomalies)
		}
	}
	// On the anonymous principal too: a service key is not a provider's.
	anyone := awsFace(t, statement(`"Effect": "Allow", "Principal": "*", "Action": "sts:AssumeRole", "Condition": {"StringEquals": {"iam:ResourceTag/env": "prod"}}`))
	if a, ok := findAnomaly(anyone, trust.Unmodelled, "iam:ResourceTag/env"); !ok || !strings.HasSuffix(a.Message, sentence) {
		t.Errorf("anonymous principal: anomaly = %+v, %v", a, ok)
	}
	// Another provider's key still stays verbatim: its prefix is a host.
	foreign := oneGrant(t, github(`{"StringEquals": {"accounts.google.com:aud": "x"}}`))
	if foreign.Admits.String() != `{accounts.google.com:aud="x"}` || !foreign.Exact() {
		t.Errorf("a built-in provider's key on a GitHub grant stays verbatim: %s exact %v", foreign.Admits, foreign.Exact())
	}
}

// TestPolicyVariableInAKeyIsUnknown: the variables page allows a policy
// variable in the Resource element and in condition values, never in a
// key. A key holding one was read as the literal claim name, called
// exact, and rejected every token; which key AWS reads it as is not
// known, and a variable is never compared as a literal.
func TestPolicyVariableInAKeyIsUnknown(t *testing.T) {
	gs := policyGrants(t, "20-policy-variable-in-a-key")
	if len(gs) != 2 {
		t.Fatalf("%d grants, want 2", len(gs))
	}
	inClaim := bySid(gs, "VariableInTheClaimPosition")
	if want := `{${aws:username}=?("${aws:username}"), aud="sts.amazonaws.com"}`; len(inClaim) != 1 || inClaim[0].Admits.String() != want || inClaim[0].Exact() || !hasCaveatOn(inClaim[0], "${aws:username}") {
		t.Errorf("variable in the claim position: %+v; want %s inexact", inClaim, want)
	}
	if len(inClaim) == 1 && !inClaim[0].Admits.Admits(token{"aud": "sts.amazonaws.com"}) {
		t.Errorf("a token with aud alone is admitted")
	}
	inProvider := bySid(gs, "VariableInTheProviderPosition")
	if len(inProvider) != 1 || !inProvider[0].Admits.IsTop() || inProvider[0].Exact() || !hasCaveatOn(inProvider[0], "${aws:principaltag/provider}:sub") {
		t.Errorf("variable in the provider position: %+v; want everything, declared", inProvider)
	}
	cases := []struct {
		key, variable string
		claim         trust.ClaimKey
	}{
		{gh("${aws:username}"), "${aws:username}", "${aws:username}"},
		{"${aws:username}:sub", "${aws:username}", "${aws:username}:sub"},
		{gh("sub${*}"), "${*}", "sub${*}"},
		{"aws:PrincipalTag/${aws:username}", "${aws:username}", "aws:principaltag/${aws:username}"},
	}
	for _, c := range cases {
		g := oneGrant(t, github(`{"StringEquals": {"`+c.key+`": "x"}}`))
		if !g.Admits.IsTop() || g.Exact() || !hasCaveatOn(g, c.claim) {
			t.Errorf("%s: Admits = %s, exact %v, caveats %v; want Unknown on %q, declared", c.key, g.Admits, g.Exact(), g.Admits.Caveats(), c.claim)
		}
		want := "the condition key " + strconv.Quote(c.key) + " holds the policy variable " + c.variable + "; AWS documents variables in condition values and the Resource element, not in keys, so which key it names is not known and the claim is not constrained"
		if a, ok := findAnomaly(g, trust.Unmodelled, c.variable); !ok || a.Claim != c.claim || a.Message != want {
			t.Errorf("%s: anomaly = %+v, %v; want %q", c.key, a, ok, want)
		}
	}
	// Under the 2008 language "${" is literal text in a key as in a value,
	// and the grant says so.
	literal := oneGrant(t, `{"Version": "2008-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Federated": "`+githubProvider+`"}, "Action": "sts:AssumeRoleWithWebIdentity", "Condition": {"StringEquals": {"`+gh("${aws:username}")+`": "x"}}}]}`)
	if literal.Admits.String() != `{${aws:username}="x"}` || !literal.Exact() {
		t.Errorf("2008: %s exact %v", literal.Admits, literal.Exact())
	}
	if a, ok := findAnomaly(literal, VariableIsLiteral, "${aws:username}"); !ok || a.Claim != "${aws:username}" || a.Message != `the condition key "`+gh("${aws:username}")+`" holds "${aws:username}", which is literal text because this document's Version does not resolve policy variables; if a variable was meant, the condition does not do what it looks like it does` {
		t.Errorf("2008: anomaly = %+v, %v", a, ok)
	}
}

// TestOperatorNamesAreQuotedWhenNotDocumented: a sentence naming an
// operator AWS documents spells it as AWS does; any other spelling is
// quoted, so an empty or a lookalike name is visible rather than a blank.
func TestOperatorNamesAreQuotedWhenNotDocumented(t *testing.T) {
	empty := oneGrant(t, github(`{"": {"`+gh("sub")+`": "x"}}`))
	if a, ok := findAnomaly(empty, trust.Unmodelled, ""); !ok || a.Claim != "sub" || a.Message != `operator "" on sub is not modelled by this parser, so the claim is not constrained` {
		t.Errorf("empty operator: anomaly = %+v, %v", a, ok)
	}
	if c := empty.Admits.Caveats(); len(c) != 1 || c[0].Reason != `operator "" on sub is not modelled by this parser, so the claim is not constrained` {
		t.Errorf("empty operator: caveats %v", c)
	}
	null := oneGrant(t, github(`{"": null}`))
	if a, ok := findAnomaly(null, Malformed, ""); !ok || a.Message != `the operator block "" is null (null), not an object, so what it requires is not known` {
		t.Errorf("empty operator on a null block: anomaly = %+v, %v", a, ok)
	}
	blank := oneGrant(t, github(`{" ": {}}`))
	if a, ok := findAnomaly(blank, Malformed, " "); !ok || a.Message != `the operator block " " lists no keys; the IAM grammar requires at least one, so what it requires is not known` {
		t.Errorf("blank operator on an empty block: anomaly = %+v, %v", a, ok)
	}
	twice := oneGrant(t, github(`{"": {"`+gh("sub")+`": "x"}, "": {"`+gh("aud")+`": "y"}}`))
	if !slices.ContainsFunc(twice.Anomalies, func(a trust.Anomaly) bool {
		return a.Kind == DuplicateKey && a.Message == `the operator "" appears more than once in the Condition; a JSON decoder keeps one block and the deployed policy may carry either`
	}) {
		t.Errorf("empty operator twice: %v", twice.Anomalies)
	}
	// A lookalike letter is spelled as its escape.
	lookalike := oneGrant(t, github(`{"String`+cyrillicIe+`quals": {"`+gh("sub")+`": 5}}`))
	for _, want := range []string{
		`operator "String\u0415quals" on sub is not modelled by this parser, so the claim is not constrained`,
		`"String\u0415quals" on sub has a value that is a number (5) where a string or a list of strings is expected, so the claim is not constrained`,
	} {
		if !slices.ContainsFunc(lookalike.Anomalies, func(a trust.Anomaly) bool { return a.Message == want }) {
			t.Errorf("lookalike operator: anomalies %v lack %q", lookalike.Anomalies, want)
		}
	}
	// A claim spelled outside ASCII is quoted in the sentence too.
	claim := oneGrant(t, github(`{"ArnLike": {"`+gh(cjk)+`": "x"}}`))
	if a, ok := findAnomaly(claim, trust.Unmodelled, "ArnLike"); !ok || a.Message != `operator ArnLike on "\u4e2d" is not modelled by this parser, so the claim is not constrained` {
		t.Errorf("non-ASCII claim: anomaly = %+v, %v", a, ok)
	}
}

// TestVacuitySentenceFollowsTheEffect: an operator that passes on an
// absent key restricts nothing in an Allow, and in a Deny it denies more
// than it reads. The operators page says so for the Deny: "the request is
// still denied even if the condition key is not present". Which tokens
// the Deny denies beside those depends on the operator: a positive one
// denies the values it names, a negated one every value but them, so the
// value named is the one token a negated Deny does not deny. The set is
// sound either way; the sentence a customer reads must be true either
// way.
func TestVacuitySentenceFollowsTheEffect(t *testing.T) {
	denies := map[string]string{
		"StringEqualsIfExists":              " on sub passes when the claim is absent, so this Deny denies tokens without the claim as well as the ones it names",
		"ForAllValues:StringLike":           " on sub passes when the claim is absent, so this Deny denies tokens without the claim as well as the ones it names",
		"ForAllValues:ArnLikeIfExists":      " on sub passes when the claim is absent, so this Deny denies tokens without the claim as well as the ones it names",
		"StringNotEqualsIfExists":           " on sub passes when the claim is absent, so this Deny denies tokens without the claim as well as every token whose claim does not match the values it names",
		"StringNotLikeIfExists":             " on sub passes when the claim is absent, so this Deny denies tokens without the claim as well as every token whose claim does not match the values it names",
		"StringNotEqualsIgnoreCaseIfExists": " on sub passes when the claim is absent, so this Deny denies tokens without the claim as well as every token whose claim does not match the values it names",
		"ArnNotLikeIfExists":                " on sub passes when the claim is absent, so this Deny denies tokens without the claim as well as every token whose claim does not match the values it names",
		"NotIpAddressIfExists":              " on sub passes when the claim is absent, so this Deny denies tokens without the claim as well as every token whose claim does not match the values it names",
		"ForAllValues:StringNotEquals":      " on sub passes when the claim is absent, so this Deny denies tokens without the claim as well as every token whose claim does not match the values it names",
	}
	for op, sentence := range denies {
		deny := oneGrant(t, statement(`"Effect": "Deny", "Principal": {"Federated": "`+githubProvider+`"}, "Action": "sts:AssumeRoleWithWebIdentity", "Condition": {"`+op+`": {"`+gh("sub")+`": "`+mainBranch+`"}}`))
		if a, ok := findAnomaly(deny, trust.Unmodelled, op); !ok || a.Message != op+sentence {
			t.Errorf("Deny with %s: anomaly = %+v, %v; want %q", op, a, ok, op+sentence)
		}
		if !deny.Admits.IsEmpty() || deny.Exact() || !hasCaveatOn(deny, "sub") {
			t.Errorf("Deny with %s: %s exact %v; the set is still nothing denied, declared", op, deny.Admits, deny.Exact())
		}
		for _, effect := range []string{"Allow", "allow"} {
			g := oneGrant(t, statement(`"Effect": "`+effect+`", "Principal": {"Federated": "`+githubProvider+`"}, "Action": "sts:AssumeRoleWithWebIdentity", "Condition": {"`+op+`": {"`+gh("sub")+`": "`+mainBranch+`"}}`))
			if a, ok := findAnomaly(g, trust.Unmodelled, op); !ok || a.Message != op+" on sub passes when the claim is absent, so it does not restrict what it looks like it restricts" {
				t.Errorf("%s with %s: anomaly = %+v, %v", effect, op, a, ok)
			}
		}
	}
}

// TestValueListsScaleWithTheDocument: a StringEquals over thousands of
// values once joined them one at a time, each Join renormalising the
// union so far, cubic in the list; 4,000 values took over a minute and
// 8,000 never returned. A 300 KB document must project in time and
// memory proportional to what it says.
func TestValueListsScaleWithTheDocument(t *testing.T) {
	values := make([]string, 8000)
	for i := range values {
		values[i] = fmt.Sprintf(`"repo:acme/r%d:ref:refs/heads/main"`, i)
	}
	raw := github(`{"StringEquals": {"` + gh("sub") + `": [` + strings.Join(values, ", ") + `]}}`)
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	start := time.Now()
	g := oneGrant(t, raw)
	elapsed := time.Since(start)
	runtime.ReadMemStats(&after)
	allocated := after.TotalAlloc - before.TotalAlloc
	if !g.Exact() || !g.Admits.Admits(token{"sub": "repo:acme/r7999:ref:refs/heads/main"}) || g.Admits.Admits(token{"sub": "repo:acme/r8000:ref:refs/heads/main"}) {
		t.Errorf("the list is the union of its values: %v", g.Exact())
	}
	if limit := uint64(512 << 20); allocated > limit {
		t.Errorf("allocated %d MB projecting %d bytes, limit %d MB", allocated>>20, len(raw), limit>>20)
	}
	if elapsed > 30*time.Second {
		t.Errorf("projecting %d values took %v", len(values), elapsed)
	}
	t.Logf("%d values, %d bytes: %v, %d MB allocated", len(values), len(raw), elapsed, allocated>>20)
	// Thousands of unrecognised operators on one key merged their reasons
	// one at a time the same way.
	var blocks []string
	for i := 0; i < 20000; i++ {
		blocks = append(blocks, fmt.Sprintf(`"Op%d": {"%s": "x"}`, i, gh("sub")))
	}
	start = time.Now()
	g = oneGrant(t, github(`{`+strings.Join(blocks, ", ")+`}`))
	if elapsed := time.Since(start); elapsed > 30*time.Second || g.Exact() {
		t.Errorf("%d operators on one key took %v, exact %v", len(blocks), elapsed, g.Exact())
	}
}
