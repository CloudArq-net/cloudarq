package aws

import (
	"fmt"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/CloudArq-net/cloudarq/internal/eval"
	"github.com/CloudArq-net/cloudarq/internal/trust"
)

// semantic is what a grant means, with its position in the document
// projected out: the source bytes and the statement index in every Source
// string change when statements move, the meaning must not.
type semantic struct {
	issuer    trust.IssuerRef
	effect    trust.Effect
	admits    string
	caveats   string
	anomalies string
}

func semanticOf(g trust.Grant) semantic {
	var caveats, anomalies []string
	for _, c := range g.Admits.Caveats() {
		caveats = append(caveats, string(c.Claim)+"="+c.Reason)
	}
	for _, a := range g.Anomalies {
		anomalies = append(anomalies, a.Kind+"/"+string(a.Claim)+"/"+a.Construct+"/"+a.Message)
	}
	slices.Sort(caveats)
	slices.Sort(anomalies)
	return semantic{g.Issuer, g.Effect, g.Admits.String(), strings.Join(caveats, "; "), strings.Join(anomalies, "; ")}
}

// semanticsOf is the sorted multiset of meanings, so that two documents
// compare as sets of grants.
func semanticsOf(gs []trust.Grant) []semantic {
	out := make([]semantic, len(gs))
	for i, g := range gs {
		out[i] = semanticOf(g)
	}
	slices.SortFunc(out, func(a, b semantic) int {
		return strings.Compare(a.admits+a.caveats+a.anomalies+string(a.issuer)+string(a.effect), b.admits+b.caveats+b.anomalies+string(b.issuer)+string(b.effect))
	})
	return out
}

// wantDenyNotApplied is the sentence spelled here rather than taken from
// grant.go, so that the assertion is about the words a customer reads.
const wantDenyNotApplied = "this Deny statement could not be fully evaluated, so it is not applied; the admitted set is an upper bound"

// TestDenyWithAnyUnknownDeniesNothing: Unknown widens an Allow, which is
// sound, and would widen a Deny, which is not: the final set is Allow minus
// Deny, so a Deny that denied more than the policy does would report the
// role as narrower than it is. A Deny this parser cannot fully evaluate is
// therefore not applied, and says so.
func TestDenyWithAnyUnknownDeniesNothing(t *testing.T) {
	// Trace A, the standard "deny everything outside my org" shape.
	gs := grantsOf(t, `{"Version": "2012-10-17", "Statement": [
		{"Effect": "Allow", "Principal": {"Federated": "`+githubProvider+`"}, "Action": "sts:AssumeRoleWithWebIdentity", "Condition": {"StringLike": {"`+gh("sub")+`": "*"}}},
		{"Effect": "Deny", "Principal": {"Federated": "`+githubProvider+`"}, "Action": "sts:AssumeRoleWithWebIdentity", "Condition": {"StringNotLike": {"`+gh("sub")+`": "repo:acme/*"}}}
	]}`)
	if len(gs) != 2 {
		t.Fatalf("%d grants", len(gs))
	}
	for _, g := range gs {
		switch g.Effect {
		case trust.Allow:
			if !g.Admits.IsTop() || g.Exact() || !hasCaveatOn(g, "sub") {
				t.Errorf("Allow: %s exact %v; a star pattern is a presence test, so the set is everything as an upper bound", g.Admits, g.Exact())
			}
		case trust.Deny:
			if !g.Admits.IsEmpty() || g.Exact() || !hasCaveatOn(g, "") {
				t.Errorf("Deny with a negated operator: %s exact %v caveats %v; want nothing denied, declared", g.Admits, g.Exact(), g.Admits.Caveats())
			}
			if _, ok := findAnomaly(g, trust.Unmodelled, "StringNotLike"); !ok {
				t.Errorf("the construct that could not be evaluated is still named: %v", g.Anomalies)
			}
			if a, ok := findAnomaly(g, trust.Unmodelled, "Deny"); !ok || a.Message != wantDenyNotApplied || a.Source != "statement[1]" || a.Claim != "" {
				t.Errorf("Deny anomaly = %+v, %v", a, ok)
			}
		default:
			t.Errorf("unexpected effect %q", g.Effect)
		}
	}
	// Trace B: NotAction on a Deny denies everything but the assume, so it
	// does not restrict assumption at all.
	g := oneGrant(t, statement(`"Effect": "Deny", "Principal": {"Federated": "`+githubProvider+`"}, "NotAction": "sts:AssumeRoleWithWebIdentity"`))
	if !g.Admits.IsEmpty() || g.Exact() {
		t.Errorf("Deny NotAction: %s exact %v", g.Admits, g.Exact())
	}
	// Trace C: every construct that widens an Allow flips a Deny.
	conditions := map[string]string{
		"IgnoreCase":     `{"StringEqualsIgnoreCase": {"` + gh("sub") + `": "x"}}`,
		"IfExists":       `{"StringEqualsIfExists": {"` + gh("sub") + `": "x"}}`,
		"Null":           `{"Null": {"` + gh("sub") + `": "false"}}`,
		"ForAllValues":   `{"ForAllValues:StringLike": {"` + gh("sub") + `": "x"}}`,
		"ForAnyValue":    `{"ForAnyValue:StringEquals": {"` + gh("sub") + `": "x"}}`,
		"duplicate key":  `{"StringEquals": {"` + gh("sub") + `": "x", "` + gh("sub") + `": "y"}}`,
		"variable":       `{"StringEquals": {"` + gh("sub") + `": "${aws:username}"}}`,
		"operator":       `{"ArnLike": {"` + gh("sub") + `": "x"}}`,
		"request key":    `{"StringEquals": {"aws:SourceIp": "x"}}`,
		"empty list":     `{"StringEquals": {"` + gh("sub") + `": []}}`,
		"malformed leaf": `{"StringEquals": {"` + gh("sub") + `": 1}}`,
		"mixed":          `{"StringEquals": {"` + gh("aud") + `": "x"}, "StringNotEquals": {"` + gh("sub") + `": "y"}}`,
	}
	for name, condition := range conditions {
		g := oneGrant(t, statement(`"Effect": "Deny", "Principal": {"Federated": "`+githubProvider+`"}, "Action": "sts:AssumeRoleWithWebIdentity", "Condition": `+condition))
		if !g.Admits.IsEmpty() || g.Exact() || !hasCaveatOn(g, "") {
			t.Errorf("Deny with %s: %s exact %v caveats %v; want nothing denied, declared", name, g.Admits, g.Exact(), g.Admits.Caveats())
		}
		if a, ok := findAnomaly(g, trust.Unmodelled, "Deny"); !ok || a.Message != wantDenyNotApplied {
			t.Errorf("Deny with %s: anomaly = %+v, %v", name, a, ok)
		}
	}
	// An unknown vocabulary is an Unknown like any other.
	g = mustParse(t, statement(`"Effect": "Deny", "Principal": {"Federated": "arn:aws:iam::123456789012:oidc-provider/gitlab.com"}, "Action": "sts:AssumeRoleWithWebIdentity", "Condition": {"StringEquals": {"gitlab.com:sub": "x"}}`)).Grants(role, nil)[0]
	if !g.Admits.IsEmpty() || g.Exact() {
		t.Errorf("Deny on an issuer without a vocabulary: %s exact %v", g.Admits, g.Exact())
	}
	// A fully modelled Deny keeps its exact denied set.
	g = oneGrant(t, statement(`"Effect": "Deny", "Principal": {"Federated": "`+githubProvider+`"}, "Action": "sts:AssumeRoleWithWebIdentity", "Condition": {"StringEquals": {"`+gh("aud")+`": "sts.amazonaws.com"}, "StringLike": {"`+gh("sub")+`": "repo:acme/infra:*"}}`))
	if want := `{aud="sts.amazonaws.com", sub=like:"repo:acme/infra:*"}`; g.Admits.String() != want || !g.Exact() || g.Effect != trust.Deny {
		t.Errorf("modelled Deny = %s exact %v effect %q; want %s exact", g.Admits, g.Exact(), g.Effect, want)
	}
	if _, ok := findAnomaly(g, trust.Unmodelled, "Deny"); ok {
		t.Errorf("a Deny that was applied carries no Deny anomaly: %v", g.Anomalies)
	}
	// A Deny whose actions do not cover the assume action denies nothing,
	// exactly: the action test is exact.
	g = oneGrant(t, statement(`"Effect": "Deny", "Principal": {"Federated": "`+githubProvider+`"}, "Action": "s3:*", "Condition": {"StringEquals": {"`+gh("sub")+`": "x"}}`))
	if !g.Admits.IsEmpty() || !g.Exact() {
		t.Errorf("Deny without the assume action: %s exact %v", g.Admits, g.Exact())
	}
	// A Deny on a foreign key stays exact: it denies GitHub tokens nothing,
	// and that is what AWS does with a positive operator on an absent key.
	g = oneGrant(t, statement(`"Effect": "Deny", "Principal": {"Federated": "`+githubProvider+`"}, "Action": "sts:AssumeRoleWithWebIdentity", "Condition": {"StringEquals": {"gitlab.com:sub": "x"}}`))
	if g.Admits.String() != `{gitlab.com:sub="x"}` || !g.Exact() {
		t.Errorf("Deny on a foreign key: %s exact %v", g.Admits, g.Exact())
	}
}

// TestEffectUnknownIsProjectedAsAllow: a malformed effect is read as
// possibly Allow, so its Unknowns widen rather than flip.
func TestEffectUnknownIsProjectedAsAllow(t *testing.T) {
	g := oneGrant(t, statement(`"Effect": "deny", "Principal": {"Federated": "`+githubProvider+`"}, "Action": "sts:AssumeRoleWithWebIdentity", "Condition": {"StringEqualsIfExists": {"`+gh("sub")+`": "x"}}`))
	if g.Effect != trust.EffectUnknown || !g.Admits.IsTop() || g.Exact() {
		t.Errorf("grant = effect %q, admits %s, exact %v; want possibly-Allow admitting everything, declared", g.Effect, g.Admits, g.Exact())
	}
	if _, ok := findAnomaly(g, trust.Unmodelled, "Deny"); ok {
		t.Errorf("a malformed effect is not a Deny: %v", g.Anomalies)
	}
}

func TestWholeGrantUnknownCarriesAnEmptyClaimCaveat(t *testing.T) {
	g := oneGrant(t, statement(`"Effect": "Allow", "Principal": {"Federated": "`+githubProvider+`"}, "NotAction": "s3:*", "Condition": {"StringEquals": {"`+gh("sub")+`": "x"}}`))
	want := eval.Caveat{Claim: "", Reason: "NotAction grants every action but the ones listed; this parser does not compute that complement, so which actions the statement grants is not known", Source: "statement[0].Action"}
	if c := g.Admits.Caveats(); len(c) != 1 || c[0] != want {
		t.Errorf("caveats = %v, want %v", c, want)
	}
	if !g.Admits.IsTop() {
		t.Errorf("a whole-grant Unknown admits everything: %s", g.Admits)
	}
}

// TestAWSIdentityKeysAreClaims: for AWS principals the caller's identity is
// what the keys describe, so aws:PrincipalArn and its kin are claims of
// the pseudo-issuer, and the principal itself is a constraint on them.
func TestAWSIdentityKeysAreClaims(t *testing.T) {
	g := awsFace(t, statement(`"Effect": "Allow", "Principal": "*", "Action": "sts:AssumeRole", "Condition": {
		"StringEquals": {"aws:PrincipalArn": "arn:aws:iam::123456789012:role/ci", "sts:ExternalId": "secret"},
		"StringLike": {"aws:PrincipalOrgID": "o-*"}
	}`))
	want := `{aws:principalarn="arn:aws:iam::123456789012:role/ci", aws:principalorgid=like:"o-*", sts:externalid="secret"}`
	if g.Admits.String() != want || !g.Exact() || g.Issuer != AWSPrincipalIssuer {
		t.Errorf("Admits = %s, exact %v, issuer %q; want %s exact", g.Admits, g.Exact(), g.Issuer, want)
	}
	if !g.Admits.Admits(token{"aws:principalarn": "arn:aws:iam::123456789012:role/ci", "aws:principalorgid": "o-abc", "sts:externalid": "secret"}) {
		t.Errorf("the intended caller is admitted")
	}
	arn := awsFace(t, statement(`"Effect": "Allow", "Principal": "*", "Action": "sts:AssumeRole", "Condition": {"ArnLike": {"aws:PrincipalArn": "arn:aws:iam::123456789012:role/*"}}`))
	if a, ok := findAnomaly(arn, trust.Unmodelled, "ArnLike"); !ok || a.Claim != "aws:principalarn" || !hasCaveatOn(arn, "aws:principalarn") {
		t.Errorf("ArnLike on an identity key is an unmodelled operator: %+v %v", a, ok)
	}
	ip := awsFace(t, statement(`"Effect": "Allow", "Principal": "*", "Action": "sts:AssumeRole", "Condition": {"IpAddress": {"aws:SourceIp": "203.0.113.0/24"}}`))
	if a, ok := findAnomaly(ip, trust.Unmodelled, "aws:SourceIp"); !ok || !hasCaveatOn(ip, "aws:sourceip") {
		t.Errorf("a request key on the anonymous principal is Unknown: %+v %v", a, ok)
	}
	account := oneGrant(t, statement(`"Effect": "Allow", "Principal": {"AWS": "123456789012"}, "Action": "sts:AssumeRole", "Condition": {"StringEquals": {"aws:PrincipalArn": "arn:aws:iam::123456789012:role/ci"}}`))
	if account.Admits.String() != `{aws:principalaccount="123456789012", aws:principalarn="arn:aws:iam::123456789012:role/ci"}` || !account.Exact() {
		t.Errorf("account principal with an ARN condition: %s", account.Admits)
	}
	root := oneGrant(t, statement(`"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::123456789012:root"}, "Action": "sts:AssumeRole"`))
	if root.Admits.String() != `{aws:principalaccount="123456789012"}` {
		t.Errorf("the root ARN delegates to the account: %s", root.Admits)
	}
	contradiction := oneGrant(t, statement(`"Effect": "Allow", "Principal": {"AWS": "123456789012"}, "Action": "sts:AssumeRole", "Condition": {"StringEquals": {"aws:PrincipalAccount": "999999999999"}}`))
	if !contradiction.Admits.IsEmpty() || !contradiction.Exact() {
		t.Errorf("an account principal conditioned on another account admits nothing: %s", contradiction.Admits)
	}
	user := oneGrant(t, statement(`"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::123456789012:user/alice"}, "Action": "sts:AssumeRole"`))
	if user.Admits.String() != `{aws:principalaccount="123456789012", aws:principalarn="arn:aws:iam::123456789012:user/alice"}` {
		t.Errorf("user principal: %s", user.Admits)
	}
	// A role session ARN is not a value aws:PrincipalArn ever carries, so
	// it constrains the account and leaves the ARN Unknown, declared.
	session := oneGrant(t, statement(`"Effect": "Allow", "Principal": {"AWS": "arn:aws:sts::123456789012:assumed-role/ci/session"}, "Action": "sts:AssumeRole"`))
	if session.Admits.String() != `{aws:principalaccount="123456789012", aws:principalarn=?("arn:aws:sts::123456789012:assumed-role/ci/session")}` || session.Exact() || !hasCaveatOn(session, "aws:principalarn") {
		t.Errorf("session principal: %s exact %v", session.Admits, session.Exact())
	}
}

// TestAnyoneWithAForeignKeyIsUnknown: with every principal admitted, the
// parser cannot say which provider populates a provider-prefixed key, so
// it is not a constraint it can evaluate.
func TestAnyoneWithAForeignKeyIsUnknown(t *testing.T) {
	gs := grantsOf(t, statement(`"Effect": "Allow", "Principal": "*", "Action": "sts:AssumeRoleWithWebIdentity", "Condition": {"StringEquals": {"`+gh("sub")+`": "`+mainBranch+`"}}`))
	if len(gs) != 2 {
		t.Fatalf("%d grants, want the AWS face and the federated face", len(gs))
	}
	for _, g := range gs {
		if g.Issuer == AWSPrincipalIssuer {
			// No AWS principal assumes through the web identity action.
			if !g.Admits.IsEmpty() || !g.Exact() {
				t.Errorf("AWS face: %s exact %v; want nothing, exactly", g.Admits, g.Exact())
			}
			continue
		}
		if !g.Admits.IsTop() || g.Exact() || !hasCaveatOn(g, trust.ClaimKey(gh("sub"))) {
			t.Errorf("federated face: Admits = %s, exact %v, caveats %v", g.Admits, g.Exact(), g.Admits.Caveats())
		}
		a, ok := findAnomaly(g, trust.Unmodelled, gh("sub"))
		if !ok || a.Message != `the condition key "`+gh("sub")+`" is a claim of a provider this statement does not name; with every principal admitted, which provider populates it is not known, so the claim is not constrained` {
			t.Errorf("anomaly = %+v, %v", a, ok)
		}
	}
}

func TestOpaqueAWSPrincipalIsUnknown(t *testing.T) {
	g := oneGrant(t, statement(`"Effect": "Allow", "Principal": {"AWS": "AROAEXAMPLEID"}, "Action": "sts:AssumeRole"`))
	if g.Issuer != AWSPrincipalIssuer || !g.Admits.IsTop() || g.Exact() || !hasCaveatOn(g, "aws:principalarn") {
		t.Errorf("grant = issuer %q, admits %s, exact %v, caveats %v", g.Issuer, g.Admits, g.Exact(), g.Admits.Caveats())
	}
	a, ok := findAnomaly(g, trust.Unmodelled, "AROAEXAMPLEID")
	if !ok || a.Claim != "aws:principalarn" || a.Message != `the AWS principal "AROAEXAMPLEID" is neither an account id nor an ARN; it may be the unique id of a principal that has been deleted, so who it names is not known` {
		t.Errorf("anomaly = %+v, %v", a, ok)
	}
	// An ARN of a service that names no principal is opaque too, and says so.
	g = oneGrant(t, statement(`"Effect": "Allow", "Principal": {"AWS": "arn:aws:s3:::bucket"}, "Action": "sts:AssumeRole"`))
	if a, ok := findAnomaly(g, trust.Unmodelled, "arn:aws:s3:::bucket"); !ok || !g.Admits.IsTop() || g.Exact() || a.Message != `the AWS principal "arn:aws:s3:::bucket" is an ARN of a service other than IAM or STS, which names no principal this parser knows, so who it names is not known` {
		t.Errorf("s3 ARN as a principal: admits %s exact %v anomaly %+v %v", g.Admits, g.Exact(), a, ok)
	}
	// Twelve characters are an account id only when every one is a digit.
	for _, text := range []string{"AIDAEXAMPLE1", "12345678901a", "1234567890123", "12345678901"} {
		g := oneGrant(t, statement(`"Effect": "Allow", "Principal": {"AWS": "`+text+`"}, "Action": "sts:AssumeRole"`))
		if !g.Admits.IsTop() || g.Exact() {
			t.Errorf("%q: admits %s exact %v; want opaque", text, g.Admits, g.Exact())
		}
	}
	// A root ARN with no account names every principal of no account: who
	// it names is not known, and it must not read as everyone, exactly.
	g = oneGrant(t, statement(`"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam:::root"}, "Action": "sts:AssumeRole"`))
	if !g.Admits.IsTop() || g.Exact() || !hasCaveatOn(g, "aws:principalaccount") {
		t.Errorf("root ARN without an account: %s exact %v caveats %v; want everything, declared on the account", g.Admits, g.Exact(), g.Admits.Caveats())
	}
	if a, ok := findAnomaly(g, trust.Unmodelled, "arn:aws:iam:::root"); !ok || a.Claim != "aws:principalaccount" || a.Message != `the AWS principal "arn:aws:iam:::root" is a root ARN with no account id, so which account it names is not known` {
		t.Errorf("root ARN without an account: anomaly = %+v, %v", a, ok)
	}
	if deny := oneGrant(t, statement(`"Effect": "Deny", "Principal": {"AWS": "arn:aws:iam:::root"}, "Action": "sts:AssumeRole"`)); !deny.Admits.IsEmpty() || deny.Exact() {
		t.Errorf("a Deny on it is not applied: %s exact %v", deny.Admits, deny.Exact())
	}
	// An ARN whose account field is empty names no principal AWS documents:
	// every IAM and STS principal ARN carries a 12-digit account.
	g = oneGrant(t, statement(`"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam:::role/ci"}, "Action": "sts:AssumeRole"`))
	if !g.Admits.IsTop() || g.Exact() || !hasCaveatOn(g, "aws:principalarn") {
		t.Errorf("ARN without an account: %s exact %v", g.Admits, g.Exact())
	}
	// Five colon-separated fields are not an ARN, so the text is opaque.
	g = oneGrant(t, statement(`"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::role/ci"}, "Action": "sts:AssumeRole"`))
	if !g.Admits.IsTop() || g.Exact() || !hasCaveatOn(g, "aws:principalarn") {
		t.Errorf("a five-field ARN is opaque: %s exact %v", g.Admits, g.Exact())
	}
}

// TestPrincipalElementShapes pins every way the Principal element can be
// mis-shaped or duplicated, and that each still yields a grant.
func TestPrincipalElementShapes(t *testing.T) {
	cases := []struct {
		name      string
		members   string
		kind      string
		construct string
		want      string
	}{
		{"empty provider", `"Effect": "Allow", "Principal": {"Federated": "arn:aws:iam::123456789012:oidc-provider/"}, "Action": "sts:AssumeRoleWithWebIdentity"`, Malformed, "Federated",
			`the Federated principal "arn:aws:iam::123456789012:oidc-provider/" names no provider, so its issuer is not known`},
		{"unknown federated resource", `"Effect": "Allow", "Principal": {"Federated": "arn:aws:iam::123456789012:foo/bar"}, "Action": "sts:AssumeRoleWithWebIdentity"`, trust.Unmodelled, "Federated",
			`the Federated principal "arn:aws:iam::123456789012:foo/bar" is neither an OIDC nor a SAML provider, so its issuer is not known`},
		{"not an iam arn", `"Effect": "Allow", "Principal": {"Federated": "arn:aws:s3:::bucket"}, "Action": "sts:AssumeRoleWithWebIdentity"`, Malformed, "Federated",
			`the Federated principal "arn:aws:s3:::bucket" is not an IAM provider ARN, so its issuer is not known`},
		{"short arn", `"Effect": "Allow", "Principal": {"Federated": "arn:aws:iam:oidc-provider/x"}, "Action": "sts:AssumeRoleWithWebIdentity"`, Malformed, "Federated",
			`the Federated principal "arn:aws:iam:oidc-provider/x" is not an IAM provider ARN, so its issuer is not known`},
		{"federated star", `"Effect": "Allow", "Principal": {"Federated": "*"}, "Action": "sts:AssumeRoleWithWebIdentity"`, Malformed, "Federated",
			`the Federated principal "*" is not a provider identifier, so its issuer is not known`},
		{"federated empty", `"Effect": "Allow", "Principal": {"Federated": ""}, "Action": "sts:AssumeRoleWithWebIdentity"`, Malformed, "Federated",
			`the Federated principal "" is not a provider identifier, so its issuer is not known`},
		{"service star", `"Effect": "Allow", "Principal": {"Service": "*"}, "Action": "sts:AssumeRole"`, Malformed, "Service",
			`the Service principal "*" is not a service identifier, so which service it names is not known`},
		{"federated number", `"Effect": "Allow", "Principal": {"Federated": 5}, "Action": "sts:AssumeRoleWithWebIdentity"`, Malformed, "Federated",
			`the Federated principal is a number (5) where a string or a list of strings is expected, so who it names is not known`},
		{"aws list with a null", `"Effect": "Allow", "Principal": {"AWS": [null]}, "Action": "sts:AssumeRole"`, Malformed, "AWS",
			`the AWS principal lists null (null) where a string is expected, so who it names is not known`},
		{"aws object", `"Effect": "Allow", "Principal": {"AWS": {"x": 1}}, "Action": "sts:AssumeRole"`, Malformed, "AWS",
			`the AWS principal is an object ({"x": 1}) where a string or a list of strings is expected, so who it names is not known`},
		{"principal list", `"Effect": "Allow", "Principal": ["*"], "Action": "sts:AssumeRole"`, Malformed, "Principal",
			`Principal is a list (["*"]), not "*" or an object, so who it names is not known`},
		{"principal empty object", `"Effect": "Allow", "Principal": {}, "Action": "sts:AssumeRole"`, trust.Unmodelled, "Principal",
			"the statement names no Principal, so who may assume the role through it is not known"},
		{"principal and notprincipal", `"Effect": "Deny", "Principal": "*", "NotPrincipal": {"AWS": "123456789012"}, "Action": "sts:AssumeRole"`, DuplicateKey, "Principal",
			"the statement has both Principal and NotPrincipal; the IAM grammar allows one, so who it names is not known"},
		{"action and notaction", `"Effect": "Allow", "Principal": {"Federated": "` + githubProvider + `"}, "Action": "sts:AssumeRoleWithWebIdentity", "NotAction": "s3:*"`, DuplicateKey, "Action",
			"the statement has both Action and NotAction; the IAM grammar allows one, so which actions the statement grants is not known"},
		{"no action", `"Effect": "Allow", "Principal": {"Federated": "` + githubProvider + `"}`, trust.Unmodelled, "Action",
			"the statement has neither Action nor NotAction, so which actions the statement grants is not known"},
		{"action number", `"Effect": "Allow", "Principal": {"Federated": "` + githubProvider + `"}, "Action": 5`, Malformed, "Action",
			"Action is a number (5) where a string or a list of strings is expected, so which actions the statement grants is not known"},
		{"action list with a number", `"Effect": "Allow", "Principal": {"Federated": "` + githubProvider + `"}, "Action": ["sts:AssumeRoleWithWebIdentity", 5]`, Malformed, "Action",
			"Action lists a number (5) where a string is expected, so which actions the statement grants is not known"},
		{"duplicate action", `"Effect": "Allow", "Principal": {"Federated": "` + githubProvider + `"}, "Action": "s3:*", "Action": "sts:AssumeRoleWithWebIdentity"`, DuplicateKey, "Action",
			"the member Action appears more than once in the statement; a JSON decoder keeps one and the deployed policy may carry either, so which actions the statement grants is not known"},
		{"duplicate notaction", `"Effect": "Allow", "Principal": {"Federated": "` + githubProvider + `"}, "NotAction": "s3:*", "NotAction": "iam:*"`, DuplicateKey, "NotAction",
			"the member NotAction appears more than once in the statement; a JSON decoder keeps one and the deployed policy may carry either, so which actions the statement grants is not known"},
		{"empty action list", `"Effect": "Allow", "Principal": {"Federated": "` + githubProvider + `"}, "Action": []`, Malformed, "Action",
			"Action lists no actions; the IAM grammar requires at least one, so which actions the statement grants is not known"},
		{"duplicate notprincipal", `"Effect": "Allow", "NotPrincipal": {"AWS": "123456789012"}, "NotPrincipal": "*", "Action": "sts:AssumeRole"`, DuplicateKey, "NotPrincipal",
			"the member NotPrincipal appears more than once in the statement; a JSON decoder keeps one and the deployed policy may carry either, so who it excludes is not known"},
		{"duplicate condition", `"Effect": "Allow", "Principal": {"Federated": "` + githubProvider + `"}, "Action": "sts:AssumeRoleWithWebIdentity", "Condition": {}, "Condition": {}`, DuplicateKey, "Condition",
			"the member Condition appears more than once in the statement; a JSON decoder keeps one and the deployed policy may carry either, so what the conditions require is not known"},
		{"duplicate principal", `"Effect": "Allow", "Principal": {"Federated": "` + githubProvider + `"}, "Principal": "*", "Action": "sts:AssumeRoleWithWebIdentity"`, DuplicateKey, "Principal",
			"the member Principal appears more than once in the statement; a JSON decoder keeps one and the deployed policy may carry either, so every principal named in any copy is taken and who the statement names is not known"},
		{"unknown member", `"Effect": "Allow", "Principal": {"Federated": "` + githubProvider + `"}, "Action": "sts:AssumeRoleWithWebIdentity", "NotResource": "*"`, trust.Unmodelled, "NotResource",
			`the statement member "NotResource" is not one this parser models, so what it does to the statement is not known`},
	}
	for _, c := range cases {
		gs := grantsOf(t, statement(c.members))
		if len(gs) == 0 {
			t.Errorf("%s: no grant", c.name)
			continue
		}
		matched := false
		for _, g := range gs {
			a, ok := findAnomaly(g, c.kind, c.construct)
			if !ok {
				continue
			}
			if a.Message != c.want {
				t.Errorf("%s: message %q, want %q", c.name, a.Message, c.want)
			}
			// A face the action test emptied admits nothing, exactly, whatever
			// else the statement says: the AWS face of "*" under the web
			// identity action here.
			if _, emptied := findAnomaly(g, NotAnAssumeAction, "Action"); emptied {
				continue
			}
			matched = true
			if !hasCaveatOn(g, "") {
				t.Errorf("%s: no whole-grant caveat: %v", c.name, g.Admits.Caveats())
			}
			if g.Effect != trust.Deny && !g.Admits.IsTop() {
				t.Errorf("%s: admits %s, want everything", c.name, g.Admits)
			}
		}
		if !matched {
			t.Errorf("%s: no %s anomaly on %s in %+v", c.name, c.kind, c.construct, gs)
		}
	}
	// A duplicate member inside Principal names every principal in either
	// copy, each as an upper bound: which copy is deployed is not known.
	gs := grantsOf(t, statement(`"Effect": "Allow", "Principal": {"Federated": "`+githubProvider+`", "Federated": "arn:aws:iam::123456789012:oidc-provider/gitlab.com"}, "Action": "sts:AssumeRoleWithWebIdentity"`))
	if len(gs) != 2 {
		t.Fatalf("%d grants, want the union of both copies", len(gs))
	}
	for _, g := range gs {
		if a, ok := findAnomaly(g, DuplicateKey, "Federated"); !ok || a.Message != "the member Federated appears more than once in Principal; a JSON decoder keeps one and the deployed policy may carry either, so whether this principal is deployed is not known" || g.Exact() || !hasCaveatOn(g, "") {
			t.Errorf("duplicate inside Principal: %+v %v exact %v", a, ok, g.Exact())
		}
	}
	// An empty list under a kind names nobody and is outside the grammar,
	// which gives arrays one or more values; whether such a document
	// deploys as written is not known, so the grants beside it are upper
	// bounds and the fact is stated. Dropping it said nothing.
	for _, c := range []struct{ members, kind, admits string }{
		{`"Effect": "Allow", "Principal": {"AWS": "123456789012", "Federated": []}, "Action": "sts:AssumeRole"`, "Federated", `{aws:principalaccount="123456789012"}`},
		{`"Effect": "Allow", "Principal": {"AWS": [], "Federated": "` + githubProvider + `"}, "Action": "sts:AssumeRoleWithWebIdentity", "Condition": {"StringEquals": {"` + gh("sub") + `": "x"}}`, "AWS", `{sub="x"}`},
		{`"Effect": "Deny", "Principal": {"AWS": [], "Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"`, "AWS", "∅"},
	} {
		g := oneGrant(t, statement(c.members))
		want := "the " + c.kind + " principal lists no principals; the IAM grammar requires at least one, so whether the statement deploys as written is not known"
		if a, ok := findAnomaly(g, Malformed, c.kind); !ok || a.Message != want || a.Source != "statement[0].Principal" {
			t.Errorf("%s: anomaly = %+v, %v; want %q", c.members, a, ok, want)
		}
		if g.Exact() || !hasCaveatOn(g, "") {
			t.Errorf("%s: exact %v, caveats %v; the grant beside an empty list is an upper bound", c.members, g.Exact(), g.Admits.Caveats())
		}
		// The readable principal keeps its own set; a doubted Deny is not applied.
		if g.Admits.String() != c.admits {
			t.Errorf("%s: admits %s, want %s", c.members, g.Admits, c.admits)
		}
	}
	alone := oneGrant(t, statement(`"Effect": "Allow", "Principal": {"Federated": []}, "Action": "sts:AssumeRole"`))
	if _, ok := findAnomaly(alone, Malformed, "Federated"); !ok || !alone.Admits.IsTop() || alone.Exact() {
		t.Errorf("an empty list alone: %+v", alone)
	}
	if _, ok := findAnomaly(alone, trust.Unmodelled, "Principal"); !ok {
		t.Errorf("an empty list alone names no principal: %v", alone.Anomalies)
	}
	// A readable principal beside an unreadable one keeps its grant.
	gs = grantsOf(t, statement(`"Effect": "Allow", "Principal": {"Federated": ["`+githubProvider+`", 5]}, "Action": "sts:AssumeRoleWithWebIdentity"`))
	if len(gs) != 2 {
		t.Fatalf("%d grants, want 2", len(gs))
	}
	var issuers []string
	for _, g := range gs {
		issuers = append(issuers, string(g.Issuer))
	}
	slices.Sort(issuers)
	if issuers[0] != "" || issuers[1] != string(githubIssuer) {
		t.Errorf("issuers = %v", issuers)
	}
	// A duplicate Sid is noted and nothing else.
	g := oneGrant(t, statement(`"Sid": "a", "Sid": "b", "Effect": "Allow", "Principal": {"Federated": "`+githubProvider+`"}, "Action": "sts:AssumeRoleWithWebIdentity"`))
	if a, ok := findAnomaly(g, DuplicateKey, "Sid"); !ok || a.Message != "the member Sid appears more than once in the statement" || !g.Exact() {
		t.Errorf("duplicate Sid: %+v %v exact %v", a, ok, g.Exact())
	}
}

// TestGrantsDoNotDependOnStatementOrder: the same statements in another
// order are the same grants, and the output order does not depend on the
// input order beyond what the statement index in Source strings records.
func TestGrantsDoNotDependOnStatementOrder(t *testing.T) {
	a := `{"Effect": "Allow", "Principal": {"Federated": "` + githubProvider + `"}, "Action": "sts:AssumeRoleWithWebIdentity", "Condition": {"StringEquals": {"` + gh("sub") + `": "` + mainBranch + `"}}}`
	b := `{"Effect": "Deny", "Principal": {"Federated": "arn:aws:iam::123456789012:oidc-provider/gitlab.com"}, "Action": "sts:AssumeRoleWithWebIdentity", "Condition": {"StringNotEquals": {"gitlab.com:sub": "x"}}}`
	c := `{"Effect": "Allow", "Principal": "*", "Action": "sts:AssumeRole"}`
	d := `{"Effect": "Allow", "Principal": {"Federated": "` + githubProvider + `"}, "NotAction": "s3:*"}`
	forward := grantsOf(t, `{"Version": "2012-10-17", "Statement": [`+a+`,`+b+`,`+c+`,`+d+`]}`)
	backward := grantsOf(t, `{"Version": "2012-10-17", "Statement": [`+d+`,`+c+`,`+b+`,`+a+`]}`)
	// Four statements, five grants: "*" is two faces.
	if len(forward) != 5 || len(backward) != 5 {
		t.Fatalf("%d and %d grants", len(forward), len(backward))
	}
	if x, y := semanticsOf(forward), semanticsOf(backward); !slices.Equal(x, y) {
		t.Errorf("statement order changed the grants:\n%v\n%v", x, y)
	}
	// Repeated projection renders identically: nothing ranges over a map.
	first := semanticsOf(forward)
	for i := 0; i < 50; i++ {
		if again := semanticsOf(grantsOf(t, `{"Version": "2012-10-17", "Statement": [`+a+`,`+b+`,`+c+`,`+d+`]}`)); !slices.Equal(first, again) {
			t.Fatalf("run %d rendered differently", i)
		}
	}
	// Two grants that differ only in source are still two grants, in a
	// stable order.
	twice := grantsOf(t, `{"Version": "2012-10-17", "Statement": [`+a+`,`+a+`]}`)
	if len(twice) != 2 || twice[0].Admits.String() != twice[1].Admits.String() {
		t.Errorf("identical statements are two grants: %+v", twice)
	}
}

// TestGrantOrderIsCanonical: grants come back sorted by their rendering,
// issuer first, so two documents with the same statements in different
// order return the same slice up to the statement index in Source.
func TestGrantOrderIsCanonical(t *testing.T) {
	github := `{"Effect": "Allow", "Principal": {"Federated": "` + githubProvider + `"}, "Action": "sts:AssumeRoleWithWebIdentity"}`
	gitlab := `{"Effect": "Allow", "Principal": {"Federated": "arn:aws:iam::123456789012:oidc-provider/gitlab.com"}, "Action": "sts:AssumeRoleWithWebIdentity"}`
	anyone := `{"Effect": "Deny", "Principal": "*", "Action": "sts:AssumeRole"}`
	for _, order := range [][]string{{github, gitlab, anyone}, {anyone, gitlab, github}, {gitlab, anyone, github}} {
		gs := grantsOf(t, `{"Version": "2012-10-17", "Statement": [`+strings.Join(order, ",")+`]}`)
		var issuers []string
		for _, g := range gs {
			issuers = append(issuers, string(g.Issuer))
		}
		// The unnamed face of "*" has no issuer and sorts first.
		want := []string{"", string(AWSPrincipalIssuer), "https://gitlab.com", string(githubIssuer)}
		if !slices.Equal(issuers, want) {
			t.Errorf("order %v: issuers %v, want %v", order, issuers, want)
		}
	}
}

// TestConditionAnomaliesSurviveWholeGrantUnknown: an anomaly is a fact
// that survived parsing. A statement the parser cannot evaluate as a whole
// still has conditions, and what they do not do is still worth a sentence;
// a statement whose actions admit nobody likewise.
func TestConditionAnomaliesSurviveWholeGrantUnknown(t *testing.T) {
	notAction := oneGrant(t, statement(`"Effect": "Allow", "Principal": {"Federated": "`+githubProvider+`"}, "NotAction": "s3:*", "Condition": {"ForAllValues:StringLike": {"`+gh("sub")+`": "repo:acme/*"}, "StringEquals": {"`+gh("aud")+`": "sts.amazonaws.com", "`+gh("aud")+`": "other"}}`))
	if !notAction.Admits.IsTop() || notAction.Exact() || !hasCaveatOn(notAction, "") {
		t.Errorf("NotAction: %s exact %v caveats %v", notAction.Admits, notAction.Exact(), notAction.Admits.Caveats())
	}
	for _, construct := range []string{"NotAction", "ForAllValues:StringLike"} {
		if _, ok := findAnomaly(notAction, trust.Unmodelled, construct); !ok {
			t.Errorf("NotAction statement lacks the %s anomaly: %v", construct, notAction.Anomalies)
		}
	}
	if a, ok := findAnomaly(notAction, DuplicateKey, "StringEquals"); !ok || a.Claim != "aud" {
		t.Errorf("NotAction statement lacks the duplicate-key anomaly on aud: %+v %v", a, ok)
	}
	// The actions admit nobody: the set is nothing, exactly, and the facts
	// about the conditions are still stated.
	tagSession := oneGrant(t, statement(`"Effect": "Allow", "Principal": {"Federated": "`+githubProvider+`"}, "Action": "sts:TagSession", "Condition": {"ForAllValues:StringLike": {"`+gh("sub")+`": "repo:acme/*"}}`))
	if !tagSession.Admits.IsEmpty() || !tagSession.Exact() {
		t.Errorf("sts:TagSession alone: %s exact %v; want nothing, exactly", tagSession.Admits, tagSession.Exact())
	}
	for _, c := range []struct{ kind, construct string }{{NotAnAssumeAction, "Action"}, {trust.Unmodelled, "ForAllValues:StringLike"}} {
		if _, ok := findAnomaly(tagSession, c.kind, c.construct); !ok {
			t.Errorf("sts:TagSession statement lacks the %s anomaly on %s: %v", c.kind, c.construct, tagSession.Anomalies)
		}
	}
	// A duplicated operator whose first copy is mis-shaped: both facts.
	twice := oneGrant(t, github(`{"StringEquals": "x", "StringEquals": {"`+gh("sub")+`": "`+mainBranch+`"}}`))
	if _, ok := findAnomaly(twice, Malformed, "StringEquals"); !ok {
		t.Errorf("mis-shaped copy not named: %v", twice.Anomalies)
	}
	if !slices.ContainsFunc(twice.Anomalies, func(a trust.Anomaly) bool {
		return a.Kind == DuplicateKey && a.Construct == "StringEquals" && strings.HasPrefix(a.Message, "the operator StringEquals appears more than once in the Condition")
	}) {
		t.Errorf("duplicated operator not named: %v", twice.Anomalies)
	}
	if !twice.Admits.IsTop() || twice.Exact() {
		t.Errorf("mis-shaped operator block: %s exact %v", twice.Admits, twice.Exact())
	}
}

// TestAnyoneIsScopedByTheAssumeAction: "*" is every AWS principal, which
// assumes through sts:AssumeRole, and every federated identity, which
// assumes through the federated actions. A Deny for "*" on the web
// identity action alone must not subtract from an account's grant, and
// one grant on the pseudo-issuer that any assume action satisfied did.
func TestAnyoneIsScopedByTheAssumeAction(t *testing.T) {
	gs := policyGrants(t, "14-anyone-is-scoped-by-the-assume-action")
	if len(gs) != 5 {
		t.Fatalf("%d grants, want 5: %+v", len(gs), gs)
	}
	account := bySid(gs, "AllowOneAccount")
	if len(account) != 1 || account[0].Issuer != AWSPrincipalIssuer || account[0].Admits.String() != `{aws:principalaccount="111111111111"}` || !account[0].Exact() {
		t.Errorf("account grant = %+v", account)
	}
	deny := bySid(gs, "DenyEveryoneThroughWebIdentity")
	if len(deny) != 2 {
		t.Fatalf("Deny \"*\" projects two faces; got %d: %+v", len(deny), deny)
	}
	for _, g := range deny {
		if !g.Admits.IsEmpty() {
			t.Errorf("Deny face on %q denies %s; nothing assumes through sts:AssumeRole here", g.Issuer, g.Admits)
		}
		if _, ok := findAnomaly(g, AnyPrincipal, "Principal"); !ok {
			t.Errorf("face on %q lacks the any-principal note: %v", g.Issuer, g.Anomalies)
		}
		switch g.Issuer {
		case AWSPrincipalIssuer:
			if !g.Exact() {
				t.Errorf("the AWS face denies nothing exactly: caveats %v", g.Admits.Caveats())
			}
			if a, ok := findAnomaly(g, NotAnAssumeAction, "Action"); !ok || a.Message != "the actions do not include sts:AssumeRole, so this statement lets nobody assume the role through this principal" {
				t.Errorf("AWS face anomaly = %+v, %v", a, ok)
			}
		case "":
			if g.Exact() || !hasCaveatOn(g, "") {
				t.Errorf("the federated face is an upper bound: caveats %v", g.Admits.Caveats())
			}
			if a, ok := findAnomaly(g, trust.Unmodelled, "Principal"); !ok || a.Message != "the statement applies to every principal, and which identity providers' tokens it covers through sts:AssumeRoleWithWebIdentity is not known" {
				t.Errorf("unnamed face anomaly = %+v, %v", a, ok)
			}
			if _, ok := findAnomaly(g, trust.Unmodelled, "Deny"); !ok {
				t.Errorf("the federated Deny says it is not applied: %v", g.Anomalies)
			}
		default:
			t.Errorf("unexpected issuer %q", g.Issuer)
		}
	}
	if !admittedDownstream(gs, AWSPrincipalIssuer, token{"aws:principalaccount": "111111111111", "aws:principalarn": "arn:aws:iam::111111111111:role/x"}) {
		t.Errorf("account 111111111111 assumes through sts:AssumeRole, which the Deny does not name")
	}
	all := bySid(gs, "AllowEveryoneThroughEveryAction")
	if len(all) != 2 {
		t.Fatalf("Allow \"*\" on every action projects two faces; got %d", len(all))
	}
	for _, g := range all {
		if !g.Admits.IsTop() {
			t.Errorf("face on %q admits %s, want everything", g.Issuer, g.Admits)
		}
		if exact := g.Issuer == AWSPrincipalIssuer; g.Exact() != exact {
			t.Errorf("face on %q exact %v; the AWS face is exact, the unnamed face is not", g.Issuer, g.Exact())
		}
		if g.Issuer == "" {
			if a, ok := findAnomaly(g, trust.Unmodelled, "Principal"); !ok || a.Message != "the statement applies to every principal, and which AWS services and identity providers' tokens it covers through sts:AssumeRole, sts:AssumeRoleWithWebIdentity or sts:AssumeRoleWithSAML is not known" {
				t.Errorf("unnamed face under every action: anomaly = %+v, %v", a, ok)
			}
		}
	}
	// With no assume action at all there is only the AWS face, and it says
	// nobody assumes through the statement.
	g := oneGrant(t, statement(`"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject"`))
	if g.Issuer != AWSPrincipalIssuer || !g.Admits.IsEmpty() || !g.Exact() {
		t.Errorf("s3:GetObject: %+v", g)
	}
	for _, action := range []string{"sts:AssumeRole", "sts:AssumeRoleWithSAML", "sts:AssumeRoleWithWebIdentity", "sts:*"} {
		gs := grantsOf(t, statement(`"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "`+action+`"`))
		if len(gs) != 2 {
			t.Errorf("%s: %d grants, want both faces", action, len(gs))
		}
	}
	if gs := grantsOf(t, statement(`"Effect": "Allow", "Principal": "*", "NotAction": "s3:*"`)); len(gs) != 2 {
		t.Errorf("unknown actions: %d grants, want both faces, each unevaluated", len(gs))
	}
}

// TestAnyoneCoversServicesThroughAssumeRole: an AWS service assumes a role
// through sts:AssumeRole, and "*" names services among the principals it
// covers, so "*" on that action is the AWS face and the unnamed face both.
// Projected as the AWS face alone, the role read as trusting no service,
// and a Deny for "*" on sts:AssumeRole never met a service's grant.
func TestAnyoneCoversServicesThroughAssumeRole(t *testing.T) {
	gs := grantsOf(t, statement(`"Effect": "Allow", "Principal": "*", "Action": "sts:AssumeRole"`))
	if len(gs) != 2 {
		t.Fatalf("%d grants, want the AWS face and the unnamed face: %+v", len(gs), gs)
	}
	const want = "the statement applies to every principal, and which AWS services it covers through sts:AssumeRole is not known"
	for _, g := range gs {
		if !g.Admits.IsTop() {
			t.Errorf("face on %q admits %s, want everything", g.Issuer, g.Admits)
		}
		if _, ok := findAnomaly(g, AnyPrincipal, "Principal"); !ok {
			t.Errorf("face on %q lacks the any-principal note: %v", g.Issuer, g.Anomalies)
		}
		switch g.Issuer {
		case AWSPrincipalIssuer:
			if !g.Exact() {
				t.Errorf("the AWS face is exact: caveats %v", g.Admits.Caveats())
			}
		case "":
			if g.Exact() || !hasCaveatOn(g, "") {
				t.Errorf("the unnamed face is an upper bound: caveats %v", g.Admits.Caveats())
			}
			if a, ok := findAnomaly(g, trust.Unmodelled, "Principal"); !ok || a.Message != want || a.Source != "statement[0].Principal" {
				t.Errorf("unnamed face anomaly = %+v, %v; want %q", a, ok, want)
			}
		default:
			t.Errorf("unexpected issuer %q", g.Issuer)
		}
	}
	// A Deny for "*" on sts:AssumeRole beside a service's Allow: the Deny's
	// unnamed face is not applied, and says so, rather than leaving the
	// service's grant untouched in silence.
	gs = grantsOf(t, `{"Version": "2012-10-17", "Statement": [
		{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"},
		{"Effect": "Deny", "Principal": "*", "Action": "sts:AssumeRole"}
	]}`)
	if len(gs) != 3 {
		t.Fatalf("%d grants, want 3", len(gs))
	}
	denies := 0
	for _, g := range gs {
		if g.Effect != trust.Deny {
			continue
		}
		denies++
		switch g.Issuer {
		case AWSPrincipalIssuer:
			if !g.Admits.IsTop() || !g.Exact() {
				t.Errorf("the AWS face of the Deny denies every AWS principal, exactly: %s exact %v", g.Admits, g.Exact())
			}
		case "":
			if !g.Admits.IsEmpty() || g.Exact() {
				t.Errorf("the unnamed face of the Deny is not applied: %s exact %v", g.Admits, g.Exact())
			}
			if _, ok := findAnomaly(g, trust.Unmodelled, "Deny"); !ok {
				t.Errorf("the unnamed Deny says it is not applied: %v", g.Anomalies)
			}
		default:
			t.Errorf("unexpected Deny issuer %q", g.Issuer)
		}
	}
	if denies != 2 {
		t.Errorf("%d Deny grants, want both faces", denies)
	}
	// The sentence names only the assume actions the statement grants.
	sentences := map[string]string{
		`"Action": "sts:AssumeRoleWithSAML"`:                            "the statement applies to every principal, and which identity providers' tokens it covers through sts:AssumeRoleWithSAML is not known",
		`"Action": ["sts:AssumeRole", "sts:AssumeRoleWithWebIdentity"]`: "the statement applies to every principal, and which AWS services and identity providers' tokens it covers through sts:AssumeRole or sts:AssumeRoleWithWebIdentity is not known",
		`"NotAction": "s3:*"`:                                           "the statement applies to every principal, and which AWS services and identity providers' tokens it covers through sts:AssumeRole, sts:AssumeRoleWithWebIdentity or sts:AssumeRoleWithSAML is not known",
	}
	for action, want := range sentences {
		gs := grantsOf(t, statement(`"Effect": "Allow", "Principal": "*", `+action))
		if len(gs) != 2 || gs[0].Issuer != "" {
			t.Fatalf("%s: grants = %+v; want the unnamed face first", action, gs)
		}
		if a, ok := findAnomaly(gs[0], trust.Unmodelled, "Principal"); !ok || a.Message != want {
			t.Errorf("%s: anomaly = %+v, %v; want %q", action, a, ok, want)
		}
	}
}

// TestServicePrincipalHasItsOwnIssuer: a service principal and a federated
// built-in provider can share a host, cognito-identity.amazonaws.com, and
// they are two principal kinds on two actions. On one issuer, an exact Deny
// on the service subtracted every federated identity from the Allow.
func TestServicePrincipalHasItsOwnIssuer(t *testing.T) {
	const cognito = trust.IssuerRef("https://cognito-identity.amazonaws.com")
	gs := mustParse(t, string(readPolicy(t, "22-service-and-federated-share-a-host"))).Grants(role, LowercaseVocabulary(githubIssuer, cognito))
	if len(gs) != 2 {
		t.Fatalf("%d grants, want 2", len(gs))
	}
	allow := bySid(gs, "AllowCognitoIdentities")
	if len(allow) != 1 || allow[0].Issuer != cognito || allow[0].Admits.String() != `{aud="us-east-1:0f2b7c1e-5a3d-4e6f-9b8a-1c2d3e4f5a6b"}` || !allow[0].Exact() {
		t.Errorf("federated Cognito grant = %+v", allow)
	}
	deny := bySid(gs, "DenyTheCognitoService")
	if len(deny) != 1 || deny[0].Issuer != "aws:service:cognito-identity.amazonaws.com" || !deny[0].Admits.IsTop() || !deny[0].Exact() {
		t.Errorf("service Deny = %+v; want the service's own issuer, everything, exactly", deny)
	}
	if a, ok := findAnomaly(deny[0], ServicePrincipal, "Service"); !ok || a.Message != "cognito-identity.amazonaws.com is an AWS service principal, not an external identity" {
		t.Errorf("service anomaly = %+v, %v", a, ok)
	}
	if !admittedDownstream(gs, cognito, token{"aud": "us-east-1:0f2b7c1e-5a3d-4e6f-9b8a-1c2d3e4f5a6b"}) {
		t.Errorf("the Cognito identity is admitted by the Allow and subtracted by nothing")
	}
	// The issuer is the prefix and the service's name, ASCII lower-cased: a
	// service principal is a DNS name.
	for _, c := range []struct{ service, issuer string }{
		{"ec2.amazonaws.com", "aws:service:ec2.amazonaws.com"},
		{"EC2.amazonaws.com", "aws:service:ec2.amazonaws.com"},
		{"s3.ap-east-1.amazonaws.com", "aws:service:s3.ap-east-1.amazonaws.com"},
	} {
		g := oneGrant(t, statement(`"Effect": "Allow", "Principal": {"Service": "`+c.service+`"}, "Action": "sts:AssumeRole"`))
		if string(g.Issuer) != c.issuer || !strings.HasPrefix(string(g.Issuer), ServiceIssuerPrefix) {
			t.Errorf("%s: issuer %q, want %q", c.service, g.Issuer, c.issuer)
		}
	}
}

// TestValuesThatAreNotPrincipalsAreUnknown: an AWS principal value that
// AWS documents as not a principal, or that has a shape no IAM or STS
// principal ARN has, is not an exact identity. Read as one it claimed a
// role literally named "*", exactly, with no anomaly.
func TestValuesThatAreNotPrincipalsAreUnknown(t *testing.T) {
	gs := policyGrants(t, "23-values-that-are-not-principals")
	if len(gs) != 7 {
		t.Fatalf("%d grants, want 7", len(gs))
	}
	const account = `aws:principalaccount="123456789012", `
	cases := []struct {
		sid, value, admits, want string
	}{
		{"WildcardInsideARoleArn", "arn:aws:iam::123456789012:role/*", account + `aws:principalarn=?("arn:aws:iam::123456789012:role/*")`,
			"holds a wildcard, which AWS documents cannot match part of a principal name or ARN, so who it names is not known"},
		{"GroupArn", "arn:aws:iam::123456789012:group/admins", account + `aws:principalarn=?("arn:aws:iam::123456789012:group/admins")`,
			"names no account root, role or user, which are the IAM principals AWS documents, so who it names is not known"},
		{"ProviderArnUnderTheAWSKind", "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com", account + `aws:principalarn=?("arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com")`,
			"names no account root, role or user, which are the IAM principals AWS documents, so who it names is not known"},
		{"NoResource", "arn:aws:iam::123456789012:", account + `aws:principalarn=?("arn:aws:iam::123456789012:")`,
			"names no account root, role or user, which are the IAM principals AWS documents, so who it names is not known"},
		// No account constraint, since acme is not an account, and an Unknown
		// alone is everything.
		{"AccountThatIsNotAnId", "arn:aws:iam::acme:role/ci", ``,
			`has "acme" where a 12-digit account id belongs, so who it names is not known`},
		{"RegionInAnIamArn", "arn:aws:iam:us-east-1:123456789012:role/ci", account + `aws:principalarn=?("arn:aws:iam:us-east-1:123456789012:role/ci")`,
			"names a region, which an IAM or STS principal ARN never has, so who it names is not known"},
	}
	for _, c := range cases {
		g := bySid(gs, c.sid)
		if len(g) != 1 {
			t.Fatalf("%s: %d grants", c.sid, len(g))
		}
		if g[0].Issuer != AWSPrincipalIssuer || g[0].Admits.String() != "{"+c.admits+"}" || g[0].Exact() || !hasCaveatOn(g[0], "aws:principalarn") {
			t.Errorf("%s: issuer %q, admits %s, exact %v, caveats %v; want {%s} declared on the ARN", c.sid, g[0].Issuer, g[0].Admits, g[0].Exact(), g[0].Admits.Caveats(), c.admits)
		}
		want := "the AWS principal " + strconv.Quote(c.value) + " " + c.want
		if a, ok := findAnomaly(g[0], Malformed, c.value); !ok || a.Claim != "aws:principalarn" || a.Message != want {
			t.Errorf("%s: anomaly = %+v, %v; want %q", c.sid, a, ok, want)
		}
	}
	deny := bySid(gs, "DenyAWildcardRole")
	if len(deny) != 1 || !deny[0].Admits.IsEmpty() || deny[0].Exact() {
		t.Fatalf("Deny on a wildcard role: %+v; want nothing denied, declared", deny)
	}
	for _, c := range []struct{ kind, construct string }{{Malformed, "arn:aws:iam::123456789012:role/ci-*"}, {trust.Unmodelled, "Deny"}} {
		if _, ok := findAnomaly(deny[0], c.kind, c.construct); !ok {
			t.Errorf("the Deny lacks the %s anomaly on %s: %v", c.kind, c.construct, deny[0].Anomalies)
		}
	}
	// The other shapes no documented principal ARN has.
	shapes := []struct{ value, want string }{
		{"arn:aws:iam::123456789012:role/", "names no account root, role or user, which are the IAM principals AWS documents, so who it names is not known"},
		{"arn:aws:iam::123456789012:user/ali?e", "holds a wildcard, which AWS documents cannot match part of a principal name or ARN, so who it names is not known"},
		{"arn:aws:iam::*:role/ci", "holds a wildcard, which AWS documents cannot match part of a principal name or ARN, so who it names is not known"},
		{"arn::iam::123456789012:role/ci", "has no partition, so who it names is not known"},
		{"arn:aws:iam:::role/ci", "has no account id, so who it names is not known"},
		{"arn:aws:sts:::assumed-role/ci/build", "has no account id, so who it names is not known"},
		{"arn:aws:sts:eu-west-1:123456789012:federated-user/alice", "names a region, which an IAM or STS principal ARN never has, so who it names is not known"},
	}
	for _, c := range shapes {
		g := oneGrant(t, statement(`"Effect": "Allow", "Principal": {"AWS": "`+c.value+`"}, "Action": "sts:AssumeRole"`))
		if g.Exact() || !hasCaveatOn(g, "aws:principalarn") || g.Admits.IsEmpty() {
			t.Errorf("%s: admits %s, exact %v, caveats %v", c.value, g.Admits, g.Exact(), g.Admits.Caveats())
		}
		if a, ok := findAnomaly(g, Malformed, c.value); !ok || a.Message != "the AWS principal "+strconv.Quote(c.value)+" "+c.want {
			t.Errorf("%s: anomaly = %+v, %v; want %q", c.value, a, ok, c.want)
		}
	}
	// The documented forms are unchanged: exact, with the ARN as written.
	for _, value := range []string{
		"arn:aws:iam::123456789012:role/ci",
		"arn:aws:iam::123456789012:role/path/to/ci",
		"arn:aws:iam::123456789012:user/alice",
		"arn:aws-us-gov:iam::123456789012:role/ci",
		"arn:aws:sts::123456789012:federated-user/alice",
	} {
		g := oneGrant(t, statement(`"Effect": "Allow", "Principal": {"AWS": "`+value+`"}, "Action": "sts:AssumeRole"`))
		if g.Admits.String() != `{aws:principalaccount="123456789012", aws:principalarn="`+value+`"}` || !g.Exact() {
			t.Errorf("%s: admits %s, exact %v", value, g.Admits, g.Exact())
		}
	}
}

// TestServicePrincipalDoesNotShareTheAWSIssuer: sts.amazonaws.com is a
// service a policy can name, so the pseudo-issuer of AWS principals must
// be a name no principal can spell, or a Deny on that service would
// subtract from every account's grant.
func TestServicePrincipalDoesNotShareTheAWSIssuer(t *testing.T) {
	gs := grantsOf(t, `{"Version": "2012-10-17", "Statement": [
		{"Effect": "Allow", "Principal": {"AWS": "123456789012"}, "Action": "sts:AssumeRole"},
		{"Effect": "Deny", "Principal": {"Service": "sts.amazonaws.com"}, "Action": "sts:AssumeRole"}
	]}`)
	if len(gs) != 2 || gs[0].Issuer == gs[1].Issuer {
		t.Fatalf("grants = %+v; the service and the account must not share an issuer", gs)
	}
	if !admittedDownstream(gs, AWSPrincipalIssuer, token{"aws:principalaccount": "123456789012"}) {
		t.Errorf("the account is admitted; the Deny names a service, not the account")
	}
	for _, spelling := range []string{"sts.amazonaws.com", "https://sts.amazonaws.com", "arn:aws:iam::123456789012:saml-provider/sts", "aws:sts", "aws:service:ec2.amazonaws.com"} {
		for _, kind := range []string{"Federated", "Service"} {
			g := oneGrant(t, statement(`"Effect": "Allow", "Principal": {"`+kind+`": "`+spelling+`"}, "Action": "sts:AssumeRole"`))
			if g.Issuer == AWSPrincipalIssuer {
				t.Errorf("%s %q spells the pseudo-issuer %q", kind, spelling, g.Issuer)
			}
			// Nor can a Federated principal spell a service's issuer.
			if kind == "Federated" && strings.HasPrefix(string(g.Issuer), ServiceIssuerPrefix) {
				t.Errorf("Federated %q spells a service issuer %q", spelling, g.Issuer)
			}
		}
	}
}

// TestRoleSessionPrincipal: a session principal is one session of a role,
// and the request context of that session carries the role's ARN, never
// the session's. Pinning aws:principalarn to the session ARN met a
// condition naming the role in a provably empty set, exact, for a caller
// AWS admits.
func TestRoleSessionPrincipal(t *testing.T) {
	gs := policyGrants(t, "15-role-session-principal")
	if len(gs) != 4 {
		t.Fatalf("%d grants, want 4", len(gs))
	}
	const session = "arn:aws:sts::123456789012:assumed-role/ci/build-42"
	const want = `the AWS principal "` + session + `" is one session of a role in account 123456789012; aws:PrincipalArn holds the role's ARN, which the session ARN does not spell, so which identity of that account it names is not known`
	caller := token{"aws:principalaccount": "123456789012", "aws:principalarn": "arn:aws:iam::123456789012:role/ci"}
	conditioned := bySid(gs, "SessionWithTheRoleArnInACondition")
	if len(conditioned) != 1 || conditioned[0].Admits.String() != `{aws:principalaccount="123456789012", aws:principalarn="arn:aws:iam::123456789012:role/ci"}` || conditioned[0].Exact() {
		t.Errorf("session with a role ARN condition: %+v", conditioned)
	}
	if !conditioned[0].Admits.Admits(caller) {
		t.Errorf("the session's own request context is admitted")
	}
	alone := bySid(gs, "SessionAlone")
	if len(alone) != 1 || alone[0].Admits.String() != `{aws:principalaccount="123456789012", aws:principalarn=?("`+session+`")}` || alone[0].Exact() || !hasCaveatOn(alone[0], "aws:principalarn") {
		t.Errorf("session alone: %+v", alone)
	}
	for _, g := range slices.Concat(conditioned, alone) {
		if a, ok := findAnomaly(g, trust.Unmodelled, session); !ok || a.Claim != "aws:principalarn" || a.Message != want {
			t.Errorf("session anomaly = %+v, %v", a, ok)
		}
	}
	deny := bySid(gs, "DenyOneSessionOfIt")
	if len(deny) != 1 || !deny[0].Admits.IsEmpty() || deny[0].Exact() {
		t.Fatalf("Deny on a session: %+v; want nothing denied, declared", deny)
	}
	if _, ok := findAnomaly(deny[0], trust.Unmodelled, "Deny"); !ok {
		t.Errorf("the Deny says it is not applied: %v", deny[0].Anomalies)
	}
	if !admittedDownstream(gs, AWSPrincipalIssuer, caller) {
		t.Errorf("every session of the role stays admitted through AllowTheRole")
	}
	like := oneGrant(t, statement(`"Effect": "Allow", "Principal": {"AWS": "`+session+`"}, "Action": "sts:AssumeRole", "Condition": {"StringLike": {"aws:PrincipalArn": "arn:aws:iam::123456789012:role/c*"}}`))
	if like.Admits.IsEmpty() || !like.Admits.Admits(caller) {
		t.Errorf("session with a pattern on the role: %s", like.Admits)
	}
	// A federated user session carries its own ARN in aws:PrincipalArn.
	federated := oneGrant(t, statement(`"Effect": "Allow", "Principal": {"AWS": "arn:aws:sts::123456789012:federated-user/alice"}, "Action": "sts:AssumeRole"`))
	if federated.Admits.String() != `{aws:principalaccount="123456789012", aws:principalarn="arn:aws:sts::123456789012:federated-user/alice"}` || !federated.Exact() {
		t.Errorf("federated user: %s exact %v", federated.Admits, federated.Exact())
	}
	other := oneGrant(t, statement(`"Effect": "Allow", "Principal": {"AWS": "arn:aws:sts::123456789012:self"}, "Action": "sts:AssumeRole"`))
	if other.Admits.String() != `{aws:principalaccount="123456789012", aws:principalarn=?("arn:aws:sts::123456789012:self")}` || other.Exact() {
		t.Errorf("an STS ARN of another kind: %s exact %v", other.Admits, other.Exact())
	}
	if a, ok := findAnomaly(other, trust.Unmodelled, "arn:aws:sts::123456789012:self"); !ok || a.Message != `the AWS principal "arn:aws:sts::123456789012:self" is an STS ARN of a kind this parser does not know, so which identity of account 123456789012 it names is not known` {
		t.Errorf("other STS ARN anomaly = %+v, %v", a, ok)
	}
}

// TestUnmodelledPrincipalCouldUseAnyAssumeAction: a principal the parser
// does not model could assume through any action, so its grant is
// everything, declared, whenever any assume action is granted; and every
// anomaly states a fact about the document, never a consequence the grant
// beside it contradicts.
func TestUnmodelledPrincipalCouldUseAnyAssumeAction(t *testing.T) {
	const canonical = `"Principal": {"CanonicalUser": "79a59df900b949e55d96a1e698fbacedfd6e09d98eacf8f8d5218e7cd47ef2be"}`
	for _, action := range []string{"sts:AssumeRole", "sts:AssumeRoleWithWebIdentity", "sts:AssumeRoleWithSAML"} {
		g := oneGrant(t, statement(`"Effect": "Allow", `+canonical+`, "Action": "`+action+`"`))
		if !g.Admits.IsTop() || g.Exact() || !hasCaveatOn(g, "") {
			t.Errorf("CanonicalUser with %s: %s exact %v; want everything, declared", action, g.Admits, g.Exact())
		}
	}
	none := oneGrant(t, statement(`"Effect": "Allow", `+canonical+`, "Action": "s3:GetObject"`))
	if !none.Admits.IsEmpty() || !none.Exact() {
		t.Errorf("CanonicalUser without an assume action: %s exact %v; want nothing, exactly", none.Admits, none.Exact())
	}
	if a, ok := findAnomaly(none, trust.Unmodelled, "CanonicalUser"); !ok || a.Message != "a CanonicalUser principal is not modelled by this parser, so who it names is not known" {
		t.Errorf("CanonicalUser anomaly = %+v, %v", a, ok)
	}
	saml := oneGrant(t, statement(`"Effect": "Allow", "Principal": {"Federated": "arn:aws:iam::123456789012:saml-provider/okta"}, "Action": "sts:AssumeRoleWithWebIdentity"`))
	if !saml.Admits.IsEmpty() || !saml.Exact() {
		t.Errorf("SAML without its action: %s exact %v", saml.Admits, saml.Exact())
	}
	if a, ok := findAnomaly(saml, trust.Unmodelled, "SAML"); !ok || a.Message != `SAML federation through "arn:aws:iam::123456789012:saml-provider/okta" is not modelled by this parser, so which identities it admits is not known` {
		t.Errorf("SAML anomaly = %+v, %v", a, ok)
	}
	if a, ok := findAnomaly(saml, NotAnAssumeAction, "Action"); !ok || a.Message != "the actions do not include sts:AssumeRoleWithSAML, so this statement lets nobody assume the role through this principal" {
		t.Errorf("SAML action anomaly = %+v, %v", a, ok)
	}
	// No sentence on an exact, empty grant claims the statement is unconstrained.
	for _, g := range []trust.Grant{none, saml} {
		for _, a := range g.Anomalies {
			if strings.Contains(a.Message, "not constrained") {
				t.Errorf("an exact empty grant carries %q", a.Message)
			}
		}
	}
}

// TestPolicyVariableInAPrincipal: a variable is never compared as a
// literal, in a principal as in a condition value.
func TestPolicyVariableInAPrincipal(t *testing.T) {
	cases := []struct {
		kind, text, variable string
	}{
		{"AWS", "arn:aws:iam::123456789012:role/${aws:username}", "${aws:username}"},
		{"Federated", "arn:aws:iam::123456789012:oidc-provider/${aws:username}", "${aws:username}"},
		{"Service", "${aws:PrincipalTag/service}.amazonaws.com", "${aws:PrincipalTag/service}"},
		{"AWS", "1234567890${", "${"},
	}
	for _, c := range cases {
		g := oneGrant(t, statement(`"Effect": "Allow", "Principal": {"`+c.kind+`": "`+c.text+`"}, "Action": "sts:AssumeRole"`))
		if g.Issuer != "" || !g.Admits.IsTop() || g.Exact() || !hasCaveatOn(g, "") {
			t.Errorf("%s %q: issuer %q, admits %s, exact %v", c.kind, c.text, g.Issuer, g.Admits, g.Exact())
		}
		want := "the " + c.kind + " principal " + strconv.Quote(c.text) + " holds the policy variable " + c.variable + "; a policy variable is resolved per request and names no principal this parser can read, so who it names is not known"
		if a, ok := findAnomaly(g, trust.Unmodelled, c.variable); !ok || a.Message != want {
			t.Errorf("%s %q: anomaly = %+v, %v; want %q", c.kind, c.text, a, ok, want)
		}
	}
}

// TestDuplicateStatementMemberDoubtsEveryCopy: which copy of a duplicated
// Statement member the deployed policy carries is not known, so every
// statement in either is an upper bound, and a Deny among them is not
// applied.
func TestDuplicateStatementMemberDoubtsEveryCopy(t *testing.T) {
	d := mustParse(t, string(readPolicy(t, "16-duplicate-statement-member")))
	if len(d.Statements) != 2 {
		t.Fatalf("%d statements, want both copies kept", len(d.Statements))
	}
	if !slices.ContainsFunc(d.Anomalies, func(a trust.Anomaly) bool { return a.Kind == DuplicateKey && a.Construct == "Statement" }) {
		t.Errorf("document anomalies %v lack the duplicate Statement", d.Anomalies)
	}
	gs := d.Grants(role, vocabulary)
	if len(gs) != 2 {
		t.Fatalf("%d grants", len(gs))
	}
	const want = "the member Statement appears more than once in the document; a JSON decoder keeps one copy and the deployed policy may carry either, so whether this statement is deployed is not known"
	allow := bySid(gs, "AllowInTheFirstCopy")
	if len(allow) != 1 || allow[0].Admits.String() != `{aud="sts.amazonaws.com"}` || allow[0].Exact() || !hasCaveatOn(allow[0], "") {
		t.Errorf("Allow in a duplicated Statement: %+v; want its set as an upper bound", allow)
	}
	if a, ok := findAnomaly(allow[0], DuplicateKey, "Statement"); !ok || a.Message != want || a.Source != "statement[0]" {
		t.Errorf("Allow anomaly = %+v, %v", a, ok)
	}
	deny := bySid(gs, "DenyInTheSecondCopy")
	if len(deny) != 1 || !deny[0].Admits.IsEmpty() || deny[0].Exact() {
		t.Fatalf("Deny in a duplicated Statement: %+v; want nothing denied, declared", deny)
	}
	if a, ok := findAnomaly(deny[0], DuplicateKey, "Statement"); !ok || a.Source != "statement[1]" {
		t.Errorf("Deny anomaly = %+v, %v", a, ok)
	}
	if _, ok := findAnomaly(deny[0], trust.Unmodelled, "Deny"); !ok {
		t.Errorf("the Deny says it is not applied: %v", deny[0].Anomalies)
	}
	if !admittedDownstream(gs, githubIssuer, token{"aud": "sts.amazonaws.com", "sub": mainBranch}) {
		t.Errorf("the main branch is admitted by the Allow and subtracted by nothing")
	}
}

// TestDuplicateMemberInsidePrincipalDoubtsItsPrincipals: every principal
// named in any copy of a duplicated member is taken, as an upper bound;
// whether each is deployed is not known, so a Deny on one is not applied.
func TestDuplicateMemberInsidePrincipalDoubtsItsPrincipals(t *testing.T) {
	const gitlab = "arn:aws:iam::123456789012:oidc-provider/gitlab.com"
	gs := grantsOf(t, `{"Version": "2012-10-17", "Statement": [
		{"Effect": "Allow", "Principal": {"Federated": "`+githubProvider+`"}, "Action": "sts:AssumeRoleWithWebIdentity"},
		{"Effect": "Deny", "Principal": {"Federated": "`+gitlab+`", "Federated": "`+githubProvider+`"}, "Action": "sts:AssumeRoleWithWebIdentity", "Condition": {"StringEquals": {"`+gh("sub")+`": "`+mainBranch+`"}}}
	]}`)
	if len(gs) != 3 {
		t.Fatalf("%d grants, want 3", len(gs))
	}
	const want = "the member Federated appears more than once in Principal; a JSON decoder keeps one and the deployed policy may carry either, so whether this principal is deployed is not known"
	denies := 0
	for _, g := range gs {
		if g.Effect != trust.Deny {
			continue
		}
		denies++
		if !g.Admits.IsEmpty() || g.Exact() || !hasCaveatOn(g, "") {
			t.Errorf("Deny on %q: %s exact %v; want nothing denied, declared", g.Issuer, g.Admits, g.Exact())
		}
		if a, ok := findAnomaly(g, DuplicateKey, "Federated"); !ok || a.Message != want {
			t.Errorf("Deny on %q: anomaly = %+v, %v", g.Issuer, a, ok)
		}
	}
	if denies != 2 {
		t.Errorf("%d Deny grants, want one per principal in either copy", denies)
	}
	if !admittedDownstream(gs, githubIssuer, token{"aud": "sts.amazonaws.com", "sub": mainBranch}) {
		t.Errorf("the main branch is admitted by the Allow; the Deny may not be deployed")
	}
	// An Allow with the same duplicate keeps its set as an upper bound.
	allows := grantsOf(t, statement(`"Effect": "Allow", "Principal": {"Federated": "`+githubProvider+`", "Federated": "`+gitlab+`"}, "Action": "sts:AssumeRoleWithWebIdentity"`))
	if len(allows) != 2 {
		t.Fatalf("%d grants, want the union of both copies", len(allows))
	}
	for _, g := range allows {
		if !g.Admits.IsTop() || g.Exact() || !hasCaveatOn(g, "") {
			t.Errorf("Allow on %q: %s exact %v; want everything as an upper bound", g.Issuer, g.Admits, g.Exact())
		}
	}
}

// TestGrantsScaleWithTheDocument: a document AWS would refuse on size must
// still be handled in memory proportional to its size. N principals in one
// statement once held N copies of the statement's bytes in the sort key,
// and a block with K unevaluated keys attached its caveats one call at a
// time, each call re-sorting the list.
func TestGrantsScaleWithTheDocument(t *testing.T) {
	var principals strings.Builder
	for i := 0; i < 4000; i++ {
		if i > 0 {
			principals.WriteString(", ")
		}
		fmt.Fprintf(&principals, `"arn:aws:iam::123456789012:role/r%07d"`, i)
	}
	many := `{"Version": "2012-10-17", "Statement": {"Effect": "Allow", "Action": "sts:AssumeRole", "Principal": {"AWS": [` + principals.String() + `]}}}`
	var keys strings.Builder
	for i := 0; i < 20000; i++ {
		if i > 0 {
			keys.WriteString(", ")
		}
		fmt.Fprintf(&keys, `"aws:k%05d": "v"`, i)
	}
	wide := github(`{"StringEquals": {` + keys.String() + `}}`)
	cases := []struct {
		name   string
		raw    string
		grants int
		limit  uint64 // bytes allocated, generous: the quadratic shapes exceeded it a hundredfold
	}{
		{"4000 principals", many, 4000, 256 << 20},
		{"20000 keys", wide, 1, 256 << 20},
	}
	for _, c := range cases {
		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)
		gs := grantsOf(t, c.raw)
		runtime.ReadMemStats(&after)
		allocated := after.TotalAlloc - before.TotalAlloc
		if len(gs) != c.grants {
			t.Errorf("%s: %d grants, want %d", c.name, len(gs), c.grants)
		}
		if allocated > c.limit {
			t.Errorf("%s: allocated %d MB projecting %d bytes, limit %d MB", c.name, allocated>>20, len(c.raw), c.limit>>20)
		}
		t.Logf("%s: %d bytes in, %d grants, %d MB allocated", c.name, len(c.raw), len(gs), allocated>>20)
	}
}
