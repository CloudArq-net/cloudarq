package answer

import (
	"encoding/base64"
	"encoding/json"
	"slices"
	"strconv"
	"strings"
	"testing"

	"pgregory.net/rapid"

	"github.com/CloudArq-net/cloudarq/internal/eval"
	"github.com/CloudArq-net/cloudarq/internal/trust"
)

const rejectedToken = `{
  "iss": "https://token.actions.githubusercontent.com",
  "aud": "https://github.com/acme",
  "sub": "repo:acme/infra:ref:refs/heads/main",
  "ref": "refs/heads/main",
  "repository_id": "456789",
  "repository_owner_id": "123456",
  "workflow_ref": "acme/infra/.github/workflows/deploy.yml@refs/heads/main"
}`

func results(o Outcome) map[string]string {
	out := map[string]string{}
	for _, c := range o.Claims {
		out[c.Claim] = c.Result
	}
	return out
}

func TestTheRejectedTokenAgainstTheWholeOrganisation(t *testing.T) {
	e := explanationFor(t, grantCase(t, "03-whole-organisation"), []byte(rejectedToken))
	if e.Token.Claims != 7 || e.Token.Decoded || e.Token.Error != "" {
		t.Fatalf("token = %+v", e.Token)
	}
	o := e.Grants[0]
	if o.Admitted || o.Excludes == nil || o.Excludes.Claim != "aud" || o.Excludes.Constraint != `"sts.amazonaws.com"` {
		t.Errorf("outcome = admitted %v, excludes %+v", o.Admitted, o.Excludes)
	}
	if got := plain(o.Heading); got != "Not admitted: one claim short of grant 1." {
		t.Errorf("heading = %q", got)
	}
	want := "Rejected on aud: the token carries https://github.com/acme; grant 1 admits only sts.amazonaws.com. repository_owner_id and sub satisfy grant 1, iss is grant 1's issuer, and the other 3 claims are not named by it."
	if o.Sentence != want {
		t.Errorf("sentence:\n got %q\nwant %q", o.Sentence, want)
	}
	order := []string{}
	for _, c := range o.Claims {
		order = append(order, c.Claim)
	}
	if !slices.Equal(order, []string{"iss", "aud", "repository_owner_id", "sub", "ref", "repository_id", "workflow_ref"}) {
		t.Errorf("row order = %v", order)
	}
	if r := results(o); r["iss"] != satisfies || r["aud"] != fails || r["sub"] != satisfies || r["ref"] != notNamed {
		t.Errorf("results = %v", r)
	}
	if !slices.Equal(o.Named, []string{"aud", "repository_owner_id", "sub"}) {
		t.Errorf("named = %v", o.Named)
	}
	if o.Claims[0].Written[0].Line != 8 || o.Claims[1].Written[0].Line != 13 {
		t.Errorf("the issuer is written on L8 and aud on L13: %+v %+v", o.Claims[0].Written, o.Claims[1].Written)
	}
}

func TestTheRenamedRepositoryIsNotDecided(t *testing.T) {
	renamed := `{"iss": "https://token.actions.githubusercontent.com", "aud": "sts.amazonaws.com", "sub": "repo:acme/other:ref:refs/heads/main", "repository_id": "456789"}`
	o := explanationFor(t, grantCase(t, "07-expressible-by-one-provider"), []byte(renamed)).Grants[0]
	if !o.Admitted || o.Exact || o.Excludes != nil {
		t.Errorf("outcome = %+v", o)
	}
	if got := plain(o.Heading); got != "Not excluded, and not proven admitted: sub was not evaluated." {
		t.Errorf("heading = %q", got)
	}
	want := "aud and repository_id satisfy grant 1, and iss is grant 1's issuer. sub was not evaluated: ForAllValues:StringLike on sub passes when the claim is absent, so it does not restrict what it looks like it restricts. Whether it excludes the token is not decided here. The token is admitted by the upper bound, not proven admitted by the policy."
	if o.Sentence != want {
		t.Errorf("sentence:\n got %q\nwant %q", o.Sentence, want)
	}
	if r := results(o); r["sub"] != notEvaluated {
		t.Errorf("results = %v", r)
	}
	if !slices.ContainsFunc(o.Spans, func(s Span) bool { return s.Mark == "unknown" && s.Note == 1 }) {
		t.Errorf("the unknown clause refers to note 1: %+v", o.Spans)
	}
}

func TestWhereThePatternParts(t *testing.T) {
	evil := `{"iss": "https://token.actions.githubusercontent.com", "aud": "sts.amazonaws.com", "sub": "repo:acme-evil/infra:ref:refs/heads/main", "repository_owner_id": "123456"}`
	o := explanationFor(t, grantCase(t, "03-whole-organisation"), []byte(evil)).Grants[0]
	want := "the token carries repo:acme-evil/infra:ref:refs/heads/main; grant 1 admits only a subject matching repo:acme/*; after repo:acme the pattern requires / and the token has - there"
	if o.Claims[3].Claim != "sub" || o.Claims[3].Why != want {
		t.Errorf("why = %q", o.Claims[3].Why)
	}
	cases := []struct{ pattern, value, want string }{
		{"repo:acme/infra:*", "repo:acme/other:ref:refs/heads/main", "; after repo:acme/ the pattern requires infra: and the token has other: there"},
		{"repo:acme/*", "repo:ac", "; after repo:ac the pattern requires me/ and the token ends there"},
		{"repo:acme/*", "repo:acme/x", ""},
		{"*x", "y", ""},
		{"répo:*", "rèpo:x", "; after r the pattern requires épo: and the token has èpo: there"},
	}
	for _, c := range cases {
		if got := plain(mismatch(Constraint{Kind: kindLike, Value: c.pattern}, c.value)); got != c.want {
			t.Errorf("%q vs %q: %q, want %q", c.pattern, c.value, got, c.want)
		}
	}
}

func TestTheIssuerIsCheckedBeforeTheClaims(t *testing.T) {
	foreign := `{"iss": "https://gitlab.com", "aud": "sts.amazonaws.com", "sub": "repo:acme/infra:ref:refs/heads/main", "repository_owner_id": "123456"}`
	o := explanationFor(t, grantCase(t, "03-whole-organisation"), []byte(foreign)).Grants[0]
	if o.Admitted || o.Excludes == nil || o.Excludes.Claim != "iss" || results(o)["iss"] != fails {
		t.Errorf("outcome = %+v", o)
	}
	if got := plain(o.Heading); got != "Not admitted: not from grant 1's issuer." {
		t.Errorf("heading = %q", got)
	}
	spelled := `{"iss": "HTTPS://Token.Actions.GitHubUserContent.com/", "aud": "sts.amazonaws.com", "sub": "repo:acme/infra:ref:refs/heads/main", "repository_owner_id": "123456"}`
	if o := explanationFor(t, grantCase(t, "03-whole-organisation"), []byte(spelled)).Grants[0]; !o.Admitted || results(o)["iss"] != satisfies {
		t.Errorf("an issuer spelled in another case is the same issuer: %+v", o)
	}
	absent := `{"aud": "sts.amazonaws.com", "sub": "repo:acme/infra:ref:refs/heads/main", "repository_owner_id": "123456"}`
	if o := explanationFor(t, grantCase(t, "03-whole-organisation"), []byte(absent)).Grants[0]; !o.Admitted || len(o.Claims) != 3 {
		t.Errorf("a token with no iss is read on its claims alone: %+v", o)
	}
}

func TestTheBeyondGrantSaysSoForTheToken(t *testing.T) {
	evil := `{"iss": "https://token.actions.githubusercontent.com", "aud": "sts.amazonaws.com", "sub": "repo:acme-evil/infra:ref:refs/heads/main"}`
	o := explanationFor(t, grantCase(t, "06-unconstrained"), []byte(evil)).Grants[0]
	want := "Every claim grant 1 names is satisfied: aud. No claim but aud is named, so any identity the issuer signs for passes."
	if !o.Admitted || o.Sentence != want {
		t.Errorf("outcome = admitted %v, %q", o.Admitted, o.Sentence)
	}
	if sub := o.Claims[2]; sub.Claim != "sub" || sub.Result != notNamed || sub.Mark != "beyond" {
		t.Errorf("sub row = %+v", sub)
	}
}

func TestATokenIsReadAsPayloadOrWhole(t *testing.T) {
	payload := `{"iss":"https://token.actions.githubusercontent.com","aud":"sts.amazonaws.com","sub":"repo:acme/infra:ref:refs/heads/main","repository_owner_id":"123456","iat":1700000000,"nested":{"a":[1, 2]},"flag":true}`
	segment := func(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }
	whole := segment(`{"alg":"RS256","kid":"x"}`) + "." + segment(payload) + ".c2ln"
	for _, text := range []string{payload, whole, "  " + whole + "\n"} {
		tok, err := readToken([]byte(text))
		if err != nil {
			t.Fatalf("%q: %v", text, err)
		}
		if tok.decoded != strings.Contains(text, ".c2ln") {
			t.Errorf("decoded = %v for %q", tok.decoded, text)
		}
		if !slices.Equal(tok.order, []string{"iss", "aud", "sub", "repository_owner_id", "iat", "nested", "flag"}) {
			t.Errorf("order = %v", tok.order)
		}
		if tok.values["iat"] != "1700000000" || tok.values["nested"] != `{"a":[1,2]}` || tok.values["flag"] != "true" {
			t.Errorf("values = %v", tok.values)
		}
	}
	e := explanationFor(t, grantCase(t, "03-whole-organisation"), []byte(whole))
	if !e.Token.Decoded || e.Token.Claims != 7 || !e.Grants[0].Admitted {
		t.Errorf("a whole token: %+v", e.Token)
	}
	for _, bad := range []string{"", "[1]", `"x"`, `{"a": 1} x`, "a.b.c", "not json"} {
		if e := explanationFor(t, grantCase(t, "03-whole-organisation"), []byte(bad)); e.Token.Error == "" || len(e.Grants) != 0 {
			t.Errorf("%q read as a token: %+v", bad, e)
		}
	}
	dup, err := readToken([]byte(`{"a": "1", "a": "2"}`))
	if err != nil || dup.values["a"] != "2" || len(dup.order) != 1 {
		t.Errorf("a claim written twice: %+v, %v", dup, err)
	}
}

func TestEmptyAndWidenedGrantsForTheToken(t *testing.T) {
	raw := []byte(`{"Version":"2012-10-17","Statement":[
	  {"Sid":"Nobody","Effect":"Allow","Principal":{"Federated":"token.actions.githubusercontent.com"},"Action":"sts:AssumeRole"},
	  {"Sid":"NotKnown","Effect":"Allow","Principal":{"Federated":"token.actions.githubusercontent.com"},"NotAction":"s3:*"}]}`)
	e := explanationFor(t, raw, []byte(`{"iss":"https://token.actions.githubusercontent.com","sub":"x"}`))
	if len(e.Grants) != 2 {
		t.Fatalf("%d outcomes", len(e.Grants))
	}
	for _, o := range e.Grants {
		switch o.Sid {
		case "Nobody":
			if o.Admitted || plain(o.Heading) != "Not admitted: grant "+string(rune('0'+o.Number))+" admits nobody." {
				t.Errorf("Nobody: %+v", o)
			}
		case "NotKnown":
			if !o.Admitted || o.Exact || !strings.HasPrefix(plain(o.Heading), "Not excluded, and not proven admitted: the set is an upper bound.") || !strings.Contains(o.Sentence, "NotAction grants every action but the ones listed") {
				t.Errorf("NotKnown: %+v", o)
			}
		}
	}
}

func TestDenyOutcomesUseTheDenyWords(t *testing.T) {
	raw := []byte(`{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Principal":{"Federated":"token.actions.githubusercontent.com"},"Action":"sts:AssumeRoleWithWebIdentity","Condition":{"StringEquals":{"token.actions.githubusercontent.com:sub":"repo:a/b:ref:refs/heads/main"}}}]}`)
	yes := explanationFor(t, raw, []byte(`{"sub":"repo:a/b:ref:refs/heads/main"}`)).Grants[0]
	no := explanationFor(t, raw, []byte(`{"sub":"repo:a/c:ref:refs/heads/main"}`)).Grants[0]
	if plain(yes.Heading) != "Refused by grant 1." || plain(no.Heading) != "Not refused: one claim short of grant 1." {
		t.Errorf("headings = %q, %q", plain(yes.Heading), plain(no.Heading))
	}
	a := answerFor(t, raw)
	if !strings.HasPrefix(a.Grants[0].Sentence, "This role refuses any token from") || a.Grants[0].Caption != "A Deny subtracts from what the Allow statements admit; it admits nobody by itself." {
		t.Errorf("Deny sentence = %q, caption %q", a.Grants[0].Sentence, a.Grants[0].Caption)
	}
}

// TestClosestAgreesWithExcludes: the term the token view shows is chosen by
// the engine's own rule for Excludes, so the claim Excludes blames must be
// the first failing claim of that term, with the same constraint.
func TestClosestAgreesWithExcludes(t *testing.T) {
	values := []string{"a", "b", "c", ""}
	blamed := 0
	rapid.Check(t, func(t *rapid.T) {
		var terms []eval.Term
		for i := rapid.IntRange(0, 4).Draw(t, "terms"); i > 0; i-- {
			term := eval.Term{}
			for _, k := range []trust.ClaimKey{"aud", "sub", "x"} {
				switch rapid.IntRange(0, 3).Draw(t, "shape") {
				case 0:
					term[k] = eval.Exact(rapid.SampledFrom(values).Draw(t, "exact"))
				case 1:
					term[k] = eval.Glob(rapid.SampledFrom(values).Draw(t, "prefix") + "*")
				case 2:
					term[k] = eval.Unknown("why")
				}
			}
			terms = append(terms, term)
		}
		set := eval.NewAdmittedSet(terms...)
		token := map[trust.ClaimKey]string{}
		for _, k := range []trust.ClaimKey{"aud", "sub", "x"} {
			if rapid.Bool().Draw(t, "present") {
				token[k] = rapid.SampledFrom(values).Draw(t, "value")
			}
		}
		term, failed := closest(set, token)
		if (len(failed) == 0 && len(set.Terms()) > 0) != set.Admits(token) {
			t.Fatalf("closest says failures %v on %s for %v; Admits says %v", failed, set, token, set.Admits(token))
		}
		claim, got, ok := set.Excludes(token)
		if !ok || claim == "" {
			return
		}
		blamed++
		if failed[0] != claim || term[claim].String() != got.String() {
			t.Fatalf("closest blames %v (%s) on %s for %v; Excludes blames %s (%s)", failed, term[failed[0]], set, token, claim, got)
		}
	})
	// the property is about rejections; a generator that stopped producing
	// them would pass vacuously
	if blamed < 20 {
		t.Fatalf("only %d rejections were generated", blamed)
	}
}

func TestTheAnswerMarshalsWithoutMaps(t *testing.T) {
	// A map in the answer would marshal in key order, but a witness or a
	// row order that depended on one would not be the engine's order.
	out := Admits(grantCase(t, "03-whole-organisation"))
	var generic map[string]any
	if err := json.Unmarshal(out, &generic); err != nil {
		t.Fatal(err)
	}
	witness := generic["grants"].([]any)[0].(map[string]any)["witness"].(string)
	if !strings.HasPrefix(witness, "{\n  \"iss\": ") || !strings.Contains(witness, "\"aud\": \"sts.amazonaws.com\",\n  \"sub\": ") {
		t.Errorf("the witness lists iss, aud, sub first: %q", witness)
	}
}

// A value the grant admits is data, and the page sets data in code coloured
// by what the engine knows of it: the token view's sentence must carry the
// same marks as the admits view's, or the two views show one value two ways.
func TestTheRejectionSentenceMarksWhatTheGrantAdmits(t *testing.T) {
	marked := func(spans []Span, text, mark string) bool {
		return slices.ContainsFunc(spans, func(s Span) bool { return s.Text == text && s.Mark == mark })
	}
	o := explanationFor(t, grantCase(t, "03-whole-organisation"), []byte(rejectedToken)).Grants[0]
	if !marked(o.Spans, "sts.amazonaws.com", "exact") {
		t.Errorf("the audience the grant admits is not marked exact: %+v", o.Spans)
	}
	if !marked(o.Spans, "https://github.com/acme", "code") {
		t.Errorf("the token's own value is not marked code: %+v", o.Spans)
	}
	evil := `{"iss": "https://token.actions.githubusercontent.com", "aud": "sts.amazonaws.com", "sub": "repo:acme-evil/infra:ref:refs/heads/main", "repository_owner_id": "123456"}`
	o = explanationFor(t, grantCase(t, "03-whole-organisation"), []byte(evil)).Grants[0]
	if !marked(o.Spans, "repo:acme/*", "exact") {
		t.Errorf("the pattern the grant admits is not marked exact: %+v", o.Spans)
	}
	union := []byte(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Federated":"token.actions.githubusercontent.com"},"Action":"sts:AssumeRoleWithWebIdentity","Condition":{"StringEquals":{"token.actions.githubusercontent.com:sub":["repo:a/b:ref:refs/heads/main","repo:a/b:environment:prod"]}}}]}`)
	o = explanationFor(t, union, []byte(`{"sub":"repo:a/c"}`)).Grants[0]
	if !marked(o.Spans, "repo:a/b:environment:prod", "exact") || !marked(o.Spans, "repo:a/b:ref:refs/heads/main", "exact") {
		t.Errorf("the alternatives the grant admits are not marked exact: %+v", o.Spans)
	}
	if want := "Rejected on sub: the token carries repo:a/c; grant 1 admits only one of repo:a/b:environment:prod and repo:a/b:ref:refs/heads/main. "; !strings.HasPrefix(o.Sentence, want) {
		t.Errorf("sentence = %q", o.Sentence)
	}
	absent := explanationFor(t, grantCase(t, "03-whole-organisation"), []byte(`{"aud": "sts.amazonaws.com"}`)).Grants[0]
	if !marked(absent.Spans, "123456", "exact") {
		t.Errorf("the value a missing claim would need is not marked exact: %+v", absent.Spans)
	}
}

const allowAndDeny = `{"Version":"2012-10-17","Statement":[
  {"Sid":"AllowOrg","Effect":"Allow","Principal":{"Federated":"arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"},"Action":"sts:AssumeRoleWithWebIdentity","Condition":{"StringEquals":{"token.actions.githubusercontent.com:aud":"sts.amazonaws.com"},"StringLike":{"token.actions.githubusercontent.com:sub":"repo:acme/*"}}},
  {"Sid":"DenyForks","Effect":"Deny","Principal":{"Federated":"arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"},"Action":"sts:AssumeRoleWithWebIdentity","Condition":{"StringLike":{"token.actions.githubusercontent.com:sub":"repo:acme/*:pull_request"}}}]}`

// netOf reads the policy's own answer for the token, above the grants,
// through the JSON: what a reader of a link sees before any grant.
func netOf(t *testing.T, policy, token []byte) (heading, sentence string) {
	t.Helper()
	var generic map[string]any
	if err := json.Unmarshal(Explain(policy, token), &generic); err != nil {
		t.Fatal(err)
	}
	if spans, ok := generic["heading"].([]any); ok {
		for _, s := range spans {
			heading += s.(map[string]any)["text"].(string)
		}
	}
	sentence, _ = generic["sentence"].(string)
	return heading, sentence
}

// A policy admits a token when an Allow admits it and no Deny refuses it;
// the answer for the token is that, said once above the grants. Grants sort
// Allow before Deny, so a page that took the first grant's heading shared a
// refused token as admitted.
func TestThePolicyAnswersForTheTokenAboveItsGrants(t *testing.T) {
	policy := []byte(allowAndDeny)
	fork := []byte(`{"iss":"https://token.actions.githubusercontent.com","aud":"sts.amazonaws.com","sub":"repo:acme/infra:pull_request"}`)
	heading, sentence := netOf(t, policy, fork)
	if heading != "Refused by grant 2, though grant 1 admits it." {
		t.Errorf("fork: heading %q", heading)
	}
	if sentence != "Grant 1 admits it; grant 2 refuses it: a Deny subtracts from what the Allow statements admit." {
		t.Errorf("fork: sentence %q", sentence)
	}
	branch := []byte(`{"iss":"https://token.actions.githubusercontent.com","aud":"sts.amazonaws.com","sub":"repo:acme/infra:ref:refs/heads/main"}`)
	heading, sentence = netOf(t, policy, branch)
	if heading != "Admitted by grant 1." || sentence != "Grant 1 admits it; grant 2 does not refuse it." {
		t.Errorf("branch: heading %q, sentence %q", heading, sentence)
	}
	stranger := []byte(`{"iss":"https://token.actions.githubusercontent.com","aud":"sts.amazonaws.com","sub":"repo:other/infra:pull_request"}`)
	heading, sentence = netOf(t, policy, stranger)
	if heading != "Not admitted by any grant." || sentence != "Grant 1 rejects it on sub; grant 2 does not refuse it." {
		t.Errorf("stranger: heading %q, sentence %q", heading, sentence)
	}
	// one grant: the policy's answer is the grant's own, so the page says it once
	e := explanationFor(t, grantCase(t, "03-whole-organisation"), []byte(rejectedToken))
	heading, sentence = netOf(t, grantCase(t, "03-whole-organisation"), []byte(rejectedToken))
	if heading != plain(e.Grants[0].Heading) || sentence != e.Grants[0].Sentence {
		t.Errorf("one grant: heading %q, sentence %q", heading, sentence)
	}
	// an upper bound admits without proving, and an effect that could not be read decides nothing
	bound := []byte(`{"Version":"2012-10-17","Statement":[
	  {"Sid":"Bound","Effect":"Allow","Principal":{"Federated":"token.actions.githubusercontent.com"},"Action":"sts:AssumeRoleWithWebIdentity","Condition":{"ForAllValues:StringLike":{"token.actions.githubusercontent.com:sub":"repo:acme/*"}}},
	  {"Sid":"Unread","Effect":"Maybe","Principal":{"Federated":"token.actions.githubusercontent.com"},"Action":"sts:AssumeRoleWithWebIdentity","Condition":{"StringEquals":{"token.actions.githubusercontent.com:aud":"sts.amazonaws.com"}}}]}`)
	heading, sentence = netOf(t, bound, branch)
	if heading != "Not excluded, and not proven admitted: grant 1 is an upper bound, and grant 2's effect could not be read." {
		t.Errorf("bound: heading %q", heading)
	}
	if sentence != "Grant 1 admits it as an upper bound; grant 2 matches it, with an effect that could not be read." {
		t.Errorf("bound: sentence %q", sentence)
	}
	// a token no grant could read against a policy with no grant
	heading, sentence = netOf(t, []byte(`{"Version":"2012-10-17","Statement":[]}`), branch)
	if heading != "Not admitted: the policy has no grant." || sentence != "" {
		t.Errorf("no grant: heading %q, sentence %q", heading, sentence)
	}
}

// The token reader recurses once per level, on a stack the WebAssembly
// build fixes at link time, so its depth is bounded the way a document's
// is: refused by the entry with the depth, the bound and the byte, never a
// trap that kills the engine.
func TestATokenNestedTooDeepIsRefused(t *testing.T) {
	deep := func(n int) string { return `{"a":` + strings.Repeat("[", n) + strings.Repeat("]", n) + `}` }
	policy := grantCase(t, "03-whole-organisation")
	if e := explanationFor(t, policy, []byte(deep(MaxTokenNesting-1))); e.Token.Error != "" || e.Token.Claims != 1 {
		t.Errorf("%d levels inside the claim, the bound itself: %+v", MaxTokenNesting, e.Token)
	}
	for _, n := range []int{500, 5000, 8000} {
		e := explanationFor(t, policy, []byte(deep(n)))
		want := "the token is nested " + strconv.Itoa(n+1) + " levels deep; the engine reads up to 500 levels, and level 501 opens at byte 504"
		if e.Token.Error != want || len(e.Grants) != 0 {
			t.Errorf("%d levels:\n got %q\nwant %q", n, e.Token.Error, want)
		}
	}
	// past the size bound the size is what is said: it is checked first
	if e := explanationFor(t, policy, []byte(deep(9990))); e.Token.Error != "the token is 19986 bytes; the engine reads up to 16384" {
		t.Errorf("9990 levels: %+v", e.Token)
	}
	objects := `{"a":` + strings.Repeat(`{"b":`, 500) + "1" + strings.Repeat("}", 500) + "}"
	if e := explanationFor(t, policy, []byte(objects)); e.Token.Error != "the token is nested 501 levels deep; the engine reads up to 500 levels, and level 501 opens at byte 2500" {
		t.Errorf("500 objects inside the claim: %+v", e.Token)
	}
	whole := "eyJhbGciOiJSUzI1NiJ9." + base64.RawURLEncoding.EncodeToString([]byte(deep(5000))) + ".c2ln"
	if e := explanationFor(t, policy, []byte(whole)); !strings.HasPrefix(e.Token.Error, "the token is nested 5001 levels deep;") {
		t.Errorf("a whole token nested 5000 deep: %+v", e.Token)
	}
	// a bracket inside a claim's string is text
	if e := explanationFor(t, policy, []byte(`{"sub":"`+strings.Repeat(`[{`, 600)+`"}`)); e.Token.Error != "" || e.Token.Claims != 1 {
		t.Errorf("brackets inside a string: %+v", e.Token)
	}
}
