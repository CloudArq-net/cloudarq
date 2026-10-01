package report

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/CloudArq-net/cloudarq/internal/registry"
	"github.com/CloudArq-net/cloudarq/internal/trust"
)

const testdata = "../../testdata"

// corpus is every AWS document under testdata, by path.
func corpus(t *testing.T) map[string][]byte {
	t.Helper()
	docs := map[string][]byte{}
	for _, pattern := range []string{"policies/*.json", "grants/*/aws.json"} {
		paths, err := filepath.Glob(filepath.Join(testdata, pattern))
		if err != nil {
			t.Fatal(err)
		}
		for _, p := range paths {
			raw, err := os.ReadFile(p)
			if err != nil {
				t.Fatal(err)
			}
			docs[p] = raw
		}
	}
	if len(docs) < 20 {
		t.Fatalf("%d documents in the corpus; the tests would examine too little", len(docs))
	}
	return docs
}

func grantCase(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(testdata, "grants", name, "aws.json"))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func answerFor(t *testing.T, policy []byte) Answer {
	t.Helper()
	var a Answer
	if err := json.Unmarshal(Admits(policy), &a); err != nil {
		t.Fatalf("Admits rendered something that is not JSON: %v", err)
	}
	return a
}

func explanationFor(t *testing.T, policy, token []byte) Explanation {
	t.Helper()
	var e Explanation
	if err := json.Unmarshal(Explain(policy, token), &e); err != nil {
		t.Fatalf("Explain rendered something that is not JSON: %v", err)
	}
	return e
}

// claimsOf reads a witness payload back into the token the engine compares.
func claimsOf(t *testing.T, payload string) map[trust.ClaimKey]string {
	t.Helper()
	var claims map[trust.ClaimKey]string
	if err := json.Unmarshal([]byte(payload), &claims); err != nil {
		t.Fatalf("the witness %q is not a JSON object of strings: %v", payload, err)
	}
	return claims
}

// awsReads is what AWS compares for each key of a grant's set when a
// token carries claims, by the census's record of the claim AWS reads each
// key from, and the one it reads when the token sets none of that; a key
// the census does not record for the issuer reads the claim of its name.
// It is this test's own reading, apart from the engine's, and it reads a
// witness, which never sets a claim to the empty string.
func awsReads(g trust.Grant, claims map[trust.ClaimKey]string) map[trust.ClaimKey]string {
	reads := map[trust.ClaimKey]string{}
	for _, term := range g.Admits.Terms() {
		for key := range term {
			read, documented := registry.AWSConditionKeyClaim(g.Issuer, string(key))
			if !documented {
				read.Claim = string(key)
			}
			for _, c := range []string{read.Claim, read.Fallback} {
				if v, present := claims[trust.ClaimKey(c)]; present && c != "" {
					reads[key] = v
					break
				}
			}
		}
	}
	return reads
}

// TestEveryWitnessIsAdmittedByItsGrant: every witness the corpus and the
// rings cases carry is a token AWS reads as the grant admits, each key read
// from the claim AWS reads it from, and the explanation admits it as the
// grant's own.
func TestEveryWitnessIsAdmittedByItsGrant(t *testing.T) {
	documents := corpus(t)
	for _, name := range ringsCases(t) {
		documents[name], _ = ringsCase(t, name)
	}
	witnessed := 0
	for path, raw := range documents {
		r, err := readPolicy(raw)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		a := answerFor(t, raw)
		for _, g := range a.Grants {
			engine := r.grants[g.Number-1]
			if g.Witness == "" {
				if engine.Admits.IsTop() && !engine.Exact() {
					continue // nothing was evaluated, so nothing is witnessed
				}
				// a token is not known to carry what AWS's table names by a
				// phrase, as Login with Amazon's "Application ID", or by a
				// spelling no vendor sentence ties to a claim
				unnamed := func(c Claim) bool {
					read, documented := registry.AWSConditionKeyClaim(engine.Issuer, c.Claim)
					_, named := trust.Claim(read.Claim)
					return documented && !named
				}
				if !engine.Admits.IsEmpty() && !slices.ContainsFunc(slices.Concat(g.Terms...), func(c Claim) bool { return c.Constraint.Kind == kindIntersection || unnamed(c) }) {
					t.Errorf("%s grant %d: no witness for a set that admits something: %s", path, g.Number, g.Admits)
				}
				continue
			}
			witnessed++
			claims := claimsOf(t, g.Witness)
			if reads := awsReads(engine, claims); !engine.Admits.Admits(reads) {
				t.Errorf("%s grant %d: the witness %v, read by AWS as %v, is rejected by %s", path, g.Number, claims, reads, g.Admits)
			}
			if strings.HasPrefix(g.Issuer, "https://") && claims["iss"] != g.Issuer {
				t.Errorf("%s grant %d: the witness names iss %q, the grant %q", path, g.Number, claims["iss"], g.Issuer)
			}
			e := explanationFor(t, raw, []byte(g.Witness))
			if o := e.Grants[g.Number-1]; !o.Admitted || !o.Witness {
				t.Errorf("%s grant %d: explain does not admit the grant's own witness: admitted=%v witness=%v", path, g.Number, o.Admitted, o.Witness)
			}
		}
	}
	if witnessed == 0 {
		t.Fatal("no grant in the corpus carried a witness")
	}
	t.Logf("%d witnesses confirmed", witnessed)
}

func TestWitnessIsTheSimplestInstance(t *testing.T) {
	cases := []struct {
		rendered, want string
		ok             bool
	}{
		{`"sts.amazonaws.com"`, "sts.amazonaws.com", true},
		{`like:"repo:acme/*"`, "repo:acme/", true},
		{`like:"repo:acme*/infra*:*"`, "repo:acme/infra:", true},
		{`like:"a?c"`, "axc", true},
		{`like:"*:main"`, ":main", true},
		{`("a" | "b")`, "a", true},
		{`(like:"b*" | "a")`, "b", true},
		{`(like:"a*" & like:"*b")`, "", false},
		{`((like:"a*" & like:"*b") | like:"c*")`, "c", true},
	}
	for _, c := range cases {
		constraint, rest, err := parseConstraint(c.rendered)
		if err != nil || rest != "" {
			t.Errorf("%s: parse: %v, rest %q", c.rendered, err, rest)
			continue
		}
		got, ok := constraint.witness()
		if ok != c.ok || got != c.want {
			t.Errorf("%s: witness = %q, %v; want %q, %v", c.rendered, got, ok, c.want, c.ok)
		}
	}
}

func TestAUnionOfPatternsIsSaidAsAlternatives(t *testing.T) {
	c, rest, err := parseConstraint(`(like:"a*" | like:"b*" | (like:"c*" & like:"*d"))`)
	if err != nil || rest != "" {
		t.Fatal(err, rest)
	}
	if got := plain(c.clause()); got != " is one of anything that matches a*, anything that matches b*, anything that matches all of c* and *d" {
		t.Errorf("clause = %q", got)
	}
}

func TestConstraintReaderRefusesWhatItWasNotTaught(t *testing.T) {
	for _, text := range []string{"*", "∅", `?("x")`, `("a")`, `("a" | )`, `like:x`, `"a" "b"`, `("a" & "b")`} {
		if c, rest, err := parseConstraint(text); err == nil && rest == "" {
			t.Errorf("%s read as %+v; a rendering outside the grammar must be refused", text, c)
		}
	}
}

func TestStatementsAreLocatedByTheirBytes(t *testing.T) {
	for path, raw := range corpus(t) {
		a := answerFor(t, raw)
		if a.Error != "" {
			t.Fatalf("%s: %s", path, a.Error)
		}
		r, err := readPolicy(raw)
		if err != nil {
			t.Fatal(err)
		}
		if len(a.Document.Statements) != len(r.doc.Statements) {
			t.Fatalf("%s: %d statements located, %d parsed", path, len(a.Document.Statements), len(r.doc.Statements))
		}
		for _, s := range a.Document.Statements {
			quoted := raw[s.Offset : s.Offset+s.Length]
			if !bytes.Equal(quoted, r.doc.Statements[s.Index].Raw) {
				t.Errorf("%s statement[%d]: bytes %d+%d are not the statement's own", path, s.Index, s.Offset, s.Length)
			}
			if first := 1 + bytes.Count(raw[:s.Offset], []byte("\n")); first != s.FirstLine {
				t.Errorf("%s statement[%d]: first line %d, want %d", path, s.Index, s.FirstLine, first)
			}
			if last := 1 + bytes.Count(raw[:s.Offset+s.Length], []byte("\n")); last != s.LastLine {
				t.Errorf("%s statement[%d]: last line %d, want %d", path, s.Index, s.LastLine, last)
			}
			if s.SHA256 != digest(quoted) {
				t.Errorf("%s statement[%d]: digest is not of the quoted bytes", path, s.Index)
			}
		}
		if a.Document.Bytes != len(raw) || a.Document.SHA256 != digest(raw) {
			t.Errorf("%s: document size or digest wrong", path)
		}
		if want := strings.Count(strings.TrimSuffix(string(raw), "\n"), "\n") + 1; a.Document.Lines != want {
			t.Errorf("%s: %d lines, want %d", path, a.Document.Lines, want)
		}
	}
}

func TestGrantsNameTheStatementTheyCameFrom(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(testdata, "policies", "11-principal-shapes.json"))
	if err != nil {
		t.Fatal(err)
	}
	a := answerFor(t, raw)
	if len(a.Grants) < 8 {
		t.Fatalf("%d grants; the engine sorts them away from document order and this test needs many", len(a.Grants))
	}
	inOrder := true
	for i, g := range a.Grants {
		s := a.Document.Statements[g.Statement]
		if !strings.Contains(string(raw[s.Offset:s.Offset+s.Length]), `"Sid": "`+g.Sid+`"`) {
			t.Errorf("grant %d says statement[%d] %q, whose bytes do not carry that Sid", g.Number, g.Statement, g.Sid)
		}
		if g.Number != i+1 {
			t.Errorf("grant %d is numbered %d", i+1, g.Number)
		}
		inOrder = inOrder && (i == 0 || a.Grants[i-1].Statement <= g.Statement)
	}
	if inOrder {
		t.Error("the grants came back in statement order; the engine's order is canonical and this test would not notice a wrong index")
	}
}

func TestIdenticalStatementsKeepTheirOwnIndex(t *testing.T) {
	statement := `{"Effect": "Allow", "Principal": {"Federated": "token.actions.githubusercontent.com"}, "Action": "sts:AssumeRoleWithWebIdentity", "Condition": {"StringEquals": {"token.actions.githubusercontent.com:sub": "repo:a/b:ref:refs/heads/main"}}}`
	raw := []byte(`{"Version": "2012-10-17", "Statement": [` + statement + `,` + statement + `]}`)
	a := answerFor(t, raw)
	if len(a.Grants) != 2 {
		t.Fatalf("%d grants, want 2", len(a.Grants))
	}
	if a.Grants[0].Statement != 0 || a.Grants[1].Statement != 1 {
		t.Errorf("two identical statements were attributed as %d and %d", a.Grants[0].Statement, a.Grants[1].Statement)
	}
	if a.Document.Statements[0].Offset == a.Document.Statements[1].Offset {
		t.Error("two identical statements were located at one offset")
	}
}

func TestBeyondIsExactlyNoClaimButTheAudience(t *testing.T) {
	cases := map[string]bool{"03-whole-organisation": false, "06-unconstrained": true, "07-expressible-by-one-provider": false}
	for name, want := range cases {
		a := answerFor(t, grantCase(t, name))
		if got := a.Grants[0].Beyond; got != want {
			t.Errorf("%s: beyond = %v, want %v", name, got, want)
		}
		rows := a.Grants[0].Terms[0]
		hasSub := slices.ContainsFunc(rows, func(c Claim) bool { return c.Claim == "sub" && c.Mark == "beyond" })
		if hasSub != want {
			t.Errorf("%s: a beyond-coloured sub row = %v, want %v", name, hasSub, want)
		}
	}
	deny := []byte(`{"Version": "2012-10-17", "Statement": [{"Effect": "Deny", "Principal": {"Federated": "token.actions.githubusercontent.com"}, "Action": "sts:AssumeRoleWithWebIdentity", "Condition": {"StringEquals": {"token.actions.githubusercontent.com:aud": "x"}}}]}`)
	if a := answerFor(t, deny); a.Grants[0].Beyond {
		t.Error("a Deny that names only the audience refuses everyone; it is not beyond")
	}
}

func TestTheSentences(t *testing.T) {
	cases := map[string]string{
		"03-whole-organisation":          "This role admits any token from token.actions.githubusercontent.com whose aud is sts.amazonaws.com, whose repository_owner_id is 123456 and whose sub matches repo:acme/*.",
		"06-unconstrained":               "This role admits every identity token.actions.githubusercontent.com issues a token to, whoever holds it: the only claim named is aud, and an audience is not a boundary.",
		"07-expressible-by-one-provider": "This role admits any token from token.actions.githubusercontent.com whose aud is sts.amazonaws.com, whose repository_id is 456789 and whose sub was not evaluated, so the set shown is an upper bound.",
	}
	for name, want := range cases {
		a := answerFor(t, grantCase(t, name))
		if got := a.Grants[0].Sentence; got != want {
			t.Errorf("%s:\n got %q\nwant %q", name, got, want)
		}
		if plain(a.Grants[0].Spans) != a.Grants[0].Sentence {
			t.Errorf("%s: the spans do not spell the sentence", name)
		}
	}
	words := []string{}
	for _, row := range answerFor(t, grantCase(t, "03-whole-organisation")).Grants[0].Terms[0] {
		words = append(words, row.Words)
	}
	if !slices.Equal(words, []string{"exactly this audience", "exactly this value", "any subject beginning repo:acme/"}) {
		t.Errorf("03 in words: %q", words)
	}
	a := answerFor(t, grantCase(t, "07-expressible-by-one-provider"))
	g := a.Grants[0]
	refs := []int{}
	for _, s := range g.Spans {
		if s.Note != 0 {
			refs = append(refs, s.Note)
		}
	}
	if !slices.Equal(refs, []int{1}) || g.Notes[0].Kind != "caveat" || g.Notes[0].Claim != "sub" || g.Notes[1].Kind != "anomaly" {
		t.Errorf("07: the sentence refers to notes %v; notes are %+v", refs, g.Notes)
	}
	if row := g.Terms[0][2]; row.Claim != "sub" || row.Note != 1 || row.Mark != "unknown" || row.Words != "not evaluated" {
		t.Errorf("07: the sub row = %+v", row)
	}
}

func TestSentencesForTheShapesTheCorpusHas(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(testdata, "policies", "12-action-case-and-notaction.json"))
	if err != nil {
		t.Fatal(err)
	}
	sentences := map[string]string{}
	for _, g := range answerFor(t, raw).Grants {
		sentences[g.Sid] = g.Sentence
	}
	want := map[string]string{
		"NotActionInverts":                    "Who this statement admits is not known: NotAction grants every action but the ones listed; this parser does not compute that complement, so which actions the statement grants is not known.",
		"AssumeRoleIsNotTheWebIdentityAction": "This statement admits nobody through token.actions.githubusercontent.com: the actions do not include sts:AssumeRoleWithWebIdentity, so this statement lets nobody assume the role through this principal.",
	}
	for sid, sentence := range want {
		if sentences[sid] != sentence {
			t.Errorf("%s:\n got %q\nwant %q", sid, sentences[sid], sentence)
		}
	}
	// a Deny that is not applied is empty and inexact; its sentence refers to
	// the caveat that says so, not to the anomaly that repeats it
	raw, err = os.ReadFile(filepath.Join(testdata, "policies", "16-duplicate-statement-member.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, g := range answerFor(t, raw).Grants {
		if g.Sid != "DenyInTheSecondCopy" {
			continue
		}
		var ref Span
		for _, s := range g.Spans {
			if s.Note != 0 {
				ref = s
			}
		}
		if !g.Empty || g.Exact || ref.Mark != "unknown" || g.Notes[ref.Note-1].Kind != "caveat" || !strings.HasPrefix(ref.Text, "this Deny statement could not be fully evaluated") {
			t.Errorf("the Deny not applied: %+v refers to %+v", ref, g.Notes)
		}
	}
	raw, err = os.ReadFile(filepath.Join(testdata, "policies", "14-anyone-is-scoped-by-the-assume-action.json"))
	if err != nil {
		t.Fatal(err)
	}
	var everyone []string
	for _, g := range answerFor(t, raw).Grants {
		if g.Sid == "AllowEveryoneThroughEveryAction" && g.Top && g.Exact {
			everyone = append(everyone, g.Sentence)
			if !slices.ContainsFunc(g.Spans, func(s Span) bool { return s.Mark == "beyond" }) {
				t.Errorf("an unconstrained Allow carries no beyond span: %+v", g.Spans)
			}
		}
	}
	if !slices.Equal(everyone, []string{"This role admits every AWS principal, in any account: no condition constrains this statement."}) {
		t.Errorf("the * principal's sentence: %q", everyone)
	}
}

func TestUnionAndDeadTermsAreSaid(t *testing.T) {
	union := []byte(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Federated":"token.actions.githubusercontent.com"},"Action":"sts:AssumeRoleWithWebIdentity","Condition":{"StringEquals":{"token.actions.githubusercontent.com:sub":["repo:a/b:ref:refs/heads/main","repo:a/b:environment:prod"]}}}]}`)
	a := answerFor(t, union)
	row := a.Grants[0].Terms[0][0]
	if row.Constraint.Kind != kindUnion || len(row.Constraint.Members) != 2 || row.Words != "any of these 2 alternatives" {
		t.Errorf("union row = %+v", row)
	}
	if want := "This role admits any token from token.actions.githubusercontent.com whose sub is one of repo:a/b:environment:prod, repo:a/b:ref:refs/heads/main."; a.Grants[0].Sentence != want {
		t.Errorf("union sentence = %q", a.Grants[0].Sentence)
	}
	if claims := claimsOf(t, a.Grants[0].Witness); claims["sub"] != "repo:a/b:environment:prod" {
		t.Errorf("union witness = %v", claims)
	}
	dead := []byte(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Federated":"token.actions.githubusercontent.com"},"Action":"sts:AssumeRoleWithWebIdentity","Condition":{"StringLike":{"token.actions.githubusercontent.com:sub":"repo:a/*"},"StringEquals":{"token.actions.githubusercontent.com:sub":"repo:b/c:ref:refs/heads/main"}}}]}`)
	a = answerFor(t, dead)
	g := a.Grants[0]
	if !g.Empty || g.Witness != "" || len(g.Terms) != 0 || g.Sentence != "This statement admits nobody through token.actions.githubusercontent.com: no token satisfies every condition it names." {
		t.Errorf("dead term: %+v", g)
	}
}

func TestWhatCannotBeReadIsAnswered(t *testing.T) {
	cases := map[string]string{
		"":           "parse trust policy: empty input",
		"{":          "parse trust policy: unexpected EOF",
		"[1]":        "parse trust policy: the document is a list, not an object",
		"{} {}":      "parse trust policy: after the document: a second value",
		`{"a": tru}`: "parse trust policy: invalid character '}' in literal true (expecting 'e')",
		`{"Action": "` + "\ufb05" + `s:AssumeRole"}`: "parse trust policy: U+FB05 at byte 12 is a character AWS refuses in a policy document, which may hold only tab, line feed, carriage return and U+0020 to U+00FF",
	}
	for input, want := range cases {
		a := answerFor(t, []byte(input))
		if a.Error != want || a.Document != nil || len(a.Grants) != 0 || a.V != 1 {
			t.Errorf("%q: %+v", input, a)
		}
		e := explanationFor(t, []byte(input), []byte(`{}`))
		if e.Error != want {
			t.Errorf("explain %q: %+v", input, e)
		}
	}
}

// TestTheUnknownIssuerIsNotGuessed: the census does not record which keys
// AWS documents for GitLab.com's tokens, so a condition on one is not read,
// and nothing is guessed about it. It records Google's, each with the claim
// AWS reads it from, and a condition on Google's aud is read.
func TestTheUnknownIssuerIsNotGuessed(t *testing.T) {
	raw := []byte(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Federated":"arn:aws:iam::123456789012:oidc-provider/gitlab.com"},"Action":"sts:AssumeRoleWithWebIdentity","Condition":{"StringEquals":{"gitlab.com:aud":"x"}}}]}`)
	g := answerFor(t, raw).Grants[0]
	if g.Exact || !g.Top || g.Beyond || g.Witness != "" || len(g.Terms) != 1 || len(g.Terms[0]) != 0 || !strings.HasPrefix(g.Sentence, "Who this statement admits is not known: the claim vocabulary of ") || !strings.Contains(g.Sentence, "gitlab.com") {
		t.Errorf("an issuer whose keys are not known: %+v", g)
	}
	google := []byte(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Federated":"accounts.google.com"},"Action":"sts:AssumeRoleWithWebIdentity","Condition":{"StringEquals":{"accounts.google.com:aud":"x"}}}]}`)
	if g := answerFor(t, google).Grants[0]; !g.Exact || g.Top || g.Admits != `{aud="x"}` || g.Witness == "" {
		t.Errorf("Google, whose keys the census records: %+v", g)
	}
}

// TestAKeyAWSDoesNotDocumentIsNotRead: a condition reads a token's claim
// only through a key AWS puts in the request context, and AWS's GitHub tab
// lists no repository_owner. The condition on it is read as not read: it
// pins nobody, narrows nothing, and leaves the grant an upper bound with a
// note naming the key, so a token whose repository_owner is acme is not
// proven admitted. GitHub's documented keys still read their claims.
func TestAKeyAWSDoesNotDocumentIsNotRead(t *testing.T) {
	onGitHub := func(key, value string) []byte {
		return []byte(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Federated":"arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"},"Action":"sts:AssumeRoleWithWebIdentity","Condition":{"StringEquals":{"token.actions.githubusercontent.com:aud":"sts.amazonaws.com","token.actions.githubusercontent.com:` + key + `":"` + value + `"}}}]}`)
	}
	undocumented := onGitHub("repository_owner", "acme")
	g := answerFor(t, undocumented).Grants[0]
	named := slices.ContainsFunc(g.Notes, func(n Note) bool {
		return strings.Contains(n.Message, `"token.actions.githubusercontent.com:repository_owner"`) && strings.Contains(n.Message, "AWS documents")
	})
	if g.Exact || !named || !slices.Equal(g.Placement, []string{"platform"}) || g.PlacementState != "unknown" {
		t.Errorf("a key AWS does not document: exact %v, notes %+v, placed %v %s", g.Exact, g.Notes, g.Placement, g.PlacementState)
	}
	token := []byte(`{"iss":"https://token.actions.githubusercontent.com","aud":"sts.amazonaws.com","repository_owner":"acme"}`)
	if e := explanationFor(t, undocumented, token); e.Result == "admitted" || len(e.Grants) != 1 || e.Grants[0].Admitted && e.Grants[0].Exact {
		t.Errorf("a token read against a key AWS does not document: %s, %+v", e.Result, e.Grants)
	}
	for key, value := range map[string]string{"sub": "repo:acme/infra:ref:refs/heads/main", "repository_owner_id": "123456", "repository_id": "456789", "enterprise_id": "123", "REPOSITORY_OWNER_ID": "123456"} {
		if g := answerFor(t, onGitHub(key, value)).Grants[0]; !g.Exact || !slices.Equal(g.Placement, []string{"outsider"}) || g.PlacementState != "exact" {
			t.Errorf("%s, a key AWS documents: exact %v, notes %+v, placed %v %s", key, g.Exact, g.Notes, g.Placement, g.PlacementState)
		}
	}
}

func TestDocumentAnomaliesAreCarried(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(testdata, "policies", "16-duplicate-statement-member.json"))
	if err != nil {
		t.Fatal(err)
	}
	a := answerFor(t, raw)
	if len(a.Document.Anomalies) != 1 || a.Document.Anomalies[0].Anomaly != "duplicate-key" || a.Document.Anomalies[0].Number != 1 {
		t.Errorf("document anomalies = %+v", a.Document.Anomalies)
	}
	if len(a.Document.Statements) != 2 || a.Document.Statements[1].FirstLine <= a.Document.Statements[0].LastLine {
		t.Errorf("statements of two Statement members: %+v", a.Document.Statements)
	}
}

func TestDeterminismOfTheRendering(t *testing.T) {
	docs := corpus(t)
	for _, name := range ringsCases(t) {
		doc, _ := ringsCase(t, name)
		docs[name] = doc
	}
	token := []byte(`{"iss":"https://token.actions.githubusercontent.com","aud":"sts.amazonaws.com","sub":"repo:acme/infra:ref:refs/heads/main","repository_id":"456789","repository_owner_id":"123456"}`)
	// owners declared in an order the answer does not keep, one of them
	// twice, beside two refused: the echo, the rings and the owners each
	// term names must come out in one order whatever the order written
	owners := []byte("issuer:https://oidc.eks.us-east-1.amazonaws.com/id/EXAMPLED539D4633E53DE1B71EXAMPLE\ngithub:beta\nnope\ngithub:acme\naws:111122223333\ngithub:beta\ngitlab:x\n")
	for path, raw := range docs {
		first, firstExplained := AdmitsFor(raw, owners), ExplainFor(raw, token, owners)
		for i := 0; i < 20; i++ {
			if !bytes.Equal(AdmitsFor(raw, owners), first) {
				t.Fatalf("%s: run %d rendered differently", path, i)
			}
			if !bytes.Equal(ExplainFor(raw, token, owners), firstExplained) {
				t.Fatalf("%s: explain run %d rendered differently", path, i)
			}
		}
	}
}

// TestAnAnswerIsWrittenIntoTheBufferItIsGiven: the WebAssembly engine writes
// each answer into the buffer the one before it used. Appended to a buffer,
// an answer is the bytes Admits or Explain renders, after whatever the
// buffer held; and an answer that fits in the room the buffer has is
// written there, not into a new one. Every document of the corpus is
// answered, as admits and as explain, into the buffer the answer before it
// left, as the engine's calls follow one another.
func TestAnAnswerIsWrittenIntoTheBufferItIsGiven(t *testing.T) {
	token := []byte(`{"iss":"https://token.actions.githubusercontent.com","aud":"sts.amazonaws.com","sub":"repo:acme/infra:ref:refs/heads/main"}`)
	docs := corpus(t)
	paths := slices.Sorted(maps.Keys(docs))
	held := []byte("held")
	buffer := make([]byte, 0, 1<<20)
	written := 0
	for _, path := range paths {
		policy := docs[path]
		for _, c := range []struct {
			call     string
			rendered []byte
			appendTo func(dst []byte) []byte
		}{
			{"admits", Admits(policy), func(dst []byte) []byte { return AppendAdmits(dst, policy) }},
			{"explain", Explain(policy, token), func(dst []byte) []byte { return AppendExplain(dst, policy, token) }},
		} {
			if got := c.appendTo(held[:len(held):len(held)]); !bytes.Equal(got, append(slices.Clip(held), c.rendered...)) {
				t.Errorf("%s, %s: appended to %q, the answer is not those bytes and then what %s renders", path, c.call, held, c.call)
			}
			fits := len(c.rendered) <= cap(buffer)
			got := c.appendTo(buffer[:0])
			if !bytes.Equal(got, c.rendered) {
				t.Errorf("%s, %s: written into the buffer the answer before it left, the answer is not what %s renders", path, c.call, c.call)
			}
			if fits {
				if &got[:1][0] != &buffer[:1][0] {
					t.Errorf("%s, %s: the answer fits in the %d bytes the buffer has and was written into a new one", path, c.call, cap(buffer))
				}
				written++
			}
			buffer = got
		}
	}
	if written == 0 {
		t.Fatalf("no answer of the %d documents fitted in the buffer, so writing into it was never examined", len(paths))
	}
	t.Logf("%d answers to %d documents written into the buffer the answer before them left", written, len(paths))
}

// TestAnAnswerWithRoomTakesNoBlockOfItsOwn: an answer written into a buffer
// with room for it takes none of its bytes from the collector. Rendered into
// a new buffer and then copied over, it would read the same and sit at the
// same address, and the WebAssembly engine would still ask the collector on
// every call for a block the size of the answer and for each smaller one it
// grew through, which is what took its linear memory a doubling further. So
// one answer written in place allocates fewer bytes than the same answer
// rendered afresh, by at least its own length. Each count is the least of
// three, so that an allocation elsewhere in the process cannot decide it.
func TestAnAnswerWithRoomTakesNoBlockOfItsOwn(t *testing.T) {
	var statements []string
	for i := range 50 {
		n := strconv.Itoa(i)
		statements = append(statements, onGitHub("Repository"+n, "Allow", `,"StringLike":{"token.actions.githubusercontent.com:sub":"repo:acme/service-`+n+`:*"}`))
	}
	policy := policyOf(statements...)
	token := []byte(`{"iss":"https://token.actions.githubusercontent.com","aud":"sts.amazonaws.com","sub":"repo:acme-evil/infra:ref:refs/heads/main"}`)
	allocated := func(render func()) uint64 {
		least := ^uint64(0)
		for range 3 {
			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)
			render()
			runtime.ReadMemStats(&after)
			least = min(least, after.TotalAlloc-before.TotalAlloc)
		}
		return least
	}
	for _, c := range []struct {
		call     string
		rendered []byte
		afresh   func() []byte
		into     func(dst []byte) []byte
	}{
		{"admits", Admits(policy), func() []byte { return Admits(policy) }, func(dst []byte) []byte { return AppendAdmits(dst, policy) }},
		{"explain", Explain(policy, token), func() []byte { return Explain(policy, token) }, func(dst []byte) []byte { return AppendExplain(dst, policy, token) }},
	} {
		buffer := make([]byte, 0, 2*len(c.rendered))
		afresh := allocated(func() { c.afresh() })
		inPlace := allocated(func() { buffer = c.into(buffer[:0]) })
		if !bytes.Equal(buffer, c.rendered) {
			t.Errorf("%s: written in place, the answer is not what %s renders", c.call, c.call)
		}
		if inPlace+uint64(len(c.rendered)) > afresh {
			t.Errorf("%s: written into a buffer with room, the %d-byte answer allocated %d bytes against %d rendered afresh, so it took a block of its own", c.call, len(c.rendered), inPlace, afresh)
		}
		t.Logf("%s: a %d-byte answer allocated %d bytes written in place and %d rendered afresh", c.call, len(c.rendered), inPlace, afresh)
	}
}

// ratingWords are the words of a rating. The answer states who can get in
// and never rates it, so none of them reaches it.
var ratingWords = regexp.MustCompile(`(?i)security|severity|critical|warning|danger|risk|score|grade|rating|verdict`)

// TestNoRatingWordReachesTheAnswer asks every trust policy of testdata's
// policies, grants and rings, in the answer and in the explanation. The
// vendor sentences an answer quotes are part of the answer too, so they are
// held to the same words: a sentence of AWS's that needs one is not quoted.
func TestNoRatingWordReachesTheAnswer(t *testing.T) {
	docs := corpus(t)
	for _, name := range ringsCases(t) {
		docs[name], _ = ringsCase(t, name)
	}
	examined := 0
	for path, raw := range docs {
		for _, out := range [][]byte{Admits(raw), Explain(raw, []byte(`{"iss":"https://x.example","aud":"y"}`))} {
			examined++
			if m := ratingWords.Find(out); m != nil {
				t.Errorf("%s: %q in the answer", path, m)
			}
		}
	}
	// 31 documents of policies and grants and 75 rings cases, each asked twice
	if examined < 212 {
		t.Fatalf("%d answers examined; the check held over too little", examined)
	}
	t.Logf("%d answers examined", examined)
}

// witnessWords reads the heading and caption printed over a witness,
// through the JSON, so that a build without them fails here on what a
// reader would see rather than on a missing symbol.
func witnessWords(t *testing.T, policy []byte, grant int) (heading, caption string) {
	t.Helper()
	var generic struct {
		Grants []map[string]any `json:"grants"`
	}
	if err := json.Unmarshal(Admits(policy), &generic); err != nil {
		t.Fatal(err)
	}
	if grant >= len(generic.Grants) {
		t.Fatalf("no grant %d in %d", grant, len(generic.Grants))
	}
	heading, _ = generic.Grants[grant]["witnessHeading"].(string)
	caption, _ = generic.Grants[grant]["witnessCaption"].(string)
	return heading, caption
}

// The words over a witness are the engine's, because they state what the
// witness proves: a caption written outside the engine said an unevaluated
// claim was unconstrained, and headed a Deny's witness as a token it
// admits.
func TestTheWitnessIsHeadedAndCaptionedByTheEngine(t *testing.T) {
	heading, caption := witnessWords(t, grantCase(t, "03-whole-organisation"), 0)
	if heading != "a token this grant admits" || caption != "The decoded payload. A claim not shown is unconstrained by this grant, but for azp. It sets no azp: AWS reads aud from azp whenever a token sets one." {
		t.Errorf("03: heading %q, caption %q", heading, caption)
	}
	heading, caption = witnessWords(t, grantCase(t, "07-expressible-by-one-provider"), 0)
	if heading != "a token this grant admits" || caption != "The decoded payload. A claim not shown and not named by the grant is unconstrained, but for azp; sub is not shown because it was not evaluated, so whether it excludes a token is not decided here. It sets no azp: AWS reads aud from azp whenever a token sets one." {
		t.Errorf("07: heading %q, caption %q", heading, caption)
	}
	heading, caption = witnessWords(t, grantCase(t, "06-unconstrained"), 0)
	if heading != "a token this grant admits" || caption != "The decoded payload. A claim not shown is unconstrained by this grant, but for azp, and none of the claims shown names an identity: whoever holds a token like this is admitted. It sets no azp: AWS reads aud from azp whenever a token sets one." {
		t.Errorf("06: heading %q, caption %q", heading, caption)
	}
	deny := []byte(`{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Principal":{"Federated":"token.actions.githubusercontent.com"},"Action":"sts:AssumeRoleWithWebIdentity","Condition":{"StringLike":{"token.actions.githubusercontent.com:sub":"repo:acme/*:pull_request"}}}]}`)
	heading, caption = witnessWords(t, deny, 0)
	if heading != "a token this grant refuses" || caption != "The decoded payload. A claim not shown is unconstrained by this grant: a token carrying these claims is refused whatever else it carries." {
		t.Errorf("deny: heading %q, caption %q", heading, caption)
	}
	raw, err := os.ReadFile(filepath.Join(testdata, "policies", "16-duplicate-statement-member.json"))
	if err != nil {
		t.Fatal(err)
	}
	a := answerFor(t, raw)
	doubted := 0
	for i, g := range a.Grants {
		if g.Witness == "" || g.Exact || slices.ContainsFunc(slices.Concat(g.Terms...), func(c Claim) bool { return c.Constraint.Kind == kindUnknown }) {
			continue
		}
		doubted++
		_, caption = witnessWords(t, raw, i)
		if caption != "The decoded payload. A claim not shown is unconstrained by this grant, but for azp; the set is an upper bound, so the token is admitted by the bound, not proven admitted by the policy. It sets no azp: AWS reads aud from azp whenever a token sets one." {
			t.Errorf("a doubted grant's caption: %q", caption)
		}
	}
	if doubted == 0 {
		t.Fatal("no grant of the duplicated Statement is a witnessed upper bound without an unevaluated claim; the caption for that shape went unexamined")
	}
	unread := []byte(`{"Version":"2012-10-17","Statement":[{"Effect":"Maybe","Principal":{"Federated":"token.actions.githubusercontent.com"},"Action":"sts:AssumeRoleWithWebIdentity","Condition":{"StringEquals":{"token.actions.githubusercontent.com:aud":"x"}}}]}`)
	heading, caption = witnessWords(t, unread, 0)
	if heading != "a token this grant matches" || caption != "The decoded payload. A claim not shown is unconstrained by this grant, but for azp; the statement's effect could not be read, so whether such a token is admitted or refused is not known. It sets no azp: AWS reads aud from azp whenever a token sets one." {
		t.Errorf("unread effect: heading %q, caption %q", heading, caption)
	}
	// a grant with no witness has no words over one: nothing of it was
	// evaluated, since the census does not record which keys AWS documents
	// for GitLab.com's tokens
	heading, caption = witnessWords(t, []byte(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Federated":"arn:aws:iam::123456789012:oidc-provider/gitlab.com"},"Action":"sts:AssumeRoleWithWebIdentity","Condition":{"StringEquals":{"gitlab.com:aud":"x"}}}]}`), 0)
	if heading != "" || caption != "" {
		t.Errorf("a grant without a witness carries words over one: %q, %q", heading, caption)
	}
}

// A pasted document is not a deployable policy, and nothing else stops a
// megabyte of JSON from being read on every edit: the engine's heap grows
// without bound on such input, so the engine states its bound rather than
// the WebAssembly instance dying at 2 GB. AWS accepts a role trust policy of at most 8,192 characters
// (IAM quotas, read 2026-09-13); the bound sits far above that.
func TestADocumentBeyondTheBoundIsAnsweredNotRead(t *testing.T) {
	padded := func(n int) []byte {
		head := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Federated":"token.actions.githubusercontent.com"},"Action":"sts:AssumeRoleWithWebIdentity"}],"Id":"`
		return []byte(head + strings.Repeat("a", n-len(head)-2) + `"}`)
	}
	within := padded(MaxDocumentBytes)
	if len(within) != MaxDocumentBytes {
		t.Fatalf("the padded document is %d bytes", len(within))
	}
	if a := answerFor(t, within); a.Error != "" || len(a.Grants) != 1 {
		t.Errorf("a document at the bound was not read: %+v", a.Error)
	}
	beyond := padded(MaxDocumentBytes + 1)
	a := answerFor(t, beyond)
	const past = "the document is longer than 262144 bytes, the most the engine reads, and AWS accepts a role trust policy of at most 8192 characters"
	if a.Error != past || a.Document != nil || len(a.Grants) != 0 {
		t.Errorf("a document beyond the bound: %+v", a)
	}
	if e := explanationFor(t, beyond, []byte(`{}`)); e.Error != a.Error {
		t.Errorf("explain reads a document admits refused: %+v", e)
	}
	// The bound is on the bytes the engine was handed, not on what is left
	// of them after trimming: every offset, line number and digest in the
	// answer is into these exact bytes, whichever ones end the file. The
	// sentence names the bound and not the size, because a caller may stop
	// reading one byte past the bound, as the command does, and then knows
	// no size to name.
	whitespace := append(padded(MaxDocumentBytes), " \n\n\n"...)
	if len(whitespace) != MaxDocumentBytes+4 {
		t.Fatalf("the padded document is %d bytes", len(whitespace))
	}
	if a := answerFor(t, whitespace); a.Error != past {
		t.Errorf("a document whose four bytes past the bound are whitespace: %+v", a.Error)
	}
	paddedToken := func(n int) []byte { return []byte(`{"sub":"` + strings.Repeat("b", n-10) + `"}`) }
	if len(paddedToken(MaxTokenBytes)) != MaxTokenBytes {
		t.Fatalf("the padded token is %d bytes", len(paddedToken(MaxTokenBytes)))
	}
	e := explanationFor(t, within, paddedToken(MaxTokenBytes+1))
	if want := "the token is 16385 bytes; the engine reads up to 16384"; e.Token.Error != want || len(e.Grants) != 0 {
		t.Errorf("a token beyond the bound: %+v", e.Token)
	}
	if e := explanationFor(t, within, paddedToken(MaxTokenBytes)); e.Token.Error != "" || len(e.Grants) != 1 {
		t.Errorf("a token at the bound was not read: %+v", e.Token)
	}
}

// The parser and the layout reader recurse once per nesting level, on a
// stack the WebAssembly build fixes at link time, and a document nested
// past what that stack holds trapped the engine for good: every later call
// threw. The entry refuses depth before either reads a byte, with the depth
// and the bound in the sentence, and the engine answers the next document.
func TestADocumentNestedTooDeepIsRefused(t *testing.T) {
	objects := func(n int) []byte { return []byte(strings.Repeat(`{"a":`, n-1) + "{" + strings.Repeat("}", n)) }
	if a := answerFor(t, objects(MaxDocumentNesting)); a.Error != "" || len(a.Grants) != 1 {
		t.Errorf("%d levels of objects, the bound itself: %+v", MaxDocumentNesting, a.Error)
	}
	too := objects(MaxDocumentNesting + 1)
	want := "the document is nested 1001 levels deep; the engine reads up to 1000 levels, and level 1001 opens at byte 5000"
	if a := answerFor(t, too); a.Error != want || a.Document != nil || len(a.Grants) != 0 {
		t.Errorf("%d levels of objects:\n got %q\nwant %q", MaxDocumentNesting+1, a.Error, want)
	}
	if e := explanationFor(t, too, []byte(`{}`)); e.Error != want {
		t.Errorf("explain reads a document admits refused: %q", e.Error)
	}
	// the depth named is the document's, not the first past the bound
	arrays := []byte(`{"Statement":` + strings.Repeat("[", 3000) + strings.Repeat("]", 3000) + "}")
	want = "the document is nested 3001 levels deep; the engine reads up to 1000 levels, and level 1001 opens at byte 1012"
	if a := answerFor(t, arrays); a.Error != want {
		t.Errorf("3000 arrays:\n got %q\nwant %q", a.Error, want)
	}
	// depth is refused before the parser sees the bytes, so a document that
	// is not JSON at all is refused for its depth when its depth is the fault
	unclosed := []byte(strings.Repeat("[", 1001))
	if a := answerFor(t, unclosed); !strings.HasPrefix(a.Error, "the document is nested 1001 levels deep;") {
		t.Errorf("1001 unclosed arrays: %q", a.Error)
	}
	// brackets inside a string nest nothing
	quoted := []byte(`{"Version":"2012-10-17","Id":"` + strings.Repeat(`[{\"`, 2000) + `","Statement":[]}`)
	if a := answerFor(t, quoted); a.Error != "" {
		t.Errorf("brackets inside a string: %q", a.Error)
	}
	// brackets side by side nest nothing either: depth is what is open
	siblings := []byte(`{"Version":"2012-10-17","Statement":[],"Extra":[` + strings.Repeat("[],", 1500) + `[]]}`)
	if a := answerFor(t, siblings); a.Error != "" || len(a.Grants) != 1 {
		t.Errorf("1501 sibling arrays: %q, %d grants", a.Error, len(a.Grants))
	}
	// the engine answers the next document as it would have anyway
	good := grantCase(t, "03-whole-organisation")
	if a := answerFor(t, good); a.Error != "" || len(a.Grants) != 1 || a.Grants[0].Sid != "GitHubWholeOrganisation" {
		t.Errorf("the document after a refusal: %+v", a.Error)
	}
}

// The answer is written by hand, for speed; the struct tags stay the one
// statement of its shape. Every answer the corpus, the generated shapes and
// the tokens produce must be the bytes json.Marshal writes from the tags.
func TestRenderMatchesEncodingJSON(t *testing.T) {
	deep := func(n int) []byte { return []byte(strings.Repeat(`{"a":`, n) + "{" + strings.Repeat("}", n+1)) }
	docs := corpus(t)
	docs["misspelt member"] = []byte(`{"Version":"2012-10-17","Statement":[],"Statment":{"Effect":"Allow","Principal":"*","Action":"sts:AssumeRole"}}`)
	docs["scalar statement"] = []byte(`{"Version": 2012, "Id": 5, "Statement": "nope"}`)
	docs["beyond ascii"] = []byte(`{"Version":"2012-10-17","Statement":[{"Sid":"Caf\u00e9 \ud83d\ude00 <b>&amp;</b> \u2028\u2029 \t\n\b\f\r \u0001","Effect":"Allow","Principal":{"Federated":"token.actions.githubusercontent.com"},"Action":"sts:AssumeRoleWithWebIdentity","St\u00e4tement\u2603":1}],"\u00dcnknown\ud83d\ude00":{"x":"y"}}`)
	docs["not json"] = []byte("{ this is not a policy")
	docs["too deep"] = deep(MaxDocumentNesting)
	docs["too large"] = []byte(`{"Id":"` + strings.Repeat("a", MaxDocumentBytes) + `"}`)
	tokens := map[string][]byte{
		"foreign":     []byte(`{"iss":"https://token.actions.githubusercontent.com","aud":"https://github.com/acme","sub":"repo:acme-evil/infra:ref:refs/heads/main","repository_id":"1","nested":{"a":[1,{"b":null}]},"html":"<&>"}`),
		"whole":       []byte("eyJhbGciOiJSUzI1NiJ9." + base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"https://token.actions.githubusercontent.com","aud":"sts.amazonaws.com","sub":"repo:acme/infra:ref:refs/heads/main","repository_owner_id":"123456","repository_id":"456789"}`)) + ".c2ln"),
		"not a token": []byte("not a token"),
		"too deep":    []byte(`{"a":` + strings.Repeat("[", MaxTokenNesting) + strings.Repeat("]", MaxTokenNesting) + "}"),
		"empty":       []byte(`{}`),
	}
	// every rings case too, each with its own declaration and with one
	// that is refused whole or in part, so that the echo, the refusals and
	// the declared owners pass the same comparison
	for _, name := range ringsCases(t) {
		doc, _ := ringsCase(t, name)
		docs[name] = doc
	}
	declarations := [][]byte{nil, []byte("github:acme\nsaml:arn:aws:iam::123456789012:saml-provider/VendorSSO\nissuer:https://oidc.eks.us-east-1.amazonaws.com/id/EXAMPLED539D4633E53DE1B71EXAMPLE\ngitlab:x\n<b>&</b>\n"), []byte(strings.Repeat("github:o\n", 65))}
	compared := 0
	for name, doc := range docs {
		for _, owners := range declarations[1:] {
			want, err := json.Marshal(admits(doc, owners))
			if err != nil {
				t.Fatal(err)
			}
			if got := AdmitsFor(doc, owners); !bytes.Equal(got, want) {
				t.Errorf("admits %s declaring %q:\n got %s\nwant %s", name, owners, got, want)
			}
			compared++
		}
		a := admits(doc, nil)
		want, err := json.Marshal(a)
		if err != nil {
			t.Fatal(err)
		}
		if got := Admits(doc); !bytes.Equal(got, want) {
			t.Errorf("admits %s:\n got %s\nwant %s", name, got, want)
		}
		compared++
		against := map[string][]byte{}
		maps.Copy(against, tokens)
		for _, g := range a.Grants {
			if g.Witness != "" {
				against["witness of grant "+strconv.Itoa(g.Number)] = []byte(g.Witness)
			}
		}
		for tokenName, tok := range against {
			for _, owners := range declarations {
				want, err := json.Marshal(explain(doc, tok, owners))
				if err != nil {
					t.Fatal(err)
				}
				if got := ExplainFor(doc, tok, owners); !bytes.Equal(got, want) {
					t.Errorf("explain %s with %s declaring %q:\n got %s\nwant %s", name, tokenName, owners, got, want)
				}
				compared++
			}
		}
	}
	if compared < 200 {
		t.Fatalf("%d answers compared; the test would examine too little", compared)
	}
	// the zero values, whose nil lists no reachable answer carries
	for name, v := range map[string]any{
		"answer": Answer{}, "explanation": Explanation{}, "grant": Answer{Grants: []Grant{{}}}, "outcome": Explanation{Grants: []Outcome{{}}},
		"rings":        Answer{Headline: &Sentence{}, Rings: []Row{{}}, Beside: []Row{{}}, Refused: &Listing{}, Nobody: &Listing{}, Declarations: &Declarations{}, Bounds: &Bounds{Items: []Bound{{}}}},
		"placed":       Answer{Grants: []Grant{{Placement: []string{}, Populations: []Population{{}}}}},
		"declarations": Explanation{Declarations: &Declarations{Normalised: []string{}, RefusedLines: []RefusedLine{{}}, Unmatched: []UnmatchedOwner{{}}}},
		"bounds":       Explanation{Bounds: &Bounds{Items: []Bound{{}}}},
		"asked":        Answer{Rings: []Row{{Questions: []Question{{}}, Citations: []Citation{{}}}}},
	} {
		want, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		e := &encoder{}
		switch v := v.(type) {
		case Answer:
			e.answer(v)
		case Explanation:
			e.explanation(v)
		}
		if !bytes.Equal(e.b, want) {
			t.Errorf("zero %s:\n got %s\nwant %s", name, e.b, want)
		}
	}
	// every escape encoding/json writes, on its own
	for _, s := range []string{"", `"`, `\`, "<>&", "\b\f\n\r\t", "\x00\x01\x1f", "\u2028\u2029", "caf\u00e9 \U0001f600", "\x7f", "a\"b\\c<d>e&f"} {
		want, err := json.Marshal(s)
		if err != nil {
			t.Fatal(err)
		}
		e := &encoder{}
		e.quote(s)
		if !bytes.Equal(e.b, want) {
			t.Errorf("quote %q:\n got %s\nwant %s", s, e.b, want)
		}
	}
	// Invalid UTF-8 is the one place the reference depends on the toolchain:
	// json v1 (Go 1.24, which CI pins, and TinyGo) writes the six-character
	// escape, json v2 (behind encoding/json from Go 1.27) writes the
	// replacement character itself. The answer's canonical form is the
	// escape, so the expectation is written out rather than asked of the host.
	e := &encoder{}
	e.quote("bad \xff utf-8 \xc0")
	if want := `"bad \ufffd utf-8 \ufffd"`; string(e.b) != want {
		t.Errorf("quote of invalid UTF-8:\n got %s\nwant %s", e.b, want)
	}
}
