package report

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

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

func TestEveryWitnessIsAdmittedByItsGrant(t *testing.T) {
	witnessed := 0
	for path, raw := range corpus(t) {
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
				if !engine.Admits.IsEmpty() && !slices.ContainsFunc(slices.Concat(g.Terms...), func(c Claim) bool { return c.Constraint.Kind == kindIntersection }) {
					t.Errorf("%s grant %d: no witness for a set that admits something: %s", path, g.Number, g.Admits)
				}
				continue
			}
			witnessed++
			claims := claimsOf(t, g.Witness)
			if !engine.Admits.Admits(claims) {
				t.Errorf("%s grant %d: the witness %v is rejected by %s", path, g.Number, claims, g.Admits)
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
	if !slices.Equal(everyone, []string{"This role admits every AWS principal, anonymous ones included: no condition constrains this statement."}) {
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

func TestTheUnknownIssuerIsNotGuessed(t *testing.T) {
	raw := []byte(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Federated":"accounts.google.com"},"Action":"sts:AssumeRoleWithWebIdentity","Condition":{"StringEquals":{"accounts.google.com:aud":"x"}}}]}`)
	g := answerFor(t, raw).Grants[0]
	if g.Exact || !g.Top || g.Beyond || g.Witness != "" || len(g.Terms) != 1 || len(g.Terms[0]) != 0 || !strings.HasPrefix(g.Sentence, "Who this statement admits is not known: the claim vocabulary of ") || !strings.Contains(g.Sentence, "accounts.google.com") {
		t.Errorf("an issuer whose vocabulary is unknown: %+v", g)
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
	token := []byte(`{"iss":"https://token.actions.githubusercontent.com","aud":"sts.amazonaws.com","sub":"repo:acme/infra:ref:refs/heads/main","repository_id":"456789","repository_owner_id":"123456"}`)
	for path, raw := range docs {
		first, firstExplained := Admits(raw), Explain(raw, token)
		for i := 0; i < 20; i++ {
			if !bytes.Equal(Admits(raw), first) {
				t.Fatalf("%s: run %d rendered differently", path, i)
			}
			if !bytes.Equal(Explain(raw, token), firstExplained) {
				t.Fatalf("%s: explain run %d rendered differently", path, i)
			}
		}
	}
}

var forbidden = regexp.MustCompile(`(?i)security|severity|critical|warning|danger|risk|score|grade|rating|verdict`)

func TestNoForbiddenWordReachesThePage(t *testing.T) {
	for path, raw := range corpus(t) {
		for _, out := range [][]byte{Admits(raw), Explain(raw, []byte(`{"iss":"https://x.example","aud":"y"}`))} {
			if m := forbidden.Find(out); m != nil {
				t.Errorf("%s: %q in the answer", path, m)
			}
		}
	}
}

// witnessWords reads the heading and caption the page prints over a
// witness, through the JSON, so that a build without them fails here on
// what the page would show rather than on a missing symbol.
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
// witness proves: a page-authored caption said an unevaluated claim was
// unconstrained, and headed a Deny's witness as a token it admits.
func TestTheWitnessIsHeadedAndCaptionedByTheEngine(t *testing.T) {
	heading, caption := witnessWords(t, grantCase(t, "03-whole-organisation"), 0)
	if heading != "a token this grant admits" || caption != "The decoded payload. A claim not shown is unconstrained by this grant." {
		t.Errorf("03: heading %q, caption %q", heading, caption)
	}
	heading, caption = witnessWords(t, grantCase(t, "07-expressible-by-one-provider"), 0)
	if heading != "a token this grant admits" || caption != "The decoded payload. A claim not shown and not named by the grant is unconstrained; sub is not shown because it was not evaluated, so whether it excludes a token is not decided here." {
		t.Errorf("07: heading %q, caption %q", heading, caption)
	}
	heading, caption = witnessWords(t, grantCase(t, "06-unconstrained"), 0)
	if heading != "a token this grant admits" || caption != "The decoded payload. A claim not shown is unconstrained by this grant, and none of the claims shown names an identity: whoever holds a token like this is admitted." {
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
		if caption != "The decoded payload. A claim not shown is unconstrained by this grant; the set is an upper bound, so the token is admitted by the bound, not proven admitted by the policy." {
			t.Errorf("a doubted grant's caption: %q", caption)
		}
	}
	if doubted == 0 {
		t.Fatal("no grant of the duplicated Statement is a witnessed upper bound without an unevaluated claim; the caption for that shape went unexamined")
	}
	unread := []byte(`{"Version":"2012-10-17","Statement":[{"Effect":"Maybe","Principal":{"Federated":"token.actions.githubusercontent.com"},"Action":"sts:AssumeRoleWithWebIdentity","Condition":{"StringEquals":{"token.actions.githubusercontent.com:aud":"x"}}}]}`)
	heading, caption = witnessWords(t, unread, 0)
	if heading != "a token this grant matches" || caption != "The decoded payload. A claim not shown is unconstrained by this grant; the statement's effect could not be read, so whether such a token is admitted or refused is not known." {
		t.Errorf("unread effect: heading %q, caption %q", heading, caption)
	}
	// a grant with no witness has no words over one
	heading, caption = witnessWords(t, []byte(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Federated":"accounts.google.com"},"Action":"sts:AssumeRoleWithWebIdentity","Condition":{"StringEquals":{"accounts.google.com:aud":"x"}}}]}`), 0)
	if heading != "" || caption != "" {
		t.Errorf("a grant without a witness carries words over one: %q, %q", heading, caption)
	}
}

// A paste is not a deployable policy, and nothing else stops a megabyte of
// JSON from being read on every keystroke: the engine's heap grows without
// bound on such input, so the engine states its bound rather than the page
// dying at 2 GB. AWS accepts a role trust policy of at most 8,192 characters
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
	if want := "the document is 262145 bytes; the engine reads up to 262144, and AWS accepts a role trust policy of at most 8192 characters"; a.Error != want || a.Document != nil || len(a.Grants) != 0 {
		t.Errorf("a document beyond the bound: %+v", a)
	}
	if e := explanationFor(t, beyond, []byte(`{}`)); e.Error != a.Error {
		t.Errorf("explain reads a document admits refused: %+v", e)
	}
	// The bound is on the bytes the engine was handed, not on what is left
	// of them after trimming. Every offset, line number and digest in the
	// answer is into these exact bytes, the reader holds all of them
	// whichever ones end the file, and the sentence names the size the
	// reader can check with wc: a bound read off a trimmed length would let
	// a document four bytes past it through and then say it was 262,148.
	whitespace := append(padded(MaxDocumentBytes), " \n\n\n"...)
	if len(whitespace) != MaxDocumentBytes+4 {
		t.Fatalf("the padded document is %d bytes", len(whitespace))
	}
	if a := answerFor(t, whitespace); a.Error != "the document is 262148 bytes; the engine reads up to 262144, and AWS accepts a role trust policy of at most 8192 characters" {
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
	compared := 0
	for name, doc := range docs {
		a := admits(doc)
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
			want, err := json.Marshal(explain(doc, tok))
			if err != nil {
				t.Fatal(err)
			}
			if got := Explain(doc, tok); !bytes.Equal(got, want) {
				t.Errorf("explain %s with %s:\n got %s\nwant %s", name, tokenName, got, want)
			}
			compared++
		}
	}
	if compared < 200 {
		t.Fatalf("%d answers compared; the test would examine too little", compared)
	}
	// the zero values, whose nil lists no reachable answer carries
	for name, v := range map[string]any{"answer": Answer{}, "explanation": Explanation{}, "grant": Answer{Grants: []Grant{{}}}, "outcome": Explanation{Grants: []Outcome{{}}}} {
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
