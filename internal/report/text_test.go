package report

import (
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"unicode/utf8"
)

// escapes is the fixture that carries terminal escapes where a document can
// carry them: in a Sid, in a claim's value, in a condition key and in an
// operator's name. Every document in the corpus is well behaved, so without
// it the stripping rules below would be asserted over text that never had a
// control character in it.
const escapes = "testdata/escapes.json"

func fixture(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// controls counts the control characters a terminal acts on: C0 and C1,
// newline and tab excepted, which are the two docs/ENGINEERING.md section 9
// keeps.
func controls(s string) int {
	n := 0
	for _, r := range s {
		if r == '\n' || r == '\t' {
			continue
		}
		if r < 0x20 || (r >= 0x7f && r <= 0x9f) {
			n++
		}
	}
	return n
}

// The page renders the spans and the command renders the sentence. If the
// two disagree the same grant reads differently on the two surfaces, which
// is the one thing moving this package into the CLI's path must not allow.
func TestTheSentenceIsExactlyItsSpans(t *testing.T) {
	docs := corpus(t)
	docs[escapes] = fixture(t, filepath.Join(escapes))
	checked := 0
	for path, raw := range docs {
		for _, g := range answerFor(t, raw).Grants {
			var b strings.Builder
			for _, s := range g.Spans {
				b.WriteString(s.Text)
			}
			if b.String() != g.Sentence {
				t.Errorf("%s grant %d:\n spans %q\n  says %q", path, g.Number, b.String(), g.Sentence)
			}
			if n := controls(g.Sentence); n != 0 {
				t.Errorf("%s grant %d: the sentence carries %d control characters", path, g.Number, n)
			}
			for i, s := range g.Spans {
				if n := controls(s.Text); n != 0 {
					t.Errorf("%s grant %d span %d: %d control characters in %q", path, g.Number, i, n, s.Text)
				}
			}
			checked++
		}
	}
	if checked < 20 {
		t.Fatalf("%d grants checked; the corpus did not load", checked)
	}
	t.Logf("%d grants checked over %d documents", checked, len(docs))
}

// The fixture is the input the test above depends on, so its escapes are
// asserted rather than trusted: a fixture quietly repaired would leave the
// stripping rules passing over text that needs none.
func TestTheEscapeFixtureCarriesEscapes(t *testing.T) {
	raw := fixture(t, escapes)
	a := answerFor(t, raw)
	if a.Error != "" {
		t.Fatalf("the fixture is not read: %s", a.Error)
	}
	if n := controls(a.Document.Statements[0].Sid); n != 2 {
		t.Errorf("statement[0] carries %d control characters in its Sid, want 2", n)
	}
	in := 0
	for _, g := range a.Grants {
		in += controls(g.Sid) + controls(g.Admits)
		for _, term := range g.Terms {
			for _, row := range term {
				in += controls(row.Claim) + controls(row.Rendered)
			}
		}
		in += controls(g.Witness)
	}
	if in == 0 {
		t.Fatal("the fixture's answer carries no control character outside its spans; the renderer below would be proving nothing")
	}
	t.Logf("%d control characters reach the answer's sid, admits, claim names, rendered values and witness", in)
}

// options are the two renderings of every test below: a terminal and a
// pipe. Nothing else about a terminal is an input to the rendering.
var options = map[string]Options{"plain": {}, "coloured": {Colour: true}}

// R2 · no control character leaves the text rendering. The answer itself
// carries them — the test above proves the fixture puts them there — so a
// rendering that printed its strings verbatim would fail here, and a
// terminal reading that output would act on them.
func TestNoControlCharacterLeavesTheText(t *testing.T) {
	docs := corpus(t)
	docs[escapes] = fixture(t, escapes)
	token := []byte(`{"iss":"https://token.actions.githubusercontent.com","aud":"sts.amazonaws.com","sub":"repo:acme/` + "\x1b" + `[31minfra:ref:refs/heads/main"}`)
	for path, raw := range docs {
		for name, o := range options {
			for _, out := range []string{AnswerOf(raw).Text(o), ExplanationOf(raw, token).Text(o)} {
				for i, r := range out {
					if r == '\n' {
						continue
					}
					if r < 0x20 || (r >= 0x7f && r <= 0x9f) {
						if o.Colour && r == 0x1b {
							continue // the marks the command asked for
						}
						t.Errorf("%s (%s): control character %#x at %d", path, name, r, i)
						break
					}
				}
			}
		}
	}
}

// The marks are the page's three and no fourth, and they change nothing
// but the colour: the same words, in the same order, with the same widths.
func TestColourAddsNothingButTheMarks(t *testing.T) {
	sequences := regexp.MustCompile("\x1b" + `\[[0-9;]*m`)
	marks := map[string]bool{"\x1b[34m": true, "\x1b[31m": true, "\x1b[35m": true, "\x1b[0m": true}
	seen := map[string]int{}
	for path, raw := range corpus(t) {
		a := AnswerOf(raw)
		coloured := a.Text(Options{Colour: true})
		for _, s := range sequences.FindAllString(coloured, -1) {
			if !marks[s] {
				t.Errorf("%s: a fourth colour %q", path, s)
			}
			seen[s]++
		}
		if stripped := sequences.ReplaceAllString(coloured, ""); stripped != a.Text(Options{}) {
			t.Errorf("%s: colour changed the words or the widths", path)
		}
	}
	for _, mark := range []string{"\x1b[34m", "\x1b[31m", "\x1b[35m"} {
		if seen[mark] == 0 {
			t.Errorf("no document in the corpus printed %q; the mark is untested", mark)
		}
	}
	t.Logf("marks printed over the corpus: %v", seen)
}

// A value is never cut and never wrapped: a cut value is a wrong value,
// and the width of the terminal it is read in is not an input here.
func TestNothingIsTruncated(t *testing.T) {
	long := strings.Repeat("a-very-long-repository-name", 20)
	raw := []byte(`{"Version":"2012-10-17","Statement":[{"Sid":"` + long + `","Effect":"Allow","Principal":{"Federated":"token.actions.githubusercontent.com"},"Action":"sts:AssumeRoleWithWebIdentity","Condition":{"StringEquals":{"token.actions.githubusercontent.com:sub":"repo:` + long + `"}}}]}`)
	out := AnswerOf(raw).Text(Options{})
	if !strings.Contains(out, long) {
		t.Fatal("a long value was not printed whole")
	}
	if strings.Contains(out, "…") || strings.Contains(out, "...") {
		t.Error("something was elided")
	}
	widest := 0
	for _, line := range strings.Split(out, "\n") {
		if n := utf8.RuneCountInString(line); n > widest {
			widest = n
		}
	}
	if widest < 80 {
		t.Errorf("the widest line is %d characters; this document cannot be rendered inside any fixed width", widest)
	}
}

// A column is as wide as its widest cell and no wider: two spaces after
// the longest value in it, so that the table is read down its columns.
func TestColumnsAreAsWideAsTheirContent(t *testing.T) {
	a := AnswerOf(fixture(t, filepath.Join(testdata, "grants", "03-whole-organisation", "aws.json")))
	out := a.Text(Options{})
	var header, first string
	for i, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "CLAIM") {
			header, first = line, strings.Split(out, "\n")[i+1]
		}
	}
	if header == "" {
		t.Fatal("no term table was printed")
	}
	claims := []string{}
	for _, row := range a.Grants[0].Terms[0] {
		claims = append(claims, row.Claim)
	}
	widest := 0
	for _, c := range append(claims, "CLAIM") {
		if n := utf8.RuneCountInString(c); n > widest {
			widest = n
		}
	}
	if got := strings.Index(header, "ADMITS"); got != widest+2 {
		t.Errorf("the second column starts at %d; the widest cell of the first is %d and the gap is 2", got, widest)
	}
	if strings.Index(first, a.Grants[0].Terms[0][0].Rendered) != widest+2 {
		t.Errorf("the first row does not line up with the heading:\n%s\n%s", header, first)
	}
	if strings.HasSuffix(header, " ") || strings.HasSuffix(first, " ") {
		t.Error("a row was padded past its last cell")
	}
}

// The witness is a decoded payload, and its lines are its own: the
// stripping that keeps an escape out must not take the newlines with it.
func TestTheWitnessKeepsItsLines(t *testing.T) {
	raw := fixture(t, filepath.Join(testdata, "grants", "03-whole-organisation", "aws.json"))
	a := AnswerOf(raw)
	out := a.Text(Options{})
	lines := strings.Split(a.Grants[0].Witness, "\n")
	if len(lines) < 4 {
		t.Fatalf("the witness is %d lines; this test needs the block", len(lines))
	}
	for _, line := range lines {
		if !strings.Contains(out, "\n  "+line+"\n") {
			t.Errorf("the witness line %q is not printed on a line of its own", line)
		}
	}
}

// TestDeterminismOfTheText is named so that `make determinism` runs it:
// the target's -run is an unanchored regexp over the test names, and it
// reaches ./internal/... only. Twenty renderings in this process, and the
// target runs the whole thing again in twenty fresh ones, which is the
// half that catches an unsorted range over a map.
func TestDeterminismOfTheText(t *testing.T) {
	docs := corpus(t)
	docs[escapes] = fixture(t, escapes)
	token := []byte(`{"iss":"https://token.actions.githubusercontent.com","aud":"sts.amazonaws.com","sub":"repo:acme/infra:ref:refs/heads/main","repository_owner_id":"123456"}`)
	for path, raw := range docs {
		for _, o := range options {
			first, firstExplained := AnswerOf(raw).Text(o), ExplanationOf(raw, token).Text(o)
			for i := 0; i < 20; i++ {
				if AnswerOf(raw).Text(o) != first {
					t.Fatalf("%s: rendering %d differs", path, i)
				}
				if ExplanationOf(raw, token).Text(o) != firstExplained {
					t.Fatalf("%s: explanation %d differs", path, i)
				}
			}
		}
	}
}

// The forbidden words, over the text as well as over the JSON: the same
// guard the page's answers pass, on the surface the command prints.
func TestNoForbiddenWordReachesTheTerminal(t *testing.T) {
	docs := corpus(t)
	docs[escapes] = fixture(t, escapes)
	token := []byte(`{"iss":"https://x.example","aud":"y"}`)
	for path, raw := range docs {
		for name, o := range options {
			for _, out := range []string{AnswerOf(raw).Text(o), ExplanationOf(raw, token).Text(o)} {
				if m := forbidden.FindString(out); m != "" {
					t.Errorf("%s (%s): %q in the text", path, name, m)
				}
			}
		}
	}
}

// ownWords are every word the rendering composes for itself: the column
// headings, the numbering, the labels and the one sentence it says that
// the answer does not. Everything else it prints must be a string the
// answer carries. The test below deletes both sets from the output and
// fails on anything left, so a sentence written here rather than read from
// the answer shows up as residue — which is the drift a second copy of the
// words in words.go would begin with.
var ownWords = []string{
	"This command reads no other dialect yet, so each member the IAM policy grammar does not define was read as a statement.",
	"The document was not read as an AWS trust policy, and this command reads no other dialect yet.",
	"decoded from the payload segment of a whole token",
	"read as an aws trust policy",
	"no condition names it",
	"read as a payload",
	"IN WORDS · AS WRITTEN",
	"THE GRANT ADMITS",
	"any other claim",
	"unconstrained",
	"document notes",
	"issuer at",
	"statement",
	"THE TOKEN",
	"statements",
	"RESULT",
	"ADMITS",
	"CLAIM",
	"offset",
	"sha256",
	"version",
	"claims",
	"claim",
	"bytes",
	"lines",
	"notes",
	"grant",
	"token",
	"byte",
	"line",
	"note",
	"any",
	"of",
}

func TestTheRenderingSaysNothingOfItsOwn(t *testing.T) {
	docs := corpus(t)
	docs[escapes] = fixture(t, escapes)
	docs["not a document"] = []byte("{ not a policy")
	// Every document in the corpus is an AWS policy, so without one whose
	// members the grammar does not define the sentence about them is
	// declared below and never printed, and the rule would be asserted over
	// renderings that never compose it.
	docs["a member outside the grammar"] = []byte(`{"Version":"2012-10-17","Foo":{"a":1}}`)
	payload := `{"iss":"https://token.actions.githubusercontent.com","aud":"sts.amazonaws.com","sub":"repo:acme/infra:ref:refs/heads/main","extra":"x"}`
	// Both shapes a token arrives in, because the rendering says which one
	// it read and the two sentences are different words.
	tokens := [][]byte{
		[]byte(payload),
		[]byte("eyJhbGciOiJSUzI1NiJ9." + base64.RawURLEncoding.EncodeToString([]byte(payload)) + ".c2ln"),
	}
	letters := regexp.MustCompile(`\p{L}+`)
	examined := 0
	printed := map[string]bool{}
	for path, raw := range docs {
		renderings := map[string][]string{AnswerOf(raw).Text(Options{}): AnswerOf(raw).strings()}
		for _, token := range tokens {
			x := ExplanationOf(raw, token)
			renderings[x.Text(Options{})] = x.strings()
		}
		for out, carried := range renderings {
			for _, w := range ownWords {
				printed[w] = printed[w] || strings.Contains(out, w)
			}
			residue := out
			for _, s := range longestFirst(append(withoutTheirControls(carried), ownWords...)) {
				residue = strings.ReplaceAll(residue, s, " ")
			}
			if left := letters.FindAllString(residue, -1); len(left) > 0 {
				t.Errorf("%s: the rendering says %q, which is neither the answer's nor declared in ownWords", path, left)
			}
			examined++
		}
	}
	if examined < 40 {
		t.Fatalf("%d renderings examined; the corpus did not load", examined)
	}
	// Every declared word is printed by one of them. A word declared here
	// and printed by nothing takes the rule with it silently: the list
	// stops being what the rendering composes and becomes a list of things
	// it is allowed to say, and the first of those the answer stopped
	// carrying would pass unseen.
	for _, w := range ownWords {
		if !printed[w] {
			t.Errorf("declared here and printed by no rendering: %q", w)
		}
	}
	t.Logf("%d renderings carry no word but the answer's and the %d declared here, every one of which is printed", examined, len(ownWords))
}

// withoutTheirControls is each string as the rendering is allowed to
// print it: with the control characters gone, which is what R2 requires of
// it. The rule is spelt out here rather than borrowed from the package, so
// that a change to the package's stripping cannot make this test agree
// with it by construction.
func withoutTheirControls(all []string) []string {
	out := make([]string, 0, 2*len(all))
	for _, s := range all {
		out = append(out, s, strings.Map(func(r rune) rune {
			if r < 0x20 || (r >= 0x7f && r <= 0x9f) {
				return -1
			}
			return r
		}, s))
	}
	return out
}

func longestFirst(all []string) []string {
	out := make([]string, 0, len(all))
	for _, s := range all {
		if s != "" {
			out = append(out, s)
		}
	}
	slices.SortFunc(out, func(a, b string) int { return len(b) - len(a) })
	return out
}

// strings is every string an answer carries, which is every string the
// rendering is allowed to print.
func (a Answer) strings() []string {
	out := []string{a.Error}
	if a.Document != nil {
		out = append(out, a.Document.Version, a.Document.SHA256)
		for _, s := range a.Document.Statements {
			out = append(out, s.Sid, s.SHA256)
		}
		out = append(out, noteStrings(a.Document.Anomalies)...)
	}
	for _, g := range a.Grants {
		out = append(out, g.Sid, g.Issuer, g.Effect, g.Admits, g.Sentence, g.Caption,
			g.Witness, g.WitnessHeading, g.WitnessCaption)
		if g.IssuerWritten != nil {
			out = append(out, writtenStrings([]Written{*g.IssuerWritten})...)
		}
		out = append(out, strings.Split(g.Witness, "\n")...)
		out = append(out, noteStrings(g.Notes)...)
		for _, term := range g.Terms {
			for _, row := range term {
				out = append(out, row.Claim, row.Rendered, row.Words)
				out = append(out, writtenStrings(row.Written)...)
			}
		}
		for _, s := range g.Spans {
			out = append(out, s.Text)
		}
	}
	return out
}

func (x Explanation) strings() []string {
	out := []string{x.Error, x.Token.Error, x.Sentence}
	for _, s := range x.Spans {
		out = append(out, s.Text)
	}
	for _, s := range x.Heading {
		out = append(out, s.Text)
	}
	for _, o := range x.Grants {
		out = append(out, o.Sid, o.Issuer, o.Effect, o.Sentence)
		for _, s := range append(o.Spans, o.Heading...) {
			out = append(out, s.Text)
		}
		for _, row := range o.Claims {
			out = append(out, row.Claim, row.Value, row.Rendered, row.Result, row.Why)
			out = append(out, writtenStrings(row.Written)...)
		}
	}
	return out
}

func noteStrings(notes []Note) []string {
	out := []string{}
	for _, n := range notes {
		out = append(out, n.Kind, n.Anomaly, n.Claim, n.Construct, n.Message, n.Source)
	}
	return out
}

func writtenStrings(ws []Written) []string {
	out := []string{}
	for _, w := range ws {
		out = append(out, w.Operator, w.Member)
	}
	return out
}

// The command renders one answer two ways and must not compute it twice,
// so it takes the JSON from the answer it already has. That path has to be
// the same bytes as the entry the explorer calls, or the two surfaces are
// no longer showing the same answer.
func TestTheAnswersJSONIsTheEntrysBytes(t *testing.T) {
	docs := corpus(t)
	docs[escapes] = fixture(t, escapes)
	docs["not a document"] = []byte("{ not a policy")
	token := []byte(`{"iss":"https://token.actions.githubusercontent.com","aud":"sts.amazonaws.com"}`)
	for path, raw := range docs {
		if got, want := AnswerOf(raw).JSON(), Admits(raw); !bytes.Equal(got, want) {
			t.Errorf("%s: the answer's JSON is not the bytes Admits writes", path)
		}
		if got, want := ExplanationOf(raw, token).JSON(), Explain(raw, token); !bytes.Equal(got, want) {
			t.Errorf("%s: the explanation's JSON is not the bytes Explain writes", path)
		}
	}
}

// Text is exported and takes a value, so it is rendered for answers no
// reading produces: an empty one, and one whose grant names a statement
// the document does not carry. Neither may panic, and neither may invent a
// line it cannot stand behind.
func TestAnAnswerBuiltByHand(t *testing.T) {
	if got := (Answer{}).Text(Options{}); got != "" {
		t.Errorf("an empty answer rendered %q", got)
	}
	// an explanation of a token with no claims is not empty: `--token {}`
	// is a token that was read and carries nothing, and the line says so
	if got := (Explanation{}).Text(Options{}); got != "token · 0 claims · read as a payload\n" {
		t.Errorf("an explanation with no grants rendered %q", got)
	}
	loose := Answer{V: Version, Grants: []Grant{{
		Number: 1, Statement: 4, Effect: "Allow", Sentence: "This role admits nobody in particular.",
		Spans: []Span{{Text: "This role admits nobody in particular."}},
		Terms: [][]Claim{
			{{Claim: "sub", Rendered: `"a"`, Words: "exactly this subject", Mark: "exact"}},
			{{Claim: "sub", Rendered: `"b"`, Words: "exactly this subject", Mark: "exact"}},
		},
	}}}
	out := loose.Text(Options{})
	// a term of two alternatives is labelled as the page labels it, and a
	// statement the document does not carry leaves the evidence line with
	// the one thing that is still true: which statement the grant names
	for _, want := range []string{"term 1 of 2", "term 2 of 2", "This role admits nobody in particular.", "\nstatement[4]\n"} {
		if !strings.Contains(out, want) {
			t.Errorf("an answer built by hand does not carry %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "sha256") || strings.Contains(out, "offset") {
		t.Error("the evidence line claims a digest or an offset for a statement it does not have")
	}
}

// A statement with no Sid is named by its index alone: quoting an empty
// string would be a name the document does not carry.
func TestAStatementWithNoSid(t *testing.T) {
	raw := []byte(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Federated":"token.actions.githubusercontent.com"},"Action":"sts:AssumeRoleWithWebIdentity","Condition":{"StringEquals":{"token.actions.githubusercontent.com:sub":"repo:a/b:ref:refs/heads/main"}}}]}`)
	out := AnswerOf(raw).Text(Options{})
	if !strings.Contains(out, "grant 1 of 1 · statement[0] · Allow") {
		t.Errorf("a statement with no Sid:\n%s", out)
	}
	if strings.Contains(out, `statement[0] ""`) {
		t.Error("an empty Sid was quoted as if the document wrote one")
	}
}

// A whole token is read from its payload segment, and the line above the
// table says which of the two the reader handed over.
func TestAWholeTokenIsSaidToBeDecoded(t *testing.T) {
	payload := `{"iss":"https://token.actions.githubusercontent.com","aud":"sts.amazonaws.com","sub":"repo:acme/infra:ref:refs/heads/main"}`
	whole := "eyJhbGciOiJSUzI1NiJ9." + base64.RawURLEncoding.EncodeToString([]byte(payload)) + ".c2ln"
	raw := fixture(t, filepath.Join(testdata, "grants", "03-whole-organisation", "aws.json"))
	out := ExplanationOf(raw, []byte(whole)).Text(Options{})
	if !strings.Contains(out, "decoded from the payload segment of a whole token") {
		t.Errorf("a whole token:\n%s", out)
	}
	if !strings.Contains(ExplanationOf(raw, []byte(payload)).Text(Options{}), "read as a payload") {
		t.Error("a payload was said to be decoded from a whole token")
	}
}

// The refusal is composed here, not by whoever prints it. A document this
// package cannot read gets the engine's own sentence about the bytes and
// one sentence saying which documents are read at all, and both surfaces
// get both: a sentence moved into the command would be a second place the
// product's words live, and the page would lose it silently.
func TestTheRefusalIsTheReports(t *testing.T) {
	const reads = "The document was not read as an AWS trust policy, and this command reads no other dialect yet."
	for _, raw := range [][]byte{[]byte(""), []byte("{ not a policy"), []byte("[1]")} {
		answer := AnswerOf(raw)
		out := answer.Text(Options{})
		if !strings.Contains(out, answer.Error) || !strings.Contains(out, reads) {
			t.Errorf("the refusal of %q is %q", raw, out)
		}
		x := ExplanationOf(raw, []byte(`{"sub":"x"}`))
		if out := x.Text(Options{}); !strings.Contains(out, x.Error) || !strings.Contains(out, reads) {
			t.Errorf("the refusal of %q with a token is %q", raw, out)
		}
	}
	// A token that cannot be read is refused with the sentence about the
	// token and nothing else. The document was read: saying it was not is
	// a statement about this run that is false, and it is the sentence a
	// reader would act on first.
	x := ExplanationOf(fixture(t, filepath.Join(testdata, "grants", "01-one-repo-one-branch", "aws.json")), []byte("not a token"))
	out := x.Text(Options{})
	if !strings.Contains(out, x.Token.Error) {
		t.Errorf("the refusal of a token is %q", out)
	}
	if strings.Contains(out, reads) {
		t.Errorf("a token that could not be read says the document was not read:\n%s", out)
	}
	// A document longer or deeper than the engine reads is refused for how
	// much of it there is, and no reader saw a byte of it. The dialect it
	// is written in was never in question, so the sentence about which
	// dialects have a reader sends its reader to check something nothing
	// examined, and the bound was the whole reason.
	for name, raw := range map[string][]byte{
		"longer than the engine reads": append(bytes.Repeat([]byte(" "), MaxDocumentBytes), '{'),
		"deeper than the engine reads": nested(MaxDocumentNesting + 2),
	} {
		a := AnswerOf(raw)
		if a.Error == "" {
			t.Fatalf("%s: the document was read, so the bound this case is about did not fire", name)
		}
		if out := a.Text(Options{}); !strings.Contains(out, a.Error) || strings.Contains(out, reads) {
			t.Errorf("%s:\n%s", name, out)
		}
		x := ExplanationOf(raw, []byte(`{"sub":"x"}`))
		if out := x.Text(Options{}); !strings.Contains(out, x.Error) || strings.Contains(out, reads) {
			t.Errorf("%s, with a token:\n%s", name, out)
		}
	}
}

// nested is a document of nothing but brackets, levels deep.
func nested(levels int) []byte {
	return []byte(strings.Repeat("[", levels) + strings.Repeat("]", levels))
}

// unknownInATerm is the shape no document in the corpus has: a claim the
// engine could not evaluate sitting in a term that names other claims,
// with a terminal escape in the claim's name. The witness caption is the
// only sentence in the package that interpolates a claim name, and this is
// the only shape that reaches it, so without a document like this one the
// rules below are asserted over renderings that never compose it.
var unknownInATerm = []byte(`{"Version":"2012-10-17","Statement":[{"Sid":"Unknown","Effect":"Allow","Principal":{"Federated":"token.actions.githubusercontent.com"},"Action":"sts:AssumeRoleWithWebIdentity","Condition":{"StringEquals":{"token.actions.githubusercontent.com:aud":"sts.amazonaws.com","token.actions.githubusercontent.com:sub":"repo:acme/infra:ref:refs/heads/main"},"ForAnyValue:StringEquals":{"token.actions.githubusercontent.com:\u001b[31mjob_workflow_ref":"repo:acme/infra/.github/workflows/deploy.yml@refs/heads/main"}}}]}`)

// The fixture above is the input the rules below depend on, so what makes
// it interesting is asserted rather than trusted: a fixture that stopped
// producing an unevaluated claim inside a term would leave those rules
// passing over a rendering that never reaches the sentence they are about.
func TestTheUnknownClaimFixtureIsWhatItClaims(t *testing.T) {
	a := answerFor(t, unknownInATerm)
	if a.Error != "" {
		t.Fatalf("the fixture is not read: %s", a.Error)
	}
	found := false
	for _, g := range a.Grants {
		for _, term := range g.Terms {
			if len(term) < 2 {
				continue
			}
			for _, row := range term {
				if row.Mark != "unknown" || controls(row.Claim) == 0 {
					continue
				}
				if !strings.Contains(g.WitnessCaption, row.Claim) {
					t.Fatalf("the witness caption does not name the unevaluated claim: %q", g.WitnessCaption)
				}
				found = true
			}
		}
	}
	if !found {
		t.Fatal("no term of the fixture holds an unevaluated claim whose name carries an escape")
	}
}

// R2, over the shape the corpus does not have. The claim name reaches the
// witness caption, and a caption printed as the answer carries it would
// put a raw escape on a terminal's screen.
func TestNoControlCharacterLeavesTheWitnessCaption(t *testing.T) {
	for name, o := range options {
		out := AnswerOf(unknownInATerm).Text(o)
		for i, r := range out {
			if r == '\n' {
				continue
			}
			if r < 0x20 || (r >= 0x7f && r <= 0x9f) {
				if o.Colour && r == 0x1b {
					continue // the marks the command asked for
				}
				t.Errorf("(%s): control character %#x at %d, in %q", name, r, i, out[max(0, i-40):min(len(out), i+40)])
				break
			}
		}
	}
}

// R2, over the one path the answer's own composition already strips: the
// spans. Answer, Explanation and Text are exported and take values, and
// the engine is not the only thing that composes one — the test above
// renders answers no reading produces, and the explorer and the command
// both hand this package values they hold. The strip inside paint is what
// stands between a span composed anywhere else and the terminal, and every
// other rule here is satisfied by the strip at composition alone, so
// without this test that one could be taken out and nothing would say so.
func TestNoControlCharacterLeavesASpanComposedElsewhere(t *testing.T) {
	// neither escape is one of the three marks, so removing the marks below
	// cannot remove these: ESC [ 2 K erases the line it is printed on, and
	// U+009B is the 8-bit introducer that does what ESC [ does
	const raw = "repo:acme/\x1b[2Kinfra:ref:refs/heads/\u009b1;1Hmain"
	if controls(raw) != 2 {
		t.Fatalf("the span text carries %d control characters; the rule below would be asserted over text that never had one", controls(raw))
	}
	spans := []Span{{Text: "This role admits "}, {Text: raw, Mark: "exact"}, {Text: "."}}
	answer := Answer{V: Version, Grants: []Grant{{Number: 1, Sentence: plain(spans), Spans: spans}}}
	// two outcomes, because with one grant the policy's answer is that
	// grant's own and the rendering prints it once: an outcome's spans are
	// reached only when the explanation carries more than one
	outcome := func(n int) Outcome {
		return Outcome{Number: n, Heading: spans, Sentence: plain(spans), Spans: spans}
	}
	explanation := Explanation{
		V: Version, Token: Token{Claims: 3},
		Heading: spans, Sentence: plain(spans), Spans: spans,
		Grants: []Outcome{outcome(1), outcome(2)},
	}
	marks := regexp.MustCompile("\x1b\\[(?:34|31|35|0)m")
	for name, render := range map[string]func(Options) string{
		"a grant of an answer":                       answer.Text,
		"the token and the grants of an explanation": explanation.Text,
	} {
		for colour, o := range options {
			out := render(o)
			if strings.Count(out, "This role admits ") == 0 {
				t.Fatalf("%s (%s) rendered none of the spans:\n%s", name, colour, out)
			}
			if n := controls(marks.ReplaceAllString(out, "")); n != 0 {
				t.Errorf("%s (%s): %d control characters reached the rendering:\n%q", name, colour, n, out)
			}
		}
	}
}

// catchAll is the row the page appends to every term: the claims the
// document names are the ones it constrains, and every other claim is
// unconstrained. A table that stopped at the rows the document writes
// reads as a closed list — the claims that matter — which is the opposite
// of what a term says, and a term that names no claim at all is that one
// row by itself.
const catchAll = "any other claim"

func TestEveryTermSaysWhatTheDocumentDoesNotName(t *testing.T) {
	docs := corpus(t)
	docs[escapes] = fixture(t, escapes)
	docs["unknown claim in a term"] = unknownInATerm
	terms, naming := 0, 0
	for path, raw := range docs {
		a := AnswerOf(raw)
		want := 0
		for _, g := range a.Grants {
			want += len(g.Terms)
			for _, term := range g.Terms {
				if len(term) == 0 {
					naming++
				}
			}
		}
		if got := strings.Count(a.Text(Options{}), catchAll); got != want {
			t.Errorf("%s: %d terms, %d rows for the claims the document does not name", path, want, got)
		}
		terms += want
	}
	if naming == 0 {
		t.Fatal("no term in the corpus names no claim; the case this test exists for is not in the inputs")
	}
	t.Logf("%d terms, %d of them naming no claim", terms, naming)
}

// The words are printed on a page and in a terminal by the same package,
// so a sentence that names one surface is false on the other. The rule is
// on the answer's own sentences rather than on the rendering, because the
// rendering prints them verbatim and both surfaces take them from here.
func TestNoSentenceOfTheAnswerNamesASurface(t *testing.T) {
	docs := corpus(t)
	docs[escapes] = fixture(t, escapes)
	docs["unknown claim in a term"] = unknownInATerm
	surfaces := regexp.MustCompile(`(?i)this page|this command|this terminal|on screen|this browser`)
	checked := 0
	for path, raw := range docs {
		a := AnswerOf(raw)
		for _, g := range a.Grants {
			for _, s := range []string{g.Sentence, g.Caption, g.WitnessHeading, g.WitnessCaption} {
				if m := surfaces.FindString(s); m != "" {
					t.Errorf("%s grant %d: %q names a surface in %q", path, g.Number, m, s)
				}
				checked++
			}
		}
	}
	if checked < 100 {
		t.Fatalf("%d sentences checked; the corpus did not load", checked)
	}
	t.Logf("%d sentences of the answer name no surface", checked)
}

// The two lines the rendering owns about which dialect was applied to the
// bytes, spelt out here rather than read from the package: a test that
// borrowed the constant would agree with whatever it was changed to.
const (
	wantReadAs     = "read as an aws trust policy"
	wantReadAnyway = "This command reads no other dialect yet, so each member the IAM policy grammar does not define was read as a statement."
)

// A document whose members the IAM grammar does not define is still
// answered — the parser reads each such member as a statement it could not
// read — and the rendering may not state as a fact that the bytes are an
// AWS trust policy. Nothing established that, and the reader holding an
// Azure credential needs to be told which dialect was applied to it.
//
// The second line is about those members and about nothing else. The
// parser gives "the document has no Statement member" and "Statement is an
// empty list" the same kind, construct and source, so a rendering that
// recognised the case by that triple prints the explanation of the first
// under the second — where the document does have a Statement member and
// nothing at all was read as a statement.
func TestADocumentWithNoStatementMemberIsNotCalledATrustPolicy(t *testing.T) {
	credential := []byte(`{"@odata.type":"#microsoft.graph.federatedIdentityCredential","name":"deploy","issuer":"https://token.actions.githubusercontent.com","subject":"repo:acme/infra:ref:refs/heads/main","audiences":["api://AzureADTokenExchange"]}`)
	emptyList := []byte(`{"Version":"2012-10-17","Statement":[]}`)
	saying := map[string][]byte{
		"an azure federated identity credential":         credential,
		"one member outside the grammar":                 []byte(`{"Version":"2012-10-17","Foo":{"a":1}}`),
		"a Statement member and one outside the grammar": []byte(`{"Statement":[],"Foo":{"a":1}}`),
	}
	silent := map[string][]byte{
		"an empty Statement list":              emptyList,
		"a document with no member at all":     []byte(`{}`),
		"a version and nothing else":           []byte(`{"Version":"2012-10-17"}`),
		"a policy every member of which reads": grantCase(t, "01-one-repo-one-branch"),
	}
	// The document block is the shape line, the digest, and then either
	// the sentence or the blank line that ends the block, so what the
	// rendering says about the reading is the third line and its absence
	// is that line being empty.
	for want, docs := range map[string]map[string][]byte{wantReadAnyway: saying, "": silent} {
		for name, raw := range docs {
			out := AnswerOf(raw).Text(Options{})
			if strings.HasPrefix(out, "aws trust policy") {
				t.Errorf("%s is stated to be an aws trust policy:\n%s", name, out)
			}
			if !strings.HasPrefix(out, wantReadAs) {
				t.Errorf("%s: the first line does not say how the bytes were read:\n%s", name, out)
			}
			lines := strings.Split(out, "\n")
			if len(lines) < 3 {
				t.Fatalf("%s: the rendering has no document block:\n%s", name, out)
			}
			if lines[2] != want {
				t.Errorf("%s: the rendering says %q of the reading, want %q:\n%s", name, lines[2], want, out)
			}
		}
	}
	// The guard on the empty list, which is the case the two triples are
	// told apart by: it must still carry the anomaly a rendering that read
	// the wording would match, or this test passes over a document that
	// never reached the rule it is about.
	anomalies := AnswerOf(emptyList).Document.Anomalies
	if !slices.ContainsFunc(anomalies, func(n Note) bool {
		return n.Anomaly == "malformed" && n.Construct == "Statement" && n.Source == "document"
	}) {
		t.Fatalf("an empty Statement list no longer carries the anomaly this rule turns on: %v", anomalies)
	}
}
