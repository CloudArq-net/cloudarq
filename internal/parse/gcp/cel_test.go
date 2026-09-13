package gcp

import (
	"maps"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/CloudArq-net/cloudarq/internal/eval"
	"github.com/CloudArq-net/cloudarq/internal/trust"
)

// sexpr renders a parse tree as nested lists, so that a test can pin the
// grouping the parser chose without depending on how the tree is stored.
func sexpr(n *expr) string {
	switch n.kind {
	case exprString:
		return strconv.Quote(n.text)
	case exprBytes:
		return "b" + strconv.Quote(n.text)
	case exprLiteral, exprIdent:
		return n.text
	case exprSelect:
		return "(. " + sexpr(n.kids[0]) + " " + n.text + ")"
	case exprCall:
		parts := []string{"(" + n.text}
		if n.kids[0] != nil {
			parts[0] = "(." + n.text
			parts = append(parts, sexpr(n.kids[0]))
		}
		for _, k := range n.kids[1:] {
			parts = append(parts, sexpr(k))
		}
		return strings.Join(parts, " ") + ")"
	}
	parts := []string{"(" + n.text}
	if n.kind == exprList {
		parts[0] = "(list"
	}
	if n.kind == exprMap {
		parts[0] = "(map"
	}
	if n.kind == exprTernary {
		parts[0] = "(?:"
	}
	if n.kind == exprIndex {
		parts[0] = "(index"
	}
	for _, k := range n.kids {
		parts = append(parts, sexpr(k))
	}
	return strings.Join(parts, " ") + ")"
}

func mustParse(t *testing.T, src string) *expr {
	t.Helper()
	n, err := parseCEL(src)
	if err != nil {
		t.Fatalf("parseCEL(%q): %v", src, err)
	}
	return n
}

// TestStringLiterals: every escape CEL defines decodes to the code point it
// names, raw strings keep their backslashes, triple quotes hold newlines and
// the other quote, and every form the lexer does not know is a refusal
// rather than a backslash dropped or a character kept.
func TestStringLiterals(t *testing.T) {
	decoded := map[string]string{
		`'a'`:                   "a",
		`"a"`:                   "a",
		`''`:                    "",
		`'it\'s'`:               "it's",
		`"say \"hi\""`:          `say "hi"`,
		`'\\'`:                  `\`,
		`'\a\b\f\n\r\t\v'`:      "\a\b\f\n\r\t\v",
		"'\\?\\`'":              "?`",
		`'\x41\X42'`:            "AB",
		`'\u00e9'`:              "\u00e9",
		`'\u00E9'`:              "\u00e9",
		`'\U0001F600'`:          "😀",
		`'\101\377'`:            "A\u00ff",
		`r'a\nb'`:               `a\nb`,
		`R"a\\b"`:               `a\\b`,
		`r'a\ib'`:               `a\ib`,
		`r'\'`:                  `\`,
		`'''x''x'''`:            "x''x",
		"'''line\nbreak'''":     "line\nbreak",
		`"""say "hi" here"""`:   `say "hi" here`,
		`r'''raw \n triple'''`:  `raw \n triple`,
		`'https://example.com'`: "https://example.com",
		`'a // not a comment'`:  "a // not a comment",
	}
	for src, want := range decoded {
		n := mustParse(t, src)
		if n.kind != exprString || n.text != want {
			t.Errorf("%s parsed to kind %d %q, want string %q", src, n.kind, n.text, want)
		}
	}
	bytesLiterals := []string{`b'abc'`, `B"abc"`, `br'a\nb'`, `bR'x'`, `Br'x'`, `BR'x'`}
	for _, src := range bytesLiterals {
		if n := mustParse(t, src); n.kind != exprBytes {
			t.Errorf("%s parsed to kind %d, want bytes", src, n.kind)
		}
	}
	refused := map[string]string{
		`'unterminated`:      "unterminated string literal",
		"'line\nbreak'":      "unterminated string literal",
		`'\s'`:               "invalid escape sequence",
		`'\x4'`:              "invalid escape sequence",
		`'\u12'`:             "invalid escape sequence",
		`'\ud800'`:           "invalid escape sequence",
		`'\U00110000'`:       "invalid escape sequence",
		`'\400'`:             "invalid escape sequence",
		`'\8'`:               "invalid escape sequence",
		`'a' 'b'`:            `unexpected "'b'" after the expression`,
		`r'it\'s'`:           "unterminated string literal",
		`rb'x'`:              "unexpected",
		`'''unterminated''`:  "unterminated string literal",
		`'a' // comment 'b'`: "",
	}
	for src, problem := range refused {
		_, err := parseCEL(src)
		if problem == "" {
			if err != nil {
				t.Errorf("%s: refused: %v", src, err)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), problem) {
			t.Errorf("%s: err %v, want %q", src, err, problem)
		}
	}
}

// TestCarriageReturnsInLiterals: a triple-quoted literal may hold a raw
// newline; cel-go and cel-cpp both read a carriage return, alone or before
// a line feed, as a line feed, and the language definition does not say.
// The lexer reads the literal as the two implementations do and marks it,
// so that the evaluator can decline to claim exactness on a value the
// specification does not settle; an escaped \r and a raw line feed are
// settled and unmarked.
func TestCarriageReturnsInLiterals(t *testing.T) {
	cases := map[string]struct {
		text    string
		newline bool
	}{
		"'''a\r\nb'''":     {"a\nb", true},
		"'''a\rb'''":       {"a\nb", true},
		"r'''a\r\nb'''":    {"a\nb", true},
		"r'''a\rb'''":      {"a\nb", true},
		"\"\"\"a\r\"\"\"":  {"a\n", true},
		"'''\r\n'''":       {"\n", true},
		"'''a\r\n\r\nb'''": {"a\n\nb", true},
		`'''a\rb'''`:       {"a\rb", false},
		"'''a\nb'''":       {"a\nb", false},
		`'a\rb'`:           {"a\rb", false},
	}
	for src, want := range cases {
		n := mustParse(t, src)
		if n.kind != exprString || n.text != want.text || n.newline != want.newline {
			t.Errorf("%q parsed to kind %d %q newline %v, want string %q newline %v", src, n.kind, n.text, n.newline, want.text, want.newline)
		}
	}
	if n := mustParse(t, "b'''a\rb'''"); n.kind != exprBytes || n.text != "a\nb" {
		t.Errorf("bytes: kind %d %q", n.kind, n.text)
	}
	for _, src := range []string{"'a\rb'", "'a\r\nb'", "r'a\rb'"} {
		if _, err := parseCEL(src); err == nil || !strings.Contains(err.Error(), "unterminated string literal") {
			t.Errorf("%q: err %v, want a refusal: a single-quoted literal cannot hold a newline", src, err)
		}
	}
	// Under every modelled form the value is not read: the claim is Unknown
	// with the doubt stated, never an Exact on one of the two readings.
	res := oidcResolver(githubMapping)
	explanation := "cel-go and cel-cpp read one as a line feed and the CEL language definition does not say, so the value is not read and sub is read as unconstrained"
	cases2 := map[string]doubt{
		"assertion.sub == '''a\r\nb'''":          {"sub", "carriage return", `"assertion.sub == '''a\r\nb'''" compares sub against a literal holding an unescaped carriage return; ` + explanation},
		"'''a\rb''' == assertion.sub":            {"sub", "carriage return", `"'''a\rb''' == assertion.sub" compares sub against a literal holding an unescaped carriage return; ` + explanation},
		"assertion.sub in ['c', r'''a\rb''']":    {"sub", "carriage return", `"assertion.sub in ['c', r'''a\rb''']" tests sub for membership of a list holding a literal with an unescaped carriage return; ` + explanation},
		"assertion.sub.startsWith('''a\r\n''')":  {"sub", "carriage return", `"assertion.sub.startsWith('''a\r\n''')" tests sub for a prefix holding an unescaped carriage return; ` + explanation},
		"assertion.sub.endsWith('''\rb''')":      {"sub", "carriage return", `"assertion.sub.endsWith('''\rb''')" tests sub for a suffix holding an unescaped carriage return; ` + explanation},
		"assertion.sub.contains(\"\"\"\r\"\"\")": {"sub", "carriage return", `"assertion.sub.contains(\"\"\"\r\"\"\")" tests sub for a substring holding an unescaped carriage return; ` + explanation},
	}
	for condition, d := range cases2 {
		got := evaluate(t, res, condition)
		if got.admits != "{}" || !slices.Equal(got.anomalies, []trust.Anomaly{d.anomaly()}) || !slices.Equal(got.caveats, []eval.Caveat{d.caveat()}) {
			t.Errorf("%q: %s\n  anomalies %+v\n  caveats %+v\n  want %+v", condition, got.admits, got.anomalies, got.caveats, d.anomaly())
		}
	}
	// A literal that holds a line feed alone, escaped or raw, is exact.
	for condition, want := range map[string]string{
		"assertion.sub == '''a\nb'''": `{sub="a\nb"}`,
		`assertion.sub == 'a\rb'`:     `{sub="a\rb"}`,
	} {
		if got := evaluate(t, res, condition); got.admits != want || len(got.anomalies) != 0 {
			t.Errorf("%q: %s %+v, want %s", condition, got.admits, got.anomalies, want)
		}
	}
}

// TestReservedWordsAsFields: CEL's reserved words cannot be identifiers or
// global function names, but "they *are* valid field names for protos", as
// cel-go's parser puts it, and the language definition permits them as
// receiver-call names; cel-go and cel-cpp check them only where a bare
// identifier or a global call is parsed. assertion.package therefore names
// the claim package, exactly as assertion['package'] does, and refusing it
// would widen every clause beside it for no reason.
func TestReservedWordsAsFields(t *testing.T) {
	res := oidcResolver(githubMapping)
	for _, word := range reserved {
		n := mustParse(t, "assertion."+word+" == 'x'")
		if got, want := sexpr(n), `(== (. assertion `+word+`) "x")`; got != want {
			t.Errorf("%s: %s, want %s", word, got, want)
		}
		want := eval.NewAdmittedSet(eval.Term{trust.ClaimKey(word): eval.Exact("x"), "sub": eval.Exact("deploy")}).String()
		if got := evaluate(t, res, "assertion."+word+" == 'x' && assertion.sub == 'deploy'"); got.admits != want || len(got.anomalies) != 0 {
			t.Errorf("%s: %s %+v, want %s", word, got.admits, got.anomalies, want)
		}
		if got := evaluate(t, res, "assertion['"+word+"'] == 'x'"); got.admits != `{`+word+`="x"}` {
			t.Errorf("%s indexed: %s", word, got.admits)
		}
		// As a receiver-call name it is a function this parser does not
		// model, named as written; as a bare identifier or a global call it
		// stays a refusal.
		if got := evaluate(t, res, "assertion.sub."+word+"('x')"); got.admits != "{}" || len(got.anomalies) != 1 || got.anomalies[0].Construct != word || got.anomalies[0].Claim != "sub" {
			t.Errorf("%s as a receiver call: %s %+v", word, got.admits, got.anomalies)
		}
		for _, src := range []string{word, word + " == 'x'", word + "(assertion.sub)", "assertion.sub == " + word} {
			if _, err := parseCEL(src); err == nil || !strings.Contains(err.Error(), "reserved word "+strconv.Quote(word)) {
				t.Errorf("%q: err %v, want a refusal", src, err)
			}
		}
	}
	// The keywords true, false, null and in are tokens of their own and
	// cannot follow a dot, as the grammar's escapeIdent says.
	for _, src := range []string{"assertion.true", "assertion.false == 'x'", "assertion.null", "assertion.in == 'x'"} {
		if _, err := parseCEL(src); err == nil {
			t.Errorf("%q: parsed, want a refusal", src)
		}
	}
}

// TestSyntaxErrorsNameThePlace: the character index in a syntax error is
// counted in characters, not bytes, so that a customer reading "at
// character 12" can find it in an editor.
func TestSyntaxErrorsNameThePlace(t *testing.T) {
	_, err := parseCEL("assertion.sub == 'é' && #")
	if err == nil || err.at != 24 {
		t.Fatalf("err %v", err)
	}
	if !strings.Contains(err.Error(), "unexpected character \"#\" at character 25") {
		t.Errorf("err %v", err)
	}
}

// TestParserPrecedence pins the grouping of every operator level the grammar
// defines: && binds tighter than ||, relations tighter than both, ! and
// unary - tighter than relations, arithmetic in between, and the ternary
// loosest of all.
func TestParserPrecedence(t *testing.T) {
	cases := map[string]string{
		"a && b || c":                 "(|| (&& a b) c)",
		"a || b && c":                 "(|| a (&& b c))",
		"a || b || c":                 "(|| (|| a b) c)",
		"a && b && c":                 "(&& (&& a b) c)",
		"a == 'x' && b == 'y'":        `(&& (== a "x") (== b "y"))`,
		"!a == 'x'":                   `(== (! a) "x")`,
		"!(a == 'x')":                 `(! (== a "x"))`,
		"!!a":                         "(! (! a))",
		"-a + b * c":                  "(+ (- a) (* b c))",
		"a + b - c":                   "(- (+ a b) c)",
		"a < b == c":                  "(== (< a b) c)",
		"a in [b, c]":                 "(in a (list b c))",
		"a ? b : c ? d : e":           "(?: a b (?: c d e))",
		"a || b ? c : d":              "(?: (|| a b) c d)",
		"assertion.sub.startsWith(p)": "(.startsWith (. assertion sub) p)",
		"has(assertion.sub)":          "(has (. assertion sub))",
		"size(a, b)":                  "(size a b)",
		"assertion['sub']":            `(index assertion "sub")`,
		"assertion.a.b.c":             "(. (. (. assertion a) b) c)",
		"[a, b,]":                     "(list a b)",
		"[]":                          "(list)",
		"{a: b, 'c': d,}":             `(map a b "c" d)`,
		"(a || b) && c":               "(&& (|| a b) c)",
		"a.b(c)(d)":                   "",
		"1 + 0x1F + 2u + 1.5e3 + .5":  "(+ (+ (+ (+ 1 0x1F) 2u) 1.5e3) .5)",
		"true && false || null":       "(|| (&& true false) null)",
		"a // comment\n&& b":          "(&& a b)",
		"a\t&&\f\rb":                  "(&& a b)",
	}
	for src, want := range cases {
		n, err := parseCEL(src)
		if want == "" {
			if err == nil {
				t.Errorf("%q: parsed as %s, want a refusal", src, sexpr(n))
			}
			continue
		}
		if err != nil {
			t.Errorf("%q: %v", src, err)
			continue
		}
		if got := sexpr(n); got != want {
			t.Errorf("%q: %s, want %s", src, got, want)
		}
	}
}

// TestParserRefusals: text outside the grammar is refused with the problem
// named, never read as some nearby expression.
func TestParserRefusals(t *testing.T) {
	cases := map[string]string{
		"":                    "empty expression",
		"   ":                 "empty expression",
		"a &&":                "unexpected end of expression",
		"&& a":                "unexpected \"&&\"",
		"a ==":                "unexpected end of expression",
		"(a":                  "unexpected end of expression",
		"a)":                  "unexpected \")\" after the expression",
		"a.":                  "unexpected end of expression",
		"a.'x'":               "unexpected \"'x'\"",
		"a[":                  "unexpected end of expression",
		"a ? b":               "unexpected end of expression",
		"if":                  "reserved word \"if\"",
		"assertion.in == 'x'": "unexpected \"in\"",
		"a & b":               "unexpected character \"&\"",
		"a | b":               "unexpected character \"|\"",
		"a = 'x'":             "unexpected character \"=\"",
		"a #":                 "unexpected character \"#\"",
		"a == 'x' b":          "unexpected \"b\" after the expression",
		// A doubled quote is two literals side by side, which the grammar
		// refuses; it is the Azure expression language, not CEL, that
		// reads it as an escaped quote.
		"assertion.sub == 'it''s'": "unexpected \"'s'\" after the expression",
		"{a}":                      "unexpected \"}\"",
		"a..b":                     "unexpected \".\"",
		"0x":                       "invalid number",
		"0xg":                      "invalid number",
		"1e":                       "invalid number",
		"1e+":                      "invalid number",
		"1e+5 ==":                  "unexpected end of expression",
		"'\\":                      "invalid escape sequence",
		"a ? && : b":               "unexpected \"&&\"",
		"a ? b : &&":               "unexpected \"&&\"",
		"!&&":                      "unexpected \"&&\"",
		"a[&&]":                    "unexpected \"&&\"",
		"a[1":                      "unexpected end of expression",
		"a.b(&&)":                  "unexpected \"&&\"",
		"[a b]":                    "unexpected \"b\"",
		"[&&]":                     "unexpected \"&&\"",
		"(&&)":                     "unexpected \"&&\"",
		"{&&: b}":                  "unexpected \"&&\"",
		"{a: &&}":                  "unexpected \"&&\"",
		"{a: b c: d}":              "unexpected \"c\"",
		"{a b}":                    "unexpected \"b\"",
		strings.Repeat("f(", 101) + "a" + strings.Repeat(")", 101):             "nested more than 100 levels deep",
		strings.Repeat("[", 101) + "a" + strings.Repeat("]", 101):              "nested more than 100 levels deep",
		strings.Repeat("{a:", 101) + "a" + strings.Repeat("}", 101):            "nested more than 100 levels deep",
		"a[" + strings.Repeat("[", 100) + "a" + strings.Repeat("]", 100) + "]": "nested more than 100 levels deep",
		strings.Repeat("a[", 101) + "a" + strings.Repeat("]", 101):             "nested more than 100 levels deep",
		".a":                     "unexpected \".\"",
		"assertion.sub == 'x' }": "unexpected \"}\" after the expression",
		strings.Repeat("(", 101) + "a" + strings.Repeat(")", 101): "nested more than 100 levels deep",
	}
	for src, problem := range cases {
		_, err := parseCEL(src)
		if err == nil || !strings.Contains(err.Error(), problem) {
			t.Errorf("%q: err %v, want %q", src, err, problem)
		}
	}
	// Depth right at the bound is read.
	if _, err := parseCEL(strings.Repeat("(", 100) + "a" + strings.Repeat(")", 100)); err != nil {
		t.Errorf("100 levels: %v", err)
	}
}

// TestNodesCarryTheirSpans: every node knows where in the source it was
// written, which is what "as written" in an anomaly means.
func TestNodesCarryTheirSpans(t *testing.T) {
	src := " assertion.sub == 'a'  && !assertion.x.startsWith('p') "
	n := mustParse(t, src)
	if got := src[n.start:n.end]; got != "assertion.sub == 'a'  && !assertion.x.startsWith('p')" {
		t.Errorf("root span %q", got)
	}
	if got := src[n.kids[0].start:n.kids[0].end]; got != "assertion.sub == 'a'" {
		t.Errorf("left span %q", got)
	}
	not := n.kids[1]
	if got := src[not.start:not.end]; got != "!assertion.x.startsWith('p')" {
		t.Errorf("not span %q", got)
	}
	call := not.kids[0]
	if got := src[call.start:call.end]; got != "assertion.x.startsWith('p')" {
		t.Errorf("call span %q", got)
	}
	if got := src[call.kids[1].start:call.kids[1].end]; got != "'p'" {
		t.Errorf("argument span %q", got)
	}
}

const conditionSource = "attributeCondition"

// githubMapping is the mapping the corpus uses for GitHub: the subject and
// three attributes named after their claims, the groups after theirs.
var githubMapping = map[string]string{
	"google.subject":                "assertion.sub",
	"google.groups":                 "assertion.groups",
	"attribute.repository":          "assertion.repository",
	"attribute.repository_id":       "assertion.repository_id",
	"attribute.repository_owner_id": "assertion.repository_owner_id",
	"attribute.org":                 "assertion.repository.extract('{org}/')",
}

// oidcResolver builds the resolver an OIDC provider with the given mapping
// has, the way provider.go builds it from a document.
func oidcResolver(mapping map[string]string) resolver {
	res := resolver{mapping: map[string]mapped{}}
	for attribute, expression := range mapping {
		res.mapping[attribute] = mappedBy(expression)
	}
	return res
}

func awsResolver(mapping map[string]string) resolver {
	res := oidcResolver(mapping)
	res.translate = awsClaims
	return res
}

// evaluated is what one evaluation produced, rendered for comparison.
type evaluated struct {
	admits    string
	caveats   []eval.Caveat
	anomalies []trust.Anomaly
}

func evaluate(t *testing.T, res resolver, condition string) evaluated {
	t.Helper()
	r := &reading{}
	admits := r.evaluate(condition, res, conditionSource)
	for _, c := range r.caveats {
		admits = admits.WithCaveat(c)
	}
	return evaluated{admits.String(), admits.Caveats(), canonical(r.anomalies)}
}

// TestModelledForms: every form the subset models evaluates to its exact
// set, with no anomaly and no caveat.
func TestModelledForms(t *testing.T) {
	cases := map[string]string{
		`assertion.sub == 'a'`:                                                             `{sub="a"}`,
		`'a' == assertion.sub`:                                                             `{sub="a"}`,
		`assertion.sub=='a'`:                                                               `{sub="a"}`,
		`assertion.sub == "a"`:                                                             `{sub="a"}`,
		`assertion.sub == r'a\b'`:                                                          `{sub="a\\b"}`,
		`assertion.sub == 'it\'s'`:                                                         `{sub="it's"}`,
		`assertion.sub == '''x''x'''`:                                                      `{sub="x''x"}`,
		`assertion.Sub == 'a'`:                                                             `{Sub="a"}`,
		`assertion.sub in ['a', 'b']`:                                                      `{sub=("a" | "b")}`,
		`assertion.sub in ['b', 'a', 'b',]`:                                                `{sub=("a" | "b")}`,
		`assertion.sub in ['a']`:                                                           `{sub="a"}`,
		`assertion.sub.startsWith('repo:acme/')`:                                           `{sub=like:"repo:acme/*"}`,
		`assertion.sub.endsWith(':main')`:                                                  `{sub=like:"*:main"}`,
		`assertion.sub.contains('/infra:')`:                                                `{sub=like:"*/infra:*"}`,
		`assertion.sub.startsWith('a') && assertion.sub.endsWith('b')`:                     `{sub=(like:"*b" & like:"a*")}`,
		`assertion.sub == 'a' && assertion.repository_id == '1'`:                           `{repository_id="1", sub="a"}`,
		`assertion.sub == 'a' || assertion.sub == 'b'`:                                     `{sub="a"} | {sub="b"}`,
		`assertion.sub == 'a' || assertion.repository_id == '1'`:                           `{repository_id="1"} | {sub="a"}`,
		`assertion.sub == 'a' && assertion.sub == 'a'`:                                     `{sub="a"}`,
		`assertion.sub == 'a' && assertion.sub == 'b'`:                                     `∅`,
		`assertion.sub == 'a' && assertion.sub.startsWith('a')`:                            `{sub="a"}`,
		`assertion.sub == 'a' && assertion.sub.startsWith('b')`:                            `∅`,
		`(assertion.sub == 'a' || assertion.sub == 'b') && assertion.repository_id == '1'`: `{repository_id="1", sub="a"} | {repository_id="1", sub="b"}`,
		`assertion.sub == 'a' && assertion.repository_id == '1' || assertion.repository_owner_id == '2'`:   `{repository_id="1", sub="a"} | {repository_owner_id="2"}`,
		`assertion.sub == 'a' && (assertion.repository_id == '1' || assertion.repository_owner_id == '2')`: `{repository_id="1", sub="a"} | {repository_owner_id="2", sub="a"}`,
		`google.subject == 'a'`:                   `{sub="a"}`,
		`attribute.repository == 'acme/infra'`:    `{repository="acme/infra"}`,
		`attribute.repository_id in ['1', '2']`:   `{repository_id=("1" | "2")}`,
		`true`:                                    `{}`,
		`false`:                                   `∅`,
		`assertion.sub == 'a' || true`:            `{}`,
		`assertion.sub == 'a' || false`:           `{sub="a"}`,
		`assertion.sub == 'a' && false`:           `∅`,
		`!!(assertion.sub == 'a')`:                `{sub="a"}`,
		"assertion.sub == 'a' // the main branch": `{sub="a"}`,
		`assertion.sub == '\u00e9'`:               `{sub="\u00e9"}`,
		`assertion.sub == 'é'`:                    `{sub="\u00e9"}`,
		`assertion.sub == 'a*?'`:                  `{sub="a*?"}`,
		`assertion.sub in ['a*', 'b?']`:           `{sub=("a*" | "b?")}`,
	}
	res := oidcResolver(githubMapping)
	for condition, want := range cases {
		got := evaluate(t, res, condition)
		if got.admits != want {
			t.Errorf("%s: %s, want %s", condition, got.admits, want)
		}
		if len(got.caveats) != 0 || len(got.anomalies) != 0 {
			t.Errorf("%s: caveats %v anomalies %v, want none", condition, got.caveats, got.anomalies)
		}
	}
}

// TestInListIsOneTerm: a list under in is a union inside one Term, and the
// same values under || are a Join of Terms. Both are exact, and they are
// two canonical forms; the harness judges by form.
func TestInListIsOneTerm(t *testing.T) {
	res := oidcResolver(githubMapping)
	list := evaluate(t, res, `assertion.sub in ['a', 'b']`).admits
	joined := evaluate(t, res, `assertion.sub == 'a' || assertion.sub == 'b'`).admits
	if list != `{sub=("a" | "b")}` || joined != `{sub="a"} | {sub="b"}` {
		t.Errorf("in: %s, ||: %s", list, joined)
	}
	// A list of many values does not overflow the term cap, which a Join of
	// Terms per value would.
	values := make([]string, listCap)
	for i := range values {
		values[i] = "'v" + strconv.Itoa(i) + "'"
	}
	many := evaluate(t, res, "assertion.sub in ["+strings.Join(values, ", ")+"] && assertion.repository_id in ["+strings.Join(values, ", ")+"]")
	if strings.Count(many.admits, "|") != 2*(listCap-1) || len(many.caveats) != 0 {
		t.Errorf("many values: %d unions, caveats %v", strings.Count(many.admits, "|"), many.caveats)
	}
}

// doubt is an expected anomaly with its caveat.
type doubt struct {
	claim     trust.ClaimKey
	construct string
	message   string
}

func (d doubt) anomaly() trust.Anomaly {
	return trust.Anomaly{Kind: trust.Unmodelled, Claim: d.claim, Construct: d.construct, Message: d.message, Source: conditionSource}
}

func (d doubt) caveat() eval.Caveat {
	return eval.Caveat{Claim: d.claim, Reason: d.message, Source: conditionSource}
}

// TestUnmodelledForms: every construct the subset does not model widens
// exactly one thing, the claim it constrains or the whole grant, and says
// which in a sentence that names what it met.
func TestUnmodelledForms(t *testing.T) {
	cases := []struct {
		condition string
		admits    string
		doubts    []doubt
	}{
		{`assertion.sub != 'a'`, `{}`, []doubt{{"sub", "!=", `"assertion.sub != 'a'" constrains sub with the operator "!=", which this parser does not model, so sub is read as unconstrained`}}},
		{`assertion.sub < 'a'`, `{}`, []doubt{{"sub", "<", `"assertion.sub < 'a'" constrains sub with the operator "<", which this parser does not model, so sub is read as unconstrained`}}},
		{`assertion.sub.matches('^a')`, `{}`, []doubt{{"sub", "matches", `"assertion.sub.matches('^a')" constrains sub with the function "matches", which this parser does not model, so sub is read as unconstrained`}}},
		{`assertion.sub.extract('{x}/') == 'a'`, `{}`, []doubt{{"sub", "extract", `"assertion.sub.extract('{x}/') == 'a'" constrains sub with the function "extract", which this parser does not model, so sub is read as unconstrained`}}},
		{`size(assertion.sub) == 3`, `{}`, []doubt{{"sub", "size", `"size(assertion.sub) == 3" constrains sub with the function "size", which this parser does not model, so sub is read as unconstrained`}}},
		{`assertion.sub.lowerAscii().startsWith('a')`, `{}`, []doubt{{"sub", "lowerAscii", `"assertion.sub.lowerAscii().startsWith('a')" constrains sub with the function "lowerAscii", which this parser does not model, so sub is read as unconstrained`}}},
		{`assertion.sub.startsWith('a', 'b')`, `{}`, []doubt{{"sub", "startsWith", `"assertion.sub.startsWith('a', 'b')" calls startsWith with 2 arguments, not the one string it takes, so sub is read as unconstrained`}}},
		{`assertion.sub.startsWith(assertion.repository)`, `{}`, []doubt{{"sub", "startsWith", `"assertion.sub.startsWith(assertion.repository)" tests sub for a prefix that is not a string literal, so sub is read as unconstrained`}}},
		{`assertion.sub.startsWith('repo:a*')`, `{}`, []doubt{{"sub", "startsWith", `"assertion.sub.startsWith('repo:a*')" tests sub for a prefix containing "*", which this parser's patterns read as a wildcard, so it cannot be stated as a pattern and sub is read as unconstrained`}}},
		{`assertion.sub.endsWith('a?')`, `{}`, []doubt{{"sub", "endsWith", `"assertion.sub.endsWith('a?')" tests sub for a suffix containing "?", which this parser's patterns read as a wildcard, so it cannot be stated as a pattern and sub is read as unconstrained`}}},
		{`assertion.sub.contains('*')`, `{}`, []doubt{{"sub", "contains", `"assertion.sub.contains('*')" tests sub for a substring containing "*", which this parser's patterns read as a wildcard, so it cannot be stated as a pattern and sub is read as unconstrained`}}},
		{`assertion.sub.startsWith('')`, `{}`, []doubt{{"sub", "startsWith", `"assertion.sub.startsWith('')" tests sub for the empty prefix, which every value has but only when the claim is present; this parser cannot express presence, so sub is read as unconstrained`}}},
		{`assertion.sub.contains('')`, `{}`, []doubt{{"sub", "contains", `"assertion.sub.contains('')" tests sub for the empty substring, which every value has but only when the claim is present; this parser cannot express presence, so sub is read as unconstrained`}}},
		{`assertion.sub == 1`, `{}`, []doubt{{"sub", "1", `"assertion.sub == 1" compares sub against 1, which is not a string literal, so sub is read as unconstrained`}}},
		{`assertion.sub == true`, `{}`, []doubt{{"sub", "true", `"assertion.sub == true" compares sub against true, which is not a string literal, so sub is read as unconstrained`}}},
		{`assertion.sub == b'a'`, `{}`, []doubt{{"sub", "b'a'", `"assertion.sub == b'a'" compares sub against b'a', which is not a string literal, so sub is read as unconstrained`}}},
		{`assertion.sub == assertion.repository`, `{}`, []doubt{{"sub", "assertion.repository", `"assertion.sub == assertion.repository" compares sub against assertion.repository, which is not a string literal, so sub is read as unconstrained`}}},
		{`assertion.sub == 'a' + 'b'`, `{}`, []doubt{{"sub", "'a' + 'b'", `"assertion.sub == 'a' + 'b'" compares sub against 'a' + 'b', which is not a string literal, so sub is read as unconstrained`}}},
		{`assertion.sub in assertion.list`, `{}`, []doubt{{"sub", "in", `"assertion.sub in assertion.list" tests sub for membership of assertion.list, which is not a list of string literals, so sub is read as unconstrained`}}},
		{`assertion.sub in ['a', 1]`, `{}`, []doubt{{"sub", "in", `"assertion.sub in ['a', 1]" tests sub for membership of ['a', 1], which is not a list of string literals, so sub is read as unconstrained`}}},
		{`assertion.sub in []`, `{}`, []doubt{{"sub", "in", `"assertion.sub in []" tests sub for membership of an empty list; Google does not document such a condition, so sub is read as unconstrained`}}},
		{`'admins' in google.groups`, `{}`, []doubt{{"groups", "in", `"'admins' in google.groups" tests membership of google.groups, which maps to the claim groups; a list-valued claim is outside what this parser models, so groups is read as unconstrained`}}},
		{`'admins' in assertion.groups`, `{}`, []doubt{{"groups", "in", `"'admins' in assertion.groups" tests membership of assertion.groups; a list-valued claim is outside what this parser models, so groups is read as unconstrained`}}},
		{`has(assertion.sub)`, `{}`, []doubt{{"sub", "has", `"has(assertion.sub)" tests whether sub is present, which this parser cannot express, so sub is read as unconstrained`}}},
		{`assertion.email_verified`, `{}`, []doubt{{"email_verified", "assertion.email_verified", `"assertion.email_verified" tests the truth of email_verified, which this parser does not model, so email_verified is read as unconstrained`}}},
		{`assertion.a.b == 'x'`, `{}`, []doubt{{"a", "assertion.a.b", `"assertion.a.b == 'x'" constrains a field inside a, which this parser models as one value, so a is read as unconstrained`}}},
		{`assertion.a['b'] == 'x'`, `{}`, []doubt{{"a", "assertion.a['b']", `"assertion.a['b'] == 'x'" constrains a field inside a, which this parser models as one value, so a is read as unconstrained`}}},
		{`assertion.sub + 'x' == 'y'`, `{}`, []doubt{{"sub", "+", `"assertion.sub + 'x' == 'y'" constrains sub with the operator "+", which this parser does not model, so sub is read as unconstrained`}}},
		{`-assertion.n == 'y'`, `{}`, []doubt{{"n", "-", `"-assertion.n == 'y'" constrains n with the operator "-", which this parser does not model, so n is read as unconstrained`}}},
		{`assertion.sub == 'a' ? true : false`, `{}`, []doubt{{"", "?", `"assertion.sub == 'a' ? true : false" is a conditional expression, which this parser does not model, so nothing it says about the credential is modelled`}}},
		{`'a' == 'a'`, `{}`, []doubt{{"", "==", `"'a' == 'a'" uses "==" between operands that name no claim, so nothing it says about the credential is modelled`}}},
		{`size('a') == 1`, `{}`, []doubt{{"", "==", `"size('a') == 1" uses "==" between operands that name no claim, so nothing it says about the credential is modelled`}}},
		{`size('a')`, `{}`, []doubt{{"", "size", `"size('a')" calls "size" on operands that name no claim, so nothing it says about the credential is modelled`}}},
		{`1`, `{}`, []doubt{{"", "1", `"1" is the literal 1 where a comparison on a claim was expected, so nothing it says about the credential is modelled`}}},
		{`null`, `{}`, []doubt{{"", "null", `"null" is the literal null where a comparison on a claim was expected, so nothing it says about the credential is modelled`}}},
		{`request.auth == 'x'`, `{}`, []doubt{{"", "request", `"request.auth == 'x'" refers to request, which is not assertion, google or attribute, the keywords Google documents for a condition, so nothing it says about the credential is modelled`}}},
		{`assertion == 'x'`, `{}`, []doubt{{"", "assertion", `"assertion == 'x'" refers to assertion without naming a field of it, so nothing it says about the credential is modelled`}}},
		{`['a'] == ['a']`, `{}`, []doubt{{"", "==", `"['a'] == ['a']" uses "==" between operands that name no claim, so nothing it says about the credential is modelled`}}},
		{`{'a': 'b'}.a == 'b'`, `{}`, []doubt{{"", "==", `"{'a': 'b'}.a == 'b'" uses "==" between operands that name no claim, so nothing it says about the credential is modelled`}}},
		{`-'a'`, `{}`, []doubt{{"", "-", `"-'a'" applies "-" to an operand that names no claim, so nothing it says about the credential is modelled`}}},
		{`'a'.b`, `{}`, []doubt{{"", "'a'.b", `"'a'.b" names no claim, so nothing it says about the credential is modelled`}}},
		{`'a' in ['a']`, `{}`, []doubt{{"", "in", `"'a' in ['a']" uses "in" between operands that name no claim, so nothing it says about the credential is modelled`}}},
		{`(assertion.sub == 'a' ? 'x' : 'y') == 'z'`, `{}`, []doubt{{"sub", "?", `"(assertion.sub == 'a' ? 'x' : 'y') == 'z'" constrains sub with the operator "?", which this parser does not model, so sub is read as unconstrained`}}},
		{`[assertion.sub] == ['a']`, `{}`, []doubt{{"sub", "[assertion.sub]", `"[assertion.sub] == ['a']" constrains sub inside [assertion.sub], which this parser does not model, so sub is read as unconstrained`}}},
		{`!(assertion.sub == 'a' || assertion.repository_id == '1')`, `{}`, []doubt{{"", "!", `"!(assertion.sub == 'a' || assertion.repository_id == '1')" negates an expression that is not a single comparison on one claim, so nothing it says about the credential is modelled`}}},
		{`assertion.subject.dn.cn == 'a'`, `{}`, []doubt{{"subject", "assertion.subject.dn.cn", `"assertion.subject.dn.cn == 'a'" constrains a field inside subject, which this parser models as one value, so subject is read as unconstrained`}}},
		{`!(assertion.sub == 'a')`, `{}`, []doubt{{"sub", "!", `"!(assertion.sub == 'a')" negates a comparison on sub; this parser models what a condition admits, not what it excludes, so sub is read as unconstrained`}}},
		{`!assertion.sub.startsWith('a')`, `{}`, []doubt{{"sub", "!", `"!assertion.sub.startsWith('a')" negates a comparison on sub; this parser models what a condition admits, not what it excludes, so sub is read as unconstrained`}}},
		{`!(assertion.sub in ['a', 'b'])`, `{}`, []doubt{{"sub", "!", `"!(assertion.sub in ['a', 'b'])" negates a comparison on sub; this parser models what a condition admits, not what it excludes, so sub is read as unconstrained`}}},
		{`!(assertion.sub == 'a' || assertion.sub == 'b')`, `{}`, []doubt{{"sub", "!", `"!(assertion.sub == 'a' || assertion.sub == 'b')" negates a comparison on sub; this parser models what a condition admits, not what it excludes, so sub is read as unconstrained`}}},
		{`!(assertion.sub == 'a' && assertion.repository_id == '1')`, `{}`, []doubt{{"", "!", `"!(assertion.sub == 'a' && assertion.repository_id == '1')" negates an expression that is not a single comparison on one claim, so nothing it says about the credential is modelled`}}},
		{`!true`, `{}`, []doubt{{"", "!", `"!true" negates an expression that is not a single comparison on one claim, so nothing it says about the credential is modelled`}}},
		{`!!!(assertion.sub == 'a')`, `{}`, []doubt{{"sub", "!", `"!!!(assertion.sub == 'a')" negates a comparison on sub; this parser models what a condition admits, not what it excludes, so sub is read as unconstrained`}}},
		{`!assertion.sub == 'a'`, `{}`, []doubt{{"sub", "!", `"!assertion.sub == 'a'" constrains sub with the operator "!", which this parser does not model, so sub is read as unconstrained`}}},
		{`assertion.sub == 'a' || assertion.repository_id != '1'`, `{}`, []doubt{{"repository_id", "!=", `"assertion.repository_id != '1'" constrains repository_id with the operator "!=", which this parser does not model, so repository_id is read as unconstrained`}}},
		{`assertion.sub == 'a' && assertion.repository_id != '1'`, `{sub="a"}`, []doubt{{"repository_id", "!=", `"assertion.repository_id != '1'" constrains repository_id with the operator "!=", which this parser does not model, so repository_id is read as unconstrained`}}},
		{`assertion.sub == 'a' && assertion.sub != 'b'`, `{sub="a"}`, []doubt{{"sub", "!=", `"assertion.sub != 'b'" constrains sub with the operator "!=", which this parser does not model, so sub is read as unconstrained`}}},
		{`attribute.org == 'acme'`, `{}`, []doubt{{"", "assertion.repository.extract('{org}/')", `"attribute.org == 'acme'" constrains attribute.org, which the attribute mapping maps by the expression "assertion.repository.extract('{org}/')"; this parser does not evaluate mapping expressions, so which claim the clause constrains is not stated and nothing it says about the credential is modelled`}}},
		{`attribute.org != 'acme'`, `{}`, []doubt{{"", "assertion.repository.extract('{org}/')", `"attribute.org != 'acme'" constrains attribute.org, which the attribute mapping maps by the expression "assertion.repository.extract('{org}/')"; this parser does not evaluate mapping expressions, so which claim the clause constrains is not stated and nothing it says about the credential is modelled`}}},
		{`attribute.org == 'acme' || assertion.sub == 'a'`, `{}`, []doubt{{"", "assertion.repository.extract('{org}/')", `"attribute.org == 'acme'" constrains attribute.org, which the attribute mapping maps by the expression "assertion.repository.extract('{org}/')"; this parser does not evaluate mapping expressions, so which claim the clause constrains is not stated and nothing it says about the credential is modelled`}}},
		{`attribute.org == 'acme' && assertion.sub == 'a'`, `{sub="a"}`, []doubt{{"", "assertion.repository.extract('{org}/')", `"attribute.org == 'acme'" constrains attribute.org, which the attribute mapping maps by the expression "assertion.repository.extract('{org}/')"; this parser does not evaluate mapping expressions, so which claim the clause constrains is not stated and nothing it says about the credential is modelled`}}},
		{`!(attribute.org == 'acme')`, `{}`, []doubt{
			{"", "!", `"!(attribute.org == 'acme')" negates an expression that is not a single comparison on one claim, so nothing it says about the credential is modelled`},
			{"", "assertion.repository.extract('{org}/')", `"attribute.org == 'acme'" constrains attribute.org, which the attribute mapping maps by the expression "assertion.repository.extract('{org}/')"; this parser does not evaluate mapping expressions, so which claim the clause constrains is not stated and nothing it says about the credential is modelled`},
		}},
		// A modelled form written as an operand of another operator is outside
		// the subset by its position, not by its operator: the sentence names
		// the operand as written and never calls ==, in, startsWith, contains,
		// && or ! unmodelled, because the parser models exactly those.
		{`assertion.sub == 'a' == true`, `{}`, []doubt{{"sub", "assertion.sub == 'a'", `"assertion.sub == 'a' == true" constrains sub inside assertion.sub == 'a', a condition written as an operand of "=="; this parser models such a condition only as a clause of its own, so sub is read as unconstrained`}}},
		{`assertion.sub.startsWith('a') == true`, `{}`, []doubt{{"sub", "assertion.sub.startsWith('a')", `"assertion.sub.startsWith('a') == true" constrains sub inside assertion.sub.startsWith('a'), a condition written as an operand of "=="; this parser models such a condition only as a clause of its own, so sub is read as unconstrained`}}},
		{`(assertion.sub in ['a']) == true`, `{}`, []doubt{{"sub", "assertion.sub in ['a']", `"(assertion.sub in ['a']) == true" constrains sub inside assertion.sub in ['a'], a condition written as an operand of "=="; this parser models such a condition only as a clause of its own, so sub is read as unconstrained`}}},
		{`(assertion.sub == 'a') in [true]`, `{}`, []doubt{{"sub", "assertion.sub == 'a'", `"(assertion.sub == 'a') in [true]" constrains sub inside assertion.sub == 'a', a condition written as an operand of "in"; this parser models such a condition only as a clause of its own, so sub is read as unconstrained`}}},
		{`assertion.sub.contains('a') == 'x'`, `{}`, []doubt{{"sub", "assertion.sub.contains('a')", `"assertion.sub.contains('a') == 'x'" constrains sub inside assertion.sub.contains('a'), a condition written as an operand of "=="; this parser models such a condition only as a clause of its own, so sub is read as unconstrained`}}},
		{`(assertion.sub == 'a') == (assertion.sub == 'b')`, `{}`, []doubt{{"sub", "assertion.sub == 'a'", `"(assertion.sub == 'a') == (assertion.sub == 'b')" constrains sub inside assertion.sub == 'a', a condition written as an operand of "=="; this parser models such a condition only as a clause of its own, so sub is read as unconstrained`}}},
		{`(assertion.sub == 'a' && assertion.repository_id == '1') == true`, `{}`, []doubt{{"sub", "assertion.sub == 'a' && assertion.repository_id == '1'", `"(assertion.sub == 'a' && assertion.repository_id == '1') == true" constrains sub inside assertion.sub == 'a' && assertion.repository_id == '1', a condition written as an operand of "=="; this parser models such a condition only as a clause of its own, so sub is read as unconstrained`}}},
		{`(assertion.sub == 'a' || assertion.sub == 'b') != true`, `{}`, []doubt{{"sub", "!=", `"(assertion.sub == 'a' || assertion.sub == 'b') != true" constrains sub with the operator "!=", which this parser does not model, so sub is read as unconstrained`}}},
		{`(!(assertion.sub == 'a')) == true`, `{}`, []doubt{{"sub", "!", `"(!(assertion.sub == 'a')) == true" constrains sub with the operator "!", which this parser does not model, so sub is read as unconstrained`}}},
		{`(assertion.sub == 'a').startsWith('x')`, `{}`, []doubt{{"sub", "assertion.sub == 'a'", `"(assertion.sub == 'a').startsWith('x')" constrains sub inside assertion.sub == 'a', a condition written as the receiver of "startsWith"; this parser models such a condition only as a clause of its own, so sub is read as unconstrained`}}},
		{`size(assertion.sub == 'a') == 1`, `{}`, []doubt{{"sub", "size", `"size(assertion.sub == 'a') == 1" constrains sub with the function "size", which this parser does not model, so sub is read as unconstrained`}}},
		// google.groups is set-valued by Google's own description, whatever
		// the form it is compared under; only membership of it is a documented
		// condition, and the lattice models neither.
		{`google.groups == 'admins'`, `{}`, []doubt{{"groups", "google.groups", `"google.groups == 'admins'" constrains google.groups, which maps to the claim groups and which Google documents as the set of groups the identity belongs to; a list-valued claim is outside what this parser models, so groups is read as unconstrained`}}},
		{`'admins' == google.groups`, `{}`, []doubt{{"groups", "google.groups", `"'admins' == google.groups" constrains google.groups, which maps to the claim groups and which Google documents as the set of groups the identity belongs to; a list-valued claim is outside what this parser models, so groups is read as unconstrained`}}},
		{`google.groups in ['admins']`, `{}`, []doubt{{"groups", "google.groups", `"google.groups in ['admins']" constrains google.groups, which maps to the claim groups and which Google documents as the set of groups the identity belongs to; a list-valued claim is outside what this parser models, so groups is read as unconstrained`}}},
		{`google.groups.startsWith('adm')`, `{}`, []doubt{{"groups", "google.groups", `"google.groups.startsWith('adm')" constrains google.groups, which maps to the claim groups and which Google documents as the set of groups the identity belongs to; a list-valued claim is outside what this parser models, so groups is read as unconstrained`}}},
		{`google.groups.contains('adm') && assertion.sub == 'a'`, `{sub="a"}`, []doubt{{"groups", "google.groups", `"google.groups.contains('adm')" constrains google.groups, which maps to the claim groups and which Google documents as the set of groups the identity belongs to; a list-valued claim is outside what this parser models, so groups is read as unconstrained`}}},
		{`attribute.missing == 'x'`, `{}`, []doubt{{"", "attribute.missing", `"attribute.missing == 'x'" constrains attribute.missing, which the attribute mapping does not map, so which claim the clause constrains is not stated and nothing it says about the credential is modelled`}}},
		{`assertion.sub == 'a' || attribute.missing == 'x' && assertion.sub == 'b'`, `{sub="a"} | {sub="b"}`, []doubt{{"", "attribute.missing", `"attribute.missing == 'x'" constrains attribute.missing, which the attribute mapping does not map, so which claim the clause constrains is not stated and nothing it says about the credential is modelled`}}},
	}
	res := oidcResolver(githubMapping)
	for _, c := range cases {
		got := evaluate(t, res, c.condition)
		if got.admits != c.admits {
			t.Errorf("%s: %s, want %s", c.condition, got.admits, c.admits)
		}
		var wantAnomalies []trust.Anomaly
		var wantCaveats []eval.Caveat
		for _, d := range c.doubts {
			wantAnomalies = append(wantAnomalies, d.anomaly())
			wantCaveats = append(wantCaveats, d.caveat())
		}
		wantAnomalies = canonical(wantAnomalies)
		if !slices.Equal(got.anomalies, wantAnomalies) {
			t.Errorf("%s: anomalies\n  %+v\nwant\n  %+v", c.condition, got.anomalies, wantAnomalies)
		}
		normalised := eval.Nothing()
		for _, cv := range wantCaveats {
			normalised = normalised.WithCaveat(cv)
		}
		if !slices.Equal(got.caveats, normalised.Caveats()) {
			t.Errorf("%s: caveats\n  %+v\nwant\n  %+v", c.condition, got.caveats, normalised.Caveats())
		}
	}
}

// TestMappingResolution: a mapping value that is exactly a reference to
// one assertion field names that claim, whitespace and comments allowed
// because CEL allows them; anything else is an expression this parser does
// not evaluate, with the reason stated.
func TestMappingResolution(t *testing.T) {
	cases := map[string]mapped{
		"assertion.sub":                 {claim: "sub", expression: "assertion.sub"},
		"  assertion.sub  ":             {claim: "sub", expression: "  assertion.sub  "},
		"assertion.sub // the subject":  {claim: "sub", expression: "assertion.sub // the subject"},
		"assertion.repository_owner_id": {claim: "repository_owner_id", expression: "assertion.repository_owner_id"},
		"assertion.arn.extract('{x}/')": {expression: "assertion.arn.extract('{x}/')", why: `the attribute mapping maps by the expression "assertion.arn.extract('{x}/')"; this parser does not evaluate mapping expressions`},
		"assertion.a.b":                 {expression: "assertion.a.b", why: `the attribute mapping maps by the expression "assertion.a.b"; this parser does not evaluate mapping expressions`},
		"assertion['sub']":              {claim: "sub", expression: "assertion['sub']"},
		"'literal'":                     {expression: "'literal'", why: `the attribute mapping maps by the expression "'literal'"; this parser does not evaluate mapping expressions`},
		"google.subject":                {expression: "google.subject", why: `the attribute mapping maps by the expression "google.subject"; this parser does not evaluate mapping expressions`},
		"assertion.sub +":               {expression: "assertion.sub +", why: `the attribute mapping maps by "assertion.sub +", which is not an expression this parser can read`},
		"":                              {expression: "", why: `the attribute mapping maps by "", which is not an expression this parser can read`},
		strings.Repeat("assertion.sub || ", 200) + "assertion.sub": {expression: strings.Repeat("assertion.sub || ", 200) + "assertion.sub", why: `the attribute mapping maps by an expression 3413 characters long; Google accepts at most 2048, so it is not read`},
	}
	for expression, want := range cases {
		if got := mappedBy(expression); got != want {
			t.Errorf("mappedBy(%q) = %+v, want %+v", expression, got, want)
		}
	}
}

// TestAWSClaims: under an AWS provider the account is spelt as the AWS
// parser spells the same fact, and the ARN keeps Google's own name, so a
// join on the pseudo-issuer pairs accounts exactly and never mistakes an
// STS ARN for the IAM ARN the other side holds.
func TestAWSClaims(t *testing.T) {
	res := awsResolver(nil)
	res.mapping = defaultAWSMapping()
	cases := map[string]string{
		`assertion.account == '123456789012'`:                      `{aws:principalaccount="123456789012"}`,
		`assertion.arn.startsWith('arn:aws:sts::1:assumed-role/')`: `{arn=like:"arn:aws:sts::1:assumed-role/*"}`,
		`assertion.userid == 'AROA'`:                               `{userid="AROA"}`,
		`google.subject == 'arn:aws:sts::1:assumed-role/x/y'`:      `{arn="arn:aws:sts::1:assumed-role/x/y"}`,
	}
	for condition, want := range cases {
		got := evaluate(t, res, condition)
		if got.admits != want || len(got.anomalies) != 0 {
			t.Errorf("%s: %s %v, want %s", condition, got.admits, got.anomalies, want)
		}
	}
	role := evaluate(t, res, `attribute.aws_role == 'arn:aws:sts::1:assumed-role/deploy'`)
	if role.admits != "{}" || len(role.anomalies) != 1 || role.anomalies[0].Construct != awsRoleExpression || role.anomalies[0].Claim != "" {
		t.Errorf("attribute.aws_role: %s %+v", role.admits, role.anomalies)
	}
}

// TestUnattributableProvider: when the provider's kind leaves the claim
// space unknown, every clause is top on the whole grant, with the kind's
// reason in the sentence, and nothing is guessed about claim names.
func TestUnattributableProvider(t *testing.T) {
	res := resolver{unattributable: "the provider is a SAML 2.0 provider, whose assertion this parser does not model as claims"}
	got := evaluate(t, res, `assertion.subject == 'deploy' && assertion.attributes['dept'] == 'ops'`)
	want := []trust.Anomaly{
		{Kind: trust.Unmodelled, Construct: "assertion.attributes['dept']", Message: `"assertion.attributes['dept'] == 'ops'" constrains assertion.attributes['dept'], but the provider is a SAML 2.0 provider, whose assertion this parser does not model as claims, so nothing it says about the credential is modelled`, Source: conditionSource},
		{Kind: trust.Unmodelled, Construct: "assertion.subject", Message: `"assertion.subject == 'deploy'" constrains assertion.subject, but the provider is a SAML 2.0 provider, whose assertion this parser does not model as claims, so nothing it says about the credential is modelled`, Source: conditionSource},
	}
	if got.admits != "{}" || !slices.Equal(got.anomalies, want) {
		t.Errorf("%s\n%+v\nwant\n%+v", got.admits, got.anomalies, want)
	}
	if len(got.caveats) != 2 || got.caveats[0].Claim != "" || got.caveats[1].Claim != "" {
		t.Errorf("caveats %+v", got.caveats)
	}
}

// TestUnparseableAndOverlong: an expression outside the grammar, or past
// Google's length limit, is not read at all; the whole grant is top with
// the fact stated.
func TestUnparseableAndOverlong(t *testing.T) {
	res := oidcResolver(githubMapping)
	broken := evaluate(t, res, `assertion.sub == 'a' &&`)
	want := trust.Anomaly{Kind: trust.Unmodelled, Construct: "unparseable expression", Message: `attributeCondition is not an expression this parser can read: unexpected end of expression at character 24; nothing it says about the credential is modelled`, Source: conditionSource}
	if broken.admits != "{}" || len(broken.anomalies) != 1 || broken.anomalies[0] != want {
		t.Errorf("broken: %s %+v", broken.admits, broken.anomalies)
	}
	empty := evaluate(t, res, "   ")
	if empty.admits != "{}" || len(empty.anomalies) != 1 || !strings.Contains(empty.anomalies[0].Message, "read: empty expression; nothing") {
		t.Errorf("blank: %s %+v", empty.admits, empty.anomalies)
	}
	long := "assertion.sub == '" + strings.Repeat("é", conditionLimit) + "'"
	over := evaluate(t, res, long)
	wantLong := trust.Anomaly{Kind: trust.Unmodelled, Construct: "expression length", Message: "attributeCondition is " + strconv.Itoa(conditionLimit+19) + " characters long; Google accepts at most 4096, so it is not read and nothing it says about the credential is modelled", Source: conditionSource}
	if over.admits != "{}" || len(over.anomalies) != 1 || over.anomalies[0] != wantLong {
		t.Errorf("over: %s %+v", over.admits, over.anomalies)
	}
	// Exactly at the limit is read: Google counts characters, and so does
	// the parser, so a multi-byte literal does not push it over. The claim
	// is one the subject does not map to, so that the only fact in play is
	// the condition's length.
	exact := evaluate(t, res, "assertion.repository == '"+strings.Repeat("é", conditionLimit-26)+"'")
	if len(exact.anomalies) != 0 || !strings.HasPrefix(exact.admits, `{repository="`) {
		t.Errorf("at the limit: %s %+v", exact.admits, exact.anomalies)
	}
}

// TestSubjectLimit: a value the condition writes for the claim google.subject
// maps to, longer than Google's 127 bytes, is one no credential maps to;
// the set keeps the value, declared an upper bound on that claim, and the
// sentence names the form. The limit counts bytes, falls on the mapped
// claim whatever reference reached it, and falls on nothing when the
// mapping does not attribute google.subject to a claim.
func TestSubjectLimit(t *testing.T) {
	over, at := strings.Repeat("x", subjectLimit+1), strings.Repeat("x", subjectLimit)
	limit := func(construct, wrote, such string) trust.Anomaly {
		return trust.Anomaly{Kind: SubjectLength, Claim: "sub", Construct: construct, Message: wrote + " " + strconv.Itoa(subjectLimit+1) + " bytes long; Google says google.subject, which maps to sub, cannot exceed 127 bytes, so no credential carrying " + such + " can be exchanged and the set stated is read as an upper bound", Source: conditionSource}
	}
	cases := []struct {
		condition string
		admits    string
		anomaly   trust.Anomaly
	}{
		{"assertion.sub == '" + over + "'", `{sub="` + over + `"}`, limit("==", `"assertion.sub == '`+over+`'" compares sub against a value`, "that value")},
		{"'" + over + "' == google.subject", `{sub="` + over + `"}`, limit("==", `"'`+over+`' == google.subject" compares sub against a value`, "that value")},
		{"assertion.sub in ['a', '" + over + "']", `{sub=("a" | "` + over + `")}`, limit("in", `"assertion.sub in ['a', '`+over+`']" lists for sub a value`, "that value")},
		{"assertion.sub.startsWith('" + over + "')", `{sub=like:"` + over + `*"}`, limit("startsWith", `"assertion.sub.startsWith('`+over+`')" tests sub for a prefix`, "such a prefix")},
		{"assertion.sub.endsWith('" + over + "')", `{sub=like:"*` + over + `"}`, limit("endsWith", `"assertion.sub.endsWith('`+over+`')" tests sub for a suffix`, "such a suffix")},
		{"assertion.sub.contains('" + over + "')", `{sub=like:"*` + over + `*"}`, limit("contains", `"assertion.sub.contains('`+over+`')" tests sub for a substring`, "such a substring")},
		{"assertion.sub == '" + strings.Repeat("é", 64) + "'", `{sub=` + strconv.QuoteToASCII(strings.Repeat("é", 64)) + `}`, trust.Anomaly{Kind: SubjectLength, Claim: "sub", Construct: "==", Message: strconv.QuoteToASCII("assertion.sub == '"+strings.Repeat("é", 64)+"'") + ` compares sub against a value 128 bytes long; Google says google.subject, which maps to sub, cannot exceed 127 bytes, so no credential carrying that value can be exchanged and the set stated is read as an upper bound`, Source: conditionSource}},
		{"assertion.sub == '" + over + "' && assertion.repository_id == '1'", `{repository_id="1", sub="` + over + `"}`, limit("==", `"assertion.sub == '`+over+`'" compares sub against a value`, "that value")},
		// Two exact values on one claim admit nobody, which the document
		// proves on its own; the fact about the long one is still recorded.
		{"assertion.sub == '" + over + "' && assertion.sub == 'a'", `∅`, limit("==", `"assertion.sub == '`+over+`'" compares sub against a value`, "that value")},
		// One clause is one fact, however many of its values are past the
		// limit.
		{"assertion.sub in ['" + over + "', '" + over + "y']", `{sub=("` + over + `" | "` + over + `y")}`, limit("in", quote("assertion.sub in ['"+over+"', '"+over+"y']")+" lists for sub a value", "that value")},
	}
	res := oidcResolver(githubMapping)
	for _, c := range cases {
		got := evaluate(t, res, c.condition)
		caveat := eval.Caveat{Claim: "sub", Reason: c.anomaly.Message, Source: conditionSource}
		if got.admits != c.admits || !slices.Equal(got.anomalies, []trust.Anomaly{c.anomaly}) || !slices.Equal(got.caveats, []eval.Caveat{caveat}) {
			t.Errorf("%.80s...:\n  %s\n  %+v\n  %+v\n  want %s\n  %+v", c.condition, got.admits, got.anomalies, got.caveats, c.admits, c.anomaly)
		}
	}
	exact := map[string]string{
		"assertion.sub == '" + at + "'":                   `{sub="` + at + `"}`,
		"assertion.sub in ['" + at + "']":                 `{sub="` + at + `"}`,
		"assertion.sub.startsWith('" + at + "')":          `{sub=like:"` + at + `*"}`,
		"assertion.repository == '" + over + "'":          `{repository="` + over + `"}`,
		"attribute.repository == '" + over + "'":          `{repository="` + over + `"}`,
		"assertion.repository.startsWith('" + over + "')": `{repository=like:"` + over + `*"}`,
	}
	for condition, want := range exact {
		got := evaluate(t, res, condition)
		if got.admits != want || len(got.anomalies) != 0 || len(got.caveats) != 0 {
			t.Errorf("%.60s...: %s %+v %+v, want %s exact", condition, got.admits, got.anomalies, got.caveats, want)
		}
	}
	// Under a mapping that does not attribute google.subject to a claim,
	// no claim carries the limit: the subject is some function of sub.
	expression := maps.Clone(githubMapping)
	expression["google.subject"] = "assertion.sub.extract('repo:{owner}/')"
	got := evaluate(t, oidcResolver(expression), "assertion.sub == '"+over+"'")
	if got.admits != `{sub="`+over+`"}` || len(got.anomalies) != 0 {
		t.Errorf("expression-mapped subject: %s %+v", got.admits, got.anomalies)
	}
	unmapped := maps.Clone(githubMapping)
	delete(unmapped, "google.subject")
	got = evaluate(t, oidcResolver(unmapped), "assertion.sub == '"+over+"'")
	if got.admits != `{sub="`+over+`"}` || len(got.anomalies) != 0 {
		t.Errorf("unmapped subject: %s %+v", got.admits, got.anomalies)
	}
	// Under Google's default mapping for AWS the subject is the ARN, and an
	// assumed-role ARN can be long.
	aws := awsResolver(nil)
	aws.mapping = defaultAWSMapping()
	arn := "arn:aws:sts::123456789012:assumed-role/" + strings.Repeat("r", 64) + "/" + strings.Repeat("s", 64)
	got = evaluate(t, aws, "assertion.arn == '"+arn+"'")
	want := trust.Anomaly{Kind: SubjectLength, Claim: "arn", Construct: "==", Message: `"assertion.arn == '` + arn + `'" compares arn against a value ` + strconv.Itoa(len(arn)) + ` bytes long; Google says google.subject, which maps to arn, cannot exceed 127 bytes, so no credential carrying that value can be exchanged and the set stated is read as an upper bound`, Source: conditionSource}
	if got.admits != `{arn="`+arn+`"}` || !slices.Equal(got.anomalies, []trust.Anomaly{want}) {
		t.Errorf("aws: %s %+v", got.admits, got.anomalies)
	}
}

// TestListCapWidens: a list past the cap is Unknown with the count stated,
// never a truncated union.
func TestListCapWidens(t *testing.T) {
	values := make([]string, listCap+1)
	for i := range values {
		values[i] = "'v" + strconv.Itoa(i) + "'"
	}
	got := evaluate(t, oidcResolver(githubMapping), "assertion.sub in ["+strings.Join(values, ",")+"]")
	if got.admits != "{}" || len(got.anomalies) != 1 || got.anomalies[0].Claim != "sub" || got.anomalies[0].Construct != "in" {
		t.Fatalf("%s %+v", got.admits, got.anomalies)
	}
	if !strings.HasSuffix(got.anomalies[0].Message, "lists "+strconv.Itoa(listCap+1)+" values; this parser reads at most "+strconv.Itoa(listCap)+", so sub is read as unconstrained") {
		t.Errorf("%s", got.anomalies[0].Message)
	}
}

// TestSentencesAreBoundedAndPrintable: a clause quoted into a sentence is
// cut past quoteLimit at a character boundary and holds no control
// character, whatever the condition held.
func TestSentencesAreBoundedAndPrintable(t *testing.T) {
	long := strings.Repeat("€", 100)
	got := evaluate(t, oidcResolver(githubMapping), "assertion.sub != '"+long+"\x1b[2K'")
	if len(got.anomalies) != 1 {
		t.Fatalf("%+v", got.anomalies)
	}
	m := got.anomalies[0].Message
	if strings.ContainsRune(m, 0x1b) || strings.Contains(m, "�") || !strings.Contains(m, "...") {
		t.Errorf("%q", m)
	}
	if len(m) > 6*quoteLimit+200 {
		t.Errorf("sentence of %d bytes", len(m))
	}
	// A construct is document text too: a comparand longer than the limit
	// is cut the same way, and never at a broken character.
	got = evaluate(t, oidcResolver(githubMapping), "assertion.sub == b'"+long+"'")
	if len(got.anomalies) != 1 {
		t.Fatalf("%+v", got.anomalies)
	}
	construct := got.anomalies[0].Construct
	if !strings.HasSuffix(construct, "...") || strings.Contains(construct, "�") || len(construct) > 8*quoteLimit {
		t.Errorf("%q", construct)
	}
}
