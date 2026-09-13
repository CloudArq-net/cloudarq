package gcp

import (
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/CloudArq-net/cloudarq/internal/eval"
	"github.com/CloudArq-net/cloudarq/internal/trust"
)

// The Common Expression Language, as its specification defines it at
// https://github.com/google/cel-spec/blob/master/doc/langdef.md and as the
// ANTLR grammar in cel-go, parser/gen/CEL.g4, spells its lexis. The
// expression syntax is parsed in full, message construction, optional
// selection and backtick-quoted identifiers aside, which no condition over
// a credential names and which are refused as syntax, so that a construct
// outside the modelled subset is named as written rather than read as some
// nearby expression. The subset that is evaluated is the brief's: ==, in
// over a list of string literals, startsWith, endsWith, contains, &&, ||,
// and ! over one comparison; everything else widens what it constrains,
// declared.

// conditionLimit is Google's own bound, counted in characters as Google
// counts it: "The maximum length of the attribute condition expression is
// 4096 characters." A longer condition is not read, which also bounds the
// parser's recursion by the text it is handed.
const conditionLimit = 4096

// mappingLimit is the same bound for a mapping value: "The maximum length
// of an attribute mapping expression is 2048 characters."
const mappingLimit = 2048

// listCap bounds the values read from one list under in. The union of
// exact values costs eval a comparison per pair of members, so a list long
// enough would take minutes to read; past the cap the claim is Unknown with
// the count stated, never a truncated union, which would under-approximate.
const listCap = 256

// nestingBound bounds how deep parentheses, calls, lists and maps may
// nest, so that the parser's recursion is bounded by something other than
// the length of the text. Real conditions nest a few levels.
const nestingBound = 100

// syntaxError is where an expression stopped being one, in characters
// from its start, and why. An empty expression stopped nowhere, which at
// records as -1.
type syntaxError struct {
	at      int
	problem string
}

func (e *syntaxError) Error() string {
	if e.at < 0 {
		return e.problem
	}
	return e.problem + " at character " + strconv.Itoa(e.at+1)
}

type tokenKind uint8

const (
	tokEOF tokenKind = iota
	tokIdent
	tokReserved
	tokString
	tokBytes
	tokNumber
	tokBool
	tokNull
	tokOp
)

type token struct {
	kind       tokenKind
	text       string // an identifier, a decoded string, a number or operator as written
	start, end int    // byte offsets in the source
	newline    bool   // a literal that held an unescaped carriage return, read as a line feed
}

// lexer turns the source into tokens. Every token keeps its byte span, so
// that "as written" in a sentence is the customer's own text.
type lexer struct {
	src    string
	pos    int
	tokens []token
}

func lex(src string) ([]token, *syntaxError) {
	l := &lexer{src: src}
	for {
		l.skipSpace()
		if l.pos == len(src) {
			return l.tokens, nil
		}
		if err := l.token(); err != nil {
			return nil, err
		}
	}
}

func (l *lexer) fail(at int, problem string) *syntaxError {
	return &syntaxError{at: utf8.RuneCountInString(l.src[:at]), problem: problem}
}

// skipSpace skips whitespace, which CEL defines as [\t\n\f\r ], and
// comments, which run from // to the end of the line. A // inside a
// string literal is never seen here, because the literal is scanned whole.
func (l *lexer) skipSpace() {
	for l.pos < len(l.src) {
		switch {
		case strings.IndexByte("\t\n\f\r ", l.src[l.pos]) >= 0:
			l.pos++
		case strings.HasPrefix(l.src[l.pos:], "//"):
			end := strings.IndexByte(l.src[l.pos:], '\n')
			if end < 0 {
				l.pos = len(l.src)
			} else {
				l.pos += end + 1
			}
		default:
			return
		}
	}
}

var reserved = []string{"as", "break", "const", "continue", "else", "for", "function", "if", "import", "let", "loop", "package", "namespace", "return", "var", "void", "while"}

func (l *lexer) token() *syntaxError {
	start := l.pos
	c := l.src[l.pos]
	switch {
	case isIdentStart(c):
		for l.pos < len(l.src) && isIdentByte(l.src[l.pos]) {
			l.pos++
		}
		word := l.src[start:l.pos]
		if l.pos < len(l.src) && (l.src[l.pos] == '\'' || l.src[l.pos] == '"') {
			if prefix, ok := literalPrefix(word); ok {
				return l.stringLiteral(start, prefix.raw, prefix.bytes)
			}
		}
		switch {
		case word == "true" || word == "false":
			l.emit(tokBool, word, start)
		case word == "null":
			l.emit(tokNull, word, start)
		case word == "in":
			l.emit(tokOp, word, start)
		case slices.Contains(reserved, word):
			l.emit(tokReserved, word, start)
		default:
			l.emit(tokIdent, word, start)
		}
	case c == '\'' || c == '"':
		return l.stringLiteral(start, false, false)
	case isDigit(c) || (c == '.' && l.pos+1 < len(l.src) && isDigit(l.src[l.pos+1])):
		return l.number(start)
	default:
		for _, op := range []string{"&&", "||", "==", "!=", "<=", ">="} {
			if strings.HasPrefix(l.src[l.pos:], op) {
				l.pos += 2
				l.emit(tokOp, op, start)
				return nil
			}
		}
		if strings.IndexByte("!<>+-*/%?:.,()[]{}", c) < 0 {
			r, _ := utf8.DecodeRuneInString(l.src[l.pos:])
			return l.fail(start, "unexpected character "+strconv.QuoteToASCII(string(r)))
		}
		l.pos++
		l.emit(tokOp, string(c), start)
	}
	return nil
}

func (l *lexer) emit(kind tokenKind, text string, start int) {
	l.tokens = append(l.tokens, token{kind: kind, text: text, start: start, end: l.pos})
}

func isIdentStart(c byte) bool { return c == '_' || ('a' <= c && c <= 'z') || ('A' <= c && c <= 'Z') }
func isIdentByte(c byte) bool  { return isIdentStart(c) || isDigit(c) }
func isDigit(c byte) bool      { return '0' <= c && c <= '9' }
func isHexDigit(c byte) bool {
	return isDigit(c) || ('a' <= c && c <= 'f') || ('A' <= c && c <= 'F')
}

// literalPrefix reads the letters before a quote: r or R for a raw
// string, b or B for bytes, and a bytes prefix followed by a raw one,
// which is the order the grammar gives, BYTES_LIT ::= [bB] STRING_LIT.
func literalPrefix(word string) (prefix struct{ raw, bytes bool }, ok bool) {
	switch strings.ToLower(word) {
	case "r":
		return struct{ raw, bytes bool }{raw: true}, true
	case "b":
		return struct{ raw, bytes bool }{bytes: true}, true
	case "br":
		return struct{ raw, bytes bool }{raw: true, bytes: true}, true
	}
	return prefix, false
}

// number scans an INT_LIT, UINT_LIT or FLOAT_LIT. Numbers are never
// evaluated, so the scan need only find where the literal ends and refuse
// what the grammar refuses.
func (l *lexer) number(start int) *syntaxError {
	if strings.HasPrefix(l.src[l.pos:], "0x") || strings.HasPrefix(l.src[l.pos:], "0X") {
		l.pos += 2
		digits := l.pos
		for l.pos < len(l.src) && isHexDigit(l.src[l.pos]) {
			l.pos++
		}
		if l.pos == digits {
			return l.fail(start, "invalid number")
		}
	} else {
		for l.pos < len(l.src) && isDigit(l.src[l.pos]) {
			l.pos++
		}
		if l.pos < len(l.src) && l.src[l.pos] == '.' {
			l.pos++
			for l.pos < len(l.src) && isDigit(l.src[l.pos]) {
				l.pos++
			}
		}
		if l.pos < len(l.src) && (l.src[l.pos] == 'e' || l.src[l.pos] == 'E') {
			l.pos++
			if l.pos < len(l.src) && (l.src[l.pos] == '+' || l.src[l.pos] == '-') {
				l.pos++
			}
			digits := l.pos
			for l.pos < len(l.src) && isDigit(l.src[l.pos]) {
				l.pos++
			}
			if l.pos == digits {
				return l.fail(start, "invalid number")
			}
		}
	}
	if l.pos < len(l.src) && (l.src[l.pos] == 'u' || l.src[l.pos] == 'U') {
		l.pos++
	}
	l.emit(tokNumber, l.src[start:l.pos], start)
	return nil
}

// stringLiteral scans a literal from its opening quote: single-quoted,
// double-quoted, or triple-quoted, in which newlines and the other quote
// may appear. An escape the grammar does not define is a refusal, never
// a backslash dropped or a character kept. A raw literal is the
// characters between its delimiters, backslashes included: the grammar
// cel-go and cel-cpp generate their lexers from scans no escape in one,
// so a backslash before the closing quote does not keep the literal open.
//
// An unescaped carriage return, alone or before a line feed, is read as a
// line feed, which is what cel-go's unescape and cel-cpp's UnescapeInternal
// do to every literal, raw ones included; the language definition says
// only that a triple-quoted literal may hold newlines. The token is marked
// so that the evaluator does not claim exactness on a value the definition
// leaves to the implementation.
func (l *lexer) stringLiteral(start int, raw, isBytes bool) *syntaxError {
	quote := l.src[l.pos]
	delimiter := string(quote)
	if strings.HasPrefix(l.src[l.pos:], strings.Repeat(delimiter, 3)) {
		delimiter = strings.Repeat(delimiter, 3)
	}
	l.pos += len(delimiter)
	var text strings.Builder
	newline := false
	for {
		if strings.HasPrefix(l.src[l.pos:], delimiter) {
			l.pos += len(delimiter)
			break
		}
		if l.pos == len(l.src) || (len(delimiter) == 1 && (l.src[l.pos] == '\n' || l.src[l.pos] == '\r')) {
			return l.fail(start, "unterminated string literal")
		}
		switch {
		case l.src[l.pos] == '\r':
			text.WriteByte('\n')
			l.pos++
			if l.pos < len(l.src) && l.src[l.pos] == '\n' {
				l.pos++
			}
			newline = true
		case raw || l.src[l.pos] != '\\':
			r, size := utf8.DecodeRuneInString(l.src[l.pos:])
			text.WriteRune(r)
			l.pos += size
		default:
			decoded, size, ok := decodeEscape(l.src[l.pos:])
			if !ok {
				return l.fail(l.pos, "invalid escape sequence")
			}
			text.WriteRune(decoded)
			l.pos += size
		}
	}
	kind := tokString
	if isBytes {
		kind = tokBytes
	}
	l.tokens = append(l.tokens, token{kind: kind, text: text.String(), start: start, end: l.pos, newline: newline})
	return nil
}

// decodeEscape reads the escape at the start of s: the code point it
// names and how many bytes it spans. The forms are the grammar's: a
// punctuation mark or a whitespace code after the backslash, \x and two
// hex digits, \u and four, \U and eight, or three octal digits from 000 to
// 377. A surrogate or a code point past U+10FFFF is not a code point.
func decodeEscape(s string) (rune, int, bool) {
	if len(s) < 2 {
		return 0, 0, false
	}
	switch c := s[1]; c {
	case 'a':
		return '\a', 2, true
	case 'b':
		return '\b', 2, true
	case 'f':
		return '\f', 2, true
	case 'n':
		return '\n', 2, true
	case 'r':
		return '\r', 2, true
	case 't':
		return '\t', 2, true
	case 'v':
		return '\v', 2, true
	case '\\', '?', '"', '\'', '`':
		return rune(c), 2, true
	case 'x', 'X':
		return hexEscape(s, 2)
	case 'u':
		return hexEscape(s, 4)
	case 'U':
		return hexEscape(s, 8)
	}
	if len(s) < 4 || s[1] < '0' || s[1] > '3' || s[2] < '0' || s[2] > '7' || s[3] < '0' || s[3] > '7' {
		return 0, 0, false
	}
	n, _ := strconv.ParseUint(s[1:4], 8, 16)
	return rune(n), 4, true
}

func hexEscape(s string, digits int) (rune, int, bool) {
	if len(s) < 2+digits {
		return 0, 0, false
	}
	for i := 2; i < 2+digits; i++ {
		if !isHexDigit(s[i]) {
			return 0, 0, false
		}
	}
	n, _ := strconv.ParseUint(s[2:2+digits], 16, 32)
	if n > utf8.MaxRune || (0xD800 <= n && n <= 0xDFFF) {
		return 0, 0, false
	}
	return rune(n), 2 + digits, true
}

type exprKind uint8

const (
	exprString  exprKind = iota // text is the decoded value
	exprBytes                   // text is the decoded value; the literal is bytes, not a string
	exprLiteral                 // a number, true, false or null, as written
	exprIdent                   // text is the name
	exprSelect                  // kids[0].text: text is the field
	exprCall                    // text is the function; kids[0] the receiver, nil for a global call; kids[1:] the arguments
	exprIndex                   // kids[0][kids[1]]
	exprList                    // kids are the elements
	exprMap                     // kids are key, value, key, value, ...
	exprUnary                   // text is ! or -; kids[0] the operand
	exprBinary                  // text is the operator; kids are the operands
	exprTernary                 // kids are the condition and the two branches
)

// expr is one node of a parsed expression, with the byte span it was
// written in.
type expr struct {
	kind       exprKind
	text       string
	kids       []*expr
	start, end int
	newline    bool // a string literal that held an unescaped carriage return
}

// parser is a recursive descent over the grammar, one function per
// precedence level, so that A && B || C groups as CEL groups it.
type parser struct {
	src    string
	tokens []token
	pos    int
	depth  int
}

// parseCEL lexes and parses one expression, or says where it stopped
// being one.
func parseCEL(src string) (*expr, *syntaxError) {
	tokens, err := lex(src)
	if err != nil {
		return nil, err
	}
	if len(tokens) == 0 {
		return nil, &syntaxError{at: -1, problem: "empty expression"}
	}
	p := &parser{src: src, tokens: tokens}
	n, err := p.expression()
	if err != nil {
		return nil, err
	}
	if p.pos < len(p.tokens) {
		return nil, p.unexpected(p.tokens[p.pos], " after the expression")
	}
	return n, nil
}

func (p *parser) peek() token {
	if p.pos < len(p.tokens) {
		return p.tokens[p.pos]
	}
	return token{kind: tokEOF, start: len(p.src), end: len(p.src)}
}

func (p *parser) isOp(text string) bool {
	t := p.peek()
	return t.kind == tokOp && t.text == text
}

func (p *parser) unexpected(t token, where string) *syntaxError {
	if t.kind == tokEOF {
		return p.fail(t, "unexpected end of expression")
	}
	if t.kind == tokReserved {
		return p.fail(t, "reserved word "+strconv.QuoteToASCII(t.text))
	}
	return p.fail(t, "unexpected "+strconv.QuoteToASCII(p.src[t.start:t.end])+where)
}

func (p *parser) fail(t token, problem string) *syntaxError {
	return &syntaxError{at: utf8.RuneCountInString(p.src[:t.start]), problem: problem}
}

func (p *parser) expect(op string) *syntaxError {
	if !p.isOp(op) {
		return p.unexpected(p.peek(), "")
	}
	p.pos++
	return nil
}

// enter and leave track the containers open around the parse, so that a
// nesting past nestingBound is refused rather than recursed into.
func (p *parser) enter(t token) *syntaxError {
	if p.depth == nestingBound {
		return p.fail(t, "nested more than "+strconv.Itoa(nestingBound)+" levels deep")
	}
	p.depth++
	return nil
}

func (p *parser) leave() { p.depth-- }

// node builds an inner node over the source span from start to the end of
// the last token consumed. The span is taken from the tokens rather than
// from the children because a parenthesised child keeps its own tight
// span, and a clause quoted "as written" must not stop short of its
// closing parenthesis.
func (p *parser) node(kind exprKind, text string, start int, kids ...*expr) *expr {
	return &expr{kind: kind, text: text, kids: kids, start: start, end: p.tokens[p.pos-1].end}
}

// expression is the ternary level: ConditionalOr ["?" ConditionalOr ":" Expr].
func (p *parser) expression() (*expr, *syntaxError) {
	start := p.peek().start
	cond, err := p.or()
	if err != nil {
		return nil, err
	}
	if !p.isOp("?") {
		return cond, nil
	}
	p.pos++
	then, err := p.or()
	if err != nil {
		return nil, err
	}
	if err := p.expect(":"); err != nil {
		return nil, err
	}
	otherwise, err := p.expression()
	if err != nil {
		return nil, err
	}
	return p.node(exprTernary, "?", start, cond, then, otherwise), nil
}

// binary parses one left-associative level: operand (op operand)*.
func (p *parser) binary(ops []string, operand func() (*expr, *syntaxError)) (*expr, *syntaxError) {
	start := p.peek().start
	left, err := operand()
	if err != nil {
		return nil, err
	}
	for {
		t := p.peek()
		if t.kind != tokOp || !slices.Contains(ops, t.text) {
			return left, nil
		}
		p.pos++
		right, err := operand()
		if err != nil {
			return nil, err
		}
		left = p.node(exprBinary, t.text, start, left, right)
	}
}

func (p *parser) or() (*expr, *syntaxError)  { return p.binary([]string{"||"}, p.and) }
func (p *parser) and() (*expr, *syntaxError) { return p.binary([]string{"&&"}, p.relation) }
func (p *parser) relation() (*expr, *syntaxError) {
	return p.binary([]string{"<", "<=", ">=", ">", "==", "!=", "in"}, p.addition)
}
func (p *parser) addition() (*expr, *syntaxError) {
	return p.binary([]string{"+", "-"}, p.multiplication)
}
func (p *parser) multiplication() (*expr, *syntaxError) {
	return p.binary([]string{"*", "/", "%"}, p.unary)
}

// unary parses ! and - prefixes; a run of either nests, and the evaluator
// counts the nesting.
func (p *parser) unary() (*expr, *syntaxError) {
	t := p.peek()
	if t.kind == tokOp && (t.text == "!" || t.text == "-") {
		p.pos++
		operand, err := p.unary()
		if err != nil {
			return nil, err
		}
		return p.node(exprUnary, t.text, t.start, operand), nil
	}
	return p.member()
}

// member parses the postfix chain: field selection, a receiver call, and
// indexing.
func (p *parser) member() (*expr, *syntaxError) {
	start := p.peek().start
	n, err := p.primary()
	if err != nil {
		return nil, err
	}
	for {
		switch {
		case p.isOp("."):
			p.pos++
			// A reserved word may follow the dot: cel-go and cel-cpp refuse
			// one only as a bare identifier or a global call, "as they *are*
			// valid field names for protos", and the language definition
			// permits a receiver call such as a.package(). The keywords true,
			// false, null and in are tokens of their own and cannot.
			field := p.peek()
			if field.kind != tokIdent && field.kind != tokReserved {
				return nil, p.unexpected(field, "")
			}
			p.pos++
			if p.isOp("(") {
				args, err := p.arguments()
				if err != nil {
					return nil, err
				}
				n = p.node(exprCall, field.text, start, append([]*expr{n}, args...)...)
				continue
			}
			n = p.node(exprSelect, field.text, start, n)
		case p.isOp("["):
			open := p.peek()
			if err := p.enter(open); err != nil {
				return nil, err
			}
			p.pos++
			key, err := p.expression()
			if err != nil {
				return nil, err
			}
			if err := p.expect("]"); err != nil {
				return nil, err
			}
			p.leave()
			n = p.node(exprIndex, "[]", start, n, key)
		default:
			return n, nil
		}
	}
}

// arguments parses "(" [ExprList] ")".
func (p *parser) arguments() ([]*expr, *syntaxError) {
	open := p.peek()
	if err := p.enter(open); err != nil {
		return nil, err
	}
	p.pos++
	args, err := p.list(")", false)
	if err != nil {
		return nil, err
	}
	p.leave()
	return args, nil
}

// list parses comma-separated expressions up to the closing delimiter,
// which is consumed. A trailing comma is allowed where the grammar allows
// it, in list and map literals.
func (p *parser) list(closing string, trailingComma bool) ([]*expr, *syntaxError) {
	var items []*expr
	for !p.isOp(closing) {
		if len(items) > 0 {
			if err := p.expect(","); err != nil {
				return nil, err
			}
			if trailingComma && p.isOp(closing) {
				break
			}
		}
		item, err := p.expression()
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	p.pos++
	return items, nil
}

// primary parses an identifier or global call, a parenthesised expression,
// a list or map literal, or a literal. A leading dot, which the grammar
// allows for an absolute name, is refused: no condition names one.
func (p *parser) primary() (*expr, *syntaxError) {
	t := p.peek()
	switch t.kind {
	case tokIdent:
		p.pos++
		if p.isOp("(") {
			args, err := p.arguments()
			if err != nil {
				return nil, err
			}
			return p.node(exprCall, t.text, t.start, append([]*expr{nil}, args...)...), nil
		}
		return &expr{kind: exprIdent, text: t.text, start: t.start, end: t.end}, nil
	case tokString:
		p.pos++
		return &expr{kind: exprString, text: t.text, start: t.start, end: t.end, newline: t.newline}, nil
	case tokBytes:
		p.pos++
		return &expr{kind: exprBytes, text: t.text, start: t.start, end: t.end, newline: t.newline}, nil
	case tokNumber, tokBool, tokNull:
		p.pos++
		return &expr{kind: exprLiteral, text: t.text, start: t.start, end: t.end}, nil
	case tokOp:
		switch t.text {
		case "(":
			if err := p.enter(t); err != nil {
				return nil, err
			}
			p.pos++
			inner, err := p.expression()
			if err != nil {
				return nil, err
			}
			if err := p.expect(")"); err != nil {
				return nil, err
			}
			p.leave()
			// The parentheses are not part of the expression's span: an
			// anomaly quotes the clause, and a clause written in
			// parentheses is the same clause.
			return inner, nil
		case "[":
			if err := p.enter(t); err != nil {
				return nil, err
			}
			p.pos++
			items, err := p.list("]", true)
			if err != nil {
				return nil, err
			}
			p.leave()
			return p.node(exprList, "[]", t.start, items...), nil
		case "{":
			if err := p.enter(t); err != nil {
				return nil, err
			}
			p.pos++
			entries, err := p.mapEntries()
			if err != nil {
				return nil, err
			}
			p.leave()
			return p.node(exprMap, "{}", t.start, entries...), nil
		}
	}
	return nil, p.unexpected(t, "")
}

// mapEntries parses [MapInits] [","] "}" and returns keys and values
// alternating.
func (p *parser) mapEntries() ([]*expr, *syntaxError) {
	var entries []*expr
	for !p.isOp("}") {
		if len(entries) > 0 {
			if err := p.expect(","); err != nil {
				return nil, err
			}
			if p.isOp("}") {
				break
			}
		}
		key, err := p.expression()
		if err != nil {
			return nil, err
		}
		if err := p.expect(":"); err != nil {
			return nil, err
		}
		val, err := p.expression()
		if err != nil {
			return nil, err
		}
		entries = append(entries, key, val)
	}
	p.pos++
	return entries, nil
}

// reference is a keyword and the field selected from it: assertion.sub,
// google.subject, attribute.repository, or assertion['sub']. A bare
// keyword is a reference with no field, so that the sentence can say so.
type reference struct {
	root, field string
	node        *expr
}

// mapped is how the attribute mapping maps one attribute: to the claim
// its expression names when the expression is exactly a reference to one
// assertion field, or to nothing this parser can attribute, with why.
type mapped struct {
	claim      trust.ClaimKey
	expression string
	why        string
}

// mappedBy reads one mapping value. A value that is exactly assertion.<field>,
// comments and whitespace aside, names that field; any other expression,
// one past Google's length limit, or text that is not an expression, maps
// the attribute to something this parser cannot attribute to a claim.
func mappedBy(expression string) mapped {
	m := mapped{expression: expression}
	if n := utf8.RuneCountInString(expression); n > mappingLimit {
		m.why = "the attribute mapping maps by an expression " + strconv.Itoa(n) + " characters long; Google accepts at most " + strconv.Itoa(mappingLimit) + ", so it is not read"
		return m
	}
	tree, err := parseCEL(expression)
	if err != nil {
		m.why = "the attribute mapping maps by " + quote(expression) + ", which is not an expression this parser can read"
		return m
	}
	if ref, ok := referenceOf(tree); ok && ref.root == "assertion" && ref.field != "" {
		m.claim = trust.ClaimKey(ref.field)
		return m
	}
	m.why = "the attribute mapping maps by the expression " + quote(expression) + "; this parser does not evaluate mapping expressions"
	return m
}

// resolver turns a reference into the claim it constrains, under one
// provider: its mapping, its respelling of assertion fields, or the
// reason none of its references can be attributed to a claim at all.
type resolver struct {
	unattributable string // why nothing resolves: the provider's kind leaves its credential's shape unstated
	translate      map[string]trust.ClaimKey
	mapping        map[string]mapped
	mappingUnread  bool // the document writes a mapping this parser did not read, so what it maps is not stated
}

// failure is why a reference does not name a claim, and what an anomaly
// names for it. about says which part of the document the reason is in,
// because the sentence around the reason differs: a keyword failure is
// the clause's own, the provider's kind and an unread mapping are stated
// with "but", a mapping that was read with "which".
type failure struct {
	why       string
	construct string
	about     failureAbout
}

type failureAbout int

const (
	theKeyword failureAbout = iota
	theProvider
	theMapping
	theUnreadMapping
)

var keywords = []string{"assertion", "google", "attribute"}

// resolve attributes a reference to a claim, or says why it cannot. The
// keyword is checked first, then the provider's kind, then the mapping:
// a reference outside Google's three keywords names nothing whatever the
// provider is.
func (res resolver) resolve(ref reference) (trust.ClaimKey, *failure) {
	written := ref.root
	if ref.field != "" {
		written += "." + ref.field
	}
	if !slices.Contains(keywords, ref.root) {
		return "", &failure{why: "refers to " + printable(ref.root) + ", which is not assertion, google or attribute, the keywords Google documents for a condition", construct: printable(ref.root), about: theKeyword}
	}
	if ref.field == "" {
		return "", &failure{why: "refers to " + ref.root + " without naming a field of it", construct: ref.root, about: theKeyword}
	}
	if res.unattributable != "" {
		return "", &failure{why: res.unattributable, construct: printable(written), about: theProvider}
	}
	if ref.root == "assertion" {
		return res.claim(ref.field), nil
	}
	if res.mappingUnread {
		return "", &failure{why: "the attribute mapping is not read", construct: printable(written), about: theUnreadMapping}
	}
	m, ok := res.mapping[written]
	switch {
	case !ok && written == "google.subject":
		return "", &failure{why: "the attribute mapping does not map; Google says the mapping must include google.subject", construct: written, about: theMapping}
	case !ok:
		return "", &failure{why: "the attribute mapping does not map", construct: printable(written), about: theMapping}
	case m.claim == "":
		construct := printable(m.expression)
		if m.expression == "" {
			construct = printable(written)
		}
		return "", &failure{why: m.why, construct: construct, about: theMapping}
	}
	return res.claim(string(m.claim)), nil
}

func (res resolver) claim(field string) trust.ClaimKey {
	if claim, ok := res.translate[field]; ok {
		return claim
	}
	return trust.ClaimKey(field)
}

// subject is the claim google.subject maps to, the one Google's length
// limit on the subject falls on, and "" when the mapping does not
// attribute the subject to a claim: the subject is then some function of
// the claims, and no value written for a claim is known to exceed it.
func (res resolver) subject() trust.ClaimKey {
	claim, failed := res.resolve(reference{root: "google", field: "subject"})
	if failed != nil {
		return ""
	}
	return claim
}

// subjectLimitDoubt ends every sentence about a value past Google's limit
// on the subject: the fact, and what the parser does with it. The value
// is kept and the set declared an upper bound rather than reported as
// admitting nobody, because the limit is Google's documentation, not a
// refusal this parser observed, and a set proven empty from a document
// alone is the one output the lattice must never produce by mistake.
func subjectLimitDoubt(claim trust.ClaimKey, such string) string {
	return "; Google says google.subject, which maps to " + string(claim) + ", cannot exceed " + strconv.Itoa(subjectLimit) + " bytes, so no credential carrying " + such + " can be exchanged and the set stated is read as an upper bound"
}

// referenceOf reads a node as a reference: a keyword, a field selected
// from one, or a field indexed from one by a string literal.
func referenceOf(n *expr) (reference, bool) {
	switch n.kind {
	case exprIdent:
		return reference{root: n.text, node: n}, true
	case exprSelect:
		if n.kids[0].kind == exprIdent {
			return reference{root: n.kids[0].text, field: n.text, node: n}, true
		}
	case exprIndex:
		if n.kids[0].kind == exprIdent && n.kids[1].kind == exprString {
			return reference{root: n.kids[0].text, field: n.kids[1].text, node: n}, true
		}
	}
	return reference{}, false
}

// constrained finds the first reference in a subtree, in source order,
// together with the whole field path written on it: in
// assertion.attributes['dept'] the reference is assertion.attributes and
// the whole is the indexing, which is what a sentence says the clause
// constrains.
func constrained(n *expr) (ref reference, whole *expr, ok bool) {
	if n == nil {
		return reference{}, nil, false
	}
	if ref, ok := referenceOf(n); ok {
		return ref, n, true
	}
	if n.kind == exprSelect || n.kind == exprIndex {
		if ref, base, ok := constrained(n.kids[0]); ok && base == n.kids[0] {
			return ref, n, true
		}
	}
	for _, k := range n.kids {
		if ref, whole, ok := constrained(k); ok {
			return ref, whole, true
		}
	}
	return reference{}, nil, false
}

// condition evaluates one parsed expression under a resolver, recording
// every doubt on the reading. Every result is an upper bound on the
// credentials the expression admits: the Meet of the operands of &&, the
// Join of the operands of ||, the exact set of a modelled comparison, and
// the top of a claim, or of the whole grant, for everything else.
type condition struct {
	r      *reading
	res    resolver
	src    string
	source string
}

// evaluate reads an attribute condition into the set it admits. A
// condition past Google's length limit, or outside the grammar, is not
// read at all: the piece that was not understood may have governed every
// clause that was, so the whole grant is top.
func (r *reading) evaluate(text string, res resolver, source string) eval.AdmittedSet {
	if n := utf8.RuneCountInString(text); n > conditionLimit {
		r.doubt(trust.Anomaly{Kind: trust.Unmodelled, Construct: "expression length", Message: source + " is " + strconv.Itoa(n) + " characters long; Google accepts at most " + strconv.Itoa(conditionLimit) + ", so it is not read and nothing it says about the credential is modelled", Source: source})
		return eval.Everything()
	}
	tree, err := parseCEL(text)
	if err != nil {
		r.doubt(trust.Anomaly{Kind: trust.Unmodelled, Construct: "unparseable expression", Message: source + " is not an expression this parser can read: " + err.Error() + "; nothing it says about the credential is modelled", Source: source})
		return eval.Everything()
	}
	c := &condition{r: r, res: res, src: text, source: source}
	return c.admitted(tree)
}

func (c *condition) admitted(n *expr) eval.AdmittedSet {
	switch {
	case n.kind == exprBinary && n.text == "&&":
		return c.admitted(n.kids[0]).Meet(c.admitted(n.kids[1]))
	case n.kind == exprBinary && n.text == "||":
		return c.admitted(n.kids[0]).Join(c.admitted(n.kids[1]))
	case n.kind == exprUnary && n.text == "!":
		return c.negated(n)
	case n.kind == exprLiteral && n.text == "true":
		return eval.Everything()
	case n.kind == exprLiteral && n.text == "false":
		return eval.Nothing()
	case n.kind == exprTernary:
		return c.unattributable("?", c.quoted(n)+" is a conditional expression, which this parser does not model, so nothing it says about the credential is modelled")
	}
	return c.clause(n)
}

// negated evaluates a run of ! operators. An even run is the operand. An
// odd run over a single comparison on one claim, which its set shows as
// terms constraining that claim alone with no doubt recorded, admits
// every value of the claim but those, the top of the claim; over anything
// else it makes its whole operand top, because a token failing one of two
// claims is one no single claim's Unknown describes.
func (c *condition) negated(n *expr) eval.AdmittedSet {
	operand, count := n, 0
	for operand.kind == exprUnary && operand.text == "!" {
		operand, count = operand.kids[0], count+1
	}
	if count%2 == 0 {
		return c.admitted(operand)
	}
	before := len(c.r.caveats)
	set := c.admitted(operand)
	if len(c.r.caveats) == before {
		if claim, ok := singleClaim(set); ok {
			return c.unknownOn(claim, "operator !", "!", c.quoted(n)+" negates a comparison on "+string(claim)+"; this parser models what a condition admits, not what it excludes, so "+string(claim)+" is read as unconstrained")
		}
	}
	return c.unattributable("!", c.quoted(n)+" negates an expression that is not a single comparison on one claim, so nothing it says about the credential is modelled")
}

// singleClaim reports the one claim a set constrains, when every term
// constrains exactly that claim and nothing else.
func singleClaim(set eval.AdmittedSet) (trust.ClaimKey, bool) {
	var claim trust.ClaimKey
	terms := set.Terms()
	for _, term := range terms {
		if len(term) != 1 {
			return "", false
		}
		for k := range term {
			if claim != "" && k != claim {
				return "", false
			}
			claim = k
		}
	}
	return claim, claim != ""
}

// clause evaluates one comparison, call or leaf: a modelled form into its
// set, and every other into the top of the claim it names, or of the
// whole grant when it names none.
func (c *condition) clause(n *expr) eval.AdmittedSet {
	switch n.kind {
	case exprBinary:
		switch n.text {
		case "==":
			return c.equality(n)
		case "in":
			return c.membership(n)
		}
	case exprCall:
		return c.call(n)
	case exprLiteral, exprString, exprBytes, exprList, exprMap:
		return c.unattributable(c.written(n), c.quoted(n)+" is the literal "+c.written(n)+" where a comparison on a claim was expected, so nothing it says about the credential is modelled")
	}
	if ref, ok := referenceOf(n); ok {
		claim, failed := c.res.resolve(ref)
		if failed != nil {
			return c.failed(n, ref, ref.node, failed)
		}
		return c.unknownOn(claim, "truth", c.written(n), c.quoted(n)+" tests the truth of "+string(claim)+", which this parser does not model, so "+string(claim)+" is read as unconstrained")
	}
	return c.unmodelled(n, n)
}

// equality models <reference> == '<literal>' in either order. A comparand
// that is not a string literal leaves the claim Unknown, named by the
// comparand; a comparison with no reference on either side is judged by
// the side that is not a literal.
func (c *condition) equality(n *expr) eval.AdmittedSet {
	ref, ok := referenceOf(n.kids[0])
	other := n.kids[1]
	if !ok {
		ref, ok = referenceOf(n.kids[1])
		other = n.kids[0]
	}
	if !ok {
		culprit := n.kids[0]
		if culprit.kind == exprString {
			culprit = n.kids[1]
		}
		return c.unmodelled(n, culprit)
	}
	claim, failed := c.res.resolve(ref)
	if failed != nil {
		return c.failed(n, ref, ref.node, failed)
	}
	if other.kind != exprString {
		return c.unknownOn(claim, "comparand", c.written(other), c.quoted(n)+" compares "+string(claim)+" against "+c.written(other)+", which is not a string literal, so "+string(claim)+" is read as unconstrained")
	}
	switch {
	case groups(ref):
		return c.setValued(n, claim)
	case other.newline:
		return c.unsettled(n, claim, "compares "+string(claim)+" against a literal holding an unescaped carriage return")
	}
	c.overlong(n, claim, "compares "+string(claim)+" against a value", "that value", other.text)
	return onClaim(claim, eval.Exact(other.text))
}

// overlong records that a value the condition writes for the claim
// google.subject maps to is one no credential maps to: "google.subject:
// … Cannot exceed 127 bytes." The limit counts bytes, as Google counts
// it, and is applied to the values the document writes: a pattern also
// matches values past the limit, but so does every pattern, and a grant
// declared inexact for what every grant admits would say nothing. One
// fact per clause, however many of its values are past the limit.
func (c *condition) overlong(n *expr, claim trust.ClaimKey, wrote, such string, values ...string) {
	if claim != c.res.subject() {
		return
	}
	for _, v := range values {
		if len(v) > subjectLimit {
			c.r.doubt(trust.Anomaly{Kind: SubjectLength, Claim: claim, Construct: describe(n, c.src), Message: c.quoted(n) + " " + wrote + " " + strconv.Itoa(len(v)) + " bytes long" + subjectLimitDoubt(claim, such), Source: c.source})
			return
		}
	}
}

// groups reports whether a reference names google.groups, which Google
// describes as "A set of groups that the identity belongs to": a value the
// lattice, which models a claim as one string, cannot hold, under any
// form it is compared in.
func groups(ref reference) bool { return ref.root == "google" && ref.field == "groups" }

// setValued widens a modelled form written on google.groups to the top of
// the claim it maps to, with the reason stated.
func (c *condition) setValued(n *expr, claim trust.ClaimKey) eval.AdmittedSet {
	return c.unknownOn(claim, "group membership", "google.groups", c.quoted(n)+" constrains google.groups, which maps to the claim "+string(claim)+" and which Google documents as the set of groups the identity belongs to; a list-valued claim is outside what this parser models, so "+string(claim)+" is read as unconstrained")
}

// unsettled widens a modelled form whose literal held an unescaped
// carriage return. Both reference implementations read it as a line feed
// and the language definition does not say, so an Exact on either reading
// could be narrower than Google; what says what the clause does with the
// literal, in the sentence's own words.
func (c *condition) unsettled(n *expr, claim trust.ClaimKey, what string) eval.AdmittedSet {
	return c.unknownOn(claim, "carriage return", "carriage return", c.quoted(n)+" "+what+"; cel-go and cel-cpp read one as a line feed and the CEL language definition does not say, so the value is not read and "+string(claim)+" is read as unconstrained")
}

// membership models <reference> in [<literals>]: a union inside one
// Term, folded as a balanced tree, capped. A list that is empty, past the
// cap, or not a list of string literals leaves the claim Unknown, as does
// a literal tested against a claim, which is membership of a list-valued
// claim the lattice models as one value.
func (c *condition) membership(n *expr) eval.AdmittedSet {
	left, right := n.kids[0], n.kids[1]
	if ref, ok := referenceOf(left); ok {
		claim, failed := c.res.resolve(ref)
		if failed != nil {
			return c.failed(n, ref, ref.node, failed)
		}
		if right.kind != exprList || !literals(right.kids) {
			return c.unknownOn(claim, "list", "in", c.quoted(n)+" tests "+string(claim)+" for membership of "+c.written(right)+", which is not a list of string literals, so "+string(claim)+" is read as unconstrained")
		}
		switch {
		case groups(ref):
			return c.setValued(n, claim)
		case len(right.kids) == 0:
			return c.unknownOn(claim, "empty list", "in", c.quoted(n)+" tests "+string(claim)+" for membership of an empty list; Google does not document such a condition, so "+string(claim)+" is read as unconstrained")
		case len(right.kids) > listCap:
			return c.unknownOn(claim, "list count", "in", c.quoted(n)+" lists "+strconv.Itoa(len(right.kids))+" values; this parser reads at most "+strconv.Itoa(listCap)+", so "+string(claim)+" is read as unconstrained")
		case slices.ContainsFunc(right.kids, func(item *expr) bool { return item.newline }):
			return c.unsettled(n, claim, "tests "+string(claim)+" for membership of a list holding a literal with an unescaped carriage return")
		}
		values, texts := make([]eval.StringSet, len(right.kids)), make([]string, len(right.kids))
		for i, item := range right.kids {
			values[i], texts[i] = eval.Exact(item.text), item.text
		}
		c.overlong(n, claim, "lists for "+string(claim)+" a value", "that value", texts...)
		return onClaim(claim, union(values))
	}
	if ref, ok := referenceOf(right); ok {
		claim, failed := c.res.resolve(ref)
		if failed != nil {
			return c.failed(n, ref, ref.node, failed)
		}
		mapped := ""
		if ref.root != "assertion" {
			mapped = ", which maps to the claim " + string(claim)
		}
		return c.unknownOn(claim, "group membership", "in", c.quoted(n)+" tests membership of "+c.written(right)+mapped+"; a list-valued claim is outside what this parser models, so "+string(claim)+" is read as unconstrained")
	}
	return c.unmodelled(n, left)
}

func literals(items []*expr) bool {
	for _, item := range items {
		if item.kind != exprString {
			return false
		}
	}
	return true
}

// union folds sets with Join as a balanced tree. Join renormalises its
// result, so a left fold over n values renormalises n lists of growing
// length; the balanced fold renormalises each value about log n times,
// and the result is the same, because Join is associative and commutative
// and the normal form is canonical.
func union(sets []eval.StringSet) eval.StringSet {
	for len(sets) > 1 {
		merged := make([]eval.StringSet, 0, (len(sets)+1)/2)
		for i := 0; i < len(sets); i += 2 {
			if i+1 < len(sets) {
				merged = append(merged, sets[i].Join(sets[i+1]))
			} else {
				merged = append(merged, sets[i])
			}
		}
		sets = merged
	}
	return sets[0]
}

// call models startsWith, endsWith and contains on a reference with one
// string literal, as the glob with the text and a star on the open side.
// The text must hold no star or question mark, which the pattern language
// reads as wildcards, and must not be empty, which is a presence test the
// lattice cannot express. Any other function on a reference, and has() on
// one, leaves the claim Unknown by the function's name.
func (c *condition) call(n *expr) eval.AdmittedSet {
	fn, receiver, args := n.text, n.kids[0], n.kids[1:]
	if receiver == nil {
		if fn == "has" && len(args) == 1 {
			if ref, ok := referenceOf(args[0]); ok {
				claim, failed := c.res.resolve(ref)
				if failed != nil {
					return c.failed(n, ref, ref.node, failed)
				}
				return c.unknownOn(claim, "presence", "has", c.quoted(n)+" tests whether "+string(claim)+" is present, which this parser cannot express, so "+string(claim)+" is read as unconstrained")
			}
		}
		return c.unmodelled(n, n)
	}
	ref, ok := referenceOf(receiver)
	if !ok {
		return c.unmodelled(n, receiver)
	}
	claim, failed := c.res.resolve(ref)
	if failed != nil {
		return c.failed(n, ref, ref.node, failed)
	}
	part, modelled := map[string]string{"startsWith": "prefix", "endsWith": "suffix", "contains": "substring"}[fn]
	if !modelled {
		return c.unknownOn(claim, "function "+fn, fn, c.quoted(n)+" constrains "+string(claim)+" with the function "+strconv.Quote(fn)+", which this parser does not model, so "+string(claim)+" is read as unconstrained")
	}
	switch {
	case len(args) != 1:
		return c.unknownOn(claim, "function "+fn, fn, c.quoted(n)+" calls "+fn+" with "+strconv.Itoa(len(args))+" arguments, not the one string it takes, so "+string(claim)+" is read as unconstrained")
	case args[0].kind != exprString:
		return c.unknownOn(claim, "function "+fn, fn, c.quoted(n)+" tests "+string(claim)+" for a "+part+" that is not a string literal, so "+string(claim)+" is read as unconstrained")
	case groups(ref):
		return c.setValued(n, claim)
	case args[0].newline:
		return c.unsettled(n, claim, "tests "+string(claim)+" for a "+part+" holding an unescaped carriage return")
	}
	text := args[0].text
	if text == "" {
		return c.unknownOn(claim, "presence", fn, c.quoted(n)+" tests "+string(claim)+" for the empty "+part+", which every value has but only when the claim is present; this parser cannot express presence, so "+string(claim)+" is read as unconstrained")
	}
	if i := strings.IndexAny(text, "*?"); i >= 0 {
		return c.unknownOn(claim, "wildcard", fn, c.quoted(n)+" tests "+string(claim)+" for a "+part+" containing "+strconv.Quote(text[i:i+1])+", which this parser's patterns read as a wildcard, so it cannot be stated as a pattern and "+string(claim)+" is read as unconstrained")
	}
	c.overlong(n, claim, "tests "+string(claim)+" for a "+part, "such a "+part, text)
	pattern := map[string]string{"startsWith": text + "*", "endsWith": "*" + text, "contains": "*" + text + "*"}[fn]
	return onClaim(claim, eval.Glob(pattern))
}

// unmodelled widens for a construct the subset does not model: the top
// of the first claim the culprit names, or of the whole grant when it
// names none, in which case the clause itself is what the sentence names.
// A culprit that is itself a form the subset models is outside the subset
// by its position, as an operand of the clause, not by its operator, and
// the sentence must not say otherwise: a reporter counting constructs by
// name would count == or startsWith as unmodelled.
func (c *condition) unmodelled(clause, culprit *expr) eval.AdmittedSet {
	ref, whole, found := constrained(culprit)
	if !found {
		return c.unattributable(describe(clause, c.src), c.quoted(clause)+" "+noClaim(clause, c.src)+", so nothing it says about the credential is modelled")
	}
	claim, failed := c.res.resolve(ref)
	if failed != nil {
		return c.failed(clause, ref, whole, failed)
	}
	construct := describe(culprit, c.src)
	var what string
	switch {
	case modelledForm(culprit):
		construct = c.written(culprit)
		what = "constrains " + string(claim) + " inside " + construct + ", a condition written as " + position(clause) + "; this parser models such a condition only as a clause of its own"
	case culprit.kind == exprCall:
		what = "constrains " + string(claim) + " with the function " + strconv.Quote(culprit.text) + ", which this parser does not model"
	case culprit.kind == exprBinary, culprit.kind == exprUnary, culprit.kind == exprTernary:
		what = "constrains " + string(claim) + " with the operator " + strconv.Quote(construct) + ", which this parser does not model"
	case culprit.kind == exprSelect, culprit.kind == exprIndex:
		what = "constrains a field inside " + string(claim) + ", which this parser models as one value"
	default:
		what = "constrains " + string(claim) + " inside " + construct + ", which this parser does not model"
	}
	return c.unknownOn(claim, "operator "+construct, construct, c.quoted(clause)+" "+what+", so "+string(claim)+" is read as unconstrained")
}

// modelledForm reports whether a node is one of the forms the subset
// evaluates when it stands as a clause: a comparison by == or in, a
// conjunction, a disjunction, or a receiver call to startsWith, endsWith
// or contains. A negation is not one: the parser reads what a condition
// admits, never what it excludes, so ! is a construct it does not model
// wherever it stands.
func modelledForm(n *expr) bool {
	switch n.kind {
	case exprBinary:
		return slices.Contains([]string{"==", "in", "&&", "||"}, n.text)
	case exprCall:
		return n.kids[0] != nil && slices.Contains([]string{"startsWith", "endsWith", "contains"}, n.text)
	}
	return false
}

// position says where in a clause an operand stands, for the sentence
// about a condition written there.
func position(clause *expr) string {
	if clause.kind == exprCall {
		return "the receiver of " + strconv.Quote(clause.text)
	}
	return "an operand of " + strconv.Quote(clause.text)
}

// describe names a construct for an anomaly: an operator or a function by
// its name, anything else as written.
func describe(n *expr, src string) string {
	switch n.kind {
	case exprBinary, exprUnary, exprCall:
		return n.text
	case exprTernary:
		return "?"
	}
	return printable(src[n.start:n.end])
}

// noClaim says what a clause that names no claim does.
func noClaim(n *expr, src string) string {
	switch n.kind {
	case exprBinary:
		return "uses " + strconv.Quote(n.text) + " between operands that name no claim"
	case exprUnary:
		return "applies " + strconv.Quote(n.text) + " to an operand that names no claim"
	case exprCall:
		return "calls " + strconv.Quote(n.text) + " on operands that name no claim"
	}
	return "names no claim"
}

// failed widens for a reference that resolves to no claim, on the whole
// grant: the clause may constrain a claim this parser cannot name, so no
// claim can carry the doubt. When the mapping is the reason, the sentence
// names the reference, which is what the mapping maps; when the
// provider's kind is, it names the whole field path written on the
// reference, which is what the clause constrains, and that text is the
// construct.
func (c *condition) failed(clause *expr, ref reference, whole *expr, f *failure) eval.AdmittedSet {
	switch f.about {
	case theKeyword:
		return c.unattributable(f.construct, c.quoted(clause)+" "+f.why+", so nothing it says about the credential is modelled")
	case theProvider:
		return c.unattributable(c.written(whole), c.quoted(clause)+" constrains "+c.written(whole)+", but "+f.why+", so nothing it says about the credential is modelled")
	case theUnreadMapping:
		return c.unattributable(f.construct, c.quoted(clause)+" constrains "+c.written(ref.node)+", but "+f.why+", so which claim the clause constrains is not stated and nothing it says about the credential is modelled")
	}
	return c.unattributable(f.construct, c.quoted(clause)+" constrains "+c.written(ref.node)+", which "+f.why+", so which claim the clause constrains is not stated and nothing it says about the credential is modelled")
}

// onClaim is the set that constrains one claim and nothing else.
func onClaim(claim trust.ClaimKey, set eval.StringSet) eval.AdmittedSet {
	return eval.NewAdmittedSet(eval.Term{claim: set})
}

// unknownOn records a doubt on one claim and returns its top.
func (c *condition) unknownOn(claim trust.ClaimKey, reason, construct, message string) eval.AdmittedSet {
	c.r.doubt(trust.Anomaly{Kind: trust.Unmodelled, Claim: claim, Construct: construct, Message: message, Source: c.source})
	return onClaim(claim, eval.Unknown(reason))
}

// unattributable records a doubt on the whole grant and returns everything.
func (c *condition) unattributable(construct, message string) eval.AdmittedSet {
	c.r.doubt(trust.Anomaly{Kind: trust.Unmodelled, Construct: construct, Message: message, Source: c.source})
	return eval.Everything()
}

// quoted renders a node's source text for a sentence, in quotes.
func (c *condition) quoted(n *expr) string { return quote(c.src[n.start:n.end]) }

// written renders a node's source text for a sentence, bare: an
// expression fragment, not a string.
func (c *condition) written(n *expr) string { return printable(c.src[n.start:n.end]) }

// quoteLimit bounds how much of the document a sentence repeats: a
// condition can be 4096 characters, and a sentence that grows with the
// input is not a sentence.
const quoteLimit = 200

// quote renders document text for a sentence a customer will read: ASCII
// only, so that a control character or a terminal escape written into a
// document cannot rewrite the line that reports it, and cut at a
// character boundary past quoteLimit bytes.
func quote(s string) string {
	s, cut := clip(s)
	quoted := strconv.QuoteToASCII(s)
	if cut {
		quoted += "..."
	}
	return quoted
}

// printable is quote without the quotes, for text that is an expression
// or a name rather than a string value.
func printable(s string) string {
	s, cut := clip(s)
	quoted := strconv.QuoteToASCII(s)
	escaped := quoted[1 : len(quoted)-1]
	if cut {
		escaped += "..."
	}
	return escaped
}

// clip cuts s at a character boundary past quoteLimit bytes and reports
// whether it did, so that a cut never yields a broken character.
func clip(s string) (string, bool) {
	if len(s) <= quoteLimit {
		return s, false
	}
	cut := quoteLimit
	for !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut], true
}
