package report

import (
	"strconv"
	"strings"
	"unicode/utf8"
)

// The answer as a terminal shows it. The words are the ones the page
// prints, taken from the answer verbatim; what this file composes is the
// column headings, the numbering, the labels, the evidence line, where the
// blank lines fall, the row every term ends with, and the three sentences
// about which dialect was applied to the bytes. Those are the whole of it,
// and ownWords in text_test.go is the same list asserted against every
// rendering: anything else composed here would be a second copy of the
// rules in words.go, and the two would drift apart the first time either
// was edited.

// Options carries what the terminal knows and the report must not read for
// itself. The command decides colour from the terminal and the
// environment; the rendering is then a function of the answer and this,
// which is why it can be asserted both ways and is identical in every
// process.
type Options struct {
	// Colour paints the three marks the explorer paints, and nothing else:
	// a value known exactly, an identity admitted beyond any boundary the
	// document names, and a constraint that was not evaluated.
	Colour bool
}

// AnswerOf reads a trust policy and answers what it admits, as the values
// Admits writes as JSON. The command renders these, so that a grant reads
// the same in a terminal as on the page.
func AnswerOf(policy []byte) Answer { return admits(policy) }

// ExplanationOf reads a trust policy and a token and answers, grant by
// grant, whether the token is admitted and why, as the values Explain
// writes as JSON.
func ExplanationOf(policy, token []byte) Explanation { return explain(policy, token) }

// JSON is the answer as the explorer receives it, written by the same
// encoder Admits writes with: the command renders one answer two ways, and
// the two must be the same answer. That they are the same bytes as Admits
// is asserted over the whole corpus by the command's own tests.
func (a Answer) JSON() []byte {
	e := &encoder{}
	e.answer(a)
	return e.b
}

// JSON is the explanation as the explorer receives it, written by the same
// encoder Explain writes with.
func (x Explanation) JSON() []byte {
	e := &encoder{}
	e.explanation(x)
	return e.b
}

// Text is the answer as a terminal shows it: the document, then one block
// per grant — the sentence, the terms as a table, the notes, a token the
// grant admits, and where the statement is written.
func (a Answer) Text(o Options) string {
	t := &text{colour: o.Colour}
	if a.Error != "" {
		t.unreadDocument(a.Error, a.beyondABound)
		return t.String()
	}
	t.document(a.Document)
	for i := range a.Grants {
		t.grant(&a.Grants[i], a.Document, len(a.Grants))
	}
	return t.String()
}

// Text is the explanation as a terminal shows it: the token as read, the
// policy's answer for it, then one block per grant.
func (x Explanation) Text(o Options) string {
	t := &text{colour: o.Colour}
	if x.Error != "" {
		t.unreadDocument(x.Error, x.beyondABound)
		return t.String()
	}
	if x.Token.Error != "" {
		t.refusal(x.Token.Error)
		return t.String()
	}
	t.token(x)
	for i := range x.Grants {
		// With one grant the policy's answer is that grant's own, and the
		// engine composes it once for exactly that reason; printing it
		// again under the grant would be the rendering adding words.
		t.outcome(&x.Grants[i], len(x.Grants), len(x.Grants) > 1)
	}
	return t.String()
}

// text accumulates the rendering. Every string it takes from the answer
// passes through withoutControls on its way in: a Sid, a claim name and a
// claim's value are all customer configuration, and docs/ENGINEERING.md
// section 9 has the reason — an escape inside one rewrites the line it is
// printed on, and can make a grant that admits everyone look like one that
// admits nobody.
type text struct {
	b      strings.Builder
	colour bool
}

func (t *text) String() string {
	s := strings.TrimRight(t.b.String(), "\n")
	if s == "" {
		return ""
	}
	return s + "\n"
}

// line writes one line of the rendering. The parts are joined as written;
// the caller has already decided the separators.
func (t *text) line(parts ...string) {
	for _, p := range parts {
		t.b.WriteString(p)
	}
	t.b.WriteByte('\n')
}

// block ends a block. Blocks are separated by one blank line, and the
// trailing ones are trimmed when the rendering is taken.
func (t *text) block() { t.b.WriteByte('\n') }

// refusal is the engine's own sentence about the input it could not read,
// and is the whole of what a reader is told about a token: that sentence
// already names the three shapes a token may arrive in.
func (t *text) refusal(why string) { t.line(withoutControls(why)) }

// The three things the rendering says about the dialect, which are the
// only facts here that are about this command rather than about the
// document. The engine's sentences are about the bytes it was given; which
// dialects have a reader at all is not something it says, and a reader
// holding an Azure credential is owed it. The first line says how the
// bytes were read rather than what they are: "aws trust policy" stated
// flat is the rendering asserting something no reading established.
const (
	readAsAWS       = "read as an aws trust policy"
	readAsAWSAnyway = "This command reads no other dialect yet, so each member the IAM policy grammar does not define was read as a statement."
	notReadAsAWS    = "The document was not read as an AWS trust policy, and this command reads no other dialect yet."
)

// unreadDocument adds the one thing the engine's sentence deliberately
// does not say. That sentence is about the bytes; it is not about which
// dialects have a reader, so a valid Azure credential would otherwise be
// refused without the reason a reader needs.
//
// A document refused for its size or its depth gets the engine's sentence
// alone. No reader saw a byte of it, so nothing about its dialect was
// established either way, and sending its reader to check the dialect
// sends them to check something this run never looked at: the bound was
// the whole reason.
func (t *text) unreadDocument(why string, beyondABound bool) {
	t.refusal(why)
	if !beyondABound {
		t.line(notReadAsAWS)
	}
}

func (t *text) document(d *Document) {
	if d == nil {
		return
	}
	shape := []string{readAsAWS}
	if d.Version != "" {
		shape = append(shape, "version "+withoutControls(d.Version))
	}
	shape = append(shape,
		counted(d.Bytes, "byte"),
		counted(d.Lines, "line"),
		counted(len(d.Statements), "statement"),
	)
	t.line(strings.Join(shape, " · "))
	t.line("sha256 ", d.SHA256)
	// How a document written in another dialect arrives here: every member
	// the IAM grammar does not define is read as a statement that could not
	// be read, which is why an Azure credential yields grants at all. The
	// fact is the document's own, read from the members it writes, because
	// the parser gives "the document has no Statement member" and
	// "Statement is an empty list" the same kind, construct and source, and
	// a rendering that matched those three fields would print this under a
	// document that has a Statement member and no statement outside it.
	if d.membersOutsideTheGrammar {
		t.line(readAsAWSAnyway)
	}
	t.block()
	t.notes("document notes", d.Anomalies)
}

func (t *text) grant(g *Grant, d *Document, total int) {
	head := []string{"grant " + strconv.Itoa(g.Number) + " of " + strconv.Itoa(total), statementName(g.Sid, g.Statement)}
	if g.Effect != "" {
		head = append(head, withoutControls(g.Effect))
	}
	if g.Issuer != "" {
		head = append(head, withoutControls(g.Issuer))
	}
	t.line(strings.Join(head, " · "))
	t.line(t.paint(g.Spans))
	if g.Caption != "" {
		t.line(withoutControls(g.Caption))
	}
	t.block()
	for i, term := range g.Terms {
		// "term", as the page labels the same table: an admitted set is a
		// union of terms, and a reader moving between the two surfaces
		// should not have to learn a second word for it
		if len(g.Terms) > 1 {
			t.line("term ", strconv.Itoa(i+1), " of ", strconv.Itoa(len(g.Terms)))
		}
		t.terms(term)
		t.block()
	}
	t.notes("notes", g.Notes)
	t.witness(g)
	t.line(evidence(g, d))
	t.block()
}

// statementName is the statement a grant came from, as the head names it
// and the evidence line repeats it.
func statementName(sid string, index int) string {
	at := "statement[" + strconv.Itoa(index) + "]"
	if sid == "" {
		return at
	}
	return at + " " + strconv.Quote(withoutControls(sid))
}

// terms is one alternative of the admitted set: one row per claim it
// names, in the claim order the answer carries.
func (t *text) terms(rows []Claim) {
	table := [][]cell{{{text: "CLAIM"}, {text: "ADMITS"}, {text: "IN WORDS · AS WRITTEN"}}}
	for _, row := range rows {
		words := []string{row.Words}
		if row.Note != 0 {
			words = append(words, "note "+strconv.Itoa(row.Note))
		}
		if w := written(row.Written); w != "" {
			words = append(words, w)
		}
		table = append(table, []cell{
			{text: row.Claim},
			{text: row.Rendered, mark: row.Mark},
			// the page colours this column only where the claim was not
			// evaluated, which is the one case where the words are a
			// statement about the engine rather than about the document
			{text: strings.Join(words, " · "), mark: unknownOnly(row.Mark)},
		})
	}
	// The row the page appends to every term, in the page's words. The
	// claims a term names are the ones the document constrains, so a table
	// that stopped at them would read as the list of claims that matter,
	// which is the opposite of what a term says; and a term that names no
	// claim — a statement no condition constrains — is this row alone,
	// which is the whole of what such a term says and was printed as
	// nothing at all.
	table = append(table, []cell{{text: "any other claim"}, {text: "any"}, {text: "unconstrained · no condition names it"}})
	for _, line := range t.columns(table) {
		t.line(line)
	}
}

func unknownOnly(mark string) string {
	if mark == "unknown" {
		return mark
	}
	return ""
}

// written is where the document writes a claim: the line, and the operator
// its key sits under or the Principal member its leaf sits under.
func written(ws []Written) string {
	out := make([]string, 0, len(ws))
	for _, w := range ws {
		at := "line " + strconv.Itoa(w.Line)
		if w.Operator != "" {
			at += " " + withoutControls(w.Operator)
		}
		if w.Member != "" {
			at += " " + withoutControls(w.Member)
		}
		out = append(out, at)
	}
	return strings.Join(out, ", ")
}

// notes is the caveats and anomalies, under the numbers the sentence and
// the table point at. Each is the engine's message, then what kind of note
// it is and where it came from.
func (t *text) notes(heading string, notes []Note) {
	if len(notes) == 0 {
		return
	}
	t.line(heading)
	for _, n := range notes {
		t.line("  ", strconv.Itoa(n.Number), "  ", withoutControls(n.Message))
		provenance := []string{n.Kind}
		for _, part := range []string{n.Anomaly, n.Claim, n.Construct, n.Source} {
			if part != "" {
				provenance = append(provenance, withoutControls(part))
			}
		}
		t.line("     ", strings.Join(provenance, " · "))
	}
	t.block()
}

// witness is a decoded token the grant admits, with the engine's own words
// over and under it: what the token proves is the engine's statement, not
// the renderer's.
func (t *text) witness(g *Grant) {
	if g.Witness == "" {
		return
	}
	t.line(withoutControls(g.WitnessHeading))
	for _, line := range strings.Split(g.Witness, "\n") {
		t.line("  ", withoutControls(line))
	}
	if g.WitnessCaption != "" {
		// the caption names the claims the grant did not evaluate, and a
		// claim's name is the customer's: this is the one sentence of the
		// answer that carries a string out of the document
		t.line(withoutControls(g.WitnessCaption))
	}
	t.block()
}

// evidence is where the grant's statement is written, where the document
// names its issuer, and the digest of the statement's bytes, so that a
// sentence can be taken back to the document it came from and the quotation
// checked against the file.
func evidence(g *Grant, d *Document) string {
	at := []string{statementName(g.Sid, g.Statement)}
	if d != nil && g.Statement < len(d.Statements) {
		s := d.Statements[g.Statement]
		at = append(at,
			"offset "+strconv.Itoa(s.Offset),
			counted(s.Length, "byte"),
			lineSpan(s.FirstLine, s.LastLine),
		)
		if g.IssuerWritten != nil {
			at = append(at, "issuer at "+written([]Written{*g.IssuerWritten}))
		}
		at = append(at, "sha256 "+s.SHA256)
	}
	return strings.Join(at, " · ")
}

func lineSpan(first, last int) string {
	if first == last {
		return "line " + strconv.Itoa(first)
	}
	return "lines " + strconv.Itoa(first) + "-" + strconv.Itoa(last)
}

func (t *text) token(x Explanation) {
	read := "read as a payload"
	if x.Token.Decoded {
		read = "decoded from the payload segment of a whole token"
	}
	t.line("token · ", counted(x.Token.Claims, "claim"), " · ", read)
	t.line(t.paint(x.Heading))
	if len(x.Spans) > 0 {
		t.line(t.paint(x.Spans))
	}
	t.block()
}

// outcome is one grant against the token: the engine's heading and
// sentence, then the claims it read, in the engine's order.
func (t *text) outcome(o *Outcome, total int, saying bool) {
	head := []string{"grant " + strconv.Itoa(o.Number) + " of " + strconv.Itoa(total), statementName(o.Sid, o.Statement)}
	if o.Effect != "" {
		head = append(head, withoutControls(o.Effect))
	}
	if o.Issuer != "" {
		head = append(head, withoutControls(o.Issuer))
	}
	t.line(strings.Join(head, " · "))
	if saying {
		t.line(t.paint(o.Heading))
		if len(o.Spans) > 0 {
			t.line(t.paint(o.Spans))
		}
	}
	t.block()
	if len(o.Claims) > 0 {
		t.claims(o.Claims)
		t.block()
	}
}

func (t *text) claims(rows []ClaimOutcome) {
	table := [][]cell{{{text: "CLAIM"}, {text: "THE TOKEN"}, {text: "THE GRANT ADMITS"}, {text: "RESULT"}}}
	for _, row := range rows {
		result := row.Result
		if row.Note != 0 {
			result += " · note " + strconv.Itoa(row.Note)
		}
		table = append(table, []cell{
			{text: row.Claim},
			{text: row.Value},
			{text: row.Rendered, mark: row.Mark},
			{text: result, mark: unknownOnly(row.Mark)},
		})
	}
	for _, line := range t.columns(table) {
		t.line(line)
	}
}

// counted is "1 statement", "2 statements": the noun with the number the
// answer holds, which is not the explanation's count, whose numbers are
// spelt out because they sit inside a sentence.
func counted(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return strconv.Itoa(n) + " " + noun + "s"
}

// cell is one field of a table and the mark it earns.
type cell struct{ text, mark string }

// columns lays a table out in columns as wide as their widest cell, with
// two spaces between. Nothing is wrapped and nothing is truncated: a value
// cut to fit is a wrong value, and the width a terminal happens to have is
// not an input to this rendering — it would make the output depend on
// where it was run, which is the opposite of what the command promises.
//
// Width is counted in characters rather than bytes, so that a value
// written outside ASCII still lines up, and the padding is measured on the
// text rather than on the painted text, so that colour cannot move a
// column.
func (t *text) columns(rows [][]cell) []string {
	widest := make([]int, 0)
	for _, row := range rows {
		for i, c := range row {
			w := utf8.RuneCountInString(withoutControls(c.text))
			if i >= len(widest) {
				widest = append(widest, w)
			} else if w > widest[i] {
				widest[i] = w
			}
		}
	}
	out := make([]string, 0, len(rows))
	for _, row := range rows {
		var b strings.Builder
		for i, c := range row {
			plain := withoutControls(c.text)
			b.WriteString(t.mark(c.mark, plain))
			if i < len(row)-1 {
				b.WriteString(strings.Repeat(" ", widest[i]-utf8.RuneCountInString(plain)+2))
			}
		}
		out = append(out, strings.TrimRight(b.String(), " "))
	}
	return out
}

// paint is a run of spans as one line, each in the colour its mark earns.
// The spans already spell the sentence: the page renders these and the
// command renders these, so neither can say something the other does not.
func (t *text) paint(spans []Span) string {
	var b strings.Builder
	for _, s := range spans {
		b.WriteString(t.mark(s.Mark, withoutControls(s.Text)))
	}
	return b.String()
}

// The three marks, in the three nearest colours a terminal is sure to
// have: exact is the page's blue, beyond its warm one, unknown its violet.
// "code" earns none — the whole rendering is already monospace — and there
// is no fourth.
const (
	sgrExact   = "\x1b[34m"
	sgrBeyond  = "\x1b[31m"
	sgrUnknown = "\x1b[35m"
	sgrOff     = "\x1b[0m"
)

func (t *text) mark(mark, s string) string {
	if !t.colour || s == "" {
		return s
	}
	switch mark {
	case "exact":
		return sgrExact + s + sgrOff
	case "beyond":
		return sgrBeyond + s + sgrOff
	case "unknown":
		return sgrUnknown + s + sgrOff
	}
	return s
}
