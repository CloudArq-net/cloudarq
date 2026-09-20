package answer

import (
	"strconv"
	"unicode/utf8"
)

// The answer is written by hand rather than by encoding/json. Reflection
// took 1.5 ms of the WebAssembly engine's 6.5 on the 50-statement policy
// (node, 2026-09-13), a fifth of the budget the page has for a keystroke,
// and the shape is a contract frozen at Version. The struct tags remain the
// shape's one statement: TestRenderMatchesEncodingJSON holds every answer
// the corpus and the generated shapes produce to the bytes json.Marshal
// writes from them, so the two cannot drift apart unseen.

// encoder appends JSON to b; n counts the members written so far in the
// object being written, so that a member omitted for being empty leaves no
// comma behind.
type encoder struct {
	b []byte
	n int
}

func (e *encoder) begin() int {
	saved := e.n
	e.n = 0
	e.b = append(e.b, '{')
	return saved
}

func (e *encoder) end(saved int) {
	e.b = append(e.b, '}')
	e.n = saved
}

func (e *encoder) key(name string) {
	if e.n > 0 {
		e.b = append(e.b, ',')
	}
	e.n++
	e.b = append(e.b, '"')
	e.b = append(e.b, name...)
	e.b = append(e.b, '"', ':')
}

func (e *encoder) str(name, v string) {
	e.key(name)
	e.quote(v)
}

func (e *encoder) strOmit(name, v string) {
	if v != "" {
		e.str(name, v)
	}
}

func (e *encoder) num(name string, v int) {
	e.key(name)
	e.b = strconv.AppendInt(e.b, int64(v), 10)
}

func (e *encoder) numOmit(name string, v int) {
	if v != 0 {
		e.num(name, v)
	}
}

func (e *encoder) boolean(name string, v bool) {
	e.key(name)
	e.b = strconv.AppendBool(e.b, v)
}

// comma separates list items: the caller has written '[' and counts.
func (e *encoder) comma(i int) {
	if i > 0 {
		e.b = append(e.b, ',')
	}
}

func (e *encoder) null() {
	e.b = append(e.b, "null"...)
}

const hexDigits = "0123456789abcdef"

// quote writes a string as this toolchain's encoding/json does with HTML
// escaping on: the short escapes for the five control characters that have
// them, \u00XX for the rest and for <, > and &, U+FFFD itself for a byte
// that is not UTF-8, and \u2028 and \u2029 spelt out.
func (e *encoder) quote(s string) {
	e.b = append(e.b, '"')
	start := 0
	for i := 0; i < len(s); {
		b := s[i]
		if b < utf8.RuneSelf {
			if b >= 0x20 && b != '"' && b != '\\' && b != '<' && b != '>' && b != '&' {
				i++
				continue
			}
			e.b = append(e.b, s[start:i]...)
			switch b {
			case '\\', '"':
				e.b = append(e.b, '\\', b)
			case '\b':
				e.b = append(e.b, '\\', 'b')
			case '\f':
				e.b = append(e.b, '\\', 'f')
			case '\n':
				e.b = append(e.b, '\\', 'n')
			case '\r':
				e.b = append(e.b, '\\', 'r')
			case '\t':
				e.b = append(e.b, '\\', 't')
			default:
				e.b = append(e.b, '\\', 'u', '0', '0', hexDigits[b>>4], hexDigits[b&0xF])
			}
			i++
			start = i
			continue
		}
		c, size := utf8.DecodeRuneInString(s[i:])
		if c == utf8.RuneError && size == 1 {
			// An invalid byte becomes the six ASCII characters of the escape,
			// never the replacement character itself: json v1 (Go 1.24, the
			// toolchain CI pins, and TinyGo) writes the escape, json v2, which
			// backs encoding/json from Go 1.27, writes the character, and the
			// answer must be the same bytes whichever built it.
			e.b = append(e.b, s[start:i]...)
			e.b = append(e.b, `\ufffd`...)
			i += size
			start = i
			continue
		}
		if c == '\u2028' || c == '\u2029' {
			e.b = append(e.b, s[start:i]...)
			e.b = append(e.b, '\\', 'u', '2', '0', '2', hexDigits[c&0xF])
			i += size
			start = i
			continue
		}
		i += size
	}
	e.b = append(e.b, s[start:]...)
	e.b = append(e.b, '"')
}

// ---- the answer of admits ----

func (e *encoder) answer(a Answer) {
	saved := e.begin()
	e.num("v", a.V)
	e.strOmit("error", a.Error)
	if a.Document != nil {
		e.key("document")
		e.document(a.Document)
	}
	e.key("grants")
	if a.Grants == nil {
		e.null()
	} else {
		e.b = append(e.b, '[')
		for i := range a.Grants {
			e.comma(i)
			e.grant(&a.Grants[i])
		}
		e.b = append(e.b, ']')
	}
	e.end(saved)
}

func (e *encoder) document(d *Document) {
	saved := e.begin()
	e.num("bytes", d.Bytes)
	e.num("lines", d.Lines)
	e.str("sha256", d.SHA256)
	e.str("version", d.Version)
	e.key("statements")
	if d.Statements == nil {
		e.null()
	} else {
		e.b = append(e.b, '[')
		for i := range d.Statements {
			e.comma(i)
			e.statement(&d.Statements[i])
		}
		e.b = append(e.b, ']')
	}
	e.notes("anomalies", d.Anomalies)
	e.end(saved)
}

func (e *encoder) statement(s *Statement) {
	saved := e.begin()
	e.num("index", s.Index)
	e.str("sid", s.Sid)
	e.num("offset", s.Offset)
	e.num("length", s.Length)
	e.num("firstLine", s.FirstLine)
	e.num("lastLine", s.LastLine)
	e.str("sha256", s.SHA256)
	e.end(saved)
}

func (e *encoder) grant(g *Grant) {
	saved := e.begin()
	e.num("number", g.Number)
	e.num("statement", g.Statement)
	e.str("sid", g.Sid)
	e.str("issuer", g.Issuer)
	if g.IssuerWritten != nil {
		e.key("issuerWritten")
		e.written(g.IssuerWritten)
	}
	e.str("effect", g.Effect)
	e.boolean("exact", g.Exact)
	e.boolean("beyond", g.Beyond)
	e.boolean("empty", g.Empty)
	e.boolean("top", g.Top)
	e.str("admits", g.Admits)
	e.key("terms")
	if g.Terms == nil {
		e.null()
	} else {
		e.b = append(e.b, '[')
		for i, term := range g.Terms {
			e.comma(i)
			e.claims(term)
		}
		e.b = append(e.b, ']')
	}
	e.notes("notes", g.Notes)
	e.str("sentence", g.Sentence)
	e.spans("spans", g.Spans)
	e.str("caption", g.Caption)
	e.strOmit("witness", g.Witness)
	e.strOmit("witnessHeading", g.WitnessHeading)
	e.strOmit("witnessCaption", g.WitnessCaption)
	e.end(saved)
}

func (e *encoder) claims(rows []Claim) {
	if rows == nil {
		e.null()
		return
	}
	e.b = append(e.b, '[')
	for i := range rows {
		e.comma(i)
		e.claim(&rows[i])
	}
	e.b = append(e.b, ']')
}

func (e *encoder) claim(c *Claim) {
	saved := e.begin()
	e.str("claim", c.Claim)
	e.key("constraint")
	e.constraint(&c.Constraint)
	e.str("rendered", c.Rendered)
	e.str("words", c.Words)
	e.strOmit("mark", c.Mark)
	e.numOmit("note", c.Note)
	e.writtens("written", c.Written)
	e.end(saved)
}

func (e *encoder) constraint(c *Constraint) {
	saved := e.begin()
	e.str("kind", c.Kind)
	e.strOmit("value", c.Value)
	e.strOmit("reason", c.Reason)
	if len(c.Members) > 0 {
		e.key("members")
		e.b = append(e.b, '[')
		for i := range c.Members {
			e.comma(i)
			e.constraint(&c.Members[i])
		}
		e.b = append(e.b, ']')
	}
	e.end(saved)
}

func (e *encoder) written(w *Written) {
	saved := e.begin()
	e.num("line", w.Line)
	e.strOmit("operator", w.Operator)
	e.strOmit("member", w.Member)
	e.end(saved)
}

func (e *encoder) writtens(name string, ws []Written) {
	e.key(name)
	if ws == nil {
		e.null()
		return
	}
	e.b = append(e.b, '[')
	for i := range ws {
		e.comma(i)
		e.written(&ws[i])
	}
	e.b = append(e.b, ']')
}

func (e *encoder) notes(name string, notes []Note) {
	e.key(name)
	if notes == nil {
		e.null()
		return
	}
	e.b = append(e.b, '[')
	for i := range notes {
		e.comma(i)
		n := &notes[i]
		saved := e.begin()
		e.num("number", n.Number)
		e.str("kind", n.Kind)
		e.strOmit("anomaly", n.Anomaly)
		e.strOmit("claim", n.Claim)
		e.strOmit("construct", n.Construct)
		e.str("message", n.Message)
		e.str("source", n.Source)
		e.end(saved)
	}
	e.b = append(e.b, ']')
}

func (e *encoder) spans(name string, spans []Span) {
	e.key(name)
	if spans == nil {
		e.null()
		return
	}
	e.b = append(e.b, '[')
	for i := range spans {
		e.comma(i)
		s := &spans[i]
		saved := e.begin()
		e.str("text", s.Text)
		e.strOmit("mark", s.Mark)
		e.numOmit("note", s.Note)
		e.end(saved)
	}
	e.b = append(e.b, ']')
}

// ---- the answer of explain ----

func (e *encoder) explanation(x Explanation) {
	saved := e.begin()
	e.num("v", x.V)
	e.strOmit("error", x.Error)
	e.key("token")
	{
		saved := e.begin()
		e.strOmit("error", x.Token.Error)
		e.boolean("decoded", x.Token.Decoded)
		e.num("claims", x.Token.Claims)
		e.end(saved)
	}
	e.spans("heading", x.Heading)
	e.str("sentence", x.Sentence)
	e.spans("spans", x.Spans)
	e.key("grants")
	if x.Grants == nil {
		e.null()
	} else {
		e.b = append(e.b, '[')
		for i := range x.Grants {
			e.comma(i)
			e.outcome(&x.Grants[i])
		}
		e.b = append(e.b, ']')
	}
	e.end(saved)
}

func (e *encoder) outcome(o *Outcome) {
	saved := e.begin()
	e.num("number", o.Number)
	e.num("statement", o.Statement)
	e.str("sid", o.Sid)
	e.str("issuer", o.Issuer)
	e.str("effect", o.Effect)
	e.boolean("exact", o.Exact)
	e.boolean("admitted", o.Admitted)
	e.boolean("witness", o.Witness)
	e.spans("heading", o.Heading)
	e.str("sentence", o.Sentence)
	e.spans("spans", o.Spans)
	e.key("excludes")
	if o.Excludes == nil {
		e.null()
	} else {
		saved := e.begin()
		e.str("claim", o.Excludes.Claim)
		e.str("constraint", o.Excludes.Constraint)
		e.end(saved)
	}
	e.key("named")
	if o.Named == nil {
		e.null()
	} else {
		e.b = append(e.b, '[')
		for i, name := range o.Named {
			e.comma(i)
			e.quote(name)
		}
		e.b = append(e.b, ']')
	}
	e.key("claims")
	if o.Claims == nil {
		e.null()
	} else {
		e.b = append(e.b, '[')
		for i := range o.Claims {
			e.comma(i)
			e.claimOutcome(&o.Claims[i])
		}
		e.b = append(e.b, ']')
	}
	e.end(saved)
}

func (e *encoder) claimOutcome(c *ClaimOutcome) {
	saved := e.begin()
	e.str("claim", c.Claim)
	e.str("value", c.Value)
	e.key("constraint")
	e.constraint(&c.Constraint)
	e.str("rendered", c.Rendered)
	e.strOmit("mark", c.Mark)
	e.str("result", c.Result)
	e.strOmit("why", c.Why)
	e.numOmit("note", c.Note)
	e.writtens("written", c.Written)
	e.end(saved)
}
