// Package report renders what the explorer shows and what the command
// prints: the grants of a trust policy and, for a token, why each grant
// admits or rejects it, as JSON the page prints verbatim and as text for a
// terminal. It is the one place those words are composed, so that the page
// and the command say the same sentence about the same document, and so
// that the page itself evaluates nothing. It is the rendering layer of
// docs/ENGINEERING.md section 1, and reaches no IO.
//
// Both entry points are total. A policy that cannot be read, or a token
// that cannot, is stated in the answer rather than returned as an error,
// because the page shows the reason in the same pane as any other answer.
package report

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/CloudArq-net/cloudarq/internal/eval"
	"github.com/CloudArq-net/cloudarq/internal/parse/aws"
	"github.com/CloudArq-net/cloudarq/internal/trust"
)

// Version is the "v" of every answer: the JSON shape is a public contract
// between the engine and the page, and a page that meets another version
// must say so rather than render it.
const Version = 1

// MaxDocumentBytes and MaxTokenBytes bound what the engine reads. A paste
// is not a deployable policy: AWS accepts a role trust policy of at most
// 8,192 characters (IAM quotas, read 2026-09-13), and a megabyte of JSON
// read on every keystroke grows the WebAssembly heap without bound, since
// that runtime's collector doubles the heap whenever a collection frees
// under a third of it and linear memory never shrinks. Measured on the
// wasm build: memory settles at 72 MB for a 261 KB document and doubles
// past 576 MB for a 535 KB one. A token's values are repeated per grant in
// the explanation, so its bound is the document's divided by the grants
// the document can carry. Both sit far above anything a role or a
// workflow carries.
const (
	MaxDocumentBytes = 256 << 10
	MaxTokenBytes    = 16 << 10
)

// target is the role the policy is attached to, which a trust policy does
// not name; the explorer has no account to read it from.
var target = trust.TargetRef{Kind: "role"}

// vocabulary is the claim vocabulary the parser reconciles condition keys
// with. The registry will fill this seam; until it names GitHub's claims,
// the one issuer whose claims are known to be lower-case is seeded here,
// exactly as the parser's own conformance tests seed it. This is the only
// issuer named in this package.
var vocabulary = aws.LowercaseVocabulary("https://token.actions.githubusercontent.com")

// Answer is what admits renders: the document as read and one Grant per
// grant of it, in the engine's order.
type Answer struct {
	V        int       `json:"v"`
	Error    string    `json:"error,omitempty"`
	Document *Document `json:"document,omitempty"`
	Grants   []Grant   `json:"grants"`
	// beyondABound records that Error is one of the engine's bounds rather
	// than a reading of the bytes. It is not part of the schema: the page
	// prints the sentence and nothing more, and the terminal rendering is
	// the only surface that adds a second one to it.
	beyondABound bool
}

// Document is the pasted document as the engine read it.
type Document struct {
	Bytes      int         `json:"bytes"`
	Lines      int         `json:"lines"`
	SHA256     string      `json:"sha256"`
	Version    string      `json:"version"`
	Statements []Statement `json:"statements"`
	Anomalies  []Note      `json:"anomalies"`
	// membersOutsideTheGrammar reports that a top-level member the IAM
	// policy grammar does not define was read as a statement. The parser
	// says so of each such member in that statement's own note, which is
	// what the schema carries; this is the document-wide fact the terminal
	// rendering states once, above the grants.
	membersOutsideTheGrammar bool
}

// Statement locates one statement in the document: its bytes, so that the
// page can quote them from the source, and its lines, so that the listing
// can mark them.
type Statement struct {
	Index     int    `json:"index"`
	Sid       string `json:"sid"`
	Offset    int    `json:"offset"`
	Length    int    `json:"length"`
	FirstLine int    `json:"firstLine"`
	LastLine  int    `json:"lastLine"`
	SHA256    string `json:"sha256"`
}

// Grant is one grant as the page shows it.
type Grant struct {
	Number    int    `json:"number"` // 1-based, in the engine's order
	Statement int    `json:"statement"`
	Sid       string `json:"sid"`
	Issuer    string `json:"issuer"`
	// IssuerWritten is where the Principal names the issuer, when a leaf of
	// it does; otherwise the Principal member's own line.
	IssuerWritten *Written `json:"issuerWritten,omitempty"`
	Effect        string   `json:"effect"`
	Exact         bool     `json:"exact"`
	// Beyond reports that the identities admitted are unconstrained: no
	// claim but the audience is named, and an audience is not a boundary.
	Beyond bool `json:"beyond"`
	Empty  bool `json:"empty"`
	Top    bool `json:"top"`
	// Admits is the engine's canonical rendering of the admitted set.
	Admits string `json:"admits"`
	// Terms are the alternatives of the admitted set, each a conjunction of
	// claims in claim order; a Term shows one row per claim it names.
	Terms    [][]Claim `json:"terms"`
	Notes    []Note    `json:"notes"`
	Sentence string    `json:"sentence"`
	Spans    []Span    `json:"spans"`
	Caption  string    `json:"caption"`
	// Witness is the decoded payload of one token the grant admits, or ""
	// when none could be built. WitnessHeading and WitnessCaption are the
	// words the page prints over it, in the grant's effect and saying what
	// the witness proves and what it does not.
	Witness        string `json:"witness,omitempty"`
	WitnessHeading string `json:"witnessHeading,omitempty"`
	WitnessCaption string `json:"witnessCaption,omitempty"`
}

// Claim is one row of a term: the claim, what the engine holds for it, the
// same in words, and where the document writes it.
type Claim struct {
	Claim      string     `json:"claim"`
	Constraint Constraint `json:"constraint"`
	// Rendered is the constraint as eval renders it, the admits column.
	Rendered string `json:"rendered"`
	Words    string `json:"words"`
	// Mark is the colour the row earns: exact, unknown or beyond.
	Mark string `json:"mark,omitempty"`
	// Note numbers the caveat on this claim, when there is one.
	Note    int       `json:"note,omitempty"`
	Written []Written `json:"written"`
}

// Written is a place in the document: a line, and the operator the key
// sits under or the Principal member the leaf sits under.
type Written struct {
	Line     int    `json:"line"`
	Operator string `json:"operator,omitempty"`
	Member   string `json:"member,omitempty"`
}

// Note is one caveat or anomaly, numbered so that the sentence and the
// table can point at it. Every field the engine's types carry is here.
type Note struct {
	Number    int    `json:"number"`
	Kind      string `json:"kind"` // caveat or anomaly
	Anomaly   string `json:"anomaly,omitempty"`
	Claim     string `json:"claim,omitempty"`
	Construct string `json:"construct,omitempty"`
	Message   string `json:"message"`
	Source    string `json:"source"`
}

// Span is a run of a sentence: its text, the colour or the code face it
// takes, and the note it refers to.
type Span struct {
	Text string `json:"text"`
	Mark string `json:"mark,omitempty"` // exact, beyond, unknown, or code
	Note int    `json:"note,omitempty"`
}

// Admits reads a trust policy and renders the answer the explorer shows.
func Admits(policy []byte) []byte {
	e := &encoder{}
	e.answer(admits(policy))
	return e.b
}

func admits(policy []byte) Answer {
	a := Answer{V: Version, Grants: []Grant{}}
	r, err := readPolicy(policy)
	if err != nil {
		a.Error, a.beyondABound = err.Error(), beyondABound(err)
		return a
	}
	a.Document = r.document()
	for i := range r.grants {
		grant, err := r.grant(i)
		if err != nil {
			return Answer{V: Version, Error: fmt.Sprintf("grant %d: %v", i+1, err), Grants: []Grant{}}
		}
		a.Grants = append(a.Grants, grant)
	}
	return a
}

// reading is one policy read in full: the document, where its parts are
// written, and its grants with the statement each came from.
type reading struct {
	raw        []byte
	doc        aws.Document
	lay        layout
	grants     []trust.Grant
	statements []int // the statement index of each grant
}

func readPolicy(policy []byte) (reading, error) {
	if len(policy) > MaxDocumentBytes {
		return reading{}, bounded{fmt.Errorf("the document is %d bytes; the engine reads up to %d, and AWS accepts a role trust policy of at most 8192 characters", len(policy), MaxDocumentBytes)}
	}
	if err := nesting(policy, MaxDocumentNesting, "document"); err != nil {
		return reading{}, bounded{err}
	}
	d, err := aws.ParseTrustPolicy(policy)
	if err != nil {
		return reading{}, err
	}
	lay, err := layoutOf(policy, d)
	if err != nil {
		return reading{}, err
	}
	r := reading{raw: policy, doc: d, lay: lay, grants: d.Grants(target, vocabulary)}
	for i, g := range r.grants {
		s, ok := statementOf(g, d)
		if !ok {
			return reading{}, fmt.Errorf("grant %d: its source is not one of the document's statements", i+1)
		}
		r.statements = append(r.statements, s)
	}
	return r, nil
}

// bounded marks a refusal about how much there is rather than about what
// the bytes are: a document longer or deeper than the engine reads is
// turned away before any reader sees one of them. The two classes read
// alike in the answer — both are a sentence in Error — and the terminal
// rendering has to tell them apart, because the sentence it adds to a
// refusal says which dialects have a reader at all, and that is a question
// a bound refusal never reached.
type bounded struct{ error }

// beyondABound reports whether a refusal is one of the engine's bounds.
func beyondABound(err error) bool {
	var b bounded
	return errors.As(err, &b)
}

// statementOf finds the statement a grant came from. The engine sorts its
// grants by what they mean and keeps no index, but a grant's Source is the
// statement's own slice of the parser's copy of the input, so the two are
// matched by identity: same bytes at the same address, which tells two
// statements written identically apart where their bytes could not.
func statementOf(g trust.Grant, d aws.Document) (int, bool) {
	for i, s := range d.Statements {
		if len(g.Source) > 0 && len(g.Source) == len(s.Raw) && &g.Source[0] == &s.Raw[0] {
			return i, true
		}
	}
	return 0, false
}

func (r reading) document() *Document {
	doc := &Document{
		Bytes:                    len(r.raw),
		Lines:                    lines(r.raw),
		SHA256:                   digest(r.raw),
		Version:                  r.doc.Version,
		Statements:               []Statement{},
		Anomalies:                []Note{},
		membersOutsideTheGrammar: r.lay.membersOutsideTheGrammar,
	}
	for i, s := range r.doc.Statements {
		at := r.lay.statements[i]
		doc.Statements = append(doc.Statements, Statement{
			Index:     i,
			Sid:       s.Sid,
			Offset:    at.start,
			Length:    at.end - at.start,
			FirstLine: r.lay.line(at.start),
			LastLine:  r.lay.line(at.end - 1),
			SHA256:    digest(s.Raw),
		})
	}
	for _, a := range r.doc.Anomalies {
		doc.Anomalies = append(doc.Anomalies, anomalyNote(len(doc.Anomalies)+1, a))
	}
	return doc
}

func digest(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func (r reading) grant(i int) (Grant, error) {
	g := r.grants[i]
	s := r.statements[i]
	at := r.lay.statements[s]
	out := Grant{
		Number:    i + 1,
		Statement: s,
		Sid:       r.doc.Statements[s].Sid,
		Issuer:    string(g.Issuer),
		Effect:    string(g.Effect),
		Exact:     g.Exact(),
		Empty:     g.Admits.IsEmpty(),
		Top:       g.Admits.IsTop(),
		Admits:    g.Admits.String(),
		Terms:     [][]Claim{},
		Notes:     notesOf(g),
	}
	out.Beyond = g.Effect == trust.Allow && out.Exact && !out.Empty && g.WithoutAudience().IsTop()
	if at.principalLine != 0 {
		w := at.issuerWritten(g.Issuer)
		out.IssuerWritten = &w
	}
	for _, term := range g.Admits.Terms() {
		rows, err := rowsOf(term, at, out.Notes, g.Issuer)
		if err != nil {
			return Grant{}, err
		}
		if out.Beyond && !slices.ContainsFunc(rows, func(c Claim) bool { return c.Claim == "sub" }) {
			rows = append(rows, unconstrainedSubject())
		}
		out.Terms = append(out.Terms, rows)
	}
	out.Spans = stripped(sentenceOf(g, out))
	out.Sentence = plain(out.Spans)
	out.Caption = captionOf(g, out)
	if out.Witness = witnessOf(g, out.Terms); out.Witness != "" {
		out.WitnessHeading = witnessHeading(g.Effect)
		out.WitnessCaption = witnessCaption(g, out)
	}
	return out, nil
}

// rowsOf renders a term in claim order. A claim no condition key writes
// came from the Principal element, the only other place a constraint is
// read from.
func rowsOf(term eval.Term, at statementLayout, notes []Note, issuer trust.IssuerRef) ([]Claim, error) {
	rows := []Claim{}
	for _, k := range slices.Sorted(maps.Keys(term)) {
		c, err := constraintOf(term[k])
		if err != nil {
			return nil, err
		}
		row := Claim{
			Claim:      string(k),
			Constraint: c,
			Rendered:   term[k].String(),
			Words:      c.words(string(k)),
			Mark:       markOf(c),
			Written:    at.keysFor(string(k), issuer),
		}
		if c.Kind == kindUnknown {
			row.Note = noteOn(notes, string(k))
		}
		if len(row.Written) == 0 {
			row.Words += " · from Principal"
		}
		rows = append(rows, row)
	}
	return rows, nil
}

// unconstrainedSubject is the row the page shows when no claim but the
// audience is named: the subject, the one claim every token carries, is
// admitted whatever it says.
func unconstrainedSubject() Claim {
	return Claim{
		Claim:      "sub",
		Constraint: Constraint{Kind: kindAny},
		Rendered:   "any",
		Words:      "any subject · no condition names it",
		Mark:       "beyond",
		Written:    []Written{},
	}
}

func markOf(c Constraint) string {
	switch c.Kind {
	case kindUnknown:
		return "unknown"
	case kindAny:
		return ""
	}
	return "exact"
}

// notesOf numbers the caveats, in the engine's canonical order, then the
// anomalies in the engine's order.
func notesOf(g trust.Grant) []Note {
	notes := []Note{}
	for _, c := range g.Admits.Caveats() {
		notes = append(notes, Note{Number: len(notes) + 1, Kind: "caveat", Claim: string(c.Claim), Message: c.Reason, Source: c.Source})
	}
	for _, a := range g.Anomalies {
		notes = append(notes, anomalyNote(len(notes)+1, a))
	}
	return notes
}

func anomalyNote(number int, a trust.Anomaly) Note {
	return Note{Number: number, Kind: "anomaly", Anomaly: a.Kind, Claim: string(a.Claim), Construct: a.Construct, Message: a.Message, Source: a.Source}
}

// noteOn is the number of the first caveat on a claim, or 0.
func noteOn(notes []Note, claim string) int {
	for _, n := range notes {
		if n.Kind == "caveat" && n.Claim == claim {
			return n.Number
		}
	}
	return 0
}

// keysFor lists where the statement writes a condition key for the claim.
// A key names the principal's own claim when the part before a colon is
// the issuer's host and path and the part after it is the claim, which is
// the parser's rule for reading keys; any other key names its claim by its
// whole lower-cased text.
func (s statementLayout) keysFor(claim string, issuer trust.IssuerRef) []Written {
	ident := strings.ToLower(strings.TrimPrefix(string(issuer), "https://"))
	out := []Written{}
	for _, k := range s.keys {
		if fold(k.key) == claim || ownClaim(k.key, ident) == claim {
			out = append(out, Written{Line: k.line, Operator: k.operator})
		}
	}
	return out
}

func ownClaim(key, ident string) string {
	for i := 0; i < len(key); i++ {
		if key[i] == ':' && strings.EqualFold(key[:i], ident) {
			return fold(key[i+1:])
		}
	}
	return ""
}

// fold lower-cases ASCII letters only, as the parser folds a claim name.
func fold(s string) string {
	return strings.Map(func(r rune) rune {
		if 'A' <= r && r <= 'Z' {
			return r + 'a' - 'A'
		}
		return r
	}, s)
}

// issuerWritten is the leaf under Principal that names the issuer, found
// by its host and path, or the Principal member itself when no leaf does,
// as for an AWS principal whose pseudo-issuer no leaf spells.
func (s statementLayout) issuerWritten(issuer trust.IssuerRef) Written {
	ident := strings.ToLower(strings.TrimPrefix(string(issuer), "https://"))
	for _, l := range s.leaves {
		if ident != "" && strings.Contains(strings.ToLower(l.text), ident) {
			member := "Principal"
			if l.member != "" {
				member += "." + l.member
			}
			return Written{Line: l.line, Member: member}
		}
	}
	return Written{Line: s.principalLine, Member: "Principal"}
}

// witnessOf builds the decoded payload of a token the grant admits: the
// simplest instance of the first term that yields one and that the engine
// confirms with Admits. A witness the engine rejected is never returned,
// and a set widened to everything has none to offer: nothing about it was
// evaluated, so no token is witnessed by it.
func witnessOf(g trust.Grant, terms [][]Claim) string {
	if g.Admits.IsTop() && !g.Exact() {
		return ""
	}
	for _, rows := range terms {
		tok := map[trust.ClaimKey]string{}
		complete := true
		for _, row := range rows {
			switch row.Constraint.Kind {
			case kindAny, kindUnknown:
				continue
			}
			v, ok := row.Constraint.witness()
			if !ok {
				complete = false
				break
			}
			tok[trust.ClaimKey(row.Claim)] = v
		}
		if complete && g.Admits.Admits(tok) {
			return payload(g.Issuer, tok)
		}
	}
	return ""
}

// payload renders a token's claims as a decoded payload: iss first when
// the issuer is a URL, then aud and sub, then the rest in claim order.
func payload(issuer trust.IssuerRef, claims map[trust.ClaimKey]string) string {
	ordered := map[trust.ClaimKey]string{}
	maps.Copy(ordered, claims)
	if strings.HasPrefix(string(issuer), "https://") {
		ordered["iss"] = string(issuer)
	}
	first := []trust.ClaimKey{"iss", "aud", "sub"}
	keys := make([]trust.ClaimKey, 0, len(ordered))
	for _, k := range first {
		if _, ok := ordered[k]; ok {
			keys = append(keys, k)
		}
	}
	for _, k := range slices.Sorted(maps.Keys(ordered)) {
		if !slices.Contains(first, k) {
			keys = append(keys, k)
		}
	}
	if len(keys) == 0 {
		return "{}"
	}
	lines := make([]string, len(keys))
	for i, k := range keys {
		lines[i] = "  " + quote(string(k)) + ": " + quote(ordered[k])
	}
	return "{\n" + strings.Join(lines, ",\n") + "\n}"
}

// quote is a JSON string literal without HTML escaping, so that a payload
// reads as the token would.
func quote(s string) string {
	var b strings.Builder
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(s); err != nil {
		// A string always encodes; the fallback keeps the payload valid JSON.
		return fmt.Sprintf("%q", s)
	}
	return strings.TrimSuffix(b.String(), "\n")
}
