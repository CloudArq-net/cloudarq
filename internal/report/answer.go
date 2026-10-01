// Package report composes the answer: the grants of a trust policy, the
// ring each lands in, and, for a token, why each grant admits or rejects
// it, as JSON and as text for a terminal. It is the one place those words
// are composed, so that the command and the WebAssembly engine say the same
// sentence about the same document, and so that a page embedding the
// engine evaluates nothing itself. It is the rendering layer above the pure
// packages, and reaches no IO.
//
// Every entry point is total. A policy that cannot be read, a token that
// cannot, or owners declared past their bounds is stated in the answer
// rather than returned as an error, so that a caller shows the reason
// where it shows any other answer.
package report

import (
	"cmp"
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
	"github.com/CloudArq-net/cloudarq/internal/parse/casefold"
	"github.com/CloudArq-net/cloudarq/internal/registry"
	"github.com/CloudArq-net/cloudarq/internal/ring"
	"github.com/CloudArq-net/cloudarq/internal/trust"
)

// Version is the "v" of every answer: the JSON shape is a public contract
// between the engine and whatever reads it, and a reader that meets another
// version must say so rather than render it. The rule for it:
//
// v changes only when a field is removed or renamed, or a field's meaning
// changes. New fields, and new values of an existing field, are added under
// the same v; a consumer ignores fields it does not know, and reads a value
// it does not know as Unknown, never as clean.
//
// A consumer can tell a value it does not know only from the ones it does,
// so every field whose values are a closed set lists them beside it, after
// "Values:".
const Version = 1

// MaxDocumentBytes and MaxTokenBytes bound what the engine reads. AWS
// accepts a role trust policy of at most 8,192 characters (IAM quotas, read
// 2026-09-13), and a megabyte of JSON read call after call grows the
// WebAssembly heap without bound, since
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
// not name; the engine reads no account to find it.
var target = trust.TargetRef{Kind: "role"}

// vocabulary is the one the parser reads condition keys with: the keys AWS
// documents for each issuer's tokens, which the registry reads from the
// census, each under its own name, which of them AWS documents as
// multivalued, and which it reads from a claim the issuer's tokens may carry
// with several values. Which claim of a token AWS reads each from is the
// census's too, and a token is read by it, pasted or built as a witness:
// readKey and tokenFor.
var vocabulary = aws.DocumentedKeys(registry.AWSDocumentsConditionKey, registry.AWSDocumentsMultivalued, registry.AWSReadsAMultiValuedClaim)

// Answer is what admits renders: the document as read, one Grant per
// grant of it, in the engine's order, and the rings those grants land in.
// The rings and everything after them are absent from an answer that read
// no document, and from one whose document holds no statement, which
// keeps its headline: a ring nobody placed a grant in is itself an answer,
// and nothing was read to give it.
type Answer struct {
	V        int       `json:"v"`
	Error    string    `json:"error,omitempty"`
	Document *Document `json:"document,omitempty"`
	Grants   []Grant   `json:"grants"`
	// Headline is the one sentence the answer opens on: the class of identity
	// furthest from the user that can assume the role, and every line
	// beside the rings that holds a grant, which it never omits.
	Headline *Sentence `json:"headline,omitempty"`
	// Rings are the five rings, in every answer that read a statement,
	// ordered by distance and never by anything else, each listing its
	// grants by their numbers.
	Rings []Row `json:"rings,omitempty"`
	// Beside are the lines beside the rings: the populations a trust policy
	// cannot place, SAML sign-ins and cloud services, one row each when it
	// holds a grant.
	Beside []Row `json:"beside,omitempty"`
	// Refused lists the Deny grants, which are in no ring and are never
	// subtracted from one; Nobody lists the grants that admit no token.
	Refused *Listing `json:"refused,omitempty"`
	Nobody  *Listing `json:"nobody,omitempty"`
	// Declarations echoes the declaration the rings were placed with, so
	// that owners a caller declared on the reader's behalf are shown.
	Declarations *Declarations `json:"declarations,omitempty"`
	// Bounds is what can narrow the rings and was not read: a ring printed
	// as exact is exact for the document read, and no more.
	Bounds *Bounds `json:"bounds,omitempty"`
	// beyondABound records that Error is one of the engine's bounds rather
	// than a reading of the bytes. It is not part of the schema: the JSON
	// carries the sentence and nothing more, and the terminal rendering is
	// the only one that adds a second one to it.
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

// Statement locates one statement in the document: its bytes, so that a
// caller can quote them from the source, and its lines, so that it can mark
// them in the document.
type Statement struct {
	Index     int    `json:"index"`
	Sid       string `json:"sid"`
	Offset    int    `json:"offset"`
	Length    int    `json:"length"`
	FirstLine int    `json:"firstLine"`
	LastLine  int    `json:"lastLine"`
	SHA256    string `json:"sha256"`
}

// Grant is one grant as the answer states it.
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
	// words printed over it, in the grant's effect and saying what
	// the witness proves and what it does not.
	Witness        string `json:"witness,omitempty"`
	WitnessHeading string `json:"witnessHeading,omitempty"`
	WitnessCaption string `json:"witnessCaption,omitempty"`
	// Placement is where the grant lands: the outermost ring its terms
	// reach, and each line beside the rings one reaches; or refused, for a
	// Deny, and nobody, for a grant that admits no token.
	// Values: anyone, platform, outsider, yours, people, saml, service,
	// refused, nobody.
	Placement []string `json:"placement,omitempty"`
	// PlacementState is exact when the placement follows from verified
	// facts and constraints read exactly, and unknown otherwise; it is
	// absent beside refused and nobody. Values: exact, unknown.
	PlacementState string `json:"placementState,omitempty"`
	// Populations are where each term lands on its own, in term order, with
	// the owners that pin it.
	Populations []Population `json:"populations,omitempty"`
}

// Sentence is one sentence of the answer: the text, and its spans.
type Sentence struct {
	Sentence string `json:"sentence"`
	Spans    []Span `json:"spans"`
}

// Row is one ring, or one line beside the rings: where it is, its label,
// its state, the numbers of the grants in it, and its sentence. A ring
// that holds no grant is exact: nothing was placed there, which is itself
// the finding, and an outer grant that might belong nearer carries its own
// unknown. The ring of anyone is the exception: beside a population that
// is not read, a SAML provider's sign-ins, declared or not, or a service's
// callers, nothing read rules out anyone at all, so it is unknown.
type Row struct {
	// Place is a ring, one of the first five values, or a line beside the
	// rings, one of the last two. Values: anyone, platform, outsider, yours,
	// people, saml, service.
	Place string `json:"place"`
	Label string `json:"label"`
	// Values: exact, unknown.
	State        string `json:"state"`
	GrantNumbers []int  `json:"grantNumbers"`
	Sentence     string `json:"sentence"`
	Spans        []Span `json:"spans"`
	// Questions are what a reader may be asked of the row, one owner or
	// provider at a time: whether one the engine cannot place as the
	// user's own is theirs. Only a named outsider's row and the line of
	// SAML sign-ins ask; which one to put is the caller's choice.
	Questions []Question `json:"questions,omitempty"`
	// CitationsHeading and Citations are the vendor's sentences a row's
	// place or its words rest on, quoted as written, and the words over
	// them, which say that the place is the engine's reading of them and no
	// sentence of the vendor's: the reading that places the face of "*" with
	// anyone, and the one that names whom a service on the line of cloud
	// services acts for.
	CitationsHeading string     `json:"citationsHeading,omitempty"`
	Citations        []Citation `json:"citations,omitempty"`
}

// Question is one question a reader may be asked: the declaration that
// answers yes, as --owner takes it and as an owner's declaration carries
// it, so that declaring it names that owner; and the question in words,
// which alone is stripped of what a terminal acts on.
type Question struct {
	Declaration string `json:"declaration"`
	Sentence    string `json:"sentence"`
	Spans       []Span `json:"spans"`
}

// Citation is one vendor sentence, verbatim, and the page it is on.
type Citation struct {
	Quote  string `json:"quote"`
	Source string `json:"source"`
}

// Listing is grants that are in no ring, by number, and why.
type Listing struct {
	GrantNumbers []int  `json:"grantNumbers"`
	Sentence     string `json:"sentence"`
	Spans        []Span `json:"spans"`
}

// Declarations is the declaration as read: the owners it declares, each in
// its one normalised form, sorted and deduplicated; every line refused; and
// every owner declared that no grant which admits is pinned to, since a
// declaration that moved nothing and said nothing would leave its reader
// believing it had.
type Declarations struct {
	Normalised   []string         `json:"normalised"`
	RefusedLines []RefusedLine    `json:"refusedLines"`
	Unmatched    []UnmatchedOwner `json:"unmatched"`
}

// RefusedLine is one line of the declaration that declared nothing, by its
// number and as written, with why.
type RefusedLine struct {
	Line int    `json:"line"`
	Text string `json:"text"`
	// Values: not-utf-8, no-namespace, unknown-namespace, claims-not-read,
	// no-owner, a-repository, not-a-github-owner, not-an-aws-id,
	// not-a-saml-provider, not-an-issuer-url.
	Reason   string `json:"reason"`
	Sentence string `json:"sentence"`
}

// UnmatchedOwner is one owner declared that no grant which admits is pinned
// to, in its normalised form, and what that means for the reader.
type UnmatchedOwner struct {
	Declaration string `json:"declaration"`
	Sentence    string `json:"sentence"`
}

// Bounds is what was not read and can narrow the rings: each with its
// sentence, and one sentence naming them all, which a view that prints the
// rings prints beside them.
type Bounds struct {
	Sentence string  `json:"sentence"`
	Items    []Bound `json:"items"`
}

// Bound is one thing that can narrow the rings and was not read.
type Bound struct {
	// Bound is which: the organisation's resource control policies, the
	// calling accounts' service control policies, the account's identity
	// providers, or the settings of each audience the role accepts from the
	// issuer Issuer names. Values: resource-control-policies,
	// service-control-policies, identity-providers, audience-settings.
	Bound    string `json:"bound"`
	Issuer   string `json:"issuer,omitempty"`
	Sentence string `json:"sentence"`
}

// Population is where one term of a grant lands, and the owners that pin
// it. Basis is what decided the place.
type Population struct {
	Term int `json:"term"`
	// Values: anyone, platform, outsider, yours, people, saml, service.
	Place string `json:"place"`
	// Values: exact, unknown.
	State string `json:"state"`
	// Values: issuer-not-surveyed, tokens-without-account,
	// account-not-verified, any-issuer, principal-not-modelled, unpinned,
	// unread-constraint, tenancy-not-recorded, open-tenant,
	// membership-not-verified, pinned, controlled-tenant, saml-provider,
	// account-saml-providers, service-principal, any-service,
	// service-intermediary.
	Basis  string  `json:"basis"`
	Owners []Owner `json:"owners"`
}

// Owner is one owner a term is pinned to, typed as the classifier typed it:
// its scope, whether it is named by a name or an id, the value, and the
// declaration a user writes to declare it as theirs, empty when it
// cannot be declared. An owner is recyclable when whoever holds its
// value can change: a name, which whoever registers it next holds, and an
// id no vendor sentence calls immutable.
type Owner struct {
	// Label is the words that name the owner, as a sentence that starts
	// with it names it: its declaration, when it has one, and otherwise
	// what it is and its value, as "Repository 456789".
	Label       string `json:"label"`
	Declaration string `json:"declaration,omitempty"`
	// Values: owner, repository, enterprise, account, organisation, tenant,
	// provider.
	Scope string `json:"scope"`
	// Values: name, id.
	Kind       string `json:"kind"`
	Value      string `json:"value"`
	Name       string `json:"name,omitempty"`
	Declared   bool   `json:"declared"`
	Recyclable bool   `json:"recyclable"`
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

// Admits reads a trust policy and renders the answer as JSON, with no owner
// declared. It is what the WebAssembly engine's admits returns.
func Admits(policy []byte) []byte { return admitsWith(nil, policy, nil) }

// AppendAdmits appends to dst the answer Admits renders and returns the
// extended buffer. The WebAssembly engine writes each answer into the
// buffer the one before it used. TinyGo grows a slice to the next power of
// two, so an answer rendered into a new buffer on every call asks the
// collector for a block of that size and for each smaller one it grew
// through, and on the 50-statement policy the collector answered those by
// doubling linear memory once more.
func AppendAdmits(dst, policy []byte) []byte { return admitsWith(dst, policy, nil) }

// AdmitsFor reads a trust policy and the owners the user declares as
// theirs, one declaration a line, and renders the answer as JSON. With no
// owners it is Admits, byte for byte.
func AdmitsFor(policy, owners []byte) []byte { return admitsWith(nil, policy, owners) }

// admitsWith is the one path the entry points take, kept out of line so
// that the WebAssembly engine carries the reading of a policy once.
//
//go:noinline
func admitsWith(dst, policy, owners []byte) []byte {
	e := &encoder{b: dst}
	e.answer(admits(policy, owners))
	return e.b
}

func admits(policy, owners []byte) Answer {
	a := Answer{V: Version, Grants: []Grant{}}
	r, err := readPolicy(policy)
	if err != nil {
		a.Error, a.beyondABound = err.Error(), beyondABound(err)
		return a
	}
	declared := ring.ReadDeclarations(string(owners))
	if declared.Overrun != nil {
		// A declaration past its bounds is refused whole, as a document past
		// its bounds is: the document was not the fault, so nothing is said
		// about its dialect.
		return Answer{V: Version, Error: overrunWords(*declared.Overrun), Grants: []Grant{}, beyondABound: true}
	}
	a.Document = r.document()
	placed := r.place(declared.Owners)
	for i := range r.grants {
		grant, err := r.grant(i)
		if err != nil {
			return Answer{V: Version, Error: fmt.Sprintf("grant %d: %v", i+1, err), Grants: []Grant{}}
		}
		grant.Placement, grant.PlacementState, grant.Populations = placementOf(placed[i].placement)
		a.Grants = append(a.Grants, grant)
	}
	a.rings(placed, declared)
	return a
}

// place classifies every grant: the census's facts for its issuer, what
// the parser reads of the statement it came from, whether it modelled the
// grant's principal and who a grant with no issuer admits, and the owners
// declared. A policy names few issuers, so each issuer's facts are read
// once a call rather than once a grant.
func (r reading) place(declared []ring.Declaration) []placed {
	var lookedUp []placed
	out := make([]placed, len(r.grants))
	for i, g := range r.grants {
		at := slices.IndexFunc(lookedUp, func(p placed) bool { return p.issuer == g.Issuer })
		if at < 0 {
			facts, names := registry.Facts(g.Issuer)
			lookedUp = append(lookedUp, placed{issuer: g.Issuer, facts: facts, platform: platformName(g.Issuer, names)})
			at = len(lookedUp) - 1
		}
		p := lookedUp[at]
		s := r.doc.Statements[r.statements[i]]
		p.facts.Issuerless = s.IssuerlessPopulation()
		p.facts.PrincipalModelled = s.ModelsPrincipalOf(g)
		p.number, p.placement = i+1, ring.Classify(g, p.facts, declared)
		out[i] = p
	}
	return out
}

// placed is one grant's placement, with what its sentences name: its
// number, its issuer, and the platform that issuer is on.
type placed struct {
	number    int
	issuer    trust.IssuerRef
	facts     ring.Facts
	platform  string
	placement ring.Placement
}

// placementOf is a placement in the answer's vocabulary.
func placementOf(p ring.Placement) ([]string, string, []Population) {
	if p.Outcome != ring.Placed {
		return []string{p.Outcome.String()}, "", nil
	}
	places := make([]string, len(p.Places))
	for i, place := range p.Places {
		places[i] = place.String()
	}
	populations := make([]Population, len(p.Populations))
	for i, pop := range p.Populations {
		owners := make([]Owner, len(pop.Owners))
		for j, o := range pop.Owners {
			owners[j] = Owner{Label: withoutControls(ownerLabel(o)), Declaration: o.Declaration(), Scope: o.Scope.String(), Kind: o.Kind.String(), Value: o.Value, Name: o.Name, Declared: o.Declared, Recyclable: o.Recyclable}
		}
		populations[i] = Population{Term: pop.Term, Place: pop.Place.String(), State: pop.State.String(), Basis: pop.Basis.String(), Owners: owners}
	}
	return places, p.State.String(), populations
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
		return reading{}, bounded{fmt.Errorf("the document is longer than %d bytes, the most the engine reads, and AWS accepts a role trust policy of at most 8192 characters", MaxDocumentBytes)}
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
	witness, unset := witnessOf(g, out.Terms)
	if out.Witness = witness; out.Witness != "" {
		out.WitnessHeading = witnessHeading(g.Effect)
		out.WitnessCaption = witnessCaption(g, out, unset)
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

// unconstrainedSubject is the row the answer holds when no claim but the
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
// A key names the principal's own claim when the part before a colon may be
// the issuer's host and path under a case folding and the part after it is
// the claim in ASCII case: a key the parser reads as the claim, and one it
// cannot place because a folding it does not know may make it the claim.
// Any other key names its claim by its whole text in ASCII case.
func (s statementLayout) keysFor(claim string, issuer trust.IssuerRef) []Written {
	provider := casefold.Wide(strings.TrimPrefix(string(issuer), "https://"))
	out := []Written{}
	for _, k := range s.keys {
		if fold(k.key) == claim || ownClaim(k.key, provider) == claim {
			out = append(out, Written{Line: k.line, Operator: k.operator})
		}
	}
	return out
}

// claimsNamed lists the claim each condition key of the statement names, by
// the rule keysFor reads: the principal's own claim for a key that is one,
// and the key's whole text in ASCII case for any other.
func (s statementLayout) claimsNamed(issuer trust.IssuerRef) []string {
	provider := casefold.Wide(strings.TrimPrefix(string(issuer), "https://"))
	out := make([]string, 0, len(s.keys))
	for _, k := range s.keys {
		out = append(out, cmp.Or(ownClaim(k.key, provider), fold(k.key)))
	}
	return out
}

// ownClaim is the claim a key names as the principal's own, in ASCII case,
// when the part before a colon is the provider under casefold.Wide.
func ownClaim(key, provider string) string {
	for i := 0; i < len(key); i++ {
		if key[i] == ':' && casefold.Wide(key[:i]) == provider {
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
// by its host and path in ASCII case, as the issuer was normalised, or the
// Principal member itself when no leaf does, as for an AWS principal whose
// pseudo-issuer no leaf spells.
func (s statementLayout) issuerWritten(issuer trust.IssuerRef) Written {
	ident := fold(strings.TrimPrefix(string(issuer), "https://"))
	for _, l := range s.leaves {
		if ident != "" && strings.Contains(fold(l.text), ident) {
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
// simplest instance of the first term that yields one, each value in the
// claim AWS reads its key from, which the engine confirms by reading the
// token back as it reads a pasted one. A witness the engine rejected is
// never returned, and a set widened to everything has none to offer:
// nothing about it was evaluated, so no token is witnessed by it. unset is
// what the witness leaves out so that AWS reads the claims it carries.
func witnessOf(g trust.Grant, terms [][]Claim) (witness string, unset []leftOut) {
	if g.Admits.IsTop() && !g.Exact() {
		return "", nil
	}
	for _, rows := range terms {
		values := map[trust.ClaimKey]string{}
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
			values[trust.ClaimKey(row.Claim)] = v
		}
		if !complete {
			continue
		}
		if tok, unset, ok := tokenFor(g.Issuer, values); ok && tok.heldBy(g) {
			return payload(g.Issuer, tok.values), unset
		}
	}
	return "", nil
}

// leftOut is a claim a witness leaves out because AWS would read the key
// from it, in place of the claim the witness carries the key's value in.
type leftOut struct{ claim, key string }

// tokenFor is a token in which AWS reads each key's value: the value in the
// claim AWS reads the key from. A key AWS reads from one claim, or from
// another when the token sets none of the first, as aud from azp, or from
// aud, takes the second while it is free, which is how a token of GitHub's
// carries its audience, and the first is left out; where the second holds
// another key's value, the key takes the first. ok is false when AWS reads a
// key from what is no claim, or when one claim would hold two values.
func tokenFor(issuer trust.IssuerRef, values map[trust.ClaimKey]string) (tok token, unset []leftOut, ok bool) {
	tok = token{values: map[trust.ClaimKey]string{}, null: map[trust.ClaimKey]bool{}}
	put := func(claim, value string) bool {
		held, taken := tok.values[trust.ClaimKey(claim)]
		if _, named := trust.Claim(claim); !named || taken && held != value {
			return false
		}
		tok.values[trust.ClaimKey(claim)] = value
		return true
	}
	type either struct{ key, claim, fallback, value string }
	var eithers []either
	for _, k := range slices.Sorted(maps.Keys(values)) {
		read, documented := registry.AWSConditionKeyClaim(issuer, string(k))
		claim := read.Claim
		switch {
		case !documented:
			claim = string(k)
		case read.Fallback != "":
			eithers = append(eithers, either{string(k), claim, read.Fallback, values[k]})
			continue
		}
		if !put(claim, values[k]) {
			return token{}, nil, false
		}
	}
	for _, e := range eithers {
		held, taken := tok.values[trust.ClaimKey(e.fallback)]
		_, preferred := tok.values[trust.ClaimKey(e.claim)]
		target := e.claim
		if !preferred && (!taken || held == e.value) {
			target = e.fallback
		}
		if !put(target, e.value) {
			return token{}, nil, false
		}
	}
	for _, e := range eithers {
		if _, set := tok.values[trust.ClaimKey(e.claim)]; !set && !slices.Contains(unset, leftOut{e.claim, e.key}) {
			unset = append(unset, leftOut{e.claim, e.key})
		}
	}
	return tok, unset, true
}

// heldBy reports whether the grant's set holds the token as AWS reads it:
// some term every key of which the token settles and meets.
func (tok token) heldBy(g trust.Grant) bool {
	reads := readsOf(g, tok)
	for _, term := range g.Admits.Terms() {
		if !slices.ContainsFunc(slices.Collect(maps.Keys(term)), func(k trust.ClaimKey) bool { return reads[k].against(term[k]) != meets }) {
			return true
		}
	}
	return false
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
		return fmt.Sprintf("%+q", s)
	}
	return strings.TrimSuffix(b.String(), "\n")
}
