package report

import (
	"encoding/json"
	"slices"
	"strings"

	"github.com/CloudArq-net/cloudarq/internal/eval"
	"github.com/CloudArq-net/cloudarq/internal/parse/aws"
	"github.com/CloudArq-net/cloudarq/internal/registry"
	"github.com/CloudArq-net/cloudarq/internal/ring"
	"github.com/CloudArq-net/cloudarq/internal/trust"
)

// Re-marking: one answer a scan kept, placed again with the owners declared
// now, without its policy. Owners move nothing but where a grant's
// populations land, and everything said of the rings follows from that, so
// the answer keeps what it read and its grants are placed again by the one
// classifier. A grant is rebuilt from what the answer states of it, its
// claims' renderings and its caveats, and only once it renders back to the
// answer's own words; it is placed again only where its populations land as
// the answer kept them, but for what the owners move. Where the answer
// cannot be re-marked exactly, it is declined, never guessed at.
//
// The owners a scan recognised as the reader's, the account it read, are
// the reader's whatever they declare later, so they are placed again with
// the owners declared now, from the answer's echo of them. Each must be one
// this build recognises, and marked where the answer kept it marked, or the
// answer is declined.

// Declined is what Remark returns in place of an answer it cannot give
// exactly: why, and the sentence a reader is shown beside the answer kept,
// which stands until the role is read again.
type Declined struct {
	V int `json:"v"`
	// Declined is why the answer is not re-marked: another build of the
	// engine wrote it; the owners declared, when the role was read or now,
	// were refused whole; or what was given is not an answer this build
	// writes. Owners refused now are the cause given whatever else holds,
	// since the next upload does not read them either. Values: engine,
	// owners, answer.
	Declined string `json:"declined"`
	Sentence string `json:"sentence"`
	Spans    []Span `json:"spans"`
}

// cause is why Remark declines, as finely as the sentence beside the decline
// says it.
type cause int

const (
	anotherEngine cause = iota
	// The answer kept is the refusal of the owners declared when the role was
	// read, so it kept no grant to place again.
	ownersRefusedAtUpload
	// The owners declared now are past their bounds, beside an answer that
	// is an error or is declined for any other cause.
	ownersRefusedNow
	notAnAnswer
)

// String is the cause as Declined writes it. Both refusals of owners are
// written as owners, and the sentence says which owners were refused.
func (c cause) String() string {
	switch c {
	case anotherEngine:
		return "engine"
	case ownersRefusedAtUpload, ownersRefusedNow:
		return "owners"
	}
	return "answer"
}

// maxAnswerNesting bounds how deep an answer given to Remark may nest. The
// deepest an answer can be is a claim's constraint in a grant's terms,
// eleven levels when a union holds an intersection, which eval's sets
// allow; the decoder recurses once per level on the WebAssembly build's
// fixed stack, so a deeper answer is refused before it is read, as a deeper
// document is (nesting.go).
const maxAnswerNesting = 32

// Remark re-marks one answer a scan kept, with the owners the user declares
// now, one a line as AdmitsFor takes them. It returns the bytes the
// findings render for the policy the answer was read from, with those
// owners and the owners the answer recognised, which for an answer that
// recognised none are AdmitsFor's; or a Declined. wrote is the engine the
// scan's findings name, and engine is this one's name as Findings records
// it: facts and words can change between builds, and a bare answer does
// not say which build wrote it. The answer is read as JSON, in whatever
// form it was kept.
func Remark(answer, owners []byte, wrote, engine string) []byte {
	return AppendRemark(nil, answer, owners, wrote, engine)
}

// AppendRemark appends to dst what Remark returns and returns the extended
// buffer, as AppendAdmits does for one policy.
func AppendRemark(dst, answer, owners []byte, wrote, engine string) []byte {
	e := &encoder{b: dst}
	// The owners are read before anything else, since every decline says
	// what the next upload does with them.
	declared := ring.ReadDeclarations(string(owners))
	if wrote != engine {
		e.declined(declining(anotherEngine, declared))
		return e.b
	}
	// No bound is set here on the answer's size: a document of 262,136 bytes
	// whose 14,561 statements each name the principal "*" is answered in
	// 66,956,465 bytes, and a bound below that would decline an answer this
	// build wrote as one it does not write. The answer is bounded before it
	// arrives, by the 25 MiB a scan's findings may take, and by the loader,
	// which replaces an instance that traps or grows past its memory bound.
	var kept Answer
	if nesting(answer, maxAnswerNesting, "answer") != nil || json.Unmarshal(answer, &kept) != nil || kept.V != Version {
		e.declined(declining(notAnAnswer, declared))
		return e.b
	}
	switch {
	// The owners declared now are past their bounds, beside an answer that
	// read no grant to place again. The next upload refuses them, or never
	// reaches them when it refuses the document first, and an error does not
	// always say which; either way the role keeps the answer it has.
	case kept.Error != "" && declared.Overrun != nil:
		e.declined(declining(ownersRefusedNow, declared))
	// The owners declared at upload were refused whole after the document
	// was read, so no grant was kept; those declared now are read at the
	// next upload.
	case kept.Error != "" && isOverrunWords(kept.Error):
		e.declined(declining(ownersRefusedAtUpload, declared))
	// The document is read before the owners, so they change nothing of an
	// answer that stopped at it.
	case kept.Error != "":
		e.answer(kept)
	case kept.Document == nil:
		e.declined(declining(notAnAnswer, declared))
	// A document was read, and a declaration past its bounds is refused
	// whole, as admits refuses it.
	case declared.Overrun != nil:
		e.answer(Answer{V: Version, Error: overrunWords(*declared.Overrun), Grants: []Grant{}})
	default:
		recognised, ok := recognisedOf(kept)
		if !ok {
			e.declined(declining(notAnAnswer, declared))
			break
		}
		remarked, ok := remark(kept, declared, recognised)
		if !ok {
			e.declined(declining(notAnAnswer, declared))
			break
		}
		e.answer(remarked)
	}
	return e.b
}

// remark places every grant of a document's answer with the owners
// declared and recognised, and says again everything that follows from
// where they land. ok is false when a grant is not one this build placed.
func remark(a Answer, declared ring.Declarations, recognised []ring.Declaration) (Answer, bool) {
	mine := ownership{declared: declared.Owners, recognised: recognised}
	placements := make([]placed, len(a.Grants))
	for i := range a.Grants {
		g := &a.Grants[i]
		grant, ok := grantOf(*g)
		if !ok || g.Number != i+1 {
			return Answer{}, false
		}
		facts, platform := factsOf(grant.Issuer, g.Populations)
		placements[i] = placed{number: g.Number, issuer: grant.Issuer, facts: facts, platform: platform, placement: ring.Classify(grant, facts, mine.all()), mine: mine}
		kept := g.Populations
		g.Placement, g.PlacementState, g.Populations = placements[i].stated()
		if !onlyOwnersMoved(kept, g.Populations) {
			return Answer{}, false
		}
	}
	a.Headline, a.Rings, a.Beside, a.Refused, a.Nobody, a.Declarations, a.Bounds = nil, nil, nil, nil, nil, nil, nil
	a.rings(placements, declared)
	return a, true
}

// recognisedOf reads the owners an answer recognised as the reader's from
// its echo: at most one, the AWS account a scan read, written as a
// declaration of it writes it, with the words that say why. ok is false
// for anything else, which this build never recognises.
func recognisedOf(a Answer) (recognised []ring.Declaration, ok bool) {
	if a.Declarations == nil || len(a.Declarations.Recognitions) == 0 {
		return nil, true
	}
	if len(a.Declarations.Recognitions) > 1 {
		return nil, false
	}
	r := a.Declarations.Recognitions[0]
	d := ring.ReadDeclarations(r.Declaration)
	if len(d.Owners) != 1 || len(d.Refused) != 0 || d.Owners[0].Scope != ring.ScopeAccount || d.Owners[0].String() != r.Declaration || r.Sentence != recognisedWords {
		return nil, false
	}
	return d.Owners, true
}

// grantOf is the grant an answer states, as the classifier reads one: its
// issuer, its effect, and its admitted set, each claim built from its
// rendering, which is eval's canonical statement of a set, with the caveats
// its notes carry. ok is false unless the set built renders as the answer's
// admits and is exact exactly when the answer says the grant is. The
// caveats are read from the notes alone, so the set holds whichever notes
// the answer kept, and comparing the two says only that they are in eval's
// order, each once. Notes lost whole leave a set built exact beside a grant
// the answer calls inexact; notes lost in part are caught where they would
// move the grant, since a caveat moves a population only through its basis
// and state, which remark holds to those kept.
func grantOf(g Grant) (trust.Grant, bool) {
	terms := make([]eval.Term, 0, len(g.Terms))
	for _, rows := range g.Terms {
		term := eval.Term{}
		for _, row := range rows {
			// The subject's row the answer adds to a grant that names no
			// claim but the audience: no term eval builds holds Any.
			if row.Constraint.Kind == kindAny {
				continue
			}
			set, ok := setOf(row.Rendered)
			if !ok {
				return trust.Grant{}, false
			}
			term[eval.ClaimKey(row.Claim)] = set
		}
		terms = append(terms, term)
	}
	admits := eval.NewAdmittedSet(terms...)
	var caveats []eval.Caveat
	for _, n := range g.Notes {
		if n.Kind == "caveat" {
			c := eval.Caveat{Claim: eval.ClaimKey(n.Claim), Reason: n.Message, Source: n.Source}
			caveats = append(caveats, c)
			admits = admits.WithCaveat(c)
		}
	}
	if admits.String() != g.Admits || admits.Exact() != g.Exact || !slices.Equal(admits.Caveats(), caveats) {
		return trust.Grant{}, false
	}
	return trust.Grant{Target: target, Issuer: trust.IssuerRef(g.Issuer), Effect: trust.Effect(g.Effect), Admits: admits}, true
}

// setOf is the set a claim's rendering states. A value, a pattern and the
// lists of them are read by the reader that reads them for the answer's
// constraint; an Unknown is read here, because the constraint carries its
// reasons joined into one, which cannot be split back, and the rendering
// quotes each.
func setOf(rendered string) (eval.StringSet, bool) {
	if reasons, ok := strings.CutPrefix(rendered, "?("); ok {
		return unknownOf(reasons)
	}
	if listsDeep(rendered) > maxListNesting {
		return nil, false
	}
	c, rest, err := parseConstraint(rendered)
	if err != nil || rest != "" {
		return nil, false
	}
	return c.set(), true
}

// maxListNesting is how deep eval nests the lists of a rendering: a union
// whose members are intersections. The reader and the builder below recurse
// once per list, and a rendering given to Remark is not eval's until it has
// rendered back, so one nested deeper is refused before either sees it.
const maxListNesting = 2

// listsDeep is how deep a rendering nests its parenthesised lists, outside
// the values it quotes, which may hold parentheses of their own.
func listsDeep(rendered string) int {
	depth, deepest := 0, 0
	quoted, escaped := false, false
	for i := 0; i < len(rendered); i++ {
		switch b := rendered[i]; {
		case escaped:
			escaped = false
		case quoted && b == '\\':
			escaped = true
		case b == '"':
			quoted = !quoted
		case quoted:
		case b == '(':
			depth++
			deepest = max(deepest, depth)
		case b == ')':
			depth--
		}
	}
	return deepest
}

// set builds the constraint with eval's own constructors, each of which
// normalises as the set read from a policy was normalised.
func (c Constraint) set() eval.StringSet {
	switch c.Kind {
	case kindExact:
		return eval.Exact(c.Value)
	case kindLike:
		return eval.Glob(c.Value)
	}
	s := c.Members[0].set()
	for _, m := range c.Members[1:] {
		if c.Kind == kindUnion {
			s = s.Join(m.set())
		} else {
			s = s.Meet(m.set())
		}
	}
	return s
}

// unknownOf is the Unknown whose reasons follow "?(" in a rendering, each
// quoted, separated by ", ", up to the closing parenthesis.
func unknownOf(reasons string) (eval.StringSet, bool) {
	var s eval.StringSet
	for {
		reason, rest, err := unquote(reasons)
		if err != nil {
			return nil, false
		}
		if s == nil {
			s = eval.Unknown(reason)
		} else {
			s = s.Join(eval.Unknown(reason))
		}
		if rest == ")" {
			return s, true
		}
		var more bool
		if reasons, more = strings.CutPrefix(rest, ", "); !more {
			return nil, false
		}
	}
}

// factsOf is what place gives the classifier for a grant: the census's
// facts for its issuer, and the platform they are on; and the two facts the
// parser reads from the grant's statement, which the answer does not carry
// and its populations were placed by, one for one and whatever the owners:
// a principal the parser did not model places every population with the
// same basis, and so does whom a statement naming no issuer admits.
func factsOf(issuer trust.IssuerRef, populations []Population) (ring.Facts, string) {
	facts, names := registry.Facts(issuer)
	basis := func(b ring.Basis) bool {
		return slices.ContainsFunc(populations, func(p Population) bool { return p.Basis == b.String() })
	}
	facts.PrincipalModelled = !basis(ring.PrincipalNotModelled)
	switch services, saml := basis(ring.AnyService), basis(ring.AccountSAMLProviders); {
	case services && saml:
		facts.Issuerless = aws.AWSServicesAndAccountSAMLProviders
	case services:
		facts.Issuerless = aws.AWSServices
	case saml:
		facts.Issuerless = aws.AccountSAMLProviders
	}
	return facts, platformName(issuer, names)
}

// onlyOwnersMoved reports whether a grant's populations as the answer kept
// them and as placed again differ in nothing but what declaring owners
// moves: where each lands, and which of its owners are declared. Which are
// recognised does not move, since it does not depend on what is declared.
// The rest follows from the grant and the facts factsOf read from the
// populations kept, so a grant whose populations say otherwise, or were
// lost, was not placed by this build from what the answer states, and is
// not placed again.
func onlyOwnersMoved(kept, placed []Population) bool {
	return slices.EqualFunc(kept, placed, func(k, p Population) bool {
		return k.Term == p.Term && k.State == p.State && k.Basis == p.Basis &&
			slices.EqualFunc(k.Owners, p.Owners, func(a, b Owner) bool {
				a.Declared, b.Declared = false, false
				return a == b
			})
	})
}

// declining is the Declined for why, in the engine's words, beside the
// owners declared now. Owners past their bounds are refused whole by the
// next upload, or never reached when it refuses the document first, so
// whatever else declines the answer, the decline is theirs: every other
// says that the role is read again with the owners declared now, and the
// next upload does not read these.
func declining(why cause, declared ring.Declarations) Declined {
	if declared.Overrun != nil {
		why = ownersRefusedNow
	}
	spans := stripped(declinedWords(why))
	return Declined{V: Version, Declined: why.String(), Sentence: plain(spans), Spans: spans}
}

func (e *encoder) declined(d Declined) {
	saved := e.begin()
	e.num("v", d.V)
	e.str("declined", d.Declined)
	e.str("sentence", d.Sentence)
	e.spans("spans", d.Spans)
	e.end(saved)
}
