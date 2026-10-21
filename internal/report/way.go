package report

import (
	"slices"
	"strconv"
	"strings"

	"github.com/CloudArq-net/cloudarq/internal/parse/aws"
	"github.com/CloudArq-net/cloudarq/internal/ring"
	"github.com/CloudArq-net/cloudarq/internal/trust"
)

// The way of a population: who it is and how the policy lets it in, each in
// one sentence, from what the engine already read and placed, and nothing
// it did not. Who is the sentence the row the population lands in says,
// read with that population alone in it, so a population is named in the
// rings' words and asked about as the rings ask; how is the statement it
// was read from, the principal that statement names and the conditions its
// term holds, as the grant's own sentence states them.

// Way is who one population is and how the policy lets it in.
type Way struct {
	// Principal is the principal the grant was read from, as the statement
	// writes it, once for each place it is written: none when the statement
	// writes no principal string the grant came from.
	Principal []Leaf `json:"principal"`
	// Who is the population as the row it lands in names it, with the
	// owners it is pinned to and whether each is the reader's.
	Who *Sentence `json:"who"`
	// How is the statement that lets the population in, the principal it
	// names and the conditions the population's term holds.
	How *Sentence `json:"how"`
	// Questions are what the reader may be asked of the population's
	// owners, as its row asks them: whether one nobody declared is theirs.
	Questions []Question `json:"questions,omitempty"`
	// Fix is how the policy could shut the population out, and whether
	// the engine proved it (fix.go). Every way in has one. A population
	// placed as the reader's, yours or your people, carries the fix it
	// would have were it not declared, so that an answer re-marked with the
	// declaration withdrawn, without the policy, says it again; it is not
	// advice to shut the reader's own out, and ExplainWays does not say it.
	Fix *Fix `json:"fix,omitempty"`
}

// Leaf is one string under Principal: its text as written, the member it
// sits under, as "Principal.AWS", or "Principal" for a Principal that is
// "*" itself, and its line.
type Leaf struct {
	Text   string `json:"text"`
	Member string `json:"member"`
	Line   int    `json:"line"`
	// Start and End are where the principal's literal is written, as the
	// byte offsets [Start, End), given only where an edit names the one
	// place it removes.
	Start int `json:"start,omitempty"`
	End   int `json:"end,omitempty"`
}

// principalLeaves are the places the statement writes the principal a grant
// was read from: every string under Principal of its member and its text.
func (s statementLayout) principalLeaves(w aws.Written) []Leaf {
	out := []Leaf{}
	if w == (aws.Written{}) {
		return out
	}
	for _, l := range s.leaves {
		if l.member != w.Member || l.text != w.Text {
			continue
		}
		member := "Principal"
		if l.member != "" {
			member += "." + l.member
		}
		out = append(out, Leaf{Text: l.text, Member: member, Line: l.line})
	}
	return out
}

// whoOf is who the grant's population j is, in the words of the row it
// lands in with that population alone in it, and what that row asks of
// its owners.
func (p placed) whoOf(j int) (*Sentence, []Question) {
	pop := p.placement.Populations[j]
	alone := p
	alone.placement.Populations = []ring.Population{pop}
	r := row{place: pop.Place, state: pop.State, grants: []placed{alone}}
	var questions []Question
	for _, q := range r.questions() {
		asked := stripped(questionWords(q))
		questions = append(questions, Question{Declaration: q.Declaration(), Sentence: plain(asked), Spans: asked})
	}
	return sentence(rowWords(r)), questions
}

// ways sets the way of every population of grant i, placed as p, with what
// the reading holds of the statement it came from, and the parts of each
// finding that follow from the way and the grant.
func (r reading) ways(i int, p placed, g *Grant, d *Document) {
	at := r.lay.statements[r.statements[i]]
	p.ways(g, d.Statements[r.statements[i]], at.principalLeaves(r.written[i]), len(at.keys))
	g.findingParts()
}

// findingParts sets, on each finding of a grant's populations, what owners
// move none of and the population's term does not say: what the way in
// comes through, from its principal as written, and the conditions its
// statement writes that the grant does not read, as the grant writes them.
// An answer marked again keeps both, in its ways and its grants, and so
// says them again of a finding it meets only now.
func (g *Grant) findingParts() {
	for j := range g.Populations {
		pop := &g.Populations[j]
		if pop.Finding == nil {
			continue
		}
		pop.Finding.Through = throughOf(pop.Way)
		pop.Finding.Unread = slices.Clone(g.Unread)
	}
}

// throughOf is what a way in comes through: the principal its statement
// writes, where it names an identity provider, under Federated, or a
// service, under Service. An AWS principal, or a Principal that is "*"
// itself, names neither, and a way with no principal written says none.
func throughOf(w *Way) *string {
	if w == nil || len(w.Principal) == 0 {
		return nil
	}
	switch l := w.Principal[0]; l.Member {
	case "Principal.Federated", "Principal.Service":
		text := l.Text
		return &text
	}
	return nil
}

// ways sets the way of every population of a grant the answer placed: who
// from where it lands, and how from the statement it was read from, where
// the principal is written and how many condition keys the statement
// writes.
func (p placed) ways(g *Grant, st Statement, principal []Leaf, conditionKeys int) {
	for j := range g.Populations {
		who, questions := p.whoOf(j)
		var term []Claim
		if t := g.Populations[j].Term; t >= 0 && t < len(g.Terms) {
			term = g.Terms[t]
		}
		g.Populations[j].Way = &Way{
			Principal: principal,
			Who:       who,
			How:       sentence(howWords(*g, st, term, principal, conditionKeys)),
			Questions: questions,
		}
	}
}

// howWords is how a statement lets one term of its grant in: the statement
// by its number, its Sid and its lines; the principal it names, by what
// the term reads of it; and the conditions the term holds, in the words
// the grant's sentence says them in. A statement whose conditions the term
// holds none of says that none is read as narrowing it, and one that writes
// none says so; a grant whose set is an upper bound says that too.
func howWords(g Grant, st Statement, term []Claim, principal []Leaf, conditionKeys int) []Span {
	s := statementRef(g.Statement, st)
	s = append(s, Span{Text: " names "})
	s = append(s, namedPrincipal(trust.IssuerRef(g.Issuer), term, principal)...)
	var conditions [][]Span
	for _, row := range term {
		if len(row.Written) == 0 {
			continue
		}
		c := []Span{{Text: row.Claim, Mark: "code"}}
		if row.Constraint.Kind == kindUnknown {
			c = append(c, Span{Text: " was not evaluated", Mark: "unknown", Note: row.Note})
		} else {
			c = append(c, row.Constraint.clause()...)
		}
		conditions = append(conditions, c)
	}
	switch {
	case len(conditions) > 0:
		s = append(s, Span{Text: ", on condition that "})
		for i, c := range conditions {
			switch {
			case i > 0 && i == len(conditions)-1:
				s = append(s, Span{Text: " and "})
			case i > 0:
				s = append(s, Span{Text: ", "})
			}
			s = append(s, c...)
		}
	case conditionKeys > 0:
		s = append(s, Span{Text: ", and no condition it writes is read as narrowing it"})
	default:
		s = append(s, Span{Text: ", with no condition"})
	}
	if !g.Exact {
		s = append(s, Span{Text: ", so the set shown is an upper bound"})
	}
	return append(s, Span{Text: "."})
}

// statementRef names a statement in a sentence: by its number, counted
// from one as a reader counts, its Sid when it has one, and its lines.
func statementRef(index int, st Statement) []Span {
	s := []Span{{Text: "Statement " + strconv.Itoa(index+1)}}
	if st.Sid != "" {
		s = append(s, Span{Text: " (\""}, Span{Text: st.Sid, Mark: "code"}, Span{Text: "\")"})
	}
	at := ", line " + strconv.Itoa(st.FirstLine)
	if st.LastLine != st.FirstLine {
		at = ", lines " + strconv.Itoa(st.FirstLine) + "-" + strconv.Itoa(st.LastLine)
	}
	return append(s, Span{Text: at + ","})
}

// namedPrincipal is the principal a statement names, as how says it: "*"
// as written; for an AWS principal, the principal its ARN names when the
// term reads one from Principal, and otherwise the account it names; a
// service, a SAML provider or another provider by what it is; and a
// principal the parser did not read by the words the rings say it in.
func namedPrincipal(issuer trust.IssuerRef, term []Claim, principal []Leaf) []Span {
	fromPrincipal := func(claim string) bool {
		return slices.ContainsFunc(term, func(c Claim) bool { return c.Claim == claim && len(c.Written) == 0 })
	}
	switch {
	case slices.ContainsFunc(principal, func(l Leaf) bool { return l.Text == "*" }):
		return []Span{{Text: "\""}, {Text: "*", Mark: "code"}, {Text: "\""}}
	case issuer == aws.AWSPrincipalIssuer && !fromPrincipal("aws:principalarn") && fromPrincipal("aws:principalaccount"):
		return []Span{{Text: "this account"}}
	case issuer == aws.AWSPrincipalIssuer:
		return []Span{{Text: "this principal"}}
	case issuer == "":
		return []Span{{Text: "a principal whose kind is not read"}}
	case strings.HasPrefix(string(issuer), aws.ServiceIssuerPrefix):
		return []Span{{Text: "this service"}}
	case aws.IsSAMLIssuer(issuer):
		return []Span{{Text: "this SAML provider"}}
	}
	return []Span{{Text: "this provider"}}
}

// Asking is the answer with each population's question about an owner the
// findings ask about put in the findings' words, which say what that owner
// is to the bundle's account: the account that manages its AWS
// Organization, and the Organization. The answer is copied, never changed
// in place; an owner declared already is asked nothing.
func (a Answer) Asking(asked []Suggestion) Answer {
	grants := slices.Clone(a.Grants)
	for i := range grants {
		pops := slices.Clone(grants[i].Populations)
		for j := range pops {
			if pops[j].Way == nil {
				continue
			}
			way := *pops[j].Way
			way.Questions = slices.Clone(way.Questions)
			for k, q := range way.Questions {
				at := slices.IndexFunc(asked, func(s Suggestion) bool { return !s.Declared && s.Declaration == q.Declaration })
				if at >= 0 {
					words := stripped(spans(asked[at].Question))
					way.Questions[k] = Question{Declaration: q.Declaration, Sentence: plain(words), Spans: words}
				}
			}
			pops[j].Way = &way
		}
		grants[i].Populations = pops
	}
	a.Grants = grants
	return a
}

// declaredPlace reports whether a place is the reader's own: an owner
// declared as yours, or a SAML provider declared as your people's.
func declaredPlace(place string) bool {
	return place == ring.Yours.String() || place == ring.People.String()
}

// Managing is the answer with the fix of each way, for a role AWS made and
// manages for one of its services, the one such a role has: none the
// account can make, since only the service can change its trust policy. It
// is for saying the answer beside what the findings say of the role, as
// Asking is: the answer the findings carry is the trust policy's own, and a
// role nothing is said of is given back as it is. The answer is copied,
// never changed in place.
func (a Answer) Managing(m *Managed) Answer {
	if m == nil {
		return a
	}
	fix := unproven(checkManaged, spans("AWS manages this role's trust policy for ", Span{Text: m.Service, Mark: "code"}, ", and nobody in this account can edit it."))
	grants := slices.Clone(a.Grants)
	for i := range grants {
		pops := slices.Clone(grants[i].Populations)
		for j := range pops {
			if pops[j].Way == nil {
				continue
			}
			way := *pops[j].Way
			way.Fix = fix
			pops[j].Way = &way
		}
		grants[i].Populations = pops
	}
	a.Grants = grants
	return a
}

// ExplainWays is what --explain prints, once the command has answered, of
// who each grant lets in and how: under a heading, each grant by its
// number, and the term when it has several, then for each population who
// it is, each place the principal is written, how the statement lets it in,
// each question asked of its owners, by the declaration that answers it,
// and the fix, with what a proven one takes out, the headline after it and
// the digest of the policy it leaves, for every population but one placed
// as the reader's, which is never told how to shut itself out. role names
// the bundle's role the answer is of, "" for a document. An answer whose
// grants place no population has nothing to say.
func (a Answer) ExplainWays(role string) []string {
	var lines []string
	for _, g := range a.Grants {
		for _, p := range g.Populations {
			if p.Way == nil {
				continue
			}
			if lines == nil {
				heading := "cloudarq admits, who and how:"
				if role != "" {
					heading = "cloudarq admits, who and how, for the role " + strconv.QuoteToASCII(role) + ":"
				}
				lines = []string{heading}
			}
			at := "  grant " + strconv.Itoa(g.Number)
			if len(g.Terms) > 1 {
				at += ", term " + strconv.Itoa(p.Term+1) + " of " + strconv.Itoa(len(g.Terms))
			}
			lines = append(lines, at)
			if p.Way.Who != nil {
				lines = append(lines, "    who  "+plain(p.Way.Who.Spans))
			}
			for _, l := range p.Way.Principal {
				lines = append(lines, "         written "+withoutControls(l.Text)+" at line "+strconv.Itoa(l.Line)+" "+withoutControls(l.Member))
			}
			if p.Way.How != nil {
				lines = append(lines, "    how  "+plain(p.Way.How.Spans))
			}
			for _, q := range p.Way.Questions {
				lines = append(lines, "    ask  "+withoutControls(q.Declaration)+" · "+plain(q.Spans))
			}
			if f := p.Way.Fix; f != nil && !declaredPlace(p.Place) {
				lines = append(lines, "    fix  "+plain(f.Spans))
				if f.ShutsOut != nil {
					lines = append(lines, "         "+plain(f.ShutsOut.Spans))
				}
				if f.After != nil {
					lines = append(lines, "         after it: "+plain(f.After.Spans))
				}
				if f.Edit != nil {
					lines = append(lines, "         sha256 of the policy after it: "+f.Edit.SHA256)
				}
			}
		}
	}
	return lines
}
