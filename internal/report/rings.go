package report

import (
	"slices"
	"strings"

	"github.com/CloudArq-net/cloudarq/internal/parse/aws"
	"github.com/CloudArq-net/cloudarq/internal/ring"
)

// rings sets what the answer says of the rings: the five rows, in order,
// each with the grants whose outermost place it is; the lines beside them
// that hold a grant; the grants in no ring; the owners declared; what was
// not read that could narrow them; and the headline. The grants are listed
// by number and never copied, so a row cannot say something of a grant
// that the grant itself does not.
func (a *Answer) rings(placed []placed, declared ring.Declarations) {
	// A document with no grant holds no statement, since the parser
	// projects at least one grant from every statement, and IAM holds no
	// such policy, so the paste is not the role's. Nothing was read to place
	// in a ring: the headline says who can assume the role is not known,
	// and nothing after it is said, since an empty ring is a finding and a
	// declaration has nothing here to move.
	if len(placed) == 0 {
		a.Headline = sentence(noStatementWords())
		return
	}
	var refused, nobody []int
	for _, p := range placed {
		switch p.placement.Outcome {
		case ring.Refused:
			refused = append(refused, p.number)
		case ring.Nobody:
			nobody = append(nobody, p.number)
		}
	}
	var rows, lines []row
	for place := ring.Anyone; place <= ring.Service; place++ {
		r := rowOf(place, placed)
		if place.Ring() {
			rows = append(rows, r)
		} else if len(r.grants) > 0 {
			lines = append(lines, r)
		}
	}
	// Who can make a service act, or receives its session, is not read, and
	// nothing read rules out people with no account anywhere: IAM Roles
	// Anywhere hands a role's session to whoever holds a certificate its
	// trust anchor accepts. So the ring of anyone is not established while
	// the line of cloud services holds a grant, whatever that line's own
	// state: reading which account a service acts for could make the line
	// exact, and would still say nothing of who receives the session. Who a
	// SAML provider signs in is not read either, so the ring is not
	// established beside sign-ins not let in for certain. A provider declared
	// as the user's is one too, in the ring of your people: a
	// declaration moves where a population is placed, never what is known of
	// it, and says whose the provider is, not whom it signs in.
	saml := lineOf(lines, ring.SAML)
	if lineOf(lines, ring.Service) != nil || saml != nil && saml.uncertain() || rows[ring.People].uncertain() {
		rows[ring.Anyone].state = ring.StateUnknown
	}
	for _, r := range rows {
		a.Rings = append(a.Rings, r.answer())
	}
	for _, r := range lines {
		a.Beside = append(a.Beside, r.answer())
	}
	a.Headline = sentence(headline(rows, lines))
	if len(refused) > 0 {
		a.Refused = listing(refused, refusedWords(refused))
	}
	if len(nobody) > 0 {
		a.Nobody = listing(nobody, nobodyWords(nobody))
	}
	a.Declarations = declarationsOf(declared, placed)
	a.Bounds = boundsOf(placed)
}

// row is one ring or line as the words read it: where it is, its state,
// and the grants whose place it is, each with its placement.
type row struct {
	place  ring.Place
	state  ring.State
	grants []placed
}

// rowOf is the row of a place. A grant belongs to a ring when that ring is
// the outermost its terms reach, and to a line when a term reaches the
// line. A row is exact when a population at its place is, which is what
// reaching it for certain takes, and a row no grant is in is exact too:
// nothing was placed there. Whether a line beside the rings leaves the
// ring of anyone unknown is decided where every row is seen, in rings.
func rowOf(place ring.Place, placed []placed) row {
	r := row{place: place, state: ring.StateExact}
	for _, p := range placed {
		if p.placement.Outcome == ring.Placed && p.reaches(place) {
			r.grants = append(r.grants, p)
		}
	}
	if len(r.grants) > 0 && !slices.ContainsFunc(r.populations(), certain) {
		r.state = ring.StateUnknown
	}
	return r
}

// reaches reports whether place is one of the grant's places.
func (p placed) reaches(place ring.Place) bool {
	for _, at := range p.placement.Places {
		if at == place {
			return true
		}
	}
	return false
}

// population is one population at a row's place, with the grant it is of.
type population struct {
	grant placed
	ring.Population
}

// certain reports whether a grant lets the population in for certain.
func certain(p population) bool { return p.State == ring.StateExact }

// uncertain reports whether a population at the row's place is not let in
// for certain.
func (r row) uncertain() bool {
	return slices.ContainsFunc(r.populations(), func(p population) bool { return !certain(p) })
}

// populations are the populations of the row's grants at its place, in
// the order of the grants and then of their terms. A row's words are said
// of these, each with its own state: one grant reaching a ring for certain
// makes the ring exact, and lends nothing to a population another grant
// placed there as unknown.
func (r row) populations() []population {
	var out []population
	for _, p := range r.grants {
		for _, pop := range p.placement.Populations {
			if pop.Place == r.place {
				out = append(out, population{grant: p, Population: pop})
			}
		}
	}
	return out
}

// leading is what a row's sentence leads with: the populations a grant lets
// in for certain, when there are any, which can assume the role, and
// otherwise every one, which could.
func (r row) leading() (pops []population, sure bool) {
	all := r.populations()
	for _, p := range all {
		if certain(p) {
			pops = append(pops, p)
		}
	}
	if len(pops) > 0 {
		return pops, true
	}
	return all, false
}

// numbers are the row's grants by number.
func (r row) numbers() []int {
	out := []int{}
	for _, p := range r.grants {
		out = append(out, p.number)
	}
	return out
}

// answer is the row as the answer carries it.
func (r row) answer() Row {
	spans := stripped(rowWords(r))
	out := Row{Place: r.place.String(), Label: withoutControls(label(r)), State: r.state.String(), GrantNumbers: r.numbers(), Sentence: plain(spans), Spans: spans}
	for _, q := range r.questions() {
		asked := stripped(questionWords(q))
		out.Questions = append(out.Questions, Question{Declaration: q.Declaration(), Sentence: plain(asked), Spans: asked})
	}
	var cited []Citation
	switch {
	case slices.ContainsFunc(r.populations(), func(p population) bool { return p.Basis == ring.AnyIssuer }):
		cited = readingOfAWS()
	case r.place == ring.Service:
		cited = readingOfIntermediaries(r.intermediaries())
	}
	if len(cited) > 0 {
		out.CitationsHeading, out.Citations = withoutControls(citationsHeading(r)), cited
	}
	return out
}

// questions are the owners the row may ask about: on a named outsider's
// row, each owner the declaration grammar has a form for that nobody has,
// and on the line of SAML sign-ins, each provider, which is declarable and
// declared by nobody.
func (r row) questions() []named {
	if r.place != ring.Outsider && r.place != ring.SAML {
		return nil
	}
	var out []named
	for _, o := range r.owners() {
		if !o.Declared && o.Declaration() != "" {
			out = append(out, o)
		}
	}
	return out
}

// sentence is a run of spans as the answer carries a sentence.
func sentence(spans []Span) *Sentence {
	spans = stripped(spans)
	return &Sentence{Sentence: plain(spans), Spans: spans}
}

func listing(numbers []int, spans []Span) *Listing {
	spans = stripped(spans)
	return &Listing{GrantNumbers: numbers, Sentence: plain(spans), Spans: spans}
}

// declarationsOf is the declaration as the answer echoes it: the owners in
// their one normalised form, each refused line as it was written, with why,
// and each owner declared that no grant which admits is pinned to, with
// why.
func declarationsOf(d ring.Declarations, placed []placed) *Declarations {
	out := &Declarations{Normalised: []string{}, RefusedLines: []RefusedLine{}, Unmatched: []UnmatchedOwner{}}
	for _, owner := range d.Owners {
		out.Normalised = append(out.Normalised, owner.String())
		if matched, spelledLike := match(owner, placed); !matched {
			out.Unmatched = append(out.Unmatched, UnmatchedOwner{Declaration: owner.String(), Sentence: withoutControls(unmatchedWords(spelledLike))})
		}
	}
	for _, r := range d.Refused {
		out.RefusedLines = append(out.RefusedLines, RefusedLine{Line: r.Line, Text: r.Text, Reason: r.Reason.String(), Sentence: refusalWords(r.Reason)})
	}
	return out
}

// OwnerRefused is why one owner declared on its own, one line, declares no
// owner, in the words the answer echoes a refused line with, or "" when it
// declares one. A blank line declares nothing and is refused here, though a
// declaration of many lines skips it: one owner given alone and blank was
// meant to declare someone. A line past the engine's bounds is not refused
// here; the whole declaration is, as the answer's error.
func OwnerRefused(owner string) string {
	d := ring.ReadDeclarations(owner)
	switch {
	case d.Overrun != nil:
		return ""
	case len(d.Refused) > 0:
		return refusalWords(d.Refused[0].Reason)
	case len(d.Owners) == 0:
		return blankWords
	}
	return ""
}

// match reports whether the declaration names an owner some grant that
// admits is pinned to, by the classifier's own rule; and, when it names
// none, the first pinned owner whose declaration it is in another letter
// case, as the declaration a reader who wrote it most likely meant.
func match(d ring.Declaration, placed []placed) (matched bool, spelledLike *ring.Owner) {
	for _, p := range placed {
		for _, pop := range p.placement.Populations {
			for i, o := range pop.Owners {
				switch {
				case d.Names(o, p.facts):
					return true, nil
				case spelledLike == nil && d.SpelledLike(o):
					spelledLike = &pop.Owners[i]
				}
			}
		}
	}
	return false, spelledLike
}

// boundsOf is what was not read and can narrow the rings: the three every
// answer carries, and, for each issuer that mints tokens to people with no
// account, its own settings, each with its sentence, and the line that
// names them all.
func boundsOf(placed []placed) *Bounds {
	b := &Bounds{}
	var names []string
	add := func(id, issuer, platform string) {
		b.Items = append(b.Items, Bound{Bound: id, Issuer: issuer, Sentence: withoutControls(boundWords(id, platform))})
		names = append(names, boundName(id, platform))
	}
	for _, id := range []string{rcpBound, scpBound, providersBound} {
		add(id, "", "")
	}
	for _, p := range placed {
		if p.mintsWithoutAccounts() && !containsIssuer(b.Items, string(p.issuer)) {
			add(settingsBound, string(p.issuer), p.platform)
		}
	}
	b.Sentence = withoutControls(boundsWords(names))
	return b
}

// mintsWithoutAccounts reports whether a term of the grant is placed with
// anyone because its issuer mints tokens to people with no account.
func (p placed) mintsWithoutAccounts() bool {
	for _, pop := range p.placement.Populations {
		if pop.Basis == ring.TokensWithoutAccount {
			return true
		}
	}
	return false
}

func containsIssuer(items []Bound, issuer string) bool {
	for _, b := range items {
		if b.Issuer == issuer {
			return true
		}
	}
	return false
}

// platforms are the platforms the row's populations are on, each once, in
// the order of the grants: those a population is on for certain, and then
// the rest.
func (r row) platforms() (sure, unsure []string) {
	pops := r.populations()
	for _, p := range pops {
		if certain(p) && !slices.Contains(sure, p.grant.platform) {
			sure = append(sure, p.grant.platform)
		}
	}
	for _, p := range pops {
		if !slices.Contains(sure, p.grant.platform) && !slices.Contains(unsure, p.grant.platform) {
			unsure = append(unsure, p.grant.platform)
		}
	}
	return sure, unsure
}

// reason is why populations are placed where they are, for a sentence that
// gives one: the basis they share, when they share one, and the grant of
// the first, whose issuer that sentence names when every one of them is on
// it.
func reason(pops []population) (basis ring.Basis, first placed, shared, oneIssuer bool) {
	basis, first = pops[0].Basis, pops[0].grant
	shared, oneIssuer = true, true
	for _, p := range pops {
		shared = shared && p.Basis == basis
		oneIssuer = oneIssuer && p.grant.issuer == first.issuer
	}
	return basis, first, shared, oneIssuer
}

// named is one owner a row names, by its name in a sentence, and whether a
// grant lets it in for certain.
type named struct {
	ring.Owner
	name string
	sure bool
}

// owners are the owners the populations here are pinned to, each once, in
// the order of the grants. In a ring of the user's own they are the
// declared ones: a pin that also names an undeclared owner there only
// narrows. In any other ring they are every one, declared or not, since a
// pin naming an outsider beside a declared owner admits both.
func (r row) owners() []named {
	declaredOnly := r.place == ring.Yours || r.place == ring.People
	var out []named
	for _, p := range r.populations() {
		for _, o := range p.Owners {
			if declaredOnly && !o.Declared {
				continue
			}
			name := ownerName(o)
			if i := slices.IndexFunc(out, func(n named) bool { return n.name == name }); i >= 0 {
				out[i].sure = out[i].sure || certain(p)
				continue
			}
			out = append(out, named{Owner: o, name: name, sure: certain(p)})
		}
	}
	return out
}

// saml is whether a population here is the face of "*" on every SAML
// provider in the role's account, and the names of the providers the
// others trust.
func (r row) saml() (face bool, providers []string) {
	for _, p := range r.populations() {
		face = face || p.Basis == ring.AccountSAMLProviders
		for _, o := range p.Owners {
			if name := providerName(o.Value); !slices.Contains(providers, name) {
				providers = append(providers, name)
			}
		}
	}
	return face, providers
}

// services is whether a population here is the face of "*" on every AWS
// service, and the names of the services the others trust.
func (r row) services() (face bool, services []string) {
	for _, p := range r.populations() {
		face = face || p.Basis == ring.AnyService
		if name, ok := strings.CutPrefix(string(p.grant.issuer), aws.ServiceIssuerPrefix); ok && !slices.Contains(services, name) {
			services = append(services, name)
		}
	}
	return face, services
}

// intermediaries are the services on the row that the parser's table of
// intermediaries lists, in the order the row names its services.
func (r row) intermediaries() []aws.Intermediary {
	_, services := r.services()
	var out []aws.Intermediary
	for _, name := range services {
		if i, ok := aws.IntermediaryOf(name); ok {
			out = append(out, i)
		}
	}
	return out
}

// oneService reports whether the line of cloud services is one named
// service.
func (r row) oneService() bool {
	face, services := r.services()
	return !face && len(services) == 1
}

// lineOf is the line at place, or nil when it holds no grant.
func lineOf(lines []row, place ring.Place) *row {
	for i := range lines {
		if lines[i].place == place {
			return &lines[i]
		}
	}
	return nil
}
