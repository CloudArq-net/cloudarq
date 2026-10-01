package report

import (
	"cmp"
	"maps"
	"slices"
	"strconv"
	"strings"

	"github.com/CloudArq-net/cloudarq/internal/eval"
	"github.com/CloudArq-net/cloudarq/internal/parse/aws"
	"github.com/CloudArq-net/cloudarq/internal/parse/casefold"
	"github.com/CloudArq-net/cloudarq/internal/ring"
	"github.com/CloudArq-net/cloudarq/internal/trust"
)

// Explanation is what explain renders: the token as read, the policy's
// answer for it, and for every grant whether it admits the token and,
// claim by claim, why.
//
// Heading and Sentence are the policy's answer, Allow minus Deny across
// every grant: what the explanation says before any grant is read. With
// one grant they are that grant's own.
type Explanation struct {
	V     int    `json:"v"`
	Error string `json:"error,omitempty"`
	Token Token  `json:"token"`
	// Result is the policy's answer as a value, which the heading words: a
	// page reads it rather than the heading's words, and never decides it
	// itself. It is absent when the policy or the token was not read.
	// Values: refused, admitted, not proven, not admitted, not known.
	Result   string    `json:"result,omitempty"`
	Heading  []Span    `json:"heading"`
	Sentence string    `json:"sentence"`
	Spans    []Span    `json:"spans"`
	Grants   []Outcome `json:"grants"`
	// Declarations echoes the declaration the grants were placed with, as
	// the answer of admits does.
	Declarations *Declarations `json:"declarations,omitempty"`
	// Bounds is what can narrow the rings and was not read, as the answer
	// of admits carries it: every outcome names its grant's ring and that
	// ring's state, and a ring printed as exact is printed with the bounds
	// that were not read, in the same view.
	Bounds *Bounds `json:"bounds,omitempty"`
	// beyondABound is Answer's, for the same reason and on the same terms.
	beyondABound bool
}

// Token is the pasted token as the engine read it.
type Token struct {
	Error   string `json:"error,omitempty"`
	Decoded bool   `json:"decoded"` // read from the middle segment of a whole token
	Claims  int    `json:"claims"`
}

// Outcome is one grant's answer for the token.
type Outcome struct {
	Number    int    `json:"number"`
	Statement int    `json:"statement"`
	Sid       string `json:"sid"`
	Issuer    string `json:"issuer"`
	Effect    string `json:"effect"`
	Exact     bool   `json:"exact"`
	// Admitted reports that the grant admits the token: its issuer is the
	// token's, when the token names one, and the engine's Admits holds.
	Admitted bool `json:"admitted"`
	// Witness reports that the token is the grant's own witness.
	Witness  bool      `json:"witness"`
	Heading  []Span    `json:"heading"`
	Sentence string    `json:"sentence"`
	Spans    []Span    `json:"spans"`
	Excludes *Excluded `json:"excludes"`
	// Named lists the claims of the term the token was read against.
	Named  []string       `json:"named"`
	Claims []ClaimOutcome `json:"claims"`
	// Placement and PlacementState are the grant's, as the answer of admits
	// carries them: the ring a token the grant admits comes from.
	// Values: anyone, platform, outsider, yours, people, saml, service,
	// refused, nobody.
	Placement []string `json:"placement,omitempty"`
	// Values: exact, unknown.
	PlacementState string `json:"placementState,omitempty"`
	// notApplied is set for a Deny the parser could not fully evaluate, and
	// so did not apply, that may name the token: what it refuses is not
	// known, so it may refuse the token.
	notApplied bool
}

// Excluded is the engine's explanation of a rejection: the claim whose
// constraint kept the token out, and that constraint as rendered.
type Excluded struct {
	Claim      string `json:"claim"`
	Constraint string `json:"constraint"`
}

// ClaimOutcome is one claim of the token against the grant.
type ClaimOutcome struct {
	Claim string `json:"claim"`
	Value string `json:"value"`
	// ReadFrom is the claim of the token Value was read from, when AWS
	// reads the condition key Claim from a claim of another name, as oaud
	// from aud; it is absent when the two are one.
	ReadFrom   string     `json:"readFrom,omitempty"`
	Constraint Constraint `json:"constraint"`
	Rendered   string     `json:"rendered"`
	Mark       string     `json:"mark,omitempty"`
	// Result is satisfies, fails, not named or not evaluated.
	Result string `json:"result"`
	// Why says, for a claim that fails, what the token carries against
	// what the grant admits, and for one the token leaves unsettled, why
	// it is not evaluated.
	Why     string    `json:"why,omitempty"`
	Note    int       `json:"note,omitempty"`
	Written []Written `json:"written"`
	absent  bool      // the token carries no such claim
}

const (
	satisfies    = "satisfies"
	fails        = "fails"
	notNamed     = "not named"
	notEvaluated = "not evaluated"
	issuerKind   = "issuer"
)

// The policy's results for a token.
const (
	refusedResult     = "refused"
	admittedResult    = "admitted"
	notProvenResult   = "not proven"
	notAdmittedResult = "not admitted"
	notKnownResult    = "not known"
)

// Explain reads a trust policy and a token and renders, for every grant,
// whether the token is admitted and why, with no owner declared.
func Explain(policy, tokenText []byte) []byte { return explainWith(nil, policy, tokenText, nil) }

// AppendExplain appends to dst the explanation Explain renders and returns
// the extended buffer, for the reason AppendAdmits does.
func AppendExplain(dst, policy, tokenText []byte) []byte {
	return explainWith(dst, policy, tokenText, nil)
}

// ExplainFor is Explain with the owners the user declares as theirs,
// one declaration a line. With no owners it is Explain, byte for byte.
func ExplainFor(policy, tokenText, owners []byte) []byte {
	return explainWith(nil, policy, tokenText, owners)
}

// explainWith is the one path the entry points take, kept out of line as
// admitsWith is.
//
//go:noinline
func explainWith(dst, policy, tokenText, owners []byte) []byte {
	e := &encoder{b: dst}
	e.explanation(explain(policy, tokenText, owners))
	return e.b
}

func explain(policy, tokenText, owners []byte) Explanation {
	e := Explanation{V: Version, Heading: []Span{}, Spans: []Span{}, Grants: []Outcome{}}
	r, err := readPolicy(policy)
	if err != nil {
		e.Error, e.beyondABound = err.Error(), beyondABound(err)
		return e
	}
	declared := ring.ReadDeclarations(string(owners))
	if declared.Overrun != nil {
		e.Error, e.beyondABound = overrunWords(*declared.Overrun), true
		return e
	}
	tok, err := readToken(tokenText)
	if err != nil {
		e.Token.Error = err.Error()
		return e
	}
	e.Token = Token{Decoded: tok.decoded, Claims: len(tok.order)}
	// A document with no grant holds no statement, as the answer of admits
	// says, and whether it admits the token is not known: it says so, and
	// nothing the answer does not say, no bounds and no declaration.
	if len(r.grants) == 0 {
		e.Result, e.Heading = notKnownResult, stripped(noStatementForTokenWords())
		return e
	}
	placed := r.place(declared.Owners)
	e.Declarations, e.Bounds = declarationsOf(declared, placed), boundsOf(placed)
	var grants []Grant
	for i := range r.grants {
		grant, err := r.grant(i)
		if err != nil {
			return Explanation{V: Version, Error: "grant " + strconv.Itoa(i+1) + ": " + err.Error(), Grants: []Outcome{}}
		}
		grants = append(grants, grant)
		o := r.outcome(grant, tok)
		o.Placement, o.PlacementState, _ = placementOf(placed[i].placement)
		e.Grants = append(e.Grants, o)
	}
	result, heading, sentence := net(grants, e.Grants)
	e.Result, e.Heading, e.Spans = result, stripped(heading), stripped(sentence)
	e.Sentence = plain(e.Spans)
	return e
}

// net is the policy's answer for the token, as a result and in words: a
// Deny that matches refuses it whatever the Allows say; otherwise an exact
// Allow that matches admits it, unless a Deny may refuse it, as one the
// parser did not apply may; otherwise a
// matching upper bound, an Allow that may admit it, or a statement whose
// effect could not be read, leaves it not excluded and not proven
// admitted; otherwise no grant admits it. A grant may admit or refuse a
// token that leaves a claim it names unsettled. The result is decided once,
// here, whatever the number of grants, and the heading words it. The
// sentence is the roll call of every grant. With one grant the words are
// the grant's own, so the answer says them once.
func net(grants []Grant, outcomes []Outcome) (result string, heading, sentence []Span) {
	var refusing, mayRefuse, admitting, mayAdmit, bounding, unread []int
	for _, o := range outcomes {
		switch {
		case o.Effect == string(trust.Deny) && o.Admitted:
			refusing = append(refusing, o.Number)
		case o.Effect == string(trust.Deny) && (o.unsettled() || o.notApplied):
			mayRefuse = append(mayRefuse, o.Number)
		case !o.Admitted || o.Effect == string(trust.Deny):
		case o.Effect == string(trust.EffectUnknown):
			unread = append(unread, o.Number)
		case o.proven():
			admitting = append(admitting, o.Number)
		case o.Exact:
			mayAdmit = append(mayAdmit, o.Number)
		default:
			bounding = append(bounding, o.Number)
		}
	}
	switch {
	case len(refusing) > 0:
		result = refusedResult
	case len(admitting) > 0 && len(mayRefuse) == 0:
		result = admittedResult
	case len(admitting)+len(mayAdmit)+len(bounding)+len(unread) > 0:
		result = notProvenResult
	default:
		result = notAdmittedResult
	}
	if len(outcomes) == 1 {
		return result, outcomes[0].Heading, outcomes[0].Spans
	}
	matching := slices.Concat(admitting, mayAdmit, bounding, unread)
	switch result {
	case refusedResult:
		heading = spans("Refused by " + grantsNamed(refusing))
		if len(matching) > 0 {
			heading = append(heading, Span{Text: ", though " + grantsNamed(matching) + " " + verbFor(len(matching), "admits", "admit") + " it"})
		}
		heading = append(heading, Span{Text: "."})
	case admittedResult:
		heading = spans("Admitted by " + grantsNamed(admitting) + ".")
	case notProvenResult:
		var parts []string
		if len(admitting) > 0 {
			parts = append(parts, grantsNamed(admitting)+" "+verbFor(len(admitting), "admits", "admit")+" it")
		}
		if len(mayAdmit) > 0 {
			parts = append(parts, grantsNamed(mayAdmit)+" may admit it")
		}
		if len(bounding) > 0 {
			parts = append(parts, grantsNamed(bounding)+" "+verbFor(len(bounding), "is an upper bound", "are upper bounds"))
		}
		if len(unread) > 0 {
			parts = append(parts, effectsUnread(unread))
		}
		if len(mayRefuse) > 0 {
			parts = append(parts, grantsNamed(mayRefuse)+" may refuse it")
		}
		heading = spans("Not excluded, and not proven admitted: ", Span{Text: strings.Join(parts, ", and ") + ".", Mark: "unknown"})
	default:
		heading = spans("Not admitted by any grant.")
	}
	for i := range outcomes {
		if i > 0 {
			sentence = append(sentence, Span{Text: "; "})
		}
		sentence = append(sentence, rollCall(grants[i], outcomes[i])...)
	}
	sentence[0].Text = capitalised(sentence[0].Text)
	if result == refusedResult {
		return result, heading, append(sentence, Span{Text: ": a Deny subtracts from what the Allow statements admit."})
	}
	return result, heading, append(sentence, Span{Text: "."})
}

// rollCall is what one grant did with the token, as a clause.
func rollCall(g Grant, o Outcome) []Span {
	n := "grant " + strconv.Itoa(o.Number)
	switch trust.Effect(o.Effect) {
	case trust.Deny:
		switch {
		case o.Admitted:
			return spans(n + " refuses it")
		case o.unsettled() || o.notApplied:
			return spans(n+" ", Span{Text: "may refuse it", Mark: "unknown"})
		}
		return spans(n + " does not refuse it")
	case trust.EffectUnknown:
		if o.Admitted {
			return spans(n+" matches it, ", Span{Text: "with an effect that could not be read", Mark: "unknown"})
		}
		return spans(n + " does not match it")
	}
	switch {
	case o.Admitted && o.proven():
		return spans(n + " admits it")
	case o.Admitted && o.Exact:
		return spans(n+" ", Span{Text: "may admit it", Mark: "unknown"})
	case o.Admitted:
		return spans(n+" admits it ", Span{Text: "as an upper bound", Mark: "unknown"})
	case g.Empty:
		return spans(n + " admits nobody")
	case o.Excludes != nil:
		return spans(n+" rejects it on ", Span{Text: o.Excludes.Claim, Mark: "code"})
	}
	return spans(n + " rejects it")
}

// grantsNamed names grants in a sentence: "grant 1", "grants 1 and 3".
func grantsNamed(numbers []int) string {
	names := make([]string, len(numbers))
	for i, n := range numbers {
		names[i] = strconv.Itoa(n)
	}
	return verbFor(len(numbers), "grant ", "grants ") + prose(names)
}

func effectsUnread(numbers []int) string {
	if len(numbers) == 1 {
		return grantsNamed(numbers) + "'s effect could not be read"
	}
	return "the effect of " + grantsNamed(numbers) + " could not be read"
}

// outcome reads the token against one grant: the issuer first, then every
// claim against the term the token comes closest to satisfying, then the
// claims the grant does not name, in the token's order. Each condition key
// is read from the claim AWS reads it from, and a claim so read is named by
// the grant.
func (r reading) outcome(g Grant, tok token) Outcome {
	grant := r.grants[g.Number-1]
	o := Outcome{
		Number: g.Number, Statement: g.Statement, Sid: g.Sid, Issuer: g.Issuer, Effect: g.Effect, Exact: g.Exact,
		Named: []string{}, Claims: []ClaimOutcome{},
	}
	reads := readsOf(grant, tok)
	term, failed := closest(grant.Admits, reads, grant.Effect == trust.Deny)
	o.Admitted = len(failed) == 0 && !g.Empty
	for _, k := range failed {
		if reads[k].against(term[k]) == misses {
			o.Excludes = &Excluded{Claim: string(k), Constraint: term[k].String()}
			break
		}
	}
	statement := r.doc.Statements[g.Statement]
	noToken := takesNoToken(grant, statement)
	issuerRuledOut := false
	if issuer := issuerRow(g, tok, noToken); issuer != nil {
		o.Claims = append(o.Claims, *issuer)
		switch {
		case issuer.Result == fails:
			o.Admitted, issuerRuledOut = false, true
			if o.Excludes == nil || noToken {
				o.Excludes = &Excluded{Claim: "iss", Constraint: g.Issuer}
			}
		case issuer.Result == notEvaluated && grant.Effect == trust.Deny:
			// A Deny is applied only where it refuses under every reading,
			// as failures applies it to a claim the token leaves unsettled.
			o.Admitted = false
		}
	}
	at := r.lay.statements[g.Statement]
	readClaims := map[string]bool{}
	for _, k := range slices.Sorted(maps.Keys(term)) {
		o.Named = append(o.Named, string(k))
		o.Claims = append(o.Claims, claimRow(g, at, k, term[k], reads[k]))
		for _, c := range reads[k].claims() {
			readClaims[c] = true
		}
	}
	if grant.Effect == trust.Deny && !g.Exact {
		for _, k := range unappliedClaims(g, at) {
			read := tok.readKey(grant.Issuer, trust.ClaimKey(k))
			o.Claims = append(o.Claims, unappliedRow(g, at, k, read))
			for _, c := range read.claims() {
				readClaims[c] = true
			}
		}
	}
	for _, name := range tok.order {
		if _, named := term[trust.ClaimKey(name)]; named || readClaims[name] || name == "iss" {
			continue
		}
		o.Claims = append(o.Claims, ClaimOutcome{
			Claim: name, Value: tok.values[trust.ClaimKey(name)], Constraint: Constraint{Kind: kindAny}, Rendered: "any",
			Result: notNamed, Mark: beyondMark(g), Written: []Written{},
		})
	}
	o.Witness = g.Witness != "" && g.Witness == payload(grant.Issuer, tok.values)
	o.notApplied = grant.Effect == trust.Deny && !g.Exact && !issuerRuledOut && !assumesWithoutAToken(grant, statement)
	heading, sentence := wording(g, o)
	o.Heading, o.Spans = stripped(heading), stripped(sentence)
	o.Sentence = plain(o.Spans)
	return o
}

// readsOf is what AWS reads from the token for every key the grant's set
// holds, each read once.
func readsOf(g trust.Grant, tok token) map[trust.ClaimKey]keyRead {
	reads := map[trust.ClaimKey]keyRead{}
	for _, term := range g.Admits.Terms() {
		for k := range term {
			if _, done := reads[k]; !done {
				reads[k] = tok.readKey(g.Issuer, k)
			}
		}
	}
	return reads
}

// closest is the term the token comes closest to satisfying, and the
// claims of it the token fails, in claim order: the term with the fewest
// failures, then the one whose first failing claim sorts first, then the
// first in canonical order. This is the engine's own rule for Excludes,
// applied here because Excludes names the claim but not the term, and the
// table shows every claim of one term; it is applied to what AWS reads for
// each key, which Excludes, reading a token's claims by the keys' names,
// cannot be handed. A set with no term has nothing to show.
func closest(admits eval.AdmittedSet, reads map[trust.ClaimKey]keyRead, deny bool) (eval.Term, []trust.ClaimKey) {
	best, bestFailed := eval.Term{}, []trust.ClaimKey{}
	for i, term := range admits.Terms() {
		failed := failures(term, reads, deny)
		if i == 0 || len(failed) < len(bestFailed) || (len(failed) == len(bestFailed) && len(failed) > 0 && failed[0] < bestFailed[0]) {
			best, bestFailed = term, failed
		}
	}
	return best, bestFailed
}

// failures lists the claims of a term the token does not satisfy: a claim
// present must be contained, a claim absent passes only a constraint that
// admits everything. A key whose reading the token leaves unsettled passes
// an Allow, which keeps what the Allow is said to admit an upper bound, and
// fails a Deny, which is applied only where it refuses under every reading.
func failures(term eval.Term, reads map[trust.ClaimKey]keyRead, deny bool) []trust.ClaimKey {
	failed := []trust.ClaimKey{}
	for k, s := range term {
		switch reads[k].against(s) {
		case meets:
			continue
		case open:
			if !deny {
				continue
			}
		}
		failed = append(failed, k)
	}
	slices.Sort(failed)
	return failed
}

// proven reports that the grant's answer for the token is exact: its set
// is, and the token settles every claim the grant names.
func (o Outcome) proven() bool { return o.Exact && !o.unsettled() }

// unsettled reports that the token leaves a claim the grant names open:
// which claim AWS reads it from, or what the token carries there.
func (o Outcome) unsettled() bool {
	return slices.ContainsFunc(o.Claims, func(c ClaimOutcome) bool {
		return c.Result == notEvaluated && c.Constraint.Kind != kindUnknown
	})
}

// takesNoToken reports that no token can be presented through the grant's
// principal. A token is presented through sts:AssumeRoleWithWebIdentity; an
// AWS principal, or a service, assumes a role through sts:AssumeRole, and a
// SAML provider's sign-ins through sts:AssumeRoleWithSAML, as the engine
// places them. A grant that names no issuer, the face of "*" for every
// identity, may admit one, and so may a principal the parser did not model,
// whose grant is filed where the parser put it and vouches for no
// population.
func takesNoToken(g trust.Grant, s aws.Statement) bool {
	i := g.Issuer
	return (i == aws.AWSPrincipalIssuer || strings.HasPrefix(string(i), aws.ServiceIssuerPrefix) || aws.IsSAMLIssuer(i)) && s.ModelsPrincipalOf(g)
}

// assumesWithoutAToken reports that a grant naming no issuer, a face of the
// statement's "*", is one whose actions no token is presented through: the
// parser reads its statement's actions as sts:AssumeRole, through which AWS
// services assume a role, or sts:AssumeRoleWithSAML, or the two, and a token
// is presented through sts:AssumeRoleWithWebIdentity.
func assumesWithoutAToken(g trust.Grant, s aws.Statement) bool {
	return g.Issuer == "" && s.IssuerlessPopulation() != aws.EveryIssuer
}

// issuerRow is the iss row, first in the table: the token's issuer against
// the grant's, compared as the registry keys issuers, when the token
// carries one. A token that carries an issuer is one an identity provider
// issued, which the principal of a grant that takes no token never
// presents. A grant whose issuer is not a URL names none a token could
// carry, and the row says so. A token that names no issuer is read on its
// claims alone, as an AWS principal's are, which is how the admits view
// witnesses such a grant.
func issuerRow(g Grant, tok token, noToken bool) *ClaimOutcome {
	value, present := tok.values["iss"]
	if !present {
		return nil
	}
	row := &ClaimOutcome{Claim: "iss", Value: value, Constraint: Constraint{Kind: issuerKind, Value: g.Issuer}, Rendered: g.Issuer, Written: []Written{}}
	if g.IssuerWritten != nil {
		row.Written = []Written{*g.IssuerWritten}
	}
	switch normalised, ok := trust.NormaliseIssuer(value); {
	case noToken:
		row.Result = fails
		row.Why = plain(whySpans(*row, g.Number))
	case !strings.HasPrefix(g.Issuer, "https://"):
		row.Result, row.Rendered = notNamed, "any"
	case ok && string(normalised) == g.Issuer:
		row.Result = satisfies
	case ok && mayBeIssuer(normalised, trust.IssuerRef(g.Issuer)):
		row.Result, row.Mark = notEvaluated, "unknown"
		row.Why = plain(foldedIssuerSpans(*row, g.Number))
	default:
		row.Result = fails
		row.Why = plain(whySpans(*row, g.Number))
	}
	return row
}

// mayBeIssuer reports whether a token's issuer may be a grant's it is not
// equal to: the paths, which keep their case, are equal, and the hosts, which
// differ, differ in letters outside ASCII that a case folding may make one.
// Both are normalised, so an ASCII letter's case is not what differs. Which
// folding AWS applies to a host beyond ASCII, if any, no AWS page says.
func mayBeIssuer(token, grant trust.IssuerRef) bool {
	tokenHost, tokenPath, _ := strings.Cut(strings.TrimPrefix(string(token), "https://"), "/")
	grantHost, grantPath, _ := strings.Cut(strings.TrimPrefix(string(grant), "https://"), "/")
	return tokenPath == grantPath && casefold.Wide(tokenHost) == casefold.Wide(grantHost)
}

// claimRow is one named claim of the term against what AWS reads for it
// from the token.
func claimRow(g Grant, at statementLayout, k trust.ClaimKey, s eval.StringSet, r keyRead) ClaimOutcome {
	c, err := constraintOf(s)
	if err != nil {
		// The grant rendered this same term without error.
		c = Constraint{Kind: kindUnknown, Reason: err.Error()}
	}
	row := ClaimOutcome{
		Claim: string(k), Value: r.value, Constraint: c, Rendered: s.String(), Mark: markOf(c),
		Written: at.keysFor(string(k), trust.IssuerRef(g.Issuer)), absent: !r.present,
	}
	if r.claim != string(k) {
		row.ReadFrom = r.claim
	}
	switch v := r.against(s); {
	case c.Kind == kindUnknown:
		row.Result = notEvaluated
		row.Note = noteOn(g.Notes, string(k))
	case v == meets:
		row.Result = satisfies
	case v == open:
		row.Result, row.Mark = notEvaluated, "unknown"
		row.Why = plain(unsettledSpans(string(k), r))
	default:
		row.Result = fails
		row.Why = plain(whySpans(row, g.Number))
	}
	return row
}

// unappliedClaims lists, sorted, the claims the conditions of a Deny the
// parser did not apply name. The parser keeps no term for such a Deny, whose
// set is empty, so they are read from the claims its caveats are filed under
// and from the condition keys its statement writes.
func unappliedClaims(g Grant, at statementLayout) []string {
	named := at.claimsNamed(trust.IssuerRef(g.Issuer))
	for _, n := range g.Notes {
		if n.Kind == "caveat" && n.Claim != "" {
			named = append(named, n.Claim)
		}
	}
	slices.Sort(named)
	return slices.Compact(named)
}

// unappliedRow is one claim a Deny the parser did not apply names. No
// constraint of such a Deny is compared with the token, so the claim is not
// evaluated, and its note is the caveat on the claim or, where the claim has
// none, the one on the whole grant, which says why the Deny was not applied.
func unappliedRow(g Grant, at statementLayout, claim string, r keyRead) ClaimOutcome {
	row := ClaimOutcome{
		Claim: claim, Value: r.value, Constraint: Constraint{Kind: kindUnknown}, Rendered: unappliedConstraint, Mark: "unknown",
		Result: notEvaluated, Note: cmp.Or(noteOn(g.Notes, claim), noteOn(g.Notes, "")),
		Written: at.keysFor(claim, trust.IssuerRef(g.Issuer)), absent: !r.present,
	}
	if row.Note > 0 {
		row.Constraint.Reason = g.Notes[row.Note-1].Message
	}
	if r.claim != claim {
		row.ReadFrom = r.claim
	}
	return row
}

// whySpans says why a claim fails: what the token carries, what the grant
// admits, and for a pattern where the two part.
func whySpans(row ClaimOutcome, number int) []Span {
	n := "grant " + strconv.Itoa(number)
	switch issuer := trust.IssuerRef(row.Constraint.Value); {
	case row.Constraint.Kind != issuerKind:
	case !strings.HasPrefix(string(issuer), "https://"):
		return noTokenSpans(n, issuer)
	default:
		return spans("the token was issued by ", Span{Text: row.Value, Mark: "code"}, "; "+n+" admits tokens from "+host(issuer))
	}
	if row.absent {
		s := append(spans("the token carries no "), readFromSpans(row, false)...)
		return append(append(s, Span{Text: "; " + n + " requires "}), row.Constraint.only(row.Claim)...)
	}
	s := append(spans("the token carries ", Span{Text: row.Value, Mark: "code"}), readFromSpans(row, true)...)
	s = append(append(s, Span{Text: "; " + n + " admits only "}), row.Constraint.only(row.Claim)...)
	return append(s, mismatch(row.Constraint, row.Value)...)
}

// only is what the grant admits for the claim, after "admits only". A
// value or a pattern the grant holds is marked exact, as the admits view
// marks it: one value is shown one way on both views.
func (c Constraint) only(claim string) []Span {
	n := noun(claim)
	switch c.Kind {
	case kindExact:
		return []Span{{Text: c.Value, Mark: "exact"}}
	case kindLike:
		return []Span{{Text: "a " + n + " matching "}, {Text: c.Value, Mark: "exact"}}
	case kindIntersection:
		return append([]Span{{Text: "a " + n + " matching all of "}}, list(c.patterns())...)
	case kindUnion:
		out := []Span{{Text: "one of "}}
		for i, m := range c.Members {
			switch {
			case i > 0 && i == len(c.Members)-1:
				out = append(out, Span{Text: " and "})
			case i > 0:
				out = append(out, Span{Text: ", "})
			}
			out = append(out, m.only(claim)...)
		}
		return out
	}
	return []Span{{Text: "any " + n}}
}

func (c Constraint) patterns() []Span {
	out := make([]Span, len(c.Members))
	for i, m := range c.Members {
		out[i] = Span{Text: m.Value, Mark: "exact"}
	}
	return out
}

// list joins spans the way a sentence does: "a", "a and b", "a, b and c".
func list(items []Span) []Span {
	var out []Span
	for i, item := range items {
		switch {
		case i > 0 && i == len(items)-1:
			out = append(out, Span{Text: " and "})
		case i > 0:
			out = append(out, Span{Text: ", "})
		}
		out = append(out, item)
	}
	return out
}

// prose joins items the way a sentence does: "a", "a and b", "a, b and c".
func prose(items []string) string {
	if len(items) <= 1 {
		return strings.Join(items, "")
	}
	return strings.Join(items[:len(items)-1], ", ") + " and " + items[len(items)-1]
}

// mismatch says where a pattern and a value part, when the value departs
// from the pattern's literal opening: after their common prefix, what the
// pattern requires and what the token has there. It is a fact about two
// strings; that the pattern does not match was the engine's decision.
func mismatch(c Constraint, value string) []Span {
	if c.Kind != kindLike {
		return nil
	}
	literal := c.Value
	if i := strings.IndexAny(literal, "*?"); i >= 0 {
		literal = literal[:i]
	}
	if literal == "" || strings.HasPrefix(value, literal) {
		return nil
	}
	want, got := []rune(literal), []rune(value)
	n := 0
	for n < len(want) && n < len(got) && want[n] == got[n] {
		n++
	}
	requires := want[n:]
	has := got[n:]
	if len(has) > len(requires) {
		has = has[:len(requires)]
	}
	s := spans("; after ", Span{Text: string(want[:n]), Mark: "code"}, " the pattern requires ", Span{Text: string(requires), Mark: "code"})
	if len(has) == 0 {
		return append(s, Span{Text: " and the token ends there"})
	}
	return append(s, spans(" and the token has ", Span{Text: string(has), Mark: "code"}, " there")...)
}

// beyondMark colours a claim the grant leaves unconstrained when the grant
// constrains no identity at all.
func beyondMark(g Grant) string {
	if g.Beyond {
		return "beyond"
	}
	return ""
}

// wording is the heading and the sentence of an outcome, in the words of
// the grant's effect.
func wording(g Grant, o Outcome) (heading, sentence []Span) {
	n := "grant " + strconv.Itoa(g.Number)
	var failing, satisfied, unknown, unnamed []ClaimOutcome
	var issuer *ClaimOutcome
	for i := range o.Claims {
		row := o.Claims[i]
		switch {
		case row.Constraint.Kind == issuerKind:
			issuer = &o.Claims[i]
			if row.Result == notEvaluated {
				unknown = append(unknown, row)
			}
		case row.Result == fails:
			failing = append(failing, row)
		case row.Result == satisfies:
			satisfied = append(satisfied, row)
		case row.Result == notEvaluated:
			unknown = append(unknown, row)
		default:
			unnamed = append(unnamed, row)
		}
	}
	switch {
	case o.notApplied && len(unknown) > 0:
		// The claims whose own caveat kept them from being read say why the
		// Deny was not applied; the rest are listed as not evaluated, for the
		// note on the whole grant the heading already words.
		var own, others []ClaimOutcome
		for _, row := range unknown {
			if row.Note > 0 && g.Notes[row.Note-1].Claim == row.Claim {
				own = append(own, row)
			} else {
				others = append(others, row)
			}
		}
		if sentence = rest(n, satisfied, others, unnamed, issuer); len(sentence) > 0 && len(own) > 0 {
			sentence = append(sentence, Span{Text: " "})
		}
		for _, row := range own {
			sentence = append(sentence, unevaluated(row, g.Notes)...)
		}
		last := &sentence[len(sentence)-1]
		last.Text = strings.TrimSuffix(last.Text, " ")
		return notAppliedSpans(n), sentence
	case o.notApplied:
		return notAppliedSpans(n), g.Spans
	case g.Empty:
		return spans(rejected(g.Effect) + ": " + n + " admits nobody."), g.Spans
	case issuer != nil && issuer.Result == fails && !strings.HasPrefix(g.Issuer, "https://"):
		sentence = append(whySpans(*issuer, g.Number), Span{Text: "."})
		sentence[0].Text = capitalised(sentence[0].Text)
		return spans(rejected(g.Effect) + ": " + n + "'s principal presents no token."), sentence
	case issuer != nil && issuer.Result == fails:
		return spans(rejected(g.Effect) + ": not from " + n + "'s issuer."),
			append(spans("Rejected on ", Span{Text: "iss", Mark: "code"}, ": "), append(whySpans(*issuer, g.Number), Span{Text: "."})...)
	case len(failing) > 0:
		heading = spans(rejected(g.Effect) + ": " + count(len(failing), "claim") + " short of " + n + ".")
		for _, row := range failing {
			sentence = append(sentence, spans("Rejected on ", Span{Text: row.Claim, Mark: "code"}, ": ")...)
			sentence = append(sentence, whySpans(row, g.Number)...)
			sentence = append(sentence, Span{Text: ". "})
		}
		return heading, append(sentence, rest(n, satisfied, unknown, unnamed, issuer)...)
	case len(unknown) > 0 || !g.Exact:
		heading = spans("Not excluded, and not proven "+past(g.Effect)+": ", Span{Text: bound(unknown), Mark: "unknown"})
		if sentence = rest(n, satisfied, nil, unnamed, issuer); len(sentence) > 0 {
			sentence = append(sentence, Span{Text: " "})
		}
		for _, row := range unknown {
			sentence = append(sentence, unevaluated(row, g.Notes)...)
		}
		if len(unknown) == 0 {
			sentence = append(sentence, Span{Text: "The set is an upper bound", Mark: "unknown"}, Span{Text: ": "})
			sentence = append(sentence, caveatList(g.Notes)...)
			sentence = append(sentence, Span{Text: ". "})
		}
		if !g.Exact {
			return heading, append(sentence, Span{Text: "The token is " + past(g.Effect) + " by the upper bound, not proven " + past(g.Effect) + " by the policy."})
		}
		// Only the token left a claim unsettled; the set itself is exact.
		last := &sentence[len(sentence)-1]
		last.Text = strings.TrimSuffix(last.Text, " ")
		return heading, sentence
	}
	heading = spans(accepted(g.Effect) + " by " + n + ".")
	if len(o.Named) == 0 {
		sentence = spans(n + " names no claim, so every token from its issuer is " + past(g.Effect) + ".")
	} else {
		sentence = append(spans("Every claim "+n+" names is satisfied: "), claimList(satisfied)...)
		sentence = append(sentence, Span{Text: "."})
	}
	if g.Beyond {
		sentence = append(sentence, spans(" No claim but ", Span{Text: "aud", Mark: "code"}, " is named, so ", Span{Text: "any identity the issuer signs for passes", Mark: "beyond"}, ".")...)
	}
	if o.Witness {
		sentence = append(sentence, Span{Text: " This is the witness from the admits view."})
	}
	return heading, sentence
}

// unevaluated says in a sentence of its own why a claim was not evaluated.
// The reason is the engine's own sentence and may end in a "so" clause of
// its own, so the consequence is a sentence, not a clause.
func unevaluated(row ClaimOutcome, notes []Note) []Span {
	return spans(Span{Text: row.Claim, Mark: "code"}, " was not evaluated: ", Span{Text: reasonFor(row, notes), Mark: "unknown", Note: row.Note}, ". Whether it excludes the token is not decided here. ")
}

// reasonFor is why a claim was not evaluated: the caveat's sentence when
// the grant declares one, why the token leaves it unsettled when it does,
// else the reason the engine's Unknown carries.
func reasonFor(row ClaimOutcome, notes []Note) string {
	switch {
	case row.Note > 0 && row.Note <= len(notes):
		return notes[row.Note-1].Message
	case row.Why != "":
		return row.Why
	}
	return row.Constraint.Reason
}

// rest is the tail of a sentence: what else the token did against the
// grant, as clauses.
func rest(n string, satisfied, unknown, unnamed []ClaimOutcome, issuer *ClaimOutcome) []Span {
	var parts [][]Span
	if len(satisfied) > 0 {
		parts = append(parts, append(claimList(satisfied), Span{Text: " " + verbFor(len(satisfied), "satisfies", "satisfy") + " " + n}))
	}
	if len(unknown) > 0 {
		parts = append(parts, append(claimList(unknown), Span{Text: " " + verbFor(len(unknown), "was", "were") + " not evaluated"}))
	}
	if issuer != nil && issuer.Result == satisfies {
		parts = append(parts, spans(Span{Text: "iss", Mark: "code"}, " is "+n+"'s issuer"))
	}
	if len(unnamed) > 0 {
		parts = append(parts, spans("the other "+count(len(unnamed), "claim")+" "+verbFor(len(unnamed), "is", "are")+" not named by it"))
	}
	if len(parts) == 0 {
		return nil
	}
	var out []Span
	for i, p := range parts {
		switch {
		case i > 0 && i == len(parts)-1:
			out = append(out, Span{Text: ", and "})
		case i > 0:
			out = append(out, Span{Text: ", "})
		}
		out = append(out, p...)
	}
	if out[0].Mark == "" {
		out[0].Text = capitalised(out[0].Text)
	}
	return append(out, Span{Text: "."})
}

// claimList names claims in a sentence: "aud, repository_owner_id and sub".
func claimList(rows []ClaimOutcome) []Span {
	var out []Span
	for i, row := range rows {
		switch {
		case i > 0 && i == len(rows)-1:
			out = append(out, Span{Text: " and "})
		case i > 0:
			out = append(out, Span{Text: ", "})
		}
		out = append(out, Span{Text: row.Claim, Mark: "code"})
	}
	return out
}

// caveatList names every caveat of a grant, each a reference to its note.
func caveatList(notes []Note) []Span {
	var out []Span
	for _, note := range notes {
		if note.Kind != "caveat" {
			continue
		}
		if len(out) > 0 {
			out = append(out, Span{Text: "; "})
		}
		out = append(out, Span{Text: note.Message, Mark: "unknown", Note: note.Number})
	}
	return out
}

func bound(unknown []ClaimOutcome) string {
	if len(unknown) == 0 {
		return "the set is an upper bound."
	}
	names := make([]string, len(unknown))
	for i, row := range unknown {
		names[i] = row.Claim
	}
	return prose(names) + " " + verbFor(len(unknown), "was", "were") + " not evaluated."
}

func count(n int, word string) string {
	if n == 1 {
		return "one " + word
	}
	return strconv.Itoa(n) + " " + word + "s"
}

func verbFor(n int, singular, plural string) string {
	if n == 1 {
		return singular
	}
	return plural
}

// The outcome words, by effect: what a grant does to a token it matches.
func accepted(effect string) string {
	switch trust.Effect(effect) {
	case trust.Allow:
		return "Admitted"
	case trust.Deny:
		return "Refused"
	}
	return "Matched, by a statement whose effect could not be read,"
}

func rejected(effect string) string {
	switch trust.Effect(effect) {
	case trust.Allow:
		return "Not admitted"
	case trust.Deny:
		return "Not refused"
	}
	return "Not matched"
}

func past(effect string) string {
	switch trust.Effect(effect) {
	case trust.Allow:
		return "admitted"
	case trust.Deny:
		return "refused"
	}
	return "matched"
}
