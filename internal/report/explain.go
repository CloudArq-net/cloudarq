package report

import (
	"maps"
	"slices"
	"strconv"
	"strings"

	"github.com/CloudArq-net/cloudarq/internal/eval"
	"github.com/CloudArq-net/cloudarq/internal/trust"
)

// Explanation is what explain renders: the token as read, the policy's
// answer for it, and for every grant whether it admits the token and,
// claim by claim, why.
//
// Heading and Sentence are the policy's answer, Allow minus Deny across
// every grant: what a link's text says before any grant is read. With one
// grant they are that grant's own.
type Explanation struct {
	V        int       `json:"v"`
	Error    string    `json:"error,omitempty"`
	Token    Token     `json:"token"`
	Heading  []Span    `json:"heading"`
	Sentence string    `json:"sentence"`
	Spans    []Span    `json:"spans"`
	Grants   []Outcome `json:"grants"`
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
}

// Excluded is the engine's explanation of a rejection: the claim whose
// constraint kept the token out, and that constraint as rendered.
type Excluded struct {
	Claim      string `json:"claim"`
	Constraint string `json:"constraint"`
}

// ClaimOutcome is one claim of the token against the grant.
type ClaimOutcome struct {
	Claim      string     `json:"claim"`
	Value      string     `json:"value"`
	Constraint Constraint `json:"constraint"`
	Rendered   string     `json:"rendered"`
	Mark       string     `json:"mark,omitempty"`
	// Result is satisfies, fails, not named or not evaluated.
	Result string `json:"result"`
	// Why says, for a claim that fails, what the token carries against
	// what the grant admits.
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

// Explain reads a trust policy and a token and renders, for every grant,
// whether the token is admitted and why.
func Explain(policy, tokenText []byte) []byte {
	e := &encoder{}
	e.explanation(explain(policy, tokenText))
	return e.b
}

func explain(policy, tokenText []byte) Explanation {
	e := Explanation{V: Version, Heading: []Span{}, Spans: []Span{}, Grants: []Outcome{}}
	r, err := readPolicy(policy)
	if err != nil {
		e.Error, e.beyondABound = err.Error(), beyondABound(err)
		return e
	}
	tok, err := readToken(tokenText)
	if err != nil {
		e.Token.Error = err.Error()
		return e
	}
	e.Token = Token{Decoded: tok.decoded, Claims: len(tok.order)}
	var grants []Grant
	for i := range r.grants {
		grant, err := r.grant(i)
		if err != nil {
			return Explanation{V: Version, Error: "grant " + strconv.Itoa(i+1) + ": " + err.Error(), Grants: []Outcome{}}
		}
		grants = append(grants, grant)
		e.Grants = append(e.Grants, r.outcome(grant, tok))
	}
	heading, sentence := net(grants, e.Grants)
	e.Heading, e.Spans = stripped(heading), stripped(sentence)
	e.Sentence = plain(e.Spans)
	return e
}

// net is the policy's answer for the token: a Deny that matches refuses it
// whatever the Allows say; otherwise an exact Allow that matches admits it;
// otherwise a matching upper bound, or a statement whose effect could not
// be read, leaves it not excluded and not proven admitted; otherwise no
// grant admits it. The sentence is the roll call of every grant. With one
// grant the answer is the grant's own, so the page says it once.
func net(grants []Grant, outcomes []Outcome) (heading, sentence []Span) {
	switch len(outcomes) {
	case 0:
		return spans("Not admitted: the policy has no grant."), []Span{}
	case 1:
		return outcomes[0].Heading, outcomes[0].Spans
	}
	var refusing, admitting, bounding, unread []int
	for _, o := range outcomes {
		if !o.Admitted {
			continue
		}
		switch {
		case o.Effect == string(trust.Deny):
			refusing = append(refusing, o.Number)
		case o.Effect == string(trust.EffectUnknown):
			unread = append(unread, o.Number)
		case o.Exact:
			admitting = append(admitting, o.Number)
		default:
			bounding = append(bounding, o.Number)
		}
	}
	matching := slices.Concat(admitting, bounding, unread)
	switch {
	case len(refusing) > 0:
		heading = spans("Refused by " + grantsNamed(refusing))
		if len(matching) > 0 {
			heading = append(heading, Span{Text: ", though " + grantsNamed(matching) + " " + verbFor(len(matching), "admits", "admit") + " it"})
		}
		heading = append(heading, Span{Text: "."})
	case len(admitting) > 0:
		heading = spans("Admitted by " + grantsNamed(admitting) + ".")
	case len(bounding)+len(unread) > 0:
		var parts []string
		if len(bounding) > 0 {
			parts = append(parts, grantsNamed(bounding)+" "+verbFor(len(bounding), "is an upper bound", "are upper bounds"))
		}
		if len(unread) > 0 {
			parts = append(parts, effectsUnread(unread))
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
	sentence[0].Text = strings.ToUpper(sentence[0].Text[:1]) + sentence[0].Text[1:]
	if len(refusing) > 0 {
		return heading, append(sentence, Span{Text: ": a Deny subtracts from what the Allow statements admit."})
	}
	return heading, append(sentence, Span{Text: "."})
}

// rollCall is what one grant did with the token, as a clause.
func rollCall(g Grant, o Outcome) []Span {
	n := "grant " + strconv.Itoa(o.Number)
	switch trust.Effect(o.Effect) {
	case trust.Deny:
		if o.Admitted {
			return spans(n + " refuses it")
		}
		return spans(n + " does not refuse it")
	case trust.EffectUnknown:
		if o.Admitted {
			return spans(n+" matches it, ", Span{Text: "with an effect that could not be read", Mark: "unknown"})
		}
		return spans(n + " does not match it")
	}
	switch {
	case o.Admitted && o.Exact:
		return spans(n + " admits it")
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
// claims the grant does not name, in the token's order.
func (r reading) outcome(g Grant, tok token) Outcome {
	grant := r.grants[g.Number-1]
	o := Outcome{
		Number: g.Number, Statement: g.Statement, Sid: g.Sid, Issuer: g.Issuer, Effect: g.Effect, Exact: g.Exact,
		Named: []string{}, Claims: []ClaimOutcome{},
	}
	term, failed := closest(grant.Admits, tok.values)
	o.Admitted = len(failed) == 0 && !g.Empty
	if claim, got, ok := grant.Admits.Excludes(tok.values); ok && claim != "" {
		o.Excludes = &Excluded{Claim: string(claim), Constraint: got.String()}
	}
	if issuer := issuerRow(g, tok); issuer != nil {
		o.Claims = append(o.Claims, *issuer)
		if issuer.Result == fails {
			o.Admitted = false
			if o.Excludes == nil {
				o.Excludes = &Excluded{Claim: "iss", Constraint: g.Issuer}
			}
		}
	}
	at := r.lay.statements[g.Statement]
	for _, k := range slices.Sorted(maps.Keys(term)) {
		o.Named = append(o.Named, string(k))
		value, present := tok.values[k]
		o.Claims = append(o.Claims, claimRow(g, at, k, term[k], value, present))
	}
	for _, name := range tok.order {
		if _, named := term[trust.ClaimKey(name)]; named || name == "iss" {
			continue
		}
		o.Claims = append(o.Claims, ClaimOutcome{
			Claim: name, Value: tok.values[trust.ClaimKey(name)], Constraint: Constraint{Kind: kindAny}, Rendered: "any",
			Result: notNamed, Mark: beyondMark(g), Written: []Written{},
		})
	}
	o.Witness = g.Witness != "" && g.Witness == payload(grant.Issuer, tok.values)
	heading, sentence := wording(g, o)
	o.Heading, o.Spans = stripped(heading), stripped(sentence)
	o.Sentence = plain(o.Spans)
	return o
}

// closest is the term the token comes closest to satisfying, and the
// claims of it the token fails, in claim order: the term with the fewest
// failures, then the one whose first failing claim sorts first, then the
// first in canonical order. This is the engine's own rule for Excludes,
// applied here because Excludes names the claim but not the term, and the
// table shows every claim of one term. A set with no term has nothing to
// show.
func closest(admits eval.AdmittedSet, values map[trust.ClaimKey]string) (eval.Term, []trust.ClaimKey) {
	best, bestFailed := eval.Term{}, []trust.ClaimKey{}
	for i, term := range admits.Terms() {
		failed := failures(term, values)
		if i == 0 || len(failed) < len(bestFailed) || (len(failed) == len(bestFailed) && len(failed) > 0 && failed[0] < bestFailed[0]) {
			best, bestFailed = term, failed
		}
	}
	return best, bestFailed
}

// failures lists the claims of a term the token does not satisfy: a claim
// present must be contained, a claim absent passes only a constraint that
// admits everything.
func failures(term eval.Term, values map[trust.ClaimKey]string) []trust.ClaimKey {
	failed := []trust.ClaimKey{}
	for k, s := range term {
		v, present := values[k]
		if (present && s.Contains(v)) || (!present && s.IsTop()) {
			continue
		}
		failed = append(failed, k)
	}
	slices.Sort(failed)
	return failed
}

// issuerRow is the iss row, first in the table: the token's issuer against
// the grant's, compared as the registry keys issuers, when the token
// carries one. A grant whose issuer is not a URL names none a token could
// carry, and the row says so.
func issuerRow(g Grant, tok token) *ClaimOutcome {
	value, present := tok.values["iss"]
	if !present {
		return nil
	}
	row := &ClaimOutcome{Claim: "iss", Value: value, Constraint: Constraint{Kind: issuerKind, Value: g.Issuer}, Rendered: g.Issuer, Written: []Written{}}
	if g.IssuerWritten != nil {
		row.Written = []Written{*g.IssuerWritten}
	}
	switch normalised, ok := trust.NormaliseIssuer(value); {
	case !strings.HasPrefix(g.Issuer, "https://"):
		row.Result, row.Rendered = notNamed, "any"
	case ok && string(normalised) == g.Issuer:
		row.Result = satisfies
	default:
		row.Result = fails
		row.Why = plain(whySpans(*row, g.Number))
	}
	return row
}

// claimRow is one named claim of the term against the token's value.
func claimRow(g Grant, at statementLayout, k trust.ClaimKey, s eval.StringSet, value string, present bool) ClaimOutcome {
	c, err := constraintOf(s)
	if err != nil {
		// The grant rendered this same term without error.
		c = Constraint{Kind: kindUnknown, Reason: err.Error()}
	}
	row := ClaimOutcome{
		Claim: string(k), Value: value, Constraint: c, Rendered: s.String(), Mark: markOf(c),
		Written: at.keysFor(string(k), trust.IssuerRef(g.Issuer)), absent: !present,
	}
	switch {
	case c.Kind == kindUnknown:
		row.Result = notEvaluated
		row.Note = noteOn(g.Notes, string(k))
	case present && s.Contains(value):
		row.Result = satisfies
	default:
		row.Result = fails
		row.Why = plain(whySpans(row, g.Number))
	}
	return row
}

// whySpans says why a claim fails: what the token carries, what the grant
// admits, and for a pattern where the two part.
func whySpans(row ClaimOutcome, number int) []Span {
	n := "grant " + strconv.Itoa(number)
	if row.Constraint.Kind == issuerKind {
		return spans("the token was issued by ", Span{Text: row.Value, Mark: "code"}, "; "+n+" admits tokens from "+host(trust.IssuerRef(row.Constraint.Value)))
	}
	if row.absent {
		return append(spans("the token carries no ", Span{Text: row.Claim, Mark: "code"}, "; "+n+" requires "), row.Constraint.only(row.Claim)...)
	}
	s := append(spans("the token carries ", Span{Text: row.Value, Mark: "code"}, "; "+n+" admits only "), row.Constraint.only(row.Claim)...)
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
	case g.Empty:
		return spans(rejected(g.Effect) + ": " + n + " admits nobody."), g.Spans
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
		// the reason is the engine's own sentence and may end in a "so"
		// clause of its own, so the consequence is a sentence, not a clause
		for _, row := range unknown {
			sentence = append(sentence, spans(Span{Text: row.Claim, Mark: "code"}, " was not evaluated: ", Span{Text: reasonFor(row, g.Notes), Mark: "unknown", Note: row.Note}, ". Whether it excludes the token is not decided here. ")...)
		}
		if len(unknown) == 0 {
			sentence = append(sentence, Span{Text: "The set is an upper bound", Mark: "unknown"}, Span{Text: ": "})
			sentence = append(sentence, caveatList(g.Notes)...)
			sentence = append(sentence, Span{Text: ". "})
		}
		return heading, append(sentence, Span{Text: "The token is " + past(g.Effect) + " by the upper bound, not proven " + past(g.Effect) + " by the policy."})
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

// reasonFor is why a claim was not evaluated: the caveat's sentence when
// the grant declares one, else the reason the engine's Unknown carries.
func reasonFor(row ClaimOutcome, notes []Note) string {
	if row.Note > 0 && row.Note <= len(notes) {
		return notes[row.Note-1].Message
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
		out[0].Text = strings.ToUpper(out[0].Text[:1]) + out[0].Text[1:]
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
