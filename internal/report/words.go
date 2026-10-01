package report

import (
	"slices"
	"strconv"
	"strings"

	"github.com/CloudArq-net/cloudarq/internal/parse/aws"
	"github.com/CloudArq-net/cloudarq/internal/registry"
	"github.com/CloudArq-net/cloudarq/internal/ring"
	"github.com/CloudArq-net/cloudarq/internal/trust"
)

// The words of the answer. A grant's own sentence is neutral about the
// issuer: what a subject is made of, or which claim names the tenant,
// belongs to the registry, and the sentence says what the engine holds and
// nothing it does not. The rings' words, further down, name what the
// registry and the classifier established, and no more.

// noun is the word for a claim's value in a phrase. The standard claims
// have names of their own; any other claim's value is a value.
func noun(claim string) string {
	switch claim {
	case "aud":
		return "audience"
	case "sub":
		return "subject"
	case "iss":
		return "issuer"
	}
	return "value"
}

// words is the constraint as the table's "in words" column says it.
func (c Constraint) words(claim string) string {
	n := noun(claim)
	switch c.Kind {
	case kindExact:
		return "exactly this " + n
	case kindLike:
		if prefix, ok := strings.CutSuffix(c.Value, "*"); ok && !strings.ContainsAny(prefix, "*?") {
			return "any " + n + " beginning " + prefix
		}
		if suffix, ok := strings.CutPrefix(c.Value, "*"); ok && !strings.ContainsAny(suffix, "*?") {
			return "any " + n + " ending " + suffix
		}
		return "any " + n + " matching this pattern"
	case kindUnion:
		return "any of these " + strconv.Itoa(len(c.Members)) + " alternatives"
	case kindIntersection:
		return "any " + n + " matching all " + strconv.Itoa(len(c.Members)) + " patterns"
	case kindUnknown:
		return "not evaluated"
	}
	return "unconstrained"
}

// clause is the constraint as a sentence says it, after the claim: "is
// sts.amazonaws.com", "matches repo:acme/*".
func (c Constraint) clause() []Span {
	switch c.Kind {
	case kindExact:
		return []Span{{Text: " is "}, {Text: c.Value, Mark: "exact"}}
	case kindLike:
		return []Span{{Text: " matches "}, {Text: c.Value, Mark: "exact"}}
	case kindUnion:
		spans := []Span{{Text: " is one of "}}
		for i, m := range c.Members {
			if i > 0 {
				spans = append(spans, Span{Text: ", "})
			}
			spans = append(spans, m.alternative()...)
		}
		return spans
	case kindIntersection:
		spans := []Span{{Text: " matches all of "}}
		for i, m := range c.Members {
			if i > 0 {
				spans = append(spans, Span{Text: " and "})
			}
			spans = append(spans, Span{Text: m.Value, Mark: "exact"})
		}
		return spans
	}
	return []Span{{Text: " is unconstrained"}}
}

// alternative is one member of a union as the sentence lists it: a value
// as itself, a pattern or an intersection as what matches it.
func (c Constraint) alternative() []Span {
	if c.Kind == kindExact {
		return []Span{{Text: c.Value, Mark: "exact"}}
	}
	return append([]Span{{Text: "anything that"}}, c.clause()...)
}

// sentenceOf composes the one sentence the answer states for a grant.
func sentenceOf(g trust.Grant, out Grant) []Span {
	switch {
	case out.Empty:
		return nobody(g, out)
	case out.Top && !out.Exact:
		return unknownWho(out)
	case out.Top:
		return spans(verb(g.Effect)+" ", beyondSpan(g.Effect, everyone(g.Issuer)), ": no condition constrains this statement.")
	case out.Beyond:
		return spans(verb(g.Effect)+" ", beyondSpan(g.Effect, everyone(g.Issuer)), ", whoever holds it: the only claim named is ", Span{Text: "aud", Mark: "code"}, ", and an audience is not a boundary.")
	}
	s := []Span{{Text: verb(g.Effect) + " " + subject(g.Issuer) + " "}}
	for i, term := range out.Terms {
		if i > 0 {
			s = append(s, Span{Text: ", or "})
		}
		s = append(s, termClause(term)...)
	}
	if !out.Exact {
		s = append(s, Span{Text: ", so the set shown is an upper bound"})
	}
	return append(s, Span{Text: "."})
}

// termClause is one term as clauses: "whose aud is x, whose sub matches y".
func termClause(term []Claim) []Span {
	var s []Span
	for i, row := range term {
		switch {
		case i > 0 && i == len(term)-1:
			s = append(s, Span{Text: " and "})
		case i > 0:
			s = append(s, Span{Text: ", "})
		}
		s = append(s, Span{Text: "whose "}, Span{Text: row.Claim, Mark: "code"})
		if row.Constraint.Kind == kindUnknown {
			s = append(s, Span{Text: " was not evaluated", Mark: "unknown", Note: row.Note})
			continue
		}
		s = append(s, row.Constraint.clause()...)
	}
	return s
}

// nobody is the sentence for a set proven empty: the statement lets no
// token through this principal, and the notes say why when the engine
// recorded a reason.
func nobody(g trust.Grant, out Grant) []Span {
	s := []Span{{Text: "This statement admits nobody through " + principal(g.Issuer)}}
	for _, n := range out.Notes {
		if n.Anomaly == aws.NotAnAssumeAction || (n.Anomaly == trust.Unmodelled && n.Construct == "Deny") {
			return append(s, Span{Text: ": "}, declared(out.Notes, n), Span{Text: "."})
		}
	}
	return append(s, Span{Text: ": no token satisfies every condition it names."})
}

// declared is an anomaly's sentence as a reference to the caveat that
// declares it, when one does: a Deny not applied carries both, and the
// caveat is what makes the set an upper bound. An anomaly with no caveat
// changes nothing about the set and earns no colour.
func declared(notes []Note, a Note) Span {
	for _, n := range notes {
		if n.Kind == "caveat" && n.Message == a.Message {
			return Span{Text: a.Message, Mark: "unknown", Note: n.Number}
		}
	}
	return Span{Text: a.Message, Note: a.Number}
}

// unknownWho is the sentence for a set widened to everything: nothing about
// who is admitted could be evaluated, and every caveat says why.
func unknownWho(out Grant) []Span {
	s := []Span{{Text: "Who this statement admits is not known", Mark: "unknown"}, {Text: ": "}}
	return append(append(s, caveatList(out.Notes)...), Span{Text: "."})
}

// beyondSpan colours the phrase for an unconstrained identity when the
// grant admits; a Deny that refuses everyone earns no colour.
func beyondSpan(effect trust.Effect, text string) Span {
	if effect == trust.Allow {
		return Span{Text: text, Mark: "beyond"}
	}
	return Span{Text: text}
}

func verb(effect trust.Effect) string {
	switch effect {
	case trust.Allow:
		return "This role admits"
	case trust.Deny:
		return "This role refuses"
	}
	return "This statement, whose effect could not be read, may admit"
}

// subject is who a constrained grant is about: a token from the issuer,
// or an AWS principal when the issuer is the pseudo-issuer of AWS's own.
func subject(issuer trust.IssuerRef) string {
	if issuer == aws.AWSPrincipalIssuer {
		return "any AWS principal"
	}
	return "any token from " + host(issuer)
}

// everyone is the whole of what an unconstrained grant admits. The AWS
// face of "*" is every principal of every account, and never an anonymous
// one: AWS requires credentials of whoever calls sts:AssumeRole ("You must
// call this API using active credentials",
// https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp_request.html),
// and people with no account are the face that names no issuer, placed
// apart. Saying otherwise here put a sentence beside the rings that
// contradicted them. A service issues no token: its grant admits the
// service, acting for whoever can make it act, which is who gets in and is
// not read.
func everyone(issuer trust.IssuerRef) string {
	switch issuer {
	case aws.AWSPrincipalIssuer:
		return "every AWS principal, in any account"
	case "":
		return "anyone"
	}
	if service, ok := strings.CutPrefix(string(issuer), aws.ServiceIssuerPrefix); ok {
		return service + ", acting for whoever can make it act"
	}
	return "every identity " + host(issuer) + " issues a token to"
}

// principal names the issuer after "through".
func principal(issuer trust.IssuerRef) string {
	switch issuer {
	case aws.AWSPrincipalIssuer:
		return "an AWS principal"
	case "":
		return "this principal"
	}
	return host(issuer)
}

// host is the issuer without its scheme, as a sentence names it.
func host(issuer trust.IssuerRef) string {
	return strings.TrimPrefix(string(issuer), "https://")
}

// captionOf is the muted line under the sentence: what the reader should
// not take the sentence to say.
//
// No caption names the surface it is read on. These words are printed by
// the command and by any page embedding the engine, from this one place, so a sentence saying
// "this page" is false in a terminal, and a sentence saying "this command"
// is false in a browser; what both can say is where the answer came from,
// which is here.
//
// A service's grant is exact when every condition on it was read, and who
// it lets in is still not known: the service acts for whoever can make it
// act, and no trust policy says who that is. Its caption says so, where an
// identity's would say that no construct went unevaluated.
func captionOf(g trust.Grant, out Grant) string {
	switch {
	case out.Empty:
		return ""
	case !out.Exact:
		return "The set shown is an upper bound, not the set: a token not excluded here may still be refused by AWS."
	case g.Effect == trust.Deny:
		return "A Deny subtracts from what the Allow statements admit; it admits nobody by itself."
	case strings.HasPrefix(string(g.Issuer), aws.ServiceIssuerPrefix):
		return "Who can make the service act, or receives its session, is not read: who gets in through it is not known."
	case out.Beyond:
		return "Exact means the set is known exactly, not that it is small: no construct went unevaluated."
	}
	return "Who holds those identities now is not computed here: no network request is made."
}

// readFromSpans names, after a value or after "no", the claim AWS reads a
// key from when it is not the key's own: "in azp, which AWS reads for aud".
// A value read from the key's own claim needs nothing more, and an absent
// one is named by its claim.
func readFromSpans(row ClaimOutcome, afterValue bool) []Span {
	key := Span{Text: row.Claim, Mark: "code"}
	switch {
	case row.ReadFrom == "" && afterValue:
		return nil
	case row.ReadFrom == "":
		return []Span{key}
	}
	from := Span{Text: row.ReadFrom, Mark: "code"}
	if afterValue {
		return []Span{{Text: " in "}, from, {Text: ", which AWS reads for "}, key}
	}
	return []Span{from, {Text: ", which AWS reads for "}, key}
}

// unsettledSpans is why a key's value is not read from a token: the claim
// AWS reads it from is not a string, or AWS reads it from what its table
// writes in a form no token is known to carry, or the token sets the claim
// AWS prefers to a value that may be no value, and AWS reads another claim
// only when the token sets none.
func unsettledSpans(key string, r keyRead) []Span {
	if r.shape != "" {
		return spans("the token carries ", Span{Text: r.claim, Mark: "code"}, " as "+r.shape+", not a string, and AWS documents no rule for what a string condition compares in such a claim, so what AWS reads for ", Span{Text: key, Mark: "code"}, " is not known")
	}
	if r.unnamed {
		return spans("AWS reads ", Span{Text: key, Mark: "code"}, " from what its table writes as "+strconv.QuoteToASCII(r.claim)+", which names no claim a token is known to carry, so what this token carries for it is not known")
	}
	value := "the empty string"
	if r.null {
		value = "null"
	}
	preferred, instead := Span{Text: r.claim, Mark: "code"}, Span{Text: r.instead.claim, Mark: "code"}
	return spans("the token sets ", preferred, " to "+value+"; AWS reads ", Span{Text: key, Mark: "code"}, " from ", preferred, ", or from ", instead, " when a token sets no ", preferred, ", and does not say whether "+value+" is a value, so which it reads is not decided here")
}

// unappliedConstraint is what the token view shows for a claim a Deny the
// parser did not apply names, where a grant's constraint on the claim goes:
// the Deny keeps none that is compared with the token.
const unappliedConstraint = "not applied"

// notAppliedSpans is the heading of a Deny, n, that the parser could not
// fully evaluate and did not apply, for a token it may name.
func notAppliedSpans(n string) []Span {
	return spans("Not excluded, and not proven refused: ", Span{Text: n + " could not be fully evaluated, so it is not applied.", Mark: "unknown"})
}

// foldedIssuerSpans says why a token's issuer is not evaluated against a
// grant's: the two hosts differ in letters outside ASCII that a case folding
// may make one, and no AWS page says whether AWS reads them so.
func foldedIssuerSpans(row ClaimOutcome, number int) []Span {
	return spans("the token was issued by ", Span{Text: row.Value, Mark: "code"}, "; grant "+strconv.Itoa(number)+" admits tokens from "+host(trust.IssuerRef(row.Constraint.Value))+", and the two hosts differ in letters outside ASCII that a case folding may make one; whether AWS reads them as one is not documented")
}

// noTokenSpans says why the principal of a grant, n, filed under issuer,
// presents no token: what assumes the role through it, and through which
// action.
func noTokenSpans(n string, issuer trust.IssuerRef) []Span {
	who, through := "an AWS principal, which assumes a role", "sts:AssumeRole"
	switch {
	case strings.HasPrefix(string(issuer), aws.ServiceIssuerPrefix):
		who = "the service " + strings.TrimPrefix(string(issuer), aws.ServiceIssuerPrefix) + ", which assumes a role"
	case aws.IsSAMLIssuer(issuer):
		who, through = "the SAML provider "+providerName(string(issuer))+", whose sign-ins assume a role", "sts:AssumeRoleWithSAML"
	}
	return spans(n+"'s principal is "+who+" through ", Span{Text: through, Mark: "code"}, ", and a token is presented through ", Span{Text: "sts:AssumeRoleWithWebIdentity", Mark: "code"})
}

// tokenCell is what the token carries for a claim, as the explanation's
// table prints it, with the claim AWS reads it from when that is not the
// claim's own name.
func tokenCell(row ClaimOutcome) string {
	switch {
	case row.ReadFrom == "":
		return row.Value
	case row.Value == "":
		return "from " + row.ReadFrom
	}
	return row.Value + " · from " + row.ReadFrom
}

// witnessHeading is the label over a witness, in the grant's effect.
func witnessHeading(effect trust.Effect) string {
	return "a token this grant " + does(effect)
}

// witnessCaption says what the witness proves. A claim the witness leaves
// out is one the grant leaves unconstrained, except an Unknown one, which
// the grant did not evaluate and the caption must not call unconstrained,
// and one the witness leaves out because AWS would read it in place of a
// claim the witness carries, which unset names; and a token admitted by an
// upper bound is not proven admitted.
func witnessCaption(g trust.Grant, out Grant, unset []leftOut) string {
	const payload = "The decoded payload. "
	var unknown []string
	for _, term := range out.Terms {
		for _, row := range term {
			if row.Constraint.Kind == kindUnknown && !slices.Contains(unknown, row.Claim) {
				unknown = append(unknown, row.Claim)
			}
		}
	}
	but, whatever, why := "", "whatever else it carries", ""
	if len(unset) > 0 {
		claims := make([]string, len(unset))
		readings := make([]string, len(unset))
		for i, l := range unset {
			claims[i] = l.claim
			readings[i] = "AWS reads " + l.key + " from " + l.claim + " whenever a token sets one"
		}
		but = ", but for " + prose(claims)
		whatever += " but " + prose(claims)
		why = " It sets no " + prose(claims) + ": " + strings.Join(readings, "; ") + "."
	}
	switch {
	case len(unknown) > 0:
		return payload + "A claim not shown and not named by the grant is unconstrained" + but + "; " + prose(unknown) + " " + verbFor(len(unknown), "is", "are") + " not shown because " + verbFor(len(unknown), "it was", "they were") + " not evaluated, so whether " + verbFor(len(unknown), "it excludes", "they exclude") + " a token is not decided here." + why
	case !out.Exact:
		return payload + "A claim not shown is unconstrained by this grant" + but + "; the set is an upper bound, so the token is " + past(string(g.Effect)) + " by the bound, not proven " + past(string(g.Effect)) + " by the policy." + why
	case g.Effect == trust.Deny:
		return payload + "A claim not shown is unconstrained by this grant" + but + ": a token carrying these claims is refused " + whatever + "." + why
	case g.Effect == trust.EffectUnknown:
		return payload + "A claim not shown is unconstrained by this grant" + but + "; the statement's effect could not be read, so whether such a token is admitted or refused is not known." + why
	case out.Beyond:
		return payload + "A claim not shown is unconstrained by this grant" + but + ", and none of the claims shown names an identity: whoever holds a token like this is admitted." + why
	}
	return payload + "A claim not shown is unconstrained by this grant" + but + "." + why
}

// does is what a grant does to a token it matches, in the present tense.
func does(effect trust.Effect) string {
	switch effect {
	case trust.Allow:
		return "admits"
	case trust.Deny:
		return "refuses"
	}
	return "matches"
}

// spans builds a run from strings and Spans.
func spans(parts ...any) []Span {
	out := make([]Span, 0, len(parts))
	for _, p := range parts {
		switch v := p.(type) {
		case string:
			out = append(out, Span{Text: v})
		case Span:
			out = append(out, v)
		}
	}
	return out
}

// plain is a run of spans as text, with control characters stripped: a
// claim value is user configuration, and a terminal escape inside one
// could rewrite the line the CLI prints it on.
func plain(s []Span) string {
	var b strings.Builder
	for _, span := range s {
		b.WriteString(span.Text)
	}
	return withoutControls(b.String())
}

// stripped is the run with the control characters gone from every span,
// which is where they must go rather than from the sentence alone: a page
// renders the spans and the command renders the sentence, and a grant that
// read differently on the two surfaces would make the differential between
// them meaningless. The spans are composed here and nowhere else, so they
// are stripped in place.
func stripped(spans []Span) []Span {
	for i := range spans {
		spans[i].Text = withoutControls(spans[i].Text)
	}
	return spans
}

// withoutControls removes the C0 and C1 characters a terminal acts on. It
// removes the newline and the tab with them: these are the words of one
// sentence, printed on one line, and a claim value carrying a newline would
// break the line the command prints it on as surely as an escape would.
func withoutControls(text string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || (r >= 0x7f && r <= 0x9f) {
			return -1
		}
		return r
	}, text)
}

// ---- the rings ----

// The words of the rings: the labels of the five rings and of the two lines
// beside them, a sentence for each, the headline the answer opens on, the
// grants in no ring, what was not read that could narrow the rings, and why
// a declared owner was refused or moved nothing. A sentence says what the
// engine placed and nothing else: a population a grant lets in for certain
// "can" assume the role, one whose place rests on a fact or a constraint
// nobody read "could", each said of its own population and never lent from
// another's, and no sentence says "only", which would read as reassurance
// about a population nobody read. No row sentence counts or numbers grants:
// a grant is the engine's unit, and a reader of the rings needs none.

// platformName is how a sentence names the platform an issuer's grants are
// on, which is where its accounts are, not the product that mints its
// tokens: AWS for AWS principals; the platform the census names, where a
// vendor sentence names one; otherwise the census's name for the issuer,
// without the qualifier it adds in parentheses, when that is two words or
// fewer, which is what a ring's label has room for; and otherwise, or when
// the census has not surveyed it, the issuer's host, without the path that
// names a tenant: the platform is the host's.
func platformName(issuer trust.IssuerRef, census registry.Names) string {
	switch {
	case issuer == aws.AWSPrincipalIssuer:
		return "AWS"
	case census.Platform != "":
		return census.Platform
	}
	name, _, _ := strings.Cut(census.Entry, " (")
	if name != "" && len(strings.Fields(name)) <= 2 {
		return name
	}
	h, _, _ := strings.Cut(host(issuer), "/")
	return h
}

// label is a row's label. The platform ring names the platform its grants
// are on, or how many there are when they are on several.
func label(r row) string {
	switch r.place {
	case ring.Anyone:
		return "Anyone"
	case ring.Platform:
		sure, unsure := r.platforms()
		return platformsLabel(append(sure, unsure...))
	case ring.Outsider:
		return "A named outsider"
	case ring.Yours:
		return "Your pipelines"
	case ring.People:
		return "Your people"
	case ring.SAML:
		return "SAML sign-ins"
	}
	return "Cloud services"
}

// platformsLabel names platforms as a label or a headline has room to: one
// by its name, several by how many.
func platformsLabel(platforms []string) string {
	switch len(platforms) {
	case 0:
		return "Anyone on a platform"
	case 1:
		return "Anyone on " + platforms[0]
	}
	return "Anyone on " + strconv.Itoa(len(platforms)) + " platforms"
}

// verbOf is the verb for populations a grant lets in for certain, "can",
// or not, "could".
func verbOf(sure bool) string {
	if sure {
		return "can"
	}
	return "could"
}

// can is the verb a headline says of a row's population: "can" when the row
// is reached for certain, and always for a line and for the user's own
// people, whose population is whoever the provider signs in or the service
// acts for; "could" when the ring is the outermost the engine could not rule
// out.
func can(r row) string {
	return verbOf(r.state == ring.StateExact || r.place == ring.People || !r.place.Ring())
}

// populationMark is the colour a row's population takes: unknown when its
// place is not established, beyond when the ring admits past any owner,
// exact when named owners confine it.
func populationMark(r row) string {
	switch {
	case r.state == ring.StateUnknown:
		return "unknown"
	case r.place == ring.Anyone || r.place == ring.Platform:
		return "beyond"
	}
	return "exact"
}

// emptyRow is the sentence of a ring no grant is placed in. It says where
// the grants are not, never who cannot get in: a grant placed further out
// admits this ring's population and more, and beside the rings a SAML
// provider or a service may let in anyone at all, which the ring of
// anyone's state says and its sentence does not. The ring of the
// user's own is where a grant is confined to declared owners, which a
// grant pinned to a declared owner and an outsider is not.
var emptyRow = [...]string{
	ring.Anyone:   "No grant is placed with people who have no account anywhere.",
	ring.Platform: "No grant is placed at a whole platform.",
	ring.Outsider: "No grant is placed with a named outsider.",
	ring.Yours:    "No grant is confined to owners declared as yours.",
	ring.People:   "No grant trusts a SAML provider declared as yours.",
}

// rowWords is a row's sentence, shown when the row opens.
func rowWords(r row) []Span {
	if len(r.grants) == 0 && r.place.Ring() {
		return spans(emptyRow[r.place])
	}
	switch r.place {
	case ring.Anyone:
		return anyoneWords(r)
	case ring.Platform:
		return platformWords(r)
	case ring.Outsider:
		return outsiderWords(r)
	case ring.Yours:
		return yoursWords(r)
	case ring.People, ring.SAML:
		return signInWords(r)
	}
	return serviceWords(r)
}

// anyoneWords says why anyone at all could assume the role, naming the
// issuer when every population here is there for one reason and on one
// issuer, and otherwise saying what they share. The face of "*" is placed
// here on the engine's reading of two AWS sentences, which the sentence
// says is the engine's, and on conditions it may not have read, so it says
// what the reading lets in may, never that it is let in. An identity pool
// gives tokens to guests and to whoever its providers let sign in, and a
// grant whose conditions on the kind of identity nobody read is there for
// either, so the sentence names both.
func anyoneWords(r row) []Span {
	pops, sure := r.leading()
	s := spans(Span{Text: "Anyone", Mark: populationMark(r)}, " "+verbOf(sure)+" assume this role: ")
	basis, first, shared, oneIssuer := reason(pops)
	switch {
	case !shared || !oneIssuer && basis != ring.AnyIssuer && basis != ring.PrincipalNotModelled:
		return append(s, Span{Text: "some credentials it trusts may need no account."})
	case basis == ring.IssuerNotSurveyed:
		return append(s, spans("whether ", Span{Text: host(first.issuer), Mark: "code"}, " requires an account was not surveyed.")...)
	case basis == ring.TokensWithoutAccount:
		return append(s, spans(Span{Text: first.platform, Mark: "code"}, " gives tokens to guests and to whoever signs in.")...)
	case basis == ring.AccountNotVerified:
		return append(s, spans("nothing read shows ", Span{Text: first.platform, Mark: "code"}, " requires an account.")...)
	case basis == ring.AnyIssuer:
		return append(s, Span{Text: "by the engine's reading of AWS's documentation, identity-pool guests may."})
	}
	return append(s, Span{Text: "it trusts a principal whose kind is not read."})
}

// platformWords says who on which platforms can assume the role and who
// could, and, for one platform every population of the row shares one
// reason for, why no owner confines them. The reason is the row's only when
// it is every population's: a population let in for certain leads the
// sentence, and its reason said of the row would be lent to one placed
// there for another. Both groups are named when three platforms or fewer
// are, which the row's budget has room for; past that, a group of more than
// one is counted.
func platformWords(r row) []Span {
	sure, unsure := r.platforms()
	lead, verb := sure, "can"
	if len(sure) == 0 {
		lead, verb, unsure = unsure, "could", nil
	}
	who := Span{Text: "Anyone on " + platformList(lead), Mark: populationMark(r)}
	if len(unsure) > 0 {
		others := Span{Text: "anyone on " + platformList(unsure), Mark: "unknown"}
		if len(lead)+len(unsure) > 3 {
			who.Text = "Anyone on " + oneOrCount(lead, "platforms")
			others.Text = "anyone on " + oneOrCount(unsure, "more platforms")
		}
		return spans(who, " "+verb+" assume this role; ", others, " could.")
	}
	s := spans(who, " "+verb+" assume this role")
	if basis, first, shared, _ := reason(r.populations()); shared && len(lead) == 1 {
		if why := unconfined(basis, first.issuer); why != "" {
			s = append(s, Span{Text: "; " + why})
		}
	}
	return append(s, Span{Text: "."})
}

// unconfined is why no owner confines a platform's population, by the
// basis that placed it there; an AWS principal's tenant is an account or an
// organisation, and a token's an owner.
func unconfined(basis ring.Basis, issuer trust.IssuerRef) string {
	switch basis {
	case ring.Unpinned:
		if issuer == aws.AWSPrincipalIssuer {
			return "no condition confines callers to one account or organisation"
		}
		return "no condition confines its tokens to one owner"
	case ring.OpenTenant:
		return "anyone can join the tenant its issuer names"
	case ring.TenancyNotRecorded:
		return "which claims name an owner is not recorded"
	case ring.UnreadConstraint:
		return "one of its conditions was not read"
	case ring.MembershipNotVerified:
		return "who can join its tenant is not established"
	}
	return ""
}

// platformList names platforms in a sentence: "A", "A or B", "A, B or C",
// four by name, and past four the first two and how many more.
func platformList(platforms []string) string {
	if len(platforms) > 4 {
		return platforms[0] + ", " + platforms[1] + " and " + strconv.Itoa(len(platforms)-2) + " other platforms"
	}
	if len(platforms) == 1 {
		return platforms[0]
	}
	return strings.Join(platforms[:len(platforms)-1], ", ") + " or " + platforms[len(platforms)-1]
}

// oneOrCount names one platform, or counts several as what they are.
func oneOrCount(platforms []string, what string) string {
	if len(platforms) == 1 {
		return platforms[0]
	}
	return strconv.Itoa(len(platforms)) + " " + what
}

// outsiderWords names the owners a named outsider is, which is the question
// the answer asks: is this one yours? Every owner a grant here admits is
// named, declared or not, since a pin naming a declared owner beside an
// outsider admits both; each is said to be let in for certain or not; and
// the sentence says which cannot be declared, a repository or an
// enterprise, which no answer to that question could move.
func outsiderWords(r row) []Span {
	owners := r.owners()
	sure, unsure := bySureness(owners)
	mark := populationMark(r)
	switch {
	case len(sure) > 0 && len(unsure) > 0 && len(owners) == 2:
		return spans(ownerSpan(sure[0], mark, true), " can assume this role, and ", ownerSpan(unsure[0], "unknown", false), " could", outsiderStatus(owners, false), ".")
	case len(sure) > 0 && len(unsure) > 0:
		return spans(ownersSpan(sure, mark), " can assume this role, ", Span{Text: strconv.Itoa(len(unsure)) + " more", Mark: "unknown"}, " could", outsiderStatus(owners, false), ".")
	case len(owners) > 2:
		return spans(ownersSpan(owners, mark), " "+verbOf(len(sure) > 0)+" assume this role", outsiderStatus(owners, false), ".")
	}
	s := []Span{ownerSpan(owners[0], mark, true)}
	if len(owners) == 2 {
		s = append(s, Span{Text: " and "}, ownerSpan(owners[1], mark, false))
	}
	return append(s, spans(" "+verbOf(len(sure) > 0)+" assume this role", outsiderStatus(owners, true), ".")...)
}

// bySureness splits owners into those a grant lets in for certain, which
// can assume the role, and the rest, which could.
func bySureness(owners []named) (sure, unsure []named) {
	for _, o := range owners {
		if o.sure {
			sure = append(sure, o)
		} else {
			unsure = append(unsure, o)
		}
	}
	return sure, unsure
}

// outsiderStatus is what the question can do with a named outsider's
// owners: which are not declared as yours, which cannot be declared,
// and, beside a declared one, which of them is the outsider. joined is a
// clause after the owners named one or two and joined by "and"; otherwise
// it follows a semicolon.
func outsiderStatus(owners []named, joined bool) string {
	var open, fixed, declared []named
	for _, o := range owners {
		switch {
		case o.Declared:
			declared = append(declared, o)
		case o.Declaration() == "":
			fixed = append(fixed, o)
		default:
			open = append(open, o)
		}
	}
	n := len(owners)
	switch {
	case len(fixed) == 0 && len(declared) == 0 && joined:
		return " and " + verbFor(n, "is", "are") + " not declared as yours"
	case len(fixed) == 0 && len(declared) == 0:
		return "; " + neitherOrNone(n) + " is declared as yours"
	case len(open) == 0 && len(declared) == 0 && joined:
		return " and cannot be declared"
	case len(open) == 0 && len(declared) == 0:
		return "; " + neitherOrNone(n) + " can be declared"
	case len(fixed) > 0 && n <= 2:
		return "; the " + fixed[0].Scope.String() + " cannot be declared"
	case len(fixed) > 0:
		return "; " + strconv.Itoa(len(fixed)) + " cannot be declared"
	case n <= 2:
		return "; " + open[0].name + " is not declared as yours"
	}
	return "; " + strconv.Itoa(len(open)) + " " + verbFor(len(open), "is", "are") + " not declared as yours"
}

// neitherOrNone is "none of them" said of two or of more.
func neitherOrNone(n int) string {
	if n == 2 {
		return "neither"
	}
	return "none"
}

// ownerSpan is an owner in a sentence, marked, and as its label when the
// sentence starts with it.
func ownerSpan(o named, mark string, first bool) Span {
	if first {
		return Span{Text: ownerLabel(o.Owner), Mark: mark}
	}
	return Span{Text: o.name, Mark: mark}
}

// ownersSpan is owners named one by one when there is one, and otherwise
// counted: as named outsiders when none is declared, and as owners when one
// is, which an outsider is not.
func ownersSpan(owners []named, mark string) Span {
	if len(owners) == 1 {
		return ownerSpan(owners[0], mark, true)
	}
	what := " named outsiders"
	if slices.ContainsFunc(owners, func(o named) bool { return o.Declared }) {
		what = " owners"
	}
	return Span{Text: strconv.Itoa(len(owners)) + what, Mark: mark}
}

// yoursWords names the owners declared as the user's that the grants
// here are pinned to, each let in for certain or not.
func yoursWords(r row) []Span {
	owners := r.owners()
	sure, unsure := bySureness(owners)
	mark := populationMark(r)
	lead, verb := owners, verbOf(len(sure) > 0)
	if len(sure) > 0 && len(unsure) > 0 {
		lead = sure
	}
	var s []Span
	if len(lead) > 2 {
		s = spans(Span{Text: strconv.Itoa(len(lead)) + " owners declared as yours", Mark: mark}, " "+verb+" assume this role")
	} else {
		s = []Span{ownerSpan(lead[0], mark, true)}
		if len(lead) == 2 {
			s = append(s, Span{Text: " and "}, ownerSpan(lead[1], mark, false))
		}
		s = append(s, Span{Text: ", declared as yours, " + verb + " assume this role"})
	}
	switch {
	case len(sure) > 0 && len(unsure) > 0 && len(owners) == 2:
		s = append(s, Span{Text: ", and "}, ownerSpan(unsure[0], "unknown", false), Span{Text: " could"})
	case len(sure) > 0 && len(unsure) > 0:
		s = append(s, Span{Text: ", "}, Span{Text: strconv.Itoa(len(unsure)) + " more", Mark: "unknown"}, Span{Text: " could"})
	}
	return append(s, Span{Text: "."})
}

// signInWords is the ring of the user's people and the line of SAML
// sign-ins: who a provider signs in is set in the provider, which no trust
// policy carries, and the face of "*" on sts:AssumeRoleWithSAML is every
// provider in the role's own account.
func signInWords(r row) []Span {
	face, providers := r.saml()
	who := Span{Text: r.samlPopulation(), Mark: populationMark(r)}
	switch {
	case face:
		return spans(who, " can assume this role.")
	case len(providers) == 1:
		return spans(who, " can assume this role; who they are is set in ", Span{Text: providers[0], Mark: "code"}, ".")
	}
	return spans(who, " can assume this role; each sets who they are.")
}

// serviceWords is the line of cloud services. Who can make a service act
// is not read, so the line says so, and never that no one can. One service
// the parser's table of intermediaries lists, whose row records no other
// use, is named with whom it acts for, and who they are is not read either.
// A service whose row records other uses, several services, or the face of
// "*", keep the words true of every service, which are true of those too:
// naming one use of several would drop who can make the service act, and
// who can make IAM Roles Anywhere act is whoever holds a certificate its
// trust anchor accepts.
func serviceWords(r row) []Span {
	face, services := r.services()
	who := Span{Text: r.servicePopulation(), Mark: populationMark(r)}
	switch {
	case face:
		return spans(who, " can assume this role; which ones, and for whom, is not read.")
	case len(services) == 1:
		if listed := r.intermediaries(); len(listed) == 1 && !listed[0].HasOtherUses() {
			return spans(who, " can assume this role for "+listed[0].ActsFor+"; who they are is not read.")
		}
		return spans(who, " can assume this role; who can make it act is not read.")
	}
	return spans(who, " can assume this role; who can make them act is not read.")
}

// samlPopulation names the people a row's SAML providers sign in, for its
// sentence and for a headline that names the row: every provider in the
// role's account for the face of "*", one provider by the name its
// administrator gave it, or several by how many, declared as the
// user's in the ring of their people.
func (r row) samlPopulation() string {
	face, providers := r.saml()
	switch {
	case face:
		return "People any SAML provider in this account signs in"
	case len(providers) == 1:
		return "People " + providers[0] + " signs in"
	case r.place == ring.People:
		return "People " + strconv.Itoa(len(providers)) + " declared SAML providers sign in"
	}
	return "People " + strconv.Itoa(len(providers)) + " SAML providers sign in"
}

// servicePopulation names the services a row holds, for its sentence and
// for a headline that names the row: every AWS service for the face of
// "*", one by its name, or several by how many.
func (r row) servicePopulation() string {
	face, services := r.services()
	switch {
	case face:
		return "Any cloud service"
	case len(services) == 1:
		return services[0]
	}
	return strconv.Itoa(len(services)) + " cloud services"
}

// questionWords is the question the answer asks of an owner the engine
// cannot place as the user's, whether it is theirs: a SAML provider by
// the name its administrator gave it, as its line names it, and any other
// owner by the declaration answering it writes.
func questionWords(o named) []Span {
	name := o.name
	if o.Scope == ring.ScopeProvider {
		name = providerName(o.Value)
	}
	return spans("Is ", Span{Text: name, Mark: "code"}, " yours?")
}

// citationsHeading is the words over the vendor's sentences a row's place
// rests on: the row, and that its place is the engine's reading of them.
func citationsHeading(r row) string {
	return label(r) + " rests on the engine's reading of what AWS writes:"
}

// readingOfAWS is what the face of "*" is placed at Anyone on, by the
// engine's reading, quoted as AWS wrote it, read 23 September 2026: the
// Principal element's wildcard, and the providers AWS builds in, one of
// which gives tokens to guests. No single AWS sentence says the face admits
// anyone; the row's sentence says the reading is the engine's, and these
// are what it reads.
func readingOfAWS() []Citation {
	const principal = "https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html"
	return []Citation{
		{Quote: "You can use a wildcard (*) to specify all principals in the Principal element of a resource-based policy or in condition keys that support principals.", Source: principal},
		{Quote: "An OIDC federated principal can represent an OIDC IDP in your AWS account, or the 4 built in identity providers: Login with Amazon, Google, Facebook, and Amazon Cognito.", Source: principal},
	}
}

// readingOfIntermediaries is what the words of a line holding services AWS
// documents as assuming a role for identities outside IAM rest on: AWS's
// own sentences for each, quoted as written, in the order the services are
// given and each service's in the order its reading follows them, the
// sentences on its other uses last.
func readingOfIntermediaries(listed []aws.Intermediary) []Citation {
	var out []Citation
	for _, i := range listed {
		for _, c := range i.Citations() {
			out = append(out, Citation{Quote: c.Quote, Source: c.Source})
		}
	}
	return out
}

// ownerName names an owner in a sentence: the declaration a user would
// write for it, or what it is and its value when it cannot be declared.
func ownerName(o ring.Owner) string {
	if d := o.Declaration(); d != "" {
		return d
	}
	return o.Scope.String() + " " + o.Value
}

// ownerLabel names an owner on its own, as a sentence that starts with it
// does: an owner that cannot be declared starts with a capital, since its
// name is words, where a declaration is text the reader writes as it
// stands.
func ownerLabel(o ring.Owner) string {
	if o.Declaration() == "" {
		return capitalised(ownerName(o))
	}
	return ownerName(o)
}

// providerName is a SAML provider's name, the part of its ARN after
// saml-provider/, which is what its administrator chose to call it.
func providerName(arn string) string {
	_, name, _ := strings.Cut(arn, ":saml-provider/")
	return name
}

// headline is the sentence the answer opens on. With a ring outside the
// user reached, it is the outermost one, and every line beside the
// rings that holds a grant, never omitted. With none, the lines alone. With
// neither, a ring inside whose place is not established, which must be
// named rather than let the sentence for an empty set of rings stand beside
// it. Only when nothing outside the user is reached, no line holds a
// grant and no Unknown remains is that sentence said.
func headline(rows, lines []row) []Span {
	saml, service := lineOf(lines, ring.SAML), lineOf(lines, ring.Service)
	for _, r := range rows[:ring.Yours] {
		if len(r.grants) > 0 {
			return append(append(headlineSubject(r), Span{Text: " " + can(r) + " assume this role"}), clause(saml, service)...)
		}
	}
	if saml != nil || service != nil {
		return linesHeadline(saml, service)
	}
	for _, r := range rows[ring.Yours:] {
		if len(r.grants) == 0 || r.state == ring.StateExact {
			continue
		}
		if r.place == ring.People {
			return peopleHeadline(r)
		}
		return spans(Span{Text: label(r), Mark: populationMark(r)}, " "+can(r)+" assume this role.")
	}
	return spans(Span{Text: "Nothing outside your company", Mark: "exact"}, " can assume this role.")
}

// headlineSubject names a reached ring's population in the headline, as
// its label does, which is on the same screen: the headline counts what
// the label counts. The platform ring that holds platforms a grant lets in
// for certain beside platforms it does not is counted as a range, from the
// certain ones, of which "can" is said, to the label's count, the excess
// marked unknown: "Anyone on 2-3 platforms".
func headlineSubject(r row) []Span {
	mark := populationMark(r)
	if r.place == ring.Platform {
		if sure, unsure := r.platforms(); len(sure) > 0 && len(unsure) > 0 {
			return []Span{
				{Text: "Anyone on " + strconv.Itoa(len(sure)), Mark: mark},
				{Text: "-" + strconv.Itoa(len(sure)+len(unsure)), Mark: "unknown"},
				{Text: " platforms", Mark: mark},
			}
		}
	}
	return []Span{{Text: label(r), Mark: mark}}
}

// noStatementWords is the headline of a document that holds no statement:
// a truncated paste, or one the parser reads as outside the IAM grammar.
// Who can assume the role it came from is what the reader asked, and this
// document does not say.
func noStatementWords() []Span {
	return spans("The document holds no statement, so ", Span{Text: "who can assume this role is not known", Mark: "unknown"}, ".")
}

// noStatementForTokenWords is the heading of a token's explanation against
// a document that holds no statement, which says what the headline of its
// answer says.
func noStatementForTokenWords() []Span {
	return spans("The document holds no statement, so ", Span{Text: "whether this token is admitted is not known", Mark: "unknown"}, ".")
}

// clause ends a headline whose ring is reached with the lines beside the
// rings that hold a grant.
func clause(saml, service *row) []Span {
	switch {
	case saml != nil && service != nil:
		return spans("; so can ", Span{Text: "SAML and cloud services", Mark: "unknown"}, ".")
	case saml != nil:
		return spans("; so can ", Span{Text: "SAML sign-ins", Mark: "unknown"}, ".")
	case service != nil && service.oneService():
		return spans("; so can ", Span{Text: "a cloud service", Mark: "unknown"}, ".")
	case service != nil:
		return spans("; so can ", Span{Text: "cloud services", Mark: "unknown"}, ".")
	}
	return spans(".")
}

// linesHeadline is the headline when no ring is reached and a line beside
// the rings holds a grant.
func linesHeadline(saml, service *row) []Span {
	var who string
	switch {
	case saml != nil && service != nil && service.oneService():
		who = "SAML sign-ins and a cloud service"
	case saml != nil && service != nil:
		who = "SAML sign-ins and cloud services"
	case saml != nil:
		who = saml.samlPopulation()
	default:
		who = service.servicePopulation()
	}
	return spans(Span{Text: who, Mark: "unknown"}, " can assume this role.")
}

// peopleHeadline is the headline when the user's own people are the
// only place reached: who they are is set in the provider, which is the
// Unknown the sentence for an empty set of rings would hide.
func peopleHeadline(r row) []Span {
	_, providers := r.saml()
	who := Span{Text: "Your people", Mark: populationMark(r)}
	if len(providers) == 1 {
		return spans(who, " can assume this role; who they are is set in ", Span{Text: providers[0], Mark: "code"}, ".")
	}
	return spans(who, " can assume this role; "+strconv.Itoa(len(providers))+" SAML providers set who they are.")
}

// refusedWords says why a Deny is in no ring: a refusal places no one, and
// no ring subtracts it, so the rings may be wider than AWS enforces, never
// narrower.
func refusedWords(numbers []int) []Span {
	n := len(numbers)
	return spans(capitalised(grantsNamed(numbers)) + " " + verbFor(n, "refuses", "refuse") + ", so " + verbFor(n, "it is", "they are") + " in no ring; the rings do not subtract " + verbFor(n, "it", "them") + ".")
}

// nobodyWords says why a grant that admits no token is in no ring.
func nobodyWords(numbers []int) []Span {
	n := len(numbers)
	return spans(capitalised(grantsNamed(numbers)) + " " + verbFor(n, "admits", "admit") + " nobody, so " + verbFor(n, "it is", "they are") + " in no ring.")
}

// capitalised is s with its first letter upper-cased. Every sentence the
// engine capitalises starts with one of its own words, and those are ASCII,
// so ASCII is the only case it folds.
func capitalised(s string) string {
	if s != "" && 'a' <= s[0] && s[0] <= 'z' {
		return string(s[0]-'a'+'A') + s[1:]
	}
	return s
}

// The bounds, by id: what can narrow the rings and was not read. Who gets
// the tokens of an issuer that mints them to people with no account is set
// by each audience its tokens carry, as an identity pool, named in aud, is
// for Amazon Cognito's: the settings are the audience's, never the issuer's.
const (
	rcpBound       = "resource-control-policies"
	scpBound       = "service-control-policies"
	providersBound = "identity-providers"
	settingsBound  = "audience-settings"
)

// boundWords is one bound's sentence; platform names the issuer whose
// audiences' settings it is, for that bound.
func boundWords(id, platform string) string {
	switch id {
	case rcpBound:
		return "The organisation's resource control policies can narrow who assumes this role, and were not read."
	case scpBound:
		return "For AWS principals, the calling accounts' service control policies can narrow who assumes this role, and were not read."
	case providersBound:
		return "Whether this account's identity providers exist, and which audiences they accept, can narrow who assumes this role, and was not read."
	}
	return "The settings of " + audiencesOf(platform) + ", such as whether it admits guests, can narrow who assumes this role, and were not read."
}

// boundName is how the line of bounds names one.
func boundName(id, platform string) string {
	switch id {
	case rcpBound:
		return "the organisation's resource control policies"
	case scpBound:
		return "the calling accounts' service control policies"
	case providersBound:
		return "this account's identity providers"
	}
	return "the settings of " + audiencesOf(platform)
}

// audiencesOf names the audiences a role accepts from an issuer.
func audiencesOf(platform string) string {
	return "each audience this role accepts from " + platform
}

// boundsWords names every bound on one line, which a view printing the
// rings prints beside them.
func boundsWords(names []string) string {
	return "Each of these can narrow the rings and was not read: " + prose(names) + "."
}

// overrunWords is why a whole declaration was refused, counted in what the
// bound counts: lines, blank ones included, which is not a count of owners,
// since a blank line declares none.
func overrunWords(o ring.Overrun) string {
	switch o.Bound {
	case ring.DeclarationLines:
		return "the owners declared come to " + strconv.Itoa(o.Size) + " lines; the engine reads up to " + strconv.Itoa(ring.MaxDeclarationLines)
	case ring.LineBytes:
		return "line " + strconv.Itoa(o.Line) + " of the owners declared is " + strconv.Itoa(o.Size) + " bytes; the engine reads up to " + strconv.Itoa(ring.MaxDeclarationLineBytes) + " bytes a line"
	}
	return "the owners declared come to " + strconv.Itoa(o.Size) + " bytes; the engine reads up to " + strconv.Itoa(ring.MaxDeclarationBytes)
}

// unmatchedWords is why an owner declared moved nothing: no grant that
// admits is pinned to it, and, when one is pinned to the same owner in
// another letter case, that names compare exactly and which one that is.
func unmatchedWords(spelledLike *ring.Owner) string {
	if spelledLike == nil {
		return "no grant that admits is pinned to it, so declaring it moves nothing"
	}
	return "no grant that admits is pinned to it; names compare exactly, and one is pinned to " + spelledLike.Declaration()
}

// declareAs is how an owner is declared, for a line that declared none.
const declareAs = "declare an owner as github:acme, aws:111122223333, saml:<provider ARN> or issuer:<issuer URL>"

// blankWords is why an owner given alone and blank declares nothing.
const blankWords = "blank: " + declareAs

// refusalWords is why a declared line declares nothing.
func refusalWords(r ring.Reason) string {
	switch r {
	case ring.NotUTF8:
		return "not UTF-8"
	case ring.NoNamespace:
		return "no namespace: " + declareAs
	case ring.UnknownNamespace:
		return "not a namespace owners are declared in: github, aws, saml or issuer"
	case ring.ClaimsNotRead:
		return "owners on GitLab, HCP Terraform and Buildkite cannot be declared: their claims are not read"
	case ring.NoOwner:
		return "no owner: declare it as github:acme, github:acme@123456 or github:@123456"
	case ring.ARepository:
		return "a repository cannot be declared; declaring its owner, as github:acme, moves the grants pinned to that owner, and none pinned to a repository"
	case ring.NotAGitHubOwner:
		return "not a GitHub owner: a name, a name@id or @id, where the id is a number"
	case ring.NotAnAWSID:
		return "neither a 12-digit account id nor an organisation id, o- followed by 10 to 32 lower-case letters or digits"
	case ring.NotASAMLProvider:
		return "not the ARN of a SAML provider, arn:aws:iam::<account>:saml-provider/<name>"
	case ring.NotAnIssuerURL:
		return "not an https issuer URL a trust policy's provider can name, such as https://oidc.eks.us-east-1.amazonaws.com/id/<cluster>"
	}
	return "not read, for a reason this version does not know: " + r.String()
}

// ---- what --explain prints ----

// ExplainPlan is what the command's --explain prints before it answers,
// one line each: every file, input and variable it reads, the owners as
// they were given, and that it makes no network request and no API call,
// since the answer is computed where it runs. path is "-" for standard
// input.
func ExplainPlan(path, token string, owners []string) []string {
	plan := []string{"cloudarq admits, before it answers:"}
	if path == "-" {
		plan = append(plan, "  reads the document from standard input, and no file")
	} else {
		plan = append(plan, "  reads "+path+", and no other file")
	}
	if token != "" {
		plan = append(plan, "  reads the token from the command line, and no file")
	}
	for _, owner := range owners {
		plan = append(plan, "  reads the owner "+strconv.QuoteToASCII(owner)+" from --owner, as yours")
	}
	return append(plan,
		"  consults NO_COLOR, and no other environment variable",
		"  makes no network request and no API call: the answer is computed here",
		"  writes the answer to standard output and nothing to any file",
	)
}

// ExplainCitations is what --explain prints once the command has answered,
// one line each: for every row whose place rests on the engine's reading of
// what a vendor writes, the heading the answer carries over the quotes, then
// each quote as written and the page it is on. An answer that rests on no
// reading has nothing to cite.
func (a Answer) ExplainCitations() []string {
	var lines []string
	for _, r := range append(append([]Row{}, a.Rings...), a.Beside...) {
		if len(r.Citations) == 0 {
			continue
		}
		if lines == nil {
			lines = []string{"cloudarq admits, after it answers:"}
		}
		lines = append(lines, "  "+r.CitationsHeading)
		for _, c := range r.Citations {
			lines = append(lines, "    \""+c.Quote+"\"", "      "+c.Source)
		}
	}
	return lines
}
