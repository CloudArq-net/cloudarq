package answer

import (
	"slices"
	"strconv"
	"strings"

	"github.com/CloudArq-net/cloudarq/internal/parse/aws"
	"github.com/CloudArq-net/cloudarq/internal/trust"
)

// The words of the answer. Every phrase is neutral about the issuer: what a
// subject is made of, or which claim names the tenant, belongs to the
// registry, and until it names an issuer the sentence says what the engine
// holds and nothing it does not.

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

// sentenceOf composes the one sentence the page prints for a grant.
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

// everyone is the whole of what an unconstrained grant admits.
func everyone(issuer trust.IssuerRef) string {
	switch issuer {
	case aws.AWSPrincipalIssuer:
		return "every AWS principal, anonymous ones included"
	case "":
		return "anyone"
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
func captionOf(g trust.Grant, out Grant) string {
	switch {
	case out.Empty:
		return ""
	case !out.Exact:
		return "The set shown is an upper bound, not the set: a token this page does not exclude may still be refused by AWS."
	case g.Effect == trust.Deny:
		return "A Deny subtracts from what the Allow statements admit; it admits nobody by itself."
	case out.Beyond:
		return "Exact means the set is known exactly, not that it is small: no construct went unevaluated."
	}
	return "Who holds those identities now is not computed here: this page makes no network request."
}

// witnessHeading is the label over a witness, in the grant's effect.
func witnessHeading(effect trust.Effect) string {
	return "a token this grant " + does(effect)
}

// witnessCaption says what the witness proves. A claim the witness leaves
// out is one the grant leaves unconstrained, except an Unknown one, which
// the grant did not evaluate and the caption must not call unconstrained;
// and a token admitted by an upper bound is not proven admitted.
func witnessCaption(g trust.Grant, out Grant) string {
	const payload = "The decoded payload. "
	var unknown []string
	for _, term := range out.Terms {
		for _, row := range term {
			if row.Constraint.Kind == kindUnknown && !slices.Contains(unknown, row.Claim) {
				unknown = append(unknown, row.Claim)
			}
		}
	}
	switch {
	case len(unknown) > 0:
		return payload + "A claim not shown and not named by the grant is unconstrained; " + prose(unknown) + " " + verbFor(len(unknown), "is", "are") + " not shown because " + verbFor(len(unknown), "it was", "they were") + " not evaluated, so whether " + verbFor(len(unknown), "it excludes", "they exclude") + " a token is not decided here."
	case !out.Exact:
		return payload + "A claim not shown is unconstrained by this grant; the set is an upper bound, so the token is " + past(string(g.Effect)) + " by the bound, not proven " + past(string(g.Effect)) + " by the policy."
	case g.Effect == trust.Deny:
		return payload + "A claim not shown is unconstrained by this grant: a token carrying these claims is refused whatever else it carries."
	case g.Effect == trust.EffectUnknown:
		return payload + "A claim not shown is unconstrained by this grant; the statement's effect could not be read, so whether such a token is admitted or refused is not known."
	case out.Beyond:
		return payload + "A claim not shown is unconstrained by this grant, and none of the claims shown names an identity: whoever holds a token like this is admitted."
	}
	return payload + "A claim not shown is unconstrained by this grant."
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

// plain is the sentence as text, with control characters stripped: a
// claim value is customer configuration, and a terminal escape inside one
// could rewrite the line the CLI prints it on.
func plain(s []Span) string {
	var b strings.Builder
	for _, span := range s {
		b.WriteString(span.Text)
	}
	return strings.Map(func(r rune) rune {
		if r < 0x20 || (r >= 0x7f && r <= 0x9f) {
			return -1
		}
		return r
	}, b.String())
}
