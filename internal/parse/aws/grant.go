package aws

import (
	"slices"
	"strconv"
	"strings"

	"github.com/CloudArq-net/cloudarq/internal/eval"
	"github.com/CloudArq-net/cloudarq/internal/trust"
)

// ClaimVocabulary reads a condition key of an issuer's provider as the name
// the admitted set constrains it under. AWS matches condition keys without
// regard to case, and fills each from a claim of the issuer's token that is
// not always the claim of the key's own name: on AWS's Default tab oaud is
// filled from aud, and aud from azp, or from aud when the token sets no azp.
// The parser hands over the key's name after the provider and the colon,
// lower-cased, and the vocabulary answers with the name and how it knows
// it. A key it cannot read is left Unknown, for the reason it gives, rather
// than guessed at: a guessed key could be one AWS never fills, and a
// constraint on it would reject every token.
//
// The issuer registry fills this seam: which keys AWS documents for an
// issuer, which claim AWS fills each from, which of them AWS documents as
// multivalued and which claims the issuer's tokens may carry with several
// values are the census's, and a reader that tests a token against the set
// fills each name the way the census says. LowercaseVocabulary reads the
// keys of issuers the caller names as the claims of the same names; no
// issuer is named in this package.
type ClaimVocabulary func(issuer trust.IssuerRef, spelling string) (trust.ClaimKey, KeyReading)

// KeyReading is how a vocabulary reads a condition key. The zero value
// reads nothing.
type KeyReading int

const (
	// IssuerNotKnown: the vocabulary does not know the issuer's keys.
	IssuerNotKnown KeyReading = iota
	// KeyNotDocumented: AWS documents no such condition key for the
	// issuer's tokens, so whether a request carries it is not known. AWS
	// puts in the request context only the claims it maps to keys, and a
	// key not in the context is a mismatch; which of the two happens to a
	// key it does not document is not documented either.
	KeyNotDocumented
	// ClaimRead: the key is read under the name the vocabulary answers with.
	ClaimRead
	// MultivaluedRead: ClaimRead, and AWS documents the key as multivalued:
	// "The key is multivalued, meaning that you test it in a policy using
	// condition set operators." A request may carry several values for it,
	// and what an operator without a set prefix does on such a key AWS does
	// not document.
	MultivaluedRead
	// MultiValuedClaimRead: ClaimRead, and the issuer's tokens may carry
	// several values in the claim AWS reads the key from, as a Kubernetes
	// service account token may carry several audiences. AWS says nothing of
	// how many values the key then holds, nor what an operator without a set
	// prefix compares on such a claim.
	MultiValuedClaimRead
)

// LowercaseVocabulary knows the given issuers and reads every key of theirs
// as the claim of the same name, in lower case. It knows nothing about any
// other issuer.
func LowercaseVocabulary(issuers ...trust.IssuerRef) ClaimVocabulary {
	known := make(map[trust.IssuerRef]bool, len(issuers))
	for _, issuer := range issuers {
		known[issuer] = true
	}
	return func(issuer trust.IssuerRef, spelling string) (trust.ClaimKey, KeyReading) {
		if !known[issuer] {
			return "", IssuerNotKnown
		}
		return trust.ClaimKey(fold(spelling)), ClaimRead
	}
}

// DocumentedKeys reads the condition keys AWS documents for each issuer's
// tokens, each under its own name in lower case, which is how AWS compares
// keys. documents reports whether AWS lists key for the issuer's tokens,
// and whether the list is known at all: a key the list leaves out is not
// documented, and an issuer whose list is not known has no key the parser
// can read. multivalued reports whether AWS documents a key as multivalued
// for the issuer's tokens, and multiValuedClaim whether a sentence says the
// issuer's tokens may carry several values in the claim AWS reads the key
// from. Only such keys are read as MultivaluedRead and MultiValuedClaimRead;
// any other documented key is compared as one value, although no sentence
// says it holds one either. Which claim of the token AWS fills a key from is
// not the parser's to know, and the name says only which key the set
// constrains.
func DocumentedKeys(documents func(issuer trust.IssuerRef, key string) (documented, known bool), multivalued, multiValuedClaim func(issuer trust.IssuerRef, key string) bool) ClaimVocabulary {
	return func(issuer trust.IssuerRef, spelling string) (trust.ClaimKey, KeyReading) {
		switch documented, known := documents(issuer, spelling); {
		case !known:
			return "", IssuerNotKnown
		case !documented:
			return "", KeyNotDocumented
		case multivalued(issuer, spelling):
			return trust.ClaimKey(fold(spelling)), MultivaluedRead
		case multiValuedClaim(issuer, spelling):
			return trust.ClaimKey(fold(spelling)), MultiValuedClaimRead
		}
		return trust.ClaimKey(fold(spelling)), ClaimRead
	}
}

// Grants projects the document onto the trust model: one Grant per
// (statement, principal face), for the given target. Every statement
// projects at least one grant, whatever the parser made of it, and the loop
// has no early exit: the statement-order property is what that guarantees.
// The grants are returned in canonical order.
func (d Document) Grants(target trust.TargetRef, vocabulary ClaimVocabulary) []trust.Grant {
	var out []trust.Grant
	for i, s := range d.Statements {
		src := "statement[" + strconv.Itoa(i) + "]"
		for _, p := range s.Principals.list {
			for _, face := range p.faces(s.Actions, src+".Principal") {
				out = append(out, s.grant(face, src, target, vocabulary, d.variables))
			}
		}
	}
	sortGrants(out)
	return out
}

const denyNotApplied = "this Deny statement could not be fully evaluated, so it is not applied; the admitted set is an upper bound"

// grant is the projection of one statement for one face of one of its
// principals.
//
// The conditions are projected first, whatever else the statement does,
// because what they do not do is a fact the reporter prints even on a
// grant that admits nobody. The action test then comes before the set: a
// statement whose actions do not include the action this kind of
// principal assumes through admits nothing, whatever else it says, unless
// an action holding a letter outside ASCII may be that action under a
// folding AWS does not document, and then the set stands, doubted. A
// finding that left the whole statement unevaluated makes the set
// everything; otherwise the set is the conditions met with the
// principal's own identity; and every doubt is carried as a caveat, so
// the set is declared the upper bound it is.
//
// A Deny is the exception to widening. The final admitted set is Allow
// minus Deny, so an Unknown that widens a Deny would deny more than the
// policy does and report the role as narrower than it is. A Deny this
// parser could not fully evaluate is therefore not applied at all, which
// keeps the result an upper bound, and it says so.
func (s Statement) grant(p principal, src string, target trust.TargetRef, vocabulary ClaimVocabulary, variables variableMode) trust.Grant {
	g := trust.Grant{Target: target, Issuer: p.issuer, Effect: s.Effect, Source: s.Raw}
	conditions, conditionAnomalies := s.Conditions.project(p, s.Effect, vocabulary, variables, src+".Condition")
	g.Anomalies = distinct(slices.Concat(s.findings.anomalies, p.findings.anomalies, conditionAnomalies))
	assume := p.assumeActions()
	var folding findings
	if !s.Actions.unknown && !s.Actions.covers(assume...) {
		folding = s.Actions.foldingDoubts(assume, src+".Action")
		if len(folding.anomalies) == 0 {
			g.Anomalies = append(g.Anomalies, trust.Anomaly{Kind: NotAnAssumeAction, Construct: "Action", Message: "the actions do not include " + spellActions(assume) + ", so this statement lets nobody assume the role through this principal", Source: src + ".Action"})
			g.Admits = eval.Nothing()
			return g
		}
		g.Anomalies = distinct(append(g.Anomalies, folding.anomalies...))
	}
	admits := conditions
	if len(s.findings.widenings)+len(p.findings.widenings) > 0 {
		admits = withCaveats(eval.Everything(), admits.Caveats())
	}
	admits = withCaveats(admits, slices.Concat(s.findings.caveats(), p.findings.caveats(), folding.caveats()))
	if s.Effect == trust.Deny && !admits.Exact() {
		a := trust.Anomaly{Kind: trust.Unmodelled, Construct: "Deny", Message: denyNotApplied, Source: src}
		g.Anomalies = append(g.Anomalies, a)
		admits = withCaveats(eval.Nothing(), append(admits.Caveats(), eval.Caveat{Reason: a.Message, Source: src}))
	}
	g.Admits = admits
	return g
}

// distinct drops repeated anomalies, keeping the first of each. A key
// written twice under one operator is evaluated once per copy, and each
// copy reports the same duplicate; one fact is one sentence.
func distinct(anomalies []trust.Anomaly) []trust.Anomaly {
	seen := make(map[trust.Anomaly]bool, len(anomalies))
	out := make([]trust.Anomaly, 0, len(anomalies))
	for _, a := range anomalies {
		if !seen[a] {
			seen[a] = true
			out = append(out, a)
		}
	}
	return out
}

// sortGrants orders grants by what they mean, so that the output does not
// depend on the order statements were written in. The key leaves out every
// Source, which carries the statement index, and the statement's bytes;
// two grants that mean the same keep their document order, the sort being
// stable.
func sortGrants(gs []trust.Grant) {
	type keyed struct {
		key   string
		grant trust.Grant
	}
	ks := make([]keyed, len(gs))
	for i, g := range gs {
		ks[i] = keyed{grantKey(g), g}
	}
	slices.SortStableFunc(ks, func(a, b keyed) int { return strings.Compare(a.key, b.key) })
	for i, k := range ks {
		gs[i] = k.grant
	}
}

// grantKey renders everything about a grant but where it came from. Two
// statements that say the same thing about the same issuer, one written
// first and one last, must sort the same whichever came first.
func grantKey(g trust.Grant) string {
	var b strings.Builder
	b.WriteString(string(g.Issuer))
	b.WriteByte(0)
	b.WriteString(string(g.Effect))
	b.WriteByte(0)
	b.WriteString(g.Admits.String())
	b.WriteByte(0)
	for _, c := range g.Admits.Caveats() {
		b.WriteString(string(c.Claim) + "=" + c.Reason + ";")
	}
	b.WriteByte(0)
	for _, a := range g.Anomalies {
		b.WriteString(a.Kind + "/" + string(a.Claim) + "/" + a.Construct + "/" + a.Message + ";")
	}
	return b.String()
}
