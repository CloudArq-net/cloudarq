package aws

import (
	"slices"
	"strconv"
	"strings"

	"github.com/CloudArq-net/cloudarq/internal/eval"
	"github.com/CloudArq-net/cloudarq/internal/trust"
)

// ClaimVocabulary reconciles a policy's spelling of a claim with the
// issuer's own. AWS matches condition keys without regard to case, and a
// token's claim names belong to the issuer: GitHub's are lower-case,
// Spacelift's are camelCase. The parser hands over the spelling it read,
// lower-cased, and the vocabulary answers with the name the issuer's tokens
// carry, or false when it does not know the issuer, in which case the
// parser leaves the claim Unknown rather than guess a name no token has.
//
// This is the seam the issuer registry will fill. Until it does,
// LowercaseVocabulary is the interim substitute, seeded by the caller
// with the issuers whose claims are known to be lower-case; no issuer is
// named in this package.
type ClaimVocabulary func(issuer trust.IssuerRef, spelling string) (trust.ClaimKey, bool)

// LowercaseVocabulary knows the given issuers and spells every claim of
// theirs in lower case. It knows nothing about any other issuer.
func LowercaseVocabulary(issuers ...trust.IssuerRef) ClaimVocabulary {
	known := make(map[trust.IssuerRef]bool, len(issuers))
	for _, issuer := range issuers {
		known[issuer] = true
	}
	return func(issuer trust.IssuerRef, spelling string) (trust.ClaimKey, bool) {
		if !known[issuer] {
			return "", false
		}
		return trust.ClaimKey(fold(spelling)), true
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
// grant that admits nobody. The action test then comes before the set and
// is exact: a statement whose actions do not include the action this kind
// of principal assumes through admits nothing, whatever else it says. A
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
	if !s.Actions.unknown && !s.Actions.covers(assume...) {
		g.Anomalies = append(g.Anomalies, trust.Anomaly{Kind: NotAnAssumeAction, Construct: "Action", Message: "the actions do not include " + spellActions(assume) + ", so this statement lets nobody assume the role through this principal", Source: src + ".Action"})
		g.Admits = eval.Nothing()
		return g
	}
	admits := conditions
	if len(s.findings.widenings)+len(p.findings.widenings) > 0 {
		admits = withCaveats(eval.Everything(), admits.Caveats())
	}
	admits = withCaveats(admits, slices.Concat(s.findings.caveats(), p.findings.caveats()))
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
