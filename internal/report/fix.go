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

// How to shut a population out, proven or not at all. For a named outsider
// the policy names by an AWS principal, the one edit the engine makes is to
// remove that principal from the Allow statement that names it, or the
// statement when the principal is the only one its Principal names: never a
// Deny, and never NotPrincipal, where a removal lets more in. Where that
// statement is the policy's only one, removing it would leave a policy with
// no statement, which IAM refuses, and the edit is instead to replace the
// whole policy with one that lets no one in (checkReplaced). The engine
// makes the edit to the policy's bytes, reads the result again with the
// same owners, and offers the edit only when four checks hold: the edited
// policy reads with no fault the original does not have; no population
// pinned to the outsider remains; every grant left is one of the
// original's, one for one, and every grant of the original but the
// principal's is left; and each grant left is placed by the same facts as
// its twin and is an upper bound for the same reasons, so where it lands
// moves only inward, and in fact not at all, whoever the owners are.
// Otherwise the fix says which check refused it. The edited policy itself
// never leaves the engine's caller: the answer carries its digest, and the
// whole of it is made again from the caller's own file (AppendFixed).
//
// For anyone on a platform and for a cloud service, no edit is proven
// here: the fix names in words the condition that would narrow the way in.
// For anyone, a SAML provider's sign-ins and the reader's people, the way
// in is through a principal the engine does not remove, and the fix says
// so: every way in has a fix, so that none reads as one with nothing to
// fix.
//
// A population placed as the reader's carries the fix it has as a named
// outsider: none of it but the headline a proven edit leaves depends on
// the owners declared, so an answer re-marked with a declaration withdrawn
// says what reading the policy again would. It is kept for that, and never
// said to the reader as advice (ExplainWays).

// Fix is how the policy could shut one population out, and whether the
// engine proved it.
type Fix struct {
	// Status is proven when the engine read the policy again with the edit
	// made and every check held; unproven when no edit can be proven yet,
	// and Check says why; and words when the condition that would narrow
	// the way in is named and not proven. Values: proven, unproven, words.
	Status string `json:"status"`
	// Check is what refused an unproven fix: no principal the statement
	// writes names the outsider; the statement is not read as an Allow; the
	// engine's bounds on reading policies again and on placing their grants
	// again; the principal's bytes are not one it may edit; the edited
	// policy, or the policy that would replace it, reads with a fault the
	// original does not have; the outsider is still let in by name, or,
	// by the policy that would replace it, anyone; a grant other than the
	// principal's would go, or one would be made, by a replacement one that
	// is not a Deny; a grant left would be placed by other facts;
	// for a platform, no condition the engine can name would pin it; the
	// principal the way in is through is not one the engine removes; or,
	// where a role AWS manages is said beside its answer (Managing), its
	// trust policy is not the account's to edit. Values: leaf, effect,
	// bound, span, parse, owner, grants, placements, condition, principal,
	// managed.
	Check    string `json:"check,omitempty"`
	Sentence string `json:"sentence"`
	Spans    []Span `json:"spans"`
	// Edit is the edit a proven fix makes.
	Edit *Edit `json:"edit,omitempty"`
	// ShutsOut is what a proven fix takes out: the grants it removes, and
	// that no grant left lets the outsider in by name.
	ShutsOut *Sentence `json:"shutsOut,omitempty"`
	// After is the headline the answer opens on once the edit is made, as
	// the engine read the edited policy with the same owners.
	After *Sentence `json:"after,omitempty"`
}

// Edit is one principal removed from the policy, where it is written, and
// the edited policy's digest. The edited policy is never in the answer.
type Edit struct {
	// Removes is what the edit takes out: the principal from its list, the
	// member of Principal it is the only value of, the statement whose
	// Principal names nothing else, or, where that statement is the
	// policy's only one, the whole policy, replaced by one that lets no one
	// in. Values: principal, member, statement, policy.
	Removes   string `json:"removes"`
	Statement int    `json:"statement"`
	Sid       string `json:"sid"`
	FirstLine int    `json:"firstLine"`
	LastLine  int    `json:"lastLine"`
	// Leaf is the principal as the statement writes it, with the byte
	// offsets of its literal in the document, [start, end).
	Leaf Leaf `json:"leaf"`
	// GrantNumbers are the grants of the answer the edit takes out.
	GrantNumbers []int `json:"grantNumbers"`
	// SHA256 is the digest of the policy with the edit made.
	SHA256 string `json:"sha256"`
}

// maxFixGrants bounds the grants the engine places again for one answer's
// fixes. A proof reads the policy again and places every grant of it
// again, so a policy that names many AWS principals costs about the square
// of their number, which bytes alone do not bound: AWS's default 2,048
// characters hold 125 accounts. Past it, a principal's fix says so.
const maxFixGrants = 256

// The statuses, as Status writes them.
const (
	fixProven   = "proven"
	fixUnproven = "unproven"
	fixWords    = "words"
)

// The checks, as Check writes them.
const (
	checkLeaf       = "leaf"
	checkEffect     = "effect"
	checkBound      = "bound"
	checkSpan       = "span"
	checkParse      = "parse"
	checkOwner      = "owner"
	checkGrants     = "grants"
	checkPlacements = "placements"
	checkCondition  = "condition"
	checkPrincipal  = "principal"
	checkManaged    = "managed"
)

// fixes sets the fix of every population of the answer's grants: every
// way in has one, proven, unproven with the check that refused it, or in
// words. A grant's edit is proven once, for every population of it that
// needs one. A population placed as the reader's has the fix it would have
// as an outsider's, and the reader's people the fix of a SAML provider
// nobody declared, so that an answer re-marked with other owners declared
// says what reading the policy again would.
func (a *Answer) fixes(r reading, p *placing) {
	candidates := 0
	for i := range a.Grants {
		w := r.written[i]
		candidate := w.Member == "AWS" && w.Text != "*" && w.End != 0
		if candidate {
			candidates++
		}
		var proof *Fix
		for j := range a.Grants[i].Populations {
			pop := p.placed[i].placement.Populations[j]
			var fix *Fix
			switch pop.Place {
			case ring.Platform:
				fix = platformFix(p.placed[i], pop)
			case ring.Service:
				fix = serviceFix(r, i, p.placed[i], pop)
			case ring.Outsider, ring.Yours:
				fix = r.pinnedFix(i, pop, candidate, candidates, p, &proof)
			default:
				// anyone, a SAML provider's sign-ins and the reader's people
				fix = unproven(checkPrincipal, principalWords(w))
			}
			a.Grants[i].Populations[j].Way.Fix = fix
		}
	}
}

// pinnedFix is the fix of grant i's population pop, pinned to named owners.
// candidate says whether the grant was read from an AWS principal string
// other than "*", and candidates how many such grants there are up to and
// including this one. The proof is made once a grant and kept in proof.
func (r reading) pinnedFix(i int, pop ring.Population, candidate bool, candidates int, p *placing, proof **Fix) *Fix {
	var targets []ring.Owner
	for _, o := range pop.Owners {
		if o.Scope == ring.ScopeAccount {
			targets = append(targets, o)
		}
	}
	switch {
	// A per-tenant issuer's owner is the tenant its URL names: the
	// provider the statement's Principal writes names it, not a condition.
	case pop.Basis == ring.ControlledTenant:
		return unproven(checkPrincipal, principalWords(r.written[i]))
	case !candidate || len(targets) == 0:
		return unproven(checkLeaf, leafWords(pop.Owners))
	case r.grants[i].Effect != trust.Allow:
		return unproven(checkEffect, effectWords(r.statements[i]))
	// The bounds count every grant read from an AWS principal, wherever it
	// lands, so whether a principal is within them does not depend on the
	// owners declared.
	case candidates*len(r.raw) > MaxDocumentBytes:
		return unproven(checkBound, fixBoundWords())
	case candidates*len(r.grants) > maxFixGrants:
		return unproven(checkBound, fixGrantsWords())
	}
	if *proof == nil {
		*proof = r.prove(i, targets, p)
	}
	return *proof
}

// prove makes the edit that removes the principal grant i was read from,
// reads the edited policy again with the same owners, and offers the edit
// only when every check holds. targets are the accounts the outsider is.
func (r reading) prove(i int, targets []ring.Owner, p *placing) *Fix {
	w := r.written[i]
	st := r.statements[i]
	at := r.lay.statements[st]
	if w.Start < at.start || w.End > at.end {
		return unproven(checkSpan, spanWords("the principal is not written inside the statement its grant was read from"))
	}
	edited, removed, err := r.edit(i)
	switch {
	case err != nil:
		return unproven(checkSpan, spanWords(err.Error()))
	case removed == removedPolicy:
		return r.checkReplaced(i, targets, p, edited)
	}
	return r.check(i, targets, p, edited, removed)
}

// removedPolicy is what an edit removes when it replaces the whole policy
// with one that lets no one in, beside what aws.RemovePrincipal removes.
const removedPolicy aws.Removed = -1

// edit is the policy with the principal grant i was read from shut out,
// and what that takes out: the principal removed, by the least
// aws.RemovePrincipal removes; or, where that removes the policy's only
// statement and so would leave it with none, the whole policy, replaced by
// one that lets no one in (aws.LetNoOneIn). An edit is made only here, so
// the policy a fix is proven on is the one AppendFixed makes.
func (r reading) edit(i int) ([]byte, aws.Removed, error) {
	w := r.written[i]
	edited, removed, err := aws.RemovePrincipal(r.raw, w.Start, w.End)
	if err != nil || removed != aws.RemovedStatement || len(r.doc.Statements) > 1 {
		return edited, removed, err
	}
	replacement, err := aws.LetNoOneIn(r.raw)
	return replacement, removedPolicy, err
}

// check reads edited, the policy with removed taken out to remove the
// principal grant i was read from, again with the same owners, and offers
// the edit only when every check holds.
func (r reading) check(i int, targets []ring.Owner, p *placing, edited []byte, removed aws.Removed) *Fix {
	w := r.written[i]
	again, err := readPolicy(edited)
	if err != nil {
		return unproven(checkParse, notReadWords(err.Error()))
	}
	if fault, ok := newAnomaly(r, again, true); ok {
		return unproven(checkParse, faultWords(fault))
	}
	placedAgain := again.place(p.declared.Owners, p.recognised...)
	gone := r.goneWith(i)
	var still []ring.Owner
	for _, t := range targets {
		if len(lettingIn(placedAgain, nil, []ring.Owner{t})) > 0 {
			still = append(still, t)
		}
	}
	if len(still) > 0 {
		return unproven(checkOwner, stillLetInWords(still, p.placed, gone))
	}
	twins, missing, extra := twinsOf(r, gone, again)
	switch {
	case extra:
		return unproven(checkGrants, extraGrantWords())
	case missing > 0:
		return unproven(checkGrants, missingGrantWords(missing))
	}
	for k, twin := range twins {
		if !sameCaveats(again.grants[k], r.grants[twin]) || !placedAlike(placedAgain[k], p.placed[twin]) {
			return unproven(checkPlacements, movedWords(twin+1))
		}
	}
	var after Answer
	after.rings(placedAgain, p.declared)
	edit := r.made(i, removed, edited, gone)
	instruction := sentence(editWords(*edit, string(r.raw[w.Start:w.End])))
	return &Fix{
		Status:   fixProven,
		Sentence: instruction.Sentence,
		Spans:    instruction.Spans,
		Edit:     edit,
		ShutsOut: sentence(shutsOutWords(gone, targets)),
		After:    after.Headline,
	}
}

// checkReplaced reads replacement, the policy that replaces the whole of
// one whose only statement removing the principal grant i was read from
// would remove, again with the same owners, and offers it only when every
// check holds, as check offers an edit. The replacement keeps no grant of
// the original: its faults are counted but those of a Deny's grants, since
// a Deny that is not applied only refuses less, and with no other grant
// there is nothing for it to refuse; every grant of it is a Deny, placed in
// no ring, so that it lets in no population, the outsider's or any other,
// and none moves; and every grant of the original goes with the principal.
func (r reading) checkReplaced(i int, targets []ring.Owner, p *placing, replacement []byte) *Fix {
	w := r.written[i]
	again, err := readPolicy(replacement)
	if err != nil {
		return unproven(checkParse, replacedNotReadWords(err.Error()))
	}
	if fault, ok := newAnomaly(r, again, false); ok {
		return unproven(checkParse, replacedFaultWords(fault))
	}
	placedAgain := again.place(p.declared.Owners, p.recognised...)
	if slices.ContainsFunc(placedAgain, func(g placed) bool { return len(g.placement.Populations) > 0 }) {
		return unproven(checkOwner, replacedLetsInWords())
	}
	gone := r.goneWith(i)
	for k := range r.grants {
		if !slices.Contains(gone, k+1) {
			return unproven(checkGrants, replacedMissingWords(k+1))
		}
	}
	if slices.ContainsFunc(again.grants, func(g trust.Grant) bool { return g.Effect != trust.Deny }) {
		return unproven(checkGrants, replacedGrantWords())
	}
	var after Answer
	after.rings(placedAgain, p.declared)
	edit := r.made(i, removedPolicy, replacement, gone)
	instruction := sentence(replacedWords(*edit, string(r.raw[w.Start:w.End]), targets))
	return &Fix{
		Status:   fixProven,
		Sentence: instruction.Sentence,
		Spans:    instruction.Spans,
		Edit:     edit,
		ShutsOut: sentence(spans(grantsWords(gone) + " taken out, and no grant left lets anyone in.")),
		After:    after.Headline,
	}
}

// made is the edit a proven fix names: what removed takes out to shut out
// the principal grant i was read from, the statement that principal is
// written in, the principal, the grants that go, and the digest of edited,
// the policy it leaves.
func (r reading) made(i int, removed aws.Removed, edited []byte, gone []int) *Edit {
	w := r.written[i]
	st := r.statements[i]
	at := r.lay.statements[st]
	return &Edit{
		Removes:      removedName(removed),
		Statement:    st,
		Sid:          r.doc.Statements[st].Sid,
		FirstLine:    r.lay.line(at.start),
		LastLine:     r.lay.line(at.end - 1),
		Leaf:         Leaf{Text: w.Text, Member: "Principal." + w.Member, Line: r.lay.line(w.Start), Start: w.Start, End: w.End},
		GrantNumbers: gone,
		SHA256:       digest(edited),
	}
}

// goneWith is the numbers of the grants read from the principal grant i
// was read from: the grants removing that principal takes out.
func (r reading) goneWith(i int) []int {
	var gone []int
	for k, w := range r.written {
		if w.Start == r.written[i].Start && w.End == r.written[i].End {
			gone = append(gone, k+1)
		}
	}
	return gone
}

// newAnomaly is a fault the policy read again has more often than the
// original: in the document, or in any grant, each counted by what it says
// and not where, since removing a statement renumbers the ones after it.
// Where denies is false, the faults of the Deny grants of the policy read
// again are not counted.
func newAnomaly(original, again reading, denies bool) (trust.Anomaly, bool) {
	count := map[trust.Anomaly]int{}
	every := func(r reading, denies bool) []trust.Anomaly {
		out := slices.Clone(r.doc.Anomalies)
		for _, g := range r.grants {
			if denies || g.Effect != trust.Deny {
				out = append(out, g.Anomalies...)
			}
		}
		for k := range out {
			out[k].Source = ""
		}
		return out
	}
	for _, a := range every(original, true) {
		count[a]++
	}
	for _, a := range every(again, denies) {
		if count[a]--; count[a] < 0 {
			return a, true
		}
	}
	return trust.Anomaly{}, false
}

// lettingIn is the numbers of the grants placed, but those numbered in
// skip, with a population pinned to one of targets.
func lettingIn(placed []placed, skip []int, targets []ring.Owner) []int {
	var out []int
	for _, g := range placed {
		if slices.Contains(skip, g.number) {
			continue
		}
		if slices.ContainsFunc(g.placement.Populations, func(pop ring.Population) bool {
			return slices.ContainsFunc(pop.Owners, func(o ring.Owner) bool {
				return slices.ContainsFunc(targets, func(t ring.Owner) bool { return sameOwner(o, t) })
			})
		}) {
			out = append(out, g.number)
		}
	}
	return out
}

// sameOwner reports whether two owners are one: the same value, of the
// same kind and scope, pinned under the same issuer. Whether either is
// declared is not who it is.
func sameOwner(a, b ring.Owner) bool {
	return a.Issuer == b.Issuer && a.Scope == b.Scope && a.Kind == b.Kind && a.Value == b.Value
}

// twinsOf pairs each grant of the policy read again with a grant of the
// original that means the same, the same issuer, effect and admitted set,
// none of those numbered in gone, each original used once. missing is the
// number of the first original grant not in gone that no grant read again
// pairs with, 0 when there is none; extra is whether a grant read again
// pairs with none.
func twinsOf(original reading, gone []int, again reading) (twins []int, missing int, extra bool) {
	used := make([]bool, len(original.grants))
	for _, n := range gone {
		used[n-1] = true
	}
	for _, g := range again.grants {
		twin := -1
		for k, o := range original.grants {
			if !used[k] && o.Issuer == g.Issuer && o.Effect == g.Effect && o.Admits.String() == g.Admits.String() {
				twin = k
				break
			}
		}
		if twin < 0 {
			return nil, 0, true
		}
		used[twin] = true
		twins = append(twins, twin)
	}
	if at := slices.Index(used, false); at >= 0 {
		return nil, at + 1, false
	}
	return twins, 0, false
}

// sameCaveats reports whether two grants' sets are upper bounds for the
// same reasons on the same claims: a set that is exact on one side and not
// on the other is placed with another certainty, and a caveat on a claim
// can decide whether an owner pins it. Where a caveat was read is not
// compared, since removing a statement renumbers the ones after it.
func sameCaveats(a, b trust.Grant) bool {
	count := map[string]int{}
	for _, c := range a.Admits.Caveats() {
		count[string(c.Claim)+"\x00"+c.Reason]++
	}
	for _, c := range b.Admits.Caveats() {
		count[string(c.Claim)+"\x00"+c.Reason]--
	}
	for _, n := range count {
		if n != 0 {
			return false
		}
	}
	return true
}

// placedAlike reports whether a grant of the edited policy is placed by the
// facts its twin was, those the parser reads from the statement, and so
// lands where its twin does whoever the owners are, and whether each of its
// populations lands at its twin's place or a nearer ring.
func placedAlike(again, original placed) bool {
	if again.facts.Issuerless != original.facts.Issuerless || again.facts.PrincipalModelled != original.facts.PrincipalModelled {
		return false
	}
	a, o := again.placement, original.placement
	if a.Outcome != o.Outcome || len(a.Populations) != len(o.Populations) {
		return false
	}
	for k := range a.Populations {
		now, before := a.Populations[k].Place, o.Populations[k].Place
		if now != before && !(now.Ring() && before.Ring() && now > before) {
			return false
		}
	}
	return true
}

// removedName is what an edit removes, as Edit.Removes writes it.
func removedName(r aws.Removed) string {
	switch r {
	case aws.RemovedPrincipal:
		return "principal"
	case aws.RemovedKind:
		return "member"
	case removedPolicy:
		return "policy"
	}
	return "statement"
}

// unproven is a fix the engine cannot prove, for the reason check names,
// in words.
func unproven(check string, words []Span) *Fix {
	s := sentence(append([]Span{{Text: "No fix the engine can prove yet: "}}, words...))
	return &Fix{Status: fixUnproven, Check: check, Sentence: s.Sentence, Spans: s.Spans}
}

// inWords is a fix named in words and not proven.
func inWords(words []Span) *Fix {
	s := sentence(words)
	return &Fix{Status: fixWords, Sentence: s.Sentence, Spans: s.Spans}
}

// platformFix is the fix of a population on a platform: the condition that
// would pin it to an owner, in words, when the population is let in because
// nothing pins it, or because a condition that might was not read, since a
// statement's conditions all hold at once and a pin confines the
// population whatever else is not read; otherwise why no condition the
// engine can name would.
func platformFix(g placed, pop ring.Population) *Fix {
	if pop.Basis != ring.Unpinned && pop.Basis != ring.UnreadConstraint {
		return unproven(checkCondition, spans(unconfined(pop.Basis, pop.Bounded, g.issuer)+", so no condition the engine can name would pin it."))
	}
	if g.issuer == aws.AWSPrincipalIssuer {
		return inWords(spans("A condition on ", Span{Text: "aws:PrincipalAccount", Mark: "code"}, " naming your own account, or on ", Span{Text: "aws:PrincipalOrgID", Mark: "code"}, " naming your AWS Organization, would let in only that account or that Organization's accounts; the engine does not prove that change yet."))
	}
	claims := tenantClaims(g)
	if len(claims) == 0 {
		return inWords(spans("A condition naming an owner of yours, on a claim of these tokens that names one, would let in only that owner's tokens; the engine does not prove that change yet."))
	}
	s := spans("A condition naming an owner of yours, on ")
	for k, c := range claims {
		switch {
		case k > 0 && k == len(claims)-1:
			s = append(s, Span{Text: " or "})
		case k > 0:
			s = append(s, Span{Text: ", "})
		}
		s = append(s, Span{Text: c, Mark: "code"})
	}
	return inWords(append(s, Span{Text: ", would let in only that owner's tokens; the engine does not prove that change yet."}))
}

// tenantClaims are the claims of a platform's tokens that name an owner and
// whose condition keys AWS documents for the issuer: sub, when the census
// records the forms of sub that lead with an owner, and each claim it
// records as naming an owner, in its order. A claim naming a repository or
// an enterprise is not one: a condition on it lets in less, or more, than
// an owner's tokens.
func tenantClaims(g placed) []string {
	t := g.facts.Tenancy
	if t == nil {
		return nil
	}
	var out []string
	documented := func(claim string) bool {
		d, _ := registry.AWSDocumentsConditionKey(g.issuer, claim)
		return d
	}
	if len(t.SubjectForms) > 0 && documented("sub") {
		out = append(out, "sub")
	}
	for _, c := range t.Claims {
		if c.Scope == ring.ScopeOwner && !slices.Contains(out, string(c.Claim)) && documented(string(c.Claim)) {
			out = append(out, string(c.Claim))
		}
	}
	return out
}

// serviceFix is the fix of a cloud service's population, named and not
// proven: the one service in place of "*", or the source account the
// service acts for, which the engine does not read where the statement
// names it.
func serviceFix(r reading, i int, g placed, pop ring.Population) *Fix {
	if pop.Basis == ring.AnyService {
		return inWords(spans("Naming the one AWS service this role is for, in place of ", Span{Text: `"*"`, Mark: "code"}, ", would shut every other service out; the engine does not prove that change yet."))
	}
	service := Span{Text: strings.TrimPrefix(string(g.issuer), aws.ServiceIssuerPrefix), Mark: "code"}
	for _, k := range r.lay.statements[r.statements[i]].keys {
		if fold(k.key) == "aws:sourceaccount" {
			return inWords(spans("The statement names ", Span{Text: "aws:SourceAccount", Mark: "code"}, ", which the engine does not read yet, so whether it keeps ", service, " acting for this account's own resources is not proven."))
		}
	}
	return inWords(spans("Where ", service, " sends ", Span{Text: "aws:SourceAccount", Mark: "code"}, ", a condition on it naming this account keeps the service acting for this account's own resources; the engine does not prove that change yet."))
}

// statementWords is where the statement an edit is made in is: its number,
// its Sid where it has one, and its lines.
func statementWords(e Edit) []Span {
	ref := []Span{{Text: "statement " + strconv.Itoa(e.Statement+1)}}
	if e.Sid != "" {
		ref = append(ref, Span{Text: " (\""}, Span{Text: e.Sid, Mark: "code"}, Span{Text: "\")"})
	}
	at := ", line " + strconv.Itoa(e.FirstLine)
	if e.LastLine != e.FirstLine {
		at = ", lines " + strconv.Itoa(e.FirstLine) + "-" + strconv.Itoa(e.LastLine)
	}
	return append(ref, Span{Text: at})
}

// editWords is the edit in one sentence: where, and what to remove, the
// principal quoted as its literal is written so that it can be found.
func editWords(e Edit, literal string) []Span {
	ref := statementWords(e)
	leaf := Span{Text: literal, Mark: "code"}
	switch e.Removes {
	case "principal":
		return slices.Concat([]Span{{Text: "In "}}, ref, spans(", remove ", leaf, " from ", Span{Text: e.Leaf.Member, Mark: "code"}, "."))
	case "member":
		return slices.Concat([]Span{{Text: "In "}}, ref, spans(", remove ", Span{Text: e.Leaf.Member, Mark: "code"}, ", which names only ", leaf, "."))
	}
	return slices.Concat([]Span{{Text: "Remove "}}, ref, spans(": the only principal it names is ", leaf, "."))
}

// replacedWords is the replacement of a whole policy in words: where its
// only statement is and the only principal that statement names, the
// principal quoted as its literal is written, and why the policy is
// replaced rather than the statement removed; then, beside it, whom it
// shuts out, and what it does not do.
//
// Replacing a trust policy does not end a session already open:
// "Temporary security credentials are valid until they expire." Ending
// them is a step of its own: "For IAM role sessions, you can revoke the
// role's temporary security credentials to force all users assuming the
// role to reauthenticate and request new credentials."
// (https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp_control-access_disable-perms.html),
// which the IAM console does with "Revoke active sessions"
// (https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_revoke-sessions.html).
// The words give no bound on how long that lasts. Credentials still valid
// can be sent to the federation endpoint for a console session, and that
// call does not read the trust policy. The console session's
// SessionDuration "is separate from the duration of the temporary
// credentials", is at most 12 hours from sign-in, and "cannot be greater
// than or equal to the maximum session duration setting for the role";
// "you can immediately disable the active console sessions for any role by
// choosing Revoke Sessions"
// (https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_enable-console-custom-url.html).
// So a console session made just before the credentials expire outlasts
// them, and revoking is the only step that ends both now. A session can
// take hours to end, as the words say: a console session alone can last
// up to 12 from sign-in.
func replacedWords(e Edit, literal string, targets []ring.Owner) []Span {
	return slices.Concat(
		spans("Replace the whole trust policy with one that lets no one in: "),
		statementWords(e),
		spans(", is its only statement, the only principal it names is ", Span{Text: literal, Mark: "code"}, ", and IAM refuses a trust policy with no statement. This stops "),
		ownersSpans(targets),
		spans(" from getting in. If you still work with them, don't apply it."+
			` Anyone already in keeps their access until their session ends, which can take hours. The role's "Revoke active sessions" ends those sessions now.`+
			" Deleting the role instead also removes what its permissions allow."),
	)
}

// shutsOutWords is what a proven edit takes out: its grants, by number,
// and that no grant left lets the outsider in by name.
func shutsOutWords(gone []int, targets []ring.Owner) []Span {
	return slices.Concat(spans(grantsWords(gone)+" taken out, and no grant left lets "), ownersSpans(targets), spans(" in by name."))
}

// grantsWords names grants by number as the subject of "is" or "are".
func grantsWords(numbers []int) string {
	if len(numbers) == 1 {
		return "Grant " + strconv.Itoa(numbers[0]) + " is"
	}
	return "Grants " + numberList(numbers) + " are"
}

// numberList is "1", "1 and 2", "1, 2 and 3".
func numberList(numbers []int) string {
	words := make([]string, len(numbers))
	for i, n := range numbers {
		words[i] = strconv.Itoa(n)
	}
	if len(words) == 1 {
		return words[0]
	}
	return strings.Join(words[:len(words)-1], ", ") + " and " + words[len(words)-1]
}

// ownersSpans names owners inside a sentence, each in the code face,
// joined with "and".
func ownersSpans(owners []ring.Owner) []Span {
	var s []Span
	for i, o := range owners {
		switch {
		case i > 0 && i == len(owners)-1:
			s = append(s, Span{Text: " and "})
		case i > 0:
			s = append(s, Span{Text: ", "})
		}
		s = append(s, Span{Text: ownerName(o), Mark: "code"})
	}
	return s
}

// leafWords is why no edit is made for a population no principal names:
// the owners are let in by a condition.
func leafWords(owners []ring.Owner) []Span {
	verb := " is"
	if len(owners) > 1 {
		verb = " are"
	}
	return append(ownersSpans(owners), Span{Text: verb + " let in by a condition, not by a principal the statement names."})
}

// principalWords is why no edit is made for a way in through a principal
// the engine does not remove: the principal as written and where, or that
// none the engine reads lets it in. The engine removes only a principal
// written under Principal.AWS, other than "*", that it reads as naming an
// AWS account.
func principalWords(w aws.Written) []Span {
	underAWS, star := Span{Text: "Principal.AWS", Mark: "code"}, Span{Text: `"*"`, Mark: "code"}
	if w == (aws.Written{}) {
		return spans("no principal the engine reads lets this way in, and so far it removes only a principal written under ", underAWS, ", other than ", star, ".")
	}
	member := "Principal"
	if w.Member != "" {
		member += "." + w.Member
	}
	through := spans("this way in is through ", Span{Text: w.Text, Mark: "code"}, " at ", Span{Text: member, Mark: "code"})
	if w.Member == "AWS" && w.Text != "*" {
		return append(through, spans(", which the engine does not read as naming an AWS account, and so far it removes only a principal it reads as naming one.")...)
	}
	return append(through, spans(", and so far the engine removes only a principal written under ", underAWS, ", other than ", star, ".")...)
}

// effectWords is why no edit is made to a statement not read as an Allow.
func effectWords(statement int) []Span {
	return spans("statement " + strconv.Itoa(statement+1) + " is not read as an Allow, and the engine removes a principal only from an Allow statement.")
}

// fixBoundWords is why no edit is tried past the engine's bound on reading
// edited policies again.
func fixBoundWords() []Span {
	return spans("proving it would take the engine past the " + strconv.Itoa(MaxDocumentBytes) + " bytes it reads again for one answer's fixes.")
}

// fixGrantsWords is why no edit is tried past the engine's bound on placing
// the grants of edited policies again.
func fixGrantsWords() []Span {
	return spans("proving it would take the engine past the " + strconv.Itoa(maxFixGrants) + " grants it places again for one answer's fixes.")
}

// spanWords is why the principal's bytes could not be edited.
func spanWords(why string) []Span { return spans(why + ".") }

// notReadWords is why the edited policy is not read.
func notReadWords(why string) []Span {
	return spans("with the principal removed, the policy is not read: " + why + ".")
}

// faultWords names a fault the edited policy has that the original does
// not, in the parser's words.
func faultWords(a trust.Anomaly) []Span {
	return spans("with the principal removed, the policy reads with a fault it does not have now: " + a.Message + ".")
}

// stillLetInWords is why removing the principal does not shut the outsider
// out: still, the owners the edited policy lets in by name, and the grants
// of the original but those numbered in gone that let any of them in by
// name, each with only the owners it lets in, grants that let in the same
// owners together; or, when no grant of the original does, that the
// edited policy would.
func stillLetInWords(still []ring.Owner, original []placed, gone []int) []Span {
	type clause struct {
		grants []int
		owners []ring.Owner
	}
	var clauses []clause
	for _, g := range original {
		var owners []ring.Owner
		for _, t := range still {
			if len(lettingIn([]placed{g}, gone, []ring.Owner{t})) > 0 {
				owners = append(owners, t)
			}
		}
		if len(owners) == 0 {
			continue
		}
		at := slices.IndexFunc(clauses, func(c clause) bool {
			return slices.EqualFunc(c.owners, owners, sameOwner)
		})
		if at < 0 {
			clauses = append(clauses, clause{owners: owners})
			at = len(clauses) - 1
		}
		clauses[at].grants = append(clauses[at].grants, g.number)
	}
	if len(clauses) == 0 {
		return append(append([]Span{{Text: "with the principal removed, a grant would still let "}}, ownersSpans(still)...), Span{Text: " in by name."})
	}
	var s []Span
	for k, c := range clauses {
		switch {
		case k > 0 && k == len(clauses)-1:
			s = append(s, Span{Text: " and "})
		case k > 0:
			s = append(s, Span{Text: ", "})
		}
		lead := "grant " + strconv.Itoa(c.grants[0]) + " also lets "
		if len(c.grants) > 1 {
			lead = "grants " + numberList(c.grants) + " also let "
		}
		s = append(append(append(s, Span{Text: lead}), ownersSpans(c.owners)...), Span{Text: " in by name"})
	}
	pronoun := "it"
	if len(still) > 1 {
		pronoun = "them"
	}
	return append(s, Span{Text: ", so removing this principal does not shut " + pronoun + " out."})
}

// replacedNotReadWords is why a replacement that is not read is not
// offered.
func replacedNotReadWords(why string) []Span {
	return spans("the policy that would replace it is not read: " + why + ".")
}

// replacedFaultWords names a fault the replacement has that the original
// does not, beside those of its own Deny, in the parser's words.
func replacedFaultWords(a trust.Anomaly) []Span {
	return spans("the policy that would replace it reads with a fault this one does not have: " + a.Message + ".")
}

// replacedLetsInWords is why a replacement that lets someone in is not
// offered.
func replacedLetsInWords() []Span {
	return spans("the policy that would replace it would still let someone in.")
}

// replacedGrantWords is why a replacement that makes a grant other than a
// Deny is not offered.
func replacedGrantWords() []Span {
	return spans("the policy that would replace it would make a grant that is not a Deny.")
}

// replacedMissingWords is why a replacement that takes out a grant the
// principal does not make is not offered.
func replacedMissingWords(number int) []Span {
	return spans("replacing the policy would take grant " + strconv.Itoa(number) + " out as well, which this principal does not make.")
}

// missingGrantWords is why an edit that takes out another grant too is not
// offered.
func missingGrantWords(number int) []Span {
	return spans("removing it would take grant " + strconv.Itoa(number) + " out as well, which this principal does not make.")
}

// extraGrantWords is why an edit that makes a grant the original does not
// is not offered.
func extraGrantWords() []Span {
	return spans("with the principal removed, the policy would make a grant it does not make now.")
}

// movedWords is why an edit that would place a grant left by other facts
// is not offered.
func movedWords(number int) []Span {
	return spans("with the principal removed, grant " + strconv.Itoa(number) + " would not be placed as it is now.")
}
