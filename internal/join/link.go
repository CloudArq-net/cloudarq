package join

import (
	"bytes"
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/CloudArq-net/cloudarq/internal/eval"
	"github.com/CloudArq-net/cloudarq/internal/evidence"
	"github.com/CloudArq-net/cloudarq/internal/trust"
)

// LinkKind names the join that produced a Link.
type LinkKind string

// CounterpartyFanOut is J6: one counterparty, known by its issuer and the
// identities it can present, admitted by more than one target.
const CounterpartyFanOut LinkKind = "counterparty-fan-out"

// Confidence is two-valued on purpose: there is no "probably". A Link is
// Established when an identity both sides admit was built and confirmed,
// both sides name their issuer, both admitted sets are exact, both effects
// read Allow, every evidence record on both sides names its call and its
// status and is conclusive, and no statement on either target that denies,
// or whose effect could not be read, can touch the overlap or was read
// too doubtfully to say. Anything short of that is Indeterminate, and the
// reason says which of those failed and how.
type Confidence string

const (
	Established   Confidence = "established"
	Indeterminate Confidence = "indeterminate"
)

// GrantRef is the cloud side of a Link: one statement, by everything that
// tells it from the other statements on its target. Admits is the canonical
// rendering of the grant's whole admitted set, audience included; Caveats
// are why that set is an upper bound, when it is; Effect is Allow or the
// effect the parser could not read. Two statements on one role can admit
// one set and differ in nothing else, and a reader folding links by their
// grants must not fold the exact statement with the doubtful one.
type GrantRef struct {
	Target  trust.TargetRef
	Issuer  trust.IssuerRef
	Effect  trust.Effect
	Admits  string
	Caveats []eval.Caveat
}

// CounterpartyRef is the other side of a fan-out: the issuer and the
// identities it can present that every target of the Link admits. Issuer
// is the one the sides name, and "" when neither does. Overlap is the
// canonical rendering of the identities, for machines; Witness is one such
// identity, for people, and is nil when none could be built.
type CounterpartyRef struct {
	Issuer  trust.IssuerRef
	Overlap string
	Witness map[trust.ClaimKey]string
}

// Link is a fact that needed two independently controlled systems to
// establish: neither side's API returns it. Its fields are unexported so
// that a Link exists only through NewLink or FanOut, which refuse to build
// one without evidence from every side; the zero value answers every
// method with nothing and renders as an error.
type Link struct {
	kind       LinkKind
	grants     []GrantRef
	subject    CounterpartyRef
	confidence Confidence
	reason     string
	sentence   string
	provenance []evidence.Record
}

// The reasons NewLink refuses a pair. Each names the pair in its message
// and wraps one of these, so a caller can tell a parser bug (a grant that
// names no target) and a collector bug (no evidence, or none that names
// its call and its status) from a pair that simply is not a fan-out.
var (
	ErrNoTarget          = errors.New("names no target")
	ErrNoEvidence        = errors.New("carries no evidence")
	ErrMalformedEvidence = errors.New("carries only malformed evidence records")
	ErrSameTarget        = errors.New("one target on both sides")
	ErrDifferentIssuers  = errors.New("different issuers")
	ErrDeny              = errors.New("a Deny grant admits nobody and is not a side")
	ErrDisjoint          = errors.New("the admitted sets are provably disjoint")
)

// NewLink builds the fan-out Link between two grants on two targets whose
// issuers may coincide, or explains why the two are not a pair. denials
// are the grants from anywhere in the corpus that may deny: Deny grants,
// and grants whose effect could not be read, which are possibly Allow, so
// they pair, and possibly Deny, so they doubt. Those on either target
// whose issuer may be the pair's count against the pair when they can
// touch the overlap, or were read too doubtfully to bound; their evidence
// then joins the Link's. A side is never its own denial.
//
// The overlap is computed with each grant's audience set aside, because
// audiences are provider-specific by nature and a counterparty presents a
// different one to each cloud; the identities admitted are what the two
// sides can agree on.
//
// A blank issuer is an issuer the parser could not name: AWS's bare "*"
// principal admits every identity provider's tokens through
// sts:AssumeRoleWithWebIdentity without saying which. Such a grant may
// admit the same counterparty as any issuer's grant, so it pairs with each
// of them, never Established, and the pair's issuer is the one the other
// side names.
func NewLink(a, b trust.Grant, denials ...trust.Grant) (Link, error) {
	// The sides are read in canonical order before anything else, so that a
	// refusal, like a Link, is the same bytes whichever way the pair was
	// given: the side named first is the one that sorts first.
	if compareGrants(a, b) > 0 {
		a, b = b, a
	}
	if err := pairable(a, b); err != nil {
		return Link{}, err
	}
	from, to := describeTarget(a.Target), describeTarget(b.Target)
	issuer := issuerOf(a, b)
	identitiesA, identitiesB := a.WithoutAudience(), b.WithoutAudience()
	overlap := identitiesA.Meet(identitiesB)
	if overlap.IsEmpty() {
		return Link{}, fmt.Errorf("link %s with %s: %w", from, to, ErrDisjoint)
	}
	witness := witnessOf(overlap, identitiesA, identitiesB)

	var doubts []string
	records := slices.Concat(a.Provenance, b.Provenance)
	for _, side := range []trust.Grant{a, b} {
		doubts = append(doubts, doubtsAbout(side)...)
		counted := denialsAgainst(side, issuer, overlap, denials)
		doubts = append(doubts, describeDenials(side.Target, counted)...)
		for _, d := range counted {
			records = append(records, d.grant.Provenance...)
		}
	}
	if widened := caveatsBeyond(overlap, a.Admits, b.Admits); len(widened) > 0 {
		doubts = append(doubts, "the identities admitted by both are an upper bound ("+strings.Join(widened, "; ")+")")
	}
	description, exemplified := describeAdmitted(overlap, issuer)
	if witness == nil {
		doubts = append(doubts, "no example identity could be constructed for "+description)
	}

	l := Link{
		kind:       CounterpartyFanOut,
		grants:     []GrantRef{refOf(a), refOf(b)},
		subject:    CounterpartyRef{Issuer: issuer, Overlap: overlap.String(), Witness: witness},
		confidence: Indeterminate,
		provenance: owned(canonicalRecords(records)),
	}
	reason := strings.Join(doubts, "; ")
	sentence := "Identities admitted by " + from + " may also be admitted by " + to + fromIssuer(issuer) + "; " + reason + "."
	if len(doubts) == 0 {
		l.confidence = Established
		reason = "both admit " + description
		if exemplified {
			reason += ", for example " + describeToken(witness)
		}
		sentence = "Identities admitted by " + from + " are also admitted by " + to + ": " + reason + "."
	}
	l.reason, l.sentence = printable(reason), printable(sentence)
	return l, nil
}

// pairable is why a and b cannot be the two sides of a fan-out, if they
// cannot be. A grant that is not well formed is refused here rather than
// tolerated: a Link is the claim that two named systems were read, and a
// side nobody read, or nobody can name, is not a side. Target identity is
// struct equality on TargetRef, so a parser must spell one resource's Kind
// one way.
func pairable(a, b trust.Grant) error {
	pair := "link " + nameOf(a) + " with " + nameOf(b)
	for _, g := range []trust.Grant{a, b} {
		if err := named(g); err != nil {
			return fmt.Errorf("%s: %w", pair, err)
		}
	}
	if a.Target == b.Target {
		return fmt.Errorf("%s: %w", pair, ErrSameTarget)
	}
	if !mayShareIssuer(a.Issuer, b.Issuer) {
		return fmt.Errorf("link %s from %s with %s from %s: %w", nameOf(a), a.Issuer, nameOf(b), b.Issuer, ErrDifferentIssuers)
	}
	for _, g := range []trust.Grant{a, b} {
		if g.Effect == trust.Deny {
			return fmt.Errorf("%s: %s: %w", pair, nameOf(g), ErrDeny)
		}
	}
	for _, g := range []trust.Grant{a, b} {
		if err := evidenced(g); err != nil {
			return fmt.Errorf("%s: %w", pair, err)
		}
	}
	return nil
}

// wellFormed is why a grant cannot be a side of any Link, if it cannot: the
// sentence names the target and every call made, and a blank where a name
// goes is not a sentence.
func wellFormed(g trust.Grant) error {
	if err := named(g); err != nil {
		return err
	}
	return evidenced(g)
}

// named is why a grant cannot be spoken of: it names no target, which is a
// parser bug.
func named(g trust.Grant) error {
	if blank(g.Target.ID) {
		return fmt.Errorf("%s %w", describeGrant(g), ErrNoTarget)
	}
	return nil
}

// evidenced is why a named grant's provenance cannot back a Link: it has
// no record, or none that names its call and its status, which is a
// collector bug. One such record beside well-formed ones does not refuse
// the grant: the fan-out is then real and proved, the sentence can name
// the defect, and dropping the pair would report it as absent. The
// records are read in canonical order, so the one the error names does
// not depend on the order the collector listed them in.
func evidenced(g trust.Grant) error {
	if len(g.Provenance) == 0 {
		return fmt.Errorf("%s %w", describeGrant(g), ErrNoEvidence)
	}
	records := canonicalRecords(g.Provenance)
	if slices.ContainsFunc(records, func(r evidence.Record) bool { return malformed(r) == "" }) {
		return nil
	}
	return fmt.Errorf("%s %w: %s", describeGrant(g), ErrMalformedEvidence, malformed(records[0]))
}

// malformed is what keeps a record from being named, naming the record by
// its call, or "" when nothing does. The sentence names a record by its
// call and its status, and a blank where either goes is not a sentence.
// The body is not read: whatever bytes the call returned, the rendering
// carries them.
func malformed(r evidence.Record) string {
	switch {
	case blank(r.API):
		return "a record names no API call"
	case blank(string(r.Status)):
		return "the record of " + r.API + " names no status"
	}
	return ""
}

// blank reports whether a name has nothing printable in it. The sentence
// strips control characters before it is printed, so a name made of them
// prints as nothing, exactly as one made of spaces does; either is a hole
// where a name goes, and a hole is no name.
func blank(s string) bool { return strings.TrimSpace(printable(s)) == "" }

// nameOf is how an error names a grant: by its target, or as "a grant"
// when the target has no identifier to name it by.
func nameOf(g trust.Grant) string {
	if blank(g.Target.ID) {
		return "a grant"
	}
	return describeTarget(g.Target)
}

// describeGrant is nameOf with the issuer, when the grant names one: two
// statements on one target from two issuers are told apart by it.
func describeGrant(g trust.Grant) string {
	if blank(string(g.Issuer)) {
		return nameOf(g)
	}
	return nameOf(g) + " from " + string(g.Issuer)
}

// mayShareIssuer reports whether two issuers may be one: they are, or one
// of them is not named, and so may be any. A blank issuer is Unknown on
// the claim the trust model keeps beside the lattice rather than in it,
// and Unknown meets anything to give the other operand.
func mayShareIssuer(x, y trust.IssuerRef) bool {
	return blank(string(x)) || blank(string(y)) || x == y
}

// issuerOf is the issuer of a pair: the one named, when only one side
// names one; theirs when both do, since they pair only when they agree;
// and "" when neither does.
func issuerOf(a, b trust.Grant) trust.IssuerRef {
	if !blank(string(a.Issuer)) {
		return a.Issuer
	}
	if !blank(string(b.Issuer)) {
		return b.Issuer
	}
	return ""
}

// fromIssuer is the sentence's "from <issuer>", or nothing when the pair
// has no issuer to name.
func fromIssuer(issuer trust.IssuerRef) string {
	if issuer == "" {
		return ""
	}
	return " from " + string(issuer)
}

// doubtsAbout lists, as sentences, everything about one side that keeps
// the pair from being Established: an issuer it does not name, an effect
// that could not be read, an admitted set that is an upper bound, a
// constraint left Unknown with no caveat saying so, and every evidence
// record that is malformed or inconclusive.
func doubtsAbout(g trust.Grant) []string {
	target := describeTarget(g.Target)
	var doubts []string
	if blank(string(g.Issuer)) {
		doubts = append(doubts, "which issuers' tokens "+target+" admits is not known")
	}
	if g.Effect != trust.Allow {
		doubts = append(doubts, "the effect of the statement granting "+target+" could not be read")
	}
	if caveats := g.Admits.Caveats(); len(caveats) > 0 {
		doubts = append(doubts, "the identities admitted by "+target+" are an upper bound ("+strings.Join(describeCaveats(caveats), "; ")+")")
	}
	for _, claim := range undeclaredUnknowns(g) {
		doubts = append(doubts, "the constraint on "+claim.name+" for "+target+" was not evaluated ("+claim.reason+")")
	}
	return append(doubts, recordDoubts(g)...)
}

// recordDoubts lists, in record order, every record of a grant that cannot
// support a finding: one that names no call or no status, which the
// sentence cannot name and so describes, and one whose status is
// inconclusive.
func recordDoubts(g trust.Grant) []string {
	target := describeTarget(g.Target)
	var doubts []string
	for _, r := range canonicalRecords(g.Provenance) {
		switch {
		case blank(r.API):
			doubts = append(doubts, "a record for "+target+" names no API call")
		case blank(string(r.Status)):
			doubts = append(doubts, "the record of "+r.API+" for "+target+" names no status")
		case !r.Status.Conclusive():
			doubts = append(doubts, "the call "+r.API+" for "+target+" returned "+string(r.Status))
		}
	}
	return doubts
}

// unevaluated is a claim a grant left Unknown without declaring it.
type unevaluated struct{ name, reason string }

// undeclaredUnknowns is the join's copy of the rule the parser harness
// enforces: an Unknown beside a real constraint, with no caveat naming its
// claim, is silence read as clean. The lattice drops the flag under Meet,
// so it can only be seen on the grant itself, before the overlap is taken.
func undeclaredUnknowns(g trust.Grant) []unevaluated {
	declared := map[trust.ClaimKey]bool{}
	for _, c := range g.Admits.Caveats() {
		declared[c.Claim] = true
	}
	var out []unevaluated
	for _, term := range g.Admits.Terms() {
		for _, k := range slices.Sorted(maps.Keys(term)) {
			if eval.IsUnknown(term[k]) && !declared[k] {
				out = append(out, unevaluated{string(k), eval.Reason(term[k])})
			}
		}
	}
	slices.SortFunc(out, func(x, y unevaluated) int {
		return cmp.Or(cmp.Compare(x.name, y.name), cmp.Compare(x.reason, y.reason))
	})
	return slices.Compact(out)
}

// denial is a statement counted against a pair on one side: a Deny, or a
// statement whose effect could not be read, with the reasons its reading
// cannot bound what it denies, when it has any.
type denial struct {
	grant    trust.Grant
	unproved []string
}

// denialsAgainst is every statement on the side's target, from an issuer
// that may be the pair's, that may take an identity out of the overlap:
// the Denies, and the statements whose effect could not be read, that
// admit some token the side admits with an identity in the overlap, or
// whose reading cannot be relied on to say. The reach is one Meet of the
// three sets, so a Deny whose audiences and subjects are paired up is read
// as the tokens it denies and not as its audiences and its subjects apart.
// One that provably misses, read exactly and conclusively, is not a
// doubt; one whose reach cannot be decided is, since the lattice has no
// complement to subtract it with; and one read as an upper bound, without
// evidence, or through a record that is malformed or inconclusive is a
// doubt wherever its reading puts it, because what it denies is then at
// least what was read, and may be more. The side itself is not a doubt
// about itself: its own unread effect is its own doubt.
func denialsAgainst(side trust.Grant, issuer trust.IssuerRef, overlap eval.AdmittedSet, denials []trust.Grant) []denial {
	var out []denial
	for _, d := range denials {
		if d.Effect == trust.Allow || d.Target != side.Target || !mayShareIssuer(d.Issuer, issuer) || compareGrants(d, side) == 0 {
			continue
		}
		unproved := unprovedReading(d)
		if len(unproved) == 0 && d.Admits.Meet(side.Admits).Meet(overlap).IsEmpty() {
			continue
		}
		out = append(out, denial{d, unproved})
	}
	return out
}

// unprovedReading lists why a statement's reading cannot be relied on to
// bound what it denies: an admitted set that is an upper bound, no
// evidence at all, and every record that is malformed or inconclusive.
func unprovedReading(g trust.Grant) []string {
	var out []string
	if caveats := g.Admits.Caveats(); len(caveats) > 0 {
		out = append(out, describeCaveats(caveats)...)
	}
	if len(g.Provenance) == 0 {
		out = append(out, "the statement carries no evidence")
	}
	return append(out, recordDoubts(g)...)
}

// describeDenials is one sentence per issuer of the Denies counted against
// a side, then one per issuer of the unread statements, each carrying the
// reasons the statements were read too doubtfully to bound, when they
// were. The issuers are read in order, so the sentences are a function of
// the statements alone.
func describeDenials(target trust.TargetRef, counted []denial) []string {
	denies, unreads := map[string][]string{}, map[string][]string{}
	for _, d := range counted {
		group := unreads
		if d.grant.Effect == trust.Deny {
			group = denies
		}
		phrase := issuerPhrase(d.grant.Issuer)
		group[phrase] = append(group[phrase], d.unproved...)
	}
	var out []string
	for _, phrase := range slices.Sorted(maps.Keys(denies)) {
		out = append(out, describeTarget(target)+" also denies identities from "+phrase+", and whether these are among them could not be decided"+parenthetical(denies[phrase]))
	}
	for _, phrase := range slices.Sorted(maps.Keys(unreads)) {
		out = append(out, describeTarget(target)+" also has a statement from "+phrase+" whose effect could not be read, and whether it denies these identities could not be decided"+parenthetical(unreads[phrase]))
	}
	return out
}

// issuerPhrase names a statement's issuer in a sentence about the
// statement, or says that it names none.
func issuerPhrase(issuer trust.IssuerRef) string {
	if blank(string(issuer)) {
		return "an issuer it does not name"
	}
	return string(issuer)
}

// parenthetical is the details a sentence carries in brackets, sorted and
// read once each, or nothing when there are none.
func parenthetical(details []string) string {
	if len(details) == 0 {
		return ""
	}
	sorted := slices.Clone(details)
	slices.Sort(sorted)
	return " (" + strings.Join(slices.Compact(sorted), "; ") + ")"
}

// caveatsBeyond lists the caveats the overlap carries that neither side
// did: a widening the Meet itself applied, which makes the overlap an upper
// bound even between two exact grants.
func caveatsBeyond(overlap, a, b eval.AdmittedSet) []string {
	carried := map[eval.Caveat]bool{}
	for _, c := range slices.Concat(a.Caveats(), b.Caveats()) {
		carried[c] = true
	}
	var out []string
	for _, c := range overlap.Caveats() {
		if !carried[c] {
			out = append(out, c.Reason)
		}
	}
	return out
}

func describeCaveats(caveats []eval.Caveat) []string {
	out := make([]string, len(caveats))
	for i, c := range caveats {
		out[i] = c.Reason
		if c.Source != "" {
			out[i] += " at " + c.Source
		}
	}
	return out
}

// describeAdmitted says what the overlap admits in the customer's words,
// and whether an example would add anything: a value repeated as its own
// example is noise, a pattern's example is the point.
func describeAdmitted(overlap eval.AdmittedSet, issuer trust.IssuerRef) (string, bool) {
	if overlap.IsTop() {
		return "any identity" + fromIssuer(issuer), false
	}
	exemplified := false
	var terms []string
	for _, term := range overlap.Terms() {
		var claims []string
		for _, c := range constraintsOf(term) {
			if c.top {
				claims = append(claims, "any "+string(c.claim))
				continue
			}
			claims = append(claims, string(c.claim)+" "+c.shape.describe())
			exemplified = exemplified || c.shape.kind != exactValue
		}
		terms = append(terms, prose(claims))
	}
	combinations := abbreviate(terms, func(n int) string { return "one of " + strconv.Itoa(n) + " more combinations" })
	return "identities" + fromIssuer(issuer) + " with " + strings.Join(combinations, ", or with "), exemplified
}

// describe is the shape in words: the value itself, "matching" a pattern,
// "matching all of" the patterns of an intersection, and the alternatives
// of a union joined by "or". The empty value is the one value that cannot
// be shown as itself.
func (s shape) describe() string {
	switch s.kind {
	case exactValue:
		if s.text == "" {
			return `""`
		}
		return s.text
	case globPattern:
		return "matching " + s.text
	case allOf:
		return "matching all of " + prose(abbreviate(s.patterns(), func(n int) string { return strconv.Itoa(n) + " more patterns" }))
	}
	alternatives := make([]string, len(s.members))
	for i, m := range s.members {
		alternatives[i] = m.describe()
	}
	return strings.Join(abbreviate(alternatives, func(n int) string { return "one of " + strconv.Itoa(n) + " more alternatives" }), " or ")
}

// listed is how many members of a list the sentence names before counting
// the rest: enough to show the shape of the overlap, few enough that a
// policy listing thirty repositories against another listing thirty still
// reads as one sentence. The rendering on the Link carries every member.
const listed = 3

// abbreviate names the first members of a long list and counts the rest
// as one more item of rest's making. A list one over the cap is named
// whole, since "and 1 more" hides nothing shorter than what it hides.
func abbreviate(items []string, rest func(n int) string) []string {
	if len(items) <= listed+1 {
		return items
	}
	return append(slices.Clone(items[:listed]), rest(len(items)-listed))
}

// prose joins items the way a sentence does: "a", "a and b", "a, b and c".
func prose(items []string) string {
	if len(items) == 1 {
		return items[0]
	}
	return strings.Join(items[:len(items)-1], ", ") + " and " + items[len(items)-1]
}

// describeToken renders a witness as claim=value pairs in claim order.
func describeToken(tok token) string {
	parts := make([]string, 0, len(tok))
	for _, k := range slices.Sorted(maps.Keys(tok)) {
		parts = append(parts, string(k)+"="+tok[k])
	}
	return strings.Join(parts, ", ")
}

// describeTarget names a target the way the sentence does: its kind, in
// the provider's own word, then its identifier; a kind that is blank is
// no kind, so that it leaves no hole before the identifier.
func describeTarget(t trust.TargetRef) string {
	if blank(string(t.Kind)) {
		return t.ID
	}
	return string(t.Kind) + " " + t.ID
}

// printable strips C0 and C1 controls from prose. A target id or a claim
// value is customer configuration, and a terminal escape inside one could
// rewrite the line that prints the sentence, including making a finding
// look clean. A sentence is one line, so newline and tab go too.
func printable(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || (r >= 0x7f && r <= 0x9f) {
			return -1
		}
		return r
	}, s)
}

func refOf(g trust.Grant) GrantRef {
	return GrantRef{Target: g.Target, Issuer: g.Issuer, Effect: g.Effect, Admits: g.Admits.String(), Caveats: g.Admits.Caveats()}
}

// canonicalRecords sorts evidence into record order and keeps one copy of
// a record that two grants share, as the Allow and the Deny of one policy
// document do. Two fetches of one document at two times are two records.
// The fetch time first loses the monotonic reading a clock attaches beside
// the wall clock: nothing renders it, and it would otherwise tell two
// readings of one grant apart in memory that are one grant once the
// records have been through a file.
func canonicalRecords(records []evidence.Record) []evidence.Record {
	out := slices.Clone(records)
	for i := range out {
		out[i].FetchedAt = out[i].FetchedAt.Round(0)
	}
	slices.SortFunc(out, compareRecords)
	return slices.CompactFunc(out, func(x, y evidence.Record) bool { return compareRecords(x, y) == 0 })
}

// owned is the records with the Link's own copy of each body. A Link is a
// fact at the time it was built, and a collector that reuses its response
// buffer, or a caller that edits the grant, must not change what the Link
// renders beside a digest that no longer matches.
func owned(records []evidence.Record) []evidence.Record {
	for i := range records {
		records[i].Bytes = slices.Clone(records[i].Bytes)
	}
	return records
}

// compareRecords orders evidence by what it is, then by when it was
// fetched. FetchedAt is part of no hash and no sentence, but the rendering
// carries it, zone included, and an order blind to it would leave the
// collector's listing order in the bytes; so it is read last, as the
// tie-break, and its rendering after it. Records reach here canonical, so
// the instant compared is the wall clock the rendering carries.
func compareRecords(x, y evidence.Record) int {
	return cmp.Or(
		cmp.Compare(x.API, y.API),
		cmp.Compare(x.Params, y.Params),
		cmp.Compare(x.Status, y.Status),
		cmp.Compare(x.SHA256, y.SHA256),
		bytes.Compare(x.Bytes, y.Bytes),
		x.FetchedAt.Compare(y.FetchedAt),
		cmp.Compare(x.FetchedAt.Format(time.RFC3339Nano), y.FetchedAt.Format(time.RFC3339Nano)),
	)
}

// compareGrants is the order sides and corpora are read in: by target,
// then issuer, then admitted set, caveats, effect and evidence. It is total
// over everything a Link reads from a grant, so the same corpus in any
// order renders the same, and two grants it cannot tell apart are one
// grant: a role a collector listed twice is one role, however it listed
// the role's records each time, which is why the evidence is compared in
// record order rather than the collector's.
func compareGrants(x, y trust.Grant) int {
	return cmp.Or(
		compareTargets(x.Target, y.Target),
		cmp.Compare(x.Issuer, y.Issuer),
		cmp.Compare(x.Admits.String(), y.Admits.String()),
		slices.CompareFunc(x.Admits.Caveats(), y.Admits.Caveats(), compareCaveats),
		cmp.Compare(x.Effect, y.Effect),
		slices.CompareFunc(canonicalRecords(x.Provenance), canonicalRecords(y.Provenance), compareRecords),
	)
}

func compareCaveats(x, y eval.Caveat) int {
	return cmp.Or(cmp.Compare(x.Source, y.Source), cmp.Compare(x.Claim, y.Claim), cmp.Compare(x.Reason, y.Reason))
}

func compareTargets(x, y trust.TargetRef) int {
	return cmp.Or(cmp.Compare(x.Kind, y.Kind), cmp.Compare(x.ID, y.ID))
}

// compareRefs orders references as compareGrants orders the grants they
// name, over the fields a reference carries.
func compareRefs(x, y GrantRef) int {
	return cmp.Or(
		compareTargets(x.Target, y.Target),
		cmp.Compare(x.Issuer, y.Issuer),
		cmp.Compare(x.Admits, y.Admits),
		slices.CompareFunc(x.Caveats, y.Caveats, compareCaveats),
		cmp.Compare(x.Effect, y.Effect),
	)
}

// Valid reports whether the Link was built by NewLink or FanOut. The zero
// value is not a Link and every other method answers it with nothing.
func (l Link) Valid() bool { return l.kind != "" }

// Kind is the join that produced the Link; "" on the zero value.
func (l Link) Kind() LinkKind { return l.kind }

// Grants are the two cloud sides in canonical order, a deep copy; empty on
// the zero value.
func (l Link) Grants() []GrantRef {
	out := slices.Clone(l.grants)
	for i := range out {
		out[i].Caveats = slices.Clone(out[i].Caveats)
	}
	return out
}

// Subject is the counterparty, with its own copy of the witness; empty on
// the zero value.
func (l Link) Subject() CounterpartyRef {
	s := l.subject
	s.Witness = maps.Clone(s.Witness)
	return s
}

// Confidence is Established or Indeterminate; "" on the zero value.
func (l Link) Confidence() Confidence { return l.confidence }

// Reason is why the Link has the confidence it has, printable to a
// customer verbatim; "" on the zero value.
func (l Link) Reason() string { return l.reason }

// Sentence is the Link as one line a customer can act on; "" on the zero
// value.
func (l Link) Sentence() string { return l.sentence }

// Provenance is the evidence from every side, a deep copy; empty on the
// zero value.
func (l Link) Provenance() []evidence.Record {
	out := slices.Clone(l.provenance)
	for i := range out {
		out[i].Bytes = slices.Clone(out[i].Bytes)
	}
	return out
}

// The wire form is the reporter's schema, a public API: field names in the
// product's vocabulary, never the Go names.
type wireLink struct {
	Kind       LinkKind     `json:"kind"`
	Grants     []wireGrant  `json:"grants"`
	Subject    wireSubject  `json:"subject"`
	Confidence Confidence   `json:"confidence"`
	Reason     string       `json:"reason"`
	Sentence   string       `json:"sentence"`
	Provenance []wireRecord `json:"provenance"`
}

type wireGrant struct {
	Target  wireTarget      `json:"target"`
	Issuer  trust.IssuerRef `json:"issuer"`
	Effect  trust.Effect    `json:"effect"`
	Admits  string          `json:"admits"`
	Caveats []wireCaveat    `json:"caveats"`
}

type wireCaveat struct {
	Claim  trust.ClaimKey `json:"claim"`
	Reason string         `json:"reason"`
	Source string         `json:"source"`
}

type wireTarget struct {
	Kind trust.TargetKind `json:"kind"`
	ID   string           `json:"id"`
}

type wireSubject struct {
	Issuer  trust.IssuerRef           `json:"issuer"`
	Overlap string                    `json:"overlap"`
	Witness map[trust.ClaimKey]string `json:"witness"`
}

// wireRecord is an evidence record as the Link renders it: the record's
// own fields, with the body verbatim as JSON when it is JSON and verbatim
// as base64 when it is not, and neither field when the call returned no
// body. The throttled and refused responses most likely to be
// inconclusive are the ones most likely to carry an HTML page, or the XML
// the IAM query API answers in, and a Link must not be lost, at
// construction or at render time, because a proof of its doubt is not
// JSON. A body that is a JSON string renders as JSON, so the two fields
// never mean the same bytes.
type wireRecord struct {
	API       string          `json:"api"`
	Params    string          `json:"params"`
	Status    evidence.Status `json:"status"`
	Bytes     json.RawMessage `json:"bytes,omitempty"`
	Base64    []byte          `json:"bytes_base64,omitempty"`
	SHA256    string          `json:"sha256"`
	FetchedAt time.Time       `json:"fetched_at"`
}

func wireRecordOf(r evidence.Record) wireRecord {
	w := wireRecord{API: r.API, Params: r.Params, Status: r.Status, SHA256: r.SHA256, FetchedAt: r.FetchedAt}
	switch {
	case len(r.Bytes) == 0:
	case json.Valid(r.Bytes):
		w.Bytes = r.Bytes
	default:
		w.Base64 = r.Bytes
	}
	return w
}

// MarshalJSON renders the Link for the reporter and the golden files. The
// zero value is an error rather than a document of empty fields, and an
// error from the encoder names which Link it lost.
//
// These bytes are the canonical rendering: nothing in them is
// HTML-escaped, so an identifier reads back as the customer wrote it, and
// a finding id or a golden file is built on them. json.Marshal re-escapes
// "<", ">" and "&" in every Marshaler's output on its way out, as it
// documents, and so renders the same Link differently; a caller that
// needs the canonical bytes calls this method, or encodes through a
// json.Encoder with SetEscapeHTML(false), which leaves them as written.
func (l Link) MarshalJSON() ([]byte, error) {
	if !l.Valid() {
		return nil, errors.New("join: the zero Link has nothing to render")
	}
	provenance := make([]wireRecord, len(l.provenance))
	for i, r := range l.provenance {
		provenance[i] = wireRecordOf(r)
	}
	grants := make([]wireGrant, len(l.grants))
	for i, g := range l.grants {
		// An exact statement renders an empty list, never null: the field
		// is the answer to "why is this an upper bound", and "it is not"
		// is an answer.
		caveats := make([]wireCaveat, len(g.Caveats))
		for j, c := range g.Caveats {
			caveats[j] = wireCaveat{c.Claim, c.Reason, c.Source}
		}
		grants[i] = wireGrant{Target: wireTarget{g.Target.Kind, g.Target.ID}, Issuer: g.Issuer, Effect: g.Effect, Admits: g.Admits, Caveats: caveats}
	}
	var out strings.Builder
	enc := json.NewEncoder(&out)
	enc.SetEscapeHTML(false)
	err := enc.Encode(wireLink{
		Kind:       l.kind,
		Grants:     grants,
		Subject:    wireSubject{l.subject.Issuer, l.subject.Overlap, l.subject.Witness},
		Confidence: l.confidence,
		Reason:     l.reason,
		Sentence:   l.sentence,
		Provenance: provenance,
	})
	if err != nil {
		return nil, fmt.Errorf("render the link between %s and %s: %w", describeTarget(l.grants[0].Target), describeTarget(l.grants[1].Target), err)
	}
	return []byte(strings.TrimSuffix(out.String(), "\n")), nil
}
