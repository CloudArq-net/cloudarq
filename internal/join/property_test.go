package join

import (
	"bytes"
	"errors"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"pgregory.net/rapid"

	"github.com/CloudArq-net/cloudarq/internal/eval"
	"github.com/CloudArq-net/cloudarq/internal/evidence"
	"github.com/CloudArq-net/cloudarq/internal/trust"
)

// The generators draw from a world small enough that the interesting
// shapes are common: four targets, two issuers and the blank one, subjects
// over the alphabet "ab*?" so that patterns overlap, coincide and exclude
// each other constantly, admitted sets that are sometimes upper bounds and
// sometimes nothing at all, and evidence that is sometimes inconclusive,
// sometimes malformed and sometimes missing. Every property counts the
// draws it needs and fails if the generator stopped producing them.

var targets = []trust.TargetRef{
	deployRole,
	infraApp,
	buildAccount,
	{Kind: "role", ID: "arn:aws:iam::222222222222:role/deploy"},
}

// genSubject draws a value, an Unknown, or a pattern. Most draws are
// patterns, each opening with "a*" or "b*", so that two patterns are as
// often disjoint in truth, which the lattice cannot prove and the walk
// cannot witness, as they are overlapping.
func genSubject() *rapid.Generator[eval.StringSet] {
	return rapid.Custom(func(t *rapid.T) eval.StringSet {
		switch rapid.IntRange(0, 4).Draw(t, "kind") {
		case 0:
			return eval.Exact(rapid.StringOfN(rapid.RuneFrom([]rune("ab")), 0, 3, -1).Draw(t, "value"))
		case 1:
			return eval.Unknown("NotModelled")
		default:
			opening := rapid.SampledFrom([]string{"a*", "b*"}).Draw(t, "opening")
			return eval.Glob(opening + rapid.StringOfN(rapid.RuneFrom([]rune("ab*?")), 0, 2, -1).Draw(t, "pattern"))
		}
	})
}

// genRecord draws a record for the target, sometimes inconclusive,
// sometimes naming no call or no status, and fetched at one of two
// instants, so that records equal in every field but the time, and grants
// that differ only by such a record, are drawn.
func genRecord(target string) *rapid.Generator[evidence.Record] {
	return rapid.Custom(func(t *rapid.T) evidence.Record {
		status := rapid.SampledFrom([]evidence.Status{evidence.StatusOK, evidence.StatusOK, evidence.StatusOK, evidence.StatusOK, evidence.StatusOK, evidence.StatusOK, evidence.StatusDenied, evidence.StatusDenied, evidence.StatusThrottled, ""}).Draw(t, "status")
		api := rapid.SampledFrom([]string{"iam:GetRole", "iam:GetRole", "iam:GetRole", "iam:GetRole", "iam:GetRole", "iam:GetRole", "iam:GetRole", "iam:ListRolePolicies", "graph:federatedIdentityCredentials.list", ""}).Draw(t, "api")
		at := time.Unix(rapid.Int64Range(0, 1).Draw(t, "fetched"), 0)
		return evidence.New(api, `{"target":`+strconv.Quote(target)+`}`, status, []byte(`{"n":`+strconv.Itoa(rapid.IntRange(0, 3).Draw(t, "n"))+`}`), at)
	})
}

// wellFormed is the test's own reading of a record that can be named: it
// names its call and its status.
func wellFormedRecord(r evidence.Record) bool { return r.API != "" && r.Status != "" }

// proved reports whether a grant has a record that can be named, which is
// what makes it a side.
func proved(g trust.Grant) bool { return slices.ContainsFunc(g.Provenance, wellFormedRecord) }

// mayShare is the test's own reading of two issuers that may be one: equal,
// or one of them blank.
func mayShare(x, y trust.IssuerRef) bool { return x == "" || y == "" || x == y }

func genGrant() *rapid.Generator[trust.Grant] {
	return rapid.Custom(func(t *rapid.T) trust.Grant {
		target := rapid.SampledFrom(targets).Draw(t, "target")
		term := eval.Term{}
		if rapid.IntRange(0, 9).Draw(t, "pinned") > 0 {
			term["sub"] = genSubject().Draw(t, "sub")
		}
		if rapid.Bool().Draw(t, "audience") {
			term["aud"] = eval.Exact(rapid.SampledFrom([]string{awsAudience, azureAudience}).Draw(t, "aud"))
		}
		if rapid.IntRange(0, 3).Draw(t, "repository") == 0 {
			term["repository_id"] = eval.Exact(rapid.SampledFrom([]string{"1", "2"}).Draw(t, "id"))
		}
		admits := eval.NewAdmittedSet(term)
		if rapid.IntRange(0, 5).Draw(t, "union") == 0 {
			admits = admits.Join(eval.NewAdmittedSet(eval.Term{"sub": genSubject().Draw(t, "other")}))
		}
		effect := rapid.SampledFrom([]trust.Effect{trust.Allow, trust.Allow, trust.Allow, trust.Allow, trust.Deny, trust.EffectUnknown}).Draw(t, "effect")
		if effect == trust.Deny && rapid.IntRange(0, 2).Draw(t, "unevaluated") == 0 {
			// The shape the AWS parser gives a Deny it could not evaluate:
			// nothing admitted, and a caveat saying that is an upper bound.
			admits = eval.Nothing().WithCaveat(eval.Caveat{Reason: "this Deny statement could not be fully evaluated, so it is not applied; the admitted set is an upper bound", Source: "statement[1]"})
		}
		if rapid.IntRange(0, 5).Draw(t, "caveat") == 0 {
			admits = admits.WithCaveat(eval.Caveat{Claim: "sub", Reason: "operator NotModelled is not modelled", Source: "document"})
		}
		g := trust.Grant{
			Target: target,
			Issuer: rapid.SampledFrom([]trust.IssuerRef{github, github, github, gitlab, ""}).Draw(t, "issuer"),
			Admits: admits,
			Effect: effect,
		}
		if rapid.IntRange(0, 9).Draw(t, "evidence") > 0 {
			g.Provenance = rapid.SliceOfN(genRecord(target.ID), 1, 2).Draw(t, "records")
		}
		return g
	})
}

func genCorpus() *rapid.Generator[[]trust.Grant] {
	return rapid.SliceOfN(genGrant(), 2, 6)
}

// ref is the GrantRef a grant appears under in a Link.
func ref(g trust.Grant) GrantRef {
	return GrantRef{Target: g.Target, Issuer: g.Issuer, Effect: g.Effect, Admits: g.Admits.String(), Caveats: g.Admits.Caveats()}
}

func sameRef(x, y GrantRef) bool { return compareRefs(x, y) == 0 }

func involves(l Link, r GrantRef) bool {
	g := l.Grants()
	return sameRef(g[0], r) || sameRef(g[1], r)
}

// sides returns the grants of the corpus a link's two GrantRefs name: the
// candidates for each side, since a corpus may hold two grants that differ
// only in their evidence.
func sides(corpus []trust.Grant, l Link) [2][]trust.Grant {
	var out [2][]trust.Grant
	for i, r := range l.Grants() {
		for _, g := range corpus {
			if sameRef(ref(g), r) {
				out[i] = append(out[i], g)
			}
		}
	}
	return out
}

func carries(l Link, r evidence.Record) bool {
	return slices.ContainsFunc(l.Provenance(), func(p evidence.Record) bool {
		return p.API == r.API && p.Params == r.Params && p.Status == r.Status && p.SHA256 == r.SHA256
	})
}

// TestNoOneSidedLink is spec property 1. Every Link names two distinct
// targets whose issuers may be one, and its provenance carries every
// record of a grant on each side, one of which can be named; nothing in
// the corpus can produce a Link from one grant's evidence, and a grant
// with no record that can be named is refused and named in the error.
func TestNoOneSidedLink(t *testing.T) {
	links, refusing, unnamed := 0, 0, 0
	// The census of shapes the generator must keep drawing: a record with
	// no call named, a record with no status, a grant with no evidence at
	// all, and a grant that pins no subject. Each is a distinct way for
	// the property to stop being exercised while every other count stays
	// healthy.
	blankAPI, blankStatus, noEvidence, unpinned := 0, 0, 0, 0
	rapid.Check(t, func(t *rapid.T) {
		corpus := genCorpus().Draw(t, "corpus")
		for _, g := range corpus {
			if len(g.Provenance) == 0 {
				noEvidence++
			}
			for _, r := range g.Provenance {
				if r.API == "" {
					blankAPI++
				}
				if r.Status == "" {
					blankStatus++
				}
			}
			// A term that constrains something and not sub: a Term whose sub
			// is Unknown keeps the claim beside its other constraints, so
			// only a draw that never pinned sub produces this shape.
			if slices.ContainsFunc(g.Admits.Terms(), func(term eval.Term) bool { _, pinned := term["sub"]; return !pinned && len(term) > 0 }) {
				unpinned++
			}
		}
		out, err := FanOut(corpus)
		unproven := slices.ContainsFunc(corpus, func(g trust.Grant) bool { return !proved(g) })
		if (err != nil) != unproven {
			t.Fatalf("err = %v, though a grant without evidence that can be named is present: %v", err, unproven)
		}
		if unproven {
			refusing++
			if slices.ContainsFunc(corpus, func(g trust.Grant) bool { return len(g.Provenance) > 0 && !proved(g) }) {
				unnamed++
			}
		}
		for _, l := range out {
			links++
			g := l.Grants()
			if len(g) != 2 || g[0].Target == g[1].Target || !mayShare(g[0].Issuer, g[1].Issuer) {
				t.Fatalf("a Link that is not a pair of targets under one issuer: %v", g)
			}
			for i, candidates := range sides(corpus, l) {
				if !slices.ContainsFunc(candidates, func(c trust.Grant) bool {
					return proved(c) && !slices.ContainsFunc(c.Provenance, func(r evidence.Record) bool { return !carries(l, r) })
				}) {
					t.Fatalf("side %d of %s has no grant whose evidence the Link carries in full", i, l.Sentence())
				}
			}
		}
	})
	if links == 0 || refusing == 0 || unnamed == 0 {
		t.Fatalf("%d links, %d corpora with a refusal, %d with a grant whose records cannot be named; the property was never exercised", links, refusing, unnamed)
	}
	for name, n := range map[string]int{"a record naming no call": blankAPI, "a record with no status": blankStatus, "a grant with no evidence": noEvidence, "a grant pinning no subject": unpinned} {
		if n == 0 {
			t.Fatalf("the generator never drew %s; the property was never exercised on it", name)
		}
	}
	t.Logf("examined %d links, %d corpora with a refusal, %d with a grant whose records cannot be named; drew %d records naming no call, %d with no status, %d grants with no evidence, %d pinning no subject", links, refusing, unnamed, blankAPI, blankStatus, noEvidence, unpinned)
}

// TestFanOutIsSymmetricAndReflexiveFree is spec property 2: the pair (a, b)
// and the pair (b, a) are one Link, byte for byte, or the same refusal,
// byte for byte; and a grant never fans out with itself, alone or inside
// a corpus.
func TestFanOutIsSymmetricAndReflexiveFree(t *testing.T) {
	overlappingUnequal, refused := 0, 0
	rapid.Check(t, func(t *rapid.T) {
		corpus := genCorpus().Draw(t, "corpus")
		for i, a := range corpus {
			for _, b := range corpus[i+1:] {
				ab, errAB := NewLink(a, b)
				ba, errBA := NewLink(b, a)
				if (errAB == nil) != (errBA == nil) {
					t.Fatalf("NewLink(a, b) = %v but NewLink(b, a) = %v", errAB, errBA)
				}
				if errAB == nil {
					if x, y := mustEncode(t, ab), mustEncode(t, ba); !bytes.Equal(x, y) {
						t.Fatalf("the pair renders differently by argument order:\n%s\n%s", x, y)
					}
					if a.Admits.String() != b.Admits.String() {
						overlappingUnequal++
					}
				} else {
					refused++
					if errAB.Error() != errBA.Error() {
						t.Fatalf("the refusal depends on argument order:\n%v\n%v", errAB, errBA)
					}
				}
			}
			if _, err := NewLink(a, a); !errors.Is(err, ErrSameTarget) {
				t.Fatalf("NewLink(a, a) = %v, want ErrSameTarget", err)
			}
		}
		out, _ := FanOut(slices.Concat(corpus, corpus[:1]))
		for _, l := range out {
			if g := l.Grants(); g[0].Target == g[1].Target {
				t.Fatalf("a grant fanned out with itself: %s", l.Sentence())
			}
		}
	})
	if overlappingUnequal == 0 || refused == 0 {
		t.Fatalf("%d overlapping but unequal pairs, %d refusals; the property was never exercised", overlappingUnequal, refused)
	}
	t.Logf("exercised on %d overlapping, unequal pairs and %d refusals", overlappingUnequal, refused)
}

func mustEncode(t *rapid.T, l Link) []byte {
	t.Helper()
	b, err := l.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}
	return b
}

// pairs lists the (a, b) pairs of a corpus that are candidates for a Link:
// issuers that may be one, different targets, neither a Deny, both with a
// record that can be named.
func pairs(corpus []trust.Grant) [][2]trust.Grant {
	var out [][2]trust.Grant
	for i, a := range corpus {
		for _, b := range corpus[i+1:] {
			if mayShare(a.Issuer, b.Issuer) && a.Target != b.Target && a.Effect != trust.Deny && b.Effect != trust.Deny && proved(a) && proved(b) {
				out = append(out, [2]trust.Grant{a, b})
			}
		}
	}
	return out
}

// TestUnprovableOverlapIsIndeterminateNeverAbsent is spec property 3, the
// one that stops the package quietly under-reporting: a candidate pair
// whose overlap is not provably empty always has a Link, and when no
// witness could be built that Link is Indeterminate. A pair in which one
// side names no issuer is a candidate like any other, and its Link is
// Indeterminate whatever else is known.
func TestUnprovableOverlapIsIndeterminateNeverAbsent(t *testing.T) {
	undecided, unnamed := 0, 0
	rapid.Check(t, func(t *rapid.T) {
		corpus := genCorpus().Draw(t, "corpus")
		out, _ := FanOut(corpus)
		for _, p := range pairs(corpus) {
			a, b := p[0], p[1]
			if a.WithoutAudience().Meet(b.WithoutAudience()).IsEmpty() {
				continue
			}
			i := slices.IndexFunc(out, func(l Link) bool { return involves(l, ref(a)) && involves(l, ref(b)) })
			if i < 0 {
				t.Fatalf("no Link for %s and %s, whose overlap %s is not provably empty", ref(a).Admits, ref(b).Admits, a.WithoutAudience().Meet(b.WithoutAudience()))
			}
			if out[i].Subject().Witness == nil {
				undecided++
				if out[i].Confidence() != Indeterminate {
					t.Fatalf("no witness, yet %s", out[i].Sentence())
				}
			}
			if a.Issuer == "" || b.Issuer == "" {
				unnamed++
				if out[i].Confidence() != Indeterminate {
					t.Fatalf("a side names no issuer, yet %s", out[i].Sentence())
				}
			}
		}
	})
	if undecided == 0 || unnamed == 0 {
		t.Fatalf("%d undecidable overlaps, %d pairs with a side naming no issuer; the property was never exercised", undecided, unnamed)
	}
	t.Logf("exercised on %d undecidable overlaps and %d pairs with a side naming no issuer", undecided, unnamed)
}

// doubtful is the test's own reading of a grant whose reading cannot be
// relied on: an issuer it does not name, an effect other than Allow, an
// admitted set that is an upper bound, and a record that is inconclusive
// or cannot be named.
func doubtful(g trust.Grant) bool {
	return g.Issuer == "" || g.Effect != trust.Allow || !g.Exact() ||
		slices.ContainsFunc(g.Provenance, func(r evidence.Record) bool { return !r.Status.Conclusive() || !wellFormedRecord(r) })
}

// TestInconclusiveEvidenceCannotProduceEstablished is spec property 4, and
// carries the gates the architect added beside it: a grant that is not
// Exact, whose effect could not be read, whose issuer is not named, or
// whose records cannot all be named never takes part in an Established
// Link; and a Deny or an unread statement on either target that is read
// that way, or without evidence, keeps every link on its target from
// Established, wherever its reading puts its reach.
func TestInconclusiveEvidenceCannotProduceEstablished(t *testing.T) {
	inconclusive, inexact, unreadable, unnamed, malformedRecords, doubtedDenials, unevaluatedDenials := 0, 0, 0, 0, 0, 0, 0
	rapid.Check(t, func(t *rapid.T) {
		corpus := rapid.OneOf(genCorpus(), genDeniedCorpus()).Draw(t, "corpus")
		out, _ := FanOut(corpus)
		for _, l := range out {
			for _, candidates := range sides(corpus, l) {
				for _, g := range candidates {
					if slices.ContainsFunc(g.Provenance, func(r evidence.Record) bool { return !r.Status.Conclusive() }) {
						inconclusive++
					}
					if slices.ContainsFunc(g.Provenance, func(r evidence.Record) bool { return !wellFormedRecord(r) }) {
						malformedRecords++
					}
					if !g.Exact() {
						inexact++
					}
					if g.Effect != trust.Allow {
						unreadable++
					}
					if g.Issuer == "" {
						unnamed++
					}
				}
				// Every candidate for this side is doubtful, so whichever
				// grant produced the Link was.
				if !slices.ContainsFunc(candidates, func(g trust.Grant) bool { return !doubtful(g) }) && l.Confidence() == Established {
					t.Fatalf("Established on a doubtful side: %s", l.Sentence())
				}
			}
			for _, d := range corpus {
				if d.Effect == trust.Allow || !mayShare(d.Issuer, l.Subject().Issuer) {
					continue
				}
				for _, r := range l.Grants() {
					if r.Target != d.Target {
						continue
					}
					if d.Admits.IsEmpty() && !d.Exact() {
						// The AWS parser's shape for a Deny it could not
						// evaluate: as read it denies nobody.
						unevaluatedDenials++
					}
					if !d.Exact() || !proved(d) || slices.ContainsFunc(d.Provenance, func(r evidence.Record) bool { return !r.Status.Conclusive() || !wellFormedRecord(r) }) {
						doubtedDenials++
						if l.Confidence() == Established {
							t.Fatalf("Established beside a denial on %s that was not read conclusively: %s", r.Target.ID, l.Sentence())
						}
					}
				}
			}
		}
	})
	for name, n := range map[string]int{"inconclusive evidence": inconclusive, "inexact grants": inexact, "unreadable effects": unreadable, "an issuer not named": unnamed, "a record that cannot be named": malformedRecords, "a denial not read conclusively": doubtedDenials, "a denial that admits nobody as read": unevaluatedDenials} {
		if n == 0 {
			t.Fatalf("no Link involved %s; the property was never exercised", name)
		}
	}
	t.Logf("inconclusive %d, inexact %d, unreadable %d, unnamed issuers %d, malformed records %d, doubted denials %d, unevaluated denials %d", inconclusive, inexact, unreadable, unnamed, malformedRecords, doubtedDenials, unevaluatedDenials)
}

// TestWitnessIsAdmittedByBothSides: a witness is a token both grants admit
// once their audiences are set aside, and an Established Link always has
// one. A witness is never a claim of the sentence alone.
func TestWitnessIsAdmittedByBothSides(t *testing.T) {
	witnessed := 0
	rapid.Check(t, func(t *rapid.T) {
		corpus := genCorpus().Draw(t, "corpus")
		out, _ := FanOut(corpus)
		for _, l := range out {
			w := l.Subject().Witness
			if w == nil {
				if l.Confidence() == Established {
					t.Fatalf("Established without a witness: %s", l.Sentence())
				}
				continue
			}
			witnessed++
			for i, candidates := range sides(corpus, l) {
				if !slices.ContainsFunc(candidates, func(g trust.Grant) bool { return g.WithoutAudience().Admits(w) }) {
					t.Fatalf("side %d does not admit the witness %v: %s", i, w, l.Sentence())
				}
			}
		}
	})
	if witnessed == 0 {
		t.Fatalf("no witness was produced; the property was never exercised")
	}
	t.Logf("checked %d witnesses", witnessed)
}

// TestUnreadableEffectNeverReducesLinks is the architect's decision on
// Effect: an EffectUnknown grant is treated as possibly Allow, so turning
// an Allow into EffectUnknown can only add doubt, never remove a Link.
//
// The corpus is a set, so a flip that leaves the grant identical to a
// grant already in the corpus merges the two, and their links with it:
// the count may then fall, but no pair of grant references loses its link.
// That weaker check holds on every draw; the count holds whenever the
// grant stays its own.
func TestUnreadableEffectNeverReducesLinks(t *testing.T) {
	exercised, merged := 0, 0
	rapid.Check(t, func(t *rapid.T) {
		corpus := genCorpus().Draw(t, "corpus")
		i := rapid.IntRange(0, len(corpus)-1).Draw(t, "which")
		if corpus[i].Effect != trust.Allow {
			return
		}
		exercised++
		before, _ := FanOut(corpus)
		doubted := slices.Clone(corpus)
		doubted[i].Effect = trust.EffectUnknown
		after, _ := FanOut(doubted)
		if slices.ContainsFunc(slices.Concat(doubted[:i], doubted[i+1:]), func(g trust.Grant) bool { return compareGrants(g, doubted[i]) == 0 }) {
			merged++
		} else if len(after) < len(before) {
			t.Fatalf("an unreadable effect removed links: %d before, %d after", len(before), len(after))
		}
		for _, x := range before {
			if !slices.ContainsFunc(after, func(y Link) bool { return samePair(x, y) }) {
				t.Fatalf("an unreadable effect removed the link for a pair: %s", x.Sentence())
			}
		}
		for _, l := range after {
			if involves(l, ref(doubted[i])) && l.Confidence() == Established {
				t.Fatalf("Established through a grant whose effect could not be read: %s", l.Sentence())
			}
		}
	})
	if exercised == 0 {
		t.Fatalf("no Allow grant was drawn; the property was never exercised")
	}
	t.Logf("exercised %d times, %d of them merging the grant into a twin", exercised, merged)
}

// samePair reports whether two links are about the same two statements,
// whatever their effects read: the flip above changes one effect, and the
// pair is still the pair.
func samePair(x, y Link) bool {
	gx, gy := x.Grants(), y.Grants()
	for i := range gx {
		gx[i].Effect, gy[i].Effect = "", ""
	}
	return sameRef(gx[0], gy[0]) && sameRef(gx[1], gy[1])
}

// TestRemovingEvidenceChangesOnlyThatGrantsLinks is the architect's
// decision on evidence-less grants: the grant is named in the error and
// every Link it took no part in, as a side or as a denial, is rendered
// exactly as before.
func TestRemovingEvidenceChangesOnlyThatGrantsLinks(t *testing.T) {
	exercised := 0
	rapid.Check(t, func(t *rapid.T) {
		corpus := genCorpus().Draw(t, "corpus")
		i := rapid.IntRange(0, len(corpus)-1).Draw(t, "which")
		if len(corpus[i].Provenance) == 0 {
			return
		}
		exercised++
		before, _ := FanOut(corpus)
		stripped := slices.Clone(corpus)
		stripped[i].Provenance = nil
		after, err := FanOut(stripped)
		if !errors.Is(err, ErrNoEvidence) || !strings.Contains(err.Error(), corpus[i].Target.ID) {
			t.Fatalf("err = %v, want ErrNoEvidence naming %s", err, corpus[i].Target.ID)
		}
		others := func(links []Link) [][]byte {
			var out [][]byte
			for _, l := range links {
				if !involves(l, ref(corpus[i])) && !carriesDenial(l, corpus[i]) {
					out = append(out, mustEncode(t, l))
				}
			}
			return out
		}
		x, y := others(before), others(after)
		if len(x) != len(y) {
			t.Fatalf("removing one grant's evidence changed the other links: %d before, %d after", len(x), len(y))
		}
		for j := range x {
			if !bytes.Equal(x[j], y[j]) {
				t.Fatalf("removing one grant's evidence changed another link:\n%s\n%s", x[j], y[j])
			}
		}
	})
	if exercised == 0 {
		t.Fatalf("no grant with evidence was drawn; the property was never exercised")
	}
	t.Logf("exercised %d times", exercised)
}

// carriesDenial reports whether l may name g as a denial on one of its
// targets, a Deny or a statement whose effect could not be read, in which
// case g's evidence is part of l's provenance and the property above
// expects l to change when it is removed.
func carriesDenial(l Link, g trust.Grant) bool {
	if g.Effect == trust.Allow {
		return false
	}
	for _, r := range l.Grants() {
		if r.Target == g.Target && mayShare(g.Issuer, l.Subject().Issuer) {
			return true
		}
	}
	return false
}

// TestFanOutIsOrderIndependent: the corpus is a set, and a collector that
// lists roles, or a role's records, in a different order must not change a
// single byte.
func TestFanOutIsOrderIndependent(t *testing.T) {
	compared := 0
	rapid.Check(t, func(t *rapid.T) {
		corpus := genCorpus().Draw(t, "corpus")
		shuffled := rapid.Permutation(slices.Clone(corpus)).Draw(t, "shuffled")
		for i := range shuffled {
			shuffled[i].Provenance = rapid.Permutation(slices.Clone(shuffled[i].Provenance)).Draw(t, "records")
		}
		x, errX := FanOut(corpus)
		y, errY := FanOut(shuffled)
		if (errX == nil) != (errY == nil) || (errX != nil && errX.Error() != errY.Error()) {
			t.Fatalf("the error depends on order: %v vs %v", errX, errY)
		}
		if len(x) != len(y) {
			t.Fatalf("%d links vs %d after shuffling", len(x), len(y))
		}
		for i := range x {
			compared++
			if a, b := mustEncode(t, x[i]), mustEncode(t, y[i]); !bytes.Equal(a, b) {
				t.Fatalf("link %d depends on input order:\n%s\n%s", i, a, b)
			}
		}
	})
	if compared == 0 {
		t.Fatalf("no link was compared; the property was never exercised")
	}
	t.Logf("compared %d links", compared)
}

// genDeniedCorpus draws a corpus around one Deny, which genCorpus alone
// draws too rarely to count on: two Allow grants on two targets from one
// issuer, each exact and conclusively proved, then a Deny on the first
// target whose reach may or may not touch their overlap and whose reading
// is conclusive, or an upper bound, or inconclusive, or unproved, then
// whatever else genCorpus draws.
func genDeniedCorpus() *rapid.Generator[[]trust.Grant] {
	return rapid.Custom(func(t *rapid.T) []trust.Grant {
		pair := rapid.SliceOfNDistinct(rapid.SampledFrom(targets), 2, 2, func(r trust.TargetRef) string { return r.ID }).Draw(t, "pair")
		side := func(target trust.TargetRef, label string) trust.Grant {
			term := eval.Term{"sub": genSubject().Draw(t, label+" sub")}
			if rapid.Bool().Draw(t, label+" audience") {
				term["aud"] = eval.Exact(rapid.SampledFrom([]string{awsAudience, azureAudience}).Draw(t, label+" aud"))
			}
			return trust.Grant{Target: target, Issuer: github, Admits: eval.NewAdmittedSet(term), Effect: trust.Allow,
				Provenance: []evidence.Record{evidence.New("iam:GetRole", `{"target":`+strconv.Quote(target.ID)+`}`, evidence.StatusOK, []byte(`{}`), time.Unix(0, 0))}}
		}
		deny := side(pair[0], "deny")
		deny.Effect = trust.Deny
		switch rapid.SampledFrom([]string{"conclusive", "conclusive", "upper bound", "inconclusive", "unproved"}).Draw(t, "deny reading") {
		case "upper bound":
			deny.Admits = eval.Nothing().WithCaveat(eval.Caveat{Reason: "this Deny statement could not be fully evaluated, so it is not applied; the admitted set is an upper bound", Source: "statement[1]"})
		case "inconclusive":
			deny.Provenance = append(deny.Provenance, evidence.New("iam:GetRolePolicy", `{"target":`+strconv.Quote(pair[0].ID)+`}`, evidence.StatusThrottled, nil, time.Unix(0, 0)))
		case "unproved":
			deny.Provenance = nil
		}
		return append([]trust.Grant{side(pair[0], "a"), side(pair[1], "b"), deny}, genCorpus().Draw(t, "rest")...)
	})
}

// TestUnreadDenyNeverPromotes: a statement whose effect could not be read
// is possibly a Deny. Reading a Deny as unreadable may add links, since
// the statement now pairs as possibly Allow, but every Established link
// afterwards was Established before, byte for byte: nothing the Deny kept
// Indeterminate is promoted. The guard counts the links a Deny alone had
// kept Indeterminate, the ones a dropped rule would flip.
func TestUnreadDenyNeverPromotes(t *testing.T) {
	deniedAlone := 0
	// The four readings genDeniedCorpus gives its Deny; a generator that
	// stopped drawing one of them, or drew an Allow in the Deny's place,
	// would leave every other count healthy.
	readings := map[string]int{}
	rapid.Check(t, func(t *rapid.T) {
		corpus := genDeniedCorpus().Draw(t, "corpus")
		i := 2
		if corpus[i].Effect != trust.Deny {
			t.Fatalf("the denied corpus placed %v where its Deny belongs", corpus[i].Effect)
		}
		switch d := corpus[i]; {
		case len(d.Provenance) == 0:
			readings["unproved"]++
		case d.Admits.IsEmpty() && !d.Exact():
			readings["upper bound"]++
		case slices.ContainsFunc(d.Provenance, func(r evidence.Record) bool { return !r.Status.Conclusive() }):
			readings["inconclusive"]++
		default:
			readings["conclusive"]++
		}
		before, _ := FanOut(corpus)
		unread := slices.Clone(corpus)
		unread[i].Effect = trust.EffectUnknown
		after, _ := FanOut(unread)
		if len(after) < len(before) {
			t.Fatalf("reading a Deny as unreadable removed links: %d before, %d after", len(before), len(after))
		}
		soleDoubt := describeTarget(corpus[i].Target) + " also denies identities from " + string(corpus[i].Issuer) + ", and whether these are among them could not be decided"
		var established [][]byte
		for _, x := range before {
			if x.Reason() == soleDoubt {
				deniedAlone++
			}
			if x.Confidence() == Established {
				established = append(established, mustEncode(t, x))
			}
		}
		for _, y := range after {
			if y.Confidence() == Established && !slices.ContainsFunc(established, func(x []byte) bool { return bytes.Equal(x, mustEncode(t, y)) }) {
				t.Fatalf("reading a Deny as unreadable promoted a link: %s", y.Sentence())
			}
		}
	})
	if deniedAlone == 0 {
		t.Fatalf("no link was kept Indeterminate by a Deny alone; the property was never exercised")
	}
	for _, name := range []string{"conclusive", "upper bound", "inconclusive", "unproved"} {
		if readings[name] == 0 {
			t.Fatalf("the denied corpus never gave its Deny the %s reading; the property was never exercised on it", name)
		}
	}
	t.Logf("exercised on %d links a Deny alone kept Indeterminate; Deny readings %v", deniedAlone, readings)
}
