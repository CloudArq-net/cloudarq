package join

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/CloudArq-net/cloudarq/internal/eval"
	"github.com/CloudArq-net/cloudarq/internal/evidence"
	"github.com/CloudArq-net/cloudarq/internal/trust"
)

// goldenDir holds one directory per case: grants.json, the Grants as the
// parsers would produce them; links.json, the bytes FanOut must render; and
// a rationale saying why those links are the right answer.
const goldenDir = "../../testdata/join"

// grantDocument is the fixture form of a trust.Grant. The package has no
// JSON form for a Grant, and the parsers build Grants from provider
// documents; the fixtures state the Grant directly so that the join is
// judged on what every parser agrees to produce, not on one parser.
type grantDocument struct {
	Target struct {
		Kind trust.TargetKind `json:"kind"`
		ID   string           `json:"id"`
	} `json:"target"`
	Issuer     trust.IssuerRef                         `json:"issuer"`
	Effect     trust.Effect                            `json:"effect"`
	Admits     []map[trust.ClaimKey]constraintDocument `json:"admits"`
	Caveats    []caveatDocument                        `json:"caveats"`
	Provenance []recordDocument                        `json:"provenance"`
}

// constraintDocument names one of the five constraints a fixture states
// on a claim: a value, a StringLike pattern, the strings matching every
// one of several patterns, the strings matching any of several, or an
// Unknown with its reason.
type constraintDocument struct {
	Exact   *string  `json:"exact"`
	Like    *string  `json:"like"`
	AllOf   []string `json:"all_of"`
	AnyOf   []string `json:"any_of"`
	Unknown *string  `json:"unknown"`
}

type caveatDocument struct {
	Claim  trust.ClaimKey `json:"claim"`
	Reason string         `json:"reason"`
	Source string         `json:"source"`
}

// recordDocument is an evidence record before its digest: the digest is
// sealed on load, so a fixture can never carry a body and a hash that
// disagree. The body is stated as the Link renders it: as JSON when it is
// JSON, as base64 when it is not.
type recordDocument struct {
	API       string          `json:"api"`
	Params    string          `json:"params"`
	Status    evidence.Status `json:"status"`
	Bytes     json.RawMessage `json:"bytes"`
	Base64    []byte          `json:"bytes_base64"`
	FetchedAt time.Time       `json:"fetched_at"`
}

func (r recordDocument) body(t testing.TB) []byte {
	t.Helper()
	if len(r.Bytes) > 0 && len(r.Base64) > 0 {
		t.Fatalf("the record of %s states its body twice", r.API)
	}
	if len(r.Base64) > 0 {
		return r.Base64
	}
	return r.Bytes
}

func loadGrants(t testing.TB, name string) []trust.Grant {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(goldenDir, name, "grants.json"))
	if err != nil {
		t.Fatalf("%v", err)
	}
	var docs []grantDocument
	if err := json.Unmarshal(raw, &docs); err != nil {
		t.Fatalf("%s/grants.json: %v", name, err)
	}
	grants := make([]trust.Grant, 0, len(docs))
	for _, d := range docs {
		grants = append(grants, d.grant(t))
	}
	return grants
}

func (d grantDocument) grant(t testing.TB) trust.Grant {
	t.Helper()
	terms := make([]eval.Term, 0, len(d.Admits))
	for _, claims := range d.Admits {
		term := eval.Term{}
		for k, c := range claims {
			term[k] = c.constraint(t, k)
		}
		terms = append(terms, term)
	}
	admits := eval.NewAdmittedSet(terms...)
	for _, c := range d.Caveats {
		admits = admits.WithCaveat(eval.Caveat{Claim: c.Claim, Reason: c.Reason, Source: c.Source})
	}
	g := trust.Grant{
		Target: trust.TargetRef{Kind: d.Target.Kind, ID: d.Target.ID},
		Issuer: d.Issuer,
		Admits: admits,
		Effect: d.Effect,
	}
	for _, r := range d.Provenance {
		g.Provenance = append(g.Provenance, evidence.New(r.API, r.Params, r.Status, r.body(t), r.FetchedAt))
	}
	return g
}

func (c constraintDocument) constraint(t testing.TB, claim trust.ClaimKey) eval.StringSet {
	t.Helper()
	stated := 0
	for _, present := range []bool{c.Exact != nil, c.Like != nil, c.AllOf != nil, c.AnyOf != nil, c.Unknown != nil} {
		if present {
			stated++
		}
	}
	switch {
	case stated != 1:
		t.Fatalf("claim %s: a constraint is exactly one of exact, like, all_of, any_of or unknown", claim)
	case c.Exact != nil:
		return eval.Exact(*c.Exact)
	case c.Like != nil:
		return eval.Glob(*c.Like)
	case c.AllOf != nil:
		return inter(c.AllOf...)
	case c.AnyOf != nil:
		return union(c.AnyOf...)
	}
	return eval.Unknown(*c.Unknown)
}

func goldenCases(t testing.TB) []string {
	t.Helper()
	entries, err := os.ReadDir(goldenDir)
	if err != nil {
		t.Fatalf("%v", err)
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() {
			names = append(names, e.Name())
		}
	}
	if len(names) == 0 {
		t.Fatalf("no cases under %s; the golden test would examine nothing", goldenDir)
	}
	return names
}

// TestGoldens compares FanOut's rendering of each case with the bytes on
// disk. The corpus must hold each shape the spec names, so the shapes are
// counted rather than assumed: a corpus that lost its glob-overlap case
// would still pass byte for byte.
func TestGoldens(t *testing.T) {
	var establishedByGlob, indeterminateUnproved, provablyDisjoint, inconclusive, sharedTarget, unreadBesideAllow, sharedRecord, pastTheWalk, notJSON int
	var unnamedIssuer, unevaluatedDenial, doubtedDenial, malformedRecord, counted int
	for _, name := range goldenCases(t) {
		grants := loadGrants(t, name)
		links, err := FanOut(grants)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		want, err := os.ReadFile(filepath.Join(goldenDir, name, "links.json"))
		if err != nil {
			t.Fatalf("%v", err)
		}
		if got := encode(t, links); !bytes.Equal(got, want) {
			t.Errorf("%s: FanOut rendered\n%s\nwant\n%s", name, got, want)
		}
		if rationale, err := os.ReadFile(filepath.Join(goldenDir, name, name+".rationale.md")); err != nil || len(bytes.TrimSpace(rationale)) == 0 {
			t.Errorf("%s: every golden case carries a rationale: %v", name, err)
		}
		for _, l := range links {
			g := l.Grants()
			if !l.Valid() || l.Sentence() == "" || len(g) != 2 {
				t.Errorf("%s: an invalid or silent link was rendered: %+v", name, l)
				continue
			}
			if strings.Contains(l.Sentence(), " more ") {
				counted++
			}
			if l.Confidence() == Established && g[0].Target.Kind != g[1].Target.Kind && strings.Contains(l.Subject().Overlap, "like:") {
				establishedByGlob++
			}
			if l.Confidence() == Indeterminate && l.Subject().Witness == nil {
				indeterminateUnproved++
			}
		}
		doubtedDenial += doubtedDenials(grants)
		for i, a := range grants {
			for _, r := range a.Provenance {
				if !r.Status.Conclusive() {
					inconclusive++
				}
				if !json.Valid(r.Bytes) {
					notJSON++
				}
				if malformed(r) != "" {
					malformedRecord++
				}
			}
			if a.Issuer == "" {
				unnamedIssuer++
			}
			if a.Effect == trust.Deny && !a.Exact() {
				unevaluatedDenial++
			}
			for _, b := range grants[i+1:] {
				if a.Target == b.Target {
					sharedTarget++
					if (a.Effect == trust.Allow) != (b.Effect == trust.Allow) && a.Effect != trust.Deny && b.Effect != trust.Deny {
						unreadBesideAllow++
					}
					continue
				}
				if a.Issuer != b.Issuer {
					continue
				}
				overlap := a.WithoutAudience().Meet(b.WithoutAudience())
				if overlap.IsEmpty() {
					provablyDisjoint++
				}
				// The eight patterns of case 11 are past the walk's bound by
				// measurement (see walkBound).
				if strings.Count(overlap.String(), "like:") >= 8 {
					pastTheWalk++
				}
				for _, r := range a.Provenance {
					if slices.ContainsFunc(b.Provenance, func(x evidence.Record) bool { return compareRecords(x, r) == 0 }) {
						sharedRecord++
					}
				}
			}
		}
	}
	for name, n := range map[string]int{
		"a link established by glob overlap across target kinds":         establishedByGlob,
		"an Indeterminate link with no witness":                          indeterminateUnproved,
		"a pair with a provably empty overlap":                           provablyDisjoint,
		"an inconclusive evidence record":                                inconclusive,
		"two grants on one target":                                       sharedTarget,
		"an unread effect beside an Allow on one target":                 unreadBesideAllow,
		"one record proving two targets":                                 sharedRecord,
		"a pair whose overlap holds more patterns than the walk settles": pastTheWalk,
		"an evidence record whose body is not JSON":                      notJSON,
		"a grant naming no issuer":                                       unnamedIssuer,
		"a Deny read as an upper bound":                                  unevaluatedDenial,
		"a Deny that provably misses, read inconclusively":               doubtedDenial,
		"a record that names no call or no status":                       malformedRecord,
		"a sentence that counts the members it does not list":            counted,
	} {
		if n == 0 {
			t.Errorf("the golden corpus has no case with %s", name)
		}
	}
	t.Logf("glob-established %d, unproved %d, disjoint pairs %d, inconclusive records %d, shared targets %d, unread beside allow %d, shared records %d, past the walk %d, not JSON %d, unnamed issuers %d, unevaluated denials %d, doubted denials %d, malformed records %d, counted lists %d",
		establishedByGlob, indeterminateUnproved, provablyDisjoint, inconclusive, sharedTarget, unreadBesideAllow, sharedRecord, pastTheWalk, notJSON, unnamedIssuer, unevaluatedDenial, doubtedDenial, malformedRecord, counted)
}

// doubtedDenials counts the Denies of a corpus, read exactly but through
// an inconclusive record, that provably miss the overlap of a sibling on
// their target with a grant on another: the shape whose doubt is about the
// reading and not the reach.
func doubtedDenials(grants []trust.Grant) int {
	n := 0
	for _, d := range grants {
		if d.Effect != trust.Deny || !d.Exact() || !slices.ContainsFunc(d.Provenance, func(r evidence.Record) bool { return !r.Status.Conclusive() }) {
			continue
		}
		for _, sibling := range grants {
			if sibling.Target != d.Target || sibling.Effect != trust.Allow {
				continue
			}
			for _, partner := range grants {
				if partner.Target == d.Target || partner.Issuer != sibling.Issuer {
					continue
				}
				overlap := sibling.WithoutAudience().Meet(partner.WithoutAudience())
				if !overlap.IsEmpty() && d.Admits.Meet(sibling.Admits).Meet(overlap).IsEmpty() {
					n++
				}
			}
		}
	}
	return n
}

// TestDeterminism is the section 2 promise at this layer, and the test the
// Makefile's twenty fresh processes run: the same corpus, loaded twice and
// in reverse, renders byte for byte the same links and sentences.
func TestDeterminism(t *testing.T) {
	examined := 0
	for _, name := range goldenCases(t) {
		first, err := FanOut(loadGrants(t, name))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		reversed := loadGrants(t, name)
		slices.Reverse(reversed)
		for label, grants := range map[string][]trust.Grant{"again": loadGrants(t, name), "reversed": reversed} {
			again, err := FanOut(grants)
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			if x, y := encode(t, first), encode(t, again); !bytes.Equal(x, y) {
				t.Errorf("%s (%s): two runs rendered differently:\n%s\n%s", name, label, x, y)
			}
			for i := range first {
				if i < len(again) && first[i].Sentence() != again[i].Sentence() {
					t.Errorf("%s (%s): sentence %d differs: %q vs %q", name, label, i, first[i].Sentence(), again[i].Sentence())
				}
			}
		}
		examined += len(first)
	}
	if examined == 0 {
		t.Fatalf("no links were compared")
	}
	t.Logf("compared %d links twice", examined)
}

// TestFanOutNamesGrantsWithoutEvidence: a grant with no evidence record is a
// collector bug, and the bug is reported beside the links the other grants
// still produce, never by dropping every link on the floor.
func TestFanOutNamesGrantsWithoutEvidence(t *testing.T) {
	aws := awsGrant(pinned(eval.Glob("repo:acme/*"), awsAudience))
	azure := azureGrant(pinned(eval.Exact(mainBranch), azureAudience))
	azure.Provenance = nil
	gcp := gcpGrant(pinned(eval.Glob("repo:acme/infra:*"), gcpAudience))
	links, err := FanOut([]trust.Grant{aws, azure, gcp})
	if !errors.Is(err, ErrNoEvidence) || !strings.Contains(err.Error(), infraApp.ID) {
		t.Errorf("err = %v, want ErrNoEvidence naming %s", err, infraApp.ID)
	}
	if len(links) != 1 || links[0].Grants()[0].Target != deployRole || links[0].Grants()[1].Target != buildAccount {
		t.Errorf("links = %v, want the role and the service account alone", links)
	}
	// A Deny without evidence is named too, and still casts its doubt.
	deny := awsGrant(pinned(eval.Glob("repo:acme/infra:*"), awsAudience))
	deny.Effect, deny.Provenance = trust.Deny, nil
	links, err = FanOut([]trust.Grant{aws, gcp, deny})
	if !errors.Is(err, ErrNoEvidence) || !strings.Contains(err.Error(), deployRole.ID) {
		t.Errorf("err = %v, want ErrNoEvidence naming %s", err, deployRole.ID)
	}
	if len(links) != 1 || links[0].Confidence() != Indeterminate {
		t.Errorf("links = %v, want one Indeterminate link", links)
	}
	// Every grant without evidence is named, once each, in grant order.
	links, err = FanOut([]trust.Grant{azure, deny})
	if err == nil || len(links) != 0 || strings.Count(err.Error(), ErrNoEvidence.Error()) != 2 || strings.Index(err.Error(), infraApp.ID) > strings.Index(err.Error(), deployRole.ID) {
		t.Errorf("links = %v, err = %v", links, err)
	}
	// With evidence everywhere there is nothing to report.
	if _, err := FanOut([]trust.Grant{aws, gcp}); err != nil {
		t.Errorf("err = %v", err)
	}
}

// TestFanOutPairsWithinAnIssuer: a fan-out is one counterparty, and a
// counterparty is known by its issuer. Grants from two issuers never pair,
// whatever their subjects; grants on one target never pair with each
// other; a Deny is never a side.
func TestFanOutPairsWithinAnIssuer(t *testing.T) {
	aws := awsGrant(pinned(eval.Glob("repo:acme/*"), awsAudience))
	azure := azureGrant(pinned(eval.Exact(mainBranch), azureAudience))
	gcp := gcpGrant(pinned(eval.Glob("repo:acme/infra:*"), gcpAudience))
	gcp.Issuer = gitlab
	twin := aws
	twin.Admits = pinned(eval.Exact(mainBranch), awsAudience)
	deny := azureGrant(pinned(eval.Exact(mainBranch), azureAudience))
	deny.Effect = trust.Deny
	links, err := FanOut([]trust.Grant{gcp, azure, aws, twin, deny})
	if err != nil {
		t.Fatalf("FanOut: %v", err)
	}
	if len(links) != 2 {
		t.Fatalf("got %d links, want the two role grants each against the application: %v", len(links), links)
	}
	for _, l := range links {
		if g := l.Grants(); g[0].Target != infraApp || g[1].Target != deployRole || l.Confidence() != Indeterminate {
			t.Errorf("unexpected link: %s", l.Sentence())
		}
	}
	// Links are sorted by their pair, then by what distinguishes the grants.
	if links[0].Grants()[1].Admits >= links[1].Grants()[1].Admits {
		t.Errorf("links are not in canonical order: %q, %q", links[0].Grants()[1].Admits, links[1].Grants()[1].Admits)
	}
	if links, err := FanOut(nil); err != nil || links == nil || len(links) != 0 {
		t.Errorf("FanOut(nil) = %v, %v; want an empty list, never null", links, err)
	}
}

// TestFanOutOrdersTwins: statements can render to the same admitted set
// and still differ, by a caveat or by the evidence that proved them. A
// caveat is part of the GrantRef, so the caveated twins' links sort by
// their caveats' canonical order, source first; the two caveats sort one
// way by source and the other by reason, so that order is visibly the
// reference's and not the reason's. Twins that differ only in evidence
// share both GrantRefs, and confidence, reason and provenance order them:
// the twin whose record was refused sorts first as a grant, since
// "denied" sorts before "ok", and its link sorts last, since
// Indeterminate sorts after Established. Neither order may depend on
// which twin the collector listed first.
func TestFanOutOrdersTwins(t *testing.T) {
	azure := azureGrant(pinned(eval.Exact(mainBranch), azureAudience))
	exact := awsGrant(pinned(eval.Glob("repo:acme/*"), awsAudience))
	notPrincipal, forAllValues, twiceRead, refusedRead := exact, exact, exact, exact
	notPrincipal.Admits = exact.Admits.WithCaveat(eval.Caveat{Reason: "NotPrincipal is not modelled", Source: "statement[1]"})
	forAllValues.Admits = exact.Admits.WithCaveat(eval.Caveat{Reason: "operator ForAllValues:StringLike is not modelled", Source: "statement[0]"})
	twiceRead.Provenance = append(slices.Clone(exact.Provenance), record("iam:ListRoles", deployRole.ID))
	refusedRead.Provenance = []evidence.Record{refused("iam:GetRole", deployRole.ID)}
	twins := []trust.Grant{azure, exact, notPrincipal, forAllValues, twiceRead, refusedRead}
	first, err := FanOut(twins)
	if err != nil {
		t.Fatalf("FanOut: %v", err)
	}
	if len(first) != 5 {
		t.Fatalf("got %d links, want one per twin: %v", len(first), first)
	}
	for i, l := range first {
		if g := l.Grants()[1]; g.Target != deployRole || g.Admits != exact.Admits.String() {
			t.Fatalf("link %d is not on the twins' target and set: %v", i, l.Grants())
		}
	}
	// The exact twins first, the one read once before the one read twice,
	// then the one whose reading was refused; then the caveated twins in
	// their caveats' order, statement[0] before statement[1].
	if first[0].Confidence() != Established || first[1].Confidence() != Established || len(first[1].Provenance()) != 3 ||
		first[2].Confidence() != Indeterminate || !strings.Contains(first[2].Reason(), "returned denied") ||
		!strings.Contains(first[3].Reason(), "ForAllValues") || !strings.Contains(first[4].Reason(), "NotPrincipal") {
		for _, l := range first {
			t.Logf("%s | %d records", l.Sentence(), len(l.Provenance()))
		}
		t.Fatalf("twins are not in canonical order")
	}
	for _, shuffled := range [][]trust.Grant{{twiceRead, forAllValues, notPrincipal, refusedRead, exact, azure}, {forAllValues, azure, refusedRead, twiceRead, exact, notPrincipal}} {
		again, err := FanOut(shuffled)
		if err != nil {
			t.Fatalf("FanOut: %v", err)
		}
		if x, y := encode(t, first), encode(t, again); !bytes.Equal(x, y) {
			t.Errorf("twin order follows the input:\n%s\n%s", x, y)
		}
	}
}

// TestFanOutTreatsTheCorpusAsASet: a collector that lists one role twice
// has listed one role. A grant repeated in the corpus yields its links once
// and is named once, and a grant that differs from another only in what no
// Link reads, its anomalies or its source bytes, is the same grant.
func TestFanOutTreatsTheCorpusAsASet(t *testing.T) {
	aws := awsGrant(pinned(eval.Glob("repo:acme/*"), awsAudience))
	azure := azureGrant(pinned(eval.Exact(mainBranch), azureAudience))
	annotated := aws
	annotated.Anomalies = []trust.Anomaly{{Kind: "duplicate-statement-id", Message: "two statements share the Sid deploy"}}
	annotated.Source = []byte(`{"Version":"2012-10-17"}`)
	twiceRead := aws
	twiceRead.Provenance = []evidence.Record{record("iam:GetRole", deployRole.ID), record("iam:ListRoles", deployRole.ID)}
	listedBackwards := aws
	listedBackwards.Provenance = []evidence.Record{record("iam:ListRoles", deployRole.ID), record("iam:GetRole", deployRole.ID)}
	for name, corpus := range map[string][]trust.Grant{
		"listed twice":                      {aws, azure, aws},
		"listed five times":                 {aws, aws, aws, azure, azure},
		"annotated twin":                    {aws, azure, annotated},
		"the same records in another order": {twiceRead, azure, listedBackwards},
		"a Deny listed twice":               {aws, azure, denyOn(deployRole, eval.Glob("repo:acme/infra:*")), denyOn(deployRole, eval.Glob("repo:acme/infra:*"))},
	} {
		links, err := FanOut(corpus)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(links) != 1 {
			t.Errorf("%s: %d links, want one", name, len(links))
		}
	}
	// A grant without evidence listed twice is one collector bug.
	bare := aws
	bare.Provenance = nil
	_, err := FanOut([]trust.Grant{bare, azure, bare})
	if err == nil || strings.Count(err.Error(), ErrNoEvidence.Error()) != 1 {
		t.Errorf("err = %v, want the grant named once", err)
	}
	// Two twins whose records are all malformed are named in canonical
	// order, whichever the collector listed first and however it listed
	// their records.
	noCall, noStatus := aws, aws
	noCall.Provenance = []evidence.Record{evidence.New("", `{"page":2}`, evidence.StatusOK, nil, time.Unix(0, 0)), evidence.New("", `{}`, evidence.StatusOK, nil, time.Unix(0, 0))}
	noStatus.Provenance = []evidence.Record{evidence.New("iam:GetRole", `{"target":`+strconv.Quote(deployRole.ID)+`}`, "", nil, time.Unix(0, 0))}
	linksX, errX := FanOut([]trust.Grant{noCall, azure, noStatus})
	slices.Reverse(noCall.Provenance)
	linksY, errY := FanOut([]trust.Grant{noStatus, azure, noCall})
	if errX == nil || errY == nil || errX.Error() != errY.Error() || strings.Count(errX.Error(), ErrMalformedEvidence.Error()) != 2 || len(linksX) != 0 || len(linksY) != 0 {
		t.Errorf("the order of the grants named follows the listing, or a twin was not named:\n%v\n%v", errX, errY)
	}
	// Twins that differ in evidence are two grants: the collector read the
	// role twice and each reading is a record.
	twin := aws
	twin.Provenance = []evidence.Record{record("iam:ListRoles", deployRole.ID)}
	if links, _ := FanOut([]trust.Grant{aws, azure, twin}); len(links) != 2 {
		t.Errorf("twins differing in evidence: %d links, want two", len(links))
	}
}

// denyOn is a Deny statement on target over sub, proved by its own record.
func denyOn(target trust.TargetRef, sub eval.StringSet) trust.Grant {
	return trust.Grant{Target: target, Issuer: github, Admits: pinned(sub, awsAudience), Effect: trust.Deny, Provenance: []evidence.Record{record("iam:GetRolePolicy", target.ID)}}
}

// TestFanOutOrdersEvidenceByEveryRenderedField: the rendering carries a
// record's body and the time it was fetched, so the order of records, and
// of the links that differ only by them, has to read both; an order that
// ignored a rendered field would leave the collector's listing order in the
// bytes. Two fetches of one document at two times are two records, and
// both are kept.
func TestFanOutOrdersEvidenceByEveryRenderedField(t *testing.T) {
	azure := azureGrant(pinned(eval.Exact(mainBranch), azureAudience))
	at := func(when int64) evidence.Record {
		return evidence.New("iam:GetRole", `{"target":`+strconv.Quote(deployRole.ID)+`}`, evidence.StatusOK, []byte(`{"ok":true}`), time.Unix(when, 0))
	}
	early, late := awsGrant(pinned(eval.Glob("repo:acme/*"), awsAudience)), awsGrant(pinned(eval.Glob("repo:acme/*"), awsAudience))
	early.Provenance, late.Provenance = []evidence.Record{at(1)}, []evidence.Record{at(2)}
	twiceRead := awsGrant(pinned(eval.Glob("repo:acme/*"), awsAudience))
	twiceRead.Provenance = []evidence.Record{at(2), at(1)}
	// One instant written in two zones is one instant and two renderings.
	zoned, utc := at(1), at(1)
	zoned.FetchedAt = zoned.FetchedAt.In(time.FixedZone("", 2*60*60))
	utc.FetchedAt = utc.FetchedAt.UTC()
	twoZones := awsGrant(pinned(eval.Glob("repo:acme/*"), awsAudience))
	twoZones.Provenance = []evidence.Record{zoned, utc}
	sameDigest := awsGrant(pinned(eval.Glob("repo:acme/*"), awsAudience))
	forged := at(1)
	forged.Bytes = []byte(`{"ok":false}`)
	sameDigest.Provenance = []evidence.Record{forged, at(1)}
	deny := denyOn(deployRole, eval.Glob("repo:acme/infra:*"))
	denyAgain := deny
	denyAgain.Provenance = []evidence.Record{evidence.New("iam:GetRolePolicy", `{"target":`+strconv.Quote(deployRole.ID)+`}`, evidence.StatusOK, []byte(`{"ok":true}`), time.Unix(5, 0))}
	cases := []struct {
		name    string
		corpus  []trust.Grant
		links   int
		records int // on the first link
	}{
		{"twins fetched at two times", []trust.Grant{azure, early, late}, 2, 2},
		{"one grant read twice", []trust.Grant{azure, twiceRead}, 1, 3},
		{"one instant in two zones", []trust.Grant{azure, twoZones}, 1, 3},
		{"one digest, two bodies", []trust.Grant{azure, sameDigest}, 1, 3},
		{"a Deny read twice", []trust.Grant{azure, early, deny, denyAgain}, 1, 4},
	}
	for _, c := range cases {
		first, err := FanOut(c.corpus)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if len(first) != c.links {
			t.Errorf("%s: %d links, want %d", c.name, len(first), c.links)
		} else if len(first[0].Provenance()) != c.records {
			t.Errorf("%s: %d records on the first link, want %d", c.name, len(first[0].Provenance()), c.records)
		}
		reversed := slices.Clone(c.corpus)
		slices.Reverse(reversed)
		for i := range reversed {
			slices.Reverse(reversed[i].Provenance)
		}
		again, err := FanOut(reversed)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if x, y := encode(t, first), encode(t, again); !bytes.Equal(x, y) {
			t.Errorf("%s: the rendering follows the listing order:\n%s\n%s", c.name, x, y)
		}
	}
}

// TestLinkHoldsTheFetchTimeAsRendered: a time read from the clock carries a
// monotonic reading beside the wall clock, and nothing renders it. A Link
// keeps the fetch time as the rendering carries it, so that every
// comparison downstream reads what a reader of the JSON could read, and no
// more.
func TestLinkHoldsTheFetchTimeAsRendered(t *testing.T) {
	read := time.Now()
	if read == read.Round(0) {
		t.Fatalf("the clock returned no monotonic reading; the test would examine nothing")
	}
	aws := awsGrant(pinned(eval.Glob("repo:acme/*"), awsAudience))
	aws.Provenance = []evidence.Record{evidence.New("iam:GetRole", `{}`, evidence.StatusOK, []byte(`{}`), read)}
	azure := azureGrant(pinned(eval.Exact(mainBranch), azureAudience))
	azure.Provenance = []evidence.Record{evidence.New("graph:federatedIdentityCredentials.list", `{}`, evidence.StatusOK, []byte(`{}`), read)}
	l := mustLink(t, aws, azure)
	for _, r := range l.Provenance() {
		if r.FetchedAt != r.FetchedAt.Round(0) {
			t.Errorf("%s was fetched at %v, which carries a reading the rendering does not", r.API, r.FetchedAt)
		}
		if !r.FetchedAt.Equal(read) {
			t.Errorf("%s was fetched at %v, want the instant %v", r.API, r.FetchedAt, read)
		}
	}
}

// TestOneGrantReadTwiceInOneInstantIsOneGrant is the collapse the rule
// above guarantees: two readings of one grant whose records differ only in
// a monotonic reading render byte for byte the same, and are one grant, as
// they are once the records have been through a JSON file. The clock
// returns such a pair only where its wall clock is coarser than its
// monotonic one; where it never does, the shape cannot be drawn here and
// the test says so instead of examining nothing.
func TestOneGrantReadTwiceInOneInstantIsOneGrant(t *testing.T) {
	first, second, ok := oneInstantTwice()
	if !ok {
		t.Skipf("the clock never returned one wall reading with two monotonic readings; the shape cannot be drawn on this platform")
	}
	at := func(when time.Time) trust.Grant {
		g := awsGrant(pinned(eval.Glob("repo:acme/*"), awsAudience))
		g.Provenance = []evidence.Record{evidence.New("iam:GetRole", `{}`, evidence.StatusOK, []byte(`{}`), when)}
		return g
	}
	azure := azureGrant(pinned(eval.Exact(mainBranch), azureAudience))
	links, err := FanOut([]trust.Grant{at(first), azure, at(second)})
	if err != nil {
		t.Fatalf("FanOut: %v", err)
	}
	if len(links) != 1 {
		t.Fatalf("%d links from one grant read twice at %s, want one", len(links), first.Format(time.RFC3339Nano))
	}
	twice := at(first)
	twice.Provenance = append(twice.Provenance, at(second).Provenance...)
	if l := mustLink(t, twice, azure); len(l.Provenance()) != 2 {
		t.Errorf("%d records on the link, want the two sides' one each", len(l.Provenance()))
	}
}

// oneInstantTwice reads the clock until two readings share a wall clock
// and differ in their monotonic reading, or gives up.
func oneInstantTwice() (time.Time, time.Time, bool) {
	for range 1 << 12 {
		a, b := time.Now(), time.Now()
		if a.Round(0).Equal(b.Round(0)) && a.Compare(b) != 0 {
			return a, b, true
		}
	}
	return time.Time{}, time.Time{}, false
}

// TestRecordsOrderByInstantBeforeRendering: two fetches of one document
// order by the instant each names, and only then by the rendering. A time
// written in a zone east of UTC renders with a later hour than an instant
// after it written in UTC; an order that read the text first would put the
// later fetch first.
func TestRecordsOrderByInstantBeforeRendering(t *testing.T) {
	at := func(when time.Time) evidence.Record {
		return evidence.New("iam:GetRole", `{"target":`+strconv.Quote(deployRole.ID)+`}`, evidence.StatusOK, []byte(`{"ok":true}`), when)
	}
	earlier := at(time.Date(2026, 9, 13, 10, 0, 0, 0, time.FixedZone("", 2*60*60))) // 08:00Z
	later := at(time.Date(2026, 9, 13, 9, 0, 0, 0, time.UTC))                       // 09:00Z
	aws := awsGrant(pinned(eval.Glob("repo:acme/*"), awsAudience))
	aws.Provenance = []evidence.Record{later, earlier}
	links, err := FanOut([]trust.Grant{azureGrant(pinned(eval.Exact(mainBranch), azureAudience)), aws})
	if err != nil || len(links) != 1 {
		t.Fatalf("links %d, err %v", len(links), err)
	}
	var fetched []time.Time
	for _, r := range links[0].Provenance() {
		if r.API == "iam:GetRole" {
			fetched = append(fetched, r.FetchedAt)
		}
	}
	if len(fetched) != 2 || !fetched[0].Before(fetched[1]) {
		t.Fatalf("iam:GetRole records fetched at %v; want the earlier instant first", fetched)
	}
}
