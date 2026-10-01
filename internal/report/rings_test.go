package report

import (
	"bytes"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/CloudArq-net/cloudarq/internal/parse/aws"
	"github.com/CloudArq-net/cloudarq/internal/ring"
	"github.com/CloudArq-net/cloudarq/internal/trust"
)

// The rings as a consumer reads them: through the JSON, so that a build
// whose answer lacks a field fails here on what a reader would see rather
// than on a missing symbol.
type ringsAnswer struct {
	Error    string `json:"error"`
	Document *struct {
		Statements []Statement `json:"statements"`
	} `json:"document"`
	Headline *struct {
		Sentence string `json:"sentence"`
		Spans    []Span `json:"spans"`
	} `json:"headline"`
	Rings        []Row         `json:"rings"`
	Beside       []Row         `json:"beside"`
	Refused      *Listing      `json:"refused"`
	Nobody       *Listing      `json:"nobody"`
	Declarations *Declarations `json:"declarations"`
	Bounds       *Bounds       `json:"bounds"`
	Grants       []struct {
		Number         int          `json:"number"`
		Effect         string       `json:"effect"`
		Empty          bool         `json:"empty"`
		Placement      []string     `json:"placement"`
		PlacementState string       `json:"placementState"`
		Populations    []Population `json:"populations"`
	} `json:"grants"`
}

func ringsOf(t *testing.T, answer []byte) ringsAnswer {
	t.Helper()
	var a ringsAnswer
	if err := json.Unmarshal(answer, &a); err != nil {
		t.Fatalf("the answer is not JSON: %v", err)
	}
	return a
}

const ringsDir = "../../testdata/rings"

// ringsCase is a case of testdata/rings: its document and its declaration.
func ringsCase(t *testing.T, name string) (doc, owners []byte) {
	t.Helper()
	doc, err := os.ReadFile(filepath.Join(ringsDir, name, "aws.json"))
	if err != nil {
		t.Fatal(err)
	}
	owners, err = os.ReadFile(filepath.Join(ringsDir, name, "owners.txt"))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		t.Fatal(err)
	}
	return doc, owners
}

// ringsCases is every case under testdata/rings, by name.
func ringsCases(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(ringsDir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() {
			names = append(names, e.Name())
		}
	}
	if len(names) < 40 {
		t.Fatalf("%d cases under %s; the tests would examine too little", len(names), ringsDir)
	}
	return names
}

var ringOrder = []string{"anyone", "platform", "outsider", "yours", "people"}

// TestTheDefaultDocument: case 01 is the document the README shows, and its
// headline is "Anyone on GitHub can assume this role.": the platform is
// where the accounts are, github.com, not the product that mints the token.
// Its rings are a platform reached exactly and a named outsider, with no
// Unknown; declaring acme moves the pinned statement to the user's own
// pipelines and leaves the prefix where it was, which is what declaring can
// do and what it cannot; and acme spelt in another case declares nobody,
// since GitHub's names compare exactly.
func TestTheDefaultDocument(t *testing.T) {
	doc, _ := ringsCase(t, "01-branch-pin-and-owner-prefix")
	type want struct {
		grants   map[string][]int
		sentence map[string]string
		declared []string
	}
	for owners, w := range map[string]want{
		"": {
			grants: map[string][]int{"platform": {2}, "outsider": {1}},
			sentence: map[string]string{
				"platform": "Anyone on GitHub can assume this role; no condition confines its tokens to one owner.",
				"outsider": "github:acme can assume this role and is not declared as yours.",
			},
			declared: []string{},
		},
		"github:acme\n": {
			grants: map[string][]int{"platform": {2}, "yours": {1}},
			sentence: map[string]string{
				"yours":    "github:acme, declared as yours, can assume this role.",
				"outsider": "No grant is placed with a named outsider.",
			},
			declared: []string{"github:acme"},
		},
		"github:Acme\n": {
			grants:   map[string][]int{"platform": {2}, "outsider": {1}},
			sentence: map[string]string{"outsider": "github:acme can assume this role and is not declared as yours."},
			declared: []string{"github:Acme"},
		},
	} {
		a := ringsOf(t, AdmitsFor(doc, []byte(owners)))
		if a.Headline == nil || a.Headline.Sentence != "Anyone on GitHub can assume this role." {
			t.Errorf("declaring %q: headline %+v", owners, a.Headline)
		}
		if len(a.Rings) != len(ringOrder) || len(a.Beside) != 0 {
			t.Fatalf("declaring %q: %d rings and %d lines", owners, len(a.Rings), len(a.Beside))
		}
		for i, r := range a.Rings {
			if r.Place != ringOrder[i] || r.State != "exact" || !slices.Equal(r.GrantNumbers, append([]int{}, w.grants[r.Place]...)) {
				t.Errorf("declaring %q: ring %d is %+v", owners, i, r)
			}
			if want, ok := w.sentence[r.Place]; ok && r.Sentence != want {
				t.Errorf("declaring %q: %s says %q, want %q", owners, r.Place, r.Sentence, want)
			}
		}
		if a.Rings[1].Label != "Anyone on GitHub" {
			t.Errorf("declaring %q: the platform ring is labelled %q", owners, a.Rings[1].Label)
		}
		if a.Declarations == nil || !slices.Equal(a.Declarations.Normalised, w.declared) || len(a.Declarations.RefusedLines) != 0 {
			t.Errorf("declaring %q: echoed %+v", owners, a.Declarations)
		}
		for _, g := range a.Grants {
			if g.PlacementState != "exact" {
				t.Errorf("declaring %q: grant %d is %s, want exact: the rings carry no Unknown", owners, g.Number, g.PlacementState)
			}
		}
	}
}

// TestEveryAnswerCarriesTheRings holds the shape of every answer the corpus
// and the rings cases produce, with and without a declaration: the five
// rings in order and no other, each exact or unknown; each grant in exactly
// the rows its placement names, by number and in order; a line only when
// it holds a grant; the refusals and the grants that admit nobody listed
// and in no row; the three bounds; the declaration echoed; and a headline.
// A document that holds no statement, case 52, carries the headline and
// nothing after it: nothing was read to place in a ring, so no ring is
// printed, exact or otherwise.
func TestEveryAnswerCarriesTheRings(t *testing.T) {
	docs := corpus(t)
	declared := map[string][]byte{}
	for _, name := range ringsCases(t) {
		doc, owners := ringsCase(t, name)
		docs[name] = doc
		declared[name] = owners
	}
	examined, lines, listed, unread := 0, 0, 0, 0
	for name, doc := range docs {
		for _, owners := range [][]byte{nil, declared[name], []byte("github:acme\naws:111122223333\ngitlab:x\n")} {
			a := ringsOf(t, AdmitsFor(doc, owners))
			if a.Error != "" {
				if a.Rings != nil || a.Headline != nil || a.Bounds != nil || a.Declarations != nil {
					t.Errorf("%s: an answer that read no document carries rings: %+v", name, a)
				}
				continue
			}
			if len(a.Document.Statements) == 0 {
				unread++
				if a.Headline == nil || a.Rings != nil || a.Beside != nil || a.Refused != nil || a.Nobody != nil || a.Declarations != nil || a.Bounds != nil {
					t.Errorf("%s: an answer that read no statement has headline %+v, rings %+v, lines %+v, refused %+v, nobody %+v, owners %+v, bounds %+v", name, a.Headline, a.Rings, a.Beside, a.Refused, a.Nobody, a.Declarations, a.Bounds)
				}
				continue
			}
			examined++
			if len(a.Rings) != len(ringOrder) || a.Headline == nil || a.Headline.Sentence == "" || a.Declarations == nil {
				t.Fatalf("%s: rings %+v, headline %+v, owners %+v", name, a.Rings, a.Headline, a.Declarations)
			}
			in := map[int][]string{}
			for i, r := range append(append([]Row{}, a.Rings...), a.Beside...) {
				if i < len(ringOrder) && r.Place != ringOrder[i] {
					t.Errorf("%s: ring %d is %q", name, i, r.Place)
				}
				if i >= len(ringOrder) && (len(r.GrantNumbers) == 0 || r.Place != "saml" && r.Place != "service") {
					t.Errorf("%s: a line %+v", name, r)
				}
				if !slices.IsSorted(r.GrantNumbers) || r.Label == "" || r.Sentence == "" || plain(r.Spans) != r.Sentence {
					t.Errorf("%s: row %+v", name, r)
				}
				if r.State != "exact" && r.State != "unknown" {
					t.Errorf("%s: row %s in state %q", name, r.Place, r.State)
				}
				for _, n := range r.GrantNumbers {
					in[n] = append(in[n], r.Place)
				}
			}
			lines += len(a.Beside)
			for _, l := range []struct {
				listing *Listing
				place   string
			}{{a.Refused, "refused"}, {a.Nobody, "nobody"}} {
				if l.listing == nil {
					continue
				}
				listed++
				for _, n := range l.listing.GrantNumbers {
					in[n] = append(in[n], l.place)
				}
			}
			for _, g := range a.Grants {
				if !slices.Equal(in[g.Number], g.Placement) {
					t.Errorf("%s: grant %d is placed %v and listed in %v", name, g.Number, g.Placement, in[g.Number])
				}
				switch {
				case g.Effect == "Deny" || g.Empty:
					outcome := map[bool]string{true: "refused", false: "nobody"}[g.Effect == "Deny"]
					if !slices.Equal(g.Placement, []string{outcome}) || g.PlacementState != "" || g.Populations != nil {
						t.Errorf("%s: grant %d, %s and empty %v, is placed %v %q %v", name, g.Number, g.Effect, g.Empty, g.Placement, g.PlacementState, g.Populations)
					}
				case len(g.Placement) == 0 || slices.Contains(g.Placement, "refused") || slices.Contains(g.Placement, "nobody") || g.PlacementState == "" || len(g.Populations) == 0:
					t.Errorf("%s: grant %d admits someone and is placed %v %q %v", name, g.Number, g.Placement, g.PlacementState, g.Populations)
				}
			}
			if a.Bounds == nil || len(a.Bounds.Items) < 3 || a.Bounds.Items[0].Bound != "resource-control-policies" || a.Bounds.Items[1].Bound != "service-control-policies" || a.Bounds.Items[2].Bound != "identity-providers" || a.Bounds.Sentence == "" {
				t.Errorf("%s: bounds %+v", name, a.Bounds)
			}
		}
	}
	if examined < 100 || lines == 0 || listed == 0 || unread == 0 {
		t.Fatalf("%d answers, %d lines, %d listings and %d answers with no statement examined; the corpus did not reach every part", examined, lines, listed, unread)
	}
	t.Logf("%d answers, %d lines beside the rings, %d listings of grants in no ring, %d answers with no statement", examined, lines, listed, unread)
}

// TestTheHeadlineNeverOmitsALine holds the headline to the populations
// nobody read, over every answer: a line beside the rings that holds a
// grant is named in the headline, "only" is never said, and the sentence
// for an empty set of rings is said exactly when no ring outside the
// user is reached, no line holds a grant, no row reached is unknown and
// the document holds a statement to have read.
func TestTheHeadlineNeverOmitsALine(t *testing.T) {
	docs := corpus(t)
	for _, name := range ringsCases(t) {
		docs[name], _ = ringsCase(t, name)
	}
	const empty = "Nothing outside your company can assume this role."
	saidEmpty, saidLines := 0, 0
	for name, doc := range docs {
		for _, owners := range [][]byte{nil, []byte("saml:arn:aws:iam::123456789012:saml-provider/VendorSSO\ngithub:acme\n")} {
			a := ringsOf(t, AdmitsFor(doc, owners))
			if a.Error != "" {
				continue
			}
			h := a.Headline.Sentence
			if len(strings.Fields(h)) > 14 {
				t.Errorf("%s: the headline is %d words: %q", name, len(strings.Fields(h)), h)
			}
			if strings.Contains(" "+strings.ToLower(h)+" ", " only ") {
				t.Errorf("%s: the headline says only: %q", name, h)
			}
			// a line is named by its class beside a ring, and by its own
			// population when it is the headline's whole subject
			for _, l := range a.Beside {
				saidLines++
				if class := map[string]string{"saml": "SAML", "service": "cloud service"}[l.Place]; !strings.Contains(h, class) && !strings.HasPrefix(h, l.Spans[0].Text) {
					t.Errorf("%s: the headline %q omits the line %s, %q", name, h, l.Place, l.Sentence)
				}
			}
			outside, unknown := false, false
			for _, r := range a.Rings {
				outside = outside || len(r.GrantNumbers) > 0 && slices.Contains(ringOrder[:3], r.Place)
				unknown = unknown || len(r.GrantNumbers) > 0 && r.State == "unknown"
			}
			if wantEmpty := !outside && len(a.Beside) == 0 && !unknown && len(a.Grants) > 0; (h == empty) != wantEmpty {
				t.Errorf("%s: headline %q; outside %v, lines %d, unknown %v", name, h, outside, len(a.Beside), unknown)
			}
			if h == empty {
				saidEmpty++
			}
		}
	}
	if saidEmpty == 0 || saidLines == 0 {
		t.Fatalf("the empty-rings sentence was said %d times and lines named %d times; the rule went unexamined", saidEmpty, saidLines)
	}
}

// TestAGrantSaysNoMoreThanItsRing: a grant's own sentence and the rings
// are printed on one screen, so they must not disagree about who gets in.
// A grant the rings place anywhere but Anyone admits nobody without an
// account, and its sentence must not say it admits anonymous principals:
// AWS requires credentials of whoever calls sts:AssumeRole ("You must
// call this API using active credentials", rings case 10).
func TestAGrantSaysNoMoreThanItsRing(t *testing.T) {
	docs := corpus(t)
	for _, name := range ringsCases(t) {
		docs[name], _ = ringsCase(t, name)
	}
	examined := 0
	for name, doc := range docs {
		a := AnswerOf(doc)
		for _, g := range a.Grants {
			if slices.Contains(g.Placement, "anyone") || g.Empty || g.Effect == "Deny" {
				continue
			}
			examined++
			if strings.Contains(g.Sentence, "anonymous") {
				t.Errorf("%s: grant %d is placed %v and says %q", name, g.Number, g.Placement, g.Sentence)
			}
		}
	}
	if examined < 100 {
		t.Fatalf("%d grants examined; the corpus did not load", examined)
	}
}

// TestAnEmptyRingSaysOnlyWhereGrantsAreNot holds two rules over every
// answer the corpus and the rings cases give. A ring no grant is placed in
// says so and no more: never that a grant admits someone, or that someone
// can assume the role. And the ring of anyone is unknown whenever a grant's
// population is one whose members are not read, a SAML provider's sign-ins
// or a service's callers: who a SAML provider signs in, and who can make a
// service act, is not read, so nothing read rules out people with no
// account anywhere. A provider declared as the user's is one too: the
// declaration says whose it is, not whom it signs in.
func TestAnEmptyRingSaysOnlyWhereGrantsAreNot(t *testing.T) {
	docs := corpus(t)
	declared := map[string][]byte{}
	for _, name := range ringsCases(t) {
		docs[name], declared[name] = ringsCase(t, name)
	}
	// two providers, declared one at a time and together
	twoProviders := []byte(`{"Version":"2012-10-17","Statement":[{"Sid":"TwoProviders","Effect":"Allow","Principal":{"Federated":["arn:aws:iam::123456789012:saml-provider/CorpA","arn:aws:iam::123456789012:saml-provider/CorpB"]},"Action":"sts:AssumeRoleWithSAML","Condition":{"StringEquals":{"SAML:aud":"https://signin.aws.amazon.com/saml"}}}]}`)
	for name, owners := range map[string]string{
		"two providers, one declared":  "saml:arn:aws:iam::123456789012:saml-provider/CorpA\n",
		"two providers, both declared": "saml:arn:aws:iam::123456789012:saml-provider/CorpA\nsaml:arn:aws:iam::123456789012:saml-provider/CorpB\n",
	} {
		docs[name], declared[name] = twoProviders, []byte(owners)
	}
	empty, beside, declaredProviders := 0, 0, 0
	for name, doc := range docs {
		for _, owners := range [][]byte{nil, declared[name]} {
			a := ringsOf(t, AdmitsFor(doc, owners))
			if len(a.Rings) == 0 {
				continue
			}
			for _, r := range a.Rings {
				if len(r.GrantNumbers) > 0 {
					continue
				}
				empty++
				if !strings.HasPrefix(r.Sentence, "No grant ") || strings.Contains(r.Sentence, "admit") || strings.Contains(r.Sentence, "assume") {
					t.Errorf("%s: the empty ring %s says %q", name, r.Place, r.Sentence)
				}
			}
			unread := false
			for _, g := range a.Grants {
				unread = unread || slices.ContainsFunc(g.Populations, func(p Population) bool {
					return slices.Contains([]string{"saml-provider", "account-saml-providers", "service-principal", "any-service", "service-intermediary"}, p.Basis)
				})
			}
			if !unread {
				continue
			}
			beside++
			if slices.ContainsFunc(a.Rings, func(r Row) bool { return r.Place == "people" && len(r.GrantNumbers) > 0 }) {
				declaredProviders++
			}
			if anyone := a.Rings[0]; anyone.Place != "anyone" || anyone.State != "unknown" {
				t.Errorf("%s, declaring %q: beside a population whose members are not read, the ring of anyone is %s %q", name, owners, anyone.State, anyone.Sentence)
			}
		}
	}
	if empty == 0 || beside == 0 || declaredProviders == 0 {
		t.Fatalf("%d empty rings, %d answers with an unread population, %d of them in the ring of your people, examined; all must be positive", empty, beside, declaredProviders)
	}
	t.Logf("%d empty rings, %d answers with an unread population, %d of them in the ring of your people", empty, beside, declaredProviders)
}

// TestAServiceLineLeavesAnyoneUnknown: who can make a service act, or
// receives its session, is not read, and nothing read rules out people with
// no account anywhere, so the ring of anyone is unknown whenever the line of
// cloud services holds a grant, whatever the line's own state. Reading which
// account a service acts for may one day make its line exact; that says
// nothing of who receives the service's session, as a certificate holder
// does from IAM Roles Anywhere. The SAML rule is as it was: a line of
// sign-ins not let in for certain, or the ring of your people, leaves the
// ring unknown. A grant on a platform alone leaves it exact, so the ring's
// state here is the rule's and no default's.
func TestAServiceLineLeavesAnyoneUnknown(t *testing.T) {
	service := trust.IssuerRef(aws.ServiceIssuerPrefix + "rolesanywhere.amazonaws.com")
	const saml = trust.IssuerRef("arn:aws:iam::123456789012:saml-provider/VendorSSO")
	provider := []ring.Owner{{Issuer: saml, Namespace: ring.NamespaceSAML, Scope: ring.ScopeProvider, Value: string(saml)}}
	platform := grantAt(2, aws.AWSPrincipalIssuer, "AWS", ring.Platform, ring.StateExact, nil, ring.Unpinned)
	cases := []struct {
		name   string
		grants []placed
		anyone string
	}{
		{"a service line whose population is exact", []placed{grantAt(1, service, "", ring.Service, ring.StateExact, nil, ring.ServicePrincipal), platform}, "unknown"},
		{"a service line whose population is unknown", []placed{grantAt(1, service, "", ring.Service, ring.StateUnknown, nil, ring.ServicePrincipal), platform}, "unknown"},
		{"a SAML line whose population is unknown", []placed{grantAt(1, saml, "", ring.SAML, ring.StateUnknown, provider, ring.SAMLProvider), platform}, "unknown"},
		{"your people, unknown", []placed{grantAt(1, saml, "", ring.People, ring.StateUnknown, provider, ring.SAMLProvider), platform}, "unknown"},
		{"a platform alone", []placed{platform}, "exact"},
	}
	for _, c := range cases {
		var a Answer
		a.rings(c.grants, ring.Declarations{})
		if anyone := a.Rings[ring.Anyone]; anyone.Place != "anyone" || anyone.State != c.anyone {
			t.Errorf("%s: the ring of anyone is %s %s, want %s", c.name, anyone.Place, anyone.State, c.anyone)
		}
	}
}

// TestADocumentWithNoStatementIsNotClean: a document that holds no
// statement, a truncated paste or one the parser calls malformed, is not a
// policy IAM holds, so nothing in it can be placed in a ring. The headline
// says who can assume the role is not known, rather than the sentence for
// an empty set of rings, the worst output when it is wrong; and no ring is
// printed, since five empty rings marked exact would draw as a role nobody
// reaches, whatever the headline says, and a declaration has nothing to
// move.
func TestADocumentWithNoStatementIsNotClean(t *testing.T) {
	for _, doc := range []string{`{}`, `{"Version":"2012-10-17","Id":"TruncatedPaste"}`, `{"Statement":[]}`, `{"Version":"2012-10-17","Statement":[]}`} {
		for _, owners := range []string{"", "github:acme\ngithub:\n"} {
			a := ringsOf(t, AdmitsFor([]byte(doc), []byte(owners)))
			if a.Error != "" || a.Headline == nil {
				t.Fatalf("%s: %+v", doc, a)
			}
			if h := a.Headline.Sentence; h != "The document holds no statement, so who can assume this role is not known." {
				t.Errorf("%s: headline %q", doc, h)
			}
			if !slices.ContainsFunc(a.Headline.Spans, func(s Span) bool { return s.Mark == "unknown" }) || slices.ContainsFunc(a.Headline.Spans, func(s Span) bool { return s.Mark == "exact" }) {
				t.Errorf("%s: the headline is marked %+v", doc, a.Headline.Spans)
			}
			if a.Rings != nil || a.Beside != nil || a.Refused != nil || a.Nobody != nil || a.Declarations != nil || a.Bounds != nil {
				t.Errorf("%s, declaring %q: rings %+v, lines %+v, refused %+v, nobody %+v, owners %+v, bounds %+v", doc, owners, a.Rings, a.Beside, a.Refused, a.Nobody, a.Declarations, a.Bounds)
			}
		}
	}
	// a document whose one statement admits nobody holds a statement, and
	// its rings are the finding
	if a := ringsOf(t, Admits([]byte(`{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Principal":"*","Action":"sts:AssumeRole"}]}`))); a.Headline.Sentence != "Nothing outside your company can assume this role." {
		t.Errorf("a lone Deny: headline %q", a.Headline.Sentence)
	}
}

// TestTheTokenOfADocumentWithNoStatementIsNotAnswered: the explanation of a
// document with no statement says what the answer says, that it is not
// known, as its result and its heading, and carries no grant, no bounds
// and no declaration, as the answer carries none. The token is still read.
func TestTheTokenOfADocumentWithNoStatementIsNotAnswered(t *testing.T) {
	token := []byte(`{"iss":"https://token.actions.githubusercontent.com","aud":"sts.amazonaws.com","sub":"repo:acme/infra:ref:refs/heads/main"}`)
	for _, doc := range []string{`{}`, `{"Version":"2012-10-17","Id":"TruncatedPaste"}`, `{"Statement":[]}`, `{"Version":"2012-10-17","Statement":[]}`} {
		for _, owners := range []string{"", "github:acme\ngithub:\n"} {
			var e Explanation
			if err := json.Unmarshal(ExplainFor([]byte(doc), token, []byte(owners)), &e); err != nil {
				t.Fatal(err)
			}
			if e.Error != "" || e.Token.Error != "" || e.Token.Claims != 3 {
				t.Fatalf("%s: %+v", doc, e)
			}
			if e.Result != "not known" {
				t.Errorf("%s, declaring %q: result %q", doc, owners, e.Result)
			}
			if h := plain(e.Heading); h != "The document holds no statement, so whether this token is admitted is not known." {
				t.Errorf("%s: heading %q", doc, h)
			}
			if !slices.ContainsFunc(e.Heading, func(s Span) bool { return s.Mark == "unknown" }) || len(e.Spans) != 0 || len(e.Grants) != 0 {
				t.Errorf("%s: heading %+v, sentence %+v, %d grants", doc, e.Heading, e.Spans, len(e.Grants))
			}
			if e.Declarations != nil || e.Bounds != nil {
				t.Errorf("%s, declaring %q: owners %+v, bounds %+v", doc, owners, e.Declarations, e.Bounds)
			}
		}
	}
}

// TestWhatEachRingSays holds the sentence of a row, and the headline, for
// every reason a grant is placed where it is, each on the rings case that
// exhibits it.
func TestWhatEachRingSays(t *testing.T) {
	type row struct{ place, label, state, sentence string }
	cases := []struct {
		name     string
		headline string
		rows     []row
	}{
		{"07-anyone-on-web-identity", "Anyone could assume this role.", []row{
			{"anyone", "Anyone", "unknown", "Anyone could assume this role: by the engine's reading of AWS's documentation, identity-pool guests may."},
		}},
		{"08-anyone-on-saml-alone", "People any SAML provider in this account signs in can assume this role.", []row{
			{"saml", "SAML sign-ins", "unknown", "People any SAML provider in this account signs in can assume this role."},
			{"anyone", "Anyone", "unknown", "No grant is placed with people who have no account anywhere."},
		}},
		{"10-anyone-on-assume-role", "Anyone on AWS can assume this role; so can cloud services.", []row{
			{"platform", "Anyone on AWS", "exact", "Anyone on AWS can assume this role; no condition confines callers to one account or organisation."},
			{"service", "Cloud services", "unknown", "Any cloud service can assume this role; which ones, and for whom, is not read."},
		}},
		{"11-cognito-guests", "Anyone could assume this role.", []row{
			{"anyone", "Anyone", "unknown", "Anyone could assume this role: cognito-identity.amazonaws.com gives tokens to guests and to whoever signs in."},
		}},
		{"12-cognito-authenticated", "Anyone could assume this role.", []row{
			{"anyone", "Anyone", "unknown", "Anyone could assume this role: cognito-identity.amazonaws.com gives tokens to guests and to whoever signs in."},
		}},
		{"13-google", "Anyone on Google could assume this role.", []row{
			{"platform", "Anyone on Google", "unknown", "Anyone on Google could assume this role; which claims name an owner is not recorded."},
		}},
		{"15-facebook", "Anyone could assume this role.", []row{
			{"anyone", "Anyone", "unknown", "Anyone could assume this role: nothing read shows Facebook requires an account."},
		}},
		{"20-saml-provider-of-a-vendor", "People VendorSSO signs in can assume this role.", []row{
			{"saml", "SAML sign-ins", "unknown", "People VendorSSO signs in can assume this role; who they are is set in VendorSSO."},
			{"anyone", "Anyone", "unknown", "No grant is placed with people who have no account anywhere."},
		}},
		{"21-service-without-source-account", "sns.amazonaws.com can assume this role.", []row{
			{"service", "Cloud services", "unknown", "sns.amazonaws.com can assume this role; who can make it act is not read."},
			{"anyone", "Anyone", "unknown", "No grant is placed with people who have no account anywhere."},
		}},
		{"25-eks-cluster", "A named outsider can assume this role.", []row{
			{"outsider", "A named outsider", "exact", "issuer:https://oidc.eks.us-east-1.amazonaws.com/id/EXAMPLED539D4633E53DE1B71EXAMPLE can assume this role and is not declared as yours."},
			{"anyone", "Anyone", "exact", "No grant is placed with people who have no account anywhere."},
		}},
		{"27-deny-for-anyone", "A named outsider can assume this role.", nil},
		{"28-no-assume-action", "Nothing outside your company can assume this role.", nil},
		{"29-unsurveyed-issuer", "Anyone could assume this role.", []row{
			{"anyone", "Anyone", "unknown", "Anyone could assume this role: whether ci.example.com requires an account was not surveyed."},
		}},
		{"31-unread-subject", "Anyone on GitHub could assume this role.", []row{
			{"platform", "Anyone on GitHub", "unknown", "Anyone on GitHub could assume this role; one of its conditions was not read."},
		}},
		{"35-saml-provider-declared", "Your people can assume this role; who they are is set in VendorSSO.", []row{
			{"people", "Your people", "unknown", "People VendorSSO signs in can assume this role; who they are is set in VendorSSO."},
			{"anyone", "Anyone", "unknown", "No grant is placed with people who have no account anywhere."},
		}},
		{"36-entra-tenants", "Anyone on login.microsoftonline.com can assume this role.", []row{
			{"platform", "Anyone on login.microsoftonline.com", "exact", "Anyone on login.microsoftonline.com can assume this role."},
		}},
		{"38-repository-id-subject", "A named outsider can assume this role.", []row{
			{"outsider", "A named outsider", "exact", "Repository 456789 can assume this role and cannot be declared."},
		}},
		{"41-union-of-owners", "A named outsider can assume this role.", []row{
			{"outsider", "A named outsider", "exact", "3 named outsiders can assume this role; none is declared as yours."},
		}},
		{"42-principals-not-modelled", "Anyone could assume this role.", []row{
			{"anyone", "Anyone", "unknown", "Anyone could assume this role: it trusts a principal whose kind is not read."},
		}},
		{"43-spacelift-account", "Anyone on Spacelift could assume this role.", []row{
			{"platform", "Anyone on Spacelift", "unknown", "Anyone on Spacelift could assume this role; who can join its tenant is not established."},
		}},
		// the platform is where the tenants hold their accounts, as the
		// census names it, not the product that mints the tokens
		{"44-bitbucket-workspace", "Anyone on Bitbucket could assume this role.", []row{
			{"platform", "Anyone on Bitbucket", "unknown", "Anyone on Bitbucket could assume this role; who can join its tenant is not established."},
		}},
		{"46-look-alike-hosts", "Anyone could assume this role.", []row{
			{"anyone", "Anyone", "unknown", "Anyone could assume this role: it trusts a principal whose kind is not read."},
			{"yours", "Your pipelines", "exact", "No grant is confined to owners declared as yours."},
		}},
		// a pattern that may confine a repository's tokens to its owner is
		// not read as confining them to nobody
		{"62-repository-pattern-closing-the-owner", "Anyone on GitHub could assume this role.", []row{
			{"platform", "Anyone on GitHub", "unknown", "Anyone on GitHub could assume this role; one of its conditions was not read."},
		}},
		// a key AWS documents as multivalued, named twice under operators
		// without a set prefix with no one value meeting both, is not read
		// as admitting nobody
		{"63-amr-named-twice-cognito", "Anyone could assume this role.", []row{
			{"anyone", "Anyone", "unknown", "Anyone could assume this role: cognito-identity.amazonaws.com gives tokens to guests and to whoever signs in."},
		}},
		{"64-amr-named-twice-entra", "Anyone on login.microsoftonline.com could assume this role.", []row{
			{"platform", "Anyone on login.microsoftonline.com", "unknown", "Anyone on login.microsoftonline.com could assume this role; who can join its tenant is not established."},
		}},
		// a key read from a claim the issuer's tokens may carry with several
		// values, named twice with no one value meeting both, is not read as
		// admitting nobody
		{"65-aud-named-twice-eks", "A named outsider can assume this role.", []row{
			{"outsider", "A named outsider", "exact", "issuer:https://oidc.eks.us-east-1.amazonaws.com/id/EXAMPLED539D4633E53DE1B71EXAMPLE can assume this role and is not declared as yours."},
			{"anyone", "Anyone", "exact", "No grant is placed with people who have no account anywhere."},
		}},
		{"49-assume-actions-beyond-ascii", "Anyone could assume this role; so can SAML and cloud services.", []row{
			{"anyone", "Anyone", "unknown", "Anyone could assume this role: some credentials it trusts may need no account."},
		}},
		// a service the table lists is a door: whom it acts for is named,
		// who they are is not read, and the ring of anyone is unknown
		// beside it, whatever its conditions name
		{"66-roles-anywhere-documented-policy", "rolesanywhere.amazonaws.com can assume this role.", []row{
			{"service", "Cloud services", "unknown", "rolesanywhere.amazonaws.com can assume this role for workloads holding a certificate; who they are is not read."},
			{"anyone", "Anyone", "unknown", "No grant is placed with people who have no account anywhere."},
		}},
		{"67-iot-credentials-provider", "credentials.iot.amazonaws.com can assume this role.", []row{
			{"service", "Cloud services", "unknown", "credentials.iot.amazonaws.com can assume this role for devices holding a certificate; who they are is not read."},
			{"anyone", "Anyone", "unknown", "No grant is placed with people who have no account anywhere."},
		}},
		{"68-ssm-hybrid-activation-role", "ssm.amazonaws.com can assume this role.", []row{
			{"service", "Cloud services", "unknown", "ssm.amazonaws.com can assume this role; who can make it act is not read."},
			{"anyone", "Anyone", "unknown", "No grant is placed with people who have no account anywhere."},
		}},
		{"69-any-service-face-with-source-account", "Anyone on AWS could assume this role; so can cloud services.", []row{
			{"platform", "Anyone on AWS", "unknown", "Anyone on AWS could assume this role; one of its conditions was not read."},
			{"service", "Cloud services", "unknown", "Any cloud service can assume this role; which ones, and for whom, is not read."},
			{"anyone", "Anyone", "unknown", "No grant is placed with people who have no account anywhere."},
		}},
		{"70-eks-pod-identity-documented-policy", "pods.eks.amazonaws.com can assume this role.", []row{
			{"service", "Cloud services", "unknown", "pods.eks.amazonaws.com can assume this role for pods of EKS clusters; who they are is not read."},
			{"anyone", "Anyone", "unknown", "No grant is placed with people who have no account anywhere."},
		}},
		{"71-transfer-family-user-role", "transfer.amazonaws.com can assume this role.", []row{
			{"service", "Cloud services", "unknown", "transfer.amazonaws.com can assume this role; who can make it act is not read."},
			{"anyone", "Anyone", "unknown", "No grant is placed with people who have no account anywhere."},
		}},
		{"72-ec2-and-ssm-in-one-statement", "2 cloud services can assume this role.", []row{
			{"service", "Cloud services", "unknown", "2 cloud services can assume this role; who can make them act is not read."},
			{"anyone", "Anyone", "unknown", "No grant is placed with people who have no account anywhere."},
		}},
		{"73-five-services-acting-for-identities-outside-iam", "5 cloud services can assume this role.", []row{
			{"service", "Cloud services", "unknown", "5 cloud services can assume this role; who can make them act is not read."},
			{"anyone", "Anyone", "unknown", "No grant is placed with people who have no account anywhere."},
		}},
		// a service whose row records other uses names none of them on the
		// line, which says who can make it act is not read
		{"74-ssm-maintenance-window-service-role", "ssm.amazonaws.com can assume this role.", []row{
			{"service", "Cloud services", "unknown", "ssm.amazonaws.com can assume this role; who can make it act is not read."},
			{"anyone", "Anyone", "unknown", "No grant is placed with people who have no account anywhere."},
		}},
		{"75-ssm-automation-service-role", "ssm.amazonaws.com can assume this role.", []row{
			{"service", "Cloud services", "unknown", "ssm.amazonaws.com can assume this role; who can make it act is not read."},
			{"anyone", "Anyone", "unknown", "No grant is placed with people who have no account anywhere."},
		}},
	}
	for _, c := range cases {
		doc, owners := ringsCase(t, c.name)
		a := ringsOf(t, AdmitsFor(doc, owners))
		if a.Headline == nil || a.Headline.Sentence != c.headline {
			t.Errorf("%s: headline %+v, want %q", c.name, a.Headline, c.headline)
		}
		for _, want := range c.rows {
			i := slices.IndexFunc(append(append([]Row{}, a.Rings...), a.Beside...), func(r Row) bool { return r.Place == want.place })
			if i < 0 {
				t.Errorf("%s: no row %s", c.name, want.place)
				continue
			}
			got := append(append([]Row{}, a.Rings...), a.Beside...)[i]
			if got.Label != want.label || got.State != want.state || got.Sentence != want.sentence {
				t.Errorf("%s, %s:\n got  %q %s %q\n want %q %s %q", c.name, want.place, got.Label, got.State, got.Sentence, want.label, want.state, want.sentence)
			}
		}
	}
	// a ring reached with a SAML line alone beside it, and a statement whose
	// effect could not be read, which may be a Deny: its ring is not
	// established, so the outsider could, not can, assume the role
	beside := ringsOf(t, Admits([]byte(`{"Version":"2012-10-17","Statement":[
{"Effect":"Allow","Principal":{"Federated":"token.actions.githubusercontent.com"},"Action":"sts:AssumeRoleWithWebIdentity","Condition":{"StringEquals":{"token.actions.githubusercontent.com:sub":"repo:acme/infra:ref:refs/heads/main"}}},
{"Effect":"Allow","Principal":{"Federated":"arn:aws:iam::123456789012:saml-provider/VendorSSO"},"Action":"sts:AssumeRoleWithSAML"}]}`)))
	if beside.Headline.Sentence != "A named outsider can assume this role; so can SAML sign-ins." {
		t.Errorf("a ring and a SAML line: %q", beside.Headline.Sentence)
	}
	unread := ringsOf(t, Admits([]byte(`{"Version":"2012-10-17","Statement":[{"Effect":"Maybe","Principal":{"Federated":"token.actions.githubusercontent.com"},"Action":"sts:AssumeRoleWithWebIdentity","Condition":{"StringEquals":{"token.actions.githubusercontent.com:sub":"repo:acme/infra:ref:refs/heads/main"}}}]}`)))
	if unread.Headline.Sentence != "A named outsider could assume this role." || unread.Rings[2].State != "unknown" || unread.Rings[2].Sentence != "github:acme could assume this role and is not declared as yours." {
		t.Errorf("an effect not read: %q, %+v", unread.Headline.Sentence, unread.Rings[2])
	}
	doc, _ := ringsCase(t, "27-deny-for-anyone")
	if a := ringsOf(t, Admits(doc)); a.Refused == nil || a.Refused.Sentence != "Grants 1 and 2 refuse, so they are in no ring; the rings do not subtract them." {
		t.Errorf("27: refused %+v", a.Refused)
	}
	doc, _ = ringsCase(t, "28-no-assume-action")
	if a := ringsOf(t, Admits(doc)); a.Nobody == nil || a.Nobody.Sentence != "Grant 1 admits nobody, so it is in no ring." {
		t.Errorf("28: nobody %+v", a.Nobody)
	}
	doc, _ = ringsCase(t, "11-cognito-guests")
	a := ringsOf(t, Admits(doc))
	// who gets an identity pool's tokens is set in each pool, the audience
	// its tokens carry, and never in the issuer they share
	if len(a.Bounds.Items) != 4 || a.Bounds.Items[3].Bound != "audience-settings" || a.Bounds.Items[3].Issuer != "https://cognito-identity.amazonaws.com" ||
		a.Bounds.Items[3].Sentence != "The settings of each audience this role accepts from cognito-identity.amazonaws.com, such as whether it admits guests, can narrow who assumes this role, and were not read." ||
		!strings.HasSuffix(a.Bounds.Sentence, "this account's identity providers and the settings of each audience this role accepts from cognito-identity.amazonaws.com.") {
		t.Errorf("11: bounds %+v", a.Bounds)
	}
}

// policyOf is a trust policy of the statements given, each a JSON object.
func policyOf(statements ...string) []byte {
	return []byte(`{"Version":"2012-10-17","Statement":[` + strings.Join(statements, ",") + `]}`)
}

// onGitHub is a statement trusting GitHub's issuer under the effect given,
// with the conditions given beside the audience.
func onGitHub(sid, effect, conditions string) string {
	return `{"Sid":"` + sid + `","Effect":"` + effect + `","Principal":{"Federated":"arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"},"Action":"sts:AssumeRoleWithWebIdentity","Condition":{"StringEquals":{"token.actions.githubusercontent.com:aud":"sts.amazonaws.com"}` + conditions + `}}`
}

// TestEachPopulationHasItsOwnVerb: a row that one grant reaches for certain
// does not lend its "can" to a population another grant placed as unknown.
// What is certain can assume the role and what is not could, each named;
// the ring's state is exact, since it is reached for certain; and the
// headline counts what the label counts, from what is certain to all of it.
func TestEachPopulationHasItsOwnVerb(t *testing.T) {
	google := `{"Sid":"Google","Effect":"Allow","Principal":{"Federated":"accounts.google.com"},"Action":"sts:AssumeRoleWithWebIdentity","Condition":{"StringEquals":{"accounts.google.com:aud":"1234.apps.googleusercontent.com","accounts.google.com:sub":"110169484474386276334"}}}`
	awsAnyone := `{"Sid":"AnyAccount","Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}`
	anyOwner := onGitHub("AnyOwner", "Allow", `,"StringLike":{"token.actions.githubusercontent.com:sub":"repo:acme*"}`)
	acme := onGitHub("Acme", "Allow", `,"StringLike":{"token.actions.githubusercontent.com:sub":"repo:acme/*"}`)
	betaMaybe := onGitHub("BetaMaybe", "Permit", `,"StringLike":{"token.actions.githubusercontent.com:sub":"repo:beta/*"}`)
	subjectUnread := onGitHub("SubjectUnread", "Allow", `,"ForAllValues:StringLike":{"token.actions.githubusercontent.com:sub":"repo:acme/*"}`)
	cases := []struct {
		name, owners, headline string
		doc                    []byte
		place, label, sentence string
	}{
		{"a platform for certain beside one unknown", "", "Anyone on 1-2 platforms can assume this role.", policyOf(anyOwner, google),
			"platform", "Anyone on 2 platforms", "Anyone on GitHub can assume this role; anyone on Google could."},
		// the reason no owner confines the first grant is not the second's,
		// whose condition was not read, so the row gives no reason
		{"one platform for certain and unknown, for two reasons", "", "Anyone on GitHub can assume this role.", policyOf(anyOwner, subjectUnread),
			"platform", "Anyone on GitHub", "Anyone on GitHub can assume this role."},
		{"two platforms for certain beside one unknown", "", "Anyone on 2-3 platforms can assume this role; so can cloud services.", policyOf(anyOwner, google, awsAnyone),
			"platform", "Anyone on 3 platforms", "Anyone on AWS or GitHub can assume this role; anyone on Google could."},
		{"an owner for certain beside one whose effect was not read", "", "A named outsider can assume this role.", policyOf(acme, betaMaybe),
			"outsider", "A named outsider", "github:acme can assume this role, and github:beta could; neither is declared as yours."},
		{"the same owners declared", "github:acme\ngithub:beta", "Nothing outside your company can assume this role.", policyOf(acme, betaMaybe),
			"yours", "Your pipelines", "github:acme, declared as yours, can assume this role, and github:beta could."},
	}
	for _, c := range cases {
		a := ringsOf(t, AdmitsFor(c.doc, []byte(c.owners)))
		if a.Headline == nil || a.Headline.Sentence != c.headline {
			t.Errorf("%s: headline %+v, want %q", c.name, a.Headline, c.headline)
		}
		i := slices.Index(ringOrder, c.place)
		if got := a.Rings[i]; got.Label != c.label || got.State != "exact" || got.Sentence != c.sentence {
			t.Errorf("%s:\n got  %q %s %q\n want %q exact %q", c.name, got.Label, got.State, got.Sentence, c.label, c.sentence)
		}
	}
}

// TestOwnersThatCannotBeDeclaredSaySo: a named outsider the declaration
// grammar has no form for, a repository or an enterprise, says so rather
// than reading as one the reader has only to declare, and a sentence
// starting with one starts with a capital; an owner declared as yours that
// a grant also admits beside an outsider is named with it, and the sentence
// of the empty ring of the reader's own is true beside it.
func TestOwnersThatCannotBeDeclaredSaySo(t *testing.T) {
	cases := []struct {
		name, owners string
		doc          []byte
		want         map[string]string
	}{
		{"a repository by name", "github:acme", policyOf(onGitHub("Repository", "Allow", `,"StringLike":{"token.actions.githubusercontent.com:repository":"acme/infra"}`)),
			map[string]string{"outsider": "Repository acme/infra can assume this role and cannot be declared."}},
		{"an enterprise", "", policyOf(onGitHub("Enterprise", "Allow", `,"StringLike":{"token.actions.githubusercontent.com:enterprise_id":"4200000"}`)),
			map[string]string{"outsider": "Enterprise 4200000 can assume this role and cannot be declared."}},
		{"an owner and a repository of it", "", policyOf(onGitHub("OwnerAndRepository", "Allow", `,"StringLike":{"token.actions.githubusercontent.com:sub":"repo:acme/infra:*","token.actions.githubusercontent.com:repository_id":"456789"}`)),
			map[string]string{"outsider": "github:acme and repository 456789 can assume this role; the repository cannot be declared."}},
		{"a declared owner beside an outsider in one pin", "github:acme", policyOf(onGitHub("AcmeOrVendor", "Allow", `,"StringLike":{"token.actions.githubusercontent.com:sub":["repo:acme/*","repo:vendor/*"]}`)),
			map[string]string{
				"outsider": "github:acme and github:vendor can assume this role; github:vendor is not declared as yours.",
				"yours":    "No grant is confined to owners declared as yours.",
			}},
	}
	for _, c := range cases {
		a := ringsOf(t, AdmitsFor(c.doc, []byte(c.owners)))
		for place, want := range c.want {
			if got := a.Rings[slices.Index(ringOrder, place)].Sentence; got != want {
				t.Errorf("%s, %s:\n got  %q\n want %q", c.name, place, got, want)
			}
		}
	}
}

// TestNoRowCountsOrNumbersGrants: a grant is the engine's unit, and a reader
// of the rings needs none, so no row or line sentence counts grants
// or names one by number, over every answer the corpus and the rings cases
// give.
func TestNoRowCountsOrNumbersGrants(t *testing.T) {
	docs := corpus(t)
	for _, name := range ringsCases(t) {
		docs[name], _ = ringsCase(t, name)
	}
	counted := regexp.MustCompile(`\bgrants? \d|\d+ grants\b`)
	rows := 0
	for name, doc := range docs {
		a := ringsOf(t, Admits(doc))
		for _, r := range append(append([]Row{}, a.Rings...), a.Beside...) {
			rows++
			if counted.MatchString(r.Sentence) {
				t.Errorf("%s, %s: %q", name, r.Place, r.Sentence)
			}
		}
	}
	if rows < 400 {
		t.Fatalf("%d rows read; the corpus did not load", rows)
	}
}

// asked is a row's questions as a consumer reads them: the declaration each
// would add, and its sentence.
func asked(t *testing.T, answer []byte, place string) [][2]string {
	t.Helper()
	var a struct {
		Rings, Beside []struct {
			Place     string `json:"place"`
			Questions []struct {
				Declaration string `json:"declaration"`
				Sentence    string `json:"sentence"`
				Spans       []Span `json:"spans"`
			} `json:"questions"`
		}
	}
	if err := json.Unmarshal(answer, &a); err != nil {
		t.Fatal(err)
	}
	var out [][2]string
	for _, r := range append(a.Rings, a.Beside...) {
		if r.Place != place {
			continue
		}
		for _, q := range r.Questions {
			if plain(q.Spans) != q.Sentence {
				t.Errorf("the question %q is not its spans %+v", q.Sentence, q.Spans)
			}
			out = append(out, [2]string{q.Declaration, q.Sentence})
		}
	}
	return out
}

// TestTheQuestionIsTheEngines: the one question the answer asks, is this
// owner yours, names an owner the engine computed, so the engine composes
// it, in words.go, with the declaration that answering it adds. It is asked of every owner a named outsider's row names that the
// declaration grammar has a form for and nobody has, and of every SAML
// provider on its line; never of a repository, an enterprise or an owner
// declared.
func TestTheQuestionIsTheEngines(t *testing.T) {
	doc01, _ := ringsCase(t, "01-branch-pin-and-owner-prefix")
	doc20, _ := ringsCase(t, "20-saml-provider-of-a-vendor")
	doc38, _ := ringsCase(t, "38-repository-id-subject")
	doc41, _ := ringsCase(t, "41-union-of-owners")
	union := policyOf(onGitHub("AcmeOrVendor", "Allow", `,"StringLike":{"token.actions.githubusercontent.com:sub":["repo:acme/*","repo:vendor/*"]}`))
	cases := []struct {
		name   string
		answer []byte
		place  string
		want   [][2]string
	}{
		{"the default document", Admits(doc01), "outsider", [][2]string{{"github:acme", "Is github:acme yours?"}}},
		{"the default document, acme declared", AdmitsFor(doc01, []byte("github:acme")), "outsider", nil},
		{"a vendor's SAML provider", Admits(doc20), "saml", [][2]string{{"saml:arn:aws:iam::123456789012:saml-provider/VendorSSO", "Is VendorSSO yours?"}}},
		{"a repository", Admits(doc38), "outsider", nil},
		{"three owners", Admits(doc41), "outsider", [][2]string{{"github:acme", "Is github:acme yours?"}, {"github:beta", "Is github:beta yours?"}, {"github:gamma", "Is github:gamma yours?"}}},
		{"a declared owner beside an outsider", AdmitsFor(union, []byte("github:acme")), "outsider", [][2]string{{"github:vendor", "Is github:vendor yours?"}}},
	}
	for _, c := range cases {
		if got := asked(t, c.answer, c.place); !slices.Equal(got, c.want) {
			t.Errorf("%s: asked %q, want %q", c.name, got, c.want)
		}
	}
}

// TestTheReadingOfAWSIsCited: the face of "*" is placed at Anyone on the
// engine's reading of two AWS sentences, and the answer carries both,
// quoted as AWS wrote them, beside the row whose sentence says it is a
// reading, so that --explain can cite them without composing a word; a row
// that rests on no such reading cites nothing. A line of cloud services
// holding a service the parser's table of intermediaries lists carries that
// service's sentences, which its words rest on.
// The words over the quotes are the answer's too, and say that the reading
// is the engine's: every renderer prints the same heading, and none writes
// one of its own.
func TestTheReadingOfAWSIsCited(t *testing.T) {
	headings := map[string]string{
		"anyone":  "Anyone rests on the engine's reading of what AWS writes:",
		"service": "Cloud services rests on the engine's reading of what AWS writes:",
	}
	cited := func(answer []byte) []string {
		var a struct {
			Rings  []Row `json:"rings"`
			Beside []Row `json:"beside"`
		}
		if err := json.Unmarshal(answer, &a); err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, r := range append(a.Rings, a.Beside...) {
			if len(r.Citations) == 0 {
				if r.CitationsHeading != "" {
					t.Errorf("a row that cites nothing is headed %q", r.CitationsHeading)
				}
				continue
			}
			if r.CitationsHeading != headings[r.Place] || r.Place == "anyone" && !strings.Contains(r.Sentence, "the engine's reading of AWS's documentation") {
				t.Errorf("the %s row's citations are headed %q under the sentence %q; the heading must say the reading is the engine's, and so must the ring of anyone's sentence", r.Place, r.CitationsHeading, r.Sentence)
			}
			for _, c := range r.Citations {
				out = append(out, c.Quote+" · "+c.Source)
			}
		}
		return out
	}
	sentencesOf := func(services ...string) []string {
		var out []string
		for _, service := range services {
			row, ok := aws.IntermediaryOf(service)
			if !ok {
				t.Fatalf("%s is not in the table", service)
			}
			for _, c := range row.Citations() {
				out = append(out, c.Quote+" · "+c.Source)
			}
		}
		return out
	}
	const principal = "https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html"
	faceOfAnyone := []string{
		"You can use a wildcard (*) to specify all principals in the Principal element of a resource-based policy or in condition keys that support principals. · " + principal,
		"An OIDC federated principal can represent an OIDC IDP in your AWS account, or the 4 built in identity providers: Login with Amazon, Google, Facebook, and Amazon Cognito. · " + principal,
	}
	for name, want := range map[string][]string{
		"07-anyone-on-web-identity":           faceOfAnyone,
		"09-anyone-on-every-sts-action":       faceOfAnyone,
		"66-roles-anywhere-documented-policy": sentencesOf("rolesanywhere.amazonaws.com"),
		"72-ec2-and-ssm-in-one-statement":     sentencesOf("ssm.amazonaws.com"),
		// in the order of the line's grants, which is the engine's
		"73-five-services-acting-for-identities-outside-iam": sentencesOf("credentials.iot.amazonaws.com", "pods.eks.amazonaws.com", "rolesanywhere.amazonaws.com", "ssm.amazonaws.com", "transfer.amazonaws.com"),
	} {
		doc, _ := ringsCase(t, name)
		if got := cited(Admits(doc)); !slices.Equal(got, want) {
			t.Errorf("%s cites %q, want %q", name, got, want)
		}
	}
	for _, name := range []string{"11-cognito-guests", "01-branch-pin-and-owner-prefix", "10-anyone-on-assume-role", "21-service-without-source-account"} {
		doc, _ := ringsCase(t, name)
		if got := cited(Admits(doc)); got != nil {
			t.Errorf("%s rests on no reading of AWS's and cites %q", name, got)
		}
	}
}

// TestAServiceOfSeveralUsesKeepsWhoCanMakeItAct: AWS documents Systems
// Manager and Transfer Family assuming roles for more than the one use the
// table names. A maintenance window's tasks and Automation's runbooks run
// with a role Systems Manager assumes, for whoever names it; Transfer Family
// assumes invocation, logging and execution roles for its servers and
// workflows. On AWS's own trust policies for those roles, and for the uses
// the table names, the line says who can make the service act is not read
// and names no one use, and every note says the use it names is one among
// others and that who can make the service act is not read.
func TestAServiceOfSeveralUsesKeepsWhoCanMakeItAct(t *testing.T) {
	const neutral = " can assume this role; who can make it act is not read."
	for _, c := range []struct{ name, service string }{
		{"68-ssm-hybrid-activation-role", "ssm.amazonaws.com"},
		{"74-ssm-maintenance-window-service-role", "ssm.amazonaws.com"},
		{"75-ssm-automation-service-role", "ssm.amazonaws.com"},
		{"71-transfer-family-user-role", "transfer.amazonaws.com"},
	} {
		doc, _ := ringsCase(t, c.name)
		answer := Admits(doc)
		a := ringsOf(t, answer)
		i := slices.IndexFunc(a.Beside, func(r Row) bool { return r.Place == "service" })
		if i < 0 || a.Beside[i].Sentence != c.service+neutral || a.Beside[i].State != "unknown" {
			t.Errorf("%s: the line of cloud services is %+v, want unknown %q", c.name, a.Beside, c.service+neutral)
		}
		var grants struct {
			Grants []Grant `json:"grants"`
		}
		if err := json.Unmarshal(answer, &grants); err != nil {
			t.Fatal(err)
		}
		notes := 0
		for _, g := range grants.Grants {
			for _, n := range g.Notes {
				if n.Anomaly != "service-principal" {
					continue
				}
				notes++
				if !strings.HasPrefix(n.Message, c.service+" can assume a role for ") || !strings.HasSuffix(n.Message, ", among other uses; who can make it act, or receives its session, is not read") {
					t.Errorf("%s: the note says %q", c.name, n.Message)
				}
			}
		}
		if notes == 0 {
			t.Errorf("%s: no grant carries a note on %s", c.name, c.service)
		}
	}
}

// TestTheLineOfCloudServicesSaysForWhom: a line holding one service the
// parser's table of intermediaries lists, whose row records no other use,
// says for whom, and that who they are is not read, and cites the sentences
// of AWS's it rests on under the heading the rings' readings take; a line
// holding one whose row records other uses, several services, or the face
// of "*", keeps words true of every service and cites the sentences of each
// listed service on it, in the order the line names them, its other uses'
// last. A line of services the table does not list cites nothing.
func TestTheLineOfCloudServicesSaysForWhom(t *testing.T) {
	service := func(sid, name string) string {
		return `{"Sid":"` + sid + `","Effect":"Allow","Principal":{"Service":` + name + `},"Action":"sts:AssumeRole"}`
	}
	sentencesOf := func(names ...string) []Citation {
		var out []Citation
		for _, name := range names {
			row, ok := aws.IntermediaryOf(name)
			if !ok {
				t.Fatalf("%s is not in the table", name)
			}
			for _, c := range row.Citations() {
				out = append(out, Citation{Quote: c.Quote, Source: c.Source})
			}
		}
		return out
	}
	const heading = "Cloud services rests on the engine's reading of what AWS writes:"
	cases := []struct {
		name     string
		doc      []byte
		sentence string
		cited    []Citation
	}{
		{"IAM Roles Anywhere", policyOf(service("A", `"rolesanywhere.amazonaws.com"`)), "rolesanywhere.amazonaws.com can assume this role for workloads holding a certificate; who they are is not read.", sentencesOf("rolesanywhere.amazonaws.com")},
		{"the IoT credentials provider", policyOf(service("A", `"credentials.iot.amazonaws.com"`)), "credentials.iot.amazonaws.com can assume this role for devices holding a certificate; who they are is not read.", sentencesOf("credentials.iot.amazonaws.com")},
		{"Systems Manager", policyOf(service("A", `"ssm.amazonaws.com"`)), "ssm.amazonaws.com can assume this role; who can make it act is not read.", sentencesOf("ssm.amazonaws.com")},
		{"EKS Pod Identity", policyOf(service("A", `"pods.eks.amazonaws.com"`)), "pods.eks.amazonaws.com can assume this role for pods of EKS clusters; who they are is not read.", sentencesOf("pods.eks.amazonaws.com")},
		{"Transfer Family", policyOf(service("A", `"transfer.amazonaws.com"`)), "transfer.amazonaws.com can assume this role; who can make it act is not read.", sentencesOf("transfer.amazonaws.com")},
		{"written in another case", policyOf(service("A", `"RolesAnywhere.amazonaws.com"`)), "rolesanywhere.amazonaws.com can assume this role for workloads holding a certificate; who they are is not read.", sentencesOf("rolesanywhere.amazonaws.com")},
		{"one service twice", policyOf(service("A", `"pods.eks.amazonaws.com"`), service("B", `"Pods.EKS.amazonaws.com"`)), "pods.eks.amazonaws.com can assume this role for pods of EKS clusters; who they are is not read.", sentencesOf("pods.eks.amazonaws.com")},
		{"another service beside one", policyOf(service("A", `["ec2.amazonaws.com", "ssm.amazonaws.com"]`)), "2 cloud services can assume this role; who can make them act is not read.", sentencesOf("ssm.amazonaws.com")},
		// the engine orders grants by what they mean, and the line cites
		// its services in the order of its grants
		{"two beside each other", policyOf(service("A", `"transfer.amazonaws.com"`), service("B", `"rolesanywhere.amazonaws.com"`)), "2 cloud services can assume this role; who can make them act is not read.", sentencesOf("rolesanywhere.amazonaws.com", "transfer.amazonaws.com")},
		{"the face of * beside one", policyOf(`{"Sid":"A","Effect":"Allow","Principal":"*","Action":"sts:AssumeRole"}`, service("B", `"pods.eks.amazonaws.com"`)), "Any cloud service can assume this role; which ones, and for whom, is not read.", sentencesOf("pods.eks.amazonaws.com")},
		{"a service the table does not list", policyOf(service("A", `"sns.amazonaws.com"`)), "sns.amazonaws.com can assume this role; who can make it act is not read.", nil},
	}
	for _, c := range cases {
		a := ringsOf(t, Admits(c.doc))
		i := slices.IndexFunc(a.Beside, func(r Row) bool { return r.Place == "service" })
		if i < 0 {
			t.Errorf("%s: no line of cloud services", c.name)
			continue
		}
		line := a.Beside[i]
		if line.Sentence != c.sentence || line.State != "unknown" {
			t.Errorf("%s: the line is %s %q, want unknown %q", c.name, line.State, line.Sentence, c.sentence)
		}
		wantHeading := heading
		if c.cited == nil {
			wantHeading = ""
		}
		if line.CitationsHeading != wantHeading || !slices.Equal(line.Citations, c.cited) {
			t.Errorf("%s: the line cites under %q\n%q\nwant under %q\n%q", c.name, line.CitationsHeading, line.Citations, wantHeading, c.cited)
		}
		if a.Rings[0].State != "unknown" {
			t.Errorf("%s: beside a line of cloud services the ring of anyone is %s", c.name, a.Rings[0].State)
		}
	}
}

// TestTheOwnersAreEchoed: the declaration is echoed normalised, sorted and
// deduplicated; every line refused as written, with the reason's id and its
// words; and every owner declared that no grant which admits is pinned to,
// with why, so that a declaration that moved nothing says so. Past a bound
// the whole declaration is refused as the answer's error, in words about
// owners declared, which is what the reader wrote, and the rendering says nothing of the document's dialect,
// which was not the fault.
func TestTheOwnersAreEchoed(t *testing.T) {
	ownersJSON := func(answer []byte) string {
		var a struct {
			Declarations json.RawMessage `json:"declarations"`
		}
		if err := json.Unmarshal(answer, &a); err != nil {
			t.Fatal(err)
		}
		return string(a.Declarations)
	}
	const nothing = "no grant that admits is pinned to it, so declaring it moves nothing"
	for _, c := range []struct {
		name, owners, want string
	}{
		{"01-branch-pin-and-owner-prefix", "GITHUB:acme\n\ngitlab:acme\naws:111122223333\ngithub:acme\nacme",
			`{"normalised":["aws:111122223333","github:acme"],"refusedLines":[` +
				`{"line":3,"text":"gitlab:acme","reason":"claims-not-read","sentence":"owners on GitLab, HCP Terraform and Buildkite cannot be declared: their claims are not read"},` +
				`{"line":6,"text":"acme","reason":"no-namespace","sentence":"no namespace: declare an owner as github:acme, aws:111122223333, saml:\u003cprovider ARN\u003e or issuer:\u003cissuer URL\u003e"}],` +
				`"unmatched":[{"declaration":"aws:111122223333","sentence":"` + nothing + `"}]}`},
		{"33-declared-in-another-case", "github:Acme",
			`{"normalised":["github:Acme"],"refusedLines":[],"unmatched":[{"declaration":"github:Acme","sentence":"no grant that admits is pinned to it; names compare exactly, and one is pinned to github:acme"}]}`},
		{"38-repository-id-subject", "github:@456789\ngithub:acme/infra",
			`{"normalised":["github:@456789"],"refusedLines":[{"line":2,"text":"github:acme/infra","reason":"a-repository","sentence":"a repository cannot be declared; declaring its owner, as github:acme, moves the grants pinned to that owner, and none pinned to a repository"}],` +
				`"unmatched":[{"declaration":"github:@456789","sentence":"` + nothing + `"}]}`},
		{"32-default-with-acme-declared", "github:acme", `{"normalised":["github:acme"],"refusedLines":[],"unmatched":[]}`},
	} {
		doc, _ := ringsCase(t, c.name)
		owners := c.owners
		if got := ownersJSON(AdmitsFor(doc, []byte(owners))); got != c.want {
			t.Errorf("%s declaring %q, the echo\n got  %s\n want %s", c.name, owners, got, c.want)
		}
		token := []byte(`{"iss":"https://token.actions.githubusercontent.com","sub":"x"}`)
		if got := ownersJSON(ExplainFor(doc, token, []byte(owners))); got != c.want {
			t.Errorf("%s declaring %q against a token, the echo\n got  %s\n want %s", c.name, owners, got, c.want)
		}
	}
	// the text prints each owner declared that moved nothing, with why
	doc, _ := ringsCase(t, "33-declared-in-another-case")
	if text := AnswerFor(doc, []byte("github:Acme")).Text(Options{}); !strings.Contains(text, "\nowner unmatched  github:Acme · no grant that admits is pinned to it; names compare exactly, and one is pinned to github:acme\n") {
		t.Errorf("the text does not say github:Acme moved nothing:\n%s", text)
	}
	doc, _ = ringsCase(t, "01-branch-pin-and-owner-prefix")
	line := func(n int) string { return "github:" + strings.Repeat("a", n-len("github:")) }
	// The bounds count lines, blank ones included, and the words count
	// what the bounds count: a blank line declares no owner, so a sentence
	// counting owners would count owners nobody declared.
	for declared, want := range map[string]string{
		strings.Repeat("github:o\n", 65):                           "the owners declared come to 65 lines; the engine reads up to 64",
		strings.Repeat("\n", 65):                                   "the owners declared come to 65 lines; the engine reads up to 64",
		strings.Repeat("\n", 5) + strings.Repeat("github:o\n", 60): "the owners declared come to 65 lines; the engine reads up to 64",
		"github:acme\n" + line(513):                                "line 2 of the owners declared is 513 bytes; the engine reads up to 512 bytes a line",
		"\n\n" + line(600):                                         "line 3 of the owners declared is 600 bytes; the engine reads up to 512 bytes a line",
		strings.Repeat(line(511)+"\n", 33):                         "the owners declared come to 16896 bytes; the engine reads up to 16384",
	} {
		over := AnswerFor(doc, []byte(declared))
		if over.Error != want || over.Document != nil || len(over.Grants) != 0 || over.Rings != nil {
			t.Errorf("%d bytes declared: %q, want %q", len(declared), over.Error, want)
		}
		if text := over.Text(Options{}); text != over.Error+"\n" {
			t.Errorf("%d bytes declared are rendered as %q", len(declared), text)
		}
		if x := ExplanationFor(doc, []byte(`{"sub":"x"}`), []byte(declared)); x.Error != over.Error || x.Text(Options{}) != over.Error+"\n" {
			t.Errorf("%d bytes declared against a token: %+v", len(declared), x)
		}
	}
}

// TestNoOwnersIsAdmits: with no owners, and with a declaration of nothing,
// the owner-taking entry points are the ones that take none, byte for byte,
// new fields included.
func TestNoOwnersIsAdmits(t *testing.T) {
	token := []byte(`{"iss":"https://token.actions.githubusercontent.com","aud":"sts.amazonaws.com","sub":"repo:acme/infra:ref:refs/heads/main"}`)
	compared := 0
	for path, raw := range corpus(t) {
		for _, none := range [][]byte{nil, {}, []byte("\n"), []byte("  \n\t\n")} {
			if !bytes.Equal(AdmitsFor(raw, none), Admits(raw)) || !bytes.Equal(ExplainFor(raw, token, none), Explain(raw, token)) {
				t.Errorf("%s: declaring %q is not declaring nothing", path, none)
			}
			compared++
		}
	}
	t.Logf("%d answers compared", compared)
}

// TestTheExplanationCarriesTheRings: explain takes owners, echoes them, and
// each outcome carries the ring of its grant, as the answer of admits
// places it.
func TestTheExplanationCarriesTheRings(t *testing.T) {
	doc, _ := ringsCase(t, "01-branch-pin-and-owner-prefix")
	token := []byte(`{"iss":"https://token.actions.githubusercontent.com","aud":"sts.amazonaws.com","sub":"repo:acme/infra:ref:refs/heads/main"}`)
	for _, owners := range []string{"", "github:acme\n"} {
		a := AnswerFor(doc, []byte(owners))
		x := ExplanationFor(doc, token, []byte(owners))
		if x.Declarations == nil || !slices.Equal(x.Declarations.Normalised, a.Declarations.Normalised) {
			t.Errorf("declaring %q: the explanation echoes %+v", owners, x.Declarations)
		}
		for i, o := range x.Grants {
			if !slices.Equal(o.Placement, a.Grants[i].Placement) || o.PlacementState != a.Grants[i].PlacementState {
				t.Errorf("declaring %q: outcome %d is placed %v %s, its grant %v %s", owners, i+1, o.Placement, o.PlacementState, a.Grants[i].Placement, a.Grants[i].PlacementState)
			}
		}
		if !strings.Contains(x.Text(Options{}), " · "+strings.Join(a.Grants[0].Placement, " + ")+" · "+a.Grants[0].PlacementState) {
			t.Errorf("declaring %q: the explanation's text does not say where grant 1 lands:\n%s", owners, x.Text(Options{}))
		}
	}
}

// TestTheExplanationPrintsItsBounds: a ring printed as exact is printed
// with the bounds that were not read, in the token view too. An explanation
// names each grant's ring and its state, so it carries the bounds that were
// not read beside them, the same bounds the answer of admits carries for
// the same document, in its JSON and in its text.
func TestTheExplanationPrintsItsBounds(t *testing.T) {
	token := []byte(`{"iss":"https://token.actions.githubusercontent.com","aud":"sts.amazonaws.com","sub":"repo:acme/infra:ref:refs/heads/main"}`)
	examined := 0
	for _, name := range []string{"01-branch-pin-and-owner-prefix", "11-cognito-guests", "10-anyone-on-assume-role"} {
		doc, owners := ringsCase(t, name)
		for _, declared := range [][]byte{nil, owners, []byte("github:acme\n")} {
			a := AnswerFor(doc, declared)
			x := ExplanationFor(doc, token, declared)
			var carried struct {
				Bounds *Bounds `json:"bounds"`
			}
			if err := json.Unmarshal(x.JSON(), &carried); err != nil {
				t.Fatal(err)
			}
			want, _ := json.Marshal(a.Bounds)
			got, _ := json.Marshal(carried.Bounds)
			if carried.Bounds == nil || !bytes.Equal(got, want) {
				t.Errorf("%s declaring %q: the explanation's bounds are %s, the answer's %s", name, declared, got, want)
			}
			text := x.Text(Options{})
			if !strings.Contains(text, a.Bounds.Sentence) {
				t.Errorf("%s declaring %q: the explanation's text names no bounds:\n%s", name, declared, text)
			}
			if i, j := strings.Index(text, a.Bounds.Sentence), strings.Index(text, "grant 1 of"); i > j {
				t.Errorf("%s declaring %q: the bounds come after the grants:\n%s", name, declared, text)
			}
			examined++
		}
	}
	// a token that cannot be read reads no grant, so no ring is printed and
	// no bounds with it
	doc, _ := ringsCase(t, "01-branch-pin-and-owner-prefix")
	if x := ExplanationFor(doc, []byte("not a token"), nil); strings.Contains(string(x.JSON()), `"bounds"`) || strings.Contains(x.Text(Options{}), "can narrow") {
		t.Errorf("an unread token carries bounds: %s", x.JSON())
	}
	t.Logf("%d explanations carry the answer's bounds", examined)
}

// TestTheTextPrintsTheRingsInOrder: the command prints how the bytes were
// read, then the headline, the rings, the lines beside them after a rule,
// the grants in no ring, the bounds line and the owners declared, and only
// then the grants.
func TestTheTextPrintsTheRingsInOrder(t *testing.T) {
	doc := []byte(`{"Version":"2012-10-17","Statement":[
{"Sid":"Pinned","Effect":"Allow","Principal":{"Federated":"token.actions.githubusercontent.com"},"Action":"sts:AssumeRoleWithWebIdentity","Condition":{"StringEquals":{"token.actions.githubusercontent.com:sub":"repo:acme/infra:ref:refs/heads/main"}}},
{"Sid":"Vendor","Effect":"Allow","Principal":{"Federated":"arn:aws:iam::123456789012:saml-provider/VendorSSO"},"Action":"sts:AssumeRoleWithSAML"},
{"Sid":"Service","Effect":"Allow","Principal":{"Service":"sns.amazonaws.com"},"Action":"sts:AssumeRole"},
{"Sid":"Refusal","Effect":"Deny","Principal":{"Federated":"token.actions.githubusercontent.com"},"Action":"sts:AssumeRoleWithWebIdentity"}]}`)
	a := AnswerFor(doc, []byte("github:beta\nnope\n"))
	text := a.Text(Options{})
	order := []string{
		"read as an aws trust policy",
		a.Headline.Sentence,
		a.Rings[0].Sentence, a.Rings[1].Sentence, a.Rings[2].Sentence, a.Rings[3].Sentence, a.Rings[4].Sentence,
		"  ──",
		a.Beside[0].Sentence, a.Beside[1].Sentence,
		a.Refused.Sentence,
		a.Bounds.Sentence,
		"owners declared  github:beta",
		"owner 2 refused  nope · " + a.Declarations.RefusedLines[0].Sentence,
		"grant 1 of 4",
	}
	at := 0
	for _, s := range order {
		i := strings.Index(text[at:], s)
		if i < 0 {
			t.Fatalf("%q is not printed after what precedes it:\n%s", s, text)
		}
		at += i + len(s)
	}
	if a.Headline.Sentence != "A named outsider can assume this role; so can SAML and cloud services." {
		t.Errorf("headline %q", a.Headline.Sentence)
	}
	// every row is one line, its sentence starting where every other row's
	// does, empty rows included, which list no grant
	column := -1
	for _, r := range append(append([]Row{}, a.Rings...), a.Beside...) {
		i := slices.IndexFunc(strings.Split(text, "\n"), func(line string) bool {
			return strings.HasPrefix(line, "  "+r.Label+" ") && strings.HasSuffix(line, r.Sentence)
		})
		if i < 0 {
			t.Fatalf("the row %s is not one line:\n%s", r.Place, text)
		}
		at := strings.Index(strings.Split(text, "\n")[i], r.Sentence)
		if column < 0 {
			column = at
		}
		if at != column {
			t.Errorf("the row %s starts its sentence at %d, the first row at %d:\n%s", r.Place, at, column, text)
		}
	}
}

// TestGrantNumbers: a row lists its grants in the text as numbers after
// grant or grants, and nothing for none.
func TestGrantNumbers(t *testing.T) {
	for want, numbers := range map[string][]int{"": nil, "grant 2": {2}, "grants 1, 3, 10": {1, 3, 10}} {
		if got := grantNumbers(numbers); got != want {
			t.Errorf("grantNumbers(%v) = %q, want %q", numbers, got, want)
		}
	}
}

// TestOneGrantOnBothLines: "*" on sts:AssumeRole and sts:AssumeRoleWithSAML
// is one grant with no issuer whose one term is two populations, every AWS
// service and every SAML provider in the account: it is on both lines, each
// saying only its own population, and the headline names both beside the
// AWS face's ring. A grant at a ring whose other term is pinned is worded
// by the terms at that ring alone. Two grants on one issuer that mints
// tokens to guests name its settings once.
func TestOneGrantOnBothLines(t *testing.T) {
	doc := []byte(`{"Version":"2012-10-17","Statement":[
{"Sid":"Everyone","Effect":"Allow","Principal":"*","Action":["sts:AssumeRole","sts:AssumeRoleWithSAML"]},
{"Sid":"OneOwnerOrAnyone","Effect":"Allow","Principal":{"Federated":"token.actions.githubusercontent.com"},"Action":"sts:AssumeRoleWithWebIdentity","Condition":{"StringLike":{"token.actions.githubusercontent.com:sub":["repo:acme/*","repo:ac*"]}}},
{"Sid":"Guests","Effect":"Allow","Principal":{"Federated":"cognito-identity.amazonaws.com"},"Action":"sts:AssumeRoleWithWebIdentity"},
{"Sid":"MoreGuests","Effect":"Allow","Principal":{"Federated":"cognito-identity.amazonaws.com"},"Action":"sts:AssumeRoleWithWebIdentity","Condition":{"StringEquals":{"cognito-identity.amazonaws.com:aud":"us-east-1:x"}}}]}`)
	a := ringsOf(t, Admits(doc))
	if len(a.Beside) != 2 || a.Beside[0].Sentence != "People any SAML provider in this account signs in can assume this role." || a.Beside[1].Sentence != "Any cloud service can assume this role; which ones, and for whom, is not read." || !slices.Equal(a.Beside[0].GrantNumbers, a.Beside[1].GrantNumbers) {
		t.Errorf("lines %+v", a.Beside)
	}
	if a.Headline.Sentence != "Anyone could assume this role; so can SAML and cloud services." {
		t.Errorf("headline %q", a.Headline.Sentence)
	}
	platform := a.Rings[1]
	if platform.Sentence != "Anyone on AWS or GitHub can assume this role." && platform.Sentence != "Anyone on GitHub or AWS can assume this role." {
		t.Errorf("platform %+v", platform)
	}
	settings := 0
	for _, b := range a.Bounds.Items {
		if b.Bound == "audience-settings" {
			settings++
		}
	}
	if settings != 1 {
		t.Errorf("%d settings bounds for one issuer: %+v", settings, a.Bounds.Items)
	}
	one := ringsOf(t, Admits([]byte(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Federated":"token.actions.githubusercontent.com"},"Action":"sts:AssumeRoleWithWebIdentity","Condition":{"StringLike":{"token.actions.githubusercontent.com:sub":["repo:acme/*","repo:ac*"]}}}]}`)))
	if one.Rings[1].Sentence != "Anyone on GitHub can assume this role; no condition confines its tokens to one owner." || len(one.Rings[2].GrantNumbers) != 0 {
		t.Errorf("a grant with a pinned term and an open one: %+v", one.Rings)
	}
}

// TestEveryOwnerIsNamedByTheEngine: every owner a population is pinned to
// carries the words that name it, so that a renderer drawing who a term admits
// never composes an owner's name: the declaration a user writes, for an
// owner that can be declared, and otherwise what it is and its value, as a
// sentence that starts with it names it. A repository known only by its id
// is the owner no other field names in words.
func TestEveryOwnerIsNamedByTheEngine(t *testing.T) {
	type owner struct {
		Declaration string `json:"declaration"`
		Scope       string `json:"scope"`
		Value       string `json:"value"`
		Label       string `json:"label"`
	}
	named, undeclarable := 0, 0
	for _, name := range ringsCases(t) {
		doc, owners := ringsCase(t, name)
		var answer struct {
			Rings  []Row `json:"rings"`
			Grants []struct {
				Populations []struct {
					Owners []owner `json:"owners"`
				} `json:"populations"`
			} `json:"grants"`
		}
		if err := json.Unmarshal(AdmitsFor(doc, owners), &answer); err != nil {
			t.Fatal(err)
		}
		for _, g := range answer.Grants {
			for _, p := range g.Populations {
				for _, o := range p.Owners {
					want := o.Declaration
					if want == "" {
						want = strings.ToUpper(o.Scope[:1]) + o.Scope[1:] + " " + o.Value
						undeclarable++
					}
					if o.Label != want {
						t.Errorf("%s: the owner %+v is labelled %q, want %q", name, o, o.Label, want)
					}
					named++
				}
			}
		}
		if name == "38-repository-id-subject" && !strings.HasPrefix(answer.Rings[2].Sentence, "Repository 456789 ") {
			t.Errorf("38: the outsider's sentence %q does not start with the label the owner carries", answer.Rings[2].Sentence)
		}
	}
	if named < 20 || undeclarable == 0 {
		t.Fatalf("%d owners named, %d of them undeclarable; the labels were held over too few", named, undeclarable)
	}
}

// TestAnOwnerIsRecyclableUnlessTheCensusSaysNot: whether a pinned value can
// pass to someone else is the census's, claim by claim, and a claim whose
// value no vendor sentence settles is recyclable whatever its kind. GitHub
// says a repository's name is released on a rename and its owner's and its
// own ids are immutable; of the enterprise's id it says only that a slug
// change leaves it alone, which is less.
func TestAnOwnerIsRecyclableUnlessTheCensusSaysNot(t *testing.T) {
	pin := func(sid, claim, value string) string {
		return `{"Sid":"` + sid + `","Effect":"Allow","Principal":{"Federated":"arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"},"Action":"sts:AssumeRoleWithWebIdentity","Condition":{"StringEquals":{"token.actions.githubusercontent.com:aud":"sts.amazonaws.com","token.actions.githubusercontent.com:` + claim + `":"` + value + `"}}}`
	}
	var answer struct {
		Grants []struct {
			Sid         string `json:"sid"`
			Populations []struct {
				Owners []struct {
					Scope      string `json:"scope"`
					Kind       string `json:"kind"`
					Value      string `json:"value"`
					Recyclable bool   `json:"recyclable"`
				} `json:"owners"`
			} `json:"populations"`
		} `json:"grants"`
	}
	doc := policyOf(pin("Repository", "repository", "acme/infra"), pin("OwnerID", "repository_owner_id", "123456"), pin("RepositoryID", "repository_id", "456789"), pin("EnterpriseID", "enterprise_id", "123"))
	if err := json.Unmarshal(Admits(doc), &answer); err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{"Repository": true, "OwnerID": false, "RepositoryID": false, "EnterpriseID": true}
	seen := 0
	for _, g := range answer.Grants {
		if len(g.Populations) != 1 || len(g.Populations[0].Owners) != 1 {
			t.Errorf("%s: populations %+v, want one owner", g.Sid, g.Populations)
			continue
		}
		if o := g.Populations[0].Owners[0]; o.Recyclable != want[g.Sid] {
			t.Errorf("%s: the %s %s %q is recyclable %v, want %v", g.Sid, o.Scope, o.Kind, o.Value, o.Recyclable, want[g.Sid])
		}
		seen++
	}
	if seen != len(want) {
		t.Fatalf("%d owners read of %d pins; the test held too few", seen, len(want))
	}
}

// TestAnsweringAQuestionDeclaresItsOwner: a question carries the
// declaration that answering yes writes, and that declaration, declared,
// names the owner the question asked about: it is not echoed as moving
// nothing, and the row no longer asks it. The declaration is the owner's
// own, as the document spells it; only the sentence is stripped of what a
// terminal acts on. A provider named with an escape inside it is the case
// where the two part.
func TestAnsweringAQuestionDeclaresItsOwner(t *testing.T) {
	type answer struct {
		Rings, Beside []struct {
			Place     string `json:"place"`
			Questions []struct {
				Declaration string `json:"declaration"`
			} `json:"questions"`
		}
		Declarations struct {
			Unmatched []struct {
				Declaration string `json:"declaration"`
			} `json:"unmatched"`
		} `json:"declarations"`
	}
	read := func(doc, owners []byte) answer {
		t.Helper()
		var a answer
		if err := json.Unmarshal(AdmitsFor(doc, owners), &a); err != nil {
			t.Fatal(err)
		}
		return a
	}
	docs := map[string][2][]byte{
		"a provider named with an escape": {[]byte("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Sid\":\"S\",\"Effect\":\"Allow\",\"Principal\":{\"Federated\":\"arn:aws:iam::123456789012:saml-provider/Ven\\u001b[2Jdor\"},\"Action\":\"sts:AssumeRoleWithSAML\"}]}"), nil},
	}
	for _, name := range ringsCases(t) {
		doc, owners := ringsCase(t, name)
		docs[name] = [2][]byte{doc, owners}
	}
	asked := 0
	for name, in := range docs {
		doc, owners := in[0], in[1]
		before := read(doc, owners)
		for _, r := range append(before.Rings, before.Beside...) {
			for _, q := range r.Questions {
				asked++
				after := read(doc, append(append(append([]byte{}, owners...), '\n'), q.Declaration...))
				for _, u := range after.Declarations.Unmatched {
					if u.Declaration == q.Declaration {
						t.Errorf("%s: answering yes declares %q, which moves nothing", name, q.Declaration)
					}
				}
				for _, again := range append(after.Rings, after.Beside...) {
					for _, still := range again.Questions {
						if again.Place == r.Place && still.Declaration == q.Declaration {
							t.Errorf("%s: after %q is declared, the %s row still asks about it", name, q.Declaration, r.Place)
						}
					}
				}
			}
		}
	}
	if asked < 10 {
		t.Fatalf("%d questions answered; the corpus asked too few", asked)
	}
}
