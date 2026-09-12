package trust

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CloudArq-net/cloudarq/internal/eval"
)

// grantsDir holds the triples: the same logical grant as an AWS trust policy,
// an Azure federated identity credential, and a GCP workload identity pool
// provider. Loaded by tests only; the package itself reads no files.
const grantsDir = "../../testdata/grants"

func documentPath(c Case, p Provider) string {
	return filepath.Join(grantsDir, c.Name, string(p)+".json")
}

// loadDocuments reads provider p's document for every case it can express.
func loadDocuments(t *testing.T, p Provider) map[string][]byte {
	t.Helper()
	docs := map[string][]byte{}
	for _, c := range Cases() {
		if _, no := c.Inexpressible[p]; no {
			continue
		}
		raw, err := os.ReadFile(documentPath(c, p))
		if err != nil {
			t.Fatalf("%v", err)
		}
		docs[c.Name] = raw
	}
	return docs
}

// expressibleCases counts the cases provider p has a document for.
func expressibleCases(p Provider) int {
	n := 0
	for _, c := range Cases() {
		if _, no := c.Inexpressible[p]; !no {
			n++
		}
	}
	return n
}

// failing lists the names of the cases that failed.
func failing(failures []Failure) map[string]bool {
	out := map[string]bool{}
	for _, f := range failures {
		out[f.Case] = true
	}
	return out
}

// TestCaseSevenExists: the case where one provider can express what the
// others cannot is the one that finds the design flaw, so it is pinned by
// name and shape before anything else.
func TestCaseSevenExists(t *testing.T) {
	var seven *Case
	for _, c := range Cases() {
		if c.Name == "07-expressible-by-one-provider" {
			seven = &c
		}
	}
	if seven == nil {
		t.Fatalf("case 7 is missing")
	}
	if seven.Expressive != AWS || seven.UnknownOn != "sub" || seven.Construct != "ForAllValues:StringLike" {
		t.Errorf("case 7 = expressive %q, unknown on %q, construct %q", seven.Expressive, seven.UnknownOn, seven.Construct)
	}
	if seven.Relation(AWS) != WidensWithAnomaly || seven.Relation(Azure) != Equal || seven.Relation(GCP) != Equal {
		t.Errorf("case 7 relations: aws %v, azure %v, gcp %v", seven.Relation(AWS), seven.Relation(Azure), seven.Relation(GCP))
	}
	// The expected grant is the exact one the constrained providers state.
	if !seven.Expected.Exact() || seven.Expected.IsTop() || seven.Expected.IsEmpty() {
		t.Errorf("case 7's expected set must be exact and constrained; got %s", seven.Expected)
	}
}

func TestEveryCaseTheSpecNamesExists(t *testing.T) {
	want := []string{
		"01-one-repo-one-branch",
		"02-one-repo-any-branch",
		"03-whole-organisation",
		"04-immutable-subject",
		"05-repository-id",
		"06-unconstrained",
		"07-expressible-by-one-provider",
	}
	cases := Cases()
	if len(cases) != len(want) {
		t.Fatalf("%d cases, want %d", len(cases), len(want))
	}
	for i, c := range cases {
		if c.Name != want[i] {
			t.Errorf("case %d is %q, want %q", i, c.Name, want[i])
		}
	}
}

// TestCasesAreSelfConsistent checks the expectations before any parser
// exists: each admits its witnesses and rejects its counters, every
// expressible provider has a well-formed document naming the issuer, and
// every inexpressible one has a stated reason and no document.
func TestCasesAreSelfConsistent(t *testing.T) {
	for _, c := range Cases() {
		if len(c.Witnesses) == 0 || (len(c.Counters) == 0 && !c.Expected.IsTop()) {
			t.Errorf("%s: %d witnesses, %d counters; a case with nothing to admit or reject proves nothing", c.Name, len(c.Witnesses), len(c.Counters))
		}
		for _, w := range c.Witnesses {
			if !c.Expected.Admits(w) {
				t.Errorf("%s: expected set %s rejects its own witness %v", c.Name, c.Expected, w)
			}
		}
		for _, x := range c.Counters {
			if c.Expected.Admits(x) {
				t.Errorf("%s: expected set %s admits its own counter-witness %v", c.Name, c.Expected, x)
			}
		}
		if c.Issuer == "" || c.Effect != Allow || !c.Expected.Exact() {
			t.Errorf("%s: issuer %q, effect %q, exact %v", c.Name, c.Issuer, c.Effect, c.Expected.Exact())
		}
		if c.Expressive != "" && (c.UnknownOn == "" || c.Construct == "") {
			t.Errorf("%s: an expressive provider needs the claim and the construct named", c.Name)
		}
		for _, p := range Providers {
			if c.Audiences[p] == "" {
				t.Errorf("%s: no %s audience", c.Name, p)
			}
			path := documentPath(c, p)
			raw, err := os.ReadFile(path)
			if reason, no := c.Inexpressible[p]; no {
				if reason == "" {
					t.Errorf("%s: %s is inexpressible without a reason", c.Name, p)
				}
				if err == nil {
					t.Errorf("%s: %s is declared inexpressible, yet %s exists", c.Name, p, path)
				}
				continue
			}
			if err != nil {
				t.Errorf("%s: %v", c.Name, err)
				continue
			}
			if !json.Valid(raw) {
				t.Errorf("%s: %s is not valid JSON", c.Name, path)
			}
			if !strings.Contains(string(raw), "token.actions.githubusercontent.com") {
				t.Errorf("%s: %s does not name the issuer", c.Name, path)
			}
		}
	}
	// The audiences table is built per case, so one case cannot be edited
	// through another.
	cases := Cases()
	cases[0].Audiences[AWS] = "tampered"
	if Cases()[0].Audiences[AWS] == "tampered" || cases[1].Audiences[AWS] == "tampered" {
		t.Errorf("cases share one audiences map")
	}
}

// expectedParser is a stand-in for a real parser: it recognises the
// document by its bytes and returns the case's conformant grant for p.
func expectedParser(t *testing.T, p Provider) Parser {
	t.Helper()
	docs := loadDocuments(t, p)
	return func(document []byte) ([]Grant, error) {
		for _, c := range Cases() {
			if raw, ok := docs[c.Name]; ok && bytes.Equal(raw, document) {
				return []Grant{c.conformant(p)}, nil
			}
		}
		return nil, errors.New("document belongs to no case")
	}
}

// bend returns a parser that returns the conformant grant with one thing wrong.
func bend(t *testing.T, p Provider, mutate func(*Grant)) Parser {
	t.Helper()
	exact := expectedParser(t, p)
	return func(document []byte) ([]Grant, error) {
		gs, err := exact(document)
		if err != nil {
			return nil, err
		}
		mutate(&gs[0])
		return gs, nil
	}
}

func TestCheckAcceptsTheConformantGrants(t *testing.T) {
	for _, p := range Providers {
		if failures := Check(p, expectedParser(t, p), loadDocuments(t, p)); len(failures) != 0 {
			t.Errorf("%s: the conformant grants themselves fail conformance: %v", p, failures)
		}
	}
}

func TestCheckRefusesToExamineNothing(t *testing.T) {
	// No parser at all: one failure per provider, none of them a case.
	failures := Suite(nil, nil)
	if len(failures) != len(Providers) {
		t.Fatalf("an empty suite must fail once per provider; got %v", failures)
	}
	for _, f := range failures {
		if f.Case != "" || !strings.Contains(f.String(), "no parser registered") {
			t.Errorf("unexpected failure %v", f)
		}
	}
	// A missing document is a failure, never a skip.
	docs := loadDocuments(t, AWS)
	delete(docs, "03-whole-organisation")
	failures = Check(AWS, expectedParser(t, AWS), docs)
	if len(failures) != 1 || failures[0].Case != "03-whole-organisation" || !strings.Contains(failures[0].String(), "no document") {
		t.Errorf("got %v", failures)
	}
	// A document for a provider that cannot express the case is the failure.
	azure := loadDocuments(t, Azure)
	azure["06-unconstrained"] = azure["01-one-repo-one-branch"]
	failures = Check(Azure, expectedParser(t, Azure), azure)
	if len(failures) != 1 || failures[0].Case != "06-unconstrained" || !strings.Contains(failures[0].String(), "inexpressible") {
		t.Errorf("got %v", failures)
	}
	// A document no case names would be examined by nothing.
	stray := loadDocuments(t, GCP)
	stray["99-stray-case"] = stray["01-one-repo-one-branch"]
	failures = Check(GCP, expectedParser(t, GCP), stray)
	if len(failures) != 1 || failures[0].Case != "99-stray-case" || !strings.Contains(failures[0].String(), "no case by this name") {
		t.Errorf("got %v", failures)
	}
}

func TestCheckRejectsANarrowingParser(t *testing.T) {
	narrowing := bend(t, AWS, func(g *Grant) { g.Admits = eval.Nothing() })
	if failures := Check(AWS, narrowing, loadDocuments(t, AWS)); len(failures) != expressibleCases(AWS) {
		t.Errorf("a parser that admits nothing must fail every case; got %d failures: %v", len(failures), failures)
	}
	// Narrower by one claim value is still narrower.
	pinned := bend(t, AWS, func(g *Grant) {
		g.Admits = eval.NewAdmittedSet(eval.Term{"sub": eval.Exact(mainBranch), aud: eval.Exact(awsAudience)})
	})
	caught := failing(Check(AWS, pinned, loadDocuments(t, AWS)))
	if caught["01-one-repo-one-branch"] {
		t.Errorf("case 1 is exactly one repo and one branch")
	}
	for _, name := range []string{"02-one-repo-any-branch", "03-whole-organisation", "06-unconstrained", "07-expressible-by-one-provider"} {
		if !caught[name] {
			t.Errorf("%s must reject a grant pinned to one branch", name)
		}
	}
}

// TestCheckJudgesEqualityNotSamples: a parser that turns a Glob into the
// three Exacts a witness list happens to contain admits every witness and
// rejects every counter, and is still the wrong grant.
func TestCheckJudgesEqualityNotSamples(t *testing.T) {
	sampled := bend(t, GCP, func(g *Grant) {
		g.Admits = eval.NewAdmittedSet(
			eval.Term{"sub": eval.Exact(mainBranch), aud: eval.Exact(gcpAudience)},
			eval.Term{"sub": eval.Exact(devBranch), aud: eval.Exact(gcpAudience)},
			eval.Term{"sub": eval.Exact("repo:acme/infra:environment:production"), aud: eval.Exact(gcpAudience)},
		)
	})
	failures := Check(GCP, sampled, loadDocuments(t, GCP))
	if !failing(failures)["02-one-repo-any-branch"] {
		t.Errorf("three Exacts are not a Glob; got %v", failures)
	}
}

func TestCheckRejectsASilentlyWideningParser(t *testing.T) {
	widening := bend(t, AWS, func(g *Grant) { g.Admits = eval.NewAdmittedSet(eval.Term{aud: eval.Exact(awsAudience)}) })
	failures := Check(AWS, widening, loadDocuments(t, AWS))
	// Every constrained case fails; the unconstrained one is exactly that.
	if len(failures) != expressibleCases(AWS)-1 || failing(failures)["06-unconstrained"] {
		t.Errorf("a parser that admits everything without saying so must fail every constrained case; got %v", failures)
	}
}

// declare is what a conformant AWS parser does with ForAllValues:StringLike
// on sub: Unknown on sub, a caveat on sub, an anomaly naming the construct.
func declare(g *Grant) {
	g.Admits = eval.NewAdmittedSet(eval.Term{"sub": eval.Unknown("ForAllValues"), "repository_id": eval.Exact(repositoryID), aud: eval.Exact(awsAudience)}).
		WithCaveat(notModelled)
	g.Anomalies = []Anomaly{{
		Kind:      Unmodelled,
		Claim:     "sub",
		Construct: "ForAllValues:StringLike",
		Message:   "ForAllValues:StringLike on sub passes when the claim is absent, so it does not restrict what it looks like it restricts",
		Source:    "statement[0].Condition",
	}}
}

func TestCheckAcceptsWideningOnlyWhenDeclared(t *testing.T) {
	failures := Check(AWS, bend(t, AWS, declare), loadDocuments(t, AWS))
	if failing(failures)["07-expressible-by-one-provider"] {
		t.Errorf("case 7 must accept a declared widening from the expressive provider: %v", failures)
	}
	// Every other case states its grant exactly, so the declared grant fails it.
	if len(failures) != expressibleCases(AWS)-1 {
		t.Errorf("got %d failures, want %d: %v", len(failures), expressibleCases(AWS)-1, failures)
	}
	// Anything less than the full declaration, or anything else changed, is
	// a silent widening or a narrowing, and case 7 must say so.
	for name, spoil := range map[string]func(*Grant){
		"no anomaly":                      func(g *Grant) { g.Anomalies = nil },
		"anomaly of another kind":         func(g *Grant) { g.Anomalies[0].Kind = "note" },
		"anomaly names another construct": func(g *Grant) { g.Anomalies[0].Construct = "StringEqualsIgnoreCase" },
		"anomaly on another claim":        func(g *Grant) { g.Anomalies[0].Claim = aud },
		"no caveat": func(g *Grant) {
			g.Admits = eval.NewAdmittedSet(eval.Term{"sub": eval.Unknown("r"), "repository_id": eval.Exact(repositoryID), aud: eval.Exact(awsAudience)})
		},
		"caveat on the wrong claim": func(g *Grant) {
			g.Admits = eval.NewAdmittedSet(eval.Term{"sub": eval.Unknown("r"), "repository_id": eval.Exact(repositoryID), aud: eval.Exact(awsAudience)}).
				WithCaveat(eval.Caveat{Claim: aud, Reason: "r", Source: "s"})
		},
		"modelled as a plain glob": func(g *Grant) {
			g.Admits = eval.NewAdmittedSet(eval.Term{"sub": eval.Glob("repo:acme/infra:*"), "repository_id": eval.Exact(repositoryID), aud: eval.Exact(awsAudience)}).
				WithCaveat(notModelled)
		},
		"repository_id dropped": func(g *Grant) {
			g.Admits = eval.NewAdmittedSet(eval.Term{"sub": eval.Unknown("r"), aud: eval.Exact(awsAudience)}).WithCaveat(notModelled)
		},
		"everything, declared": func(g *Grant) {
			g.Admits = eval.Everything().WithCaveat(notModelled)
		},
		"audience dropped": func(g *Grant) {
			g.Admits = eval.NewAdmittedSet(eval.Term{"sub": eval.Unknown("r"), "repository_id": eval.Exact(repositoryID)}).WithCaveat(notModelled)
		},
		"narrowed while declaring": func(g *Grant) {
			g.Admits = eval.NewAdmittedSet(eval.Term{"sub": eval.Exact(mainBranch), aud: eval.Exact(awsAudience)}).WithCaveat(notModelled)
		},
	} {
		silent := bend(t, AWS, func(g *Grant) { declare(g); spoil(g) })
		if !failing(Check(AWS, silent, loadDocuments(t, AWS)))["07-expressible-by-one-provider"] {
			t.Errorf("%s: case 7 must reject a widening that is not fully declared", name)
		}
	}
}

// TestCheckRejectsACaveatOnAnExactCase: the right set with a caveat it does
// not need claims an inexactness the provider did not state, and the
// renderer would refuse a clean verdict on a grant that deserves one.
func TestCheckRejectsACaveatOnAnExactCase(t *testing.T) {
	caveated := bend(t, GCP, func(g *Grant) { g.Admits = g.Admits.WithCaveat(notModelled) })
	failures := Check(GCP, caveated, loadDocuments(t, GCP))
	if len(failures) != expressibleCases(GCP) {
		t.Errorf("every exact case must reject a caveated grant; got %v", failures)
	}
	for _, f := range failures {
		if !strings.Contains(f.String(), "caveats") {
			t.Errorf("failure does not name the caveat: %v", f)
		}
	}
}

// TestCheckRefusesUndeclaredUnknowns: an Unknown beside a real constraint,
// with no caveat saying so, is silence read as clean.
func TestCheckRefusesUndeclaredUnknowns(t *testing.T) {
	undeclared := bend(t, GCP, func(g *Grant) {
		terms := g.Admits.Terms()
		for _, term := range terms {
			term["repository_owner_id"] = eval.Unknown("r")
		}
		g.Admits = eval.NewAdmittedSet(terms...)
	})
	failures := Check(GCP, undeclared, loadDocuments(t, GCP))
	if len(failures) != expressibleCases(GCP) {
		t.Errorf("every case must reject an undeclared Unknown; got %v", failures)
	}
	for _, f := range failures {
		if !strings.Contains(f.String(), "without a caveat") {
			t.Errorf("failure does not name the undeclared Unknown: %v", f)
		}
	}
}

func TestCheckRequiresTheProvidersOwnAudience(t *testing.T) {
	wrong := bend(t, Azure, func(g *Grant) { g.Admits = swapAudience(g.Admits, awsAudience) })
	if failures := Check(Azure, wrong, loadDocuments(t, Azure)); len(failures) != expressibleCases(Azure) {
		t.Errorf("an Azure grant admitting AWS's audience must fail every case; got %v", failures)
	}
	loose := bend(t, Azure, func(g *Grant) { g.Admits = swapAudience(g.Admits, "") })
	if failures := Check(Azure, loose, loadDocuments(t, Azure)); len(failures) != expressibleCases(Azure) {
		t.Errorf("a grant that accepts any audience must fail every case; got %v", failures)
	}
}

func TestCheckRequiresIssuerEffectAndOneGrant(t *testing.T) {
	for name, mutate := range map[string]func(*Grant){
		"issuer":  func(g *Grant) { g.Issuer = "https://gitlab.com" },
		"effect":  func(g *Grant) { g.Effect = Deny },
		"unknown": func(g *Grant) { g.Effect = EffectUnknown },
	} {
		if failures := Check(GCP, bend(t, GCP, mutate), loadDocuments(t, GCP)); len(failures) != expressibleCases(GCP) {
			t.Errorf("%s: a grant with the wrong %s must fail every case; got %v", name, name, failures)
		}
	}
	failingParser := func([]byte) ([]Grant, error) { return nil, errors.New("not a policy") }
	if failures := Check(GCP, failingParser, loadDocuments(t, GCP)); len(failures) != expressibleCases(GCP) {
		t.Errorf("a parser error must be a failure for its case; got %v", failures)
	}
	none := func([]byte) ([]Grant, error) { return nil, nil }
	if failures := Check(GCP, none, loadDocuments(t, GCP)); len(failures) != expressibleCases(GCP) {
		t.Errorf("a parser that returns no grant must fail its case; got %v", failures)
	}
	two := func(d []byte) ([]Grant, error) {
		gs, err := expectedParser(t, GCP)(d)
		return append(gs, gs...), err
	}
	if failures := Check(GCP, two, loadDocuments(t, GCP)); len(failures) != expressibleCases(GCP) {
		t.Errorf("a document is one grant; two must fail; got %v", failures)
	}
}

func TestSuiteExaminesEveryProvider(t *testing.T) {
	parsers := map[Provider]Parser{}
	docs := map[Provider]map[string][]byte{}
	for _, p := range Providers {
		parsers[p] = expectedParser(t, p)
		docs[p] = loadDocuments(t, p)
	}
	if failures := Suite(parsers, docs); len(failures) != 0 {
		t.Errorf("Suite over the conformant grants: %v", failures)
	}
	// One provider without a parser: one failure for it, nothing for the others.
	delete(parsers, Azure)
	failures := Suite(parsers, docs)
	if len(failures) != 1 || failures[0].Provider != Azure || failures[0].Case != "" || !strings.Contains(failures[0].String(), "no parser registered") {
		t.Errorf("got %v", failures)
	}
	// A parser for a provider the triples are not written in.
	parsers[Azure] = expectedParser(t, Azure)
	parsers["oracle"] = func([]byte) ([]Grant, error) { return nil, nil }
	failures = Suite(parsers, docs)
	if len(failures) != 1 || failures[0].Provider != "oracle" || !strings.Contains(failures[0].String(), "no triples") {
		t.Errorf("got %v", failures)
	}
	// A provider with a parser and no documents fails every expressible case.
	delete(parsers, "oracle")
	docs[GCP] = nil
	failures = Suite(parsers, docs)
	if len(failures) != expressibleCases(GCP) {
		t.Errorf("Suite must report every case a provider has no document for; got %v", failures)
	}
	for _, f := range failures {
		if f.Provider != GCP || !strings.Contains(f.String(), "no document") {
			t.Errorf("unexpected failure %v", f)
		}
	}
}

func TestConformantGrantsCarryTheProvidersAudience(t *testing.T) {
	for _, c := range Cases() {
		for _, p := range Providers {
			g := c.conformant(p)
			if !g.Audience().Admits(token{aud: c.Audiences[p]}) || g.Audience().Admits(token{aud: "other"}) {
				t.Errorf("%s/%s: conformant grant %s does not pin its audience %q", c.Name, p, g.Admits, c.Audiences[p])
			}
			if g.Issuer != c.Issuer || g.Effect != c.Effect || g.Exact() != (c.Relation(p) == Equal) {
				t.Errorf("%s/%s: issuer %q effect %q exact %v", c.Name, p, g.Issuer, g.Effect, g.Exact())
			}
		}
	}
}

// swapAudience rebuilds a set with every aud constraint replaced, or
// removed when the audience is empty.
func swapAudience(s eval.AdmittedSet, audience string) eval.AdmittedSet {
	terms := s.Terms()
	for _, term := range terms {
		if audience == "" {
			delete(term, aud)
		} else {
			term[aud] = eval.Exact(audience)
		}
	}
	return eval.NewAdmittedSet(terms...)
}
