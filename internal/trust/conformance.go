package trust

import (
	"maps"
	"slices"
	"strconv"
	"strings"

	"github.com/CloudArq-net/cloudarq/internal/eval"
)

// Providers are the clouds the triples are written in. Suite demands a
// parser for each, so that a provider nobody registered is a failure rather
// than a silence.
var Providers = []Provider{AWS, Azure, GCP}

// Relation is how a provider's parse of a case must relate to the case's
// expected set.
type Relation int

const (
	// Equal: the parse admits exactly the expected set and is exact.
	Equal Relation = iota
	// WidensWithAnomaly: the provider can express what the others cannot,
	// so its parse is the expected set with the claim it could not model
	// left Unknown, declared by a caveat on that claim and an anomaly naming
	// the construct. Everything else must still match: never narrower, never
	// silently wider.
	WidensWithAnomaly
)

// Case is one logical trust relationship written in every provider's syntax.
// A parser is conformant when every case parses to what the case expects.
type Case struct {
	Name string
	// Expected is the admitted set with aud projected out; audiences are
	// provider-specific by nature and are checked per provider instead.
	Expected  eval.AdmittedSet
	Audiences map[Provider]string
	Issuer    IssuerRef
	Effect    Effect
	// Witnesses are tokens the logical grant admits and Counters tokens it
	// rejects. They check the expectation itself; a parse is judged by
	// canonical equality with it.
	Witnesses []map[ClaimKey]string
	Counters  []map[ClaimKey]string
	// Expressive is the provider that can say more than the others for this
	// case, "" when none; its parse must leave UnknownOn Unknown and name
	// Construct in an anomaly.
	Expressive Provider
	UnknownOn  ClaimKey
	Construct  string
	// Inexpressible names providers that cannot state this grant at all, with
	// the reason. A document for such a provider is a failure, not a bonus:
	// the reason is a fact about the provider and must stay stated.
	Inexpressible map[Provider]string
}

// Relation reports how provider p's parse of the case is judged.
func (c Case) Relation(p Provider) Relation {
	if p == c.Expressive {
		return WidensWithAnomaly
	}
	return Equal
}

// conformant is the Grant a conformant parser produces for provider p's
// document of this case: the expected set with the provider's own audience,
// or, for the provider that can say more than the others, that set widened
// on the claim it cannot model, with the caveat and the anomaly that make
// the widening honest.
func (c Case) conformant(p Provider) Grant {
	terms := c.Expected.Terms()
	for _, term := range terms {
		term[aud] = eval.Exact(c.Audiences[p])
	}
	g := Grant{Issuer: c.Issuer, Admits: eval.NewAdmittedSet(terms...), Effect: c.Effect}
	if c.Relation(p) != WidensWithAnomaly {
		return g
	}
	for _, term := range terms {
		term[c.UnknownOn] = eval.Unknown(c.Construct)
	}
	g.Admits = eval.NewAdmittedSet(terms...).WithCaveat(eval.Caveat{
		Claim:  c.UnknownOn,
		Reason: "operator " + c.Construct + " is not modelled",
		Source: "document",
	})
	g.Anomalies = []Anomaly{{
		Kind:      Unmodelled,
		Claim:     c.UnknownOn,
		Construct: c.Construct,
		Message:   c.Construct + " on " + string(c.UnknownOn) + " passes when the claim is absent, so it does not restrict what it looks like it restricts",
		Source:    "document",
	}}
	return g
}

// Parser turns one provider document into the Grants it states.
type Parser func(document []byte) ([]Grant, error)

// Failure is one case a parse fell short of, with every reason. A failure
// with no case is about the provider as a whole.
type Failure struct {
	Case     string
	Provider Provider
	Reasons  []string
}

func (f Failure) String() string {
	where := string(f.Provider)
	if f.Case != "" {
		where = f.Case + "/" + where
	}
	return where + ": " + strings.Join(f.Reasons, "; ")
}

// Check runs every case against one provider's parser. documents maps a case
// name to that provider's document. A case with no document is a failure,
// never a skip, unless the case declares the provider unable to express it,
// in which case a document is the failure. A document no case names is a
// failure too: it would be examined by nothing.
func Check(p Provider, parse Parser, documents map[string][]byte) []Failure {
	var failures []Failure
	named := map[string]bool{}
	for _, c := range Cases() {
		named[c.Name] = true
		if reasons := c.check(p, parse, documents); len(reasons) != 0 {
			failures = append(failures, Failure{c.Name, p, reasons})
		}
	}
	for _, name := range slices.Sorted(maps.Keys(documents)) {
		if !named[name] {
			failures = append(failures, Failure{name, p, []string{"no case by this name; the document would be examined by nothing"}})
		}
	}
	return failures
}

// check lists every way provider p's parse of the case falls short.
func (c Case) check(p Provider, parse Parser, documents map[string][]byte) []string {
	doc, present := documents[c.Name]
	if reason, no := c.Inexpressible[p]; no {
		if present {
			return []string{"declared inexpressible (" + reason + "), yet a document exists"}
		}
		return nil
	}
	if !present {
		return []string{"no document for this provider"}
	}
	grants, err := parse(doc)
	if err != nil {
		return []string{"parse: " + err.Error()}
	}
	if len(grants) != 1 {
		return []string{"parsed " + strconv.Itoa(len(grants)) + " grants, want 1"}
	}
	return c.judge(p, grants[0])
}

// judge lists every way g falls short of what a conformant parser produces
// for provider p. Equality is canonical: AdmittedSet renders one way per
// set, so two renderings that differ are two different sets, and sampling
// tokens could not tell a Glob from the three Exacts a lazy parser might
// substitute for it. The audience is a claim like any other and is judged
// by the same comparison.
func (c Case) judge(p Provider, g Grant) []string {
	want := c.conformant(p)
	var out []string
	if g.Issuer != want.Issuer {
		out = append(out, "issuer "+strconv.Quote(string(g.Issuer))+", want "+strconv.Quote(string(want.Issuer)))
	}
	if g.Effect != want.Effect {
		out = append(out, "effect "+strconv.Quote(string(g.Effect))+", want "+strconv.Quote(string(want.Effect)))
	}
	out = append(out, undeclaredUnknowns(g)...)
	switch c.Relation(p) {
	case Equal:
		if x, y := g.Admits.String(), want.Admits.String(); x != y {
			out = append(out, "admits "+x+", want "+y)
		}
		if !g.Exact() {
			out = append(out, "carries caveats on a grant the provider states exactly")
		}
	case WidensWithAnomaly:
		beyond := func(k ClaimKey) bool { return k != c.UnknownOn }
		if x, y := project(g.Admits, beyond).String(), project(want.Admits, beyond).String(); x != y {
			out = append(out, "beyond "+string(c.UnknownOn)+" admits "+x+", want "+y)
		}
		// With the claim required to be Unknown, the undeclared-Unknown rule
		// above is what demands the caveat.
		for _, term := range g.Admits.Terms() {
			if s, ok := term[c.UnknownOn]; !ok || !eval.IsUnknown(s) {
				out = append(out, string(c.UnknownOn)+" must be Unknown in every term; a narrower constraint claims to model "+c.Construct)
				break
			}
		}
		if !slices.ContainsFunc(g.Anomalies, func(a Anomaly) bool {
			return a.Kind == Unmodelled && a.Claim == c.UnknownOn && a.Construct == c.Construct
		}) {
			out = append(out, "no "+Unmodelled+" anomaly on "+strconv.Quote(string(c.UnknownOn))+" naming "+strconv.Quote(c.Construct))
		}
	}
	return out
}

// undeclaredUnknowns lists claims left Unknown without a caveat saying so:
// silence read as clean. A Term whose every claim is Unknown has already
// collapsed to Everything inside the lattice, so that shape can only be
// declared by its parser, never detected here.
func undeclaredUnknowns(g Grant) []string {
	var out []string
	for _, term := range g.Admits.Terms() {
		for _, k := range slices.Sorted(maps.Keys(term)) {
			if eval.IsUnknown(term[k]) && !hasCaveat(g, k) {
				out = append(out, string(k)+" is Unknown without a caveat: silence read as clean")
			}
		}
	}
	return slices.Compact(out)
}

func hasCaveat(g Grant, k ClaimKey) bool {
	return slices.ContainsFunc(g.Admits.Caveats(), func(cv eval.Caveat) bool { return cv.Claim == k })
}

// Suite runs Check for every provider the triples are written in. A provider
// with no parser is a failure, so the suite passes only when every provider
// has been examined; a parser for a provider with no triples is a failure
// too, because nothing would examine it.
func Suite(parsers map[Provider]Parser, documents map[Provider]map[string][]byte) []Failure {
	var failures []Failure
	for _, p := range Providers {
		parse, ok := parsers[p]
		if !ok {
			failures = append(failures, Failure{Provider: p, Reasons: []string{"no parser registered; every case for this provider went unexamined"}})
			continue
		}
		failures = append(failures, Check(p, parse, documents[p])...)
	}
	for _, p := range slices.Sorted(maps.Keys(parsers)) {
		if !slices.Contains(Providers, p) {
			failures = append(failures, Failure{Provider: p, Reasons: []string{"no triples are written for this provider; the parser would be examined by nothing"}})
		}
	}
	return failures
}

// The GitHub Actions issuer and the identifiers the triples share. The ids
// are the immutable claims GitHub issues beside the subject.
const (
	github          IssuerRef = "https://token.actions.githubusercontent.com"
	awsAudience               = "sts.amazonaws.com"
	azureAudience             = "api://AzureADTokenExchange"
	gcpAudience               = "https://iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/github/providers/github"
	repositoryID              = "456789"
	repositoryOwner           = "123456"
	mainBranch                = "repo:acme/infra:ref:refs/heads/main"
	devBranch                 = "repo:acme/infra:ref:refs/heads/dev"
	immutableMain             = "repo:acme@123456/infra@456789:ref:refs/heads/main"
	lookalikeOrg              = "repo:acme-evil/infra:ref:refs/heads/main"
	lookalikeRepo             = "repo:acme/infra-evil:ref:refs/heads/main"
)

// azureNeedsAnImmutableClaim is why Azure cannot state a grant that pins the
// subject by pattern alone: a classic federated identity credential matches
// the subject exactly, and a flexible one must match sub together with
// repository_id or repository_owner_id.
const azureNeedsAnImmutableClaim = "a federated identity credential matches the subject exactly, and a flexible one must match sub together with an immutable claim; a subject pattern alone cannot be stated"

func audiences() map[Provider]string {
	return map[Provider]string{AWS: awsAudience, Azure: azureAudience, GCP: gcpAudience}
}

type token = map[ClaimKey]string

// Cases are the seven logical grants every parser must agree on. Case 7 is
// the one that finds the design flaw: one provider can say what the others
// cannot, and the model must carry that as Unknown with a reason, never as a
// quiet narrowing or widening.
func Cases() []Case {
	return []Case{
		{
			Name:      "01-one-repo-one-branch",
			Expected:  eval.NewAdmittedSet(eval.Term{"sub": eval.Exact(mainBranch)}),
			Audiences: audiences(), Issuer: github, Effect: Allow,
			Witnesses: []token{{"sub": mainBranch}, {"sub": mainBranch, "repository_id": repositoryID}},
			Counters:  []token{{"sub": devBranch}, {"sub": lookalikeOrg}, {"sub": immutableMain}, {}},
		},
		{
			Name:      "02-one-repo-any-branch",
			Expected:  eval.NewAdmittedSet(eval.Term{"sub": eval.Glob("repo:acme/infra:*")}),
			Audiences: audiences(), Issuer: github, Effect: Allow,
			Witnesses: []token{{"sub": mainBranch}, {"sub": devBranch}, {"sub": "repo:acme/infra:environment:production"}},
			Counters: []token{
				{"sub": lookalikeRepo},
				{"sub": "repo:acme/infrastructure:ref:refs/heads/main"},
				{},
			},
			Inexpressible: map[Provider]string{Azure: azureNeedsAnImmutableClaim},
		},
		{
			Name: "03-whole-organisation",
			Expected: eval.NewAdmittedSet(eval.Term{
				"sub":                 eval.Glob("repo:acme/*"),
				"repository_owner_id": eval.Exact(repositoryOwner),
			}),
			Audiences: audiences(), Issuer: github, Effect: Allow,
			Witnesses: []token{
				{"sub": mainBranch, "repository_owner_id": repositoryOwner},
				{"sub": "repo:acme/anything:environment:production", "repository_owner_id": repositoryOwner},
			},
			Counters: []token{
				{"sub": lookalikeOrg, "repository_owner_id": repositoryOwner},
				{"sub": "repo:acmeco/infra:ref:refs/heads/main", "repository_owner_id": repositoryOwner},
				{"sub": mainBranch, "repository_owner_id": "999999"},
				{"sub": mainBranch},
			},
		},
		{
			Name:      "04-immutable-subject",
			Expected:  eval.NewAdmittedSet(eval.Term{"sub": eval.Exact(immutableMain)}),
			Audiences: audiences(), Issuer: github, Effect: Allow,
			Witnesses: []token{{"sub": immutableMain}},
			Counters:  []token{{"sub": mainBranch}, {"sub": "repo:acme@123456/infra@456789:ref:refs/heads/dev"}, {}},
		},
		{
			Name:      "05-repository-id",
			Expected:  eval.NewAdmittedSet(eval.Term{"repository_id": eval.Exact(repositoryID)}),
			Audiences: audiences(), Issuer: github, Effect: Allow,
			Witnesses: []token{
				{"repository_id": repositoryID, "sub": mainBranch},
				{"repository_id": repositoryID, "sub": "repo:renamed/moved:ref:refs/heads/main"},
			},
			Counters: []token{{"repository_id": "999999", "sub": mainBranch}, {"sub": mainBranch}},
		},
		{
			Name:      "06-unconstrained",
			Expected:  eval.Everything(),
			Audiences: audiences(), Issuer: github, Effect: Allow,
			Witnesses: []token{{"sub": mainBranch}, {"sub": lookalikeOrg}, {}},
			Inexpressible: map[Provider]string{
				Azure: "a federated identity credential must pin the subject, and a flexible one must match sub together with an immutable claim; there is no way to trust every subject from an issuer",
			},
		},
		{
			Name: "07-expressible-by-one-provider",
			Expected: eval.NewAdmittedSet(eval.Term{
				"sub":           eval.Glob("repo:acme/infra:*"),
				"repository_id": eval.Exact(repositoryID),
			}),
			Audiences: audiences(), Issuer: github, Effect: Allow,
			Witnesses: []token{
				{"sub": mainBranch, "repository_id": repositoryID},
				{"sub": devBranch, "repository_id": repositoryID},
			},
			Counters: []token{
				{"sub": lookalikeRepo, "repository_id": repositoryID},
				{"sub": mainBranch, "repository_id": "999999"},
			},
			Expressive: AWS,
			UnknownOn:  "sub",
			Construct:  "ForAllValues:StringLike",
		},
	}
}
