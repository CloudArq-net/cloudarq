package azure

import (
	"encoding/json"
	"maps"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/CloudArq-net/cloudarq/internal/eval"
	"github.com/CloudArq-net/cloudarq/internal/trust"
	"pgregory.net/rapid"
)

type token = map[trust.ClaimKey]string

// The vocabulary is small on purpose so that generated documents collide
// with the documented table constantly: claims Microsoft lists and claims
// it does not, both spellings of a listed claim, a homoglyph of one, the
// audience under both spellings, operators in and outside the language,
// comparands that match everything, hold a doubled or a stray quote,
// contain the word and, or are empty, and issuers Microsoft documents and
// does not, one padded with whitespace and one that is not https.
var (
	claimNames    = []string{"sub", "sub", "repository_id", "repository_owner_id", "job_workflow_ref", "environment", "SUB", "Repository_Id", "\u017fub", "aud", "AUD"}
	operatorNames = []string{"eq", "eq", "eq", "matches", "matches", "startsWith", "EQ"}
	issuerNames   = []string{string(github), string(github), string(github), string(gitlab), string(terraform), string(google), "", " " + string(github) + " ", "http://gitlab.com"}
	documentedFor = []string{string(github), string(gitlab), string(terraform)}
	audienceName  = "api://AzureADTokenExchange"
)

func genComparand() *rapid.Generator[string] {
	return rapid.OneOf(
		rapid.StringOfN(rapid.RuneFrom([]rune("ab:/")), 1, 6, -1),
		rapid.StringOfN(rapid.RuneFrom([]rune("ab:/*?")), 1, 6, -1),
		rapid.Just("*"),
		rapid.Just(""),
		rapid.Just("it''s"),
		rapid.Just("o'reilly"),
		rapid.Just("a and b"),
	)
}

// strayQuote reports whether a clause carries an odd number of single
// quotes, which makes the text around it a quoted region of unknown extent.
func strayQuote(c clauseSpec) bool { return strings.Count(c.text(), "'")%2 == 1 }

// clauseSpec is one clause the generator wrote, kept structured so that a
// property can reorder, remove or corrupt clauses and rebuild the text.
type clauseSpec struct{ claim, operator, comparand string }

func (c clauseSpec) text() string {
	return "claims['" + c.claim + "'] " + c.operator + " '" + c.comparand + "'"
}

func genClause() *rapid.Generator[clauseSpec] {
	return rapid.Custom(func(t *rapid.T) clauseSpec {
		return clauseSpec{
			claim:     rapid.SampledFrom(claimNames).Draw(t, "claim"),
			operator:  rapid.SampledFrom(operatorNames).Draw(t, "operator"),
			comparand: genComparand().Draw(t, "comparand"),
		}
	})
}

// documentSpec is a generated credential. A nil subject, audiences or
// clauses is a member left out of the document; an empty issuer too. The
// trailer is text appended to the expression, " and " for a dangling
// connective. An enveloped document is written the way Resource Manager
// returns a managed identity's credential: the members under properties,
// beside the resource's id, name and type.
type documentSpec struct {
	issuer     string
	subject    *string
	audiences  []string
	clauses    []clauseSpec
	version    string // the languageVersion literal
	connective string
	trailer    string
	envelope   bool
}

func (d documentSpec) expression() string {
	texts := make([]string, len(d.clauses))
	for i, c := range d.clauses {
		texts[i] = c.text()
	}
	return strings.Join(texts, d.connective) + d.trailer
}

func (d documentSpec) json() []byte {
	credential := map[string]any{}
	if d.issuer != "" {
		credential["issuer"] = d.issuer
	}
	if d.subject != nil {
		credential["subject"] = *d.subject
	}
	if d.audiences != nil {
		credential["audiences"] = d.audiences
	}
	if d.clauses != nil {
		credential["claimsMatchingExpression"] = map[string]any{"value": d.expression(), "languageVersion": json.RawMessage(d.version)}
	}
	if d.envelope {
		return mustJSON(map[string]any{
			"id":         "/subscriptions/c267c0e7-0a73-4789-9e17-d26aeb0904e5/resourcegroups/rg/providers/Microsoft.ManagedIdentity/userAssignedIdentities/generated/federatedIdentityCredentials/generated",
			"name":       "generated",
			"type":       "Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials",
			"properties": credential,
		})
	}
	credential["@odata.type"] = "#microsoft.graph.federatedIdentityCredential"
	credential["name"] = "generated"
	return mustJSON(credential)
}

// manyClauses writes n clauses on n distinct claims, more than any
// documented issuer has, for the clause cap.
func manyClauses(n int) []clauseSpec {
	clauses := make([]clauseSpec, n)
	for i := range clauses {
		clauses[i] = clauseSpec{"c" + strconv.Itoa(i), "eq", "v"}
	}
	return clauses
}

func ptr(s string) *string { return &s }

// states reports whether the document carries a member that states a
// credential; one with none is not a credential document and is refused,
// which the properties over credentials must not draw.
func (d documentSpec) states() bool {
	return d.issuer != "" || d.subject != nil || d.audiences != nil || d.clauses != nil
}

// genDocument draws any credential, well-formed or not. The defect rates
// are high enough that every fact the parser can record is drawn many
// times per run; TestGeneratorIsNotStale is what proves that.
func genDocument() *rapid.Generator[documentSpec] {
	return genAnyDocument().Filter(documentSpec.states)
}

// genAnyDocument draws a document that may carry no credential member at
// all, so that the totality property sees such a document refused.
func genAnyDocument() *rapid.Generator[documentSpec] {
	return rapid.Custom(func(t *rapid.T) documentSpec {
		d := documentSpec{issuer: rapid.SampledFrom(issuerNames).Draw(t, "issuer"), version: "1", connective: " and "}
		switch rapid.IntRange(0, 9).Draw(t, "subject") {
		case 0, 1, 2, 3:
		case 4:
			d.subject = ptr("")
		default:
			d.subject = ptr(rapid.StringOfN(rapid.RuneFrom([]rune("ab:/")), 1, 8, -1).Draw(t, "subjectValue"))
		}
		switch rapid.IntRange(0, 19).Draw(t, "expression") {
		case 0, 1, 2, 3, 4, 5, 6, 7:
		case 8, 9:
			d.clauses = manyClauses(clauseCap + 1)
		default:
			d.clauses = rapid.SliceOfN(genClause(), 1, 4).Draw(t, "clauses")
			if rapid.IntRange(0, 9).Draw(t, "everything") < 4 {
				d.clauses = append([]clauseSpec{{"sub", "matches", "*"}}, d.clauses...)
			}
		}
		d.envelope = rapid.IntRange(0, 4).Draw(t, "envelope") == 0
		switch rapid.IntRange(0, 19).Draw(t, "audiences") {
		case 0:
		case 1:
			d.audiences = []string{}
		case 2, 3:
			d.audiences = []string{audienceName, "api://acme-exchange"}
		case 4:
			d.audiences = []string{""}
		case 5:
			d.audiences = []string{audienceName, ""}
		case 6:
			d.audiences = numberedAudiences(audienceCap + 1)
		default:
			d.audiences = []string{audienceName}
		}
		if rapid.IntRange(0, 4).Draw(t, "version") == 0 {
			d.version = "2"
		}
		if rapid.IntRange(0, 3).Draw(t, "connective") == 0 {
			d.connective = " or "
		}
		if rapid.IntRange(0, 9).Draw(t, "trailer") == 0 {
			d.trailer = " and "
		}
		return d
	})
}

// genClean draws a document every clause of which the language models: a
// documented issuer, distinct documented claims under documented operators
// with every claim Microsoft says must appear, plain comparands, one
// audience, version 1, no subject. Its parse is exact, which is what makes
// it a base to corrupt.
func genClean() *rapid.Generator[documentSpec] {
	return rapid.Custom(func(t *rapid.T) documentSpec {
		issuer := rapid.SampledFrom(documentedFor).Draw(t, "issuer")
		lang, _ := documentedLanguage(trust.IssuerRef(issuer))
		var chosen []trust.ClaimKey
		for _, group := range lang.required {
			chosen = append(chosen, rapid.SampledFrom(group).Draw(t, "required"))
		}
		keys := slices.Sorted(maps.Keys(lang.operators))
		fewest := 0
		if len(chosen) == 0 {
			fewest = 1
		}
		for _, k := range rapid.SliceOfNDistinct(rapid.SampledFrom(keys), fewest, len(keys), func(k trust.ClaimKey) trust.ClaimKey { return k }).Draw(t, "claims") {
			if !slices.Contains(chosen, k) {
				chosen = append(chosen, k)
			}
		}
		chosen = rapid.Permutation(chosen).Draw(t, "order")
		clauses := make([]clauseSpec, len(chosen))
		for i, k := range chosen {
			operator := rapid.SampledFrom(lang.operators[k]).Draw(t, "operator")
			comparand := rapid.StringOfN(rapid.RuneFrom([]rune("ab:/")), 1, 6, -1).Draw(t, "comparand")
			if operator == "matches" {
				comparand = rapid.StringOfN(rapid.RuneFrom([]rune("ab:/*?")), 1, 6, -1).Draw(t, "pattern")
			}
			clauses[i] = clauseSpec{string(k), operator, comparand}
		}
		return documentSpec{issuer: issuer, audiences: []string{audienceName}, clauses: clauses, version: "1", connective: " and "}
	})
}

// corruptions are the ways one clause, or the document around it, can
// leave the documented language, each named with the fact it exists to
// make the parser record. Each must widen, never narrow, and each must be
// seen to reach its fact, or a corruption that stopped doing its job would
// hide behind another that reaches the same fact by accident.
var corruptions = map[string]string{
	"operator":       "undocumented operator",
	"claim":          "undocumented claim",
	"repeat":         "repeated claim",
	"quote":          "escaped quote",
	"stray quote":    "unbalanced quote",
	"empty":          "empty comparand",
	"connective":     "unparseable clause",
	"trailer":        "empty clause",
	"version":        "language version",
	"issuer":         "undocumented issuer",
	"subject":        "subject-and-expression",
	"audiences":      "audience-count no audience is set",
	"audience cap":   "audience-count 257 audiences are set",
	"empty audience": "empty audience",
	"case":           "claim-folded",
	"shape":          "missing required claim",
	"clause cap":     "clause count",
}

func corrupt(t *rapid.T, d documentSpec, kind string) documentSpec {
	c := d
	c.clauses = slices.Clone(d.clauses)
	i := rapid.IntRange(0, len(c.clauses)-1).Draw(t, "clause")
	switch kind {
	case "operator":
		c.clauses[i].operator = "startsWith"
	case "claim":
		c.clauses[i].claim = "environment"
	case "repeat":
		c.clauses = append(c.clauses, c.clauses[i])
	case "quote":
		c.clauses[i].comparand = "it''s"
	case "stray quote":
		c.clauses[i].comparand = "o'reilly"
	case "empty":
		c.clauses[i].comparand = ""
	case "connective":
		c.clauses = append(c.clauses, c.clauses[i])
		c.connective = " or "
	case "trailer":
		c.trailer = " and "
	case "version":
		c.version = "2"
	case "issuer":
		c.issuer = string(google)
	case "subject":
		c.subject = ptr("repo:acme/other:ref:refs/heads/main")
	case "audiences":
		c.audiences = nil
	case "audience cap":
		c.audiences = numberedAudiences(audienceCap + 1)
	case "clause cap":
		c.clauses = append(c.clauses, manyClauses(clauseCap+1)...)
	case "empty audience":
		c.audiences = []string{""}
	case "case":
		c.clauses[i].claim = strings.ToUpper(c.clauses[i].claim)
	case "shape":
		// Every clause but the one on sub goes, which for GitHub removes the
		// immutable claim Microsoft requires; for an issuer with no such rule
		// the document is still clean, and the property holds trivially.
		c.clauses = slices.DeleteFunc(c.clauses, func(cl clauseSpec) bool { return cl.claim != "sub" })
	}
	return c
}

// fill turns a pattern into one string it matches.
func fill(pattern, star string) string {
	return strings.ReplaceAll(strings.ReplaceAll(pattern, "*", star), "?", "a")
}

// genTokens draws tokens over the claims the documents name, from values
// that stand a chance of being admitted: the comparands with wildcards
// filled in, the subjects, the audiences, and a little noise. Claims are
// visited in sorted order so that the draws are reproducible.
func genTokens(t *rapid.T, docs ...documentSpec) []token {
	candidates := map[trust.ClaimKey][]string{"aud": {audienceName, "api://acme-exchange", "other"}}
	for _, d := range docs {
		if d.subject != nil {
			candidates["sub"] = append(candidates["sub"], *d.subject)
		}
		for _, c := range d.clauses {
			k := trust.ClaimKey(strings.ToLower(c.claim))
			candidates[k] = append(candidates[k], fill(c.comparand, "ab"), fill(c.comparand, ""), c.comparand)
		}
	}
	keys := slices.Sorted(maps.Keys(candidates))
	return rapid.SliceOfN(rapid.Custom(func(t *rapid.T) token {
		tok := token{}
		for _, k := range keys {
			if rapid.IntRange(0, 4).Draw(t, "absent") == 0 {
				continue
			}
			values := append(slices.Clone(candidates[k]), rapid.StringOfN(rapid.RuneFrom([]rune("ab:/")), 0, 6, -1).Draw(t, "noise"))
			tok[k] = rapid.SampledFrom(values).Draw(t, "value")
		}
		return tok
	}), 1, 8).Draw(t, "tokens")
}

func parseSpec(t *rapid.T, d documentSpec) trust.Grant {
	c, err := ParseFederatedCredential(d.json())
	if err != nil {
		t.Fatalf("%v", err)
	}
	return c.Grants(infraApp)[0]
}

// fingerprint is everything a Grant states, rendered, for equality.
func fingerprint(g trust.Grant) string {
	return string(g.Issuer) + "\n" + string(g.Effect) + "\n" + g.Admits.String() + "\n" + renderCaveats(g.Admits.Caveats()) + renderAnomalies(g.Anomalies)
}

// damageKinds are the ways damage makes a document worse, each of which
// the totality property must be seen to try.
var damageKinds = []string{"truncated", "byte overwritten", "trailing bytes", "member duplicated"}

// damage makes a well-formed document worse in one of the ways a hand or
// a broken serialiser would: truncated, a byte overwritten, bytes after
// the end, or a member written twice. It reports which.
func damage(t *rapid.T, raw []byte) ([]byte, string) {
	out := slices.Clone(raw)
	switch rapid.IntRange(0, 3).Draw(t, "damage") {
	case 0:
		return out[:rapid.IntRange(0, len(out)).Draw(t, "cut")], damageKinds[0]
	case 1:
		out[rapid.IntRange(0, len(out)-1).Draw(t, "at")] = rapid.Byte().Draw(t, "byte")
		return out, damageKinds[1]
	case 2:
		return append(out, " x"...), damageKinds[2]
	}
	return slices.Concat([]byte(`{"subject": "twice", `), out[1:]), damageKinds[3]
}

// TestTotalityOverArbitraryBytes: the parser never panics, refuses only
// what is not a credential document, and for everything else states a
// Grant that admits at least one token, declares every Unknown, and comes
// out identical on a second reading. Every example reads random bytes, a
// generated document, and that document damaged, so that each kind of
// damage is tried on every run rather than when the dice allow.
func TestTotalityOverArbitraryBytes(t *testing.T) {
	parsed, refused, inexact := 0, 0, 0
	noticed := map[string]int{}
	rapid.Check(t, func(t *rapid.T) {
		// examine checks the promises above on one input and renders what
		// the parser said, so that two inputs can be compared: "refused",
		// or the fingerprint of every grant.
		examine := func(raw []byte) string {
			credentials, err := ParseFederatedCredentials(raw)
			if err != nil {
				refused++
				if credentials != nil {
					t.Fatalf("an error came with credentials: %v", credentials)
				}
				if _, err := ParseFederatedCredential(raw); err == nil {
					t.Fatalf("the singular parse accepted what the plural refused: %q", raw)
				}
				return "refused"
			}
			parsed++
			again, err := ParseFederatedCredentials(raw)
			if err != nil {
				t.Fatalf("second parse of %q: %v", raw, err)
			}
			var prints []string
			for i, c := range credentials {
				grants := c.Grants(infraApp)
				if len(grants) != 1 {
					t.Fatalf("%q: %d grants, want 1", raw, len(grants))
				}
				g := grants[0]
				if g.Admits.IsEmpty() {
					t.Fatalf("%q admits nothing: %s", raw, g.Admits)
				}
				if g.Effect != trust.Allow {
					t.Fatalf("%q: effect %q", raw, g.Effect)
				}
				if !g.Exact() {
					inexact++
				}
				for _, term := range g.Admits.Terms() {
					for k, s := range term {
						if eval.IsUnknown(s) && !hasCaveatOn(g.Admits.Caveats(), k) {
							t.Fatalf("%q: %s is Unknown without a caveat", raw, k)
						}
					}
				}
				if !slices.Equal(g.Anomalies, canonical(g.Anomalies)) {
					t.Fatalf("%q: anomalies are not canonical: %v", raw, g.Anomalies)
				}
				if x, y := fingerprint(g), fingerprint(again[i].Grants(infraApp)[0]); x != y {
					t.Fatalf("%q parsed differently twice:\n%s\n---\n%s", raw, x, y)
				}
				prints = append(prints, fingerprint(g))
			}
			return strings.Join(prints, "\n===\n")
		}
		examine(rapid.SliceOfN(rapid.Byte(), 0, 64).Draw(t, "bytes"))
		intact := genAnyDocument().Draw(t, "doc").json()
		said := examine(intact)
		worse, kind := damage(t, intact)
		if examine(worse) != said {
			noticed[kind]++
		}
	})
	if parsed == 0 || refused == 0 || inexact == 0 {
		t.Fatalf("parsed %d, refused %d, inexact %d; every count must be positive", parsed, refused, inexact)
	}
	// Every kind of damage must have changed what the parser said at least
	// once, or the property was never tried on that way of breaking a
	// document: a damage function that stopped drawing a kind, or drew it
	// and left the document intact, would pass everything above.
	for _, kind := range damageKinds {
		if noticed[kind] == 0 {
			t.Errorf("damage %q never changed what the parser said", kind)
		}
	}
	t.Logf("parsed %d, refused %d, inexact %d, damage noticed %v", parsed, refused, inexact, noticed)
}

// TestMonotonicityOfIgnorance: a construct the parser does not model can
// only widen what it reports. Every corruption of a clean document, and
// the removal of any clause from it, admits every token the clean parse
// admits. The property is stated from the exact base outwards, because the
// converse direction, removing a clause from a document that already holds
// something unmodelled, legitimately narrows: removing the second of two
// clauses on one claim turns an Unknown back into the first clause's value.
func TestMonotonicityOfIgnorance(t *testing.T) {
	admitted, removed := 0, 0
	reached := map[string]int{}
	rapid.Check(t, func(t *rapid.T) {
		base := genClean().Draw(t, "base")
		g := parseSpec(t, base)
		if !g.Exact() {
			t.Fatalf("a clean document parsed inexactly: %s -> %v", base.expression(), g.Admits.Caveats())
		}
		for _, kind := range slices.Sorted(maps.Keys(corruptions)) {
			worse := corrupt(t, base, kind)
			w := parseSpec(t, worse)
			for _, a := range w.Anomalies {
				if factOf(t, a) == corruptions[kind] {
					reached[kind]++
				}
			}
			for _, tok := range genTokens(t, base, worse) {
				if !g.Admits.Admits(tok) {
					continue
				}
				admitted++
				if !w.Admits.Admits(tok) {
					t.Fatalf("corruption %q narrowed the grant:\n  %s admits %v\n  %s does not\n  document %s", kind, g.Admits, tok, w.Admits, worse.json())
				}
			}
		}
		if len(base.clauses) > 1 {
			removed++
			fewer := base
			at := rapid.IntRange(0, len(base.clauses)-1).Draw(t, "remove")
			fewer.clauses = slices.Delete(slices.Clone(base.clauses), at, at+1)
			f := parseSpec(t, fewer)
			for _, tok := range genTokens(t, base) {
				if g.Admits.Admits(tok) && !f.Admits.Admits(tok) {
					t.Fatalf("removing a clause narrowed the grant: %s admits %v, %s does not", g.Admits, tok, f.Admits)
				}
			}
		}
	})
	if admitted == 0 || removed == 0 {
		t.Fatalf("admitted %d tokens, removed %d clauses; both must be positive", admitted, removed)
	}
	// Every corruption must have made the parser record the fact it exists
	// for, or the property was never tried on that way of failing.
	for kind, fact := range corruptions {
		if reached[kind] == 0 {
			t.Errorf("corruption %q never reached %q", kind, fact)
		}
	}
	t.Logf("checked %d admitted tokens against every corruption, removed a clause %d times, reached %v", admitted, removed, reached)
}

// TestClauseOrderInvariance: reordering the clauses of an expression gives
// an identical Grant, facts included, whatever the clauses hold. At most
// one clause carries a stray quote: with one, the expression is judged as a
// whole by its quote count, which no order changes; with two, the text
// between them is one quoted region in one order and two clauses in
// another, so the document has no clause structure to reorder, and what
// the parser names as the broken piece is a fact about the text, not about
// the clauses.
func TestClauseOrderInvariance(t *testing.T) {
	reordered, stray := 0, 0
	rapid.Check(t, func(t *rapid.T) {
		d := genDocument().Draw(t, "doc")
		if len(d.clauses) < 2 {
			d.clauses = rapid.SliceOfN(genClause(), 2, 4).Draw(t, "clauses")
		}
		d.connective = " and "
		seen := false
		for i, c := range d.clauses {
			if !strayQuote(c) {
				continue
			}
			if seen {
				d.clauses[i].comparand = "a"
				continue
			}
			seen = true
			stray++
		}
		shuffled := d
		shuffled.clauses = rapid.Permutation(slices.Clone(d.clauses)).Draw(t, "order")
		if !slices.Equal(shuffled.clauses, d.clauses) {
			reordered++
		}
		if x, y := fingerprint(parseSpec(t, d)), fingerprint(parseSpec(t, shuffled)); x != y {
			t.Fatalf("clause order changed the grant:\n%s\n---\n%s\n  %s\n  %s", x, y, d.expression(), shuffled.expression())
		}
	})
	if reordered == 0 || stray == 0 {
		t.Fatalf("reordered %d, with a stray quote %d; both must be positive", reordered, stray)
	}
	t.Logf("exercised on %d reorderings, %d with a stray quote", reordered, stray)
}

// TestSubjectAndExpressionNeverNarrower: a document that sets both, which
// Microsoft says cannot exist, admits every token that either alone would.
// The empty subject is left out: it is no subject, so alone it is read as
// an unknown constraint, wider than the expression that stands alone
// beside it.
func TestSubjectAndExpressionNeverNarrower(t *testing.T) {
	bySubject, byExpression := 0, 0
	rapid.Check(t, func(t *rapid.T) {
		d := genDocument().Draw(t, "doc")
		if d.subject == nil || *d.subject == "" {
			d.subject = ptr(rapid.StringOfN(rapid.RuneFrom([]rune("ab:/")), 1, 8, -1).Draw(t, "subject"))
		}
		if d.clauses == nil {
			d.clauses = rapid.SliceOfN(genClause(), 1, 3).Draw(t, "clauses")
		}
		both := parseSpec(t, d)
		if both.Exact() {
			t.Fatalf("both set must caveat the grant: %s", d.json())
		}
		subjectOnly, expressionOnly := d, d
		subjectOnly.clauses = nil
		expressionOnly.subject = nil
		s, e := parseSpec(t, subjectOnly), parseSpec(t, expressionOnly)
		for _, tok := range genTokens(t, d) {
			if s.Admits.Admits(tok) {
				bySubject++
				if !both.Admits.Admits(tok) {
					t.Fatalf("both set is narrower than the subject alone: %s rejects %v that %s admits", both.Admits, tok, s.Admits)
				}
			}
			if e.Admits.Admits(tok) {
				byExpression++
				if !both.Admits.Admits(tok) {
					t.Fatalf("both set is narrower than the expression alone: %s rejects %v that %s admits", both.Admits, tok, e.Admits)
				}
			}
		}
	})
	if bySubject == 0 || byExpression == 0 {
		t.Fatalf("subject alone admitted %d tokens, expression alone %d; both must be positive", bySubject, byExpression)
	}
	t.Logf("exercised on %d tokens by subject, %d by expression", bySubject, byExpression)
}

// TestResourceEnvelopeIsTransparent: a credential states the same Grant
// whether it arrives as a Graph object or under the properties of a
// Resource Manager resource; the envelope labels the credential and is
// otherwise nothing to the Grant.
func TestResourceEnvelopeIsTransparent(t *testing.T) {
	compared := 0
	rapid.Check(t, func(t *rapid.T) {
		bare := genDocument().Draw(t, "doc")
		bare.envelope = false
		wrapped := bare
		wrapped.envelope = true
		compared++
		if x, y := fingerprint(parseSpec(t, bare)), fingerprint(parseSpec(t, wrapped)); x != y {
			t.Fatalf("the envelope changed the grant:\n%s\n---\n%s", x, y)
		}
	})
	if compared == 0 {
		t.Fatalf("compared nothing")
	}
	t.Logf("compared %d documents with their enveloped form", compared)
}

// namedConstructs are the constructs an unmodelled-construct anomaly names
// by a fixed phrase; the rest name the operator, the claim lookup, the
// issuer or the language version the document wrote.
var namedConstructs = []string{"repeated claim", "escaped quote", "empty comparand", "unbalanced quote", "empty clause", "empty expression", "unparseable clause", "missing required claim", "clause count", "empty audience"}

// factOf names what an anomaly records, finer than its Kind where one kind
// carries several facts, by the construct it names, so that the guards
// below count each separately.
func factOf(t *rapid.T, a trust.Anomaly) string {
	switch {
	case a.Kind == "audience-count":
		return a.Kind + " " + strings.SplitN(a.Message, ";", 2)[0]
	case a.Kind != trust.Unmodelled:
		return a.Kind
	case slices.Contains(namedConstructs, a.Construct):
		return a.Construct
	case strings.HasPrefix(a.Construct, "claims['"):
		return "undocumented claim"
	case strings.HasPrefix(a.Construct, `"`):
		return "undocumented issuer"
	case a.Source == "claimsMatchingExpression.languageVersion":
		return "language version"
	case isOperatorWord(a.Construct):
		return "undocumented operator"
	}
	t.Fatalf("an anomaly no category names: %+v", a)
	return ""
}

// isOperatorWord reports whether a construct is spelt the way the grammar
// spells an operator: ASCII letters and nothing else.
func isOperatorWord(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !isASCIILetter(s[i]) {
			return false
		}
	}
	return true
}

// TestGeneratorIsNotStale guards the guards: every fact the parser can
// record must be drawn by genDocument, or the properties above pass over
// documents that never exercise it. Where two document shapes record the
// same fact, an absent audiences member and an empty list, the shapes are
// counted too, since each is its own path through the parser. Several
// documents are drawn per example so that the rarest fact, an empty
// subject with no expression at four draws in a hundred, is missed by a
// whole run with negligible odds.
func TestGeneratorIsNotStale(t *testing.T) {
	seen := map[string]int{}
	rapid.Check(t, func(t *rapid.T) {
		for _, d := range rapid.SliceOfN(genDocument(), 5, 5).Draw(t, "docs") {
			switch {
			case d.audiences == nil:
				seen["audiences absent"]++
			case len(d.audiences) == 0:
				seen["audiences empty"]++
			}
			if d.envelope {
				seen["envelope"]++
			}
			g := parseSpec(t, d)
			if g.Exact() {
				seen["exact"]++
			}
			for _, a := range g.Anomalies {
				seen[factOf(t, a)]++
			}
		}
	})
	for _, want := range []string{
		"exact", "envelope", "repeated claim", "escaped quote", "unbalanced quote", "empty comparand", "empty clause", "language version", "unparseable clause",
		"undocumented claim", "undocumented operator", "undocumented issuer", "undocumented-acceptance", "claim-folded", "missing required claim", "clause count",
		"audiences absent", "audiences empty", "empty audience", "audience-count no audience is set", "audience-count 2 audiences are set",
		"audience-count 257 audiences are set",
		"no-subject-constraint", "empty-subject",
		"missing-issuer", "issuer-whitespace", "issuer-scheme", "subject-and-expression",
	} {
		if seen[want] == 0 {
			t.Errorf("the generator never produced %q", want)
		}
	}
	t.Logf("drew %v", seen)
}
