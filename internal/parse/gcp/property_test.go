package gcp

import (
	"maps"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/CloudArq-net/cloudarq/internal/eval"
	"github.com/CloudArq-net/cloudarq/internal/trust"
	"pgregory.net/rapid"
)

type claims = map[trust.ClaimKey]string

// The references a generated clause may name, and the claim each reaches
// under the generated mapping: three assertion fields, the subject and an
// attribute mapped to a field, an attribute mapped by an expression, an
// attribute the mapping leaves out, and the groups.
// assertion.namespace is a field spelt with one of CEL's reserved words,
// which is a claim name like any other after a dot.
var (
	references  = []string{"assertion.sub", "assertion.sub", "assertion.repository_id", "assertion.repository", "assertion.namespace", "google.subject", "attribute.repository", "attribute.org", "attribute.missing"}
	claimFor    = map[string]trust.ClaimKey{"assertion.sub": "sub", "assertion.repository_id": "repository_id", "assertion.repository": "repository", "assertion.namespace": "namespace", "google.subject": "sub", "attribute.repository": "repository"}
	bareMapping = map[string]string{"google.subject": "assertion.sub", "google.groups": "assertion.groups", "attribute.repository": "assertion.repository", "attribute.org": "assertion.repository.extract('{org}/')"}
)

// modelledKinds are the clause shapes the subset models exactly on an
// attributable reference; unmodelledKinds each widen one thing and record
// one fact, named by factOf.
var (
	modelledKinds   = []string{"eq", "in", "startsWith", "endsWith", "contains", "raw"}
	unmodelledKinds = []string{"neq", "lt", "matches", "extract", "wildcard", "emptyPrefix", "nonString", "bytes", "inNotList", "inEmpty", "inNonString", "group", "groupsCompared", "has", "nested", "index", "truth", "ternary", "literal", "unknownRoot", "bareAssertion", "noClaim", "arith", "listCap", "chained", "crLiteral"}
	literalKinds    = []string{"true", "false"}
	// limitedKinds are modelled exactly and, on the claim google.subject
	// maps to, write a value Google issues no identity for.
	limitedKinds = []string{"longSubject"}
)

type clause struct {
	kind   string
	ref    string
	values []string
}

func quoteCEL(v string) string { return "'" + v + "'" }

// text renders the clause as CEL.
func (c clause) text() string {
	v := c.values[0]
	switch c.kind {
	case "eq":
		return c.ref + " == " + quoteCEL(v)
	case "raw":
		return c.ref + " == r" + quoteCEL(v)
	case "in":
		quoted := make([]string, len(c.values))
		for i, v := range c.values {
			quoted[i] = quoteCEL(v)
		}
		return c.ref + " in [" + strings.Join(quoted, ", ") + "]"
	case "startsWith", "endsWith", "contains":
		return c.ref + "." + c.kind + "(" + quoteCEL(v) + ")"
	case "neq":
		return c.ref + " != " + quoteCEL(v)
	case "lt":
		return c.ref + " < " + quoteCEL(v)
	case "matches":
		return c.ref + ".matches('^" + v + "')"
	case "extract":
		return c.ref + ".extract('{x}/') == " + quoteCEL(v)
	case "wildcard":
		return c.ref + ".startsWith(" + quoteCEL(v+"*") + ")"
	case "emptyPrefix":
		return c.ref + ".startsWith('')"
	case "nonString":
		return c.ref + " == 1"
	case "bytes":
		return c.ref + " == b" + quoteCEL(v)
	case "inNotList":
		return c.ref + " in assertion.list"
	case "inEmpty":
		return c.ref + " in []"
	case "inNonString":
		return c.ref + " in [" + quoteCEL(v) + ", 1]"
	case "group":
		return quoteCEL(v) + " in google.groups"
	case "groupsCompared":
		return "google.groups == " + quoteCEL(v)
	case "chained":
		return "(" + c.ref + " == " + quoteCEL(v) + ") == true"
	case "crLiteral":
		return c.ref + " == '''" + v + "\r\n'''"
	case "has":
		return "has(" + c.ref + ")"
	case "nested":
		return c.ref + ".x == " + quoteCEL(v)
	case "index":
		return c.ref + "['x'] == " + quoteCEL(v)
	case "truth":
		return c.ref
	case "ternary":
		return "(" + c.ref + " == " + quoteCEL(v) + " ? true : false)"
	case "literal":
		return "1"
	case "unknownRoot":
		return "request.x == " + quoteCEL(v)
	case "bareAssertion":
		return "assertion == " + quoteCEL(v)
	case "noClaim":
		return "'a' == 'a'"
	case "arith":
		return c.ref + " + 'x' == " + quoteCEL(v)
	case "listCap":
		values := make([]string, listCap+1)
		for i := range values {
			values[i] = "'v" + strconv.Itoa(i) + "'"
		}
		return c.ref + " in [" + strings.Join(values, ",") + "]"
	case "longSubject":
		return c.ref + " == " + quoteCEL(v+strings.Repeat("x", subjectLimit))
	case "verbatim":
		return v
	}
	return c.kind // true, false
}

func genValue() *rapid.Generator[string] {
	return rapid.StringOfN(rapid.RuneFrom([]rune("ab:/")), 1, 5, -1)
}

func genClause(kinds []string) *rapid.Generator[clause] {
	return rapid.Custom(func(t *rapid.T) clause {
		c := clause{kind: rapid.SampledFrom(kinds).Draw(t, "kind"), ref: rapid.SampledFrom(references).Draw(t, "ref")}
		c.values = rapid.SliceOfN(genValue(), 1, 3).Draw(t, "values")
		return c
	})
}

// tree is a generated condition: leaves joined by the connectives, with
// every binary node parenthesised when rendered so that a permutation of
// its operands is the same tree reordered, never a different grouping.
type tree struct {
	op   string // "&&", "||", "!", or "" for a leaf
	kids []*tree
	leaf clause
}

func (n *tree) text() string {
	switch n.op {
	case "":
		return n.leaf.text()
	case "!":
		return "!(" + n.kids[0].text() + ")"
	}
	return "(" + n.kids[0].text() + " " + n.op + " " + n.kids[1].text() + ")"
}

func (n *tree) leaves() []clause {
	if n.op == "" {
		return []clause{n.leaf}
	}
	var out []clause
	for _, k := range n.kids {
		out = append(out, k.leaves()...)
	}
	return out
}

func (n *tree) hasNotOverCompound() bool {
	if n.op == "!" && n.kids[0].op != "" {
		return true
	}
	for _, k := range n.kids {
		if k.hasNotOverCompound() {
			return true
		}
	}
	return false
}

func genTree(kinds []string, depth int) *rapid.Generator[*tree] {
	return rapid.Custom(func(t *rapid.T) *tree {
		if depth == 0 || rapid.IntRange(0, 2).Draw(t, "leaf") == 0 {
			return &tree{leaf: genClause(kinds).Draw(t, "clause")}
		}
		switch rapid.IntRange(0, 4).Draw(t, "op") {
		case 0:
			return &tree{op: "!", kids: []*tree{genTree(kinds, depth-1).Draw(t, "operand")}}
		case 1, 2:
			return &tree{op: "||", kids: []*tree{genTree(kinds, depth-1).Draw(t, "left"), genTree(kinds, depth-1).Draw(t, "right")}}
		}
		return &tree{op: "&&", kids: []*tree{genTree(kinds, depth-1).Draw(t, "left"), genTree(kinds, depth-1).Draw(t, "right")}}
	})
}

// documentSpec is a generated provider document. Every shape the parser
// tells apart is drawn: the union member, the name forms the default
// audience depends on, the states and the disabled flag, the mapping,
// the condition, the audiences, the proto spelling of member names, a
// member written twice or in the wrong case, and the list envelope.
type documentSpec struct {
	kind         string // oidc, aws, saml, x509, none, two
	name         string // "" for absent
	state        string
	disabled     string // "" absent, or the JSON value
	mapping      string // "" absent, "bare", "expression", "duplicate", "unknownKey", "wrongType", "list", "empty"
	condition    *tree
	conditionDup bool
	audiences    string // "absent", "one", "eleven", "cap", "empty", "emptyString", "wrongType", "miscased"
	issuer       string
	snake        bool
	miscased     bool
	envelope     string // "", "list", "page", "bare"
	blank        bool   // a whitespace condition
	overlong     bool
}

func genDocument() *rapid.Generator[documentSpec] {
	return rapid.Custom(func(t *rapid.T) documentSpec {
		d := documentSpec{
			kind:      rapid.SampledFrom([]string{"oidc", "oidc", "oidc", "oidc", "aws", "saml", "x509", "none", "two"}).Draw(t, "kind"),
			name:      rapid.SampledFrom([]string{providerName, providerName, "projects/acme-prod/locations/global/workloadIdentityPools/github/providers/github", "", "x"}).Draw(t, "name"),
			state:     rapid.SampledFrom([]string{"", "", "ACTIVE", "DELETED", "STATE_UNSPECIFIED", "SUSPENDED"}).Draw(t, "state"),
			disabled:  rapid.SampledFrom([]string{"", "", "true", "false", `"true"`}).Draw(t, "disabled"),
			mapping:   rapid.SampledFrom([]string{"", "bare", "bare", "bare", "expression", "duplicate", "unknownKey", "wrongType", "list", "empty"}).Draw(t, "mapping"),
			audiences: rapid.SampledFrom([]string{"absent", "one", "one", "one", "eleven", "cap", "empty", "emptyString", "wrongType", "miscased"}).Draw(t, "audiences"),
			issuer:    rapid.SampledFrom([]string{string(github), string(github), "https://gitlab.com", "http://gitlab.com", "", "https://"}).Draw(t, "issuer"),
			envelope:  rapid.SampledFrom([]string{"", "", "", "list", "page", "bare"}).Draw(t, "envelope"),
		}
		switch rapid.IntRange(0, 6).Draw(t, "condition") {
		case 0:
		case 1:
			d.blank = true
		case 2:
			// A condition that admits nobody, which a document can state
			// and a parser must report as proven, not as a doubt.
			d.condition = &tree{leaf: clause{kind: "false", values: []string{""}}}
		default:
			d.condition = genTree(slices.Concat(modelledKinds, unmodelledKinds, literalKinds, limitedKinds), 3).Draw(t, "tree")
		}
		d.conditionDup = rapid.IntRange(0, 14).Draw(t, "conditionDup") == 0
		d.snake = rapid.IntRange(0, 3).Draw(t, "snake") == 0
		d.miscased = rapid.IntRange(0, 14).Draw(t, "miscased") == 0
		d.overlong = rapid.IntRange(0, 29).Draw(t, "overlong") == 0
		return d
	})
}

// pair is one JSON object member, kept as a pair so that a document can
// hold a name twice.
type pair struct{ name, value string }

func object(members ...pair) string {
	parts := make([]string, len(members))
	for i, m := range members {
		parts[i] = strconv.Quote(m.name) + ": " + m.value
	}
	return "{" + strings.Join(parts, ", ") + "}"
}

func (d documentSpec) spell(camel, snake string) string {
	if d.snake {
		return snake
	}
	return camel
}

func (d documentSpec) conditionText() string {
	if d.blank {
		return " "
	}
	if d.condition == nil {
		return ""
	}
	text := d.condition.text()
	if d.overlong {
		text += " && assertion.sub == '" + strings.Repeat("x", conditionLimit) + "'"
	}
	return text
}

func (d documentSpec) mappingJSON() string {
	switch d.mapping {
	case "bare":
		return string(mustJSON(bareMapping))
	case "expression":
		m := maps.Clone(bareMapping)
		m["attribute.repository"] = "assertion.repository.extract('{org}/')"
		m["google.subject"] = "assertion.sub.extract('repo:{owner}/')"
		return string(mustJSON(m))
	case "duplicate":
		return `{"google.subject": "assertion.sub", "google.subject": "assertion.sub", "attribute.repository": "assertion.repository", "attribute.repository": "assertion.x"}`
	case "unknownKey":
		return `{"google.subject": "assertion.sub", "foo": "assertion.sub"}`
	case "wrongType":
		return `{"google.subject": 1, "attribute.repository": "assertion.repository"}`
	case "list":
		return `[]`
	}
	return `{}`
}

func (d documentSpec) audiencesJSON() string {
	switch d.audiences {
	case "one":
		return string(mustJSON([]string{audienceName}))
	case "eleven":
		return string(mustJSON(append([]string{audienceName}, numbered(10)...)))
	case "cap":
		return string(mustJSON(append([]string{audienceName}, numbered(audienceCap)...)))
	case "empty":
		return `[]`
	case "emptyString":
		return `["` + audienceName + `", ""]`
	case "wrongType":
		return `["x", 1]`
	case "miscased":
		return string(mustJSON([]string{audienceName}))
	}
	return ""
}

func numbered(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = "aud" + strconv.Itoa(i)
	}
	return out
}

// provider renders the provider object alone.
func (d documentSpec) provider() string {
	var ms []pair
	if d.name != "" {
		ms = append(ms, pair{"name", strconv.Quote(d.name)})
	}
	if d.state != "" {
		ms = append(ms, pair{"state", strconv.Quote(d.state)})
	}
	if d.disabled != "" {
		ms = append(ms, pair{"disabled", d.disabled})
	}
	if d.mapping != "" {
		ms = append(ms, pair{d.spell("attributeMapping", "attribute_mapping"), d.mappingJSON()})
	}
	if text := d.conditionText(); text != "" {
		ms = append(ms, pair{d.spell("attributeCondition", "attribute_condition"), strconv.Quote(text)})
		if d.conditionDup {
			ms = append(ms, pair{"attributeCondition", strconv.Quote("assertion.sub == 'dup'")})
		}
	}
	if d.miscased {
		ms = append(ms, pair{"AttributeCondition", `"assertion.sub == 'x'"`})
	}
	oidc := func() pair {
		var inner []pair
		if d.issuer != "" {
			inner = append(inner, pair{d.spell("issuerUri", "issuer_uri"), strconv.Quote(d.issuer)})
		}
		if a := d.audiencesJSON(); a != "" {
			name := d.spell("allowedAudiences", "allowed_audiences")
			if d.audiences == "miscased" {
				name = d.spell("AllowedAudiences", "Allowed_audiences")
			}
			inner = append(inner, pair{name, a})
		}
		return pair{"oidc", object(inner...)}
	}
	switch d.kind {
	case "oidc":
		ms = append(ms, oidc())
	case "aws":
		ms = append(ms, pair{"aws", `{"accountId": "123456789012"}`})
	case "saml":
		ms = append(ms, pair{"saml", `{"idpMetadataXml": "<x/>"}`})
	case "x509":
		ms = append(ms, pair{"x509", `{"trustStore": {"trustAnchors": [{"pemCertificate": "x"}]}}`})
	case "two":
		ms = append(ms, oidc(), pair{"aws", `{"accountId": "123456789012"}`})
	}
	if len(ms) == 0 {
		ms = append(ms, pair{"attributeCondition", `"true"`})
	}
	return object(ms...)
}

func (d documentSpec) json() []byte {
	p := d.provider()
	switch d.envelope {
	case "list":
		return []byte(object(pair{d.spell("workloadIdentityPoolProviders", "workload_identity_pool_providers"), "[" + p + "]"}))
	case "page":
		return []byte(object(pair{"workloadIdentityPoolProviders", "[" + p + "]"}, pair{d.spell("nextPageToken", "next_page_token"), `"CAE="`}))
	case "bare":
		return []byte("[" + p + "]")
	}
	return []byte(p)
}

// factOf names what an anomaly records, finer than its Kind where one
// kind carries several facts, so that the guards below count each. It is
// total over the sentences the parser can write, damage included: a
// sentence no category names is a sentence this test has not seen, and
// it fails rather than counting it as something else.
func factOf(t *rapid.T, a trust.Anomaly) string {
	m := a.Message
	switch {
	case a.Kind == DefaultAudience:
		if strings.Contains(m, "cannot be derived") {
			return "default audience underivable"
		}
		return "default audience derived"
	case a.Kind == AudienceCount:
		if strings.Contains(m, "this parser reads at most") {
			return "audience cap"
		}
		return "audience count"
	case a.Kind == Malformed && strings.HasPrefix(m, "attributeMapping key"):
		return "unknown mapping key"
	case a.Kind == MissingIssuer && a.Construct == "provider_config":
		return "no provider config"
	case a.Kind != trust.Unmodelled:
		return a.Kind
	case a.Source == "state":
		return "unknown state"
	case a.Construct == "group":
		return "group member"
	case a.Construct == "%" && strings.Contains(m, "names the pool"):
		return "percent escape in the pool"
	case a.Construct == "%" && strings.Contains(m, "selects from the pool by"):
		return "percent escape in the selector"
	case a.Construct == "%" && strings.Contains(m, "holds a percent escape in the host"):
		return "percent escape in the fixed text"
	case a.Construct == "%":
		return "percent escape in the value"
	case a.Construct == "spelling":
		return "respelt member"
	case strings.Contains(m, "and no other form, so whether Google accepts the member"):
		return "undocumented selector"
	case a.Construct == "pool":
		return "pool project"
	case a.Construct == "name":
		return "unplaceable provider"
	case a.Construct == "condition":
		return "binding condition"
	case a.Construct == "provider_config":
		return "two provider configs"
	case a.Construct == "saml", a.Construct == "x509", a.Construct == "unparseable expression", a.Construct == "expression length", a.Construct == "empty audience", a.Construct == "has", a.Construct == "?", a.Construct == "carriage return":
		return a.Construct
	case strings.Contains(m, "a condition written as"):
		return "condition as operand"
	case strings.Contains(m, "Google documents as the set of groups"):
		return "set-valued attribute"
	case strings.Contains(m, "but the attribute mapping is not read"):
		return "unread mapping"
	case a.Construct == "!":
		if strings.Contains(m, "negates a comparison") {
			return "not comparison"
		}
		return "not expression"
	case strings.Contains(m, "which this parser's patterns read as a wildcard"):
		return "wildcard"
	case strings.Contains(m, "this parser cannot express presence"):
		return "empty prefix"
	case strings.Contains(m, "that is not a string literal, so"):
		return "non-literal prefix"
	case strings.Contains(m, "arguments, not the one string it takes"):
		return "arity"
	case strings.Contains(m, "a list-valued claim"):
		return "group membership"
	case strings.Contains(m, "membership of an empty list"):
		return "empty list"
	case strings.Contains(m, "values; this parser reads at most"):
		return "list cap"
	case strings.Contains(m, "not a list of string literals"):
		return "list not literal"
	case strings.Contains(m, "is not a string literal, so"):
		return "non-string comparand"
	case strings.Contains(m, "tests the truth of"):
		return "truth"
	case strings.Contains(m, "a field inside"):
		return "nested field"
	case strings.Contains(m, "with the operator"):
		return "operator " + a.Construct
	case strings.Contains(m, "with the function"):
		return "function " + a.Construct
	case strings.Contains(m, ", which this parser does not model, so"):
		return "nested construct"
	case strings.Contains(m, "is the literal"):
		return "literal"
	case strings.Contains(m, "operands that name no claim"), strings.Contains(m, "an operand that names no claim"):
		return "no claim " + a.Construct
	case strings.HasSuffix(m, "names no claim, so nothing it says about the credential is modelled"):
		return "no claim"
	case strings.Contains(m, "the keywords Google documents"):
		return "unknown root"
	case strings.Contains(m, "without naming a field"):
		return "bare assertion"
	case strings.Contains(m, "maps by the expression"):
		return "expression mapping"
	case strings.Contains(m, "not an expression this parser can read"):
		return "unreadable mapping"
	case strings.Contains(m, "does not map"):
		return "unmapped"
	case strings.Contains(m, " times, so which claim"):
		return "duplicate mapping"
	case strings.Contains(m, "not a string, so"):
		return "wrong-type mapping"
	case strings.Contains(m, "but the provider"):
		return "unattributable kind"
	}
	t.Fatalf("an anomaly no category names: %+v", a)
	return ""
}

// examine checks what every parse must satisfy on one grant: no Unknown
// without a caveat, canonical anomalies, and that emptiness is explained
// by the document. It returns the fingerprint.
func examine(t *rapid.T, g trust.Grant, mayBeEmpty bool) string {
	if g.Effect != trust.Allow {
		t.Fatalf("effect %q", g.Effect)
	}
	if g.Admits.IsEmpty() && !mayBeEmpty {
		t.Fatalf("admits nothing without a false literal or a claim constrained twice: %s", g.Source)
	}
	for _, term := range g.Admits.Terms() {
		for k, s := range term {
			if eval.IsUnknown(s) && !hasCaveatOn(g.Admits.Caveats(), k) {
				t.Fatalf("%s is Unknown without a caveat: %s", k, g.Source)
			}
		}
	}
	if !slices.Equal(g.Anomalies, canonical(g.Anomalies)) {
		t.Fatalf("anomalies are not canonical: %v", g.Anomalies)
	}
	for _, a := range g.Anomalies {
		factOf(t, a)
		if a.Message == "" || a.Construct == "" || a.Source == "" || a.Kind == "" {
			t.Fatalf("an anomaly with an empty field: %+v", a)
		}
	}
	return fingerprint(g)
}

// mayBeEmpty reports whether the generated condition can admit nobody by
// its own logic: a false literal, or one claim compared twice, which under
// && can contradict.
func (d documentSpec) mayBeEmpty() bool {
	if d.condition == nil {
		return false
	}
	seen := map[trust.ClaimKey]int{}
	for _, c := range d.condition.leaves() {
		if c.kind == "false" {
			return true
		}
		if slices.Contains(modelledKinds, c.kind) || slices.Contains(limitedKinds, c.kind) {
			seen[claimFor[c.ref]]++
		}
	}
	for _, n := range seen {
		if n > 1 {
			return true
		}
	}
	return false
}

// damageKinds are the ways damage makes a document worse, each of which
// the totality property must be seen to try.
var damageKinds = []string{"truncated", "byte overwritten", "trailing bytes", "member duplicated"}

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
	return slices.Concat([]byte(`{"state": "DELETED", `), out[1:]), damageKinds[3]
}

// TestTotalityOverArbitraryBytes: the parser never panics, refuses only
// what is not a provider document, states one Grant per provider, and
// comes out identical on a second reading; every kind of damage is seen
// to change what the parser said.
func TestTotalityOverArbitraryBytes(t *testing.T) {
	parsed, refused, inexact, empty := 0, 0, 0, 0
	noticed := map[string]int{}
	rapid.Check(t, func(t *rapid.T) {
		read := func(raw []byte, mayBeEmpty bool) string {
			providers, err := ParseProviders(raw)
			if err != nil {
				refused++
				if providers != nil {
					t.Fatalf("an error came with providers")
				}
				if _, err := ParseProvider(raw); err == nil {
					t.Fatalf("the singular parse accepted what the plural refused: %q", raw)
				}
				if _, err := ParsePage(raw); err == nil && !strings.Contains(string(raw), "PageToken") && !strings.Contains(string(raw), "page_token") {
					t.Fatalf("ParsePage accepted what ParseProviders refused: %q", raw)
				}
				return "refused: " + err.Error()
			}
			parsed++
			again, err := ParseProviders(raw)
			if err != nil {
				t.Fatalf("second parse: %v", err)
			}
			var prints []string
			for i, p := range providers {
				grants := p.Grants(githubProvider)
				if len(grants) != 1 {
					t.Fatalf("%d grants, want 1", len(grants))
				}
				g := grants[0]
				if !g.Exact() {
					inexact++
				}
				if g.Admits.IsEmpty() {
					empty++
				}
				print := examine(t, g, mayBeEmpty)
				if print != fingerprint(again[i].Grants(githubProvider)[0]) {
					t.Fatalf("parsed differently twice: %s", raw)
				}
				prints = append(prints, print)
			}
			return strings.Join(prints, "\n===\n")
		}
		read(rapid.SliceOfN(rapid.Byte(), 0, 64).Draw(t, "bytes"), true)
		for _, d := range rapid.SliceOfN(genDocument(), 4, 4).Draw(t, "docs") {
			intact := d.json()
			said := read(intact, d.mayBeEmpty())
			worse, kind := damage(t, intact)
			if read(worse, true) != said {
				noticed[kind]++
			}
		}
	})
	if parsed == 0 || refused == 0 || inexact == 0 || empty == 0 {
		t.Fatalf("parsed %d, refused %d, inexact %d, empty %d; every count must be positive", parsed, refused, inexact, empty)
	}
	for _, kind := range damageKinds {
		if noticed[kind] == 0 {
			t.Errorf("damage %q never changed what the parser said", kind)
		}
	}
	t.Logf("parsed %d, refused %d, inexact %d, empty %d, damage noticed %v", parsed, refused, inexact, empty, noticed)
}

// genClean draws a document every clause of which the subset models: an
// OIDC provider with the bare mapping, one audience, and a conjunction of
// modelled clauses on distinct claims, so that its parse is exact and
// non-empty: a base to corrupt.
func genClean() *rapid.Generator[documentSpec] {
	return rapid.Custom(func(t *rapid.T) documentSpec {
		refs := rapid.SliceOfNDistinct(rapid.SampledFrom([]string{"assertion.sub", "assertion.repository_id", "assertion.repository", "assertion.namespace"}), 1, 4, func(r string) string { return r }).Draw(t, "refs")
		var n *tree
		mapped := map[string]string{"assertion.sub": "google.subject", "assertion.repository": "attribute.repository"}
		for _, ref := range refs {
			if alt, ok := mapped[ref]; ok && rapid.Bool().Draw(t, "mapped") {
				ref = alt
			}
			leaf := &tree{leaf: clause{kind: rapid.SampledFrom(modelledKinds).Draw(t, "kind"), ref: ref, values: rapid.SliceOfN(genValue(), 1, 3).Draw(t, "values")}}
			if n == nil {
				n = leaf
			} else {
				n = &tree{op: "&&", kids: []*tree{n, leaf}}
			}
		}
		return documentSpec{kind: "oidc", name: providerName, mapping: "bare", condition: n, audiences: "one", issuer: string(github), snake: rapid.Bool().Draw(t, "snake")}
	})
}

// corruptions are the ways a clause, or the document around it, can leave
// the modelled subset, each named with the fact it exists to make the
// parser record. Each must widen, never narrow, and each must be seen to
// reach its fact.
var corruptions = map[string]string{
	"neq":               "operator !=",
	"lt":                "operator <",
	"matches":           "function matches",
	"extract":           "function extract",
	"wildcard":          "wildcard",
	"emptyPrefix":       "empty prefix",
	"nonString":         "non-string comparand",
	"bytes":             "non-string comparand",
	"inNotList":         "list not literal",
	"inEmpty":           "empty list",
	"inNonString":       "list not literal",
	"group":             "group membership",
	"groupsCompared":    "set-valued attribute",
	"chained":           "condition as operand",
	"crLiteral":         "carriage return",
	"has":               "has",
	"nested":            "nested field",
	"index":             "nested field",
	"truth":             "truth",
	"ternary":           "?",
	"literal":           "literal",
	"unknownRoot":       "unknown root",
	"bareAssertion":     "bare assertion",
	"noClaim":           "no claim ==",
	"arith":             "operator +",
	"listCap":           "list cap",
	"not":               "not comparison",
	"notConjunction":    "not expression",
	"orUnmodelled":      "operator !=",
	"exprMapped":        "expression mapping",
	"unmapped":          "unmapped",
	"unparseable":       "unparseable expression",
	"overlong":          "expression length",
	"conditionDup":      DuplicateKey,
	"miscased":          MiscasedKey,
	"miscasedAudiences": MiscasedKey,
	"mappingUnread":     "unread mapping",
	"disabled":          ProviderDisabled,
	"deleted":           ProviderDeleted,
	"unknownState":      "unknown state",
	"noAudience":        "default audience derived",
	"noAudienceNoName":  "default audience underivable",
	"elevenAudiences":   "audience count",
	"audienceCap":       "audience cap",
	"emptyAudience":     "empty audience",
	"wrongTypeAudience": Malformed,
	"httpIssuer":        IssuerScheme,
	"noIssuer":          MissingIssuer,
	"saml":              "saml",
	"x509":              "x509",
	"noConfig":          "no provider config",
	"twoConfigs":        "two provider configs",
	"unknownMappingKey": "unknown mapping key",
	"wrongTypeMapping":  "wrong-type mapping",
	"duplicateMapping":  "duplicate mapping",
	"mappingList":       Malformed,
	"page":              "",
}

// corrupt applies one corruption to a clean document. Clause corruptions
// replace the clause at i or wrap it; the rest change the document around
// the condition.
func corrupt(t *rapid.T, d documentSpec, kind string) documentSpec {
	c := d
	leaves := d.condition.leaves()
	i := rapid.IntRange(0, len(leaves)-1).Draw(t, "clause")
	replace := func(with clause) {
		c.condition = replaceLeaf(d.condition, i, &tree{leaf: with})
	}
	target := leaves[i]
	switch kind {
	case "neq", "lt", "matches", "extract", "wildcard", "emptyPrefix", "nonString", "bytes", "inNotList", "inEmpty", "inNonString", "has", "nested", "index", "truth", "ternary", "arith", "listCap", "chained", "crLiteral":
		replace(clause{kind: kind, ref: target.ref, values: target.values})
	case "group", "groupsCompared":
		replace(clause{kind: kind, ref: "google.groups", values: target.values})
	case "literal", "unknownRoot", "bareAssertion", "noClaim":
		replace(clause{kind: kind, ref: target.ref, values: target.values})
	case "not":
		c.condition = replaceLeaf(d.condition, i, &tree{op: "!", kids: []*tree{{leaf: target}}})
	case "notConjunction":
		c.condition = &tree{op: "!", kids: []*tree{d.condition}}
	case "orUnmodelled":
		c.condition = replaceLeaf(d.condition, i, &tree{op: "||", kids: []*tree{{leaf: target}, {leaf: clause{kind: "neq", ref: "assertion.repository_id", values: []string{"1"}}}}})
	case "exprMapped":
		replace(clause{kind: "eq", ref: "attribute.org", values: target.values})
	case "unmapped":
		replace(clause{kind: "eq", ref: "attribute.missing", values: target.values})
	case "unparseable":
		c.condition = &tree{op: "&&", kids: []*tree{d.condition, {leaf: clause{kind: "verbatim", values: []string{"assertion.sub == 'x' &&"}}}}}
	case "overlong":
		c.overlong = true
	case "conditionDup":
		c.conditionDup = true
	case "miscased":
		c.miscased = true
	case "miscasedAudiences":
		c.audiences = "miscased"
	case "mappingUnread":
		c.mapping = "list"
		replace(clause{kind: "eq", ref: "google.subject", values: target.values})
	case "disabled":
		c.disabled = "true"
	case "deleted":
		c.state = "DELETED"
	case "unknownState":
		c.state = "SUSPENDED"
	case "noAudience":
		c.audiences = "absent"
	case "noAudienceNoName":
		c.audiences, c.name = "absent", ""
	case "elevenAudiences":
		c.audiences = "eleven"
	case "audienceCap":
		c.audiences = "cap"
	case "emptyAudience":
		c.audiences = "emptyString"
	case "wrongTypeAudience":
		c.audiences = "wrongType"
	case "httpIssuer":
		c.issuer = "http://gitlab.com"
	case "noIssuer":
		c.issuer = ""
	case "saml", "x509":
		c.kind = kind
	case "noConfig":
		c.kind = "none"
	case "twoConfigs":
		c.kind = "two"
	case "unknownMappingKey":
		c.mapping = "unknownKey"
	case "wrongTypeMapping":
		c.mapping = "wrongType"
		replace(clause{kind: "eq", ref: "google.subject", values: target.values})
	case "duplicateMapping":
		c.mapping = "duplicate"
		replace(clause{kind: "eq", ref: "attribute.repository", values: target.values})
	case "mappingList":
		c.mapping = "list"
	case "page":
		c.envelope = "list"
	}
	return c
}

// replaceLeaf returns the tree with its i-th leaf, in left-to-right order,
// replaced by with.
func replaceLeaf(n *tree, i int, with *tree) *tree {
	count := 0
	var walk func(n *tree) *tree
	walk = func(n *tree) *tree {
		if n.op == "" {
			count++
			if count-1 == i {
				return with
			}
			return n
		}
		out := &tree{op: n.op}
		for _, k := range n.kids {
			out.kids = append(out.kids, walk(k))
		}
		return out
	}
	return walk(n)
}

// fill turns a pattern into one string it matches.
func fill(pattern string) string { return strings.ReplaceAll(pattern, "*", "ab") }

// genTokens draws tokens over the claims the documents name, from values
// that stand a chance of being admitted, and the audience.
func genTokens(t *rapid.T, docs ...documentSpec) []claims {
	candidates := map[trust.ClaimKey][]string{"aud": {audienceName, "https://iam.googleapis.com/" + providerName, "//iam.googleapis.com/" + providerName, "other"}}
	for _, d := range docs {
		if d.condition == nil {
			continue
		}
		for _, c := range d.condition.leaves() {
			k, ok := claimFor[c.ref]
			if !ok {
				k = "repository"
			}
			for _, v := range c.values {
				candidates[k] = append(candidates[k], v, fill(v), v+"x", "x"+v)
			}
		}
	}
	keys := slices.Sorted(maps.Keys(candidates))
	return rapid.SliceOfN(rapid.Custom(func(t *rapid.T) claims {
		tok := claims{}
		for _, k := range keys {
			if rapid.IntRange(0, 4).Draw(t, "absent") == 0 {
				continue
			}
			values := append(slices.Clone(candidates[k]), genValue().Draw(t, "noise"))
			tok[k] = rapid.SampledFrom(values).Draw(t, "value")
		}
		return tok
	}), 1, 8).Draw(t, "tokens")
}

func parseSpec(t *rapid.T, d documentSpec) trust.Grant {
	p, err := ParseProvider(d.json())
	if err != nil {
		t.Fatalf("%v: %s", err, d.json())
	}
	return p.Grants(githubProvider)[0]
}

// TestMonotonicityOfIgnorance: a construct the parser does not model can
// only widen what it reports. Every corruption of a clean document, and
// the removal of any clause of it, admits every token the clean parse
// admits; and every corruption reaches the fact it exists for.
func TestMonotonicityOfIgnorance(t *testing.T) {
	admitted, removed := 0, 0
	reached := map[string]int{}
	rapid.Check(t, func(t *rapid.T) {
		base := genClean().Draw(t, "base")
		g := parseSpec(t, base)
		if !g.Exact() || g.Admits.IsEmpty() {
			t.Fatalf("a clean document parsed inexactly or empty: %s -> %s %v", base.condition.text(), g.Admits, g.Admits.Caveats())
		}
		for _, kind := range slices.Sorted(maps.Keys(corruptions)) {
			worse := corrupt(t, base, kind)
			w := parseSpec(t, worse)
			for _, a := range w.Anomalies {
				if factOf(t, a) == corruptions[kind] {
					reached[kind]++
				}
			}
			if kind == "page" && fingerprint(w) == fingerprint(g) {
				reached[kind]++
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
		if base.condition.op == "&&" {
			removed++
			fewer := base
			fewer.condition = base.condition.kids[rapid.IntRange(0, 1).Draw(t, "keep")]
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
	for kind, fact := range corruptions {
		if reached[kind] == 0 {
			t.Errorf("corruption %q never reached %q", kind, fact)
		}
	}
	t.Logf("checked %d admitted tokens against every corruption, removed a clause %d times, reached %v", admitted, removed, reached)
}

// swap permutes the operands of every binary node.
func swap(n *tree) *tree {
	if n.op == "" {
		return n
	}
	out := &tree{op: n.op, leaf: n.leaf}
	for _, k := range n.kids {
		out.kids = append(out.kids, swap(k))
	}
	if len(out.kids) == 2 {
		out.kids[0], out.kids[1] = out.kids[1], out.kids[0]
	}
	return out
}

// TestClauseOrderInvariance: swapping the operands of every && and || in
// a condition yields an identical Grant, facts included. CEL's own
// semantics say the operators are commutative. A ! over a compound
// operand quotes that operand, and a swapped operand is a different
// quotation, so such trees are compared on everything but the sentences.
func TestClauseOrderInvariance(t *testing.T) {
	swapped, quoted := 0, 0
	rapid.Check(t, func(t *rapid.T) {
		d := genDocument().Draw(t, "doc")
		d.blank, d.overlong, d.conditionDup, d.miscased, d.envelope = false, false, false, false, ""
		if d.condition == nil || d.condition.op == "" {
			d.condition = &tree{op: rapid.SampledFrom([]string{"&&", "||"}).Draw(t, "op"), kids: []*tree{genTree(slices.Concat(modelledKinds, unmodelledKinds), 2).Draw(t, "left"), genTree(slices.Concat(modelledKinds, unmodelledKinds), 2).Draw(t, "right")}}
		}
		if d.condition.text() == swap(d.condition).text() {
			return
		}
		swapped++
		mirror := d
		mirror.condition = swap(d.condition)
		a, b := parseSpec(t, d), parseSpec(t, mirror)
		if d.condition.hasNotOverCompound() {
			quoted++
			if structure(a) != structure(b) {
				t.Fatalf("operand order changed the grant:\n%s\n---\n%s\n  %s\n  %s", structure(a), structure(b), d.condition.text(), mirror.condition.text())
			}
			return
		}
		if fingerprint(a) != fingerprint(b) {
			t.Fatalf("operand order changed the grant:\n%s\n---\n%s\n  %s\n  %s", fingerprint(a), fingerprint(b), d.condition.text(), mirror.condition.text())
		}
	})
	if swapped == 0 || quoted == 0 {
		t.Fatalf("swapped %d, of which quoted %d; both must be positive", swapped, quoted)
	}
	t.Logf("exercised on %d swapped conditions, %d compared by structure", swapped, quoted)
}

// structure is a Grant without the sentences: the set, the claims caveated,
// and each anomaly's kind, claim and construct.
func structure(g trust.Grant) string {
	var b strings.Builder
	b.WriteString(string(g.Issuer) + "\n" + g.Admits.String() + "\n")
	for _, c := range g.Admits.Caveats() {
		b.WriteString(string(c.Claim) + "|" + c.Source + "\n")
	}
	for _, a := range g.Anomalies {
		b.WriteString(a.Kind + "|" + string(a.Claim) + "|" + a.Construct + "|" + a.Source + "\n")
	}
	return b.String()
}

// TestPrecedenceProperty: && binds tighter than ||, so A && B || C is the Join of
// (A && B) with C, and A || B && C is the Join of A with (B && C); the
// other groupings are different sets for some draws, which the counters
// prove, so that a parser binding the two equally would fail.
func TestPrecedenceProperty(t *testing.T) {
	agreed, distinguished := 0, 0
	rapid.Check(t, func(t *rapid.T) {
		leaves := rapid.SliceOfN(genClause(modelledKinds), 3, 3).Draw(t, "leaves")
		a, b, c := leaves[0].text(), leaves[1].text(), leaves[2].text()
		doc := func(condition string) trust.Grant {
			return parseSpec(t, documentSpec{kind: "oidc", name: providerName, mapping: "bare", audiences: "one", issuer: string(github), condition: &tree{leaf: clause{kind: "verbatim", values: []string{condition}}}})
		}
		for _, pair := range [][3]string{
			{a + " && " + b + " || " + c, "(" + a + " && " + b + ") || " + c, a + " && (" + b + " || " + c + ")"},
			{a + " || " + b + " && " + c, a + " || (" + b + " && " + c + ")", "(" + a + " || " + b + ") && " + c},
		} {
			bare, grouped, other := doc(pair[0]), doc(pair[1]), doc(pair[2])
			if fingerprint(bare) != fingerprint(grouped) {
				t.Fatalf("%s\n  parsed as %s\n  want %s", pair[0], bare.Admits, grouped.Admits)
			}
			agreed++
			if fingerprint(bare) != fingerprint(other) {
				distinguished++
			}
		}
	})
	if agreed == 0 || distinguished == 0 {
		t.Fatalf("agreed %d, distinguished %d; both must be positive", agreed, distinguished)
	}
	t.Logf("agreed on %d groupings, distinguished %d from the other grouping", agreed, distinguished)
}

// The pool spellings every selector is bound under: Google's own, one with
// a percent escape in the pool's id, one whose fixed text is spelt in
// another case, one whose fixed text holds a percent escape, and another
// pool, which no selector binds.
const (
	miscasedPool     = "projects/123456789012/Locations/global/workloadIdentityPools/github"
	escapedFixedPool = "projects/123456789012/loc%61tions/global/workloadIdentityPools/github"
	otherPool        = "projects/123456789012/locations/global/workloadIdentityPools/gitlab"
)

// TestBindNeverAdmitsMoreThanTheProvider: binding never admits more than
// the provider does; binding the whole pool admits exactly what the
// provider does; binding a subject or an attribute the provider admits
// admits a token carrying it; a member on an unattributable attribute, one
// that holds a percent escape in its pool or its selector, or one that
// selects by a form Google does not document for the pool, admits the
// whole pool, declared; a subject past Google's limit is kept, declared; a
// member whose fixed text is not Google's own spelling binds with the
// doubt stated; and a member of another pool is not a binding on the
// provider. Every selector form is bound against every drawn provider
// under every pool spelling and both spellings of the scheme, so that
// every fact Bind can record is seen on every run rather than sampled.
func TestBindNeverAdmitsMoreThanTheProvider(t *testing.T) {
	bound, whole, selected, overlong, widened, unbound := 0, 0, 0, 0, 0, 0
	facts := map[string]int{}
	rapid.Check(t, func(t *rapid.T) {
		d := genClean().Draw(t, "base")
		d.mapping = "bare"
		p, err := ParseProvider(d.json())
		if err != nil {
			t.Fatalf("%v", err)
		}
		own := p.Grants(githubProvider)[0]
		value := genValue().Draw(t, "value")
		long := value + strings.Repeat("x", subjectLimit)
		selectors := []string{"subject/" + value, "attribute.repository/" + value, "group/" + value, "*", "attribute.org/" + value, "attribute.missing/" + value, "namespace/" + value, "kubernetes.serviceaccount.uid/" + value, "attribute./" + value, "%73ubject/" + value, "%2A", "attribute.%72epository/" + value, "subject/" + value + "%3A", "subject/" + long, "attribute.repository/" + long, "", "**"}
		tokens := genTokens(t, d)
		upper := rapid.Bool().Draw(t, "upper")
		for _, pool := range []string{githubPool, escapedPool, miscasedPool, escapedFixedPool, otherPool} {
			for _, selector := range selectors {
				scheme := "principalSet://"
				if strings.HasPrefix(selector, "subject/") || strings.HasPrefix(selector, "kubernetes.") || strings.HasPrefix(selector, "%73ubject/") {
					scheme = "principal://"
				}
				if upper {
					scheme = strings.ToUpper(scheme)
				}
				m := mustMembersT(t, policy(scheme+"iam.googleapis.com/"+pool+"/"+selector))[0]
				g, ok := p.Bind(m, deployAccount)
				if pool == otherPool {
					if ok {
						t.Fatalf("bound a member of another pool: %s", m.Text)
					}
					unbound++
					continue
				}
				if !ok {
					t.Fatalf("not bound: %s", m.Text)
				}
				bound++
				if g.Target != deployAccount || g.Issuer != own.Issuer {
					t.Fatalf("target %+v issuer %q", g.Target, g.Issuer)
				}
				examine(t, g, true)
				for _, a := range g.Anomalies {
					facts[factOf(t, a)]++
				}
				// Only Google's own spelling of the pool and the scheme places
				// the member without doubt.
				placed := pool == githubPool && !upper
				if !placed && g.Exact() {
					t.Fatalf("a member whose text cannot be placed exactly bound exactly: %s", m.Text)
				}
				for _, tok := range tokens {
					if g.Admits.Admits(tok) && !own.Admits.Admits(tok) {
						t.Fatalf("the bound grant %s admits %v, which the provider %s does not", g.Admits, tok, own.Admits)
					}
				}
				kind, chosen, _ := strings.Cut(selector, "/")
				switch {
				case selector == "*":
					whole++
					if g.Admits.String() != own.Admits.String() || g.Exact() != placed {
						t.Fatalf("the whole pool: %s, provider %s, exact %v", g.Admits, own.Admits, g.Exact())
					}
				case m.Attribute != "" && (kind == "subject" || kind == "attribute.repository"):
					claim := trust.ClaimKey("sub")
					if kind != "subject" {
						claim = "repository"
					}
					// A subject past the limit is kept as written, declared an
					// upper bound; a value with an escape is Unknown, so the
					// token carrying it as written is admitted like any other.
					switch {
					case chosen == long && claim == "sub":
						overlong++
						if g.Exact() || !hasCaveatOn(g.Admits.Caveats(), "sub") {
							t.Fatalf("a subject past the limit bound exactly: %s", m.Text)
						}
					case chosen == value:
						selected++
						if g.Exact() != placed {
							t.Fatalf("%s: exact %v, want %v", m.Text, g.Exact(), placed)
						}
					}
					for _, tok := range tokens {
						tok[claim] = chosen
						if own.Admits.Admits(tok) != g.Admits.Admits(tok) {
							t.Fatalf("a token carrying the member's value: provider %v, bound %v: %s / %s", own.Admits.Admits(tok), g.Admits.Admits(tok), own.Admits, g.Admits)
						}
					}
				default:
					widened++
					if g.Exact() {
						t.Fatalf("%s: exact: %s", selector, g.Admits)
					}
					for _, tok := range tokens {
						if own.Admits.Admits(tok) != g.Admits.Admits(tok) {
							t.Fatalf("%s: provider %v, bound %v: %s / %s", selector, own.Admits.Admits(tok), g.Admits.Admits(tok), own.Admits, g.Admits)
						}
					}
				}
			}
		}
	})
	if bound == 0 || whole == 0 || selected == 0 || overlong == 0 || widened == 0 || unbound == 0 {
		t.Fatalf("bound %d, whole %d, selected %d, overlong %d, widened %d, unbound %d; every count must be positive", bound, whole, selected, overlong, widened, unbound)
	}
	for _, fact := range []string{"percent escape in the pool", "percent escape in the selector", "percent escape in the value", "percent escape in the fixed text", "respelt member", "undocumented selector", SubjectLength, "group member", "expression mapping", "unmapped"} {
		if facts[fact] == 0 {
			t.Errorf("Bind never recorded %q", fact)
		}
	}
	t.Logf("bound %d members: %d whole pool, %d selecting a value, %d past the subject limit, %d widened; %d not bound; facts %v", bound, whole, selected, overlong, widened, unbound, facts)
}

func mustMembersT(t *rapid.T, raw []byte) []Member {
	members, err := ParseMembers(raw)
	if err != nil {
		t.Fatalf("%v", err)
	}
	return members
}

// valueFloor is the fewest distinct strings a run of the guard below may
// see genValue draw. The generator can spell 1,364 strings, and a run
// draws thousands of them; a run that sees fewer distinct ones than this
// is drawing from a generator that has collapsed onto a handful, under
// which the corruption properties compare one value with itself and the
// tokens carry nothing a pattern could tell from an exact value.
const valueFloor = 64

// TestGeneratorStalenessGuard guards the guards: every fact the parser can
// record, every clause kind, every document shape and every envelope must
// be drawn by genDocument, or the properties above pass over documents
// that never exercise them. The clean base and the tokens the corruption
// properties rest on are drawn here too: a base of one clause kind, a
// value drawn from one string, or a token that always carries every
// claim would leave those properties agreeing with whatever the parser
// does to the rest.
func TestGeneratorStalenessGuard(t *testing.T) {
	seen := map[string]int{}
	values := map[string]bool{}
	rapid.Check(t, func(t *rapid.T) {
		for _, d := range rapid.SliceOfN(genDocument(), 48, 48).Draw(t, "docs") {
			seen["kind "+d.kind]++
			seen["envelope "+d.envelope]++
			seen["audiences "+d.audiences]++
			seen["mapping "+d.mapping]++
			if d.snake {
				seen["snake"]++
			}
			if d.miscased {
				seen["miscased"]++
			}
			if d.condition != nil {
				for _, c := range d.condition.leaves() {
					seen["clause "+c.kind]++
				}
				if d.condition.hasNotOverCompound() {
					seen["not over compound"]++
				}
			}
			if d.mayBeEmpty() {
				seen["may be empty"]++
			}
			providers, err := ParseProviders(d.json())
			if err != nil {
				seen["refused"]++
				continue
			}
			for _, p := range providers {
				g := p.Grants(githubProvider)[0]
				if g.Exact() {
					seen["exact"]++
				}
				if g.Admits.IsEmpty() {
					seen["empty"]++
				}
				for _, a := range g.Anomalies {
					seen[factOf(t, a)]++
					if a.Kind == MiscasedKey {
						// The member itself, not only the kind: a miscased
						// audience list and a miscased condition are one
						// kind of fact drawn by two different draws.
						seen["miscased "+a.Construct]++
					}
				}
			}
		}
		for _, d := range rapid.SliceOfN(genClean(), 8, 8).Draw(t, "clean") {
			named := map[trust.ClaimKey]bool{}
			for _, c := range d.condition.leaves() {
				seen["clean clause "+c.kind]++
				named[claimFor[c.ref]] = true
				for _, v := range c.values {
					values[v] = true
				}
			}
			for _, tok := range genTokens(t, d) {
				if _, ok := tok["aud"]; !ok {
					seen["token without aud"]++
				}
				for claim := range named {
					if _, ok := tok[claim]; !ok {
						seen["token without a claim the condition names"]++
					}
				}
				for _, v := range tok {
					values[v] = true
				}
			}
		}
	})
	var want []string
	for _, k := range []string{"oidc", "aws", "saml", "x509", "none", "two"} {
		want = append(want, "kind "+k)
	}
	for _, e := range []string{"", "list", "page", "bare"} {
		want = append(want, "envelope "+e)
	}
	for _, a := range []string{"absent", "one", "eleven", "cap", "empty", "emptyString", "wrongType", "miscased"} {
		want = append(want, "audiences "+a)
	}
	for _, m := range []string{"", "bare", "expression", "duplicate", "unknownKey", "wrongType", "list", "empty"} {
		want = append(want, "mapping "+m)
	}
	// The clause kinds and the facts are spelt here rather than taken
	// from the generator's own tables, so that a kind dropped from a
	// table is a kind this guard misses, not one it stops wanting.
	for _, c := range []string{"eq", "in", "startsWith", "endsWith", "contains", "raw", "neq", "lt", "matches", "extract", "wildcard", "emptyPrefix", "nonString", "bytes", "inNotList", "inEmpty", "inNonString", "group", "groupsCompared", "has", "nested", "index", "truth", "ternary", "literal", "unknownRoot", "bareAssertion", "noClaim", "arith", "listCap", "chained", "crLiteral", "longSubject", "true", "false"} {
		want = append(want, "clause "+c)
	}
	for _, c := range []string{"eq", "in", "startsWith", "endsWith", "contains", "raw"} {
		want = append(want, "clean clause "+c)
	}
	want = append(want,
		"operator !=", "operator <", "function matches", "function extract", "wildcard", "empty prefix", "non-string comparand", "list not literal", "empty list", "group membership", "set-valued attribute", "condition as operand", "carriage return", "unread mapping", "has", "nested field", "truth", "?", "literal", "unknown root", "bare assertion", "no claim ==", "operator +", "list cap", "not comparison", "not expression", "expression mapping", "unmapped", "unparseable expression", "expression length",
		DuplicateKey, MiscasedKey, ProviderDisabled, ProviderDeleted, SubjectLength, "unknown state", "default audience derived", "default audience underivable", "audience count", "audience cap", "empty audience", Malformed, IssuerScheme, MissingIssuer, "saml", "x509", "no provider config", "two provider configs", "unknown mapping key", "wrong-type mapping", "duplicate mapping",
		"snake", "miscased", "miscased AttributeCondition", "miscased AllowedAudiences", "miscased Allowed_audiences", "not over compound", "may be empty", "refused", "exact", "empty", "unattributable kind",
		"token without aud", "token without a claim the condition names")
	for _, w := range want {
		if seen[w] == 0 {
			t.Errorf("the generator never produced %q", w)
		}
	}
	if len(values) < valueFloor {
		t.Errorf("genValue drew %d distinct strings across the clean bases and their tokens; fewer than %d means the generator has collapsed", len(values), valueFloor)
	}
	t.Logf("genValue drew %d distinct strings", len(values))
	t.Logf("drew %v", seen)
}
