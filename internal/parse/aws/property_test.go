package aws

import (
	"encoding/json"
	"slices"
	"strconv"
	"strings"
	"testing"

	"pgregory.net/rapid"

	"github.com/CloudArq-net/cloudarq/internal/eval"
	"github.com/CloudArq-net/cloudarq/internal/trust"
)

const gitlabProvider = "arn:aws:iam::123456789012:oidc-provider/gitlab.com"

// Everything the generators draw from is small, so that shapes collide and
// the interesting cases are drawn often rather than by luck.
var (
	genOperators = []string{
		"StringEquals", "StringLike", "StringEqualsIgnoreCase", "StringNotEquals", "StringEqualsIfExists",
		"ForAllValues:StringLike", "ForAnyValue:StringEquals", "Null", "ArnLike", "Bool",
	}
	// literalOperators compare the value as written; every other operator
	// widens to Unknown, where the value does not matter.
	literalOperators = []string{"StringEquals", "StringLike"}
	genClaims        = []string{"sub", "aud", "repository_id", "environment"}
	genPrincipals    = []string{
		`{"Federated": "` + githubProvider + `"}`,
		`{"Federated": "` + gitlabProvider + `"}`,
		`"*"`,
		`{"AWS": "123456789012"}`,
		`{"Federated": "accounts.google.com"}`,
	}
	genActions = []string{
		`"Action": "sts:AssumeRoleWithWebIdentity"`,
		`"Action": "sts:*"`,
		`"Action": "sts:AssumeRole"`,
		`"NotAction": "s3:*"`,
		`"Action": ["sts:TagSession", "sts:Assume*"]`,
	}
	genEffects = []string{"Allow", "Deny", "allow"}
	// genMembers and genLeaves feed the random-JSON generator: names a policy
	// uses, in shapes it does not, duplicates included.
	genMembers = []string{
		"Version", "Id", "Statement", "Sid", "Effect", "Principal", "NotPrincipal", "Action", "NotAction",
		"Resource", "Condition", "StringEquals", "StringLike", "ForAllValues:StringLike", "Null",
		"AWS", "Federated", "Service", "CanonicalUser", githubHost + ":sub", "aws:SourceIp", "x",
	}
	genLeaves = []string{
		"Allow", "Deny", "allow", "*", "sts:AssumeRole", "sts:AssumeRoleWithWebIdentity", githubProvider,
		"accounts.google.com", "123456789012", "2012-10-17", "2008-10-17", "true", "false", "a", "${aws:username}", "${*}",
	}
)

type constraintShape struct {
	operator string
	key      string
	values   []string
}

type statementShape struct {
	effect      string
	principal   string
	action      string
	constraints []constraintShape
}

func genValue() *rapid.Generator[string] {
	return rapid.StringOfN(rapid.RuneFrom([]rune("abAB*?/:")), 0, 4, -1)
}

// genKey draws a condition key: a GitHub claim most of the time, sometimes
// a request-context key or another provider's claim.
func genKey() *rapid.Generator[string] {
	return rapid.Custom(func(t *rapid.T) string {
		switch rapid.IntRange(0, 5).Draw(t, "scope") {
		case 0:
			return "aws:SourceIp"
		case 1:
			return "gitlab.com:" + rapid.SampledFrom(genClaims).Draw(t, "claim")
		default:
			return gh(rapid.SampledFrom(genClaims).Draw(t, "claim"))
		}
	})
}

// genOperator draws uniformly from every operator shape.
func genOperator() *rapid.Generator[string] { return rapid.SampledFrom(genOperators) }

// genLiteralLeaningOperator draws a literal operator half the time. The
// value-case property needs an exact grant whose value survives every
// other constraint on its claim, which two operators in ten make rare
// enough for a hundred draws to miss.
func genLiteralLeaningOperator() *rapid.Generator[string] {
	return rapid.Custom(func(t *rapid.T) string {
		if rapid.Bool().Draw(t, "literal") {
			return rapid.SampledFrom(literalOperators).Draw(t, "operator")
		}
		return genOperator().Draw(t, "operator")
	})
}

// genConstraints draws distinct (operator, key) pairs. A repeated pair is
// a duplicate, which has a rule of its own and would make removing one
// copy narrow the set; the duplicate rule is tested by example instead.
func genConstraints(min, max int, operator *rapid.Generator[string]) *rapid.Generator[[]constraintShape] {
	one := rapid.Custom(func(t *rapid.T) constraintShape {
		return constraintShape{
			operator: operator.Draw(t, "operator"),
			key:      genKey().Draw(t, "key"),
			values:   rapid.SliceOfN(genValue(), 1, 2).Draw(t, "values"),
		}
	})
	return rapid.SliceOfNDistinct(one, min, max, func(c constraintShape) string {
		return c.operator + "\x00" + strings.ToLower(c.key)
	})
}

func genStatement() *rapid.Generator[statementShape] {
	return rapid.Custom(func(t *rapid.T) statementShape {
		return statementShape{
			effect:      rapid.SampledFrom(genEffects).Draw(t, "effect"),
			principal:   rapid.SampledFrom(genPrincipals).Draw(t, "principal"),
			action:      rapid.SampledFrom(genActions).Draw(t, "action"),
			constraints: genConstraints(0, 3, genOperator()).Draw(t, "constraints"),
		}
	})
}

func jsonText(t *rapid.T, s string) string {
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatalf("marshal %q: %v", s, err)
	}
	return string(b)
}

func jsonList(t *rapid.T, values []string) string {
	parts := make([]string, len(values))
	for i, v := range values {
		parts[i] = jsonText(t, v)
	}
	return "[" + strings.Join(parts, ", ") + "]"
}

// renderStatement writes one block per operator, in order of first
// appearance, so that no operator block is duplicated.
func renderStatement(t *rapid.T, s statementShape) string {
	var b strings.Builder
	b.WriteString(`{"Effect": ` + jsonText(t, s.effect) + `, "Principal": ` + s.principal + `, ` + s.action)
	if len(s.constraints) > 0 {
		b.WriteString(`, "Condition": {`)
		var operators []string
		blocks := map[string][]constraintShape{}
		for _, c := range s.constraints {
			if _, seen := blocks[c.operator]; !seen {
				operators = append(operators, c.operator)
			}
			blocks[c.operator] = append(blocks[c.operator], c)
		}
		for i, op := range operators {
			if i > 0 {
				b.WriteString(", ")
			}
			b.WriteString(jsonText(t, op) + ": {")
			for j, c := range blocks[op] {
				if j > 0 {
					b.WriteString(", ")
				}
				b.WriteString(jsonText(t, c.key) + ": " + jsonList(t, c.values))
			}
			b.WriteString("}")
		}
		b.WriteString("}")
	}
	b.WriteString("}")
	return b.String()
}

func renderPolicy(t *rapid.T, statements []statementShape) string {
	parts := make([]string, len(statements))
	for i, s := range statements {
		parts[i] = renderStatement(t, s)
	}
	return `{"Version": "2012-10-17", "Statement": [` + strings.Join(parts, ", ") + `]}`
}

func parseGrants(t *rapid.T, raw string) []trust.Grant {
	d, err := ParseTrustPolicy([]byte(raw))
	if err != nil {
		t.Fatalf("ParseTrustPolicy(%s): %v", raw, err)
	}
	return d.Grants(role, vocabulary)
}

// genJSON draws a random JSON value shaped like a policy: member names a
// policy uses, in shapes it does not, with duplicates whenever the dice
// repeat a name.
func genJSON(t *rapid.T, depth int) string {
	kind := rapid.IntRange(0, 6).Draw(t, "kind")
	if depth >= 3 {
		kind = rapid.IntRange(0, 4).Draw(t, "leaf")
	}
	switch kind {
	case 0:
		return jsonText(t, rapid.SampledFrom(genLeaves).Draw(t, "string"))
	case 1:
		return strconv.Itoa(rapid.IntRange(-5, 5).Draw(t, "number"))
	case 2:
		return "true"
	case 3:
		return "false"
	case 4:
		return "null"
	case 5:
		n := rapid.IntRange(0, 3).Draw(t, "items")
		items := make([]string, n)
		for i := range items {
			items[i] = genJSON(t, depth+1)
		}
		return "[" + strings.Join(items, ", ") + "]"
	default:
		n := rapid.IntRange(0, 4).Draw(t, "members")
		members := make([]string, n)
		for i := range members {
			members[i] = jsonText(t, rapid.SampledFrom(genMembers).Draw(t, "name")) + ": " + genJSON(t, depth+1)
		}
		return "{" + strings.Join(members, ", ") + "}"
	}
}

// mutate damages a document in one place, or leaves it alone.
func mutate(t *rapid.T, raw []byte) []byte {
	if len(raw) == 0 {
		return raw
	}
	at := rapid.IntRange(0, len(raw)-1).Draw(t, "at")
	switch rapid.IntRange(0, 4).Draw(t, "damage") {
	case 0:
		return slices.Concat(raw[:at], []byte{rapid.Byte().Draw(t, "byte")}, raw[at:])
	case 1:
		return slices.Concat(raw[:at], raw[at+1:])
	case 2:
		out := slices.Clone(raw)
		out[at] = rapid.Byte().Draw(t, "byte")
		return out
	case 3:
		return raw[:at]
	default:
		return raw
	}
}

// TestTotality is property 1: for arbitrary bytes, ParseTrustPolicy never
// panics, and either refuses the input or returns a Document whose Grants
// never panic either.
func TestTotality(t *testing.T) {
	parsed, errored, granted, damaged := 0, 0, 0, 0
	rapid.Check(t, func(t *rapid.T) {
		var raw []byte
		switch rapid.IntRange(0, 2).Draw(t, "shape") {
		case 0:
			raw = rapid.SliceOfN(rapid.Byte(), 0, 64).Draw(t, "bytes")
		case 1:
			policy := renderPolicy(t, rapid.SliceOfN(genStatement(), 0, 3).Draw(t, "statements"))
			raw = mutate(t, []byte(policy))
			if string(raw) != policy {
				damaged++
			}
		default:
			raw = []byte(genJSON(t, 0))
		}
		d, err := ParseTrustPolicy(raw)
		if err != nil {
			errored++
			return
		}
		parsed++
		if gs := d.Grants(role, vocabulary); len(gs) > 0 {
			granted++
		}
		d.Grants(role, nil)
	})
	// The random bytes alone would keep errored positive, so the damaged
	// count is what proves a policy with one byte wrong was ever drawn.
	if parsed == 0 || errored == 0 || granted == 0 || damaged == 0 {
		t.Fatalf("parsed=%d errored=%d granted=%d damaged=%d; every count must be positive or the property examined one branch", parsed, errored, granted, damaged)
	}
	t.Logf("parsed=%d errored=%d granted=%d damaged=%d", parsed, errored, granted, damaged)
}

// genToken draws claim assignments over the same small alphabet as the
// values, so that tokens are admitted often enough for the implications to
// be exercised rather than vacuous.
func genToken() *rapid.Generator[token] {
	claims := []trust.ClaimKey{"sub", "aud", "repository_id", "environment", "aws:principalarn", "aws:principalaccount", "gitlab.com:sub", "gitlab.com:aud", "aws:sourceip"}
	return rapid.Custom(func(t *rapid.T) token {
		tok := token{}
		for _, k := range rapid.SliceOfN(rapid.SampledFrom(claims), 0, 4).Draw(t, "claims") {
			if rapid.Bool().Draw(t, "account") {
				tok[k] = "123456789012"
			} else {
				tok[k] = genValue().Draw(t, "value")
			}
		}
		return tok
	})
}

// TestMonotonicityOfIgnorance is the first half of property 2: removing a
// condition from a statement never narrows the grant. A condition the
// parser dropped in silence would leave the reduced document equal to the
// full one, which narrows nothing, so this half cannot see a dropped
// condition; TestNoConditionIsSilentlyDropped is the half that can.
func TestMonotonicityOfIgnorance(t *testing.T) {
	exercised, widened, denied := 0, 0, 0
	rapid.Check(t, func(t *rapid.T) {
		s := genStatement().Draw(t, "statement")
		s.constraints = genConstraints(1, 4, genOperator()).Draw(t, "constraints")
		i := rapid.IntRange(0, len(s.constraints)-1).Draw(t, "removed")
		reduced := s
		reduced.constraints = slices.Concat(s.constraints[:i], s.constraints[i+1:])
		full := parseGrants(t, renderPolicy(t, []statementShape{s}))
		less := parseGrants(t, renderPolicy(t, []statementShape{reduced}))
		// One principal is one grant, except "*" on a federated action,
		// which is two faces on two issuers; the faces pair up by issuer.
		if len(full) != len(less) || len(full) == 0 || len(full) > 2 {
			t.Fatalf("%d and %d grants for one principal", len(full), len(less))
		}
		for k := range full {
			if full[k].Issuer != less[k].Issuer {
				t.Fatalf("the faces do not pair up: %q and %q", full[k].Issuer, less[k].Issuer)
			}
			if !full[k].Exact() {
				widened++
			}
			if full[k].Effect == trust.Deny {
				denied++
			}
			for _, tok := range rapid.SliceOfN(genToken(), 1, 8).Draw(t, "tokens") {
				if !full[k].Admits.Admits(tok) {
					continue
				}
				exercised++
				if !less[k].Admits.Admits(tok) {
					t.Fatalf("removing %+v narrowed the grant on %q: %s admits %v, %s does not", s.constraints[i], full[k].Issuer, full[k].Admits, tok, less[k].Admits)
				}
			}
		}
	})
	if exercised == 0 || widened == 0 || denied == 0 {
		t.Fatalf("exercised=%d widened=%d denied=%d; every count must be positive", exercised, widened, denied)
	}
	t.Logf("exercised=%d widened=%d denied=%d", exercised, widened, denied)
}

// TestNoConditionIsSilentlyDropped is the second half of property 2: every
// condition is either honoured or widens to Unknown, never silently
// dropped. A statement with one condition projects a grant that differs
// from the same statement without it, or carries a caveat the other lacks.
// A parser that skipped a whole operator family, the Checkov defect, keeps
// the first half green and fails this one. A face the action test emptied,
// or one the statement as a whole left unevaluated, admits what it admits
// whatever the condition says, so those are not examined here and are
// counted so that the exemption is seen to be narrow. The declarations
// that a widening operator produced are counted apart from the ones a key
// produced, a request-context key say, because the operator family is the
// case this property exists for and a generator that stopped drawing it
// would leave the other count positive.
func TestNoConditionIsSilentlyDropped(t *testing.T) {
	honoured, declared, widening, exempt := 0, 0, 0, 0
	rapid.Check(t, func(t *rapid.T) {
		s := genStatement().Draw(t, "statement")
		s.constraints = genConstraints(1, 1, genOperator()).Draw(t, "constraint")
		c := s.constraints[0]
		bare := s
		bare.constraints = nil
		with := parseGrants(t, renderPolicy(t, []statementShape{s}))
		without := parseGrants(t, renderPolicy(t, []statementShape{bare}))
		if len(with) != len(without) || len(with) == 0 || len(with) > 2 {
			t.Fatalf("%d and %d grants for one principal", len(with), len(without))
		}
		for k := range with {
			if with[k].Issuer != without[k].Issuer {
				t.Fatalf("the faces do not pair up: %q and %q", with[k].Issuer, without[k].Issuer)
			}
			if without[k].Admits.IsEmpty() || hasCaveatOn(without[k], "") {
				exempt++
				continue
			}
			switch {
			case with[k].Admits.String() != without[k].Admits.String():
				honoured++
			case len(with[k].Admits.Caveats()) > len(without[k].Admits.Caveats()):
				declared++
				if !slices.Contains(literalOperators, c.operator) {
					widening++
				}
			default:
				t.Fatalf("%+v is silently dropped on %q: %s with it and without it, caveats %v", c, with[k].Issuer, with[k].Admits, with[k].Admits.Caveats())
			}
		}
	})
	if honoured == 0 || declared == 0 || widening == 0 || exempt == 0 {
		t.Fatalf("honoured=%d declared=%d widening=%d exempt=%d; every count must be positive", honoured, declared, widening, exempt)
	}
	t.Logf("honoured=%d declared=%d widening=%d exempt=%d", honoured, declared, widening, exempt)
}

// recase flips the case of a random subset of letters.
func recase(t *rapid.T, s string) string {
	var b strings.Builder
	for _, r := range s {
		if rapid.Bool().Draw(t, "flip") {
			b.WriteString(strings.ToUpper(string(r)))
		} else {
			b.WriteString(strings.ToLower(string(r)))
		}
	}
	return b.String()
}

// flipCase inverts every letter, so that a string with a letter changes.
func flipCase(s string) string {
	var b strings.Builder
	for _, r := range s {
		if strings.ToUpper(string(r)) == string(r) {
			b.WriteString(strings.ToLower(string(r)))
		} else {
			b.WriteString(strings.ToUpper(string(r)))
		}
	}
	return b.String()
}

// core is the part of a grant's meaning that key case must not touch: the
// set, and which claims are declared inexact and by what kind of fact.
// Constructs and sentences quote the key as the customer wrote it, so they
// are left out here and compared in the order property, where nothing is
// recased. Caveats and anomalies are deduplicated on their full text,
// sentence included, so two spellings of one key can leave one or two; the
// sets of claims and kinds they declare are what spelling must not touch.
type core struct {
	issuer  trust.IssuerRef
	effect  trust.Effect
	admits  string
	caveats string
	kinds   string
}

func coreOf(g trust.Grant) core {
	var caveats, kinds []string
	for _, c := range g.Admits.Caveats() {
		caveats = append(caveats, string(c.Claim))
	}
	for _, a := range g.Anomalies {
		kinds = append(kinds, a.Kind+"/"+string(a.Claim))
	}
	slices.Sort(caveats)
	slices.Sort(kinds)
	return core{g.Issuer, g.Effect, g.Admits.String(), strings.Join(slices.Compact(caveats), ","), strings.Join(slices.Compact(kinds), ",")}
}

// TestKeyCaseInvarianceAndValueCaseSensitivity is property 3: recasing
// condition keys leaves the grant unchanged; recasing a value changes it
// under the operators that compare values literally, and under no other.
func TestKeyCaseInvarianceAndValueCaseSensitivity(t *testing.T) {
	keysChanged, keysRaised, mustDiffer, mustEqual := 0, 0, 0, 0
	rapid.Check(t, func(t *rapid.T) {
		s := statementShape{
			effect:      rapid.SampledFrom([]string{"Allow", "Deny"}).Draw(t, "effect"),
			principal:   `{"Federated": "` + githubProvider + `"}`,
			action:      `"Action": "sts:AssumeRoleWithWebIdentity"`,
			constraints: genConstraints(1, 3, genLiteralLeaningOperator()).Draw(t, "constraints"),
		}
		base := parseGrants(t, renderPolicy(t, []statementShape{s}))
		if len(base) != 1 {
			t.Fatalf("%d grants", len(base))
		}

		recased := s
		recased.constraints = slices.Clone(s.constraints)
		changed, raised := false, false
		for i := range recased.constraints {
			k := recase(t, recased.constraints[i].key)
			changed = changed || k != recased.constraints[i].key
			// A key the generator only ever lower-cases would leave the
			// already-lower-case GitHub keys untouched while aws:SourceIp
			// still counts as changed; the invariance is only exercised
			// when some key gains an upper-case letter.
			raised = raised || strings.ToLower(k) != k
			recased.constraints[i].key = k
		}
		if changed {
			keysChanged++
		}
		if raised {
			keysRaised++
		}
		if got := parseGrants(t, renderPolicy(t, []statementShape{recased})); coreOf(got[0]) != coreOf(base[0]) {
			t.Fatalf("recasing keys changed the grant:\n%+v\n%+v", coreOf(base[0]), coreOf(got[0]))
		}

		i := rapid.IntRange(0, len(s.constraints)-1).Draw(t, "constraint")
		j := rapid.IntRange(0, len(s.constraints[i].values)-1).Draw(t, "value")
		flipped := flipCase(s.constraints[i].values[j])
		if flipped == s.constraints[i].values[j] {
			return
		}
		revalued := s
		revalued.constraints = slices.Clone(s.constraints)
		revalued.constraints[i].values = slices.Clone(s.constraints[i].values)
		revalued.constraints[i].values[j] = flipped
		got := parseGrants(t, renderPolicy(t, []statementShape{revalued}))
		same := coreOf(got[0]) == coreOf(base[0])
		c := s.constraints[i]
		literal := slices.Contains(literalOperators, c.operator) && !strings.HasPrefix(strings.ToLower(c.key), "aws:")
		// The value's spelling can only matter when the value itself is what
		// the grant admits on its claim: not when a sibling admits it on its
		// own, as "*" or a second "a" does, and not when another operator on
		// the same claim already excluded it.
		absorbed := slices.ContainsFunc(slices.Concat(c.values[:j], c.values[j+1:]), func(sibling string) bool {
			if c.operator == "StringLike" {
				return eval.Glob(sibling).Contains(c.values[j])
			}
			return sibling == c.values[j]
		})
		switch {
		case literal && !absorbed && base[0].Exact() && admitsOnClaim(base[0].Admits, claimOf(c.key), c.values[j]):
			mustDiffer++
			if same {
				t.Fatalf("recasing %q under %s on %s left the grant unchanged: %s", c.values[j], c.operator, c.key, base[0].Admits)
			}
		case !literal || (s.effect == "Deny" && !base[0].Exact()):
			// A widening operator ignores the value; a Deny that met any
			// Unknown is not applied whatever the value.
			mustEqual++
			if !same {
				t.Fatalf("recasing %q under %s on %s changed the grant:\n%+v\n%+v", c.values[j], c.operator, c.key, coreOf(base[0]), coreOf(got[0]))
			}
		}
	})
	if keysChanged == 0 || keysRaised == 0 || mustDiffer == 0 || mustEqual == 0 {
		t.Fatalf("keysChanged=%d keysRaised=%d mustDiffer=%d mustEqual=%d; every count must be positive", keysChanged, keysRaised, mustDiffer, mustEqual)
	}
	t.Logf("keysChanged=%d keysRaised=%d mustDiffer=%d mustEqual=%d", keysChanged, keysRaised, mustDiffer, mustEqual)
}

// claimOf is the claim a condition key names on the GitHub grant: the name
// after the provider's prefix for GitHub's own keys, the folded key for
// another provider's, which the grant keeps verbatim.
func claimOf(key string) trust.ClaimKey {
	folded := strings.ToLower(key)
	if strings.HasPrefix(folded, githubHost+":") {
		return trust.ClaimKey(strings.TrimPrefix(folded, githubHost+":"))
	}
	return trust.ClaimKey(folded)
}

// admitsOnClaim reports whether some term of s admits v as the claim's
// value, an absent claim admitting anything.
func admitsOnClaim(s eval.AdmittedSet, claim trust.ClaimKey, v string) bool {
	for _, term := range s.Terms() {
		if set, ok := term[claim]; !ok || set.Contains(v) {
			return true
		}
	}
	return false
}

// TestStatementOrderInvariance is property 4, the one whose absence is the
// Checkov defect: shuffling the statements produces the same grants. A
// parser that returned from inside the statement loop could not pass it.
func TestStatementOrderInvariance(t *testing.T) {
	shuffled, multi := 0, 0
	rapid.Check(t, func(t *rapid.T) {
		statements := rapid.SliceOfN(genStatement(), 2, 5).Draw(t, "statements")
		identity := make([]int, len(statements))
		for i := range identity {
			identity[i] = i
		}
		perm := rapid.Permutation(identity).Draw(t, "permutation")
		reordered := make([]statementShape, len(statements))
		for i, p := range perm {
			reordered[i] = statements[p]
		}
		if !slices.Equal(perm, identity) {
			shuffled++
		}
		a := semanticsOf(parseGrants(t, renderPolicy(t, statements)))
		b := semanticsOf(parseGrants(t, renderPolicy(t, reordered)))
		if len(a) > 1 {
			multi++
		}
		if !slices.Equal(a, b) {
			t.Fatalf("statement order changed the grants:\n%v\n%v", a, b)
		}
	})
	if shuffled == 0 || multi == 0 {
		t.Fatalf("shuffled=%d multi=%d; every count must be positive", shuffled, multi)
	}
	t.Logf("shuffled=%d multi=%d", shuffled, multi)
}
