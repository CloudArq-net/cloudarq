package report

import (
	"cmp"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"

	"pgregory.net/rapid"
)

// The headline of a role whose one way in is one GitHub subject, or the
// subjects beginning with one prefix, says which: the subject is what a
// token must carry, and saying "a named outsider" of it reads the same as
// a trust in every repository the owner has. It quotes the subject and
// reads nothing into it, since the engine reads the owner alone from sub.

// gitHubSubject is a statement trusting GitHub's provider for the audience
// AWS documents, on condition that sub meets value under operator. The
// statement is a value encoding/json writes, so no key is written twice.
func gitHubSubject(effect, operator string, value any) map[string]any {
	conditions := map[string]map[string]any{"StringEquals": {"token.actions.githubusercontent.com:aud": "sts.amazonaws.com"}}
	if operator != "" {
		if conditions[operator] == nil {
			conditions[operator] = map[string]any{}
		}
		conditions[operator]["token.actions.githubusercontent.com:sub"] = value
	}
	return map[string]any{
		"Effect":    effect,
		"Principal": map[string]any{"Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"},
		"Action":    "sts:AssumeRoleWithWebIdentity",
		"Condition": conditions,
	}
}

// encodedPolicy is a trust policy of the statements given, as encoding/json
// writes it.
func encodedPolicy(t fataler, statements ...map[string]any) []byte {
	b, err := json.Marshal(map[string]any{"Version": "2012-10-17", "Statement": statements})
	if err != nil {
		t.Fatalf("encode the policy: %v", err)
	}
	return b
}

// escapedPolicy is encodedPolicy with every character past ASCII written as
// a \u escape, as Python's json.dump writes it. Such a character is only
// ever inside a string, where the escape reads as the character.
func escapedPolicy(t fataler, statements ...map[string]any) []byte {
	var b strings.Builder
	for _, r := range string(encodedPolicy(t, statements...)) {
		switch {
		case r < utf8.RuneSelf:
			b.WriteRune(r)
		case r > 0xffff:
			high, low := utf16.EncodeRune(r)
			fmt.Fprintf(&b, `\u%04x\u%04x`, high, low)
		default:
			fmt.Fprintf(&b, `\u%04x`, r)
		}
	}
	return []byte(b.String())
}

// Statements a role's trust may hold beside a GitHub subject: an AWS
// account, a SAML provider, a Deny of everyone, and a grant of the wrong
// action, which admits nobody.
var (
	anAccount = map[string]any{"Effect": "Allow", "Principal": map[string]any{"AWS": "arn:aws:iam::111122223333:root"}, "Action": "sts:AssumeRole"}
	aProvider = map[string]any{"Effect": "Allow", "Principal": map[string]any{"Federated": "arn:aws:iam::123456789012:saml-provider/CorpIdP"}, "Action": "sts:AssumeRoleWithSAML"}
	aDeny     = map[string]any{"Effect": "Deny", "Principal": "*", "Action": "sts:AssumeRole"}
	noAction  = map[string]any{
		"Effect":    "Allow",
		"Principal": map[string]any{"Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"},
		"Action":    "sts:AssumeRole",
		"Condition": map[string]any{"StringLike": map[string]any{"token.actions.githubusercontent.com:sub": "repo:acme/*"}},
	}
)

func TestAnExactSubjectSaysHowExact(t *testing.T) {
	const main = "repo:acme/api:ref:refs/heads/main"
	cases := []struct {
		name       string
		statements []map[string]any
		owners     string
		headline   string
	}{
		{"one subject", []map[string]any{gitHubSubject("Allow", "StringEquals", main)}, "",
			"Only tokens whose subject is exactly repo:acme/api:ref:refs/heads/main can assume this role."},
		{"one prefix", []map[string]any{gitHubSubject("Allow", "StringLike", "repo:acme/api:*")}, "",
			"Only tokens whose subject begins repo:acme/api: can assume this role."},
		// a pattern with no wildcard matches its own text and nothing else
		{"StringLike with no wildcard", []map[string]any{gitHubSubject("Allow", "StringLike", main)}, "",
			"Only tokens whose subject is exactly repo:acme/api:ref:refs/heads/main can assume this role."},
		{"one subject declared", []map[string]any{gitHubSubject("Allow", "StringEquals", main)}, "github:acme",
			"Nothing outside your company can assume this role."},
		{"one prefix declared", []map[string]any{gitHubSubject("Allow", "StringLike", "repo:acme/api:*")}, "github:acme",
			"Nothing outside your company can assume this role."},
		// a Deny and a grant that admits nobody let no one in, so the
		// subject is still the one way in
		{"beside a Deny", []map[string]any{gitHubSubject("Allow", "StringEquals", main), aDeny}, "",
			"Only tokens whose subject is exactly repo:acme/api:ref:refs/heads/main can assume this role."},
		{"beside a grant of nobody", []map[string]any{gitHubSubject("Allow", "StringEquals", main), noAction}, "",
			"Only tokens whose subject is exactly repo:acme/api:ref:refs/heads/main can assume this role."},
		// another way in, wherever it lands, is not that subject
		{"beside a SAML line", []map[string]any{gitHubSubject("Allow", "StringEquals", main), aProvider}, "",
			"A named outsider can assume this role; so can SAML sign-ins."},
		{"beside an account declared", []map[string]any{gitHubSubject("Allow", "StringEquals", main), anAccount}, "aws:111122223333",
			"A named outsider can assume this role."},
		{"beside an account not declared", []map[string]any{gitHubSubject("Allow", "StringEquals", main), anAccount}, "",
			"A named outsider can assume this role."},
		{"two grants of one owner", []map[string]any{gitHubSubject("Allow", "StringEquals", main), gitHubSubject("Allow", "StringEquals", "repo:acme/web:ref:refs/heads/main")}, "",
			"A named outsider can assume this role."},
		{"two subjects", []map[string]any{gitHubSubject("Allow", "StringEquals", []string{main, "repo:acme/web:ref:refs/heads/main"})}, "",
			"A named outsider can assume this role."},
		{"two owners", []map[string]any{gitHubSubject("Allow", "StringEquals", []string{main, "repo:beta/api:ref:refs/heads/main"})}, "",
			"A named outsider can assume this role."},
		{"a star inside", []map[string]any{gitHubSubject("Allow", "StringLike", "repo:acme/*:ref:refs/heads/main")}, "",
			"A named outsider can assume this role."},
		{"a question mark", []map[string]any{gitHubSubject("Allow", "StringLike", "repo:acme/api:ref:refs/heads/mai?")}, "",
			"A named outsider can assume this role."},
		{"a question mark before the star", []map[string]any{gitHubSubject("Allow", "StringLike", "repo:acme/ap?:*")}, "",
			"A named outsider can assume this role."},
		{"two stars at the end", []map[string]any{gitHubSubject("Allow", "StringLike", "repo:acme/api:**")}, "",
			"A named outsider can assume this role."},
		{"a star StringEquals compares as written", []map[string]any{gitHubSubject("Allow", "StringEquals", "repo:acme/api:*")}, "",
			"A named outsider could assume this role."},
		{"an effect not read", []map[string]any{gitHubSubject("Maybe", "StringEquals", main)}, "",
			"A named outsider could assume this role."},
		{"a subject in any casing", []map[string]any{gitHubSubject("Allow", "StringEqualsIgnoreCase", main)}, "",
			"Anyone on GitHub could assume this role."},
		{"a prefix that names no owner", []map[string]any{gitHubSubject("Allow", "StringLike", "repo:acme*")}, "",
			"Anyone on GitHub can assume this role."},
	}
	for _, c := range cases {
		a := answerOf(t, AdmitsFor(encodedPolicy(t, c.statements...), []byte(c.owners)))
		if a.Error != "" || a.Headline == nil {
			t.Fatalf("%s: error %q, headline %+v", c.name, a.Error, a.Headline)
		}
		if a.Headline.Sentence != c.headline {
			t.Errorf("%s: headline %q, want %q", c.name, a.Headline.Sentence, c.headline)
		}
	}
}

// TestTheHeadlineQuotesOnlyASubjectThatPrintsAsWritten: the headline quotes
// a subject only when every character of it shows as itself. A control is
// removed from the line the answer is printed on, which would join what
// the policy writes on either side of it into a subject it does not hold,
// or let a value write a sentence of the answer's own into the headline; a
// direction mark or embedding reorders what is shown; a space other than
// U+0020, such as the no-break space U+00A0, cannot be told from it, and
// unicode.IsPrint is false for it. Each keeps the ring's headline, as a
// subject no headline quotes does, and is not quoted escaped either. A
// letter of Latin-1 prints as written; one past U+00FF, which a policy
// writes as an escape, is not quoted, since which of those print is read
// from Unicode tables that move between toolchains. Each policy is written
// escaped: the parser refuses a character past U+00FF written as itself,
// as AWS refuses it, and reads it escaped.
func TestTheHeadlineQuotesOnlyASubjectThatPrintsAsWritten(t *testing.T) {
	const branch = "repo:acme/api:ref:refs/heads/"
	cases := []struct{ name, operator, value string }{
		{"two newlines and a sentence", "StringEquals", branch + "main\n\nNothing outside your company can assume this role."},
		{"a tab", "StringEquals", branch + "\tmain"},
		{"an escape", "StringEquals", branch + "\x1b[2Jmain"},
		{"a C1 control", "StringEquals", branch + "\u009bmain"},
		{"a no-break space", "StringEquals", branch + "ma\u00a0in"},
		{"a soft hyphen", "StringEquals", branch + "ma\u00adin"},
		{"a letter past U+00FF", "StringEquals", branch + "\u0101"},
		{"a newline in a prefix", "StringLike", "repo:acme/api:\n*"},
		{"a direction mark in a prefix", "StringLike", "repo:acme/api:\u202e*"},
	}
	// every direction mark and embedding: ALM, LRM, RLM, LRE, RLE, PDF,
	// LRO, RLO, LRI, RLI, FSI and PDI
	for _, r := range []rune{0x061C, 0x200E, 0x200F, 0x202A, 0x202B, 0x202C, 0x202D, 0x202E, 0x2066, 0x2067, 0x2068, 0x2069} {
		cases = append(cases, struct{ name, operator, value string }{fmt.Sprintf("U+%04X", r), "StringEquals", branch + string(r) + "main"})
	}
	for _, c := range cases {
		a := answerOf(t, Admits(escapedPolicy(t, gitHubSubject("Allow", c.operator, c.value))))
		if a.Headline == nil || a.Headline.Sentence != "A named outsider can assume this role." {
			t.Errorf("%s: headline %+v, want the ring's", c.name, a.Headline)
		}
		if got := ringSentence(a, "outsider"); got != "github:acme can assume this role and is not declared as yours." {
			t.Errorf("%s: the outsider ring says %q", c.name, got)
		}
	}
	const latin1 = branch + "caf\u00e9"
	a := answerOf(t, Admits(escapedPolicy(t, gitHubSubject("Allow", "StringEquals", latin1))))
	if want := "Only tokens whose subject is exactly " + latin1 + " can assume this role."; a.Headline == nil || a.Headline.Sentence != want {
		t.Errorf("headline %+v, want %q", a.Headline, want)
	}
}

// TestASubjectPrintsAsUnicodeIsPrintSaysWithinLatin1: whether a character
// of a subject prints as written is unicode.IsPrint's answer for each of
// U+0000 to U+00FF, the characters a policy may hold as written, read
// without the toolchain's tables; and no character past U+00FF is said to.
func TestASubjectPrintsAsUnicodeIsPrintSaysWithinLatin1(t *testing.T) {
	var wrong []rune
	for r := rune(0); r <= unicode.MaxRune; r++ {
		if printsAsWritten(string(r)) != (r <= unicode.MaxLatin1 && unicode.IsPrint(r)) {
			wrong = append(wrong, r)
		}
	}
	if len(wrong) > 0 {
		t.Errorf("%d characters part from unicode.IsPrint within Latin-1, or print as written past it; the first %U", len(wrong), wrong[:min(len(wrong), 8)])
	}
}

// TestTheHeadlineMarksTheSubjectItQuotes: the subject the headline quotes
// is the value the policy writes, marked as the population a ring names is,
// and the words around it are not marked.
func TestTheHeadlineMarksTheSubjectItQuotes(t *testing.T) {
	for _, c := range []struct {
		operator, value string
		want            []Span
	}{
		{"StringEquals", "repo:acme/api:ref:refs/heads/main", []Span{{Text: "Only tokens whose subject is exactly "}, {Text: "repo:acme/api:ref:refs/heads/main", Mark: "exact"}, {Text: " can assume this role."}}},
		{"StringLike", "repo:acme/api:*", []Span{{Text: "Only tokens whose subject begins "}, {Text: "repo:acme/api:", Mark: "exact"}, {Text: " can assume this role."}}},
	} {
		a := answerOf(t, Admits(encodedPolicy(t, gitHubSubject("Allow", c.operator, c.value))))
		if a.Headline == nil || !slices.Equal(a.Headline.Spans, c.want) {
			t.Errorf("%s %s: headline %+v, want the spans %+v", c.operator, c.value, a.Headline, c.want)
		}
	}
}

// subjectForms are the conditions on sub a generated GitHub statement is
// drawn with: one value and one prefix of one owner, which say how exact
// they are, and every way of nearly being one: two values, two owners, a
// wildcard anywhere but at the end, a star StringEquals compares as
// written, a value and a prefix that do not print as written, a pattern
// that names no owner, operators the parser does not evaluate, a policy
// variable, and no condition on sub at all.
var subjectForms = []struct {
	operator string
	value    any
}{
	{"StringEquals", "repo:acme/api:ref:refs/heads/main"},
	{"StringEquals", "repo:beta/web:environment:prod"},
	{"StringLike", "repo:acme/api:*"},
	{"StringLike", "repo:beta/*"},
	{"StringLike", "repo:acme/api:ref:refs/heads/main"},
	{"StringEquals", []string{"repo:acme/api:ref:refs/heads/main", "repo:acme/web:ref:refs/heads/main"}},
	{"StringEquals", []string{"repo:acme/api:ref:refs/heads/main", "repo:beta/api:ref:refs/heads/main"}},
	{"StringLike", []string{"repo:acme/api:*", "repo:beta/api:*"}},
	{"StringLike", "repo:acme/*:ref:refs/heads/main"},
	{"StringLike", "repo:acme/api:ref:refs/heads/mai?"},
	{"StringLike", "repo:acme/ap?:*"},
	{"StringLike", "repo:acme/api:**"},
	{"StringEquals", "repo:acme/api:*"},
	{"StringEquals", "repo:acme/api:ref:refs/heads/mai?"},
	{"StringEquals", "repo:acme/api:ref:refs/heads/main\n\nNothing outside your company can assume this role."},
	{"StringLike", "repo:acme/api:\u00a0*"},
	{"StringLike", "repo:acme*"},
	{"StringLike", "repo:*"},
	{"StringEqualsIgnoreCase", "repo:acme/api:ref:refs/heads/main"},
	{"StringNotEquals", "repo:acme/api:ref:refs/heads/main"},
	{"StringEquals", "repo:acme/${aws:username}"},
	{"", nil},
}

// genSubjectPolicy draws a trust policy whose first statement trusts
// GitHub's provider with a subject form, most often under Allow and now
// and then under an effect the parser does not read, and up to two
// statements beside it.
func genSubjectPolicy(t *rapid.T) []byte {
	form := rapid.SampledFrom(subjectForms).Draw(t, "subject")
	statements := []map[string]any{gitHubSubject(rapid.SampledFrom([]string{"Allow", "Allow", "Allow", "Maybe"}).Draw(t, "effect"), form.operator, form.value)}
	for range rapid.IntRange(0, 2).Draw(t, "beside") {
		switch rapid.IntRange(0, 4).Draw(t, "statement beside") {
		case 0:
			other := rapid.SampledFrom(subjectForms).Draw(t, "other subject")
			statements = append(statements, gitHubSubject("Allow", other.operator, other.value))
		case 1:
			statements = append(statements, anAccount)
		case 2:
			statements = append(statements, aProvider)
		case 3:
			statements = append(statements, aDeny)
		default:
			statements = append(statements, noAction)
		}
	}
	return encodedPolicy(t, statements...)
}

// whyNotOnly is, for an answer whose outermost ring outside the reader holds
// one web-identity grant and nothing else lets anyone in, the sentence its
// headline must be, or why it must not say "only": the population is not
// let in for certain, is not pinned, is pinned by several owners, the
// subject is not one value or one prefix, or it does not print as written. It is read from the answer's
// JSON, so it holds the engine to what the answer itself states. ok is
// false for every other answer, whose headline is not this rule's.
func whyNotOnly(a Answer) (headline, why string, ok bool) {
	if len(a.Beside) > 0 {
		return "", "", false
	}
	var reached []Row
	for _, r := range a.Rings {
		if len(r.GrantNumbers) > 0 {
			reached = append(reached, r)
		}
	}
	if len(reached) != 1 || len(reached[0].GrantNumbers) != 1 || !slices.Contains([]string{"anyone", "platform", "outsider"}, reached[0].Place) {
		return "", "", false
	}
	g := a.Grants[reached[0].GrantNumbers[0]-1]
	if !strings.HasPrefix(g.Issuer, "https://") || len(g.Populations) != 1 {
		return "", "", false
	}
	p := g.Populations[0]
	switch {
	case p.State != "exact" || reached[0].State != "exact":
		return "", "unknown", true
	case p.Basis != "pinned":
		return "", "not pinned", true
	case len(p.Owners) != 1:
		return "", "several owners", true
	}
	at := slices.IndexFunc(g.Terms[p.Term], func(c Claim) bool { return c.Claim == "sub" })
	if at < 0 {
		return "", "no subject", true
	}
	c := g.Terms[p.Term][at].Constraint
	switch {
	case c.Kind == "exact" && !strings.ContainsAny(c.Value, "*?"):
		return onlyIfPrinted("Only tokens whose subject is exactly ", c.Value)
	case c.Kind == "like" && strings.HasSuffix(c.Value, "*") && !strings.ContainsAny(strings.TrimSuffix(c.Value, "*"), "*?"):
		return onlyIfPrinted("Only tokens whose subject begins ", strings.TrimSuffix(c.Value, "*"))
	}
	return "", "not one value or one prefix", true
}

// onlyIfPrinted is whyNotOnly's headline quoting subject after opening, or,
// when a character of the subject is not one of Latin-1 that
// unicode.IsPrint passes, why there is none.
func onlyIfPrinted(opening, subject string) (headline, why string, ok bool) {
	if strings.ContainsFunc(subject, func(r rune) bool { return r > unicode.MaxLatin1 || !unicode.IsPrint(r) }) {
		return "", "not printed as written", true
	}
	return opening + subject + " can assume this role.", "", true
}

// TestOnlyAnExactSubjectSaysOnly: across generated policies and owners, the
// headline says "only" exactly when the role's one way in, outside the
// reader, is one web-identity grant let in for certain, pinned to one owner,
// whose subject is one value or one prefix, and then it quotes that
// subject; it never does when the population is not let in for certain,
// is not pinned, is pinned by several owners, its subject holds any other
// wildcard or does not print as written, nor beside any other way in.
func TestOnlyAnExactSubjectSaysOnly(t *testing.T) {
	said := map[string]int{}
	// A thousand policies rather than rapid's hundred: a subject of two
	// owners is examined only when it is drawn alone in its policy and
	// under an effect the parser reads, and the check below fails on a
	// count of zero.
	for range 10 {
		rapid.Check(t, func(t *rapid.T) {
			policy := genSubjectPolicy(t)
			owners := rapid.SampledFrom([]string{"", "", "github:acme", "github:beta", "aws:111122223333", "github:acme\naws:111122223333"}).Draw(t, "owners")
			a := answerOf(t, AdmitsFor(policy, []byte(owners)))
			if a.Error != "" || a.Headline == nil {
				t.Fatalf("error %q, headline %+v\npolicy: %s", a.Error, a.Headline, policy)
			}
			got := a.Headline.Sentence
			want, why, ruled := whyNotOnly(a)
			switch {
			case want != "" && got != want:
				t.Fatalf("headline %q, want %q\npolicy: %s\nowners: %q", got, want, policy, owners)
			case want == "" && strings.HasPrefix(got, "Only"):
				t.Fatalf("headline %q, though %s\npolicy: %s\nowners: %q", got, cmp.Or(why, "another way in is beside it or none is outside the reader"), policy, owners)
			case want != "":
				said[strings.Join(strings.Fields(want)[:5], " ")]++
			case ruled:
				said[why]++
			default:
				said["another way in or none"]++
			}
		})
	}
	t.Logf("headlines by why: %v", said)
	for _, why := range []string{"Only tokens whose subject is", "Only tokens whose subject begins", "unknown", "not pinned", "several owners", "not one value or one prefix", "not printed as written", "another way in or none"} {
		if said[why] == 0 {
			t.Errorf("no generated policy was %q; the property examined none of them", why)
		}
	}
}
