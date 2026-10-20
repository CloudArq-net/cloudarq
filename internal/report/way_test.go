package report

import (
	"encoding/json"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// The way of each population: the principal as the statement writes it,
// who the population is in the words of the row it lands in, and how the
// policy lets it in, from the statement and the claims its term names.
// These tests read the answer as JSON, which is what a consumer reads.

// wayShape is a population's way as the answer writes it.
type wayShape struct {
	Principal []struct {
		Text   string `json:"text"`
		Member string `json:"member"`
		Line   int    `json:"line"`
	} `json:"principal"`
	Who       *Sentence  `json:"who"`
	How       *Sentence  `json:"how"`
	Questions []Question `json:"questions"`
}

// populationShape is a population with its place and its way.
type populationShape struct {
	Place string    `json:"place"`
	Basis string    `json:"basis"`
	Way   *wayShape `json:"way"`
}

// waysOf reads every grant's populations from an answer's JSON, in the
// answer's order.
func waysOf(t *testing.T, answer []byte) [][]populationShape {
	t.Helper()
	var a struct {
		Grants []struct {
			Populations []populationShape `json:"populations"`
		} `json:"grants"`
	}
	if err := json.Unmarshal(answer, &a); err != nil {
		t.Fatalf("the answer is not JSON: %v\n%s", err, answer)
	}
	out := make([][]populationShape, len(a.Grants))
	for i, g := range a.Grants {
		out[i] = g.Populations
	}
	return out
}

// wayAt is the way of one population, failing when it has none.
func wayAt(t *testing.T, answer []byte, grant, population int) wayShape {
	t.Helper()
	ways := waysOf(t, answer)
	if grant >= len(ways) || population >= len(ways[grant]) {
		t.Fatalf("grant %d population %d: the answer has %d grants", grant+1, population, len(ways))
	}
	w := ways[grant][population].Way
	if w == nil {
		t.Fatalf("grant %d population %d carries no way:\n%s", grant+1, population, answer)
	}
	return *w
}

const (
	// oneAccount trusts one account by its root ARN, in a statement with a
	// Sid and no condition, on one line.
	oneAccount = `{"Version":"2012-10-17","Statement":[{"Sid":"Partner","Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111122223333:root"},"Action":"sts:AssumeRole"}]}`
	// partners trusts two accounts, one by its root ARN and one by its ID,
	// and a role of a third, under an external ID; and, in a statement with
	// no Sid, GitHub's tokens of two owners.
	partners = `{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "Partners",
      "Effect": "Allow",
      "Principal": {"AWS": ["arn:aws:iam::111122223333:root", "444455556666", "arn:aws:iam::777788889999:role/Deploy"]},
      "Action": "sts:AssumeRole",
      "Condition": {"StringEquals": {"sts:ExternalId": "x1"}}
    },
    {
      "Effect": "Allow",
      "Principal": {"Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"},
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {"StringEquals": {"token.actions.githubusercontent.com:aud": "sts.amazonaws.com"}, "StringLike": {"token.actions.githubusercontent.com:sub": ["repo:acme/app:*", "repo:other/x:*"]}}
    }
  ]
}`
	oneService   = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}`
	anyPrincipal = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"sts:AssumeRole"}]}`
)

// The principal is named as the statement writes it: the leaf of
// Principal the grant was read from, its member and its line, a root ARN
// as a root ARN and a bare account ID as the ID.
func TestAWayNamesThePrincipalAsTheStatementWritesIt(t *testing.T) {
	type leaf struct {
		text, member string
		line         int
	}
	cases := []struct {
		name       string
		policy     string
		grant, pop int
		want       []leaf
	}{
		{"a root ARN", oneAccount, 0, 0, []leaf{{"arn:aws:iam::111122223333:root", "Principal.AWS", 1}}},
		{"a root ARN in a list", partners, 0, 0, []leaf{{"arn:aws:iam::111122223333:root", "Principal.AWS", 7}}},
		{"an account ID in a list", partners, 1, 0, []leaf{{"444455556666", "Principal.AWS", 7}}},
		{"a role's ARN", partners, 2, 0, []leaf{{"arn:aws:iam::777788889999:role/Deploy", "Principal.AWS", 7}}},
		{"an OIDC provider", partners, 3, 0, []leaf{{"arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com", "Principal.Federated", 13}}},
		{"a service", oneService, 0, 0, []leaf{{"ec2.amazonaws.com", "Principal.Service", 1}}},
		{"the face of * on services", anyPrincipal, 0, 0, []leaf{{"*", "Principal", 1}}},
		{"the face of * on AWS principals", anyPrincipal, 1, 0, []leaf{{"*", "Principal", 1}}},
	}
	for _, c := range cases {
		w := wayAt(t, Admits([]byte(c.policy)), c.grant, c.pop)
		var got []leaf
		for _, p := range w.Principal {
			got = append(got, leaf{p.Text, p.Member, p.Line})
		}
		if !slices.Equal(got, c.want) {
			t.Errorf("%s: the principal is %+v, want %+v", c.name, got, c.want)
		}
	}
}

// --explain never tells the reader how to shut out what they declared as
// theirs, an account or a SAML provider: a population placed as yours or
// as your people carries its fix in the answer, so that a re-mark with the
// declaration withdrawn says it again, but no line of ExplainWays says it,
// while an outsider's fix is said.
func TestExplainWaysSaysNoFixForWhatIsYours(t *testing.T) {
	people, peopleOwners := ringsCase(t, "35-saml-provider-declared")
	cases := []struct {
		name           string
		policy, owners []byte
		outsiderFixed  bool
	}{
		{"your account beside a partner", []byte(`{"Version":"2012-10-17","Statement":[{"Sid":"PartnerAndUs","Effect":"Allow","Principal":{"AWS":["arn:aws:iam::111122223333:root","arn:aws:iam::444455556666:root"]},"Action":"sts:AssumeRole"},{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}`), []byte("aws:444455556666"), true},
		{"your people", people, peopleOwners, false},
	}
	for _, c := range cases {
		a := answerOf(t, AdmitsFor(c.policy, c.owners))
		said := strings.Join(a.ExplainWays(""), "\n")
		yours, outsiders := 0, 0
		for _, g := range a.Grants {
			for _, p := range g.Populations {
				if p.Way.Fix == nil {
					t.Fatalf("%s grant %d: the answer carries no fix", c.name, g.Number)
				}
				fix := "    fix  " + p.Way.Fix.Sentence
				switch p.Place {
				case "yours", "people":
					yours++
					if strings.Contains(said, fix) {
						t.Errorf("%s grant %d: --explain tells the reader to shut out their own:\n%s", c.name, g.Number, said)
					}
				case "outsider":
					outsiders++
					if !strings.Contains(said, fix) {
						t.Errorf("%s grant %d: --explain does not say the outsider's fix:\n%s", c.name, g.Number, said)
					}
				}
			}
		}
		if yours == 0 || (outsiders > 0) != c.outsiderFixed {
			t.Errorf("%s: %d populations of yours and %d outsiders examined", c.name, yours, outsiders)
		}
	}
}

// A CanonicalUser principal is not modelled, and the answer says only
// that: its text, an S3 canonical user ID or whatever the statement
// writes there, is nowhere in the answer, as a document or in a bundle's
// findings, and its way names no principal.
func TestAWayNeverCarriesACanonicalUsersText(t *testing.T) {
	for _, id := range []string{"79a59df900b949e55d96a1e698fbacedfd6e09d98eacf8f8d5218e7cd47ef2be", "zzsecretTOKENzz"} {
		policy := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"CanonicalUser":"` + id + `"},"Action":["sts:AssumeRole","sts:AssumeRoleWithWebIdentity","sts:AssumeRoleWithSAML"]}]}`
		answer := Admits([]byte(policy))
		if strings.Contains(string(answer), id) {
			t.Errorf("the answer carries the CanonicalUser %q:\n%s", id, answer)
		}
		a := answerOf(t, answer)
		ways := 0
		for _, g := range a.Grants {
			for _, p := range g.Populations {
				if p.Way == nil {
					continue
				}
				ways++
				if len(p.Way.Principal) != 0 {
					t.Errorf("the way of a CanonicalUser names the principal %+v", p.Way.Principal)
				}
			}
		}
		if ways == 0 {
			t.Errorf("no population of the CanonicalUser's grants has a way, so none was examined")
		}
		if findings := Findings(bundleOf(t, nil, testRole{"canonical", policy}), nil, "cloudarq test"); strings.Contains(string(findings), id) {
			t.Errorf("the findings carry the CanonicalUser %q", id)
		}
	}
}

// Who a population is, in the words the row it lands in says of it: the
// row's sentence as it reads with this population alone in it.
func TestAWaySaysWhoInTheWordsOfItsRow(t *testing.T) {
	cases := []struct {
		name, policy, owners string
		grant, pop           int
		want                 string
	}{
		{"an account nobody declared", oneAccount, "", 0, 0, "aws:111122223333 can assume this role and is not declared as yours."},
		{"an account declared", oneAccount, "aws:111122223333", 0, 0, "aws:111122223333, declared as yours, can assume this role."},
		{"two GitHub owners", partners, "", 3, 0, "github:acme and github:other can assume this role and are not declared as yours."},
		{"a service", oneService, "", 0, 0, "ec2.amazonaws.com can assume this role; who can make it act is not read."},
		{"the face of * on services", anyPrincipal, "", 0, 0, "Any cloud service can assume this role; which ones, and for whom, is not read."},
		{"the face of * on AWS principals", anyPrincipal, "", 1, 0, "Anyone on AWS can assume this role; no condition confines callers to one account or organisation."},
	}
	for _, c := range cases {
		w := wayAt(t, AdmitsFor([]byte(c.policy), []byte(c.owners)), c.grant, c.pop)
		if w.Who == nil || w.Who.Sentence != c.want {
			t.Errorf("%s: who is %+v, want %q", c.name, w.Who, c.want)
		}
	}
}

// How the policy lets a population in: the statement, by its number, its
// Sid and its lines, names the principal, with the conditions its term
// names as the grant's own sentence says them, or with none.
func TestAWaySaysHowFromTheStatementAndItsConditions(t *testing.T) {
	cases := []struct {
		name, policy string
		grant, pop   int
		want         string
	}{
		{"an account with no condition", oneAccount, 0, 0, `Statement 1 ("Partner"), line 1, names this account, with no condition.`},
		{"an account under an external ID", partners, 0, 0, `Statement 1 ("Partners"), lines 4-10, names this account, on condition that sts:externalid is x1.`},
		{"an account ID under an external ID", partners, 1, 0, `Statement 1 ("Partners"), lines 4-10, names this account, on condition that sts:externalid is x1.`},
		{"a role under an external ID", partners, 2, 0, `Statement 1 ("Partners"), lines 4-10, names this principal, on condition that sts:externalid is x1.`},
		{"a provider under two conditions", partners, 3, 0, `Statement 2, lines 11-16, names this provider, on condition that aud is sts.amazonaws.com and sub is one of anything that matches repo:acme/app:*, anything that matches repo:other/x:*.`},
		{"a service", oneService, 0, 0, `Statement 1, line 1, names this service, with no condition.`},
		{"the face of * on services", anyPrincipal, 0, 0, `Statement 1, line 1, names "*", with no condition, so the set shown is an upper bound.`},
		{"the face of * on AWS principals", anyPrincipal, 1, 0, `Statement 1, line 1, names "*", with no condition.`},
	}
	for _, c := range cases {
		w := wayAt(t, Admits([]byte(c.policy)), c.grant, c.pop)
		if w.How == nil || w.How.Sentence != c.want {
			t.Errorf("%s: how is %+v, want %q", c.name, w.How, c.want)
		}
	}
}

// A way asks of each owner its population is pinned to whether it is the
// reader's, as the row of a named outsider asks, and asks nothing once the
// owner is declared.
func TestAWayAsksAboutAnOwnerNobodyDeclared(t *testing.T) {
	asked := func(w wayShape) []string {
		var out []string
		for _, q := range w.Questions {
			out = append(out, q.Declaration+" "+q.Sentence)
		}
		return out
	}
	if got, want := asked(wayAt(t, Admits([]byte(oneAccount)), 0, 0)), []string{"aws:111122223333 Is aws:111122223333 yours?"}; !slices.Equal(got, want) {
		t.Errorf("an account nobody declared: asked %q, want %q", got, want)
	}
	if got, want := asked(wayAt(t, Admits([]byte(partners)), 3, 0)), []string{"github:acme Is github:acme yours?", "github:other Is github:other yours?"}; !slices.Equal(got, want) {
		t.Errorf("two GitHub owners: asked %q, want %q", got, want)
	}
	if got := asked(wayAt(t, AdmitsFor([]byte(oneAccount), []byte("aws:111122223333")), 0, 0)); len(got) != 0 {
		t.Errorf("an account declared: asked %q, want nothing", got)
	}
	if got := asked(wayAt(t, Admits([]byte(oneService)), 0, 0)); len(got) != 0 {
		t.Errorf("a service: asked %q, want nothing", got)
	}
}

// onlyWord is the word no sentence of the engine says: it would read as
// reassurance about a population nobody read.
var onlyWord = regexp.MustCompile(`(?i)\bonly\b`)

// Every population of every grant the corpus and the rings cases place
// carries a way, whose sentences are exactly their spans, carry no control
// character, no rating word and never "only", and whose principal is
// written inside its grant's statement.
func TestEveryPopulationCarriesAWay(t *testing.T) {
	docs := corpus(t)
	docs[escapes] = fixture(t, escapes)
	declared := map[string][]byte{}
	for _, name := range ringsCases(t) {
		doc, owners := ringsCase(t, name)
		docs[name] = doc
		declared[name] = owners
	}
	examined, written := 0, 0
	for path, raw := range docs {
		answer := AdmitsFor(raw, declared[path])
		var a struct {
			Document *Document `json:"document"`
			Grants   []struct {
				Statement   int               `json:"statement"`
				Populations []populationShape `json:"populations"`
			} `json:"grants"`
		}
		if err := json.Unmarshal(answer, &a); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		for i, g := range a.Grants {
			for j, p := range g.Populations {
				examined++
				w := p.Way
				if w == nil || w.Who == nil || w.How == nil {
					t.Errorf("%s grant %d population %d: no way, or a way without who or how: %+v", path, i+1, j, w)
					continue
				}
				for _, s := range []*Sentence{w.Who, w.How} {
					var b strings.Builder
					for _, span := range s.Spans {
						b.WriteString(span.Text)
						if n := controls(span.Text); n != 0 {
							t.Errorf("%s grant %d: %d control characters in the span %q", path, i+1, n, span.Text)
						}
					}
					switch {
					case s.Sentence == "" || b.String() != s.Sentence:
						t.Errorf("%s grant %d: the sentence %q is not its spans %q", path, i+1, s.Sentence, b.String())
					case ratingWords.MatchString(s.Sentence), onlyWord.MatchString(s.Sentence):
						t.Errorf("%s grant %d: %q", path, i+1, s.Sentence)
					}
				}
				st := a.Document.Statements[g.Statement]
				for _, l := range w.Principal {
					written++
					if l.Line < st.FirstLine || l.Line > st.LastLine || !strings.HasPrefix(l.Member, "Principal") {
						t.Errorf("%s grant %d: the principal %+v is not written in its statement, lines %d-%d", path, i+1, l, st.FirstLine, st.LastLine)
					}
				}
			}
		}
	}
	// 170 populations and 170 principals written when this was written
	if examined < 160 || written < 160 {
		t.Fatalf("%d populations examined, %d principals written; the property held over too little", examined, written)
	}
	t.Logf("%d populations examined, %d principals written", examined, written)
}

// A re-marked answer says who each population is with the owners declared
// now, as AdmitsFor says it with them.
func TestRemarkSaysWhoWithTheOwnersDeclaredNow(t *testing.T) {
	kept := Admits([]byte(oneAccount))
	got := wayAt(t, remarkNow(kept, "aws:111122223333"), 0, 0)
	if want := "aws:111122223333, declared as yours, can assume this role."; got.Who == nil || got.Who.Sentence != want {
		t.Fatalf("re-marked, who is %+v, want %q", got.Who, want)
	}
	if len(got.Questions) != 0 {
		t.Fatalf("re-marked with the account declared, the way still asks %+v", got.Questions)
	}
}

// An answer kept with a population that carries no way is not one this
// build writes, so it is declined, never re-marked with a way made up for
// it: the principal as written is read from the policy, which Remark does
// not have.
func TestRemarkDeclinesAPopulationWithoutItsWay(t *testing.T) {
	var kept map[string]any
	if err := json.Unmarshal(Admits([]byte(oneAccount)), &kept); err != nil {
		t.Fatal(err)
	}
	removed := 0
	for _, g := range kept["grants"].([]any) {
		for _, p := range g.(map[string]any)["populations"].([]any) {
			if _, ok := p.(map[string]any)["way"]; ok {
				removed++
			}
			delete(p.(map[string]any), "way")
		}
	}
	stripped, err := json.Marshal(kept)
	if err != nil {
		t.Fatal(err)
	}
	d, declined := declinedOf(remarkNow(stripped, "aws:111122223333"))
	if removed != 1 || !declined || d.Declined != "answer" {
		t.Fatalf("a kept answer with %d ways taken out was re-marked: %+v, declined %v", removed, d, declined)
	}
}
