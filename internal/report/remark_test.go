package report

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"pgregory.net/rapid"

	"github.com/CloudArq-net/cloudarq/internal/eval"
	"github.com/CloudArq-net/cloudarq/internal/ring"
)

// thisBuild is the engine that wrote the answer kept and the one that
// re-marks it, in every test here but those about another build.
const thisBuild = "cloudarq v0.0.0-remark-test"

// fataler is what a check needs of a test, so that one check serves a test
// and a rapid property alike.
type fataler interface {
	Fatalf(format string, args ...any)
}

// remarkNow re-marks an answer this build kept with the owners declared now.
func remarkNow(kept []byte, owners string) []byte {
	return Remark(kept, []byte(owners), thisBuild, thisBuild)
}

// declinedOf reads what Remark returned as a Declined. ok is false when it
// is an answer: only a decline carries "declined".
func declinedOf(b []byte) (d Declined, ok bool) {
	var members map[string]json.RawMessage
	if json.Unmarshal(b, &members) != nil {
		return Declined{}, false
	}
	if _, ok := members["declined"]; !ok {
		return Declined{}, false
	}
	if json.Unmarshal(b, &d) != nil {
		return Declined{}, false
	}
	return d, true
}

// answerOf decodes an answer a test holds to be one.
func answerOf(t fataler, b []byte) Answer {
	var a Answer
	if err := json.Unmarshal(b, &a); err != nil {
		t.Fatalf("not an answer: %v\n%s", err, b)
	}
	return a
}

// The forms an answer is kept in. A scan keeps each role's answer inside its
// findings, and a caller that parsed them passes the answer back as its own
// serialiser writes it: other key order, other spacing, other escapes. The
// answer is decoded, so each form must re-mark alike.
var keptForms = []struct {
	name string
	form func(t fataler, kept []byte) []byte
}{
	{"as written", func(_ fataler, kept []byte) []byte { return kept }},
	{"re-serialised", func(t fataler, kept []byte) []byte {
		var v any
		if err := json.Unmarshal(kept, &v); err != nil {
			t.Fatalf("the answer kept is not JSON: %v", err)
		}
		// Marshalling a map sorts its keys and escapes <, > and &, and the
		// indent adds what a pretty-printer would.
		b, err := json.MarshalIndent(v, "", "\t")
		if err != nil {
			t.Fatalf("%v", err)
		}
		return b
	}},
}

// Owner declarations past each of the declaration's bounds, which refuse
// the whole declaration: too many bytes, too many lines, one line too long.
var overruns = []string{
	strings.Repeat("github:"+strings.Repeat("a", 500)+"\n", 40),
	strings.Repeat("github:acme\n", ring.MaxDeclarationLines+1),
	"github:" + strings.Repeat("a", ring.MaxDeclarationLineBytes) + "\n",
}

// pastABound reports whether a declaration is refused whole.
func pastABound(owners string) bool { return ring.ReadDeclarations(owners).Overrun != nil }

// remarks holds Remark to AdmitsFor and tallies what it answered. The
// corpus is re-marked one document at a time in parallel, so the counts are
// taken under a lock.
type remarks struct {
	mu    sync.Mutex
	equal int // AdmitsFor's bytes
	moved int // of those, answers in which the owners now moved a grant
	// declinedForOwners are the declines for a declaration refused whole.
	declinedForOwners int
}

func (r *remarks) count(equal, moved, declinedForOwners int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.equal += equal
	r.moved += moved
	r.declinedForOwners += declinedForOwners
}

// answers are what AdmitsFor renders for one policy, by the declaration it
// is given, each rendered once however often a test compares with it. A
// generated policy may be rendered by admitsMeeting instead: AdmitsFor's
// answer with sets the reader does not write met into its grants.
type answers struct {
	policy []byte
	render func(owners []byte) []byte
	by     map[string][]byte
	placed map[string][][]string
}

func answersFor(policy []byte) *answers {
	return answersBy(policy, func(owners []byte) []byte { return AdmitsFor(policy, owners) })
}

func answersBy(policy []byte, render func(owners []byte) []byte) *answers {
	return &answers{policy: policy, render: render, by: map[string][]byte{}, placed: map[string][][]string{}}
}

func (a *answers) with(owners string) []byte {
	if b, ok := a.by[owners]; ok {
		return b
	}
	b := a.render([]byte(owners))
	a.by[owners] = b
	return b
}

// placements are each grant's placement in the answer with owners.
func (a *answers) placements(t fataler, owners string) [][]string {
	if p, ok := a.placed[owners]; ok {
		return p
	}
	p := placementsOf(t, a.with(owners))
	a.placed[owners] = p
	return p
}

// hold holds Remark to AdmitsFor for one policy: the answer AdmitsFor
// renders with the owners at upload, kept in the form given and re-marked
// with the owners now, is AdmitsFor's answer with the owners now, byte for
// byte. The one decline allowed is for the owners, and only where nothing
// kept can say what AdmitsFor would: the answer kept refused the owners at
// upload whole, after reading the document, and so kept no grant; or the
// answer kept is an error and the owners now are refused whole, where an
// error does not say whether its document was read. A decline that says
// the answer is not one this build writes, on an answer this build wrote,
// fails: it would hide the class of policy Remark cannot rebuild. It
// reports whether Remark gave AdmitsFor's bytes.
func (r *remarks) hold(t fataler, name string, policy *answers, upload, now string, form func(fataler, []byte) []byte) bool {
	kept, want := policy.with(upload), policy.with(now)
	got := Remark(form(t, kept), []byte(now), thisBuild, thisBuild)
	if bytes.Equal(got, want) {
		moved := 0
		if !slices.EqualFunc(policy.placements(t, upload), policy.placements(t, now), slices.Equal) {
			moved = 1
		}
		r.count(1, moved, 0)
		return true
	}
	d, declined := declinedOf(got)
	if declined && d.Declined == "owners" {
		_, unread := readPolicy(policy.policy)
		keptAnError := answerOf(t, kept).Error != ""
		if unread == nil && pastABound(upload) || keptAnError && pastABound(now) {
			r.count(0, 0, 1)
			return false
		}
	}
	at := firstDifference(got, want)
	t.Fatalf("%s: kept with owners %q, re-marked with %q:\nRemark    ...%s...\nAdmitsFor ...%s...\npolicy: %s",
		name, clipped(upload), clipped(now), around(got, at), around(want, at), policy.policy)
	return false
}

func firstDifference(a, b []byte) int {
	for i := range min(len(a), len(b)) {
		if a[i] != b[i] {
			return i
		}
	}
	return min(len(a), len(b))
}

// around is the text near a byte of an answer, enough to see what differs.
func around(b []byte, at int) string {
	return string(b[max(0, at-160):min(len(b), at+160)])
}

func clipped(s string) string {
	if len(s) > 120 {
		return s[:120] + "…(" + strconv.Itoa(len(s)) + " bytes)"
	}
	return s
}

// corpusDocument is one JSON file under testdata, whatever it holds: a trust
// policy, a policy the parser refuses, a token, a bundle. AdmitsFor reads
// every one, and Remark re-marks every answer it gives.
type corpusDocument struct {
	path string
	raw  []byte
	// owners is the declaration the case keeps beside its document, for a
	// case of testdata/rings that has one.
	owners string
}

// everyCorpusDocument is every distinct JSON file under testdata, by
// content: the same bytes under two paths are one document.
func everyCorpusDocument(t *testing.T) []corpusDocument {
	t.Helper()
	var docs []corpusDocument
	seen := map[[sha256.Size]byte]bool{}
	err := filepath.WalkDir(testdata, func(path string, e fs.DirEntry, err error) error {
		if err != nil || e.IsDir() || filepath.Ext(path) != ".json" {
			return err
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if sum := sha256.Sum256(raw); !seen[sum] {
			seen[sum] = true
			owners, err := os.ReadFile(filepath.Join(filepath.Dir(path), "owners.txt"))
			if err != nil && !os.IsNotExist(err) {
				return err
			}
			docs = append(docs, corpusDocument{path: path, raw: raw, owners: string(owners)})
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return docs
}

// Owners every document is re-marked with besides its own, so that a
// declaration that pins nothing in it is echoed as such: one of each kind
// the grammar declares.
var everyKindOfOwner = []string{
	"github:acme", "github:@123456", "aws:111122223333", "aws:o-a1b2c3d4e5",
	"saml:arn:aws:iam::123456789012:saml-provider/CorpIdP",
	"issuer:https://oidc.eks.us-east-1.amazonaws.com/id/EXAMPLED539D4633E53DE1B71EXAMPLE",
}

// pinnedOwners are the declarations of every owner a grant of the answer is
// pinned to, each once, in the order the answer names them; and, beside a
// GitHub owner pinned by id, its id declared alone.
func pinnedOwners(a Answer) []string {
	var out []string
	add := func(d string) {
		if d != "" && !slices.Contains(out, d) {
			out = append(out, d)
		}
	}
	for _, g := range a.Grants {
		for _, p := range g.Populations {
			for _, o := range p.Owners {
				add(o.Declaration)
				if o.Scope == "owner" && o.Kind == "id" {
					add("github:@" + o.Value)
				}
			}
		}
	}
	return out
}

// nearMisses are declarations one step from declaring the owner: the name in
// another letter case, a longer name and a shorter one that begins alike,
// the name with a star after it, which declares the name with the star in
// it; an id written as a name; an id, an account or a provider one character
// away.
func nearMisses(declaration string) []string {
	namespace, value, _ := strings.Cut(declaration, ":")
	switch namespace {
	case "github":
		name, id, withID := strings.Cut(value, "@")
		var out []string
		if name != "" {
			out = append(out, "github:"+name+"-evil", "github:"+name+"*")
			if swapped := swapCase(name); swapped != name {
				out = append(out, "github:"+swapped)
			}
			if len(name) > 1 {
				out = append(out, "github:"+name[:len(name)-1], "github:"+name[:len(name)-1]+"*")
			}
		}
		if withID {
			out = append(out, "github:"+id, "github:@"+oneAway(id))
		}
		return out
	case "aws", "saml":
		return []string{namespace + ":" + oneAway(value)}
	}
	return nil
}

// swapCase turns the first ASCII letter of s to the other case.
func swapCase(s string) string {
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case 'a' <= c && c <= 'z':
			return s[:i] + string(c-'a'+'A') + s[i+1:]
		case 'A' <= c && c <= 'Z':
			return s[:i] + string(c-'A'+'a') + s[i+1:]
		}
	}
	return s
}

// oneAway is s with its last character changed, a digit to the next digit
// and anything else to an x, or a y when it is an x.
func oneAway(s string) string {
	if s == "" {
		return "x"
	}
	last := s[len(s)-1]
	switch {
	case '0' <= last && last <= '9':
		last = '0' + (last-'0'+1)%10
	case last == 'x':
		last = 'y'
	default:
		last = 'x'
	}
	return s[:len(s)-1] + string(last)
}

// ownerSets are the declarations a document is kept with and re-marked
// with. At upload: none; all it pins; all of them with every near miss; the
// case's own; one overrun; and a subset drawn by the document's digest. Now:
// those but the overrun and the subset; each owner it pins and each near
// miss alone; all it pins but one; a declaration with refused lines beside
// an owner; every overrun; and two more subsets drawn by the digest, so that
// each document meets its own mix of declared and undeclared owners.
func ownerSets(doc corpusDocument, pinned []string) (upload, now []string) {
	candidates := slices.Clone(pinned)
	for _, k := range everyKindOfOwner {
		if !slices.Contains(candidates, k) {
			candidates = append(candidates, k)
		}
	}
	var misses []string
	for _, p := range pinned {
		for _, m := range nearMisses(p) {
			if !slices.Contains(candidates, m) && !slices.Contains(misses, m) {
				misses = append(misses, m)
			}
		}
	}
	lines := func(owners []string) string { return strings.Join(owners, "\n") }
	sum := sha256.Sum256(doc.raw)
	drawn := func(salt byte) string {
		var owners []string
		for i, c := range candidates {
			if (sum[(i+int(salt))%len(sum)]>>(i%8))&1 == 1 {
				owners = append(owners, c)
			}
		}
		return lines(owners)
	}
	everyOne := append(slices.Clone(candidates), misses...)
	refusedBeside := "gitlab:acme\ngithub:acme/infra\n  \n" + candidates[0]
	upload = []string{"", lines(pinned), lines(everyOne), doc.owners, overruns[int(sum[0])%len(overruns)], drawn(0)}
	now = []string{"", lines(pinned), lines(everyOne), doc.owners, refusedBeside, drawn(7), drawn(13)}
	now = append(now, overruns...)
	now = append(now, everyOne...)
	if len(pinned) > 1 {
		for i := range pinned {
			now = append(now, lines(slices.Delete(slices.Clone(pinned), i, i+1)))
		}
	}
	// A document that pins nothing, or has no declaration of its own, would
	// otherwise be re-marked with the same declaration more than once.
	slices.Sort(upload)
	slices.Sort(now)
	return slices.Compact(upload), slices.Compact(now)
}

// TestRemarkIsAdmitsForOverTheCorpus is the property Remark exists for, over
// every JSON file under testdata: for each, the answer AdmitsFor renders with
// the owners at upload, re-marked with the owners now, is the answer
// AdmitsFor renders with the owners now, or a decline for the owners where
// nothing kept can say what that answer is. The owners are those the
// document pins, their near misses and one of each kind, so that a grant
// moves, stays, and is echoed as unmatched or spelled like another. Half
// the answers are passed back re-serialised, as a caller that parsed the
// findings passes them. Each document is also re-marked as if another build
// had kept it, which is declined.
func TestRemarkIsAdmitsForOverTheCorpus(t *testing.T) {
	docs := everyCorpusDocument(t)
	var r remarks
	var anotherBuild atomic.Int64
	read, pinning, severalOwners := 0, 0, 0
	t.Run("document", func(t *testing.T) {
		for i, doc := range docs {
			plain := Admits(doc.raw)
			a := answerOf(t, plain)
			if a.Document != nil {
				read++
			}
			pinned := pinnedOwners(a)
			if len(pinned) > 0 {
				pinning++
			}
			if slices.ContainsFunc(a.Grants, func(g Grant) bool {
				return slices.ContainsFunc(g.Populations, func(p Population) bool { return len(p.Owners) > 1 })
			}) {
				severalOwners++
			}
			name, _ := filepath.Rel(testdata, doc.path)
			t.Run(name, func(t *testing.T) {
				t.Parallel()
				policy := answersFor(doc.raw)
				upload, now := ownerSets(doc, pinned)
				for j, u := range upload {
					for k, n := range now {
						form := keptForms[(i+j+k)%len(keptForms)]
						r.hold(t, doc.path+" ("+form.name+")", policy, u, n, form.form)
					}
				}
				got := Remark(plain, []byte(oneOwnerOf(pinned)), "cloudarq v0.1.0", thisBuild)
				if d, declined := declinedOf(got); !declined || d.Declined != "engine" {
					t.Fatalf("%s: an answer another build kept was not declined for the engine: %s", doc.path, clipped(string(got)))
				}
				anotherBuild.Add(1)
			})
		}
	})
	t.Logf("%d distinct JSON files, %d read as policies, %d pinning an owner, %d with a population of several owners; %d re-marks: %d AdmitsFor's bytes (%d moved a grant), %d declined for the owners; %d declined as another build's",
		len(docs), read, pinning, severalOwners, r.equal+r.declinedForOwners, r.equal, r.moved, r.declinedForOwners, anotherBuild.Load())
	if read == 0 || r.moved == 0 || r.declinedForOwners == 0 || severalOwners == 0 {
		t.Fatalf("read=%d moved=%d declinedForOwners=%d severalOwners=%d; every count must be positive, or the property examined nothing", read, r.moved, r.declinedForOwners, severalOwners)
	}
}

// oneOwnerOf is a declaration of one owner a document pins, or of one it
// does not when it pins none.
func oneOwnerOf(pinned []string) string {
	if len(pinned) == 0 {
		return everyKindOfOwner[0]
	}
	return pinned[0]
}

// TestRemarkWithTheOwnersKeptIsTheAnswerKept is the identity control: an
// answer re-marked with the owners it was kept with is the answer, byte for
// byte, over every document and every declaration within its bounds. It
// holds of a Remark that returns what it was given, so it proves nothing
// about marking; it proves that decoding an answer and writing it again
// loses nothing, which every other test here relies on.
func TestRemarkWithTheOwnersKeptIsTheAnswerKept(t *testing.T) {
	compared := 0
	for _, doc := range everyCorpusDocument(t) {
		upload, now := ownerSets(doc, pinnedOwners(answerOf(t, Admits(doc.raw))))
		for _, owners := range append(upload, now...) {
			if pastABound(owners) {
				continue
			}
			kept := AdmitsFor(doc.raw, []byte(owners))
			if got := remarkNow(kept, owners); !bytes.Equal(got, kept) {
				at := firstDifference(got, kept)
				t.Fatalf("%s with %q: re-marked with the same owners\n...%s...\nkept\n...%s...", doc.path, clipped(owners), around(got, at), around(kept, at))
			}
			compared++
		}
	}
	if compared == 0 {
		t.Fatal("no answer was compared")
	}
	t.Logf("%d answers re-marked with the owners they were kept with", compared)
}

// placementsOf is each grant's placement in a re-marked answer.
func placementsOf(t fataler, b []byte) [][]string {
	var out [][]string
	for _, g := range answerOf(t, b).Grants {
		out = append(out, g.Placement)
	}
	return out
}

// TestRemarkKeepsPinsApart: the answer lists a population's owners as one
// list, and that list does not say how they pin it. grants/03 has two pins,
// acme by its name in the subject and @123456 by its id; rings/41 has one,
// the union acme, beta, gamma. Declaring github:acme leaves each with one
// owner of several declared, and moves the first to the user's own
// pipelines, since one of its pins is declared whole, and not the second,
// since acme's pin also admits beta and gamma.
func TestRemarkKeepsPinsApart(t *testing.T) {
	union, _ := ringsCase(t, "41-union-of-owners")
	for _, c := range []struct {
		name   string
		policy []byte
		place  string
	}{
		{"grants/03-whole-organisation", grantCase(t, "03-whole-organisation"), "yours"},
		{"rings/41-union-of-owners", union, "outsider"},
	} {
		for _, upload := range []string{"", "github:beta\ngithub:gamma\ngithub:@123456"} {
			got := remarkNow(AdmitsFor(c.policy, []byte(upload)), "github:acme")
			if want := AdmitsFor(c.policy, []byte("github:acme")); !bytes.Equal(got, want) {
				at := firstDifference(got, want)
				t.Fatalf("%s kept with %q: Remark\n...%s...\nAdmitsFor\n...%s...", c.name, upload, around(got, at), around(want, at))
			}
			g := answerOf(t, got).Grants[0]
			if len(g.Populations) != 1 || len(g.Populations[0].Owners) < 2 {
				t.Fatalf("%s: one population of several owners was expected: %+v", c.name, g.Populations)
			}
			declared := 0
			for _, o := range g.Populations[0].Owners {
				if o.Declared {
					declared++
				}
			}
			if declared != 1 || !slices.Equal(g.Placement, []string{c.place}) {
				t.Fatalf("%s kept with %q: %d owners declared, placed %v; want 1 declared and %s", c.name, upload, declared, g.Placement, c.place)
			}
		}
	}
}

// TestRemarkMarksNoNearMiss: every declaration one step from an owner leaves
// the owner a named outsider, and the declaration that names it moves it,
// each re-marked from an answer kept with no owner and from one kept with
// the other declaration, and each AdmitsFor's answer byte for byte. A name
// is not a prefix of a longer one; a name and an id are different owners
// even when they are the same digits; an account is not the organisation
// it is in, nor the organisation its accounts; GitHub's names compare in
// their own case; and a star in a declared name is part of the name.
func TestRemarkMarksNoNearMiss(t *testing.T) {
	subject := func(pattern string) []byte {
		return policyOf(onGitHub("S", "Allow", `,"StringLike":{"token.actions.githubusercontent.com:sub":"`+pattern+`"}`))
	}
	evilSubject, octoSubject := subject("repo:octo-org-evil/*"), subject("repo:octo-org/*")
	// The owner's id pins only as an exact value: a pattern on it admits
	// every id it matches.
	ownerID := policyOf(`{"Effect":"Allow","Principal":{"Federated":"arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"},"Action":"sts:AssumeRoleWithWebIdentity","Condition":{"StringEquals":{"token.actions.githubusercontent.com:aud":"sts.amazonaws.com","token.actions.githubusercontent.com:repository_owner_id":"123456"}}}`)
	account, _ := ringsCase(t, "34-aws-account")
	organisation := policyOf(`{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole","Condition":{"StringEquals":{"aws:PrincipalOrgID":"o-a1b2c3d4e5"}}}`)
	for _, c := range []struct {
		name        string
		policy      []byte
		miss, owner string
	}{
		{"a shorter name that begins alike", evilSubject, "github:octo-org", "github:octo-org-evil"},
		{"a longer name that begins alike", octoSubject, "github:octo-org-evil", "github:octo-org"},
		{"the same name in another case", octoSubject, "github:Octo-Org", "github:octo-org"},
		{"a star in the name", octoSubject, "github:octo-*", "github:octo-org"},
		{"an id written as a name", ownerID, "github:123456", "github:@123456"},
		{"an organisation for an account", account, "aws:o-a1b2c3d4e5", "aws:111122223333"},
		{"an account for an organisation", organisation, "aws:111122223333", "aws:o-a1b2c3d4e5"},
	} {
		for _, step := range []struct{ upload, now, place string }{
			{"", c.miss, "outsider"},
			{c.owner, c.miss, "outsider"},
			{"", c.owner, "yours"},
			{c.miss, c.owner, "yours"},
		} {
			got := remarkNow(AdmitsFor(c.policy, []byte(step.upload)), step.now)
			if want := AdmitsFor(c.policy, []byte(step.now)); !bytes.Equal(got, want) {
				at := firstDifference(got, want)
				t.Fatalf("%s, kept with %q, re-marked with %q: Remark\n...%s...\nAdmitsFor\n...%s...", c.name, step.upload, step.now, around(got, at), around(want, at))
			}
			a := answerOf(t, got)
			// A principal of "*" is also every AWS service, a grant of its
			// own; the grant the owner pins is the one that moves.
			i := slices.IndexFunc(a.Grants, func(g Grant) bool {
				return slices.ContainsFunc(g.Populations, func(p Population) bool { return len(p.Owners) > 0 })
			})
			if p := a.Grants[max(i, 0)].Placement; i < 0 || !slices.Equal(p, []string{step.place}) {
				t.Fatalf("%s, kept with %q, re-marked with %q: placed %v, want %s", c.name, step.upload, step.now, p, step.place)
			}
			// The near miss moved nothing and is echoed as declaring no owner
			// the role admits; the owner is not.
			unmatched := len(a.Declarations.Unmatched) == 1 && a.Declarations.Unmatched[0].Declaration == step.now
			if unmatched != (step.now == c.miss) {
				t.Fatalf("%s, re-marked with %q: echoed %+v", c.name, step.now, a.Declarations)
			}
		}
	}
}

// TestRemarkDeclinesWhatItCannotSayExactly: the answers Remark declines
// though this engine's AdmitsFor wrote them, and what it declines as no
// answer this build writes. An answer another build kept is declined
// whatever it holds, since the facts and the words it was read with may not
// be this build's; an answer kept after the owners were refused whole kept
// no grant to place again, whichever bound they went past; and beside an
// answer that stopped at its document, owners past their bounds now would
// be refused or not as the document was read or not, which an error does
// not say. Owners past their bounds now are refused by the next upload, or
// never reached by it, whatever else declines the answer. Each decline is
// the whole result. Beside owners past their bounds it says the role keeps
// the answer it has; beside owners within them, that the role is read
// again with them at the next upload, and never that it is updated with
// them: Remark cannot tell an answer this build wrote from a forged one,
// nor which document either stood for, and that document may be one this
// build refuses.
func TestRemarkDeclinesWhatItCannotSayExactly(t *testing.T) {
	policy := grantCase(t, "03-whole-organisation")
	truncated := []byte(`{"Version":"2012-10-17","Statement":`)
	notAnAnswer := []byte("not an answer")
	neitherReadNorRefused := []byte(`{"v":` + strconv.Itoa(Version) + `,"grants":[]}`)
	type decline struct {
		name                  string
		kept                  []byte
		owners, wrote, engine string
		why                   string
	}
	cases := []decline{
		{"another build", Admits(policy), "github:acme", "cloudarq v0.2.0", "cloudarq v0.3.0", "engine"},
		{"a build that names no engine", Admits(policy), "github:acme", "", thisBuild, "engine"},
		{"another build, with the owners it was kept with", AdmitsFor(policy, []byte("github:acme")), "github:acme", "cloudarq v0.2.0-dirty", "cloudarq v0.2.0", "engine"},
		{"another build, for a document this build refuses", Admits(truncated), "github:acme", "cloudarq v0.2.0", "cloudarq v0.3.0", "engine"},
		{"not an answer", notAnAnswer, "github:acme", thisBuild, thisBuild, "answer"},
		{"an answer that read no document and refused none", neitherReadNorRefused, "github:acme", thisBuild, thisBuild, "answer"},
	}
	for _, o := range overruns {
		past := ", where " + overrunWords(*ring.ReadDeclarations(o).Overrun)
		cases = append(cases,
			decline{"owners refused whole at upload" + past, AdmitsFor(policy, []byte(o)), "github:acme", thisBuild, thisBuild, "owners"},
			decline{"owners refused whole at upload and now" + past, AdmitsFor(policy, []byte(o)), o, thisBuild, thisBuild, "owners"},
			decline{"owners refused whole now, beside a document refused" + past, Admits(truncated), o, thisBuild, thisBuild, "owners"},
			decline{"owners refused whole now, beside another build's answer" + past, Admits(policy), o, "cloudarq v0.2.0", "cloudarq v0.3.0", "owners"},
			decline{"owners refused whole now, beside what is not an answer" + past, notAnAnswer, o, thisBuild, thisBuild, "owners"},
			decline{"owners refused whole now, beside an answer that read no document and refused none" + past, neitherReadNorRefused, o, thisBuild, thisBuild, "owners"},
		)
	}
	// Each overrun goes past its own bound, so that the refusal of the owners
	// is recognised in each of the three sentences that say one.
	var bounds []ring.Bound
	for _, o := range overruns {
		bounds = append(bounds, ring.ReadDeclarations(o).Overrun.Bound)
	}
	if !slices.Equal(bounds, []ring.Bound{ring.DeclarationBytes, ring.DeclarationLines, ring.LineBytes}) {
		t.Fatalf("the overruns go past %v", bounds)
	}
	for _, c := range cases {
		got := Remark(c.kept, []byte(c.owners), c.wrote, c.engine)
		d, declined := declinedOf(got)
		if !declined || d.V != Version || d.Declined != c.why {
			t.Errorf("%s: want a decline for %q, got %s", c.name, c.why, got)
			continue
		}
		if plain(d.Spans) != d.Sentence {
			t.Errorf("%s: the decline says %q in spans %+v", c.name, d.Sentence, d.Spans)
		}
		ending := "this role is read again with the owners declared now at the next upload."
		if pastABound(c.owners) {
			ending = "this role keeps the answer it has."
		}
		if strings.Contains(d.Sentence, "updated with") || !strings.HasSuffix(d.Sentence, ending) {
			t.Errorf("%s: the decline says %q, where it promises no update and ends %q", c.name, d.Sentence, ending)
		}
		var members map[string]json.RawMessage
		if err := json.Unmarshal(got, &members); err != nil || len(members) != 4 {
			t.Errorf("%s: a decline carries v, declined, sentence and spans and nothing else: %s", c.name, got)
		}
	}
	t.Logf("%d declines examined", len(cases))
}

// grantsEdited is an answer with every grant edited, as a caller that keeps a
// typed subset of the answer passes it back.
func grantsEdited(t fataler, kept []byte, edit func(grant map[string]any)) []byte {
	var answer map[string]any
	if err := json.Unmarshal(kept, &answer); err != nil {
		t.Fatalf("the answer kept is not JSON: %v", err)
	}
	grants, _ := answer["grants"].([]any)
	for _, g := range grants {
		edit(g.(map[string]any))
	}
	b, err := json.Marshal(answer)
	if err != nil {
		t.Fatalf("%v", err)
	}
	return b
}

// TestRemarkDeclinesAnAnswerMissingWhatPlacedIt: a caller that keeps a typed
// subset of an answer may pass it back without a member of its grants. The
// populations carry two facts the parser read of the statement and the
// answer states nowhere else, whether it modelled the principal and whom a
// statement naming no issuer admits; without them a grant would be placed
// from its terms alone, as if the parser had read its principal. The notes
// carry the caveats; without them a set read in part is rebuilt as read in
// full, and a grant placed with the whole platform as unknown, because a
// constraint on it was not read, is placed there exactly. Every answer of
// the corpus that loses a member one of its grants states is declined as
// not an answer this build writes; first among them a principal the parser
// does not model, an S3 bucket, pinned to an account, which is anyone's and
// would otherwise land in the user's own ring.
func TestRemarkDeclinesAnAnswerMissingWhatPlacedIt(t *testing.T) {
	notModelled := corpusDocument{
		path: "a principal the parser does not model, pinned to an account",
		raw:  policyOf(`{"Effect":"Allow","Principal":{"AWS":"arn:aws:s3:::deploy-bucket"},"Action":"sts:AssumeRole","Condition":{"StringEquals":{"aws:PrincipalAccount":"111122223333"}}}`),
	}
	docs := append([]corpusDocument{notModelled}, everyCorpusDocument(t)...)
	placed := func(g Grant) bool { return len(g.Populations) > 0 }
	caveated := func(g Grant) bool {
		return slices.ContainsFunc(g.Notes, func(n Note) bool { return n.Kind == "caveat" })
	}
	for _, missing := range []struct {
		name   string
		states func(Grant) bool
		edit   func(grant map[string]any)
	}{
		{"populations absent", placed, func(g map[string]any) { delete(g, "populations") }},
		{"populations empty", placed, func(g map[string]any) { g["populations"] = []any{} }},
		{"populations null", placed, func(g map[string]any) { g["populations"] = nil }},
		{"notes absent", caveated, func(g map[string]any) { delete(g, "notes") }},
		{"notes empty", caveated, func(g map[string]any) { g["notes"] = []any{} }},
	} {
		examined, declined := 0, 0
		var first string
		for _, doc := range docs {
			kept := Admits(doc.raw)
			a := answerOf(t, kept)
			if !slices.ContainsFunc(a.Grants, missing.states) {
				continue
			}
			examined++
			// Every owner the answer pins is declared, and one of each kind,
			// so that a grant placed from its terms alone moves if it can.
			owners := strings.Join(append(pinnedOwners(a), everyKindOfOwner...), "\n")
			got := remarkNow(grantsEdited(t, kept, missing.edit), owners)
			if d, ok := declinedOf(got); ok && d.Declined == "answer" {
				declined++
				continue
			}
			if first == "" {
				var headline string
				if h := answerOf(t, got).Headline; h != nil {
					headline = h.Sentence
				}
				first = fmt.Sprintf("%s, re-marked with %q: placed %v under %q", doc.path, owners, placementsOf(t, got), headline)
			}
		}
		t.Logf("%s: %d answers examined, %d declined as not an answer", missing.name, examined, declined)
		if examined == 0 {
			t.Errorf("%s: no answer states what was removed, so nothing was examined", missing.name)
		}
		if declined != examined {
			t.Errorf("%s: %d of %d answers were re-marked rather than declined; the first: %s", missing.name, examined-declined, examined, first)
		}
	}
}

// The universe the generated policies are written in. It is small on
// purpose, so that a declaration drawn from it often names an owner a
// policy drawn from it pins, and often nearly does.
var (
	remarkGitHubNames = []string{"acme", "Acme", "beta", "gamma", "octo-org", "octo-org-evil", "Octo-Org"}
	remarkGitHubIDs   = []string{"123456", "654321", "1234567"}
	remarkAccounts    = []string{"111122223333", "444455556666", "111122223334"}
	remarkOrgs        = []string{"o-a1b2c3d4e5", "o-f6g7h8i9j0"}
	remarkProviders   = []string{"arn:aws:iam::123456789012:saml-provider/CorpIdP", "arn:aws:iam::123456789012:saml-provider/CorpIdQ"}
	remarkEKS         = "https://oidc.eks.us-east-1.amazonaws.com/id/EXAMPLED539D4633E53DE1B71EXAMPLE"

	// remarkOperators are the condition operators a generated condition is
	// written under: those that pin, those that read a set, those that
	// widen to whether a key exists, and those the parser does not
	// evaluate, so that a grant is rebuilt with Unknowns and caveats as well
	// as with exact values, patterns and unions.
	remarkOperators = []string{
		"StringEquals", "StringEquals", "StringEquals", "StringLike", "StringLike", "StringLike",
		"StringEqualsIfExists", "StringLikeIfExists", "ForAnyValue:StringEquals", "ForAllValues:StringLike",
		"StringNotEquals", "StringNotLike", "StringEqualsIgnoreCase", "ArnLike",
	}
)

// remarkGitHubValue draws a value for a GitHub claim: what pins an owner by
// name or by id, what nearly does, what pins nothing, and what the parser
// cannot read.
func remarkGitHubValue(t *rapid.T, claim string) string {
	name := rapid.SampledFrom(remarkGitHubNames).Draw(t, "name")
	id := rapid.SampledFrom(remarkGitHubIDs).Draw(t, "id")
	byClaim := map[string][]string{
		"sub": {
			"repo:" + name + "/*", "repo:" + name + "/infra:ref:refs/heads/main", "repo:" + name + "@" + id + "/*",
			"repo:" + name + "*", "repo:*", "repo:" + name + "/${aws:username}", "repo:" + name + "/${*}",
		},
		"repository_owner":    {name, name, name + "*", "octo-*"},
		"repository_owner_id": {id, id, id[:3] + "*"},
		"repository_id":       {"456789"},
		"job_workflow_ref":    {name + "/deploy/.github/workflows/release.yml@refs/heads/main"},
		"aud":                 {"sts.amazonaws.com", "https://github.com/" + name},
	}
	return rapid.SampledFrom(byClaim[claim]).Draw(t, "value")
}

// remarkConditions draws a statement's Condition: up to three conditions,
// most often two or three, each under an operator, on a key, with up to
// remarkValues values. Two values are a union, two conditions on one claim
// meet, and two claims that pin are two pins; so a population is pinned by
// several owners in both of the ways the answer flattens into one list.
func remarkConditions(t *rapid.T, keys []string, value func(*rapid.T, string) string) map[string]map[string][]string {
	conditions := map[string]map[string][]string{}
	for range rapid.SampledFrom([]int{0, 1, 2, 2, 3, 3}).Draw(t, "conditions") {
		operator := rapid.SampledFrom(remarkOperators).Draw(t, "operator")
		key := rapid.SampledFrom(keys).Draw(t, "key")
		n := rapid.IntRange(1, remarkValues).Draw(t, "values")
		var vs []string
		for range n {
			vs = append(vs, value(t, key))
		}
		if conditions[operator] == nil {
			conditions[operator] = map[string][]string{}
		}
		conditions[operator][key] = vs
	}
	return conditions
}

// remarkValues is how many values a generated condition may hold.
const remarkValues = 3

// remarkStatement is one statement of a generated policy, and the sets its
// grants are met with, in turn, once it is read: what further conditions on
// its claims would require, in eval's terms, since the reader writes no such
// set (admitsMeeting says why).
type remarkStatement struct {
	text string
	meet []eval.AdmittedSet
}

// meetable is a claim a statement's grants are met on, and the patterns
// drawn for it, each written so that it pins an owner, nearly does, or
// overlaps a pattern the statement's own conditions write.
type meetable struct {
	claim    string
	patterns []string
}

var (
	gitHubMeetable = []meetable{
		{"sub", []string{"repo:acme/*", "repo:beta/*", "repo:octo-org*", "*:ref:refs/heads/main", "repo:*/infra:*"}},
		{"repository_owner", []string{"ac*", "*me", "octo-*"}},
		{"job_workflow_ref", []string{"acme/*", "*@refs/heads/main"}},
	}
	awsMeetable = []meetable{
		{"aws:principalarn", []string{"arn:aws:iam::111122223333:*", "arn:aws:iam::*:role/deploy", "arn:aws:iam::1111*"}},
		{"aws:principalaccount", []string{"1111*", "*3333"}},
		{"aws:principalorgid", []string{"o-a1b2*", "o-*e5"}},
	}
	eksMeetable = []meetable{
		{"sub", []string{"system:serviceaccount:deploy:*", "system:serviceaccount:*:runner"}},
	}
)

// genRemarkMeet draws what a statement's grants are met with once it is
// read: nothing seven times in ten, since only a policy read as written
// counts toward the mixed re-marks; patterns on its claims twice, so that a
// claim holds an intersection, a union of intersections, or the grant
// several terms; or once, under an Allow, the two lists of termsToTheBound,
// past the bound three times in four, since an answer of 256 terms takes
// most of the run to render and decode. rapid shrinks a draw toward the
// bottom of its range, so a failure shrinks to the fewest statements met
// that show it.
func genRemarkMeet(t *rapid.T, effect string, claims []meetable) []eval.AdmittedSet {
	switch rapid.IntRange(0, 9).Draw(t, "met with") {
	case 7, 8:
		if len(claims) == 0 {
			return nil
		}
		var terms []eval.Term
		for range rapid.IntRange(1, 3).Draw(t, "met terms") {
			term := eval.Term{}
			for range rapid.IntRange(1, 2).Draw(t, "met claims") {
				m := rapid.SampledFrom(claims).Draw(t, "met claim")
				term[eval.ClaimKey(m.claim)] = genRemarkPatterns(t, m.patterns)
			}
			terms = append(terms, term)
		}
		return []eval.AdmittedSet{eval.NewAdmittedSet(terms...)}
	case 9:
		if effect == "Allow" {
			return termsToTheBound(rapid.SampledFrom([]int{17, 17, 17, 16}).Draw(t, "terms on actor"))
		}
	}
	return nil
}

// genRemarkPatterns draws a set of patterns on one claim: a pattern, either
// of two, both of two, or both of two or a third, which eval writes as a
// pattern, a union, an intersection, and a union holding an intersection.
func genRemarkPatterns(t *rapid.T, patterns []string) eval.StringSet {
	pattern := func(label string) eval.StringSet { return eval.Glob(rapid.SampledFrom(patterns).Draw(t, label)) }
	switch rapid.IntRange(0, 3).Draw(t, "patterns") {
	case 1:
		return pattern("pattern").Join(pattern("or"))
	case 2:
		return pattern("pattern").Meet(pattern("and"))
	case 3:
		return pattern("pattern").Meet(pattern("and")).Join(pattern("or"))
	}
	return pattern("pattern")
}

// termsAtTheBound is the most terms eval keeps in a set; one more widens it.
const termsAtTheBound = 256

// termsToTheBound is two lists of terms, each term a pattern on a claim no
// generated condition names, so that none dies when met with a grant's one
// term: first terms on actor, then 16 on workflow. Met in turn with such a
// grant they make first × 16 terms: 256 with 16, at eval's bound, which it
// keeps; 272 with 17, past it, which eval widens to everything, with a
// caveat saying so.
func termsToTheBound(first int) []eval.AdmittedSet {
	list := func(claim string, n int) eval.AdmittedSet {
		terms := make([]eval.Term, n)
		for i := range terms {
			terms[i] = eval.Term{eval.ClaimKey(claim): eval.Glob(claim + "-" + strconv.Itoa(i) + "-*")}
		}
		return eval.NewAdmittedSet(terms...)
	}
	return []eval.AdmittedSet{list("actor", first), list("workflow", 16)}
}

// admitsMeeting is the answer admits renders for a policy and owners, with
// the grants of each statement given met, after the policy is read and
// before any grant is placed, with that statement's sets in turn. The AWS
// reader writes none of the sets Remark must rebuild all the same: of two
// conditions it reads on one claim, one names a value under StringEquals,
// which decides the meeting, since StringLike is the only operator it reads
// as patterns; two patterns on one claim need that operator block or the
// key written twice, which it reads as not known; and it reads a statement
// as one term, so no set it reads comes near eval's term bound. Met here,
// the sets are rendered and placed by admits' own functions and the one
// classifier. With nothing to meet it is AdmitsFor's answer, and the
// generated property holds it to that on every draw, so that the two cannot
// drift apart.
func admitsMeeting(t fataler, policy, owners []byte, met map[int][]eval.AdmittedSet) []byte {
	r, err := readPolicy(policy)
	declared := ring.ReadDeclarations(string(owners))
	if err != nil || declared.Overrun != nil {
		// No grant was read, so nothing is met.
		return AdmitsFor(policy, owners)
	}
	for i, s := range r.statements {
		for _, set := range met[s] {
			r.grants[i].Admits = r.grants[i].Admits.Meet(set)
		}
	}
	a := Answer{V: Version, Document: r.document(), Grants: []Grant{}}
	placed := r.place(declared.Owners)
	for i := range r.grants {
		grant, err := r.grant(i)
		if err != nil {
			t.Fatalf("grant %d of %s does not render once met: %v", i+1, policy, err)
		}
		grant.Placement, grant.PlacementState, grant.Populations = placementOf(placed[i].placement)
		r.ways(i, placed[i], &grant, a.Document)
		a.Grants = append(a.Grants, grant)
	}
	a.fixes(r, &placing{read: r, declared: declared, placed: placed})
	a.rings(placed, declared)
	e := &encoder{}
	e.answer(a)
	return e.b
}

// genRemarkStatement draws one statement, of every kind of principal the
// classifier places: GitHub's issuer, most often, since its claims pin
// owners by name and by id; an AWS principal pinned by account or
// organisation; a SAML provider; a per-tenant issuer; and a service, anyone
// at all and a principal the parser does not model. Beside it, what its
// grants are met with once read.
func genRemarkStatement(t *rapid.T) remarkStatement {
	effect := rapid.SampledFrom([]string{"Allow", "Allow", "Allow", "Deny"}).Draw(t, "effect")
	var principal, action string
	var conditions map[string]map[string][]string
	var claims []meetable
	switch rapid.IntRange(0, 9).Draw(t, "principal kind") {
	case 0, 1, 2, 3, 4:
		principal, action = `{"Federated":"arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"}`, `"sts:AssumeRoleWithWebIdentity"`
		var keys []string
		for _, claim := range []string{"sub", "sub", "repository_owner", "repository_owner_id", "repository_id", "job_workflow_ref", "aud"} {
			keys = append(keys, "token.actions.githubusercontent.com:"+claim)
		}
		conditions = remarkConditions(t, keys, func(t *rapid.T, key string) string {
			return remarkGitHubValue(t, strings.TrimPrefix(key, "token.actions.githubusercontent.com:"))
		})
		claims = gitHubMeetable
	case 5, 6:
		principal = rapid.SampledFrom([]string{`"*"`, `{"AWS":"*"}`, `{"AWS":"111122223333"}`, `{"AWS":"arn:aws:iam::444455556666:role/deploy"}`, `{"AWS":["111122223333","444455556666"]}`}).Draw(t, "aws principal")
		action = `"sts:AssumeRole"`
		conditions = remarkConditions(t, []string{"aws:PrincipalAccount", "aws:PrincipalOrgID", "aws:PrincipalArn", "aws:SourceAccount", "sts:ExternalId"}, func(t *rapid.T, key string) string {
			account := rapid.SampledFrom(remarkAccounts).Draw(t, "account")
			return rapid.SampledFrom(map[string][]string{
				"aws:PrincipalAccount": {account, account[:4] + "*"},
				"aws:PrincipalOrgID":   {rapid.SampledFrom(remarkOrgs).Draw(t, "organisation"), "o-a1b2*"},
				"aws:PrincipalArn":     {"arn:aws:iam::" + account + ":role/*", "arn:aws:iam::" + account + ":root", "arn:aws:iam::1111*"},
				"aws:SourceAccount":    {account},
				"sts:ExternalId":       {"vendor-abc"},
			}[key]).Draw(t, "value")
		})
		claims = awsMeetable
	case 7:
		principal = `{"Federated":"` + rapid.SampledFrom(remarkProviders).Draw(t, "provider") + `"}`
		action = rapid.SampledFrom([]string{`"sts:AssumeRoleWithSAML"`, `["sts:AssumeRoleWithSAML","sts:TagSession"]`}).Draw(t, "saml action")
		conditions = map[string]map[string][]string{"StringEquals": {"SAML:aud": {"https://signin.aws.amazon.com/saml"}}}
	case 8:
		principal, action = `{"Federated":"arn:aws:iam::123456789012:oidc-provider/`+strings.TrimPrefix(remarkEKS, "https://")+`"}`, `"sts:AssumeRoleWithWebIdentity"`
		conditions = map[string]map[string][]string{"StringEquals": {strings.TrimPrefix(remarkEKS, "https://") + ":sub": {"system:serviceaccount:deploy:runner"}}}
		claims = eksMeetable
	default:
		principal = rapid.SampledFrom([]string{
			`"*"`, `{"Service":"sns.amazonaws.com"}`, `{"Service":"rolesanywhere.amazonaws.com"}`,
			`{"CanonicalUser":"79a59df900b949e55d96a1e698fbacedfd6e09d98eacf8f8d5218e7cd47ef2be"}`,
			`{"Federated":"accounts.google.com"}`,
		}).Draw(t, "other principal")
		action = rapid.SampledFrom([]string{`"sts:AssumeRole"`, `"sts:AssumeRoleWithSAML"`, `"sts:*"`, `["sts:AssumeRole","sts:AssumeRoleWithSAML"]`, `"sts:AssumeRoleWithWebIdentity"`}).Draw(t, "other action")
	}
	condition, err := json.Marshal(conditions)
	if err != nil {
		t.Fatalf("%v", err)
	}
	return remarkStatement{
		text: `{"Effect":"` + effect + `","Principal":` + principal + `,"Action":` + action + `,"Condition":` + string(condition) + `}`,
		meet: genRemarkMeet(t, effect, claims),
	}
}

// remarkDeclarable is every line a generated declaration is drawn from:
// each owner the generated policies can pin, the near misses of each, and
// lines the grammar refuses.
var remarkDeclarable = []string{
	"github:acme", "github:Acme", "github:beta", "github:gamma", "github:octo-org", "github:Octo-Org", "github:octo-org-evil", "github:octo-*",
	"github:@123456", "github:123456", "github:acme@123456", "github:beta@654321", "github:@654321", "github:@1234567",
	"aws:111122223333", "aws:444455556666", "aws:111122223334", "aws:o-a1b2c3d4e5", "aws:o-f6g7h8i9j0",
	"saml:" + remarkProviders[0], "saml:" + remarkProviders[1], "issuer:" + remarkEKS,
	"gitlab:acme", "github:acme/infra", "acme",
}

// genRemarkOwners draws a declaration: each owner the policy pins with one
// chance in two, so that a population of several owners is often declared
// in part; each line of remarkDeclarable with one chance in four; and now
// and then one past a bound. rapid shrinks a draw toward the bottom of its
// range, so a line is declared, and a bound passed, only at the top of
// theirs: a failure shrinks to the fewest owners that show it.
func genRemarkOwners(t *rapid.T, label string, pinned []string) string {
	if rapid.IntRange(0, 24).Draw(t, label+" past a bound") == 24 {
		return rapid.SampledFrom(overruns).Draw(t, label+" overrun")
	}
	var lines []string
	for _, d := range pinned {
		if rapid.Bool().Draw(t, label+" pinned "+d) {
			lines = append(lines, d)
		}
	}
	for _, d := range remarkDeclarable {
		if rapid.IntRange(0, 3).Draw(t, label+" "+d) == 3 {
			lines = append(lines, d)
		}
	}
	return strings.Join(lines, "\n")
}

// mixed reports how a re-marked answer places a population pinned by
// several owners of which some, not all, are declared: in the user's own
// ring, when one pin of several is declared whole, and with a named
// outsider, when a pin of several owners is declared in part.
func mixed(a Answer) (yours, outsider bool) {
	for _, g := range a.Grants {
		for _, p := range g.Populations {
			declared := 0
			for _, o := range p.Owners {
				if o.Declared {
					declared++
				}
			}
			if declared == 0 || declared == len(p.Owners) {
				continue
			}
			switch p.Place {
			case "yours", "people":
				yours = true
			case "outsider":
				outsider = true
			}
		}
	}
	return yours, outsider
}

// grantShapes counts the grants a property re-marked by what Remark had to
// rebuild them from, so that a run says which shapes it examined. The
// generated property requires three of the counts, for the shapes only the
// sets it meets into its grants make; the others are logged, and a shape
// the generator does not reach shows as a zero to whoever reads the run.
type grantShapes struct {
	grants, unknown, severalReasons, union, intersection, unionOfIntersections int
	caveat, widened, severalTerms, atTheBound, beyond, notModelled, issuerless int
}

func (c *grantShapes) add(a Answer) {
	for _, g := range a.Grants {
		c.grants++
		has := func(row func(Claim) bool) bool {
			return slices.ContainsFunc(g.Terms, func(rows []Claim) bool { return slices.ContainsFunc(rows, row) })
		}
		basis := func(b ...string) bool {
			return slices.ContainsFunc(g.Populations, func(p Population) bool { return slices.Contains(b, p.Basis) })
		}
		caveat := func(n Note) bool { return n.Kind == "caveat" }
		for _, counted := range []struct {
			n  *int
			is bool
		}{
			{&c.unknown, has(func(r Claim) bool { return strings.HasPrefix(r.Rendered, "?(") })},
			{&c.severalReasons, has(func(r Claim) bool { return strings.HasPrefix(r.Rendered, "?(") && strings.Contains(r.Rendered, `", "`) })},
			{&c.union, has(func(r Claim) bool { return r.Constraint.Kind == kindUnion })},
			{&c.intersection, has(func(r Claim) bool { return strings.Contains(r.Rendered, " & ") })},
			{&c.unionOfIntersections, has(func(r Claim) bool { return listsDeep(r.Rendered) == 2 })},
			{&c.caveat, slices.ContainsFunc(g.Notes, caveat)},
			{&c.widened, slices.ContainsFunc(g.Notes, func(n Note) bool { return caveat(n) && strings.Contains(n.Message, "term count exceeded") })},
			{&c.severalTerms, len(g.Terms) > 1},
			{&c.atTheBound, len(g.Terms) == termsAtTheBound},
			{&c.beyond, g.Beyond},
			{&c.notModelled, basis(ring.PrincipalNotModelled.String())},
			{&c.issuerless, basis(ring.AnyService.String(), ring.AccountSAMLProviders.String(), ring.AnyIssuer.String())},
		} {
			if counted.is {
				*counted.n++
			}
		}
	}
}

// TestRemarkIsAdmitsForOnGeneratedPolicies is the property over trust
// policies the corpus does not hold: populations pinned through unions,
// through several claims and through conditions that meet, under every
// operator, re-marked from declarations drawn at upload and now. The
// corpus holds few populations of several owners, so the proof that pins
// are kept apart rests here, and it counts the re-marks that prove it: a
// population re-marked with some of its owners declared that lands in the
// user's ring, and one that stays with a named outsider. Either count at
// zero fails, since then the generator proved nothing about it.
//
// No answer AdmitsFor writes holds a claim of several patterns that meet, a
// union holding such a claim, or a set eval widened past its term bound,
// since the reader writes none of them (admitsMeeting says why); Remark
// rebuilds each from its rendering all the same, and must give the reader's
// answer the day the reader meets patterns. So a drawn statement's grants
// may be met, once read, with patterns on its claims or with terms up to
// and past the bound, and the answer held to is admits' with those sets in
// place; a count of zero grants holding any of the three fails as well.
func TestRemarkIsAdmitsForOnGeneratedPolicies(t *testing.T) {
	var r remarks
	var shapes grantShapes
	mixedYours, mixedOutsider := 0, 0
	// Two thousand policies rather than rapid's hundred: a population
	// declared in part lands in the user's ring in about one draw in a
	// hundred, and the check below fails on a count of zero.
	for range 20 {
		rapid.Check(t, func(t *rapid.T) {
			statements := rapid.SliceOfN(rapid.Custom(genRemarkStatement), 1, 3).Draw(t, "statements")
			texts := make([]string, len(statements))
			met := map[int][]eval.AdmittedSet{}
			var metWith []string
			for i, s := range statements {
				texts[i] = s.text
				if len(s.meet) == 0 {
					continue
				}
				met[i] = s.meet
				var sets []string
				for _, set := range s.meet {
					sets = append(sets, set.String())
				}
				metWith = append(metWith, fmt.Sprintf("statement %d met with %s", i, strings.Join(sets, " and then ")))
			}
			raw := policyOf(texts...)
			policy := answersBy(raw, func(owners []byte) []byte { return admitsMeeting(t, raw, owners, met) })
			pinned := pinnedOwners(answerOf(t, policy.with("")))
			upload, now := genRemarkOwners(t, "upload", pinned), genRemarkOwners(t, "now", pinned)
			if read, want := admitsMeeting(t, raw, []byte(upload), nil), AdmitsFor(raw, []byte(upload)); !bytes.Equal(read, want) {
				at := firstDifference(read, want)
				t.Fatalf("met with nothing, the answer is not AdmitsFor's:\n...%s...\nAdmitsFor\n...%s...\npolicy: %s", around(read, at), around(want, at), raw)
			}
			form := rapid.SampledFrom(keptForms).Draw(t, "kept form")
			shapes.add(answerOf(t, policy.with("")))
			name := "generated (" + form.name + ")"
			if len(metWith) > 0 {
				name += ", " + strings.Join(metWith, "; ")
			}
			// Only a policy read as written counts toward the mixed re-marks:
			// a union of patterns met into a grant pins several owners of
			// its own, and would keep both counts above zero for a
			// generator whose policies pin no population by several.
			if !r.hold(t, name, policy, upload, now, form.form) || len(met) > 0 || bytes.Equal(policy.with(upload), policy.with(now)) {
				return
			}
			yours, outsider := mixed(answerOf(t, policy.with(now)))
			if yours {
				mixedYours++
			}
			if outsider {
				mixedOutsider++
			}
		})
	}
	t.Logf("%d re-marks: %d AdmitsFor's bytes (%d moved a grant), %d declined for the owners; mixed re-marks: %d in the user's ring, %d with a named outsider",
		r.equal+r.declinedForOwners, r.equal, r.moved, r.declinedForOwners, mixedYours, mixedOutsider)
	t.Logf("grants drawn %+v", shapes)
	if mixedYours == 0 || mixedOutsider == 0 {
		t.Fatalf("mixed re-marks: %d in the user's ring, %d with a named outsider; both must be positive, or no population of several owners was re-marked", mixedYours, mixedOutsider)
	}
	if shapes.intersection == 0 || shapes.unionOfIntersections == 0 || shapes.widened == 0 {
		t.Fatalf("grants drawn with an intersection: %d, with a union of intersections: %d, widened past the term bound: %d; each must be positive, or Remark's rebuild of that set was not examined", shapes.intersection, shapes.unionOfIntersections, shapes.widened)
	}
}

// recognisedAnswers are the answers a scan's findings keep for roles that
// trust the account the scan read, beside one or more other owners, and
// for roles that trust none of them, each with the policy it was read from
// and the owners declared at upload.
func recognisedAnswers(t *testing.T) (kept []struct {
	policy, upload string
	answer         []byte
}) {
	t.Helper()
	documents := []string{ownAccountTrust, ownAndManaging, managementTrust, githubTrust, orgTrust}
	var roles []testRole
	for i, d := range documents {
		roles = append(roles, testRole{"role" + strconv.Itoa(i), d})
	}
	bundle := bundleOf(t, organizationMember(management, nil), roles...)
	for _, upload := range []string{"", "aws:" + management, "aws:" + bundleAccount} {
		for i, role := range findingsOf(t, bundle, upload).Roles {
			kept = append(kept, struct {
				policy, upload string
				answer         []byte
			}{documents[i], upload, role.Answer})
		}
	}
	return kept
}

// TestRemarkKeepsTheAccountRecognised: an answer a scan kept, re-marked
// with the owners declared now, is the answer the findings give its policy
// with those owners and the account the scan read recognised still, in
// every form a caller keeps it in. The account is the reader's whatever
// they declare, so no declaration made later drops it.
func TestRemarkKeepsTheAccountRecognised(t *testing.T) {
	recognised := Bundle{Account: bundleAccount}.recognised()
	marked := 0
	for _, k := range recognisedAnswers(t) {
		for _, now := range []string{"", "aws:" + management, "aws:" + bundleAccount, "github:acme", "aws:" + orgID} {
			want := admitsWith(nil, []byte(k.policy), []byte(now), recognised)
			for _, kf := range keptForms {
				if got := remarkNow(kf.form(t, k.answer), now); !bytes.Equal(got, want) {
					t.Fatalf("%s, kept with %+q, re-marked %s with %+q:\n got %s\nwant %s", k.policy, k.upload, kf.name, now, got, want)
				}
			}
			if a := answerOf(t, want); a.Declarations != nil && len(a.Declarations.Recognitions) > 0 {
				marked++
			}
		}
	}
	if marked == 0 {
		t.Fatal("no answer re-marked recognised an owner; the property examined nothing")
	}
}

// TestRemarkDeclinesARecognitionItWouldNotWrite: the owners recognised are
// the account a scan read and nothing else, so an answer that recognises
// anything this build would not, or whose owners and echo disagree on what
// is recognised, is declined, never re-marked as though it were the reader's.
func TestRemarkDeclinesARecognitionItWouldNotWrite(t *testing.T) {
	var own, managed []byte
	for _, k := range recognisedAnswers(t) {
		switch {
		case k.policy == ownAccountTrust && k.upload == "":
			own = k.answer
		case k.policy == managementTrust && k.upload == "":
			managed = k.answer
		}
	}
	echo := func(answer []byte, recognitions any) []byte {
		var v map[string]any
		if err := json.Unmarshal(answer, &v); err != nil {
			t.Fatal(err)
		}
		d := v["declarations"].(map[string]any)
		if recognitions == nil {
			delete(d, "recognitions")
		} else {
			d["recognitions"] = recognitions
		}
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	one := func(declaration, sentence string) []any {
		return []any{map[string]any{"declaration": declaration, "sentence": sentence}}
	}
	const why = "recognised: the account this scan read"
	for _, c := range []struct {
		name   string
		answer []byte
	}{
		{"the recognitions dropped", echo(own, nil)},
		{"a GitHub owner recognised", echo(own, one("github:acme", why))},
		{"the Organization recognised", echo(own, one("aws:"+orgID, why))},
		{"another account recognised beside a pin to it", echo(managed, one("aws:"+management, why))},
		{"a second account recognised", echo(own, append(one("aws:"+bundleAccount, why), one("aws:444455556666", why)...))},
		{"an account recognised for another reason", echo(own, one("aws:"+bundleAccount, "declared as yours"))},
		{"an account recognised in a form no declaration writes", echo(own, one(" aws:"+bundleAccount, why))},
		{"two lines recognised", echo(own, one("aws:"+bundleAccount+"\naws:"+management, why))},
	} {
		for _, now := range []string{"", "aws:" + management} {
			if d, ok := declinedOf(remarkNow(c.answer, now)); !ok || d.Declined != "answer" {
				t.Errorf("%s, re-marked with %+q: %s", c.name, now, remarkNow(c.answer, now))
			}
		}
	}
}

// hasRecognition reports whether an answer echoes an owner recognised.
func hasRecognition(t fataler, b []byte) bool {
	a := answerOf(t, b)
	return a.Declarations != nil && len(a.Declarations.Recognitions) > 0
}

// recognisedRemarks counts what the property that Remark keeps the account
// recognised examined, beside what remarks counts: re-marks of an answer
// that recognised the account into one that recognises it still, and those
// in which recognising it moved a grant from where the owners alone place
// it.
type recognisedRemarks struct {
	kept, mattered atomic.Int64
}

// holdRecognised holds Remark to the findings for one policy read from one
// account: the answer the findings give with the owners at upload,
// re-marked with the owners now, is the answer they give with the owners
// now, the account recognised still, as remarks.hold holds it to AdmitsFor.
func (n *recognisedRemarks) hold(t fataler, r *remarks, name string, policy, plain *answers, upload, now string, form func(fataler, []byte) []byte) {
	if !r.hold(t, name, policy, upload, now, form) {
		return
	}
	if hasRecognition(t, policy.with(upload)) && hasRecognition(t, policy.with(now)) {
		n.kept.Add(1)
	}
	if !slices.EqualFunc(policy.placements(t, now), plain.placements(t, now), slices.Equal) {
		n.mattered.Add(1)
	}
}

// recognising are the findings' answers for a policy read from account, by
// the declaration they are given.
func recognising(policy []byte, account string) *answers {
	recognised := Bundle{Account: account}.recognised()
	return answersBy(policy, func(owners []byte) []byte { return admitsWith(nil, policy, owners, recognised) })
}

// TestRemarkKeepsTheAccountRecognisedOverTheCorpus is the property that a
// re-marked answer keeps the account its scan read as the reader's, over
// every JSON file under testdata and over generated policies: each answer
// the findings give a document read from each AWS account it pins, and from
// one it does not, kept with the owners at upload and re-marked with the
// owners now, is the answer the findings give with the owners now, the
// account recognised still, whatever is declared, the account itself
// included; or a decline for the owners where remarks.hold allows one. A
// count of zero re-marks that kept a recognition, or in which it moved a
// grant, fails.
func TestRemarkKeepsTheAccountRecognisedOverTheCorpus(t *testing.T) {
	var r remarks
	var n recognisedRemarks
	docs := everyCorpusDocument(t)
	t.Run("document", func(t *testing.T) {
		for i, doc := range docs {
			name, _ := filepath.Rel(testdata, doc.path)
			t.Run(name, func(t *testing.T) {
				t.Parallel()
				a := answerOf(t, Admits(doc.raw))
				pinned := pinnedOwners(a)
				accounts, _ := awsOwnersPinned(a)
				if !slices.Contains(accounts, bundleAccount) {
					accounts = append(accounts, bundleAccount)
				}
				upload, now := ownerSets(doc, pinned)
				plain := answersFor(doc.raw)
				for _, account := range accounts {
					policy := recognising(doc.raw, account)
					for j, u := range slices.Concat(upload, []string{"aws:" + account}) {
						for k, w := range slices.Concat(now, []string{"aws:" + account}) {
							form := keptForms[(i+j+k)%len(keptForms)]
							n.hold(t, &r, doc.path+" read from "+account+" ("+form.name+")", policy, plain, u, w, form.form)
						}
					}
				}
			})
		}
	})
	t.Logf("corpus: %d documents; %d re-marks: %d the findings' bytes (%d moved a grant), %d declined for the owners; %d kept the account recognised, %d in which it moved a grant",
		len(docs), r.equal+r.declinedForOwners, r.equal, r.moved, r.declinedForOwners, n.kept.Load(), n.mattered.Load())
	if r.moved == 0 || r.declinedForOwners == 0 || n.kept.Load() == 0 || n.mattered.Load() == 0 {
		t.Fatalf("over the corpus: moved=%d declinedForOwners=%d kept=%d mattered=%d; each must be positive", r.moved, r.declinedForOwners, n.kept.Load(), n.mattered.Load())
	}

	var g remarks
	var m recognisedRemarks
	// a subtest of its own: rapid panics on a test that a failed corpus
	// subtest has already marked failed, and the panic ends the package's run
	t.Run("drawn", func(t *testing.T) {
		for range 20 {
			rapid.Check(t, func(t *rapid.T) {
				statements := rapid.SliceOfN(rapid.Custom(genRemarkStatement), 1, 3).Draw(t, "statements")
				var texts []string
				for _, s := range statements {
					texts = append(texts, s.text)
				}
				raw := policyOf(texts...)
				account := rapid.SampledFrom(append(slices.Clone(remarkAccounts), bundleAccount)).Draw(t, "account read")
				pinned := pinnedOwners(answerOf(t, Admits(raw)))
				upload, now := genRemarkOwners(t, "upload", pinned), genRemarkOwners(t, "now", pinned)
				form := rapid.SampledFrom(keptForms).Draw(t, "kept form")
				m.hold(t, &g, "drawn, read from "+account+" ("+form.name+")", recognising(raw, account), answersFor(raw), upload, now, form.form)
			})
		}
	})
	t.Logf("generated: %d re-marks: %d the findings' bytes (%d moved a grant), %d declined for the owners; %d kept the account recognised, %d in which it moved a grant",
		g.equal+g.declinedForOwners, g.equal, g.moved, g.declinedForOwners, m.kept.Load(), m.mattered.Load())
	if g.moved == 0 || m.kept.Load() == 0 || m.mattered.Load() == 0 {
		t.Fatalf("over generated policies: moved=%d kept=%d mattered=%d; each must be positive", g.moved, m.kept.Load(), m.mattered.Load())
	}
}
