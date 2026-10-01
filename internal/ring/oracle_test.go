package ring

import (
	"slices"
	"strings"
	"testing"

	"pgregory.net/rapid"

	"github.com/CloudArq-net/cloudarq/internal/eval"
	"github.com/CloudArq-net/cloudarq/internal/parse/aws"
	"github.com/CloudArq-net/cloudarq/internal/trust"
)

// The soundness oracle: for every generated grant, every alternative placed
// outsider or yours with owners O, and every token minted by construction
// that the alternative admits, the token was minted for an owner in O,
// compared by the platform's rule. An alternative placed yours is held to
// more, since the ring says every token it admits is the user's: the
// token's owner, by name or by id, is one of O marked declared, and one a
// declaration names, read from the declarations as written rather than
// from the classifier's marks. The owner is known because the test minted
// the token, never parsed back from it, and the engine's own witness plays
// no part. A classifier that read repo:acme* as pinning acme meets a token
// minted for acme-evil that the grant admits, and fails here; so does one
// that placed a pin of acme and beta yours with only acme declared, on a
// token minted for beta.

// enoughExamples runs a property over six hundred examples rather than
// rapid's hundred, as the Terraform reader's properties do, so that the
// rarest shapes the counts below insist on are drawn with room to spare.
func enoughExamples(t *testing.T, property func(*rapid.T)) {
	t.Helper()
	for range 6 {
		rapid.Check(t, property)
	}
}

// The universe the generators draw from and the pools mint from. It is
// small on purpose, so that the patterns a generator writes and the tokens
// a pool mints collide.
var (
	universeOwners = []string{"acme", "beta"}
	universeIDs    = map[string]string{"acme": "123456", "beta": "654321"}
	universeRepos  = []repository{{"infra", "456789"}, {"site", "987654"}}
)

type repository struct{ name, id string }

// identity is who a GitHub token is minted for: the repository's owner,
// by name and by id, and the repository, and how it misses the owners the
// pool was minted around, "" when it is one of them under its own id.
type identity struct {
	owner, ownerID string
	repo           repository
	miss           missKind
}

// missKind is how an identity the pool mints misses the owners it was
// minted around. Each kind is the evidence for its own class of defect, so
// the oracle counts the tokens of each it sees admitted: a pool that
// stopped minting one kind would otherwise pass on the others' counts.
type missKind string

const (
	// lookalike is a name imitating an owner's, which an owner glob read as
	// a pin lets in.
	lookalike missKind = "look-alike"
	// reregistered is an owner's name under an id nobody drew: the name
	// released and registered again, which a name pin lets in and an id pin
	// keeps out.
	reregistered missKind = "re-registered"
	// otherID is an owner's name under an id that extends its own, or under
	// an id another owner was pinned by.
	otherID missKind = "another id"
	// stranger is an owner nobody drew.
	stranger missKind = "random"
)

// contexts are the subject tails a pool mints, among them branches whose
// names carry an owner's id or name mid-string: "They can include slash /
// for hierarchical (directory) grouping" (git-check-ref-format).
func contexts() []string {
	out := []string{"ref:refs/heads/main", "environment:prod", "pull_request"}
	for _, owner := range universeOwners {
		out = append(out, "ref:refs/heads/x@"+universeIDs[owner]+"/y", "ref:refs/heads/"+owner+"/x")
	}
	return out
}

// subjects are every subject a GitHub identity can be issued, in every form
// the census records, plus the ones any identity can have: a called public
// workflow's, a custom property's, and the free subjects drawn for the
// grant.
func (id identity) subjects(free []string) []string {
	var out []string
	for _, ctx := range contexts() {
		out = append(out,
			"repo:"+id.owner+"/"+id.repo.name+":"+ctx,
			"repo:"+id.owner+"@"+id.ownerID+"/"+id.repo.name+"@"+id.repo.id+":"+ctx)
	}
	out = append(out,
		"repository_owner:"+id.owner, "repository_owner:"+id.owner+":environment:prod",
		"repository_owner_id:"+id.ownerID, "repository_owner_id:"+id.ownerID+":environment:prod",
		"repository_id:"+id.repo.id+":ref:refs/heads/main",
		"repo_property_workspace_id:ws-abc123")
	for _, owner := range universeOwners {
		out = append(out, "job_workflow_ref:"+owner+"/deploy/.github/workflows/deploy.yml@refs/heads/main")
	}
	return append(out, free...)
}

// lookalikes are the names that imitate an owner: a case variant, one
// appended to, one inserted into, one truncated and one with its last
// character replaced.
func lookalikes(owner string) []string {
	if owner == "" {
		return nil
	}
	half := len(owner) / 2
	return []string{
		strings.ToUpper(owner), strings.ToUpper(owner[:1]) + owner[1:],
		owner + "-evil", owner + "x",
		owner[:half] + "-" + owner[half:],
		owner[:len(owner)-1],
		owner[:len(owner)-1] + "x",
	}
}

// pool mints the identities a grant's tokens are checked against: the
// universe's owners and the owners the classifier named, every look-alike
// of each, a random owner, each name under another id (a name released
// and re-registered) and under an id that extends its own.
func pool(t *rapid.T, named []Owner) []identity {
	names := slices.Clone(universeOwners)
	ids := map[string]string{}
	for k, v := range universeIDs {
		ids[k] = v
	}
	extraIDs := []string{}
	extraRepos := slices.Clone(universeRepos)
	for _, o := range named {
		switch {
		case o.Scope == ScopeOwner && o.Kind == KindName:
			names = append(names, o.Value)
		case o.Scope == ScopeOwner && o.Kind == KindID:
			extraIDs = append(extraIDs, o.Value, o.Value+"7")
			if o.Name != "" {
				names = append(names, o.Name)
			}
		case o.Scope == ScopeRepository && o.Kind == KindName:
			owner, repo, _ := strings.Cut(o.Value, "/")
			names = append(names, owner)
			extraRepos = append(extraRepos, repository{repo, "111"})
		case o.Scope == ScopeRepository && o.Kind == KindID:
			extraRepos = append(extraRepos, repository{"r" + o.Value, o.Value}, repository{"s", o.Value + "7"})
		}
	}
	random := rapid.StringMatching(`[a-z][a-z0-9-]{0,6}`).Draw(t, "random owner")
	var out []identity
	seen := map[string]bool{}
	add := func(owner, ownerID string, miss missKind) {
		for _, r := range extraRepos {
			key := owner + "\x00" + ownerID + "\x00" + r.name + "\x00" + r.id
			if !seen[key] {
				seen[key] = true
				out = append(out, identity{owner, ownerID, r, miss})
			}
		}
	}
	for _, name := range slices.Compact(slices.Sorted(slices.Values(names))) {
		own := ids[name]
		if own == "" {
			own = "100000"
		}
		add(name, own, "")
		add(name, "999999", reregistered)
		add(name, own+"7", otherID)
		for _, id := range extraIDs {
			if id != own {
				add(name, id, otherID)
			}
		}
		for _, l := range lookalikes(name) {
			add(l, own, lookalike)
			add(l, "999999", lookalike)
		}
	}
	add(random, "424242", stranger)
	return out
}

// token is a GitHub token minted for id with sub as its subject; every
// claim the minter chooses carries the value the grant constrains it to,
// so that only the claims naming a tenant decide who is admitted.
func (id identity) token(sub string, chosen map[trust.ClaimKey]string) map[trust.ClaimKey]string {
	tok := map[trust.ClaimKey]string{
		"sub":                 sub,
		"repository_owner":    id.owner,
		"repository_owner_id": id.ownerID,
		"repository":          id.owner + "/" + id.repo.name,
		"repository_id":       id.repo.id,
	}
	for k, v := range chosen {
		tok[k] = v
	}
	return tok
}

// in reports whether id is one of the owners, compared by GitHub's rule as
// the facts record it: names exactly unless the census says otherwise, ids
// exactly.
func (id identity) in(owners []Owner, ignoreCase bool) bool {
	for _, o := range owners {
		switch {
		case o.Scope == ScopeOwner && o.Kind == KindName && (id.owner == o.Value || ignoreCase && strings.EqualFold(id.owner, o.Value)):
			return true
		case o.Scope == ScopeOwner && o.Kind == KindID && id.ownerID == o.Value:
			return true
		case o.Scope == ScopeRepository && o.Kind == KindName && id.owner+"/"+id.repo.name == o.Value:
			return true
		case o.Scope == ScopeRepository && o.Kind == KindID && id.repo.id == o.Value:
			return true
		}
	}
	return false
}

// declaredBy reports whether a declaration names id's owner as the
// user's, by the owner's name, compared by GitHub's rule as the facts
// record it, or by its id. Only a GitHub declaration carries either.
func (id identity) declaredBy(declared []Declaration, ignoreCase bool) bool {
	for _, d := range declared {
		switch {
		case d.Name != "" && (id.owner == d.Name || ignoreCase && strings.EqualFold(id.owner, d.Name)):
			return true
		case d.ID != "" && id.ownerID == d.ID:
			return true
		}
	}
	return false
}

// declaredOwners are the owners the classifier marked declared, which are
// the ones a ring of the user's own names.
func declaredOwners(owners []Owner) []Owner {
	var out []Owner
	for _, o := range owners {
		if o.Declared {
			out = append(out, o)
		}
	}
	return out
}

// declarationsText is declarations as a failure prints them.
func declarationsText(declared []Declaration) string {
	parts := make([]string, len(declared))
	for i, d := range declared {
		parts[i] = d.String()
	}
	return strings.Join(parts, " ")
}

// witness is a string the pattern matches: each star deleted and each
// question mark a letter.
func witness(pattern string) string {
	return strings.ReplaceAll(strings.ReplaceAll(pattern, "*", ""), "?", "x")
}

// subjectDraw is one alternative of a generated subject constraint, and
// what the generator knows of it by construction: whether it imitates an
// owner without pinning one, and whether any identity at all can be issued
// a subject it matches.
type subjectDraw struct {
	set      eval.StringSet
	nearMiss bool
	imitates string
	free     string // a subject any identity can be issued, "" when none
}

// known is what the draw is: a subject that pins an owner, a pattern that
// imitates an owner's pin, or a subject no recorded form leads.
func (s subjectDraw) known() subjectKnown {
	return subjectKnown{pins: !s.nearMiss, imitation: s.nearMiss && s.free == "", unled: s.free != ""}
}

// subjectKnown is what the generator knows of a subject constraint by
// construction: whether it pins an owner, and which kinds of near miss, a
// constraint that reads like a pin and pins nobody, reach what it admits.
// The two kinds are told apart because each stands for its own class of
// defect: a pattern imitating an owner (repo:acme*, repo:acm?/*) for the
// owner glob, a subject no form leads (a called workflow's) for the
// literals that never pin. Counted together, a generator that stopped
// drawing one kind would pass on the other's count.
type subjectKnown struct{ pins, imitation, unled bool }

// or is what is known of a union: it pins when both sides do, and a near
// miss on either side reaches it.
func (a subjectKnown) or(b subjectKnown) subjectKnown {
	return subjectKnown{pins: a.pins && b.pins, imitation: a.imitation || b.imitation, unled: a.unled || b.unled}
}

// and is what is known of an intersection: it pins when either side does,
// since the other only narrows, and a near miss reaches it only through
// both sides.
func (a subjectKnown) and(b subjectKnown) subjectKnown {
	return subjectKnown{pins: a.pins || b.pins, imitation: a.imitation && b.imitation, unled: a.unled && b.unled}
}

// genSubject draws one alternative of a sub constraint: most often a form
// that pins an owner of the universe, often a near miss that imitates one,
// sometimes a subject no recorded form leads.
func genSubject(t *rapid.T) subjectDraw {
	owner := rapid.SampledFrom(universeOwners).Draw(t, "owner")
	id := universeIDs[owner]
	repo := rapid.SampledFrom(universeRepos).Draw(t, "repo")
	pinning := []string{
		"repo:" + owner + "/*", "repo:" + owner + "/" + repo.name + ":*", "repo:" + owner + "@*/*",
		"repo:" + owner + "@" + id + "/*", "repo:" + owner + "@" + id[:3] + "*", "repo:" + owner + "/*:ref:refs/heads/main",
		"repository_owner:" + owner + ":*", "repository_owner_id:" + id + ":*", "repository_id:" + repo.id + ":*",
	}
	exact := []string{
		"repo:" + owner + "/" + repo.name + ":ref:refs/heads/main",
		"repo:" + owner + "@" + id + "/" + repo.name + "@" + repo.id + ":ref:refs/heads/main",
		"repository_owner:" + owner, "repository_owner_id:" + id,
	}
	nearMisses := []string{
		"repo:" + owner + "*", "repo:" + owner[:len(owner)-1] + "?/*", "repo:" + owner[:1] + "*/*",
		"repo:*@" + id + "/*", "repo:*/" + repo.name + ":*", "*" + owner + "/*", "repo:" + owner + "-*",
		"repository_owner:" + owner + "*", "repository_owner_id:" + id[:3] + "*", "repo:*", "rep*",
	}
	free := []string{
		"job_workflow_ref:" + owner + "/deploy/*", "repo_property_owner:" + owner,
		"job_workflow_ref:" + owner + "/deploy/.github/workflows/deploy.yml@refs/heads/main", "foo:" + owner + "/" + repo.name,
	}
	switch rapid.IntRange(0, 9).Draw(t, "shape") {
	case 0, 1, 2:
		return subjectDraw{set: eval.Glob(rapid.SampledFrom(pinning).Draw(t, "pinning"))}
	case 3, 4:
		return subjectDraw{set: eval.Exact(rapid.SampledFrom(exact).Draw(t, "exact"))}
	case 5, 6, 7:
		return subjectDraw{set: eval.Glob(rapid.SampledFrom(nearMisses).Draw(t, "near miss")), nearMiss: true, imitates: owner}
	}
	s := rapid.SampledFrom(free).Draw(t, "free")
	return subjectDraw{set: eval.Glob(s), nearMiss: true, imitates: owner, free: witness(s)}
}

// githubDraw is a generated GitHub grant and what the generator knows of it.
type githubDraw struct {
	grant  trust.Grant
	terms  []termDraw // per term of the grant's admitted set, in its order
	free   []string
	chosen map[trust.ClaimKey]string
}

// termDraw is what the generator knows of one alternative of a grant by
// construction, never read back from the classifier: whether its subject
// pins an owner and whether a claim does, which kind of near miss reaches
// what it admits with no claim pinning it, and the owner the near miss
// imitates.
type termDraw struct {
	subjectPins, claimPins bool
	imitation, unled       bool
	imitates               string
}

func (k termDraw) nearMiss() bool { return k.imitation || k.unled }

// claimDraw is a value a claim naming a tenant is constrained to, and
// whether it pins by construction: a finite set of exact values does, a
// pattern on a claim whose whole value is the tenant never does, and a
// pattern that closes the owner's name at the head of owner/repo does,
// since an owner's name holds no /.
type claimDraw struct {
	set  eval.StringSet
	pins bool
}

// genGitHubGrant draws a GitHub grant of one or two terms: a subject of one
// to three alternatives, joined or met, and some of the claims that name a
// tenant or that the minter chooses.
func genGitHubGrant(t *rapid.T) githubDraw {
	d := githubDraw{chosen: map[trust.ClaimKey]string{"aud": "sts.amazonaws.com"}}
	var terms []eval.Term
	var drawn []termDraw
	for range rapid.IntRange(1, 2).Draw(t, "terms") {
		term := eval.Term{"aud": eval.Exact("sts.amazonaws.com")}
		var subject subjectKnown
		imitated := ""
		if rapid.IntRange(0, 5).Draw(t, "subject") != 0 {
			first := genSubject(t)
			set := first.set
			subject, imitated = first.known(), first.imitates
			if first.free != "" {
				d.free = append(d.free, first.free)
			}
			for range rapid.IntRange(0, 2).Draw(t, "alternatives") {
				next := genSubject(t)
				if next.free != "" {
					d.free = append(d.free, next.free)
				}
				if rapid.Bool().Draw(t, "join") {
					set, subject = set.Join(next.set), subject.or(next.known())
				} else {
					set, subject = set.Meet(next.set), subject.and(next.known())
				}
				if imitated == "" {
					imitated = next.imitates
				}
			}
			// an unread subject admits every subject, so what was drawn for
			// it no longer says what it admits
			if rapid.IntRange(0, 9).Draw(t, "unread") == 0 {
				set, subject = eval.Unknown("not read"), subjectKnown{}
			}
			term["sub"] = set
		}
		owner := rapid.SampledFrom(universeOwners).Draw(t, "claim owner")
		repo := rapid.SampledFrom(universeRepos).Draw(t, "claim repo")
		claims := map[trust.ClaimKey][]claimDraw{
			"repository_owner":    {{eval.Exact(owner), true}, {eval.Glob(owner + "*"), false}, {eval.Exact(owner).Join(eval.Exact("beta")), true}},
			"repository_owner_id": {{eval.Exact(universeIDs[owner]), true}, {eval.Glob(universeIDs[owner][:3] + "*"), false}},
			"repository":          {{eval.Exact(owner + "/" + repo.name), true}, {eval.Glob(owner + "/*"), true}},
			"repository_id":       {{eval.Exact(repo.id), true}, {eval.Glob(repo.id + "*"), false}},
		}
		claimPins := false
		for _, claim := range []trust.ClaimKey{"repository_owner", "repository_owner_id", "repository", "repository_id"} {
			if rapid.IntRange(0, 7).Draw(t, "with "+string(claim)) == 0 {
				value := rapid.SampledFrom(claims[claim]).Draw(t, string(claim))
				term[claim], claimPins = value.set, claimPins || value.pins
			}
		}
		if rapid.IntRange(0, 3).Draw(t, "actor") == 0 {
			term["actor_id"] = eval.Exact("583231")
			d.chosen["actor_id"] = "583231"
		}
		if rapid.IntRange(0, 3).Draw(t, "workflow") == 0 {
			term["job_workflow_ref"] = eval.Glob(owner + "/deploy/*")
			d.chosen["job_workflow_ref"] = owner + "/deploy/x"
		}
		terms = append(terms, term)
		drawn = append(drawn, termDraw{
			subjectPins: subject.pins,
			claimPins:   claimPins,
			imitation:   subject.imitation && !claimPins,
			unled:       subject.unled && !claimPins,
			imitates:    imitated,
		})
	}
	d.grant = grantOf(githubIssuer, terms...)
	// The admitted set orders its terms by rendering; the generator's
	// knowledge follows each term there.
	for _, term := range d.grant.Admits.Terms() {
		i := slices.IndexFunc(terms, func(u eval.Term) bool { return eval.NewAdmittedSet(u).String() == eval.NewAdmittedSet(term).String() })
		if i < 0 {
			d.terms = append(d.terms, termDraw{})
			continue
		}
		d.terms = append(d.terms, drawn[i])
	}
	return d
}

// genDeclared draws what the user declared: nothing, or some of the
// universe's owners by name, by id, or by both.
func genDeclared(t *rapid.T) []Declaration {
	var lines []string
	for _, owner := range universeOwners {
		switch rapid.IntRange(0, 5).Draw(t, "declare "+owner) {
		case 0:
			lines = append(lines, "github:"+owner)
		case 1:
			lines = append(lines, "github:@"+universeIDs[owner])
		case 2:
			lines = append(lines, "github:"+owner+"@"+universeIDs[owner])
		}
	}
	d := ReadDeclarations(strings.Join(lines, "\n"))
	if d.Overrun != nil || len(d.Refused) != 0 {
		t.Fatalf("the generator wrote a declaration the parser refused: %+v %v", d.Overrun, d.Refused)
	}
	return d.Owners
}

// soundnessCounts are what one run of the oracle examined. Every count but
// yours and nobody must be above zero, so that the oracle cannot pass by
// examining nothing, and each kind of pin and of near miss is counted on
// its own, so that a generator that stopped drawing one kind cannot pass
// on another's count.
type soundnessCounts struct {
	admitted, nearMissRejected, outsider, platform int
	subjectPinned, claimPinned                     int // tokens held to the owners of an alternative that its subject, or one of its claims, pins by construction
	nearMissDrawn                                  int // alternatives a near miss reaches with no claim pinning them
	imitationForeign, unledForeign                 int // tokens of owners other than the one imitated, admitted by an alternative a near miss of each kind reaches
	lookalikeAdmitted                              int // of the imitation's, those minted for a look-alike (acme-evil for repo:acme*), which the owner glob is caught on
	reregisteredAdmitted                           int // tokens of a name registered again held to the owners of a pinned alternative, which a name pin read as an id pin is caught on
	yoursAdmitted                                  int // tokens an alternative placed yours admits, each held to the declarations, which a pin placed yours with an owner undeclared is caught on
	yours                                          int
	nobody                                         int // grants whose alternatives meet in nothing, which the lattice proves
	pinsHeld                                       int // alternatives that pin by construction, each held off the platform, exact, where no condition would confine it
}

func TestSoundnessOracle(t *testing.T) {
	var c soundnessCounts
	enoughExamples(t, func(t *rapid.T) {
		d := genGitHubGrant(t)
		facts := githubFacts()
		facts.Tenancy.NamesIgnoreCase = rapid.IntRange(0, 4).Draw(t, "ignore case") == 0
		declared := genDeclared(t)
		p := Classify(d.grant, facts, declared)
		switch {
		case p.Outcome == Nobody:
			c.nobody++
			return
		case p.Outcome != Placed || len(p.Places) != 1:
			t.Fatalf("a GitHub grant placed %s", p)
		}
		switch p.Places[0] {
		case Outsider:
			c.outsider++
		case Yours:
			c.yours++
		case Platform:
			c.platform++
		}
		terms := d.grant.Admits.Terms()
		for _, pop := range p.Populations {
			term := eval.NewAdmittedSet(terms[pop.Term])
			drawn := d.terms[pop.Term]
			pinned := pop.Place == Outsider || pop.Place == Yours
			// an alternative a condition confines to named owners is at the
			// platform only as an upper bound: exact there says no condition
			// confines it, which is false
			if drawn.subjectPins || drawn.claimPins {
				c.pinsHeld++
				if pop.Place == Platform && pop.State == StateExact {
					t.Fatalf("term %s pins an owner by construction and is placed %s", term, pop)
				}
			}
			if drawn.nearMiss() {
				c.nearMissDrawn++
			} else if !pinned {
				continue
			}
			for _, id := range pool(t, pop.Owners) {
				for _, sub := range id.subjects(d.free) {
					tok := id.token(sub, d.chosen)
					admitted := term.Admits(tok)
					if admitted && id.owner != drawn.imitates {
						if drawn.imitation {
							c.imitationForeign++
							if id.miss == lookalike {
								c.lookalikeAdmitted++
							}
						}
						if drawn.unled {
							c.unledForeign++
						}
					}
					if !pinned {
						continue
					}
					if !admitted {
						if id.miss != "" {
							c.nearMissRejected++
						}
						continue
					}
					c.admitted++
					if id.miss == reregistered {
						c.reregisteredAdmitted++
					}
					if drawn.subjectPins {
						c.subjectPinned++
					}
					if drawn.claimPins {
						c.claimPinned++
					}
					if !id.in(pop.Owners, facts.Tenancy.NamesIgnoreCase) {
						t.Fatalf("term %s placed %s with owners [%s] admits a token minted for %+v: %v", term, pop, ownersText(pop.Owners), id, tok)
					}
					if pop.Place != Yours {
						continue
					}
					c.yoursAdmitted++
					if !id.in(declaredOwners(pop.Owners), facts.Tenancy.NamesIgnoreCase) || !id.declaredBy(declared, facts.Tenancy.NamesIgnoreCase) {
						t.Fatalf("term %s placed yours with owners [%s] admits a token minted for %+v, and the declarations are [%s]: %v", term, ownersText(pop.Owners), id, declarationsText(declared), tok)
					}
				}
			}
		}
	})
	if c.admitted == 0 || c.nearMissRejected == 0 || c.outsider == 0 || c.platform == 0 || c.subjectPinned == 0 || c.claimPinned == 0 ||
		c.nearMissDrawn == 0 || c.imitationForeign == 0 || c.unledForeign == 0 || c.lookalikeAdmitted == 0 || c.reregisteredAdmitted == 0 || c.yoursAdmitted == 0 || c.pinsHeld == 0 {
		t.Fatalf("%+v; every count but yours and nobody must be positive", c)
	}
	t.Logf("%+v", c)
}

// awsIdentity is who an AWS principal is: its account, the organisation
// the account is in, and its ARN.
type awsIdentity struct {
	account, org, arn string
	nearMiss          bool
}

var (
	universeAccounts = []string{"111122223333", "444455556666"}
	universeOrgs     = map[string]string{"111122223333": "o-a1b2c3d4e5", "444455556666": "o-f6g7h8i9j0"}
)

// awsPool mints principals of the universe's accounts, of accounts one
// digit away, and in organisations one character away, each as a role and
// as a user.
func awsPool(t *rapid.T) []awsIdentity {
	random := rapid.StringMatching(`[0-9]{12}`).Draw(t, "random account")
	var out []awsIdentity
	for _, acct := range append(slices.Clone(universeAccounts), "111122223334", "211122223333", random) {
		orgs := []string{universeOrgs[acct], "o-a1b2c3d4e5x", "o-a1b2c3d4e6", ""}
		for _, org := range orgs {
			for _, resource := range []string{"role/deploy", "user/ci"} {
				near := universeOrgs[acct] == "" || org != universeOrgs[acct]
				out = append(out, awsIdentity{acct, org, "arn:aws:iam::" + acct + ":" + resource, near})
			}
		}
	}
	return out
}

func (id awsIdentity) token(chosen map[trust.ClaimKey]string) map[trust.ClaimKey]string {
	tok := map[trust.ClaimKey]string{"aws:principalaccount": id.account, "aws:principalarn": id.arn, "aws:principaltype": "AssumedRole"}
	if id.org != "" {
		tok["aws:principalorgid"] = id.org
	}
	for k, v := range chosen {
		tok[k] = v
	}
	return tok
}

func (id awsIdentity) in(owners []Owner) bool {
	for _, o := range owners {
		if o.Scope == ScopeAccount && o.Value == id.account || o.Scope == ScopeOrganisation && o.Value == id.org {
			return true
		}
	}
	return false
}

// declaredBy reports whether a declaration names id's account or its
// organisation, read from the declaration as written: an AWS id names
// itself and nothing else.
func (id awsIdentity) declaredBy(declared []Declaration) bool {
	return slices.ContainsFunc(declared, func(d Declaration) bool {
		return d.Namespace == NamespaceAWS && (d.Scope == ScopeAccount && d.Value == id.account || d.Scope == ScopeOrganisation && d.Value == id.org)
	})
}

// awsNearMisses are an account one digit from the universe's first and an
// organisation one character from its first, which a user might
// declare and which name nobody the grants here pin.
var awsNearMisses = []string{"111122223334", "o-a1b2c3d4e6"}

// genAWSDeclared draws what the user declared of AWS: nothing, or some
// of the universe's accounts and organisations and of their near misses.
func genAWSDeclared(t *rapid.T) []Declaration {
	var lines []string
	for _, acct := range universeAccounts {
		for _, id := range []string{acct, universeOrgs[acct]} {
			if rapid.IntRange(0, 2).Draw(t, "declare "+id) == 0 {
				lines = append(lines, "aws:"+id)
			}
		}
	}
	for _, id := range awsNearMisses {
		if rapid.IntRange(0, 1).Draw(t, "declare "+id) == 0 {
			lines = append(lines, "aws:"+id)
		}
	}
	d := ReadDeclarations(strings.Join(lines, "\n"))
	if d.Overrun != nil || len(d.Refused) != 0 {
		t.Fatalf("the generator wrote a declaration the parser refused: %+v %v", d.Overrun, d.Refused)
	}
	return d.Owners
}

// TestSoundnessOracleOnAWSPrincipals is the oracle over the pseudo-issuer:
// every principal a grant placed on an account or an organisation admits
// is in it, and every principal a grant placed yours admits is of an
// account or an organisation a declaration names as written. A near miss
// declared, an account one digit away or an organisation one character
// away, names nobody the grant pins.
func TestSoundnessOracleOnAWSPrincipals(t *testing.T) {
	admitted, rejected, outsider, platform, yoursAdmitted, nearMissDeclared := 0, 0, 0, 0, 0, 0
	enoughExamples(t, func(t *rapid.T) {
		acct := rapid.SampledFrom(universeAccounts).Draw(t, "account")
		org := universeOrgs[acct]
		options := map[trust.ClaimKey][]eval.StringSet{
			"aws:principalaccount": {eval.Exact(acct), eval.Exact(acct).Join(eval.Exact("444455556666")), eval.Glob(acct[:11] + "?"), eval.Unknown("x")},
			"aws:principalorgid":   {eval.Exact(org), eval.Glob(org + "*"), eval.Exact("o-A1B2C3D4E5")},
			"aws:principalarn": {
				eval.Exact("arn:aws:iam::" + acct + ":role/deploy"), eval.Glob("arn:aws:iam::" + acct + ":*"),
				eval.Glob("arn:aws:iam::" + acct[:11] + "*"), eval.Glob("arn:aws:iam::*:role/deploy"), eval.Glob("arn:aws:iam::" + acct + "*"),
			},
		}
		term := eval.Term{}
		for _, claim := range aws.TenancyClaims() {
			if rapid.Bool().Draw(t, "with "+string(claim)) {
				term[claim] = rapid.SampledFrom(options[claim]).Draw(t, string(claim))
			}
		}
		chosen := map[trust.ClaimKey]string{}
		if rapid.Bool().Draw(t, "external id") {
			term["sts:externalid"] = eval.Exact("vendor-abc")
			chosen["sts:externalid"] = "vendor-abc"
		}
		g := grantOf(aws.AWSPrincipalIssuer, term)
		declared := genAWSDeclared(t)
		p := Classify(g, Facts{PrincipalModelled: true}, declared)
		switch p.Places[0] {
		case Outsider:
			outsider++
			if slices.ContainsFunc(declared, func(d Declaration) bool { return slices.Contains(awsNearMisses, d.Value) }) {
				nearMissDeclared++
			}
		case Yours:
		case Platform:
			platform++
			return
		default:
			t.Fatalf("an AWS principal placed %s", p)
		}
		for _, id := range awsPool(t) {
			tok := id.token(chosen)
			if !g.Admits.Admits(tok) {
				if id.nearMiss {
					rejected++
				}
				continue
			}
			admitted++
			if !id.in(p.Owners) {
				t.Fatalf("%s placed %s admits %+v", g.Admits, p, id)
			}
			if p.Places[0] != Yours {
				continue
			}
			yoursAdmitted++
			if !id.in(declaredOwners(p.Owners)) || !id.declaredBy(declared) {
				t.Fatalf("%s placed yours with owners [%s] admits %+v, and the declarations are [%s]", g.Admits, ownersText(p.Owners), id, declarationsText(declared))
			}
		}
	})
	if admitted == 0 || rejected == 0 || outsider == 0 || platform == 0 || yoursAdmitted == 0 || nearMissDeclared == 0 {
		t.Fatalf("admitted=%d nearMissRejected=%d outsider=%d platform=%d yoursAdmitted=%d nearMissDeclared=%d; every count must be positive", admitted, rejected, outsider, platform, yoursAdmitted, nearMissDeclared)
	}
	t.Logf("admitted=%d nearMissRejected=%d outsider=%d platform=%d yoursAdmitted=%d nearMissDeclared=%d", admitted, rejected, outsider, platform, yoursAdmitted, nearMissDeclared)
}

// samlProviders are SAML providers of the role's account and of another,
// each with a near miss: a name one letter away, and the same name in
// another case, which IAM spells as another ARN.
var samlProviders = []trust.IssuerRef{
	"arn:aws:iam::123456789012:saml-provider/CorpIdP",
	"arn:aws:iam::123456789012:saml-provider/CorpIdQ",
	"arn:aws:iam::123456789012:saml-provider/corpidp",
	"arn:aws:iam::210987654321:saml-provider/CorpIdP",
}

// TestSoundnessOracleOnSAMLProviders holds the ring of your people to the
// declarations as written: a provider's sign-ins are placed there when a
// declaration names that provider, by its whole ARN, and only then, so a
// provider whose near miss alone is declared stays beside the rings.
func TestSoundnessOracleOnSAMLProviders(t *testing.T) {
	people, beside, nearMissDeclared := 0, 0, 0
	enoughExamples(t, func(t *rapid.T) {
		provider := rapid.SampledFrom(samlProviders).Draw(t, "provider")
		var lines []string
		for _, arn := range samlProviders {
			if rapid.IntRange(0, 2).Draw(t, "declare "+string(arn)) == 0 {
				lines = append(lines, "saml:"+string(arn))
			}
		}
		read := ReadDeclarations(strings.Join(lines, "\n"))
		if read.Overrun != nil || len(read.Refused) != 0 {
			t.Fatalf("the generator wrote a declaration the parser refused: %+v %v", read.Overrun, read.Refused)
		}
		declared := slices.ContainsFunc(read.Owners, func(d Declaration) bool { return d.Namespace == NamespaceSAML && d.Value == string(provider) })
		p := Classify(grantOf(provider, eval.Term{}), Facts{PrincipalModelled: true}, read.Owners)
		if p.Outcome != Placed || len(p.Populations) != 1 {
			t.Fatalf("a SAML provider placed %s", p)
		}
		switch place := p.Populations[0].Place; {
		case place == People && declared:
			people++
		case place == SAML && !declared:
			beside++
			if len(read.Owners) > 0 {
				nearMissDeclared++
			}
		default:
			t.Fatalf("%s placed %s, and the declarations are [%s]", provider, p, declarationsText(read.Owners))
		}
	})
	if people == 0 || beside == 0 || nearMissDeclared == 0 {
		t.Fatalf("people=%d beside=%d nearMissDeclared=%d; every count must be positive", people, beside, nearMissDeclared)
	}
	t.Logf("people=%d beside=%d nearMissDeclared=%d", people, beside, nearMissDeclared)
}

// TestSoundnessOracleOnServices holds the line of cloud services to what a
// trust policy shows of it: who can make a service act, or receives its
// session, is not in the policy, so a service's grant is placed on the line
// and never exact, whatever conditions it carries and whatever the user
// declares. A service the parser's table of intermediaries lists is placed
// as one assuming a role for identities outside IAM; a condition naming the
// account or the trust anchor it acts for names nobody who receives its
// session, as a certificate holder does from IAM Roles Anywhere. The
// generator draws both kinds of service, with and without such conditions,
// and the counts say it did.
func TestSoundnessOracleOnServices(t *testing.T) {
	intermediaries, others, conditioned := 0, 0, 0
	enoughExamples(t, func(t *rapid.T) {
		d := genAnyGrant(t)
		if !strings.HasPrefix(string(d.grant.Issuer), aws.ServiceIssuerPrefix) {
			return
		}
		p := Classify(d.grant, d.facts, genAnyDeclared(t))
		if p.Outcome != Placed || p.State != StateUnknown || len(p.Populations) != 1 {
			t.Fatalf("%s placed %s", d.grant.Issuer, p)
		}
		pop := p.Populations[0]
		want := ServicePrincipal
		if isIntermediary(d.grant.Issuer) {
			want = ServiceIntermediary
			intermediaries++
		} else {
			others++
		}
		if pop.Place != Service || pop.State != StateUnknown || pop.Basis != want || len(pop.Owners) != 0 {
			t.Fatalf("%s with %s placed %s; want service unknown %s", d.grant.Issuer, d.grant.Admits, pop, want)
		}
		if len(d.grant.Admits.Terms()) > 0 && len(d.grant.Admits.Terms()[0]) > 0 {
			conditioned++
		}
	})
	if intermediaries == 0 || others == 0 || conditioned == 0 {
		t.Fatalf("intermediaries=%d others=%d conditioned=%d; every count must be positive", intermediaries, others, conditioned)
	}
	t.Logf("intermediaries=%d others=%d conditioned=%d", intermediaries, others, conditioned)
}

// TestSoundnessOracleOnTheCorpus holds every GitHub grant of testdata/rings
// to the same law, read through the parser rather than built by hand:
// whatever a document placed on an owner admits was minted for that owner,
// and whatever it placed yours, for an owner its case declared.
func TestSoundnessOracleOnTheCorpus(t *testing.T) {
	var placed []classified
	for _, c := range corpus {
		for _, got := range classifyCase(t, c) {
			if got.grant.Issuer == githubIssuer {
				placed = append(placed, got)
			}
		}
	}
	admitted, examined, yoursAdmitted := 0, 0, 0
	rapid.Check(t, func(t *rapid.T) {
		for _, got := range placed {
			terms := got.grant.Admits.Terms()
			for _, pop := range got.placement.Populations {
				if pop.Place != Outsider && pop.Place != Yours {
					continue
				}
				examined++
				term := eval.NewAdmittedSet(terms[pop.Term])
				for _, id := range pool(t, pop.Owners) {
					for _, sub := range id.subjects(nil) {
						tok := id.token(sub, map[trust.ClaimKey]string{"aud": "sts.amazonaws.com"})
						if !term.Admits(tok) {
							continue
						}
						admitted++
						if !id.in(pop.Owners, false) {
							t.Fatalf("%s placed %s admits %+v", got.sid, pop, id)
						}
						if pop.Place != Yours {
							continue
						}
						yoursAdmitted++
						if !id.in(declaredOwners(pop.Owners), false) || !id.declaredBy(got.declared, false) {
							t.Fatalf("%s placed %s admits %+v, and the declarations are [%s]", got.sid, pop, id, declarationsText(got.declared))
						}
					}
				}
			}
		}
	})
	if admitted == 0 || examined == 0 || yoursAdmitted == 0 {
		t.Fatalf("admitted=%d examined=%d yoursAdmitted=%d; each must be positive", admitted, examined, yoursAdmitted)
	}
	t.Logf("admitted=%d yoursAdmitted=%d over %d populations", admitted, yoursAdmitted, examined)
}
