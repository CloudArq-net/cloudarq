package join

import (
	"bytes"
	"encoding/json"
	"errors"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/CloudArq-net/cloudarq/internal/eval"
	"github.com/CloudArq-net/cloudarq/internal/evidence"
	"github.com/CloudArq-net/cloudarq/internal/trust"
)

// The GitHub Actions issuer and the targets most tests join: an AWS role, an
// Azure application and a GCP service account. Which cloud each belongs to
// is the fixture's knowledge, never the package's.
const (
	github        = trust.IssuerRef("https://token.actions.githubusercontent.com")
	gitlab        = trust.IssuerRef("https://gitlab.com")
	awsAudience   = "sts.amazonaws.com"
	azureAudience = "api://AzureADTokenExchange"
	gcpAudience   = "https://iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/github/providers/github"
	mainBranch    = "repo:acme/infra:ref:refs/heads/main"
	devBranch     = "repo:acme/infra:ref:refs/heads/dev"
	toolsBranch   = "repo:acme/tools:ref:refs/heads/main"
)

var (
	deployRole   = trust.TargetRef{Kind: "role", ID: "arn:aws:iam::111111111111:role/deploy"}
	infraApp     = trust.TargetRef{Kind: "application", ID: "6b1e6c7e-0f1a-4d2b-9c3d-8e4f5a6b7c8d"}
	buildAccount = trust.TargetRef{Kind: "service-account", ID: "deploy@acme-prod.iam.gserviceaccount.com"}
)

// record is one conclusive API call. Params carries the target so that two
// records for two targets never collide.
func record(api, target string) evidence.Record {
	return evidence.New(api, `{"target":`+strconv.Quote(target)+`}`, evidence.StatusOK, []byte(`{"ok":true}`), time.Unix(0, 0))
}

func refused(api, target string) evidence.Record {
	return evidence.New(api, `{"target":`+strconv.Quote(target)+`}`, evidence.StatusDenied, nil, time.Unix(0, 0))
}

func pinned(sub eval.StringSet, audience string, extra ...eval.Term) eval.AdmittedSet {
	term := eval.Term{"sub": sub, "aud": eval.Exact(audience)}
	for _, e := range extra {
		for k, s := range e {
			term[k] = s
		}
	}
	return eval.NewAdmittedSet(term)
}

func awsGrant(admits eval.AdmittedSet) trust.Grant {
	return trust.Grant{Target: deployRole, Issuer: github, Admits: admits, Effect: trust.Allow, Provenance: []evidence.Record{record("iam:GetRole", deployRole.ID)}}
}

func azureGrant(admits eval.AdmittedSet) trust.Grant {
	return trust.Grant{Target: infraApp, Issuer: github, Admits: admits, Effect: trust.Allow, Provenance: []evidence.Record{record("graph:federatedIdentityCredentials.list", infraApp.ID)}}
}

func gcpGrant(admits eval.AdmittedSet) trust.Grant {
	return trust.Grant{Target: buildAccount, Issuer: github, Admits: admits, Effect: trust.Allow, Provenance: []evidence.Record{record("iam:serviceAccounts.getIamPolicy", buildAccount.ID)}}
}

// encode renders links the way the goldens and the reporter do: no HTML
// escaping, so that a target id or a sentence reads back as written.
func encode(t testing.TB, v any) []byte {
	t.Helper()
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		t.Fatalf("encode: %v", err)
	}
	return buf.Bytes()
}

func mustLink(t testing.TB, a, b trust.Grant, denies ...trust.Grant) Link {
	t.Helper()
	l, err := NewLink(a, b, denies...)
	if err != nil {
		t.Fatalf("NewLink: %v", err)
	}
	return l
}

const (
	pair    = "application 6b1e6c7e-0f1a-4d2b-9c3d-8e4f5a6b7c8d are also admitted by role arn:aws:iam::111111111111:role/deploy: "
	mayPair = "application 6b1e6c7e-0f1a-4d2b-9c3d-8e4f5a6b7c8d may also be admitted by role arn:aws:iam::111111111111:role/deploy from https://token.actions.githubusercontent.com; "
)

// TestEstablishedSentence pins the J6 sentence on the pair the product
// exists to state plainly: a role pinned to a branch across every acme
// repository, an application pinned to one repository across every branch.
// Neither pattern contains the other; the sets overlap on one branch of one
// repository, and the sentence describes the overlap and names an example.
func TestEstablishedSentence(t *testing.T) {
	aws := awsGrant(pinned(eval.Glob("repo:acme/*:ref:refs/heads/main"), awsAudience, eval.Term{"repository_owner_id": eval.Exact("123456")}))
	azure := azureGrant(pinned(eval.Glob("repo:acme/infra:*"), azureAudience, eval.Term{"repository_id": eval.Exact("456789")}))
	l := mustLink(t, aws, azure)

	reason := "both admit identities from https://token.actions.githubusercontent.com with repository_id 456789, " +
		"repository_owner_id 123456 and sub matching all of repo:acme/*:ref:refs/heads/main and repo:acme/infra:*, " +
		"for example repository_id=456789, repository_owner_id=123456, sub=repo:acme/infra:ref:refs/heads/main"
	if got := l.Sentence(); got != "Identities admitted by "+pair+reason+"." {
		t.Errorf("Sentence() =\n%s\nwant\n%s", got, "Identities admitted by "+pair+reason+".")
	}
	if l.Reason() != reason {
		t.Errorf("Reason() = %q", l.Reason())
	}
	if l.Confidence() != Established || l.Kind() != CounterpartyFanOut || !l.Valid() {
		t.Errorf("Confidence() = %q, Kind() = %q, Valid() = %v", l.Confidence(), l.Kind(), l.Valid())
	}
	// The pair is ordered by target kind then id, whichever way it was given.
	if got := l.Grants(); len(got) != 2 || got[0].Target != infraApp || got[1].Target != deployRole || got[0].Issuer != github || got[1].Admits != aws.Admits.String() {
		t.Errorf("Grants() = %v", got)
	}
	if again := mustLink(t, azure, aws); !bytes.Equal(encode(t, again), encode(t, l)) {
		t.Errorf("NewLink depends on argument order:\n%s\n%s", encode(t, again), encode(t, l))
	}
	subject := l.Subject()
	wantOverlap := `{repository_id="456789", repository_owner_id="123456", sub=(like:"repo:acme/*:ref:refs/heads/main" & like:"repo:acme/infra:*")}`
	if subject.Issuer != github || subject.Overlap != wantOverlap {
		t.Errorf("Subject() = %+v", subject)
	}
	wantWitness := token{"sub": mainBranch, "repository_id": "456789", "repository_owner_id": "123456"}
	if len(subject.Witness) != len(wantWitness) {
		t.Fatalf("Witness = %v, want %v", subject.Witness, wantWitness)
	}
	for k, v := range wantWitness {
		if subject.Witness[k] != v {
			t.Errorf("Witness[%s] = %q, want %q", k, subject.Witness[k], v)
		}
	}
	for _, g := range []trust.Grant{aws, azure} {
		if !g.WithoutAudience().Admits(subject.Witness) {
			t.Errorf("%s does not admit the witness %v", g.Target.ID, subject.Witness)
		}
	}
	// Provenance carries both sides, in record order, not collector order.
	if got := l.Provenance(); len(got) != 2 || got[0].API != "graph:federatedIdentityCredentials.list" || got[1].API != "iam:GetRole" {
		t.Errorf("Provenance() = %v", got)
	}
}

// TestBriefsOwnExample is the pair the spec names: repo:acme/* on one side,
// repo:acme/infra:* on the other. The shortest string both patterns match
// is one GitHub never mints, which is why the sentence describes the
// patterns and offers the witness only as an example.
func TestBriefsOwnExample(t *testing.T) {
	aws := awsGrant(pinned(eval.Glob("repo:acme/*"), awsAudience))
	azure := azureGrant(pinned(eval.Glob("repo:acme/infra:*"), azureAudience))
	l := mustLink(t, aws, azure)
	want := "Identities admitted by " + pair + "both admit identities from https://token.actions.githubusercontent.com " +
		"with sub matching all of repo:acme/* and repo:acme/infra:*, for example sub=repo:acme/infra:."
	if got := l.Sentence(); got != want {
		t.Errorf("Sentence() =\n%s\nwant\n%s", got, want)
	}
	if l.Confidence() != Established {
		t.Errorf("Confidence() = %q", l.Confidence())
	}
}

func TestEveryIdentitySentence(t *testing.T) {
	aws := awsGrant(eval.NewAdmittedSet(eval.Term{"aud": eval.Exact(awsAudience)}))
	azure := azureGrant(eval.NewAdmittedSet(eval.Term{"aud": eval.Exact(azureAudience)}))
	l := mustLink(t, aws, azure)
	want := "Identities admitted by " + pair + "both admit any identity from https://token.actions.githubusercontent.com."
	if got := l.Sentence(); got != want {
		t.Errorf("Sentence() =\n%s\nwant\n%s", got, want)
	}
	// The empty token is the witness: it is admitted, and it is not "none".
	if s := l.Subject(); s.Witness == nil || len(s.Witness) != 0 || s.Overlap != "{}" {
		t.Errorf("Subject() = %+v; want the empty token as witness of everything", s)
	}
	if !strings.Contains(string(encode(t, l)), `"witness": {}`) {
		t.Errorf("the empty token must render as {}, not null:\n%s", encode(t, l))
	}
}

// TestDescriptionShapes covers every shape a claim's constraint can take
// in an overlap: a value, a pattern, an intersection, a union, and a
// union whose member is itself an intersection; and an overlap of several
// terms. A witness that repeats the description word for word is not an
// example and is left out.
func TestDescriptionShapes(t *testing.T) {
	cases := []struct {
		name       string
		aws, azure eval.AdmittedSet
		want       string
	}{
		{
			"pinned on both sides",
			pinned(eval.Exact(mainBranch), awsAudience),
			pinned(eval.Exact(mainBranch), azureAudience),
			"both admit identities from https://token.actions.githubusercontent.com with sub repo:acme/infra:ref:refs/heads/main",
		},
		{
			"pattern against a value",
			pinned(eval.Glob("repo:acme/*"), awsAudience),
			pinned(eval.Exact(mainBranch), azureAudience),
			"both admit identities from https://token.actions.githubusercontent.com with sub repo:acme/infra:ref:refs/heads/main",
		},
		{
			"one pattern survives",
			pinned(eval.Glob("repo:acme/*"), awsAudience),
			pinned(eval.Glob("repo:acme/*"), azureAudience),
			"both admit identities from https://token.actions.githubusercontent.com with sub matching repo:acme/*, for example sub=repo:acme/",
		},
		{
			"three patterns",
			pinned(eval.Glob("repo:acme/*").Meet(eval.Glob("*:ref:*")), awsAudience),
			pinned(eval.Glob("repo:acme/infra:*"), azureAudience),
			"both admit identities from https://token.actions.githubusercontent.com with sub matching all of *:ref:*, repo:acme/* and repo:acme/infra:*, for example sub=repo:acme/infra:ref:",
		},
		{
			"a union of a value and a pattern",
			pinned(eval.Exact(toolsBranch).Join(eval.Glob("repo:acme/infra:*")), awsAudience),
			pinned(eval.Glob("repo:acme/*"), azureAudience),
			"both admit identities from https://token.actions.githubusercontent.com with sub repo:acme/tools:ref:refs/heads/main or matching all of repo:acme/* and repo:acme/infra:*, for example sub=repo:acme/tools:ref:refs/heads/main",
		},
		{
			"the empty value",
			pinned(eval.Exact(""), awsAudience),
			pinned(eval.Glob("*"), azureAudience),
			`both admit identities from https://token.actions.githubusercontent.com with sub ""`,
		},
		{
			"two terms",
			eval.NewAdmittedSet(
				eval.Term{"sub": eval.Exact(mainBranch), "aud": eval.Exact(awsAudience)},
				eval.Term{"sub": eval.Exact(devBranch), "repository_id": eval.Exact("456789"), "aud": eval.Exact(awsAudience)},
			),
			pinned(eval.Glob("repo:acme/infra:*"), azureAudience),
			"both admit identities from https://token.actions.githubusercontent.com with repository_id 456789 and sub repo:acme/infra:ref:refs/heads/dev, or with sub repo:acme/infra:ref:refs/heads/main",
		},
	}
	for _, c := range cases {
		l := mustLink(t, awsGrant(c.aws), azureGrant(c.azure))
		if l.Reason() != c.want || l.Confidence() != Established {
			t.Errorf("%s: Reason() =\n%s\nwant\n%s", c.name, l.Reason(), c.want)
		}
		if !c.aws.Admits(withAudience(l.Subject().Witness, awsAudience)) || !c.azure.Admits(withAudience(l.Subject().Witness, azureAudience)) {
			t.Errorf("%s: witness %v is not admitted by both sides", c.name, l.Subject().Witness)
		}
	}
}

func withAudience(w token, audience string) token {
	out := token{"aud": audience}
	for k, v := range w {
		out[k] = v
	}
	return out
}

// indeterminate asserts the verbatim sentence and that the witness data, if
// any, was never promoted into the sentence.
func indeterminate(t *testing.T, l Link, reason string) {
	t.Helper()
	if l.Confidence() != Indeterminate {
		t.Errorf("Confidence() = %q, want Indeterminate", l.Confidence())
	}
	want := "Identities admitted by " + mayPair + reason + "."
	if got := l.Sentence(); got != want {
		t.Errorf("Sentence() =\n%s\nwant\n%s", got, want)
	}
	if l.Reason() != reason {
		t.Errorf("Reason() = %q", l.Reason())
	}
}

func TestInconclusiveEvidenceSentence(t *testing.T) {
	aws := awsGrant(pinned(eval.Exact(mainBranch), awsAudience))
	aws.Provenance = []evidence.Record{refused("iam:GetRole", deployRole.ID), record("iam:ListRoles", deployRole.ID)}
	azure := azureGrant(pinned(eval.Exact(mainBranch), azureAudience))
	l := mustLink(t, aws, azure)
	indeterminate(t, l, "the call iam:GetRole for role arn:aws:iam::111111111111:role/deploy returned denied")
	// The witness is still data on the Link, for the reporter.
	if w := l.Subject().Witness; w["sub"] != mainBranch {
		t.Errorf("Witness = %v", w)
	}
	// Two inconclusive records read in record order, and every record stays
	// in the provenance whatever its status.
	aws.Provenance = append(aws.Provenance, evidence.New("iam:GetRolePolicy", `{}`, evidence.StatusThrottled, nil, time.Unix(0, 0)))
	l = mustLink(t, aws, azure)
	indeterminate(t, l, "the call iam:GetRole for role arn:aws:iam::111111111111:role/deploy returned denied; "+
		"the call iam:GetRolePolicy for role arn:aws:iam::111111111111:role/deploy returned throttled")
	if got := l.Provenance(); len(got) != 4 {
		t.Errorf("Provenance() has %d records, want 4", len(got))
	}
}

func TestUpperBoundSentence(t *testing.T) {
	notModelled := eval.Caveat{Claim: "sub", Reason: "operator ForAllValues:StringLike is not modelled", Source: "statement[0].Condition"}
	aws := awsGrant(pinned(eval.Unknown("ForAllValues:StringLike"), awsAudience, eval.Term{"repository_id": eval.Exact("456789")}).WithCaveat(notModelled))
	azure := azureGrant(pinned(eval.Exact(mainBranch), azureAudience, eval.Term{"repository_id": eval.Exact("456789")}))
	indeterminate(t, mustLink(t, aws, azure), "the identities admitted by role arn:aws:iam::111111111111:role/deploy are an upper bound (operator ForAllValues:StringLike is not modelled at statement[0].Condition)")
	// A caveat without a source, and two caveats, read in caveat order.
	aws.Admits = aws.Admits.WithCaveat(eval.Caveat{Reason: "NotPrincipal is not modelled"})
	indeterminate(t, mustLink(t, aws, azure), "the identities admitted by role arn:aws:iam::111111111111:role/deploy are an upper bound (NotPrincipal is not modelled; operator ForAllValues:StringLike is not modelled at statement[0].Condition)")
}

// TestUndeclaredUnknownSentence: an Unknown beside a real constraint with no
// caveat saying so is silence read as clean. The parser harness refuses it;
// the join refuses to build an Established Link on it either way.
func TestUndeclaredUnknownSentence(t *testing.T) {
	aws := awsGrant(pinned(eval.Unknown("ForAllValues:StringLike"), awsAudience, eval.Term{"repository_id": eval.Exact("456789")}))
	azure := azureGrant(pinned(eval.Exact(mainBranch), azureAudience, eval.Term{"repository_id": eval.Exact("456789")}))
	indeterminate(t, mustLink(t, aws, azure), "the constraint on sub for role arn:aws:iam::111111111111:role/deploy was not evaluated (ForAllValues:StringLike)")
	// Declared on another claim is still undeclared on this one.
	aws.Admits = aws.Admits.WithCaveat(eval.Caveat{Claim: "aud", Reason: "r", Source: "s"})
	indeterminate(t, mustLink(t, aws, azure), "the identities admitted by role arn:aws:iam::111111111111:role/deploy are an upper bound (r at s); the constraint on sub for role arn:aws:iam::111111111111:role/deploy was not evaluated (ForAllValues:StringLike)")
	// Several Unknowns over several terms read once each, in claim order.
	aws.Admits = eval.NewAdmittedSet(
		eval.Term{"sub": eval.Unknown("ForAllValues:StringLike"), "repository_id": eval.Exact("456789"), "aud": eval.Exact(awsAudience)},
		eval.Term{"sub": eval.Unknown("ForAllValues:StringLike"), "repository_owner_id": eval.Unknown("ForAnyValue:StringEquals"), "aud": eval.Exact(awsAudience)},
	)
	indeterminate(t, mustLink(t, aws, azure), "the constraint on repository_owner_id for role arn:aws:iam::111111111111:role/deploy was not evaluated (ForAnyValue:StringEquals); "+
		"the constraint on sub for role arn:aws:iam::111111111111:role/deploy was not evaluated (ForAllValues:StringLike)")
}

func TestEffectUnknownSentence(t *testing.T) {
	aws := awsGrant(pinned(eval.Exact(mainBranch), awsAudience))
	aws.Effect = trust.EffectUnknown
	azure := azureGrant(pinned(eval.Exact(mainBranch), azureAudience))
	indeterminate(t, mustLink(t, aws, azure), "the effect of the statement granting role arn:aws:iam::111111111111:role/deploy could not be read")
	// An effect that is none of the three values is as unreadable as Unknown.
	aws.Effect = ""
	indeterminate(t, mustLink(t, aws, azure), "the effect of the statement granting role arn:aws:iam::111111111111:role/deploy could not be read")
}

// TestUnprovedOverlapSentence: two patterns with no string in common that
// the lattice cannot prove apart. The walk finds no witness, IsEmpty stays
// false, and the honest answer is a Link that says so.
func TestUnprovedOverlapSentence(t *testing.T) {
	aws := awsGrant(pinned(eval.Glob("repo:acme/*"), awsAudience))
	azure := azureGrant(pinned(eval.Glob("repo:acme-evil/*"), azureAudience))
	l := mustLink(t, aws, azure)
	indeterminate(t, l, "no example identity could be constructed for identities from https://token.actions.githubusercontent.com with sub matching all of repo:acme-evil/* and repo:acme/*")
	if s := l.Subject(); s.Witness != nil || s.Overlap != `{sub=(like:"repo:acme-evil/*" & like:"repo:acme/*")}` {
		t.Errorf("Subject() = %+v; want no witness and the undecided intersection", s)
	}
	if !strings.Contains(string(encode(t, l)), `"witness": null`) {
		t.Errorf("no witness must render as null:\n%s", encode(t, l))
	}
	// A claim both sides left Unknown is unconstrained as far as could be
	// evaluated, and the description says so beside the claim that failed.
	aws = awsGrant(pinned(eval.Unknown("r"), awsAudience, eval.Term{"repository_id": eval.Glob("4*")}))
	azure = azureGrant(pinned(eval.Unknown("r"), azureAudience, eval.Term{"repository_id": eval.Glob("5*")}))
	indeterminate(t, mustLink(t, aws, azure), "the constraint on sub for application 6b1e6c7e-0f1a-4d2b-9c3d-8e4f5a6b7c8d was not evaluated (r); "+
		"the constraint on sub for role arn:aws:iam::111111111111:role/deploy was not evaluated (r); "+
		"no example identity could be constructed for identities from https://token.actions.githubusercontent.com with repository_id matching all of 4* and 5* and any sub")
}

// TestWidenedIntersectionSentence: a Meet past the term cap widens to
// everything with a caveat neither side carried. The pair is not
// Established on a witness of "any token".
func TestWidenedIntersectionSentence(t *testing.T) {
	aws := awsGrant(wide("repository_id", 17, awsAudience))
	azure := azureGrant(wide("repository_owner_id", 17, azureAudience))
	l := mustLink(t, aws, azure)
	// The widened overlap admits the empty token; the sides do not, so no
	// example can be confirmed, and the sentence says both.
	indeterminate(t, l, "the identities admitted by both are an upper bound (term count exceeded 256; widened to unconstrained); "+
		"no example identity could be constructed for any identity from https://token.actions.githubusercontent.com")
	if s := l.Subject(); s.Overlap != "{}" || s.Witness != nil {
		t.Errorf("Subject() = %+v", s)
	}
}

// wide is n terms that each pin claim to a different value, beside one
// audience, the shape whose cross product overflows the term cap.
func wide(claim trust.ClaimKey, n int, audience string) eval.AdmittedSet {
	terms := make([]eval.Term, n)
	for i := range terms {
		terms[i] = eval.Term{claim: eval.Exact(strconv.Itoa(i)), "aud": eval.Exact(audience)}
	}
	return eval.NewAdmittedSet(terms...)
}

const denyDoubt = "role arn:aws:iam::111111111111:role/deploy also denies identities from https://token.actions.githubusercontent.com, and whether these are among them could not be decided"

func TestDenySentence(t *testing.T) {
	aws := awsGrant(pinned(eval.Glob("repo:acme/*"), awsAudience))
	azure := azureGrant(pinned(eval.Exact(mainBranch), azureAudience))
	deny := awsGrant(pinned(eval.Glob("repo:acme/infra:*"), awsAudience))
	deny.Effect = trust.Deny
	deny.Provenance = []evidence.Record{record("iam:GetRolePolicy", deployRole.ID)}
	l := mustLink(t, aws, azure, deny)
	indeterminate(t, l, denyDoubt)
	// The Deny's evidence is part of the story, and a Deny counted twice
	// reads once.
	if got := l.Provenance(); len(got) != 3 {
		t.Errorf("Provenance() has %d records, want the two sides and the Deny", len(got))
	}
	if l := mustLink(t, aws, azure, deny, deny); len(l.Provenance()) != 3 || l.Reason() != denyDoubt {
		t.Errorf("the same Deny twice: %d records, %s", len(l.Provenance()), l.Reason())
	}
	// A Deny that provably misses the overlap, or the side's audience, takes
	// nothing away from it. A Deny is read as the tokens it denies, not as
	// its audiences and its subjects apart: one that denies the tools branch
	// for this audience and every acme repository for another cannot touch
	// the main branch for this one, though each projection alone could.
	elsewhere := deny
	elsewhere.Admits = pinned(eval.Exact(toolsBranch), awsAudience)
	otherAudience := deny
	otherAudience.Admits = pinned(eval.Glob("repo:acme/*"), "sts.amazonaws.com.cn")
	correlated := deny
	correlated.Admits = eval.NewAdmittedSet(
		eval.Term{"aud": eval.Exact(awsAudience), "sub": eval.Exact(toolsBranch)},
		eval.Term{"aud": eval.Exact("sts.amazonaws.com.cn"), "sub": eval.Glob("repo:acme/*")},
	)
	for name, d := range map[string]trust.Grant{"disjoint": elsewhere, "other audience": otherAudience, "correlated": correlated} {
		if l := mustLink(t, aws, azure, d); l.Confidence() != Established || len(l.Provenance()) != 2 {
			t.Errorf("a Deny that cannot touch the overlap must not count (%s): %s", name, l.Sentence())
		}
	}
	// A Deny on another target, or from another issuer, or an Allow passed as
	// a deny, is not a Deny on this pair.
	other := deny
	other.Target = trust.TargetRef{Kind: "role", ID: "arn:aws:iam::111111111111:role/other"}
	foreign := deny
	foreign.Issuer = gitlab
	allow := deny
	allow.Effect = trust.Allow
	for name, d := range map[string]trust.Grant{"other target": other, "other issuer": foreign, "not a deny": allow} {
		if l := mustLink(t, aws, azure, d); l.Confidence() != Established {
			t.Errorf("%s: %s", name, l.Sentence())
		}
	}
	// Doubts on both sides read in pair order, side by side.
	azure.Effect = trust.EffectUnknown
	indeterminate(t, mustLink(t, aws, azure, deny),
		"the effect of the statement granting application 6b1e6c7e-0f1a-4d2b-9c3d-8e4f5a6b7c8d could not be read; "+denyDoubt)
}

func TestNewLinkRefusesOneSidedProvenance(t *testing.T) {
	aws := awsGrant(pinned(eval.Exact(mainBranch), awsAudience))
	azure := azureGrant(pinned(eval.Exact(mainBranch), azureAudience))
	bare := azure
	bare.Provenance = nil
	for name, pair := range map[string][2]trust.Grant{"second": {aws, bare}, "first": {bare, aws}} {
		_, err := NewLink(pair[0], pair[1])
		if !errors.Is(err, ErrNoEvidence) {
			t.Errorf("%s side without evidence: err = %v, want ErrNoEvidence", name, err)
		}
		if err == nil || !strings.Contains(err.Error(), infraApp.ID) {
			t.Errorf("%s: the error must name the grant without evidence: %v", name, err)
		}
	}
	// A Deny without evidence still counts against the pair: doubt needs no
	// proof, and dropping it would promote the pair to Established.
	deny := awsGrant(pinned(eval.Glob("repo:acme/*"), awsAudience))
	deny.Effect, deny.Provenance = trust.Deny, nil
	l := mustLink(t, aws, azure, deny)
	if l.Confidence() != Indeterminate || len(l.Provenance()) != 2 {
		t.Errorf("a Deny without evidence must count and add nothing to provenance: %s", l.Sentence())
	}
}

func TestNewLinkRefusesWhatIsNotAPair(t *testing.T) {
	aws := awsGrant(pinned(eval.Exact(mainBranch), awsAudience))
	azure := azureGrant(pinned(eval.Exact(mainBranch), azureAudience))
	twin := aws
	twin.Admits = pinned(eval.Glob("repo:acme/*"), awsAudience)
	foreign := azure
	foreign.Issuer = gitlab
	deny := azure
	deny.Effect = trust.Deny
	disjoint := azureGrant(pinned(eval.Exact(devBranch), azureAudience))
	cases := []struct {
		name string
		b    trust.Grant
		want error
	}{
		{"same target", twin, ErrSameTarget},
		{"different issuers", foreign, ErrDifferentIssuers},
		{"a Deny as a side", deny, ErrDeny},
		{"provably disjoint", disjoint, ErrDisjoint},
	}
	for _, c := range cases {
		if _, err := NewLink(aws, c.b); !errors.Is(err, c.want) {
			t.Errorf("%s: err = %v, want %v", c.name, err, c.want)
		}
		if _, err := NewLink(c.b, aws); !errors.Is(err, c.want) {
			t.Errorf("%s, flipped: err = %v, want %v", c.name, err, c.want)
		}
	}
	if _, err := NewLink(aws, aws); !errors.Is(err, ErrSameTarget) {
		t.Errorf("a grant with itself: err = %v", err)
	}
	// Every refusal names both targets, so a caller can find the pair.
	if _, err := NewLink(aws, foreign); err == nil || !strings.Contains(err.Error(), deployRole.ID) || !strings.Contains(err.Error(), infraApp.ID) {
		t.Errorf("err = %v", err)
	}
}

// TestSentenceIsPrintable: a target id, an issuer path or a claim value is
// customer configuration, and a terminal escape inside one could rewrite
// the line that prints it.
func TestSentenceIsPrintable(t *testing.T) {
	aws := awsGrant(pinned(eval.Exact("repo:acme/infra:ref:refs/heads/ma\x1b[2Kin"), awsAudience))
	aws.Target.ID = "arn:aws:iam::111111111111:role/dep\x07loy"
	azure := azureGrant(pinned(eval.Exact("repo:acme/infra:ref:refs/heads/ma\x1b[2Kin"), azureAudience))
	l := mustLink(t, aws, azure)
	for name, s := range map[string]string{"Sentence": l.Sentence(), "Reason": l.Reason()} {
		if strings.ContainsFunc(s, func(r rune) bool { return r < 0x20 || (r >= 0x7f && r <= 0x9f) }) {
			t.Errorf("%s() carries a control character: %q", name, s)
		}
	}
	if !strings.Contains(l.Sentence(), "role arn:aws:iam::111111111111:role/deploy") || !strings.Contains(l.Sentence(), "sub repo:acme/infra:ref:refs/heads/ma[2Kin") {
		t.Errorf("stripping must keep the printable text: %s", l.Sentence())
	}
	// The data keeps the bytes; only the prose is stripped.
	if l.Grants()[1].Target.ID != aws.Target.ID || l.Subject().Witness["sub"] != "repo:acme/infra:ref:refs/heads/ma\x1b[2Kin" {
		t.Errorf("the accessors must return the customer's bytes: %+v", l.Subject())
	}
	// A target without a kind is named by its id alone, and sorts first.
	aws.Target = trust.TargetRef{ID: "arn:aws:iam::111111111111:role/deploy"}
	if got := mustLink(t, aws, azure).Sentence(); !strings.HasPrefix(got, "Identities admitted by arn:aws:iam::111111111111:role/deploy are also admitted by application") {
		t.Errorf("Sentence() = %s", got)
	}
}

func TestAccessorsReturnCopies(t *testing.T) {
	aws := awsGrant(pinned(eval.Exact(mainBranch), awsAudience).WithCaveat(eval.Caveat{Claim: "sub", Reason: "r", Source: "s"}))
	azure := azureGrant(pinned(eval.Exact(mainBranch), azureAudience))
	l := mustLink(t, aws, azure)
	before := encode(t, l)
	l.Grants()[0].Target.ID = "tampered"
	l.Grants()[1].Caveats[0].Reason = "tampered"
	l.Subject().Witness["sub"] = "tampered"
	l.Provenance()[0].Bytes[0] = '!'
	l.Provenance()[0].API = "tampered"
	if after := encode(t, l); !bytes.Equal(before, after) {
		t.Errorf("an accessor exposed the Link's own storage:\n%s\n%s", before, after)
	}
}

// TestZeroLinkSaysNothing: the fields are unexported, so a Link built any
// way but NewLink or FanOut is the zero value, and the zero value has no
// sentence to print and no JSON to render.
func TestZeroLinkSaysNothing(t *testing.T) {
	var zero Link
	if zero.Valid() || zero.Sentence() != "" || zero.Reason() != "" || zero.Kind() != "" || zero.Confidence() != "" {
		t.Errorf("the zero Link must say nothing: %q", zero.Sentence())
	}
	if len(zero.Grants()) != 0 || len(zero.Provenance()) != 0 || zero.Subject().Issuer != "" {
		t.Errorf("the zero Link must hold nothing: %v %v %v", zero.Grants(), zero.Provenance(), zero.Subject())
	}
	if _, err := json.Marshal(zero); err == nil {
		t.Errorf("the zero Link must not render")
	}
}

func TestJSONIsTheReporterSchema(t *testing.T) {
	aws := awsGrant(pinned(eval.Exact(mainBranch), awsAudience))
	azure := azureGrant(pinned(eval.Exact(mainBranch), azureAudience))
	l := mustLink(t, aws, azure)
	var got map[string]json.RawMessage
	if err := json.Unmarshal(encode(t, l), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, key := range []string{"kind", "grants", "subject", "confidence", "reason", "sentence", "provenance"} {
		if _, ok := got[key]; !ok {
			t.Errorf("JSON lacks %q: %s", key, encode(t, l))
		}
	}
	if len(got) != 7 {
		t.Errorf("JSON has %d keys, want 7: %s", len(got), encode(t, l))
	}
	if string(got["kind"]) != `"counterparty-fan-out"` || string(got["confidence"]) != `"established"` {
		t.Errorf("kind = %s, confidence = %s", got["kind"], got["confidence"])
	}
	// The vocabulary rule applies to field names and values alike.
	lower := strings.ToLower(string(encode(t, l)))
	for _, banned := range []string{"severity", "security", "critical", "risk", "score", "grade"} {
		if strings.Contains(lower, banned) {
			t.Errorf("JSON contains %q", banned)
		}
	}
	if !strings.Contains(string(encode(t, l)), `"target": {
        "kind": "role",
        "id": "arn:aws:iam::111111111111:role/deploy"
      }`) {
		t.Errorf("target must render as kind and id:\n%s", encode(t, l))
	}
	// A body that is not JSON renders as base64 (see
	// TestEvidenceThatIsNotJSONIsCarried), so the one way left for the
	// rendering to fail is a fetch time outside the years JSON can carry;
	// the error then names the link rather than leaving the reporter to
	// guess which one it lost.
	aws.Provenance = []evidence.Record{evidence.New("iam:GetRole", `{}`, evidence.StatusOK, []byte(`{}`), time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC))}
	if _, err := json.Marshal(mustLink(t, aws, azure)); err == nil || !strings.Contains(err.Error(), deployRole.ID) || !strings.Contains(err.Error(), infraApp.ID) {
		t.Errorf("marshal with an unrenderable fetch time: err = %v", err)
	}
}

// TestNewLinkRefusesAGrantThatNamesNothing: the sentence names the target
// of each side and, for a doubted record, its call and its status. A grant
// whose target is blank, or whose records are all blank where a name goes,
// is a parser or collector bug, and building a Link on it would print a
// sentence with a hole in it. Blank means nothing printable: spaces, and
// control characters the sentence strips before it is printed, are as
// much of a hole as nothing at all.
func TestNewLinkRefusesAGrantThatNamesNothing(t *testing.T) {
	aws := awsGrant(pinned(eval.Exact(mainBranch), awsAudience))
	azure := azureGrant(pinned(eval.Exact(mainBranch), azureAudience))
	unnamed := azure
	unnamed.Target = trust.TargetRef{Kind: "application"}
	spaces := azure
	spaces.Target.ID = " \t "
	controls := azure
	controls.Target.ID = "\x1b\x07\x7f"
	noCall := azure
	noCall.Provenance = []evidence.Record{{}}
	noStatus := azure
	noStatus.Provenance = []evidence.Record{evidence.New("graph:applications.get", `{}`, "", nil, time.Unix(0, 0)), evidence.New("graph:applications.list", `{}`, " ", nil, time.Unix(0, 0))}
	blankCall := azure
	blankCall.Provenance = []evidence.Record{evidence.New(" ", `{}`, evidence.StatusOK, nil, time.Unix(0, 0)), evidence.New("\x01", `{}`, evidence.StatusOK, nil, time.Unix(0, 0))}
	cases := []struct {
		name string
		b    trust.Grant
		want error
		text string // what the error says beyond the grant's name
	}{
		{"no target id", unnamed, ErrNoTarget, "names no target"},
		{"a target id of spaces", spaces, ErrNoTarget, "names no target"},
		{"a target id of control characters", controls, ErrNoTarget, "names no target"},
		{"only a record naming no call", noCall, ErrMalformedEvidence, "carries only malformed evidence records: a record names no API call"},
		{"only records naming no status", noStatus, ErrMalformedEvidence, "carries only malformed evidence records: the record of graph:applications.get names no status"},
		{"only records whose call is blank", blankCall, ErrMalformedEvidence, "carries only malformed evidence records: a record names no API call"},
	}
	for _, c := range cases {
		for _, pair := range [][2]trust.Grant{{aws, c.b}, {c.b, aws}} {
			_, err := NewLink(pair[0], pair[1])
			if !errors.Is(err, c.want) {
				t.Errorf("%s: err = %v, want %v", c.name, err, c.want)
			}
			if err == nil || !strings.Contains(err.Error(), c.text) {
				t.Errorf("%s: the error must say %q: %v", c.name, c.text, err)
			}
			if err != nil && c.want != ErrNoTarget && !strings.Contains(err.Error(), c.b.Target.ID+" from "+string(github)) {
				t.Errorf("%s: the error must name the grant by target and issuer: %v", c.name, err)
			}
		}
	}
	// Which record the error names does not follow the collector's listing
	// order: two malformed records read in canonical order, whichever came
	// first.
	reversed := noStatus
	reversed.Provenance = slices.Clone(noStatus.Provenance)
	slices.Reverse(reversed.Provenance)
	_, errTwo := NewLink(aws, noStatus)
	_, errReversed := NewLink(aws, reversed)
	if errTwo == nil || errReversed == nil || errTwo.Error() != errReversed.Error() {
		t.Errorf("the record named depends on listing order:\n%v\n%v", errTwo, errReversed)
	}
	// The zero grant is named as what it is, with no blank where a name goes,
	// and a grant naming no issuer is named without one. The refusal names
	// the sides in canonical order, whichever way they were given.
	if _, err := NewLink(aws, trust.Grant{}); err == nil || err.Error() != "link a grant with role arn:aws:iam::111111111111:role/deploy: a grant names no target" {
		t.Errorf("the zero grant: err = %v", err)
	}
	unissued := noCall
	unissued.Issuer = ""
	if _, err := NewLink(aws, unissued); err == nil || err.Error() != "link application 6b1e6c7e-0f1a-4d2b-9c3d-8e4f5a6b7c8d with role arn:aws:iam::111111111111:role/deploy: application 6b1e6c7e-0f1a-4d2b-9c3d-8e4f5a6b7c8d carries only malformed evidence records: a record names no API call" {
		t.Errorf("a grant naming no issuer: err = %v", err)
	}
	// FanOut names the malformed grants beside the links the others make.
	gcp := gcpGrant(pinned(eval.Exact(mainBranch), gcpAudience))
	links, err := FanOut([]trust.Grant{aws, noCall, gcp, spaces})
	if !errors.Is(err, ErrMalformedEvidence) || !errors.Is(err, ErrNoTarget) {
		t.Errorf("err = %v, want ErrMalformedEvidence and ErrNoTarget", err)
	}
	if len(links) != 1 || links[0].Grants()[0].Target != deployRole || links[0].Grants()[1].Target != buildAccount {
		t.Errorf("links = %v, want the role and the service account alone", links)
	}
	// A Deny whose only record names no call still casts its doubt, since
	// doubt needs no proof, and the record is carried as it is: hiding the
	// record would hide the collector bug the sentence names.
	deny := denyOn(deployRole, eval.Exact(mainBranch))
	deny.Provenance = []evidence.Record{{}}
	links, err = FanOut([]trust.Grant{aws, gcp, deny})
	if !errors.Is(err, ErrMalformedEvidence) || len(links) != 1 || links[0].Confidence() != Indeterminate || len(links[0].Provenance()) != 3 {
		t.Errorf("a Deny with a malformed record: links = %v, err = %v", links, err)
	}
	if len(links) == 1 && links[0].Reason() != denyDoubt+" (a record for role arn:aws:iam::111111111111:role/deploy names no API call)" {
		t.Errorf("Reason() = %q", links[0].Reason())
	}
}

// TestMalformedRecordIsADoubt: one record that names no call or no status
// beside well-formed ones is a collector bug on that record, not a reason
// to drop a fan-out the other records prove. The pair is a Link, the
// sentence names the defect instead of printing a hole, and the record is
// carried as it is. A status made of control characters, which the
// sentence would print as nothing, is no status.
func TestMalformedRecordIsADoubt(t *testing.T) {
	aws := awsGrant(pinned(eval.Exact(mainBranch), awsAudience))
	for i := range 5 {
		aws.Provenance = append(aws.Provenance, record("iam:Call"+strconv.Itoa(i), deployRole.ID))
	}
	azure := azureGrant(pinned(eval.Exact(mainBranch), azureAudience))
	cases := []struct {
		name   string
		record evidence.Record
		doubt  string
	}{
		{"no call", evidence.New("", `{}`, evidence.StatusOK, []byte(`{}`), time.Unix(0, 0)), "a record for role arn:aws:iam::111111111111:role/deploy names no API call"},
		{"a call of spaces", evidence.New("  ", `{}`, evidence.StatusOK, nil, time.Unix(0, 0)), "a record for role arn:aws:iam::111111111111:role/deploy names no API call"},
		{"no status", evidence.New("iam:GetRole", `{}`, "", nil, time.Unix(0, 0)), "the record of iam:GetRole for role arn:aws:iam::111111111111:role/deploy names no status"},
		{"a status of spaces", evidence.New("iam:GetRole", `{}`, " ", nil, time.Unix(0, 0)), "the record of iam:GetRole for role arn:aws:iam::111111111111:role/deploy names no status"},
		{"a status of control characters", evidence.New("iam:GetRole", `{}`, "\x01\x7f", nil, time.Unix(0, 0)), "the record of iam:GetRole for role arn:aws:iam::111111111111:role/deploy names no status"},
		{"neither", evidence.New("", `{}`, "", nil, time.Unix(0, 0)), "a record for role arn:aws:iam::111111111111:role/deploy names no API call"},
	}
	for _, c := range cases {
		doubted := aws
		doubted.Provenance = append(slices.Clone(aws.Provenance), c.record)
		links, err := FanOut([]trust.Grant{doubted, azure})
		if err != nil || len(links) != 1 {
			t.Fatalf("%s: %d links, err = %v; want the pair, doubted, and no error", c.name, len(links), err)
		}
		indeterminate(t, links[0], c.doubt)
		if got := links[0].Provenance(); len(got) != 8 || !slices.ContainsFunc(got, func(r evidence.Record) bool { return r.API == c.record.API && r.Status == c.record.Status }) {
			t.Errorf("%s: Provenance() has %d records; want all 8, the malformed one as it is", c.name, len(got))
		}
	}
	// Every doubted record is named, in record order, and a witness is still
	// data on the Link.
	doubted := aws
	doubted.Provenance = append(slices.Clone(aws.Provenance), evidence.New("iam:GetRole", `{}`, "", nil, time.Unix(0, 0)), evidence.New("", `{}`, evidence.StatusOK, nil, time.Unix(0, 0)), refused("iam:GetRolePolicy", deployRole.ID))
	l := mustLink(t, doubted, azure)
	indeterminate(t, l, "a record for role arn:aws:iam::111111111111:role/deploy names no API call; "+
		"the record of iam:GetRole for role arn:aws:iam::111111111111:role/deploy names no status; "+
		"the call iam:GetRolePolicy for role arn:aws:iam::111111111111:role/deploy returned denied")
	if l.Subject().Witness["sub"] != mainBranch {
		t.Errorf("Witness = %v", l.Subject().Witness)
	}
}

// TestBlankKindLeavesNoHole: a target kind of spaces or control characters
// prints as nothing, so the target is named by its id alone, as one with
// no kind is. The data keeps the bytes.
func TestBlankKindLeavesNoHole(t *testing.T) {
	aws := awsGrant(pinned(eval.Exact(mainBranch), awsAudience))
	aws.Target.Kind = " \x1b "
	azure := azureGrant(pinned(eval.Exact(mainBranch), azureAudience))
	l := mustLink(t, aws, azure)
	if !strings.HasPrefix(l.Sentence(), "Identities admitted by arn:aws:iam::111111111111:role/deploy are also admitted by application") {
		t.Errorf("Sentence() = %s", l.Sentence())
	}
	if l.Grants()[0].Target.Kind != aws.Target.Kind {
		t.Errorf("the reference must keep the customer's bytes: %q", l.Grants()[0].Target.Kind)
	}
}

const denyDoubtDetailed = denyDoubt + " (the call iam:GetRolePolicy for role arn:aws:iam::111111111111:role/deploy returned denied)"

// TestDoubtedDenialCounts: a Deny that provably misses the overlap takes
// nothing from it only when its reading can be relied on. Read through an
// inconclusive or malformed record, without evidence, or as an upper
// bound, what it denies is at least what was read and may be more, so it
// counts against every pair on its target, its evidence joins the Link's,
// and the sentence says why the denial could not be ruled out.
func TestDoubtedDenialCounts(t *testing.T) {
	aws := awsGrant(pinned(eval.Exact(mainBranch), awsAudience))
	azure := azureGrant(pinned(eval.Exact(mainBranch), azureAudience))
	misses := denyOn(deployRole, eval.Exact(toolsBranch))
	if l := mustLink(t, aws, azure, misses); l.Confidence() != Established || len(l.Provenance()) != 2 {
		t.Fatalf("a Deny read exactly and conclusively that provably misses must not count: %s", l.Sentence())
	}
	refusedRead := misses
	refusedRead.Provenance = []evidence.Record{refused("iam:GetRolePolicy", deployRole.ID)}
	l := mustLink(t, aws, azure, refusedRead)
	indeterminate(t, l, denyDoubtDetailed)
	if got := l.Provenance(); len(got) != 3 || got[2].API != "iam:GetRolePolicy" || got[2].Status != evidence.StatusDenied {
		t.Errorf("Provenance() = %v; want the refused record carried beside the sides'", got)
	}
	unproved := misses
	unproved.Provenance = nil
	indeterminate(t, mustLink(t, aws, azure, unproved), denyDoubt+" (the statement carries no evidence)")
	malformedRead := misses
	malformedRead.Provenance = []evidence.Record{record("iam:GetRolePolicy", deployRole.ID), evidence.New("iam:GetRole", `{}`, "", nil, time.Unix(0, 0))}
	indeterminate(t, mustLink(t, aws, azure, malformedRead), denyDoubt+" (the record of iam:GetRole for role arn:aws:iam::111111111111:role/deploy names no status)")
	// A Deny the parser could not evaluate admits nothing as read and says so
	// in a caveat; as read, that is the least it denies. The shape is the AWS
	// parser's for a Deny with an operator it does not model.
	unevaluated := misses
	unevaluated.Admits = eval.Nothing().WithCaveat(eval.Caveat{Reason: "this Deny statement could not be fully evaluated, so it is not applied; the admitted set is an upper bound", Source: "statement[1]"})
	indeterminate(t, mustLink(t, aws, azure, unevaluated), denyDoubt+" (this Deny statement could not be fully evaluated, so it is not applied; the admitted set is an upper bound at statement[1])")
	// The details read once each, sorted, from every counted Deny, whatever
	// order the Denies were given in; a Deny that touches and one that is
	// doubted share the one sentence.
	touches := denyOn(deployRole, eval.Glob("repo:acme/*"))
	detailed := denyDoubt + " (the call iam:GetRolePolicy for role arn:aws:iam::111111111111:role/deploy returned denied; this Deny statement could not be fully evaluated, so it is not applied; the admitted set is an upper bound at statement[1])"
	indeterminate(t, mustLink(t, aws, azure, touches, refusedRead, unevaluated, refusedRead), detailed)
	indeterminate(t, mustLink(t, aws, azure, unevaluated, refusedRead, touches), detailed)
	// An unread statement is read by the same rule.
	unread := refusedRead
	unread.Effect = trust.EffectUnknown
	indeterminate(t, mustLink(t, aws, azure, unread), unreadDoubt+" (the call iam:GetRolePolicy for role arn:aws:iam::111111111111:role/deploy returned denied)")
	// FanOut gathers the doubted Deny as it gathers a touching one, and the
	// pair on the other application, which the Deny provably misses too, is
	// doubted as well: the doubt is about the reading, not the reach.
	other := azureGrant(pinned(eval.Exact(toolsBranch), azureAudience))
	other.Target = trust.TargetRef{Kind: "application", ID: "9d2f4a6b-1c3e-4f5a-8b7c-6d5e4f3a2b1c"}
	links, err := FanOut([]trust.Grant{aws, azure, other, refusedRead})
	if err != nil || len(links) != 1 || links[0].Reason() != denyDoubtDetailed {
		t.Errorf("FanOut: %d links, err = %v: %v", len(links), err, links)
	}
	links, err = FanOut([]trust.Grant{awsGrant(pinned(eval.Glob("repo:acme/*"), awsAudience)), azure, other, refusedRead})
	if err != nil || len(links) != 2 || links[0].Reason() != denyDoubtDetailed || links[1].Reason() != denyDoubtDetailed {
		t.Errorf("FanOut: %d links, err = %v: %v", len(links), err, links)
	}
}

const unnamedIssuerDoubt = "which issuers' tokens role arn:aws:iam::111111111111:role/deploy admits is not known"

// TestIssuerNotNamed: a grant whose issuer is blank admits, as far as the
// parser could read, tokens from any issuer; the AWS parser emits one for
// a bare "*" principal on sts:AssumeRoleWithWebIdentity, with the caveat
// below. It pairs with every issuer's grants on other targets, never
// Established, and the pair's issuer is the one the other side names.
func TestIssuerNotNamed(t *testing.T) {
	anyone := awsGrant(eval.NewAdmittedSet(eval.Term{}).WithCaveat(eval.Caveat{Reason: "the statement applies to every principal, and which identity providers' tokens that admits through sts:AssumeRoleWithWebIdentity or sts:AssumeRoleWithSAML is not known", Source: "statement[0].Principal"}))
	anyone.Issuer = ""
	azure := azureGrant(pinned(eval.Glob("repo:acme/infra:*"), azureAudience))
	l := mustLink(t, anyone, azure)
	indeterminate(t, l, unnamedIssuerDoubt+"; the identities admitted by role arn:aws:iam::111111111111:role/deploy are an upper bound (the statement applies to every principal, and which identity providers' tokens that admits through sts:AssumeRoleWithWebIdentity or sts:AssumeRoleWithSAML is not known at statement[0].Principal)")
	if s := l.Subject(); s.Issuer != github || s.Overlap != `{sub=like:"repo:acme/infra:*"}` || s.Witness["sub"] != "repo:acme/infra:" {
		t.Errorf("Subject() = %+v; want the application's issuer and its identities", s)
	}
	if g := l.Grants(); g[1].Issuer != "" {
		t.Errorf("the reference must keep the blank issuer: %+v", g[1])
	}
	// The join's own rule, without the parser's caveat, and against a value.
	pinnedAnyone := awsGrant(pinned(eval.Glob("repo:acme/*"), awsAudience))
	pinnedAnyone.Issuer = ""
	indeterminate(t, mustLink(t, pinnedAnyone, azure), unnamedIssuerDoubt)
	// The pair's issuer is the named one whichever side names it: here the
	// side naming none sorts first.
	unnamedApp := azureGrant(pinned(eval.Glob("repo:acme/infra:*"), azureAudience))
	unnamedApp.Issuer = ""
	aws := awsGrant(pinned(eval.Glob("repo:acme/*"), awsAudience))
	if l := mustLink(t, unnamedApp, aws); l.Subject().Issuer != github || l.Sentence() != "Identities admitted by "+mayPair+"which issuers' tokens application 6b1e6c7e-0f1a-4d2b-9c3d-8e4f5a6b7c8d admits is not known." {
		t.Errorf("Subject().Issuer = %q, Sentence() = %s", l.Subject().Issuer, l.Sentence())
	}
	// Two grants naming no issuer pair with each other, and the sentence
	// names no issuer anywhere.
	gcp := gcpGrant(pinned(eval.Exact(mainBranch), gcpAudience))
	gcp.Issuer = " "
	both := mustLink(t, pinnedAnyone, gcp)
	want := "Identities admitted by role arn:aws:iam::111111111111:role/deploy may also be admitted by service-account deploy@acme-prod.iam.gserviceaccount.com; " +
		unnamedIssuerDoubt + "; which issuers' tokens service-account deploy@acme-prod.iam.gserviceaccount.com admits is not known."
	if both.Sentence() != want {
		t.Errorf("Sentence() =\n%s\nwant\n%s", both.Sentence(), want)
	}
	if s := both.Subject(); s.Issuer != "" || !strings.Contains(string(encode(t, both)), `"issuer": ""`) {
		t.Errorf("Subject() = %+v; want no issuer", s)
	}
	// With no witness the description names no issuer either.
	unwitnessed := gcpGrant(pinned(eval.Glob("repo:acme-evil/*"), gcpAudience))
	unwitnessed.Issuer = ""
	if l := mustLink(t, pinnedAnyone, unwitnessed); !strings.HasSuffix(l.Reason(), "; no example identity could be constructed for identities with sub matching all of repo:acme-evil/* and repo:acme/*") {
		t.Errorf("Reason() = %s", l.Reason())
	}
	// A blank issuer is not the same as another blank issuer for the corpus:
	// the two are two grants, each pairing with the other.
	links, err := FanOut([]trust.Grant{pinnedAnyone, gcp, azure})
	if err != nil || len(links) != 3 {
		t.Fatalf("FanOut: %d links, err = %v; want every pair", len(links), err)
	}
	for _, l := range links {
		if l.Confidence() != Indeterminate {
			t.Errorf("Established through a grant naming no issuer: %s", l.Sentence())
		}
	}
	// A Deny naming no issuer may deny any issuer's tokens, so it counts
	// against every pair on its target; a Deny naming another issuer does
	// not.
	deny := denyOn(deployRole, eval.Glob("repo:acme/infra:*"))
	deny.Issuer = ""
	indeterminate(t, mustLink(t, aws, azure, deny), "role arn:aws:iam::111111111111:role/deploy also denies identities from an issuer it does not name, and whether these are among them could not be decided")
	unread := deny
	unread.Effect = trust.EffectUnknown
	indeterminate(t, mustLink(t, aws, azure, unread), "role arn:aws:iam::111111111111:role/deploy also has a statement from an issuer it does not name whose effect could not be read, and whether it denies these identities could not be decided")
	foreign := denyOn(deployRole, eval.Glob("repo:acme/infra:*"))
	foreign.Issuer = gitlab
	if l := mustLink(t, aws, azure, foreign); l.Confidence() != Established {
		t.Errorf("a Deny from another issuer counted: %s", l.Sentence())
	}
	// Against a side naming no issuer, the pair's issuer is the partner's,
	// and a Deny from a third issuer cannot touch the partner's tokens.
	if l := mustLink(t, pinnedAnyone, azure, foreign); l.Reason() != unnamedIssuerDoubt {
		t.Errorf("Reason() = %s", l.Reason())
	}
	named := denyOn(deployRole, eval.Glob("repo:acme/infra:*"))
	indeterminate(t, mustLink(t, pinnedAnyone, azure, named, deny), unnamedIssuerDoubt+"; "+
		"role arn:aws:iam::111111111111:role/deploy also denies identities from an issuer it does not name, and whether these are among them could not be decided; "+denyDoubt)
	// Two named issuers that differ still never pair.
	if _, err := NewLink(aws, gcpGrant(pinned(eval.Exact(mainBranch), gcpAudience))); err != nil {
		t.Errorf("one issuer: %v", err)
	}
	foreignSide := gcpGrant(pinned(eval.Exact(mainBranch), gcpAudience))
	foreignSide.Issuer = gitlab
	if _, err := NewLink(aws, foreignSide); !errors.Is(err, ErrDifferentIssuers) {
		t.Errorf("two issuers: err = %v", err)
	}
}

// TestLongListsAreCounted: a policy listing thirty repositories against
// another listing thirty is nine hundred alternatives, and a sentence that
// lists them all is not a sentence. The description names three members of
// any list and counts the rest; the rendering on the Link keeps them all.
func TestLongListsAreCounted(t *testing.T) {
	var lower, upper eval.StringSet = eval.None(), eval.None()
	for i := range 30 {
		lower = lower.Join(eval.Glob("repo:acme/service-" + string(rune('a'+i)) + ":ref:refs/heads/*"))
		upper = upper.Join(eval.Glob("repo:acme/service-" + string(rune('A'+i)) + ":*"))
	}
	l := mustLink(t, awsGrant(pinned(lower, awsAudience)), azureGrant(pinned(upper, azureAudience)))
	indeterminate(t, l, "no example identity could be constructed for identities from https://token.actions.githubusercontent.com with sub "+
		"matching all of repo:acme/service-A:* and repo:acme/service-a:ref:refs/heads/* or "+
		"matching all of repo:acme/service-A:* and repo:acme/service-b:ref:refs/heads/* or "+
		"matching all of repo:acme/service-A:* and repo:acme/service-c:ref:refs/heads/* or one of 897 more alternatives")
	if n := strings.Count(l.Subject().Overlap, "&"); n != 900 {
		t.Errorf("the rendering holds %d alternatives, want all 900", n)
	}
	// An intersection of many patterns, as several StringLike conditions on
	// one claim produce, is counted the same way; an overlap of exactly four
	// is named whole, since "and 1 more" would hide one pattern to say as
	// much.
	three := awsGrant(pinned(inter("repo:acme/*", "*:ref:*", "*infra*"), awsAudience))
	four := awsGrant(pinned(inter("repo:acme/*", "*:ref:*", "*infra*", "*main*"), awsAudience))
	azure := azureGrant(pinned(eval.Glob("repo:acme/infra:*"), azureAudience))
	if got := mustLink(t, three, azure).Reason(); got != "both admit identities from https://token.actions.githubusercontent.com with sub matching all of *:ref:*, *infra*, repo:acme/* and repo:acme/infra:*, for example sub=repo:acme/infra:ref:" {
		t.Errorf("four patterns: Reason() = %s", got)
	}
	if got := mustLink(t, four, azure).Reason(); got != "both admit identities from https://token.actions.githubusercontent.com with sub matching all of *:ref:*, *infra*, *main* and 2 more patterns, for example sub=repo:acme/infra:ref:main" {
		t.Errorf("five patterns: Reason() = %s", got)
	}
	// Terms are counted the same way: a role that pins each of six branches
	// beside its own repository id is six combinations.
	terms := make([]eval.Term, 6)
	for i := range terms {
		terms[i] = eval.Term{"sub": eval.Exact("repo:acme/infra:ref:refs/heads/" + string(rune('a'+i))), "repository_id": eval.Exact(strconv.Itoa(i)), "aud": eval.Exact(awsAudience)}
	}
	if got := mustLink(t, awsGrant(eval.NewAdmittedSet(terms...)), azure).Reason(); got != "both admit identities from https://token.actions.githubusercontent.com with repository_id 0 and sub repo:acme/infra:ref:refs/heads/a, or with repository_id 1 and sub repo:acme/infra:ref:refs/heads/b, or with repository_id 2 and sub repo:acme/infra:ref:refs/heads/c, or with one of 3 more combinations" {
		t.Errorf("six terms: Reason() = %s", got)
	}
}

// TestMarshalJSONIsTheCanonicalRendering: the bytes MarshalJSON returns
// are the ones the goldens hold and a finding id is built on, and an
// Encoder with HTML escaping off writes the same. json.Marshal re-escapes
// every Marshaler's output, so it does not: a reporter hashing its output
// would not match the golden, which is why the method's comment says
// which entry point is canonical.
func TestMarshalJSONIsTheCanonicalRendering(t *testing.T) {
	aws := awsGrant(pinned(eval.Glob("repo:acme/*:ref:refs/heads/main"), awsAudience))
	aws.Provenance = []evidence.Record{evidence.New("iam:GetRole", `{}`, evidence.StatusOK, []byte(`{"s":"<b>&</b>"}`), time.Unix(0, 0))}
	azure := azureGrant(pinned(eval.Glob("repo:acme/infra:*"), azureAudience))
	l := mustLink(t, aws, azure)
	direct, err := l.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(l); err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if !bytes.Equal(direct, bytes.TrimSuffix(buf.Bytes(), []byte("\n"))) {
		t.Errorf("MarshalJSON and an Encoder without HTML escaping disagree:\n%s\n%s", direct, buf.Bytes())
	}
	for _, written := range []string{`sub=(like:\"repo:acme/*:ref:refs/heads/main\" & like:\"repo:acme/infra:*\")`, `{"s":"<b>&</b>"}`} {
		if !bytes.Contains(direct, []byte(written)) {
			t.Errorf("the canonical bytes must carry %s as written:\n%s", written, direct)
		}
	}
	std, err := json.Marshal(l)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	escaped := strings.NewReplacer("<", `\u003c`, ">", `\u003e`, "&", `\u0026`).Replace(string(direct))
	if string(std) != escaped {
		t.Errorf("json.Marshal differs from the canonical bytes by more than HTML escaping:\n%s\n%s", std, escaped)
	}
}

const unreadDoubt = "role arn:aws:iam::111111111111:role/deploy also has a statement from https://token.actions.githubusercontent.com whose effect could not be read, and whether it denies these identities could not be decided"

// TestUnreadEffectSiblingSentence: a statement whose effect could not be
// read is possibly Allow, which is why it pairs, and possibly Deny, which
// is why it casts on its target's other links the doubt a Deny would. A
// sentence that read "are also admitted" beside a statement that may deny
// exactly those identities would be a guess.
func TestUnreadEffectSiblingSentence(t *testing.T) {
	aws := awsGrant(pinned(eval.Glob("repo:acme/*"), awsAudience))
	azure := azureGrant(pinned(eval.Exact(mainBranch), azureAudience))
	unread := awsGrant(pinned(eval.Glob("repo:acme/infra:*"), awsAudience))
	unread.Effect = trust.EffectUnknown
	unread.Provenance = []evidence.Record{record("iam:GetRolePolicy", deployRole.ID)}
	l := mustLink(t, aws, azure, unread)
	indeterminate(t, l, unreadDoubt)
	if got := l.Provenance(); len(got) != 3 {
		t.Errorf("Provenance() has %d records, want the two sides and the unread statement", len(got))
	}
	// One that provably misses the overlap, or the side's audience, is no
	// doubt, exactly as a Deny that misses is none.
	elsewhere := unread
	elsewhere.Admits = pinned(eval.Exact(toolsBranch), awsAudience)
	otherAudience := unread
	otherAudience.Admits = pinned(eval.Glob("repo:acme/*"), "sts.amazonaws.com.cn")
	for name, d := range map[string]trust.Grant{"disjoint": elsewhere, "other audience": otherAudience} {
		if l := mustLink(t, aws, azure, d); l.Confidence() != Established || len(l.Provenance()) != 2 {
			t.Errorf("an unread statement that cannot touch the overlap must not count (%s): %s", name, l.Sentence())
		}
	}
	// A side never doubts itself: its own unread effect is said once.
	indeterminate(t, mustLink(t, unread, azure, unread), "the effect of the statement granting role arn:aws:iam::111111111111:role/deploy could not be read")
	// Both kinds of doubt on one target read Deny first.
	deny := awsGrant(pinned(eval.Glob("repo:acme/infra:*"), awsAudience))
	deny.Effect = trust.Deny
	indeterminate(t, mustLink(t, aws, azure, unread, deny), denyDoubt+"; "+unreadDoubt)
	// FanOut gathers unread statements as it gathers Denies. Read as a Deny
	// instead, the same statement takes the same link away from Established
	// and is itself no side.
	links, err := FanOut([]trust.Grant{aws, azure, unread})
	if err != nil {
		t.Fatalf("FanOut: %v", err)
	}
	if len(links) != 2 || links[0].Reason() != unreadDoubt || links[1].Reason() != "the effect of the statement granting role arn:aws:iam::111111111111:role/deploy could not be read" {
		for _, l := range links {
			t.Logf("%s", l.Sentence())
		}
		t.Errorf("FanOut with an unread sibling: %d links", len(links))
	}
	unread.Effect = trust.Deny
	if links, _ := FanOut([]trust.Grant{aws, azure, unread}); len(links) != 1 || links[0].Reason() != denyDoubt {
		t.Errorf("the same statement read as a Deny: %v", links)
	}
}

// TestSharedRecordIsCarriedOnce: one iam:ListRoles response proves every
// role in an account, and a collector attaches it to each role's grant.
// The invariant is that each side has evidence, which the constructor
// checks; a document read once is one record, so a Link between two roles
// proved by one response carries it once. A same-account pair is a pair,
// and the reporter's to fold.
func TestSharedRecordIsCarriedOnce(t *testing.T) {
	shared := evidence.New("iam:ListRoles", `{"account":"111111111111"}`, evidence.StatusOK, []byte(`{"Roles":[]}`), time.Unix(0, 0))
	deploy := trust.Grant{Target: deployRole, Issuer: github, Admits: pinned(eval.Glob("repo:acme/*"), awsAudience), Effect: trust.Allow, Provenance: []evidence.Record{shared}}
	release := deploy
	release.Target = trust.TargetRef{Kind: "role", ID: "arn:aws:iam::111111111111:role/release"}
	release.Admits = pinned(eval.Exact(mainBranch), awsAudience)
	l := mustLink(t, deploy, release)
	if got := l.Provenance(); l.Confidence() != Established || len(got) != 1 || got[0].SHA256 != shared.SHA256 {
		t.Errorf("Confidence() = %s, Provenance() = %v; want Established on the one shared record", l.Confidence(), got)
	}
	want := "Identities admitted by role arn:aws:iam::111111111111:role/deploy are also admitted by role arn:aws:iam::111111111111:role/release: " +
		"both admit identities from https://token.actions.githubusercontent.com with sub repo:acme/infra:ref:refs/heads/main."
	if l.Sentence() != want {
		t.Errorf("Sentence() =\n%s\nwant\n%s", l.Sentence(), want)
	}
}

// TestLinkHoldsItsOwnEvidence: a Link is a fact at the time it was built.
// A collector that reuses its response buffer after handing a grant over,
// or a caller that edits the grant, must not change what the Link renders,
// and a rendered body must always hash to the digest beside it. The
// accessors copy on the way out; this is the way in.
func TestLinkHoldsItsOwnEvidence(t *testing.T) {
	body := []byte(`{"ok":true}`)
	aws := awsGrant(pinned(eval.Glob("repo:acme/*"), awsAudience))
	aws.Provenance = []evidence.Record{evidence.New("iam:GetRole", `{}`, evidence.StatusOK, body, time.Unix(0, 0))}
	azure := azureGrant(pinned(eval.Glob("repo:acme/infra:*"), azureAudience))
	l := mustLink(t, aws, azure)
	links, err := FanOut([]trust.Grant{aws, azure})
	if err != nil || len(links) != 1 {
		t.Fatalf("FanOut: %d links, %v", len(links), err)
	}
	before, beforeFanOut := encode(t, l), encode(t, links[0])
	copy(body, []byte(`{"ok":9999}`))
	copy(aws.Provenance[0].Bytes, []byte(`{"ok":fals}`))
	if after := encode(t, l); !bytes.Equal(before, after) {
		t.Errorf("NewLink kept the caller's bytes:\n%s\n%s", before, after)
	}
	if after := encode(t, links[0]); !bytes.Equal(beforeFanOut, after) {
		t.Errorf("FanOut kept the caller's bytes:\n%s\n%s", beforeFanOut, after)
	}
	if got := l.Provenance()[1].Bytes; string(got) != `{"ok":true}` {
		t.Errorf("Provenance() = %s, want the body as it was when the Link was built", got)
	}
}

// TestGrantRefIdentifiesTheStatement: a role with three statements that
// admit the same set, one exact, one an upper bound, one whose effect could
// not be read, is three grants and three links, and a reader keyed on the
// grants of a Link must be able to tell which statement each is about.
// The reason already says; the reference must too, or a consumer folding
// links by their grants keeps one of the three and loses the other two.
func TestGrantRefIdentifiesTheStatement(t *testing.T) {
	azure := azureGrant(pinned(eval.Glob("repo:acme/infra:*"), azureAudience))
	exact := awsGrant(pinned(eval.Glob("repo:acme/*"), awsAudience))
	bounded := exact
	bounded.Admits = exact.Admits.WithCaveat(eval.Caveat{Claim: "sub", Reason: "operator ForAllValues:StringLike is not modelled", Source: "statement[1].Condition"})
	unread := exact
	unread.Effect = trust.EffectUnknown
	links, err := FanOut([]trust.Grant{azure, exact, bounded, unread})
	if err != nil {
		t.Fatalf("FanOut: %v", err)
	}
	if len(links) != 3 {
		t.Fatalf("%d links, want one per statement", len(links))
	}
	for i, x := range links {
		for _, y := range links[i+1:] {
			if compareRefs(x.Grants()[1], y.Grants()[1]) == 0 {
				t.Errorf("two links about different statements share a grant reference:\n%s\n%s", x.Sentence(), y.Sentence())
			}
		}
	}
	rendered := string(encode(t, links))
	for _, want := range []string{
		`"effect": "Allow"`,
		`"effect": "Unknown"`,
		`"caveats": []`,
		`"caveats": [
          {
            "claim": "sub",
            "reason": "operator ForAllValues:StringLike is not modelled",
            "source": "statement[1].Condition"
          }
        ]`,
	} {
		if !strings.Contains(rendered, want) {
			t.Errorf("the grants of the links do not render %s:\n%s", want, rendered)
		}
	}
}

// TestEvidenceThatIsNotJSONIsCarried: the responses most likely to be
// inconclusive, a throttled or refused call, are the ones most likely to
// carry an HTML page rather than JSON, and a pair whose overlap is real
// must not lose its Link because one record's body cannot be rendered
// verbatim as JSON. The Link exists, says what the call returned, and
// renders the body verbatim in the one encoding JSON carries any bytes in.
func TestEvidenceThatIsNotJSONIsCarried(t *testing.T) {
	aws := awsGrant(pinned(eval.Glob("repo:acme/*"), awsAudience))
	azure := azureGrant(pinned(eval.Glob("repo:acme/infra:*"), azureAudience))
	throttled := evidence.New("graph:federatedIdentityCredentials.list", `{"page":2}`, evidence.StatusThrottled, []byte("<html>429 Too Many Requests</html>"), time.Unix(0, 0))
	azure.Provenance = append(azure.Provenance, throttled)
	links, err := FanOut([]trust.Grant{aws, azure})
	if err != nil || len(links) != 1 {
		t.Fatalf("FanOut: %d links, %v", len(links), err)
	}
	indeterminate(t, links[0], "the call graph:federatedIdentityCredentials.list for application 6b1e6c7e-0f1a-4d2b-9c3d-8e4f5a6b7c8d returned throttled")
	rendered := string(encode(t, links[0]))
	if !strings.Contains(rendered, `"bytes_base64": "PGh0bWw+NDI5IFRvbyBNYW55IFJlcXVlc3RzPC9odG1sPg=="`) || strings.Count(rendered, `"bytes":`) != 2 {
		t.Errorf("the body must render as base64 beside the JSON bodies:\n%s", rendered)
	}
	if !strings.Contains(rendered, `"sha256": "`+throttled.SHA256+`"`) {
		t.Errorf("the digest must render beside the body:\n%s", rendered)
	}
	if got := links[0].Provenance(); len(got) != 3 || string(got[0].Bytes) != "<html>429 Too Many Requests</html>" {
		t.Errorf("Provenance() = %v, want the body verbatim", got)
	}
	// A conclusive record whose body is not JSON, as the AWS query protocol
	// answers, establishes the pair as any conclusive record does.
	azure.Provenance = []evidence.Record{evidence.New("graph:federatedIdentityCredentials.list", `{}`, evidence.StatusOK, []byte("<xml/>"), time.Unix(0, 0))}
	if l := mustLink(t, aws, azure); l.Confidence() != Established || !strings.Contains(string(encode(t, l)), `"bytes_base64": "PHhtbC8+"`) {
		t.Errorf("an XML body on a conclusive record: %s\n%s", l.Sentence(), encode(t, l))
	}
	// No body at all renders neither field, as the record itself does.
	azure.Provenance = []evidence.Record{refused("graph:federatedIdentityCredentials.list", infraApp.ID)}
	if rendered := string(encode(t, mustLink(t, aws, azure))); strings.Contains(rendered, `"bytes_base64"`) || strings.Count(rendered, `"bytes":`) != 1 {
		t.Errorf("an empty body must render no body field:\n%s", rendered)
	}
}

// TestWitnessOmitsAClaimLeftUnevaluated: a claim both sides left Unknown
// survives in the overlap as a constraint that admits everything, and the
// example identity leaves it out rather than filling it with a value no
// issuer mints. An absent claim satisfies only an unconstrained one, so
// omission is exactly the statement "this claim was not what admitted the
// token"; a filled value would be admitted too, and would be a fabrication.
func TestWitnessOmitsAClaimLeftUnevaluated(t *testing.T) {
	notModelled := eval.Caveat{Claim: "sub", Reason: "operator ForAllValues:StringLike is not modelled", Source: "statement[0].Condition"}
	aws := awsGrant(pinned(eval.Unknown("ForAllValues:StringLike"), awsAudience, eval.Term{"repository_id": eval.Exact("456789")}).WithCaveat(notModelled))
	azure := azureGrant(pinned(eval.Unknown("ForAllValues:StringLike"), azureAudience, eval.Term{"repository_id": eval.Exact("456789")}).WithCaveat(notModelled))
	l := mustLink(t, aws, azure)
	if s := l.Subject(); s.Overlap != `{repository_id="456789", sub=?("ForAllValues:StringLike")}` || len(s.Witness) != 1 || s.Witness["repository_id"] != "456789" {
		t.Errorf("Subject() = %+v; want the overlap with sub unevaluated and a witness of repository_id alone", s)
	}
	var rendered struct {
		Subject struct {
			Witness map[string]string `json:"witness"`
		} `json:"subject"`
	}
	if err := json.Unmarshal(encode(t, l), &rendered); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if w := rendered.Subject.Witness; len(w) != 1 || w["repository_id"] != "456789" {
		t.Errorf("the witness renders as %v, want repository_id alone", w)
	}
}
