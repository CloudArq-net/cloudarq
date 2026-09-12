package trust

import (
	"testing"

	"github.com/CloudArq-net/cloudarq/internal/eval"
)

var notModelled = eval.Caveat{Claim: "sub", Reason: "operator ForAllValues:StringLike is not modelled", Source: "statement[0].Condition"}

func TestAudienceIsTheAudClaimProjected(t *testing.T) {
	g := Grant{Admits: eval.NewAdmittedSet(
		eval.Term{"sub": eval.Exact("repo:acme/infra:ref:refs/heads/main"), "aud": eval.Exact("sts.amazonaws.com")},
		eval.Term{"sub": eval.Glob("repo:acme/tools:*"), "aud": eval.Exact("sts.amazonaws.com")},
	)}
	audience := g.Audience()
	if !audience.Admits(token{"aud": "sts.amazonaws.com"}) || audience.Admits(token{"aud": "other"}) {
		t.Errorf("Audience() = %s, want exactly aud=sts.amazonaws.com", audience)
	}
	if audience.Admits(token{"sub": "anything"}) {
		t.Errorf("Audience() must still require the audience: %s", audience)
	}
	// A grant that never mentions aud accepts any audience.
	if got := (Grant{Admits: eval.NewAdmittedSet(eval.Term{"sub": eval.Exact("x")})}).Audience(); !got.IsTop() {
		t.Errorf("Audience() of a grant without aud = %s, want everything", got)
	}
	if got := (Grant{}).Audience(); !got.IsEmpty() {
		t.Errorf("Audience() of a grant admitting nothing = %s, want nothing", got)
	}
}

func TestWithoutAudienceDropsOnlyAud(t *testing.T) {
	g := Grant{Admits: eval.NewAdmittedSet(
		eval.Term{"sub": eval.Exact("a"), "aud": eval.Exact("x")},
		eval.Term{"sub": eval.Exact("b"), "aud": eval.Exact("y"), "ref": eval.Exact("main")},
	)}
	got := g.WithoutAudience()
	if !got.Admits(token{"sub": "a"}) || !got.Admits(token{"sub": "b", "ref": "main"}) {
		t.Errorf("WithoutAudience() = %s rejects tokens the grant admits with any audience", got)
	}
	if got.Admits(token{"sub": "b"}) {
		t.Errorf("WithoutAudience() = %s dropped a constraint other than aud", got)
	}
	if !g.Admits.Admits(token{"sub": "a", "aud": "x"}) || g.Admits.Admits(token{"sub": "a"}) {
		t.Errorf("WithoutAudience() must not change the grant it was called on")
	}
}

// TestProjectionsCarryCaveats: the reporter reads Audience(); an inexact
// grant must not project to a clean-looking one.
func TestProjectionsCarryCaveats(t *testing.T) {
	g := Grant{Admits: eval.NewAdmittedSet(eval.Term{"sub": eval.Unknown("r"), "aud": eval.Exact("x")}).WithCaveat(notModelled)}
	for name, got := range map[string]eval.AdmittedSet{"Audience": g.Audience(), "WithoutAudience": g.WithoutAudience()} {
		if got.Exact() || len(got.Caveats()) != 1 || got.Caveats()[0] != notModelled {
			t.Errorf("%s() = %s dropped the caveat; got %v", name, got, got.Caveats())
		}
	}
}

func TestExactFollowsTheAdmittedSet(t *testing.T) {
	exact := Grant{Admits: eval.NewAdmittedSet(eval.Term{"sub": eval.Exact("x")})}
	if !exact.Exact() {
		t.Errorf("a grant with a caveat-free set is exact")
	}
	if (Grant{Admits: exact.Admits.WithCaveat(notModelled)}).Exact() {
		t.Errorf("a grant with a caveat is not exact")
	}
	// An anomaly alone is a fact about the document, not about admission.
	noted := Grant{Admits: exact.Admits, Anomalies: []Anomaly{{Kind: "duplicate-statement-id", Message: "two statements share the Sid deploy"}}}
	if !noted.Exact() {
		t.Errorf("an anomaly that does not touch admission leaves the grant exact")
	}
}
