package eval

import "testing"

// TestExcludesNamesTheFailingClaim is the real-world failure the free tool
// exists to explain: a repository rename flipped the subject to the immutable
// format and the policy stopped matching.
func TestExcludesNamesTheFailingClaim(t *testing.T) {
	policy := NewAdmittedSet(Term{
		"aud": Exact("sts.amazonaws.com"),
		"sub": Glob("repo:acme/infra:*"),
	})
	tok := token{
		"aud": "sts.amazonaws.com",
		"sub": "repo:acme/infra@88:ref:refs/heads/main",
	}
	claim, got, ok := policy.Excludes(tok)
	if !ok {
		t.Fatalf("Excludes(%v) says the token is admitted", tok)
	}
	if claim != "sub" {
		t.Errorf("claim = %q, want %q", claim, "sub")
	}
	if got == nil || got.String() != Glob("repo:acme/infra:*").String() {
		t.Errorf("got = %v, want the sub constraint", got)
	}
	// The absent-claim case names the claim too.
	claim, got, ok = policy.Excludes(token{"sub": "repo:acme/infra:ref:refs/heads/main"})
	if !ok || claim != "aud" || got.String() != Exact("sts.amazonaws.com").String() {
		t.Errorf("Excludes on a missing aud = (%q, %v, %v)", claim, got, ok)
	}
}

func TestExcludesPrefersClosestTerm(t *testing.T) {
	far := Term{"b": Exact("1"), "c": Exact("1"), "d": Exact("1")}
	near := Term{"z": Exact("1")}
	tok := token{"a": "x"}
	for _, s := range []AdmittedSet{NewAdmittedSet(far, near), NewAdmittedSet(near, far)} {
		claim, got, ok := s.Excludes(tok)
		if !ok || claim != "z" || got.String() != Exact("1").String() {
			t.Errorf("Excludes = (%q, %v, %v); want the one-failure term's claim z", claim, got, ok)
		}
	}
	// A term that fails on one present-but-wrong claim beats one failing on two absent ones.
	s := NewAdmittedSet(Term{"a": Exact("1"), "b": Exact("1")}, Term{"sub": Exact("y")})
	if claim, _, _ := s.Excludes(token{"sub": "x"}); claim != "sub" {
		t.Errorf("claim = %q, want sub", claim)
	}
}

func TestExcludesIsDeterministic(t *testing.T) {
	tok := token{}
	for i := 0; i < 100; i++ {
		// Built fresh each time so that map initialisation order varies.
		s := NewAdmittedSet(Term{"sub": Exact("x"), "aud": Exact("y"), "iss": Exact("z")})
		claim, got, ok := s.Excludes(tok)
		if !ok || claim != "aud" || got.String() != Exact("y").String() {
			t.Fatalf("run %d: Excludes = (%q, %v, %v); want the smallest failing key aud", i, claim, got, ok)
		}
	}
	// Two terms tied on failure count and on failing key: the term that sorts
	// first by rendering wins, whichever order the set was built in.
	a, b := Term{"sub": Exact("a")}, Term{"sub": Exact("b")}
	for _, s := range []AdmittedSet{NewAdmittedSet(a, b), NewAdmittedSet(b, a), NewAdmittedSet(b).Join(NewAdmittedSet(a))} {
		claim, got, ok := s.Excludes(token{"sub": "z"})
		if !ok || claim != "sub" || got.String() != Exact("a").String() {
			t.Errorf("%s: Excludes = (%q, %v, %v); want the canonical first term's constraint", s, claim, got, ok)
		}
	}
	// Tie on count, different failing keys: the smaller key wins.
	s := NewAdmittedSet(Term{"sub": Exact("a")}, Term{"aud": Exact("b")})
	if claim, _, _ := s.Excludes(token{}); claim != "aud" {
		t.Errorf("claim = %q, want aud", claim)
	}
}

func TestExcludesReturnsFalseWhenAdmitted(t *testing.T) {
	s := NewAdmittedSet(Term{"a": Exact("1"), "b": Exact("1")}, Term{"sub": Exact("x")})
	for _, tok := range []token{{"sub": "x"}, {"a": "1", "b": "1"}, {"sub": "x", "a": "9"}} {
		claim, got, ok := s.Excludes(tok)
		if ok || claim != "" || got != nil {
			t.Errorf("Excludes(%v) = (%q, %v, %v); want (\"\", nil, false)", tok, claim, got, ok)
		}
	}
	if _, _, ok := Everything().Excludes(token{}); ok {
		t.Errorf("Everything excludes nothing")
	}
	if _, _, ok := NewAdmittedSet(Term{"sub": Unknown("r")}).Excludes(token{}); ok {
		t.Errorf("an Unknown constraint excludes nothing")
	}
}

func TestExcludesOnEmptySet(t *testing.T) {
	for _, s := range []AdmittedSet{Nothing(), {}, NewAdmittedSet(Term{"sub": None()})} {
		claim, got, ok := s.Excludes(token{"sub": "x"})
		if !ok || claim != "" || got != nil {
			t.Errorf("%s.Excludes = (%q, %v, %v); want (\"\", nil, true)", s, claim, got, ok)
		}
	}
}
