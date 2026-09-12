package eval

import "testing"

// evilSubject is a GitHub OIDC subject for an organisation an attacker can
// register. "acme-evil" shares the prefix "acme" with the intended org, so the
// only thing standing between it and a trust policy is whether the glob stops
// at the delimiter.
const evilSubject = "repo:acme-evil/takeover:ref:refs/heads/main"

// goodSubject is a subject the policy author intended to admit.
const goodSubject = "repo:acme/app:ref:refs/heads/main"

func TestGlobStarCrossesDelimiters(t *testing.T) {
	cases := []struct {
		pattern, value string
		want           bool
	}{
		// One character apart. The first admits the attacker's org.
		{"repo:acme*", evilSubject, true},
		{"repo:acme/*", evilSubject, false},
		// Both admit what the author meant.
		{"repo:acme*", goodSubject, true},
		{"repo:acme/*", goodSubject, true},
		// A star in the middle crosses ":" and "/" just the same.
		{"repo:*:ref:refs/heads/main", evilSubject, true},
		{"repo:*:ref:refs/heads/main", goodSubject, true},
	}
	for _, c := range cases {
		if got := Glob(c.pattern).Contains(c.value); got != c.want {
			t.Errorf("Glob(%q).Contains(%q) = %v, want %v", c.pattern, c.value, got, c.want)
		}
	}
}

func TestGlobRegexMetacharactersAreLiteral(t *testing.T) {
	// Every pattern matches itself and nothing a regex engine would also
	// accept. A naive "replace * with .*" implementation fails each row.
	cases := []struct {
		pattern string
		reject  []string
	}{
		{"a.c", []string{"abc", "ac", "a.cc"}},
		{"a+c", []string{"ac", "aac", "aaac"}},
		{"(a)", []string{"a", ""}},
		{"[a]", []string{"a", "[b]"}},
		{"a|b", []string{"a", "b", ""}},
		{`a\c`, []string{"ac", "a\\\\c"}},
		{"^a", []string{"a"}},
		{"a$", []string{"a"}},
		{".*", []string{"", "abc", "a.b"}},
		// StringLike has no escape mechanism: the backslash is a literal and
		// the star is still a wildcard.
		{`\*`, []string{"*", "x", ""}},
	}
	for _, c := range cases {
		g := Glob(c.pattern)
		if !g.Contains(c.pattern) {
			t.Errorf("Glob(%q) must match itself", c.pattern)
		}
		for _, v := range c.reject {
			if g.Contains(v) {
				t.Errorf("Glob(%q).Contains(%q) = true; the pattern must be literal", c.pattern, v)
			}
		}
	}
	// Literal metacharacters mixed with a real wildcard.
	if !Glob("a.*").Contains("a.b/c") || Glob("a.*").Contains("abc") {
		t.Errorf(`Glob("a.*") must match "a.b/c" and reject "abc"`)
	}
}

func TestGlobQuestionMarkIsExactlyOne(t *testing.T) {
	g := Glob("a?c")
	for _, v := range []string{"abc", "a/c", "a:c", "a*c", "a?c", "aéc"} {
		if !g.Contains(v) {
			t.Errorf("Glob(%q).Contains(%q) = false, want true", "a?c", v)
		}
	}
	for _, v := range []string{"ac", "abbc", "abcd", "xabc"} {
		if g.Contains(v) {
			t.Errorf("Glob(%q).Contains(%q) = true, want false", "a?c", v)
		}
	}
	// "?" is one character, not one byte: a two-byte rune fills it, and a
	// second "?" is then unfilled.
	if Glob("a??c").Contains("aéc") {
		t.Errorf(`Glob("a??c") must not match "aéc"; "?" is one character`)
	}
	// "?" is not optional.
	if Glob("?").Contains("") {
		t.Errorf(`Glob("?") must not match ""`)
	}
}

func TestGlobIsAnchored(t *testing.T) {
	cases := []struct {
		pattern, value string
	}{
		{"abc", "xabcx"},
		{"abc", "abcx"},
		{"abc", "xabc"},
		{"ab*", "xab"},
		{"*bc", "abcx"},
		{"a*c", "xac"},
		{"a*c", "acx"},
	}
	for _, c := range cases {
		if Glob(c.pattern).Contains(c.value) {
			t.Errorf("Glob(%q).Contains(%q) = true; the match must be anchored", c.pattern, c.value)
		}
	}
}

func TestGlobIsCaseSensitive(t *testing.T) {
	cases := []struct {
		pattern, value string
	}{
		{"Repo:X", "repo:x"},
		{"repo:x", "Repo:X"},
		{"Repo:*", "repo:x"},
		{"Repo:?", "repo:x"},
	}
	for _, c := range cases {
		if Glob(c.pattern).Contains(c.value) {
			t.Errorf("Glob(%q).Contains(%q) = true; values are case-sensitive", c.pattern, c.value)
		}
	}
	if !Glob("Repo:*").Contains("Repo:x") {
		t.Errorf(`Glob("Repo:*") must still match "Repo:x"`)
	}
}

func TestGlobEmptyPattern(t *testing.T) {
	g := Glob("")
	if !g.Contains("") {
		t.Errorf(`Glob("") must match ""`)
	}
	for _, v := range []string{"a", " ", "*"} {
		if g.Contains(v) {
			t.Errorf(`Glob("").Contains(%q) = true, want false`, v)
		}
	}
	if !Glob("*").Contains("") {
		t.Errorf(`Glob("*") must match ""`)
	}
}

func TestGlobNormalisation(t *testing.T) {
	for _, p := range []string{"*", "**", "***"} {
		if !Glob(p).IsTop() {
			t.Errorf("Glob(%q).IsTop() = false, want true", p)
		}
	}
	for _, p := range []string{"?", "*?*", "a*", ""} {
		if Glob(p).IsTop() {
			t.Errorf("Glob(%q).IsTop() = true, want false", p)
		}
	}

	g, e := Glob("abc"), Exact("abc")
	for _, v := range []string{"abc", "abcd", "ab", "", "ABC", "xabc"} {
		if g.Contains(v) != e.Contains(v) {
			t.Errorf("Glob(%q).Contains(%q) = %v, Exact disagrees", "abc", v, g.Contains(v))
		}
	}
	if g.String() != e.String() {
		t.Errorf("Glob(%q).String() = %q, Exact(%q).String() = %q", "abc", g.String(), "abc", e.String())
	}
	if g.IsEmpty() != e.IsEmpty() || g.IsTop() != e.IsTop() {
		t.Errorf("Glob(%q) and Exact(%q) disagree on IsEmpty/IsTop", "abc", "abc")
	}
}

// TestGlobStarPlacement pins the search for segments between stars: a
// segment must be found after the previous one, and in order.
func TestGlobStarPlacement(t *testing.T) {
	cases := []struct {
		pattern, value string
		want           bool
	}{
		{"*a*", "bab", true},
		{"*a*", "bbb", false},
		{"*a*b*", "ab", true},
		{"*a*b*", "ba", false},
		{"*a*b*", "xaxbx", true},
		{"a**b", "ab", true},
		{"a**b", "axxb", true},
		{"ab*ba", "aba", false},
		{"ab*ba", "abba", true},
		{"a*a", "a", false},
		{"a*", "a", true},
		{"*a?*", "xa", false},
		{"*a?*", "xab", true},
	}
	for _, c := range cases {
		if got := Glob(c.pattern).Contains(c.value); got != c.want {
			t.Errorf("Glob(%q).Contains(%q) = %v, want %v", c.pattern, c.value, got, c.want)
		}
	}
}
