package trust

import (
	"strings"
	"testing"

	"pgregory.net/rapid"
)

// The spec names three properties. Two of them, provider-independence
// (render a random logical grant into each syntax and parse it back) and
// "no parser may narrow", need parsers and renderers that do not exist yet;
// they are the contract each parser unit fulfils through Check. This file
// holds the one that needs neither: claim normalisation is injective, which
// with the issuer's spelling kept means it never merges two names, whatever
// their case.

// genClaimName draws a claim name of the shapes issuers use, mixed case
// included.
func genClaimName() *rapid.Generator[string] {
	return rapid.StringOfN(rapid.RuneFrom([]rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_0123456789.:/-")), 1, 24, -1)
}

// genHost draws an issuer host: at least one dot, never a slash.
func genHost() *rapid.Generator[string] {
	return rapid.Custom(func(t *rapid.T) string {
		labels := rapid.SliceOfN(rapid.StringOfN(rapid.RuneFrom([]rune("abcdefghijklmnopqrstuvwxyz0123456789-")), 1, 12, -1), 2, 4).Draw(t, "labels")
		return strings.Join(labels, ".")
	})
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

func TestClaimIsInjective(t *testing.T) {
	exercised := 0
	rapid.Check(t, func(t *rapid.T) {
		a := genClaimName().Draw(t, "a")
		b := a
		if rapid.Bool().Draw(t, "recase") {
			b = recase(t, a)
		} else {
			b = genClaimName().Draw(t, "b")
		}
		if a != b {
			exercised++
		}
		ka, oka := Claim(a)
		kb, okb := Claim(b)
		if !oka || !okb {
			t.Fatalf("a well-formed name was refused: %q -> %v, %q -> %v", a, oka, b, okb)
		}
		if (a == b) != (ka == kb) {
			t.Fatalf("names %q and %q map to %q and %q", a, b, ka, kb)
		}
	})
	if exercised == 0 {
		t.Fatalf("every pair was identical; the property was never exercised")
	}
	t.Logf("exercised on %d distinct pairs", exercised)
}

func TestNormaliseIssuerIsIdempotentAndCaseInsensitiveOnTheHost(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		host := genHost().Draw(t, "host")
		path := rapid.SampledFrom([]string{"", "/org/2c3f7a0e", "/ng/api/oidc/account/AbC123"}).Draw(t, "path")
		raw := rapid.SampledFrom([]string{"", "https://", "http://", "HTTPS://"}).Draw(t, "scheme") + recase(t, host) + path
		if rapid.Bool().Draw(t, "slash") {
			raw += "/"
		}
		want := IssuerRef("https://" + host + path)
		got, ok := NormaliseIssuer(raw)
		if !ok || got != want {
			t.Fatalf("NormaliseIssuer(%q) = (%q, %v), want %q", raw, got, ok, want)
		}
		if again, ok := NormaliseIssuer(string(want)); !ok || again != want {
			t.Fatalf("NormaliseIssuer is not idempotent: %q -> %q", want, again)
		}
	})
}
