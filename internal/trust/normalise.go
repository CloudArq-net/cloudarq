package trust

import (
	"strings"
	"unicode"
)

// Claim returns the canonical key for a claim name as the issuer spells it,
// or false for something that is not a name at all. Which prefix a provider
// wraps around the name, an AWS key's issuer host, GCP's "assertion.", an
// Azure expression's claims['…'], is the parser's knowledge: the parser
// strips its own prefix and hands the bare name over, so adding a provider
// changes nothing here.
//
// Case is kept. Claim names belong to the issuer: GitHub's are lower-case,
// Spacelift's are camelCase, and a key that differs in case names a claim no
// token carries. AWS alone matches condition keys case-insensitively, so the
// AWS parser reconciles a policy's spelling with the issuer's through the
// registry, and records an anomaly when it cannot.
func Claim(name string) (ClaimKey, bool) {
	if name == "" || strings.ContainsFunc(name, unicode.IsSpace) {
		return "", false
	}
	return ClaimKey(name), true
}

// NormaliseIssuer turns any URL form of an issuer into the registry key:
// "https://" + lower-cased host + path, no trailing slash, or false when
// there is no host. The path is part of a per-tenant issuer's identity and
// keeps its case. A provider that names an issuer some other way, as AWS
// does through an OIDC provider ARN, has its parser recover the URL first.
func NormaliseIssuer(raw string) (IssuerRef, bool) {
	s := raw
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	host, path, _ := strings.Cut(s, "/")
	if host == "" {
		return "", false
	}
	path = strings.TrimSuffix(path, "/")
	if path != "" {
		path = "/" + path
	}
	return IssuerRef("https://" + strings.ToLower(host) + path), true
}
