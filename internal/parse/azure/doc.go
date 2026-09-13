// Package azure reads Microsoft Entra federated identity credentials, the
// documents by which an application or a user-assigned managed identity
// trusts tokens from an outside issuer, into provider-neutral trust.Grants.
// An application's credentials come from Microsoft Graph as credential
// objects; a managed identity's come from Azure Resource Manager as
// resources whose properties hold the credential. The parser reads both, a
// single one or the value collection either API lists them in, so that a
// collector hands over the response body as received.
//
// It exists because the credential is not the exact-match triple the build
// order called it. A classic credential is one: issuer, subject and
// audience, compared verbatim. A flexible credential, in preview and
// documented by Microsoft on 2026-08-14, replaces the subject with an
// expression language of eq, matches and and, with the same two wildcards
// as AWS StringLike, up to four claims per issuer, and for GitHub a rule
// that an expression must match sub and an immutable claim. A parser that
// read only the triple would be silently wrong on every flexible credential
// a customer has, so this one reads both, and everything the documented
// language does not cover, an operator, a claim, a quoting, a shape,
// becomes Unknown with a caveat and an anomaly rather than a guessed set.
//
// Two assumptions Microsoft's pages do not settle, stated with the
// direction each errs in. First, the wildcard in matches: * is taken to
// cross / and :, as AWS's does, so repo:acme/* admits repo:acme/infra:ref:
// refs/heads/main; if Entra's * stopped at a separator, the sets here would
// admit more than Entra, which is the safe direction. Second, case: eq,
// matches and the classic subject are taken to compare case-sensitively; if
// Entra folded case, the sets here would admit less than Entra, the unsafe
// direction, and no documented sentence says which, so the assumption is
// written here rather than hidden in a matcher.
//
// The list of issuers, claims and operators Microsoft documents lives in
// expression.go with its source and date. It is Microsoft's knowledge about
// Entra, not the issuer's about its tokens, and it moves to the registry as
// data when the registry gains an Azure section.
//
// The package is pure: no IO, no clock, no randomness, enforced by
// test/arch. It is total over arbitrary bytes and linear in their length:
// the two lists a document may inflate without limit, audiences and the
// clauses of an expression, are read up to a cap, past which the claim they
// constrain is Unknown with the count stated, never a truncation. Graph
// must be read at /beta, because v1.0 omits claimsMatchingExpression and a
// flexible credential read there looks like one with no subject; the
// parser reports that shape as an unknown subject constraint, never as an
// unconstrained credential.
package azure
