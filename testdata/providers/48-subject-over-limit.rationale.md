# 48 — a subject longer than Google's limit, in the condition

Hand-written fixture, 2026-09-14.

## Document

`assertion.sub == 'repo:acme/infra:xxx…'`, the literal 216 bytes long,
with `google.subject` mapped from `assertion.sub`.

## Expected

`{aud="…/providers/github", sub="repo:acme/infra:xxx…"}`, inexact: a
caveat on `sub` and a `subject-length` anomaly whose Construct is `==`.

## Why

Google: "google.subject: The principal IAM is authenticating. You can
reference this value in IAM bindings. This is also the subject that
appears in Cloud Logging logs. Cannot exceed 127 bytes." The mapping
makes the token's `sub` the subject, so a token the condition admits maps
to a 216-byte subject, which is one Google exchanges no credential for.
The value is kept as written and the set is declared an upper bound rather
than reported as admitting nobody: the limit is Google's documentation,
not a refusal this parser observed, and a set proven empty from a document
alone is the one output the lattice must never produce by mistake. The
limit is counted in bytes, as Google counts it, and a 127-byte subject is
exact. It is applied to values the document writes; a pattern such as
`startsWith('repo:acme/')` also matches subjects longer than the limit,
but so does every pattern, and declaring each inexact for it would fail
the conformance harness on the grants every provider states exactly.

## Sources

- https://docs.cloud.google.com/iam/docs/reference/rest/v1/projects.locations.workloadIdentityPools.providers (attributeMapping, google.subject)
- internal/eval/stringset.go (IsEmpty is true only for proven emptiness)
