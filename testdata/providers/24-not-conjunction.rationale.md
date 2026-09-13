# 24 — a negated conjunction

Hand-written fixture, 2026-09-13.

## Document

`!(assertion.sub == '…main' && assertion.repository_id == '456789')`.

## Expected

`{aud="…/providers/github"}`: everything from the issuer, inexact, with a
whole-grant caveat and an `unmodelled-construct` anomaly whose Construct is
`!`.

## Why

`!(A && B)` admits every credential that fails A or fails B: almost every
credential, and one that no single claim's Unknown describes, since a token
with the right subject and the wrong repository passes. A `!` over anything
but a single comparison on one claim therefore makes its whole operand top,
declared on the whole grant, so that a reader is not told the doubt sits on
one claim when it sits on the expression.

## Sources

- https://github.com/google/cel-spec/blob/master/doc/langdef.md (`!`, `&&`)
