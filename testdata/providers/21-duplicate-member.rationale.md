# 21 — a member written twice

Hand-written fixture, 2026-09-13.

## Document

`"attributeCondition"` written twice with different conditions.

## Expected

`{aud="…/providers/github"}`: everything from the issuer, inexact, with a
whole-grant caveat and a `duplicate-key` anomaly whose Construct is
`attributeCondition`.

## Why

RFC 8259 says object member names "SHOULD be unique" and that software
receiving duplicates behaves unpredictably; Go's decoder keeps the last,
and the Terraform providers collapse duplicates before the cloud sees them.
Which condition Google would apply is not stated anywhere, and guessing
`dev` reports a provider as pinned to a branch it may not be pinned to. The
member is not read, the grant is an upper bound, and the document keeps
both values in `Source`. This is the rule the AWS and Azure parsers apply to
the same defect, spelt with the same kind so that a reporter treats one
defect one way; it needs a reader that keeps every member in document order
rather than a map that would erase the fact.

## Sources

- https://www.rfc-editor.org/rfc/rfc8259#section-4
- internal/parse/azure/credential.go (DuplicateKey)
