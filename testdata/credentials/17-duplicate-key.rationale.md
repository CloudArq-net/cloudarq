# 17 — the subject member written twice

Hand-written fixture, 2026-09-13.

## Document

`"subject": "…main"` followed by `"subject": "…dev"` in the same object.

## Expected

`{aud="api://AzureADTokenExchange", sub=?("duplicate key")}`, inexact, with
a caveat on `sub` and a `duplicate-key` anomaly whose Construct is `subject`.

## Why

RFC 8259 says object member names "SHOULD be unique" and that software
receiving duplicates behaves unpredictably; Go's decoder keeps the last, the
Terraform AWS provider collapses duplicates before the cloud sees them. Which
value Entra would apply is not stated anywhere. Guessing `dev` reports a
credential as pinned to a branch it may not be pinned to. The member is not
read, the claim is Unknown, and the document keeps both values in `Source`
for quoting back. This is the rule `specs/B2-aws-trust-policy-parser.md` §4
sets for AWS, adopted so the two parsers do not disagree on the same defect;
it is detected by a reader that keeps every member in document order rather
than by a map that would erase the fact.

## Sources

- https://www.rfc-editor.org/rfc/rfc8259#section-4
- specs/B2-aws-trust-policy-parser.md §4
