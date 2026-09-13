# 17 — an operator block with no keys is outside the grammar

Hand-written fixture, 2026-09-13.

## Document

`EmptyStringEqualsBesideAnAudience` matches `sub` against `repo:acme/*`
and has an empty `StringEquals` block beside it.
`EmptyUnrecognisedOperator` has only an empty `ArnLike` block.
`DenyWithAnEmptyBlock` is a Deny with only an empty `StringEqualsIfExists`
block.

## Expected

Three grants for the GitHub issuer.

- `EmptyStringEqualsBesideAnAudience`: `{sub=like:"repo:acme/*"}`, inexact,
  with a whole-grant caveat and a `malformed` anomaly on `StringEquals`
  whose sentence is
  `the operator block StringEquals lists no keys; the IAM grammar requires at least one, so what it requires is not known`.
- `EmptyUnrecognisedOperator`: everything, inexact, the same anomaly on
  `ArnLike`.
- `DenyWithAnEmptyBlock`: a Deny that denies nothing, inexact, with the
  anomaly on `StringEqualsIfExists` and the Deny-not-applied anomaly.

## Why

The grammar's production is
`<condition_type_string> : { <condition_key_string> : <condition_value_list> }`:
an operator block holds at least one key. A block with none is a document
the grammar does not describe, and none of the pages read says how IAM
evaluates one. If IAM reads it as no constraint, the other blocks decide
and the set above is the answer; if IAM reads it as never matched, the
statement admits nothing; if IAM refuses the document, nothing deploys.
The set the other blocks give is a superset of every reading, so it is
kept and declared an upper bound rather than widened to everything, and
the anomaly names the block. Reporting the grant as exact, as an earlier
draft did, claimed knowledge of a construct outside the grammar; under a
Deny it applied a Deny the parser could not read, which is the direction
the Deny rule forbids, so the Deny is not applied.

## Sources

- https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_grammar.html (fetched 2026-09-13)
- specs/B2-aws-trust-policy-parser.md §9
