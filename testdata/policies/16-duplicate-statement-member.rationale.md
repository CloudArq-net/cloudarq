# 16 — the Statement member written twice: a Deny that may not be deployed

Hand-written fixture, 2026-09-13.

## Document

Two `Statement` members at the top level. The first holds an Allow for
the GitHub provider with `aud` pinned; the second holds a Deny for the
same provider with `sub` pinned to the main branch.

## Expected

Two statements, both kept, and a document anomaly of kind `duplicate-key`
on `Statement`. Two grants:

- `AllowInTheFirstCopy`: `{aud="sts.amazonaws.com"}`, inexact: a
  whole-grant caveat and a `duplicate-key` anomaly on `Statement` at
  `statement[0]` whose sentence is
  `the member Statement appears more than once in the document; a JSON decoder keeps one copy and the deployed policy may carry either, so whether this statement is deployed is not known`.
- `DenyInTheSecondCopy`: a Deny that denies nothing, inexact, with the same
  anomaly at `statement[1]` and the Deny-not-applied anomaly.

The main-branch token with `aud` is admitted by the Allow and not
subtracted.

## Why

The grammar page: "Individual elements must not contain multiple instances
of the same key." Which copy a deployed policy carries is therefore stated
nowhere: a decoder that keeps the last deploys only the Deny, one that
keeps the first deploys only the Allow, and one that refuses the document
deploys nothing. The Allow's set is an upper bound on what the statement
admits in deployment, which is what a caveat declares. Applying the Deny
would subtract the main branch from a role whose deployed policy may hold
no such Deny at all, so the Deny is not applied, and the result stays an
upper bound in every reading. Both statements are still in the Document,
because dropping either would be the decoder's silence, reproduced.

## Sources

- https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_grammar.html (fetched 2026-09-13)
- https://www.rfc-editor.org/rfc/rfc8259#section-4
- specs/B2-aws-trust-policy-parser.md §4
