# 06 — IfExists is the same trap with a suffix

Hand-written fixture, 2026-09-13.

## Document

`StringEquals` on `aud`, then `StringEqualsIfExists` on `sub` pinned to the
main branch.

## Expected

`{aud="sts.amazonaws.com", sub=?("StringEqualsIfExists")}`, inexact, with a
caveat on `sub` and an `unmodelled-construct` anomaly naming
`StringEqualsIfExists` whose sentence is
`StringEqualsIfExists on sub passes when the claim is absent, so it does not restrict what it looks like it restricts`.
A token with only `aud` is admitted.

## Why

The operators page on `...IfExists`: "If the key is not present, evaluate
the condition element as true." A request without `sub` passes, so over all
requests the condition restricts nothing. The suffix is parsed off the
operator name rather than matched as a whole, so `StringLikeIfExists`,
`ArnLikeIfExists`, `StringNotEqualsIfExists` and
`ForAllValues:StringEqualsIfExists` all widen the same way. The page also
says "You can add IfExists to the end of any condition operator name except
the Null condition", so `NullIfExists` is not an operator AWS documents and
is Unknown as an unrecognised one.

## Sources

- https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition_operators.html (fetched 2026-09-13)
- specs/B2-aws-trust-policy-parser.md §6
