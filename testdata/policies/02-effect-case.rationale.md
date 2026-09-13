# 02 — Effect spelled "allow"

Hand-written fixture, 2026-09-13.

## Document

`"Effect": "allow"` on an otherwise ordinary GitHub statement with `aud`
and `sub` pinned.

## Expected

`Effect` is `trust.EffectUnknown`, on the statement and on its grant. The
grant is still exact, `{aud="sts.amazonaws.com", sub="repo:acme/infra:ref:refs/heads/main"}`,
and carries one `malformed` anomaly on `Effect` whose sentence is
`Effect is "allow"; AWS accepts exactly "Allow" or "Deny", so the effect is not known and is read as possibly Allow`.

## Why

The grammar's production is `<effect_block> = "Effect" : ("Allow" | "Deny")`,
two literal terminals, and none of the pages read states any case folding
for them. A document spelling the effect any other way is outside the
grammar. Reading it as Deny would report the role as narrower than it is;
reading it as Allow would claim a certainty the grammar does not give. The
model's own contract, `trust.EffectUnknown`, is "a malformed effect the
parser could not read; the evaluator must treat it as possibly Allow", and
the conditions are still evaluated, so the set is exact for that reading.
The same rule covers `"Deny "`, `"ALLOW"`, a boolean, a list, null, a
missing Effect and a duplicated one.

## Sources

- https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_grammar.html (fetched 2026-09-13)
- internal/trust/grant.go, `Effect`
- specs/B2-aws-trust-policy-parser.md §2
