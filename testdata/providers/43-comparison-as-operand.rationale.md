# 43 — a modelled comparison written as an operand

Hand-written fixture, 2026-09-13.

## Document

`assertion.sub == 'repo:acme/infra:ref:refs/heads/main' == true`, which
CEL groups as `(assertion.sub == '…') == true`: `relation` is
left-associative.

## Expected

`{aud="…/providers/github"}` with `sub` Unknown: inexact, a caveat on
`sub`, an `unmodelled-construct` anomaly whose Construct is the operand as
written, `assertion.sub == 'repo:acme/infra:ref:refs/heads/main'`, and
whose sentence says it is a condition written as an operand of `==`, which
the parser models only as a clause of its own.

## Why

The parser models `==` between a claim and a string literal; here the
outer `==` compares a boolean with a boolean, which is outside the subset,
and the set is the top of `sub` (wide, since the whole condition admits
exactly the branch). What the sentence must not say is that `==` is a
construct the parser does not model: it models exactly that, and a reporter
counting anomalies by Construct would count `==`, `in`, `startsWith` and
`contains` as unmodelled. The construct outside the subset is the
comparison's position, so the anomaly names the operand as written and
the outer operator in the sentence.

## Sources

- https://github.com/google/cel-go/blob/v0.32.0/parser/gen/CEL.g4 (`relation`)
