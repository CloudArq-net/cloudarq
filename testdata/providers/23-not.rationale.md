# 23 — a negated comparison

Hand-written fixture, 2026-09-13.

## Document

`!(assertion.sub == 'repo:acme/infra:ref:refs/heads/main')`.

## Expected

`{aud="…/providers/github"}` with `sub` Unknown: inexact, a caveat on
`sub`, an `unmodelled-construct` anomaly whose Construct is `!`.

## Why

The negation of one comparison on one claim admits every value of that
claim but one, the set case 12 explains has no exact form in the lattice;
the claim is Unknown, named by the operator. `!` binds tighter than `==`,
so the parentheses are what make this a negated comparison: `!assertion.sub
== 'a'` is `(!assertion.sub) == 'a'`, which applies `!` to a string. The
language definition gives logical NOT the one signature `!bool -> bool`,
so the expression has no boolean value on any token; what Google's API
does with such a condition at create is not stated on the pages read, and
the parser reports the expression by its own shape, `!` as an operator on
`sub`, rather than reading it as this case by accident of grammar.

## Sources

- https://github.com/google/cel-spec/blob/master/doc/langdef.md (precedence: `!` at 2, relations at 5; "Logical NOT (!) - Takes a boolean value as input", signature `!bool -> bool`)
