# 29 — operator precedence

Hand-written fixture, 2026-09-13.

## Document

`A && B || C` with no parentheses.

## Expected

`{aud="…/providers/github", repository_id="456789", sub="repo:acme/infra:ref:refs/heads/main"} | {aud="…/providers/github", repository_owner_id="123456"}`,
exact: the Join of (A Meet B) with C.

## Why

CEL's precedence table puts `&&` at 6 and `||` at 7, so `A && B || C` is
`(A && B) || C`. A parser that grouped them the other way would answer
`A && (B || C)`, which requires the subject on the C branch where Google
does not: narrower. The parenthesised spellings of both groupings parse to
their own sets, so the two are told apart by the corpus.

## Sources

- https://github.com/google/cel-spec/blob/master/doc/langdef.md (operator precedence and associativity)
