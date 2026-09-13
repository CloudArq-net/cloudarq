# 42 — a claim spelt with a reserved word

Hand-written fixture, 2026-09-13.

## Document

`assertion.namespace == 'acme' && assertion.sub == 'repo:acme/infra:ref:refs/heads/main'`;
`namespace` is one of CEL's reserved words.

## Expected

`{aud="…/providers/github", namespace="acme", sub="repo:acme/infra:ref:refs/heads/main"}`,
exact.

## Why

The language definition reserves `as break const continue else for
function if import let loop package namespace return var void while` so
that they "cannot be used as identifiers or function names", with the
footnote "Except for receiver-call-style functions, e.g. `a.package()`,
which is permitted"; only `false in null true` are barred from selectors
and field names. cel-go's parser checks its `reservedIds` in `VisitIdent`
and `VisitGlobalCall` alone, with the comment that "they *are* valid field
names for protos", and its grammar lexes the words as `IDENTIFIER`, which
is what may follow a dot. `assertion.namespace` therefore names the claim
`namespace`, exactly as `assertion['namespace']` does, and a parser that
refused it would widen the clause beside it to everything for no reason.

## Sources

- https://github.com/google/cel-spec/blob/master/doc/langdef.md (Syntax, reserved words)
- https://github.com/google/cel-go/blob/v0.32.0/parser/parser.go (`reservedIds`, `VisitIdent`, `VisitSelect`)
- https://github.com/google/cel-go/blob/v0.32.0/parser/gen/CEL.g4 (`member`, `escapeIdent`, `IDENTIFIER`)
