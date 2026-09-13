# 26 — an expression the parser cannot read

Hand-written fixture, 2026-09-13.

## Document

`assertion.sub == 'repo:acme/infra:ref:refs/heads/main' &&`, a dangling
operator.

## Expected

`{aud="…/providers/github"}`: everything from the issuer, inexact, with a
whole-grant caveat and an `unmodelled-construct` anomaly whose Construct is
`unparseable expression`.

## Why

Whether Google's API refuses such a condition at create is not stated on
the pages read; a request body or a hand-edited file can carry one, and a
live document can if the API accepts it. An expression with no parse
has no clauses to attribute, and the piece that was not understood may
have governed every clause that was, so nothing of it is read: the grant is
the whole issuer, declared. The kind is the one the Azure parser gives an
expression outside its grammar, so that a reporter treats one defect one
way; the construct names it. The Pass 1 table named a kind of its own,
`unparseable-condition`; this fixture departs from it so that one defect
has one kind across the parsers.

## Sources

- https://github.com/google/cel-spec/blob/master/doc/langdef.md (ConditionalAnd requires a Relation on each side)
- internal/parse/azure/expression.go (Construct "unparseable clause")
