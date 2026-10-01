# 31 — a comparison against something that is not a string literal

Hand-written fixture, 2026-09-13.

## Document

`assertion.repository_id == 456789`, an integer literal.

## Expected

`{aud="…/providers/github"}` with `repository_id` Unknown: inexact, a
caveat on `repository_id`, an `unmodelled-construct` anomaly whose
Construct is `456789`.

## Why

A token claim is a string to the lattice, and CEL defines equality per
type, so which credentials Google would admit depends on the claim's JSON
type in the assertion, which this parser does not know. The
claim is Unknown, and the construct named is the literal as written, so a
reporter can count the conditions that compare against numbers.

## Sources

- https://github.com/google/cel-spec/blob/master/doc/langdef.md (equality is defined per type)
