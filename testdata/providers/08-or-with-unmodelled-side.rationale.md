# 08 — a disjunction with a side this parser does not model

Hand-written fixture, 2026-09-13. This is the first of the three things the
Pass 1 names as most likely to go wrong.

## Document

`assertion.sub == 'repo:acme/infra:ref:refs/heads/main' || assertion.repository_id != '1'`.

## Expected

`{aud="…/providers/github"}`: everything from the issuer, inexact, with a
caveat on `repository_id` and an `unmodelled-construct` anomaly whose
Construct is `!=`.

## Why

Google admits every credential whose `repository_id` is not `1`, which is
almost every credential. The right side is `!=`, which this parser does not
model, so that side is Unknown on `repository_id`: the top of the lattice for
that claim. A Join with a top side is top. A parser that dropped the side it
could not read would answer `{sub="…main"}`, narrower than Google by every
repository but one: the under-approximation this product exists never to
produce. The Unknown is declared by the caveat, so the result cannot pass as
exact.

## Sources

- https://github.com/google/cel-spec/blob/master/doc/langdef.md (`!=`, `||`)
- docs/ENGINEERING.md §3 (Unknown absorbing under Join)
