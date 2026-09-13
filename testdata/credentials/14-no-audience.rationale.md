# 14 — an empty audience list

Hand-written fixture, 2026-09-13.

## Document

`audiences: []`.

## Expected

`{aud=?("no audience"), sub="repo:acme/infra:ref:refs/heads/main"}`,
inexact, with a caveat on `aud` and an `audience-count` anomaly.

## Why

Graph: audiences is "Required" and "can only accept a single value";
Microsoft: "You must add a single audience value". An empty list cannot have
come from Graph, but a hand-written or generated document can carry one. The
Join of Exacts over an empty list is the empty set, which would drop the Term
and report a credential that admits nobody, exactly. The audience this
credential accepts is not stated, so `aud` is Unknown, declared by a caveat.
The same rule applies to `audiences: null` and to a missing member.

## Sources

- https://learn.microsoft.com/en-us/graph/api/resources/federatedidentitycredential?view=graph-rest-beta
- https://learn.microsoft.com/en-us/entra/workload-id/workload-identity-federation-considerations (updated 2026-06-15)
