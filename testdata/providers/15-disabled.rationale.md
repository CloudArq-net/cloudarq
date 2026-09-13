# 15 — a disabled provider

Hand-written fixture, 2026-09-13.

## Document

`"disabled": true` beside an exact condition.

## Expected

`{aud="…/providers/github", sub="repo:acme/infra:ref:refs/heads/main"}`,
inexact: a whole-grant caveat and a `provider-disabled` anomaly.

## Why

Google: "Optional. Whether the provider is disabled. You cannot use a
disabled provider to exchange tokens. However, existing tokens still grant
access." The set the condition admits is kept and declared an upper bound,
rather than reported as admitting nobody: existing tokens still grant
access, the flag is one update from false, and a consumer that asks what
the provider admits once re-enabled needs the set. Proven emptiness is the
one output the lattice must never produce by mistake, and a reversible
flag is not a proof. The Pass 1 table read a disabled provider as
`Nothing()` with a caveat; this fixture departs from it, because
`Nothing().WithCaveat(…)` still answers `IsEmpty() == true`, a proven
emptiness on a flag one update from false.

## Sources

- https://docs.cloud.google.com/iam/docs/reference/rest/v1/projects.locations.workloadIdentityPools.providers (disabled)
- internal/eval/stringset.go (IsEmpty: "reporting a dangerous policy as admitting nothing is the worst output this program can produce")
