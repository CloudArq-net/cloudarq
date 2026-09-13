# 23 — a GitHub expression with no immutable claim

Hand-written fixture, 2026-09-13.

## Document

`claims['sub'] matches 'repo:acme/infra:*'` alone, under the GitHub issuer.

## Expected

`{aud="api://AzureADTokenExchange", sub=?("required claim missing")}`,
inexact, with a caveat on `sub` and an `unmodelled-construct` anomaly with
Construct `missing required claim`, whose sentence names the group
`repository_id or repository_owner_id`.

## Why

Microsoft: "GitHub expressions must match `sub` and at least one immutable
claim", and "For GitHub, a flexible federated identity credential must match
the `sub` claim and one or both of the following immutable claims:
`repository_id` … `repository_owner_id` … These claims are required
regardless of whether `sub` uses a name-based, customized, or immutable
format." An expression without one is outside the documented language.
Whether Entra refuses it at creation, applies it as written, or accepts it
and applies nothing of it is not stated; only the last reading is wider than
the pattern, and `Glob("repo:acme/infra:*")` presented as exact would be
narrower than Entra under it. Nothing the expression says survives and `sub`
carries the Unknown, exactly as for an expression outside the grammar.

The cross-provider harness agrees: case `02-one-repo-any-branch`, which is
this very grant, is declared inexpressible for Azure with the reason "a
flexible one must match sub together with an immutable claim".

## Sources

- https://learn.microsoft.com/en-us/entra/workload-id/workload-identities-flexible-federated-identity-credentials (ms.date 2026-08-14), "Issuer URLs, supported claims, and operators by platform", GitHub tab
- internal/trust/conformance.go, `azureNeedsAnImmutableClaim`
