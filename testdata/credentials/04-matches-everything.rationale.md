# 04 — matches '*'

Hand-written fixture, 2026-09-13.

## Document

`claims['sub'] matches '*' and claims['repository_id'] eq '456789'`.

## Expected

`{aud="api://AzureADTokenExchange", repository_id="456789"}`, exact, with one
anomaly of kind `undocumented-acceptance` on `sub`, whose Construct is the
pattern as written, `*`, and no caveat.

## Why

`*` matches every value, so the clause constrains nothing and the lattice
drops it; the credential is pinned by `repository_id` alone. Microsoft says a
GitHub expression "must match the `sub` claim and one or both of the
following immutable claims" and does not say whether a pattern that matches
everything is accepted. If Entra accepted the credential, the clause admits
every subject; if Entra refused it, the document could not have come from
Graph. Neither reading is narrower than the set here, so the set is exact and
the uncertainty is a fact for the reporter, not a caveat.

This reverses `specs/NEXT-PROMPT.md`, which asked for Unknown here. The
committed harness case `05-repository-id` judges Azure with `Relation Equal`,
which refuses any caveat, so the two instructions contradict each other and
the harness, being code, wins; the conflict is reported to Product.

## Sources

- https://learn.microsoft.com/en-us/entra/workload-id/workload-identities-flexible-federated-identity-credentials (ms.date 2026-08-14)
- internal/trust/conformance.go, case 05
