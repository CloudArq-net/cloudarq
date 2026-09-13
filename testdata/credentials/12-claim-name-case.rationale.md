# 12 — claim names that differ from the documented ones only by case

Hand-written fixture, 2026-09-13.

## Document

`claims['SUB'] eq '…' and claims['REPOSITORY_ID'] eq '456789'`.

## Expected

`{aud="api://AzureADTokenExchange", repository_id="456789", sub="repo:acme/infra:ref:refs/heads/main"}`,
inexact, with a `claim-folded` anomaly and a caveat on each of `sub` and
`repository_id`, the anomaly's Construct being the lookup as written,
`claims['SUB']` and `claims['REPOSITORY_ID']`.

## Why

Microsoft's tables spell the claims `sub`, `job_workflow_ref`,
`repository_id` and `repository_owner_id`, and say nothing about the case of
`<claimName>`. Two things Entra could do: fold case, in which case
`claims['SUB']` is `sub` and the folded reading is exact; or compare exactly,
in which case the clause names a claim no GitHub token carries, Entra admits
nothing, and the folded reading is wider. Folding is therefore never narrower
than Entra. The first design kept the case as written, producing a Term on
`SUB` that rejects every real token; if Entra folds, that reading admits
fewer tokens than Entra, which is the one direction this product must never
err in. The doubt is recorded as a caveat because which of the two Entra does
cannot be known from the document.

## Sources

- https://learn.microsoft.com/en-us/entra/workload-id/workload-identities-flexible-federated-identity-credentials (ms.date 2026-08-14)
- product/CONTEXT.md, test 4: "Over-approximate, always."
