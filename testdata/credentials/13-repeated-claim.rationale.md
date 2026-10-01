# 13 — one claim constrained twice

Hand-written fixture, 2026-09-13.

## Document

`claims['sub'] eq '…main' and claims['sub'] eq '…dev' and claims['repository_id'] eq '456789'`.

## Expected

`{aud="api://AzureADTokenExchange", repository_id="456789", sub=?("repeated claim")}`,
inexact, with a caveat on `sub` and an `unmodelled-construct` anomaly with
Construct `repeated claim`.

## Why

Microsoft documents `and` as the operator "for combining expressions against
multiple claims" and says nothing about naming one claim twice. A Meet of the
two clauses would be the empty set, and the lattice would then drop the Term
and report a credential that admits nobody, exactly and without a caveat: the
worst output this program can produce, on a construct whose meaning is not
documented. If Entra evaluates the conjunction the set is empty; if it applies
either clause the set is not; if it refuses the credential the document cannot
exist. Unknown on the repeated claim covers every case. `repository_id` is
kept: whatever the repeated clauses mean, they are joined to it by `and` and
can only narrow.

## Sources

- https://learn.microsoft.com/en-us/entra/workload-id/workload-identities-flexible-federated-identity-credentials (ms.date 2026-08-14)
- internal/eval/admitted.go: `normaliseTerm` drops a Term with a provably empty claim
