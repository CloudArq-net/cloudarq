# 21 — a flexible expression under an issuer Microsoft does not list

Hand-written fixture, 2026-09-13.

## Document

`issuer: https://accounts.google.com` with `claims['sub'] eq '112633961854638529490'`.

## Expected

`{aud="api://AzureADTokenExchange", sub=?("undocumented issuer")}`,
inexact, with a caveat on `sub` and an `unmodelled-construct` anomaly whose
Construct is the issuer, `"https://accounts.google.com"`, and whose
sentence quotes the clause.

## Why

Microsoft: "Flexible federated identity credentials support is currently
provided for matching against GitHub, GitLab, and Terraform Cloud issued
tokens." The page's per-issuer tables are the whole of the documented
behaviour, and there is none for any other issuer. Whether Entra evaluates
the clause, ignores it, or refuses the credential is not stated, so every
claim the expression names is Unknown with the fact stated. The table of
documented issuers is Microsoft's, and it is written in the parser,
`documentedLanguage` in `internal/parse/azure/expression.go`, with its
source and date.

## Sources

- https://learn.microsoft.com/en-us/entra/workload-id/workload-identities-flexible-federated-identity-credentials (ms.date 2026-08-14)
