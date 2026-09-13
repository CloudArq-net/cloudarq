# 08 — text that is not an expression

Hand-written fixture, 2026-09-13.

## Document

`claims[sub] == 'repo:acme/infra:ref:refs/heads/main'`: no quotes around the
claim name, `==` for an operator.

## Expected

`{aud="api://AzureADTokenExchange", sub=?("unparseable expression")}`,
inexact, with a caveat on `sub` and one `unmodelled-construct` anomaly with
Construct `unparseable clause`, whose sentence quotes the clause.

## Why

Microsoft's grammar: "The claim lookup must follow the pattern of
`claims['<claimName>']`", "The operator portion must be just the operator
name, separated from the claim lookup and comparand by a single space", and
the comparand "must be contained within single quotes". The grammar here is
strict on every one of those: a document outside it has no documented
meaning, and reading it leniently could read a construct Entra means
differently. The subject constraint is therefore Unknown, with the text quoted
back so the customer can see what is outside the language.

## Sources

- https://learn.microsoft.com/en-us/entra/workload-id/workload-identities-flexible-federated-identity-credentials (ms.date 2026-08-14)
