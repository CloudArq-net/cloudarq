# 07 — an operator the language does not have: or

Hand-written fixture, 2026-09-13.

## Document

`claims['sub'] eq '…main' or claims['sub'] eq '…dev'`.

## Expected

`{aud="api://AzureADTokenExchange", sub=?("unparseable expression")}`,
inexact, with a caveat on `sub` and one `unmodelled-construct` anomaly with
Construct `unparseable clause`, whose sentence quotes the whole clause.

## Why

Microsoft's operator table lists `matches`, `eq` and `and`, and the grammar
joins clauses with `and` only. Text containing `or` is outside the language:
the lexer splits on `and` and finds one piece that is not
`claims['<name>'] <operator> '<comparand>'`. Nothing from such an expression
survives, because the operator that was not understood may govern the meaning
of every clause around it: keeping `sub = main` from the first half would
reject `dev`, which the disjunction admits. `sub` carries the Unknown because
every documented expression must match `sub`, so a whole-expression Unknown
has a claim to live on.

## Sources

- https://learn.microsoft.com/en-us/entra/workload-id/workload-identities-flexible-federated-identity-credentials (ms.date 2026-08-14)
