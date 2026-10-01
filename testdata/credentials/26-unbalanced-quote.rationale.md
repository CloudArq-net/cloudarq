# 26 — a stray single quote

Hand-written fixture, 2026-09-13.

## Document

`claims['sub'] eq 'repo:o'reilly/infra:ref:refs/heads/main' and claims['repository_id'] eq '456789'`:
nine single quotes.

## Expected

`{aud="api://AzureADTokenExchange", sub=?("unparseable expression")}`,
inexact, with a caveat on `sub` and one `unmodelled-construct` anomaly with
Construct `unbalanced quote`.

## Why

Microsoft's grammar encloses every claim name and every comparand in single
quotes and says of quotes only that they "are interpreted as escape
characters". With an odd number of them, where a comparand ends cannot be
read: the lexer would close the comparand at `o`, read `reilly/infra…` as
text after it, and take the next quote as opening a region that swallows
the ` and ` before `repository_id`. Which text ends up in which piece then
depends on which clause the stray quote sits in, so naming a piece would
name a different piece for the same clauses written in another order. The
expression is judged as a whole by its quote count, which no reordering
changes, and nothing it says is modelled; `repository_id` does not survive,
because the clause boundary that would isolate it is exactly what cannot be
read.

## Sources

- https://learn.microsoft.com/en-us/entra/workload-id/workload-identities-flexible-federated-identity-credentials (ms.date 2026-08-14), "Flexible federated identity credential language structure" and "expression language functionality"
