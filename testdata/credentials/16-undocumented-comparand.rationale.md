# 16 — a comparand holding a doubled single quote

Hand-written fixture, 2026-09-13.

## Document

`claims['sub'] eq 'repo:acme/it''s:ref:refs/heads/main' and claims['repository_id'] eq '456789'`.

## Expected

`{aud="api://AzureADTokenExchange", repository_id="456789", sub=?("escaped quote")}`,
inexact, with a caveat on `sub` and an `unmodelled-construct` anomaly with
Construct `escaped quote`.

## Why

The whole of Microsoft's quoting rule is one sentence: "Single quotes are
interpreted as escape characters within the flexible federated identity
credential expression language." It does not say what a doubled quote
produces. The lexer takes the pair as staying inside the comparand only to
find where the clause ends, so that `repository_id` is still read; what the
pair means is not guessed. `Exact("repo:acme/it's:…")` would be a set built on
an assumed escape rule and presented as exact, and if the rule were wrong the
error would be in the narrow direction and undetectable from the document.

## Sources

- https://learn.microsoft.com/en-us/entra/workload-id/workload-identities-flexible-federated-identity-credentials (ms.date 2026-08-14)
