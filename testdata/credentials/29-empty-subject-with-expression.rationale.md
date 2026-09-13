# 29 — an empty subject string beside an expression

Hand-written fixture, 2026-09-13.

## Document

`"subject": ""` and a `claimsMatchingExpression` of
`claims['sub'] eq '…main' and claims['repository_id'] eq '456789'`.

## Expected

`{aud="api://AzureADTokenExchange", repository_id="456789", sub="repo:acme/infra:ref:refs/heads/main"}`,
exact, with one `empty-subject` anomaly and no caveat.

## Why

Graph says that when `claimsMatchingExpression` is defined, `subject` "must
be `null`", so a document that writes `""` is outside the contract: a
serialiser wrote the empty string for null. The empty string is no subject
(case 18): no documented issuer mints a token whose `sub` is empty, so a
reading under which Entra applied it would admit no real token, and the
expression's reading is what the credential admits. It is not a second
reading, so there is no `subject-and-expression` doubt and no caveat, and
the set is exact; but the member was written, and a member dropped without
a word would be silence, so the fact is recorded for the reporter. The same
fact is recorded when the empty subject stands alone, beside the
`no-subject-constraint` doubt it leaves.

## Sources

- https://learn.microsoft.com/en-us/graph/api/resources/federatedidentitycredential?view=graph-rest-beta, the `subject` property
