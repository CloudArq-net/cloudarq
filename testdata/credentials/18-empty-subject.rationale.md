# 18 — an empty subject string

Hand-written fixture, 2026-09-13.

## Document

`"subject": ""`, no `claimsMatchingExpression`.

## Expected

`{aud="api://AzureADTokenExchange", sub=?("no subject constraint")}`,
inexact, with two anomalies: `empty-subject`, a fact with no caveat, saying
the subject is the empty string and is read as no subject; and
`no-subject-constraint`, the same doubt as case 06, with the caveat on
`sub`.

## Why

Graph documents `subject` as nullable and says nothing about the empty
string; no documented issuer mints a token whose `sub` is empty. Read as
`Exact("")`, the credential would admit only such tokens, which is a
credential reported as admitting nobody, on a value that a serialiser
writing `""` for `null` could produce. The empty string is therefore no
subject at all, and a fact: the member was written, and a member dropped
without a word would be silence, so `empty-subject` records it wherever it
sits. Standing alone it leaves no subject constraint, the same Unknown as
case 06. Beside an expression it is not a second reading: the expression
stands alone and exact, with no `subject-and-expression` doubt, because a
serialiser that writes `""` for `null` would otherwise turn every ordinary
flexible credential into an inexact one. That is case 29.

## Sources

- https://learn.microsoft.com/en-us/graph/api/resources/federatedidentitycredential?view=graph-rest-beta
