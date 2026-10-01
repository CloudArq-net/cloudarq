# 25 — an audience that is the empty string

Hand-written fixture, 2026-09-13.

## Document

`audiences: [""]`.

## Expected

`{aud=?("empty audience"), sub="repo:acme/infra:ref:refs/heads/main"}`,
inexact, with a caveat on `aud` and an `unmodelled-construct` anomaly with
Construct `empty audience`.

## Why

Microsoft: the audience "says what Microsoft identity platform must accept
in the `aud` claim in the incoming token", and "You must add a single
audience value". Nothing documents an empty one. No documented issuer mints
a token whose `aud` is empty, so `Exact("")` would report a credential that
admits nobody, on a construct whose meaning is not stated; the same reason
case 18 refuses to read an empty subject as `Exact("")`. The member is
Unknown on `aud`, and because Unknown absorbs under Join, a list holding an
empty string beside a real audience is Unknown too: what Entra does with the
list is not stated, and the union of the real audience with "anything" is
anything.

## Sources

- https://learn.microsoft.com/en-us/entra/workload-id/workload-identity-federation-create-trust (ms.date 2024-12-13, updated 2026-02-26), "Important considerations and restrictions"
- https://learn.microsoft.com/en-us/graph/api/resources/federatedidentitycredential?view=graph-rest-beta
