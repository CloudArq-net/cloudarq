# 27 — an issuer with leading or trailing whitespace

Hand-written fixture, 2026-09-13.

## Document

`"issuer": " https://token.actions.githubusercontent.com"`: the GitHub issuer
with one leading space.

## Expected

Issuer normalised to `https://token.actions.githubusercontent.com`; admits
`{aud="api://AzureADTokenExchange", sub="repo:acme/infra:ref:refs/heads/main"}`
exactly; an `issuer-whitespace` anomaly quoting the value as written; no
caveat.

## Why

Microsoft, on the *issuer* property: "*issuer* is the URL of the external
identity provider and must match the `issuer` claim of the external token
being exchanged. Required. If the `issuer` claim has leading or trailing
whitespace in the value, the token exchange is blocked." A token can match
this credential's issuer as written only by carrying the whitespace itself,
and such a token is blocked; if Entra compares the value as written, the
credential admits no token at all. Whether Entra trims the property before
comparing is not stated. Of the two readings, trusting the issuer with the
whitespace removed is the wider one, so that is the Grant, and the anomaly is
what keeps it from passing as an unqualified trust in GitHub: the reporter
can say the exchange may never succeed. The admitted set is what the document
says about the token's claims and is exact; the issuer is what is in doubt,
and the issuer is not a claim, so no caveat is warranted, exactly as for a
scheme other than https (case 19).

Whitespace is read as Go's `unicode.IsSpace`, wider than ASCII: if Entra
trims less than that, a value trimmed here and not by Entra admits no token,
which the anomaly already says may be so.

## Sources

- https://learn.microsoft.com/en-us/entra/workload-id/workload-identity-federation-considerations (updated 2026-06-15), "General federated identity credential considerations", the *issuer* bullet
- https://learn.microsoft.com/en-us/graph/api/resources/federatedidentitycredential?view=graph-rest-beta
