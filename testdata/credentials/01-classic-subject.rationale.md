# 01 — classic subject

Hand-written fixture, 2026-09-13, in the shape of the Graph beta
`federatedIdentityCredential` JSON representation.

## Document

A classic credential: issuer, one subject, one audience.

## Expected

`{aud="api://AzureADTokenExchange", sub="repo:acme/infra:ref:refs/heads/main"}`,
exact, no anomalies. Issuer `https://token.actions.githubusercontent.com`.

## Why

Microsoft: "the *issuer* and *subject* values of the federated identity
credential are checked against the `issuer` and `subject` claims provided in
the external token", and "Wildcard characters aren't supported in any
federated identity credential property value." A classic subject is therefore
one literal value, `Exact`, and so is the audience: "It says what Microsoft
identity platform must accept in the `aud` claim in the incoming token."

## Sources

- https://learn.microsoft.com/en-us/entra/workload-id/workload-identity-federation-considerations (updated 2026-06-15)
- https://learn.microsoft.com/en-us/graph/api/resources/federatedidentitycredential?view=graph-rest-beta
