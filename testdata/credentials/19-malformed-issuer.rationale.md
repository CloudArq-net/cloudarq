# 19 — an issuer that is not an https URL

Hand-written fixture, 2026-09-13.

## Document

`"issuer": "http://token.actions.githubusercontent.com"`.

## Expected

Issuer normalised to `https://token.actions.githubusercontent.com`; admits
`{aud="api://AzureADTokenExchange", sub="repo:acme/infra:ref:refs/heads/main"}`
exactly; an `issuer-scheme` anomaly quoting the value as written; no caveat.

## Why

`trust.NormaliseIssuer` rewrites any scheme to `https://` so that the
registry key is one string per issuer, and in doing so loses the fact that
the document said `http://`. Graph: the issuer "must match the `issuer` claim
of the external token being exchanged"; GitHub's token states its `iss` as
`https://token.actions.githubusercontent.com`, as do the other documented
issuers. A credential written with another scheme may therefore never match a
token, which is a fact the reporter needs and the normalised key cannot
carry. The admitted set is what the document says about the token's claims
and is exact; the anomaly carries the raw value.

## Sources

- https://learn.microsoft.com/en-us/graph/api/resources/federatedidentitycredential?view=graph-rest-beta
- https://docs.github.com/en/actions/security-for-github-actions/security-hardening-your-deployments/about-security-hardening-with-openid-connect (example token: `"iss": "https://token.actions.githubusercontent.com"`)
- internal/trust/normalise.go
