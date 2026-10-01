# 43 — a Spacelift account, whose runs are not shown to be its owner's alone

A per-tenant issuer whose tenant is not shown to control who joins it: Spacelift's
`tenant_membership` is `unverified` in census v0.2.0.

**Expected.** `SpaceliftAccount` → **platform** (anyone on Spacelift), unknown, although the account
`acme` is declared.

**Why.** The issuer URL names the account, and every run in the account holds a token. Who can
cause a run in an account, a pull request from a fork among them, is not established by any
sentence the census read, so the account is not shown to control who obtains its tokens: the grant
is the platform, unknown, and not a named outsider. Declaring moves only a named outsider, so the
declaration of the account moves nothing here.

> "iss: The issuer of the token. This is the URL of your Spacelift account, for example https://demo.app.spacelift.io, and is unique for each Spacelift account." — https://docs.spacelift.io/integrations/cloud-providers/oidc · read 2026-09-23 (recorded in the census, `match`)
> "The token is valid for an hour and is available to every run in any paid Spacelift account." — https://docs.spacelift.io/integrations/cloud-providers/oidc · read 2026-09-23 (recorded in the census as context to `tenant_membership`: which runs hold a token, not who can cause a run)
