# 09 — `"*"` on `sts:*`

A trap: `"*"` on `sts:*` covers the web-identity action and `sts:AssumeRole` both.

**Expected.**
- the face with no issuer → **anyone**, unknown.
- the AWS face (`aws:sts`) → **platform** (anyone with an AWS account), exact.

**Why.** `sts:*` covers `sts:AssumeRoleWithWebIdentity`, so the face with no issuer admits every
web identity provider's tokens, as in case 07; a wildcard is read as covering it whatever it
matches. It also covers `sts:AssumeRole`, which an AWS principal calls with credentials of its own,
so the AWS face admits every AWS principal: no account is pinned.

> "You can use a wildcard (*) to specify all principals in the `Principal` element of a resource-based policy or in condition keys that support principals." — https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html · read 2026-09-23
> "An OIDC federated principal can represent an OIDC IDP in your AWS account, or the 4 built in identity providers: Login with Amazon, Google, Facebook, and Amazon Cognito." — https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html · read 2026-09-23
> "You must call this API using active credentials." — https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp_request.html (`AssumeRole`) · read 2026-09-23
