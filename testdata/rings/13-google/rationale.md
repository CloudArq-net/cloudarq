# 13 — Google as a built-in provider, `aud` pinned

One of the four identity providers AWS builds in: Google.

**Expected.** `GoogleAudience` → **platform** (anyone with a Google account), unknown.

**Why.** Census v0.2.0 records Google's `anonymous_tokens` as `no`, by a chain of Google's sentences: the
two kinds of identity token issued as `https://accounts.google.com` each authenticate a user or a
service account. No claim of Google's is recorded as naming a tenant, so the place is the platform,
unknown.

**The token and the witness.** Census v0.2.0 records the keys AWS documents for Google's tokens, each with
the claim AWS reads it from (census v0.2.0), so the condition is read, and read as AWS reads
it: `aud` from the token's `azp`, or from its `aud` when the token sets no `azp`. A token whose `azp`
is the client is admitted whatever its `aud`; one whose `aud` is the client and whose `azp` is another
is not. The witness carries the client in `aud` and sets no `azp`, and its caption says so. Only
`aud` is named, and an audience is not a boundary, so the grant admits every identity Google issues
a token to, which the ring already says.

> "User ID tokens are JSON Web Tokens (JWTs) that authenticate a user. Clients can obtain a user ID Token by initiating an OIDC authentication flow." — https://cloud.google.com/docs/authentication/token-types · read 2026-09-23
> "Service account ID tokens are JSON Web Tokens (JWTs) that authenticate a service account." — https://cloud.google.com/docs/authentication/token-types · read 2026-09-23
> "An OIDC federated principal can represent an OIDC IDP in your AWS account, or the 4 built in identity providers: Login with Amazon, Google, Facebook, and Amazon Cognito." — https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html · read 2026-09-23
> "GitHub Actions workflows and Google are some examples of IdPs that use the default implementation in their OIDC JWT ID token." — https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_iam-condition-keys.html · read 2026-09-24 (recorded in the census, `aws_condition_keys`)
> "AWS STS condition key IdP JWT claim Available in session amr amr Yes aud azp If no value is set for azp, the aud condition key maps to the aud claim. Yes email email No oaud aud No sub sub Yes" — https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_iam-condition-keys.html · read 2026-09-24 (recorded in the census, `aws_condition_keys`)
