# 14 — Login with Amazon as a built-in provider

One of the four identity providers AWS builds in: Login with Amazon.

**Expected.** `LoginWithAmazonApp` → **platform** (anyone with an Amazon account), unknown.

**Why.** An access token is issued to a person who has logged in, so census v0.2.0 records Login with
Amazon's `anonymous_tokens` as `no`. No tenancy fact is recorded, so the app id pins nothing, and
the place is the platform, unknown.

> "After users log in, they are returned to your website or mobile app. At this point, your client can obtain an access token by calling the Login with Amazon authorization service" — https://developer.amazon.com/docs/login-with-amazon/access-token.html · read 2026-09-23
> "Currently `www.amazon.com` and `graph.facebook.com` are the only supported identity providers for OAuth 2.0 access tokens." — https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRoleWithWebIdentity.html · read 2026-09-23
> "An OIDC federated principal can represent an OIDC IDP in your AWS account, or the 4 built in identity providers: Login with Amazon, Google, Facebook, and Amazon Cognito." — https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html · read 2026-09-23
