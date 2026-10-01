# 11 — an Amazon Cognito identity pool's guest role

A trap: an identity pool pinned by its id in `aud`, whose guests need no account anywhere.

**Expected.** `IdentityPoolGuests` → **anyone**, unknown.

**Why.** An identity pool issues credentials to guests, who need no account anywhere: a credential
exists, and nobody needs one to get it. Census v0.2.0 records the pool's `anonymous_tokens` as `yes`. The
pool id in `aud` pins the pool, never who can get into it. The place would be exact were `amr` read
as pinning the guest kind, but the parser does not model `ForAnyValue`, so it stays unknown. The
condition on `aud` is read: the census records the keys AWS documents for an identity pool's tokens,
`aud` read from the token's `aud` (census v0.2.0), so the grant's set is an upper bound on
`amr` alone.

> "Amazon Cognito identity pools guest access (unauthenticated identities) provides a unique identifier and AWS credentials for users who do not authenticate with an identity provider." — https://docs.aws.amazon.com/cognito/latest/developerguide/identity-pools.html · read 2026-09-23
> "This is a public API. You do not need any credentials to call this API." — https://docs.aws.amazon.com/cognitoidentity/latest/APIReference/API_GetId.html · read 2026-09-23
> "Remember that unauthenticated identities are assumed by users who do not log in to your app." — https://docs.aws.amazon.com/cognito/latest/developerguide/iam-roles.html · read 2026-09-23
> "If the user is unauthenticated, the key contains only `unauthenticated`." — https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_iam-condition-keys.html (`cognito-identity.amazonaws.com:amr`) · read 2026-09-23
> "An OIDC federated principal can represent an OIDC IDP in your AWS account, or the 4 built in identity providers: Login with Amazon, Google, Facebook, and Amazon Cognito." — https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html · read 2026-09-23
