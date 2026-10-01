# 12 — an Amazon Cognito identity pool's signed-in role

A trap: an identity pool's signed-in identities are whoever its providers let sign in.

**Expected.** `IdentityPoolSignedIn` → **anyone**, unknown.

**Why.** `amr` `authenticated` says a person signed in through one of the pool's providers, and a
pool's providers can be public ones, so the signed-in population is whoever those providers let in.
It is never *yours* on the pool id. It stays at anyone, unknown, however `amr` is read: the pool's
providers and its sign-up setting decide who signs in, and neither is read from the policy.

> "If `amr` is `authenticated`, the token includes any providers used during authentication." — https://docs.aws.amazon.com/cognito/latest/developerguide/iam-roles.html · read 2026-09-23
> "Amazon Cognito identity pools guest access (unauthenticated identities) provides a unique identifier and AWS credentials for users who do not authenticate with an identity provider." — https://docs.aws.amazon.com/cognito/latest/developerguide/identity-pools.html · read 2026-09-23
> "This is a public API. You do not need any credentials to call this API." — https://docs.aws.amazon.com/cognitoidentity/latest/APIReference/API_GetId.html · read 2026-09-23
> "Remember that unauthenticated identities are assumed by users who do not log in to your app." — https://docs.aws.amazon.com/cognito/latest/developerguide/iam-roles.html · read 2026-09-23
