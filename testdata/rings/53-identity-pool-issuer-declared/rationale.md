# 53 — an identity pool whose issuer the user declared

Case 12's document, with `issuer:https://cognito-identity.amazonaws.com` declared, which is what a
user who runs the pool would write.

**Expected.** `IdentityPoolSignedIn` → **anyone**, unknown. The declaration is read, echoed, and
said to move nothing.

**Why.** Declaring never moves a grant out of anyone: anyone says who can obtain a token, and who
runs the issuer does not bound that. The pool is the user's, and it still gives tokens to
guests and to whoever its providers sign in. An `issuer:` declaration names one tenant of a
per-tenant issuer by its URL, and census v0.2.0 records no tenant in Cognito's issuer URL, so no grant
that admits is pinned to it.

> "Remember that unauthenticated identities are assumed by users who do not log in to your app." — https://docs.aws.amazon.com/cognito/latest/developerguide/iam-roles.html · read 2026-09-23
> "If `amr` is `authenticated`, the token includes any providers used during authentication." — https://docs.aws.amazon.com/cognito/latest/developerguide/iam-roles.html · read 2026-09-23
> "Amazon Cognito identity pools guest access (unauthenticated identities) provides a unique identifier and AWS credentials for users who do not authenticate with an identity provider." — https://docs.aws.amazon.com/cognito/latest/developerguide/identity-pools.html · read 2026-09-23
