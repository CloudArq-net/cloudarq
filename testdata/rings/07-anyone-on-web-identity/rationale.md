# 07 — `"*"` on `sts:AssumeRoleWithWebIdentity`, with no condition

A trap: `"*"` on a web-identity action is every issuer's tokens, never only the well-known
providers'.

**Expected.**
- the face with no issuer → **anyone**, unknown: every issuer's tokens.
- the AWS face (`aws:sts`) → **nobody**: an AWS principal assumes a role through `sts:AssumeRole`,
  which the statement does not grant.

**Why.** The parser projects `"*"` as two faces. The face with no issuer admits every web identity
provider's tokens, and among the providers STS takes them from are Amazon Cognito's identity pools,
which issue credentials to guests. That any holder of a Google, Amazon or Facebook account is
admitted is the engine's reading of two AWS sentences, the Principal element's wildcard and its
four built-in providers, never a sentence AWS writes. The face stays `unknown`: the account's own
OIDC providers, and who they serve, are not read.

> "You can use a wildcard (*) to specify all principals in the `Principal` element of a resource-based policy or in condition keys that support principals." — https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html · read 2026-09-23
> "An OIDC federated principal can represent an OIDC IDP in your AWS account, or the 4 built in identity providers: Login with Amazon, Google, Facebook, and Amazon Cognito." — https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html · read 2026-09-23
> "Amazon Cognito identity pools guest access (unauthenticated identities) provides a unique identifier and AWS credentials for users who do not authenticate with an identity provider." — https://docs.aws.amazon.com/cognito/latest/developerguide/identity-pools.html · read 2026-09-23
> "This is a public API. You do not need any credentials to call this API." — https://docs.aws.amazon.com/cognitoidentity/latest/APIReference/API_GetId.html · read 2026-09-23
> "Remember that unauthenticated identities are assumed by users who do not log in to your app." — https://docs.aws.amazon.com/cognito/latest/developerguide/iam-roles.html · read 2026-09-23
