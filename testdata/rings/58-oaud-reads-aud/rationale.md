# 58 — GitHub's audience conditioned through `oaud`, which AWS reads from `aud`

A condition key does not always read the claim of its own name. AWS's Default tab, which GitHub's
tokens are read by, fills `oaud` from the token's `aud` claim.

**Expected.** `AudienceByOaud` → **outsider**, exact: the owner `acme`, by name, recyclable, not
declared. The subject pins the owner as it does in case 01; `oaud` names no tenant.

**The token and the witness.** A token whose `aud` is `sts.amazonaws.com` and which carries no
`oaud` claim is admitted: AWS tests the condition on `oaud` against the token's `aud`. A token that
carries an `oaud` claim of `sts.amazonaws.com` beside another `aud` is not, for the same reason. The
witness carries `aud`, and no `oaud` claim, which AWS would not read.

**Why.** The census records each condition key AWS documents for GitHub's tokens with the claim AWS
reads it from (census v0.2.0): `oaud` reads `aud`.

> "GitHub Actions workflows and Google are some examples of IdPs that use the default implementation in their OIDC JWT ID token." — https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_iam-condition-keys.html · read 2026-09-24 (recorded in the census, `aws_condition_keys`)
> "AWS STS condition key IdP JWT claim Available in session amr amr Yes aud azp If no value is set for azp, the aud condition key maps to the aud claim. Yes email email No oaud aud No sub sub Yes" — https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_iam-condition-keys.html · read 2026-09-24 (recorded in the census, `aws_condition_keys`)
