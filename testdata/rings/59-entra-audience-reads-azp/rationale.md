# 59 — One client of an Entra work tenant, conditioned through `aud`, which AWS reads from `azp`

AWS's Default tab, which reads every issuer without a tab of its own, Microsoft Entra ID among them,
fills the `aud` condition key from the token's `azp` claim, and from its `aud` claim only when the
token sets no `azp`.

**Expected.** `OneClientOfAWorkTenant` → **platform**, unknown, as the work tenant of case 36: the
census does not record that the tenant's owner controls who holds its tokens. The condition on `aud`
names no tenant, so it moves nothing.

**The token and the witness.** A token whose `azp` is the client `11111111-2222-3333-4444-555555555555`
is admitted whatever its `aud`, and one whose `aud` is that client and whose `azp` is another is not.
The witness carries the client in `aud` and sets no `azp`, which AWS would read in its place, and its
caption says so.

**Why.** The census records the Default tab's keys for Entra with the claim AWS reads each from
(census v0.2.0): `aud` reads `azp`, or `aud` when the token sets no `azp`.

> "Use this mapping if your IdP is not listed in the tab options." — https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_iam-condition-keys.html · read 2026-09-24 (recorded in the census, `aws_condition_keys`)
> "AWS STS condition key IdP JWT claim Available in session amr amr Yes aud azp If no value is set for azp, the aud condition key maps to the aud claim. Yes email email No oaud aud No sub sub Yes" — https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_iam-condition-keys.html · read 2026-09-24 (recorded in the census, `aws_condition_keys`)
