# 34 — an AWS account as the principal

An AWS account as the principal pins that account.

**Expected.** `PartnerAccount` → **outsider**, exact: the account `111122223333`, by id, not
declared.

**Why.** An account's root ARN names every principal of that account, so the grant pins the account
claim to one exact value, and an account id is never reused. The user declares it as
`aws:111122223333`.

> "Use this key to compare the account to which the requesting principal belongs with the account identifier that you specify in the policy." — https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html (`aws:PrincipalAccount`) · read 2026-09-23
> "A 12-digit number, such as 012345678901, that uniquely identifies an AWS account." — https://docs.aws.amazon.com/accounts/latest/reference/manage-acct-identifiers.html · read 2026-09-23
