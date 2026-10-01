# 40 — `aws:PrincipalArn` patterns under `{"AWS": "*"}`

An ARN pins its account when the prefix runs through the colon that closes it.

**Expected.**
- `RolesOfOneAccount` on `aws:sts` → **outsider**, exact: the account `111122223333`.
- `AccountNotClosed` on `aws:sts` → **platform** (anyone with an AWS account), exact.
- each statement's face with no issuer → **cloud services**, unknown.

**Why.** An ARN carries the account in its fifth field. `arn:aws:iam::111122223333:role/*` runs
through that field and the colon after it, so every principal it admits is in that account.
`arn:aws:iam::11112222333*` stops inside the field: `111122223333` and `111122223334` both begin
with it, so it names no account.

> "The ID of the AWS account that owns the resource, without the hyphens." — https://docs.aws.amazon.com/IAM/latest/UserGuide/reference-arns.html · read 2026-09-23
> "Use this key to compare the Amazon Resource Name (ARN) of the principal that made the request with the ARN that you specify in the policy." — https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html (`aws:PrincipalArn`) · read 2026-09-23
