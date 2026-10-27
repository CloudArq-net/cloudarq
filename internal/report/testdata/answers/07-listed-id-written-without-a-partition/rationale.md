# 07 — Datadog's digits, written as a bare account id

The policy's principal is `464622532012`, the account id alone.

**Expected.** As the answer was before the list: grant 1 → **outsider**, exact, the account
`464622532012`, with no `listed`, and no vendor in any sentence.

**Why.** The shortened form names an account by its id and writes no partition, and the list
matches an account by its partition and its id together: Datadog's row is `464622532012` in
`aws`, and the same digits in `aws-us-gov` or `aws-cn` are another partition's account (case 06).
The policy alone does not say which partition the role it guards is in, so the engine does not
claim the account is the one Datadog publishes, and names no vendor.

> "When you specify an AWS account, you can use the account ARN (arn:aws:iam::account-ID:root), or
> a shortened form that consists of the "AWS": prefix followed by the account ID." —
> https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html,
> read 27 October 2026
