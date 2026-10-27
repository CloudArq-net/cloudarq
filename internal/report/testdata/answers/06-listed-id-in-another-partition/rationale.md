# 06 — Datadog's digits in GovCloud

The policy trusts `arn:aws-us-gov:iam::464622532012:root`.

**Expected.** As the answer was before the list: grant 1 → **outsider**, exact, the account
`464622532012`, with no `listed`, and no vendor in any sentence.

**Why.** The ARN's partition is `aws-us-gov`, and the list holds `464622532012` in `aws` alone.
A partition keeps its own IAM, so the account these digits name in `aws-us-gov` is not the one
Datadog's page names in `aws`, and the engine says nothing about whose it is.

> "Partitions have independent instances of AWS Identity and Access Management (IAM) and provide
> a hard boundary between Regions in different partitions." —
> https://docs.aws.amazon.com/whitepapers/latest/aws-fault-isolation-boundaries/partitions.html,
> read 27 October 2026
