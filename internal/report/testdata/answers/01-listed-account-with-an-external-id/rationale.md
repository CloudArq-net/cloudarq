# 01 — an account Datadog publishes, behind an external ID

The policy trusts `arn:aws:iam::464622532012:root` on condition that `sts:ExternalId` is one
value.

**Expected.** Grant 1 → **outsider**, exact: the account `464622532012`, by id, not declared. Its
owner carries `listed`: the vendor `Datadog`, and one use, `AWS integration (role delegation)`,
with its source and the date it was checked. The ring's sentence and the grant's *who* name the
vendor alone: "aws:464622532012, which Datadog publishes as its own, can assume this role and is
not declared as yours." The question stays "Is aws:464622532012 yours?", the headline stays "A
named outsider can assume this role.", and --explain gives, after the principal as written, the
vendor, the use, the page and the date it was checked.

**Why.** `internal/vendors/aws-accounts.json` holds `464622532012` in the partition `aws` as
Datadog's, for AWS integration (role delegation), from
https://raw.githubusercontent.com/DataDog/cloudformation-template/master/aws/datadog_integration_role.yaml,
checked 2026-10-19, and the ARN names that account in that partition. The list names an account;
it moves no ring. Whose account it is says nothing about whether the reader works with Datadog, so
the account is still an outsider until the reader declares it.
