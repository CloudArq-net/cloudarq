# 08 — an Organization that does not hold together: refused

A bundle whose `organization` names `111122223333` as the management account of `o-exampleorgid`,
and gives that account's ARN as `arn:aws:organizations::111122223333:account/o-exampleorgid/444455556666`:
the account at the end of its own ARN is another one.

**Expected.** The whole bundle is refused: exit code 1, no role answered, and the reason on
standard error, naming the ARN given and the one AWS writes,
`arn:aws:organizations::111122223333:account/o-exampleorgid/111122223333`.

**Why.** The management account and the Organization are owners the findings ask the reader about,
so a member whose parts disagree is not as `cloudarq-collect` wrote it, as a stranger's role is
not. AWS writes the management account's ARN from the Organization and the account:

> "MasterAccountArn The Amazon Resource Name (ARN) of the account that is designated as the
> management account for the organization." … "Pattern:
> ^arn:aws:organizations::\d{12}:account\/o-[a-z0-9]{10,32}\/\d{12}" —
> https://docs.aws.amazon.com/organizations/latest/APIReference/API_Organization.html · read 2026-10-03

The accounts, the Organization's ID, the role ID and the dates are placeholders in AWS's own
example form.
