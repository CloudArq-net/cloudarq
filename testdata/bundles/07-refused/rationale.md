# 07 — the Organization refused

A bundle `cloudarq-collect` writes when AWS refuses `organizations:DescribeOrganization`:
`organization` is `{"status": "refused"}`, and `refused` lists the call with AWS's code and words.
The same two roles as case 06.

**Expected.** The findings write `"organization": {"status": "refused"}` and ask nothing, since no
Organization was read to ask about. `break-glass` is recognised as yours all the same: the account
read is yours whatever Organizations answers. `OrganizationAccountAccessRole` reads *"A named
outsider can assume this role."* The command exits 0 and says on standard error what the collector
was refused, in AWS's words, as it says of any refusal.

**Why.** A refusal is not an account in no Organization, and must not read as one: the member says
refused, the refusal is listed beside the others, and a bundle in which the two disagree is refused
whole (`internal/report/findings_test.go`).

The refusal is one DescribeOrganization documents, in the words AWS documents it with:

> "AccessDeniedException You don't have permissions to perform the requested operation." —
> https://docs.aws.amazon.com/organizations/latest/APIReference/API_DescribeOrganization.html · read 2026-10-03

The accounts, the role IDs and the dates are placeholders in AWS's own example form.
