# 06 — an account in no AWS Organization

A bundle `cloudarq-collect` writes from an account AWS Organizations says is in no organization:
`organization` is `{"status": "not-a-member"}`. Two roles at `/`:

- `break-glass`, trusting `arn:aws:iam::123456789012:root`, the account read;
- `OrganizationAccountAccessRole`, trusting `arn:aws:iam::111122223333:root`.

**Expected.** The findings write `"organization": {"status": "not-a-member"}` and ask nothing:
`suggested` is empty and every `would_move` is empty. `break-glass` is recognised as yours, as in
case 04. `OrganizationAccountAccessRole` reads *"A named outsider can assume this role."*: with no
Organization, nothing names `111122223333` but the trust policy, and an account nobody declared is
an outsider. The command exits 0 and says nothing on standard error: an account in no Organization
is a whole read.

**Why.** It is its own state, not a refusal and not an Organization unread. AWS answers it with
an error of its own:

> "AWSOrganizationsNotInUseException Your account isn't a member of an organization. To make this
> request, you must use the credentials of an account that belongs to an organization." —
> https://docs.aws.amazon.com/organizations/latest/APIReference/API_DescribeOrganization.html · read 2026-10-03

The accounts, the role IDs and the dates are placeholders in AWS's own example form.
