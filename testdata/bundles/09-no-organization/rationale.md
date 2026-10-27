# 09 — a bundle with no `organization` member: the control

The bundle every `cloudarq-collect` up to 0.2.0 writes: the account's roles and nothing about its
AWS Organization. Two roles, neither on AWS's path and neither trusting the scanned account itself:

- `OrganizationAccountAccessRole` at `/`, trusting `arn:aws:iam::111122223333:root`, the shape AWS
  Organizations gives the role it makes in an account it creates, trusting that Organization's
  management account;
- `deploy` at `/`, trusting GitHub's tokens for `repo:acme/infra:ref:refs/heads/main`.

**Expected.** Exactly what each trust policy answers alone, and nothing said beside it: both
`managed` are `null`. Nothing is declared: `OrganizationAccountAccessRole` reads *"A named
outsider can assume this role."* and asks *"Is aws:111122223333 yours?"*, and `deploy`, which
admits one repository's main branch, reads *"Only tokens whose subject is exactly
repo:acme/infra:ref:refs/heads/main can assume this role."* and asks *"Is github:acme yours?"*.
The findings say the Organization was not read, `"organization": {"status": "not-read"}`, and ask
nothing of it: `suggested` and every `would_move` are empty.

The account the scan read, `123456789012`, is recognised as yours in every bundle, this one too:
the findings' `recognised` names it, and each answer's echo carries it under `recognitions`. No
grant here is pinned to it, so it moves nothing, and each answer is the one `AdmitsFor` gives its
trust policy alone, byte for byte, but for that echo.

**Why.** Nothing in this bundle says which Organization the account is in or which account manages
it, so nothing can be said about `111122223333` but what the trust policy names: an account, not
declared. The engine infers no owner from a bundle that does not carry one, but for the account the
bundle was read from, which the reader's own credentials read.

`OrganizationAccountAccessRole` is a role AWS creates and is not a service-linked one: it sits at
`/`, its trust admits an account, and the account can edit it, so it is never said to be AWS's.

> "When you create an account in your organization, in addition to the root user, AWS
> Organizations automatically creates an IAM role that is by default named
> OrganizationAccountAccessRole." —
> https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_accounts_access.html · read 2026-10-03

**Why it is the control.** When the collector reads the Organization, a bundle carrying it may say
more about these roles; a bundle without it must keep these answers, so no reading of an
Organization can happen without one. A bundle without it is never read as an account in no
Organization either: that is case 06, which AWS answers in words of its own. A test account's `OrganizationAccountAccessRole`, listed on 2026-10-03, has
this trust policy with its own management account in place of `111122223333`.

The accounts `123456789012` and `111122223333`, the role IDs and the dates are placeholders in AWS's
own example form.
