# 61 — an AWS account one digit from the one declared

A trap: the user declared `aws:111122223333`, and the policy trusts `111122223334`.

**Expected.** `PartnerAccount` → **outsider**, exact: the account `111122223334`, by id, not declared.
The declaration of `aws:111122223333` is echoed and said to move nothing, and the headline says a
named outsider can assume the role.

**Why.** An account's root ARN names every principal of that account, so the grant pins the account
to one exact value; a declaration names an account by its whole id, and an account one digit away is
another account.

> "A 12-digit number, such as 012345678901, that uniquely identifies an AWS account." — https://docs.aws.amazon.com/accounts/latest/reference/manage-acct-identifiers.html · read 2026-09-23
