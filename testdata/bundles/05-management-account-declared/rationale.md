# 05 — read from the management account, which is also declared

A bundle `cloudarq-collect` writes from the management account of an AWS Organization: the account
read, `111122223333`, is the one `organization` names as managing `o-exampleorgid`. `owners.txt`
declares the same account. Three roles at `/`:

- `break-glass`, trusting `arn:aws:iam::111122223333:root`, the account read;
- `member-admin`, trusting `arn:aws:iam::123456789012:root`, an account in the Organization;
- `organization-reader`, trusting every principal whose `aws:PrincipalOrgID` is `o-exampleorgid`.

**Expected.**
- `break-glass` reads *"Nothing outside your company can assume this role."*, in *"Your AWS
  accounts"*, as *"aws:111122223333, declared as yours, can assume this role."*: the owner is marked
  both `"declared": true` and `"recognised": true`, and the words say what you said.
- `member-admin` reads *"A named outsider can assume this role."*: an account in your Organization
  is not yours until you say so, and nothing here says so.
- `organization-reader` asks only *"Is every account in this AWS Organization yours?"*, and says
  what it would read: *"If aws:o-exampleorgid is yours, this role reads: Any cloud service can
  assume this role."*
- `suggested` holds the Organization alone: the management account is the account read, which is
  recognised, so it is never asked about.
- No answer echoes `aws:111122223333` as unmatched, though two roles pin nothing to it: it is yours
  whatever is declared, and declaring it as well moves nothing either way.

**Why.** Recognising the account read and declaring it place it alike, through the one classifier;
the answer keeps them apart only in its marks and words. An owner declared that is also recognised
is never one that "moved nothing": the reader would otherwise be told, on every role of the scan,
that declaring their own account did nothing.

> "You can call this operation from any account in a organization." —
> https://docs.aws.amazon.com/organizations/latest/APIReference/API_DescribeOrganization.html · read 2026-10-03

The accounts, the Organization's ID, the role IDs and the dates are placeholders in AWS's own
example form.
