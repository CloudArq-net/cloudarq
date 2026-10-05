# 04 — an account in an AWS Organization: the account read is yours, the rest is asked

A bundle `cloudarq-collect` writes from an account in an AWS Organization it does not manage:
`organization` names the Organization `o-exampleorgid` and its management account `111122223333`.
Four roles at `/`:

- `OrganizationAccountAccessRole`, trusting `arn:aws:iam::111122223333:root`, the management
  account: the trust a test account's role of that name held on 2026-10-03 (case 09);
- `organization-reader`, trusting every principal whose `aws:PrincipalOrgID` is `o-exampleorgid`;
- `partner-audit`, trusting `arn:aws:iam::444455556666:root`, an account outside the Organization;
- `break-glass`, trusting `arn:aws:iam::123456789012:root`, the account the scan read.

**Expected.**
- `break-glass` reads *"Nothing outside your company can assume this role."*: its grant is placed in
  the ring labelled *"Your AWS accounts"*, whose sentence is *"aws:123456789012, recognised: the
  account this scan read, can assume this role."* The owner is marked `"recognised": true` and
  `"declared": false`.
- `OrganizationAccountAccessRole` still reads *"A named outsider can assume this role."*, its owner
  `aws:111122223333` marked neither. Its `would_move` asks *"Is this account, which manages your AWS
  Organization, yours? A reseller or a managed service provider may run it."* and says *"If
  aws:111122223333 is yours, this role reads: Nothing outside your company can assume this role."*
- `organization-reader` still reads *"A named outsider can assume this role; so can cloud
  services."* Its `would_move` asks *"Is every account in this AWS Organization yours?"* and says
  *"If aws:o-exampleorgid is yours, this role reads: Any cloud service can assume this role."*: the
  statement names every principal, so the line of cloud services stays, and only the grant pinned
  to the Organization would move.
- `partner-audit` reads *"A named outsider can assume this role."*, and nothing is asked of it.
- The findings carry `recognised`, the account read, and `suggested`, the two questions, neither
  declared. Every answer echoes the account recognised, and none echoes it as unmatched.

**Why the account read is yours.** The collector read it with your own credentials: it is the
account those credentials belong to, `sts:GetCallerIdentity`'s answer. A role trusting its own
account trusts whoever that account's identity policies let in, which is the account's business,
not an outsider's.

**Why the management account and the Organization are asked, never assumed.** Either may be
someone else's. A reseller or a managed service provider may run the management account, and an
Organization may hold accounts of other companies. Counting either as yours unasked would place a
role an outsider can assume in your own ring, which is the one reading this engine exists to
prevent. So each is carried with its question, and counts only once you declare it; meanwhile the
role says what declaring it would change.

> "You can call this operation from any account in a organization." —
> https://docs.aws.amazon.com/organizations/latest/APIReference/API_DescribeOrganization.html · read 2026-10-03
> "Use this key to compare the identifier of the organization in AWS Organizations to which the
> requesting principal belongs with the identifier specified in the policy." —
> https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html · read 2026-10-03

The accounts, the Organization's ID, the role IDs and the dates are placeholders in AWS's own
example form; `o-exampleorgid` is the ID of AWS's own example of an Organization.
