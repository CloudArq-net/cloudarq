# 19 — `"*"` with `aws:PrincipalOrgID`

A trap: `"*"` narrowed by `aws:PrincipalOrgID`, whose face on `sts:AssumeRole` the engine still
reads as every AWS service.

**Expected.**
- the AWS face (`aws:sts`) → **outsider**, exact: the organisation `o-a1b2c3d4e5`.
- the face with no issuer → **cloud services**, unknown.

**Why.** The organisation id is pinned exactly and names one organisation in AWS Organizations, so
every AWS principal admitted belongs to it. The face with no issuer is every AWS service on
`sts:AssumeRole`. Whether AWS's availability rule for the key keeps services out needs a reading of
service principals the engine does not do, so the services line stays, and the headline names it.

> "Use this key to compare the identifier of the organization in AWS Organizations to which the requesting principal belongs with the identifier specified in the policy." — https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html (`aws:PrincipalOrgID`) · read 2026-09-23
> "This key is included in the request context only if the principal is a member of an organization." — https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html · read 2026-09-23
