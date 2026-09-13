# 23 — an AWS principal value that names no principal is not an exact identity

Hand-written fixture, 2026-09-13.

## Document

Seven statements on `sts:AssumeRole`, each with an `AWS` principal AWS
documents as not a principal, or of a shape no IAM or STS principal ARN
has: a role ARN with a wildcard in the name, a group ARN, an OIDC provider
ARN under the `AWS` kind, an IAM ARN with nothing after the account id, an
ARN whose account field is `acme`, an IAM ARN with a region, and a Deny
on a role ARN with a wildcard.

## Expected

Seven grants, all on issuer `aws:sts`, none exact.

- `WildcardInsideARoleArn`:
  `{aws:principalaccount="123456789012", aws:principalarn=?("arn:aws:iam::123456789012:role/*")}`,
  with a caveat on `aws:principalarn` and a `malformed` anomaly naming the
  value whose sentence is
  `the AWS principal "arn:aws:iam::123456789012:role/*" holds a wildcard, which AWS documents cannot match part of a principal name or ARN, so who it names is not known`.
- `GroupArn`: the same shape with the account kept; the sentence is
  `the AWS principal "arn:aws:iam::123456789012:group/admins" names no account root, role or user, which are the IAM principals AWS documents, so who it names is not known`.
- `ProviderArnUnderTheAWSKind` and `NoResource`: the same shape and
  sentence as `GroupArn`, for their own values.
- `AccountThatIsNotAnId`: everything, with a caveat on `aws:principalarn`
  and the sentence
  `the AWS principal "arn:aws:iam::acme:role/ci" has "acme" where a 12-digit account id belongs, so who it names is not known`.
  No account constraint: `acme` is not an account.
- `RegionInAnIamArn`:
  `{aws:principalaccount="123456789012", aws:principalarn=?("arn:aws:iam:us-east-1:123456789012:role/ci")}`
  with the sentence
  `the AWS principal "arn:aws:iam:us-east-1:123456789012:role/ci" names a region, which an IAM or STS principal ARN never has, so who it names is not known`.
- `DenyAWildcardRole`: a Deny that denies nothing, inexact, with the
  wildcard sentence and the Deny-not-applied anomaly.

## Why

The principal page: "You cannot use a wildcard to match part of a
principal name or ARN"; "You cannot identify a user group as a principal in
a policy (such as a resource-based policy) because groups relate to
permissions, not authentication, and principals are authenticated IAM
entities"; and the ARN forms it documents for the `AWS` kind are the
account (`arn:aws:iam::account-ID:root` or the bare id), a role
(`arn:aws:iam::AWS-account-ID:role/role-name`), a user
(`arn:aws:iam::AWS-account-ID:user/user-name`), a role session
(`arn:aws:sts::AWS-account-ID:assumed-role/role-name/role-session-name`) and
a federated user (`arn:aws:sts::AWS-account-ID:federated-user/user-name`).
Every one has a 12-digit account and no region.

An earlier draft read any six-field IAM or STS ARN as an identity and
pinned `aws:principalarn` to it, exactly, with no anomaly. For
`role/*` that claimed the policy trusts a role literally named `*`: a
silent reinterpretation of a value AWS documents as not a principal, and a
provably empty set for a document that either does not deploy or, if a
wildcard were honoured, admits every role in the account. What IAM does
with each of these values at save time is not stated on the pages read,
so the ARN is Unknown, declared, and the account is kept when the field
holds one: under every reading the deployed set lies inside it. The
sentence names the documented fact rather than guessing which reading
applies. Under a Deny the Unknown makes the Deny inapplicable, which keeps
the result an upper bound. A string that is not an ARN at all is unchanged
from before: it may be the unique id of a deleted principal, and is Unknown
for that reason (case 11 and TestOpaqueAWSPrincipalIsUnknown).

## Sources

- https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html (fetched 2026-09-13)
- specs/B2-aws-trust-policy-parser.md §11
