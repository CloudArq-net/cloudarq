# 19 — an AWS provider

Hand-written fixture, 2026-09-13.

## Document

`"aws": {"accountId": "123456789012"}`, no `attributeMapping`, and the
condition Google documents for restricting access to roles.

## Expected

Issuer `aws:sts`, the pseudo-issuer the AWS parser gives every AWS
principal; `{arn=like:"arn:aws:sts::123456789012:assumed-role/*", aws:principalaccount="123456789012"}`,
exact. No audience claim: an AWS credential is a signed GetCallerIdentity
request, not a token with an `aud`.

## Why

Google: "accountId: Required. The AWS account ID." Only that account's
credentials are accepted, which is Exact on the account. The account is
spelt `aws:principalaccount`, the claim the AWS parser gives the same fact,
because its value space is the same twelve digits and the join must find
that a GCP provider and an AWS trust policy trust the same account. The ARN
is not respelt: Google's "arn: the AWS ARN of the external entity" holds
the STS form for an assumed role, "arn:aws:sts::000000000000:assumed-role/ec2-my-role/i-00000000000000000",
while `aws:principalarn` holds the IAM role ARN, so an Exact on one never
equals an Exact on the other and a join keyed on one claim name would pair
nothing; the claim keeps Google's own name `arn`. The Pass 1 table
respelt `assertion.arn` as `aws:principalarn`; this fixture departs from
it for that reason, and the rewrite between the two ARN forms is the
join's to learn. Google: "For AWS
providers, if no attribute mapping is defined, the following default
mapping applies: {"google.subject":"assertion.arn", "attribute.aws_role":
…}", which the binding fixture 40 exercises. The condition is Google's own:
"assertion.arn.startsWith('arn:aws:sts:: AWS_ACCOUNT_ID :assumed-role/')".

## Sources

- https://docs.cloud.google.com/iam/docs/reference/rest/v1/projects.locations.workloadIdentityPools.providers (Aws, attributeMapping)
- https://cloud.google.com/iam/docs/workload-identity-federation-with-other-clouds (GetCallerIdentity fields; the documented condition)
- internal/parse/aws/principal.go (AWSPrincipalIssuer, aws:principalarn holds the role ARN)
