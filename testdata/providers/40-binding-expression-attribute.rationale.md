# 40 — a binding on an attribute mapped by an expression

Hand-written fixture, 2026-09-13, bound against provider 19, the AWS
provider with Google's default mapping.

## Document

`principalSet://…/workloadIdentityPools/aws/attribute.aws_role/arn:aws:sts::123456789012:assumed-role/deploy`.

## Expected

Bind returns true and `{arn=like:"arn:aws:sts::123456789012:assumed-role/*", aws:principalaccount="123456789012"}`,
inexact: the provider's own set with a whole-grant caveat and an
`unmodelled-construct` anomaly whose Construct is the default mapping's
expression for `attribute.aws_role`.

## Why

Google's default AWS mapping makes `attribute.aws_role` the ternary
"assertion.arn.contains('assumed-role') ? assertion.arn.extract('{account_arn}assumed-role/')
+ 'assumed-role/' + assertion.arn.extract('assumed-role/{role_name}/') :
assertion.arn", so a binding on `attribute.aws_role` is the common
real-world binding for an AWS provider, not an edge. A parser that keyed
the member's value on the mapping text would build a Term on a claim no
credential carries, and that Term admits nobody: a Bind narrower than
Google on the shape Google documents as the default. A member on an
attribute whose mapping is not a bare assertion reference therefore
contributes top, with the caveat on the whole grant and the anomaly naming
the expression, exactly as a condition on such an attribute does in case 10.

## Sources

- https://docs.cloud.google.com/iam/docs/reference/rest/v1/projects.locations.workloadIdentityPools.providers (attributeMapping: the default AWS mapping)
- https://cloud.google.com/iam/docs/principal-identifiers
