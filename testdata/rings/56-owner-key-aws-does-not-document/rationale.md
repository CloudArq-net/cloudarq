# 56 — a condition on GitHub's owner name, a key AWS does not document for GitHub

**Expected.** `OwnerByAKeyAWSDoesNotDocument` → **platform** (anyone on GitHub), unknown: the
condition on `repository_owner` is read as not read, and the grant's set is an upper bound with a
caveat naming the key.

**Why.** A condition reads a token's claim only through a key AWS puts in the request context, and
AWS's GitHub tab lists `repository_owner_id` but no `repository_owner`; the census records AWS's
keys for GitHub (census v0.2.0). A key AWS does not put in the request is, by AWS's rule,
a mismatch, so the statement may admit nobody at all; AWS may also read a key it does not document.
Neither is established, so the condition is read as not read: it pins no owner, it narrows nothing,
and the grant is not exact. Reading it as a pin on `acme` would print a named outsider, exact, on a
key AWS is not documented to read.

> "The name of the organization in which the `repository` is stored." — https://docs.github.com/en/actions/reference/security/oidc (`repository_owner`) · read 2026-09-23 (recorded in the census, `tenancy_claims`)
> "This tab explains how GitHub Actions maps OIDC claims to AWS STS condition context keys in AWS." — https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_iam-condition-keys.html · read 2026-09-24 (recorded in the census, `aws_condition_keys`)
> "AWS STS condition key IdP JWT claim Available in session actor actor No actor_id actor_id No job_workflow_ref job_workflow_ref No repository repository No repository_id repository_id No repository_owner_id repository_owner_id No workflow workflow No ref ref No environment environment No enterprise_id enterprise_id No" — https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_iam-condition-keys.html · read 2026-09-24 (recorded in the census, `aws_condition_keys`)
> "A context key that is not present in the request is considered a mismatch." — https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition.html · read 2026-09-24
