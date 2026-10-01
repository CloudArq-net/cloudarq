# 48 — GitHub's enterprise claim, which the census does not record as naming a tenant

A claim the census does not list among an issuer's tenancy claims pins nothing: GitHub's
`enterprise` claim is `not_tenancy`, `unverified`, in census v0.2.0.

**Expected.** `EnterpriseByName` → **platform** (anyone on GitHub), exact. The grant's own set is
an upper bound, with a caveat naming the `enterprise` key.

**Why.** GitHub describes the claim as the enterprise's name, and does not say whether it carries
the enterprise's slug, which one enterprise holds at a time and GitHub releases to other customers,
or a name another enterprise can share. The census therefore does not list it among GitHub's
tenancy claims, and a claim it does not list pins nothing. `repo:*` names no owner, so no condition
of the statement confines its tokens to one, and the grant is at the platform whichever way the
enterprise condition goes: a condition that cannot pin can only narrow.

AWS's GitHub tab lists no `enterprise` key either (census v0.2.0), so the condition is read
as not read: a key AWS does not put in the request is, by AWS's rule, a mismatch, and AWS may also
read a key it does not document. The grant's set is an upper bound on either reading, and the note
names the key.

> "The name of the enterprise that contains the repository from where the workflow is running." — https://docs.github.com/en/enterprise-cloud@latest/actions/reference/security/oidc (`enterprise`) · read 2026-09-23 (recorded in the census, `not_tenancy`)
> "AWS STS condition key IdP JWT claim Available in session actor actor No actor_id actor_id No job_workflow_ref job_workflow_ref No repository repository No repository_id repository_id No repository_owner_id repository_owner_id No workflow workflow No ref ref No environment environment No enterprise_id enterprise_id No" — https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_iam-condition-keys.html · read 2026-09-24 (recorded in the census, `aws_condition_keys`)
> "A context key that is not present in the request is considered a mismatch." — https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition.html · read 2026-09-24
