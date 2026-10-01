# 69 — `"*"` on `sts:AssumeRole`, with a source account

A guard: `"*"` on `sts:AssumeRole` with `StringEquals` on `aws:SourceAccount`, the condition AWS
recommends whenever a service principal is given access to a resource.

**Expected.**
- the face with no issuer → **cloud services**, unknown, basis `any-service`: every AWS service.
- the AWS face (`aws:sts`) → **platform**, unknown, basis `unread-constraint`, and the ring's
  sentence says one of its conditions was not read.
- The ring of anyone holds no grant and is **unknown** beside the line.

**Why the services line.** `aws:SourceAccount` names the account a service acts on behalf of. That
is whom the service acts for, not who can make it act or who receives its session, and some
services hand the session to workloads outside AWS. So the ring of anyone is not established
beside the line, and it stays unknown however the source key is read: a reading that named the
account cannot establish it.

**Why the AWS face is unknown.** The engine does not evaluate `aws:SourceAccount`: it is a key of
the request, not a claim of a token. AWS puts it in the request only when a service principal
makes the call, and a condition on a key the request does not carry is false, so AWS admits no AWS
principal through this face. The platform is therefore an upper bound, not a place that follows
from constraints read exactly. A condition on any key of AWS's request context that the engine did
not read leaves a platform place unknown, because some of those keys name the account or
organisation a request comes from and some are absent from whole kinds of request.

> "Use aws:SourceAccount to allow an AWS service principal to access your resources on behalf of a specific AWS account." — https://docs.aws.amazon.com/IAM/latest/UserGuide/confused-deputy.html · read 2026-09-27
> "We recommend using these condition keys whenever access to one of your resources is granted to an AWS service principal." — https://docs.aws.amazon.com/IAM/latest/UserGuide/confused-deputy.html · read 2026-09-27
> "You can use AWS Identity and Access Management Roles Anywhere to obtain temporary security credentials in IAM for workloads such as servers, containers, and applications that run outside of AWS." — https://docs.aws.amazon.com/rolesanywhere/latest/userguide/introduction.html · read 2026-09-27
> "Use this key to compare the account ID of the resource making a service-to-service request with the account ID that you specify in the policy, but only when the request is made by an AWS service principal." — https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html · read 2026-09-27
> "Availability – This key is included in the request context only when the call to your resource is being made directly by an AWS service principal on behalf of a resource for which the configuration triggered the service-to-service request." — https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html · read 2026-09-27
> "If the key that you specify in a policy condition is not present in the request context, the values do not match and the condition is false." — https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition_operators.html · read 2026-09-27
