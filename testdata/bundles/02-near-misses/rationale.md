# 02 — near misses: never said to be AWS's

Six roles that come close to a service-linked role and are not one, or whose claim to be one the
bundle cannot back. None is explained: each `managed` is `null`, and nothing is printed under its
name. Each answer is still the one `AdmitsFor` gives its trust policy.

| Role | Path | Trust | Why it is not explained |
|---|---|---|---|
| `deploy-function-role` | `/service-role/` | `lambda.amazonaws.com` | the path a console gives the service roles customers make; anybody can create a role there, and its trust is theirs to edit |
| `NoServiceSegment` | `/aws-service-role/` | `organizations.amazonaws.com` | AWS's path names the service in one segment after it, and this one names none |
| `CapitalisedPath` | `/AWS-Service-Role/organizations.amazonaws.com/` | `organizations.amazonaws.com` | not the path AWS writes: IAM paths are compared as written |
| `AnAccountBesideTheService` | `/aws-service-role/organizations.amazonaws.com/` | the service, and `111122223333`'s root in a second statement | a role AWS made trusts its service alone; this trust admits an account too, so the bundle's claim does not hold, and the account is answered as a named outsider |
| `TwoSegments` | `/aws-service-role/organizations.amazonaws.com/extra/` | `organizations.amazonaws.com` | AWS's path is the service and nothing after it |
| `AnotherServicesPath` | `/aws-service-role/support.amazonaws.com/` | `organizations.amazonaws.com` | the path names one service and the trust admits another |

**Why these fall short, and why short is the safe side.** The path is AWS's to give only as
written:

> "Paths beginning with '/aws-service-role' are reserved for AWS Service Linked Roles" — IAM's
> answer (`InvalidInput`) to `CreateRole` at `/aws-service-role/cloudarq-probe.amazonaws.com/`, asked
> of a test account on 2026-10-03; nothing was created
> "The linked service defines the permissions of its service-linked roles, and unless defined
> otherwise, only that service can assume the roles." —
> https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create-service-linked-role.html · read 2026-10-03
> "A service-linked role : arn:aws:iam::123456789012:role/aws-service-role/access-analyzer.amazonaws.com/AWSServiceRoleForAccessAnalyzer
> A service role : arn:aws:iam::123456789012:role/service-role/QuickSightAction" —
> https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html · read 2026-10-03

So IAM never lists the last four as they are written here: each is what a bundle edited by hand, or
written by something other than `cloudarq-collect`, could claim. The engine says a role is AWS's only
when the path and the trust agree. A role that is AWS's and goes unexplained loses a sentence; a role
explained that is not AWS's would tell the reader a role somebody made is one AWS manages, and
`AnAccountBesideTheService` shows the cost: its answer names the account as an outsider, and the
explanation must not sit beside that answer saying only AWS's service gets in.

The account `123456789012`, `111122223333`, the role IDs and the dates are placeholders in AWS's own
example form.
