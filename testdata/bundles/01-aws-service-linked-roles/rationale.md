# 01 — AWS's own roles: said to be AWS's, and still `service · unknown`

The three service-linked roles a test account in an AWS Organization held on 2026-10-03, each at the
path IAM lists it at and with the trust policy AWS wrote for it: the service, and nothing else, may
assume it.

**Expected.**
- Each role's `managed` is `{"by": "aws", "service": <the path's segment>, …}`, with the sentence
  *"AWS made this role for <service> and manages it: the service wrote its trust policy and
  permissions, and nobody in this account can edit them."* and the caption *"Who gets in through it
  is whoever can make <service> act. That may be someone this account lets call it, or, if this
  account's AWS Organization gives the service trusted access, the Organization's management account
  or a delegated administrator. The engine does not read who yet."* The terminal prints both under
  the role's name.
- Each answer is the one `AdmitsFor` gives the trust policy alone: the headline *"<service> can
  assume this role."*, one grant on the line of cloud services, placed `service`, **unknown**.

**Why AWS's.** The path is AWS's to give. IAM refuses `CreateRole` at it to anyone else, and an
account cannot change such a role's trust:

> "Paths beginning with '/aws-service-role' are reserved for AWS Service Linked Roles" — IAM's
> answer (`InvalidInput`) to `CreateRole` at `/aws-service-role/cloudarq-probe.amazonaws.com/`, asked
> of a test account on 2026-10-03; nothing was created
> "Service-linked roles are predefined by the service and include all the permissions that the
> service requires to call other AWS services on your behalf." —
> https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create-service-linked-role.html · read 2026-10-03
> "The request was rejected because service-linked roles are protected AWS resources. Only the
> service that depends on the service-linked role can modify or delete the role on your behalf." —
> https://docs.aws.amazon.com/IAM/latest/APIReference/API_UpdateAssumeRolePolicy.html
> (`UnmodifiableEntity`) · read 2026-10-03

A bundle is a file, so the path is a claim; it is held to the trust the role carries, which here
admits the path's service alone. Case 02 holds the claims that fall short.

**Why still unknown.** Saying whose role it is says nothing about who gets in through it. AWS
says who that is, and it is not in a trust policy. In the account:

> "This means that users and roles with permissions to call a service that uses a service-linked
> role may have indirect access to services that can be accessed by that service-linked role." —
> https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create-service-linked-role.html · read 2026-10-03

And beyond it, when the account's AWS Organization gives the service trusted access. The first of
these roles is the one Organizations itself acts through to set that up:

> "To make all of this possible, when you create an account in an organization or you accept an
> invitation to join your existing account to an organization, AWS Organizations provisions the
> member account with a service-linked role named AWSServiceRoleForOrganizations. … The role has
> permissions that allow AWS Organizations to create service-linked roles for other AWS services." —
> https://docs.aws.amazon.com/organizations/latest/userguide/orgs_integrate_services.html · read 2026-10-03
> "Provides an AWS service (the service that is specified by `ServicePrincipal`) with permissions
> to view the structure of an organization, create a service-linked role in all the accounts in the
> organization, and allow the service to perform operations on behalf of the organization and its
> accounts." … "You can only call this operation from the management account." —
> https://docs.aws.amazon.com/organizations/latest/APIReference/API_EnableAWSServiceAccess.html · read 2026-10-03
> "These services enable you to register one or more member accounts as administrators that can
> manage all of the organization's accounts used in the service." —
> https://docs.aws.amazon.com/organizations/latest/userguide/orgs_integrate_delegated_admin.html · read 2026-10-03

So the caption does not confine who makes the service act to the account: the Organization's
management account, or a delegated administrator, may be a reseller or a managed service provider,
and words naming only the account's own people would describe that outsider as one of them. Their
permissions are in identity policies the engine does not read, so the grant stays where every
service's grant is: who can make the service act is not read. Placing it as exact would narrow the
answer without reading anything.

**Where the trust policies come from.** Each is the text AWS writes for that role; a test
account's three, listed on 2026-10-03, are equal to them byte for byte, at the same paths. The
account `123456789012`, the role IDs and the dates are placeholders in AWS's own example form.
