# 72 — EC2 and Systems Manager in one statement

A trap: one statement trusts two services, one the engine's table lists, holding AWS's sentences on
its assuming a role for identities outside IAM, `ssm.amazonaws.com`, and one the table does not
list, `ec2.amazonaws.com`.

**Expected.** Two grants, both → **cloud services**, unknown: `ec2.amazonaws.com` with basis
`service-principal`, `ssm.amazonaws.com` with basis `service-intermediary`. The line says two cloud
services can assume the role and who can make them act is not read, which is true of both, and cites
Systems Manager's sentences alone, those on its other uses last. Each grant admits its service,
acting for whoever can make it act; EC2's note says what is not read of any service, Systems
Manager's names whom it acts for as one use among others. The ring of anyone holds no grant and is
**unknown** beside the line.

**Why.** Each service in a Principal is its own grant, and the words of each are its own: calling
EC2 AWS's own would say something nobody checked, and reading Systems Manager as EC2 would hide the
hybrid-activated machines it can pass its session to. AWS writes of EC2 providing a role's
credentials to the applications on an instance; the table does not list it, since no service beyond
its five has been surveyed, and its note says what is not read of any service, which is true of EC2
too.

> "A service principal is an identifier for a service." — https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html · read 2026-09-27
> "Non-EC2 (Amazon Elastic Compute Cloud) machines in a hybrid and multicloud environment require an AWS Identity and Access Management (IAM) service role to communicate with the AWS Systems Manager service." — https://docs.aws.amazon.com/systems-manager/latest/userguide/hybrid-multicloud-service-role.html · read 2026-09-27
> "The instance profile contains the role and can provide the role's temporary credentials to an application that runs on the instance." — https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_switch-role-ec2.html · read 2026-09-27
