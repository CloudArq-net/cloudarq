# 68 — AWS's own trust policy for a hybrid activation's service role

The trust policy the Systems Manager user guide prints for the service role of machines outside
EC2, as written: the service principal `ssm.amazonaws.com`, `aws:SourceAccount` under
`StringEquals`, and `aws:SourceArn` under `ArnEquals`. Its source account and the account in its
source ARN differ as AWS prints them; the document is kept as printed.

**Expected.** The one grant → **cloud services**, unknown, basis `service-intermediary`. The line
keeps the words true of every service: the service can assume the role, and who can make it act is
not read. The note names machines registered by a hybrid activation as one use among others. The
grant's own sentence says who it admits is not known, since neither source condition is read. The
ring of anyone holds no grant and is **unknown** beside the line.

**Why.** A hybrid activation registers servers, edge devices and virtual machines outside AWS, and
SSM Agent on each of them gets the service role's permissions through a credentials file written
during the activation. Which machines hold an activation is set in Systems Manager, which the policy does not
carry, so the role is a door and who comes through it is not read. The source conditions name the
account and the resources the service acts for, not the machines that receive its session. Systems
Manager assumes roles for maintenance windows and Automation too (cases 74 and 75), so the line does
not name hybrid-activated machines alone.

> "Non-EC2 (Amazon Elastic Compute Cloud) machines in a hybrid and multicloud environment require an AWS Identity and Access Management (IAM) service role to communicate with the AWS Systems Manager service." — https://docs.aws.amazon.com/systems-manager/latest/userguide/hybrid-multicloud-service-role.html · read 2026-09-27
> "On a non-EC2 machine, SSM Agent normally gets the needed permissions from the shared credentials file, located at /root/.aws/credentials (Linux and macOS) or %USERPROFILE%\.aws\credentials (Windows Server)." — https://docs.aws.amazon.com/systems-manager/latest/userguide/ssm-agent-technical-details.html · read 2026-09-27
> "The needed permissions are added to this file during the hybrid activation process." — https://docs.aws.amazon.com/systems-manager/latest/userguide/ssm-agent-technical-details.html · read 2026-09-27
> "Systems Manager supports on-premises servers, edge devices, and virtual machines running in other cloud environments, including Microsoft Azure." — https://docs.aws.amazon.com/systems-manager/latest/userguide/systems-manager-hybrid-multicloud.html · read 2026-09-27
