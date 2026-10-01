# 75 — AWS's own trust policy for an Automation service role

The trust policy the Systems Manager user guide prints for the service role Automation runs its
runbooks with, as written: the service principal `ssm.amazonaws.com`, `aws:SourceAccount` under
`StringEquals`, and `aws:SourceArn` under `ArnLike` on the account's automation executions.

**Expected.** The one grant → **cloud services**, unknown, basis `service-intermediary`. The line
keeps the words true of every service: `ssm.amazonaws.com` can assume the role, and who can make it
act is not read. The note names machines registered by a hybrid activation as one use among others.
The grant's own sentence says who it admits is not known, since neither source condition is read.
The ring of anyone holds no grant and is **unknown** beside the line.

**Why.** This is the role Automation assumes to act in the account for whoever names it in a
runbook, and AWS's condition on it names automation executions as the source. The engine reads
neither condition. A line saying the role is for hybrid-activated machines would name a use this
page does not give the role, and drop who can make the service act; so the line says what is not
read, and the note names the use the table records as one among others.

> "Using this role, or the Amazon Resource Name (ARN) of an AWS Identity and Access Management (IAM) role, in runbooks allows Automation to perform actions in your environment, such as launch new instances and perform actions on your behalf." — https://docs.aws.amazon.com/systems-manager/latest/userguide/automation-setup-iam.html · read 2026-09-27
> "The value of aws:SourceArn must be the ARN for automation executions." — https://docs.aws.amazon.com/systems-manager/latest/userguide/automation-setup-iam.html · read 2026-09-27
> "The following example shows how you can use the aws:SourceArn and aws:SourceAccount global condition context keys for Automation to prevent the confused deputy problem." — https://docs.aws.amazon.com/systems-manager/latest/userguide/automation-setup-iam.html · read 2026-09-27
