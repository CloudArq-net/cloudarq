# 74 — AWS's own trust policy for a maintenance window's service role

The trust policy the Systems Manager user guide shows for the service role a maintenance window runs
its tasks with, as written: the service principal `ssm.amazonaws.com` on `sts:AssumeRole`, with no
condition.

**Expected.** The one grant → **cloud services**, unknown, basis `service-intermediary`. The line
keeps the words true of every service: `ssm.amazonaws.com` can assume the role, and who can make it
act is not read. The note names machines registered by a hybrid activation as one use among others.
The grant admits `ssm.amazonaws.com`, acting for whoever can make it act. The ring of anyone holds
no grant and is **unknown** beside the line.

**Why.** Systems Manager assumes roles for more than hybrid activations. A maintenance window runs
its tasks with a service role the service assumes, and the role is named by whoever registers a
task, having been allowed to pass it. Who that is is set in the account's IAM policies and in the
window's tasks, which the trust policy does not carry. A line saying the role is for
hybrid-activated machines would name one use of several and drop who can make the service act, so
the line says what is not read and the note names the use the table records as one among others.

> "When you register a task with a maintenance window, you specify a service role to run the actual task operations. This is the role that the service assumes when it runs tasks on your behalf." — https://docs.aws.amazon.com/systems-manager/latest/userguide/sysman-maintenance-perm-console.html · read 2026-09-27
> "Before that, to register the task itself, assign the IAM PassRole policy to an IAM entity (such as a user or group). This allows the IAM entity to specify, as part of registering those tasks with the maintenance window, the role that should be used when running tasks." — https://docs.aws.amazon.com/systems-manager/latest/userguide/sysman-maintenance-perm-console.html · read 2026-09-27
