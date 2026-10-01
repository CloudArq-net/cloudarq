# 71 — AWS's own trust policy for a Transfer Family user's role

The trust policy the AWS Transfer Family user guide prints for the role a server's users act with,
as written: the service principal `transfer.amazonaws.com` on `sts:AssumeRole`, with no condition.

**Expected.** The one grant → **cloud services**, unknown, basis `service-intermediary`. The line
keeps the words true of every service: the service can assume the role, and who can make it act is
not read. The note names the users of a Transfer Family server as one use among others. The grant
admits `transfer.amazonaws.com`, acting for whoever can make it act. The ring of anyone holds no
grant and is **unknown** beside the line.

**Why.** Transfer Family assumes the role in the context of a user of one of its servers, and acts
with the session for that user; the users, and the keys they authenticate with, are set in the
server, which the policy does not carry. So the role is a door and who comes through it is not read.
The service acts with the session and hands it to no one, so the words never say it passes the
session on. It also assumes invocation, logging and execution roles for its servers and workflows,
each trusting the same service principal, so the line does not name the users alone.

> "In the Edit Trust Relationship editor, make sure service is "transfer.amazonaws.com"." — https://docs.aws.amazon.com/transfer/latest/userguide/requirements-roles.html · read 2026-09-27
> "User role – Allows service-managed users to access the necessary Transfer Family resources. AWS Transfer Family assumes this role in the context of a Transfer Family user ARN." — https://docs.aws.amazon.com/transfer/latest/userguide/requirements-roles.html · read 2026-09-27
> "When your user sends an authentication request to your server by using a client, your server first confirms that the user has access to the associated SSH private key." — https://docs.aws.amazon.com/transfer/latest/userguide/create-user.html · read 2026-09-27
> "Invocation role – For use with Amazon API Gateway as the server's custom identity provider. Transfer Family assumes this role in the context of a Transfer Family server ARN." — https://docs.aws.amazon.com/transfer/latest/userguide/requirements-roles.html · read 2026-09-27
> "Execution role – Allows a Transfer Family user to call and launch workflows. Transfer Family assumes this role in the context of a Transfer Family workflow ARN." — https://docs.aws.amazon.com/transfer/latest/userguide/requirements-roles.html · read 2026-09-27
