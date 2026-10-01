# 66 — AWS's own trust policy for IAM Roles Anywhere

The trust policy IAM Roles Anywhere's trust-model page prints for a role the service hands to
certificate holders, as written: the service principal `rolesanywhere.amazonaws.com`, a condition on
the certificate's subject CN, and the trust anchor's ARN under `ArnEquals` on `aws:SourceArn`.

**Expected.** The one grant → **cloud services**, unknown, basis `service-intermediary`. The line
says whom the service can assume the role for, workloads holding a certificate, and that who they are
is not read, and cites the first four sentences below. The ring of anyone holds no grant and is
**unknown** beside the line. The grant's own sentence says who it admits is not known, since none of
its conditions is read.

**Why.** IAM Roles Anywhere issues the role's credentials to a client holding a certificate a trust
anchor in the account accepts. AWS writes of those clients as workloads outside AWS, and its
sentences below make the certificate the one condition, so the words say workloads that hold a
certificate and never where they run. Who holds one is set by the certificate authority the anchor
trusts, which the policy does not carry, so the role is a door and who comes through it is not read.
The source ARN names the anchor exactly; it names who the service acts through, not who receives the
session, so no reading of it can make the ring of anyone exact.

> "To use IAM Roles Anywhere, your workloads must use X.509 certificates issued by your certificate authority (CA)." — https://docs.aws.amazon.com/rolesanywhere/latest/userguide/introduction.html · read 2026-09-27
> "Certificates issued by any trust anchor in the account can be used to assume any target role in that same account, unless you specify conditions in the role's trust policy." — https://docs.aws.amazon.com/rolesanywhere/latest/userguide/introduction.html · read 2026-09-27
> "Temporary credentials for IAM roles are issued to IAM Roles Anywhere clients via the API method CreateSession." — https://docs.aws.amazon.com/rolesanywhere/latest/userguide/trust-model.html · read 2026-09-27
> "After validating the signature, IAM Roles Anywhere checks that the certificate was issued by a certificate authority configured as a trust anchor in the account using algorithms defined by public key infrastructure X.509 (PKIX) standards." — https://docs.aws.amazon.com/rolesanywhere/latest/userguide/trust-model.html · read 2026-09-27
> "When a client obtains temporary security credentials from IAM Roles Anywhere, the aws:SourceArn and aws:SourceAccount will be set based on the ARN of the trust anchor specified in the call to CreateSession." — https://docs.aws.amazon.com/rolesanywhere/latest/userguide/trust-model.html · read 2026-09-27
> "You can use AWS Identity and Access Management Roles Anywhere to obtain temporary security credentials in IAM for workloads such as servers, containers, and applications that run outside of AWS." — https://docs.aws.amazon.com/rolesanywhere/latest/userguide/introduction.html · read 2026-09-27
