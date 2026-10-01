# 21 — a service principal with no `aws:SourceAccount`

A trap: a service principal whose trust no source condition bounds.

**Expected.** `ServiceAssumes` → **cloud services**, unknown. The ring of anyone holds no grant and is
unknown beside the line; its sentence says only that no grant is placed there.

**Why.** A service acts for accounts, and which accounts a service trust admits is not read here:
the source conditions that would bound it are request context, and the engine does not read
which accounts a service-principal trust admits. The grant sits on the services line beside the rings, and while it
does the empty-rings sentence is never printed.

Who can make the service act is not read, so nothing read rules out people with no account anywhere,
and the ring of anyone is not established while the line holds the grant.

> "This trust policy allows the Amazon EC2 service to assume the role." — https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create_for-service.html (beside `"Action": "sts:AssumeRole"`) · read 2026-09-23
