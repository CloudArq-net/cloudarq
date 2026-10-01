# 10 — `"*"` on `sts:AssumeRole`

A trap: `"*"` on `sts:AssumeRole` is every AWS principal and every AWS service, and no web
identity token.

**Expected.**
- the AWS face (`aws:sts`) → **platform** (anyone with an AWS account), exact.
- the face with no issuer → **cloud services**, unknown: every AWS service.

**Why.** `sts:AssumeRole` is the action AWS services assume a role through, and every other caller
of it is an AWS principal with credentials, which the AWS face already places. Which accounts a
service acts for is not read, so the face sits on the services line beside the rings.

> "You must call this API using active credentials." — https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp_request.html (`AssumeRole`) · read 2026-09-23
> "After you create the role, you can change the account to "*" to allow everyone to assume the role." — https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html · read 2026-09-23
