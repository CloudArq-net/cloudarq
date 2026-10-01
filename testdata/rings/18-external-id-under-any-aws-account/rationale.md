# 18 — `sts:ExternalId` under `{"AWS": "*"}`

A trap: `sts:ExternalId` is a value the caller sends, and names no tenant.

**Expected.**
- the AWS face (`aws:sts`) → **platform** (anyone with an AWS account), exact.
- the face with no issuer → **cloud services**, unknown.

**Why.** The external id is a value the caller sends: under `{"AWS": "*"}` any AWS principal that
sends `vendor-abc` is admitted, whatever account it is in, so it pins no tenant (the parser records
`sts:externalid` as naming none). `{"AWS": "*"}` is `"*"`, so it has the face every AWS service
presents through `sts:AssumeRole`, as in case 10.

> "Use this key to require that a principal provide a specific identifier when assuming an IAM role." — https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_iam-condition-keys.html (`sts:ExternalId`) · read 2026-09-23
> "This value can be any string, such as a passphrase or account number." — https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html · read 2026-09-23
