# 03 — a path its own ARN contradicts: the bundle is refused

One role whose `Path` claims AWS's path, `/aws-service-role/organizations.amazonaws.com/`, while its
ARN, `arn:aws:iam::123456789012:role/AWSServiceRoleForOrganizations`, names the path `/`.

**Expected.** The whole bundle is refused, as a bundle holding a stranger's role is: exit code 1,
and the reason on standard error, *"the role "arn:aws:iam::123456789012:role/AWSServiceRoleForOrganizations"
is listed with the path "/aws-service-role/organizations.amazonaws.com/", and its ARN names the path
"/", so this bundle is not as cloudarq-collect wrote it"*. The JSON is the findings format and that
sentence as `error`, with no role; the text is empty.

**Why.** IAM writes a role's ARN as the path, without its leading slash, then the name, and lists
the same path in `Path`; `cloudarq-collect` writes both as IAM returns them. The two cannot
disagree in a bundle it wrote. The path is what the engine reads to say a role is AWS's, so a
bundle whose paths do not hold together is not read at all rather than read in part.

> "arn:aws:iam:: account :role/ role-name-with-path" (the syntax), and, of the role this case
> imitates, "A service-linked role : arn:aws:iam::123456789012:role/aws-service-role/access-analyzer.amazonaws.com/AWSServiceRoleForAccessAnalyzer" —
> https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html · read 2026-10-03

The account `123456789012`, the role ID and the dates are placeholders in AWS's own example form.
