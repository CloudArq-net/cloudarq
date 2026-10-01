# 64 — An Entra work tenant's role that names two of the methods one sign-in lists in `amr`, under two operators without a set prefix

A trap: AWS documents `amr` as multivalued, and no one value meets both conditions.

**Expected.** `WorkforceWithMFA` → **platform**, unknown, as the work tenant of case 36. Never
*nobody*.

**Why.** Microsoft lists in `amr` every method a sign-in used, a password and a second factor among
them, and AWS's Default tab, which reads Entra's tokens, documents `amr` as a multivalued key and
does not say what an operator without a set prefix does on one. A person who signed in with a
password and a second factor carries both values the statement names. Read as one value that must
meet both conditions, the statement would admit nobody and every ring would read exact. The census
records `amr` as multivalued for Entra's tokens, on AWS's sentence, so each condition on it is read
as not evaluated, and the grant stays where the work tenant is.

> "The amr claim is an array that can contain multiple items, such as ["mfa", "rsa", "pwd"], for an authentication that used both a password and the Authenticator app." — https://learn.microsoft.com/en-us/entra/identity-platform/access-token-claims-reference · read 2026-09-27
> "The key is multivalued, meaning that you test it in a policy using condition set operators." — https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_iam-condition-keys.html (Default tab, `amr`) · read 2026-09-27
> "Multivalued context keys require a condition set operator." — https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-single-vs-multi-valued-context-keys.html · read 2026-09-27
