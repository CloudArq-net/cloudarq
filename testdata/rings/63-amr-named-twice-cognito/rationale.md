# 63 — A Cognito identity pool's role that names both values a Facebook user's `amr` holds, under two operators without a set prefix

A trap: AWS documents `amr` as multivalued, and no one value meets both conditions.

**Expected.** `PoolSignedInThroughFacebook` → **anyone**, unknown, as case 12. Never *nobody*.

**Why.** AWS documents `amr` as a multivalued key, which a policy tests with condition set operators,
and does not say what an operator without a set prefix does on such a key. Cognito's guide says an
authenticated user's `amr` holds `authenticated` and the providers the user signed in through, so a
user who signed in through Facebook carries both values the statement names. Read as one value that
must meet both conditions, the statement would admit nobody and every ring would read exact: a ring
nearer than its population. The census records `amr` as multivalued for Cognito's tokens, on AWS's
sentence, so each condition on it is read as not evaluated: `amr` is not constrained, `aud` still
is, and the grant stays where case 12 is.

**The token.** A Facebook user's token, `amr` `["authenticated", "graph.facebook.com"]`, is not
excluded and not proven admitted: `aud` is satisfied and `amr` is not compared.

> "The key is multivalued, meaning that you test it in a policy using condition set operators." — https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_iam-condition-keys.html (Amazon Cognito tab, `amr`) · read 2026-09-27
> "If the user is authenticated, the key contains the value authenticated and the name of the login provider used in the call" — https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_iam-condition-keys.html (Amazon Cognito tab, `amr`) · read 2026-09-27
> "Multivalued context keys require a condition set operator." — https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-single-vs-multi-valued-context-keys.html · read 2026-09-27
> "one of the array members of the multi-value amr claim of the token issued by the Amazon Cognito GetOpenIdToken API operation" — https://docs.aws.amazon.com/cognito/latest/developerguide/iam-roles.html · read 2026-09-27
> "If amr is authenticated, the token includes any providers used during authentication." — https://docs.aws.amazon.com/cognito/latest/developerguide/iam-roles.html · read 2026-09-27
