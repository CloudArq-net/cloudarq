# 44 — allowedAudiences spelt with a capital

Hand-written fixture, 2026-09-13.

## Document

`oidc` with `"AllowedAudiences": [...]` and no `allowedAudiences`, and a
`name` of the canonical form.

## Expected

`{aud=?("miscased key"), sub="repo:acme/infra:ref:refs/heads/main"}`:
inexact, a caveat on `aud`, one `miscased-key` anomaly on `aud` whose
sentence says whether Google reads the member is not stated, so
`allowedAudiences` is not read. No `default-audience` anomaly: the default
is not derived.

## Why

Google's JSON mapping for protocol buffers accepts a member under its
lowerCamelCase name or its original field name; whether a parser also
folds case is not stated on the pages read. Under a reader that does not
fold, the list is absent and the audience is the provider's resource name;
under one that does, the audience is the list. Neither set contains the
other, so an Exact on either is narrower than Google under the other
reading, and only Unknown on `aud`, declared, is never narrower. The same
rule applies to every member: a spelling that matches a documented name
only in case is not read, and neither is the documented member beside it,
since which of the two Google applies is exactly as unstated; what the
member bears on is Unknown with a caveat, as for a member written twice,
and a label is a fact. The anomaly is what keeps the member from vanishing.

## Sources

- https://docs.cloud.google.com/iam/docs/reference/rest/v1/projects.locations.workloadIdentityPools.providers (allowedAudiences)
- https://protobuf.dev/programming-guides/json/ ("Parsers accept both the lowerCamelCase name (or the one specified by the json_name option) and the original proto field name.")
