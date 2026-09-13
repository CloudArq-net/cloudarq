# 18 — a service's condition key is a fact about the request, whoever the principal is

Hand-written fixture, 2026-09-13.

## Document

`ResourceTagBesideASubject` trusts the GitHub provider with `aud` and `sub`
pinned and adds `iam:ResourceTag/env` under the same `StringEquals`.
`SamlSubjectOnARole` trusts the role `arn:aws:iam::123456789012:role/ci`
through `sts:AssumeRole` with `saml:sub` pinned. `DenyByResourceTag` is a
Deny for account `123456789012` on `iam:ResourceTag/env`.

## Expected

- `ResourceTagBesideASubject`:
  `{aud="sts.amazonaws.com", iam:resourcetag/env=?("iam:resourcetag/env"), sub="repo:acme/infra:ref:refs/heads/main"}`,
  inexact, with a caveat on `iam:resourcetag/env` and an
  `unmodelled-construct` anomaly naming the key whose sentence is
  `the condition key "iam:ResourceTag/env" is a fact about the request, not a claim of the token, so this parser does not evaluate it and the claim is not constrained`.
  The main-branch token is admitted whatever the role's tags.
- `SamlSubjectOnARole`: issuer `aws:sts`,
  `{aws:principalaccount="123456789012", aws:principalarn="arn:aws:iam::123456789012:role/ci", saml:sub=?("saml:sub")}`,
  inexact, the same shape of anomaly on `saml:sub`. The named role is
  admitted.
- `DenyByResourceTag`: a Deny that denies nothing, inexact, with the
  anomaly on the key and the Deny-not-applied anomaly.

## Why

The IAM condition keys page: "IAM and AWS STS support both the
iam:ResourceTag IAM condition key and the aws:ResourceTag global condition
key", and its SAML section lists `saml:namequalifier`, `saml:sub` and
`saml:sub_type` as "condition keys that can be used in role trust policies
when federated principals assume another role". Both name a value of the
request context, the tag on the role being assumed or the SAML-derived
identity of the caller's session, and neither is a claim of a GitHub
token or a property of the role ARN this parser models. AWS admits the
main-branch token whenever the role carries `env=prod`, and admits the
role's SAML-federated sessions whose `saml:sub` matches.

An earlier draft read every key whose prefix was neither the principal's
own provider nor `aws:` or `sts:` as another identity provider's key, kept
verbatim, which is right for `gitlab.com:sub` on a GitHub grant (case 03
of the conformance triples, and TestForeignProviderKeysStayVerbatim): a
GitHub token cannot carry it, so the term admits nothing through it,
which is what the operators page says of a key "not present in the
request context". For `iam:` and `saml:` that reading put an exact
constraint on a claim no token carries and rejected every token AWS
admits, an under-approximation reported as exact. A provider's prefix is
a host and has a dot; a service's, `aws`, `sts`, `iam`, `saml`, `ec2`,
never does, and that is how the two are told apart. Mistaking a
provider's key for a service's only widens; the reverse is the error this
parser exists to never make. Under a Deny the Unknown makes the Deny
inapplicable, which keeps the result an upper bound.

## Sources

- https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_iam-condition-keys.html (fetched 2026-09-13)
- https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition_operators.html (fetched 2026-09-13)
- specs/B2-aws-trust-policy-parser.md §9, §11
