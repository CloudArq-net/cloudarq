# 65 — An EKS cluster's role that names two audiences one token may carry, under two operators without a set prefix

A trap: no one value meets both conditions, and a service account token may carry several audiences.

**Expected.** `PodWithTwoAudiences` → **outsider**, exact, as the cluster of case 25: the tenant
`EXAMPLED539D4633E53DE1B71EXAMPLE`, named by id, not declared. Never *nobody*.

**Why.** Kubernetes issues a service account token for as many audiences as are asked for, and the
cluster's issuer signs it. AWS reads the cluster's `aud` key from `azp`, or from `aud` when the token
sets no `azp`, and says nothing of how many values the key holds, nor what an operator without a set
prefix compares on a claim that holds several. A pod whose token carries both `sts.amazonaws.com`
and `vault` meets each condition in one of its values. Read as one value that must meet both, the
statement would admit nobody and every ring would read exact. The census records that the cluster's
tokens may carry several values in `aud`, on these sentences, so each condition on `aud` is read as
not evaluated, and the grant stays where the cluster is: who can obtain the cluster's tokens does
not depend on their audience.

> "In the general case, the "aud" value is an array of case-sensitive strings, each containing a StringOrURI value." — https://www.rfc-editor.org/rfc/rfc7519.txt (4.1.3) · read 2026-09-27
> "Audience of the requested token. If unset, defaults to requesting a token for use with the Kubernetes API server. May be repeated to request a token valid for multiple audiences." — https://kubernetes.io/docs/reference/kubectl/generated/kubectl_create/kubectl_create_token/ · read 2026-09-27 (recorded in the census, `multi_valued_claims`)
> "Amazon EKS hosts a public OIDC discovery endpoint for each cluster that contains the signing keys for the ProjectedServiceAccountToken JSON web tokens so external systems, such as IAM, can validate and accept the OIDC tokens that are issued by Kubernetes." — https://docs.aws.amazon.com/eks/latest/userguide/iam-roles-for-service-accounts.html · read 2026-09-27 (recorded in the census, `multi_valued_claims`)
> "If no value is set for azp, the aud condition key maps to the aud claim." — https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_iam-condition-keys.html (Default tab) · read 2026-09-24 (recorded in the census, `aws_condition_keys`)
