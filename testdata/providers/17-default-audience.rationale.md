# 17 — the default audience, derived from the name

Hand-written fixture, 2026-09-13.

## Document

`oidc` with no `allowedAudiences`, and a `name` of the canonical form with
a project number.

## Expected

`{aud=("//iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/github/providers/github" | "https://iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/github/providers/github"), sub="repo:acme/infra:ref:refs/heads/main"}`,
exact, with a `default-audience` anomaly that is a fact, not a doubt.

## Why

Google: "If this list is empty, the OIDC token audience must be equal to
the full canonical resource name of the WorkloadIdentityPoolProvider, with
or without the HTTPS prefix. For example:
//iam.googleapis.com/projects/<project-number>/locations/<location>/workloadIdentityPools/<pool-id>/providers/<provider-id>
https://iam.googleapis.com/projects/<project-number>/locations/<location>/workloadIdentityPools/<pool-id>/providers/<provider-id>".
Both examples spell the project as a number, and `name` is "Output only",
so the two forms are derived only when `name` has exactly that shape with
digits in the project segment; case 18 is the other branch. The Pass 1
table derived the two forms from any `name` present; this fixture departs
from it, because a request body or a Terraform rendering can spell the
project by ID or name something else, and an Exact on a string Google may
not use would be narrower than Google. Each form is an
Exact and the audience is their union.

## Sources

- https://docs.cloud.google.com/iam/docs/reference/rest/v1/projects.locations.workloadIdentityPools.providers (allowedAudiences, name)
