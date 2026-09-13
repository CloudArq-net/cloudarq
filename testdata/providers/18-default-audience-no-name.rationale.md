# 18 — the default audience with no name to derive it from

Hand-written fixture, 2026-09-13.

## Document

The shape of a create request body: no `name`, no `state`, and
`"allowedAudiences": []`.

## Expected

`{aud=?("default audience"), sub="repo:acme/infra:ref:refs/heads/main"}`,
inexact: a caveat on `aud` and a `default-audience` anomaly.

## Why

Google requires the audience to equal "the full canonical resource name of
the WorkloadIdentityPoolProvider", and `name` is "Output only": a request
body, a Terraform-rendered document or a hand-edited file may carry no name,
an empty one, a project ID where Google's examples show a number, or a name
of another shape. An Exact derived from any of those would reject the
audience Google actually accepts, which is narrower; so without a name of
the canonical form the audience is Unknown, declared. An empty list is the
proto3 default and reads as absent.

## Sources

- https://docs.cloud.google.com/iam/docs/reference/rest/v1/projects.locations.workloadIdentityPools.providers (allowedAudiences, name)
- https://protobuf.dev/programming-guides/json/ (an empty repeated field is the default value)
