# 06 — Google's recommended condition, the near-miss that must pass

Hand-written fixture, 2026-09-13, from Google's page on deployment
pipelines: "Use the following attribute condition to restrict access to
tokens issued by your GitHub organization: assertion.repository_owner=='
ORGANIZATION '" and "the following condition limits access to workflows
that use the Git branch main: assertion.repository_owner==' ORGANIZATION '
&& assertion.ref=='refs/heads/main'". Google writes no space around `==`.

## Document

`assertion.repository_owner=='acme' && assertion.ref=='refs/heads/main'`.

## Expected

`{aud="…/providers/github", ref="refs/heads/main", repository_owner="acme"}`, exact.

## Why

A tool that fails the vendor's own recommendation is broken, however
satisfying a finding would look; the corpus therefore keeps this shape
permanently, spacing as Google writes it. CEL's lexer takes `==` without
surrounding whitespace, and each operand is a claim compared to a string.

## Sources

- https://cloud.google.com/iam/docs/workload-identity-federation-with-deployment-pipelines
- docs/ENGINEERING.md §7 ("Permanently include the near-misses")
