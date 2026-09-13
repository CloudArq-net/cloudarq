# 05 — a conjunction over two claims

Hand-written fixture, 2026-09-13.

## Document

`assertion.sub.startsWith('repo:acme/') && assertion.repository_owner_id == '123456'`.

## Expected

`{aud="…/providers/github", repository_owner_id="123456", sub=like:"repo:acme/*"}`, exact.

## Why

`&&` is CEL's logical and; a credential passes only when both operands
hold, which is the Meet of the two sets: one Term constraining both claims.
Google's own page on deployment pipelines extends a single equality the
same way, "assertion.repository_owner=='ORGANIZATION' &&
assertion.ref=='refs/heads/main'", which case 06 carries verbatim.

## Sources

- https://github.com/google/cel-spec/blob/master/doc/langdef.md (`&&`)
- https://cloud.google.com/iam/docs/workload-identity-federation-with-deployment-pipelines ("Optionally, extend the attribute condition to restrict access to a subset of workflows or branches.")
