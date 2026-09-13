# 22 — the list response

Hand-written fixture, 2026-09-13.

## Document

The shape `providers.list` returns: `{"workloadIdentityPoolProviders": [...]}`
holding two providers and no `nextPageToken`.

## Expected

Two providers, in document order, each parsed as it would be alone: the
first `{aud="…/providers/github", sub="repo:acme/infra:ref:refs/heads/main"}`
from the GitHub issuer, the second `{aud="…/providers/gitlab", namespace_id="9876"}`
from `https://gitlab.com`, both exact. Each Grant's Source is that
provider's own bytes.

## Why

Google's response body is "workloadIdentityPoolProviders[]: A list of
providers." and "nextPageToken: A token, which can be sent as pageToken to
retrieve the next page. If this field is omitted, there are no subsequent
pages." A page that carries a token is an incomplete pool, and a Meet with
a binding on the whole pool depends on every provider, so ParseProviders
refuses a page that carries one, naming ParsePage, which returns the token
beside the providers; a collector cannot stop at page one without seeing it. A list never shows a soft-deleted provider unless
showDeleted was set, so a `provider-deleted` grant from a list document
means the collector asked for them.

## Sources

- https://docs.cloud.google.com/iam/docs/reference/rest/v1/projects.locations.workloadIdentityPools.providers/list
