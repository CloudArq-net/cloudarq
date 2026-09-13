# 46 — a binding inside a Cloud Asset policy search result

Hand-written fixture, 2026-09-13, bound against provider 03.

## Document

One `IamPolicySearchResult`, as `cloudasset.assets.searchAllIamPolicies`
with `query=policy:principalSet` returns each result: the resource, its
asset type and project, and the policy under `policy`, whose one binding
names the whole pool.

## Expected

ParseMembers returns the one member, with `Resource` set to the service
account's full resource name; Bind returns true and
`{aud="…/providers/github", sub=like:"repo:acme/infra:*"}`, exact: the
same grant as case 38, which carries the same binding as a bare policy.

## Why

Google: the response of searchAllIamPolicies is `{"results": [
IamPolicySearchResult ], "nextPageToken": string}`, and a result is
`{"resource", "assetType", "project", "folders", "organization",
"policy", "explanation"}`, where "policy: The IAM policy directly set on
the given resource. Note that the original IAM policy can contain multiple
bindings. This only contains the bindings that match the given query."
This query is the way a collector finds every binding on a pool without a
getIamPolicy per service account, so a document in this shape that read
as a policy with no bindings would be silence on the exact binding the
unit exists to read. A page of results reads the same way, and a page
carrying a `nextPageToken` ("Set if there are more results than those
appearing in this response") is refused, so that a policy on a later page
never reads as absent.

## Sources

- https://cloud.google.com/asset-inventory/docs/reference/rest/v1/TopLevel/searchAllIamPolicies (Response body, nextPageToken)
- https://cloud.google.com/asset-inventory/docs/reference/rest/v1/IamPolicySearchResult (policy, resource)
