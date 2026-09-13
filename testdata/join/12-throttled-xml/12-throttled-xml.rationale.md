# 12 — a throttled call answered in XML is carried, and the pair keeps its link

The role admits `sub` like `repo:acme/*:ref:refs/heads/main`; the application admits `sub` like
`repo:acme/infra:*`; both from the GitHub Actions issuer, each with its own audience. The overlap
is the one of case 01: the shortest string both patterns match is
`repo:acme/infra:ref:refs/heads/main`, and both sides admit it.

The role's provenance holds two records. `iam:GetRole` returned `ok` with the trust policy.
`iam:ListRolePolicies` returned `throttled`, and its body is not JSON: IAM answers the Query API
in XML, and a throttled call is an `ErrorResponse` with the code `Throttling` (IAM API Reference,
*Common Errors*; the response shape is the one every IAM Query action returns). The collector
stored the bytes verbatim, as it must (`internal/evidence/evidence.go`: bytes are never
re-marshalled).

`throttled` is not conclusive (`Status.Conclusive()`), so spec property 4 applies and the link is
`Indeterminate`, with the reason naming the call, the target and the status. The witness stays on
the link as data.

The point of the case is what happens to the record. A body that is not JSON cannot be rendered
verbatim as JSON, and a Link that could not be built, or rendered, because a proof of its doubt
is XML would be a fan-out lost to a rendering limitation; the throttled and refused responses
most likely to be inconclusive are the ones most likely to carry a page that is not JSON. So the
link renders the body verbatim in the one encoding JSON carries any bytes in: `bytes_base64`,
beside the `sha256` of the same bytes. Decoding the field gives

```
<ErrorResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">
  <Error>
    <Type>Sender</Type>
    <Code>Throttling</Code>
    <Message>Rate exceeded</Message>
  </Error>
  <RequestId>00000000-0000-4000-8000-000000000012</RequestId>
</ErrorResponse>
```

whose SHA-256 is `7345bccdfaa4fbe7cae612cf51bcf8d6bf97a6d49cb33b3ad25a11a592cbc9d1`, the digest
beside it (checked by decoding the golden file, 2026-09-13). The two JSON bodies render under
`bytes`, as in every other case; a record renders under one of the two fields, never both, and a
record with no body under neither.

> Identities admitted by application 6b1e6c7e-0f1a-4d2b-9c3d-8e4f5a6b7c8d may also be admitted by role arn:aws:iam::111111111111:role/deploy from https://token.actions.githubusercontent.com; the call iam:ListRolePolicies for role arn:aws:iam::111111111111:role/deploy returned throttled.

One link, three provenance records, sorted by API name.
