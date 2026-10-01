# 20 — a member that differs from Graph's spelling only by case

Hand-written fixture, 2026-09-13.

## Document

`"Subject": "…main"` where Graph spells the member `subject`.

## Expected

`{aud="api://AzureADTokenExchange", sub=?("no subject constraint")}`,
inexact, with a caveat on `sub`, a `miscased-key` anomaly whose Construct is
the member as written, `Subject`, and a `no-subject-constraint` anomaly.

## Why

Graph's JSON representation spells every member exactly, and JSON member
names are compared as strings, so `Subject` is not `subject`. Go's
`encoding/json` would match the two case-insensitively and read the value as
the subject, which is an acceptance Graph itself would not perform. The
member is recorded and not read as the subject; with no subject and no
expression the credential is the same shape as case 06, and is reported the
same way.

## Sources

- https://learn.microsoft.com/en-us/graph/api/resources/federatedidentitycredential?view=graph-rest-beta (JSON representation)
- https://www.rfc-editor.org/rfc/rfc8259#section-4
