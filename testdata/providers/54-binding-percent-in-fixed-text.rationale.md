# 54 — a member with a percent escape in its fixed text

Hand-written fixture, 2026-09-14, bound against provider 03.

## Document

One member `principal://iam.googleapis.com/projects/123456789012/loc%61tions/global/workloadIdentityPools/github/subject/repo:acme/infra:ref:refs/heads/main`:
the segment `locations` is written with one letter percent-encoded.

## Expected

Bind returns true: `{aud="…/providers/github", sub="repo:acme/infra:ref:refs/heads/main"}`,
inexact, with a whole-grant caveat and an `unmodelled-construct` anomaly
whose Construct is `%`, saying whether the member is a workload identity
pool principal at all is not stated and that it is read as the one it
resembles.

## Why

Whether Google decodes percent escapes in a principal identifier is not
documented on the pages read (case 49). Decoded, the member is the subject
binding of case 35; taken as written it names no principal IAM documents.
The union of the two readings is the subject, so the member is read as
the principal it resembles with the doubt stated, the rule cases 49 and 50
apply to an escape in the pool and in the selector. Before this fixture
an escape in the fixed text alone was read as not a pool principal, on
the ground that a member whose fixed text cannot be placed "would have to
bind every provider"; it would not, because its value segments still name
one pool, and a member of another pool stays unbound (case 39). The host
is read the same way: a percent escape in it leaves the member undecided
and read as the principal it resembles. The scheme is not: RFC 3986
defines a scheme as letters, digits, "+", "-" and "." with no
percent-encoding, so text with "%" before "://" is no scheme, and such a
member is not a pool principal under any reading.

## Sources

- https://cloud.google.com/iam/docs/principal-identifiers (Workload identity pool)
- https://www.rfc-editor.org/rfc/rfc3986#section-3.1 (scheme = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." ))
