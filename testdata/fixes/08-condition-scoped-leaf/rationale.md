# 08 — a principal scoped by a condition

`WithExternalId` lists the partner's root and the declared `444455556666`, on condition that
`sts:ExternalId` is `partner-7f3c`.

**Expected.** The partner's fix is proven: remove `"arn:aws:iam::111122223333:root"` from
`Principal.AWS` in statement 1, lines 4-10. The condition stays, and still applies to the account
left. The policy then opens on "Nothing outside your company can assume this role."

**Why.** The condition scopes the statement, and through it every principal the statement names; the
principal is what names the partner. Removing it takes the partner's grant out and leaves the
statement, its condition and the other grant as they were, which the checks hold the edited policy
to.
