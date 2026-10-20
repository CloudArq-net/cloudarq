# 09 — offsets that are not exactly a principal

`Partner` lists `111122223333` and the declared `444455556666`, and writes `111122223333` again as
the value of `aws:SourceAccount`; `NotFromThePartner` denies `111122223333` on `sts:TagSession`.

**Expected.** The answer proves the partner's fix at the offsets its reader read the list item at,
and the whole fixed policy is made at exactly those offsets. Given any other offsets, the fixed
policy is refused with why, never made: one byte into the literal; the literal without its quotes;
the same twelve digits as the condition's value; and the Deny's principal, which is a principal but
not one an Allow writes.

**Why.** Where a principal is written is read, never inferred: an edit is made only at offsets that
are exactly one principal string under a statement's `Principal`, and offsets that land anywhere
else are refused rather than moved to the nearest principal, since a guessed edit is an edit to
something nobody named. The fixed policy is made from the reader's own file at the offsets the
answer gives, so a file that is not the one the answer was read from is refused the same way.
`TestFixedRefusesOffsetsThatAreNotAPrincipal` (`internal/report/fixed_test.go`) holds each case.
